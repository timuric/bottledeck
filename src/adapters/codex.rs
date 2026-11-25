use crate::adapters::{
    ParsedFile, SpanBuildArgs, build_command_spans, clamp_tool_duration, detect_handoff_text,
    detect_tool_error, detect_truncation, dominant_span_repo, extract_tool_error_preview,
    flatten_content, make_id, normalize_tool_name, to_epoch_ms, walk_files,
};
use crate::config::estimate_tokens_str;
use crate::db::{SessionRecord, ToolCallRecord};
use crate::shell::{extract_duration_ms_from_text, extract_exit_code_from_text};
use crate::workspace::{WorkspaceResolver, is_neutral_home_dir};
use anyhow::Result;
use chrono::Utc;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

pub fn discover_files(root: &Path) -> Vec<PathBuf> {
    walk_files(root, 6, |_p, name| name.ends_with(".jsonl"))
}

fn extract_js_string_literal(s: &str, start_quote_idx: usize) -> Option<(String, usize)> {
    let bytes = s.as_bytes();
    let quote = *bytes.get(start_quote_idx)?;
    if quote != b'"' && quote != b'\'' && quote != b'`' {
        return None;
    }
    let mut out = String::new();
    let mut chars = s[start_quote_idx + 1..].char_indices();
    let mut escaped = false;
    while let Some((rel_i, ch)) = chars.next() {
        if escaped {
            match ch {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                other => out.push(other),
            }
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch as u32 == quote as u32 {
            return Some((out, start_quote_idx + 1 + rel_i + ch.len_utf8()));
        }
        out.push(ch);
    }
    None
}

fn extract_inner_exec_commands_from_js(js: &str) -> Vec<String> {
    let mut cmds = Vec::new();
    let mut search_from = 0usize;
    while let Some(pos) = js[search_from..].find("exec_command") {
        let abs = search_from + pos + "exec_command".len();
        search_from = abs;
        let window = &js[abs..js.len().min(abs + 4096)];
        // Locate `cmd` key inside object literal `{ cmd: "..." }` or `{"cmd":"..."}`
        let cmd_pos = window
            .find("cmd:")
            .map(|i| i + 4)
            .or_else(|| window.find("\"cmd\":").map(|i| i + 6))
            .or_else(|| window.find("cmd :").map(|i| i + 5));
        if let Some(cp) = cmd_pos {
            let after_colon = &window[cp..];
            if let Some(q_rel) = after_colon.find(|c| c == '"' || c == '\'' || c == '`') {
                // Only accept if whitespace precedes the opening quote
                if after_colon[..q_rel].trim().is_empty()
                    && let Some((cmd_str, _)) = extract_js_string_literal(after_colon, q_rel)
                {
                    let trimmed = cmd_str.trim();
                    if !trimmed.is_empty() {
                        cmds.push(trimmed.to_string());
                    }
                }
            }
        }
    }
    cmds
}

fn extract_codex_commands(
    tool_name: &str,
    raw_args: Option<&Value>,
    raw_input: Option<&Value>,
) -> Vec<String> {
    let lower = tool_name.to_ascii_lowercase();
    if lower == "wait" {
        let yield_ms = raw_args
            .and_then(|v| {
                v.as_str()
                    .and_then(|s| serde_json::from_str::<Value>(s).ok())
                    .or_else(|| Some(v.clone()))
            })
            .and_then(|v| v.get("yield_time_ms").and_then(Value::as_i64));
        return match yield_ms {
            Some(ms) if ms <= 5_000 => vec!["codex-wait --spin".to_string()],
            _ => vec!["codex-wait".to_string()],
        };
    }
    if lower == "sleep" {
        let ms = raw_args
            .and_then(|v| {
                v.as_str()
                    .and_then(|s| serde_json::from_str::<Value>(s).ok())
                    .or_else(|| Some(v.clone()))
            })
            .and_then(|v| v.get("duration_ms").and_then(Value::as_i64))
            .unwrap_or(1000);
        return vec![format!("sleep {}", (ms / 1000).max(1))];
    }

    if matches!(
        lower.as_str(),
        "exec_command" | "shell" | "shell_command" | "bash"
    ) {
        let parsed = raw_args.and_then(|v| {
            v.as_str()
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
                .or_else(|| Some(v.clone()))
        });
        if let Some(obj) = parsed {
            if let Some(c) = obj.get("cmd").and_then(Value::as_str) {
                return vec![c.to_string()];
            }
            if let Some(c) = obj.get("command").and_then(Value::as_str) {
                return vec![c.to_string()];
            }
            if let Some(arr) = obj.get("command").and_then(Value::as_array) {
                let parts: Vec<&str> = arr.iter().filter_map(Value::as_str).collect();
                if !parts.is_empty() {
                    return vec![parts.join(" ")];
                }
            }
        }
        return raw_args
            .and_then(Value::as_str)
            .map(|s| vec![s.to_string()])
            .unwrap_or_default();
    }

    if lower == "exec" {
        let Some(src) = raw_input.or(raw_args) else {
            return Vec::new();
        };
        if let Some(s) = src.as_str() {
            let trimmed = s.trim();
            if trimmed.starts_with('{')
                && let Ok(obj) = serde_json::from_str::<Value>(trimmed)
                && let Some(c) = obj
                    .get("cmd")
                    .or_else(|| obj.get("command"))
                    .and_then(Value::as_str)
            {
                return vec![c.to_string()];
            }

            // Unwrap real shell commands called via `tools.exec_command({ cmd: "..." })` inside Codex JS exec
            let inner = extract_inner_exec_commands_from_js(trimmed);
            if !inner.is_empty() {
                return inner;
            }

            // Detect interactive polling via `tools.write_stdin`
            if trimmed.contains("write_stdin(") {
                return vec!["codex-write-stdin".to_string()];
            }

            // Ignore pure JS non-shell helpers (apply_patch, read_text, MCP tool calls)
            if trimmed.contains("await ")
                || trimmed.contains("text(")
                || trimmed.contains("tools.")
                || trimmed.starts_with("const ")
                || trimmed.starts_with("let ")
                || trimmed.starts_with("async ")
            {
                return Vec::new();
            }

            if !trimmed.is_empty() {
                return vec![trimmed.to_string()];
            }
        }
    }

    Vec::new()
}

struct PendingCall {
    cmds: Vec<String>,
    turn_idx: i64,
    ts: i64,
    cwd: Option<String>,
}

struct PendingToolCall {
    tool_name: String,
    turn_idx: i64,
    ts: i64,
    cwd: Option<String>,
}

/// Extract non-shell `tools.<name>(` helper invocations from Codex JS exec blocks.
fn extract_js_tool_name(js: &str) -> Option<String> {
    let idx = js.find("tools.")?;
    let after = &js[idx + 6..];
    let name: String = after
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    if name.is_empty() || matches!(name.as_str(), "exec_command" | "write_stdin") {
        None
    } else {
        Some(name)
    }
}

pub fn parse_file(file_path: &Path, resolver: &mut WorkspaceResolver<'_>) -> Result<ParsedFile> {
    let raw = fs::read_to_string(file_path)?;
    let source_file = file_path.to_string_lossy().to_string();

    let mut session_id = file_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();
    let mut cwd: Option<String> = None;
    let mut model: Option<String> = None;
    let mut started_at: Option<i64> = None;
    let mut ended_at: Option<i64> = None;
    let mut turn_count: i64 = 0;
    let mut is_subagent = false;
    let mut originator: Option<String> = None;
    let mut subagent_kind: Option<String> = None;
    let mut is_handoff = false;
    let mut first_user_seen = false;
    let mut first_meta_seen = false;

    let mut max_thread_in: i64 = 0;
    let mut max_thread_out: i64 = 0;
    let mut max_thread_cached: i64 = 0;
    let mut sum_in: i64 = 0;
    let mut sum_out: i64 = 0;
    let mut sum_cached: i64 = 0;

    let mut pending: HashMap<String, PendingCall> = HashMap::new();
    let mut pending_tools: HashMap<String, PendingToolCall> = HashMap::new();
    let mut spans = Vec::new();
    let mut tool_calls = Vec::new();
    let mut seq_idx: i64 = 0;
    let mut line_count: i64 = 0;

    for line in raw.lines() {
        line_count += 1;
        if !line.starts_with('{') {
            continue;
        }
        let Ok(obj) = serde_json::from_str::<Value>(line) else {
            continue;
        };

        let ts = to_epoch_ms(obj.get("timestamp"));
        if let Some(t) = ts {
            started_at = Some(started_at.map_or(t, |cur| cur.min(t)));
            ended_at = Some(ended_at.map_or(t, |cur| cur.max(t)));
        }

        let ev_type = obj.get("type").and_then(Value::as_str).unwrap_or("");
        let payload = obj.get("payload").unwrap_or(&Value::Null);

        match ev_type {
            "session_meta" => {
                // Anchor session identity, originator, and role strictly on the FIRST session_meta event
                // so forked/embedded parent or guardian metadata later in the file never corrupts it.
                if !first_meta_seen {
                    first_meta_seen = true;
                    if let Some(sid) = payload
                        .get("id")
                        .or_else(|| payload.get("session_id"))
                        .and_then(Value::as_str)
                    {
                        session_id = sid.to_string();
                    }
                    if let Some(orig) = payload.get("originator").and_then(Value::as_str) {
                        originator = Some(orig.to_string());
                    }
                    if let Some(src) = payload.get("source") {
                        if let Some(sub) = src.as_object().and_then(|m| m.get("subagent")) {
                            is_subagent = true;
                            if let Some(other) = sub.get("other").and_then(Value::as_str) {
                                subagent_kind = Some(format!("subagent:{other}"));
                            } else {
                                subagent_kind = Some("subagent".to_string());
                            }
                        } else if src.as_str() == Some("subagent") {
                            is_subagent = true;
                            subagent_kind = Some("subagent".to_string());
                        } else {
                            subagent_kind = Some("main".to_string());
                        }
                    }
                }
                if cwd.is_none() {
                    if let Some(c) = payload.get("cwd").and_then(Value::as_str) {
                        cwd = Some(c.to_string());
                    } else if let Some(first_root) = payload
                        .get("runtime_workspace_roots")
                        .and_then(Value::as_array)
                        .and_then(|a| a.first())
                        .and_then(Value::as_str)
                    {
                        cwd = Some(first_root.to_string());
                    }
                }
                if let Some(mts) = to_epoch_ms(payload.get("timestamp")) {
                    started_at = Some(started_at.map_or(mts, |cur| cur.min(mts)));
                }
            }
            "turn_context" => {
                turn_count += 1;
                if let Some(c) = payload.get("cwd").and_then(Value::as_str) {
                    cwd = Some(c.to_string());
                }
                if model.is_none()
                    && let Some(m) = payload.get("model").and_then(Value::as_str)
                {
                    model = Some(m.to_string());
                }
            }
            "token_usage_record" => {
                // OpenAI/Codex `input_tokens` ALREADY includes `cached_input_tokens`; store uncached input in `input_tokens`
                // so `cache_hit_rate = cached / (input + cached)` is consistent across all harnesses.
                if let Some(u) = payload.get("thread_token_usage") {
                    let raw_in = u.get("input_tokens").and_then(Value::as_i64).unwrap_or(0);
                    let cached = u
                        .get("cached_input_tokens")
                        .and_then(Value::as_i64)
                        .unwrap_or(0);
                    let write = u
                        .get("cache_write_input_tokens")
                        .and_then(Value::as_i64)
                        .unwrap_or(0);
                    let uncached = (raw_in - cached).max(0) + write;
                    max_thread_in = max_thread_in.max(uncached);
                    max_thread_cached = max_thread_cached.max(cached);
                    max_thread_out = max_thread_out.max(
                        u.get("output_tokens").and_then(Value::as_i64).unwrap_or(0)
                            + u.get("reasoning_output_tokens")
                                .and_then(Value::as_i64)
                                .unwrap_or(0),
                    );
                } else if let Some(u) = payload.get("usage") {
                    let raw_in = u.get("input_tokens").and_then(Value::as_i64).unwrap_or(0);
                    let cached = u
                        .get("cached_input_tokens")
                        .and_then(Value::as_i64)
                        .unwrap_or(0);
                    let write = u
                        .get("cache_write_input_tokens")
                        .and_then(Value::as_i64)
                        .unwrap_or(0);
                    sum_in += (raw_in - cached).max(0) + write;
                    sum_cached += cached;
                    sum_out += u.get("output_tokens").and_then(Value::as_i64).unwrap_or(0)
                        + u.get("reasoning_output_tokens")
                            .and_then(Value::as_i64)
                            .unwrap_or(0);
                }
            }
            "event_msg" => {
                if !first_user_seen
                    && payload.get("type").and_then(Value::as_str) == Some("user_message")
                    && let Some(msg) = payload.get("message").and_then(Value::as_str)
                    && !msg.trim().is_empty()
                {
                    first_user_seen = true;
                    if detect_handoff_text(msg) {
                        is_handoff = true;
                    }
                }
                if payload.get("type").and_then(Value::as_str) == Some("token_count")
                    && let Some(u) = payload.get("info").and_then(|i| i.get("total_token_usage"))
                {
                    let raw_in = u.get("input_tokens").and_then(Value::as_i64).unwrap_or(0);
                    let cached = u
                        .get("cached_input_tokens")
                        .and_then(Value::as_i64)
                        .unwrap_or(0);
                    max_thread_in = max_thread_in.max((raw_in - cached).max(0));
                    max_thread_cached = max_thread_cached.max(cached);
                    max_thread_out = max_thread_out.max(
                        u.get("output_tokens").and_then(Value::as_i64).unwrap_or(0)
                            + u.get("reasoning_output_tokens")
                                .and_then(Value::as_i64)
                                .unwrap_or(0),
                    );
                }
            }
            "response_item" => {
                let ptype = payload.get("type").and_then(Value::as_str).unwrap_or("");
                if !first_user_seen
                    && ptype == "message"
                    && payload.get("role").and_then(Value::as_str) == Some("user")
                {
                    let txt = flatten_content(payload.get("content"));
                    if !txt.trim().is_empty() {
                        first_user_seen = true;
                        if detect_handoff_text(&txt) {
                            is_handoff = true;
                        }
                    }
                }
                if matches!(ptype, "function_call" | "custom_tool_call") {
                    if let Some(call_id) = payload.get("call_id").and_then(Value::as_str) {
                        let name = payload.get("name").and_then(Value::as_str).unwrap_or("");
                        let cmds = extract_codex_commands(
                            name,
                            payload.get("arguments"),
                            payload.get("input"),
                        );
                        let call_ts = ts
                            .or(started_at)
                            .unwrap_or_else(|| Utc::now().timestamp_millis());
                        if !cmds.is_empty() {
                            pending.insert(
                                call_id.to_string(),
                                PendingCall {
                                    cmds,
                                    turn_idx: turn_count.max(1),
                                    ts: call_ts,
                                    cwd: cwd.clone(),
                                },
                            );
                        } else if !name.is_empty() {
                            let resolved_tool = if name.eq_ignore_ascii_case("exec") {
                                payload
                                    .get("input")
                                    .or_else(|| payload.get("arguments"))
                                    .and_then(Value::as_str)
                                    .and_then(extract_js_tool_name)
                                    .unwrap_or_else(|| "codex:exec_js".to_string())
                            } else {
                                name.to_string()
                            };
                            pending_tools.insert(
                                call_id.to_string(),
                                PendingToolCall {
                                    tool_name: resolved_tool,
                                    turn_idx: turn_count.max(1),
                                    ts: call_ts,
                                    cwd: cwd.clone(),
                                },
                            );
                        }
                    }
                } else if matches!(ptype, "function_call_output" | "custom_tool_call_output")
                    && let Some(call_id) = payload.get("call_id").and_then(Value::as_str)
                {
                    if let Some(call) = pending.remove(call_id) {
                        let out_text = flatten_content(payload.get("output"));
                        let exit_code = extract_exit_code_from_text(&out_text, false);
                        let duration_ms = extract_duration_ms_from_text(&out_text)
                            .or_else(|| ts.and_then(|t| clamp_tool_duration(Some(t - call.ts))));
                        let full_sid = format!("codex:{session_id}");
                        let combined_cmd = call.cmds.join(" && ");
                        let built = build_command_spans(
                            SpanBuildArgs {
                                command_line: &combined_cmd,
                                session_id: Some(full_sid),
                                source_file: &source_file,
                                source_kind: "transcript",
                                agent_kind: "codex",
                                tool_call_id: Some(call_id.to_string()),
                                turn_idx: call.turn_idx,
                                base_seq_idx: seq_idx,
                                base_cwd: call.cwd.as_deref().or(cwd.as_deref()),
                                exit_code: Some(exit_code),
                                duration_ms,
                                stdout_text: &out_text,
                                stderr_text: if exit_code != 0 { &out_text } else { "" },
                                started_at: call.ts,
                            },
                            resolver,
                        );
                        seq_idx += built.len() as i64;
                        spans.extend(built);
                    } else if let Some(tcall) = pending_tools.remove(call_id) {
                        let out_text = flatten_content(payload.get("output"));
                        let is_error = detect_tool_error(&out_text, false);
                        let duration_ms = extract_duration_ms_from_text(&out_text)
                            .or_else(|| ts.and_then(|t| clamp_tool_duration(Some(t - tcall.ts))));
                        let ws = tcall
                            .cwd
                            .as_deref()
                            .or(cwd.as_deref())
                            .and_then(|c| resolver.resolve(c));
                        let (norm_name, is_mcp) = normalize_tool_name(&tcall.tool_name);
                        tool_calls.push(ToolCallRecord {
                            call_id: make_id("tc", &[&source_file, call_id]),
                            session_id: format!("codex:{session_id}"),
                            source_file: source_file.clone(),
                            agent_kind: "codex".to_string(),
                            repo_id: ws.as_ref().map(|w| w.repo_id.clone()),
                            repo_name: ws.as_ref().map(|w| w.repo_name.clone()),
                            turn_idx: tcall.turn_idx,
                            tool_name: norm_name,
                            is_mcp,
                            is_error,
                            duration_ms,
                            output_bytes: out_text.len() as i64,
                            output_tokens: estimate_tokens_str(&out_text),
                            is_truncated: detect_truncation(&out_text),
                            error_preview: extract_tool_error_preview(&out_text, is_error),
                            started_at: tcall.ts,
                        });
                    }
                }
            }
            _ => {}
        }
    }

    let full_sid = format!("codex:{session_id}");
    for (call_id, call) in pending {
        let combined_cmd = call.cmds.join(" && ");
        let built = build_command_spans(
            SpanBuildArgs {
                command_line: &combined_cmd,
                session_id: Some(full_sid.clone()),
                source_file: &source_file,
                source_kind: "transcript",
                agent_kind: "codex",
                tool_call_id: Some(call_id),
                turn_idx: call.turn_idx,
                base_seq_idx: seq_idx,
                base_cwd: call.cwd.as_deref().or(cwd.as_deref()),
                exit_code: None,
                duration_ms: None,
                stdout_text: "",
                stderr_text: "",
                started_at: call.ts,
            },
            resolver,
        );
        seq_idx += built.len() as i64;
        spans.extend(built);
    }

    if cwd.is_none() && spans.is_empty() && turn_count == 0 {
        return Ok(ParsedFile {
            line_count,
            ..Default::default()
        });
    }

    let ws = cwd.as_deref().and_then(|c| resolver.resolve(c));
    let mut final_repo = ws
        .as_ref()
        .map(|w| (w.repo_id.clone(), w.repo_name.clone()));
    if cwd.as_deref().is_some_and(is_neutral_home_dir)
        && let Some(dom) = dominant_span_repo(&spans)
    {
        final_repo = Some(dom);
    }

    let input_tokens = if max_thread_in > 0 {
        max_thread_in
    } else {
        sum_in
    };
    let output_tokens = if max_thread_out > 0 {
        max_thread_out
    } else {
        sum_out
    };
    let cached_tokens = if max_thread_cached > 0 {
        max_thread_cached
    } else {
        sum_cached
    };
    let total_tool_ms = spans.iter().filter_map(|s| s.duration_ms).sum();

    let session = SessionRecord {
        session_id: full_sid,
        agent_kind: "codex".to_string(),
        source_file,
        model,
        workspace_id: ws.as_ref().map(|w| w.workspace_id.clone()),
        repo_id: final_repo
            .as_ref()
            .map(|(id, _)| id.clone())
            .or_else(|| spans.first().and_then(|s| s.repo_id.clone())),
        repo_name: final_repo
            .as_ref()
            .map(|(_, name)| name.clone())
            .or_else(|| spans.first().and_then(|s| s.repo_name.clone())),
        cwd,
        git_branch: None,
        started_at,
        ended_at,
        turn_count: turn_count.max(if spans.is_empty() { 0 } else { 1 }),
        input_tokens,
        output_tokens,
        cached_tokens,
        cost_usd: None,
        total_tool_ms,
        is_subagent,
        originator,
        subagent_kind: subagent_kind
            .or_else(|| Some(if is_subagent { "subagent" } else { "main" }.to_string())),
        is_handoff,
    };

    Ok(ParsedFile {
        sessions: vec![session],
        spans,
        file_reads: Vec::new(),
        tool_calls,
        line_count,
    })
}
