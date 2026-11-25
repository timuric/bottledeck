use crate::adapters::{
    ParsedFile, SpanBuildArgs, build_command_spans, clamp_tool_duration, detect_handoff_text,
    detect_tool_error, detect_truncation, dominant_span_repo, extract_tool_error_preview,
    flatten_content, is_doc_path, make_id, normalize_tool_name, to_epoch_ms, walk_files,
};
use crate::config::estimate_tokens_str;
use crate::db::{FileReadRecord, SessionRecord, ToolCallRecord};
use crate::shell::{extract_duration_ms_from_text, extract_exit_code_from_text};
use crate::workspace::{WorkspaceResolver, is_neutral_home_dir};
use anyhow::Result;
use chrono::Utc;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

pub fn discover_files(root: &Path) -> Vec<PathBuf> {
    walk_files(root, 5, |_p, name| name.ends_with(".jsonl"))
}

struct PendingTool {
    name: String,
    input: Value,
    turn_idx: i64,
    ts: i64,
    cwd: Option<String>,
}

pub fn parse_file(file_path: &Path, resolver: &mut WorkspaceResolver<'_>) -> Result<ParsedFile> {
    let raw = fs::read_to_string(file_path)?;
    let source_file = file_path.to_string_lossy().to_string();

    let file_stem = file_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();
    let is_subagent_path = source_file.contains("/subagents/");
    let mut session_id = file_stem.clone();
    let mut cwd: Option<String> = None;
    let mut git_branch: Option<String> = None;
    let mut model: Option<String> = None;
    let mut started_at: Option<i64> = None;
    let mut ended_at: Option<i64> = None;
    let mut turn_count: i64 = 0;
    let mut input_tokens: i64 = 0;
    let mut output_tokens: i64 = 0;
    let mut cached_tokens: i64 = 0;
    let mut cost_usd: Option<f64> = None;
    let mut total_tool_ms: i64 = 0;
    let mut is_subagent = is_subagent_path;
    let mut first_msg_seen = false;
    let mut first_user_seen = false;
    let mut originator: Option<String> = None;
    let mut is_handoff = false;

    let mut seen_msg_ids: HashSet<String> = HashSet::new();
    let mut pending_tools: HashMap<String, PendingTool> = HashMap::new();
    let mut spans = Vec::new();
    let mut file_reads = Vec::new();
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

        // Never let a subagent file's parent `sessionId` overwrite its unique subagent file stem
        if !is_subagent_path && let Some(sid) = obj.get("sessionId").and_then(Value::as_str) {
            session_id = sid.to_string();
        }
        if originator.is_none()
            && let Some(ep) = obj.get("entrypoint").and_then(Value::as_str)
        {
            originator = Some(ep.to_string());
        }
        if let Some(c) = obj.get("cwd").and_then(Value::as_str) {
            cwd = Some(c.to_string());
        }
        if let Some(b) = obj.get("gitBranch").and_then(Value::as_str) {
            git_branch = Some(b.to_string());
        }

        let ts = to_epoch_ms(obj.get("timestamp"));
        if let Some(t) = ts {
            started_at = Some(started_at.map_or(t, |cur| cur.min(t)));
            ended_at = Some(ended_at.map_or(t, |cur| cur.max(t)));
        }

        let ev_type = obj.get("type").and_then(Value::as_str).unwrap_or("");
        if !first_msg_seen && matches!(ev_type, "user" | "assistant") {
            first_msg_seen = true;
            if obj.get("isSidechain").and_then(Value::as_bool) == Some(true) {
                is_subagent = true;
            }
        }
        if !first_user_seen && ev_type == "user" {
            let txt = flatten_content(obj.get("message").and_then(|m| m.get("content")));
            if !txt.trim().is_empty() {
                first_user_seen = true;
                if detect_handoff_text(&txt) {
                    is_handoff = true;
                }
            }
        }

        if ev_type == "cost-state" {
            if let Some(c) = obj.get("totalCostUSD").and_then(Value::as_f64) {
                cost_usd = Some(c);
            }
            if let Some(ms) = obj.get("totalToolDuration").and_then(Value::as_f64) {
                total_tool_ms = ms.round() as i64;
            }
            continue;
        }

        if ev_type == "assistant"
            && let Some(msg) = obj.get("message")
        {
            if model.is_none()
                && let Some(m) = msg.get("model").and_then(Value::as_str)
            {
                model = Some(m.to_string());
            }

            let msg_id = msg
                .get("id")
                .and_then(Value::as_str)
                .or_else(|| obj.get("uuid").and_then(Value::as_str))
                .map(str::to_string);

            if let Some(id) = msg_id
                && seen_msg_ids.insert(id)
            {
                turn_count += 1;
                if let Some(u) = msg.get("usage") {
                    input_tokens += u.get("input_tokens").and_then(Value::as_i64).unwrap_or(0)
                        + u.get("cache_creation_input_tokens")
                            .and_then(Value::as_i64)
                            .unwrap_or(0);
                    cached_tokens += u
                        .get("cache_read_input_tokens")
                        .and_then(Value::as_i64)
                        .unwrap_or(0);
                    output_tokens += u.get("output_tokens").and_then(Value::as_i64).unwrap_or(0);
                }
            }

            if let Some(blocks) = msg.get("content").and_then(Value::as_array) {
                for b in blocks {
                    if b.get("type").and_then(Value::as_str) == Some("tool_use")
                        && let Some(id) = b.get("id").and_then(Value::as_str)
                    {
                        pending_tools.insert(
                            id.to_string(),
                            PendingTool {
                                name: b
                                    .get("name")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string(),
                                input: b.get("input").cloned().unwrap_or(Value::Null),
                                turn_idx: turn_count,
                                ts: ts
                                    .or(started_at)
                                    .unwrap_or_else(|| Utc::now().timestamp_millis()),
                                cwd: obj
                                    .get("cwd")
                                    .and_then(Value::as_str)
                                    .map(str::to_string)
                                    .or_else(|| cwd.clone()),
                            },
                        );
                    }
                }
            }
            continue;
        }

        if ev_type == "user"
            && let Some(blocks) = obj
                .get("message")
                .and_then(|m| m.get("content"))
                .and_then(Value::as_array)
        {
            let tool_use_result = obj.get("toolUseResult").filter(|v| v.is_object());
            let full_sid = format!("claude:{session_id}");

            for b in blocks {
                if b.get("type").and_then(Value::as_str) != Some("tool_result") {
                    continue;
                }
                let Some(tu_id) = b.get("tool_use_id").and_then(Value::as_str) else {
                    continue;
                };
                let Some(call) = pending_tools.remove(tu_id) else {
                    continue;
                };

                let content_text = flatten_content(b.get("content"));
                let tool_lower = call.name.to_ascii_lowercase();
                let call_cwd = call.cwd.as_deref().or(cwd.as_deref());

                if matches!(tool_lower.as_str(), "bash" | "shell" | "run_command") {
                    let cmd = call
                        .input
                        .get("command")
                        .and_then(Value::as_str)
                        .or_else(|| call.input.get("cmd").and_then(Value::as_str))
                        .unwrap_or("");
                    if cmd.is_empty() {
                        continue;
                    }

                    let stdout_text = tool_use_result
                        .and_then(|r| r.get("stdout").and_then(Value::as_str))
                        .unwrap_or(&content_text);
                    let is_err = b.get("is_error").and_then(Value::as_bool).unwrap_or(false);
                    let stderr_text = tool_use_result
                        .and_then(|r| r.get("stderr").and_then(Value::as_str))
                        .unwrap_or(if is_err { &content_text } else { "" });

                    let exit_code = tool_use_result
                        .and_then(|r| {
                            r.get("exitCode")
                                .and_then(Value::as_i64)
                                .or_else(|| r.get("code").and_then(Value::as_i64))
                        })
                        .unwrap_or_else(|| extract_exit_code_from_text(&content_text, is_err));

                    let duration_ms = tool_use_result
                        .and_then(|r| r.get("durationMs").and_then(Value::as_f64))
                        .map(|f| f.round() as i64)
                        .or_else(|| extract_duration_ms_from_text(&content_text))
                        .or_else(|| ts.and_then(|t| clamp_tool_duration(Some(t - call.ts))));

                    let built = build_command_spans(
                        SpanBuildArgs {
                            command_line: cmd,
                            session_id: Some(full_sid.clone()),
                            source_file: &source_file,
                            source_kind: "transcript",
                            agent_kind: "claude-code",
                            tool_call_id: Some(tu_id.to_string()),
                            turn_idx: call.turn_idx,
                            base_seq_idx: seq_idx,
                            base_cwd: call_cwd,
                            exit_code: Some(exit_code),
                            duration_ms,
                            stdout_text,
                            stderr_text,
                            started_at: call.ts,
                        },
                        resolver,
                    );
                    seq_idx += built.len() as i64;
                    spans.extend(built);
                } else {
                    let ws = call_cwd.and_then(|c| resolver.resolve(c));
                    let explicit_err = b.get("is_error").and_then(Value::as_bool).unwrap_or(false);
                    let is_error = detect_tool_error(&content_text, explicit_err);
                    let dur_ms = tool_use_result
                        .and_then(|r| r.get("durationMs").and_then(Value::as_f64))
                        .map(|f| f.round() as i64)
                        .or_else(|| ts.and_then(|t| clamp_tool_duration(Some(t - call.ts))));
                    let (norm_name, is_mcp) = normalize_tool_name(&call.name);
                    let out_bytes = content_text.len() as i64;
                    let out_tokens = estimate_tokens_str(&content_text);

                    tool_calls.push(ToolCallRecord {
                        call_id: make_id("tc", &[&source_file, tu_id]),
                        session_id: full_sid.clone(),
                        source_file: source_file.clone(),
                        agent_kind: "claude-code".to_string(),
                        repo_id: ws.as_ref().map(|w| w.repo_id.clone()),
                        repo_name: ws.as_ref().map(|w| w.repo_name.clone()),
                        turn_idx: call.turn_idx,
                        tool_name: norm_name,
                        is_mcp,
                        is_error,
                        duration_ms: dur_ms,
                        output_bytes: out_bytes,
                        output_tokens: out_tokens,
                        is_truncated: detect_truncation(&content_text),
                        error_preview: extract_tool_error_preview(&content_text, is_error),
                        started_at: call.ts,
                    });

                    if matches!(tool_lower.as_str(), "read" | "read_file" | "view_file") {
                        let target = call
                            .input
                            .get("file_path")
                            .or_else(|| call.input.get("path"))
                            .or_else(|| call.input.get("Path"))
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        if !target.is_empty() {
                            let target_name = Path::new(target)
                                .file_name()
                                .and_then(|s| s.to_str())
                                .unwrap_or(target)
                                .to_string();
                            file_reads.push(FileReadRecord {
                                read_id: make_id("rd", &[&source_file, tu_id]),
                                session_id: full_sid.clone(),
                                source_file: source_file.clone(),
                                repo_id: ws.as_ref().map(|w| w.repo_id.clone()),
                                repo_name: ws.as_ref().map(|w| w.repo_name.clone()),
                                turn_idx: call.turn_idx,
                                target_name,
                                is_doc: is_doc_path(target),
                                output_tokens: out_tokens,
                                started_at: call.ts,
                            });
                        }
                    }
                }
            }
        }
    }

    let full_sid = format!("claude:{session_id}");
    for (id, call) in pending_tools {
        let tool_lower = call.name.to_ascii_lowercase();
        if matches!(tool_lower.as_str(), "bash" | "shell") {
            let cmd = call
                .input
                .get("command")
                .and_then(Value::as_str)
                .or_else(|| call.input.get("cmd").and_then(Value::as_str))
                .unwrap_or("");
            if cmd.is_empty() {
                continue;
            }
            let built = build_command_spans(
                SpanBuildArgs {
                    command_line: cmd,
                    session_id: Some(full_sid.clone()),
                    source_file: &source_file,
                    source_kind: "transcript",
                    agent_kind: "claude-code",
                    tool_call_id: Some(id),
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
    if total_tool_ms == 0 {
        total_tool_ms = spans.iter().filter_map(|s| s.duration_ms).sum();
    }

    let session = SessionRecord {
        session_id: full_sid,
        agent_kind: "claude-code".to_string(),
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
        git_branch,
        started_at,
        ended_at,
        turn_count,
        input_tokens,
        output_tokens,
        cached_tokens,
        cost_usd,
        total_tool_ms,
        is_subagent,
        originator,
        subagent_kind: Some(if is_subagent { "subagent" } else { "main" }.to_string()),
        is_handoff,
    };

    Ok(ParsedFile {
        sessions: vec![session],
        spans,
        file_reads,
        tool_calls,
        line_count,
    })
}
