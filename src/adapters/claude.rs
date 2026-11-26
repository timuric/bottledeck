use crate::adapters::{
    ParsedFile, SpanBuildArgs, build_command_spans, classify_tool_duration, detect_handoff_text,
    detect_tool_error, detect_truncation, dominant_span_repo, extract_tool_error_preview,
    flatten_content, is_doc_path, is_edit_tool, make_id, merge_intervals_ms, normalize_target_path,
    normalize_tool_name, to_epoch_ms, walk_files,
};
use crate::config::{default_context_window, estimate_tokens_str};
use crate::db::{FileReadRecord, LlmCallRecord, SessionRecord, ToolCallRecord};
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
    let mut parent_session_id: Option<String> = None;
    let mut cwd: Option<String> = None;
    let mut git_branch: Option<String> = None;
    let mut model: Option<String> = None;
    let mut effort: Option<String> = None;
    let mut turn_origin: Option<String> = None;
    let mut started_at: Option<i64> = None;
    let mut ended_at: Option<i64> = None;
    let mut turn_count: i64 = 0;
    let mut user_turn_count: i64 = 0;
    let mut input_tokens: i64 = 0;
    let mut output_tokens: i64 = 0;
    let mut cached_tokens: i64 = 0;
    let mut cache_write_tokens: i64 = 0;
    let mut thinking_tokens: i64 = 0;
    let mut cost_usd: Option<f64> = None;
    let mut total_tool_ms: i64 = 0;
    let mut api_duration_ms: i64 = 0;
    let mut api_retry_ms: i64 = 0;
    let mut thinking_duration_ms: i64 = 0;
    let mut compaction_count: i64 = 0;
    let mut aborted_turns: i64 = 0;
    let mut api_errors: i64 = 0;
    let mut lines_added: i64 = 0;
    let mut lines_removed: i64 = 0;
    let mut max_context_tokens: i64 = 0;
    let mut last_stop_reason: Option<String> = None;
    let mut is_subagent = is_subagent_path;
    let mut first_msg_seen = false;
    let mut first_user_seen = false;
    let mut originator: Option<String> = None;
    let mut is_handoff = false;

    let mut seen_msg_ids: HashSet<String> = HashSet::new();
    let mut pending_tools: HashMap<String, PendingTool> = HashMap::new();
    let mut tool_intervals: Vec<(i64, i64)> = Vec::new();
    let mut spans = Vec::new();
    let mut file_reads = Vec::new();
    let mut tool_calls = Vec::new();
    let mut llm_calls = Vec::new();
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

        // Never let a subagent file's parent `sessionId` overwrite its unique subagent file stem;
        // instead capture it as `parent_session_id` to build subagent trees.
        if let Some(sid) = obj.get("sessionId").and_then(Value::as_str) {
            if is_subagent_path {
                if parent_session_id.is_none() && sid != file_stem {
                    parent_session_id = Some(format!("claude:{sid}"));
                }
            } else {
                session_id = sid.to_string();
            }
        }
        if originator.is_none()
            && let Some(ep) = obj.get("entrypoint").and_then(Value::as_str)
        {
            originator = Some(ep.to_string());
        }
        if effort.is_none()
            && let Some(ef) = obj
                .get("effort")
                .or_else(|| obj.get("perTurnEffort"))
                .and_then(Value::as_str)
        {
            effort = Some(ef.to_string());
        }
        if turn_origin.is_none()
            && let Some(orig) = obj.get("turnOrigin").and_then(Value::as_str)
        {
            turn_origin = Some(orig.to_string());
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

        if ev_type == "system" {
            match obj.get("subtype").and_then(Value::as_str).unwrap_or("") {
                "compact_boundary" => {
                    compaction_count += 1;
                    is_handoff = true;
                }
                "api_error" => {
                    api_errors += 1;
                }
                _ => {}
            }
            continue;
        }

        if ev_type == "cost-state" {
            if let Some(c) = obj.get("totalCostUSD").and_then(Value::as_f64) {
                cost_usd = Some(c);
            }
            if let Some(ms) = obj.get("totalToolDuration").and_then(Value::as_f64) {
                total_tool_ms = ms.round() as i64;
            }
            if let Some(api_ms) = obj.get("totalAPIDuration").and_then(Value::as_f64) {
                let api_i = api_ms.round() as i64;
                api_duration_ms = api_duration_ms.max(api_i);
                if let Some(no_retry) = obj
                    .get("totalAPIDurationWithoutRetries")
                    .and_then(Value::as_f64)
                {
                    let retry = (api_i - no_retry.round() as i64).max(0);
                    api_retry_ms = api_retry_ms.max(retry);
                }
            }
            if let Some(la) = obj.get("totalLinesAdded").and_then(Value::as_i64) {
                lines_added = lines_added.max(la);
            }
            if let Some(lr) = obj.get("totalLinesRemoved").and_then(Value::as_i64) {
                lines_removed = lines_removed.max(lr);
            }
            if let Some(mu) = obj.get("modelUsage").and_then(Value::as_object) {
                let mut mu_thinking: i64 = 0;
                for m_obj in mu.values() {
                    mu_thinking += m_obj
                        .get("thinkingTokens")
                        .and_then(Value::as_i64)
                        .unwrap_or(0);
                }
                if mu_thinking > thinking_tokens {
                    thinking_tokens = mu_thinking;
                }
            }
            continue;
        }

        if ev_type == "user" {
            let content = obj.get("message").and_then(|m| m.get("content"));
            let is_tool_result_msg = content.and_then(Value::as_array).is_some_and(|arr| {
                arr.iter()
                    .any(|b| b.get("type").and_then(Value::as_str) == Some("tool_result"))
            });
            if !is_tool_result_msg {
                let txt = flatten_content(content);
                if !txt.trim().is_empty() {
                    user_turn_count += 1;
                    if !first_user_seen {
                        first_user_seen = true;
                        if detect_handoff_text(&txt) {
                            is_handoff = true;
                        }
                    }
                }
            }
        }

        if ev_type == "assistant"
            && let Some(msg) = obj.get("message")
        {
            let msg_model = msg
                .get("model")
                .and_then(Value::as_str)
                .or_else(|| obj.get("requestedModel").and_then(Value::as_str))
                .map(str::to_string);
            if model.is_none() {
                model = msg_model.clone();
            }

            let msg_id = msg
                .get("id")
                .and_then(Value::as_str)
                .or_else(|| obj.get("uuid").and_then(Value::as_str))
                .map(str::to_string);

            let think_ms = obj
                .get("thinkingDurationMs")
                .and_then(Value::as_f64)
                .map(|v| v.round() as i64)
                .filter(|&v| v >= 0);

            if let Some(id) = msg_id
                && seen_msg_ids.insert(id.clone())
            {
                turn_count += 1;
                if let Some(tm) = think_ms {
                    thinking_duration_ms += tm;
                }
                let stop_reason = msg
                    .get("stop_reason")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                if stop_reason.is_some() {
                    last_stop_reason = stop_reason.clone();
                }

                if let Some(u) = msg.get("usage") {
                    let uncached_in = u.get("input_tokens").and_then(Value::as_i64).unwrap_or(0);
                    let cache_create = u
                        .get("cache_creation_input_tokens")
                        .and_then(Value::as_i64)
                        .unwrap_or(0);
                    let cache_read = u
                        .get("cache_read_input_tokens")
                        .and_then(Value::as_i64)
                        .unwrap_or(0);
                    let out_tok = u.get("output_tokens").and_then(Value::as_i64).unwrap_or(0);
                    let think_tok = u
                        .get("output_tokens_details")
                        .and_then(|d| d.get("thinking_tokens"))
                        .and_then(Value::as_i64)
                        .unwrap_or(0);

                    input_tokens += uncached_in.max(0);
                    cache_write_tokens += cache_create.max(0);
                    cached_tokens += cache_read.max(0);
                    output_tokens += out_tok.max(0);
                    thinking_tokens += think_tok.max(0);

                    let ctx_toks = uncached_in + cache_create + cache_read;
                    max_context_tokens = max_context_tokens.max(ctx_toks);
                    let ctx_win = default_context_window(
                        msg_model.as_deref().or(model.as_deref()),
                        "claude-code",
                    );
                    let call_ws = cwd.as_deref().and_then(|c| resolver.resolve(c));
                    llm_calls.push(LlmCallRecord {
                        call_id: make_id("llm", &[&source_file, &id]),
                        session_id: format!("claude:{session_id}"),
                        source_file: source_file.clone(),
                        agent_kind: "claude-code".to_string(),
                        repo_id: call_ws.as_ref().map(|w| w.repo_id.clone()),
                        turn_idx: turn_count,
                        model: msg_model.or_else(|| model.clone()),
                        input_tokens: uncached_in.max(0),
                        cache_read_tokens: cache_read.max(0),
                        cache_write_tokens: cache_create.max(0),
                        output_tokens: out_tok.max(0),
                        thinking_tokens: think_tok.max(0),
                        duration_ms: None,
                        ttft_ms: None,
                        thinking_ms: think_ms,
                        stop_reason,
                        context_tokens: ctx_toks,
                        context_window: ctx_win,
                        started_at: ts
                            .or(started_at)
                            .unwrap_or_else(|| Utc::now().timestamp_millis()),
                    });
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
                let interrupted = tool_use_result
                    .and_then(|r| r.get("interrupted").and_then(Value::as_bool))
                    .unwrap_or(false)
                    || content_text.contains("[Request interrupted by user");
                if interrupted {
                    aborted_turns += 1;
                }

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

                    // Prefer model-visible content when `contentNotInModelContext` is set so token/truncation
                    // stats reflect what actually entered the model context window.
                    let not_in_ctx = tool_use_result
                        .and_then(|r| r.get("contentNotInModelContext").and_then(Value::as_bool))
                        .unwrap_or(false);
                    let stdout_text = if not_in_ctx {
                        content_text.as_str()
                    } else {
                        tool_use_result
                            .and_then(|r| r.get("stdout").and_then(Value::as_str))
                            .unwrap_or(&content_text)
                    };
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

                    let explicit_dur = tool_use_result
                        .and_then(|r| r.get("durationMs").and_then(Value::as_f64))
                        .map(|f| f.round() as i64)
                        .or_else(|| extract_duration_ms_from_text(&content_text));
                    let (duration_ms, is_explicit) = if let Some(d) = explicit_dur {
                        (Some(d), true)
                    } else {
                        (ts.map(|t| t - call.ts), false)
                    };
                    if let Some(d) = classify_tool_duration(duration_ms, is_explicit).0 {
                        tool_intervals.push((call.ts, call.ts + d));
                    }

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
                            is_explicit_duration: is_explicit,
                            interrupted,
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
                    let explicit_dur = tool_use_result
                        .and_then(|r| r.get("durationMs").and_then(Value::as_f64))
                        .map(|f| f.round() as i64);
                    let (dur_ms, _) = if let Some(d) = explicit_dur {
                        classify_tool_duration(Some(d), true)
                    } else {
                        classify_tool_duration(ts.map(|t| t - call.ts), false)
                    };
                    if let Some(d) = dur_ms {
                        tool_intervals.push((call.ts, call.ts + d));
                    }

                    let (norm_name, is_mcp) = normalize_tool_name(&call.name);
                    let is_edit = is_edit_tool(&call.name);
                    let raw_target = call
                        .input
                        .get("file_path")
                        .or_else(|| call.input.get("path"))
                        .or_else(|| call.input.get("Path"))
                        .or_else(|| tool_use_result.and_then(|r| r.get("filePath")))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let repo_root = ws.as_ref().map(|w| w.worktree_path.as_str());
                    let target_path_opt = if raw_target.is_empty() {
                        None
                    } else {
                        Some(normalize_target_path(raw_target, repo_root).1)
                    };

                    // Extract lines added/removed from structuredPatch if cost-state wasn't present
                    if is_edit
                        && let Some(patches) = tool_use_result
                            .and_then(|r| r.get("structuredPatch"))
                            .and_then(Value::as_array)
                    {
                        for hunk in patches {
                            if let Some(hlines) = hunk.get("lines").and_then(Value::as_array) {
                                for hl in hlines.iter().filter_map(Value::as_str) {
                                    if hl.starts_with('+') && !hl.starts_with("+++") {
                                        lines_added += 1;
                                    } else if hl.starts_with('-') && !hl.starts_with("---") {
                                        lines_removed += 1;
                                    }
                                }
                            }
                        }
                    }

                    let out_bytes = content_text.len() as i64;
                    let out_tokens = estimate_tokens_str(&content_text);
                    let tc_seq = seq_idx;
                    seq_idx += 1;

                    tool_calls.push(ToolCallRecord {
                        call_id: make_id("tc", &[&source_file, tu_id]),
                        session_id: full_sid.clone(),
                        source_file: source_file.clone(),
                        agent_kind: "claude-code".to_string(),
                        repo_id: ws.as_ref().map(|w| w.repo_id.clone()),
                        repo_name: ws.as_ref().map(|w| w.repo_name.clone()),
                        turn_idx: call.turn_idx,
                        seq_idx: tc_seq,
                        tool_call_id: Some(tu_id.to_string()),
                        tool_name: norm_name,
                        target_path: target_path_opt.clone(),
                        is_mcp,
                        is_edit,
                        is_error,
                        interrupted,
                        duration_ms: dur_ms,
                        output_bytes: out_bytes,
                        output_tokens: out_tokens,
                        is_truncated: detect_truncation(&content_text),
                        error_preview: extract_tool_error_preview(&content_text, is_error),
                        started_at: call.ts,
                    });

                    if matches!(tool_lower.as_str(), "read" | "read_file" | "view_file")
                        && !raw_target.is_empty()
                    {
                        let (target_name, rel_path) = normalize_target_path(raw_target, repo_root);
                        file_reads.push(FileReadRecord {
                            read_id: make_id("rd", &[&source_file, tu_id]),
                            session_id: full_sid.clone(),
                            source_file: source_file.clone(),
                            repo_id: ws.as_ref().map(|w| w.repo_id.clone()),
                            repo_name: ws.as_ref().map(|w| w.repo_name.clone()),
                            turn_idx: call.turn_idx,
                            target_name,
                            target_path: Some(rel_path),
                            is_doc: is_doc_path(raw_target),
                            output_tokens: out_tokens,
                            started_at: call.ts,
                        });
                    }
                }
            }
        }
    }

    let full_sid = format!("claude:{session_id}");
    // Flush unmatched pending calls deterministically sorted by (ts, id)
    let mut leftover: Vec<(String, PendingTool)> = pending_tools.into_iter().collect();
    leftover.sort_by(|a, b| a.1.ts.cmp(&b.1.ts).then_with(|| a.0.cmp(&b.0)));
    for (id, call) in leftover {
        let tool_lower = call.name.to_ascii_lowercase();
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
                    is_explicit_duration: false,
                    interrupted: true,
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
    let span_and_tool_ms: i64 = spans.iter().filter_map(|s| s.duration_ms).sum::<i64>()
        + tool_calls.iter().filter_map(|t| t.duration_ms).sum::<i64>();
    if total_tool_ms == 0 {
        total_tool_ms = span_and_tool_ms;
    }
    let merged_wall = merge_intervals_ms(&tool_intervals);
    let tool_wall_ms = if merged_wall > 0 {
        merged_wall
    } else {
        total_tool_ms
    };
    let context_window = default_context_window(model.as_deref(), "claude-code");
    let outcome = if api_errors > 0 && last_stop_reason.is_none() {
        Some("error".to_string())
    } else if aborted_turns > 0 && last_stop_reason.as_deref() != Some("end_turn") {
        Some("aborted".to_string())
    } else if last_stop_reason.as_deref() == Some("end_turn") || turn_count > 0 {
        Some("completed".to_string())
    } else {
        None
    };

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
        user_turn_count: user_turn_count.max(if turn_count > 0 { 1 } else { 0 }),
        input_tokens,
        output_tokens,
        cached_tokens,
        cache_write_tokens,
        thinking_tokens,
        cost_usd,
        total_tool_ms,
        tool_wall_ms,
        api_duration_ms,
        api_retry_ms,
        thinking_duration_ms,
        ttft_ms_sum: 0,
        ttft_count: 0,
        compaction_count,
        aborted_turns,
        api_errors,
        outcome,
        parent_session_id,
        lines_added,
        lines_removed,
        max_context_tokens,
        context_window,
        effort,
        turn_origin,
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
        llm_calls,
        line_count,
    })
}
