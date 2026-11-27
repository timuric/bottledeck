use crate::adapters::{
    ParsedFile, SpanBuildArgs, build_command_spans, classify_tool_duration, detect_handoff_text,
    detect_tool_error, detect_truncation, dominant_span_repo, extract_tool_error_preview,
    flatten_content, is_doc_path, is_edit_tool, make_id, merge_intervals_ms, normalize_target_path,
    normalize_tool_name, to_epoch_ms, walk_files,
};
use crate::config::{default_context_window, estimate_tokens_str};
use crate::db::{FileReadRecord, LlmCallRecord, SessionRecord, ToolCallRecord};
use crate::shell::extract_exit_code_from_text;
use crate::workspace::{WorkspaceResolver, is_ephemeral_or_neutral_path, is_neutral_home_dir};
use anyhow::Result;
use chrono::Utc;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

pub fn discover_files(root: &Path) -> Vec<PathBuf> {
    walk_files(root, 6, |_p, name| name == "wire.jsonl")
}

struct PendingCall {
    name: String,
    args: Value,
    started_at: Option<i64>,
    turn_idx: i64,
}

fn read_sibling_state(wire_path: &Path) -> Option<Value> {
    // Layout: <root>/<wd_dir>/<session_dir>/agents/<agent_id>/wire.jsonl
    let session_dir = wire_path.parent()?.parent()?.parent()?;
    let state_path = session_dir.join("state.json");
    let raw = fs::read_to_string(state_path).ok()?;
    serde_json::from_str(&raw).ok()
}

pub fn parse_file(file_path: &Path, resolver: &mut WorkspaceResolver<'_>) -> Result<ParsedFile> {
    let raw = fs::read_to_string(file_path)?;
    let source_file = file_path.to_string_lossy().to_string();

    let agent_id = file_path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("main")
        .to_string();
    let dir_session_id = file_path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();

    let state_json = read_sibling_state(file_path);
    let base_sid = state_json
        .as_ref()
        .and_then(|v| v.get("id"))
        .and_then(Value::as_str)
        .unwrap_or(&dir_session_id)
        .to_string();

    let is_subagent = agent_id != "main";
    let session_id = if is_subagent {
        format!("kimi:{base_sid}:{agent_id}")
    } else {
        format!("kimi:{base_sid}")
    };
    let parent_session_id = if is_subagent {
        Some(format!("kimi:{base_sid}"))
    } else {
        None
    };
    let subagent_kind = if is_subagent {
        Some(format!("subagent:{agent_id}"))
    } else {
        Some("main".to_string())
    };

    let mut cwd: Option<String> = state_json
        .as_ref()
        .and_then(|v| v.get("cwd"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let mut started_at: Option<i64> = state_json
        .as_ref()
        .and_then(|v| to_epoch_ms(v.get("createdAt")));
    let mut ended_at: Option<i64> = state_json
        .as_ref()
        .and_then(|v| to_epoch_ms(v.get("updatedAt")));
    let mut is_handoff = state_json
        .as_ref()
        .and_then(|v| v.get("lastPrompt"))
        .and_then(Value::as_str)
        .is_some_and(detect_handoff_text);

    let mut model: Option<String> = None;
    let mut effort: Option<String> = None;
    let mut seen_turns: HashSet<String> = HashSet::new();
    let mut step_count: i64 = 0;
    let mut has_usage_records = false;
    let mut ur_in: i64 = 0;
    let mut ur_out: i64 = 0;
    let mut ur_cached: i64 = 0;
    let mut ur_cache_write: i64 = 0;
    let mut se_in: i64 = 0;
    let mut se_out: i64 = 0;
    let mut se_cached: i64 = 0;
    let mut se_cache_write: i64 = 0;
    let mut tc_fallback_in: i64 = 0;
    let mut max_context_tokens: i64 = 0;
    let mut total_tool_ms: i64 = 0;
    let mut api_duration_ms: i64 = 0;
    let mut aborted_turns: i64 = 0;
    let mut api_errors: i64 = 0;
    let mut last_turn_outcome: Option<String> = None;
    let mut last_llm_req_ts: Option<i64> = None;
    let mut first_prompt_seen = false;
    let mut pending: HashMap<String, PendingCall> = HashMap::new();
    let mut tool_intervals: Vec<(i64, i64)> = Vec::new();
    let mut spans = Vec::new();
    let mut file_reads = Vec::new();
    let mut tool_calls = Vec::new();
    let mut llm_calls = Vec::new();
    let mut seq_idx: i64 = 0;
    let mut line_count: i64 = 0;

    let mut ws = cwd.as_deref().and_then(|c| resolver.resolve(c));

    for line in raw.lines() {
        line_count += 1;
        if !line.starts_with('{') {
            continue;
        }
        let Ok(obj) = serde_json::from_str::<Value>(line) else {
            continue;
        };

        let ts = to_epoch_ms(obj.get("time").or_else(|| obj.get("created_at")));
        if let Some(t) = ts {
            started_at = Some(started_at.map_or(t, |cur| cur.min(t)));
            ended_at = Some(ended_at.map_or(t, |cur| cur.max(t)));
        }

        let ev_type = obj.get("type").and_then(Value::as_str).unwrap_or("");
        match ev_type {
            "turn.prompt" => {
                if !first_prompt_seen {
                    first_prompt_seen = true;
                    let txt = flatten_content(obj.get("input"));
                    if detect_handoff_text(&txt) {
                        is_handoff = true;
                    }
                }
            }
            "llm.request" => {
                if model.is_none()
                    && let Some(m) = obj.get("model").and_then(Value::as_str)
                {
                    model = Some(m.to_string());
                }
                if effort.is_none()
                    && let Some(ef) = obj.get("thinkingEffort").and_then(Value::as_str)
                {
                    effort = Some(ef.to_string());
                }
                last_llm_req_ts = ts;
            }
            "turn.step.interrupted" => {
                aborted_turns += 1;
            }
            "token_counting.turn_recorded" => {
                if let Some(t) = obj.get("tokens").and_then(Value::as_i64)
                    && t > 0
                {
                    tc_fallback_in += t;
                    max_context_tokens = max_context_tokens.max(t);
                }
            }
            "turn.ended" => {
                let reason = obj.get("reason").and_then(Value::as_str).unwrap_or("");
                if !reason.is_empty() {
                    last_turn_outcome = Some(reason.to_string());
                }
                if reason == "failed" {
                    api_errors += 1;
                    let dur = obj
                        .get("durationMs")
                        .and_then(Value::as_i64)
                        .and_then(|d| classify_tool_duration(Some(d), true).0);
                    if let Some(d) = dur {
                        api_duration_ms += d;
                    }
                    let err_obj = obj.get("error");
                    let code = err_obj
                        .and_then(|e| e.get("code"))
                        .and_then(Value::as_str)
                        .unwrap_or("turn_failed");
                    let status = err_obj
                        .and_then(|e| e.get("details"))
                        .and_then(|d| d.get("statusCode"))
                        .and_then(Value::as_i64);
                    let msg = err_obj
                        .and_then(|e| e.get("message"))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let preview = match (status, msg.trim().is_empty()) {
                        (Some(sc), true) => format!("{code} (HTTP {sc})"),
                        (Some(sc), false) => format!("{code} (HTTP {sc}): {}", msg.trim()),
                        (None, true) => code.to_string(),
                        (None, false) => format!("{code}: {}", msg.trim()),
                    };
                    let turn_id_str = obj
                        .get("turnId")
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| seen_turns.len().to_string());
                    let event_ts = ts
                        .or(started_at)
                        .unwrap_or_else(|| Utc::now().timestamp_millis());
                    let tc_seq = seq_idx;
                    seq_idx += 1;
                    tool_calls.push(ToolCallRecord {
                        call_id: make_id(
                            "kimi-api",
                            &[&session_id, &turn_id_str, &line_count.to_string()],
                        ),
                        session_id: session_id.clone(),
                        agent_kind: "kimi".to_string(),
                        source_file: source_file.clone(),
                        repo_id: ws.as_ref().map(|w| w.repo_id.clone()),
                        repo_name: ws.as_ref().map(|w| w.repo_name.clone()),
                        turn_idx: step_count.max(1),
                        seq_idx: tc_seq,
                        tool_call_id: None,
                        tool_name: "kimi:api_error".to_string(),
                        target_path: None,
                        is_mcp: false,
                        is_edit: false,
                        is_error: true,
                        interrupted: false,
                        duration_ms: dur,
                        output_bytes: preview.len() as i64,
                        output_tokens: estimate_tokens_str(&preview),
                        is_truncated: false,
                        error_preview: Some(preview.chars().take(240).collect()),
                        started_at: event_ts,
                    });
                }
            }
            "usage.record" => {
                if model.is_none()
                    && let Some(m) = obj.get("model").and_then(Value::as_str)
                {
                    model = Some(m.to_string());
                }
                if let Some(u) = obj.get("usage") {
                    has_usage_records = true;
                    let uncached_in = u
                        .get("inputOther")
                        .and_then(Value::as_i64)
                        .unwrap_or(0)
                        .max(0);
                    let cache_create = u
                        .get("inputCacheCreation")
                        .and_then(Value::as_i64)
                        .unwrap_or(0)
                        .max(0);
                    let cache_read = u
                        .get("inputCacheRead")
                        .and_then(Value::as_i64)
                        .unwrap_or(0)
                        .max(0);
                    let out_t = u.get("output").and_then(Value::as_i64).unwrap_or(0).max(0);
                    ur_in += uncached_in;
                    ur_cache_write += cache_create;
                    ur_cached += cache_read;
                    ur_out += out_t;
                    let ctx_toks = uncached_in + cache_create + cache_read;
                    max_context_tokens = max_context_tokens.max(ctx_toks);
                    let req_dur = match (last_llm_req_ts.take(), ts) {
                        (Some(s), Some(e)) if e >= s && e - s <= 600_000 => Some(e - s),
                        _ => None,
                    };
                    if let Some(d) = req_dur {
                        api_duration_ms += d;
                    }
                    llm_calls.push(LlmCallRecord {
                        call_id: make_id("llm", &[&source_file, &line_count.to_string()]),
                        session_id: session_id.clone(),
                        source_file: source_file.clone(),
                        agent_kind: "kimi".to_string(),
                        repo_id: ws.as_ref().map(|w| w.repo_id.clone()),
                        turn_idx: step_count.max(1),
                        model: obj
                            .get("model")
                            .and_then(Value::as_str)
                            .map(str::to_string)
                            .or_else(|| model.clone()),
                        input_tokens: uncached_in,
                        cache_read_tokens: cache_read,
                        cache_write_tokens: cache_create,
                        output_tokens: out_t,
                        thinking_tokens: 0,
                        duration_ms: req_dur,
                        ttft_ms: None,
                        thinking_ms: None,
                        stop_reason: None,
                        context_tokens: ctx_toks,
                        context_window: default_context_window(model.as_deref(), "kimi"),
                        started_at: ts
                            .or(started_at)
                            .unwrap_or_else(|| Utc::now().timestamp_millis()),
                    });
                }
            }
            "context.append_loop_event" => {
                let Some(ev) = obj.get("event") else {
                    continue;
                };
                let inner = ev.get("type").and_then(Value::as_str).unwrap_or("");
                match inner {
                    "step.begin" => {
                        step_count += 1;
                        if let Some(tid) = ev.get("turnId").and_then(Value::as_str) {
                            seen_turns.insert(tid.to_string());
                        } else if let Some(tid) = ev.get("turnId").and_then(Value::as_i64) {
                            seen_turns.insert(tid.to_string());
                        }
                    }
                    "step.end" => {
                        if let Some(u) = ev.get("usage") {
                            let uncached_in = u
                                .get("inputOther")
                                .and_then(Value::as_i64)
                                .unwrap_or(0)
                                .max(0);
                            let cache_create = u
                                .get("inputCacheCreation")
                                .and_then(Value::as_i64)
                                .unwrap_or(0)
                                .max(0);
                            let cache_read = u
                                .get("inputCacheRead")
                                .and_then(Value::as_i64)
                                .unwrap_or(0)
                                .max(0);
                            let out_t = u.get("output").and_then(Value::as_i64).unwrap_or(0).max(0);
                            se_in += uncached_in;
                            se_cache_write += cache_create;
                            se_cached += cache_read;
                            se_out += out_t;
                            max_context_tokens =
                                max_context_tokens.max(uncached_in + cache_create + cache_read);
                        }
                    }
                    "tool.call" => {
                        let Some(cid) = ev.get("toolCallId").and_then(Value::as_str) else {
                            continue;
                        };
                        let name = ev
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown")
                            .to_string();
                        let args = ev.get("args").cloned().unwrap_or(Value::Null);
                        // Use step_count (step-normalized turn index) consistently with Claude/Codex/Antigravity
                        let turn_idx = step_count.max(seen_turns.len() as i64).max(1);
                        pending.insert(
                            cid.to_string(),
                            PendingCall {
                                name,
                                args,
                                started_at: ts,
                                turn_idx,
                            },
                        );
                    }
                    "tool.result" => {
                        let Some(cid) = ev.get("toolCallId").and_then(Value::as_str) else {
                            continue;
                        };
                        let Some(call) = pending.remove(cid) else {
                            continue;
                        };
                        let res = ev.get("result").unwrap_or(&Value::Null);
                        let out_text = if res.get("output").is_some() {
                            flatten_content(res.get("output"))
                        } else {
                            flatten_content(Some(res))
                        };
                        let (dur_ms, _) = match (call.started_at, ts) {
                            (Some(s), Some(e)) if e >= s => {
                                tool_intervals.push((s, e));
                                classify_tool_duration(Some(e - s), false)
                            }
                            _ => (None, false),
                        };
                        if let Some(d) = dur_ms {
                            total_tool_ms += d;
                        }
                        let explicit_err = res
                            .get("is_error")
                            .or_else(|| res.get("isError"))
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                            || res.get("error").is_some_and(|e| !e.is_null());
                        let event_ts = call
                            .started_at
                            .or(ts)
                            .or(started_at)
                            .unwrap_or_else(|| Utc::now().timestamp_millis());

                        let lower_name = call.name.to_ascii_lowercase();
                        if matches!(
                            lower_name.as_str(),
                            "bash" | "shell" | "exec" | "run_command"
                        ) {
                            let cmd_str = call
                                .args
                                .get("command")
                                .or_else(|| call.args.get("cmd"))
                                .and_then(Value::as_str)
                                .unwrap_or("");
                            if !cmd_str.trim().is_empty() {
                                let exit_code = res
                                    .get("exit_code")
                                    .or_else(|| res.get("exitCode"))
                                    .and_then(Value::as_i64)
                                    .unwrap_or_else(|| {
                                        extract_exit_code_from_text(&out_text, explicit_err)
                                    });
                                let mut built = build_command_spans(
                                    SpanBuildArgs {
                                        command_line: cmd_str,
                                        session_id: Some(session_id.clone()),
                                        source_file: &source_file,
                                        source_kind: "kimi",
                                        agent_kind: "kimi",
                                        tool_call_id: Some(cid.to_string()),
                                        turn_idx: call.turn_idx,
                                        base_seq_idx: seq_idx,
                                        base_cwd: cwd.as_deref(),
                                        exit_code: Some(exit_code),
                                        duration_ms: dur_ms,
                                        is_explicit_duration: false,
                                        interrupted: false,
                                        stdout_text: &out_text,
                                        stderr_text: if exit_code != 0 { &out_text } else { "" },
                                        started_at: event_ts,
                                    },
                                    resolver,
                                );
                                seq_idx += built.len() as i64;
                                spans.append(&mut built);
                            }
                        } else {
                            let target = call
                                .args
                                .get("path")
                                .or_else(|| call.args.get("file_path"))
                                .and_then(Value::as_str)
                                .unwrap_or("");
                            let r_ws = if !target.is_empty() {
                                if cwd.is_none()
                                    && let Some(parent) = Path::new(target).parent()
                                {
                                    let pstr = parent.to_string_lossy().to_string();
                                    cwd = Some(pstr.clone());
                                    ws = resolver.resolve(&pstr);
                                }
                                Path::new(target)
                                    .parent()
                                    .and_then(|p| resolver.resolve(&p.to_string_lossy()))
                                    .or_else(|| ws.clone())
                            } else {
                                ws.clone()
                            };
                            let repo_root = r_ws.as_ref().map(|w| w.worktree_path.as_str());
                            let (norm_name, is_mcp) = normalize_tool_name(&call.name);
                            let is_err = detect_tool_error(&out_text, explicit_err);
                            let err_preview = extract_tool_error_preview(&out_text, is_err);
                            let is_trunc = detect_truncation(&out_text);
                            let out_tokens = estimate_tokens_str(&out_text);
                            let norm_target = if target.is_empty() {
                                None
                            } else {
                                Some(normalize_target_path(target, repo_root).1)
                            };

                            // Record ALL non-shell tools (including read_file) in `tool_calls` for parity with Claude & Antigravity
                            let tc_seq = seq_idx;
                            seq_idx += 1;
                            tool_calls.push(ToolCallRecord {
                                call_id: make_id(
                                    "kimi-tc",
                                    &[&session_id, &call.turn_idx.to_string(), cid],
                                ),
                                session_id: session_id.clone(),
                                agent_kind: "kimi".to_string(),
                                source_file: source_file.clone(),
                                repo_id: r_ws.as_ref().map(|w| w.repo_id.clone()),
                                repo_name: r_ws.as_ref().map(|w| w.repo_name.clone()),
                                turn_idx: call.turn_idx,
                                seq_idx: tc_seq,
                                tool_call_id: Some(cid.to_string()),
                                tool_name: norm_name,
                                target_path: norm_target.clone(),
                                is_mcp,
                                is_edit: is_edit_tool(&call.name),
                                is_error: is_err,
                                interrupted: false,
                                duration_ms: dur_ms,
                                output_bytes: out_text.len() as i64,
                                output_tokens: out_tokens,
                                is_truncated: is_trunc,
                                error_preview: err_preview,
                                started_at: event_ts,
                            });

                            if matches!(lower_name.as_str(), "read" | "read_file" | "view_file")
                                && !target.is_empty()
                            {
                                let (target_name, rel_path) =
                                    normalize_target_path(target, repo_root);
                                file_reads.push(FileReadRecord {
                                    read_id: make_id(
                                        "kimi-rd",
                                        &[&session_id, &call.turn_idx.to_string(), cid],
                                    ),
                                    session_id: session_id.clone(),
                                    source_file: source_file.clone(),
                                    repo_id: r_ws.as_ref().map(|w| w.repo_id.clone()),
                                    repo_name: r_ws.as_ref().map(|w| w.repo_name.clone()),
                                    turn_idx: call.turn_idx,
                                    target_name,
                                    target_path: Some(rel_path),
                                    is_doc: is_doc_path(target),
                                    output_tokens: out_tokens,
                                    started_at: event_ts,
                                });
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    // Re-attribute neutral-home or ephemeral-workspace sessions to dominant concrete span repo if possible
    let final_ws_id = ws.as_ref().map(|w| w.workspace_id.clone());
    let mut final_repo_id = ws.as_ref().map(|w| w.repo_id.clone());
    let mut final_repo_name = ws.as_ref().map(|w| w.repo_name.clone());
    if (final_repo_id.is_none()
        || cwd
            .as_deref()
            .is_some_and(|c| is_neutral_home_dir(c) || is_ephemeral_or_neutral_path(c)))
        && let Some((r_id, r_name)) = dominant_span_repo(&spans)
    {
        final_repo_id = Some(r_id);
        final_repo_name = Some(r_name);
    }

    let (input_tokens, output_tokens, cached_tokens, cache_write_tokens) = if has_usage_records {
        (ur_in, ur_out, ur_cached, ur_cache_write)
    } else if se_in > 0 || se_out > 0 || se_cached > 0 || se_cache_write > 0 {
        (se_in, se_out, se_cached, se_cache_write)
    } else {
        (tc_fallback_in, 0, 0, 0)
    };
    let user_turn_count = seen_turns.len() as i64;
    let turn_count = step_count.max(user_turn_count);
    let merged_wall = merge_intervals_ms(&tool_intervals);
    let tool_wall_ms = if merged_wall > 0 {
        merged_wall
    } else {
        total_tool_ms
    };
    let outcome = match last_turn_outcome.as_deref() {
        Some("failed") => Some("error".to_string()),
        Some("cancelled" | "interrupted") => Some("aborted".to_string()),
        Some(_) => Some("completed".to_string()),
        None if api_errors > 0 => Some("error".to_string()),
        None if aborted_turns > 0 => Some("aborted".to_string()),
        None if turn_count > 0 => Some("completed".to_string()),
        None => None,
    };

    let mut sessions = Vec::new();
    if turn_count > 0
        || !spans.is_empty()
        || !tool_calls.is_empty()
        || !file_reads.is_empty()
        || input_tokens > 0
    {
        sessions.push(SessionRecord {
            session_id,
            agent_kind: "kimi".to_string(),
            originator: Some("kimi-code".to_string()),
            subagent_kind,
            is_handoff,
            harness_version: None,
            workspace_id: final_ws_id,
            repo_id: final_repo_id,
            repo_name: final_repo_name,
            cwd,
            git_branch: None,
            model: model.clone(),
            started_at,
            ended_at,
            turn_count,
            user_turn_count: user_turn_count.max(if turn_count > 0 { 1 } else { 0 }),
            input_tokens,
            output_tokens,
            cached_tokens,
            cache_write_tokens,
            thinking_tokens: 0,
            cost_usd: None,
            total_tool_ms,
            tool_wall_ms,
            api_duration_ms,
            api_retry_ms: 0,
            thinking_duration_ms: 0,
            ttft_ms_sum: 0,
            ttft_count: 0,
            compaction_count: 0,
            aborted_turns,
            api_errors,
            outcome,
            parent_session_id,
            lines_added: 0,
            lines_removed: 0,
            max_context_tokens,
            context_window: default_context_window(model.as_deref(), "kimi"),
            effort,
            turn_origin: None,
            is_subagent,
            source_file,
        });
    }

    Ok(ParsedFile {
        sessions,
        spans,
        file_reads,
        tool_calls,
        llm_calls,
        line_count,
    })
}
