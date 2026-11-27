use crate::adapters::{
    ParsedFile, SpanBuildArgs, build_command_spans, classify_tool_duration, detect_handoff_text,
    detect_tool_error, detect_truncation, dominant_span_repo, extract_shell_file_read_paths,
    extract_tool_error_preview, flatten_content, is_doc_path, is_edit_tool, make_id,
    merge_intervals_ms, normalize_target_path, normalize_tool_name, to_epoch_ms, walk_files,
};
use crate::config::{default_context_window, estimate_tokens_str};
use crate::db::{FileReadRecord, LlmCallRecord, SessionRecord, ToolCallRecord};
use crate::shell::{extract_duration_ms_from_text, extract_exit_code_from_text};
use crate::workspace::{WorkspaceResolver, is_ephemeral_or_neutral_path, is_neutral_home_dir};
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
    let mut escaped = false;
    for (rel_i, ch) in s[start_quote_idx + 1..].char_indices() {
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
            if let Some(q_rel) = after_colon.find(['"', '\'', '`']) {
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
    extra_tools: Vec<String>,
    turn_idx: i64,
    ts: i64,
    cwd: Option<String>,
}

struct PendingToolCall {
    tool_name: String,
    target_path: Option<String>,
    turn_idx: i64,
    ts: i64,
    cwd: Option<String>,
}

fn extract_patch_target_path(raw: &str) -> Option<String> {
    for line in raw.lines() {
        for prefix in [
            "*** Update File: ",
            "*** Add File: ",
            "*** Delete File: ",
            "+++ b/",
        ] {
            if let Some(rest) = line.trim().strip_prefix(prefix) {
                let p = rest.trim();
                if !p.is_empty() && p != "/dev/null" {
                    return Some(p.to_string());
                }
            }
        }
    }
    None
}

/// Extract all distinct non-shell `tools.<name>(` helper invocations from Codex JS exec blocks.
fn extract_all_js_tool_names(js: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut search_from = 0usize;
    while let Some(pos) = js[search_from..].find("tools.") {
        let abs = search_from + pos + 6;
        search_from = abs;
        let name: String = js[abs..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .collect();
        if !name.is_empty()
            && !matches!(name.as_str(), "exec_command" | "write_stdin")
            && !out.contains(&name)
        {
            out.push(name);
        }
    }
    out
}

/// Extract per-command Codex chunk JSON objects (`{"chunk_id":...,"exit_code":...,"output":...}`)
/// from an `exec` output string so shell spans do not inherit unrelated sibling MCP tool outputs.
fn extract_codex_exec_chunks(text: &str) -> Vec<(String, Option<i64>, Option<i64>)> {
    let mut chunks = Vec::new();
    let mut push_from_val = |v: &Value| {
        let obj = v.get("value").filter(|x| x.is_object()).unwrap_or(v);
        if obj.get("chunk_id").is_some()
            || (obj.get("exit_code").is_some() && obj.get("output").is_some())
        {
            let out = obj
                .get("output")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let ec = obj.get("exit_code").and_then(Value::as_i64);
            let dur = obj
                .get("wall_time_seconds")
                .and_then(Value::as_f64)
                .map(|s| (s * 1000.0).round() as i64);
            chunks.push((out, ec, dur));
        }
    };
    for line in text.lines() {
        let t = line.trim();
        if !(t.starts_with('{') || t.starts_with('[')) {
            continue;
        }
        if let Ok(val) = serde_json::from_str::<Value>(t) {
            if let Some(arr) = val.as_array() {
                for item in arr {
                    push_from_val(item);
                }
            } else {
                push_from_val(&val);
            }
        }
    }
    chunks
}

pub fn parse_file(file_path: &Path, resolver: &mut WorkspaceResolver<'_>) -> Result<ParsedFile> {
    let raw = fs::read_to_string(file_path)?;
    let source_file = file_path.to_string_lossy().to_string();

    let mut session_id = file_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();
    let mut parent_session_id: Option<String> = None;
    let mut cwd: Option<String> = None;
    let mut git_branch: Option<String> = None;
    let mut model: Option<String> = None;
    let mut effort: Option<String> = None;
    let mut started_at: Option<i64> = None;
    let mut ended_at: Option<i64> = None;
    let mut turn_count: i64 = 0;
    let mut step_turn_idx: i64 = 0;
    let mut saw_tool_output_since_step = false;
    let mut is_subagent = false;
    let mut originator: Option<String> = None;
    let mut harness_version: Option<String> = None;
    let mut subagent_kind: Option<String> = None;
    let mut is_handoff = false;
    let mut first_user_seen = false;
    let mut first_meta_seen = false;

    let mut max_thread_in: i64 = 0;
    let mut max_thread_out: i64 = 0;
    let mut max_thread_cached: i64 = 0;
    let mut max_thread_cache_write: i64 = 0;
    let mut max_thread_thinking: i64 = 0;
    let mut sum_in: i64 = 0;
    let mut sum_out: i64 = 0;
    let mut sum_cached: i64 = 0;
    let mut sum_cache_write: i64 = 0;
    let mut sum_thinking: i64 = 0;
    let mut api_duration_ms: i64 = 0;
    let mut ttft_ms_sum: i64 = 0;
    let mut ttft_count: i64 = 0;
    let mut compaction_count: i64 = 0;
    let mut aborted_turns: i64 = 0;
    let mut last_turn_aborted = false;
    let mut task_completes: i64 = 0;
    let mut lines_added: i64 = 0;
    let mut lines_removed: i64 = 0;
    let mut max_context_tokens: i64 = 0;
    let mut context_window: Option<i64> = None;

    // Exact per-call timing from Codex `event_msg.item_completed` keyed by item.id == call_id
    let mut item_timings: HashMap<String, (i64, i64)> = HashMap::new();
    let mut tool_intervals: Vec<(i64, i64)> = Vec::new();
    let mut pending: HashMap<String, PendingCall> = HashMap::new();
    let mut pending_tools: HashMap<String, PendingToolCall> = HashMap::new();
    let mut spans = Vec::new();
    let mut file_reads = Vec::new();
    let mut tool_calls = Vec::new();
    let mut llm_calls = Vec::new();
    let mut seq_idx: i64 = 0;
    let mut line_count: i64 = 0;

    // Pre-pass: collect exact `item_completed` timings keyed by `item.id` so forward/backward
    // ordering relative to `function_call_output` never loses exact durations.
    let mut parsed_lines: Vec<(i64, Value)> = Vec::new();
    for line in raw.lines() {
        line_count += 1;
        if !line.starts_with('{') {
            continue;
        }
        let Ok(obj) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if obj.get("type").and_then(Value::as_str) == Some("event_msg")
            && let Some(p) = obj.get("payload")
            && p.get("type").and_then(Value::as_str) == Some("item_completed")
            && let Some(it) = p.get("item")
            && let (Some(s_ms), Some(e_ms)) = (
                p.get("started_at_ms")
                    .or_else(|| it.get("started_at_ms"))
                    .and_then(Value::as_i64),
                p.get("completed_at_ms")
                    .or_else(|| it.get("completed_at_ms"))
                    .and_then(Value::as_i64),
            )
            && e_ms >= s_ms
            && let Some(id) = it.get("id").and_then(Value::as_str)
        {
            item_timings.insert(id.to_string(), (s_ms, e_ms));
        }
        parsed_lines.push((line_count, obj));
    }

    for (ln, obj) in parsed_lines {
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
                    let payload_id = payload.get("id").and_then(Value::as_str);
                    let payload_sid = payload.get("session_id").and_then(Value::as_str);
                    if let Some(sid) = payload_id.or(payload_sid) {
                        session_id = sid.to_string();
                    }
                    if let Some(pid) = payload
                        .get("parent_thread_id")
                        .and_then(Value::as_str)
                        .or_else(|| {
                            payload
                                .get("source")
                                .and_then(|s| s.get("subagent"))
                                .and_then(|sub| sub.get("thread_spawn"))
                                .and_then(|ts_obj| ts_obj.get("parent_thread_id"))
                                .and_then(Value::as_str)
                        })
                        .or_else(|| match (payload_id, payload_sid) {
                            (Some(id), Some(sid)) if id != sid => Some(sid),
                            _ => None,
                        })
                    {
                        parent_session_id = Some(format!("codex:{pid}"));
                    }
                    if let Some(orig) = payload.get("originator").and_then(Value::as_str) {
                        originator = Some(orig.to_string());
                    }
                    if let Some(v) = payload.get("cli_version").and_then(Value::as_str)
                        && !v.is_empty()
                    {
                        harness_version = Some(v.to_string());
                    }
                    if let Some(br) = payload
                        .get("git")
                        .and_then(|g| g.get("branch"))
                        .and_then(Value::as_str)
                    {
                        git_branch = Some(br.to_string());
                    }
                    if let Some(cw) = payload.get("model_context_window").and_then(Value::as_i64)
                        && cw > 0
                    {
                        context_window = Some(cw);
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
                step_turn_idx += 1;
                saw_tool_output_since_step = false;
                if let Some(c) = payload.get("cwd").and_then(Value::as_str) {
                    cwd = Some(c.to_string());
                }
                if model.is_none()
                    && let Some(m) = payload.get("model").and_then(Value::as_str)
                {
                    model = Some(m.to_string());
                }
                if effort.is_none()
                    && let Some(ef) = payload
                        .get("reasoning_effort")
                        .or_else(|| payload.get("effort"))
                        .and_then(Value::as_str)
                {
                    effort = Some(ef.to_string());
                }
            }
            "compacted" => {
                compaction_count += 1;
                is_handoff = true;
            }
            "token_usage_record" => {
                // OpenAI/Codex `input_tokens` ALREADY includes `cached_input_tokens`; store purely uncached input in `input_tokens`,
                // `cache_write_input_tokens` in `cache_write_tokens`, and `reasoning_output_tokens` in `thinking_tokens`.
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
                    let out_t = u.get("output_tokens").and_then(Value::as_i64).unwrap_or(0);
                    let reason_t = u
                        .get("reasoning_output_tokens")
                        .and_then(Value::as_i64)
                        .unwrap_or(0);
                    max_thread_in = max_thread_in.max((raw_in - cached).max(0));
                    max_thread_cached = max_thread_cached.max(cached.max(0));
                    max_thread_cache_write = max_thread_cache_write.max(write.max(0));
                    max_thread_out = max_thread_out.max(out_t.max(0));
                    max_thread_thinking = max_thread_thinking.max(reason_t.max(0));
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
                    let out_t = u.get("output_tokens").and_then(Value::as_i64).unwrap_or(0);
                    let reason_t = u
                        .get("reasoning_output_tokens")
                        .and_then(Value::as_i64)
                        .unwrap_or(0);
                    sum_in += (raw_in - cached).max(0);
                    sum_cached += cached.max(0);
                    sum_cache_write += write.max(0);
                    sum_out += out_t.max(0);
                    sum_thinking += reason_t.max(0);
                }
            }
            "event_msg" => {
                let etype = payload.get("type").and_then(Value::as_str).unwrap_or("");
                match etype {
                    "user_message" => {
                        if !first_user_seen
                            && let Some(msg) = payload.get("message").and_then(Value::as_str)
                            && !msg.trim().is_empty()
                        {
                            first_user_seen = true;
                            if detect_handoff_text(msg) {
                                is_handoff = true;
                            }
                        }
                    }
                    "task_complete" => {
                        task_completes += 1;
                        last_turn_aborted = false;
                        if let Some(d) = payload.get("duration_ms").and_then(Value::as_i64)
                            && d > 0
                        {
                            api_duration_ms += d;
                        }
                        if let Some(ttft) = payload
                            .get("time_to_first_token_ms")
                            .and_then(Value::as_i64)
                            && ttft > 0
                        {
                            ttft_ms_sum += ttft;
                            ttft_count += 1;
                        }
                    }
                    "turn_aborted" => {
                        aborted_turns += 1;
                        last_turn_aborted = true;
                    }
                    "context_compacted" => {
                        compaction_count += 1;
                        is_handoff = true;
                    }
                    "item_completed" => {
                        if let Some(item) = payload.get("item") {
                            let itype = item.get("type").and_then(Value::as_str).unwrap_or("");
                            match itype {
                                "ContextCompaction" => {
                                    compaction_count += 1;
                                    is_handoff = true;
                                }
                                "AgentMessage" => {
                                    if task_completes == 0
                                        && let (Some(s), Some(e)) = (
                                            payload.get("started_at_ms").and_then(Value::as_i64),
                                            payload.get("completed_at_ms").and_then(Value::as_i64),
                                        )
                                        && e > s
                                    {
                                        api_duration_ms += e - s;
                                    }
                                }
                                "FileChange" => {
                                    let ws = cwd.as_deref().and_then(|c| resolver.resolve(c));
                                    let repo_root = ws.as_ref().map(|w| w.worktree_path.as_str());
                                    let item_id =
                                        item.get("id").and_then(Value::as_str).unwrap_or("fc");
                                    let dur = match (
                                        payload.get("started_at_ms").and_then(Value::as_i64),
                                        payload.get("completed_at_ms").and_then(Value::as_i64),
                                    ) {
                                        (Some(s), Some(e)) if e >= s => Some(e - s),
                                        _ => None,
                                    };
                                    if let Some(changes) =
                                        item.get("changes").and_then(Value::as_array)
                                    {
                                        for (c_idx, ch) in changes.iter().enumerate() {
                                            if let Some(p) = ch.get("path").and_then(Value::as_str)
                                            {
                                                let (_, rel) = normalize_target_path(p, repo_root);
                                                if let Some(diff) =
                                                    ch.get("diff").and_then(Value::as_str)
                                                {
                                                    for dl in diff.lines() {
                                                        if dl.starts_with('+')
                                                            && !dl.starts_with("+++")
                                                        {
                                                            lines_added += 1;
                                                        } else if dl.starts_with('-')
                                                            && !dl.starts_with("---")
                                                        {
                                                            lines_removed += 1;
                                                        }
                                                    }
                                                }
                                                let tc_seq = seq_idx;
                                                seq_idx += 1;
                                                tool_calls.push(ToolCallRecord {
                                                    call_id: make_id(
                                                        "tc-fc",
                                                        &[
                                                            &source_file,
                                                            item_id,
                                                            &c_idx.to_string(),
                                                        ],
                                                    ),
                                                    session_id: format!("codex:{session_id}"),
                                                    source_file: source_file.clone(),
                                                    agent_kind: "codex".to_string(),
                                                    repo_id: ws.as_ref().map(|w| w.repo_id.clone()),
                                                    repo_name: ws
                                                        .as_ref()
                                                        .map(|w| w.repo_name.clone()),
                                                    turn_idx: step_turn_idx.max(1),
                                                    seq_idx: tc_seq,
                                                    tool_call_id: Some(item_id.to_string()),
                                                    tool_name: "FileChange".to_string(),
                                                    target_path: Some(rel),
                                                    is_mcp: false,
                                                    is_edit: true,
                                                    is_error: item
                                                        .get("status")
                                                        .and_then(Value::as_str)
                                                        == Some("failed"),
                                                    interrupted: false,
                                                    duration_ms: dur,
                                                    output_bytes: 0,
                                                    output_tokens: 0,
                                                    is_truncated: false,
                                                    error_preview: None,
                                                    started_at: payload
                                                        .get("started_at_ms")
                                                        .and_then(Value::as_i64)
                                                        .or(ts)
                                                        .unwrap_or_else(|| {
                                                            Utc::now().timestamp_millis()
                                                        }),
                                                });
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    "token_count" => {
                        if let Some(info) = payload.get("info") {
                            if let Some(cw) =
                                info.get("model_context_window").and_then(Value::as_i64)
                                && cw > 0
                            {
                                context_window = Some(cw);
                            }
                            if let Some(u) = info.get("total_token_usage") {
                                let raw_in =
                                    u.get("input_tokens").and_then(Value::as_i64).unwrap_or(0);
                                let cached = u
                                    .get("cached_input_tokens")
                                    .and_then(Value::as_i64)
                                    .unwrap_or(0);
                                let write = u
                                    .get("cache_write_input_tokens")
                                    .and_then(Value::as_i64)
                                    .unwrap_or(0);
                                let out_t =
                                    u.get("output_tokens").and_then(Value::as_i64).unwrap_or(0);
                                let reason_t = u
                                    .get("reasoning_output_tokens")
                                    .and_then(Value::as_i64)
                                    .unwrap_or(0);
                                max_thread_in = max_thread_in.max((raw_in - cached).max(0));
                                max_thread_cached = max_thread_cached.max(cached.max(0));
                                max_thread_cache_write = max_thread_cache_write.max(write.max(0));
                                max_thread_out = max_thread_out.max(out_t.max(0));
                                max_thread_thinking = max_thread_thinking.max(reason_t.max(0));
                            }
                            if let Some(lu) = info.get("last_token_usage") {
                                let raw_in =
                                    lu.get("input_tokens").and_then(Value::as_i64).unwrap_or(0);
                                let cached = lu
                                    .get("cached_input_tokens")
                                    .and_then(Value::as_i64)
                                    .unwrap_or(0);
                                let write = lu
                                    .get("cache_write_input_tokens")
                                    .and_then(Value::as_i64)
                                    .unwrap_or(0);
                                let out_t =
                                    lu.get("output_tokens").and_then(Value::as_i64).unwrap_or(0);
                                let reason_t = lu
                                    .get("reasoning_output_tokens")
                                    .and_then(Value::as_i64)
                                    .unwrap_or(0);
                                let ctx_toks = raw_in.max(cached) + write;
                                if ctx_toks > 0 || out_t > 0 {
                                    max_context_tokens = max_context_tokens.max(ctx_toks);
                                    let call_ws = cwd.as_deref().and_then(|c| resolver.resolve(c));
                                    llm_calls.push(LlmCallRecord {
                                        call_id: make_id("llm", &[&source_file, &ln.to_string()]),
                                        session_id: format!("codex:{session_id}"),
                                        source_file: source_file.clone(),
                                        agent_kind: "codex".to_string(),
                                        repo_id: call_ws.as_ref().map(|w| w.repo_id.clone()),
                                        turn_idx: step_turn_idx.max(1),
                                        model: model.clone(),
                                        input_tokens: (raw_in - cached).max(0),
                                        cache_read_tokens: cached.max(0),
                                        cache_write_tokens: write.max(0),
                                        output_tokens: out_t.max(0),
                                        thinking_tokens: reason_t.max(0),
                                        duration_ms: None,
                                        ttft_ms: None,
                                        thinking_ms: None,
                                        stop_reason: None,
                                        context_tokens: ctx_toks,
                                        context_window: context_window.or_else(|| {
                                            default_context_window(model.as_deref(), "codex")
                                        }),
                                        started_at: ts
                                            .or(started_at)
                                            .unwrap_or_else(|| Utc::now().timestamp_millis()),
                                    });
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            "response_item" => {
                let ptype = payload.get("type").and_then(Value::as_str).unwrap_or("");
                if ptype == "compaction" {
                    compaction_count += 1;
                    is_handoff = true;
                }
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
                    if step_turn_idx == 0 || saw_tool_output_since_step {
                        step_turn_idx += 1;
                        saw_tool_output_since_step = false;
                    }
                    let cur_turn = step_turn_idx.max(1);
                    if let Some(call_id) = payload.get("call_id").and_then(Value::as_str) {
                        let name = payload.get("name").and_then(Value::as_str).unwrap_or("");
                        let cmds = extract_codex_commands(
                            name,
                            payload.get("arguments"),
                            payload.get("input"),
                        );
                        let extra_tools = if name.eq_ignore_ascii_case("exec") {
                            payload
                                .get("input")
                                .or_else(|| payload.get("arguments"))
                                .and_then(Value::as_str)
                                .map(extract_all_js_tool_names)
                                .unwrap_or_default()
                        } else {
                            Vec::new()
                        };
                        let call_ts = ts
                            .or(started_at)
                            .unwrap_or_else(|| Utc::now().timestamp_millis());
                        if !cmds.is_empty() {
                            pending.insert(
                                call_id.to_string(),
                                PendingCall {
                                    cmds,
                                    extra_tools,
                                    turn_idx: cur_turn,
                                    ts: call_ts,
                                    cwd: cwd.clone(),
                                },
                            );
                        } else if !name.is_empty() {
                            let resolved_tool = if name.eq_ignore_ascii_case("exec") {
                                extra_tools
                                    .into_iter()
                                    .next()
                                    .unwrap_or_else(|| "codex:exec_js".to_string())
                            } else {
                                name.to_string()
                            };
                            let target_path = payload
                                .get("input")
                                .or_else(|| payload.get("arguments"))
                                .and_then(|v| {
                                    if let Some(s) = v.as_str() {
                                        if let Ok(obj) = serde_json::from_str::<Value>(s) {
                                            obj.get("file_path")
                                                .or_else(|| obj.get("path"))
                                                .and_then(Value::as_str)
                                                .map(str::to_string)
                                        } else {
                                            extract_patch_target_path(s)
                                        }
                                    } else {
                                        v.get("file_path")
                                            .or_else(|| v.get("path"))
                                            .and_then(Value::as_str)
                                            .map(str::to_string)
                                    }
                                });
                            pending_tools.insert(
                                call_id.to_string(),
                                PendingToolCall {
                                    tool_name: resolved_tool,
                                    target_path,
                                    turn_idx: cur_turn,
                                    ts: call_ts,
                                    cwd: cwd.clone(),
                                },
                            );
                        }
                    }
                } else if matches!(ptype, "function_call_output" | "custom_tool_call_output")
                    && let Some(call_id) = payload.get("call_id").and_then(Value::as_str)
                {
                    saw_tool_output_since_step = true;
                    let exact_timing = item_timings.get(call_id).copied();
                    if let Some(call) = pending.remove(call_id) {
                        let out_text = flatten_content(payload.get("output"));
                        let full_sid = format!("codex:{session_id}");
                        let call_cwd = call.cwd.as_deref().or(cwd.as_deref());

                        // Record any sibling non-shell tools called in the same Codex JS `exec` block
                        if !call.extra_tools.is_empty() {
                            let ws = call_cwd.and_then(|c| resolver.resolve(c));
                            for (et_idx, et_name) in call.extra_tools.iter().enumerate() {
                                let (norm_name, is_mcp) = normalize_tool_name(et_name);
                                let tc_seq = seq_idx;
                                seq_idx += 1;
                                tool_calls.push(ToolCallRecord {
                                    call_id: make_id(
                                        "tc",
                                        &[&source_file, call_id, &et_idx.to_string(), &norm_name],
                                    ),
                                    session_id: full_sid.clone(),
                                    source_file: source_file.clone(),
                                    agent_kind: "codex".to_string(),
                                    repo_id: ws.as_ref().map(|w| w.repo_id.clone()),
                                    repo_name: ws.as_ref().map(|w| w.repo_name.clone()),
                                    turn_idx: call.turn_idx,
                                    seq_idx: tc_seq,
                                    tool_call_id: Some(format!("{call_id}:js:{et_idx}")),
                                    tool_name: norm_name,
                                    target_path: None,
                                    is_mcp,
                                    is_edit: is_edit_tool(et_name),
                                    is_error: false,
                                    interrupted: false,
                                    duration_ms: None,
                                    output_bytes: 0,
                                    output_tokens: 0,
                                    is_truncated: false,
                                    error_preview: None,
                                    started_at: call.ts,
                                });
                            }
                        }

                        // When Codex JS `exec` returns structured per-command chunks, attribute each chunk
                        // to its own command so sibling MCP/JSON payloads do not contaminate shell spans.
                        let chunks = extract_codex_exec_chunks(&out_text);
                        let mut newly_built = Vec::new();
                        if !chunks.is_empty() && chunks.len() == call.cmds.len() {
                            for (c_idx, (cmd_str, (ch_out, ch_ec, ch_dur))) in
                                call.cmds.iter().zip(chunks).enumerate()
                            {
                                let ec = ch_ec
                                    .unwrap_or_else(|| extract_exit_code_from_text(&ch_out, false));
                                if let Some(d) = ch_dur {
                                    tool_intervals.push((call.ts, call.ts + d));
                                }
                                let built = build_command_spans(
                                    SpanBuildArgs {
                                        command_line: cmd_str,
                                        session_id: Some(full_sid.clone()),
                                        source_file: &source_file,
                                        source_kind: "transcript",
                                        agent_kind: "codex",
                                        tool_call_id: Some(format!("{call_id}:{c_idx}")),
                                        turn_idx: call.turn_idx,
                                        base_seq_idx: seq_idx,
                                        base_cwd: call_cwd,
                                        exit_code: Some(ec),
                                        duration_ms: ch_dur,
                                        is_explicit_duration: ch_dur.is_some(),
                                        interrupted: false,
                                        stdout_text: &ch_out,
                                        stderr_text: if ec != 0 { &ch_out } else { "" },
                                        started_at: call.ts,
                                    },
                                    resolver,
                                );
                                seq_idx += built.len() as i64;
                                newly_built.extend(built);
                            }
                        } else {
                            let (effective_out, effective_ec, effective_dur, is_explicit, start_t) =
                                if chunks.len() == 1 && !call.extra_tools.is_empty() {
                                    let (co, cec, cdur) = chunks.into_iter().next().unwrap();
                                    let ec = cec
                                        .unwrap_or_else(|| extract_exit_code_from_text(&co, false));
                                    (co, ec, cdur, cdur.is_some(), call.ts)
                                } else {
                                    let ec = extract_exit_code_from_text(&out_text, false);
                                    if let Some((s_ms, e_ms)) = exact_timing {
                                        (out_text, ec, Some(e_ms - s_ms), true, s_ms)
                                    } else if let Some(wd) =
                                        extract_duration_ms_from_text(&out_text)
                                    {
                                        (out_text, ec, Some(wd), true, call.ts)
                                    } else {
                                        (out_text, ec, ts.map(|t| t - call.ts), false, call.ts)
                                    }
                                };
                            if let Some(d) = classify_tool_duration(effective_dur, is_explicit).0 {
                                tool_intervals.push((start_t, start_t + d));
                            }
                            let combined_cmd = call.cmds.join(" && ");
                            let built = build_command_spans(
                                SpanBuildArgs {
                                    command_line: &combined_cmd,
                                    session_id: Some(full_sid.clone()),
                                    source_file: &source_file,
                                    source_kind: "transcript",
                                    agent_kind: "codex",
                                    tool_call_id: Some(call_id.to_string()),
                                    turn_idx: call.turn_idx,
                                    base_seq_idx: seq_idx,
                                    base_cwd: call_cwd,
                                    exit_code: Some(effective_ec),
                                    duration_ms: effective_dur,
                                    is_explicit_duration: is_explicit,
                                    interrupted: false,
                                    stdout_text: &effective_out,
                                    stderr_text: if effective_ec != 0 {
                                        &effective_out
                                    } else {
                                        ""
                                    },
                                    started_at: start_t,
                                },
                                resolver,
                            );
                            seq_idx += built.len() as i64;
                            newly_built.extend(built);
                        }

                        // Populate `file_reads` from Codex shell file-reading commands (`sed`, `cat`, `head`, `tail`, `nl`)
                        for sp in &newly_built {
                            let paths =
                                extract_shell_file_read_paths(&sp.raw_redacted, &sp.cmd_bin);
                            if !paths.is_empty() {
                                let per_tok = sp.stdout_tokens / (paths.len() as i64).max(1);
                                for (p_idx, target) in paths.iter().enumerate() {
                                    let (target_name, rel_path) =
                                        normalize_target_path(target, call_cwd);
                                    file_reads.push(FileReadRecord {
                                        read_id: make_id(
                                            "rd",
                                            &[&source_file, &sp.span_id, &p_idx.to_string()],
                                        ),
                                        session_id: full_sid.clone(),
                                        source_file: source_file.clone(),
                                        repo_id: sp.repo_id.clone(),
                                        repo_name: sp.repo_name.clone(),
                                        turn_idx: sp.turn_idx,
                                        target_name,
                                        target_path: Some(rel_path),
                                        is_doc: is_doc_path(target),
                                        output_tokens: per_tok,
                                        started_at: sp.started_at,
                                    });
                                }
                            }
                        }
                        spans.extend(newly_built);
                    } else if let Some(tcall) = pending_tools.remove(call_id) {
                        let out_text = flatten_content(payload.get("output"));
                        let is_error = detect_tool_error(&out_text, false);
                        let (duration_ms, start_t) = if let Some((s_ms, e_ms)) = exact_timing {
                            (classify_tool_duration(Some(e_ms - s_ms), true).0, s_ms)
                        } else if let Some(wd) = extract_duration_ms_from_text(&out_text) {
                            (classify_tool_duration(Some(wd), true).0, tcall.ts)
                        } else {
                            (
                                classify_tool_duration(ts.map(|t| t - tcall.ts), false).0,
                                tcall.ts,
                            )
                        };
                        if let Some(d) = duration_ms {
                            tool_intervals.push((start_t, start_t + d));
                        }
                        let ws = tcall
                            .cwd
                            .as_deref()
                            .or(cwd.as_deref())
                            .and_then(|c| resolver.resolve(c));
                        let repo_root = ws.as_ref().map(|w| w.worktree_path.as_str());
                        let norm_target = tcall
                            .target_path
                            .as_deref()
                            .map(|p| normalize_target_path(p, repo_root).1);
                        let (norm_name, is_mcp) = normalize_tool_name(&tcall.tool_name);
                        let tc_seq = seq_idx;
                        seq_idx += 1;
                        tool_calls.push(ToolCallRecord {
                            call_id: make_id("tc", &[&source_file, call_id]),
                            session_id: format!("codex:{session_id}"),
                            source_file: source_file.clone(),
                            agent_kind: "codex".to_string(),
                            repo_id: ws.as_ref().map(|w| w.repo_id.clone()),
                            repo_name: ws.as_ref().map(|w| w.repo_name.clone()),
                            turn_idx: tcall.turn_idx,
                            seq_idx: tc_seq,
                            tool_call_id: Some(call_id.to_string()),
                            tool_name: norm_name,
                            target_path: norm_target,
                            is_mcp,
                            is_edit: is_edit_tool(&tcall.tool_name),
                            is_error,
                            interrupted: false,
                            duration_ms,
                            output_bytes: out_text.len() as i64,
                            output_tokens: estimate_tokens_str(&out_text),
                            is_truncated: detect_truncation(&out_text),
                            error_preview: extract_tool_error_preview(&out_text, is_error),
                            started_at: start_t,
                        });
                    }
                }
            }
            _ => {}
        }
    }

    let full_sid = format!("codex:{session_id}");
    // Deterministic flush of unmatched pending calls sorted by (ts, call_id)
    let mut leftover: Vec<(String, PendingCall)> = pending.into_iter().collect();
    leftover.sort_by(|a, b| a.1.ts.cmp(&b.1.ts).then_with(|| a.0.cmp(&b.0)));
    for (call_id, call) in leftover {
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
    if cwd
        .as_deref()
        .is_some_and(|c| is_neutral_home_dir(c) || is_ephemeral_or_neutral_path(c))
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
    let cache_write_tokens = if max_thread_cache_write > 0 {
        max_thread_cache_write
    } else {
        sum_cache_write
    };
    let thinking_tokens = if max_thread_thinking > 0 {
        max_thread_thinking
    } else {
        sum_thinking
    };
    let total_tool_ms: i64 = spans.iter().filter_map(|s| s.duration_ms).sum::<i64>()
        + tool_calls.iter().filter_map(|t| t.duration_ms).sum::<i64>();
    let merged_wall = merge_intervals_ms(&tool_intervals);
    let tool_wall_ms = if merged_wall > 0 {
        merged_wall
    } else {
        total_tool_ms
    };
    let normalized_turns = step_turn_idx
        .max(turn_count)
        .max(if spans.is_empty() { 0 } else { 1 });
    let outcome = if last_turn_aborted || (aborted_turns > 0 && task_completes == 0) {
        Some("aborted".to_string())
    } else if task_completes > 0 || normalized_turns > 0 {
        Some("completed".to_string())
    } else {
        None
    };

    let session = SessionRecord {
        session_id: full_sid,
        agent_kind: "codex".to_string(),
        source_file,
        model: model.clone(),
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
        turn_count: normalized_turns,
        user_turn_count: turn_count.max(if normalized_turns > 0 { 1 } else { 0 }),
        input_tokens,
        output_tokens,
        cached_tokens,
        cache_write_tokens,
        thinking_tokens,
        cost_usd: None,
        total_tool_ms,
        tool_wall_ms,
        api_duration_ms,
        api_retry_ms: 0,
        thinking_duration_ms: 0,
        ttft_ms_sum,
        ttft_count,
        compaction_count,
        aborted_turns,
        api_errors: 0,
        outcome,
        parent_session_id,
        lines_added,
        lines_removed,
        max_context_tokens,
        context_window: context_window
            .or_else(|| default_context_window(model.as_deref(), "codex")),
        effort,
        turn_origin: None,
        is_subagent,
        originator,
        subagent_kind: subagent_kind
            .or_else(|| Some(if is_subagent { "subagent" } else { "main" }.to_string())),
        is_handoff,
        harness_version,
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
