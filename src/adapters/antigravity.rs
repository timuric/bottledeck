use crate::adapters::{
    ParsedFile, SpanBuildArgs, build_command_spans, detect_handoff_text, detect_tool_error,
    detect_truncation, dominant_span_repo, extract_tool_error_preview, is_doc_path, make_id,
    normalize_tool_name, to_epoch_ms, walk_files,
};
use crate::config::estimate_tokens_str;
use crate::db::{FileReadRecord, SessionRecord, ToolCallRecord};
use crate::shell::{extract_duration_ms_from_text, extract_exit_code_from_text};
use crate::workspace::WorkspaceResolver;
use anyhow::Result;
use chrono::Utc;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub fn discover_files(root: &Path) -> Vec<PathBuf> {
    let found = walk_files(root, 10, |_p, name| {
        name == "transcript_full.jsonl" || name == "transcript.jsonl"
    });
    // Prefer `transcript_full.jsonl` over compact `transcript.jsonl` in the same logs directory
    // so we avoid 4KB compact-log truncation artifacts and double-quoted args.
    let mut by_dir: HashMap<PathBuf, PathBuf> = HashMap::new();
    for path in found {
        let is_full = path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|n| n == "transcript_full.jsonl");
        let dir = path.parent().unwrap_or(Path::new("")).to_path_buf();
        match by_dir.get(&dir) {
            Some(existing)
                if existing
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|n| n == "transcript_full.jsonl") => {}
            _ => {
                if is_full || !by_dir.contains_key(&dir) {
                    by_dir.insert(dir, path);
                }
            }
        }
    }
    let mut out: Vec<PathBuf> = by_dir.into_values().collect();
    out.sort();
    out
}

/// Unwrap JSON-encoded string values emitted in Antigravity compact `transcript.jsonl`
/// (e.g. `"\"mise run verify\""` -> `"mise run verify"`), while leaving normal strings intact.
pub fn unquote_arg(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        if let Ok(decoded) = serde_json::from_str::<String>(trimmed) {
            return decoded;
        }
        return trimmed[1..trimmed.len() - 1].to_string();
    }
    raw.to_string()
}

fn arg_str(args: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(s) = args.get(*key).and_then(Value::as_str) {
            let unquoted = unquote_arg(s);
            if !unquoted.is_empty() {
                return Some(unquoted);
            }
        }
    }
    None
}

fn derive_session_id(file_path: &Path) -> String {
    let norm = file_path.to_string_lossy().replace('\\', "/");
    static BRAIN_RE: OnceLock<Regex> = OnceLock::new();
    let re = BRAIN_RE.get_or_init(|| Regex::new(r"/brain/([^/]+)/").unwrap());
    if let Some(caps) = re.captures(&norm) {
        return caps[1].to_string();
    }
    file_path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string()
}

fn infer_cwd_from_file(p: &str) -> Option<String> {
    let path = Path::new(p);
    if !path.is_absolute() {
        return None;
    }
    if p.contains("/.t3/userdata/providers/")
        || p.contains("/.system_generated/")
        || p.contains("/.gemini/antigravity")
        || p.contains("/.local/state/")
        || p.starts_with("/tmp/")
        || p.starts_with("/private/tmp/")
        || p.starts_with("/var/folders/")
    {
        return None;
    }
    path.parent().map(|d| d.to_string_lossy().to_string())
}

fn infer_cwd_from_text(text: &str) -> Option<String> {
    static WS_RE: OnceLock<Regex> = OnceLock::new();
    let re = WS_RE.get_or_init(|| {
        Regex::new(r#"(/(?:Users|home)/[^/\s'`"\\]+/(?:code|work|\.t3/worktrees)/[^/\s'`"\\,)]+(?:/[^/\s'`"\\,)]+)?)"#)
            .unwrap()
    });
    for caps in re.captures_iter(text) {
        let cand = caps[1].trim_end_matches(|c| matches!(c, '.' | ':' | ';' | ')' | '`' | ','));
        if !cand.contains("/.t3/userdata/") && !cand.contains("/.system_generated/") {
            return Some(cand.to_string());
        }
    }
    None
}

/// Detect real CLI/task failures masked by `;` or `|| true` command chaining when the final exit code is 0.
fn detect_masked_chain_exit(cmd: &str, result_text: &str) -> Option<i64> {
    if !(cmd.contains(';') || cmd.contains("|| true") || cmd.contains('\n')) {
        return None;
    }
    // Skip search/diff commands whose stdout may legitimately contain error strings from source files
    let trimmed = cmd.trim_start();
    if trimmed.starts_with("grep ")
        || trimmed.starts_with("rg ")
        || trimmed.starts_with("git grep ")
        || trimmed.starts_with("git log ")
        || trimmed.starts_with("git diff ")
        || trimmed.starts_with("git show ")
    {
        return None;
    }
    let body = result_text
        .split_once("Command output:")
        .map(|(_, b)| b)
        .unwrap_or(result_text);
    if body.contains("zsh:1: command not found:") || body.contains(": command not found") {
        return Some(127);
    }
    if body.contains("ERROR task failed")
        || body.contains("sqlite3.OperationalError:")
        || body.contains("sqlite3.IntegrityError:")
        || body.contains("sqlite3.ProgrammingError:")
        || body.contains("Unknown argument:")
        || body.contains("Unknown command ")
        || body.contains("Unknown option:")
        || body.contains("Choose --scope or at least one --path")
        || body.contains("vps: Pass a single statement")
        || body.contains(": operation not permitted")
    {
        return Some(1);
    }
    None
}

pub fn parse_file(file_path: &Path, resolver: &mut WorkspaceResolver<'_>) -> Result<ParsedFile> {
    let raw = fs::read_to_string(file_path)?;
    let source_file = file_path.to_string_lossy().to_string();
    let session_id = format!("antigravity:{}", derive_session_id(file_path));

    let mut events = Vec::new();
    let mut line_count: i64 = 0;
    for line in raw.lines() {
        line_count += 1;
        if !line.starts_with('{') {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            events.push(v);
        }
    }

    // First pass: infer workspace cwd from unquoted file tool calls, else run_command paths, else USER_INPUT/SYSTEM_MESSAGE workspace paths
    let mut cwd: Option<String> = None;
    'outer: for ev in &events {
        if let Some(tcs) = ev.get("tool_calls").and_then(Value::as_array) {
            for tc in tcs {
                let args = tc.get("args").unwrap_or(&Value::Null);
                if let Some(p) = arg_str(args, &["Path", "path", "file_path"])
                    && let Some(dir) = infer_cwd_from_file(&p)
                {
                    cwd = Some(dir);
                    break 'outer;
                }
            }
        }
    }
    if cwd.is_none() {
        'cmd_outer: for ev in &events {
            if let Some(tcs) = ev.get("tool_calls").and_then(Value::as_array) {
                for tc in tcs {
                    let args = tc.get("args").unwrap_or(&Value::Null);
                    if let Some(cmd) = arg_str(args, &["CommandLine", "command"])
                        && let Some(dir) = infer_cwd_from_text(&cmd)
                    {
                        cwd = Some(dir);
                        break 'cmd_outer;
                    }
                }
            }
        }
    }
    if cwd.is_none() {
        for ev in events.iter().take(20) {
            if let Some(txt) = ev.get("content").and_then(Value::as_str)
                && let Some(dir) = infer_cwd_from_text(txt)
            {
                cwd = Some(dir);
                break;
            }
        }
    }

    let mut model: Option<String> = None;
    let mut started_at: Option<i64> = None;
    let mut ended_at: Option<i64> = None;
    let mut turn_count: i64 = 0;
    let mut input_tokens: i64 = 0;
    let mut output_tokens: i64 = 0;
    let mut cached_tokens: i64 = 0;

    let mut spans = Vec::new();
    let mut file_reads = Vec::new();
    let mut tool_calls = Vec::new();
    let mut seq_idx: i64 = 0;
    let mut is_handoff = false;
    let mut first_user_seen = false;
    let originator = Some(if source_file.contains("/.t3/") {
        "T3 Code".to_string()
    } else {
        "antigravity".to_string()
    });

    for (i, ev) in events.iter().enumerate() {
        let ts = to_epoch_ms(ev.get("created_at"));
        if let Some(t) = ts {
            started_at = Some(started_at.map_or(t, |cur| cur.min(t)));
            ended_at = Some(ended_at.map_or(t, |cur| cur.max(t)));
        }

        if !first_user_seen && ev.get("type").and_then(Value::as_str) == Some("USER_INPUT") {
            if let Some(txt) = ev.get("content").and_then(Value::as_str)
                && !txt.trim().is_empty()
            {
                first_user_seen = true;
                if detect_handoff_text(txt) {
                    is_handoff = true;
                }
            }
        }

        if ev.get("type").and_then(Value::as_str) != Some("PLANNER_RESPONSE") {
            continue;
        }

        turn_count += 1;
        if model.is_none()
            && let Some(m) = ev.get("model").and_then(Value::as_str)
        {
            model = Some(m.to_string());
        }
        // In Antigravity transcripts, `input_tokens` is already uncached delta input tokens
        // (separate from `cache_read_tokens`), so do not subtract `cache_read_tokens`.
        let raw_in = ev.get("input_tokens").and_then(Value::as_i64).unwrap_or(0);
        let cache_r = ev
            .get("cache_read_tokens")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        input_tokens += raw_in.max(0);
        output_tokens += ev.get("output_tokens").and_then(Value::as_i64).unwrap_or(0);
        cached_tokens += cache_r.max(0);

        let Some(tcs) = ev.get("tool_calls").and_then(Value::as_array) else {
            continue;
        };

        let mut generic_offset = 1usize;
        for (t_idx, tc) in tcs.iter().enumerate() {
            let name = tc
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            let args = tc.get("args").unwrap_or(&Value::Null);

            let mut result_text = String::new();
            let mut log_compacted = false;
            while i + generic_offset < events.len()
                && events[i + generic_offset]
                    .get("type")
                    .and_then(Value::as_str)
                    == Some("GENERIC")
            {
                let g = &events[i + generic_offset];
                generic_offset += 1;
                if let Some(c) = g.get("content").and_then(Value::as_str) {
                    result_text = c.to_string();
                    log_compacted = g
                        .get("truncated_fields")
                        .and_then(Value::as_array)
                        .is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some("content")));
                    break;
                }
            }

            let step_idx = ev
                .get("step_index")
                .and_then(Value::as_i64)
                .unwrap_or(i as i64);
            let call_ts = ts
                .or(started_at)
                .unwrap_or_else(|| Utc::now().timestamp_millis());

            if name == "run_command" {
                let Some(cmd) = arg_str(args, &["CommandLine", "command"]) else {
                    continue;
                };
                let mut exit_code = extract_exit_code_from_text(&result_text, false);
                if exit_code == 0
                    && let Some(masked) = detect_masked_chain_exit(&cmd, &result_text)
                {
                    exit_code = masked;
                }
                let duration_ms = extract_duration_ms_from_text(&result_text);
                let built = build_command_spans(
                    SpanBuildArgs {
                        command_line: &cmd,
                        session_id: Some(session_id.clone()),
                        source_file: &source_file,
                        source_kind: "transcript",
                        agent_kind: "antigravity",
                        tool_call_id: Some(format!("{step_idx}_{t_idx}")),
                        turn_idx: turn_count,
                        base_seq_idx: seq_idx,
                        base_cwd: cwd.as_deref(),
                        exit_code: Some(exit_code),
                        duration_ms,
                        stdout_text: &result_text,
                        stderr_text: if exit_code != 0 { &result_text } else { "" },
                        started_at: call_ts,
                    },
                    resolver,
                );
                seq_idx += built.len() as i64;
                spans.extend(built);
            } else {
                let raw_name = tc.get("name").and_then(Value::as_str).unwrap_or("");
                let (norm_name, is_mcp) = normalize_tool_name(raw_name);
                let is_error = detect_tool_error(&result_text, false);
                let out_tokens = estimate_tokens_str(&result_text);
                let s_step = step_idx.to_string();
                let s_t = t_idx.to_string();
                let target_path = arg_str(args, &["Path", "path", "file_path"]).unwrap_or_default();
                let call_cwd = if !target_path.is_empty() {
                    infer_cwd_from_file(&target_path).or_else(|| cwd.clone())
                } else {
                    cwd.clone()
                };
                let ws = call_cwd.as_deref().and_then(|c| resolver.resolve(c));

                let is_truncated = if log_compacted {
                    false
                } else if name == "read_file" {
                    let lower = result_text.to_ascii_lowercase();
                    lower.contains("truncated at the ") || lower.contains("output was truncated")
                } else {
                    detect_truncation(&result_text)
                };

                if !norm_name.is_empty() {
                    tool_calls.push(ToolCallRecord {
                        call_id: make_id("tc", &[&source_file, &s_step, &s_t]),
                        session_id: session_id.clone(),
                        source_file: source_file.clone(),
                        agent_kind: "antigravity".to_string(),
                        repo_id: ws.as_ref().map(|w| w.repo_id.clone()),
                        repo_name: ws.as_ref().map(|w| w.repo_name.clone()),
                        turn_idx: turn_count,
                        tool_name: norm_name,
                        is_mcp,
                        is_error,
                        duration_ms: extract_duration_ms_from_text(&result_text),
                        output_bytes: result_text.len() as i64,
                        output_tokens: out_tokens,
                        is_truncated,
                        error_preview: extract_tool_error_preview(&result_text, is_error),
                        started_at: call_ts,
                    });
                }

                if name == "read_file" && !target_path.is_empty() {
                    let target_name = if target_path.contains("/.system_generated/steps/")
                        && target_path.ends_with("/output.txt")
                    {
                        "steps/output.txt".to_string()
                    } else {
                        Path::new(&target_path)
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or(&target_path)
                            .to_string()
                    };
                    file_reads.push(FileReadRecord {
                        read_id: make_id("rd", &[&source_file, &s_step, &s_t]),
                        session_id: session_id.clone(),
                        source_file: source_file.clone(),
                        repo_id: ws.as_ref().map(|w| w.repo_id.clone()),
                        repo_name: ws.as_ref().map(|w| w.repo_name.clone()),
                        turn_idx: turn_count,
                        target_name,
                        is_doc: is_doc_path(&target_path),
                        output_tokens: out_tokens,
                        started_at: call_ts,
                    });
                }
            }
        }
    }

    if turn_count == 0 && spans.is_empty() {
        return Ok(ParsedFile {
            line_count,
            ..Default::default()
        });
    }

    let ws = cwd.as_deref().and_then(|c| resolver.resolve(c));
    let dom = dominant_span_repo(&spans);
    let total_tool_ms: i64 = spans.iter().filter_map(|s| s.duration_ms).sum::<i64>()
        + tool_calls.iter().filter_map(|t| t.duration_ms).sum::<i64>();
    // Antigravity subagent sessions start with a SYSTEM_MESSAGE and never receive USER_INPUT
    let is_subagent = !first_user_seen;

    let session = SessionRecord {
        session_id,
        agent_kind: "antigravity".to_string(),
        source_file,
        model,
        workspace_id: ws.as_ref().map(|w| w.workspace_id.clone()),
        repo_id: ws
            .as_ref()
            .map(|w| w.repo_id.clone())
            .or_else(|| dom.as_ref().map(|(rid, _)| rid.clone()))
            .or_else(|| spans.first().and_then(|s| s.repo_id.clone()))
            .or_else(|| file_reads.first().and_then(|r| r.repo_id.clone())),
        repo_name: ws
            .as_ref()
            .map(|w| w.repo_name.clone())
            .or_else(|| dom.as_ref().map(|(_, rname)| rname.clone()))
            .or_else(|| spans.first().and_then(|s| s.repo_name.clone()))
            .or_else(|| file_reads.first().and_then(|r| r.repo_name.clone())),
        cwd,
        git_branch: None,
        started_at,
        ended_at,
        turn_count,
        input_tokens,
        output_tokens,
        cached_tokens,
        cost_usd: None,
        total_tool_ms,
        is_subagent,
        originator,
        subagent_kind: Some(if is_subagent {
            "subagent".to_string()
        } else {
            "main".to_string()
        }),
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
