pub mod antigravity;
pub mod claude;
pub mod codex;
pub mod kimi;
pub mod spans;

use crate::config::estimate_tokens_bytes;
use crate::db::{CommandSpanRecord, FileReadRecord, SessionRecord, ToolCallRecord};
use crate::shell::{
    classify_output_noise, extract_state_dir_hint, extract_stderr_preview, parse_command_tokens,
    redact_secrets, split_shell_commands,
};
use crate::workspace::WorkspaceResolver;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Default)]
pub struct ParsedFile {
    pub sessions: Vec<SessionRecord>,
    pub spans: Vec<CommandSpanRecord>,
    pub file_reads: Vec<FileReadRecord>,
    pub tool_calls: Vec<ToolCallRecord>,
    pub line_count: i64,
}

/// Detect whether a tool/command output was truncated by the agent harness.
pub fn detect_truncation(text: &str) -> bool {
    if text.len() >= 15_360 {
        return true;
    }
    let lower = text.to_ascii_lowercase();
    lower.contains("tokens truncated")
        || lower.contains("chars truncated")
        || lower.contains("bytes truncated")
        || lower.contains("<truncated")
        || lower.contains("[output truncated")
        || lower.contains("... truncated")
        || lower.contains("total output lines:")
        || lower.contains("output was truncated")
}

/// Detect whether an initial prompt marks a context handoff / resumed continuation session.
pub fn detect_handoff_text(text: &str) -> bool {
    let trimmed = text.trim_start();
    trimmed.starts_with("Context handoff")
        || trimmed.starts_with("<CONTEXT_SUMMARY>")
        || trimmed.contains("This session is being continued from a previous conversation")
        || trimmed.contains("continued from a previous conversation")
        || trimmed.contains("Context handoff from ")
}

/// Normalize a non-shell tool name across harnesses and classify whether it is an MCP/external tool.
pub fn normalize_tool_name(raw: &str) -> (String, bool) {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("mcp__") {
        // Claude / Codex format: mcp__<server>__<tool>
        if let Some((srv, tool)) = rest.split_once("__") {
            return (format!("mcp:{}:{tool}", srv.replace('_', "-")), true);
        }
        return (format!("mcp:{}", rest.replace('_', "-")), true);
    }
    if let Some(rest) = trimmed.strip_prefix("mcp_") {
        // Antigravity format: mcp_<server>_<tool> (e.g. mcp_t3-code_preview_act)
        if let Some((srv, tool)) = rest.split_once('_') {
            return (format!("mcp:{}:{tool}", srv.replace('_', "-")), true);
        }
        return (format!("mcp:{}", rest.replace('_', "-")), true);
    }
    let lower = trimmed.to_ascii_lowercase();
    let is_mcp_like = lower.starts_with("t3_")
        || lower.starts_with("preview_")
        || lower.starts_with("device_")
        || lower.starts_with("pull_request_")
        || lower.starts_with("ci_")
        || lower.contains("__");
    (trimmed.to_string(), is_mcp_like)
}

/// Detect non-shell tool call failure from explicit error flag or standardized error envelopes.
pub fn detect_tool_error(text: &str, explicit_err: bool) -> bool {
    if explicit_err {
        return true;
    }
    if text.is_empty() {
        return false;
    }
    let head: String = text.chars().take(600).collect();
    let lower = head.to_ascii_lowercase();
    head.contains("OrchestratorMcpFailure")
        || head.contains("\"isError\":true")
        || head.contains("\"ok\":false")
        || lower.starts_with("error:")
        || lower.starts_with("tool error:")
        || lower.starts_with("failed to ")
        || lower.contains("tool call failed")
        || lower.contains("timed out")
        || lower.contains("timeout ")
        || lower.contains("operation not permitted")
        || lower.contains("belongs to another agent session")
}

pub fn extract_tool_error_preview(text: &str, is_err: bool) -> Option<String> {
    if !is_err || text.trim().is_empty() {
        return None;
    }
    let meaningful = text
        .lines()
        .map(str::trim)
        .find(|l| {
            !l.is_empty()
                && !l.starts_with("Script completed")
                && !l.starts_with("Wall time")
                && !l.starts_with("Output:")
                && !l.starts_with("Chunk ID:")
                && !l.starts_with("Total output lines:")
        })
        .unwrap_or("")
        .to_string();
    if meaningful.is_empty() {
        return None;
    }
    Some(redact_secrets(&meaningful).chars().take(240).collect())
}

pub fn walk_files<F>(root: &Path, max_depth: usize, mut predicate: F) -> Vec<PathBuf>
where
    F: FnMut(&Path, &str) -> bool,
{
    if !root.exists() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for entry in WalkDir::new(root)
        .max_depth(max_depth)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_str().unwrap_or("");
            name != "node_modules" && name != ".git"
        })
        .flatten()
    {
        if entry.file_type().is_file() {
            let name = entry.file_name().to_str().unwrap_or("");
            if predicate(entry.path(), name) {
                out.push(entry.into_path());
            }
        }
    }
    out
}

pub fn to_epoch_ms(val: Option<&Value>) -> Option<i64> {
    let v = val?;
    if let Some(n) = v.as_i64() {
        return Some(if n < 1_000_000_000_000 { n * 1000 } else { n });
    }
    if let Some(f) = v.as_f64() {
        if f.is_finite() {
            let n = f.round() as i64;
            return Some(if n < 1_000_000_000_000 { n * 1000 } else { n });
        }
    }
    if let Some(s) = v.as_str() {
        if let Ok(dt) = DateTime::parse_from_rfc3339(s.trim()) {
            return Some(dt.timestamp_millis());
        }
    }
    None
}

pub fn flatten_content(val: Option<&Value>) -> String {
    let Some(v) = val else { return String::new() };
    if let Some(s) = v.as_str() {
        return s.to_string();
    }
    if let Some(arr) = v.as_array() {
        let parts: Vec<String> = arr
            .iter()
            .filter_map(|item| {
                if let Some(s) = item.as_str() {
                    Some(s.to_string())
                } else if let Some(obj) = item.as_object() {
                    obj.get("text")
                        .and_then(Value::as_str)
                        .or_else(|| obj.get("content").and_then(Value::as_str))
                        .map(str::to_string)
                } else {
                    None
                }
            })
            .filter(|s| !s.is_empty())
            .collect();
        return parts.join("\n");
    }
    if let Some(obj) = v.as_object() {
        if let Some(s) = obj.get("text").and_then(Value::as_str) {
            return s.to_string();
        }
        let stdout = obj.get("stdout").and_then(Value::as_str).unwrap_or("");
        let stderr = obj.get("stderr").and_then(Value::as_str).unwrap_or("");
        if !stdout.is_empty() || !stderr.is_empty() {
            return [stdout, stderr]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join("\n");
        }
    }
    v.to_string()
}

pub fn is_doc_path(file_path: &str) -> bool {
    let lower_full = file_path.to_ascii_lowercase();
    let base = Path::new(file_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    base.starts_with("readme")
        || base.starts_with("agents")
        || base.starts_with("claude")
        || base.starts_with("contributing")
        || base.starts_with("changelog")
        || base.starts_with("architecture")
        || matches!(
            base.as_str(),
            "makefile"
                | "justfile"
                | "mise.toml"
                | "package.json"
                | "cargo.toml"
                | "pyproject.toml"
        )
        || lower_full.contains("/docs/")
}

pub fn make_id(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for p in parts {
        hasher.update(p.as_bytes());
        hasher.update(b"\0");
    }
    let hex = format!("{:x}", hasher.finalize());
    format!("{prefix}_{}", &hex[..16])
}

pub fn dominant_span_repo(spans: &[CommandSpanRecord]) -> Option<(String, String)> {
    use std::collections::HashMap;
    let mut counts: HashMap<(String, String), usize> = HashMap::new();
    for sp in spans {
        if let (Some(rid), Some(rname)) = (&sp.repo_id, &sp.repo_name)
            && !rid.starts_with("dir:")
            && !rid.starts_with("inferred/")
        {
            *counts.entry((rid.clone(), rname.clone())).or_insert(0) += 1;
        }
    }
    counts.into_iter().max_by_key(|(_, c)| *c).map(|(k, _)| k)
}

pub fn clamp_tool_duration(ms: Option<i64>) -> Option<i64> {
    let v = ms?;
    if !(0..=600_000).contains(&v) {
        return None;
    }
    Some(v)
}

pub struct SpanBuildArgs<'a> {
    pub command_line: &'a str,
    pub session_id: Option<String>,
    pub source_file: &'a str,
    pub source_kind: &'a str,
    pub agent_kind: &'a str,
    pub tool_call_id: Option<String>,
    pub turn_idx: i64,
    pub base_seq_idx: i64,
    pub base_cwd: Option<&'a str>,
    pub exit_code: Option<i64>,
    pub duration_ms: Option<i64>,
    pub stdout_text: &'a str,
    pub stderr_text: &'a str,
    pub started_at: i64,
}

pub fn build_command_spans(
    args: SpanBuildArgs<'_>,
    resolver: &mut WorkspaceResolver<'_>,
) -> Vec<CommandSpanRecord> {
    let segs = split_shell_commands(args.command_line);
    if segs.is_empty() {
        return Vec::new();
    }

    let mut parsed_segs = Vec::new();
    for seg in &segs {
        let Some(parsed) = parse_command_tokens(&seg.tokens, &seg.raw) else {
            continue;
        };
        if seg.is_pipe_consumer
            && matches!(
                parsed.cmd_bin.as_str(),
                "head"
                    | "tail"
                    | "wc"
                    | "sort"
                    | "uniq"
                    | "cut"
                    | "tr"
                    | "jq"
                    | "tee"
                    | "sed"
                    | "awk"
                    | "grep"
                    | "rg"
            )
        {
            continue;
        }
        parsed_segs.push((seg, parsed));
    }

    if parsed_segs.is_empty()
        && let Some(first) = segs.first()
        && let Some(parsed) = parse_command_tokens(&first.tokens, &first.raw)
    {
        parsed_segs.push((first, parsed));
    }

    if parsed_segs.is_empty() {
        return Vec::new();
    }

    let total_stdout_bytes = args.stdout_text.len() as i64;
    let total_stderr_bytes = args.stderr_text.len() as i64;
    let total_stdout_tokens = estimate_tokens_bytes(args.stdout_text.len());
    let noise_kind = classify_output_noise(args.stdout_text, args.exit_code);
    let err_src = if args.stderr_text.is_empty() {
        args.stdout_text
    } else {
        args.stderr_text
    };
    let stderr_preview = extract_stderr_preview(err_src, args.exit_code);

    let count = parsed_segs.len() as i64;
    let per_stdout_bytes = total_stdout_bytes / count;
    let per_stdout_tokens = total_stdout_tokens / count;
    let per_duration = args.duration_ms.map(|d| d / count);

    let is_truncated = detect_truncation(args.stdout_text);
    let base_ws = args.base_cwd.and_then(|c| resolver.resolve(c));
    let base_is_real = base_ws
        .as_ref()
        .is_some_and(|w| !w.repo_id.starts_with("dir:") && !w.repo_id.starts_with("inferred/"));
    let mut spans = Vec::with_capacity(parsed_segs.len());
    for (idx, (seg, parsed)) in parsed_segs.iter().enumerate() {
        let effective_cwd: Option<String> = match (&seg.cd_hint, args.base_cwd) {
            (Some(cd), Some(base)) => {
                let p = Path::new(cd);
                if p.is_absolute() {
                    Some(cd.clone())
                } else {
                    Some(Path::new(base).join(p).to_string_lossy().to_string())
                }
            }
            (Some(cd), None) => Some(cd.clone()),
            (None, Some(base)) => Some(base.to_string()),
            (None, None) => None,
        };

        let cd_ws = if seg.cd_hint.is_some() {
            effective_cwd.as_deref().and_then(|c| resolver.resolve(c))
        } else {
            None
        };
        let ws = match (cd_ws, &base_ws) {
            (Some(cw), Some(_))
                if base_is_real
                    && (cw.repo_id.starts_with("dir:") || cw.repo_id.starts_with("inferred/")) =>
            {
                base_ws.clone()
            }
            (Some(cw), _) => Some(cw),
            (None, _) => base_ws.clone(),
        };
        let is_last = idx + 1 == parsed_segs.len();
        let seq = args.base_seq_idx + idx as i64;
        let seq_s = seq.to_string();
        let started_s = args.started_at.to_string();
        let tc_part = args.tool_call_id.as_deref().unwrap_or(&started_s);

        spans.push(CommandSpanRecord {
            span_id: make_id(
                "sp",
                &[args.source_file, tc_part, &seq_s, &parsed.cmd_template],
            ),
            session_id: args.session_id.clone(),
            source_file: args.source_file.to_string(),
            source_kind: args.source_kind.to_string(),
            agent_kind: Some(args.agent_kind.to_string()),
            tool_call_id: args.tool_call_id.clone(),
            turn_idx: args.turn_idx,
            seq_idx: seq,
            workspace_id: ws.as_ref().map(|w| w.workspace_id.clone()),
            repo_id: ws.as_ref().map(|w| w.repo_id.clone()),
            repo_name: ws.as_ref().map(|w| w.repo_name.clone()),
            git_head: None,
            actor: "agent".to_string(),
            category: parsed.category.to_string(),
            is_repo_cli: parsed.is_repo_cli,
            surface_version: None,
            cmd_bin: parsed.cmd_bin.clone(),
            cmd_template: parsed.cmd_template.clone(),
            raw_redacted: parsed.raw_redacted.clone(),
            exit_code: if is_last { args.exit_code } else { Some(0) },
            duration_ms: per_duration,
            stdout_bytes: per_stdout_bytes,
            stdout_tokens: per_stdout_tokens,
            stderr_bytes: if is_last { total_stderr_bytes } else { 0 },
            stderr_preview: if is_last {
                stderr_preview.clone()
            } else {
                None
            },
            noise_kind: if is_last { noise_kind.clone() } else { None },
            is_orientation: parsed.is_orientation,
            piped_filter: seg.piped_filter.clone(),
            state_dir_hint: extract_state_dir_hint(&seg.raw, seg.cd_hint.as_deref()),
            is_truncated: is_last && is_truncated,
            started_at: if args.started_at > 0 {
                args.started_at
            } else {
                Utc::now().timestamp_millis()
            },
        });
    }

    spans
}
