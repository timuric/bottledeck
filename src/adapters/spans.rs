use crate::adapters::{ParsedFile, make_id};
use crate::config::estimate_tokens_bytes;
use crate::db::CommandSpanRecord;
use crate::shell::{parse_command_tokens, redact_secrets};
use crate::workspace::WorkspaceResolver;
use anyhow::Result;
use chrono::Utc;
use serde_json::Value;
use std::fs;
use std::path::Path;

pub fn parse_file(file_path: &Path, resolver: &mut WorkspaceResolver<'_>) -> Result<ParsedFile> {
    if !file_path.exists() {
        return Ok(ParsedFile::default());
    }
    let raw = fs::read_to_string(file_path)?;
    let source_file = file_path.to_string_lossy().to_string();
    let mut spans = Vec::new();
    let mut line_count: i64 = 0;

    for (idx, line) in raw.lines().enumerate() {
        line_count += 1;
        if !line.starts_with('{') {
            continue;
        }
        let Ok(rec) = serde_json::from_str::<Value>(line) else {
            continue;
        };

        let argv: Vec<String> = rec
            .get("argv")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        if argv.is_empty() {
            continue;
        }
        let joined = argv.join(" ");
        let Some(parsed) = parse_command_tokens(&argv, &joined) else {
            continue;
        };

        let ws = rec
            .get("cwd")
            .and_then(Value::as_str)
            .and_then(|c| resolver.resolve(c));
        let stdout_bytes = rec.get("stdout_bytes").and_then(Value::as_i64).unwrap_or(0);
        let stderr_bytes = rec.get("stderr_bytes").and_then(Value::as_i64).unwrap_or(0);
        let started_at = rec
            .get("started_at")
            .and_then(Value::as_i64)
            .unwrap_or_else(|| Utc::now().timestamp_millis());
        let s_idx = idx.to_string();
        let s_ts = started_at.to_string();

        let span_id = rec
            .get("span_id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| make_id("wrap", &[&source_file, &s_idx, &s_ts]));

        let session_id = rec
            .get("session_id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                rec.get("process_key")
                    .and_then(Value::as_str)
                    .map(|k| format!("proc:{k}"))
            });

        spans.push(CommandSpanRecord {
            span_id,
            session_id,
            source_file: source_file.clone(),
            source_kind: "wrap".to_string(),
            agent_kind: Some(
                rec.get("agent_kind")
                    .and_then(Value::as_str)
                    .unwrap_or("cli-wrap")
                    .to_string(),
            ),
            tool_call_id: rec
                .get("tool_call_id")
                .and_then(Value::as_str)
                .map(str::to_string),
            turn_idx: rec.get("turn_idx").and_then(Value::as_i64).unwrap_or(0),
            seq_idx: idx as i64,
            workspace_id: ws.as_ref().map(|w| w.workspace_id.clone()),
            repo_id: ws.as_ref().map(|w| w.repo_id.clone()),
            repo_name: ws.as_ref().map(|w| w.repo_name.clone()),
            git_head: rec
                .get("git_head")
                .and_then(Value::as_str)
                .map(str::to_string),
            actor: rec
                .get("actor")
                .and_then(Value::as_str)
                .unwrap_or("agent")
                .to_string(),
            category: parsed.category.to_string(),
            is_repo_cli: parsed.is_repo_cli,
            surface_version: rec
                .get("surface_version")
                .and_then(Value::as_str)
                .map(str::to_string),
            cmd_bin: parsed.cmd_bin,
            cmd_template: parsed.cmd_template,
            raw_redacted: redact_secrets(&joined).chars().take(400).collect(),
            exit_code: rec.get("exit_code").and_then(Value::as_i64),
            duration_ms: rec.get("duration_ms").and_then(Value::as_i64),
            stdout_bytes,
            stdout_tokens: estimate_tokens_bytes(stdout_bytes.max(0) as usize),
            stderr_bytes,
            stderr_preview: rec
                .get("stderr_preview")
                .and_then(Value::as_str)
                .map(|s| redact_secrets(s).chars().take(280).collect()),
            noise_kind: rec
                .get("noise_kind")
                .and_then(Value::as_str)
                .map(str::to_string),
            is_orientation: parsed.is_orientation,
            piped_filter: None,
            state_dir_hint: crate::shell::extract_state_dir_hint(&joined, None),
            is_truncated: false,
            started_at,
        });
    }

    Ok(ParsedFile {
        sessions: Vec::new(),
        spans,
        file_reads: Vec::new(),
        tool_calls: Vec::new(),
        line_count,
    })
}
