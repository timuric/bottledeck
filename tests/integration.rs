use bottledeck::analyze::issues::{add_marker, format_issues_report, issue_key, track_issues};
use bottledeck::analyze::{
    analyze_fleet, analyze_repo, diff_repo, inspect_finding, resolve_time_range,
};
use bottledeck::config::{AdapterRoots, TimeRange};
use bottledeck::db::open_db;
use bottledeck::ingest::sync_all;
use bottledeck::patterns::{
    analyze_cross_session_patterns, query_sequences, query_tools, query_top_sessions,
};
use bottledeck::report::{format_diagnosis_prompt, format_fleet_report, format_repo_report};
use bottledeck::shell::{
    clean_error_preview, parse_command_tokens, redact_secrets, split_shell_commands,
};
use bottledeck::tui::{App, DetailTab, draw};
use bottledeck::workspace::{WorkspaceResolver, normalize_remote_url};
use chrono::Utc;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

/// Fixture root for synthetic transcripts.
///
/// Adapters deliberately treat OS temp dirs (`/tmp`, `/var/folders`, …) as scratch space with no
/// repository, and a path inside a git checkout resolves to that checkout. Fixtures therefore live
/// in a throwaway dir under `$HOME` (override with `BOTTLEDECK_TEST_TMP`), removed on drop.
fn fixture_tmp() -> TempDir {
    let base = std::env::var_os("BOTTLEDECK_TEST_TMP")
        .or_else(|| std::env::var_os("HOME"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    tempfile::Builder::new()
        .prefix(".bottledeck-it-")
        .tempdir_in(base)
        .unwrap()
}

#[test]
fn shell_parsing_and_secret_redaction() {
    let raw = "cd packages/api && GITHUB_TOKEN=ghp_1234567890abcdef12345678 cargo test --package core 2>&1 | tail -n 40";
    let segs = split_shell_commands(raw);
    assert_eq!(segs.len(), 2);
    assert_eq!(segs[0].cd_hint.as_deref(), Some("packages/api"));
    assert!(!segs[0].is_pipe_consumer);
    assert!(segs[1].is_pipe_consumer);

    let parsed = parse_command_tokens(&segs[0].tokens, &segs[0].raw).unwrap();
    assert_eq!(parsed.cmd_bin, "cargo");
    assert_eq!(parsed.cmd_template, "cargo test --package");
    assert_eq!(parsed.category, "build_test");
    assert!(!parsed.raw_redacted.contains("ghp_1234567890"));
    assert!(parsed.raw_redacted.contains("GITHUB_TOKEN=<redacted>"));

    let bearer = redact_secrets(
        "curl -H 'Authorization: Bearer supersecretvalue12345' https://user:pass123@example.com",
    );
    assert!(!bearer.contains("supersecretvalue12345"));
    assert!(!bearer.contains("pass123"));
}

#[test]
fn workspace_remote_normalization_and_worktree_collapsing() {
    assert_eq!(
        normalize_remote_url("git@github.com:Acme/Demo.git").as_deref(),
        Some("github.com/acme/demo")
    );
    assert_eq!(
        normalize_remote_url("https://token:secret@github.com/Acme/Demo.git").as_deref(),
        Some("github.com/acme/demo")
    );

    let tmp = fixture_tmp();
    let repo_dir = tmp.path().join("demo");
    let wt_dir = tmp.path().join("demo-wt");
    fs::create_dir_all(&repo_dir).unwrap();

    let run = |dir: &std::path::Path, args: &[&str]| {
        let st = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@example.com")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@example.com")
            .status()
            .unwrap();
        assert!(st.success(), "git {args:?} failed");
    };

    run(&repo_dir, &["init"]);
    fs::write(repo_dir.join("README.md"), "# demo\n").unwrap();
    run(&repo_dir, &["add", "."]);
    run(&repo_dir, &["commit", "-m", "init"]);
    run(
        &repo_dir,
        &["remote", "add", "origin", "git@github.com:acme/demo.git"],
    );
    run(
        &repo_dir,
        &[
            "worktree",
            "add",
            wt_dir.to_str().unwrap(),
            "-b",
            "feat/test",
        ],
    );

    let db = open_db(&tmp.path().join("ledger.db")).unwrap();
    let mut resolver = WorkspaceResolver::new(Some(&db));
    let main_ws = resolver.resolve(repo_dir.to_str().unwrap()).unwrap();
    let wt_ws = resolver.resolve(wt_dir.to_str().unwrap()).unwrap();

    assert_eq!(main_ws.repo_id, "github.com/acme/demo");
    assert_eq!(wt_ws.repo_id, main_ws.repo_id);
    assert!(!main_ws.is_worktree);
    assert!(wt_ws.is_worktree);
}

#[test]
fn end_to_end_ingest_analysis_diff_and_tui_render() {
    let tmp = fixture_tmp();
    let repo_dir = tmp.path().join("sample-repo");
    fs::create_dir_all(&repo_dir).unwrap();
    let repo_str = repo_dir.to_string_lossy().to_string();

    let claude_root = tmp.path().join("claude");
    let codex_root = tmp.path().join("codex");
    let agy_root = tmp.path().join("agy");
    fs::create_dir_all(claude_root.join("proj")).unwrap();
    fs::create_dir_all(codex_root.join("2026")).unwrap();
    fs::create_dir_all(agy_root.join("brain/conv-1/.system_generated/logs")).unwrap();

    let now = Utc::now().timestamp_millis();
    let t0 = now - 3_600_000;
    let noisy_tests: String = (0..120)
        .map(|i| format!("test module::case_{i} ... ok"))
        .collect::<Vec<_>>()
        .join("\n");

    // 1. Synthetic Claude transcript with token bloat, flag thrash, and rebound
    let claude_lines = [
        serde_json::json!({
            "type": "assistant",
            "sessionId": "s-claude-1",
            "cwd": repo_str,
            "timestamp": chrono::DateTime::from_timestamp_millis(t0).unwrap().to_rfc3339(),
            "message": {
                "id": "m1",
                "model": "claude-sonnet",
                "usage": {"input_tokens": 5000, "output_tokens": 400, "cache_read_input_tokens": 1200},
                "content": [
                    {"type": "tool_use", "id": "tu1", "name": "Bash", "input": {"command": "mise run verify --dry-run"}}
                ]
            }
        }),
        serde_json::json!({
            "type": "user",
            "sessionId": "s-claude-1",
            "cwd": repo_str,
            "timestamp": chrono::DateTime::from_timestamp_millis(t0 + 1000).unwrap().to_rfc3339(),
            "toolUseResult": {"exitCode": 2, "durationMs": 450, "stderr": "error: unexpected argument --dry-run"},
            "message": {
                "content": [{"type": "tool_result", "tool_use_id": "tu1", "is_error": true, "content": "error: unexpected argument --dry-run"}]
            }
        }),
        serde_json::json!({
            "type": "assistant",
            "sessionId": "s-claude-1",
            "cwd": repo_str,
            "timestamp": chrono::DateTime::from_timestamp_millis(t0 + 2000).unwrap().to_rfc3339(),
            "message": {
                "id": "m2",
                "model": "claude-sonnet",
                "usage": {"input_tokens": 6000, "output_tokens": 500},
                "content": [
                    {"type": "tool_use", "id": "tu2", "name": "Bash", "input": {"command": "mise run verify --scope server"}}
                ]
            }
        }),
        serde_json::json!({
            "type": "user",
            "sessionId": "s-claude-1",
            "cwd": repo_str,
            "timestamp": chrono::DateTime::from_timestamp_millis(t0 + 12000).unwrap().to_rfc3339(),
            "toolUseResult": {"exitCode": 0, "durationMs": 9500, "stdout": noisy_tests},
            "message": {
                "content": [{"type": "tool_result", "tool_use_id": "tu2", "is_error": false, "content": noisy_tests}]
            }
        }),
        serde_json::json!({
            "type": "assistant",
            "sessionId": "s-claude-1",
            "cwd": repo_str,
            "timestamp": chrono::DateTime::from_timestamp_millis(t0 + 13000).unwrap().to_rfc3339(),
            "message": {
                "id": "m3",
                "model": "claude-sonnet",
                "usage": {"input_tokens": 7000, "output_tokens": 200},
                "content": [
                    {"type": "tool_use", "id": "tu3", "name": "Bash", "input": {"command": "rg FAILED target/out.log"}}
                ]
            }
        }),
        serde_json::json!({
            "type": "user",
            "sessionId": "s-claude-1",
            "cwd": repo_str,
            "timestamp": chrono::DateTime::from_timestamp_millis(t0 + 13200).unwrap().to_rfc3339(),
            "toolUseResult": {"exitCode": 0, "durationMs": 120, "stdout": "no matches"},
            "message": {
                "content": [{"type": "tool_result", "tool_use_id": "tu3", "is_error": false, "content": "no matches"}]
            }
        }),
    ];
    fs::write(
        claude_root.join("proj/s1.jsonl"),
        claude_lines
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    // 2. Synthetic Codex transcript with repeated flag thrash + verbose tests + polling
    let t1 = now - 1_800_000;
    let codex_lines = [
        serde_json::json!({
            "type": "session_meta",
            "timestamp": chrono::DateTime::from_timestamp_millis(t1).unwrap().to_rfc3339(),
            "payload": {"session_id": "s-codex-1", "cwd": repo_str}
        }),
        serde_json::json!({
            "type": "turn_context",
            "timestamp": chrono::DateTime::from_timestamp_millis(t1 + 100).unwrap().to_rfc3339(),
            "payload": {"cwd": repo_str, "model": "gpt-5-codex"}
        }),
        serde_json::json!({
            "type": "token_usage_record",
            "timestamp": chrono::DateTime::from_timestamp_millis(t1 + 500).unwrap().to_rfc3339(),
            "payload": {"thread_token_usage": {"input_tokens": 12000, "output_tokens": 1800, "cached_input_tokens": 4000}}
        }),
        serde_json::json!({
            "type": "response_item",
            "timestamp": chrono::DateTime::from_timestamp_millis(t1 + 1000).unwrap().to_rfc3339(),
            "payload": {"type": "function_call", "call_id": "c1", "name": "exec_command", "arguments": "{\"cmd\":\"mise run verify --dry-run\"}"}
        }),
        serde_json::json!({
            "type": "response_item",
            "timestamp": chrono::DateTime::from_timestamp_millis(t1 + 1500).unwrap().to_rfc3339(),
            "payload": {"type": "function_call_output", "call_id": "c1", "output": "Exit code: 2\nerror: unknown flag --dry-run"}
        }),
        serde_json::json!({
            "type": "response_item",
            "timestamp": chrono::DateTime::from_timestamp_millis(t1 + 2000).unwrap().to_rfc3339(),
            "payload": {"type": "function_call", "call_id": "c2", "name": "exec_command", "arguments": "{\"cmd\":\"mise run verify --scope server\"}"}
        }),
        serde_json::json!({
            "type": "response_item",
            "timestamp": chrono::DateTime::from_timestamp_millis(t1 + 11000).unwrap().to_rfc3339(),
            "payload": {"type": "function_call_output", "call_id": "c2", "output": format!("Exit code: 0\nWall time: 8.5 seconds\n{noisy_tests}")}
        }),
        serde_json::json!({
            "type": "response_item",
            "timestamp": chrono::DateTime::from_timestamp_millis(t1 + 12000).unwrap().to_rfc3339(),
            "payload": {"type": "function_call", "call_id": "c3", "name": "sleep", "arguments": "{\"duration_ms\":5000}"}
        }),
        serde_json::json!({
            "type": "response_item",
            "timestamp": chrono::DateTime::from_timestamp_millis(t1 + 17000).unwrap().to_rfc3339(),
            "payload": {"type": "function_call_output", "call_id": "c3", "output": "Exit code: 0\nWall time: 5.0 seconds"}
        }),
    ];
    fs::write(
        codex_root.join("2026/codex1.jsonl"),
        codex_lines
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    // 3. Synthetic Antigravity transcript
    let agy_lines = [
        serde_json::json!({
            "step_index": 1,
            "type": "PLANNER_RESPONSE",
            "created_at": chrono::DateTime::from_timestamp_millis(t1 + 20000).unwrap().to_rfc3339(),
            "model": "gemini-4",
            "input_tokens": 9000,
            "output_tokens": 600,
            "cache_read_tokens": 2000,
            "tool_calls": [
                {"name": "read_file", "args": {"Path": repo_dir.join("README.md").to_string_lossy()}},
                {"name": "run_command", "args": {"CommandLine": "mise run verify --scope server"}}
            ]
        }),
        serde_json::json!({
            "step_index": 2,
            "type": "GENERIC",
            "content": "# sample-repo docs"
        }),
        serde_json::json!({
            "step_index": 3,
            "type": "GENERIC",
            "content": format!("Command exited with code 0\n{noisy_tests}")
        }),
    ];
    fs::write(
        agy_root.join("brain/conv-1/.system_generated/logs/transcript.jsonl"),
        agy_lines
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    let mut conn = open_db(&tmp.path().join("ledger.db")).unwrap();
    let roots = AdapterRoots {
        claude: vec![claude_root],
        codex: vec![codex_root],
        antigravity: vec![agy_root],
        kimi: Vec::new(),
        spans: tmp.path().join("spans.jsonl"),
    };

    let stats = sync_all(&mut conn, &roots, false).unwrap();
    assert_eq!(stats.files_ingested, 3);
    assert_eq!(stats.sessions_upserted, 3);
    assert!(stats.spans_inserted >= 6);

    // Second sync should skip unchanged files
    let stats2 = sync_all(&mut conn, &roots, false).unwrap();
    assert_eq!(stats2.files_ingested, 0);
    assert_eq!(stats2.files_skipped, 3);

    let range_14d = TimeRange::from_window(Some(14 * 86_400_000), "14d");
    let fleet = analyze_fleet(&conn, &range_14d, true).unwrap();
    assert_eq!(fleet.repos.len(), 1);
    let repo_id = &fleet.repos[0].repo_id;

    let report = analyze_repo(&conn, repo_id, &range_14d, 8).unwrap();
    assert_eq!(report.kpis.sessions_analyzed, 3);

    // Verify --since / --until time range filtering cleanly partitions sessions
    let pre_range = TimeRange::bounded(0, Some(t1 - 100), "pre".into());
    let post_range = TimeRange::bounded(t1 - 100, None, "post".into());
    let pre_rep = analyze_repo(&conn, repo_id, &pre_range, 8).unwrap();
    let post_rep = analyze_repo(&conn, repo_id, &post_range, 8).unwrap();
    assert_eq!(pre_rep.kpis.sessions_analyzed, 1);
    assert_eq!(post_rep.kpis.sessions_analyzed, 2);

    let noisy = report
        .opportunities
        .iter()
        .find(|o| o.kind == "noisy_task_output")
        .expect("expected noisy_task_output opportunity");
    assert_eq!(noisy.by_harness.get("claude-code"), Some(&1));
    assert_eq!(noisy.by_harness.get("codex"), Some(&1));
    assert_eq!(noisy.by_harness.get("antigravity"), Some(&1));
    assert!(noisy.harness_summary.contains("claude-code"));
    assert!(noisy.harness_summary.contains("codex"));

    let thrash = report
        .opportunities
        .iter()
        .find(|o| o.kind == "flag_thrash")
        .expect("expected flag_thrash opportunity");
    assert_eq!(thrash.by_harness.get("claude-code"), Some(&1));
    assert_eq!(thrash.by_harness.get("codex"), Some(&1));
    assert!(thrash.harness_summary.contains("50%"));

    let llm_brief = format_repo_report(&report, "llm");
    assert!(llm_brief.contains("top_opportunities:"));
    assert!(llm_brief.contains("harnesses:"));
    assert!(llm_brief.contains("acceptance_metric:"));

    let md_brief = format_repo_report(&report, "md");
    assert!(md_brief.contains("- **Harnesses:**"));
    assert!(md_brief.contains("## Repo & Workflow Signals"));
    assert!(report.opportunities.iter().all(|o| o.scope == "repo"));

    let pat_e2e = analyze_cross_session_patterns(&conn, repo_id, &range_14d).unwrap();
    let prompt_bundle = format_diagnosis_prompt(&report, &pat_e2e);
    assert!(prompt_bundle.contains("Open-Ended Agent Telemetry Diagnosis Bundle"));
    assert!(prompt_bundle.contains("Do not restrict recommendations to canned templates"));

    let fleet_md = format_fleet_report(&fleet, "md");
    assert!(fleet_md.contains("sample-repo"));

    let inspected = inspect_finding(&conn, repo_id, "opp-1", &range_14d, 3).unwrap();
    assert!(!inspected.samples.is_empty());

    let diff = diff_repo(&conn, repo_id, t1 - 100, "midpoint").unwrap();
    assert_eq!(diff.before.sessions, 1);
    assert_eq!(diff.after.sessions, 2);

    // Session-level issue tracking: stable keys, one cell per exposed session, markers split it.
    let tracked = track_issues(&conn, repo_id, &range_14d).unwrap();
    assert_eq!(tracked.sessions, 3);
    let noisy_key = issue_key(&noisy.kind, &noisy.target);
    let noisy_track = tracked
        .issues
        .iter()
        .find(|t| t.key == noisy_key)
        .expect("noisy_task_output should be tracked per session");
    assert_eq!(noisy_track.exposed, 3);
    assert_eq!(noisy_track.affected, 3);
    assert!(
        noisy_track
            .cells
            .windows(2)
            .all(|w| w[0].started_at <= w[1].started_at)
    );
    assert_eq!(noisy_track.by_harness.len(), 3);
    assert!(tracked.issues.iter().all(|t| t.exposed > 0));

    let marker_id = add_marker(
        &conn,
        repo_id,
        Some(&noisy_key),
        t1 - 100,
        "midpoint",
        Some("quiet flag"),
    )
    .unwrap();
    let marked = track_issues(&conn, repo_id, &range_14d).unwrap();
    let t = marked.issues.iter().find(|t| t.key == noisy_key).unwrap();
    assert_eq!(t.marker.as_ref().map(|m| m.marker_id), Some(marker_id));
    let (before, after) = (t.verdict.before.unwrap(), t.verdict.after.unwrap());
    assert_eq!((before.exposed, after.exposed), (1, 2));
    // One session before the marker is no baseline: the verdict must say so instead of guessing.
    assert!(
        t.verdict.reason.contains("no baseline"),
        "{}",
        t.verdict.reason
    );
    let md = format_issues_report(&marked, "md");
    assert!(md.contains(&noisy_key));
    assert!(md.contains("│"));

    // Verify Ratatui TUI renders cleanly across all tabs, drawer, and modal using TestBackend
    let mut app = App::load(&conn, "14d", Some(repo_id)).unwrap();
    let backend = TestBackend::new(140, 40);
    let mut terminal = Terminal::new(backend).unwrap();

    for tab in [
        DetailTab::Insights,
        DetailTab::Patterns,
        DetailTab::Harnesses,
        DetailTab::Commands,
        DetailTab::Brief,
        DetailTab::Issues,
    ] {
        app.tab = tab;
        if tab == DetailTab::Issues {
            app.ensure_issues(&conn).unwrap();
        }
        terminal.draw(|f| draw(f, &mut app)).unwrap();
    }
    let issues_screen: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(issues_screen.contains("Issues by session"));
    assert!(issues_screen.contains("noisy_task_output"));
    assert!(issues_screen.contains("Session history"));

    app.sidebar_open = true;
    app.tab = DetailTab::Insights;
    terminal.draw(|f| draw(f, &mut app)).unwrap();
    app.sidebar_open = false;

    app.modal = Some(inspected);
    terminal.draw(|f| draw(f, &mut app)).unwrap();

    let rendered: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(rendered.contains("bottledeck"));
    assert!(rendered.contains("Trace Drill-Down"));
}

#[test]
fn cross_session_originator_subagent_mcp_tools_and_truncation() {
    let tmp = fixture_tmp();
    let repo_dir = tmp.path().join("demo-app");
    fs::create_dir_all(&repo_dir).unwrap();
    Command::new("git")
        .args(["init", "-q"])
        .current_dir(&repo_dir)
        .status()
        .unwrap();
    Command::new("git")
        .args([
            "remote",
            "add",
            "origin",
            "https://github.com/acme/demo-app.git",
        ])
        .current_dir(&repo_dir)
        .status()
        .unwrap();
    fs::write(
        repo_dir.join("mise.toml"),
        "[tasks.guide]\nrun = \"echo guide\"\n[tasks.changes]\nrun = \"echo diff\"\n",
    )
    .unwrap();
    fs::write(
        repo_dir.join("AGENTS.md"),
        "Use `missing_browser_tool` for visual checks.\n",
    )
    .unwrap();
    let repo_str = repo_dir.to_string_lossy().to_string();

    let claude_root = tmp.path().join("claude");
    let codex_root = tmp.path().join("codex");
    let agy_root = tmp.path().join("agy");
    fs::create_dir_all(claude_root.join("proj/subagents")).unwrap();
    fs::create_dir_all(codex_root.join("2026")).unwrap();
    fs::create_dir_all(agy_root.join("brain/conv-r5/.system_generated/logs")).unwrap();

    let now = Utc::now().timestamp_millis();
    let t0 = now - 7_200_000;
    let iso = |ms: i64| {
        chrono::DateTime::from_timestamp_millis(ms)
            .unwrap()
            .to_rfc3339()
    };

    // Claude main session (Context handoff) + separate subagent sharing parent sessionId
    let claude_main = [
        serde_json::json!({
            "type": "user",
            "sessionId": "parent-1",
            "entrypoint": "t3-code",
            "cwd": repo_str,
            "timestamp": iso(t0),
            "message": {"content": "Context handoff from earlier thread"}
        }),
        serde_json::json!({
            "type": "assistant",
            "sessionId": "parent-1",
            "entrypoint": "t3-code",
            "cwd": repo_str,
            "timestamp": iso(t0 + 1000),
            "message": {
                "id": "cm1",
                "model": "claude-opus",
                "usage": {"input_tokens": 2000, "cache_read_input_tokens": 98000, "output_tokens": 500},
                "content": [
                    {"type": "tool_use", "id": "m_wait", "name": "mcp__t3-code__t3_background_wait", "input": {"taskIds": ["x"]}}
                ]
            }
        }),
        serde_json::json!({
            "type": "user",
            "sessionId": "parent-1",
            "cwd": repo_str,
            "timestamp": iso(t0 + 1500),
            "message": {
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": "m_wait",
                    "is_error": true,
                    "content": "{\"_tag\":\"OrchestratorMcpFailure\",\"code\":\"invalid_request\"}"
                }]
            }
        }),
    ];
    fs::write(
        claude_root.join("proj/parent-1.jsonl"),
        claude_main
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    // Claude subagent file sharing parent `sessionId: "parent-1"` MUST NOT collide with parent!
    let claude_sub = [serde_json::json!({
        "type": "assistant",
        "sessionId": "parent-1",
        "entrypoint": "t3-code",
        "isSidechain": true,
        "cwd": repo_str,
        "timestamp": iso(t0 + 2000),
        "message": {
            "id": "cs1",
            "model": "claude-sonnet",
            "usage": {"input_tokens": 1000, "cache_read_input_tokens": 19000, "output_tokens": 200},
            "content": [{"type": "text", "text": "subagent result"}]
        }
    })];
    fs::write(
        claude_root.join("proj/subagents/agent-child1.jsonl"),
        claude_sub
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    // Codex guardian subagent + custom_host main session with truncated output
    let big_out = "x".repeat(16_000);
    let codex_host = [
        serde_json::json!({
            "type": "session_meta",
            "timestamp": iso(t0 + 3000),
            "payload": {"session_id": "cx-host-1", "cwd": repo_str, "originator": "custom_host", "source": "cli"}
        }),
        serde_json::json!({
            "type": "token_usage_record",
            "timestamp": iso(t0 + 3500),
            "payload": {"thread_token_usage": {"input_tokens": 100000, "cached_input_tokens": 95000, "output_tokens": 1000}}
        }),
        serde_json::json!({
            "type": "response_item",
            "timestamp": iso(t0 + 4000),
            "payload": {"type": "function_call", "call_id": "fc1", "name": "exec_command", "arguments": "{\"cmd\":\"mise run changes\"}"}
        }),
        serde_json::json!({
            "type": "response_item",
            "timestamp": iso(t0 + 4500),
            "payload": {"type": "function_call_output", "call_id": "fc1", "output": format!("Exit code: 0\n{big_out}")}
        }),
    ];
    fs::write(
        codex_root.join("2026/host.jsonl"),
        codex_host
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    // Codex guardian subagent sharing parent `session_id` MUST NOT overwrite parent thanks to distinct `id`!
    let codex_guard = [
        serde_json::json!({
            "type": "session_meta",
            "timestamp": iso(t0 + 5000),
            "payload": {"session_id": "cx-host-1", "id": "cx-guard-1", "cwd": repo_str, "originator": "custom_host", "source": {"subagent": {"other": "guardian"}}}
        }),
        serde_json::json!({
            "type": "token_usage_record",
            "timestamp": iso(t0 + 5500),
            "payload": {"thread_token_usage": {"input_tokens": 50000, "cached_input_tokens": 45000, "output_tokens": 500}}
        }),
    ];
    fs::write(
        codex_root.join("2026/guardian.jsonl"),
        codex_guard
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    // Kimi Code session with Bash command, Read, MCP tool, and usage record
    let kimi_root = tmp.path().join("kimi");
    let kimi_sess_dir = kimi_root.join("wd_demo/session_k1");
    fs::create_dir_all(kimi_sess_dir.join("agents/main")).unwrap();
    fs::write(
        kimi_sess_dir.join("state.json"),
        serde_json::json!({
            "id": "session_k1",
            "cwd": repo_str,
            "createdAt": t0 + 6000,
            "updatedAt": t0 + 9000
        })
        .to_string(),
    )
    .unwrap();
    let kimi_wire = [
        serde_json::json!({"type": "metadata", "created_at": t0 + 6000}),
        serde_json::json!({"type": "context.append_loop_event", "event": {"type": "step.begin", "turnId": "0", "step": 1}, "time": t0 + 6100}),
        serde_json::json!({"type": "context.append_loop_event", "event": {"type": "tool.call", "toolCallId": "k_c1", "name": "Bash", "args": {"command": "mise run guide"}}, "time": t0 + 6200}),
        serde_json::json!({"type": "context.append_loop_event", "event": {"type": "tool.result", "toolCallId": "k_c1", "result": {"output": "guide ok", "exit_code": 0}}, "time": t0 + 6800}),
        serde_json::json!({"type": "context.append_loop_event", "event": {"type": "tool.call", "toolCallId": "k_c2", "name": "mcp__demo__ping", "args": {}}, "time": t0 + 7000}),
        serde_json::json!({"type": "context.append_loop_event", "event": {"type": "tool.result", "toolCallId": "k_c2", "result": {"output": "pong"}}, "time": t0 + 7100}),
        serde_json::json!({"type": "usage.record", "model": "kimi-k2", "usage": {"inputOther": 4000, "output": 200, "inputCacheRead": 16000, "inputCacheCreation": 0}, "time": t0 + 7200}),
    ];
    fs::write(
        kimi_sess_dir.join("agents/main/wire.jsonl"),
        kimi_wire
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    let mut conn = open_db(&tmp.path().join("ledger.db")).unwrap();
    let roots = AdapterRoots {
        claude: vec![claude_root],
        codex: vec![codex_root],
        antigravity: vec![agy_root],
        kimi: vec![kimi_root],
        spans: tmp.path().join("spans.jsonl"),
    };
    let stats = sync_all(&mut conn, &roots, false).unwrap();
    assert_eq!(stats.sessions_upserted, 5);
    assert_eq!(stats.tool_calls_inserted, 2);

    let range_14d = TimeRange::from_window(Some(14 * 86_400_000), "14d");
    let fleet = analyze_fleet(&conn, &range_14d, true).unwrap();
    let repo_id = &fleet.repos[0].repo_id;

    // Verify patterns report separates Claude main vs subagent, Codex custom_host vs subagent:guardian, Kimi, MCP error & zero-call documented tool
    let pat = analyze_cross_session_patterns(&conn, repo_id, &range_14d).unwrap();
    assert_eq!(pat.main_sessions, 3);
    assert_eq!(pat.subagent_sessions, 2);
    assert!(
        pat.harness_comparison
            .iter()
            .any(|h| h.agent_kind == "claude-code" && h.role == "main" && h.sessions == 1)
    );
    assert!(
        pat.harness_comparison
            .iter()
            .any(|h| h.agent_kind == "claude-code" && h.role == "subagent" && h.sessions == 1)
    );
    assert!(
        pat.harness_comparison
            .iter()
            .any(|h| h.agent_kind == "codex"
                && h.originator == "custom_host"
                && h.role == "subagent:guardian")
    );
    assert!(
        pat.harness_comparison
            .iter()
            .any(|h| h.agent_kind == "codex"
                && h.originator == "custom_host"
                && h.role == "main"
                && h.truncated_outputs == 1)
    );
    assert!(
        pat.harness_comparison.iter().any(|h| h.agent_kind == "kimi"
            && h.role == "main"
            && h.sessions == 1
            && h.commands == 1)
    );
    // Codex cache hit must be exact 95.0% (not double-counted ~48.7%)
    let cx_main = pat
        .harness_comparison
        .iter()
        .find(|h| h.agent_kind == "codex" && h.role == "main")
        .unwrap();
    assert!((cx_main.weighted_cache_hit.unwrap() - 0.95).abs() < 0.005);

    // MCP tools query catches t3_background_wait 100% error + kimi mcp:demo:ping
    let tools = query_tools(&conn, repo_id, &range_14d, "errors", true, 10).unwrap();
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0].tool_name, "mcp:t3-code:t3_background_wait");
    assert_eq!(tools[0].error_count, 1);
    assert!(
        tools
            .iter()
            .any(|t| t.tool_name == "mcp:demo:ping" && t.by_harness.get("kimi") == Some(&1))
    );

    // Underused surfaces flags missing_browser_tool (0 calls) and changes (1 call)
    assert!(
        pat.underused_surfaces
            .iter()
            .any(|u| u.name == "missing_browser_tool" && u.observed_calls == 0)
    );
    assert!(
        pat.underused_surfaces
            .iter()
            .any(|u| u.name == "changes" && u.observed_calls == 1)
    );

    // Top sessions preserves handoff flag on Claude main
    let top = query_top_sessions(&conn, repo_id, &range_14d, "tokens", 10).unwrap();
    assert!(
        top.iter()
            .any(|s| s.agent_kind == "claude-code" && s.role == "main" && s.is_handoff)
    );

    // Verify query_sequences runs cleanly and resolve_time_range handles --since/--until
    let seqs = query_sequences(&conn, repo_id, &range_14d, 3, 10, 2, false, "impact", 10).unwrap();
    assert!(seqs.is_empty());
    let since_iso = iso(t0 + 5500);
    let r = resolve_time_range(
        &conn,
        None,
        Some(&since_iso),
        None,
        Some(repo_id),
        &repo_dir,
    )
    .unwrap();
    let post_kimi = analyze_repo(&conn, repo_id, &r, 10).unwrap();
    assert_eq!(post_kimi.kpis.sessions_analyzed, 1);
    assert_eq!(post_kimi.kpis.agents_seen, vec!["kimi".to_string()]);
}

#[test]
fn error_preview_cleaning_strips_harness_wrappers() {
    let codex_wrapped = r#"Script completed / Wall time 0.7 seconds / Output: / {"chunk_id":"67034b","wall_time_seconds":0.53,"exit_code":1,"output":"fatal: not a git repository"}"#;
    assert_eq!(
        clean_error_preview(codex_wrapped),
        "fatal: not a git repository"
    );

    let mcp_json = r#"{"_tag":"OrchestratorMcpFailure","code":"invalid_request","message":"None of the tasks are running"}"#;
    assert_eq!(
        clean_error_preview(mcp_json),
        "invalid_request: None of the tasks are running"
    );

    let agy_timestamp_only =
        "Created At: 2026-11-25T20:26:24+01:00 / Completed At: 2026-11-25T20:26:26+01:00";
    assert_eq!(clean_error_preview(agy_timestamp_only), "");
}

#[test]
fn antigravity_adapter_handles_full_transcripts_quoted_args_mcp_errors_and_tokens() {
    let tmp = fixture_tmp();
    let repo_dir = tmp.path().join("demo-agy-repo");
    fs::create_dir_all(repo_dir.join("src")).unwrap();
    fs::write(repo_dir.join("src/cards.rs"), "pub fn card() {}\n").unwrap();
    let repo_str = repo_dir.to_string_lossy().to_string();

    let agy_root = tmp.path().join("agy");
    let main_logs = agy_root.join("brain/main-conv/.system_generated/logs");
    let sub_logs = agy_root.join("brain/sub-conv/.system_generated/logs");
    fs::create_dir_all(&main_logs).unwrap();
    fs::create_dir_all(&sub_logs).unwrap();

    // Compact transcript.jsonl with double-quoted args and compact 4KB truncation noise
    let compact_lines = [
        serde_json::json!({
            "type": "USER_INPUT",
            "created_at": "2026-11-26T18:00:00Z",
            "content": "<USER_REQUEST><t3_code_instructions>Default</t3_code_instructions><user_request>Context handoff (full_thread_summary): resume</user_request></USER_REQUEST>"
        }),
        serde_json::json!({
            "step_index": 1,
            "type": "PLANNER_RESPONSE",
            "created_at": "2026-11-26T18:00:01Z",
            "model": "gemini-4-neon-high",
            "input_tokens": 5000,
            "cache_read_tokens": 40000,
            "output_tokens": 200,
            "tool_calls": [
                {
                    "name": "read_file",
                    "args": { "Path": format!("\"{repo_str}/src/cards.rs\"") }
                },
                {
                    "name": "run_command",
                    "args": { "CommandLine": "\"mise run vps -- sql 'SELECT x' | head -n 5; echo done\"" }
                },
                {
                    "name": "mcp_t3-code_pull_request_list",
                    "args": {}
                }
            ]
        }),
        serde_json::json!({
            "type": "GENERIC",
            "created_at": "2026-11-26T18:00:02Z",
            "content": "Created At: 2026-11-26T18:00:01Z\nCompleted At: 2026-11-26T18:00:02Z\nShowing lines 1-1 of 1\n1: pub fn card() {}"
        }),
        serde_json::json!({
            "type": "GENERIC",
            "created_at": "2026-11-26T18:00:03Z",
            "content": "Created At: 2026-11-26T18:00:02Z\nCompleted At: 2026-11-26T18:00:03Z\nCommand exited with code 0.\n\nCommand output:\nsqlite3.OperationalError: no such column: status\n[vps] ERROR task failed\ndone"
        }),
        serde_json::json!({
            "type": "GENERIC",
            "created_at": "2026-11-26T18:00:04Z",
            "content": "Created At: 2026-11-26T18:00:03Z\nCompleted At: 2026-11-26T18:00:04Z\nEncountered error in step execution: No GitHub credential on the server. Set GH_TOKEN."
        }),
    ];
    fs::write(
        main_logs.join("transcript.jsonl"),
        compact_lines
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    // Write identical full transcript alongside compact to verify `transcript_full.jsonl` wins
    fs::write(
        main_logs.join("transcript_full.jsonl"),
        compact_lines
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    // Subagent transcript (no USER_INPUT) + step spill output.txt read
    let sub_lines = [
        serde_json::json!({
            "type": "SYSTEM_MESSAGE",
            "created_at": "2026-11-26T18:05:00Z",
            "content": "Subagent task"
        }),
        serde_json::json!({
            "step_index": 1,
            "type": "PLANNER_RESPONSE",
            "created_at": "2026-11-26T18:05:01Z",
            "model": "gemini-4-neon-high",
            "input_tokens": 3000,
            "cache_read_tokens": 12000,
            "output_tokens": 150,
            "tool_calls": [
                {
                    "name": "read_file",
                    "args": { "Path": format!("{repo_str}/src/cards.rs") }
                },
                {
                    "name": "read_file",
                    "args": { "Path": "/Users/test/.t3/userdata/providers/antigravity/abc/brain/sub-conv/.system_generated/steps/4/output.txt" }
                }
            ]
        }),
        serde_json::json!({
            "type": "GENERIC",
            "created_at": "2026-11-26T18:05:02Z",
            "content": "Showing lines 1-1 of 1\n1: pub fn card() {}"
        }),
        serde_json::json!({
            "type": "GENERIC",
            "created_at": "2026-11-26T18:05:03Z",
            "content": "Showing lines 1-2 of 2\n1: spilled output"
        }),
    ];
    fs::write(
        sub_logs.join("transcript_full.jsonl"),
        sub_lines
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    let mut conn = open_db(&tmp.path().join("ledger.db")).unwrap();
    let roots = AdapterRoots {
        claude: vec![],
        codex: vec![],
        antigravity: vec![agy_root],
        kimi: vec![],
        spans: tmp.path().join("spans.jsonl"),
    };
    let stats = sync_all(&mut conn, &roots, false).unwrap();
    assert_eq!(stats.by_adapter["antigravity"].files_found, 2);

    // 1. Main session: handoff=1, subagent=0, input_tokens=5000 (not zeroed by cache_read_tokens!)
    let (in_tok, cache_tok, is_sub, is_handoff, repo_id): (i64, i64, i64, i64, Option<String>) =
        conn.query_row(
            "SELECT input_tokens, cached_tokens, is_subagent, is_handoff, repo_id
             FROM sessions WHERE session_id = 'antigravity:main-conv'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();
    assert_eq!(in_tok, 5000);
    assert_eq!(cache_tok, 40000);
    assert_eq!(is_sub, 0);
    assert_eq!(is_handoff, 1);
    assert!(repo_id.is_some());

    // 2. Subagent session detected via absence of USER_INPUT
    let sub_flag: i64 = conn
        .query_row(
            "SELECT is_subagent FROM sessions WHERE session_id = 'antigravity:sub-conv'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(sub_flag, 1);

    // 3. Quoted mise command parsed as cmd_bin=mise, is_repo_cli=1, piped_filter=head -n, masked exit=1, clean stderr
    let (cmd_bin, is_cli, piped, exit_code, stderr_prev): (
        String,
        i64,
        Option<String>,
        Option<i64>,
        Option<String>,
    ) = conn
        .query_row(
            "SELECT cmd_bin, is_repo_cli, piped_filter, exit_code, stderr_preview
             FROM command_spans WHERE session_id = 'antigravity:main-conv' AND cmd_bin = 'mise'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();
    assert_eq!(cmd_bin, "mise");
    assert_eq!(is_cli, 1);
    assert_eq!(piped.as_deref(), Some("head -n"));
    assert_eq!(exit_code, Some(1));
    assert!(
        stderr_prev
            .as_deref()
            .unwrap_or("")
            .contains("sqlite3.OperationalError: no such column: status")
    );

    // 4. MCP error detected with clean preview (no `Created At:` noise)
    let (is_err, err_prev): (i64, Option<String>) = conn
        .query_row(
            "SELECT is_error, error_preview FROM tool_calls
             WHERE session_id = 'antigravity:main-conv' AND tool_name = 'mcp:t3-code:pull_request_list'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(is_err, 1);
    assert_eq!(
        err_prev.as_deref(),
        Some("No GitHub credential on the server. Set GH_TOKEN.")
    );

    // 5. File reads unquoted (`cards.rs` without trailing `"`) and step spill normalized to `steps/output.txt`
    let read_names: Vec<String> = conn
        .prepare("SELECT target_name FROM file_reads ORDER BY target_name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .flatten()
        .collect();
    assert!(read_names.contains(&"cards.rs".to_string()));
    assert!(read_names.contains(&"steps/output.txt".to_string()));
    assert!(!read_names.iter().any(|n| n.ends_with('"')));
}

#[test]
fn regression_fixes_tool_errors_codex_steps_kimi_pruning_rebounds_and_inspect() {
    use bottledeck::adapters::detect_tool_error;
    use bottledeck::workspace::is_ephemeral_or_neutral_path;

    // 1. detect_tool_error must not false-positive on JS `setTimeout` in file reads or `--timeout` in JSON
    let read_with_set_timeout = "Created At: 2026-11-26T16:22:15+01:00\nCompleted At: 2026-11-26T16:22:16+01:00\nShowing lines 1-10 of 10\n5: import {setTimeout as delay} from 'node:timers/promises';";
    assert!(!detect_tool_error(read_with_set_timeout, false));
    let followup_json =
        r#"{"followup":{"check":"Run mise run ci:status -- --wait --timeout 900"}}"#;
    assert!(!detect_tool_error(followup_json, false));
    assert!(detect_tool_error(
        "Preview automation evaluate timed out after 15000ms.",
        false
    ));
    assert!(detect_tool_error(
        r#"{"_tag":"OrchestratorMcpFailure","code":"invalid_request"}"#,
        false
    ));

    // 2. Neutral/scratch workspaces are filtered
    assert!(is_ephemeral_or_neutral_path(
        "/Users/alice/Library/Application Support/Claude/scratch-workspaces/a/b/scratch-2026-11-25-e8046e"
    ));
    assert!(is_ephemeral_or_neutral_path(
        "/Users/alice/Documents/Codex/2026-11-26/rec"
    ));
    assert!(is_ephemeral_or_neutral_path(
        "/Users/alice/.local/state/quine-host/workspaces/kimi/tasks/x/work"
    ));

    let tmp = fixture_tmp();
    let repo_dir = tmp.path().join("reg-repo");
    fs::create_dir_all(&repo_dir).unwrap();
    Command::new("git")
        .args(["init", "-q"])
        .current_dir(&repo_dir)
        .status()
        .unwrap();
    Command::new("git")
        .args([
            "remote",
            "add",
            "origin",
            "https://github.com/acme/reg-repo.git",
        ])
        .current_dir(&repo_dir)
        .status()
        .unwrap();
    fs::write(
        repo_dir.join("package.json"),
        r#"{"name":"reg-repo","scripts":{"dev":"vite","unused-script":"echo hi","test":"vitest"}}"#,
    )
    .unwrap();
    let repo_str = repo_dir.to_string_lossy().to_string();

    let codex_root = tmp.path().join("codex");
    let kimi_root = tmp.path().join("kimi");
    let agy_root = tmp.path().join("agy");
    fs::create_dir_all(codex_root.join("2026")).unwrap();
    fs::create_dir_all(kimi_root.join("wd/session_k_err/agents/main")).unwrap();
    fs::create_dir_all(agy_root.join("brain/compact-only/.system_generated/logs")).unwrap();

    let now = Utc::now().timestamp_millis();
    let t0 = now - 3_600_000;
    let iso = |ms: i64| {
        chrono::DateTime::from_timestamp_millis(ms)
            .unwrap()
            .to_rfc3339()
    };

    // 3. Codex session: single `turn_context` with multiple LLM steps, compaction, shell file read,
    // mixed JS `exec` (quineos_connections + exec_command), and normal `git status` after CLI task.
    let codex_file = codex_root.join("2026/cx-reg.jsonl");
    let codex_lines = [
        serde_json::json!({
            "type": "session_meta",
            "timestamp": iso(t0),
            "payload": {"id": "cx-reg-1", "cwd": repo_str, "originator": "T3 Code", "source": "cli"}
        }),
        serde_json::json!({
            "type": "turn_context",
            "timestamp": iso(t0 + 100),
            "payload": {"cwd": repo_str, "model": "gpt-5-codex"}
        }),
        serde_json::json!({
            "type": "compacted",
            "timestamp": iso(t0 + 200),
            "payload": {"message": ""}
        }),
        serde_json::json!({
            "type": "token_usage_record",
            "timestamp": iso(t0 + 300),
            "payload": {"thread_token_usage": {"input_tokens": 1000000, "cached_input_tokens": 900000, "output_tokens": 5000}}
        }),
        // Step 1: mixed JS exec calling tools.quineos_connections + tools.exec_command
        serde_json::json!({
            "type": "response_item",
            "timestamp": iso(t0 + 1000),
            "payload": {
                "type": "custom_tool_call",
                "call_id": "c_mix",
                "name": "exec",
                "input": "text(await tools.quineos_connections({}));\ntext(await tools.exec_command({cmd:\"npm run test\"}));"
            }
        }),
        serde_json::json!({
            "type": "response_item",
            "timestamp": iso(t0 + 2000),
            "payload": {
                "type": "custom_tool_call_output",
                "call_id": "c_mix",
                "output": format!(
                    "Script completed\nWall time 1.2 seconds\nOutput:\n{}\n{}",
                    r#"{"as_of":"2026-11-26","connections":[{"huge":"payload"}]}"#,
                    r#"{"chunk_id":"abc123","wall_time_seconds":0.4,"exit_code":0,"output":"all tests passed"}"#
                )
            }
        }),
        // Step 2: normal git status right after npm run test -> MUST NOT count as escape-hatch rebound
        serde_json::json!({
            "type": "response_item",
            "timestamp": iso(t0 + 3000),
            "payload": {"type": "function_call", "call_id": "c_git", "name": "exec_command", "arguments": "{\"cmd\":\"git status --short\"}"}
        }),
        serde_json::json!({
            "type": "response_item",
            "timestamp": iso(t0 + 3500),
            "payload": {"type": "function_call_output", "call_id": "c_git", "output": "Exit code: 0\nM src/app.ts"}
        }),
        // Step 3: shell file read via `sed -n` -> populates `file_reads` for Codex!
        serde_json::json!({
            "type": "response_item",
            "timestamp": iso(t0 + 4000),
            "payload": {"type": "function_call", "call_id": "c_sed", "name": "exec_command", "arguments": "{\"cmd\":\"sed -n '1,40p' README.md\"}"}
        }),
        serde_json::json!({
            "type": "response_item",
            "timestamp": iso(t0 + 4500),
            "payload": {"type": "function_call_output", "call_id": "c_sed", "output": "Exit code: 0\n# Reg Repo"}
        }),
    ];
    fs::write(
        &codex_file,
        codex_lines
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    // 4. Kimi session with `token_counting.turn_recorded` fallback and HTTP 502 `turn.ended` failure
    fs::write(
        kimi_root.join("wd/session_k_err/state.json"),
        serde_json::json!({"id": "session_k_err", "cwd": repo_str, "createdAt": t0 + 5000})
            .to_string(),
    )
    .unwrap();
    let kimi_lines = [
        serde_json::json!({"type": "context.append_loop_event", "event": {"type": "step.begin", "turnId": "0", "step": 1}, "time": t0 + 5100}),
        serde_json::json!({"type": "turn.ended", "turnId": 0, "reason": "failed", "error": {"code": "provider.api_error", "details": {"statusCode": 502}}, "durationMs": 12000, "time": t0 + 17100}),
        serde_json::json!({"type": "token_counting.turn_recorded", "turnId": 0, "tokens": 4200, "time": t0 + 17101}),
    ];
    fs::write(
        kimi_root.join("wd/session_k_err/agents/main/wire.jsonl"),
        kimi_lines
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    // 5. Compact-only Antigravity log with `truncated_fields: ["content"]` must NOT falsely flag read_file as truncated
    let agy_compact = agy_root.join("brain/compact-only/.system_generated/logs/transcript.jsonl");
    let agy_lines = [
        serde_json::json!({"type": "USER_INPUT", "created_at": iso(t0 + 20000), "content": "check file"}),
        serde_json::json!({
            "step_index": 1,
            "type": "PLANNER_RESPONSE",
            "created_at": iso(t0 + 20100),
            "model": "gemini-4",
            "input_tokens": 1000,
            "cache_read_tokens": 5000,
            "output_tokens": 100,
            "tool_calls": [{"name": "read_file", "args": {"Path": format!("\"{repo_str}/package.json\"")}}]
        }),
        serde_json::json!({
            "type": "GENERIC",
            "created_at": iso(t0 + 20200),
            "truncated_fields": ["content"],
            "content": "Showing lines 1-20 of 20\n... <truncated 500 chars>"
        }),
    ];
    fs::write(
        &agy_compact,
        agy_lines
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    let mut conn = open_db(&tmp.path().join("ledger.db")).unwrap();
    let roots = AdapterRoots {
        claude: vec![],
        codex: vec![codex_root],
        antigravity: vec![agy_root],
        kimi: vec![kimi_root],
        spans: tmp.path().join("spans.jsonl"),
    };
    let stats = sync_all(&mut conn, &roots, false).unwrap();
    assert_eq!(stats.sessions_upserted, 3);

    // Verify Codex LLM-step turn_count=3 (not 1!), is_handoff=1, file_reads populated, mixed exec unwrapped
    let (cx_turns, cx_handoff): (i64, i64) = conn
        .query_row(
            "SELECT turn_count, is_handoff FROM sessions WHERE session_id = 'codex:cx-reg-1'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(cx_turns, 3);
    assert_eq!(cx_handoff, 1);

    let (npm_toks, npm_ec): (i64, Option<i64>) = conn
        .query_row(
            "SELECT stdout_tokens, exit_code FROM command_spans WHERE session_id = 'codex:cx-reg-1' AND cmd_template = 'npm run test'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(npm_ec, Some(0));
    assert!(
        npm_toks < 20,
        "expected unwrapped chunk output, got {npm_toks} toks"
    );

    let q_conn_cnt: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM tool_calls WHERE session_id = 'codex:cx-reg-1' AND tool_name = 'quineos_connections'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(q_conn_cnt, 1);

    let codex_reads: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM file_reads WHERE session_id = 'codex:cx-reg-1' AND target_name = 'README.md'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(codex_reads, 1);

    // Verify Kimi token_counting fallback + kimi:api_error
    let kimi_in: i64 = conn
        .query_row(
            "SELECT input_tokens FROM sessions WHERE session_id = 'kimi:session_k_err'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(kimi_in, 4200);
    let kimi_api_errs: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM tool_calls WHERE session_id = 'kimi:session_k_err' AND tool_name = 'kimi:api_error' AND is_error = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(kimi_api_errs, 1);

    // Verify Antigravity compact-log truncation does NOT mark read_file as truncated
    let agy_trunc: i64 = conn
        .query_row(
            "SELECT is_truncated FROM tool_calls WHERE session_id = 'antigravity:compact-only' AND tool_name = 'read_file'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(agy_trunc, 0);

    // Verify normal `git status` after `npm run test` did NOT trigger rebound, and 0-call package.json script appears in underused_surfaces
    let range_14d = TimeRange::from_window(Some(14 * 86_400_000), "14d");
    let rep = analyze_repo(&conn, "github.com/acme/reg-repo", &range_14d, 10).unwrap();
    assert_eq!(rep.kpis.escape_hatch_rebound_rate, 0.0);

    let pat =
        analyze_cross_session_patterns(&conn, "github.com/acme/reg-repo", &range_14d).unwrap();
    assert!(
        pat.underused_surfaces
            .iter()
            .any(|u| u.surface_kind == "repo_task"
                && u.name == "unused-script"
                && u.observed_calls == 0),
        "expected 0-call package.json script in underused_surfaces: {:?}",
        pat.underused_surfaces
    );

    // Verify deleted transcript files are pruned on next sync
    fs::remove_file(&agy_compact).unwrap();
    sync_all(&mut conn, &roots, false).unwrap();
    let remaining: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sessions WHERE session_id = 'antigravity:compact-only'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(remaining, 0);
}

#[test]
fn shell_parser_loops_wrappers_exit_codes_and_parallel_intervals() {
    use bottledeck::adapters::{SpanBuildArgs, build_command_spans, merge_intervals_ms};
    use bottledeck::shell::extract_exit_code_from_text;
    use bottledeck::workspace::WorkspaceResolver;

    // 1. Loop body is preserved instead of dropped
    let loop_segs = split_shell_commands("for f in a b; do cargo test --lib; done");
    assert!(
        loop_segs
            .iter()
            .filter_map(|s| parse_command_tokens(&s.tokens, &s.raw))
            .any(|p| p.cmd_bin == "cargo" && p.cmd_template.starts_with("cargo test")),
        "expected cargo test inside loop body, got: {loop_segs:?}"
    );

    // 2. `bash -c` + `timeout -s KILL 30` unwrapped and script basename preserved
    let wrap_segs =
        split_shell_commands("bash -c 'timeout -s KILL 30 python3 scripts/deploy.py --dry-run'");
    assert_eq!(wrap_segs.len(), 1);
    let parsed = parse_command_tokens(&wrap_segs[0].tokens, &wrap_segs[0].raw).unwrap();
    assert_eq!(parsed.cmd_bin, "python3");
    assert!(
        parsed.cmd_template.contains("deploy.py"),
        "expected script basename preserved, got: {}",
        parsed.cmd_template
    );

    // 3. `make test || true` with overall exit 0 must NOT falsely infer exit_code=Some(0) on `make test`
    let mut resolver = WorkspaceResolver::new(None);
    let built = build_command_spans(
        SpanBuildArgs {
            command_line: "make test || true",
            session_id: Some("s1".into()),
            source_file: "test.jsonl",
            source_kind: "claude",
            agent_kind: "claude-code",
            tool_call_id: None,
            turn_idx: 1,
            base_seq_idx: 0,
            base_cwd: None,
            exit_code: Some(0),
            duration_ms: Some(1200),
            is_explicit_duration: true,
            interrupted: false,
            stdout_text: "ok",
            stderr_text: "",
            started_at: 1_700_000_000_000,
        },
        &mut resolver,
    );
    let make_span = built.iter().find(|s| s.cmd_bin == "make").unwrap();
    assert!(make_span.is_chained);
    assert_eq!(
        make_span.exit_code, None,
        "LHS of `||` must not be inferred as exit 0"
    );

    // 4. Mid-log text containing "exit code 1" must NOT override structured head/tail "exited with code 0"
    let passing_log = (0..30)
        .map(|i| {
            if i == 15 {
                "test parser::handles_exit_code_1 ... ok\nexit code 1 test passed"
            } else {
                "test suite::case ... ok"
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let wrapped_ok = format!("Command exited with code 0.\n{passing_log}");
    assert_eq!(extract_exit_code_from_text(&wrapped_ok, false), 0);

    // 5. Parallel tool wall-clock interval merging
    let merged_ms = merge_intervals_ms(&[(1_000, 2_000), (1_200, 2_200), (3_000, 3_500)]);
    assert_eq!(merged_ms, 1700);
}

#[test]
fn advanced_telemetry_latency_tokens_trajectories_churn_and_diff() {
    let tmp = fixture_tmp();
    let repo_a = tmp.path().join("alpha-repo");
    let repo_b = tmp.path().join("beta-repo");
    fs::create_dir_all(repo_a.join("src")).unwrap();
    fs::create_dir_all(repo_b.join("src")).unwrap();
    fs::write(repo_a.join("src/engine.rs"), "pub fn run() {}\n").unwrap();
    fs::write(repo_b.join("src/lib.rs"), "pub fn b() {}\n").unwrap();

    for (dir, remote) in [
        (&repo_a, "https://github.com/acme/alpha-repo.git"),
        (&repo_b, "https://github.com/acme/beta-repo.git"),
    ] {
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(dir)
            .status()
            .unwrap();
        Command::new("git")
            .args(["remote", "add", "origin", remote])
            .current_dir(dir)
            .status()
            .unwrap();
    }
    let repo_a_str = repo_a.to_string_lossy().to_string();
    let repo_b_str = repo_b.to_string_lossy().to_string();

    let claude_root = tmp.path().join("claude");
    let codex_root = tmp.path().join("codex");
    let kimi_root = tmp.path().join("kimi");
    fs::create_dir_all(claude_root.join("proj/subagents")).unwrap();
    fs::create_dir_all(codex_root.join("2026")).unwrap();
    fs::create_dir_all(kimi_root.join("wd/k_sess/agents/main")).unwrap();

    let now = Utc::now().timestamp_millis();
    let t0 = now - 3_600_000;
    let iso = |ms: i64| {
        chrono::DateTime::from_timestamp_millis(ms)
            .unwrap()
            .to_rfc3339()
    };

    // 1. Claude session 1: cache_write separation, thinking tokens, cost-state, compact_boundary,
    // api_error, Edit -> fail -> Edit rework cycle, interrupted turn, cross-repo `cd` into beta-repo
    let claude_s1 = [
        serde_json::json!({
            "type": "user",
            "sessionId": "cl-adv-1",
            "cwd": repo_a_str,
            "turnOrigin": "user",
            "timestamp": iso(t0),
            "message": {"content": "Fix engine.rs"}
        }),
        serde_json::json!({
            "type": "assistant",
            "sessionId": "cl-adv-1",
            "cwd": repo_a_str,
            "effort": "high",
            "thinkingDurationMs": 2500,
            "timestamp": iso(t0 + 3000),
            "message": {
                "id": "m1",
                "model": "claude-opus-4-6",
                "stop_reason": "tool_use",
                "usage": {
                    "input_tokens": 2000,
                    "cache_creation_input_tokens": 8000,
                    "cache_read_input_tokens": 40000,
                    "output_tokens": 500,
                    "output_tokens_details": {"thinking_tokens": 1200}
                },
                "content": [
                    {"type": "tool_use", "id": "t_read", "name": "Read", "input": {"file_path": format!("{repo_a_str}/src/engine.rs")}},
                    {"type": "tool_use", "id": "t_edit1", "name": "Edit", "input": {"file_path": format!("{repo_a_str}/src/engine.rs"), "old_string": "a", "new_string": "b"}}
                ]
            }
        }),
        serde_json::json!({
            "type": "user",
            "sessionId": "cl-adv-1",
            "cwd": repo_a_str,
            "timestamp": iso(t0 + 3500),
            "toolUseResult": {"filePath": format!("{repo_a_str}/src/engine.rs"), "durationMs": 50},
            "message": {"content": [{"type": "tool_result", "tool_use_id": "t_read", "content": "pub fn run() {}"}]}
        }),
        serde_json::json!({
            "type": "user",
            "sessionId": "cl-adv-1",
            "cwd": repo_a_str,
            "timestamp": iso(t0 + 4000),
            "toolUseResult": {
                "filePath": format!("{repo_a_str}/src/engine.rs"),
                "durationMs": 60,
                "structuredPatch": [{"lines": ["+added line", "-removed line"]}]
            },
            "message": {"content": [{"type": "tool_result", "tool_use_id": "t_edit1", "content": "ok"}]}
        }),
        serde_json::json!({
            "type": "assistant",
            "sessionId": "cl-adv-1",
            "cwd": repo_a_str,
            "timestamp": iso(t0 + 5000),
            "message": {
                "id": "m2",
                "model": "claude-opus-4-6",
                "usage": {"input_tokens": 1000, "cache_creation_input_tokens": 2000, "cache_read_input_tokens": 47000, "output_tokens": 300},
                "content": [{"type": "tool_use", "id": "t_test", "name": "Bash", "input": {"command": "cargo test"}}]
            }
        }),
        serde_json::json!({
            "type": "user",
            "sessionId": "cl-adv-1",
            "cwd": repo_a_str,
            "timestamp": iso(t0 + 7000),
            "toolUseResult": {"exitCode": 1, "durationMs": 2000, "stderr": "assertion failed"},
            "message": {"content": [{"type": "tool_result", "tool_use_id": "t_test", "is_error": true, "content": "assertion failed"}]}
        }),
        serde_json::json!({
            "type": "assistant",
            "sessionId": "cl-adv-1",
            "cwd": repo_a_str,
            "timestamp": iso(t0 + 8000),
            "message": {
                "id": "m3",
                "model": "claude-opus-4-6",
                "usage": {"input_tokens": 1000, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 49000, "output_tokens": 200},
                "content": [
                    {"type": "tool_use", "id": "t_edit2", "name": "Edit", "input": {"file_path": format!("{repo_a_str}/src/engine.rs"), "old_string": "b", "new_string": "c"}},
                    {"type": "tool_use", "id": "t_beta", "name": "Bash", "input": {"command": format!("cd {repo_b_str} && cargo check")}}
                ]
            }
        }),
        serde_json::json!({
            "type": "user",
            "sessionId": "cl-adv-1",
            "cwd": repo_a_str,
            "timestamp": iso(t0 + 8500),
            "toolUseResult": {"filePath": format!("{repo_a_str}/src/engine.rs"), "durationMs": 40},
            "message": {"content": [{"type": "tool_result", "tool_use_id": "t_edit2", "content": "ok"}]}
        }),
        serde_json::json!({
            "type": "user",
            "sessionId": "cl-adv-1",
            "cwd": repo_a_str,
            "timestamp": iso(t0 + 9500),
            "toolUseResult": {"exitCode": 0, "durationMs": 900, "interrupted": true, "stdout": "ok"},
            "message": {"content": [{"type": "tool_result", "tool_use_id": "t_beta", "content": "ok"}]}
        }),
        serde_json::json!({"type": "system", "subtype": "compact_boundary", "sessionId": "cl-adv-1", "timestamp": iso(t0 + 10000)}),
        serde_json::json!({"type": "system", "subtype": "api_error", "sessionId": "cl-adv-1", "timestamp": iso(t0 + 10500)}),
        serde_json::json!({
            "type": "cost-state",
            "sessionId": "cl-adv-1",
            "timestamp": iso(t0 + 12000),
            "totalCostUSD": 0.42,
            "totalAPIDuration": 9500,
            "totalAPIDurationWithoutRetries": 8000,
            "totalLinesAdded": 18,
            "totalLinesRemoved": 5
        }),
    ];
    fs::write(
        claude_root.join("proj/cl-adv-1.jsonl"),
        claude_s1
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    // Claude subagent linked to cl-adv-1
    let claude_sub = [serde_json::json!({
        "type": "assistant",
        "sessionId": "cl-adv-1",
        "isSidechain": true,
        "cwd": repo_a_str,
        "timestamp": iso(t0 + 6000),
        "message": {
            "id": "sub1",
            "model": "claude-haiku-4-5",
            "usage": {"input_tokens": 500, "cache_creation_input_tokens": 500, "cache_read_input_tokens": 9000, "output_tokens": 100},
            "content": [{"type": "text", "text": "done"}]
        }
    })];
    fs::write(
        claude_root.join("proj/subagents/agent-sub1.jsonl"),
        claude_sub
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    // 2. Claude session 2: repeats `read:*.rs -> edit:*.rs -> cargo test` trajectory + edits engine.rs
    let claude_s2 = [
        serde_json::json!({
            "type": "assistant",
            "sessionId": "cl-adv-2",
            "cwd": repo_a_str,
            "timestamp": iso(t0 + 20_000),
            "message": {
                "id": "m21",
                "model": "claude-sonnet-4-6",
                "usage": {"input_tokens": 1500, "cache_creation_input_tokens": 500, "cache_read_input_tokens": 18000, "output_tokens": 250},
                "content": [
                    {"type": "tool_use", "id": "s2_r", "name": "Read", "input": {"file_path": format!("{repo_a_str}/src/engine.rs")}},
                    {"type": "tool_use", "id": "s2_e", "name": "Edit", "input": {"file_path": format!("{repo_a_str}/src/engine.rs"), "old_string": "c", "new_string": "d"}},
                    {"type": "tool_use", "id": "s2_t", "name": "Bash", "input": {"command": "cargo test"}}
                ]
            }
        }),
        serde_json::json!({"type": "user", "sessionId": "cl-adv-2", "cwd": repo_a_str, "timestamp": iso(t0 + 20_500), "message": {"content": [{"type": "tool_result", "tool_use_id": "s2_r", "content": "ok"}]}}),
        serde_json::json!({"type": "user", "sessionId": "cl-adv-2", "cwd": repo_a_str, "timestamp": iso(t0 + 21_000), "message": {"content": [{"type": "tool_result", "tool_use_id": "s2_e", "content": "ok"}]}}),
        serde_json::json!({"type": "user", "sessionId": "cl-adv-2", "cwd": repo_a_str, "timestamp": iso(t0 + 22_500), "toolUseResult": {"exitCode": 0, "durationMs": 1400, "stdout": "ok"}, "message": {"content": [{"type": "tool_result", "tool_use_id": "s2_t", "content": "ok"}]}}),
    ];
    fs::write(
        claude_root.join("proj/cl-adv-2.jsonl"),
        claude_s2
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    // 3. Codex session with item_completed exact durations, task_complete TTFT, token_count llm_calls,
    // reasoning_output_tokens, ContextCompaction, turn_aborted, FileChange edit
    let codex_adv = [
        serde_json::json!({
            "type": "session_meta",
            "timestamp": iso(t0 + 30_000),
            "payload": {"id": "cx-adv-1", "cwd": repo_a_str, "originator": "codex-cli", "source": "cli", "git": {"branch": "feat/perf"}}
        }),
        serde_json::json!({
            "type": "turn_context",
            "timestamp": iso(t0 + 30_100),
            "payload": {"cwd": repo_a_str, "model": "gpt-5-codex", "reasoning_effort": "high"}
        }),
        serde_json::json!({
            "type": "event_msg",
            "timestamp": iso(t0 + 31_000),
            "payload": {
                "type": "token_count",
                "info": {
                    "model_context_window": 200_000,
                    "total_token_usage": {
                        "input_tokens": 180_000,
                        "cached_input_tokens": 150_000,
                        "output_tokens": 4_000,
                        "reasoning_output_tokens": 1_500
                    },
                    "last_token_usage": {
                        "input_tokens": 170_000,
                        "cached_input_tokens": 150_000,
                        "output_tokens": 4_000,
                        "reasoning_output_tokens": 1_500
                    }
                }
            }
        }),
        serde_json::json!({
            "type": "response_item",
            "timestamp": iso(t0 + 31_200),
            "payload": {"type": "function_call", "call_id": "cx_cmd1", "name": "exec_command", "arguments": "{\"cmd\":\"cargo test\"}"}
        }),
        serde_json::json!({
            "type": "response_item",
            "timestamp": iso(t0 + 34_000),
            "payload": {"type": "function_call_output", "call_id": "cx_cmd1", "output": "Exit code: 0\nall passed"}
        }),
        serde_json::json!({
            "type": "event_msg",
            "timestamp": iso(t0 + 34_050),
            "payload": {
                "type": "item_completed",
                "item": {"id": "cx_cmd1", "type": "CommandExecution", "started_at_ms": t0 + 31_200, "completed_at_ms": t0 + 33_900}
            }
        }),
        serde_json::json!({
            "type": "event_msg",
            "timestamp": iso(t0 + 34_500),
            "payload": {
                "type": "item_completed",
                "item": {
                    "id": "fc_item_1",
                    "type": "FileChange",
                    "changes": [{"path": format!("{repo_a_str}/src/engine.rs"), "diff": "+line1\n+line2\n-old1"}]
                }
            }
        }),
        serde_json::json!({
            "type": "event_msg",
            "timestamp": iso(t0 + 34_800),
            "payload": {"type": "item_completed", "item": {"type": "ContextCompaction"}}
        }),
        serde_json::json!({
            "type": "event_msg",
            "timestamp": iso(t0 + 35_000),
            "payload": {"type": "task_complete", "duration_ms": 4200, "time_to_first_token_ms": 620}
        }),
        serde_json::json!({
            "type": "event_msg",
            "timestamp": iso(t0 + 36_000),
            "payload": {"type": "turn_aborted"}
        }),
    ];
    fs::write(
        codex_root.join("2026/cx-adv.jsonl"),
        codex_adv
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    // 4. Kimi session with cache_write + Read tool recorded in BOTH tool_calls and file_reads
    let kimi_state = kimi_root.join("wd/k_sess/state.json");
    fs::write(
        &kimi_state,
        serde_json::json!({"id": "k_sess", "cwd": repo_a_str, "createdAt": t0 + 40_000})
            .to_string(),
    )
    .unwrap();
    let kimi_wire = [
        serde_json::json!({"type": "llm.request", "model": "kimi-k2", "thinkingEffort": "medium", "time": t0 + 40_100}),
        serde_json::json!({"type": "context.append_loop_event", "event": {"type": "step.begin", "turnId": "0", "step": 1}, "time": t0 + 40_200}),
        serde_json::json!({"type": "context.append_loop_event", "event": {"type": "tool.call", "toolCallId": "kr1", "name": "Read", "args": {"file_path": format!("{repo_a_str}/src/engine.rs")}}, "time": t0 + 40_300}),
        serde_json::json!({"type": "context.append_loop_event", "event": {"type": "tool.result", "toolCallId": "kr1", "result": {"output": "pub fn run() {}"}}, "time": t0 + 40_400}),
        serde_json::json!({"type": "usage.record", "model": "kimi-k2", "usage": {"inputOther": 1000, "inputCacheCreation": 3000, "inputCacheRead": 16000, "output": 200}, "time": t0 + 40_800}),
    ];
    fs::write(
        kimi_root.join("wd/k_sess/agents/main/wire.jsonl"),
        kimi_wire
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    // 5. Wrap spans.jsonl containing an unprefixed duplicate of cl-adv-1's `cargo test`
    let spans_path = tmp.path().join("spans.jsonl");
    fs::write(
        &spans_path,
        format!(
            "{}\n",
            serde_json::json!({
                "ts": t0 + 5050,
                "cwd": repo_a_str,
                "session_id": "cl-adv-1",
                "agent_kind": "claude-code",
                "cmd": "cargo test",
                "exit_code": 1,
                "duration_ms": 2010,
                "stdout_bytes": 40
            })
        ),
    )
    .unwrap();

    let mut conn = open_db(&tmp.path().join("ledger.db")).unwrap();
    let roots = AdapterRoots {
        claude: vec![claude_root],
        codex: vec![codex_root],
        antigravity: vec![],
        kimi: vec![kimi_root],
        spans: spans_path,
    };
    let stats = sync_all(&mut conn, &roots, false).unwrap();
    assert!(
        stats.llm_calls_inserted >= 4,
        "expected llm_calls persisted"
    );

    // Verify Claude session columns
    let (cw, think, api_ms, retry_ms, comp, aborts, api_errs, la, lr): (
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
    ) = conn
        .query_row(
            "SELECT cache_write_tokens, thinking_tokens, api_duration_ms, api_retry_ms,
                    compaction_count, aborted_turns, api_errors, lines_added, lines_removed
             FROM sessions WHERE session_id = 'claude:cl-adv-1'",
            [],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(cw, 10_000);
    assert_eq!(think, 1_200);
    assert_eq!(api_ms, 9_500);
    assert_eq!(retry_ms, 1_500);
    assert_eq!(comp, 1);
    assert_eq!(aborts, 1);
    assert_eq!(api_errs, 1);
    assert_eq!(la, 18);
    assert_eq!(lr, 5);

    // Verify Codex exact item_completed duration (2700ms), TTFT (620ms), reasoning tokens (1500), context window
    let (cx_dur, cx_ttft, cx_think, cx_win, cx_comp): (i64, i64, i64, Option<i64>, i64) = conn
        .query_row(
            "SELECT s.api_duration_ms, s.ttft_ms_sum, s.thinking_tokens, s.context_window, s.compaction_count
             FROM sessions s WHERE s.session_id = 'codex:cx-adv-1'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();
    assert_eq!(cx_dur, 4200);
    assert_eq!(cx_ttft, 620);
    assert_eq!(cx_think, 1500);
    assert_eq!(cx_win, Some(200_000));
    assert_eq!(cx_comp, 1);
    let cx_span_dur: Option<i64> = conn
        .query_row(
            "SELECT duration_ms FROM command_spans WHERE session_id = 'codex:cx-adv-1' AND cmd_template = 'cargo test'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(cx_span_dur, Some(2700));

    // Verify Kimi Read recorded in BOTH file_reads and tool_calls, and cache_write_tokens=3000
    let k_cw: i64 = conn
        .query_row(
            "SELECT cache_write_tokens FROM sessions WHERE session_id = 'kimi:k_sess'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(k_cw, 3000);
    let k_tc_reads: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM tool_calls WHERE session_id = 'kimi:k_sess' AND tool_name = 'Read'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(k_tc_reads, 1);

    // Verify cross-repo `cd beta-repo && cargo check` span is retained when analyzing beta-repo!
    let range_14d = TimeRange::from_window(Some(14 * 86_400_000), "14d");
    let beta_rep = analyze_repo(&conn, "github.com/acme/beta-repo", &range_14d, 10).unwrap();
    assert_eq!(
        beta_rep.kpis.total_commands, 1,
        "cross-repo cd span must not be dropped"
    );

    // Verify alpha-repo report & patterns: wrap span deduplicated, latency/cost/context/outcomes populated,
    // subagent rollup linked, model breakdown present, unified tool trajectory & file edit churn detected
    let alpha_rep = analyze_repo(&conn, "github.com/acme/alpha-repo", &range_14d, 10).unwrap();
    assert!(alpha_rep.kpis.estimated_cost_usd > 0.0);
    assert!(alpha_rep.kpis.latency.total_api_wait_s > 0.0);
    assert_eq!(alpha_rep.kpis.latency.avg_ttft_ms, Some(620));
    assert_eq!(alpha_rep.kpis.context_health.total_compactions, 2);
    assert_eq!(alpha_rep.kpis.outcomes.aborted_sessions, 2);
    // 3 transcript `cargo test` runs (wrap duplicate must be deduplicated!)
    let cargo_test = alpha_rep
        .top_commands
        .iter()
        .find(|c| c.cmd_template == "cargo test")
        .unwrap();
    assert_eq!(cargo_test.runs, 3);

    let alpha_pat =
        analyze_cross_session_patterns(&conn, "github.com/acme/alpha-repo", &range_14d).unwrap();
    let sub = alpha_pat
        .subagent_rollup
        .as_ref()
        .expect("expected subagent_rollup");
    assert_eq!(sub.linked_subagents, 1);
    assert_eq!(sub.parent_sessions_with_children, 1);
    assert!(
        alpha_pat
            .model_breakdown
            .iter()
            .any(|m| m.model == "claude-opus-4-6" && m.est_cost_usd > 0.0)
    );
    assert!(
        alpha_pat
            .tool_trajectories
            .iter()
            .any(|t| t.sequence.contains("read:*.rs") && t.sequence.contains("edit:*.rs")),
        "expected unified read->edit->test trajectory, got: {:?}",
        alpha_pat.tool_trajectories
    );
    let churn = alpha_pat
        .file_edit_churn
        .iter()
        .find(|f| f.target_path.ends_with("engine.rs"))
        .expect("expected engine.rs in file_edit_churn");
    assert!(churn.edits >= 4);
    assert!(churn.rework_cycles >= 1);

    // Verify diff_repo populates by_harness and new metrics
    let diff = diff_repo(&conn, "github.com/acme/alpha-repo", t0 + 25_000, "split").unwrap();
    assert!(!diff.by_harness.is_empty());
    assert!(diff.before.estimated_cost_usd > 0.0);

    // Verify opening a legacy pre-upgrade ledger DB migrates cleanly without index errors
    let legacy_path = tmp.path().join("legacy.db");
    {
        let raw_conn = rusqlite::Connection::open(&legacy_path).unwrap();
        raw_conn
            .execute_batch(
                "CREATE TABLE sessions (
                   session_id TEXT PRIMARY KEY,
                   agent_kind TEXT NOT NULL,
                   source_file TEXT NOT NULL,
                   repo_id TEXT,
                   started_at INTEGER
                 );
                 CREATE TABLE command_spans (
                   span_id TEXT PRIMARY KEY,
                   session_id TEXT,
                   source_file TEXT NOT NULL,
                   repo_id TEXT,
                   turn_idx INTEGER NOT NULL DEFAULT 0,
                   seq_idx INTEGER NOT NULL DEFAULT 0,
                   started_at INTEGER NOT NULL
                 );
                 CREATE TABLE file_reads (
                   read_id TEXT PRIMARY KEY,
                   session_id TEXT NOT NULL,
                   source_file TEXT NOT NULL,
                   repo_id TEXT,
                   started_at INTEGER NOT NULL
                 );
                 CREATE TABLE tool_calls (
                   call_id TEXT PRIMARY KEY,
                   session_id TEXT NOT NULL,
                   source_file TEXT NOT NULL,
                   repo_id TEXT,
                   turn_idx INTEGER NOT NULL DEFAULT 0,
                   started_at INTEGER NOT NULL
                 );",
            )
            .unwrap();
    }
    let migrated = open_db(&legacy_path).unwrap();
    let has_parent: i64 = migrated
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name = 'parent_session_id'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(has_parent, 1);
}
