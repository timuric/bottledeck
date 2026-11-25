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
use bottledeck::shell::{parse_command_tokens, redact_secrets, split_shell_commands};
use bottledeck::tui::{App, DetailTab, draw};
use bottledeck::workspace::{WorkspaceResolver, normalize_remote_url};
use chrono::Utc;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

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

    let tmp = TempDir::new().unwrap();
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
    let tmp = TempDir::new().unwrap();
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
    let claude_lines = vec![
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
    let codex_lines = vec![
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
    let agy_lines = vec![
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
    ] {
        app.tab = tab;
        terminal.draw(|f| draw(f, &mut app)).unwrap();
    }

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
    let tmp = TempDir::new().unwrap();
    let repo_dir = tmp.path().join("demo-app");
    fs::create_dir_all(&repo_dir).unwrap();
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
    let claude_main = vec![
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
    let claude_sub = vec![serde_json::json!({
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
