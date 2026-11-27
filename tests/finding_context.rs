//! Finding context: per-session episodes, polling shapes, and how the Insights tab renders them.

use bottledeck::analyze::analyze_repo;
use bottledeck::config::{TimeRange, adapter_roots};
use bottledeck::context::{LineRole, finding_context};
use bottledeck::db::open_db;
use bottledeck::tui::{App, draw};
use chrono::Utc;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use rusqlite::{Connection, params};
use tempfile::TempDir;

const REPO: &str = "github.com/acme/jobs";

fn insert_session(conn: &Connection, sid: &str, started: i64, turns: i64) {
    conn.execute(
        "INSERT INTO sessions (session_id, agent_kind, source_file, repo_id, repo_name, cwd,
                               started_at, ended_at, turn_count, user_turn_count)
         VALUES (?1, 'codex', ?2, ?3, 'acme/jobs', '/home/dev/code/acme-jobs', ?4, ?5, ?6, 1)",
        params![
            sid,
            format!("/tmp/{sid}.jsonl"),
            REPO,
            started,
            started + 600_000,
            turns
        ],
    )
    .unwrap();
}

#[allow(clippy::too_many_arguments)]
fn insert_span(
    conn: &Connection,
    sid: &str,
    turn: i64,
    ts: i64,
    bin: &str,
    template: &str,
    raw: &str,
    category: &str,
    exit: i64,
    stderr: Option<&str>,
) {
    conn.execute(
        "INSERT INTO command_spans (span_id, session_id, source_file, source_kind, agent_kind,
                                    turn_idx, seq_idx, repo_id, repo_name, category, is_repo_cli,
                                    cmd_bin, cmd_template, raw_redacted, exit_code, duration_ms,
                                    stderr_preview, started_at)
         VALUES (?1, ?2, ?3, 'transcript', 'codex', ?4, 0, ?5, 'acme/jobs', ?6, ?7, ?8, ?9, ?10,
                 ?11, 30000, ?12, ?13)",
        params![
            format!("{sid}-{turn}-{bin}"),
            sid,
            format!("/tmp/{sid}.jsonl"),
            turn,
            REPO,
            category,
            i64::from(bin == "mise"),
            bin,
            template,
            raw,
            exit,
            stderr,
            ts
        ],
    )
    .unwrap();
}

/// Two codex sessions that poll `mise run job wait` with `--timeout 1`, searching in between.
fn seed(conn: &Connection) {
    let now = Utc::now().timestamp_millis();
    for (s, sid) in ["codex:s1", "codex:s2"].iter().enumerate() {
        let base = now - 3_600_000 * (s as i64 + 1);
        insert_session(conn, sid, base, 40);
        let mut turn = 1;
        for job in ["build", "tests"] {
            insert_span(
                conn,
                sid,
                turn,
                base + turn * 1000,
                "mise",
                "mise run job start",
                &format!("mise run job -- start --name {job} --timeout 1"),
                "repo_task",
                0,
                None,
            );
            turn += 1;
            for attempt in 0..3 {
                insert_span(
                    conn,
                    sid,
                    turn,
                    base + turn * 1000,
                    "mise",
                    "mise run job wait",
                    &format!("mise run job -- wait {job} --timeout 1"),
                    "polling",
                    i64::from(attempt == 2),
                    (attempt == 2).then_some("job failed: 2 tests failed"),
                );
                turn += 1;
                insert_span(
                    conn,
                    sid,
                    turn,
                    base + turn * 1000,
                    "rg",
                    "rg <pattern>",
                    "rg -n 'fn main' src",
                    "exploration",
                    0,
                    None,
                );
                turn += 1;
            }
        }
    }
}

fn render(app: &mut App) -> String {
    let mut terminal = Terminal::new(TestBackend::new(160, 48)).unwrap();
    terminal.draw(|f| draw(f, app)).unwrap();
    let buf = terminal.backend().buffer().clone();
    (0..buf.area.height)
        .map(|y| {
            (0..buf.area.width)
                .map(|x| buf[(x, y)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn polling_finding_gets_episodes_shapes_and_contextual_ui() {
    let tmp = TempDir::new().unwrap();
    let mut conn = open_db(&tmp.path().join("ledger.db")).unwrap();
    seed(&conn);
    let range = TimeRange::from_window(Some(14 * 86_400_000), "14d");

    // Analyzer side: the finding exists and its context explains it.
    let report = analyze_repo(&conn, REPO, &range, 16).unwrap();
    let opp = report
        .opportunities
        .iter()
        .chain(report.harness_overhead.iter())
        .find(|o| o.kind == "polling_tax" && o.target == "mise run job wait")
        .expect("polling finding detected")
        .clone();
    let ctx = finding_context(&conn, REPO, &opp, &range, 5).unwrap();
    assert_eq!(ctx.affected_sessions, 2);
    assert_eq!(ctx.total_matches, 12);
    assert_eq!(ctx.episodes.len(), 2);
    let shape = ctx.dominant_shape().expect("a polling shape");
    assert_eq!(shape.key, "short_timeout");
    assert_eq!((shape.sessions, shape.calls), (2, 12));
    assert!(shape.fix.contains("timeouts under ~30s"));

    let ep = ctx.representative().unwrap();
    assert_eq!(ep.matched, 6);
    assert_eq!(ep.shape.as_deref(), Some("short_timeout"));
    let roles: Vec<LineRole> = ep.lines.iter().map(|l| l.role).collect();
    assert_eq!(
        roles[0],
        LineRole::Context,
        "the job start leads into the first wait"
    );
    assert!(ep.lines[0].text.contains("start --name build"));
    assert!(roles.contains(&LineRole::Gap) || roles.contains(&LineRole::Context));
    let repeats: Vec<usize> = ep
        .lines
        .iter()
        .filter(|l| l.role == LineRole::Match)
        .filter_map(|l| l.repeat)
        .collect();
    assert_eq!(
        repeats,
        vec![1, 2, 3, 1, 2, 3],
        "repeats of the same wait are counted"
    );
    assert!(
        ep.lines
            .iter()
            .any(|l| l.role == LineRole::Match && l.exit_code == Some(1) && l.stderr.is_some())
    );

    // TUI side: grouped list, context-first detail pane, episode drill-down.
    let mut app = App::load(&conn, "14d", Some(REPO)).unwrap();
    let before = render(&mut app);
    assert!(before.contains("loading session context"), "{before}");
    assert!(app.needs_context());
    assert!(app.prepare_context(&conn).unwrap());
    assert!(!app.needs_context());

    let screen = render(&mut app);
    for expected in [
        "▾ WAITING",
        "PROBLEM",
        "Polling loop",
        "mise run job wait",
        "COST IN CONTEXT",
        "of 2 sessions",
        "SHAPES",
        "Short-timeout retry",
        "EXAMPLE",
        "mise run job -- wait build --timeout 1",
        "← 2nd same call",
        "FIX  for shape A: Short-timeout retry",
        "Now 6.0 calls/session",
        "Enter: all 2 sessions",
    ] {
        assert!(
            screen.contains(expected),
            "missing `{expected}` in:\n{screen}"
        );
    }

    let roots = adapter_roots();
    app.handle_key(KeyCode::Enter, KeyModifiers::NONE, &mut conn, &roots)
        .unwrap();
    let modal = render(&mut app);
    assert!(modal.contains("Polling loop · mise run job wait — 2 sessions · 12 matches"));
    assert!(modal.contains("Tab / Shift-Tab"));
    assert!(!modal.contains("job failed: 2 tests failed"));

    app.handle_key(KeyCode::Char('e'), KeyModifiers::NONE, &mut conn, &roots)
        .unwrap();
    let with_errors = render(&mut app);
    assert!(with_errors.contains("↳ job failed: 2 tests failed"));

    app.handle_key(KeyCode::Tab, KeyModifiers::NONE, &mut conn, &roots)
        .unwrap();
    assert!(
        app.modal_scroll > 0,
        "Tab jumps to the first session episode"
    );
}
