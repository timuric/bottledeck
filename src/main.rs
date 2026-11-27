use anyhow::Result;
use bottledeck::analyze::issues::{
    add_marker, format_issues_report, list_markers, pick_issue_key, remove_marker,
    resolve_issue_ref, track_issues,
};
use bottledeck::analyze::{
    analyze_fleet, analyze_repo, diff_repo, format_compact, inspect_finding, list_repos,
    query_bypasses, query_commands, query_errors, resolve_repo_selector, resolve_time_point,
    resolve_time_range,
};
use bottledeck::config::{TimeRange, adapter_roots, db_path, parse_window_ms, state_dir};

/// Tag a time range's label with the harness filter so report headers say what was included.
fn with_harness(mut range: TimeRange, harness: Option<&str>) -> TimeRange {
    if let Some(h) = harness {
        range.label = format!("{} · {h} only", range.label);
    }
    range
}
use bottledeck::db::{apply_harness_filter, open_db};
use bottledeck::guide::{
    AGENT_GUIDE, SkillTarget, install_paths, installed_skill_version, skill_locations,
    skill_markdown, write_skill,
};
use bottledeck::ingest::sync_all;
use bottledeck::patterns::{
    analyze_cross_session_patterns, format_patterns_report, format_sequences_report,
    format_sessions_report, format_tools_report, query_sequences, query_tools, query_top_sessions,
};
use bottledeck::report::{
    format_bypasses_report, format_commands_report, format_diagnosis_prompt, format_diff_report,
    format_errors_report, format_fleet_report, format_inspect_report, format_repo_report,
};
use bottledeck::tui::run_tui;
use bottledeck::update::{CURRENT_VERSION, cached_available_update, run_self_update};
use bottledeck::wrap::run_wrapped_command;
use clap::{Parser, Subcommand};
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

const AFTER_HELP: &str = "Agents: run `bottledeck agent-guide` for workflows, time scoping, and how to read the output.\nInstall it as a Claude Code / Codex skill with `bottledeck agent-guide --install`.";

#[derive(Parser)]
#[command(
    name = "bottledeck",
    version,
    about = "Zero-touch multi-harness telemetry, Ratatui dashboard, and bottleneck analyzer for coding agents",
    after_help = AFTER_HELP
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
#[allow(clippy::enum_variant_names)]
enum Commands {
    /// Print the agent usage guide (or install it as a Claude Code / Codex skill)
    #[command(visible_alias = "guide")]
    AgentGuide {
        /// Install the guide as a skill (SKILL.md) for agent harnesses instead of printing it
        #[arg(long)]
        install: bool,
        /// Which harness to install for
        #[arg(long, value_enum, default_value = "all", requires = "install")]
        target: SkillTarget,
        /// Print the guide wrapped as a SKILL.md (frontmatter included)
        #[arg(long, conflicts_with = "install")]
        skill: bool,
    },
    /// Launch the interactive Ratatui dashboard
    Tui {
        /// Initial time window: 24h, 7d, 14d, 30d, 90d, all
        #[arg(long, default_value = "14d")]
        window: String,
        /// Repo to open: `.`, a path, owner/name, repo_id, or unique substring
        #[arg(long)]
        repo: Option<String>,
        /// Skip the transcript sync on start
        #[arg(long)]
        no_sync: bool,
    },
    /// Incrementally ingest local coding-agent transcripts and spans into the SQLite ledger
    Sync {
        /// Re-ingest every transcript, even unchanged ones (slow; use after upgrades that change parsing)
        #[arg(long)]
        force: bool,
        /// Print sync statistics as JSON
        #[arg(long)]
        json: bool,
    },
    /// Generate fleet-wide or per-repo reports (md, llm, prompt, json)
    Report {
        /// Fleet-wide report across all repos (the default when --repo is omitted)
        #[arg(long)]
        all: bool,
        /// Repo: `.`, a path, owner/name, repo_id, or unique substring (see `bottledeck repos`)
        #[arg(long)]
        repo: Option<String>,
        /// Trailing window: 24h, 7d, 2w, 30d, all [default: 14d, or all when --since/--until is set]
        #[arg(long)]
        window: Option<String>,
        /// Only sessions that started at or after this ISO date, relative duration (48h), or git commit/ref; no trailing window unless --window is given
        #[arg(long)]
        since: Option<String>,
        /// Only sessions that started strictly before this point (same formats); without --since/--window it covers all earlier history
        #[arg(long)]
        until: Option<String>,
        /// md: readable; llm: compact YAML brief; prompt: diagnosis bundle for a reviewing agent (per repo); json: full data
        #[arg(long, default_value = "md", value_parser = ["md", "llm", "prompt", "json"])]
        format: String,
        /// Include temp/fixture repos in the fleet report
        #[arg(long)]
        include_temp: bool,
        /// Only sessions from one harness, e.g. to compare like with like across a fix
        #[arg(long, value_parser = ["claude-code", "codex", "antigravity", "kimi"])]
        harness: Option<String>,
        /// Skip the transcript sync before querying (sync once, then pass this)
        #[arg(long)]
        no_sync: bool,
    },
    /// Drill into a finding (opp-N / h-N, an issue key, or a command template) with redacted trace samples
    Inspect {
        /// opp-N / h-N from `report` (use the same time flags), an issue key from `issues`, or a command template
        query: String,
        /// Repo: `.`, a path, owner/name, repo_id, or unique substring (see `bottledeck repos`)
        #[arg(long, default_value = ".")]
        repo: String,
        /// Trailing window: 24h, 7d, 2w, 30d, all [default: 14d, or all when --since/--until is set]
        #[arg(long)]
        window: Option<String>,
        /// Only sessions that started at or after this ISO date, relative duration (48h), or git commit/ref; no trailing window unless --window is given
        #[arg(long)]
        since: Option<String>,
        /// Only sessions that started strictly before this point (same formats); without --since/--window it covers all earlier history
        #[arg(long)]
        until: Option<String>,
        /// Number of trace samples to show
        #[arg(long, default_value_t = 5)]
        samples: usize,
        #[arg(long, default_value = "md", value_parser = ["md", "json"])]
        format: String,
        /// Only sessions from one harness, e.g. to compare like with like across a fix
        #[arg(long, value_parser = ["claude-code", "codex", "antigravity", "kimi"])]
        harness: Option<String>,
        /// Skip the transcript sync before querying (sync once, then pass this)
        #[arg(long)]
        no_sync: bool,
    },
    /// Track issues session by session: after a fix, do new sessions still hit it?
    Issues {
        /// One issue: key (e.g. "polling_tax:gh run view"), unique substring, or opp-N / h-N
        issue: Option<String>,
        /// Repo: `.`, a path, owner/name, repo_id, or unique substring (see `bottledeck repos`)
        #[arg(long, default_value = ".")]
        repo: String,
        /// Trailing window: 24h, 7d, 2w, 30d, all [default: 30d, or all when --since/--until is set]
        #[arg(long)]
        window: Option<String>,
        /// Only sessions that started at or after this ISO date, relative duration (48h), or git commit/ref; no trailing window unless --window is given
        #[arg(long)]
        since: Option<String>,
        /// Only sessions that started strictly before this point (same formats); without --since/--window it covers all earlier history
        #[arg(long)]
        until: Option<String>,
        /// Only issues that still need attention (regressed / new / active / unchanged / improved)
        #[arg(long)]
        open: bool,
        #[arg(long, default_value = "md", value_parser = ["md", "json"])]
        format: String,
        /// Only sessions from one harness, e.g. to compare like with like across a fix
        #[arg(long, value_parser = ["claude-code", "codex", "antigravity", "kimi"])]
        harness: Option<String>,
        /// Skip the transcript sync before querying (sync once, then pass this)
        #[arg(long)]
        no_sync: bool,
    },
    /// Record a fix point so sessions after it are compared with sessions before it
    Mark {
        /// Issue key, unique substring, or opp-N / h-N (omit together with --all)
        issue: Option<String>,
        /// Apply the marker to every issue in the repo (e.g. a harness upgrade)
        #[arg(long)]
        all: bool,
        /// When the fix landed: git commit/ref, ISO date, or relative duration (e.g. 2h)
        #[arg(long, default_value = "HEAD")]
        at: String,
        /// Free-text description of the fix
        #[arg(long)]
        note: Option<String>,
        /// Repo: `.`, a path, owner/name, repo_id, or unique substring (see `bottledeck repos`)
        #[arg(long, default_value = ".")]
        repo: String,
        /// List existing markers
        #[arg(long)]
        list: bool,
        /// Delete a marker by id
        #[arg(long)]
        remove: Option<i64>,
        /// Skip the transcript sync first
        #[arg(long)]
        no_sync: bool,
    },
    /// Compare sessions after a change (commit SHA, ref, or date) with a matched window before it
    Diff {
        /// The change point: git commit/ref, ISO date, or relative duration (e.g. 72h)
        #[arg(long)]
        since: String,
        /// Repo: `.`, a path, owner/name, repo_id, or unique substring (see `bottledeck repos`)
        #[arg(long, default_value = ".")]
        repo: String,
        #[arg(long, default_value = "md", value_parser = ["md", "json"])]
        format: String,
        /// Only sessions from one harness, e.g. to compare like with like across a fix
        #[arg(long, value_parser = ["claude-code", "codex", "antigravity", "kimi"])]
        harness: Option<String>,
        /// Skip the transcript sync before querying (sync once, then pass this)
        #[arg(long)]
        no_sync: bool,
    },
    /// List commands for a repo sorted by effective tokens, raw tokens, wait, runs, errors, or pipe-stripping
    Commands {
        /// Repo: `.`, a path, owner/name, repo_id, or unique substring (see `bottledeck repos`)
        #[arg(long, default_value = ".")]
        repo: String,
        /// Trailing window: 24h, 7d, 2w, 30d, all [default: 14d, or all when --since/--until is set]
        #[arg(long)]
        window: Option<String>,
        /// Only sessions that started at or after this ISO date, relative duration (48h), or git commit/ref; no trailing window unless --window is given
        #[arg(long)]
        since: Option<String>,
        /// Only sessions that started strictly before this point (same formats); without --since/--window it covers all earlier history
        #[arg(long)]
        until: Option<String>,
        /// effective: context cost; tokens: raw stdout; wait: wall time; runs; errors; pipes: output piped/filtered
        #[arg(long, default_value = "effective", value_parser = ["effective", "tokens", "wait", "runs", "errors", "pipes"])]
        sort: String,
        /// Only one command category
        #[arg(long, value_parser = ["exploration", "vcs_ci", "repo_task", "build_test", "polling", "package_mgr", "other"])]
        category: Option<String>,
        /// Maximum rows
        #[arg(long, default_value_t = 30)]
        limit: usize,
        #[arg(long, default_value = "md", value_parser = ["md", "json"])]
        format: String,
        /// Only sessions from one harness, e.g. to compare like with like across a fix
        #[arg(long, value_parser = ["claude-code", "codex", "antigravity", "kimi"])]
        harness: Option<String>,
        /// Skip the transcript sync before querying (sync once, then pass this)
        #[arg(long)]
        no_sync: bool,
    },
    /// Show recurring nonzero-exit command error clusters for a repo
    Errors {
        /// Repo: `.`, a path, owner/name, repo_id, or unique substring (see `bottledeck repos`)
        #[arg(long, default_value = ".")]
        repo: String,
        /// Trailing window: 24h, 7d, 2w, 30d, all [default: 14d, or all when --since/--until is set]
        #[arg(long)]
        window: Option<String>,
        /// Only sessions that started at or after this ISO date, relative duration (48h), or git commit/ref; no trailing window unless --window is given
        #[arg(long)]
        since: Option<String>,
        /// Only sessions that started strictly before this point (same formats); without --since/--window it covers all earlier history
        #[arg(long)]
        until: Option<String>,
        /// Maximum rows
        #[arg(long, default_value_t = 25)]
        limit: usize,
        #[arg(long, default_value = "md", value_parser = ["md", "json"])]
        format: String,
        /// Only sessions from one harness, e.g. to compare like with like across a fix
        #[arg(long, value_parser = ["claude-code", "codex", "antigravity", "kimi"])]
        harness: Option<String>,
        /// Skip the transcript sync before querying (sync once, then pass this)
        #[arg(long)]
        no_sync: bool,
    },
    /// Audit state-directory scrapes, CLI pipe-stripping, help tax, and raw tool bypasses
    Bypasses {
        /// Repo: `.`, a path, owner/name, repo_id, or unique substring (see `bottledeck repos`)
        #[arg(long, default_value = ".")]
        repo: String,
        /// Trailing window: 24h, 7d, 2w, 30d, all [default: 14d, or all when --since/--until is set]
        #[arg(long)]
        window: Option<String>,
        /// Only sessions that started at or after this ISO date, relative duration (48h), or git commit/ref; no trailing window unless --window is given
        #[arg(long)]
        since: Option<String>,
        /// Only sessions that started strictly before this point (same formats); without --since/--window it covers all earlier history
        #[arg(long)]
        until: Option<String>,
        #[arg(long, default_value = "md", value_parser = ["md", "json"])]
        format: String,
        /// Only sessions from one harness, e.g. to compare like with like across a fix
        #[arg(long, value_parser = ["claude-code", "codex", "antigravity", "kimi"])]
        harness: Option<String>,
        /// Skip the transcript sync before querying (sync once, then pass this)
        #[arg(long)]
        no_sync: bool,
    },
    /// Analyze cross-session longitudinal & systemic patterns (motifs, drift, harness asymmetry, cold starts, bloat drivers, burst storms)
    Patterns {
        /// Repo: `.`, a path, owner/name, repo_id, or unique substring (see `bottledeck repos`)
        #[arg(long, default_value = ".")]
        repo: String,
        /// Trailing window: 24h, 7d, 2w, 30d, all [default: 14d, or all when --since/--until is set]
        #[arg(long)]
        window: Option<String>,
        /// Only sessions that started at or after this ISO date, relative duration (48h), or git commit/ref; no trailing window unless --window is given
        #[arg(long)]
        since: Option<String>,
        /// Only sessions that started strictly before this point (same formats); without --since/--window it covers all earlier history
        #[arg(long)]
        until: Option<String>,
        #[arg(long, default_value = "md", value_parser = ["md", "json"])]
        format: String,
        /// Only sessions from one harness, e.g. to compare like with like across a fix
        #[arg(long, value_parser = ["claude-code", "codex", "antigravity", "kimi"])]
        harness: Option<String>,
        /// Skip the transcript sync before querying (sync once, then pass this)
        #[arg(long)]
        no_sync: bool,
    },
    /// List top sessions (by total tokens, wait, stdout, or errors) with command-family breakdowns
    Sessions {
        /// Repo: `.`, a path, owner/name, repo_id, or unique substring (see `bottledeck repos`)
        #[arg(long, default_value = ".")]
        repo: String,
        /// Trailing window: 24h, 7d, 2w, 30d, all [default: 14d, or all when --since/--until is set]
        #[arg(long)]
        window: Option<String>,
        /// Only sessions that started at or after this ISO date, relative duration (48h), or git commit/ref; no trailing window unless --window is given
        #[arg(long)]
        since: Option<String>,
        /// Only sessions that started strictly before this point (same formats); without --since/--window it covers all earlier history
        #[arg(long)]
        until: Option<String>,
        #[arg(long, default_value = "tokens", value_parser = ["tokens", "wait", "stdout", "errors"])]
        sort: String,
        /// Maximum rows
        #[arg(long, default_value_t = 15)]
        limit: usize,
        #[arg(long, default_value = "md", value_parser = ["md", "json"])]
        format: String,
        /// Only sessions from one harness, e.g. to compare like with like across a fix
        #[arg(long, value_parser = ["claude-code", "codex", "antigravity", "kimi"])]
        harness: Option<String>,
        /// Skip the transcript sync before querying (sync once, then pass this)
        #[arg(long)]
        no_sync: bool,
    },
    /// Mine repeating multi-step call sequences (3-12 calls) across sessions with token/session counts
    Sequences {
        /// Repo: `.`, a path, owner/name, repo_id, or unique substring (see `bottledeck repos`)
        #[arg(long, default_value = ".")]
        repo: String,
        /// Trailing window: 24h, 7d, 2w, 30d, all [default: 14d, or all when --since/--until is set]
        #[arg(long)]
        window: Option<String>,
        /// Only sessions that started at or after this ISO date, relative duration (48h), or git commit/ref; no trailing window unless --window is given
        #[arg(long)]
        since: Option<String>,
        /// Only sessions that started strictly before this point (same formats); without --since/--window it covers all earlier history
        #[arg(long)]
        until: Option<String>,
        /// Shortest sequence length (calls)
        #[arg(long, default_value_t = 3)]
        min_len: usize,
        /// Longest sequence length (calls)
        #[arg(long, default_value_t = 10)]
        max_len: usize,
        /// Only sequences seen in at least this many sessions
        #[arg(long, default_value_t = 2)]
        min_sessions: usize,
        /// Keep pure exploration sequences (ls/cat/grep chains), hidden by default
        #[arg(long)]
        include_exploration: bool,
        /// impact: sessions × length × calls × tokens; sessions; len; tokens; wait
        #[arg(long, default_value = "impact", value_parser = ["impact", "sessions", "len", "tokens", "wait"])]
        sort: String,
        /// Maximum rows
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value = "md", value_parser = ["md", "json"])]
        format: String,
        /// Only sessions from one harness, e.g. to compare like with like across a fix
        #[arg(long, value_parser = ["claude-code", "codex", "antigravity", "kimi"])]
        harness: Option<String>,
        /// Skip the transcript sync before querying (sync once, then pass this)
        #[arg(long)]
        no_sync: bool,
    },
    /// Audit non-shell & MCP tool calls (error rates, output size, truncation) across all harnesses
    Tools {
        /// Repo: `.`, a path, owner/name, repo_id, or unique substring (see `bottledeck repos`)
        #[arg(long, default_value = ".")]
        repo: String,
        /// Trailing window: 24h, 7d, 2w, 30d, all [default: 14d, or all when --since/--until is set]
        #[arg(long)]
        window: Option<String>,
        /// Only sessions that started at or after this ISO date, relative duration (48h), or git commit/ref; no trailing window unless --window is given
        #[arg(long)]
        since: Option<String>,
        /// Only sessions that started strictly before this point (same formats); without --since/--window it covers all earlier history
        #[arg(long)]
        until: Option<String>,
        /// errors: error count; calls; bytes: average output size; truncated: truncated outputs
        #[arg(long, default_value = "errors", value_parser = ["errors", "calls", "bytes", "truncated"])]
        sort: String,
        /// Only MCP tools
        #[arg(long)]
        mcp_only: bool,
        /// Maximum rows
        #[arg(long, default_value_t = 25)]
        limit: usize,
        #[arg(long, default_value = "md", value_parser = ["md", "json"])]
        format: String,
        /// Only sessions from one harness, e.g. to compare like with like across a fix
        #[arg(long, value_parser = ["claude-code", "codex", "antigravity", "kimi"])]
        harness: Option<String>,
        /// Skip the transcript sync before querying (sync once, then pass this)
        #[arg(long)]
        no_sync: bool,
    },
    /// List all discovered repositories in the ledger
    Repos {
        /// Trailing window: 24h, 7d, 2w, 30d, all [default: all]
        #[arg(long)]
        window: Option<String>,
        /// Only sessions that started at or after this ISO date, relative duration (48h), or git commit/ref; no trailing window unless --window is given
        #[arg(long)]
        since: Option<String>,
        /// Only sessions that started strictly before this point (same formats); without --since/--window it covers all earlier history
        #[arg(long)]
        until: Option<String>,
        #[arg(long, default_value = "md", value_parser = ["md", "json"])]
        format: String,
        /// Same as --format json
        #[arg(long, hide = true)]
        json: bool,
        /// Only sessions from one harness, e.g. to compare like with like across a fix
        #[arg(long, value_parser = ["claude-code", "codex", "antigravity", "kimi"])]
        harness: Option<String>,
        /// Skip the transcript sync before querying (sync once, then pass this)
        #[arg(long)]
        no_sync: bool,
    },
    /// Optional fail-open CLI wrapper to record exact wall-clock & surface versions to spans.jsonl
    Wrap {
        #[arg(long)]
        surface: Option<String>,
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// Check detected transcript roots and ledger status
    Doctor,
    /// Check for or install the latest GitHub release of bottledeck
    Update {
        /// Only check whether a newer release is available without installing
        #[arg(long)]
        check: bool,
        /// Install a specific release version (e.g. 0.2.0 or v0.2.0)
        #[arg(long)]
        version: Option<String>,
        /// Force reinstall even if already on the latest version or managed by Homebrew
        #[arg(long)]
        force: bool,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("bottledeck error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn fallback_cwd_for_repo(repo_sel: Option<&str>) -> Result<PathBuf> {
    if let Some(r) = repo_sel
        && (r == "." || r.starts_with('/') || r.starts_with("./"))
    {
        return Ok(PathBuf::from(r));
    }
    Ok(std::env::current_dir()?)
}

fn no_repo_msg(sel: &str) -> String {
    format!(
        "No telemetry found for repo \"{sel}\". Run `bottledeck repos --no-sync` and pass a listed repo_name (e.g. --repo owner/name)."
    )
}

fn print_roots(label: &str, paths: &[PathBuf]) {
    for (i, p) in paths.iter().enumerate() {
        let prefix = if i == 0 {
            format!("  {label:<12}")
        } else {
            "              ".to_string()
        };
        println!(
            "{prefix} {} ({})",
            p.display(),
            if p.exists() { "found" } else { "absent" }
        );
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    let roots = adapter_roots();

    match cli.command {
        None => {
            let mut conn = open_db(&db_path())?;
            sync_all(&mut conn, &roots, false)?;
            if std::io::stdout().is_terminal() && std::io::stdin().is_terminal() {
                run_tui(&mut conn, &roots, "14d", None)?;
            } else {
                let range = TimeRange::from_window(parse_window_ms("14d")?, "14d");
                let fleet = analyze_fleet(&conn, &range, false)?;
                println!("{}", format_fleet_report(&fleet, "md"));
            }
            Ok(ExitCode::SUCCESS)
        }
        Some(Commands::Tui {
            window,
            repo,
            no_sync,
        }) => {
            let mut conn = open_db(&db_path())?;
            if !no_sync {
                sync_all(&mut conn, &roots, false)?;
            }
            let repo_id = repo
                .as_deref()
                .and_then(|sel| resolve_repo_selector(&conn, sel).ok().flatten())
                .map(|(id, _)| id);
            run_tui(&mut conn, &roots, &window, repo_id.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Commands::AgentGuide {
            install,
            target,
            skill,
        }) => {
            if !install {
                print!(
                    "{}",
                    if skill {
                        skill_markdown(CURRENT_VERSION)
                    } else {
                        AGENT_GUIDE.to_string()
                    }
                );
                return Ok(ExitCode::SUCCESS);
            }
            for (harness, path) in install_paths(target) {
                write_skill(&path, CURRENT_VERSION)?;
                println!(
                    "Installed bottledeck skill for {harness}: {}",
                    path.display()
                );
            }
            println!(
                "Agents pick it up in new sessions. Re-run after `bottledeck update` to refresh it."
            );
            Ok(ExitCode::SUCCESS)
        }
        Some(Commands::Wrap { surface, cmd }) => {
            let code = run_wrapped_command(&cmd, surface.as_deref())?;
            Ok(ExitCode::from(code.clamp(0, 255) as u8))
        }
        Some(Commands::Update {
            check,
            version,
            force,
        }) => {
            run_self_update(check, version.as_deref(), force)?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Commands::Doctor) => {
            let dbp = db_path();
            let db_status = if dbp.exists() {
                let kb = std::fs::metadata(&dbp).map(|m| m.len() / 1024).unwrap_or(0);
                format!("{kb} KB")
            } else {
                "not yet created".to_string()
            };
            println!("bottledeck doctor (v{CURRENT_VERSION})");
            if let Some(latest) = cached_available_update() {
                println!("  update:      {latest} available — run `bottledeck update`");
            }
            println!("  state_dir:   {}", state_dir().display());
            println!("  ledger_db:   {} ({db_status})", dbp.display());
            print_roots("claude_dir:", &roots.claude);
            print_roots("codex_dir:", &roots.codex);
            print_roots("agy_dir:", &roots.antigravity);
            print_roots("kimi_dir:", &roots.kimi);
            for (harness, path) in skill_locations() {
                let status = match installed_skill_version(&path) {
                    Some(v) if v == CURRENT_VERSION => format!("v{v}, current"),
                    Some(v) => format!("v{v}, outdated — run `bottledeck agent-guide --install`"),
                    None if path.exists() => "custom".to_string(),
                    None => "absent — `bottledeck agent-guide --install`".to_string(),
                };
                println!("  skill:       {} [{harness}] ({status})", path.display());
            }
            println!(
                "  spans_file:  {} ({})",
                roots.spans.display(),
                if roots.spans.exists() {
                    "found"
                } else {
                    "absent"
                }
            );
            Ok(ExitCode::SUCCESS)
        }
        Some(Commands::Sync { force, json }) => {
            let mut conn = open_db(&db_path())?;
            let stats = sync_all(&mut conn, &roots, force)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&stats)?);
            } else {
                println!(
                    "Synced {} file(s) ({} unchanged, {} scanned{}).",
                    stats.files_ingested,
                    stats.files_skipped,
                    stats.files_scanned,
                    if stats.full_reparse {
                        ", full re-parse"
                    } else {
                        ""
                    }
                );
                println!(
                    "  sessions: +{} | command_spans: +{} | tool_calls: +{} | file_reads: +{} | llm_calls: +{}",
                    stats.sessions_upserted,
                    stats.spans_inserted,
                    stats.tool_calls_inserted,
                    stats.file_reads_inserted,
                    stats.llm_calls_inserted
                );
                for (name, info) in &stats.by_adapter {
                    if info.files_found > 0 {
                        println!(
                            "  [{name}] files={} ingested={} skipped={} spans={}",
                            info.files_found, info.ingested, info.skipped, info.spans
                        );
                    }
                }
                if !stats.errors.is_empty() {
                    println!("  warnings: {} file(s) failed to parse", stats.errors.len());
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Some(Commands::Repos {
            window,
            since,
            until,
            format,
            json,
            harness,
            no_sync,
        }) => {
            let json = json || format == "json";
            let mut conn = open_db(&db_path())?;
            if !no_sync {
                sync_all(&mut conn, &roots, false)?;
            }
            if let Some(h) = &harness {
                apply_harness_filter(&conn, h)?;
            }
            let default_win = window.as_deref().or(Some("all"));
            let cwd = std::env::current_dir()?;
            let range = resolve_time_range(
                &conn,
                if since.is_some() || until.is_some() {
                    window.as_deref()
                } else {
                    default_win
                },
                since.as_deref(),
                until.as_deref(),
                None,
                &cwd,
            )?;
            let range = with_harness(range, harness.as_deref());
            let repos = list_repos(&conn, &range, false)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&repos)?);
            } else if repos.is_empty() {
                println!("No repos recorded yet. Run `bottledeck sync`.");
            } else {
                println!("| Repo | Sessions | Commands | Worktrees | Output Toks | Repo ID |");
                println!("| :--- | ---: | ---: | ---: | ---: | :--- |");
                for r in repos {
                    println!(
                        "| {} | {} | {} | {} | {} | `{}` |",
                        r.repo_name,
                        r.session_count,
                        r.command_count,
                        r.worktree_count,
                        format_compact(r.total_stdout_tokens),
                        r.repo_id
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Some(Commands::Report {
            all,
            repo,
            window,
            since,
            until,
            format,
            include_temp,
            harness,
            no_sync,
        }) => {
            let mut conn = open_db(&db_path())?;
            if !no_sync {
                sync_all(&mut conn, &roots, false)?;
            }
            if let Some(h) = &harness {
                apply_harness_filter(&conn, h)?;
            }
            if all || repo.is_none() {
                let cwd = std::env::current_dir()?;
                let range = resolve_time_range(
                    &conn,
                    window.as_deref(),
                    since.as_deref(),
                    until.as_deref(),
                    None,
                    &cwd,
                )?;
                let range = with_harness(range, harness.as_deref());
                let fleet = analyze_fleet(&conn, &range, include_temp)?;
                println!("{}", format_fleet_report(&fleet, &format));
            } else {
                let sel = repo.as_deref().unwrap_or(".");
                let Some((repo_id, _)) = resolve_repo_selector(&conn, sel)? else {
                    eprintln!("{}", no_repo_msg(sel));
                    return Ok(ExitCode::FAILURE);
                };
                let cwd = fallback_cwd_for_repo(Some(sel))?;
                let range = resolve_time_range(
                    &conn,
                    window.as_deref(),
                    since.as_deref(),
                    until.as_deref(),
                    Some(&repo_id),
                    &cwd,
                )?;
                let range = with_harness(range, harness.as_deref());
                let rep = analyze_repo(&conn, &repo_id, &range, 10)?;
                if format == "prompt" {
                    let pat = analyze_cross_session_patterns(&conn, &repo_id, &range)?;
                    println!("{}", format_diagnosis_prompt(&rep, &pat));
                } else {
                    println!("{}", format_repo_report(&rep, &format));
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Some(Commands::Inspect {
            query,
            repo,
            window,
            since,
            until,
            samples,
            format,
            harness,
            no_sync,
        }) => {
            let mut conn = open_db(&db_path())?;
            if !no_sync {
                sync_all(&mut conn, &roots, false)?;
            }
            if let Some(h) = &harness {
                apply_harness_filter(&conn, h)?;
            }
            let Some((repo_id, _)) = resolve_repo_selector(&conn, &repo)? else {
                eprintln!("{}", no_repo_msg(&repo));
                return Ok(ExitCode::FAILURE);
            };
            let cwd = fallback_cwd_for_repo(Some(&repo))?;
            let range = resolve_time_range(
                &conn,
                window.as_deref(),
                since.as_deref(),
                until.as_deref(),
                Some(&repo_id),
                &cwd,
            )?;
            let range = with_harness(range, harness.as_deref());
            let res = inspect_finding(&conn, &repo_id, &query, &range, samples)?;
            println!("{}", format_inspect_report(&res, &format));
            Ok(ExitCode::SUCCESS)
        }
        Some(Commands::Commands {
            repo,
            window,
            since,
            until,
            sort,
            category,
            limit,
            format,
            harness,
            no_sync,
        }) => {
            let mut conn = open_db(&db_path())?;
            if !no_sync {
                sync_all(&mut conn, &roots, false)?;
            }
            if let Some(h) = &harness {
                apply_harness_filter(&conn, h)?;
            }
            let Some((repo_id, repo_name)) = resolve_repo_selector(&conn, &repo)? else {
                eprintln!("{}", no_repo_msg(&repo));
                return Ok(ExitCode::FAILURE);
            };
            let cwd = fallback_cwd_for_repo(Some(&repo))?;
            let range = resolve_time_range(
                &conn,
                window.as_deref(),
                since.as_deref(),
                until.as_deref(),
                Some(&repo_id),
                &cwd,
            )?;
            let range = with_harness(range, harness.as_deref());
            let cmds = query_commands(&conn, &repo_id, &range, &sort, category.as_deref(), limit)?;
            println!(
                "{}",
                format_commands_report(&repo_name, &sort, &cmds, &format)
            );
            Ok(ExitCode::SUCCESS)
        }
        Some(Commands::Errors {
            repo,
            window,
            since,
            until,
            limit,
            format,
            harness,
            no_sync,
        }) => {
            let mut conn = open_db(&db_path())?;
            if !no_sync {
                sync_all(&mut conn, &roots, false)?;
            }
            if let Some(h) = &harness {
                apply_harness_filter(&conn, h)?;
            }
            let Some((repo_id, repo_name)) = resolve_repo_selector(&conn, &repo)? else {
                eprintln!("{}", no_repo_msg(&repo));
                return Ok(ExitCode::FAILURE);
            };
            let cwd = fallback_cwd_for_repo(Some(&repo))?;
            let range = resolve_time_range(
                &conn,
                window.as_deref(),
                since.as_deref(),
                until.as_deref(),
                Some(&repo_id),
                &cwd,
            )?;
            let range = with_harness(range, harness.as_deref());
            let errs = query_errors(&conn, &repo_id, &range, limit)?;
            println!("{}", format_errors_report(&repo_name, &errs, &format));
            Ok(ExitCode::SUCCESS)
        }
        Some(Commands::Bypasses {
            repo,
            window,
            since,
            until,
            format,
            harness,
            no_sync,
        }) => {
            let mut conn = open_db(&db_path())?;
            if !no_sync {
                sync_all(&mut conn, &roots, false)?;
            }
            if let Some(h) = &harness {
                apply_harness_filter(&conn, h)?;
            }
            let Some((repo_id, _)) = resolve_repo_selector(&conn, &repo)? else {
                eprintln!("{}", no_repo_msg(&repo));
                return Ok(ExitCode::FAILURE);
            };
            let cwd = fallback_cwd_for_repo(Some(&repo))?;
            let range = resolve_time_range(
                &conn,
                window.as_deref(),
                since.as_deref(),
                until.as_deref(),
                Some(&repo_id),
                &cwd,
            )?;
            let range = with_harness(range, harness.as_deref());
            let rep = query_bypasses(&conn, &repo_id, &range)?;
            println!("{}", format_bypasses_report(&rep, &format));
            Ok(ExitCode::SUCCESS)
        }
        Some(Commands::Patterns {
            repo,
            window,
            since,
            until,
            format,
            harness,
            no_sync,
        }) => {
            let mut conn = open_db(&db_path())?;
            if !no_sync {
                sync_all(&mut conn, &roots, false)?;
            }
            if let Some(h) = &harness {
                apply_harness_filter(&conn, h)?;
            }
            let Some((repo_id, _)) = resolve_repo_selector(&conn, &repo)? else {
                eprintln!("{}", no_repo_msg(&repo));
                return Ok(ExitCode::FAILURE);
            };
            let cwd = fallback_cwd_for_repo(Some(&repo))?;
            let range = resolve_time_range(
                &conn,
                window.as_deref(),
                since.as_deref(),
                until.as_deref(),
                Some(&repo_id),
                &cwd,
            )?;
            let range = with_harness(range, harness.as_deref());
            let rep = analyze_cross_session_patterns(&conn, &repo_id, &range)?;
            println!("{}", format_patterns_report(&rep, &format));
            Ok(ExitCode::SUCCESS)
        }
        Some(Commands::Sessions {
            repo,
            window,
            since,
            until,
            sort,
            limit,
            format,
            harness,
            no_sync,
        }) => {
            let mut conn = open_db(&db_path())?;
            if !no_sync {
                sync_all(&mut conn, &roots, false)?;
            }
            if let Some(h) = &harness {
                apply_harness_filter(&conn, h)?;
            }
            let Some((repo_id, repo_name)) = resolve_repo_selector(&conn, &repo)? else {
                eprintln!("{}", no_repo_msg(&repo));
                return Ok(ExitCode::FAILURE);
            };
            let cwd = fallback_cwd_for_repo(Some(&repo))?;
            let range = resolve_time_range(
                &conn,
                window.as_deref(),
                since.as_deref(),
                until.as_deref(),
                Some(&repo_id),
                &cwd,
            )?;
            let range = with_harness(range, harness.as_deref());
            let rows = query_top_sessions(&conn, &repo_id, &range, &sort, limit)?;
            println!(
                "{}",
                format_sessions_report(&repo_name, &sort, &rows, &format)
            );
            Ok(ExitCode::SUCCESS)
        }
        Some(Commands::Sequences {
            repo,
            window,
            since,
            until,
            min_len,
            max_len,
            min_sessions,
            include_exploration,
            sort,
            limit,
            format,
            harness,
            no_sync,
        }) => {
            let mut conn = open_db(&db_path())?;
            if !no_sync {
                sync_all(&mut conn, &roots, false)?;
            }
            if let Some(h) = &harness {
                apply_harness_filter(&conn, h)?;
            }
            let Some((repo_id, repo_name)) = resolve_repo_selector(&conn, &repo)? else {
                eprintln!("{}", no_repo_msg(&repo));
                return Ok(ExitCode::FAILURE);
            };
            let cwd = fallback_cwd_for_repo(Some(&repo))?;
            let range = resolve_time_range(
                &conn,
                window.as_deref(),
                since.as_deref(),
                until.as_deref(),
                Some(&repo_id),
                &cwd,
            )?;
            let range = with_harness(range, harness.as_deref());
            let rows = query_sequences(
                &conn,
                &repo_id,
                &range,
                min_len,
                max_len,
                min_sessions,
                include_exploration,
                &sort,
                limit,
            )?;
            println!(
                "{}",
                format_sequences_report(&repo_name, min_len, max_len, &sort, &rows, &format)
            );
            Ok(ExitCode::SUCCESS)
        }
        Some(Commands::Tools {
            repo,
            window,
            since,
            until,
            sort,
            mcp_only,
            limit,
            format,
            harness,
            no_sync,
        }) => {
            let mut conn = open_db(&db_path())?;
            if !no_sync {
                sync_all(&mut conn, &roots, false)?;
            }
            if let Some(h) = &harness {
                apply_harness_filter(&conn, h)?;
            }
            let Some((repo_id, repo_name)) = resolve_repo_selector(&conn, &repo)? else {
                eprintln!("{}", no_repo_msg(&repo));
                return Ok(ExitCode::FAILURE);
            };
            let cwd = fallback_cwd_for_repo(Some(&repo))?;
            let range = resolve_time_range(
                &conn,
                window.as_deref(),
                since.as_deref(),
                until.as_deref(),
                Some(&repo_id),
                &cwd,
            )?;
            let range = with_harness(range, harness.as_deref());
            let rows = query_tools(&conn, &repo_id, &range, &sort, mcp_only, usize::MAX)?;
            println!(
                "{}",
                format_tools_report(&repo_name, &sort, &rows, limit, &format)
            );
            Ok(ExitCode::SUCCESS)
        }
        Some(Commands::Issues {
            issue,
            repo,
            window,
            since,
            until,
            open,
            format,
            harness,
            no_sync,
        }) => {
            let mut conn = open_db(&db_path())?;
            if !no_sync {
                sync_all(&mut conn, &roots, false)?;
            }
            if let Some(h) = &harness {
                apply_harness_filter(&conn, h)?;
            }
            let Some((repo_id, _)) = resolve_repo_selector(&conn, &repo)? else {
                eprintln!("{}", no_repo_msg(&repo));
                return Ok(ExitCode::FAILURE);
            };
            let cwd = fallback_cwd_for_repo(Some(&repo))?;
            let window = match (&window, since.is_some() || until.is_some()) {
                (Some(w), _) => w.clone(),
                (None, true) => "all".to_string(),
                (None, false) => "30d".to_string(),
            };
            let range = resolve_time_range(
                &conn,
                Some(&window),
                since.as_deref(),
                until.as_deref(),
                Some(&repo_id),
                &cwd,
            )?;
            let range = with_harness(range, harness.as_deref());
            let mut rep = track_issues(&conn, &repo_id, &range)?;
            if let Some(q) = issue {
                let key = match pick_issue_key(&q, resolve_issue_ref(&conn, &repo_id, &range, &q)?)
                {
                    Ok(k) => k,
                    Err(msg) => {
                        eprintln!("{msg}");
                        return Ok(ExitCode::FAILURE);
                    }
                };
                rep.issues.retain(|t| t.key == key);
                if rep.issues.is_empty() {
                    eprintln!(
                        "Issue \"{key}\" has no exposed sessions in {}.",
                        range.label
                    );
                    return Ok(ExitCode::FAILURE);
                }
            }
            if open {
                rep.issues.retain(|t| t.verdict.verdict.is_open());
            }
            println!("{}", format_issues_report(&rep, &format));
            Ok(ExitCode::SUCCESS)
        }
        Some(Commands::Mark {
            issue,
            all,
            at,
            note,
            repo,
            list,
            remove,
            no_sync,
        }) => {
            let mut conn = open_db(&db_path())?;
            if !no_sync && !list && remove.is_none() {
                sync_all(&mut conn, &roots, false)?;
            }
            let Some((repo_id, repo_name)) = resolve_repo_selector(&conn, &repo)? else {
                eprintln!("{}", no_repo_msg(&repo));
                return Ok(ExitCode::FAILURE);
            };
            if let Some(id) = remove {
                if remove_marker(&conn, &repo_id, id)? {
                    println!("Removed marker #{id}.");
                    return Ok(ExitCode::SUCCESS);
                }
                eprintln!("No marker #{id} for {repo_name}.");
                return Ok(ExitCode::FAILURE);
            }
            if list {
                let markers = list_markers(&conn, &repo_id)?;
                if markers.is_empty() {
                    println!("No markers for {repo_name}.");
                }
                for m in markers {
                    println!(
                        "#{:<4} {:<32} {}{}",
                        m.marker_id,
                        m.label,
                        m.issue_key.as_deref().unwrap_or("(all issues)"),
                        m.note.map(|n| format!("  — {n}")).unwrap_or_default()
                    );
                }
                return Ok(ExitCode::SUCCESS);
            }
            let cwd = fallback_cwd_for_repo(Some(&repo))?;
            let key = match (issue, all) {
                (Some(_), true) => {
                    eprintln!("Pass either an issue or --all, not both.");
                    return Ok(ExitCode::FAILURE);
                }
                (None, false) => {
                    eprintln!("Pass an issue key (see `bottledeck issues`) or --all.");
                    return Ok(ExitCode::FAILURE);
                }
                (None, true) => None,
                (Some(q), false) => {
                    let range =
                        resolve_time_range(&conn, Some("30d"), None, None, Some(&repo_id), &cwd)?;
                    match pick_issue_key(&q, resolve_issue_ref(&conn, &repo_id, &range, &q)?) {
                        Ok(k) => Some(k),
                        Err(msg) => {
                            eprintln!("{msg}");
                            return Ok(ExitCode::FAILURE);
                        }
                    }
                }
            };
            let (at_ms, label) = resolve_time_point(&conn, &at, Some(&repo_id), &cwd)?;
            let id = add_marker(
                &conn,
                &repo_id,
                key.as_deref(),
                at_ms,
                &label,
                note.as_deref(),
            )?;
            println!(
                "Marker #{id} at {label} → {}. Sessions started after it are compared with earlier ones in `bottledeck issues`.",
                key.as_deref().unwrap_or("all issues")
            );
            Ok(ExitCode::SUCCESS)
        }
        Some(Commands::Diff {
            since,
            repo,
            format,
            harness,
            no_sync,
        }) => {
            let mut conn = open_db(&db_path())?;
            if !no_sync {
                sync_all(&mut conn, &roots, false)?;
            }
            if let Some(h) = &harness {
                apply_harness_filter(&conn, h)?;
            }
            let Some((repo_id, _)) = resolve_repo_selector(&conn, &repo)? else {
                eprintln!("{}", no_repo_msg(&repo));
                return Ok(ExitCode::FAILURE);
            };
            let cwd = fallback_cwd_for_repo(Some(&repo))?;
            let (since_ms, label) = resolve_time_point(&conn, &since, Some(&repo_id), &cwd)?;
            let label = match &harness {
                Some(h) => format!("{label} · {h} only"),
                None => label,
            };
            let res = diff_repo(&conn, &repo_id, since_ms, &label)?;
            println!("{}", format_diff_report(&res, &format));
            Ok(ExitCode::SUCCESS)
        }
    }
}
