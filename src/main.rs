use anyhow::Result;
use bottledeck::analyze::{
    analyze_fleet, analyze_repo, diff_repo, format_compact, inspect_finding, list_repos,
    query_bypasses, query_commands, query_errors, resolve_repo_selector, resolve_time_point,
    resolve_time_range,
};
use bottledeck::config::{TimeRange, adapter_roots, db_path, parse_window_ms, state_dir};
use bottledeck::db::open_db;
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

#[derive(Parser)]
#[command(
    name = "bottledeck",
    version,
    about = "Zero-touch multi-harness telemetry, Ratatui dashboard, and bottleneck analyzer for coding agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
#[allow(clippy::enum_variant_names)]
enum Commands {
    /// Launch the interactive Ratatui dashboard
    Tui {
        #[arg(long, default_value = "14d")]
        window: String,
        #[arg(long)]
        repo: Option<String>,
        #[arg(long)]
        no_sync: bool,
    },
    /// Incrementally ingest local coding-agent transcripts and spans into the SQLite ledger
    Sync {
        #[arg(long)]
        force: bool,
        #[arg(long)]
        json: bool,
    },
    /// Generate fleet-wide or per-repo reports (md, llm, prompt, json)
    Report {
        #[arg(long)]
        all: bool,
        #[arg(long)]
        repo: Option<String>,
        #[arg(long)]
        window: Option<String>,
        /// Include only sessions at or after this ISO date, relative duration (e.g. 48h), or git commit/ref
        #[arg(long)]
        since: Option<String>,
        /// Include only sessions strictly before this ISO date, relative duration, or git commit/ref
        #[arg(long)]
        until: Option<String>,
        #[arg(long, default_value = "md")]
        format: String,
        #[arg(long)]
        include_temp: bool,
        #[arg(long)]
        no_sync: bool,
    },
    /// Drill into a finding (e.g. opp-1) or command template with redacted trace samples
    Inspect {
        query: String,
        #[arg(long, default_value = ".")]
        repo: String,
        #[arg(long)]
        window: Option<String>,
        /// Include only sessions at or after this ISO date, relative duration, or git commit/ref
        #[arg(long)]
        since: Option<String>,
        /// Include only sessions strictly before this ISO date, relative duration, or git commit/ref
        #[arg(long)]
        until: Option<String>,
        #[arg(long, default_value_t = 5)]
        samples: usize,
        #[arg(long, default_value = "md")]
        format: String,
        #[arg(long)]
        no_sync: bool,
    },
    /// Compare before/after metrics around an infra commit SHA or ISO date
    Diff {
        #[arg(long)]
        since: String,
        #[arg(long, default_value = ".")]
        repo: String,
        #[arg(long, default_value = "md")]
        format: String,
        #[arg(long)]
        no_sync: bool,
    },
    /// List commands for a repo sorted by effective tokens, raw tokens, wait, runs, errors, or pipe-stripping
    Commands {
        #[arg(long, default_value = ".")]
        repo: String,
        #[arg(long)]
        window: Option<String>,
        /// Include only sessions at or after this ISO date, relative duration, or git commit/ref
        #[arg(long)]
        since: Option<String>,
        /// Include only sessions strictly before this ISO date, relative duration, or git commit/ref
        #[arg(long)]
        until: Option<String>,
        #[arg(long, default_value = "effective")]
        sort: String,
        #[arg(long)]
        category: Option<String>,
        #[arg(long, default_value_t = 30)]
        limit: usize,
        #[arg(long, default_value = "md")]
        format: String,
        #[arg(long)]
        no_sync: bool,
    },
    /// Show recurring nonzero-exit command error clusters for a repo
    Errors {
        #[arg(long, default_value = ".")]
        repo: String,
        #[arg(long)]
        window: Option<String>,
        /// Include only sessions at or after this ISO date, relative duration, or git commit/ref
        #[arg(long)]
        since: Option<String>,
        /// Include only sessions strictly before this ISO date, relative duration, or git commit/ref
        #[arg(long)]
        until: Option<String>,
        #[arg(long, default_value_t = 25)]
        limit: usize,
        #[arg(long, default_value = "md")]
        format: String,
        #[arg(long)]
        no_sync: bool,
    },
    /// Audit state-directory scrapes, CLI pipe-stripping, help tax, and raw tool bypasses
    Bypasses {
        #[arg(long, default_value = ".")]
        repo: String,
        #[arg(long)]
        window: Option<String>,
        /// Include only sessions at or after this ISO date, relative duration, or git commit/ref
        #[arg(long)]
        since: Option<String>,
        /// Include only sessions strictly before this ISO date, relative duration, or git commit/ref
        #[arg(long)]
        until: Option<String>,
        #[arg(long, default_value = "md")]
        format: String,
        #[arg(long)]
        no_sync: bool,
    },
    /// Analyze cross-session longitudinal & systemic patterns (motifs, drift, harness asymmetry, cold starts, bloat drivers, burst storms)
    Patterns {
        #[arg(long, default_value = ".")]
        repo: String,
        #[arg(long)]
        window: Option<String>,
        /// Include only sessions at or after this ISO date, relative duration, or git commit/ref
        #[arg(long)]
        since: Option<String>,
        /// Include only sessions strictly before this ISO date, relative duration, or git commit/ref
        #[arg(long)]
        until: Option<String>,
        #[arg(long, default_value = "md")]
        format: String,
        #[arg(long)]
        no_sync: bool,
    },
    /// List top sessions (by total tokens, wait, stdout, or errors) with command-family breakdowns
    Sessions {
        #[arg(long, default_value = ".")]
        repo: String,
        #[arg(long)]
        window: Option<String>,
        /// Include only sessions at or after this ISO date, relative duration, or git commit/ref
        #[arg(long)]
        since: Option<String>,
        /// Include only sessions strictly before this ISO date, relative duration, or git commit/ref
        #[arg(long)]
        until: Option<String>,
        #[arg(long, default_value = "tokens")]
        sort: String,
        #[arg(long, default_value_t = 15)]
        limit: usize,
        #[arg(long, default_value = "md")]
        format: String,
        #[arg(long)]
        no_sync: bool,
    },
    /// Mine repeating multi-step call sequences (3-12 calls) across sessions with token/session counts
    Sequences {
        #[arg(long, default_value = ".")]
        repo: String,
        #[arg(long)]
        window: Option<String>,
        /// Include only sessions at or after this ISO date, relative duration, or git commit/ref
        #[arg(long)]
        since: Option<String>,
        /// Include only sessions strictly before this ISO date, relative duration, or git commit/ref
        #[arg(long)]
        until: Option<String>,
        #[arg(long, default_value_t = 3)]
        min_len: usize,
        #[arg(long, default_value_t = 10)]
        max_len: usize,
        #[arg(long, default_value_t = 2)]
        min_sessions: usize,
        #[arg(long)]
        include_exploration: bool,
        #[arg(long, default_value = "impact")]
        sort: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value = "md")]
        format: String,
        #[arg(long)]
        no_sync: bool,
    },
    /// Audit non-shell & MCP tool calls (error rates, output size, truncation) across all harnesses
    Tools {
        #[arg(long, default_value = ".")]
        repo: String,
        #[arg(long)]
        window: Option<String>,
        /// Include only sessions at or after this ISO date, relative duration, or git commit/ref
        #[arg(long)]
        since: Option<String>,
        /// Include only sessions strictly before this ISO date, relative duration, or git commit/ref
        #[arg(long)]
        until: Option<String>,
        #[arg(long, default_value = "errors")]
        sort: String,
        #[arg(long)]
        mcp_only: bool,
        #[arg(long, default_value_t = 25)]
        limit: usize,
        #[arg(long, default_value = "md")]
        format: String,
        #[arg(long)]
        no_sync: bool,
    },
    /// List all discovered repositories in the ledger
    Repos {
        #[arg(long)]
        window: Option<String>,
        /// Include only sessions at or after this ISO date, relative duration, or git commit/ref
        #[arg(long)]
        since: Option<String>,
        /// Include only sessions strictly before this ISO date, relative duration, or git commit/ref
        #[arg(long)]
        until: Option<String>,
        #[arg(long)]
        json: bool,
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
                    "Synced {} file(s) ({} unchanged, {} scanned).",
                    stats.files_ingested, stats.files_skipped, stats.files_scanned
                );
                println!(
                    "  sessions: +{} | command_spans: +{} | tool_calls: +{} | file_reads: +{}",
                    stats.sessions_upserted,
                    stats.spans_inserted,
                    stats.tool_calls_inserted,
                    stats.file_reads_inserted
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
            json,
            no_sync,
        }) => {
            let mut conn = open_db(&db_path())?;
            if !no_sync {
                sync_all(&mut conn, &roots, false)?;
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
            no_sync,
        }) => {
            let mut conn = open_db(&db_path())?;
            if !no_sync {
                sync_all(&mut conn, &roots, false)?;
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
                let fleet = analyze_fleet(&conn, &range, include_temp)?;
                println!("{}", format_fleet_report(&fleet, &format));
            } else {
                let sel = repo.as_deref().unwrap_or(".");
                let Some((repo_id, _)) = resolve_repo_selector(&conn, sel)? else {
                    eprintln!(
                        "No telemetry found for repo \"{sel}\". Run 'bottledeck repos' to list known repos."
                    );
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
            no_sync,
        }) => {
            let mut conn = open_db(&db_path())?;
            if !no_sync {
                sync_all(&mut conn, &roots, false)?;
            }
            let Some((repo_id, _)) = resolve_repo_selector(&conn, &repo)? else {
                eprintln!("No telemetry found for repo \"{repo}\".");
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
            no_sync,
        }) => {
            let mut conn = open_db(&db_path())?;
            if !no_sync {
                sync_all(&mut conn, &roots, false)?;
            }
            let Some((repo_id, repo_name)) = resolve_repo_selector(&conn, &repo)? else {
                eprintln!("No telemetry found for repo \"{repo}\".");
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
            no_sync,
        }) => {
            let mut conn = open_db(&db_path())?;
            if !no_sync {
                sync_all(&mut conn, &roots, false)?;
            }
            let Some((repo_id, repo_name)) = resolve_repo_selector(&conn, &repo)? else {
                eprintln!("No telemetry found for repo \"{repo}\".");
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
            no_sync,
        }) => {
            let mut conn = open_db(&db_path())?;
            if !no_sync {
                sync_all(&mut conn, &roots, false)?;
            }
            let Some((repo_id, _)) = resolve_repo_selector(&conn, &repo)? else {
                eprintln!("No telemetry found for repo \"{repo}\".");
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
            no_sync,
        }) => {
            let mut conn = open_db(&db_path())?;
            if !no_sync {
                sync_all(&mut conn, &roots, false)?;
            }
            let Some((repo_id, _)) = resolve_repo_selector(&conn, &repo)? else {
                eprintln!("No telemetry found for repo \"{repo}\".");
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
            no_sync,
        }) => {
            let mut conn = open_db(&db_path())?;
            if !no_sync {
                sync_all(&mut conn, &roots, false)?;
            }
            let Some((repo_id, repo_name)) = resolve_repo_selector(&conn, &repo)? else {
                eprintln!("No telemetry found for repo \"{repo}\".");
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
            no_sync,
        }) => {
            let mut conn = open_db(&db_path())?;
            if !no_sync {
                sync_all(&mut conn, &roots, false)?;
            }
            let Some((repo_id, repo_name)) = resolve_repo_selector(&conn, &repo)? else {
                eprintln!("No telemetry found for repo \"{repo}\".");
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
            no_sync,
        }) => {
            let mut conn = open_db(&db_path())?;
            if !no_sync {
                sync_all(&mut conn, &roots, false)?;
            }
            let Some((repo_id, repo_name)) = resolve_repo_selector(&conn, &repo)? else {
                eprintln!("No telemetry found for repo \"{repo}\".");
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
            let rows = query_tools(&conn, &repo_id, &range, &sort, mcp_only, limit)?;
            println!("{}", format_tools_report(&repo_name, &sort, &rows, &format));
            Ok(ExitCode::SUCCESS)
        }
        Some(Commands::Diff {
            since,
            repo,
            format,
            no_sync,
        }) => {
            let mut conn = open_db(&db_path())?;
            if !no_sync {
                sync_all(&mut conn, &roots, false)?;
            }
            let Some((repo_id, _)) = resolve_repo_selector(&conn, &repo)? else {
                eprintln!("No telemetry found for repo \"{repo}\".");
                return Ok(ExitCode::FAILURE);
            };
            let cwd = fallback_cwd_for_repo(Some(&repo))?;
            let (since_ms, label) = resolve_time_point(&conn, &since, Some(&repo_id), &cwd)?;
            let res = diff_repo(&conn, &repo_id, since_ms, &label)?;
            println!("{}", format_diff_report(&res, &format));
            Ok(ExitCode::SUCCESS)
        }
    }
}
