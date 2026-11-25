use crate::analyze::{format_compact, format_harness_breakdown};
use crate::config::TimeRange;
use crate::repo_context::RepoContext;
use anyhow::Result;
use regex::Regex;
use rusqlite::{Connection, params};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize)]
pub struct RecurringMotif {
    pub motif_kind: String, // failure_to_workaround | cli_to_raw_rebound | workflow_sequence
    pub sequence: String,
    pub sessions: usize,
    pub total_sessions: usize,
    pub session_prevalence: f64,
    pub occurrences: usize,
    pub agents: Vec<String>,
    pub by_harness: BTreeMap<String, usize>,
    pub harness_summary: String,
    pub total_stdout_tokens: i64,
    pub total_effective_tokens: i64,
    pub total_wait_s: f64,
    pub sample_trace: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RepeatingSequence {
    pub step_count: usize,
    pub sequence: String,
    pub steps: Vec<String>,
    pub sessions: usize,
    pub total_sessions: usize,
    pub session_prevalence: f64,
    pub occurrences: usize,
    pub total_calls: usize,
    pub total_stdout_tokens: i64,
    pub total_effective_tokens: i64,
    pub total_wait_s: f64,
    pub agents: Vec<String>,
    pub by_harness: BTreeMap<String, usize>,
    pub harness_summary: String,
    pub sample_trace: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TemporalDriftItem {
    pub status: String, // surging | regressing | chronic | improving
    pub cmd_family: String,
    pub early_runs: usize,
    pub recent_runs: usize,
    pub early_per_1k: f64,
    pub recent_per_1k: f64,
    pub rate_ratio: f64,
    pub early_error_rate: f64,
    pub recent_error_rate: f64,
    pub early_p50_tokens: i64,
    pub recent_p50_tokens: i64,
    pub early_p50_wait_s: f64,
    pub recent_p50_wait_s: f64,
    pub by_harness: BTreeMap<String, usize>,
    pub harness_summary: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HarnessBreakdown {
    pub agent_kind: String,
    pub originator: String,
    pub role: String, // main | subagent | subagent:guardian | ...
    pub sessions: usize,
    pub commands: usize,
    pub tool_calls: usize,
    pub median_total_tokens: i64,
    pub avg_uncached_tokens: i64,
    pub weighted_cache_hit: Option<f64>,
    pub median_cache_hit: Option<f64>,
    pub p25_cache_hit: Option<f64>,
    pub avg_output_kb: f64,
    pub truncated_outputs: usize,
    pub truncated_sessions_pct: f64,
    pub median_tool_wait_s: f64,
    pub error_rate: f64,
    pub rebound_rate: f64,
    pub top_friction_cmds: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HandoffSummary {
    pub handoff_sessions: usize,
    pub fresh_sessions: usize,
    pub handoff_avg_tokens: i64,
    pub fresh_avg_tokens: i64,
    pub token_multiplier: f64,
    pub handoff_avg_turns: f64,
    pub fresh_avg_turns: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PostCliDocRead {
    pub cmd_template: String,
    pub runs: usize,
    pub followed_by_doc_read: usize,
    pub follow_up_rate: f64,
    pub by_harness: BTreeMap<String, usize>,
    pub harness_summary: String,
    pub top_doc_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnderusedSurface {
    pub surface_kind: String, // documented_tool | repo_task
    pub name: String,
    pub observed_calls: usize,
    pub note: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolStat {
    pub tool_name: String,
    pub is_mcp: bool,
    pub calls: usize,
    pub sessions: usize,
    pub error_count: usize,
    pub error_rate: f64,
    pub truncated_count: usize,
    pub truncated_rate: f64,
    pub avg_output_kb: f64,
    pub total_wait_s: f64,
    pub agents: Vec<String>,
    pub by_harness: BTreeMap<String, usize>,
    pub harness_summary: String,
    pub sample_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ParetoStormLift {
    pub family: String,
    pub top25_pct_sessions: f64,
    pub bottom50_pct_sessions: f64,
    pub lift_str: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ParetoSummary {
    pub main_sessions: usize,
    pub total_tokens_all_main: i64,
    pub top25_count: usize,
    pub top25_token_share_pct: f64,
    pub top25_median_tokens: i64,
    pub bottom50_median_tokens: i64,
    pub median_multiplier: f64,
    pub top25_avg_turns: f64,
    pub bottom50_avg_turns: f64,
    pub top25_avg_stdout_kb: f64,
    pub bottom50_avg_stdout_kb: f64,
    pub storm_lifts: Vec<ParetoStormLift>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ColdStartErrorClass {
    pub error_class: String,
    pub failures_turns_1_3: usize,
    pub total_failures: usize,
    pub pct_in_turns_1_3: f64,
    pub sessions: usize,
    pub worktrees: usize,
    pub by_harness: BTreeMap<String, usize>,
    pub harness_summary: String,
    pub sample_cmd: String,
    pub sample_stderr: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BloatDriver {
    pub cmd_template: String,
    pub category: String,
    pub high_cost_rate: f64,
    pub normal_cost_rate: f64,
    pub enrichment_ratio: f64,
    pub high_cost_sessions: usize,
    pub total_stdout_tokens: i64,
    pub total_wait_s: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BurstStorm {
    pub cmd_template: String,
    pub storm_sessions: usize,
    pub total_calls_in_storms: usize,
    pub max_calls_in_session: usize,
    pub total_stdout_tokens: i64,
    pub total_effective_tokens: i64,
    pub total_wait_s: f64,
    pub agents: Vec<String>,
    pub by_harness: BTreeMap<String, usize>,
    pub harness_summary: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionOverview {
    pub session_id: String,
    pub agent_kind: String,
    pub originator: String,
    pub role: String,
    pub is_handoff: bool,
    pub started_at: String,
    pub turn_count: i64,
    pub command_count: usize,
    pub tool_call_count: usize,
    pub total_tokens: i64,
    pub uncached_tokens: i64,
    pub cache_hit_rate: Option<f64>,
    pub stdout_kb: f64,
    pub total_wait_s: f64,
    pub error_count: usize,
    pub top_families: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CrossSessionPatternsReport {
    pub repo_id: String,
    pub repo_name: String,
    pub window: String,
    pub branch_behind_notice: Option<String>,
    pub sessions_analyzed: usize,
    pub main_sessions: usize,
    pub subagent_sessions: usize,
    pub midpoint_iso: String,
    pub early_cmds: usize,
    pub recent_cmds: usize,
    pub early_error_rate: f64,
    pub recent_error_rate: f64,
    pub pareto: ParetoSummary,
    pub handoff_summary: Option<HandoffSummary>,
    pub harness_comparison: Vec<HarnessBreakdown>,
    pub universal_friction_cmds: Vec<String>,
    pub recurring_motifs: Vec<RecurringMotif>,
    pub repeating_sequences: Vec<RepeatingSequence>,
    pub temporal_drift: Vec<TemporalDriftItem>,
    pub cold_start_errors: Vec<ColdStartErrorClass>,
    pub context_bloat_drivers: Vec<BloatDriver>,
    pub burst_storms: Vec<BurstStorm>,
    pub post_cli_doc_reads: Vec<PostCliDocRead>,
    pub top_mcp_errors: Vec<ToolStat>,
    pub underused_surfaces: Vec<UnderusedSurface>,
}

struct Sess {
    session_id: String,
    agent_kind: String,
    originator: String,
    role: String,
    is_subagent: bool,
    is_handoff: bool,
    started_at: i64,
    turn_count: i64,
    input_tokens: i64,
    output_tokens: i64,
    cached_tokens: i64,
    total_tool_ms: i64,
}

impl Sess {
    fn total_tokens(&self) -> i64 {
        self.input_tokens + self.cached_tokens + self.output_tokens
    }

    fn cache_hit_rate(&self) -> Option<f64> {
        let denom = self.input_tokens + self.cached_tokens;
        if denom > 0 {
            Some(self.cached_tokens as f64 / denom as f64)
        } else {
            None
        }
    }
}

struct Span {
    session_id: String,
    agent_kind: String,
    turn_idx: i64,
    workspace_id: Option<String>,
    category: String,
    is_repo_cli: bool,
    cmd_bin: String,
    cmd_template: String,
    raw_redacted: String,
    exit_code: Option<i64>,
    duration_ms: Option<i64>,
    stdout_bytes: i64,
    stdout_tokens: i64,
    stderr_preview: Option<String>,
    is_truncated: bool,
    started_at: i64,
}

struct TCall {
    session_id: String,
    agent_kind: String,
    tool_name: String,
    is_error: bool,
    output_bytes: i64,
    is_truncated: bool,
}

fn percentile_i64(values: &[i64], p: f64) -> i64 {
    if values.is_empty() {
        return 0;
    }
    let mut s = values.to_vec();
    s.sort_unstable();
    let idx = (((p / 100.0) * s.len() as f64).ceil() as isize - 1).clamp(0, (s.len() - 1) as isize)
        as usize;
    s[idx]
}

fn percentile_f64(values: &[f64], p: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut s = values.to_vec();
    s.sort_by(|a, b| a.total_cmp(b));
    let idx = (((p / 100.0) * s.len() as f64).ceil() as isize - 1).clamp(0, (s.len() - 1) as isize)
        as usize;
    s[idx]
}

fn r1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

fn r3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

fn trunc(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}...", s.chars().take(max).collect::<String>())
    }
}

fn is_generic_read_or_script(tpl: &str, cat: &str) -> bool {
    cat == "exploration"
        || tpl.starts_with("git status")
        || tpl.starts_with("git diff")
        || tpl.starts_with("git log")
        || tpl.starts_with("git show")
        || tpl.starts_with("git rev-parse")
        || tpl.starts_with("git branch")
        || tpl.starts_with("python3")
        || tpl.starts_with("python ")
        || tpl == "python"
        || tpl.starts_with("node -e")
        || tpl.starts_with("node --input-type")
}

/// Group commands into repo-agnostic semantic families for rate-normalized drift & storm tracking.
fn semantic_family(sp: &Span) -> String {
    let tpl = &sp.cmd_template;
    let parts: Vec<&str> = tpl.split_whitespace().collect();
    if parts.is_empty() {
        return tpl.clone();
    }
    // Generic task runners: `<runner> run <task>` or `<runner> <task>`
    match parts[0] {
        "mise" if parts.get(1) == Some(&"run") => {
            if let Some(task) = parts.get(2) {
                return format!("mise:{task}");
            }
        }
        "mise" if parts.get(1).is_some_and(|s| s.starts_with("job:")) => {
            return "mise:job".to_string();
        }
        "npm" | "pnpm" | "yarn" | "bun" if parts.get(1) == Some(&"run") => {
            if let Some(task) = parts.get(2) {
                return format!("{}:{task}", parts[0]);
            }
        }
        "make" | "just" | "task" | "mage" | "nx" | "turbo" => {
            if let Some(task) = parts.get(1)
                && !task.starts_with('-')
            {
                return format!("{}:{task}", parts[0]);
            }
        }
        "npm" | "pnpm" | "yarn" | "bun" | "cargo" | "go" | "bazel" | "gradle" | "mvn"
        | "docker" | "kubectl" | "helm" | "terraform" | "gh" | "pytest" | "uv" => {
            if let Some(sub) = parts.get(1)
                && !sub.starts_with('-')
            {
                return format!("{}:{sub}", parts[0]);
            }
            return format!("raw:{}", parts[0]);
        }
        "ssh" | "scp" => return "raw:ssh".to_string(),
        "sleep" => return "polling:sleep".to_string(),
        _ => {}
    }
    if sp.category == "polling" {
        return sp.cmd_bin.clone();
    }
    tpl.clone()
}

fn classify_cold_error(sp: &Span) -> Option<String> {
    let err = sp.stderr_preview.as_deref().unwrap_or("");
    let lower = err.to_ascii_lowercase();

    static CNF_RE: OnceLock<Regex> = OnceLock::new();
    let cnf_re = CNF_RE.get_or_init(|| {
        Regex::new(r"(?i)command not found:\s*([A-Za-z][A-Za-z0-9._-]*)|([A-Za-z][A-Za-z0-9._-]*):\s*command not found").unwrap()
    });
    if let Some(caps) = cnf_re.captures(err) {
        let bin = caps
            .get(1)
            .or_else(|| caps.get(2))
            .map(|m| m.as_str())
            .unwrap_or(&sp.cmd_bin);
        return Some(format!("command_not_found:{bin}"));
    }
    if lower.contains("installed but not activated") {
        return Some(format!("tool_not_activated:{}", sp.cmd_bin));
    }
    if lower.contains("cannot find module") || lower.contains("module_not_found") {
        return Some("missing_node_module".to_string());
    }
    if lower.contains("could not find `cargo.toml`") || lower.contains("could not find cargo.toml")
    {
        return Some("missing_root_cargo_toml".to_string());
    }
    if lower.contains("permission denied") {
        return Some(format!("permission_denied:{}", sp.cmd_bin));
    }
    if sp.exit_code == Some(127) {
        return Some(format!("exit_127:{}", sp.cmd_bin));
    }
    if sp.is_repo_cli {
        return Some(format!("cli_fail:{}", sp.cmd_template));
    }
    None
}

pub fn analyze_cross_session_patterns(
    conn: &Connection,
    repo_id: &str,
    range: &TimeRange,
) -> Result<CrossSessionPatternsReport> {
    let since_ms = range.since_ms;
    let until_ms = range.upper_bound();

    let repo_name: String = conn
        .query_row(
            "SELECT COALESCE(repo_name, repo_id) FROM sessions WHERE repo_id = ?1 LIMIT 1",
            params![repo_id],
            |r| r.get(0),
        )
        .unwrap_or_else(|_| repo_id.to_string());

    let mut s_stmt = conn.prepare(
        "SELECT session_id, agent_kind, COALESCE(originator, 'default'),
                COALESCE(subagent_kind, CASE WHEN is_subagent != 0 THEN 'subagent' ELSE 'main' END),
                is_subagent, is_handoff, COALESCE(started_at, ended_at, 0),
                turn_count, input_tokens, output_tokens, cached_tokens, total_tool_ms
         FROM sessions
         WHERE repo_id = ?1
           AND COALESCE(started_at, ended_at, 0) >= ?2
           AND COALESCE(started_at, ended_at, 0) < ?3
         ORDER BY started_at ASC",
    )?;
    let sessions: Vec<Sess> = s_stmt
        .query_map(params![repo_id, since_ms, until_ms], |r| {
            Ok(Sess {
                session_id: r.get(0)?,
                agent_kind: r.get(1)?,
                originator: r.get(2)?,
                role: r.get(3)?,
                is_subagent: r.get::<_, i64>(4)? != 0,
                is_handoff: r.get::<_, i64>(5)? != 0,
                started_at: r.get(6)?,
                turn_count: r.get(7)?,
                input_tokens: r.get(8)?,
                output_tokens: r.get(9)?,
                cached_tokens: r.get(10)?,
                total_tool_ms: r.get(11)?,
            })
        })?
        .flatten()
        .collect();

    let mut sp_stmt = conn.prepare(
        "SELECT COALESCE(session_id, 'orphan'), COALESCE(agent_kind, 'unknown'), turn_idx, workspace_id,
                category, is_repo_cli, cmd_bin, cmd_template, raw_redacted, exit_code, duration_ms,
                stdout_bytes, stdout_tokens, stderr_preview, is_truncated, started_at
         FROM command_spans
         WHERE repo_id = ?1
           AND started_at >= ?2 AND started_at < ?3
           AND (session_id IS NULL OR session_id IN (
               SELECT session_id FROM sessions
               WHERE repo_id = ?1
                 AND COALESCE(started_at, ended_at, 0) >= ?2
                 AND COALESCE(started_at, ended_at, 0) < ?3
           ))
         ORDER BY session_id ASC, turn_idx ASC, seq_idx ASC, started_at ASC",
    )?;
    let spans: Vec<Span> = sp_stmt
        .query_map(params![repo_id, since_ms, until_ms], |r| {
            Ok(Span {
                session_id: r.get(0)?,
                agent_kind: r.get(1)?,
                turn_idx: r.get(2)?,
                workspace_id: r.get(3)?,
                category: r.get(4)?,
                is_repo_cli: r.get::<_, i64>(5)? != 0,
                cmd_bin: r.get(6)?,
                cmd_template: r.get(7)?,
                raw_redacted: r.get(8)?,
                exit_code: r.get(9)?,
                duration_ms: r.get(10)?,
                stdout_bytes: r.get(11)?,
                stdout_tokens: r.get(12)?,
                stderr_preview: r.get(13)?,
                is_truncated: r.get::<_, i64>(14)? != 0,
                started_at: r.get(15)?,
            })
        })?
        .flatten()
        .collect();

    let mut tc_stmt = conn.prepare(
        "SELECT session_id, agent_kind, tool_name, is_error, output_bytes, is_truncated
         FROM tool_calls
         WHERE repo_id = ?1
           AND started_at >= ?2 AND started_at < ?3
           AND session_id IN (
               SELECT session_id FROM sessions
               WHERE repo_id = ?1
                 AND COALESCE(started_at, ended_at, 0) >= ?2
                 AND COALESCE(started_at, ended_at, 0) < ?3
           )",
    )?;
    let tcalls: Vec<TCall> = tc_stmt
        .query_map(params![repo_id, since_ms, until_ms], |r| {
            Ok(TCall {
                session_id: r.get(0)?,
                agent_kind: r.get(1)?,
                tool_name: r.get(2)?,
                is_error: r.get::<_, i64>(3)? != 0,
                output_bytes: r.get(4)?,
                is_truncated: r.get::<_, i64>(5)? != 0,
            })
        })?
        .flatten()
        .collect();

    let mut wt_stmt = conn.prepare(
        "SELECT worktree_path FROM workspaces WHERE repo_id = ?1 ORDER BY is_worktree ASC, updated_at DESC",
    )?;
    let worktree_paths: Vec<String> = wt_stmt
        .query_map(params![repo_id], |r| r.get::<_, String>(0))?
        .flatten()
        .collect();
    let repo_ctx = RepoContext::discover(&worktree_paths);

    let total_sessions = sessions.len().max(1);
    let main_sessions_vec: Vec<&Sess> = sessions.iter().filter(|s| !s.is_subagent).collect();
    let subagent_sessions = sessions.len().saturating_sub(main_sessions_vec.len());

    let mut spans_by_session: HashMap<&str, Vec<&Span>> = HashMap::new();
    for sp in &spans {
        spans_by_session
            .entry(sp.session_id.as_str())
            .or_default()
            .push(sp);
    }

    // Midpoint timestamp across sessions
    let start_times: Vec<i64> = sessions
        .iter()
        .map(|s| s.started_at)
        .filter(|&t| t > 0)
        .collect();
    let midpoint_ms = percentile_i64(&start_times, 50.0);
    let midpoint_iso = chrono::DateTime::from_timestamp_millis(midpoint_ms)
        .map(|d| d.to_rfc3339())
        .unwrap_or_default();

    // 0. Pareto Token Concentration on Main Sessions
    let mut main_sorted: Vec<&Sess> = main_sessions_vec.clone();
    main_sorted.sort_by_key(|s| std::cmp::Reverse(s.total_tokens()));
    let main_n = main_sorted.len();
    let total_main_toks: i64 = main_sorted.iter().map(|s| s.total_tokens()).sum();
    let top25_n = (main_n / 4).max(usize::from(main_n > 0));
    let bottom50_n = main_n / 2;
    let top25 = &main_sorted[..top25_n.min(main_n)];
    let bottom50 = if bottom50_n > 0 {
        &main_sorted[main_n - bottom50_n..]
    } else {
        &main_sorted[0..0]
    };

    let top25_toks_sum: i64 = top25.iter().map(|s| s.total_tokens()).sum();
    let top25_med = percentile_i64(
        &top25.iter().map(|s| s.total_tokens()).collect::<Vec<_>>(),
        50.0,
    );
    let bot50_med = percentile_i64(
        &bottom50
            .iter()
            .map(|s| s.total_tokens())
            .collect::<Vec<_>>(),
        50.0,
    );
    let avg_turns = |slice: &[&Sess]| -> f64 {
        if slice.is_empty() {
            0.0
        } else {
            r1(slice.iter().map(|s| s.turn_count as f64).sum::<f64>() / slice.len() as f64)
        }
    };
    let avg_stdout_kb = |slice: &[&Sess]| -> f64 {
        if slice.is_empty() {
            0.0
        } else {
            let bytes: i64 = slice
                .iter()
                .map(|s| {
                    spans_by_session
                        .get(s.session_id.as_str())
                        .map_or(0, |l| l.iter().map(|sp| sp.stdout_bytes).sum())
                })
                .sum();
            r1((bytes as f64 / 1024.0) / slice.len() as f64)
        }
    };

    // Storm prevalence (>= 5 calls of semantic family in one session) in Top25 vs Bottom50
    let mut fam_top25: HashMap<String, usize> = HashMap::new();
    let mut fam_bot50: HashMap<String, usize> = HashMap::new();
    let count_storms = |slice: &[&Sess], target: &mut HashMap<String, usize>| {
        for s in slice {
            let Some(list) = spans_by_session.get(s.session_id.as_str()) else {
                continue;
            };
            let mut per_fam: HashMap<String, usize> = HashMap::new();
            for sp in list {
                if !is_generic_read_or_script(&sp.cmd_template, &sp.category) {
                    *per_fam.entry(semantic_family(sp)).or_insert(0) += 1;
                }
            }
            for (fam, cnt) in per_fam {
                if cnt >= 5 {
                    *target.entry(fam).or_insert(0) += 1;
                }
            }
        }
    };
    count_storms(top25, &mut fam_top25);
    count_storms(bottom50, &mut fam_bot50);

    let mut storm_lifts: Vec<ParetoStormLift> = fam_top25
        .into_iter()
        .filter(|(_, c)| *c >= 3)
        .map(|(fam, t_cnt)| {
            let b_cnt = *fam_bot50.get(&fam).unwrap_or(&0);
            let t_pct = r1((t_cnt as f64 / top25.len().max(1) as f64) * 100.0);
            let b_pct = r1((b_cnt as f64 / bottom50.len().max(1) as f64) * 100.0);
            let lift_str = if b_cnt == 0 {
                "inf (0% in bot50)".to_string()
            } else {
                format!("{:.1}x", t_pct / b_pct.max(0.1))
            };
            ParetoStormLift {
                family: fam,
                top25_pct_sessions: t_pct,
                bottom50_pct_sessions: b_pct,
                lift_str,
            }
        })
        .collect();
    storm_lifts.sort_by(|a, b| b.top25_pct_sessions.total_cmp(&a.top25_pct_sessions));
    storm_lifts.truncate(8);

    let pareto = ParetoSummary {
        main_sessions: main_n,
        total_tokens_all_main: total_main_toks,
        top25_count: top25.len(),
        top25_token_share_pct: if total_main_toks > 0 {
            r1((top25_toks_sum as f64 / total_main_toks as f64) * 100.0)
        } else {
            0.0
        },
        top25_median_tokens: top25_med,
        bottom50_median_tokens: bot50_med,
        median_multiplier: if bot50_med > 0 {
            r1(top25_med as f64 / bot50_med as f64)
        } else {
            0.0
        },
        top25_avg_turns: avg_turns(top25),
        bottom50_avg_turns: avg_turns(bottom50),
        top25_avg_stdout_kb: avg_stdout_kb(top25),
        bottom50_avg_stdout_kb: avg_stdout_kb(bottom50),
        storm_lifts,
    };

    // Handoff vs Fresh session comparison on main sessions
    let handoff_main: Vec<&Sess> = main_sessions_vec
        .iter()
        .copied()
        .filter(|s| s.is_handoff)
        .collect();
    let fresh_main: Vec<&Sess> = main_sessions_vec
        .iter()
        .copied()
        .filter(|s| !s.is_handoff)
        .collect();
    let handoff_summary = if handoff_main.len() >= 2 && !fresh_main.is_empty() {
        let h_avg_tok =
            handoff_main.iter().map(|s| s.total_tokens()).sum::<i64>() / handoff_main.len() as i64;
        let f_avg_tok =
            fresh_main.iter().map(|s| s.total_tokens()).sum::<i64>() / fresh_main.len() as i64;
        let h_avg_turns = r1(handoff_main
            .iter()
            .map(|s| s.turn_count as f64)
            .sum::<f64>()
            / handoff_main.len() as f64);
        let f_avg_turns =
            r1(fresh_main.iter().map(|s| s.turn_count as f64).sum::<f64>()
                / fresh_main.len() as f64);
        Some(HandoffSummary {
            handoff_sessions: handoff_main.len(),
            fresh_sessions: fresh_main.len(),
            handoff_avg_tokens: h_avg_tok,
            fresh_avg_tokens: f_avg_tok,
            token_multiplier: if f_avg_tok > 0 {
                r1(h_avg_tok as f64 / f_avg_tok as f64)
            } else {
                0.0
            },
            handoff_avg_turns: h_avg_turns,
            fresh_avg_turns: f_avg_turns,
        })
    } else {
        None
    };

    // 1. Cross-Harness Asymmetry Stratified by (agent_kind, originator, role)
    let mut sess_by_group: HashMap<(String, String, String), Vec<&Sess>> = HashMap::new();
    let mut group_by_sid: HashMap<&str, (String, String, String)> = HashMap::new();
    for s in &sessions {
        let key = (s.agent_kind.clone(), s.originator.clone(), s.role.clone());
        group_by_sid.insert(s.session_id.as_str(), key.clone());
        sess_by_group.entry(key).or_default().push(s);
    }
    let mut spans_by_group: HashMap<(String, String, String), Vec<&Span>> = HashMap::new();
    for sp in &spans {
        let key = group_by_sid
            .get(sp.session_id.as_str())
            .cloned()
            .unwrap_or_else(|| {
                (
                    sp.agent_kind.clone(),
                    "default".to_string(),
                    "main".to_string(),
                )
            });
        spans_by_group.entry(key).or_default().push(sp);
    }
    let mut tcalls_by_group: HashMap<(String, String, String), Vec<&TCall>> = HashMap::new();
    for tc in &tcalls {
        let key = group_by_sid
            .get(tc.session_id.as_str())
            .cloned()
            .unwrap_or_else(|| {
                (
                    tc.agent_kind.clone(),
                    "default".to_string(),
                    "main".to_string(),
                )
            });
        tcalls_by_group.entry(key).or_default().push(tc);
    }

    let mut agent_friction_sets: HashMap<String, HashSet<String>> = HashMap::new();
    let mut harness_comparison = Vec::new();
    let mut group_keys: Vec<(String, String, String)> = sess_by_group.keys().cloned().collect();
    group_keys.sort();

    for key in group_keys {
        let (ag, orig, role) = key.clone();
        let g_sess = &sess_by_group[&key];
        let g_spans = spans_by_group.get(&key).map(Vec::as_slice).unwrap_or(&[]);
        let g_tcalls = tcalls_by_group.get(&key).map(Vec::as_slice).unwrap_or(&[]);
        let toks: Vec<i64> = g_sess
            .iter()
            .map(|s| s.total_tokens())
            .filter(|&v| v > 0)
            .collect();
        let waits: Vec<f64> = g_sess
            .iter()
            .map(|s| s.total_tool_ms as f64 / 1000.0)
            .filter(|&v| v > 0.0)
            .collect();
        let sum_in: i64 = g_sess.iter().map(|s| s.input_tokens).sum();
        let sum_cached: i64 = g_sess.iter().map(|s| s.cached_tokens).sum();
        let avg_uncached = if g_sess.is_empty() {
            0
        } else {
            sum_in / g_sess.len() as i64
        };
        let weighted_cache = if sum_in + sum_cached > 0 {
            Some(r3(sum_cached as f64 / (sum_in + sum_cached) as f64))
        } else {
            None
        };
        let per_sess_cache: Vec<f64> = g_sess.iter().filter_map(|s| s.cache_hit_rate()).collect();
        let med_cache = if per_sess_cache.is_empty() {
            None
        } else {
            Some(r3(percentile_f64(&per_sess_cache, 50.0)))
        };
        let p25_cache = if per_sess_cache.is_empty() {
            None
        } else {
            Some(r3(percentile_f64(&per_sess_cache, 25.0)))
        };

        let span_errs = g_spans
            .iter()
            .filter(|s| s.exit_code.is_some_and(|c| c != 0))
            .count();
        let tc_errs = g_tcalls.iter().filter(|t| t.is_error).count();
        let total_ops = g_spans.len() + g_tcalls.len();

        let total_out_bytes: i64 = g_spans.iter().map(|s| s.stdout_bytes).sum::<i64>()
            + g_tcalls.iter().map(|t| t.output_bytes).sum::<i64>();
        let avg_output_kb = if total_ops > 0 {
            r1((total_out_bytes as f64 / 1024.0) / total_ops as f64)
        } else {
            0.0
        };
        let mut trunc_sess: HashSet<&str> = HashSet::new();
        let mut trunc_cnt = 0usize;
        for sp in g_spans {
            if sp.is_truncated {
                trunc_cnt += 1;
                trunc_sess.insert(sp.session_id.as_str());
            }
        }
        for tc in g_tcalls {
            if tc.is_truncated {
                trunc_cnt += 1;
                trunc_sess.insert(tc.session_id.as_str());
            }
        }
        let trunc_sess_pct = r1((trunc_sess.len() as f64 / g_sess.len().max(1) as f64) * 100.0);

        let mut cli_calls = 0usize;
        let mut rebounds = 0usize;
        let mut friction_score: HashMap<String, i64> = HashMap::new();
        for i in 0..g_spans.len() {
            let sp = g_spans[i];
            if sp.is_repo_cli {
                cli_calls += 1;
                if let Some(nx) = g_spans.get(i + 1)
                    && nx.session_id == sp.session_id
                    && !nx.is_repo_cli
                    && (nx.category == "exploration" || nx.category == "vcs_ci")
                    && nx.turn_idx - sp.turn_idx <= 1
                {
                    rebounds += 1;
                }
            }
            if !is_generic_read_or_script(&sp.cmd_template, &sp.category) {
                let err_bonus = if sp.exit_code.is_some_and(|c| c != 0) {
                    3000
                } else {
                    0
                };
                let wait_bonus = sp.duration_ms.unwrap_or(0) / 10;
                *friction_score.entry(semantic_family(sp)).or_insert(0) +=
                    sp.stdout_tokens + err_bonus + wait_bonus;
            }
        }

        let mut top_f: Vec<(String, i64)> = friction_score.into_iter().collect();
        top_f.sort_by_key(|(_, sc)| std::cmp::Reverse(*sc));
        let top_cmds: Vec<String> = top_f.iter().take(5).map(|(k, _)| k.clone()).collect();
        if role == "main" {
            let set = agent_friction_sets.entry(ag.clone()).or_default();
            for (k, _) in top_f.iter().take(12) {
                set.insert(k.clone());
            }
        }

        harness_comparison.push(HarnessBreakdown {
            agent_kind: ag,
            originator: orig,
            role,
            sessions: g_sess.len(),
            commands: g_spans.len(),
            tool_calls: g_tcalls.len(),
            median_total_tokens: percentile_i64(&toks, 50.0),
            avg_uncached_tokens: avg_uncached,
            weighted_cache_hit: weighted_cache,
            median_cache_hit: med_cache,
            p25_cache_hit: p25_cache,
            avg_output_kb,
            truncated_outputs: trunc_cnt,
            truncated_sessions_pct: trunc_sess_pct,
            median_tool_wait_s: r1(percentile_f64(&waits, 50.0)),
            error_rate: if total_ops == 0 {
                0.0
            } else {
                r3((span_errs + tc_errs) as f64 / total_ops as f64)
            },
            rebound_rate: if cli_calls > 0 {
                r3(rebounds as f64 / cli_calls as f64)
            } else {
                0.0
            },
            top_friction_cmds: top_cmds,
        });
    }

    let mut cmd_harness_cnt: HashMap<String, usize> = HashMap::new();
    for set in agent_friction_sets.values() {
        for c in set {
            *cmd_harness_cnt.entry(c.clone()).or_insert(0) += 1;
        }
    }
    let mut universal_friction_cmds: Vec<String> = cmd_harness_cnt
        .into_iter()
        .filter(|(_, c)| *c >= 2)
        .map(|(k, _)| k)
        .collect();
    universal_friction_cmds.sort();

    // 2. Recurring Multi-Session Harness Motifs (excluding generic exploration/scripting noise)
    let mut sess_turns: HashMap<&str, i64> = HashMap::new();
    for s in &sessions {
        sess_turns.insert(s.session_id.as_str(), s.turn_count.max(1));
    }
    let eff_toks = |sp: &Span| -> i64 {
        let total_t = sess_turns
            .get(sp.session_id.as_str())
            .copied()
            .unwrap_or(sp.turn_idx.max(1));
        let rem = (total_t - sp.turn_idx + 1).clamp(1, 25);
        sp.stdout_tokens.saturating_mul(rem)
    };

    struct MotifAcc {
        kind: &'static str,
        sessions: HashSet<String>,
        agents: HashSet<String>,
        by_harness: BTreeMap<String, usize>,
        occurrences: usize,
        tokens: i64,
        eff_tokens: i64,
        wait_ms: i64,
        sample: String,
    }
    let mut motifs: HashMap<String, MotifAcc> = HashMap::new();

    for (sid, list) in &spans_by_session {
        for i in 0..list.len() {
            let cur = list[i];
            let Some(nx) = list.get(i + 1).copied() else {
                continue;
            };
            if nx.turn_idx - cur.turn_idx > 2 {
                continue;
            }
            if is_generic_read_or_script(&cur.cmd_template, &cur.category)
                || is_generic_read_or_script(&nx.cmd_template, &nx.category)
            {
                continue;
            }

            let kind = if cur.exit_code.is_some_and(|c| c != 0) {
                "failure_to_workaround"
            } else if cur.is_repo_cli && !nx.is_repo_cli {
                "cli_to_raw_rebound"
            } else if cur.cmd_template != nx.cmd_template {
                "workflow_sequence"
            } else {
                continue;
            };

            let seq_key = format!("{} -> {}", cur.cmd_template, nx.cmd_template);
            let m = motifs.entry(seq_key).or_insert_with(|| MotifAcc {
                kind,
                sessions: HashSet::new(),
                agents: HashSet::new(),
                by_harness: BTreeMap::new(),
                occurrences: 0,
                tokens: 0,
                eff_tokens: 0,
                wait_ms: 0,
                sample: format!(
                    "t{}: `{}` (exit={}) -> t{}: `{}`",
                    cur.turn_idx,
                    trunc(&cur.raw_redacted, 65),
                    cur.exit_code.map_or("?".into(), |c| c.to_string()),
                    nx.turn_idx,
                    trunc(&nx.raw_redacted, 65)
                ),
            });
            m.sessions.insert((*sid).to_string());
            m.agents.insert(cur.agent_kind.clone());
            *m.by_harness.entry(cur.agent_kind.clone()).or_insert(0) += 1;
            m.occurrences += 1;
            m.tokens += cur.stdout_tokens + nx.stdout_tokens;
            m.eff_tokens += eff_toks(cur) + eff_toks(nx);
            m.wait_ms += cur.duration_ms.unwrap_or(0) + nx.duration_ms.unwrap_or(0);
        }
    }

    let mut recurring_motifs: Vec<RecurringMotif> = motifs
        .into_iter()
        .filter(|(_, m)| m.sessions.len() >= 3 && m.occurrences >= 4)
        .map(|(seq, m)| {
            let mut ags: Vec<String> = m.agents.into_iter().collect();
            ags.sort();
            let hs = format_harness_breakdown(&m.by_harness);
            RecurringMotif {
                motif_kind: m.kind.to_string(),
                sequence: seq,
                sessions: m.sessions.len(),
                total_sessions,
                session_prevalence: r3(m.sessions.len() as f64 / total_sessions as f64),
                occurrences: m.occurrences,
                agents: ags,
                by_harness: m.by_harness,
                harness_summary: hs,
                total_stdout_tokens: m.tokens,
                total_effective_tokens: m.eff_tokens,
                total_wait_s: r1(m.wait_ms as f64 / 1000.0),
                sample_trace: m.sample,
            }
        })
        .collect();
    recurring_motifs.sort_by(|a, b| {
        b.sessions
            .cmp(&a.sessions)
            .then_with(|| b.occurrences.cmp(&a.occurrences))
    });
    recurring_motifs.truncate(15);

    // 2b. Maximal Multi-Step Repeating Call Sequences (3..=10 steps across >=2 sessions)
    let repeating_sequences = mine_sequences_from_spans(
        &spans_by_session,
        &sess_turns,
        total_sessions,
        3,
        10,
        2,
        false,
        "impact",
        15,
    );

    // 3. Rate-Normalized Per-1k-Commands Temporal Drift (Early Half vs Recent Half by semantic family)
    let early_cmds = spans
        .iter()
        .filter(|s| s.started_at < midpoint_ms)
        .count()
        .max(1);
    let recent_cmds = spans
        .iter()
        .filter(|s| s.started_at >= midpoint_ms)
        .count()
        .max(1);
    let early_errs = spans
        .iter()
        .filter(|s| s.started_at < midpoint_ms && s.exit_code.is_some_and(|c| c != 0))
        .count();
    let recent_errs = spans
        .iter()
        .filter(|s| s.started_at >= midpoint_ms && s.exit_code.is_some_and(|c| c != 0))
        .count();
    let early_error_rate = r3(early_errs as f64 / early_cmds as f64);
    let recent_error_rate = r3(recent_errs as f64 / recent_cmds as f64);

    struct HalfAcc {
        runs: usize,
        errors: usize,
        toks: Vec<i64>,
        durs: Vec<i64>,
        by_harness: BTreeMap<String, usize>,
    }
    let mut drift_map: HashMap<String, (HalfAcc, HalfAcc)> = HashMap::new();
    for sp in &spans {
        if is_generic_read_or_script(&sp.cmd_template, &sp.category) {
            continue;
        }
        let fam = semantic_family(sp);
        let pair = drift_map.entry(fam).or_insert_with(|| {
            (
                HalfAcc {
                    runs: 0,
                    errors: 0,
                    toks: Vec::new(),
                    durs: Vec::new(),
                    by_harness: BTreeMap::new(),
                },
                HalfAcc {
                    runs: 0,
                    errors: 0,
                    toks: Vec::new(),
                    durs: Vec::new(),
                    by_harness: BTreeMap::new(),
                },
            )
        });
        let h = if sp.started_at < midpoint_ms {
            &mut pair.0
        } else {
            &mut pair.1
        };
        h.runs += 1;
        *h.by_harness.entry(sp.agent_kind.clone()).or_insert(0) += 1;
        if sp.exit_code.is_some_and(|c| c != 0) {
            h.errors += 1;
        }
        h.toks.push(sp.stdout_tokens);
        if let Some(d) = sp.duration_ms {
            h.durs.push(d);
        }
    }

    let mut temporal_drift = Vec::new();
    for (fam, (early, recent)) in drift_map {
        if early.runs + recent.runs < 12 {
            continue;
        }
        let mut total_by_harness = early.by_harness.clone();
        for (k, v) in &recent.by_harness {
            *total_by_harness.entry(k.clone()).or_insert(0) += *v;
        }
        let hs = format_harness_breakdown(&total_by_harness);
        let e_per_1k = r1((early.runs as f64 / early_cmds as f64) * 1000.0);
        let r_per_1k = r1((recent.runs as f64 / recent_cmds as f64) * 1000.0);
        let ratio = if e_per_1k > 0.05 {
            r1(r_per_1k / e_per_1k)
        } else if r_per_1k > 0.0 {
            99.0
        } else {
            1.0
        };
        let e_err = if early.runs > 0 {
            r3(early.errors as f64 / early.runs as f64)
        } else {
            0.0
        };
        let r_err = if recent.runs > 0 {
            r3(recent.errors as f64 / recent.runs as f64)
        } else {
            0.0
        };
        let e_tok = percentile_i64(&early.toks, 50.0);
        let r_tok = percentile_i64(&recent.toks, 50.0);
        let e_wait = r1(percentile_i64(&early.durs, 50.0) as f64 / 1000.0);
        let r_wait = r1(percentile_i64(&recent.durs, 50.0) as f64 / 1000.0);

        let surging = ratio >= 1.6 && recent.runs >= 10;
        let err_up = early.runs >= 5 && recent.runs >= 5 && r_err > e_err + 0.04;
        let tok_up = early.runs >= 5
            && recent.runs >= 5
            && e_tok >= 100
            && r_tok as f64 > e_tok as f64 * 1.4;
        let falling = ratio <= 0.65 && early.runs >= 10;
        let err_down = early.runs >= 5 && recent.runs >= 5 && e_err > r_err + 0.04;

        let (status, summary) = if surging {
            (
                "surging",
                format!(
                    "{e_per_1k:.1} -> {r_per_1k:.1}/1k cmds ({ratio:.1}x; err {:.0}%->{:.0}%)",
                    e_err * 100.0,
                    r_err * 100.0
                ),
            )
        } else if err_up || tok_up {
            let mut parts = Vec::new();
            if err_up {
                parts.push(format!("err {:.0}%->{:.0}%", e_err * 100.0, r_err * 100.0));
            }
            if tok_up {
                parts.push(format!(
                    "p50 toks {}->{}",
                    format_compact(e_tok),
                    format_compact(r_tok)
                ));
            }
            ("regressing", parts.join(", "))
        } else if falling || err_down {
            (
                "improving",
                format!(
                    "{e_per_1k:.1} -> {r_per_1k:.1}/1k cmds ({ratio:.2}x; err {:.0}%->{:.0}%)",
                    e_err * 100.0,
                    r_err * 100.0
                ),
            )
        } else if early.runs >= 10
            && recent.runs >= 10
            && (r_err >= 0.06 || r_tok >= 400 || r_wait >= 4.0)
        {
            (
                "chronic",
                format!(
                    "steady {e_per_1k:.1}/{r_per_1k:.1} per 1k (err {:.0}%, p50 {}toks/{r_wait:.1}s)",
                    r_err * 100.0,
                    format_compact(r_tok)
                ),
            )
        } else {
            continue;
        };

        temporal_drift.push(TemporalDriftItem {
            status: status.to_string(),
            cmd_family: fam,
            early_runs: early.runs,
            recent_runs: recent.runs,
            early_per_1k: e_per_1k,
            recent_per_1k: r_per_1k,
            rate_ratio: ratio,
            early_error_rate: e_err,
            recent_error_rate: r_err,
            early_p50_tokens: e_tok,
            recent_p50_tokens: r_tok,
            early_p50_wait_s: e_wait,
            recent_p50_wait_s: r_wait,
            by_harness: total_by_harness,
            harness_summary: hs,
            summary,
        });
    }
    // Keep both top regressions/surges (up to 12) AND top genuine improvements (up to 6)
    let mut bad_drift: Vec<TemporalDriftItem> = temporal_drift
        .iter()
        .filter(|d| d.status != "improving")
        .cloned()
        .collect();
    bad_drift.sort_by(|a, b| {
        let rank = |s: &str| match s {
            "surging" => 0,
            "regressing" => 1,
            _ => 2,
        };
        rank(&a.status)
            .cmp(&rank(&b.status))
            .then_with(|| b.rate_ratio.total_cmp(&a.rate_ratio))
    });
    bad_drift.truncate(12);

    let mut good_drift: Vec<TemporalDriftItem> = temporal_drift
        .into_iter()
        .filter(|d| d.status == "improving")
        .collect();
    good_drift.sort_by(|a, b| a.rate_ratio.total_cmp(&b.rate_ratio));
    good_drift.truncate(6);
    bad_drift.extend(good_drift);
    let temporal_drift = bad_drift;

    // 4. Cold-Start (Turns 1-3) Missing-Binary & Environment Error Classifier
    struct ColdAcc {
        early_fails: usize,
        total_fails: usize,
        sessions: HashSet<String>,
        worktrees: HashSet<String>,
        early_by_harness: BTreeMap<String, usize>,
        sample_cmd: String,
        sample_stderr: String,
    }
    let mut cold_map: HashMap<String, ColdAcc> = HashMap::new();
    for sp in &spans {
        if !sp.exit_code.is_some_and(|c| c != 0) {
            continue;
        }
        let Some(cls) = classify_cold_error(sp) else {
            continue;
        };
        let e = cold_map.entry(cls).or_insert_with(|| ColdAcc {
            early_fails: 0,
            total_fails: 0,
            sessions: HashSet::new(),
            worktrees: HashSet::new(),
            early_by_harness: BTreeMap::new(),
            sample_cmd: trunc(&sp.raw_redacted, 95),
            sample_stderr: trunc(sp.stderr_preview.as_deref().unwrap_or(""), 150),
        });
        e.total_fails += 1;
        if sp.turn_idx <= 3 {
            e.early_fails += 1;
            e.sessions.insert(sp.session_id.clone());
            *e.early_by_harness.entry(sp.agent_kind.clone()).or_insert(0) += 1;
            if let Some(w) = &sp.workspace_id {
                e.worktrees.insert(w.clone());
            }
        }
    }
    let mut cold_start_errors: Vec<ColdStartErrorClass> = cold_map
        .into_iter()
        .filter(|(_, c)| c.early_fails >= 2 || (c.total_fails >= 3 && c.early_fails >= 1))
        .map(|(cls, c)| {
            let hs = format_harness_breakdown(&c.early_by_harness);
            ColdStartErrorClass {
                error_class: cls,
                failures_turns_1_3: c.early_fails,
                total_failures: c.total_fails,
                pct_in_turns_1_3: r1((c.early_fails as f64 / c.total_fails.max(1) as f64) * 100.0),
                sessions: c.sessions.len(),
                worktrees: c.worktrees.len(),
                by_harness: c.early_by_harness,
                harness_summary: hs,
                sample_cmd: c.sample_cmd,
                sample_stderr: c.sample_stderr,
            }
        })
        .collect();
    cold_start_errors.sort_by(|a, b| {
        b.failures_turns_1_3
            .cmp(&a.failures_turns_1_3)
            .then_with(|| b.sessions.cmp(&a.sessions))
    });
    cold_start_errors.truncate(15);

    // 5. Context-Bloat / High-Token Session Drivers (p75+ vs Normal sessions)
    let all_sess_toks: Vec<i64> = sessions
        .iter()
        .map(|s| s.total_tokens())
        .filter(|&v| v > 0)
        .collect();
    let p75_toks = percentile_i64(&all_sess_toks, 75.0);
    let high_sess_ids: HashSet<&str> = sessions
        .iter()
        .filter(|s| s.total_tokens() >= p75_toks && p75_toks > 0)
        .map(|s| s.session_id.as_str())
        .collect();
    let high_n = high_sess_ids.len().max(1) as f64;
    let norm_n = sessions.len().saturating_sub(high_sess_ids.len()).max(1) as f64;

    struct BloatAcc {
        cat: String,
        high_calls: usize,
        norm_calls: usize,
        high_sess: HashSet<String>,
        toks: i64,
        wait_ms: i64,
    }
    let mut bloat_map: HashMap<&str, BloatAcc> = HashMap::new();
    for sp in &spans {
        if is_generic_read_or_script(&sp.cmd_template, &sp.category) {
            continue;
        }
        let b = bloat_map
            .entry(sp.cmd_template.as_str())
            .or_insert_with(|| BloatAcc {
                cat: sp.category.clone(),
                high_calls: 0,
                norm_calls: 0,
                high_sess: HashSet::new(),
                toks: 0,
                wait_ms: 0,
            });
        if high_sess_ids.contains(sp.session_id.as_str()) {
            b.high_calls += 1;
            b.high_sess.insert(sp.session_id.clone());
        } else {
            b.norm_calls += 1;
        }
        b.toks += sp.stdout_tokens;
        b.wait_ms += sp.duration_ms.unwrap_or(0);
    }

    let mut context_bloat_drivers: Vec<BloatDriver> = bloat_map
        .into_iter()
        .filter(|(_, b)| b.high_sess.len() >= 3 && b.high_calls >= 10)
        .filter_map(|(tpl, b)| {
            let hr = b.high_calls as f64 / high_n;
            let nr = (b.norm_calls as f64 / norm_n).max(0.05);
            let ratio = hr / nr;
            if ratio < 1.8 {
                return None;
            }
            Some(BloatDriver {
                cmd_template: tpl.to_string(),
                category: b.cat,
                high_cost_rate: r1(hr),
                normal_cost_rate: r1(b.norm_calls as f64 / norm_n),
                enrichment_ratio: r1(ratio),
                high_cost_sessions: b.high_sess.len(),
                total_stdout_tokens: b.toks,
                total_wait_s: r1(b.wait_ms as f64 / 1000.0),
            })
        })
        .collect();
    context_bloat_drivers.sort_by(|a, b| {
        b.enrichment_ratio
            .total_cmp(&a.enrichment_ratio)
            .then_with(|| b.total_stdout_tokens.cmp(&a.total_stdout_tokens))
    });
    context_bloat_drivers.truncate(12);

    // 6. Burst / Serial Command Storms (>= 5 calls of same cmd_template in one session, harness/infra only)
    struct StormAcc {
        storm_sessions: usize,
        total_calls: usize,
        max_calls: usize,
        stdout_tokens: i64,
        eff_tokens: i64,
        wait_ms: i64,
        agents: HashSet<String>,
        by_harness: BTreeMap<String, usize>,
    }
    let mut storm_map: HashMap<&str, StormAcc> = HashMap::new();
    for list in spans_by_session.values() {
        let mut counts: HashMap<&str, (usize, i64, i64, i64, &str)> = HashMap::new();
        for sp in list {
            if is_generic_read_or_script(&sp.cmd_template, &sp.category) {
                continue;
            }
            let e = counts.entry(sp.cmd_template.as_str()).or_insert((
                0,
                0,
                0,
                0,
                sp.agent_kind.as_str(),
            ));
            e.0 += 1;
            e.1 += sp.duration_ms.unwrap_or(0);
            e.2 += sp.stdout_tokens;
            e.3 += eff_toks(sp);
        }
        for (tpl, (cnt, ms, stoks, etoks, ag)) in counts {
            if cnt >= 5 {
                let s = storm_map.entry(tpl).or_insert_with(|| StormAcc {
                    storm_sessions: 0,
                    total_calls: 0,
                    max_calls: 0,
                    stdout_tokens: 0,
                    eff_tokens: 0,
                    wait_ms: 0,
                    agents: HashSet::new(),
                    by_harness: BTreeMap::new(),
                });
                s.storm_sessions += 1;
                s.total_calls += cnt;
                s.max_calls = s.max_calls.max(cnt);
                s.stdout_tokens += stoks;
                s.eff_tokens += etoks;
                s.wait_ms += ms;
                s.agents.insert(ag.to_string());
                *s.by_harness.entry(ag.to_string()).or_insert(0) += cnt;
            }
        }
    }

    let mut burst_storms: Vec<BurstStorm> = storm_map
        .into_iter()
        .filter(|(_, s)| s.storm_sessions >= 2 || s.max_calls >= 12)
        .map(|(tpl, s)| {
            let mut ags: Vec<String> = s.agents.into_iter().collect();
            ags.sort();
            let hs = format_harness_breakdown(&s.by_harness);
            BurstStorm {
                cmd_template: tpl.to_string(),
                storm_sessions: s.storm_sessions,
                total_calls_in_storms: s.total_calls,
                max_calls_in_session: s.max_calls,
                total_stdout_tokens: s.stdout_tokens,
                total_effective_tokens: s.eff_tokens,
                total_wait_s: r1(s.wait_ms as f64 / 1000.0),
                agents: ags,
                by_harness: s.by_harness,
                harness_summary: hs,
            }
        })
        .collect();
    burst_storms.sort_by(|a, b| {
        b.storm_sessions
            .cmp(&a.storm_sessions)
            .then_with(|| b.total_calls_in_storms.cmp(&a.total_calls_in_storms))
    });
    burst_storms.truncate(15);

    // 7. Post-CLI Follow-Up Doc/Config Read Correlation (general-purpose across all repos)
    let mut doc_reads_by_sess: HashMap<String, Vec<(i64, i64, String)>> = HashMap::new();
    {
        let mut fr_stmt = conn.prepare(
            "SELECT session_id, turn_idx, started_at, target_name
             FROM file_reads
             WHERE repo_id = ?1
               AND started_at >= ?2 AND started_at < ?3
               AND is_doc = 1
               AND session_id IN (
                   SELECT session_id FROM sessions
                   WHERE repo_id = ?1
                     AND COALESCE(started_at, ended_at, 0) >= ?2
                     AND COALESCE(started_at, ended_at, 0) < ?3
               )",
        )?;
        let rows = fr_stmt.query_map(params![repo_id, since_ms, until_ms], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        for row in rows.flatten() {
            doc_reads_by_sess
                .entry(row.0)
                .or_default()
                .push((row.1, row.2, row.3));
        }
    }
    for sp in &spans {
        if matches!(
            sp.cmd_bin.as_str(),
            "cat" | "sed" | "head" | "tail" | "rg" | "grep"
        ) {
            let lower = sp.raw_redacted.to_ascii_lowercase();
            let doc_hit = if lower.contains("readme") {
                Some("README.md")
            } else if lower.contains("mise.toml") {
                Some("mise.toml")
            } else if lower.contains("agents.md") {
                Some("AGENTS.md")
            } else if lower.contains("claude.md") {
                Some("CLAUDE.md")
            } else if lower.contains("makefile") {
                Some("Makefile")
            } else if lower.contains("package.json") {
                Some("package.json")
            } else {
                None
            };
            if let Some(fname) = doc_hit {
                doc_reads_by_sess
                    .entry(sp.session_id.clone())
                    .or_default()
                    .push((sp.turn_idx, sp.started_at, fname.to_string()));
            }
        }
    }
    struct PostReadAcc {
        runs: usize,
        followed: usize,
        by_harness: BTreeMap<String, usize>,
        files: HashMap<String, usize>,
    }
    let mut post_read_map: HashMap<String, PostReadAcc> = HashMap::new();
    for sp in &spans {
        if !sp.is_repo_cli {
            continue;
        }
        let fam = semantic_family(sp);
        let acc = post_read_map.entry(fam).or_insert_with(|| PostReadAcc {
            runs: 0,
            followed: 0,
            by_harness: BTreeMap::new(),
            files: HashMap::new(),
        });
        acc.runs += 1;
        if let Some(dreads) = doc_reads_by_sess.get(&sp.session_id) {
            let mut matched_files: HashSet<&str> = HashSet::new();
            for (dturn, dts, dfname) in dreads {
                let in_window = (*dturn == sp.turn_idx
                    && *dts > sp.started_at
                    && *dts <= sp.started_at + 120_000)
                    || (*dturn > sp.turn_idx && *dturn <= sp.turn_idx + 2 && *dts > sp.started_at);
                if in_window {
                    matched_files.insert(dfname.as_str());
                }
            }
            if !matched_files.is_empty() {
                acc.followed += 1;
                *acc.by_harness.entry(sp.agent_kind.clone()).or_insert(0) += 1;
                for f in matched_files {
                    *acc.files.entry(f.to_string()).or_insert(0) += 1;
                }
            }
        }
    }
    let mut post_cli_doc_reads: Vec<PostCliDocRead> = post_read_map
        .into_iter()
        .filter(|(_, a)| a.runs >= 10 && a.followed >= 3)
        .filter_map(|(fam, a)| {
            let rate = r3(a.followed as f64 / a.runs as f64);
            if rate < 0.15 {
                return None;
            }
            let mut fv: Vec<(String, usize)> = a.files.into_iter().collect();
            fv.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
            let hs = format_harness_breakdown(&a.by_harness);
            Some(PostCliDocRead {
                cmd_template: fam,
                runs: a.runs,
                followed_by_doc_read: a.followed,
                follow_up_rate: rate,
                by_harness: a.by_harness,
                harness_summary: hs,
                top_doc_files: fv
                    .into_iter()
                    .take(3)
                    .map(|(f, c)| format!("{f} ({c}x)"))
                    .collect(),
            })
        })
        .collect();
    post_cli_doc_reads.sort_by(|a, b| {
        b.follow_up_rate
            .total_cmp(&a.follow_up_rate)
            .then_with(|| b.followed_by_doc_read.cmp(&a.followed_by_doc_read))
    });
    post_cli_doc_reads.truncate(10);

    // 8. Top Failing Non-Shell / MCP Tools
    let top_mcp_errors = query_tools(conn, repo_id, range, "errors", true, 12)?
        .into_iter()
        .filter(|t| t.error_count > 0 || t.truncated_count >= 5)
        .collect::<Vec<_>>();

    // 9. Underused / Zero-Adoption Documented Tools & Repo Tasks
    let mut underused_surfaces = Vec::new();
    let mut tool_call_counts: HashMap<String, usize> = HashMap::new();
    for tc in &tcalls {
        let lower = tc.tool_name.to_ascii_lowercase();
        *tool_call_counts.entry(lower.clone()).or_insert(0) += 1;
        if let Some(tail) = lower.rsplit(':').next() {
            *tool_call_counts.entry(tail.to_string()).or_insert(0) += 1;
        }
    }
    for mtool in &repo_ctx.mentioned_tools {
        let lower = mtool.to_ascii_lowercase();
        let cnt = *tool_call_counts.get(&lower).unwrap_or(&0);
        let span_cnt = spans
            .iter()
            .filter(|s| s.raw_redacted.to_ascii_lowercase().contains(&lower))
            .count();
        if cnt == 0 && span_cnt == 0 {
            underused_surfaces.push(UnderusedSurface {
                surface_kind: "documented_tool".to_string(),
                name: mtool.clone(),
                observed_calls: 0,
                note: "Mentioned in AGENTS.md/CLAUDE.md but 0 calls observed in window".to_string(),
            });
        }
    }
    let mut task_call_counts: HashMap<String, usize> = HashMap::new();
    for sp in &spans {
        if sp.is_repo_cli {
            let fam = semantic_family(sp);
            if let Some(t) = fam.strip_prefix("mise:") {
                *task_call_counts.entry(t.to_string()).or_insert(0) += 1;
            }
        }
    }
    let raw_git_diff_runs = spans
        .iter()
        .filter(|s| s.cmd_template.starts_with("git diff"))
        .count();
    for task in &repo_ctx.defined_tasks {
        let cnt = *task_call_counts.get(task).unwrap_or(&0);
        if (1..=5).contains(&cnt) {
            let note = if task.contains("change") && raw_git_diff_runs >= 20 {
                format!("Only {cnt} run(s) vs {raw_git_diff_runs} raw `git diff` calls")
            } else {
                format!("Defined task with only {cnt} run(s) in window")
            };
            underused_surfaces.push(UnderusedSurface {
                surface_kind: "repo_task".to_string(),
                name: task.clone(),
                observed_calls: cnt,
                note,
            });
        }
    }
    underused_surfaces.truncate(15);

    Ok(CrossSessionPatternsReport {
        repo_id: repo_id.to_string(),
        repo_name,
        window: range.label.clone(),
        branch_behind_notice: repo_ctx.branch_behind_notice,
        sessions_analyzed: sessions.len(),
        main_sessions: main_n,
        subagent_sessions,
        midpoint_iso,
        early_cmds,
        recent_cmds,
        early_error_rate,
        recent_error_rate,
        pareto,
        handoff_summary,
        harness_comparison,
        universal_friction_cmds,
        recurring_motifs,
        repeating_sequences,
        temporal_drift,
        cold_start_errors,
        context_bloat_drivers,
        burst_storms,
        post_cli_doc_reads,
        top_mcp_errors,
        underused_surfaces,
    })
}

#[allow(clippy::too_many_arguments)]
fn mine_sequences_from_spans(
    spans_by_session: &HashMap<&str, Vec<&Span>>,
    sess_turns: &HashMap<&str, i64>,
    total_sessions: usize,
    min_len: usize,
    max_len: usize,
    min_sessions: usize,
    include_exploration: bool,
    sort_by: &str,
    limit: usize,
) -> Vec<RepeatingSequence> {
    let min_l = min_len.clamp(2, 20);
    let max_l = max_len.clamp(min_l, 20);

    struct SeqAcc {
        steps: Vec<String>,
        sessions: HashSet<String>,
        agents: HashSet<String>,
        by_harness: BTreeMap<String, usize>,
        occurrences: usize,
        stdout_tokens: i64,
        eff_tokens: i64,
        wait_ms: i64,
        sample: String,
    }
    let mut acc_map: HashMap<Vec<String>, SeqAcc> = HashMap::new();

    for (sid, raw_list) in spans_by_session {
        let total_t = sess_turns.get(sid).copied().unwrap_or(1);
        let filtered: Vec<&Span> = raw_list
            .iter()
            .copied()
            .filter(|sp| {
                include_exploration || !is_generic_read_or_script(&sp.cmd_template, &sp.category)
            })
            .collect();
        if filtered.len() < min_l {
            continue;
        }

        // Slide non-overlapping windows for each length `len` so a single repeating block isn't overcounted
        for len in min_l..=max_l {
            if filtered.len() < len {
                break;
            }
            let mut last_end_for_key: HashMap<Vec<String>, usize> = HashMap::new();
            for start in 0..=(filtered.len() - len) {
                let slice = &filtered[start..start + len];
                // Keep coherent chains (no huge idle turn jumps between adjacent steps)
                let coherent = slice.windows(2).all(|w| w[1].turn_idx - w[0].turn_idx <= 4);
                if !coherent {
                    continue;
                }
                let steps: Vec<String> = slice.iter().map(|s| s.cmd_template.clone()).collect();
                if let Some(&prev_end) = last_end_for_key.get(&steps)
                    && start < prev_end
                {
                    continue;
                }
                last_end_for_key.insert(steps.clone(), start + len);

                let stoks: i64 = slice.iter().map(|s| s.stdout_tokens).sum();
                let etoks: i64 = slice
                    .iter()
                    .map(|s| {
                        let rem = (total_t - s.turn_idx + 1).clamp(1, 25);
                        s.stdout_tokens.saturating_mul(rem)
                    })
                    .sum();
                let wms: i64 = slice.iter().filter_map(|s| s.duration_ms).sum();

                let entry = acc_map.entry(steps.clone()).or_insert_with(|| {
                    let preview_steps: Vec<String> = slice
                        .iter()
                        .take(4)
                        .map(|s| format!("t{}:`{}`", s.turn_idx, trunc(&s.raw_redacted, 40)))
                        .collect();
                    let sample = if slice.len() > 4 {
                        format!(
                            "{} -> ... (+{} more)",
                            preview_steps.join(" -> "),
                            slice.len() - 4
                        )
                    } else {
                        preview_steps.join(" -> ")
                    };
                    SeqAcc {
                        steps,
                        sessions: HashSet::new(),
                        agents: HashSet::new(),
                        by_harness: BTreeMap::new(),
                        occurrences: 0,
                        stdout_tokens: 0,
                        eff_tokens: 0,
                        wait_ms: 0,
                        sample,
                    }
                });
                entry.sessions.insert((*sid).to_string());
                for s in slice {
                    entry.agents.insert(s.agent_kind.clone());
                }
                if let Some(first) = slice.first() {
                    *entry
                        .by_harness
                        .entry(first.agent_kind.clone())
                        .or_insert(0) += 1;
                }
                entry.occurrences += 1;
                entry.stdout_tokens += stoks;
                entry.eff_tokens += etoks;
                entry.wait_ms += wms;
            }
        }
    }

    let mut candidates: Vec<RepeatingSequence> = acc_map
        .into_values()
        .filter(|a| {
            let distinct: HashSet<&str> = a.steps.iter().map(String::as_str).collect();
            a.sessions.len() >= min_sessions && a.occurrences >= 2 && distinct.len() >= 2
        })
        .map(|a| {
            let mut ags: Vec<String> = a.agents.into_iter().collect();
            ags.sort();
            let step_count = a.steps.len();
            let seq_str = format_collapsed_steps(&a.steps);
            let hs = format_harness_breakdown(&a.by_harness);
            RepeatingSequence {
                step_count,
                sequence: seq_str,
                steps: a.steps,
                sessions: a.sessions.len(),
                total_sessions,
                session_prevalence: r3(a.sessions.len() as f64 / total_sessions.max(1) as f64),
                occurrences: a.occurrences,
                total_calls: a.occurrences * step_count,
                total_stdout_tokens: a.stdout_tokens,
                total_effective_tokens: a.eff_tokens,
                total_wait_s: r1(a.wait_ms as f64 / 1000.0),
                agents: ags,
                by_harness: a.by_harness,
                harness_summary: hs,
                sample_trace: a.sample,
            }
        })
        .collect();

    // Maximal & shifted-window deduplication:
    // 1. Drop shorter sub-sequences absorbed by a longer sequence with >=75% of its session reach.
    // 2. Drop shifted overlapping windows (same or shorter length sharing >=65% contiguous steps) of an already-kept sequence.
    candidates.sort_by(|a, b| {
        b.step_count
            .cmp(&a.step_count)
            .then_with(|| b.sessions.cmp(&a.sessions))
            .then_with(|| b.total_effective_tokens.cmp(&a.total_effective_tokens))
            .then_with(|| b.occurrences.cmp(&a.occurrences))
    });
    let mut kept: Vec<RepeatingSequence> = Vec::new();
    for cand in candidates {
        let absorbed = kept.iter().any(|existing| {
            if existing.step_count > cand.step_count
                && existing.sessions * 4 >= cand.sessions * 3
                && is_subslice(&cand.steps, &existing.steps)
            {
                return true;
            }
            if existing.sessions * 4 >= cand.sessions * 3
                && shifted_overlap_ratio(&cand.steps, &existing.steps) >= 0.65
            {
                return true;
            }
            false
        });
        if !absorbed {
            kept.push(cand);
        }
    }

    match sort_by {
        "sessions" => kept.sort_by(|a, b| {
            b.sessions
                .cmp(&a.sessions)
                .then_with(|| b.step_count.cmp(&a.step_count))
                .then_with(|| b.occurrences.cmp(&a.occurrences))
        }),
        "len" => kept.sort_by(|a, b| {
            b.step_count
                .cmp(&a.step_count)
                .then_with(|| b.sessions.cmp(&a.sessions))
                .then_with(|| b.total_effective_tokens.cmp(&a.total_effective_tokens))
        }),
        "tokens" => kept.sort_by_key(|s| std::cmp::Reverse(s.total_effective_tokens)),
        "wait" => kept.sort_by(|a, b| b.total_wait_s.total_cmp(&a.total_wait_s)),
        _ => kept.sort_by_key(|s| {
            let score = (s.sessions as i64) * (s.step_count as i64) * 1500
                + (s.total_calls as i64) * 200
                + s.total_effective_tokens / 100
                + (s.total_wait_s * 100.0) as i64;
            std::cmp::Reverse(score)
        }),
    }
    kept.truncate(limit);
    kept
}

fn is_subslice(needle: &[String], haystack: &[String]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn shifted_overlap_ratio(a: &[String], b: &[String]) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    // Longest common contiguous substring length normalized by min(len(a), len(b))
    let mut best = 0usize;
    let mut prev = vec![0usize; b.len() + 1];
    for ai in a {
        let mut curr = vec![0usize; b.len() + 1];
        for (j, bj) in b.iter().enumerate() {
            if ai == bj {
                curr[j + 1] = prev[j] + 1;
                if curr[j + 1] > best {
                    best = curr[j + 1];
                }
            }
        }
        prev = curr;
    }
    best as f64 / a.len().min(b.len()) as f64
}

fn format_collapsed_steps(steps: &[String]) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut i = 0;
    while i < steps.len() {
        let mut run = 1;
        while i + run < steps.len() && steps[i + run] == steps[i] {
            run += 1;
        }
        if run >= 2 {
            parts.push(format!("{} (×{run})", steps[i]));
        } else {
            parts.push(steps[i].clone());
        }
        i += run;
    }
    parts.join(" -> ")
}

#[allow(clippy::too_many_arguments)]
pub fn query_sequences(
    conn: &Connection,
    repo_id: &str,
    range: &TimeRange,
    min_len: usize,
    max_len: usize,
    min_sessions: usize,
    include_exploration: bool,
    sort_by: &str,
    limit: usize,
) -> Result<Vec<RepeatingSequence>> {
    let since_ms = range.since_ms;
    let until_ms = range.upper_bound();

    let mut s_stmt = conn.prepare(
        "SELECT session_id, turn_count FROM sessions
         WHERE repo_id = ?1
           AND COALESCE(started_at, ended_at, 0) >= ?2
           AND COALESCE(started_at, ended_at, 0) < ?3",
    )?;
    let sess_rows: Vec<(String, i64)> = s_stmt
        .query_map(params![repo_id, since_ms, until_ms], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?
        .flatten()
        .collect();
    let total_sessions = sess_rows.len().max(1);
    let sess_turns: HashMap<&str, i64> = sess_rows
        .iter()
        .map(|(sid, t)| (sid.as_str(), (*t).max(1)))
        .collect();

    let mut sp_stmt = conn.prepare(
        "SELECT COALESCE(session_id, 'orphan'), COALESCE(agent_kind, 'unknown'), turn_idx, workspace_id,
                category, is_repo_cli, cmd_bin, cmd_template, raw_redacted, exit_code, duration_ms,
                stdout_bytes, stdout_tokens, stderr_preview, is_truncated, started_at
         FROM command_spans
         WHERE repo_id = ?1
           AND started_at >= ?2 AND started_at < ?3
           AND (session_id IS NULL OR session_id IN (
               SELECT session_id FROM sessions
               WHERE repo_id = ?1
                 AND COALESCE(started_at, ended_at, 0) >= ?2
                 AND COALESCE(started_at, ended_at, 0) < ?3
           ))
         ORDER BY session_id ASC, turn_idx ASC, seq_idx ASC, started_at ASC",
    )?;
    let spans: Vec<Span> = sp_stmt
        .query_map(params![repo_id, since_ms, until_ms], |r| {
            Ok(Span {
                session_id: r.get(0)?,
                agent_kind: r.get(1)?,
                turn_idx: r.get(2)?,
                workspace_id: r.get(3)?,
                category: r.get(4)?,
                is_repo_cli: r.get::<_, i64>(5)? != 0,
                cmd_bin: r.get(6)?,
                cmd_template: r.get(7)?,
                raw_redacted: r.get(8)?,
                exit_code: r.get(9)?,
                duration_ms: r.get(10)?,
                stdout_bytes: r.get(11)?,
                stdout_tokens: r.get(12)?,
                stderr_preview: r.get(13)?,
                is_truncated: r.get::<_, i64>(14)? != 0,
                started_at: r.get(15)?,
            })
        })?
        .flatten()
        .collect();

    let mut spans_by_session: HashMap<&str, Vec<&Span>> = HashMap::new();
    for sp in &spans {
        spans_by_session
            .entry(sp.session_id.as_str())
            .or_default()
            .push(sp);
    }

    Ok(mine_sequences_from_spans(
        &spans_by_session,
        &sess_turns,
        total_sessions,
        min_len,
        max_len,
        min_sessions,
        include_exploration,
        sort_by,
        limit,
    ))
}

pub fn format_sequences_report(
    repo_name: &str,
    min_len: usize,
    max_len: usize,
    sort_by: &str,
    rows: &[RepeatingSequence],
    format: &str,
) -> String {
    if format == "json" {
        return serde_json::to_string_pretty(rows).unwrap_or_default();
    }
    let mut lines = vec![
        format!(
            "# Repeating Cross-Session Call Sequences in `{repo_name}` ({min_len}–{max_len} steps, sorted by `{sort_by}`, showing {})",
            rows.len()
        ),
        String::new(),
    ];
    if rows.is_empty() {
        lines.push("_No repeating multi-step call sequences matched the threshold. Try `--min-len 3 --min-sessions 2` or `--include-exploration`._".to_string());
        return lines.join("\n");
    }
    lines.push(
        "| Steps | Sessions | Runs | Calls | Out Toks | Eff Toks | Wait | Harnesses | Sequence |"
            .to_string(),
    );
    lines.push("| ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- | :--- |".to_string());
    for s in rows {
        lines.push(format!(
            "| {} | {}/{} ({:.0}%) | {} | {} | {} | {} | {:.1}s | {} | `{}` |",
            s.step_count,
            s.sessions,
            s.total_sessions,
            s.session_prevalence * 100.0,
            s.occurrences,
            s.total_calls,
            format_compact(s.total_stdout_tokens),
            format_compact(s.total_effective_tokens),
            s.total_wait_s,
            s.harness_summary,
            s.sequence.replace('|', "/")
        ));
    }
    lines.join("\n")
}

pub fn query_tools(
    conn: &Connection,
    repo_id: &str,
    range: &TimeRange,
    sort_by: &str,
    mcp_only: bool,
    limit: usize,
) -> Result<Vec<ToolStat>> {
    let since_ms = range.since_ms;
    let until_ms = range.upper_bound();
    let sql = if mcp_only {
        "SELECT session_id, agent_kind, tool_name, is_mcp, is_error, duration_ms,
                output_bytes, is_truncated, error_preview
         FROM tool_calls
         WHERE repo_id = ?1
           AND started_at >= ?2 AND started_at < ?3
           AND is_mcp = 1
           AND session_id IN (
               SELECT session_id FROM sessions
               WHERE repo_id = ?1
                 AND COALESCE(started_at, ended_at, 0) >= ?2
                 AND COALESCE(started_at, ended_at, 0) < ?3
           )"
    } else {
        "SELECT session_id, agent_kind, tool_name, is_mcp, is_error, duration_ms,
                output_bytes, is_truncated, error_preview
         FROM tool_calls
         WHERE repo_id = ?1
           AND started_at >= ?2 AND started_at < ?3
           AND session_id IN (
               SELECT session_id FROM sessions
               WHERE repo_id = ?1
                 AND COALESCE(started_at, ended_at, 0) >= ?2
                 AND COALESCE(started_at, ended_at, 0) < ?3
           )"
    };
    let mut stmt = conn.prepare(sql)?;
    struct Acc {
        is_mcp: bool,
        calls: usize,
        sessions: HashSet<String>,
        errs: usize,
        truncs: usize,
        bytes: i64,
        wait_ms: i64,
        agents: HashSet<String>,
        by_harness: BTreeMap<String, usize>,
        sample_err: Option<String>,
    }
    let mut map: HashMap<String, Acc> = HashMap::new();
    let rows = stmt.query_map(params![repo_id, since_ms, until_ms], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, i64>(3)? != 0,
            r.get::<_, i64>(4)? != 0,
            r.get::<_, Option<i64>>(5)?,
            r.get::<_, i64>(6)?,
            r.get::<_, i64>(7)? != 0,
            r.get::<_, Option<String>>(8)?,
        ))
    })?;
    for row in rows.flatten() {
        let (sid, ag, name, is_mcp, is_err, dur, bytes, is_trunc, err_prev) = row;
        let a = map.entry(name).or_insert_with(|| Acc {
            is_mcp,
            calls: 0,
            sessions: HashSet::new(),
            errs: 0,
            truncs: 0,
            bytes: 0,
            wait_ms: 0,
            agents: HashSet::new(),
            by_harness: BTreeMap::new(),
            sample_err: None,
        });
        a.calls += 1;
        a.sessions.insert(sid);
        if is_err {
            a.errs += 1;
            if a.sample_err.is_none() {
                a.sample_err = err_prev;
            }
        }
        if is_trunc {
            a.truncs += 1;
        }
        a.bytes += bytes;
        a.wait_ms += dur.unwrap_or(0);
        *a.by_harness.entry(ag.clone()).or_insert(0) += 1;
        a.agents.insert(ag);
    }

    let mut out: Vec<ToolStat> = map
        .into_iter()
        .map(|(name, a)| {
            let mut ags: Vec<String> = a.agents.into_iter().collect();
            ags.sort();
            let hs = format_harness_breakdown(&a.by_harness);
            ToolStat {
                tool_name: name,
                is_mcp: a.is_mcp,
                calls: a.calls,
                sessions: a.sessions.len(),
                error_count: a.errs,
                error_rate: r3(a.errs as f64 / a.calls.max(1) as f64),
                truncated_count: a.truncs,
                truncated_rate: r3(a.truncs as f64 / a.calls.max(1) as f64),
                avg_output_kb: r1((a.bytes as f64 / 1024.0) / a.calls.max(1) as f64),
                total_wait_s: r1(a.wait_ms as f64 / 1000.0),
                agents: ags,
                by_harness: a.by_harness,
                harness_summary: hs,
                sample_error: a.sample_err,
            }
        })
        .collect();

    match sort_by {
        "calls" => out.sort_by_key(|t| std::cmp::Reverse(t.calls)),
        "bytes" => out.sort_by(|a, b| b.avg_output_kb.total_cmp(&a.avg_output_kb)),
        "truncated" => out.sort_by_key(|t| std::cmp::Reverse(t.truncated_count)),
        _ => out.sort_by(|a, b| {
            b.error_count
                .cmp(&a.error_count)
                .then_with(|| b.error_rate.total_cmp(&a.error_rate))
                .then_with(|| b.calls.cmp(&a.calls))
        }),
    }
    out.truncate(limit);
    Ok(out)
}

pub fn format_tools_report(
    repo_name: &str,
    sort_by: &str,
    rows: &[ToolStat],
    format: &str,
) -> String {
    if format == "json" {
        return serde_json::to_string_pretty(rows).unwrap_or_default();
    }
    let mut lines = vec![
        format!(
            "# Non-Shell & MCP Tools in `{repo_name}` (sorted by `{sort_by}`, showing {})",
            rows.len()
        ),
        String::new(),
        "| Tool Name | MCP | Calls | Sess | Errs | Err% | Trunc | Avg KB | Wait | Harnesses | Sample Error |".to_string(),
        "| :--- | :---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- | :--- |".to_string(),
    ];
    for t in rows {
        lines.push(format!(
            "| `{}` | {} | {} | {} | {} | {:.1}% | {} | {:.1} | {:.1}s | {} | `{}` |",
            t.tool_name,
            if t.is_mcp { "yes" } else { "-" },
            t.calls,
            t.sessions,
            t.error_count,
            t.error_rate * 100.0,
            t.truncated_count,
            t.avg_output_kb,
            t.total_wait_s,
            t.harness_summary,
            t.sample_error
                .as_deref()
                .map(|s| trunc(s, 75).replace('|', "/"))
                .unwrap_or_else(|| "-".into())
        ));
    }
    lines.join("\n")
}

pub fn query_top_sessions(
    conn: &Connection,
    repo_id: &str,
    range: &TimeRange,
    sort_by: &str,
    limit: usize,
) -> Result<Vec<SessionOverview>> {
    let since_ms = range.since_ms;
    let until_ms = range.upper_bound();

    let mut s_stmt = conn.prepare(
        "SELECT session_id, agent_kind, COALESCE(originator, 'default'),
                COALESCE(subagent_kind, CASE WHEN is_subagent != 0 THEN 'subagent' ELSE 'main' END),
                is_subagent, is_handoff, COALESCE(started_at, ended_at, 0),
                turn_count, input_tokens, output_tokens, cached_tokens, total_tool_ms
         FROM sessions
         WHERE repo_id = ?1
           AND COALESCE(started_at, ended_at, 0) >= ?2
           AND COALESCE(started_at, ended_at, 0) < ?3",
    )?;
    let sessions: Vec<Sess> = s_stmt
        .query_map(params![repo_id, since_ms, until_ms], |r| {
            Ok(Sess {
                session_id: r.get(0)?,
                agent_kind: r.get(1)?,
                originator: r.get(2)?,
                role: r.get(3)?,
                is_subagent: r.get::<_, i64>(4)? != 0,
                is_handoff: r.get::<_, i64>(5)? != 0,
                started_at: r.get(6)?,
                turn_count: r.get(7)?,
                input_tokens: r.get(8)?,
                output_tokens: r.get(9)?,
                cached_tokens: r.get(10)?,
                total_tool_ms: r.get(11)?,
            })
        })?
        .flatten()
        .collect();

    let mut tc_counts: HashMap<String, (usize, usize)> = HashMap::new();
    {
        let mut t_stmt = conn.prepare(
            "SELECT session_id, COUNT(*), SUM(CASE WHEN is_error != 0 THEN 1 ELSE 0 END)
             FROM tool_calls
             WHERE repo_id = ?1 AND started_at >= ?2 AND started_at < ?3
             GROUP BY session_id",
        )?;
        let rows = t_stmt.query_map(params![repo_id, since_ms, until_ms], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?.max(0) as usize,
                r.get::<_, i64>(2)?.max(0) as usize,
            ))
        })?;
        for row in rows.flatten() {
            tc_counts.insert(row.0, (row.1, row.2));
        }
    }

    let mut sp_stmt = conn.prepare(
        "SELECT session_id, category, is_repo_cli, cmd_bin, cmd_template, exit_code, stdout_bytes
         FROM command_spans
         WHERE repo_id = ?1 AND started_at >= ?2 AND started_at < ?3 AND session_id IS NOT NULL",
    )?;
    struct SAcc {
        cmds: usize,
        errs: usize,
        stdout_bytes: i64,
        fams: HashMap<String, usize>,
    }
    let mut by_sid: HashMap<String, SAcc> = HashMap::new();
    let rows = sp_stmt.query_map(params![repo_id, since_ms, until_ms], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)? != 0,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, Option<i64>>(5)?,
            r.get::<_, i64>(6)?,
        ))
    })?;
    for row in rows.flatten() {
        let (sid, cat, is_cli, bin, tpl, ec, bytes) = row;
        let e = by_sid.entry(sid).or_insert_with(|| SAcc {
            cmds: 0,
            errs: 0,
            stdout_bytes: 0,
            fams: HashMap::new(),
        });
        e.cmds += 1;
        if ec.is_some_and(|c| c != 0) {
            e.errs += 1;
        }
        e.stdout_bytes += bytes;
        if !is_generic_read_or_script(&tpl, &cat) {
            let fake = Span {
                session_id: String::new(),
                agent_kind: String::new(),
                turn_idx: 0,
                workspace_id: None,
                category: cat,
                is_repo_cli: is_cli,
                cmd_bin: bin,
                cmd_template: tpl,
                raw_redacted: String::new(),
                exit_code: ec,
                duration_ms: None,
                stdout_bytes: bytes,
                stdout_tokens: 0,
                stderr_preview: None,
                is_truncated: false,
                started_at: 0,
            };
            *e.fams.entry(semantic_family(&fake)).or_insert(0) += 1;
        }
    }

    let mut out: Vec<SessionOverview> = sessions
        .into_iter()
        .map(|s| {
            let acc = by_sid.remove(&s.session_id);
            let (tcalls_n, tcalls_err) = tc_counts.remove(&s.session_id).unwrap_or((0, 0));
            let (cmds, errs, kb, top_fams) = match acc {
                Some(a) => {
                    let mut v: Vec<(String, usize)> = a.fams.into_iter().collect();
                    v.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
                    let top = v
                        .into_iter()
                        .take(4)
                        .map(|(k, c)| format!("{k} ({c}x)"))
                        .collect();
                    (
                        a.cmds,
                        a.errs + tcalls_err,
                        r1(a.stdout_bytes as f64 / 1024.0),
                        top,
                    )
                }
                None => (0, tcalls_err, 0.0, Vec::new()),
            };
            SessionOverview {
                session_id: s.session_id.clone(),
                agent_kind: s.agent_kind.clone(),
                originator: s.originator.clone(),
                role: s.role.clone(),
                is_handoff: s.is_handoff,
                started_at: chrono::DateTime::from_timestamp_millis(s.started_at)
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default(),
                turn_count: s.turn_count,
                command_count: cmds,
                tool_call_count: tcalls_n,
                total_tokens: s.total_tokens(),
                uncached_tokens: s.input_tokens,
                cache_hit_rate: s.cache_hit_rate().map(r3),
                stdout_kb: kb,
                total_wait_s: r1(s.total_tool_ms as f64 / 1000.0),
                error_count: errs,
                top_families: top_fams,
            }
        })
        .collect();

    match sort_by {
        "wait" => out.sort_by(|a, b| b.total_wait_s.total_cmp(&a.total_wait_s)),
        "errors" => out.sort_by_key(|s| std::cmp::Reverse(s.error_count)),
        "stdout" => out.sort_by(|a, b| b.stdout_kb.total_cmp(&a.stdout_kb)),
        _ => out.sort_by_key(|s| std::cmp::Reverse(s.total_tokens)),
    }
    out.truncate(limit);
    Ok(out)
}

pub fn format_sessions_report(
    repo_name: &str,
    sort_by: &str,
    rows: &[SessionOverview],
    format: &str,
) -> String {
    if format == "json" {
        return serde_json::to_string_pretty(rows).unwrap_or_default();
    }
    let mut lines = vec![
        format!("# Top Sessions in `{repo_name}` (sorted by `{sort_by}`, showing {})", rows.len()),
        String::new(),
        "| Harness | Originator | Role | Handoff | Started | Turns | Cmds | Tools | Model Toks | Uncached | Cache Hit | Stdout KB | Wait | Errs | Top Command Families |".to_string(),
        "| :--- | :--- | :--- | :---: | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- |".to_string(),
    ];
    for s in rows {
        lines.push(format!(
            "| `{}` | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {:.0} | {:.0}s | {} | {} |",
            s.agent_kind,
            s.originator,
            s.role,
            if s.is_handoff { "yes" } else { "-" },
            &s.started_at[..s.started_at.len().min(16)],
            s.turn_count,
            s.command_count,
            s.tool_call_count,
            format_compact(s.total_tokens),
            format_compact(s.uncached_tokens),
            s.cache_hit_rate
                .map(|v| format!("{:.1}%", v * 100.0))
                .unwrap_or_else(|| "n/a".into()),
            s.stdout_kb,
            s.total_wait_s,
            s.error_count,
            s.top_families.join(", ")
        ));
    }
    lines.join("\n")
}

pub fn format_patterns_report(rep: &CrossSessionPatternsReport, format: &str) -> String {
    if format == "json" {
        return serde_json::to_string_pretty(rep).unwrap_or_default();
    }

    let p = &rep.pareto;
    let mut lines = vec![
        format!(
            "# Cross-Session Pattern Report — `{}` ({}, {} sessions: {} main / {} subagent)",
            rep.repo_name,
            rep.window,
            rep.sessions_analyzed,
            rep.main_sessions,
            rep.subagent_sessions
        ),
        format!(
            "- **Temporal split midpoint:** `{}` (early: {} cmds, {:.1}% err | recent: {} cmds, {:.1}% err)",
            rep.midpoint_iso,
            rep.early_cmds,
            rep.early_error_rate * 100.0,
            rep.recent_cmds,
            rep.recent_error_rate * 100.0
        ),
        format!(
            "- **Pareto concentration (main sessions, model input+output tokens):** Top 25% ({}/{} sessions) consume **{:.1}%** of total model tokens ({} / {}); median **{}** vs **{}** bottom 50% (**{:.1}x**), avg **{:.1}** vs **{:.1}** turns, **{:.0} KB** vs **{:.0} KB** stdout",
            p.top25_count,
            p.main_sessions,
            p.top25_token_share_pct,
            format_compact(
                ((p.total_tokens_all_main as f64) * (p.top25_token_share_pct / 100.0)).round()
                    as i64
            ),
            format_compact(p.total_tokens_all_main),
            format_compact(p.top25_median_tokens),
            format_compact(p.bottom50_median_tokens),
            p.median_multiplier,
            p.top25_avg_turns,
            p.bottom50_avg_turns,
            p.top25_avg_stdout_kb,
            p.bottom50_avg_stdout_kb
        ),
    ];
    if let Some(h) = &rep.handoff_summary {
        lines.push(format!(
            "- **Context-handoff vs fresh main sessions:** {} handoff sessions avg **{}** model tokens ({:.1} turns) vs {} fresh sessions avg **{}** ({:.1} turns) — **{:.1}x token multiplier**",
            h.handoff_sessions,
            format_compact(h.handoff_avg_tokens),
            h.handoff_avg_turns,
            h.fresh_sessions,
            format_compact(h.fresh_avg_tokens),
            h.fresh_avg_turns,
            h.token_multiplier
        ));
    }
    if let Some(notice) = &rep.branch_behind_notice {
        lines.push(format!("- **Repo Ref Notice:** {notice}"));
    }
    lines.push(format!(
        "- **Universal friction (across >=2 harnesses):** {}",
        if rep.universal_friction_cmds.is_empty() {
            "none".to_string()
        } else {
            rep.universal_friction_cmds.join(", ")
        }
    ));
    lines.push(String::new());
    lines.push(
        "## 1. Cross-Harness Asymmetry (Stratified by Harness × Originator × Role)".to_string(),
    );
    lines.push(String::new());
    lines.push("| Harness | Originator | Role | Sess | Cmds | Tools | Med Model Toks | Avg Uncached | Cache (Wtd/Med/P25) | Avg Out KB | Trunc (Sess%) | Med Wait | Err% | Rebound% |".to_string());
    lines.push("| :--- | :--- | :--- | ---: | ---: | ---: | ---: | ---: | :---: | ---: | ---: | ---: | ---: | ---: |".to_string());
    for h in &rep.harness_comparison {
        let fmt_c = |o: Option<f64>| {
            o.map(|v| format!("{:.1}%", v * 100.0))
                .unwrap_or_else(|| "n/a".into())
        };
        lines.push(format!(
            "| `{}` | {} | {} | {} | {} | {} | {} | {} | {}/{}/{} | {:.1} | {} ({:.0}%) | {:.1}s | {:.1}% | {:.1}% |",
            h.agent_kind,
            h.originator,
            h.role,
            h.sessions,
            h.commands,
            h.tool_calls,
            format_compact(h.median_total_tokens),
            format_compact(h.avg_uncached_tokens),
            fmt_c(h.weighted_cache_hit),
            fmt_c(h.median_cache_hit),
            fmt_c(h.p25_cache_hit),
            h.avg_output_kb,
            h.truncated_outputs,
            h.truncated_sessions_pct,
            h.median_tool_wait_s,
            h.error_rate * 100.0,
            h.rebound_rate * 100.0,
        ));
    }

    if !p.storm_lifts.is_empty() {
        lines.push(String::new());
        lines.push(
            "## 2. Runaway Session Storm Prevalence (Top 25% vs Bottom 50% Main Sessions)"
                .to_string(),
        );
        lines.push(String::new());
        lines.push(
            "| Command Family | Top-25% Sessions w/ Storm | Bottom-50% Sessions w/ Storm | Lift |"
                .to_string(),
        );
        lines.push("| :--- | ---: | ---: | ---: |".to_string());
        for sl in &p.storm_lifts {
            lines.push(format!(
                "| `{}` | {:.1}% | {:.1}% | {} |",
                sl.family, sl.top25_pct_sessions, sl.bottom50_pct_sessions, sl.lift_str
            ));
        }
    }

    lines.push(String::new());
    lines.push(
        "## 3. Rate-Normalized Temporal Drift (Per 1,000 Commands, Early vs Recent Half)"
            .to_string(),
    );
    lines.push(String::new());
    if rep.temporal_drift.is_empty() {
        lines.push("_No significant temporal drift detected._".to_string());
    } else {
        lines.push("| Status | Command Family | Early -> Recent Runs | Rate / 1k Cmds | Ratio | Harnesses | Trend Summary |".to_string());
        lines.push("| :--- | :--- | :---: | :---: | ---: | :--- | :--- |".to_string());
        for d in &rep.temporal_drift {
            lines.push(format!(
                "| `{}` | `{}` | {} -> {} | {:.1} -> {:.1} | {:.2}x | {} | {} |",
                d.status,
                d.cmd_family,
                d.early_runs,
                d.recent_runs,
                d.early_per_1k,
                d.recent_per_1k,
                d.rate_ratio,
                d.harness_summary,
                d.summary
            ));
        }
    }

    lines.push(String::new());
    lines.push(
        "## 4. Cold-Start (Turns 1-3) Missing-Binary & Environment Error Clusters".to_string(),
    );
    lines.push(String::new());
    if rep.cold_start_errors.is_empty() {
        lines.push("_None detected._".to_string());
    } else {
        lines.push("| Error Class | Turns 1-3 / Total | % Early | Sess | Worktrees | Harnesses | Sample Stderr |".to_string());
        lines.push("| :--- | :---: | ---: | ---: | ---: | :--- | :--- |".to_string());
        for c in &rep.cold_start_errors {
            lines.push(format!(
                "| `{}` | {} / {} | {:.0}% | {} | {} | {} | `{}` |",
                c.error_class,
                c.failures_turns_1_3,
                c.total_failures,
                c.pct_in_turns_1_3,
                c.sessions,
                c.worktrees,
                c.harness_summary,
                c.sample_stderr.replace('|', "/")
            ));
        }
    }

    lines.push(String::new());
    lines.push("## 5. Recurring Multi-Session Harness Motifs (2-Step Trajectories)".to_string());
    lines.push(String::new());
    if rep.recurring_motifs.is_empty() {
        lines.push("_None detected._".to_string());
    } else {
        lines.push("| Kind | Sequence | Sessions | Prev% | Runs | Out Toks | Eff Toks | Wait | Harnesses |".to_string());
        lines.push("| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | :--- |".to_string());
        for m in &rep.recurring_motifs {
            lines.push(format!(
                "| `{}` | `{}` | {}/{} | {:.0}% | {} | {} | {} | {:.1}s | {} |",
                m.motif_kind,
                m.sequence,
                m.sessions,
                m.total_sessions,
                m.session_prevalence * 100.0,
                m.occurrences,
                format_compact(m.total_stdout_tokens),
                format_compact(m.total_effective_tokens),
                m.total_wait_s,
                m.harness_summary
            ));
        }
    }

    lines.push(String::new());
    lines.push(
        "## 5b. Repeating Multi-Step Call Sequences Across Sessions (3–10 Calls)".to_string(),
    );
    lines.push(String::new());
    if rep.repeating_sequences.is_empty() {
        lines.push("_None detected._".to_string());
    } else {
        lines.push("| Steps | Sessions | Runs | Calls | Out Toks | Eff Toks | Wait | Harnesses | Sequence |".to_string());
        lines.push("| ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- | :--- |".to_string());
        for s in &rep.repeating_sequences {
            lines.push(format!(
                "| {} | {}/{} ({:.0}%) | {} | {} | {} | {} | {:.1}s | {} | `{}` |",
                s.step_count,
                s.sessions,
                s.total_sessions,
                s.session_prevalence * 100.0,
                s.occurrences,
                s.total_calls,
                format_compact(s.total_stdout_tokens),
                format_compact(s.total_effective_tokens),
                s.total_wait_s,
                s.harness_summary,
                s.sequence.replace('|', "/")
            ));
        }
    }

    lines.push(String::new());
    lines.push(
        "## 6. Serial Burst Storms (>= 5 Calls in One Session, Infra/Workflow Only)".to_string(),
    );
    lines.push(String::new());
    if rep.burst_storms.is_empty() {
        lines.push("_None detected._".to_string());
    } else {
        lines.push("| Command Template | Storm Sess | Storm Calls | Max/Sess | Out Toks | Eff Toks | Wait | Harnesses |".to_string());
        lines.push("| :--- | ---: | ---: | ---: | ---: | ---: | ---: | :--- |".to_string());
        for s in &rep.burst_storms {
            lines.push(format!(
                "| `{}` | {} | {} | {} | {} | {} | {:.1}s | {} |",
                s.cmd_template,
                s.storm_sessions,
                s.total_calls_in_storms,
                s.max_calls_in_session,
                format_compact(s.total_stdout_tokens),
                format_compact(s.total_effective_tokens),
                s.total_wait_s,
                s.harness_summary
            ));
        }
    }

    if !rep.post_cli_doc_reads.is_empty() {
        lines.push(String::new());
        lines.push("## 7. Post-CLI Follow-Up Doc/Config Reads (Within 0-2 Turns)".to_string());
        lines.push(String::new());
        lines.push("| Repo CLI Family | Runs | Followed by Doc Read | Follow-Up% | Harnesses | Top Follow-Up Files |".to_string());
        lines.push("| :--- | ---: | ---: | ---: | :--- | :--- |".to_string());
        for pr in &rep.post_cli_doc_reads {
            lines.push(format!(
                "| `{}` | {} | {} | {:.1}% | {} | {} |",
                pr.cmd_template,
                pr.runs,
                pr.followed_by_doc_read,
                pr.follow_up_rate * 100.0,
                pr.harness_summary,
                pr.top_doc_files.join(", ")
            ));
        }
    }

    if !rep.top_mcp_errors.is_empty() {
        lines.push(String::new());
        lines.push("## 8. Failing / High-Truncation MCP Tools".to_string());
        lines.push(String::new());
        lines.push(
            "| MCP Tool | Calls | Sess | Errs | Err% | Trunc | Avg KB | Harnesses | Sample Error |"
                .to_string(),
        );
        lines.push("| :--- | ---: | ---: | ---: | ---: | ---: | ---: | :--- | :--- |".to_string());
        for t in &rep.top_mcp_errors {
            lines.push(format!(
                "| `{}` | {} | {} | {} | {:.1}% | {} | {:.1} | {} | `{}` |",
                t.tool_name,
                t.calls,
                t.sessions,
                t.error_count,
                t.error_rate * 100.0,
                t.truncated_count,
                t.avg_output_kb,
                t.harness_summary,
                t.sample_error
                    .as_deref()
                    .map(|s| trunc(s, 75).replace('|', "/"))
                    .unwrap_or_else(|| "-".into())
            ));
        }
    }

    if !rep.underused_surfaces.is_empty() {
        lines.push(String::new());
        lines.push("## 9. Underused / Zero-Adoption Documented Tools & Repo Tasks".to_string());
        lines.push(String::new());
        lines.push("| Kind | Name | Calls | Observation |".to_string());
        lines.push("| :--- | :--- | ---: | :--- |".to_string());
        for u in &rep.underused_surfaces {
            lines.push(format!(
                "| `{}` | `{}` | {} | {} |",
                u.surface_kind, u.name, u.observed_calls, u.note
            ));
        }
    }

    lines.join("\n")
}
