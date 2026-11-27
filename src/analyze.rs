use crate::config::{TimeRange, default_context_window, estimate_cost_usd, parse_window_ms};
use crate::repo_context::RepoContext;
use crate::shell::clean_error_preview;
use crate::workspace::{WorkspaceResolver, is_ephemeral_or_neutral_path};
use anyhow::{Result, bail};
use chrono::{DateTime, NaiveDate, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

pub mod issues;

#[derive(Debug, Clone, Serialize)]
pub struct RepoSummary {
    pub repo_id: String,
    pub repo_name: String,
    pub worktree_count: usize,
    pub session_count: usize,
    pub command_count: usize,
    pub median_session_tokens: i64,
    pub total_stdout_tokens: i64,
    pub median_tool_wait_s: f64,
    pub error_rate: f64,
    pub cli_adoption_rate: Option<f64>,
    pub last_seen: i64,
    pub top_driver: String,
    pub top_impact: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemicPattern {
    pub cmd_template: String,
    pub repo_count: usize,
    pub runs: usize,
    pub total_stdout_tokens: i64,
    pub total_wait_s: f64,
    pub error_rate: f64,
    pub dominant_noise: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FleetTotals {
    pub repos: usize,
    pub sessions: usize,
    pub commands: usize,
    pub stdout_tokens: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct FleetReport {
    pub window: String,
    pub generated_at: String,
    pub totals: FleetTotals,
    pub repos: Vec<RepoSummary>,
    pub systemic_patterns: Vec<SystemicPattern>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct LatencyBreakdown {
    pub total_session_wall_s: f64,
    pub median_session_wall_s: f64,
    pub total_api_wait_s: f64,
    pub median_api_wait_s: f64,
    pub total_api_retry_s: f64,
    pub total_thinking_s: f64,
    pub total_tool_serial_s: f64,
    pub total_tool_wall_s: f64,
    pub tool_parallelism_ratio: f64,
    pub avg_ttft_ms: Option<i64>,
    pub other_idle_s: f64,
    pub sessions_with_api_timing: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ContextHealthSummary {
    pub sessions_with_context_data: usize,
    pub avg_peak_context_pct: Option<f64>,
    pub p95_peak_context_pct: Option<f64>,
    pub sessions_over_80_pct: usize,
    pub total_compactions: i64,
    pub compacted_sessions: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct OutcomeSummary {
    pub completed_sessions: usize,
    pub aborted_sessions: usize,
    pub error_sessions: usize,
    pub unknown_sessions: usize,
    pub abort_rate: f64,
    pub total_aborted_turns: i64,
    pub total_api_errors: i64,
    pub aborted_session_tokens: i64,
    pub total_lines_added: i64,
    pub total_lines_removed: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RepoKpis {
    pub sessions_analyzed: usize,
    pub worktrees_seen: usize,
    pub agents_seen: Vec<String>,
    pub total_commands: usize,
    pub total_stdout_tokens: i64,
    pub total_effective_tokens: i64,
    pub total_model_tokens: i64,
    pub total_cache_write_tokens: i64,
    pub total_thinking_tokens: i64,
    pub median_tokens_per_session: i64,
    pub p95_tokens_per_session: i64,
    pub cache_hit_rate: Option<f64>,
    pub median_tool_wait_s: f64,
    pub total_tool_wait_s: f64,
    pub command_error_rate: f64,
    pub cli_adoption_rate: Option<f64>,
    pub escape_hatch_rebound_rate: f64,
    pub orientation_tokens: i64,
    pub total_cost_usd: Option<f64>,
    pub estimated_cost_usd: f64,
    pub cost_sessions: usize,
    pub latency: LatencyBreakdown,
    pub context_health: ContextHealthSummary,
    pub outcomes: OutcomeSummary,
    pub detected_config: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Opportunity {
    pub id: String,
    pub scope: String, // "repo" | "harness"
    pub kind: String,
    pub fix_target: String,
    pub target: String,
    pub score: i64,
    pub impact_summary: String,
    pub by_harness: BTreeMap<String, usize>,
    pub harness_summary: String,
    pub evidence: BTreeMap<String, serde_json::Value>,
    pub trace_proof: Vec<String>,
    pub suggested_action: String,
    pub acceptance_metric: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CommandStat {
    pub cmd_template: String,
    pub category: String,
    pub is_repo_cli: bool,
    pub runs: usize,
    pub error_count: usize,
    pub error_rate: f64,
    pub piped_count: usize,
    pub top_pipe_filter: Option<String>,
    pub p50_stdout_tokens: i64,
    pub total_stdout_tokens: i64,
    pub effective_tokens: i64,
    pub p50_wait_s: f64,
    pub p95_wait_s: Option<f64>,
    pub p99_wait_s: Option<f64>,
    pub total_wait_s: f64,
    pub dominant_noise: Option<String>,
    pub by_harness: BTreeMap<String, usize>,
    pub harness_summary: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorCluster {
    pub cmd_template: String,
    pub category: String,
    pub error_count: usize,
    pub total_runs: usize,
    pub error_rate: f64,
    pub sessions: usize,
    pub exit_codes: Vec<i64>,
    pub by_harness: BTreeMap<String, usize>,
    pub harness_summary: String,
    pub sample_cmd: String,
    pub stderr_preview: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StateDirScrape {
    pub state_dir: String,
    pub calls: usize,
    pub sessions: usize,
    pub stdout_tokens: i64,
    pub total_wait_s: f64,
    pub by_harness: BTreeMap<String, usize>,
    pub harness_summary: String,
    pub top_cmds: Vec<String>,
    pub sample_cmd: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HelpUsage {
    pub cmd_template: String,
    pub calls: usize,
    pub sessions: usize,
    pub broken_calls: usize,
    pub stdout_tokens: i64,
    pub by_harness: BTreeMap<String, usize>,
    pub harness_summary: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PipeStripStat {
    pub cmd_template: String,
    pub piped_calls: usize,
    pub total_runs: usize,
    pub pipe_rate: f64,
    pub by_harness: BTreeMap<String, usize>,
    pub harness_summary: String,
    pub top_filters: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RawBypassFamily {
    pub cmd_bin: String,
    pub category: String,
    pub total_runs: usize,
    pub sessions: usize,
    pub error_count: usize,
    pub error_rate: f64,
    pub total_stdout_tokens: i64,
    pub total_wait_s: f64,
    pub by_harness: BTreeMap<String, usize>,
    pub harness_summary: String,
    pub top_templates: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BypassReport {
    pub repo_id: String,
    pub repo_name: String,
    pub window: String,
    pub state_dir_scrapes: Vec<StateDirScrape>,
    pub pipe_stripping: Vec<PipeStripStat>,
    pub help_lookups: Vec<HelpUsage>,
    pub raw_bypass_families: Vec<RawBypassFamily>,
    pub raw_tool_bypasses: Vec<CommandStat>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RepoReport {
    pub repo_id: String,
    pub repo_name: String,
    pub window: String,
    pub generated_at: String,
    pub kpis: RepoKpis,
    pub opportunities: Vec<Opportunity>,
    pub harness_overhead: Vec<Opportunity>,
    pub top_commands: Vec<CommandStat>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceSample {
    pub session_id: String,
    pub agent_kind: String,
    pub turn_idx: i64,
    pub started_at: String,
    pub cmd_template: String,
    pub raw_redacted: String,
    pub exit_code: Option<i64>,
    pub duration_ms: Option<i64>,
    pub stdout_tokens: i64,
    pub noise_kind: Option<String>,
    pub stderr_preview: Option<String>,
    pub next_cmd: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InspectResult {
    pub repo_id: String,
    pub repo_name: String,
    pub query: String,
    pub opportunity: Option<Opportunity>,
    pub total_matching_spans: usize,
    pub samples: Vec<TraceSample>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffBucket {
    pub sessions: usize,
    pub commands: usize,
    pub median_session_tokens: i64,
    pub median_tool_wait_s: f64,
    pub avg_stdout_tokens_per_cmd: i64,
    pub error_rate: f64,
    pub rebound_rate: f64,
    pub estimated_cost_usd: f64,
    pub cache_hit_rate: Option<f64>,
    pub avg_api_wait_s: Option<f64>,
    pub abort_rate: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct HarnessDiffDelta {
    pub agent_kind: String,
    pub before_sessions: usize,
    pub after_sessions: usize,
    pub before_commands: usize,
    pub after_commands: usize,
    pub before_median_tokens: i64,
    pub after_median_tokens: i64,
    pub before_avg_stdout_tokens: i64,
    pub after_avg_stdout_tokens: i64,
    pub before_error_rate: f64,
    pub after_error_rate: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CommandDelta {
    pub cmd_template: String,
    pub before_p50_tokens: i64,
    pub after_p50_tokens: i64,
    pub delta_pct: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffDeltas {
    pub median_session_tokens_pct: Option<f64>,
    pub median_tool_wait_pct: Option<f64>,
    pub avg_stdout_tokens_per_cmd_pct: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffReport {
    pub repo_id: String,
    pub repo_name: String,
    pub since: String,
    pub matched_window: bool,
    pub verdict: String,
    pub before: DiffBucket,
    pub after: DiffBucket,
    pub deltas: DiffDeltas,
    pub by_harness: Vec<HarnessDiffDelta>,
    pub guardrails: Vec<String>,
    pub command_deltas: Vec<CommandDelta>,
}

#[derive(Debug, Clone)]
struct SessionRow {
    session_id: String,
    agent_kind: String,
    model: Option<String>,
    workspace_id: Option<String>,
    repo_id: String,
    repo_name: String,
    cwd: Option<String>,
    started_at: i64,
    ended_at: i64,
    turn_count: i64,
    input_tokens: i64,
    cache_write_tokens: i64,
    output_tokens: i64,
    cached_tokens: i64,
    thinking_tokens: i64,
    cost_usd: Option<f64>,
    total_tool_ms: i64,
    tool_wall_ms: i64,
    api_duration_ms: i64,
    api_retry_ms: i64,
    thinking_duration_ms: i64,
    ttft_ms_sum: i64,
    ttft_count: i64,
    compaction_count: i64,
    aborted_turns: i64,
    api_errors: i64,
    outcome: Option<String>,
    lines_added: i64,
    lines_removed: i64,
    max_context_tokens: i64,
    context_window: Option<i64>,
    is_subagent: bool,
    is_handoff: bool,
}

impl SessionRow {
    fn total_model_tokens(&self) -> i64 {
        self.input_tokens
            + self.cache_write_tokens
            + self.cached_tokens
            + self.output_tokens
            + self.thinking_tokens
    }

    fn uncached_billable_tokens(&self) -> i64 {
        self.input_tokens + self.cache_write_tokens + self.output_tokens + self.thinking_tokens
    }

    fn effective_cost_usd(&self) -> f64 {
        if let Some(c) = self.cost_usd
            && c > 0.0
        {
            return c;
        }
        estimate_cost_usd(
            self.model.as_deref(),
            &self.agent_kind,
            self.input_tokens,
            self.cached_tokens,
            self.cache_write_tokens,
            self.output_tokens,
            self.thinking_tokens,
        )
    }

    fn wall_ms(&self) -> i64 {
        if self.ended_at > self.started_at && self.started_at > 0 {
            (self.ended_at - self.started_at).min(86_400_000)
        } else {
            0
        }
    }

    fn peak_context_pct(&self) -> Option<f64> {
        if self.max_context_tokens <= 0 {
            return None;
        }
        let win = self
            .context_window
            .filter(|&w| w > 0)
            .or_else(|| default_context_window(self.model.as_deref(), &self.agent_kind))?;
        Some(((self.max_context_tokens as f64 / win as f64) * 100.0).min(150.0))
    }
}

#[derive(Debug, Clone)]
struct SpanRow {
    session_id: Option<String>,
    agent_kind: Option<String>,
    turn_idx: i64,
    workspace_id: Option<String>,
    repo_id: String,
    repo_name: String,
    category: String,
    is_repo_cli: bool,
    cmd_bin: String,
    cmd_template: String,
    raw_redacted: String,
    exit_code: Option<i64>,
    duration_ms: Option<i64>,
    stdout_tokens: i64,
    stderr_preview: Option<String>,
    noise_kind: Option<String>,
    is_orientation: bool,
    piped_filter: Option<String>,
    state_dir_hint: Option<String>,
    is_chained: bool,
    source_kind: String,
    started_at: i64,
}

#[derive(Debug, Clone)]
struct ReadRow {
    session_id: String,
    turn_idx: i64,
    target_name: String,
    is_doc: bool,
    output_tokens: i64,
}

fn percentile_i64(values: &[i64], p: f64) -> i64 {
    if values.is_empty() {
        return 0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let idx = (((p / 100.0) * sorted.len() as f64).ceil() as isize - 1)
        .clamp(0, (sorted.len() - 1) as isize) as usize;
    sorted[idx]
}

fn percentile_f64(values: &[f64], p: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let idx = (((p / 100.0) * sorted.len() as f64).ceil() as isize - 1)
        .clamp(0, (sorted.len() - 1) as isize) as usize;
    sorted[idx]
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

/// Cache-weighted downstream context impact of a tool output:
/// first turn is uncached (1.0x), subsequent turns in the session are cached (~0.1x).
pub(crate) fn effective_context_tokens(stdout_tokens: i64, turn_idx: i64, total_turns: i64) -> i64 {
    let rem = (total_turns - turn_idx + 1).clamp(1, 25);
    let mult = 1.0 + 0.1 * (rem - 1) as f64;
    ((stdout_tokens as f64) * mult).round() as i64
}

const SESSION_SELECT_COLS: &str = "session_id, agent_kind, model, workspace_id, repo_id, COALESCE(repo_name, repo_id),
                cwd, COALESCE(started_at, ended_at, 0), COALESCE(ended_at, started_at, 0),
                turn_count, input_tokens, cache_write_tokens, output_tokens, cached_tokens, thinking_tokens,
                cost_usd, total_tool_ms, tool_wall_ms, api_duration_ms, api_retry_ms, thinking_duration_ms,
                ttft_ms_sum, ttft_count, compaction_count, aborted_turns, api_errors, outcome,
                lines_added, lines_removed, max_context_tokens, context_window, is_subagent, is_handoff";

fn map_session_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SessionRow> {
    Ok(SessionRow {
        session_id: r.get(0)?,
        agent_kind: r.get(1)?,
        model: r.get(2)?,
        workspace_id: r.get(3)?,
        repo_id: r.get(4)?,
        repo_name: r.get(5)?,
        cwd: r.get(6)?,
        started_at: r.get(7)?,
        ended_at: r.get(8)?,
        turn_count: r.get(9)?,
        input_tokens: r.get(10)?,
        cache_write_tokens: r.get(11)?,
        output_tokens: r.get(12)?,
        cached_tokens: r.get(13)?,
        thinking_tokens: r.get(14)?,
        cost_usd: r.get(15)?,
        total_tool_ms: r.get(16)?,
        tool_wall_ms: r.get(17)?,
        api_duration_ms: r.get(18)?,
        api_retry_ms: r.get(19)?,
        thinking_duration_ms: r.get(20)?,
        ttft_ms_sum: r.get(21)?,
        ttft_count: r.get(22)?,
        compaction_count: r.get(23)?,
        aborted_turns: r.get(24)?,
        api_errors: r.get(25)?,
        outcome: r.get(26)?,
        lines_added: r.get(27)?,
        lines_removed: r.get(28)?,
        max_context_tokens: r.get(29)?,
        context_window: r.get(30)?,
        is_subagent: r.get::<_, i64>(31)? != 0,
        is_handoff: r.get::<_, i64>(32)? != 0,
    })
}

const SPAN_SELECT_COLS: &str = "session_id, agent_kind, turn_idx, workspace_id, repo_id, COALESCE(repo_name, repo_id),
                category, is_repo_cli, cmd_bin, cmd_template, raw_redacted, exit_code, duration_ms,
                stdout_tokens, stderr_preview, noise_kind, is_orientation, piped_filter, state_dir_hint,
                is_chained, source_kind, started_at";

fn map_span_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SpanRow> {
    Ok(SpanRow {
        session_id: r.get(0)?,
        agent_kind: r.get(1)?,
        turn_idx: r.get(2)?,
        workspace_id: r.get(3)?,
        repo_id: r.get(4)?,
        repo_name: r.get(5)?,
        category: r.get(6)?,
        is_repo_cli: r.get::<_, i64>(7)? != 0,
        cmd_bin: r.get(8)?,
        cmd_template: r.get(9)?,
        raw_redacted: r.get(10)?,
        exit_code: r.get(11)?,
        duration_ms: r.get(12)?,
        stdout_tokens: r.get(13)?,
        stderr_preview: r.get(14)?,
        noise_kind: r.get(15)?,
        is_orientation: r.get::<_, i64>(16)? != 0,
        piped_filter: r.get(17)?,
        state_dir_hint: r.get(18)?,
        is_chained: r.get::<_, i64>(19)? != 0,
        source_kind: r.get(20)?,
        started_at: r.get(21)?,
    })
}

/// Deduplicate `wrap` spans that overlap a transcript span for the same session + binary within ±2s.
fn dedup_wrap_spans(spans: Vec<SpanRow>) -> Vec<SpanRow> {
    if !spans.iter().any(|s| s.source_kind == "wrap") {
        return spans;
    }
    let transcript_keys: Vec<(Option<&str>, &str, i64)> = spans
        .iter()
        .filter(|s| s.source_kind != "wrap")
        .map(|s| (s.session_id.as_deref(), s.cmd_bin.as_str(), s.started_at))
        .collect();
    if transcript_keys.is_empty() {
        return spans;
    }
    let mut keep = Vec::with_capacity(spans.len());
    for (idx, sp) in spans.iter().enumerate() {
        if sp.source_kind == "wrap" {
            let dup = transcript_keys.iter().any(|(sid, bin, ts)| {
                *bin == sp.cmd_bin.as_str()
                    && (sp.started_at - *ts).abs() <= 2_000
                    && (sid.is_none()
                        || sp.session_id.is_none()
                        || *sid == sp.session_id.as_deref())
            });
            if dup {
                continue;
            }
        }
        keep.push(idx);
    }
    let keep_set: HashSet<usize> = keep.into_iter().collect();
    spans
        .into_iter()
        .enumerate()
        .filter_map(|(i, sp)| {
            if keep_set.contains(&i) {
                Some(sp)
            } else {
                None
            }
        })
        .collect()
}

fn summarize_latency(sessions: &[SessionRow]) -> LatencyBreakdown {
    let mut wall_s_vec = Vec::new();
    let mut api_s_vec = Vec::new();
    let mut total_wall_ms: i64 = 0;
    let mut total_api_ms: i64 = 0;
    let mut total_retry_ms: i64 = 0;
    let mut total_think_ms: i64 = 0;
    let mut total_tool_serial_ms: i64 = 0;
    let mut total_tool_wall_ms: i64 = 0;
    let mut ttft_sum: i64 = 0;
    let mut ttft_cnt: i64 = 0;
    let mut sessions_with_api = 0usize;

    for s in sessions {
        let w = s.wall_ms();
        if w > 0 {
            total_wall_ms += w;
            wall_s_vec.push(w as f64 / 1000.0);
        }
        if s.api_duration_ms > 0 {
            sessions_with_api += 1;
            total_api_ms += s.api_duration_ms;
            api_s_vec.push(s.api_duration_ms as f64 / 1000.0);
        }
        total_retry_ms += s.api_retry_ms.max(0);
        total_think_ms += s.thinking_duration_ms.max(0);
        total_tool_serial_ms += s.total_tool_ms.max(0);
        let tw = if s.tool_wall_ms > 0 {
            s.tool_wall_ms
        } else {
            s.total_tool_ms.max(0)
        };
        total_tool_wall_ms += tw;
        ttft_sum += s.ttft_ms_sum.max(0);
        ttft_cnt += s.ttft_count.max(0);
    }

    let other_idle_ms = (total_wall_ms - total_api_ms - total_tool_wall_ms).max(0);
    let parallelism = if total_tool_wall_ms > 0 && total_tool_serial_ms > 0 {
        round1((total_tool_serial_ms as f64 / total_tool_wall_ms as f64).max(1.0))
    } else {
        1.0
    };

    LatencyBreakdown {
        total_session_wall_s: round1(total_wall_ms as f64 / 1000.0),
        median_session_wall_s: round1(percentile_f64(&wall_s_vec, 50.0)),
        total_api_wait_s: round1(total_api_ms as f64 / 1000.0),
        median_api_wait_s: round1(percentile_f64(&api_s_vec, 50.0)),
        total_api_retry_s: round1(total_retry_ms as f64 / 1000.0),
        total_thinking_s: round1(total_think_ms as f64 / 1000.0),
        total_tool_serial_s: round1(total_tool_serial_ms as f64 / 1000.0),
        total_tool_wall_s: round1(total_tool_wall_ms as f64 / 1000.0),
        tool_parallelism_ratio: parallelism,
        avg_ttft_ms: if ttft_cnt > 0 {
            Some(ttft_sum / ttft_cnt)
        } else {
            None
        },
        other_idle_s: round1(other_idle_ms as f64 / 1000.0),
        sessions_with_api_timing: sessions_with_api,
    }
}

fn summarize_context_health(sessions: &[SessionRow]) -> ContextHealthSummary {
    let mut pcts = Vec::new();
    let mut over_80 = 0usize;
    let mut total_compactions = 0i64;
    let mut compacted_sessions = 0usize;
    for s in sessions {
        if let Some(pct) = s.peak_context_pct() {
            pcts.push(pct);
            if pct >= 80.0 {
                over_80 += 1;
            }
        }
        if s.compaction_count > 0 {
            total_compactions += s.compaction_count;
            compacted_sessions += 1;
        }
    }
    let avg_pct = if pcts.is_empty() {
        None
    } else {
        Some(round1(pcts.iter().sum::<f64>() / pcts.len() as f64))
    };
    let p95_pct = if pcts.len() >= 3 {
        Some(round1(percentile_f64(&pcts, 95.0)))
    } else {
        None
    };
    ContextHealthSummary {
        sessions_with_context_data: pcts.len(),
        avg_peak_context_pct: avg_pct,
        p95_peak_context_pct: p95_pct,
        sessions_over_80_pct: over_80,
        total_compactions,
        compacted_sessions,
    }
}

fn summarize_outcomes(sessions: &[SessionRow]) -> OutcomeSummary {
    let mut completed = 0usize;
    let mut aborted = 0usize;
    let mut errored = 0usize;
    let mut unknown = 0usize;
    let mut aborted_turns = 0i64;
    let mut api_errors = 0i64;
    let mut aborted_tokens = 0i64;
    let mut lines_added = 0i64;
    let mut lines_removed = 0i64;
    for s in sessions {
        aborted_turns += s.aborted_turns.max(0);
        api_errors += s.api_errors.max(0);
        lines_added += s.lines_added.max(0);
        lines_removed += s.lines_removed.max(0);
        if s.outcome.as_deref() == Some("aborted") || s.aborted_turns > 0 {
            aborted += 1;
            aborted_tokens += s.total_model_tokens();
        } else {
            match s.outcome.as_deref() {
                Some("error") => {
                    errored += 1;
                }
                Some("completed") => {
                    completed += 1;
                }
                _ => {
                    unknown += 1;
                }
            }
        }
    }
    let denom = sessions.len().max(1) as f64;
    OutcomeSummary {
        completed_sessions: completed,
        aborted_sessions: aborted,
        error_sessions: errored,
        unknown_sessions: unknown,
        abort_rate: round3(aborted as f64 / denom),
        total_aborted_turns: aborted_turns,
        total_api_errors: api_errors,
        aborted_session_tokens: aborted_tokens,
        total_lines_added: lines_added,
        total_lines_removed: lines_removed,
    }
}

fn mode_str(values: &[String]) -> Option<String> {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for v in values {
        if !v.is_empty() {
            *counts.entry(v.as_str()).or_insert(0) += 1;
        }
    }
    counts
        .into_iter()
        .max_by_key(|(_, c)| *c)
        .map(|(k, _)| k.to_string())
}

pub fn format_compact(n: i64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}k", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

pub fn format_duration_human(secs: f64) -> String {
    if secs < 0.05 {
        "0s".to_string()
    } else if secs < 1.0 {
        format!("{:.0}ms", secs * 1000.0)
    } else if secs < 60.0 {
        format!("{secs:.1}s")
    } else if secs < 3600.0 {
        format!("{:.1}m", secs / 60.0)
    } else {
        format!("{:.1}h", secs / 3600.0)
    }
}

pub fn harness_key(agent_kind: Option<&str>) -> String {
    match agent_kind {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => "unknown".to_string(),
    }
}

fn short_harness_name(name: &str) -> &str {
    match name {
        "claude-code" => "claude",
        other => other,
    }
}

/// Format per-harness attribution descending by share, e.g.:
/// - `"codex only (649)"`
/// - `"codex 61% (423), claude-code 39% (270)"`
pub fn format_harness_breakdown(counts: &BTreeMap<String, usize>) -> String {
    let total: usize = counts.values().sum();
    if total == 0 {
        return "unknown".to_string();
    }
    let mut items: Vec<(&String, usize)> = counts.iter().map(|(k, &v)| (k, v)).collect();
    items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    if items.len() == 1 {
        return format!("{} only ({})", items[0].0, items[0].1);
    }
    items
        .into_iter()
        .map(|(k, v)| {
            let pct = ((v as f64 / total as f64) * 100.0).round() as usize;
            format!("{k} {pct}% ({v})")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Compact per-harness tag for narrow TUI columns, e.g. `"codex only"` or `"codex 61%/claude 39%"`.
pub fn format_harness_tag(counts: &BTreeMap<String, usize>) -> String {
    let total: usize = counts.values().sum();
    if total == 0 {
        return "-".to_string();
    }
    let mut items: Vec<(&String, usize)> = counts.iter().map(|(k, &v)| (k, v)).collect();
    items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    if items.len() == 1 {
        return format!("{} only", short_harness_name(items[0].0));
    }
    items
        .into_iter()
        .take(2)
        .map(|(k, v)| {
            let pct = ((v as f64 / total as f64) * 100.0).round() as usize;
            format!("{} {pct}%", short_harness_name(k))
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn is_generic_interpreter(tpl: &str) -> bool {
    tpl.starts_with("python3")
        || tpl.starts_with("python ")
        || tpl == "python"
        || tpl.starts_with("node -e")
        || tpl.starts_with("node --input-type")
        || tpl == "node -"
        || tpl.starts_with("ruby -e")
        || tpl.starts_with("perl -")
}

fn is_help_invocation(sp: &SpanRow) -> bool {
    sp.cmd_template.contains("--help")
        || sp.cmd_template.contains(" -h")
        || sp.cmd_template.ends_with(" help")
        || sp.raw_redacted.contains(" --help")
        || sp.raw_redacted.contains(" -- help")
        || sp.raw_redacted.ends_with(" help")
}

fn is_generic_git_read(tpl: &str) -> bool {
    tpl.starts_with("git status")
        || tpl.starts_with("git diff")
        || tpl.starts_with("git log")
        || tpl.starts_with("git show")
        || tpl.starts_with("git branch")
        || tpl.starts_with("git rev-parse")
        || tpl.starts_with("git ls-files")
        || tpl.starts_with("git grep")
}

/// Routine VCS staging/inspection/commit steps that naturally follow a CLI task and
/// should not be counted as "escape-hatch rebounds".
pub(crate) fn is_normal_vcs_workflow_cmd(tpl: &str) -> bool {
    is_generic_git_read(tpl)
        || tpl.starts_with("git add")
        || tpl.starts_with("git commit")
        || tpl.starts_with("git push")
        || tpl.starts_with("git pull")
        || tpl.starts_with("git fetch")
        || tpl.starts_with("git checkout")
        || tpl.starts_with("git switch")
        || tpl.starts_with("git stash")
        || tpl.starts_with("git merge")
        || tpl.starts_with("git rebase")
        || tpl.starts_with("git reset")
}

fn is_harness_command(tpl: &str) -> bool {
    let l = tpl.to_ascii_lowercase();
    l.starts_with("codex-wait")
        || l.starts_with("codex-write-stdin")
        || l.starts_with("mcp:t3-code:")
        || l.starts_with("mcp:codex-apps:")
}

fn is_harness_tool(tool_name: &str) -> bool {
    let l = tool_name.to_ascii_lowercase();
    l.starts_with("mcp:t3-code:")
        || l.starts_with("mcp:codex-apps:")
        || l.starts_with("codex:")
        || l.starts_with("t3_")
        || l.starts_with("preview_")
        || l.starts_with("device_")
}

fn scope_for_cmd(tpl: &str) -> String {
    if is_harness_command(tpl) {
        "harness".to_string()
    } else {
        "repo".to_string()
    }
}

fn is_actual_polling_cmd(tpl: &str, category: &str) -> bool {
    if category == "polling" {
        return true;
    }
    if is_generic_git_read(tpl) || category == "exploration" {
        return false;
    }
    let l = tpl.to_ascii_lowercase();
    l.starts_with("sleep")
        || l.starts_with("watch")
        || l.contains(":wait")
        || l.contains(" wait")
        || l.contains(":status")
        || l.contains(" status")
        || l.contains(" poll")
        || l.contains(" logs")
        || l.starts_with("systemctl")
        || l.starts_with("kubectl get")
        || l.starts_with("docker ps")
}

fn is_infra_or_workflow_cmd(sp: &SpanRow) -> bool {
    if sp.is_repo_cli {
        return true;
    }
    if matches!(
        sp.category.as_str(),
        "repo_task" | "build_test" | "package_mgr" | "polling"
    ) {
        return true;
    }
    sp.category == "vcs_ci" && !is_generic_git_read(&sp.cmd_template)
}

pub fn resolve_repo_selector(
    conn: &Connection,
    selector: &str,
) -> Result<Option<(String, String)>> {
    if selector == "."
        || selector.starts_with("./")
        || selector.starts_with('/')
        || selector.starts_with('~')
    {
        let expanded = if let Some(rest) = selector.strip_prefix('~') {
            dirs::home_dir()
                .unwrap_or_default()
                .join(rest.trim_start_matches('/'))
        } else {
            std::env::current_dir()?.join(selector)
        };
        let mut resolver = WorkspaceResolver::new(Some(conn));
        if let Some(ws) = resolver.resolve(&expanded.to_string_lossy()) {
            return Ok(Some((ws.repo_id, ws.repo_name)));
        }
    }

    let exact: Option<(String, String)> = conn
        .query_row(
            "SELECT repo_id, repo_name FROM (
               SELECT repo_id, repo_name FROM sessions WHERE repo_id IS NOT NULL
               UNION
               SELECT repo_id, repo_name FROM command_spans WHERE repo_id IS NOT NULL
             ) WHERE lower(repo_id) = lower(?1) OR lower(repo_name) = lower(?1)
             LIMIT 1",
            params![selector],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if exact.is_some() {
        return Ok(exact);
    }

    let like = format!("%{}%", selector.to_ascii_lowercase());
    let fuzzy: Option<(String, String)> = conn
        .query_row(
            "SELECT repo_id, repo_name FROM (
               SELECT repo_id, repo_name FROM sessions WHERE repo_id IS NOT NULL
               UNION ALL
               SELECT repo_id, repo_name FROM command_spans WHERE repo_id IS NOT NULL
             ) WHERE lower(repo_name) LIKE ?1 OR lower(repo_id) LIKE ?1
             GROUP BY repo_id, repo_name
             ORDER BY COUNT(*) DESC
             LIMIT 1",
            params![like],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(fuzzy)
}

pub fn list_repos(
    conn: &Connection,
    range: &TimeRange,
    include_temp: bool,
) -> Result<Vec<RepoSummary>> {
    let since_ms = range.since_ms;
    let until_ms = range.upper_bound();

    let mut s_stmt = conn.prepare(&format!(
        "SELECT {SESSION_SELECT_COLS}
         FROM sessions
         WHERE repo_id IS NOT NULL
           AND COALESCE(started_at, ended_at, 0) >= ?1
           AND COALESCE(started_at, ended_at, 0) < ?2"
    ))?;
    let sessions: Vec<SessionRow> = s_stmt
        .query_map(params![since_ms, until_ms], map_session_row)?
        .flatten()
        .collect();

    let mut sp_stmt = conn.prepare(&format!(
        "SELECT {SPAN_SELECT_COLS}
         FROM command_spans
         WHERE repo_id IS NOT NULL
           AND started_at >= ?1 AND started_at < ?2
           AND (session_id IS NULL OR session_id IN (
               SELECT session_id FROM sessions
               WHERE COALESCE(started_at, ended_at, 0) >= ?1
                 AND COALESCE(started_at, ended_at, 0) < ?2
           ))"
    ))?;
    let spans: Vec<SpanRow> = dedup_wrap_spans(
        sp_stmt
            .query_map(params![since_ms, until_ms], map_span_row)?
            .flatten()
            .collect(),
    );

    struct Acc {
        repo_id: String,
        repo_name: String,
        worktrees: HashSet<String>,
        sample_cwds: Vec<String>,
        sessions: HashMap<String, SessionRow>,
        spans: Vec<SpanRow>,
        last_seen: i64,
    }

    let mut by_repo: HashMap<String, Acc> = HashMap::new();
    for s in sessions {
        let e = by_repo.entry(s.repo_id.clone()).or_insert_with(|| Acc {
            repo_id: s.repo_id.clone(),
            repo_name: s.repo_name.clone(),
            worktrees: HashSet::new(),
            sample_cwds: Vec::new(),
            sessions: HashMap::new(),
            spans: Vec::new(),
            last_seen: 0,
        });
        if let Some(w) = &s.workspace_id {
            e.worktrees.insert(w.clone());
        }
        if let Some(c) = &s.cwd
            && e.sample_cwds.len() < 3
        {
            e.sample_cwds.push(c.clone());
        }
        e.last_seen = e.last_seen.max(s.started_at);
        e.sessions.insert(s.session_id.clone(), s);
    }

    for sp in spans {
        let e = by_repo.entry(sp.repo_id.clone()).or_insert_with(|| Acc {
            repo_id: sp.repo_id.clone(),
            repo_name: sp.repo_name.clone(),
            worktrees: HashSet::new(),
            sample_cwds: Vec::new(),
            sessions: HashMap::new(),
            spans: Vec::new(),
            last_seen: 0,
        });
        if let Some(w) = &sp.workspace_id {
            e.worktrees.insert(w.clone());
        }
        e.last_seen = e.last_seen.max(sp.started_at);
        e.spans.push(sp);
    }

    let mut out: Vec<RepoSummary> = by_repo
        .into_values()
        .filter(|r| {
            if include_temp {
                return true;
            }
            let raw_path = r.repo_id.strip_prefix("dir:").unwrap_or(&r.repo_id);
            if is_ephemeral_or_neutral_path(raw_path)
                || is_ephemeral_or_neutral_path(&r.repo_name)
                || (!r.sample_cwds.is_empty()
                    && r.sample_cwds
                        .iter()
                        .all(|c| !c.is_empty() && is_ephemeral_or_neutral_path(c)))
            {
                return false;
            }
            // Hide 0-session or 0-command non-git/inferred phantom directories unless explicitly requested
            if (r.sessions.is_empty() || r.spans.is_empty())
                && (r.repo_id.starts_with("dir:") || r.repo_id.starts_with("inferred/"))
            {
                return false;
            }
            true
        })
        .map(|r| {
            let sess_toks: Vec<i64> = r
                .sessions
                .values()
                .map(SessionRow::uncached_billable_tokens)
                .filter(|&v| v > 0)
                .collect();
            let waits: Vec<f64> = r
                .sessions
                .values()
                .map(|s| s.total_tool_ms as f64 / 1000.0)
                .collect();
            let total_stdout: i64 = r.spans.iter().map(|s| s.stdout_tokens).sum();
            let err_cnt = r
                .spans
                .iter()
                .filter(|s| s.exit_code.is_some_and(|c| c != 0))
                .count();
            let cli_or_build: Vec<&SpanRow> = r
                .spans
                .iter()
                .filter(|s| s.category == "repo_task" || s.category == "build_test")
                .collect();
            let cli_used = cli_or_build.iter().filter(|s| s.is_repo_cli).count();

            RepoSummary {
                repo_id: r.repo_id,
                repo_name: r.repo_name,
                worktree_count: r.worktrees.len(),
                session_count: r.sessions.len(),
                command_count: r.spans.len(),
                median_session_tokens: percentile_i64(&sess_toks, 50.0),
                total_stdout_tokens: total_stdout,
                median_tool_wait_s: round1(percentile_f64(&waits, 50.0)),
                error_rate: if r.spans.is_empty() {
                    0.0
                } else {
                    round3(err_cnt as f64 / r.spans.len() as f64)
                },
                cli_adoption_rate: if cli_or_build.is_empty() {
                    None
                } else {
                    Some(round3(cli_used as f64 / cli_or_build.len() as f64))
                },
                last_seen: r.last_seen,
                top_driver: "low friction".to_string(),
                top_impact: None,
            }
        })
        .collect();

    out.sort_by_key(|r| std::cmp::Reverse(r.total_stdout_tokens + (r.command_count as i64) * 250));
    Ok(out)
}

pub fn analyze_fleet(
    conn: &Connection,
    range: &TimeRange,
    include_temp: bool,
) -> Result<FleetReport> {
    let mut repos = list_repos(conn, range, include_temp)?;
    for r in &mut repos {
        if let Ok(mini) = analyze_repo(conn, &r.repo_id, range, 1)
            && let Some(top) = mini.opportunities.first()
        {
            r.top_driver = format!("{}: {}", top.kind, top.target);
            r.top_impact = Some(top.impact_summary.clone());
        }
    }

    let since_ms = range.since_ms;
    let until_ms = range.upper_bound();
    let mut stmt = conn.prepare(
        "SELECT repo_id, cmd_template, category, stdout_tokens, duration_ms, exit_code, noise_kind
         FROM command_spans
         WHERE repo_id IS NOT NULL
           AND started_at >= ?1 AND started_at < ?2
           AND (session_id IS NULL OR session_id IN (
               SELECT session_id FROM sessions
               WHERE COALESCE(started_at, ended_at, 0) >= ?1
                 AND COALESCE(started_at, ended_at, 0) < ?2
           ))",
    )?;
    struct SysAcc {
        repos: HashSet<String>,
        runs: usize,
        stdout_tokens: i64,
        duration_ms: i64,
        errors: usize,
        noises: Vec<String>,
    }
    let mut by_tpl: HashMap<String, SysAcc> = HashMap::new();
    let rows = stmt.query_map(params![since_ms, until_ms], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, Option<i64>>(4)?,
            r.get::<_, Option<i64>>(5)?,
            r.get::<_, Option<String>>(6)?,
        ))
    })?;
    for row in rows.flatten() {
        let (repo_id, tpl, cat, toks, dur, exit_c, noise) = row;
        if cat == "exploration" || is_generic_git_read(&tpl) {
            continue;
        }
        let e = by_tpl.entry(tpl).or_insert_with(|| SysAcc {
            repos: HashSet::new(),
            runs: 0,
            stdout_tokens: 0,
            duration_ms: 0,
            errors: 0,
            noises: Vec::new(),
        });
        e.repos.insert(repo_id);
        e.runs += 1;
        e.stdout_tokens += toks;
        e.duration_ms += dur.unwrap_or(0);
        if exit_c.is_some_and(|c| c != 0) {
            e.errors += 1;
        }
        if let Some(n) = noise {
            e.noises.push(n);
        }
    }

    let mut systemic: Vec<SystemicPattern> = by_tpl
        .into_iter()
        .filter(|(_, g)| {
            g.repos.len() >= 2 && (g.stdout_tokens >= 2000 || g.errors >= 3 || g.runs >= 8)
        })
        .map(|(tpl, g)| SystemicPattern {
            cmd_template: tpl,
            repo_count: g.repos.len(),
            runs: g.runs,
            total_stdout_tokens: g.stdout_tokens,
            total_wait_s: round1(g.duration_ms as f64 / 1000.0),
            error_rate: round3(g.errors as f64 / g.runs.max(1) as f64),
            dominant_noise: mode_str(&g.noises),
        })
        .collect();
    systemic.sort_by_key(|p| std::cmp::Reverse(p.total_stdout_tokens));
    systemic.truncate(8);

    let totals = FleetTotals {
        repos: repos.len(),
        sessions: repos.iter().map(|r| r.session_count).sum(),
        commands: repos.iter().map(|r| r.command_count).sum(),
        stdout_tokens: repos.iter().map(|r| r.total_stdout_tokens).sum(),
    };

    Ok(FleetReport {
        window: range.label.clone(),
        generated_at: Utc::now().to_rfc3339(),
        totals,
        repos,
        systemic_patterns: systemic,
    })
}

pub fn analyze_repo(
    conn: &Connection,
    repo_id: &str,
    range: &TimeRange,
    max_opportunities: usize,
) -> Result<RepoReport> {
    let since_ms = range.since_ms;
    let until_ms = range.upper_bound();

    let mut s_stmt = conn.prepare(&format!(
        "SELECT {SESSION_SELECT_COLS}
         FROM sessions
         WHERE repo_id = ?1
           AND COALESCE(started_at, ended_at, 0) >= ?2
           AND COALESCE(started_at, ended_at, 0) < ?3
         ORDER BY started_at ASC"
    ))?;
    let sessions: Vec<SessionRow> = s_stmt
        .query_map(params![repo_id, since_ms, until_ms], map_session_row)?
        .flatten()
        .collect();

    let mut sp_stmt = conn.prepare(&format!(
        "SELECT {SPAN_SELECT_COLS}
         FROM command_spans
         WHERE repo_id = ?1
           AND started_at >= ?2 AND started_at < ?3
           AND (session_id IS NULL OR session_id IN (
               SELECT session_id FROM sessions
               WHERE COALESCE(started_at, ended_at, 0) >= ?2
                 AND COALESCE(started_at, ended_at, 0) < ?3
           ))
         ORDER BY session_id ASC, turn_idx ASC, seq_idx ASC, started_at ASC"
    ))?;
    let spans: Vec<SpanRow> = dedup_wrap_spans(
        sp_stmt
            .query_map(params![repo_id, since_ms, until_ms], map_span_row)?
            .flatten()
            .collect(),
    );

    let mut rd_stmt = conn.prepare(
        "SELECT COALESCE(session_id, ''), turn_idx, COALESCE(target_path, target_name), is_doc, output_tokens
         FROM file_reads
         WHERE repo_id = ?1
           AND started_at >= ?2 AND started_at < ?3
           AND (session_id IS NULL OR session_id IN (
               SELECT session_id FROM sessions
               WHERE COALESCE(started_at, ended_at, 0) >= ?2
                 AND COALESCE(started_at, ended_at, 0) < ?3
           ))",
    )?;
    let reads: Vec<ReadRow> = rd_stmt
        .query_map(params![repo_id, since_ms, until_ms], |r| {
            Ok(ReadRow {
                session_id: r.get(0)?,
                turn_idx: r.get(1)?,
                target_name: r.get(2)?,
                is_doc: r.get::<_, i64>(3)? != 0,
                output_tokens: r.get(4)?,
            })
        })?
        .flatten()
        .collect();

    // Load known worktree paths for repo config cross-referencing
    let mut wt_stmt = conn.prepare("SELECT worktree_path FROM workspaces WHERE repo_id = ?1")?;
    let wt_paths: Vec<String> = wt_stmt
        .query_map(params![repo_id], |r| r.get::<_, String>(0))?
        .flatten()
        .collect();
    let repo_ctx = RepoContext::discover(&wt_paths);

    let repo_name = sessions
        .first()
        .map(|s| s.repo_name.clone())
        .or_else(|| spans.first().map(|s| s.repo_name.clone()))
        .unwrap_or_else(|| repo_id.to_string());

    let mut session_turn_totals: HashMap<String, i64> = HashMap::new();
    let mut session_agent: HashMap<String, String> = HashMap::new();
    let mut worktrees = HashSet::new();
    let mut agents_set = HashSet::new();
    let mut total_in_toks: i64 = 0;
    let mut total_cache_write_toks: i64 = 0;
    let mut total_cached_toks: i64 = 0;
    let mut total_thinking_toks: i64 = 0;
    let mut total_model_toks: i64 = 0;
    let mut sum_cost_usd: f64 = 0.0;
    let mut est_cost_usd: f64 = 0.0;
    let mut cost_sessions: usize = 0;
    for s in &sessions {
        session_turn_totals.insert(s.session_id.clone(), s.turn_count.max(1));
        session_agent.insert(s.session_id.clone(), s.agent_kind.clone());
        if let Some(w) = &s.workspace_id {
            worktrees.insert(w.clone());
        }
        agents_set.insert(s.agent_kind.clone());
        total_in_toks += s.input_tokens;
        total_cache_write_toks += s.cache_write_tokens;
        total_cached_toks += s.cached_tokens;
        total_thinking_toks += s.thinking_tokens;
        total_model_toks += s.total_model_tokens();
        est_cost_usd += s.effective_cost_usd();
        if let Some(c) = s.cost_usd
            && c > 0.0
        {
            sum_cost_usd += c;
            cost_sessions += 1;
        }
    }
    for sp in &spans {
        if let Some(w) = &sp.workspace_id {
            worktrees.insert(w.clone());
        }
        if let Some(sid) = &sp.session_id {
            let e = session_turn_totals.entry(sid.clone()).or_insert(1);
            *e = (*e).max(sp.turn_idx);
        }
    }
    let mut agents_seen: Vec<String> = agents_set.into_iter().collect();
    agents_seen.sort();

    let effective_toks_for = |sp: &SpanRow| -> i64 {
        let total_t = sp
            .session_id
            .as_deref()
            .and_then(|sid| session_turn_totals.get(sid))
            .copied()
            .unwrap_or(sp.turn_idx.max(1));
        effective_context_tokens(sp.stdout_tokens, sp.turn_idx, total_t)
    };

    let sess_toks: Vec<i64> = sessions
        .iter()
        .map(SessionRow::uncached_billable_tokens)
        .filter(|&v| v > 0)
        .collect();
    let waits: Vec<f64> = sessions
        .iter()
        .map(|s| s.total_tool_ms as f64 / 1000.0)
        .collect();
    let total_stdout_tokens: i64 = spans.iter().map(|s| s.stdout_tokens).sum();
    let total_effective_tokens: i64 = spans.iter().map(&effective_toks_for).sum();
    let total_tool_wait_s: f64 =
        spans.iter().filter_map(|s| s.duration_ms).sum::<i64>() as f64 / 1000.0;
    let err_count = spans
        .iter()
        .filter(|s| s.exit_code.is_some_and(|c| c != 0))
        .count();

    let cache_denom = total_in_toks + total_cache_write_toks + total_cached_toks;
    let cache_hit_rate = if cache_denom > 0 {
        Some(round3(total_cached_toks as f64 / cache_denom as f64))
    } else {
        None
    };

    let cli_or_build: Vec<&SpanRow> = spans
        .iter()
        .filter(|s| s.category == "repo_task" || s.category == "build_test")
        .collect();
    let cli_used = cli_or_build.iter().filter(|s| s.is_repo_cli).count();

    // Group spans by session for sequential pattern mining (exclude orphan NULL-session spans!)
    let mut spans_by_session: HashMap<String, Vec<&SpanRow>> = HashMap::new();
    for sp in &spans {
        if let Some(sid) = &sp.session_id {
            spans_by_session.entry(sid.clone()).or_default().push(sp);
        }
    }

    let mut total_repo_cli_calls = 0usize;
    let mut rebound_count = 0usize;
    struct ReboundAcc {
        count: usize,
        sessions: HashSet<String>,
        by_harness: BTreeMap<String, usize>,
        followups: HashMap<String, usize>,
        proof: Vec<String>,
    }
    let mut rebounds_by_tpl: HashMap<String, ReboundAcc> = HashMap::new();

    struct ThrashAcc {
        from: String,
        to: String,
        cmd_bin: String,
        count: usize,
        sessions: HashSet<String>,
        by_harness: BTreeMap<String, usize>,
        stderr_samples: Vec<String>,
        proof: Vec<String>,
    }
    let mut thrash_pairs: HashMap<String, ThrashAcc> = HashMap::new();

    struct PollAcc {
        sessions: usize,
        total_calls: usize,
        total_ms: i64,
        max_in_session: usize,
        by_harness: BTreeMap<String, usize>,
        proof: Vec<String>,
    }
    let mut polling_by_tpl: HashMap<String, PollAcc> = HashMap::new();

    struct ChainAcc {
        count: usize,
        sessions: HashSet<String>,
        by_harness: BTreeMap<String, usize>,
        total_ms: i64,
        total_tokens: i64,
        proof: Vec<String>,
    }
    let mut chain_counts: HashMap<String, ChainAcc> = HashMap::new();

    for (sess_id, list) in &spans_by_session {
        let mut sess_tpl_counts: HashMap<&str, usize> = HashMap::new();
        for i in 0..list.len() {
            let cur = list[i];
            let next = list.get(i + 1).copied();
            *sess_tpl_counts
                .entry(cur.cmd_template.as_str())
                .or_insert(0) += 1;

            // 1. Post-CLI Rebound: repo CLI immediately followed by exploration or non-git shell fallback
            if cur.is_repo_cli {
                total_repo_cli_calls += 1;
                if let Some(nx) = next
                    && !nx.is_repo_cli
                    && !is_normal_vcs_workflow_cmd(&nx.cmd_template)
                    && (nx.category == "exploration" || nx.category == "vcs_ci")
                    && nx.turn_idx - cur.turn_idx <= 1
                    && nx.started_at.saturating_sub(cur.started_at) <= 60_000
                {
                    rebound_count += 1;
                    let rb = rebounds_by_tpl
                        .entry(cur.cmd_template.clone())
                        .or_insert_with(|| ReboundAcc {
                            count: 0,
                            sessions: HashSet::new(),
                            by_harness: BTreeMap::new(),
                            followups: HashMap::new(),
                            proof: Vec::new(),
                        });
                    rb.count += 1;
                    rb.sessions.insert(sess_id.clone());
                    *rb.by_harness
                        .entry(harness_key(cur.agent_kind.as_deref()))
                        .or_insert(0) += 1;
                    *rb.followups.entry(nx.cmd_template.clone()).or_insert(0) += 1;
                    if rb.proof.is_empty() {
                        rb.proof.push(format!(
                            "t{}: `{}` (exit={}, {} toks)",
                            cur.turn_idx,
                            truncate(&cur.raw_redacted, 90),
                            cur.exit_code.map_or("?".into(), |c| c.to_string()),
                            format_compact(cur.stdout_tokens)
                        ));
                        rb.proof.push(format!(
                            "t{}: rebound -> `{}` ({} toks)",
                            nx.turn_idx,
                            truncate(&nx.raw_redacted, 90),
                            format_compact(nx.stdout_tokens)
                        ));
                    }
                }
            }

            // 2. Flag / Retry Thrash: failed cmd followed within 2 turns by succeeded cmd on same binary
            if cur.exit_code.is_some_and(|c| c != 0) && cur.category != "exploration" {
                for cand in list.iter().skip(i + 1).take(3) {
                    if cand.turn_idx - cur.turn_idx > 2 {
                        break;
                    }
                    if cand.cmd_bin == cur.cmd_bin && cand.exit_code == Some(0) {
                        let key = format!("{} => {}", cur.cmd_template, cand.cmd_template);
                        let tp = thrash_pairs.entry(key).or_insert_with(|| ThrashAcc {
                            from: cur.cmd_template.clone(),
                            to: cand.cmd_template.clone(),
                            cmd_bin: cur.cmd_bin.clone(),
                            count: 0,
                            sessions: HashSet::new(),
                            by_harness: BTreeMap::new(),
                            stderr_samples: Vec::new(),
                            proof: Vec::new(),
                        });
                        tp.count += 1;
                        tp.sessions.insert(sess_id.clone());
                        *tp.by_harness
                            .entry(harness_key(cur.agent_kind.as_deref()))
                            .or_insert(0) += 1;
                        if let Some(prev) = &cur.stderr_preview {
                            let cleaned = clean_error_preview(prev);
                            if !cleaned.is_empty() && tp.stderr_samples.len() < 3 {
                                tp.stderr_samples.push(cleaned);
                            }
                        }
                        if tp.proof.is_empty() {
                            let clean_err = cur
                                .stderr_preview
                                .as_deref()
                                .map(clean_error_preview)
                                .filter(|e| !e.is_empty());
                            tp.proof.push(format!(
                                "t{}: `{}` (exit={}{})",
                                cur.turn_idx,
                                truncate(&cur.raw_redacted, 85),
                                cur.exit_code.unwrap_or(1),
                                clean_err
                                    .as_deref()
                                    .map(|e| format!(": {}", truncate(e, 65)))
                                    .unwrap_or_default()
                            ));
                            tp.proof.push(format!(
                                "t{}: fixed -> `{}` (exit=0)",
                                cand.turn_idx,
                                truncate(&cand.raw_redacted, 85)
                            ));
                        }
                        break;
                    }
                }
            }

            // 3. Infra/Workflow Chatter Chains (suppress generic exploration pairs like sed <-> grep!)
            if let Some(nx) = next
                && cur.cmd_template != nx.cmd_template
                && (is_infra_or_workflow_cmd(cur) || is_infra_or_workflow_cmd(nx))
                && !(cur.category == "exploration" && nx.category == "exploration")
            {
                let pair_key = format!("{} -> {}", cur.cmd_template, nx.cmd_template);
                let ch = chain_counts.entry(pair_key).or_insert_with(|| ChainAcc {
                    count: 0,
                    sessions: HashSet::new(),
                    by_harness: BTreeMap::new(),
                    total_ms: 0,
                    total_tokens: 0,
                    proof: Vec::new(),
                });
                ch.count += 1;
                ch.sessions.insert(sess_id.clone());
                *ch.by_harness
                    .entry(harness_key(cur.agent_kind.as_deref()))
                    .or_insert(0) += 1;
                ch.total_ms += cur.duration_ms.unwrap_or(0) + nx.duration_ms.unwrap_or(0);
                ch.total_tokens += cur.stdout_tokens + nx.stdout_tokens;
                if ch.proof.is_empty() {
                    ch.proof.push(format!(
                        "t{}: `{}` -> t{}: `{}`",
                        cur.turn_idx,
                        truncate(&cur.raw_redacted, 70),
                        nx.turn_idx,
                        truncate(&nx.raw_redacted, 70)
                    ));
                }
            }
        }

        // 4. Actual Polling Tax (only real wait/poll/status/sleep primitives — never git status!)
        for (tpl, cnt) in sess_tpl_counts {
            let sample_sp = list.iter().find(|x| x.cmd_template == tpl).copied();
            let cat = sample_sp.map_or("other", |x| x.category.as_str());
            if !is_actual_polling_cmd(tpl, cat) {
                continue;
            }
            if cnt >= 3 || (tpl.starts_with("sleep") && cnt >= 2) {
                let p = polling_by_tpl.entry(tpl.to_string()).or_insert(PollAcc {
                    sessions: 0,
                    total_calls: 0,
                    total_ms: 0,
                    max_in_session: 0,
                    by_harness: BTreeMap::new(),
                    proof: Vec::new(),
                });
                p.sessions += 1;
                p.total_calls += cnt;
                p.max_in_session = p.max_in_session.max(cnt);
                *p.by_harness
                    .entry(harness_key(sample_sp.and_then(|s| s.agent_kind.as_deref())))
                    .or_insert(0) += cnt;
                let sess_ms: i64 = list
                    .iter()
                    .filter(|x| x.cmd_template == tpl)
                    .filter_map(|x| x.duration_ms)
                    .sum();
                p.total_ms += sess_ms;
                if p.proof.is_empty() {
                    let turns: Vec<String> = list
                        .iter()
                        .filter(|x| x.cmd_template == tpl)
                        .take(4)
                        .map(|x| format!("t{}", x.turn_idx))
                        .collect();
                    p.proof.push(format!(
                        "`{}` polled {}x in one session ({}..., {} wait)",
                        tpl,
                        cnt,
                        turns.join(", "),
                        format_duration_human(sess_ms as f64 / 1000.0)
                    ));
                }
            }
        }
    }

    // Aggregate per command template (including effective downstream token tax & pipe stripping!)
    struct TplAcc {
        cmd_template: String,
        category: String,
        is_repo_cli: bool,
        runs: usize,
        errors: usize,
        piped_count: usize,
        by_harness: BTreeMap<String, usize>,
        error_by_harness: BTreeMap<String, usize>,
        piped_by_harness: BTreeMap<String, usize>,
        pipe_filters: Vec<String>,
        stdout_toks: Vec<i64>,
        durations_ms: Vec<i64>,
        unchained_durations_ms: Vec<i64>,
        total_stdout_tokens: i64,
        total_effective_tokens: i64,
        total_duration_ms: i64,
        noises: Vec<String>,
        error_samples: Vec<String>,
        heaviest_sample: Option<(i64, String, i64, Option<i64>)>, // (toks, raw, turn, exit)
    }
    let mut by_tpl: HashMap<String, TplAcc> = HashMap::new();
    for sp in &spans {
        let eff = effective_toks_for(sp);
        let hkey = harness_key(sp.agent_kind.as_deref());
        let g = by_tpl
            .entry(sp.cmd_template.clone())
            .or_insert_with(|| TplAcc {
                cmd_template: sp.cmd_template.clone(),
                category: sp.category.clone(),
                is_repo_cli: sp.is_repo_cli,
                runs: 0,
                errors: 0,
                piped_count: 0,
                by_harness: BTreeMap::new(),
                error_by_harness: BTreeMap::new(),
                piped_by_harness: BTreeMap::new(),
                pipe_filters: Vec::new(),
                stdout_toks: Vec::new(),
                durations_ms: Vec::new(),
                unchained_durations_ms: Vec::new(),
                total_stdout_tokens: 0,
                total_effective_tokens: 0,
                total_duration_ms: 0,
                noises: Vec::new(),
                error_samples: Vec::new(),
                heaviest_sample: None,
            });
        g.runs += 1;
        *g.by_harness.entry(hkey.clone()).or_insert(0) += 1;
        if sp.exit_code.is_some_and(|c| c != 0) {
            g.errors += 1;
            *g.error_by_harness.entry(hkey.clone()).or_insert(0) += 1;
            if g.error_samples.len() < 3 {
                let clean_err = sp
                    .stderr_preview
                    .as_deref()
                    .map(clean_error_preview)
                    .filter(|e| !e.is_empty());
                g.error_samples.push(format!(
                    "t{}: `{}` (exit={}{})",
                    sp.turn_idx,
                    truncate(&sp.raw_redacted, 80),
                    sp.exit_code.unwrap_or(1),
                    clean_err
                        .as_deref()
                        .map(|e| format!(": {}", truncate(e, 75)))
                        .unwrap_or_default()
                ));
            }
        }
        if let Some(pf) = &sp.piped_filter {
            g.piped_count += 1;
            *g.piped_by_harness.entry(hkey).or_insert(0) += 1;
            g.pipe_filters.push(pf.clone());
        }
        g.stdout_toks.push(sp.stdout_tokens);
        if let Some(d) = sp.duration_ms {
            g.durations_ms.push(d);
            if !sp.is_chained {
                g.unchained_durations_ms.push(d);
            }
            g.total_duration_ms += d;
        }
        g.total_stdout_tokens += sp.stdout_tokens;
        g.total_effective_tokens += eff;
        if let Some(n) = &sp.noise_kind {
            g.noises.push(n.clone());
        }
        if g.heaviest_sample
            .as_ref()
            .is_none_or(|(best, _, _, _)| sp.stdout_tokens > *best)
        {
            g.heaviest_sample = Some((
                sp.stdout_tokens,
                sp.raw_redacted.clone(),
                sp.turn_idx,
                sp.exit_code,
            ));
        }
    }

    let task_target = repo_ctx.task_fix_target();
    let docs_target = repo_ctx.docs_fix_target();
    let mut raw_opps: Vec<Opportunity> = Vec::new();

    // A. Noisy Infra / Build / Test Output (ranked by effective downstream token tax; suppress raw exploration & generic interpreters)
    for g in by_tpl.values() {
        if g.category == "exploration"
            || is_generic_git_read(&g.cmd_template)
            || is_generic_interpreter(&g.cmd_template)
        {
            continue;
        }
        let p50 = percentile_i64(&g.stdout_toks, 50.0);
        let p95 = percentile_i64(&g.stdout_toks, 95.0);
        if g.total_stdout_tokens >= 1500 && (p50 >= 350 || p95 >= 1200) {
            let share = if total_stdout_tokens > 0 {
                ((g.total_stdout_tokens as f64 / total_stdout_tokens as f64) * 100.0).round() as i64
            } else {
                0
            };
            let noise = mode_str(&g.noises).unwrap_or_else(|| "verbose_stdout".to_string());
            let mut ev = BTreeMap::new();
            ev.insert("runs".into(), serde_json::json!(g.runs));
            ev.insert("p50_stdout_tokens".into(), serde_json::json!(p50));
            ev.insert("p95_stdout_tokens".into(), serde_json::json!(p95));
            ev.insert(
                "effective_context_tokens".into(),
                serde_json::json!(g.total_effective_tokens),
            );
            ev.insert("dominant_noise".into(), serde_json::json!(noise));

            let proof = g
                .heaviest_sample
                .as_ref()
                .map(|(toks, raw, turn, ec)| {
                    vec![format!(
                        "t{turn}: `{}` -> {} stdout toks (exit={}, noise={noise})",
                        truncate(raw, 90),
                        format_compact(*toks),
                        ec.map_or("?".into(), |c| c.to_string())
                    )]
                })
                .unwrap_or_default();

            raw_opps.push(Opportunity {
                id: String::new(),
                scope: scope_for_cmd(&g.cmd_template),
                kind: "noisy_task_output".to_string(),
                fix_target: task_target.clone(),
                target: g.cmd_template.clone(),
                score: g.total_effective_tokens / 4 + g.total_stdout_tokens,
                impact_summary: format!(
                    "{} raw stdout (~{} effective context toks, {share}% of output) across {} runs",
                    format_compact(g.total_stdout_tokens),
                    format_compact(g.total_effective_tokens),
                    g.runs
                ),
                by_harness: g.by_harness.clone(),
                harness_summary: format_harness_breakdown(&g.by_harness),
                evidence: ev,
                trace_proof: proof,
                suggested_action: suggest_for_token_bloat(&g.cmd_template, &noise, g.is_repo_cli),
                acceptance_metric: format!(
                    "p50_stdout_tokens < {} AND rebound_rate < 0.05",
                    ((p50 as f64 * 0.35).round() as i64).max(200)
                ),
            });
        }
    }

    // B. Post-CLI Escape-Hatch Rebounds (specific repo CLI tasks whose output forces raw shell follow-ups)
    for (tpl, rb) in &rebounds_by_tpl {
        if rb.count >= 3 {
            let mut follow_list: Vec<(String, usize)> =
                rb.followups.iter().map(|(k, v)| (k.clone(), *v)).collect();
            follow_list.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
            let top_follows: Vec<String> = follow_list
                .into_iter()
                .take(4)
                .map(|(k, v)| format!("{k} ({v}x)"))
                .collect();
            let total_runs = by_tpl.get(tpl).map_or(rb.count, |g| g.runs);
            let rb_rate = rb.count as f64 / total_runs.max(1) as f64;
            if rb_rate < 0.15 && rb.count < 5 {
                continue;
            }
            let mut ev = BTreeMap::new();
            ev.insert("rebound_count".into(), serde_json::json!(rb.count));
            ev.insert("total_runs".into(), serde_json::json!(total_runs));
            ev.insert("rebound_rate".into(), serde_json::json!(round3(rb_rate)));
            ev.insert("sessions".into(), serde_json::json!(rb.sessions.len()));
            ev.insert("top_fallback_cmds".into(), serde_json::json!(top_follows));

            raw_opps.push(Opportunity {
                id: String::new(),
                scope: scope_for_cmd(tpl),
                kind: "lossy_task_rebound".to_string(),
                fix_target: task_target.clone(),
                target: tpl.clone(),
                score: (rb.count as i64) * 5500,
                impact_summary: format!(
                    "{} raw-shell rebounds ({:.0}% of {} runs) across {} sessions",
                    rb.count,
                    rb_rate * 100.0,
                    total_runs,
                    rb.sessions.len()
                ),
                by_harness: rb.by_harness.clone(),
                harness_summary: format_harness_breakdown(&rb.by_harness),
                evidence: ev,
                trace_proof: rb.proof.clone(),
                suggested_action: format!(
                    "Investigate why \"{tpl}\" is immediately followed by {} — missing fields, truncation, or unclear pointers.",
                    top_follows.first().cloned().unwrap_or_else(|| "raw shell lookups".into())
                ),
                acceptance_metric: format!("rebound_rate on \"{tpl}\" < 10%"),
            });
        }
    }

    // C. Flag / Retry Thrash
    for tp in thrash_pairs.values() {
        if tp.count >= 2 {
            let mut ev = BTreeMap::new();
            ev.insert(
                "transition".into(),
                serde_json::json!(format!("{} (nonzero) -> {} (exit 0)", tp.from, tp.to)),
            );
            ev.insert("occurrences".into(), serde_json::json!(tp.count));
            ev.insert("sessions".into(), serde_json::json!(tp.sessions.len()));
            if !tp.stderr_samples.is_empty() {
                ev.insert(
                    "stderr_samples".into(),
                    serde_json::json!(tp.stderr_samples),
                );
            }
            raw_opps.push(Opportunity {
                id: String::new(),
                scope: scope_for_cmd(&tp.from),
                kind: "flag_thrash".to_string(),
                fix_target: format!("CLI / error diagnostics ({task_target})"),
                target: if tp.from == tp.to {
                    tp.from.clone()
                } else {
                    format!("{} -> {}", tp.from, tp.to)
                },
                score: (tp.count as i64) * 5200,
                impact_summary: format!(
                    "{} retry loops across {} session(s)",
                    tp.count,
                    tp.sessions.len()
                ),
                by_harness: tp.by_harness.clone(),
                harness_summary: format_harness_breakdown(&tp.by_harness),
                evidence: ev,
                trace_proof: tp.proof.clone(),
                suggested_action: if tp.from == tp.to {
                    format!(
                        "Inspect recurring failures in \"{}\" — transient flakiness, missing prerequisite check, or unclear first-error message.",
                        tp.from
                    )
                } else {
                    format!(
                        "Agents repeatedly fail with \"{}\" before succeeding with \"{}\" — check CLI ergonomics, stderr hints, or {docs_target}.",
                        tp.from, tp.to
                    )
                },
                acceptance_metric: format!("nonzero exit rate on \"{}\" < 5%", tp.cmd_bin),
            });
        }
    }

    // D. Polling Tax (only real polling primitives)
    for (tpl, p) in &polling_by_tpl {
        let avg_calls = p.total_calls as f64 / p.sessions.max(1) as f64;
        let wait_s = round1(p.total_ms as f64 / 1000.0);
        let mut ev = BTreeMap::new();
        ev.insert("total_calls".into(), serde_json::json!(p.total_calls));
        ev.insert("sessions".into(), serde_json::json!(p.sessions));
        ev.insert(
            "max_calls_in_one_session".into(),
            serde_json::json!(p.max_in_session),
        );
        ev.insert(
            "avg_calls_per_session".into(),
            serde_json::json!(round1(avg_calls)),
        );
        ev.insert("total_wait_s".into(), serde_json::json!(wait_s));
        let sc = scope_for_cmd(tpl);
        raw_opps.push(Opportunity {
            id: String::new(),
            scope: sc.clone(),
            kind: "polling_tax".to_string(),
            fix_target: if sc == "harness" {
                "Agent harness / async job handling".to_string()
            } else {
                format!("{task_target} + {docs_target}")
            },
            target: tpl.clone(),
            score: (p.total_calls as i64) * 3200 + p.total_ms / 8,
            impact_summary: format!(
                "{} polling calls ({:.1}x/session avg, max {}x) and {} wait across {} session(s)",
                p.total_calls,
                avg_calls,
                p.max_in_session,
                format_duration_human(wait_s),
                p.sessions
            ),
            by_harness: p.by_harness.clone(),
            harness_summary: format_harness_breakdown(&p.by_harness),
            evidence: ev,
            trace_proof: p.proof.clone(),
            suggested_action: if sc == "harness" {
                format!(
                    "Harness-level wait/poll loop on \"{tpl}\" — check why background processes are polled iteratively instead of awaited or notified."
                )
            } else {
                format!(
                    "Repeated polling on \"{tpl}\" — inspect whether a blocking/event-driven wait or push notification would eliminate poll loops."
                )
            },
            acceptance_metric: "avg_calls_per_session <= 1.5".to_string(),
        });
    }

    // E. Latency Sinks (infra/build/test/vcs commands only; skip targets already flagged as polling loops)
    for g in by_tpl.values() {
        if g.category == "exploration"
            || is_generic_git_read(&g.cmd_template)
            || polling_by_tpl.contains_key(&g.cmd_template)
        {
            continue;
        }
        let dur_samples = if g.unchained_durations_ms.len() >= 3 {
            &g.unchained_durations_ms
        } else {
            &g.durations_ms
        };
        if g.total_duration_ms >= 20_000 && dur_samples.len() >= 3 {
            let p50s = round1(percentile_i64(dur_samples, 50.0) as f64 / 1000.0);
            let p95s = round1(percentile_i64(dur_samples, 95.0) as f64 / 1000.0);
            let total_s = round1(g.total_duration_ms as f64 / 1000.0);
            if p50s < 1.5 && total_s < 120.0 {
                continue;
            }
            let mut ev = BTreeMap::new();
            ev.insert("runs".into(), serde_json::json!(g.runs));
            ev.insert("p50_wait_s".into(), serde_json::json!(p50s));
            ev.insert("p95_wait_s".into(), serde_json::json!(p95s));
            ev.insert("total_wait_s".into(), serde_json::json!(total_s));
            let proof = g
                .heaviest_sample
                .as_ref()
                .map(|(_, raw, turn, _)| {
                    vec![format!(
                        "t{turn}: `{}` (p50 {}, p95 {} across {} runs)",
                        truncate(raw, 90),
                        format_duration_human(p50s),
                        format_duration_human(p95s),
                        g.runs
                    )]
                })
                .unwrap_or_default();
            let sc = scope_for_cmd(&g.cmd_template);
            raw_opps.push(Opportunity {
                id: String::new(),
                scope: sc.clone(),
                kind: "slow_task_latency".to_string(),
                fix_target: if sc == "harness" {
                    "Agent harness / PTY wait".to_string()
                } else {
                    task_target.clone()
                },
                target: g.cmd_template.clone(),
                score: g.total_duration_ms / 6,
                impact_summary: format!(
                    "{} total wait (p50 {}, p95 {}) across {} runs",
                    format_duration_human(total_s),
                    format_duration_human(p50s),
                    format_duration_human(p95s),
                    g.runs
                ),
                by_harness: g.by_harness.clone(),
                harness_summary: format_harness_breakdown(&g.by_harness),
                evidence: ev,
                trace_proof: proof,
                suggested_action: format!(
                    "High wall-clock wait on \"{}\" — inspect caching, narrower scoping, parallelism, or why agents block synchronously.",
                    g.cmd_template
                ),
                acceptance_metric: format!("p50_wait_s < {:.1}", (p50s * 0.5).max(1.0)),
            });
        }
    }

    // F. Workflow Chatter Chains (infra/workflow sequences only; skip pure harness PTY wait pairs)
    for (chain, ch) in &chain_counts {
        if ch.count >= 4 && ch.sessions.len() >= 2 {
            if chain.split(" -> ").all(is_harness_command) {
                continue;
            }
            let wait_s = round1(ch.total_ms as f64 / 1000.0);
            let mut ev = BTreeMap::new();
            ev.insert("occurrences".into(), serde_json::json!(ch.count));
            ev.insert("sessions".into(), serde_json::json!(ch.sessions.len()));
            ev.insert(
                "combined_stdout_tokens".into(),
                serde_json::json!(ch.total_tokens),
            );
            ev.insert("combined_wait_s".into(), serde_json::json!(wait_s));
            raw_opps.push(Opportunity {
                id: String::new(),
                scope: "repo".to_string(),
                kind: "missing_composite_task".to_string(),
                fix_target: task_target.clone(),
                target: chain.clone(),
                score: (ch.count as i64) * 3200 + ch.total_tokens / 2,
                impact_summary: format!(
                    "repeated {}x across {} sessions ({} tokens, {})",
                    ch.count,
                    ch.sessions.len(),
                    format_compact(ch.total_tokens),
                    format_duration_human(wait_s)
                ),
                by_harness: ch.by_harness.clone(),
                harness_summary: format_harness_breakdown(&ch.by_harness),
                evidence: ev,
                trace_proof: ch.proof.clone(),
                suggested_action: format!(
                    "Recurring multi-step chain \"{chain}\" — check whether a single higher-level workflow or richer first step removes the round-trip."
                ),
                acceptance_metric: "sequence occurrences drop > 70%".to_string(),
            });
        }
    }

    // G. Orientation Tax (early-session discovery)
    let early_orient_spans: Vec<&SpanRow> = spans
        .iter()
        .filter(|s| s.is_orientation && s.turn_idx <= 3)
        .collect();
    let early_doc_reads: Vec<&ReadRow> = reads
        .iter()
        .filter(|r| r.is_doc && r.turn_idx <= 3)
        .collect();
    let orient_tokens: i64 = early_orient_spans
        .iter()
        .map(|s| s.stdout_tokens)
        .sum::<i64>()
        + early_doc_reads.iter().map(|r| r.output_tokens).sum::<i64>();
    let orient_events = early_orient_spans.len() + early_doc_reads.len();

    if orient_events >= 5 && orient_tokens >= 2000 {
        let mut counts: HashMap<String, usize> = HashMap::new();
        let mut orient_by_harness: BTreeMap<String, usize> = BTreeMap::new();
        for s in &early_orient_spans {
            *counts.entry(s.cmd_template.clone()).or_insert(0) += 1;
            *orient_by_harness
                .entry(harness_key(s.agent_kind.as_deref()))
                .or_insert(0) += 1;
        }
        for r in &early_doc_reads {
            *counts.entry(format!("read:{}", r.target_name)).or_insert(0) += 1;
            let ag = session_agent.get(&r.session_id).map(String::as_str);
            *orient_by_harness.entry(harness_key(ag)).or_insert(0) += 1;
        }
        let mut top: Vec<(String, usize)> = counts.into_iter().collect();
        top.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
        let top_list: Vec<String> = top
            .into_iter()
            .take(5)
            .map(|(k, v)| format!("{k} ({v}x)"))
            .collect();

        let mut ev = BTreeMap::new();
        ev.insert(
            "early_commands".into(),
            serde_json::json!(early_orient_spans.len()),
        );
        ev.insert(
            "early_doc_reads".into(),
            serde_json::json!(early_doc_reads.len()),
        );
        ev.insert("top_discovery_calls".into(), serde_json::json!(top_list));

        let per_sess = orient_tokens / sessions.len().max(1) as i64;
        let orient_hs = format_harness_breakdown(&orient_by_harness);
        raw_opps.push(Opportunity {
            id: String::new(),
            scope: "repo".to_string(),
            kind: "orientation_tax".to_string(),
            fix_target: docs_target.clone(),
            target: "early-session discovery".to_string(),
            score: orient_tokens * 2 + (orient_events as i64) * 500,
            impact_summary: format!(
                "{} tokens across {} early-turn discovery calls (~{} toks/session)",
                format_compact(orient_tokens),
                orient_events,
                format_compact(per_sess)
            ),
            by_harness: orient_by_harness,
            harness_summary: orient_hs,
            evidence: ev,
            trace_proof: vec![format!("Top early turns (<=3): {}", top_list.join(", "))],
            suggested_action: format!(
                "Heavy turns 1–3 discovery — inspect what agents keep searching for in {docs_target}, project layout, or entrypoints."
            ),
            acceptance_metric: format!(
                "early_discovery_tokens per session < {}",
                ((per_sess as f64 * 0.4).round() as i64).max(300)
            ),
        });
    }

    // H. High-Failure-Rate / Broken Repo Tasks (even at low-to-medium volume!)
    for g in by_tpl.values() {
        if g.is_repo_cli && g.runs >= 4 {
            let err_rate = g.errors as f64 / g.runs as f64;
            if err_rate >= 0.20 && g.errors >= 2 {
                let mut ev = BTreeMap::new();
                ev.insert("errors".into(), serde_json::json!(g.errors));
                ev.insert("runs".into(), serde_json::json!(g.runs));
                ev.insert("error_rate".into(), serde_json::json!(round3(err_rate)));
                raw_opps.push(Opportunity {
                    id: String::new(),
                    scope: scope_for_cmd(&g.cmd_template),
                    kind: "broken_task_error_rate".to_string(),
                    fix_target: task_target.clone(),
                    target: g.cmd_template.clone(),
                    score: (g.errors as i64) * 9000 + ((err_rate * 20_000.0) as i64),
                    impact_summary: format!(
                        "{}/{} runs failed ({:.0}% failure rate)",
                        g.errors,
                        g.runs,
                        err_rate * 100.0
                    ),
                    by_harness: g.error_by_harness.clone(),
                    harness_summary: format_harness_breakdown(&g.error_by_harness),
                    evidence: ev,
                    trace_proof: g.error_samples.clone(),
                    suggested_action: format!(
                        "High failure rate on \"{}\" — inspect stderr samples for environment assumptions, stale flags, or flaky dependencies.",
                        g.cmd_template
                    ),
                    acceptance_metric: format!("error_rate on \"{}\" < 5%", g.cmd_template),
                });
            }
        }
    }

    // I. Output Banner / Pipe-Stripping Friction (repo CLI commands frequently piped into grep -v / sed / tail / jq)
    let mut total_cli_piped = 0usize;
    let mut piped_cli_breakdown: Vec<(String, usize, usize, String)> = Vec::new();
    let mut piped_by_harness: BTreeMap<String, usize> = BTreeMap::new();
    for g in by_tpl.values() {
        if g.is_repo_cli && g.piped_count >= 4 {
            let rate = g.piped_count as f64 / g.runs.max(1) as f64;
            if rate >= 0.15 || g.piped_count >= 10 {
                total_cli_piped += g.piped_count;
                for (h, c) in &g.piped_by_harness {
                    *piped_by_harness.entry(h.clone()).or_insert(0) += *c;
                }
                let top_f = mode_str(&g.pipe_filters).unwrap_or_else(|| "pipe".to_string());
                piped_cli_breakdown.push((g.cmd_template.clone(), g.piped_count, g.runs, top_f));
            }
        }
    }
    if total_cli_piped >= 12 {
        piped_cli_breakdown.sort_by_key(|(_, c, _, _)| std::cmp::Reverse(*c));
        let top_str: Vec<String> = piped_cli_breakdown
            .iter()
            .take(5)
            .map(|(t, c, r, f)| format!("{t} ({c}/{r} -> | {f})"))
            .collect();
        let mut ev = BTreeMap::new();
        ev.insert(
            "total_piped_cli_calls".into(),
            serde_json::json!(total_cli_piped),
        );
        ev.insert("top_piped_tasks".into(), serde_json::json!(top_str));
        let piped_hs = format_harness_breakdown(&piped_by_harness);
        raw_opps.push(Opportunity {
            id: String::new(),
            scope: "repo".to_string(),
            kind: "output_filtering_tax".to_string(),
            fix_target: task_target.clone(),
            target: "CLI output verbosity & filtering".to_string(),
            score: (total_cli_piped as i64) * 1800,
            impact_summary: format!(
                "{total_cli_piped} repo CLI invocations piped into post-filters (grep/sed/tail/jq)"
            ),
            by_harness: piped_by_harness,
            harness_summary: piped_hs,
            evidence: ev,
            trace_proof: top_str,
            suggested_action: format!(
                "Agents repeatedly pipe repo CLI stdout through tail/sed/grep — inspect output noise, banners, or missing structured/bounded modes in {task_target}."
            ),
            acceptance_metric: "CLI pipe-stripping rate drops by >= 80%".to_string(),
        });
    }

    // J. CLI Help Lookup & Broken `--help` Tax
    let help_spans: Vec<&SpanRow> = spans
        .iter()
        .filter(|s| s.is_repo_cli && is_help_invocation(s))
        .collect();
    if help_spans.len() >= 10 {
        let help_toks: i64 = help_spans.iter().map(|s| s.stdout_tokens).sum();
        let broken_helps: Vec<&SpanRow> = help_spans
            .iter()
            .copied()
            .filter(|s| s.exit_code.is_some_and(|c| c != 0))
            .collect();
        let mut by_help_cmd: HashMap<String, usize> = HashMap::new();
        let mut help_by_harness: BTreeMap<String, usize> = BTreeMap::new();
        for s in &help_spans {
            *by_help_cmd.entry(s.cmd_template.clone()).or_insert(0) += 1;
            *help_by_harness
                .entry(harness_key(s.agent_kind.as_deref()))
                .or_insert(0) += 1;
        }
        let mut top_h: Vec<(String, usize)> = by_help_cmd.into_iter().collect();
        top_h.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
        let top_list: Vec<String> = top_h
            .into_iter()
            .take(5)
            .map(|(k, v)| format!("{k} ({v}x)"))
            .collect();
        let mut ev = BTreeMap::new();
        ev.insert("help_calls".into(), serde_json::json!(help_spans.len()));
        ev.insert(
            "broken_help_calls".into(),
            serde_json::json!(broken_helps.len()),
        );
        ev.insert("help_stdout_tokens".into(), serde_json::json!(help_toks));
        ev.insert("top_help_cmds".into(), serde_json::json!(top_list));
        let mut proof = vec![format!("Top help lookups: {}", top_list.join(", "))];
        if let Some(bh) = broken_helps.first() {
            let clean_err = bh
                .stderr_preview
                .as_deref()
                .map(clean_error_preview)
                .filter(|e| !e.is_empty());
            proof.push(format!(
                "Broken help: `{}` (exit={}{})",
                truncate(&bh.raw_redacted, 80),
                bh.exit_code.unwrap_or(1),
                clean_err
                    .as_deref()
                    .map(|e| format!(": {}", truncate(e, 60)))
                    .unwrap_or_default()
            ));
        }
        let help_hs = format_harness_breakdown(&help_by_harness);
        raw_opps.push(Opportunity {
            id: String::new(),
            scope: "repo".to_string(),
            kind: "cli_help_tax".to_string(),
            fix_target: format!("{docs_target} + {task_target}"),
            target: "CLI help & flag discoverability".to_string(),
            score: (help_spans.len() as i64) * 1600 + (broken_helps.len() as i64) * 4000,
            impact_summary: format!(
                "{} CLI help lookups ({} toks, {} broken/nonzero exits)",
                help_spans.len(),
                format_compact(help_toks),
                broken_helps.len()
            ),
            by_harness: help_by_harness,
            harness_summary: help_hs,
            evidence: ev,
            trace_proof: proof,
            suggested_action: format!(
                "Frequent `--help` lookups (and broken help exits) — inspect flag discoverability across {task_target} and {docs_target}."
            ),
            acceptance_metric: "CLI --help calls drop by >= 60% and broken help exits drop to 0".to_string(),
        });
    }

    // K. Direct State-Directory Scraping Bypass (agents reading state dirs directly instead of via CLI)
    struct StateScrapeAcc {
        cnt: usize,
        sess: HashSet<String>,
        toks: i64,
        cmd_map: HashMap<String, usize>,
        by_harness: BTreeMap<String, usize>,
        sample: Option<String>,
    }
    let mut state_scrapes: HashMap<String, StateScrapeAcc> = HashMap::new();
    for sp in &spans {
        if sp.is_repo_cli {
            continue;
        }
        if let Some(dir) = &sp.state_dir_hint {
            let e = state_scrapes
                .entry(dir.clone())
                .or_insert_with(|| StateScrapeAcc {
                    cnt: 0,
                    sess: HashSet::new(),
                    toks: 0,
                    cmd_map: HashMap::new(),
                    by_harness: BTreeMap::new(),
                    sample: None,
                });
            e.cnt += 1;
            if let Some(sid) = &sp.session_id {
                e.sess.insert(sid.clone());
            }
            e.toks += sp.stdout_tokens;
            *e.cmd_map.entry(sp.cmd_template.clone()).or_insert(0) += 1;
            *e.by_harness
                .entry(harness_key(sp.agent_kind.as_deref()))
                .or_insert(0) += 1;
            if e.sample.is_none() {
                e.sample = Some(truncate(&sp.raw_redacted, 95));
            }
        }
    }
    for (dir, sc) in &state_scrapes {
        if sc.cnt >= 10 && sc.sess.len() >= 3 {
            let mut top_c: Vec<(String, usize)> =
                sc.cmd_map.iter().map(|(k, v)| (k.clone(), *v)).collect();
            top_c.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
            let top_list: Vec<String> = top_c
                .into_iter()
                .take(4)
                .map(|(k, v)| format!("{k} ({v}x)"))
                .collect();
            let mut ev = BTreeMap::new();
            ev.insert("direct_reads".into(), serde_json::json!(sc.cnt));
            ev.insert("sessions".into(), serde_json::json!(sc.sess.len()));
            ev.insert("stdout_tokens".into(), serde_json::json!(sc.toks));
            ev.insert("top_raw_cmds".into(), serde_json::json!(top_list));
            raw_opps.push(Opportunity {
                id: String::new(),
                scope: "repo".to_string(),
                kind: "state_dir_bypass".to_string(),
                fix_target: task_target.clone(),
                target: dir.clone(),
                score: (sc.cnt as i64) * 2400 + sc.toks,
                impact_summary: format!(
                    "{} direct shell reads of `{dir}` across {} sessions ({} stdout toks)",
                    sc.cnt,
                    sc.sess.len(),
                    format_compact(sc.toks)
                ),
                by_harness: sc.by_harness.clone(),
                harness_summary: format_harness_breakdown(&sc.by_harness),
                evidence: ev,
                trace_proof: sc.sample.iter().cloned().collect(),
                suggested_action: format!(
                    "Agents scrape raw state files under `{dir}` — inspect what diagnostic question isn't answered by existing CLI/tooling."
                ),
                acceptance_metric: format!("direct reads of `{dir}` drop by >= 75%"),
            });
        }
    }

    // L. Non-Shell & MCP Tool Friction (error clusters & heavy output truncation across all harnesses)
    {
        let mut tc_stmt = conn.prepare(
            "SELECT session_id, agent_kind, tool_name, is_mcp, is_error, output_bytes, is_truncated, error_preview
             FROM tool_calls
             WHERE repo_id = ?1
               AND started_at >= ?2 AND started_at < ?3
               AND session_id IN (
                   SELECT session_id FROM sessions
                   WHERE COALESCE(started_at, ended_at, 0) >= ?2
                     AND COALESCE(started_at, ended_at, 0) < ?3
               )",
        )?;
        struct TcAcc {
            is_mcp: bool,
            calls: usize,
            errors: usize,
            truncs: usize,
            bytes: i64,
            sessions: HashSet<String>,
            by_harness: BTreeMap<String, usize>,
            err_by_harness: BTreeMap<String, usize>,
            sample_err: Option<String>,
        }
        let mut tc_map: HashMap<String, TcAcc> = HashMap::new();
        let rows = tc_stmt.query_map(params![repo_id, since_ms, until_ms], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)? != 0,
                r.get::<_, i64>(4)? != 0,
                r.get::<_, i64>(5)?,
                r.get::<_, i64>(6)? != 0,
                r.get::<_, Option<String>>(7)?,
            ))
        })?;
        for row in rows.flatten() {
            let (sid, ag, name, is_mcp, is_err, bytes, is_trunc, err_prev) = row;
            let a = tc_map.entry(name).or_insert_with(|| TcAcc {
                is_mcp,
                calls: 0,
                errors: 0,
                truncs: 0,
                bytes: 0,
                sessions: HashSet::new(),
                by_harness: BTreeMap::new(),
                err_by_harness: BTreeMap::new(),
                sample_err: None,
            });
            a.calls += 1;
            a.sessions.insert(sid);
            a.bytes += bytes;
            *a.by_harness.entry(ag.clone()).or_insert(0) += 1;
            if is_err {
                a.errors += 1;
                *a.err_by_harness.entry(ag).or_insert(0) += 1;
                if a.sample_err.is_none() {
                    a.sample_err = err_prev;
                }
            }
            if is_trunc {
                a.truncs += 1;
            }
        }

        for (name, a) in tc_map {
            let err_rate = a.errors as f64 / a.calls.max(1) as f64;
            let avg_kb = round1((a.bytes as f64 / 1024.0) / a.calls.max(1) as f64);
            let is_builtin_reader = matches!(
                name.to_ascii_lowercase().as_str(),
                "read_file" | "read" | "view_file" | "grep_search" | "list_dir" | "find_by_name"
            );
            let high_err = a.errors >= 3 && err_rate >= 0.10;
            // Built-in chunked file readers (e.g. Antigravity read_file's 800-line pages) aren't broken tools
            // unless they actually error out or return oversized (>10 KB avg) payloads.
            let high_trunc = a.truncs >= 8
                && (a.truncs as f64 / a.calls.max(1) as f64) >= 0.10
                && (!is_builtin_reader || avg_kb >= 10.0);
            if !high_err && !high_trunc {
                continue;
            }
            let sc = if is_harness_tool(&name) {
                "harness"
            } else {
                "repo"
            };
            let h_counts = if high_err {
                &a.err_by_harness
            } else {
                &a.by_harness
            };
            let mut ev = BTreeMap::new();
            ev.insert("calls".into(), serde_json::json!(a.calls));
            ev.insert("sessions".into(), serde_json::json!(a.sessions.len()));
            ev.insert("errors".into(), serde_json::json!(a.errors));
            ev.insert("error_rate".into(), serde_json::json!(round3(err_rate)));
            ev.insert("truncated".into(), serde_json::json!(a.truncs));
            ev.insert("avg_output_kb".into(), serde_json::json!(avg_kb));
            let proof: Vec<String> = a
                .sample_err
                .as_deref()
                .map(clean_error_preview)
                .filter(|e| !e.is_empty())
                .map(|e| vec![format!("Sample error: `{}`", truncate(&e, 140))])
                .unwrap_or_default();
            let impact = if high_err && high_trunc {
                format!(
                    "{}/{} calls failed ({:.0}%) and {} truncated (avg {avg_kb:.1} KB) across {} sessions",
                    a.errors,
                    a.calls,
                    err_rate * 100.0,
                    a.truncs,
                    a.sessions.len()
                )
            } else if high_err {
                format!(
                    "{}/{} calls failed ({:.0}%) across {} sessions (avg {avg_kb:.1} KB)",
                    a.errors,
                    a.calls,
                    err_rate * 100.0,
                    a.sessions.len()
                )
            } else {
                format!(
                    "{}/{} tool outputs truncated ({:.0}%, avg {avg_kb:.1} KB) across {} sessions",
                    a.truncs,
                    a.calls,
                    (a.truncs as f64 / a.calls.max(1) as f64) * 100.0,
                    a.sessions.len()
                )
            };
            raw_opps.push(Opportunity {
                id: String::new(),
                scope: sc.to_string(),
                kind: "tool_friction".to_string(),
                fix_target: if sc == "harness" {
                    "Harness / MCP orchestrator".to_string()
                } else if a.is_mcp {
                    "Project MCP tool / integration".to_string()
                } else {
                    "Tool usage / repo structure".to_string()
                },
                target: name.clone(),
                score: (a.errors as i64) * 8000 + (a.truncs as i64) * 2500,
                impact_summary: impact,
                by_harness: h_counts.clone(),
                harness_summary: format_harness_breakdown(h_counts),
                evidence: ev,
                trace_proof: proof,
                suggested_action: format!(
                    "Inspect `{name}` failures/truncation — check tool schema clarity, payload bounds, or retry conditions."
                ),
                acceptance_metric: format!("error_rate on `{name}` < 5% and truncation < 5%"),
            });
        }
    }

    // M. Repeated File Re-Read Hotspots (all files, not just docs — surfaces bloated monoliths & context traps)
    {
        struct FileAcc {
            reads: usize,
            sessions: HashSet<String>,
            per_sess: HashMap<String, usize>,
            tokens: i64,
            by_harness: BTreeMap<String, usize>,
        }
        let mut by_file: HashMap<String, FileAcc> = HashMap::new();
        for r in &reads {
            let f = by_file
                .entry(r.target_name.clone())
                .or_insert_with(|| FileAcc {
                    reads: 0,
                    sessions: HashSet::new(),
                    per_sess: HashMap::new(),
                    tokens: 0,
                    by_harness: BTreeMap::new(),
                });
            f.reads += 1;
            f.sessions.insert(r.session_id.clone());
            *f.per_sess.entry(r.session_id.clone()).or_insert(0) += 1;
            f.tokens += r.output_tokens;
            let ag = session_agent.get(&r.session_id).map(String::as_str);
            *f.by_harness.entry(harness_key(ag)).or_insert(0) += 1;
        }
        let mut hot_files: Vec<(String, FileAcc)> = by_file
            .into_iter()
            .filter(|(_, f)| f.reads >= 8 && f.sessions.len() >= 4 && f.tokens >= 4000)
            .collect();
        hot_files.sort_by_key(|(_, f)| std::cmp::Reverse(f.tokens));
        for (fname, f) in hot_files.into_iter().take(4) {
            let max_in_sess = f.per_sess.values().copied().max().unwrap_or(1);
            let mut ev = BTreeMap::new();
            ev.insert("reads".into(), serde_json::json!(f.reads));
            ev.insert("sessions".into(), serde_json::json!(f.sessions.len()));
            ev.insert(
                "max_reads_in_session".into(),
                serde_json::json!(max_in_sess),
            );
            ev.insert("total_tokens".into(), serde_json::json!(f.tokens));
            let hs = format_harness_breakdown(&f.by_harness);
            let is_step_spill = fname == "steps/output.txt" || fname == "output.txt";
            let (scope, kind, fix_target, suggested_action, acceptance_metric) = if is_step_spill {
                (
                    "harness".to_string(),
                    "truncated_output_reread".to_string(),
                    "Verbose CLI/MCP outputs & harness truncation".to_string(),
                    format!(
                        "`{fname}` is the agent harness's truncated step-output spill file — add quiet/summary defaults and pagination to noisy CLI commands & MCP tools so outputs stop overflowing into `{fname}`."
                    ),
                    format!("truncated `{fname}` re-reads drop by >= 50%"),
                )
            } else {
                (
                    "repo".to_string(),
                    "repeated_file_reread".to_string(),
                    fname.clone(),
                    format!(
                        "`{fname}` is repeatedly re-read across sessions — inspect whether it is oversized, poorly indexed, or missing a compact summary/module split."
                    ),
                    format!("token spend reading `{fname}` drops by >= 50%"),
                )
            };
            raw_opps.push(Opportunity {
                id: String::new(),
                scope,
                kind,
                fix_target,
                target: fname.clone(),
                score: f.tokens * 2 + (f.reads as i64) * 1200,
                impact_summary: format!(
                    "read {}x across {} sessions (max {}x/session, {} tokens)",
                    f.reads,
                    f.sessions.len(),
                    max_in_sess,
                    format_compact(f.tokens)
                ),
                by_harness: f.by_harness,
                harness_summary: hs,
                evidence: ev,
                trace_proof: vec![format!(
                    "`{fname}` averaged ~{} tokens/read across {} sessions",
                    format_compact(f.tokens / f.reads.max(1) as i64),
                    f.sessions.len()
                )],
                suggested_action,
                acceptance_metric,
            });
        }
    }

    // N. Session-Level Context Handoff Bloat & Cache Efficiency Anomalies
    {
        let main_sess: Vec<&SessionRow> = sessions.iter().filter(|s| !s.is_subagent).collect();
        let handoff_s: Vec<&SessionRow> =
            main_sess.iter().copied().filter(|s| s.is_handoff).collect();
        let fresh_s: Vec<&SessionRow> = main_sess
            .iter()
            .copied()
            .filter(|s| !s.is_handoff)
            .collect();
        if handoff_s.len() >= 3 && fresh_s.len() >= 3 {
            let h_avg = handoff_s
                .iter()
                .map(|s| s.total_model_tokens())
                .sum::<i64>()
                / handoff_s.len() as i64;
            let f_avg =
                fresh_s.iter().map(|s| s.total_model_tokens()).sum::<i64>() / fresh_s.len() as i64;
            if f_avg > 0 && h_avg >= 500_000 && (h_avg as f64 / f_avg as f64) >= 2.0 {
                let mult = round1(h_avg as f64 / f_avg as f64);
                let mut h_by_ag: BTreeMap<String, usize> = BTreeMap::new();
                for s in &handoff_s {
                    *h_by_ag.entry(s.agent_kind.clone()).or_insert(0) += 1;
                }
                let hs = format_harness_breakdown(&h_by_ag);
                let mut ev = BTreeMap::new();
                ev.insert(
                    "handoff_sessions".into(),
                    serde_json::json!(handoff_s.len()),
                );
                ev.insert("fresh_sessions".into(), serde_json::json!(fresh_s.len()));
                ev.insert("handoff_avg_tokens".into(), serde_json::json!(h_avg));
                ev.insert("fresh_avg_tokens".into(), serde_json::json!(f_avg));
                ev.insert("multiplier".into(), serde_json::json!(mult));
                raw_opps.push(Opportunity {
                    id: String::new(),
                    scope: "harness".to_string(),
                    kind: "context_handoff_bloat".to_string(),
                    fix_target: "Session compaction / handoff strategy".to_string(),
                    target: "continued / handoff sessions".to_string(),
                    score: ((h_avg - f_avg).max(0) / 500) * handoff_s.len() as i64,
                    impact_summary: format!(
                        "{} handoff sessions avg {} model tokens vs {} fresh ({mult:.1}x)",
                        handoff_s.len(),
                        format_compact(h_avg),
                        format_compact(f_avg)
                    ),
                    by_harness: h_by_ag,
                    harness_summary: hs,
                    evidence: ev,
                    trace_proof: vec![format!(
                        "{} continued/handoff main sessions averaged {mult:.1}x tokens of {} fresh sessions",
                        handoff_s.len(),
                        fresh_s.len()
                    )],
                    suggested_action: "Investigate why continued/compacted threads burn multi-fold more tokens — consider cleaner handoff summaries or starting fresh threads per task.".to_string(),
                    acceptance_metric: "handoff_vs_fresh token multiplier < 1.5x".to_string(),
                });
            }
        }

        let mut cache_by_ag: BTreeMap<String, (usize, i64, i64)> = BTreeMap::new();
        for s in &main_sess {
            let e = cache_by_ag.entry(s.agent_kind.clone()).or_insert((0, 0, 0));
            e.0 += 1;
            e.1 += s.input_tokens + s.cache_write_tokens;
            e.2 += s.cached_tokens;
        }
        let best_rate = cache_by_ag
            .values()
            .filter(|(n, inc, cac)| *n >= 5 && inc + cac > 0)
            .map(|(_, inc, cac)| *cac as f64 / (*inc + *cac) as f64)
            .fold(0.0_f64, f64::max);
        for (ag, (n, uncached, cached)) in &cache_by_ag {
            if *n >= 5 && *uncached >= 500_000 && uncached + cached > 0 {
                let rate = *cached as f64 / (*uncached + *cached) as f64;
                if rate < 0.85 || (best_rate >= 0.90 && best_rate - rate >= 0.10) {
                    let mut m = BTreeMap::new();
                    m.insert(ag.clone(), *n);
                    let mut ev = BTreeMap::new();
                    ev.insert("sessions".into(), serde_json::json!(n));
                    ev.insert("weighted_cache_hit".into(), serde_json::json!(round3(rate)));
                    ev.insert("uncached_input_tokens".into(), serde_json::json!(uncached));
                    raw_opps.push(Opportunity {
                        id: String::new(),
                        scope: "harness".to_string(),
                        kind: "low_cache_efficiency".to_string(),
                        fix_target: format!("{ag} prompt prefix / caching"),
                        target: format!("{ag} cache hit rate"),
                        score: *uncached / 50,
                        impact_summary: format!(
                            "{ag} weighted cache hit is {:.1}% ({} uncached input toks across {n} main sessions)",
                            rate * 100.0,
                            format_compact(*uncached)
                        ),
                        by_harness: m.clone(),
                        harness_summary: format_harness_breakdown(&m),
                        evidence: ev,
                        trace_proof: vec![format!(
                            "Best peer harness cache hit: {:.1}% vs {ag}: {:.1}%",
                            best_rate * 100.0,
                            rate * 100.0
                        )],
                        suggested_action: format!(
                            "Investigate cache invalidation in {ag} sessions (dynamic system-prompt prefixes, tool list churn, or idle TTL gaps)."
                        ),
                        acceptance_metric: format!("{ag} weighted cache hit >= 90%"),
                    });
                }
            }
        }
    }

    // O. Cross-Harness Behavioral Divergence (same repo, >=2.5x gap in error/pipe/bypass rate per 1k cmds)
    {
        struct HStat {
            cmds: usize,
            errs: usize,
            cli_piped: usize,
            state_reads: usize,
        }
        let mut hstats: BTreeMap<String, HStat> = BTreeMap::new();
        for sp in &spans {
            let hk = harness_key(sp.agent_kind.as_deref());
            let h = hstats.entry(hk).or_insert(HStat {
                cmds: 0,
                errs: 0,
                cli_piped: 0,
                state_reads: 0,
            });
            h.cmds += 1;
            if sp.exit_code.is_some_and(|c| c != 0) {
                h.errs += 1;
            }
            if sp.is_repo_cli && sp.piped_filter.is_some() {
                h.cli_piped += 1;
            }
            if !sp.is_repo_cli && sp.state_dir_hint.is_some() {
                h.state_reads += 1;
            }
        }
        let eligible: Vec<(&String, &HStat)> =
            hstats.iter().filter(|(_, s)| s.cmds >= 100).collect();
        if eligible.len() >= 2 {
            type MetricCheck = (&'static str, fn(&HStat) -> usize);
            let checks: [MetricCheck; 3] = [
                ("CLI pipe-stripping", |s| s.cli_piped),
                ("command error rate", |s| s.errs),
                ("direct state-dir scraping", |s| s.state_reads),
            ];
            for (metric_name, getter) in checks {
                let mut rates: Vec<(&String, usize, f64)> = eligible
                    .iter()
                    .map(|(ag, st)| {
                        let cnt = getter(st);
                        (*ag, cnt, (cnt as f64 / st.cmds as f64) * 1000.0)
                    })
                    .collect();
                rates.sort_by(|a, b| b.2.total_cmp(&a.2));
                let top = rates[0];
                let low = rates[rates.len() - 1];
                let ratio = top.2 / low.2.max(0.5);
                if top.1 >= 20 && ratio >= 2.5 {
                    let mut m = BTreeMap::new();
                    for (ag, cnt, _) in &rates {
                        if *cnt > 0 {
                            m.insert((*ag).clone(), *cnt);
                        }
                    }
                    let rate_desc: Vec<String> = rates
                        .iter()
                        .map(|(ag, cnt, r)| format!("{ag}: {r:.1}/1k ({cnt})"))
                        .collect();
                    let mut ev = BTreeMap::new();
                    ev.insert("metric".into(), serde_json::json!(metric_name));
                    ev.insert("top_harness".into(), serde_json::json!(top.0));
                    ev.insert("low_harness".into(), serde_json::json!(low.0));
                    ev.insert("top_rate".into(), serde_json::json!(round1(top.2)));
                    ev.insert("low_rate".into(), serde_json::json!(round1(low.2)));
                    ev.insert("top_count".into(), serde_json::json!(top.1));
                    ev.insert("rate_ratio".into(), serde_json::json!(round1(ratio)));
                    ev.insert("rates_per_1k_cmds".into(), serde_json::json!(rate_desc));
                    let gap_phrase = if low.2 < 0.5 {
                        format!("vs {:.1}/1k in {}", low.2, low.0)
                    } else {
                        format!("vs {} at {:.1}/1k ({:.1}x gap)", low.0, low.2, ratio)
                    };
                    raw_opps.push(Opportunity {
                        id: String::new(),
                        scope: "harness".to_string(),
                        kind: "harness_divergence".to_string(),
                        fix_target: format!("{} prompt / tool ergonomics", top.0),
                        target: format!("{metric_name} ({} vs {})", top.0, low.0),
                        score: (top.1 as i64) * 600,
                        impact_summary: format!(
                            "{} triggers {metric_name} at {:.1}/1k cmds {gap_phrase}",
                            top.0, top.2
                        ),
                        by_harness: m.clone(),
                        harness_summary: format_harness_breakdown(&m),
                        evidence: ev,
                        trace_proof: vec![rate_desc.join(" | ")],
                        suggested_action: format!(
                            "Compare how {} vs {} handle {metric_name} — harness-specific instruction, shell environment, or output-handling difference.",
                            top.0, low.0
                        ),
                        acceptance_metric: format!("{metric_name} gap between harnesses < 1.5x"),
                    });
                }
            }
        }
    }

    let latency = summarize_latency(&sessions);
    let context_health = summarize_context_health(&sessions);
    let outcomes = summarize_outcomes(&sessions);

    // P. File Edit Churn / Rework Hotspots (files edited repeatedly across sessions)
    {
        let mut ed_stmt = conn.prepare(
            "SELECT session_id, agent_kind, target_path, is_error
             FROM tool_calls
             WHERE repo_id = ?1
               AND is_edit = 1
               AND target_path IS NOT NULL
               AND started_at >= ?2 AND started_at < ?3
               AND session_id IN (
                   SELECT session_id FROM sessions
                   WHERE COALESCE(started_at, ended_at, 0) >= ?2
                     AND COALESCE(started_at, ended_at, 0) < ?3
               )",
        )?;
        struct EditAcc {
            edits: usize,
            errors: usize,
            sessions: HashSet<String>,
            per_sess: HashMap<String, usize>,
            by_harness: BTreeMap<String, usize>,
        }
        let mut by_path: HashMap<String, EditAcc> = HashMap::new();
        let rows = ed_stmt.query_map(params![repo_id, since_ms, until_ms], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)? != 0,
            ))
        })?;
        for row in rows.flatten() {
            let (sid, ag, path, is_err) = row;
            let e = by_path.entry(path).or_insert_with(|| EditAcc {
                edits: 0,
                errors: 0,
                sessions: HashSet::new(),
                per_sess: HashMap::new(),
                by_harness: BTreeMap::new(),
            });
            e.edits += 1;
            if is_err {
                e.errors += 1;
            }
            e.sessions.insert(sid.clone());
            *e.per_sess.entry(sid).or_insert(0) += 1;
            *e.by_harness.entry(ag).or_insert(0) += 1;
        }
        let mut hot_edits: Vec<(String, EditAcc)> = by_path
            .into_iter()
            .filter(|(_, e)| {
                let max_s = e.per_sess.values().copied().max().unwrap_or(0);
                e.edits >= 6 && e.sessions.len() >= 2 && (max_s >= 3 || e.edits >= 10)
            })
            .collect();
        hot_edits.sort_by_key(|(_, e)| std::cmp::Reverse(e.edits));
        for (path, e) in hot_edits.into_iter().take(4) {
            let max_in_sess = e.per_sess.values().copied().max().unwrap_or(1);
            let mut ev = BTreeMap::new();
            ev.insert("edits".into(), serde_json::json!(e.edits));
            ev.insert("edit_errors".into(), serde_json::json!(e.errors));
            ev.insert("sessions".into(), serde_json::json!(e.sessions.len()));
            ev.insert(
                "max_edits_in_session".into(),
                serde_json::json!(max_in_sess),
            );
            let hs = format_harness_breakdown(&e.by_harness);
            raw_opps.push(Opportunity {
                id: String::new(),
                scope: "repo".to_string(),
                kind: "file_edit_churn".to_string(),
                fix_target: path.clone(),
                target: path.clone(),
                score: (e.edits as i64) * 2600 + (e.errors as i64) * 3500,
                impact_summary: format!(
                    "edited {}x across {} sessions (max {}x/session, {} edit errors)",
                    e.edits,
                    e.sessions.len(),
                    max_in_sess,
                    e.errors
                ),
                by_harness: e.by_harness,
                harness_summary: hs,
                evidence: ev,
                trace_proof: vec![format!(
                    "`{path}` required up to {max_in_sess} edits in a single session ({} total across {} sessions)",
                    e.edits,
                    e.sessions.len()
                )],
                suggested_action: format!(
                    "`{path}` sees heavy edit churn/rework — inspect whether it is a monolith, has fragile string-matching structure, or lacks modular boundaries/tests."
                ),
                acceptance_metric: format!("edits per session on `{path}` drop by >= 40%"),
            });
        }
    }

    // Q. Context Pressure & Compaction Overhead
    if context_health.compacted_sessions >= 3
        || (context_health.sessions_over_80_pct >= 3
            && context_health.avg_peak_context_pct.unwrap_or(0.0) >= 75.0)
    {
        let mut by_h: BTreeMap<String, usize> = BTreeMap::new();
        for s in &sessions {
            if s.compaction_count > 0 || s.peak_context_pct().is_some_and(|p| p >= 80.0) {
                *by_h.entry(s.agent_kind.clone()).or_insert(0) += 1;
            }
        }
        let hs = format_harness_breakdown(&by_h);
        let mut ev = BTreeMap::new();
        ev.insert(
            "total_compactions".into(),
            serde_json::json!(context_health.total_compactions),
        );
        ev.insert(
            "compacted_sessions".into(),
            serde_json::json!(context_health.compacted_sessions),
        );
        ev.insert(
            "sessions_over_80_pct".into(),
            serde_json::json!(context_health.sessions_over_80_pct),
        );
        if let Some(avg_p) = context_health.avg_peak_context_pct {
            ev.insert("avg_peak_context_pct".into(), serde_json::json!(avg_p));
        }
        raw_opps.push(Opportunity {
            id: String::new(),
            scope: "harness".to_string(),
            kind: "context_pressure".to_string(),
            fix_target: "Session scoping / context hygiene".to_string(),
            target: "context window pressure & compactions".to_string(),
            score: context_health.total_compactions * 6000
                + (context_health.sessions_over_80_pct as i64) * 4500,
            impact_summary: format!(
                "{} compaction(s) across {} sessions ({} sessions reached >=80% context window{})",
                context_health.total_compactions,
                context_health.compacted_sessions,
                context_health.sessions_over_80_pct,
                context_health
                    .avg_peak_context_pct
                    .map(|p| format!(", avg peak {p:.0}%"))
                    .unwrap_or_default()
            ),
            by_harness: by_h,
            harness_summary: hs,
            evidence: ev,
            trace_proof: vec![format!(
                "{} compacted sessions, {} sessions >=80% window out of {} analyzed",
                context_health.compacted_sessions,
                context_health.sessions_over_80_pct,
                sessions.len()
            )],
            suggested_action: "Break long multi-task threads earlier, reduce verbose tool/command outputs, or delegate exploratory searches to subagents to avoid repeated context compaction.".to_string(),
            acceptance_metric: "compacted_sessions rate < 10% and sessions >=80% window drop by >= 50%".to_string(),
        });
    }

    // R. High Session Abort / Interrupt Rate
    if outcomes.aborted_sessions >= 3 && outcomes.abort_rate >= 0.15 {
        let mut by_h: BTreeMap<String, usize> = BTreeMap::new();
        for s in &sessions {
            if s.outcome.as_deref() == Some("aborted") || s.aborted_turns > 0 {
                *by_h.entry(s.agent_kind.clone()).or_insert(0) += 1;
            }
        }
        let hs = format_harness_breakdown(&by_h);
        let mut ev = BTreeMap::new();
        ev.insert(
            "aborted_sessions".into(),
            serde_json::json!(outcomes.aborted_sessions),
        );
        ev.insert("abort_rate".into(), serde_json::json!(outcomes.abort_rate));
        ev.insert(
            "total_aborted_turns".into(),
            serde_json::json!(outcomes.total_aborted_turns),
        );
        ev.insert(
            "aborted_session_tokens".into(),
            serde_json::json!(outcomes.aborted_session_tokens),
        );
        raw_opps.push(Opportunity {
            id: String::new(),
            scope: "harness".to_string(),
            kind: "session_abort_rate".to_string(),
            fix_target: "Long-running tasks / harness responsiveness".to_string(),
            target: "aborted / interrupted sessions".to_string(),
            score: (outcomes.aborted_sessions as i64) * 7000
                + (outcomes.total_aborted_turns * 2500),
            impact_summary: format!(
                "{}/{} sessions aborted ({:.0}%, {} interrupted turns, {} tokens in aborted sessions)",
                outcomes.aborted_sessions,
                sessions.len(),
                outcomes.abort_rate * 100.0,
                outcomes.total_aborted_turns,
                format_compact(outcomes.aborted_session_tokens)
            ),
            by_harness: by_h,
            harness_summary: hs,
            evidence: ev,
            trace_proof: vec![format!(
                "{} sessions experienced user aborts/interrupts ({} total aborted turns)",
                outcomes.aborted_sessions, outcomes.total_aborted_turns
            )],
            suggested_action: "Inspect slow or runaway loops causing user interrupts — tighten test scopes, command timeouts, and early-turn validation.".to_string(),
            acceptance_metric: "session abort rate < 10%".to_string(),
        });
    }

    raw_opps.sort_by_key(|o| std::cmp::Reverse(o.score));
    let mut repo_opps: Vec<Opportunity> = Vec::new();
    let mut harness_opps: Vec<Opportunity> = Vec::new();
    for o in raw_opps {
        if o.scope == "harness" {
            harness_opps.push(o);
        } else {
            repo_opps.push(o);
        }
    }
    let opportunities: Vec<Opportunity> = repo_opps
        .into_iter()
        .take(max_opportunities)
        .enumerate()
        .map(|(i, mut o)| {
            o.id = format!("opp-{}", i + 1);
            o
        })
        .collect();
    let harness_overhead: Vec<Opportunity> = harness_opps
        .into_iter()
        .take(12)
        .enumerate()
        .map(|(i, mut o)| {
            o.id = format!("h-{}", i + 1);
            o
        })
        .collect();

    let mut top_commands: Vec<CommandStat> = by_tpl
        .into_values()
        .map(|g| {
            let hs = format_harness_breakdown(&g.by_harness);
            let dur_samples = if !g.unchained_durations_ms.is_empty() {
                &g.unchained_durations_ms
            } else {
                &g.durations_ms
            };
            CommandStat {
                cmd_template: g.cmd_template,
                category: g.category,
                is_repo_cli: g.is_repo_cli,
                runs: g.runs,
                error_count: g.errors,
                error_rate: round3(g.errors as f64 / g.runs.max(1) as f64),
                piped_count: g.piped_count,
                top_pipe_filter: mode_str(&g.pipe_filters),
                p50_stdout_tokens: percentile_i64(&g.stdout_toks, 50.0),
                total_stdout_tokens: g.total_stdout_tokens,
                effective_tokens: g.total_effective_tokens,
                p50_wait_s: round1(percentile_i64(dur_samples, 50.0) as f64 / 1000.0),
                p95_wait_s: if dur_samples.len() >= 5 {
                    Some(round1(percentile_i64(dur_samples, 95.0) as f64 / 1000.0))
                } else {
                    None
                },
                p99_wait_s: if dur_samples.len() >= 10 {
                    Some(round1(percentile_i64(dur_samples, 99.0) as f64 / 1000.0))
                } else {
                    None
                },
                total_wait_s: round1(g.total_duration_ms as f64 / 1000.0),
                dominant_noise: mode_str(&g.noises),
                by_harness: g.by_harness,
                harness_summary: hs,
            }
        })
        .collect();
    top_commands.sort_by(|a, b| {
        b.effective_tokens
            .cmp(&a.effective_tokens)
            .then_with(|| b.total_stdout_tokens.cmp(&a.total_stdout_tokens))
    });
    top_commands.truncate(15);

    Ok(RepoReport {
        repo_id: repo_id.to_string(),
        repo_name,
        window: range.label.clone(),
        generated_at: Utc::now().to_rfc3339(),
        kpis: RepoKpis {
            sessions_analyzed: sessions.len(),
            worktrees_seen: worktrees.len(),
            agents_seen,
            total_commands: spans.len(),
            total_stdout_tokens,
            total_effective_tokens,
            total_model_tokens: total_model_toks,
            total_cache_write_tokens: total_cache_write_toks,
            total_thinking_tokens: total_thinking_toks,
            median_tokens_per_session: percentile_i64(&sess_toks, 50.0),
            p95_tokens_per_session: percentile_i64(&sess_toks, 95.0),
            cache_hit_rate,
            median_tool_wait_s: round1(percentile_f64(&waits, 50.0)),
            total_tool_wait_s: round1(total_tool_wait_s),
            command_error_rate: if spans.is_empty() {
                0.0
            } else {
                round3(err_count as f64 / spans.len() as f64)
            },
            cli_adoption_rate: if cli_or_build.is_empty() {
                None
            } else {
                Some(round3(cli_used as f64 / cli_or_build.len() as f64))
            },
            escape_hatch_rebound_rate: if total_repo_cli_calls > 0 {
                round3(rebound_count as f64 / total_repo_cli_calls as f64)
            } else {
                0.0
            },
            orientation_tokens: orient_tokens,
            total_cost_usd: if cost_sessions > 0 {
                Some((sum_cost_usd * 100.0).round() / 100.0)
            } else {
                None
            },
            estimated_cost_usd: (est_cost_usd * 100.0).round() / 100.0,
            cost_sessions,
            latency,
            context_health,
            outcomes,
            detected_config: repo_ctx.config_files,
        },
        opportunities,
        harness_overhead,
        top_commands,
    })
}

pub fn inspect_finding(
    conn: &Connection,
    repo_id: &str,
    query: &str,
    range: &TimeRange,
    samples: usize,
) -> Result<InspectResult> {
    let report = analyze_repo(conn, repo_id, range, 20)?;
    let since_ms = range.since_ms;
    let until_ms = range.upper_bound();

    let opp = report
        .opportunities
        .iter()
        .chain(report.harness_overhead.iter())
        .find(|o| o.id.eq_ignore_ascii_case(query))
        .cloned();
    let target_match = opp
        .as_ref()
        .map(|o| {
            // For `from -> to` flag thrash targets, match the failing `from` side
            if o.kind == "flag_thrash"
                && let Some((lhs, _)) = o.target.split_once(" -> ")
            {
                return lhs.to_string();
            }
            o.target.clone()
        })
        .unwrap_or_else(|| query.to_string());
    let target_lower = target_match.to_ascii_lowercase();

    let mut stmt = conn.prepare(&format!(
        "SELECT {SPAN_SELECT_COLS}
         FROM command_spans
         WHERE repo_id = ?1
           AND started_at >= ?2 AND started_at < ?3
           AND (session_id IS NULL OR session_id IN (
               SELECT session_id FROM sessions
               WHERE COALESCE(started_at, ended_at, 0) >= ?2
                 AND COALESCE(started_at, ended_at, 0) < ?3
           ))
         ORDER BY session_id ASC, turn_idx ASC, seq_idx ASC"
    ))?;
    let spans: Vec<SpanRow> = dedup_wrap_spans(
        stmt.query_map(params![repo_id, since_ms, until_ms], map_span_row)?
            .flatten()
            .collect(),
    );

    let mut matched = Vec::new();

    // Handle non-shell tool_friction (MCP & built-in tools) directly from `tool_calls`
    if let Some(o) = &opp
        && o.kind == "tool_friction"
    {
        let mut tc_stmt = conn.prepare(
            "SELECT session_id, agent_kind, turn_idx, started_at, tool_name, is_error,
                    duration_ms, output_tokens, is_truncated, error_preview
             FROM tool_calls
             WHERE repo_id = ?1 AND tool_name = ?2
               AND started_at >= ?3 AND started_at < ?4
               AND (is_error != 0 OR is_truncated != 0)
             ORDER BY is_error DESC, output_bytes DESC",
        )?;
        let rows = tc_stmt.query_map(params![repo_id, o.target, since_ms, until_ms], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)? != 0,
                r.get::<_, Option<i64>>(6)?,
                r.get::<_, i64>(7)?,
                r.get::<_, i64>(8)? != 0,
                r.get::<_, Option<String>>(9)?,
            ))
        })?;
        for row in rows.flatten() {
            let (sid, ag, turn, ts, name, is_err, dur, toks, is_trunc, err_prev) = row;
            let dt = DateTime::from_timestamp_millis(ts)
                .map(|d| d.to_rfc3339())
                .unwrap_or_default();
            let clean_err = err_prev
                .as_deref()
                .map(clean_error_preview)
                .filter(|s| !s.is_empty());
            matched.push(TraceSample {
                session_id: sid,
                agent_kind: ag,
                turn_idx: turn,
                started_at: dt,
                cmd_template: name.clone(),
                raw_redacted: if is_err {
                    format!("tool call `{name}` (error)")
                } else {
                    format!("tool call `{name}` (truncated output)")
                },
                exit_code: Some(if is_err { 1 } else { 0 }),
                duration_ms: dur,
                stdout_tokens: toks,
                noise_kind: if is_trunc {
                    Some("truncated".into())
                } else {
                    None
                },
                stderr_preview: clean_err,
                next_cmd: None,
            });
        }
        let total = matched.len();
        matched.truncate(samples);
        return Ok(InspectResult {
            repo_id: repo_id.to_string(),
            repo_name: report.repo_name,
            query: query.to_string(),
            opportunity: opp,
            total_matching_spans: total,
            samples: matched,
        });
    }

    // Handle file_edit_churn directly from `tool_calls`
    if let Some(o) = &opp
        && o.kind == "file_edit_churn"
    {
        let mut ed_stmt = conn.prepare(
            "SELECT session_id, agent_kind, turn_idx, started_at, tool_name, is_error,
                    duration_ms, output_tokens, error_preview
             FROM tool_calls
             WHERE repo_id = ?1 AND is_edit = 1 AND target_path = ?2
               AND started_at >= ?3 AND started_at < ?4
             ORDER BY is_error DESC, started_at DESC",
        )?;
        let rows = ed_stmt.query_map(params![repo_id, o.target, since_ms, until_ms], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)? != 0,
                r.get::<_, Option<i64>>(6)?,
                r.get::<_, i64>(7)?,
                r.get::<_, Option<String>>(8)?,
            ))
        })?;
        for row in rows.flatten() {
            let (sid, ag, turn, ts, name, is_err, dur, toks, err_prev) = row;
            let dt = DateTime::from_timestamp_millis(ts)
                .map(|d| d.to_rfc3339())
                .unwrap_or_default();
            matched.push(TraceSample {
                session_id: sid,
                agent_kind: ag,
                turn_idx: turn,
                started_at: dt,
                cmd_template: format!("edit:{}", o.target),
                raw_redacted: format!("{name} {}", o.target),
                exit_code: Some(if is_err { 1 } else { 0 }),
                duration_ms: dur,
                stdout_tokens: toks,
                noise_kind: None,
                stderr_preview: err_prev
                    .as_deref()
                    .map(clean_error_preview)
                    .filter(|s| !s.is_empty()),
                next_cmd: None,
            });
        }
        let total = matched.len();
        matched.truncate(samples);
        return Ok(InspectResult {
            repo_id: repo_id.to_string(),
            repo_name: report.repo_name,
            query: query.to_string(),
            opportunity: opp,
            total_matching_spans: total,
            samples: matched,
        });
    }

    // Handle repeated_file_reread and truncated_output_reread directly from `file_reads`
    if let Some(o) = &opp
        && (o.kind == "repeated_file_reread" || o.kind == "truncated_output_reread")
    {
        let mut fr_stmt = conn.prepare(
            "SELECT fr.session_id, COALESCE(s.agent_kind, 'unknown'), fr.turn_idx, fr.started_at,
                    COALESCE(fr.target_path, fr.target_name), fr.output_tokens
             FROM file_reads fr
             LEFT JOIN sessions s ON s.session_id = fr.session_id
             WHERE fr.repo_id = ?1 AND (fr.target_path = ?2 OR fr.target_name = ?2)
               AND fr.started_at >= ?3 AND fr.started_at < ?4
             ORDER BY fr.output_tokens DESC",
        )?;
        let rows = fr_stmt.query_map(params![repo_id, o.target, since_ms, until_ms], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })?;
        for row in rows.flatten() {
            let (sid, ag, turn, ts, fname, toks) = row;
            let dt = DateTime::from_timestamp_millis(ts)
                .map(|d| d.to_rfc3339())
                .unwrap_or_default();
            matched.push(TraceSample {
                session_id: sid,
                agent_kind: ag,
                turn_idx: turn,
                started_at: dt,
                cmd_template: format!("read:{fname}"),
                raw_redacted: format!("read_file {fname}"),
                exit_code: Some(0),
                duration_ms: None,
                stdout_tokens: toks,
                noise_kind: None,
                stderr_preview: None,
                next_cmd: None,
            });
        }
        let total = matched.len();
        matched.truncate(samples);
        return Ok(InspectResult {
            repo_id: repo_id.to_string(),
            repo_name: report.repo_name,
            query: query.to_string(),
            opportunity: opp,
            total_matching_spans: total,
            samples: matched,
        });
    }

    // Handle session-level findings directly from `sessions`
    if let Some(o) = &opp
        && matches!(
            o.kind.as_str(),
            "context_handoff_bloat"
                | "low_cache_efficiency"
                | "context_pressure"
                | "session_abort_rate"
        )
    {
        let target_agent = if o.kind == "low_cache_efficiency" {
            o.target.split_whitespace().next().map(str::to_string)
        } else {
            None
        };
        let mut s_stmt = conn.prepare(&format!(
            "SELECT {SESSION_SELECT_COLS}
             FROM sessions
             WHERE repo_id = ?1
               AND COALESCE(started_at, ended_at, 0) >= ?2
               AND COALESCE(started_at, ended_at, 0) < ?3
             ORDER BY (input_tokens + cache_write_tokens + cached_tokens + output_tokens + thinking_tokens) DESC"
        ))?;
        let rows: Vec<SessionRow> = s_stmt
            .query_map(params![repo_id, since_ms, until_ms], map_session_row)?
            .flatten()
            .collect();
        for s in rows {
            if matches!(
                o.kind.as_str(),
                "context_handoff_bloat" | "low_cache_efficiency"
            ) && s.is_subagent
            {
                continue;
            }
            if o.kind == "context_handoff_bloat" && !s.is_handoff {
                continue;
            }
            if o.kind == "context_pressure"
                && s.compaction_count <= 0
                && !s.peak_context_pct().is_some_and(|p| p >= 80.0)
            {
                continue;
            }
            if o.kind == "session_abort_rate"
                && s.outcome.as_deref() != Some("aborted")
                && s.aborted_turns <= 0
            {
                continue;
            }
            if let Some(ref ta) = target_agent
                && s.agent_kind != *ta
            {
                continue;
            }
            let total_t = s.total_model_tokens();
            let cache_denom = s.input_tokens + s.cache_write_tokens + s.cached_tokens;
            let cache_pct = if cache_denom > 0 {
                (s.cached_tokens as f64 / cache_denom as f64) * 100.0
            } else {
                0.0
            };
            let dt = DateTime::from_timestamp_millis(s.started_at)
                .map(|d| d.to_rfc3339())
                .unwrap_or_default();
            matched.push(TraceSample {
                session_id: s.session_id.clone(),
                agent_kind: s.agent_kind.clone(),
                turn_idx: s.turn_count,
                started_at: dt,
                cmd_template: o.kind.clone(),
                raw_redacted: format!(
                    "session `{}` ({} turns, {} total toks, cache {:.1}%, compactions={}, aborts={})",
                    s.session_id,
                    s.turn_count,
                    format_compact(total_t),
                    cache_pct,
                    s.compaction_count,
                    s.aborted_turns
                ),
                exit_code: Some(if s.outcome.as_deref() == Some("aborted") {
                    1
                } else {
                    0
                }),
                duration_ms: if s.total_tool_ms > 0 {
                    Some(s.total_tool_ms)
                } else {
                    None
                },
                stdout_tokens: total_t,
                noise_kind: None,
                stderr_preview: None,
                next_cmd: None,
            });
        }
        let total = matched.len();
        matched.truncate(samples);
        return Ok(InspectResult {
            repo_id: repo_id.to_string(),
            repo_name: report.repo_name,
            query: query.to_string(),
            opportunity: opp,
            total_matching_spans: total,
            samples: matched,
        });
    }

    let div_metric = opp
        .as_ref()
        .filter(|o| o.kind == "harness_divergence")
        .and_then(|o| o.evidence.get("metric").and_then(|v| v.as_str()))
        .map(str::to_string);
    let div_top_ag = opp
        .as_ref()
        .filter(|o| o.kind == "harness_divergence")
        .and_then(|o| o.evidence.get("top_harness").and_then(|v| v.as_str()))
        .map(str::to_string);

    for i in 0..spans.len() {
        let sp = &spans[i];
        let next = spans.get(i + 1).filter(|nx| nx.session_id == sp.session_id);
        let hit = match opp.as_ref().map(|o| o.kind.as_str()) {
            Some("orientation_tax") => sp.is_orientation && sp.turn_idx <= 3,
            Some("state_dir_bypass") => {
                !sp.is_repo_cli && sp.state_dir_hint.as_deref() == Some(target_match.as_str())
            }
            Some("output_filtering_tax") => sp.is_repo_cli && sp.piped_filter.is_some(),
            Some("cli_help_tax") => sp.is_repo_cli && is_help_invocation(sp),
            Some("missing_composite_task") => next.is_some_and(|nx| {
                format!("{} -> {}", sp.cmd_template, nx.cmd_template) == target_match
            }),
            Some("harness_divergence") => {
                let ag_ok = div_top_ag
                    .as_deref()
                    .is_none_or(|ag| sp.agent_kind.as_deref() == Some(ag));
                ag_ok
                    && match div_metric.as_deref() {
                        Some("CLI pipe-stripping") => sp.is_repo_cli && sp.piped_filter.is_some(),
                        Some("command error rate") => sp.exit_code.is_some_and(|c| c != 0),
                        Some("direct state-dir scraping") => {
                            !sp.is_repo_cli && sp.state_dir_hint.is_some()
                        }
                        _ => false,
                    }
            }
            _ => {
                sp.cmd_template == target_match
                    || sp.cmd_bin == target_match
                    || sp.cmd_template.to_ascii_lowercase().contains(&target_lower)
            }
        };

        if hit {
            let dt = DateTime::from_timestamp_millis(sp.started_at)
                .map(|d| d.to_rfc3339())
                .unwrap_or_default();
            let clean_err = sp
                .stderr_preview
                .as_deref()
                .map(clean_error_preview)
                .filter(|s| !s.is_empty());
            matched.push(TraceSample {
                session_id: sp.session_id.clone().unwrap_or_default(),
                agent_kind: sp.agent_kind.clone().unwrap_or_else(|| "unknown".into()),
                turn_idx: sp.turn_idx,
                started_at: dt,
                cmd_template: sp.cmd_template.clone(),
                raw_redacted: sp.raw_redacted.clone(),
                exit_code: sp.exit_code,
                duration_ms: sp.duration_ms,
                stdout_tokens: sp.stdout_tokens,
                noise_kind: sp.noise_kind.clone(),
                stderr_preview: clean_err,
                next_cmd: next.map(|n| n.cmd_template.clone()),
            });
        }
    }

    matched.sort_by_key(|s| {
        std::cmp::Reverse(
            s.stdout_tokens
                + if s.exit_code.is_some_and(|c| c != 0) {
                    2000
                } else {
                    0
                },
        )
    });
    let total = matched.len();
    matched.truncate(samples);

    Ok(InspectResult {
        repo_id: repo_id.to_string(),
        repo_name: report.repo_name,
        query: query.to_string(),
        opportunity: opp,
        total_matching_spans: total,
        samples: matched,
    })
}

pub fn resolve_since_timestamp(since: &str, repo_cwd: &Path) -> Result<(i64, String)> {
    resolve_time_point_in_dirs(since, &[repo_cwd.to_path_buf()])
}

fn resolve_time_point_in_dirs(spec: &str, git_dirs: &[PathBuf]) -> Result<(i64, String)> {
    let trimmed = spec.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Ok((dt.timestamp_millis(), dt.to_rfc3339()));
    }
    if let Ok(d) = NaiveDate::parse_from_str(trimmed, "%Y-%m-%d")
        && let Some(dt) = d.and_hms_opt(0, 0, 0)
    {
        let utc = dt.and_utc();
        return Ok((
            utc.timestamp_millis(),
            utc.format("%Y-%m-%dT%H:%MZ").to_string(),
        ));
    }
    // Support relative durations like "24h", "7d", "2w"
    if !trimmed.eq_ignore_ascii_case("all")
        && trimmed.len() >= 2
        && trimmed[..trimmed.len() - 1]
            .chars()
            .all(|c| c.is_ascii_digit())
        && let Ok(Some(dur_ms)) = parse_window_ms(trimmed)
    {
        let ms = Utc::now().timestamp_millis() - dur_ms;
        let iso = DateTime::from_timestamp_millis(ms)
            .map(|d| d.format("%Y-%m-%dT%H:%MZ").to_string())
            .unwrap_or_default();
        return Ok((ms, format!("{trimmed} ago ({iso})")));
    }
    for dir in git_dirs {
        if !dir.exists() {
            continue;
        }
        if let Ok(out) = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["show", "-s", "--format=%ct|%h", trimmed])
            .output()
            && out.status.success()
        {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let (sec_str, short_sha) = s.split_once('|').unwrap_or((s.as_str(), trimmed));
            if let Ok(sec) = sec_str.parse::<i64>() {
                let ms = sec * 1000;
                let iso = DateTime::from_timestamp_millis(ms)
                    .map(|d| d.format("%Y-%m-%dT%H:%MZ").to_string())
                    .unwrap_or_default();
                let label = if short_sha == trimmed {
                    format!("{short_sha} ({iso})")
                } else {
                    format!("{trimmed}@{short_sha} ({iso})")
                };
                return Ok((ms, label));
            }
        }
    }
    bail!(
        "Could not parse \"{trimmed}\" as an ISO date (YYYY-MM-DD / RFC3339), relative duration (e.g. 48h, 7d), or git commit/ref."
    );
}

pub fn resolve_time_point(
    conn: &Connection,
    spec: &str,
    repo_id: Option<&str>,
    fallback_cwd: &Path,
) -> Result<(i64, String)> {
    let mut dirs = Vec::new();
    // Prefer fallback_cwd first if it belongs to this repo (so running from an active worktree uses its HEAD)
    if let Some(rid) = repo_id {
        let mut resolver = WorkspaceResolver::new(Some(conn));
        if let Some(ws) = resolver.resolve(&fallback_cwd.to_string_lossy())
            && ws.repo_id == rid
        {
            dirs.push(fallback_cwd.to_path_buf());
        }
        if let Ok(mut stmt) = conn.prepare(
            "SELECT worktree_path FROM workspaces WHERE repo_id = ?1 ORDER BY updated_at DESC",
        ) && let Ok(rows) = stmt.query_map(params![rid], |r| r.get::<_, String>(0))
        {
            for p in rows.flatten() {
                let pb = PathBuf::from(p);
                if !dirs.contains(&pb) {
                    dirs.push(pb);
                }
            }
        }
    }
    if !dirs.contains(&fallback_cwd.to_path_buf()) {
        dirs.push(fallback_cwd.to_path_buf());
    }
    resolve_time_point_in_dirs(spec, &dirs)
}

pub fn resolve_time_range(
    conn: &Connection,
    window: Option<&str>,
    since: Option<&str>,
    until: Option<&str>,
    repo_id: Option<&str>,
    fallback_cwd: &Path,
) -> Result<TimeRange> {
    let effective_window = match (window, since.is_some() || until.is_some()) {
        (Some(w), _) => w,
        (None, true) => "all",
        (None, false) => "14d",
    };

    let (since_ms, since_label) = if let Some(s) = since {
        let (ms, lbl) = resolve_time_point(conn, s, repo_id, fallback_cwd)?;
        (ms, Some(lbl))
    } else {
        let win_ms = parse_window_ms(effective_window)?;
        let ms = win_ms
            .map(|w| Utc::now().timestamp_millis() - w)
            .unwrap_or(0);
        (ms, None)
    };

    let (until_ms, until_label) = if let Some(u) = until {
        let (ms, lbl) = resolve_time_point(conn, u, repo_id, fallback_cwd)?;
        (Some(ms), Some(lbl))
    } else {
        (None, None)
    };

    if let Some(u) = until_ms
        && since_ms >= u
    {
        bail!("Invalid time range: --since resolves at or after --until.");
    }

    let label = match (since_label, until_label) {
        (Some(s), Some(u)) => format!("since {s} .. until {u}"),
        (Some(s), None) => format!("since {s}"),
        (None, Some(u)) if effective_window.eq_ignore_ascii_case("all") => {
            format!("until {u}")
        }
        (None, Some(u)) => format!("{effective_window} .. until {u}"),
        (None, None) => effective_window.to_string(),
    };

    Ok(TimeRange::bounded(since_ms, until_ms, label))
}

pub fn diff_repo(
    conn: &Connection,
    repo_id: &str,
    since_ms: i64,
    since_label: &str,
) -> Result<DiffReport> {
    let load_sessions_range = |lo: i64, hi: i64| -> Result<Vec<SessionRow>> {
        let mut stmt = conn.prepare(&format!(
            "SELECT {SESSION_SELECT_COLS}
             FROM sessions
             WHERE repo_id = ?1
               AND COALESCE(started_at, ended_at, 0) >= ?2
               AND COALESCE(started_at, ended_at, 0) < ?3"
        ))?;
        let rows = stmt
            .query_map(params![repo_id, lo, hi], map_session_row)?
            .flatten()
            .collect();
        Ok(rows)
    };

    let load_spans_range = |lo: i64, hi: i64| -> Result<Vec<SpanRow>> {
        let mut stmt = conn.prepare(&format!(
            "SELECT {SPAN_SELECT_COLS}
             FROM command_spans
             WHERE repo_id = ?1 AND started_at >= ?2 AND started_at < ?3
             ORDER BY session_id, turn_idx, seq_idx"
        ))?;
        let rows = dedup_wrap_spans(
            stmt.query_map(params![repo_id, lo, hi], map_span_row)?
                .flatten()
                .collect(),
        );
        Ok(rows)
    };

    let now_ms = Utc::now().timestamp_millis();
    let after_span_ms = (now_ms - since_ms).max(86_400_000);
    let matched_pre_lo = since_ms.saturating_sub(after_span_ms);

    let a_sess = load_sessions_range(since_ms, i64::MAX)?;
    let a_spans = load_spans_range(since_ms, i64::MAX)?;

    let matched_b_sess = load_sessions_range(matched_pre_lo, since_ms)?;
    let (b_sess, b_spans, matched_window) = if matched_b_sess.len() >= 3 {
        let matched_b_spans = load_spans_range(matched_pre_lo, since_ms)?;
        (matched_b_sess, matched_b_spans, true)
    } else {
        (
            load_sessions_range(0, since_ms)?,
            load_spans_range(0, since_ms)?,
            false,
        )
    };

    let repo_name = a_sess
        .first()
        .or(b_sess.first())
        .map(|s| s.repo_name.clone())
        .unwrap_or_else(|| repo_id.to_string());

    let summarize =
        |sess: &[SessionRow], sp: &[SpanRow]| -> (DiffBucket, HashMap<String, Vec<i64>>) {
            let toks: Vec<i64> = sess
                .iter()
                .map(SessionRow::uncached_billable_tokens)
                .filter(|&v| v > 0)
                .collect();
            let waits: Vec<f64> = sess
                .iter()
                .map(|s| s.total_tool_ms as f64 / 1000.0)
                .collect();
            let errs = sp
                .iter()
                .filter(|x| x.exit_code.is_some_and(|c| c != 0))
                .count();
            let total_out: i64 = sp.iter().map(|x| x.stdout_tokens).sum();
            let est_cost: f64 = sess.iter().map(SessionRow::effective_cost_usd).sum();
            let sum_in: i64 = sess
                .iter()
                .map(|s| s.input_tokens + s.cache_write_tokens)
                .sum();
            let sum_cached: i64 = sess.iter().map(|s| s.cached_tokens).sum();
            let cache_hit = if sum_in + sum_cached > 0 {
                Some(round3(sum_cached as f64 / (sum_in + sum_cached) as f64))
            } else {
                None
            };
            let api_sessions: Vec<f64> = sess
                .iter()
                .filter(|s| s.api_duration_ms > 0)
                .map(|s| s.api_duration_ms as f64 / 1000.0)
                .collect();
            let avg_api_wait = if api_sessions.is_empty() {
                None
            } else {
                Some(round1(
                    api_sessions.iter().sum::<f64>() / api_sessions.len() as f64,
                ))
            };
            let aborted = sess
                .iter()
                .filter(|s| s.outcome.as_deref() == Some("aborted") || s.aborted_turns > 0)
                .count();

            let mut cli_calls = 0usize;
            let mut rebounds = 0usize;
            let mut per_cmd: HashMap<String, Vec<i64>> = HashMap::new();
            for i in 0..sp.len() {
                per_cmd
                    .entry(sp[i].cmd_template.clone())
                    .or_default()
                    .push(sp[i].stdout_tokens);
                if sp[i].is_repo_cli && sp[i].session_id.is_some() {
                    cli_calls += 1;
                    if let Some(nx) = sp.get(i + 1)
                        && nx.session_id == sp[i].session_id
                        && !nx.is_repo_cli
                        && !is_normal_vcs_workflow_cmd(&nx.cmd_template)
                        && (nx.category == "exploration" || nx.category == "vcs_ci")
                        && nx.turn_idx - sp[i].turn_idx <= 1
                        && nx.started_at.saturating_sub(sp[i].started_at) <= 60_000
                    {
                        rebounds += 1;
                    }
                }
            }

            let bucket = DiffBucket {
                sessions: sess.len(),
                commands: sp.len(),
                median_session_tokens: percentile_i64(&toks, 50.0),
                median_tool_wait_s: round1(percentile_f64(&waits, 50.0)),
                avg_stdout_tokens_per_cmd: if sp.is_empty() {
                    0
                } else {
                    total_out / sp.len() as i64
                },
                error_rate: if sp.is_empty() {
                    0.0
                } else {
                    round3(errs as f64 / sp.len() as f64)
                },
                rebound_rate: if cli_calls > 0 {
                    round3(rebounds as f64 / cli_calls as f64)
                } else {
                    0.0
                },
                estimated_cost_usd: (est_cost * 100.0).round() / 100.0,
                cache_hit_rate: cache_hit,
                avg_api_wait_s: avg_api_wait,
                abort_rate: if sess.is_empty() {
                    0.0
                } else {
                    round3(aborted as f64 / sess.len() as f64)
                },
            };
            (bucket, per_cmd)
        };

    let (before, b_cmd) = summarize(&b_sess, &b_spans);
    let (after, a_cmd) = summarize(&a_sess, &a_spans);

    // Per-harness stratified deltas so harness-mix shifts are transparent
    let mut all_harnesses: HashSet<String> = HashSet::new();
    for s in b_sess.iter().chain(a_sess.iter()) {
        all_harnesses.insert(s.agent_kind.clone());
    }
    let mut harness_list: Vec<String> = all_harnesses.into_iter().collect();
    harness_list.sort();
    let mut by_harness = Vec::new();
    let mut max_mix_shift_pp: f64 = 0.0;
    let mut shift_desc = String::new();
    for ag in harness_list {
        let bs: Vec<SessionRow> = b_sess
            .iter()
            .filter(|s| s.agent_kind == ag)
            .cloned()
            .collect();
        let as_: Vec<SessionRow> = a_sess
            .iter()
            .filter(|s| s.agent_kind == ag)
            .cloned()
            .collect();
        let bsp: Vec<SpanRow> = b_spans
            .iter()
            .filter(|sp| sp.agent_kind.as_deref() == Some(ag.as_str()))
            .cloned()
            .collect();
        let asp: Vec<SpanRow> = a_spans
            .iter()
            .filter(|sp| sp.agent_kind.as_deref() == Some(ag.as_str()))
            .cloned()
            .collect();
        if before.commands >= 10 && after.commands >= 10 {
            let b_share = (bsp.len() as f64 / before.commands as f64) * 100.0;
            let a_share = (asp.len() as f64 / after.commands as f64) * 100.0;
            let diff_pp = (a_share - b_share).abs();
            if diff_pp > max_mix_shift_pp {
                max_mix_shift_pp = diff_pp;
                shift_desc = format!("{ag} command share {b_share:.0}% -> {a_share:.0}%");
            }
        }
        let (bb, _) = summarize(&bs, &bsp);
        let (ab, _) = summarize(&as_, &asp);
        by_harness.push(HarnessDiffDelta {
            agent_kind: ag,
            before_sessions: bb.sessions,
            after_sessions: ab.sessions,
            before_commands: bb.commands,
            after_commands: ab.commands,
            before_median_tokens: bb.median_session_tokens,
            after_median_tokens: ab.median_session_tokens,
            before_avg_stdout_tokens: bb.avg_stdout_tokens_per_cmd,
            after_avg_stdout_tokens: ab.avg_stdout_tokens_per_cmd,
            before_error_rate: bb.error_rate,
            after_error_rate: ab.error_rate,
        });
    }

    let pct_f = |a: f64, b: f64| -> Option<f64> {
        if a > 0.0 {
            Some(round1(((b - a) / a) * 100.0))
        } else {
            None
        }
    };

    let mut cmd_deltas = Vec::new();
    for (tpl, a_vals) in &a_cmd {
        if let Some(b_vals) = b_cmd.get(tpl)
            && b_vals.len() >= 2
            && a_vals.len() >= 2
        {
            let b_med = percentile_i64(b_vals, 50.0);
            let a_med = percentile_i64(a_vals, 50.0);
            if (a_med - b_med).abs() >= 100 {
                cmd_deltas.push(CommandDelta {
                    cmd_template: tpl.clone(),
                    before_p50_tokens: b_med,
                    after_p50_tokens: a_med,
                    delta_pct: pct_f(b_med as f64, a_med as f64),
                });
            }
        }
    }
    cmd_deltas.sort_by(|a, b| {
        a.delta_pct
            .unwrap_or(0.0)
            .total_cmp(&b.delta_pct.unwrap_or(0.0))
    });
    cmd_deltas.truncate(8);

    let mut guardrails = Vec::new();
    let mut has_regression_warning = false;
    if after.rebound_rate > before.rebound_rate + 0.05 {
        has_regression_warning = true;
        guardrails.push(format!(
            "WARNING: Escape-hatch rebound rate rose ({:.1}% -> {:.1}%) — check for over-truncated outputs.",
            before.rebound_rate * 100.0,
            after.rebound_rate * 100.0
        ));
    }
    if after.error_rate > before.error_rate + 0.05 {
        has_regression_warning = true;
        guardrails.push(format!(
            "WARNING: Command error rate rose ({:.1}% -> {:.1}%).",
            before.error_rate * 100.0,
            after.error_rate * 100.0
        ));
    }
    if max_mix_shift_pp >= 20.0 {
        guardrails.push(format!(
            "NOTE: Harness mix shifted ({shift_desc}) — check per-harness deltas below to avoid Simpson's paradox."
        ));
    }
    if !matched_window && before.sessions > 0 {
        guardrails.push(
            "NOTE: Matched pre-window had <3 sessions; fell back to all historical sessions before the split."
                .to_string(),
        );
    }
    if before.sessions < 5 || after.sessions < 5 || before.commands < 15 || after.commands < 15 {
        guardrails.push(format!(
            "NOTE: Low sample size (before: {} sess/{} cmds, after: {} sess/{} cmds) — treat deltas as directional.",
            before.sessions, before.commands, after.sessions, after.commands
        ));
    }

    let verdict = if before.commands < 3 || after.commands < 3 {
        "insufficient_data"
    } else if has_regression_warning {
        "mixed_guardrail_warning"
    } else if after.avg_stdout_tokens_per_cmd < before.avg_stdout_tokens_per_cmd
        && after.median_tool_wait_s <= before.median_tool_wait_s
    {
        "improved"
    } else if after.avg_stdout_tokens_per_cmd < before.avg_stdout_tokens_per_cmd
        || after.median_tool_wait_s < before.median_tool_wait_s
    {
        "mixed"
    } else {
        "regressed"
    };

    Ok(DiffReport {
        repo_id: repo_id.to_string(),
        repo_name,
        since: since_label.to_string(),
        matched_window,
        verdict: verdict.to_string(),
        deltas: DiffDeltas {
            median_session_tokens_pct: pct_f(
                before.median_session_tokens as f64,
                after.median_session_tokens as f64,
            ),
            median_tool_wait_pct: pct_f(before.median_tool_wait_s, after.median_tool_wait_s),
            avg_stdout_tokens_per_cmd_pct: pct_f(
                before.avg_stdout_tokens_per_cmd as f64,
                after.avg_stdout_tokens_per_cmd as f64,
            ),
        },
        before,
        after,
        by_harness,
        guardrails,
        command_deltas: cmd_deltas,
    })
}

pub fn query_commands(
    conn: &Connection,
    repo_id: &str,
    range: &TimeRange,
    sort_by: &str,
    category_filter: Option<&str>,
    limit: usize,
) -> Result<Vec<CommandStat>> {
    let since_ms = range.since_ms;
    let until_ms = range.upper_bound();

    let mut s_stmt = conn.prepare(
        "SELECT session_id, turn_count FROM sessions
         WHERE repo_id = ?1
           AND COALESCE(started_at, ended_at, 0) >= ?2
           AND COALESCE(started_at, ended_at, 0) < ?3",
    )?;
    let mut sess_turns: HashMap<String, i64> = s_stmt
        .query_map(params![repo_id, since_ms, until_ms], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?
        .flatten()
        .collect();

    let mut sp_stmt = conn.prepare(
        "SELECT session_id, agent_kind, turn_idx, category, is_repo_cli, cmd_template, exit_code, duration_ms,
                stdout_tokens, noise_kind, piped_filter, is_chained
         FROM command_spans
         WHERE repo_id = ?1
           AND started_at >= ?2 AND started_at < ?3
           AND (session_id IS NULL OR session_id IN (
               SELECT session_id FROM sessions
               WHERE COALESCE(started_at, ended_at, 0) >= ?2
                 AND COALESCE(started_at, ended_at, 0) < ?3
           ))",
    )?;
    struct Acc {
        category: String,
        is_repo_cli: bool,
        runs: usize,
        errors: usize,
        piped: usize,
        by_harness: BTreeMap<String, usize>,
        pipes: Vec<String>,
        toks: Vec<i64>,
        durs: Vec<i64>,
        unchained_durs: Vec<i64>,
        sum_toks: i64,
        sum_eff: i64,
        sum_dur: i64,
        noises: Vec<String>,
    }
    let mut by_tpl: HashMap<String, Acc> = HashMap::new();
    let rows = sp_stmt.query_map(params![repo_id, since_ms, until_ms], |r| {
        Ok((
            r.get::<_, Option<String>>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, i64>(4)? != 0,
            r.get::<_, String>(5)?,
            r.get::<_, Option<i64>>(6)?,
            r.get::<_, Option<i64>>(7)?,
            r.get::<_, i64>(8)?,
            r.get::<_, Option<String>>(9)?,
            r.get::<_, Option<String>>(10)?,
            r.get::<_, i64>(11)? != 0,
        ))
    })?;

    for row in rows.flatten() {
        let (sid, ag, turn_idx, cat, is_cli, tpl, ec, dur, toks, noise, pf, is_chained) = row;
        if let Some(cf) = category_filter
            && !cat.eq_ignore_ascii_case(cf)
        {
            continue;
        }
        let total_t = sid
            .as_deref()
            .map(|id| *sess_turns.entry(id.to_string()).or_insert(turn_idx.max(1)))
            .unwrap_or(turn_idx.max(1));
        let eff = effective_context_tokens(toks, turn_idx, total_t);
        let e = by_tpl.entry(tpl).or_insert_with(|| Acc {
            category: cat,
            is_repo_cli: is_cli,
            runs: 0,
            errors: 0,
            piped: 0,
            by_harness: BTreeMap::new(),
            pipes: Vec::new(),
            toks: Vec::new(),
            durs: Vec::new(),
            unchained_durs: Vec::new(),
            sum_toks: 0,
            sum_eff: 0,
            sum_dur: 0,
            noises: Vec::new(),
        });
        e.runs += 1;
        *e.by_harness.entry(harness_key(ag.as_deref())).or_insert(0) += 1;
        if ec.is_some_and(|c| c != 0) {
            e.errors += 1;
        }
        if let Some(p) = pf {
            e.piped += 1;
            e.pipes.push(p);
        }
        e.toks.push(toks);
        e.sum_toks += toks;
        e.sum_eff += eff;
        if let Some(d) = dur {
            e.durs.push(d);
            if !is_chained {
                e.unchained_durs.push(d);
            }
            e.sum_dur += d;
        }
        if let Some(n) = noise {
            e.noises.push(n);
        }
    }

    let mut out: Vec<CommandStat> = by_tpl
        .into_iter()
        .map(|(tpl, g)| {
            let hs = format_harness_breakdown(&g.by_harness);
            let dur_samples = if !g.unchained_durs.is_empty() {
                &g.unchained_durs
            } else {
                &g.durs
            };
            CommandStat {
                cmd_template: tpl,
                category: g.category,
                is_repo_cli: g.is_repo_cli,
                runs: g.runs,
                error_count: g.errors,
                error_rate: round3(g.errors as f64 / g.runs.max(1) as f64),
                piped_count: g.piped,
                top_pipe_filter: mode_str(&g.pipes),
                p50_stdout_tokens: percentile_i64(&g.toks, 50.0),
                total_stdout_tokens: g.sum_toks,
                effective_tokens: g.sum_eff,
                p50_wait_s: round1(percentile_i64(dur_samples, 50.0) as f64 / 1000.0),
                p95_wait_s: if dur_samples.len() >= 5 {
                    Some(round1(percentile_i64(dur_samples, 95.0) as f64 / 1000.0))
                } else {
                    None
                },
                p99_wait_s: if dur_samples.len() >= 10 {
                    Some(round1(percentile_i64(dur_samples, 99.0) as f64 / 1000.0))
                } else {
                    None
                },
                total_wait_s: round1(g.sum_dur as f64 / 1000.0),
                dominant_noise: mode_str(&g.noises),
                by_harness: g.by_harness,
                harness_summary: hs,
            }
        })
        .collect();

    match sort_by {
        "tokens" => out.sort_by_key(|c| std::cmp::Reverse(c.total_stdout_tokens)),
        "wait" => out.sort_by(|a, b| b.total_wait_s.total_cmp(&a.total_wait_s)),
        "runs" => out.sort_by_key(|c| std::cmp::Reverse(c.runs)),
        "errors" => out.sort_by(|a, b| {
            b.error_count
                .cmp(&a.error_count)
                .then_with(|| b.error_rate.total_cmp(&a.error_rate))
        }),
        "pipes" => out.sort_by_key(|c| std::cmp::Reverse(c.piped_count)),
        _ => out.sort_by_key(|c| std::cmp::Reverse(c.effective_tokens)),
    }
    out.truncate(limit);
    Ok(out)
}

pub fn query_errors(
    conn: &Connection,
    repo_id: &str,
    range: &TimeRange,
    limit: usize,
) -> Result<Vec<ErrorCluster>> {
    let since_ms = range.since_ms;
    let until_ms = range.upper_bound();

    let mut total_stmt = conn.prepare(
        "SELECT cmd_template, COUNT(*) FROM command_spans
         WHERE repo_id = ?1 AND started_at >= ?2 AND started_at < ?3
           AND (session_id IS NULL OR session_id IN (
               SELECT session_id FROM sessions
               WHERE COALESCE(started_at, ended_at, 0) >= ?2
                 AND COALESCE(started_at, ended_at, 0) < ?3
           ))
         GROUP BY cmd_template",
    )?;
    let totals: HashMap<String, usize> = total_stmt
        .query_map(params![repo_id, since_ms, until_ms], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as usize))
        })?
        .flatten()
        .collect();

    let mut stmt = conn.prepare(
        "SELECT session_id, agent_kind, category, cmd_template, raw_redacted, exit_code, COALESCE(stderr_preview, '')
         FROM command_spans
         WHERE repo_id = ?1
           AND started_at >= ?2 AND started_at < ?3
           AND exit_code IS NOT NULL AND exit_code != 0
           AND (session_id IS NULL OR session_id IN (
               SELECT session_id FROM sessions
               WHERE COALESCE(started_at, ended_at, 0) >= ?2
                 AND COALESCE(started_at, ended_at, 0) < ?3
           ))",
    )?;
    struct ErrAcc {
        category: String,
        count: usize,
        sessions: HashSet<String>,
        by_harness: BTreeMap<String, usize>,
        codes: HashSet<i64>,
        sample_cmd: String,
        stderr: String,
    }
    let mut by_tpl: HashMap<String, ErrAcc> = HashMap::new();
    let rows = stmt.query_map(params![repo_id, since_ms, until_ms], |r| {
        Ok((
            r.get::<_, Option<String>>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, i64>(5)?,
            r.get::<_, String>(6)?,
        ))
    })?;
    for row in rows.flatten() {
        let (sid, ag, cat, tpl, raw, code, err) = row;
        let e = by_tpl.entry(tpl).or_insert_with(|| ErrAcc {
            category: cat,
            count: 0,
            sessions: HashSet::new(),
            by_harness: BTreeMap::new(),
            codes: HashSet::new(),
            sample_cmd: truncate(&raw, 120),
            stderr: truncate(&err, 180),
        });
        e.count += 1;
        if let Some(s) = sid {
            e.sessions.insert(s);
        }
        *e.by_harness.entry(harness_key(ag.as_deref())).or_insert(0) += 1;
        e.codes.insert(code);
        if e.stderr.is_empty() && !err.is_empty() {
            e.stderr = truncate(&err, 180);
        }
    }

    let mut out: Vec<ErrorCluster> = by_tpl
        .into_iter()
        .map(|(tpl, e)| {
            let total_runs = *totals.get(&tpl).unwrap_or(&e.count);
            let mut codes: Vec<i64> = e.codes.into_iter().collect();
            codes.sort_unstable();
            let hs = format_harness_breakdown(&e.by_harness);
            ErrorCluster {
                cmd_template: tpl,
                category: e.category,
                error_count: e.count,
                total_runs,
                error_rate: round3(e.count as f64 / total_runs.max(1) as f64),
                sessions: e.sessions.len(),
                exit_codes: codes,
                by_harness: e.by_harness,
                harness_summary: hs,
                sample_cmd: e.sample_cmd,
                stderr_preview: e.stderr,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        b.error_count
            .cmp(&a.error_count)
            .then_with(|| b.error_rate.total_cmp(&a.error_rate))
    });
    out.truncate(limit);
    Ok(out)
}

pub fn query_bypasses(conn: &Connection, repo_id: &str, range: &TimeRange) -> Result<BypassReport> {
    let since_ms = range.since_ms;
    let until_ms = range.upper_bound();

    let repo_name: String = conn
        .query_row(
            "SELECT COALESCE(repo_name, repo_id) FROM sessions WHERE repo_id = ?1 LIMIT 1",
            params![repo_id],
            |r| r.get(0),
        )
        .unwrap_or_else(|_| repo_id.to_string());

    let mut stmt = conn.prepare(
        "SELECT session_id, agent_kind, category, is_repo_cli, cmd_template, raw_redacted, exit_code,
                duration_ms, stdout_tokens, piped_filter, state_dir_hint
         FROM command_spans
         WHERE repo_id = ?1
           AND started_at >= ?2 AND started_at < ?3
           AND (session_id IS NULL OR session_id IN (
               SELECT session_id FROM sessions
               WHERE COALESCE(started_at, ended_at, 0) >= ?2
                 AND COALESCE(started_at, ended_at, 0) < ?3
           ))",
    )?;

    struct StateAcc {
        calls: usize,
        sessions: HashSet<String>,
        tokens: i64,
        wait_ms: i64,
        by_harness: BTreeMap<String, usize>,
        cmds: HashMap<String, usize>,
        sample: String,
    }
    struct HelpAcc {
        calls: usize,
        sessions: HashSet<String>,
        broken: usize,
        tokens: i64,
        by_harness: BTreeMap<String, usize>,
    }
    struct PipeAcc {
        piped: usize,
        total: usize,
        by_harness: BTreeMap<String, usize>,
        filters: HashMap<String, usize>,
    }

    let mut state_map: HashMap<String, StateAcc> = HashMap::new();
    let mut help_map: HashMap<String, HelpAcc> = HashMap::new();
    let mut pipe_map: HashMap<String, PipeAcc> = HashMap::new();

    let rows = stmt.query_map(params![repo_id, since_ms, until_ms], |r| {
        Ok((
            r.get::<_, Option<String>>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, i64>(3)? != 0,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, Option<i64>>(6)?,
            r.get::<_, Option<i64>>(7)?,
            r.get::<_, i64>(8)?,
            r.get::<_, Option<String>>(9)?,
            r.get::<_, Option<String>>(10)?,
        ))
    })?;

    for row in rows.flatten() {
        let (sid, ag, _cat, is_cli, tpl, raw, ec, dur, toks, pf, sdir) = row;
        let hkey = harness_key(ag.as_deref());

        if !is_cli && let Some(dir) = sdir {
            let e = state_map.entry(dir).or_insert_with(|| StateAcc {
                calls: 0,
                sessions: HashSet::new(),
                tokens: 0,
                wait_ms: 0,
                by_harness: BTreeMap::new(),
                cmds: HashMap::new(),
                sample: truncate(&raw, 110),
            });
            e.calls += 1;
            if let Some(s) = &sid {
                e.sessions.insert(s.clone());
            }
            e.tokens += toks;
            e.wait_ms += dur.unwrap_or(0);
            *e.by_harness.entry(hkey.clone()).or_insert(0) += 1;
            *e.cmds.entry(tpl.clone()).or_insert(0) += 1;
        }

        if is_cli {
            let p = pipe_map.entry(tpl.clone()).or_insert_with(|| PipeAcc {
                piped: 0,
                total: 0,
                by_harness: BTreeMap::new(),
                filters: HashMap::new(),
            });
            p.total += 1;
            if let Some(f) = pf {
                p.piped += 1;
                *p.by_harness.entry(hkey.clone()).or_insert(0) += 1;
                *p.filters.entry(f).or_insert(0) += 1;
            }

            if tpl.contains("--help")
                || tpl.contains(" -h")
                || tpl.ends_with(" help")
                || raw.contains(" --help")
                || raw.contains(" -- help")
            {
                let h = help_map.entry(tpl.clone()).or_insert_with(|| HelpAcc {
                    calls: 0,
                    sessions: HashSet::new(),
                    broken: 0,
                    tokens: 0,
                    by_harness: BTreeMap::new(),
                });
                h.calls += 1;
                if let Some(s) = &sid {
                    h.sessions.insert(s.clone());
                }
                if ec.is_some_and(|c| c != 0) {
                    h.broken += 1;
                }
                h.tokens += toks;
                *h.by_harness.entry(hkey).or_insert(0) += 1;
            }
        }
    }

    let mut state_dir_scrapes: Vec<StateDirScrape> = state_map
        .into_iter()
        .filter(|(_, a)| a.calls >= 3)
        .map(|(dir, a)| {
            let mut cs: Vec<(String, usize)> = a.cmds.into_iter().collect();
            cs.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
            let hs = format_harness_breakdown(&a.by_harness);
            StateDirScrape {
                state_dir: dir,
                calls: a.calls,
                sessions: a.sessions.len(),
                stdout_tokens: a.tokens,
                total_wait_s: round1(a.wait_ms as f64 / 1000.0),
                by_harness: a.by_harness,
                harness_summary: hs,
                top_cmds: cs
                    .into_iter()
                    .take(4)
                    .map(|(k, v)| format!("{k} ({v}x)"))
                    .collect(),
                sample_cmd: a.sample,
            }
        })
        .collect();
    state_dir_scrapes.sort_by_key(|s| std::cmp::Reverse(s.calls));
    state_dir_scrapes.truncate(12);

    let mut pipe_stripping: Vec<PipeStripStat> = pipe_map
        .into_iter()
        .filter(|(_, a)| a.piped >= 3)
        .map(|(tpl, a)| {
            let mut fs: Vec<(String, usize)> = a.filters.into_iter().collect();
            fs.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
            let hs = format_harness_breakdown(&a.by_harness);
            PipeStripStat {
                cmd_template: tpl,
                piped_calls: a.piped,
                total_runs: a.total,
                pipe_rate: round3(a.piped as f64 / a.total.max(1) as f64),
                by_harness: a.by_harness,
                harness_summary: hs,
                top_filters: fs
                    .into_iter()
                    .take(3)
                    .map(|(k, v)| format!("| {k} ({v}x)"))
                    .collect(),
            }
        })
        .collect();
    pipe_stripping.sort_by_key(|p| std::cmp::Reverse(p.piped_calls));
    pipe_stripping.truncate(15);

    let mut help_lookups: Vec<HelpUsage> = help_map
        .into_iter()
        .map(|(tpl, a)| {
            let hs = format_harness_breakdown(&a.by_harness);
            HelpUsage {
                cmd_template: tpl,
                calls: a.calls,
                sessions: a.sessions.len(),
                broken_calls: a.broken,
                stdout_tokens: a.tokens,
                by_harness: a.by_harness,
                harness_summary: hs,
            }
        })
        .collect();
    help_lookups.sort_by_key(|h| std::cmp::Reverse(h.calls + h.broken_calls * 5));
    help_lookups.truncate(15);

    // Grouped raw tool bypass families (e.g. `cargo` -> fmt/test/build, `ssh` -> docker/sqlite3/journalctl, `gh`, `sleep`, `xcrun`)
    let mut fam_stmt = conn.prepare(
        "SELECT session_id, agent_kind, category, is_repo_cli, cmd_bin, cmd_template, exit_code, duration_ms, stdout_tokens
         FROM command_spans
         WHERE repo_id = ?1
           AND started_at >= ?2 AND started_at < ?3
           AND is_repo_cli = 0
           AND (session_id IS NULL OR session_id IN (
               SELECT session_id FROM sessions
               WHERE COALESCE(started_at, ended_at, 0) >= ?2
                 AND COALESCE(started_at, ended_at, 0) < ?3
           ))",
    )?;
    struct FamAcc {
        cat: String,
        runs: usize,
        sessions: HashSet<String>,
        errs: usize,
        toks: i64,
        wait_ms: i64,
        by_harness: BTreeMap<String, usize>,
        tpls: HashMap<String, usize>,
    }
    let mut fam_map: HashMap<String, FamAcc> = HashMap::new();
    let fam_rows = fam_stmt.query_map(params![repo_id, since_ms, until_ms], |r| {
        Ok((
            r.get::<_, Option<String>>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, Option<i64>>(6)?,
            r.get::<_, Option<i64>>(7)?,
            r.get::<_, i64>(8)?,
        ))
    })?;
    for row in fam_rows.flatten() {
        let (sid, ag, cat, bin, tpl, ec, dur, toks) = row;
        if cat == "exploration" || is_generic_git_read(&tpl) || is_generic_interpreter(&tpl) {
            continue;
        }
        if matches!(
            bin.as_str(),
            "git" | "mkdir" | "rm" | "mv" | "cp" | "chmod" | "touch" | "ln"
        ) {
            continue;
        }
        let f = fam_map.entry(bin).or_insert_with(|| FamAcc {
            cat,
            runs: 0,
            sessions: HashSet::new(),
            errs: 0,
            toks: 0,
            wait_ms: 0,
            by_harness: BTreeMap::new(),
            tpls: HashMap::new(),
        });
        f.runs += 1;
        if let Some(s) = sid {
            f.sessions.insert(s);
        }
        if ec.is_some_and(|c| c != 0) {
            f.errs += 1;
        }
        f.toks += toks;
        f.wait_ms += dur.unwrap_or(0);
        *f.by_harness.entry(harness_key(ag.as_deref())).or_insert(0) += 1;
        *f.tpls.entry(tpl).or_insert(0) += 1;
    }

    let mut raw_bypass_families: Vec<RawBypassFamily> = fam_map
        .into_iter()
        .filter(|(_, f)| f.runs >= 8 && f.sessions.len() >= 2)
        .map(|(bin, f)| {
            let mut ts: Vec<(String, usize)> = f.tpls.into_iter().collect();
            ts.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
            let hs = format_harness_breakdown(&f.by_harness);
            RawBypassFamily {
                cmd_bin: bin,
                category: f.cat,
                total_runs: f.runs,
                sessions: f.sessions.len(),
                error_count: f.errs,
                error_rate: round3(f.errs as f64 / f.runs.max(1) as f64),
                total_stdout_tokens: f.toks,
                total_wait_s: round1(f.wait_ms as f64 / 1000.0),
                by_harness: f.by_harness,
                harness_summary: hs,
                top_templates: ts
                    .into_iter()
                    .take(4)
                    .map(|(k, v)| format!("{k} ({v}x)"))
                    .collect(),
            }
        })
        .collect();
    raw_bypass_families.sort_by_key(|f| std::cmp::Reverse(f.total_runs));
    raw_bypass_families.truncate(15);

    // Raw non-CLI build/test/vcs/remote tools that often indicate missing repo tasks
    let all_cmds = query_commands(conn, repo_id, range, "runs", None, 80)?;
    let raw_tool_bypasses: Vec<CommandStat> = all_cmds
        .into_iter()
        .filter(|c| {
            !c.is_repo_cli
                && !is_generic_git_read(&c.cmd_template)
                && !is_generic_interpreter(&c.cmd_template)
                && matches!(
                    c.category.as_str(),
                    "build_test" | "vcs_ci" | "package_mgr" | "polling" | "other"
                )
                && c.runs >= 4
        })
        .take(20)
        .collect();

    Ok(BypassReport {
        repo_id: repo_id.to_string(),
        repo_name,
        window: range.label.clone(),
        state_dir_scrapes,
        pipe_stripping,
        help_lookups,
        raw_bypass_families,
        raw_tool_bypasses,
    })
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}...", s.chars().take(max).collect::<String>())
    }
}

fn suggest_for_token_bloat(cmd_template: &str, noise_kind: &str, is_repo_cli: bool) -> String {
    match noise_kind {
        "passing_test_lines" => format!(
            "Default \"{cmd_template}\" to quiet/failures-only output (e.g. -q / summary reporter) and print a drill-down command on failure."
        ),
        "build_progress" => format!(
            "Suppress compile/download progress chatter in \"{cmd_template}\" (quiet flag or non-TTY mode) so only warnings/errors and final status reach the agent."
        ),
        "json_dump" => format!(
            "Add a compact summary or field-projected output mode for \"{cmd_template}\" with an explicit --raw/--json flag when full payloads are needed."
        ),
        "repeated_warnings" => format!(
            "Deduplicate or silence recurring warnings in \"{cmd_template}\" so they don't burn context tokens on every run."
        ),
        "log_stream" => format!(
            "Bound default log tail/window in \"{cmd_template}\" and emit a pointer command for older ranges."
        ),
        _ if is_repo_cli => format!(
            "Tighten default output formatting of \"{cmd_template}\" to a concise summary + pointer to full details."
        ),
        _ => format!(
            "Wrap \"{cmd_template}\" in a concise repo task/script with quiet defaults and structured failure output."
        ),
    }
}
