//! Session-level issue tracking.
//!
//! The aggregate detectors in `analyze_repo` answer "what is wrong in this window?".
//! This module answers the longitudinal question: **after a fix, do new sessions still
//! hit the same issue?**
//!
//! For every trackable issue it walks the repo's sessions in start order and classifies each
//! one as:
//! - *not exposed*: the session never did the kind of work that could trigger the issue
//!   (e.g. never ran the polled command). Excluded from rates so unrelated sessions cannot make
//!   an issue look fixed.
//! - *exposed, clean*: it could have hit the issue and didn't.
//! - *affected*: the issue fired in that session.
//!
//! Rates are `affected / exposed`. A verdict is derived either around a user fix marker
//! (`bottledeck mark`) or, without one, from the clean streak since the last hit.

use super::{
    ReadRow, SESSION_SELECT_COLS, SPAN_SELECT_COLS, SessionRow, SpanRow, analyze_repo,
    dedup_wrap_spans, harness_key, is_actual_polling_cmd, is_help_invocation,
    is_normal_vcs_workflow_cmd, map_session_row, map_span_row, percentile_i64,
};
use crate::config::TimeRange;
use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

/// Significance level for "the issue is gone": zero hits in `n` exposed sessions would happen
/// by chance less than this often at the baseline rate.
const ALPHA: f64 = 0.05;
/// Minimum clean exposed sessions before an un-marked issue is called quiet.
const MIN_QUIET_STREAK: usize = 3;
/// Minimum exposed sessions before a marker for the before-rate to count as a baseline.
const MIN_BASELINE: usize = 3;
/// Cells rendered in text strips (most recent).
pub const STRIP_CELLS: usize = 48;

// ----------------------------------------------------------------------------------------------
// Public types
// ----------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// More sessions affected after the marker than before (or newly appeared after it).
    Regressed,
    /// Recently emerged: only present in the latest sessions.
    New,
    /// Still recurring, no marker.
    Active,
    /// Marker set, affected rate did not drop meaningfully.
    Unchanged,
    /// Marker set, rate dropped by at least half but hits remain.
    Improved,
    /// Clean so far but not enough exposed sessions to rule out luck.
    Waiting,
    /// No marker, but a clean streak long enough to be unlikely by chance.
    Quiet,
    /// Marker set and zero hits in enough exposed sessions since.
    Gone,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Self::Regressed => "REGRESSED",
            Self::New => "NEW",
            Self::Active => "ACTIVE",
            Self::Unchanged => "UNCHANGED",
            Self::Improved => "IMPROVED",
            Self::Waiting => "WAITING",
            Self::Quiet => "QUIET",
            Self::Gone => "GONE",
        }
    }

    /// true when the issue still needs attention.
    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Regressed | Self::New | Self::Active | Self::Unchanged | Self::Improved
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionCell {
    pub session_id: String,
    pub started_at: i64,
    pub harness: String,
    pub harness_version: Option<String>,
    pub affected: bool,
    pub hits: usize,
    pub waste_tokens: i64,
    pub waste_ms: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Default, PartialEq)]
pub struct RateBucket {
    pub exposed: usize,
    pub affected: usize,
}

impl RateBucket {
    pub fn rate(&self) -> Option<f64> {
        (self.exposed > 0).then(|| self.affected as f64 / self.exposed as f64)
    }

    fn of<'a>(cells: impl Iterator<Item = &'a SessionCell>) -> Self {
        let mut b = Self::default();
        for c in cells {
            b.exposed += 1;
            if c.affected {
                b.affected += 1;
            }
        }
        b
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct IssueMarker {
    pub marker_id: i64,
    pub repo_id: String,
    /// `None` = applies to every issue in the repo.
    pub issue_key: Option<String>,
    pub at_ms: i64,
    pub label: String,
    pub note: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct HarnessTrack {
    pub harness: String,
    pub exposed: usize,
    pub affected: usize,
    pub last_seen: Option<i64>,
    pub clean_streak: usize,
    /// Same verdict logic applied to this harness's sessions only.
    pub verdict: Verdict,
}

#[derive(Debug, Clone, Serialize)]
pub struct VersionRow {
    pub harness: String,
    pub version: String,
    pub first_seen: i64,
    pub exposed: usize,
    pub affected: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerdictInfo {
    pub verdict: Verdict,
    pub reason: String,
    pub before: Option<RateBucket>,
    pub after: Option<RateBucket>,
    /// Probability of the observed clean run happening by chance at the baseline rate.
    pub chance_p: Option<f64>,
    /// Extra clean exposed sessions needed before the verdict can become GONE / QUIET.
    pub sessions_needed: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IssueTrack {
    /// Stable identity: `<kind>:<target>`. Unlike `opp-N` ids it survives re-ranking.
    pub key: String,
    pub kind: String,
    pub target: String,
    pub scope: String,
    pub fix_target: String,
    /// Detector headline for the current window, when the aggregate detector still fires.
    pub headline: Option<String>,
    /// Exposed sessions only, oldest first.
    pub cells: Vec<SessionCell>,
    pub exposed: usize,
    pub affected: usize,
    pub first_seen: Option<i64>,
    pub last_seen: Option<i64>,
    pub last_seen_session: Option<String>,
    pub last_seen_harness: Option<String>,
    pub last_seen_version: Option<String>,
    pub clean_streak: usize,
    pub marker: Option<IssueMarker>,
    #[serde(flatten)]
    pub verdict: VerdictInfo,
    pub by_harness: Vec<HarnessTrack>,
    pub by_version: Vec<VersionRow>,
    pub waste_tokens: i64,
    pub waste_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct IssuesReport {
    pub repo_id: String,
    pub repo_name: String,
    pub window: String,
    pub sessions: usize,
    pub issues: Vec<IssueTrack>,
    /// Detected issues that are fleet comparisons rather than per-session events.
    pub aggregate_only: Vec<String>,
    pub markers: Vec<IssueMarker>,
}

// ----------------------------------------------------------------------------------------------
// Keys
// ----------------------------------------------------------------------------------------------

pub fn issue_key(kind: &str, target: &str) -> String {
    format!("{kind}:{target}")
}

pub fn parse_issue_key(key: &str) -> Option<(&str, &str)> {
    let (k, t) = key.split_once(':')?;
    (is_session_trackable(k) && !t.is_empty()).then_some((k, t))
}

/// Issue kinds that can be observed inside a single session.
pub fn is_session_trackable(kind: &str) -> bool {
    matches!(
        kind,
        "polling_tax"
            | "noisy_task_output"
            | "lossy_task_rebound"
            | "flag_thrash"
            | "broken_task_error_rate"
            | "output_filtering_tax"
            | "cli_help_tax"
            | "state_dir_bypass"
            | "tool_friction"
            | "orientation_tax"
            | "repeated_file_reread"
            | "truncated_output_reread"
            | "file_edit_churn"
            | "context_pressure"
            | "session_abort_rate"
    )
}

fn default_scope(kind: &str) -> &'static str {
    match kind {
        "truncated_output_reread" | "context_pressure" | "session_abort_rate" => "harness",
        _ => "repo",
    }
}

// ----------------------------------------------------------------------------------------------
// Markers
// ----------------------------------------------------------------------------------------------

pub fn add_marker(
    conn: &Connection,
    repo_id: &str,
    issue_key: Option<&str>,
    at_ms: i64,
    label: &str,
    note: Option<&str>,
) -> Result<i64> {
    conn.execute(
        "INSERT INTO issue_markers (repo_id, issue_key, at_ms, label, note, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            repo_id,
            issue_key,
            at_ms,
            label,
            note,
            Utc::now().timestamp_millis()
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn remove_marker(conn: &Connection, repo_id: &str, marker_id: i64) -> Result<bool> {
    let n = conn.execute(
        "DELETE FROM issue_markers WHERE marker_id = ?1 AND repo_id = ?2",
        params![marker_id, repo_id],
    )?;
    Ok(n > 0)
}

pub fn list_markers(conn: &Connection, repo_id: &str) -> Result<Vec<IssueMarker>> {
    let mut stmt = conn.prepare(
        "SELECT marker_id, repo_id, issue_key, at_ms, label, note, created_at
         FROM issue_markers WHERE repo_id = ?1 ORDER BY at_ms ASC, marker_id ASC",
    )?;
    let rows = stmt
        .query_map(params![repo_id], |r| {
            Ok(IssueMarker {
                marker_id: r.get(0)?,
                repo_id: r.get(1)?,
                issue_key: r.get(2)?,
                at_ms: r.get(3)?,
                label: r.get(4)?,
                note: r.get(5)?,
                created_at: r.get(6)?,
            })
        })?
        .flatten()
        .collect();
    Ok(rows)
}

/// Latest marker for an issue: an issue-specific marker wins over a repo-wide one.
fn marker_for<'a>(markers: &'a [IssueMarker], key: &str) -> Option<&'a IssueMarker> {
    markers
        .iter()
        .filter(|m| m.issue_key.as_deref() == Some(key))
        .max_by_key(|m| (m.at_ms, m.marker_id))
        .or_else(|| {
            markers
                .iter()
                .filter(|m| m.issue_key.is_none())
                .max_by_key(|m| (m.at_ms, m.marker_id))
        })
}

// ----------------------------------------------------------------------------------------------
// Session data
// ----------------------------------------------------------------------------------------------

struct ToolRow {
    tool_name: String,
    is_error: bool,
    is_truncated: bool,
    is_edit: bool,
    target_path: Option<String>,
}

struct SessionData {
    session: SessionRow,
    harness_version: Option<String>,
    spans: Vec<SpanRow>,
    reads: Vec<ReadRow>,
    tools: Vec<ToolRow>,
}

impl SessionData {
    fn is_active(&self) -> bool {
        self.session.turn_count > 0 || !self.spans.is_empty() || !self.tools.is_empty()
    }
}

fn load_sessions(conn: &Connection, repo_id: &str, range: &TimeRange) -> Result<Vec<SessionData>> {
    let since_ms = range.since_ms;
    let until_ms = range.upper_bound();

    let mut s_stmt = conn.prepare(&format!(
        "SELECT {SESSION_SELECT_COLS}, harness_version
         FROM sessions
         WHERE repo_id = ?1
           AND COALESCE(started_at, ended_at, 0) >= ?2
           AND COALESCE(started_at, ended_at, 0) < ?3
         ORDER BY COALESCE(started_at, ended_at, 0) ASC, session_id ASC"
    ))?;
    let mut out: Vec<SessionData> = s_stmt
        .query_map(params![repo_id, since_ms, until_ms], |r| {
            Ok(SessionData {
                session: map_session_row(r)?,
                harness_version: r.get(33)?,
                spans: Vec::new(),
                reads: Vec::new(),
                tools: Vec::new(),
            })
        })?
        .flatten()
        .collect();
    let idx: HashMap<String, usize> = out
        .iter()
        .enumerate()
        .map(|(i, s)| (s.session.session_id.clone(), i))
        .collect();

    let mut sp_stmt = conn.prepare(&format!(
        "SELECT {SPAN_SELECT_COLS}
         FROM command_spans
         WHERE repo_id = ?1 AND session_id IS NOT NULL
           AND session_id IN (
               SELECT session_id FROM sessions
               WHERE repo_id = ?1
                 AND COALESCE(started_at, ended_at, 0) >= ?2
                 AND COALESCE(started_at, ended_at, 0) < ?3
           )
         ORDER BY session_id ASC, turn_idx ASC, seq_idx ASC, started_at ASC"
    ))?;
    let spans = dedup_wrap_spans(
        sp_stmt
            .query_map(params![repo_id, since_ms, until_ms], map_span_row)?
            .flatten()
            .collect(),
    );
    for sp in spans {
        if let Some(i) = sp.session_id.as_ref().and_then(|s| idx.get(s)) {
            out[*i].spans.push(sp);
        }
    }

    let mut rd_stmt = conn.prepare(
        "SELECT session_id, turn_idx, COALESCE(target_path, target_name), is_doc, output_tokens
         FROM file_reads
         WHERE repo_id = ?1
           AND session_id IN (
               SELECT session_id FROM sessions
               WHERE repo_id = ?1
                 AND COALESCE(started_at, ended_at, 0) >= ?2
                 AND COALESCE(started_at, ended_at, 0) < ?3
           )",
    )?;
    let reads = rd_stmt.query_map(params![repo_id, since_ms, until_ms], |r| {
        Ok(ReadRow {
            session_id: r.get(0)?,
            turn_idx: r.get(1)?,
            target_name: r.get(2)?,
            is_doc: r.get::<_, i64>(3)? != 0,
            output_tokens: r.get(4)?,
        })
    })?;
    for rd in reads.flatten() {
        if let Some(i) = idx.get(&rd.session_id) {
            out[*i].reads.push(rd);
        }
    }

    let mut tc_stmt = conn.prepare(
        "SELECT session_id, tool_name, is_error, is_truncated, is_edit, target_path
         FROM tool_calls
         WHERE repo_id = ?1
           AND session_id IN (
               SELECT session_id FROM sessions
               WHERE repo_id = ?1
                 AND COALESCE(started_at, ended_at, 0) >= ?2
                 AND COALESCE(started_at, ended_at, 0) < ?3
           )
         ORDER BY session_id ASC, turn_idx ASC, seq_idx ASC",
    )?;
    let tools = tc_stmt.query_map(params![repo_id, since_ms, until_ms], |r| {
        Ok((
            r.get::<_, String>(0)?,
            ToolRow {
                tool_name: r.get(1)?,
                is_error: r.get::<_, i64>(2)? != 0,
                is_truncated: r.get::<_, i64>(3)? != 0,
                is_edit: r.get::<_, i64>(4)? != 0,
                target_path: r.get(5)?,
            },
        ))
    })?;
    for (sid, t) in tools.flatten() {
        if let Some(i) = idx.get(&sid) {
            out[*i].tools.push(t);
        }
    }
    Ok(out)
}

// ----------------------------------------------------------------------------------------------
// Per-session signatures (mirror the aggregate detectors at session granularity)
// ----------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Obs {
    affected: bool,
    hits: usize,
    waste_tokens: i64,
    waste_ms: i64,
}

fn obs(hits: usize, min_hits: usize, waste_tokens: i64, waste_ms: i64) -> Option<Obs> {
    Some(Obs {
        affected: hits >= min_hits.max(1),
        hits,
        waste_tokens,
        waste_ms,
    })
}

/// `None` = session not exposed to this issue.
fn observe(kind: &str, target: &str, sd: &SessionData) -> Option<Obs> {
    let spans = &sd.spans;
    let tpl_runs = || spans.iter().filter(|s| s.cmd_template == target);
    match kind {
        "polling_tax" => {
            let runs: Vec<&SpanRow> = tpl_runs().collect();
            if runs.is_empty() {
                return None;
            }
            let cat = runs[0].category.as_str();
            if !is_actual_polling_cmd(target, cat) {
                return None;
            }
            let threshold = if target.starts_with("sleep") { 2 } else { 3 };
            let ms: i64 = runs.iter().filter_map(|s| s.duration_ms).sum();
            let cnt = runs.len();
            let affected = cnt >= threshold;
            Some(Obs {
                affected,
                hits: if affected { cnt } else { 0 },
                waste_tokens: if affected {
                    runs.iter().map(|s| s.stdout_tokens).sum()
                } else {
                    0
                },
                waste_ms: if affected { ms } else { 0 },
            })
        }
        "noisy_task_output" => {
            let toks: Vec<i64> = tpl_runs().map(|s| s.stdout_tokens).collect();
            if toks.is_empty() {
                return None;
            }
            let p50 = percentile_i64(&toks, 50.0);
            let max = toks.iter().copied().max().unwrap_or(0);
            let affected = p50 >= 350 || max >= 1200;
            let noisy = toks.iter().filter(|&&t| t >= 350).count();
            Some(Obs {
                affected,
                hits: if affected { noisy.max(1) } else { 0 },
                waste_tokens: if affected { toks.iter().sum() } else { 0 },
                waste_ms: 0,
            })
        }
        "lossy_task_rebound" => {
            let mut exposed = false;
            let mut hits = 0;
            let mut waste = 0;
            for (i, cur) in spans.iter().enumerate() {
                if cur.cmd_template != target {
                    continue;
                }
                exposed = true;
                if !cur.is_repo_cli {
                    continue;
                }
                if let Some(nx) = spans.get(i + 1)
                    && !nx.is_repo_cli
                    && !is_normal_vcs_workflow_cmd(&nx.cmd_template)
                    && (nx.category == "exploration" || nx.category == "vcs_ci")
                    && nx.turn_idx - cur.turn_idx <= 1
                    && nx.started_at.saturating_sub(cur.started_at) <= 60_000
                {
                    hits += 1;
                    waste += nx.stdout_tokens;
                }
            }
            exposed.then(|| obs(hits, 1, waste, 0)).flatten()
        }
        "flag_thrash" => {
            let from = target.split_once(" -> ").map_or(target, |(f, _)| f);
            if !spans.iter().any(|s| s.cmd_template == from) {
                return None;
            }
            let mut hits = 0;
            let mut waste_tokens = 0;
            let mut waste_ms = 0;
            for (i, cur) in spans.iter().enumerate() {
                if cur.cmd_template != from
                    || !cur.exit_code.is_some_and(|c| c != 0)
                    || cur.category == "exploration"
                {
                    continue;
                }
                for cand in spans.iter().skip(i + 1).take(3) {
                    if cand.turn_idx - cur.turn_idx > 2 {
                        break;
                    }
                    if cand.cmd_bin == cur.cmd_bin && cand.exit_code == Some(0) {
                        let t = if cur.cmd_template == cand.cmd_template {
                            cur.cmd_template.clone()
                        } else {
                            format!("{} -> {}", cur.cmd_template, cand.cmd_template)
                        };
                        if t == target {
                            hits += 1;
                            waste_tokens += cur.stdout_tokens;
                            waste_ms += cur.duration_ms.unwrap_or(0);
                        }
                        break;
                    }
                }
            }
            obs(hits, 1, waste_tokens, waste_ms)
        }
        "broken_task_error_rate" => {
            let runs: Vec<&SpanRow> = tpl_runs().collect();
            if runs.is_empty() {
                return None;
            }
            let failed: Vec<&&SpanRow> = runs
                .iter()
                .filter(|s| s.exit_code.is_some_and(|c| c != 0))
                .collect();
            obs(
                failed.len(),
                1,
                failed.iter().map(|s| s.stdout_tokens).sum(),
                failed.iter().filter_map(|s| s.duration_ms).sum(),
            )
        }
        "output_filtering_tax" => {
            let cli: Vec<&SpanRow> = spans.iter().filter(|s| s.is_repo_cli).collect();
            if cli.is_empty() {
                return None;
            }
            let piped = cli.iter().filter(|s| s.piped_filter.is_some()).count();
            obs(piped, 1, 0, 0)
        }
        "cli_help_tax" => {
            let cli: Vec<&SpanRow> = spans.iter().filter(|s| s.is_repo_cli).collect();
            if cli.is_empty() {
                return None;
            }
            let helps: Vec<&&SpanRow> = cli.iter().filter(|s| is_help_invocation(s)).collect();
            // A single --help is normal discovery; repeated lookups in one session are the tax.
            obs(
                helps.len(),
                2,
                helps.iter().map(|s| s.stdout_tokens).sum(),
                0,
            )
        }
        "state_dir_bypass" => {
            if spans.is_empty() {
                return None;
            }
            let scrapes: Vec<&SpanRow> = spans
                .iter()
                .filter(|s| !s.is_repo_cli && s.state_dir_hint.as_deref() == Some(target))
                .collect();
            obs(
                scrapes.len(),
                1,
                scrapes.iter().map(|s| s.stdout_tokens).sum(),
                0,
            )
        }
        "tool_friction" => {
            let calls: Vec<&ToolRow> = sd.tools.iter().filter(|t| t.tool_name == target).collect();
            if calls.is_empty() {
                return None;
            }
            let bad = calls
                .iter()
                .filter(|t| t.is_error || t.is_truncated)
                .count();
            obs(bad, 1, 0, 0)
        }
        "orientation_tax" => {
            if !sd.is_active() {
                return None;
            }
            let early_spans: Vec<&SpanRow> = spans
                .iter()
                .filter(|s| s.is_orientation && s.turn_idx <= 3)
                .collect();
            let early_reads: Vec<&ReadRow> = sd
                .reads
                .iter()
                .filter(|r| r.is_doc && r.turn_idx <= 3)
                .collect();
            let events = early_spans.len() + early_reads.len();
            let toks: i64 = early_spans.iter().map(|s| s.stdout_tokens).sum::<i64>()
                + early_reads.iter().map(|r| r.output_tokens).sum::<i64>();
            let affected = events >= 4 && toks >= 1000;
            Some(Obs {
                affected,
                hits: if affected { events } else { 0 },
                waste_tokens: if affected { toks } else { 0 },
                waste_ms: 0,
            })
        }
        "repeated_file_reread" | "truncated_output_reread" => {
            let reads: Vec<&ReadRow> = sd
                .reads
                .iter()
                .filter(|r| r.target_name == target)
                .collect();
            if reads.is_empty() {
                return None;
            }
            let affected = reads.len() >= 2;
            Some(Obs {
                affected,
                hits: if affected { reads.len() - 1 } else { 0 },
                waste_tokens: if affected {
                    reads.iter().skip(1).map(|r| r.output_tokens).sum()
                } else {
                    0
                },
                waste_ms: 0,
            })
        }
        "file_edit_churn" => {
            let edits = sd
                .tools
                .iter()
                .filter(|t| t.is_edit && t.target_path.as_deref() == Some(target))
                .count();
            if edits == 0 {
                return None;
            }
            let affected = edits >= 3;
            Some(Obs {
                affected,
                hits: if affected { edits } else { 0 },
                waste_tokens: 0,
                waste_ms: 0,
            })
        }
        "context_pressure" => {
            if !sd.is_active() {
                return None;
            }
            let s = &sd.session;
            let compactions = s.compaction_count.max(0) as usize;
            let over = s.peak_context_pct().is_some_and(|p| p >= 80.0);
            obs(compactions + usize::from(over), 1, 0, 0)
        }
        "session_abort_rate" => {
            if !sd.is_active() {
                return None;
            }
            let s = &sd.session;
            let aborted = s.aborted_turns.max(0) as usize
                + usize::from(s.outcome.as_deref() == Some("aborted") && s.aborted_turns == 0);
            obs(aborted, 1, 0, 0)
        }
        _ => None,
    }
}

// ----------------------------------------------------------------------------------------------
// Verdicts
// ----------------------------------------------------------------------------------------------

/// Natural version ordering: numeric runs compare numerically (`2.1.10` > `2.1.9`), and a
/// pre-release suffix sorts before the release (`0.171.0-alpha.13` < `0.171.0`).
pub fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    fn parts(v: &str) -> (Vec<u64>, Option<&str>) {
        let (core, pre) = match v.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (v, None),
        };
        (
            core.split('.').map(|p| p.parse().unwrap_or(0)).collect(),
            pre,
        )
    }
    let (ca, pa) = parts(a);
    let (cb, pb) = parts(b);
    ca.cmp(&cb).then_with(|| match (pa, pb) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
        (Some(x), Some(y)) => {
            let nx: Vec<u64> = x.split('.').filter_map(|p| p.parse().ok()).collect();
            let ny: Vec<u64> = y.split('.').filter_map(|p| p.parse().ok()).collect();
            nx.cmp(&ny).then_with(|| x.cmp(y))
        }
    })
}

fn binom_pmf(n: usize, k: usize, p: f64) -> f64 {
    // ln C(n,k) via log-sum to stay stable for large n.
    let ln_c: f64 = (1..=k).map(|i| ((n - k + i) as f64 / i as f64).ln()).sum();
    (ln_c + k as f64 * p.ln() + (n - k) as f64 * (1.0 - p).ln()).exp()
}

/// P(X >= k) for X ~ Binomial(n, p).
fn binom_upper(n: usize, k: usize, p: f64) -> f64 {
    if k == 0 {
        return 1.0;
    }
    if p <= 0.0 {
        return 0.0;
    }
    if p >= 1.0 {
        return 1.0;
    }
    (k..=n).map(|i| binom_pmf(n, i, p)).sum::<f64>().min(1.0)
}

/// P(X <= k) for X ~ Binomial(n, p).
fn binom_lower(n: usize, k: usize, p: f64) -> f64 {
    if k >= n {
        return 1.0;
    }
    if p <= 0.0 {
        return 1.0;
    }
    if p >= 1.0 {
        return 0.0;
    }
    (0..=k).map(|i| binom_pmf(n, i, p)).sum::<f64>().min(1.0)
}

/// Number of consecutive clean exposed sessions (at the end) needed so that a clean run is
/// unlikely (< ALPHA) at baseline rate `p`.
fn clean_run_needed(p: f64) -> usize {
    if p <= 0.0 {
        return usize::MAX;
    }
    if p >= 1.0 {
        return 1;
    }
    (ALPHA.ln() / (1.0 - p).ln()).ceil().max(1.0) as usize
}

fn pct(r: Option<f64>) -> String {
    r.map_or("-".into(), |v| format!("{:.0}%", v * 100.0))
}

/// Derive the verdict for a chronologically-ordered list of exposed sessions.
pub fn compute_verdict(cells: &[SessionCell], marker_at: Option<i64>) -> VerdictInfo {
    let total = RateBucket::of(cells.iter());
    if let Some(at) = marker_at {
        let before = RateBucket::of(cells.iter().filter(|c| c.started_at < at));
        let after = RateBucket::of(cells.iter().filter(|c| c.started_at >= at));
        let mut info = VerdictInfo {
            verdict: Verdict::Waiting,
            reason: String::new(),
            before: Some(before),
            after: Some(after),
            chance_p: None,
            sessions_needed: None,
        };
        if after.exposed == 0 {
            info.reason = "no exposed sessions since the marker yet".into();
            return info;
        }
        if before.exposed < MIN_BASELINE {
            // Too little history before the marker to compare against: judge the post-marker
            // sessions on their own.
            let after_cells: Vec<SessionCell> = cells
                .iter()
                .filter(|c| c.started_at >= at)
                .cloned()
                .collect();
            let own = compute_verdict(&after_cells, None);
            info.verdict = own.verdict;
            info.chance_p = own.chance_p;
            info.sessions_needed = own.sessions_needed;
            info.reason = format!(
                "only {} exposed session{} before the marker, no baseline; since the marker: {}",
                before.exposed,
                if before.exposed == 1 { "" } else { "s" },
                own.reason
            );
            return info;
        }
        if before.affected == 0 {
            if after.affected > 0 {
                info.verdict = Verdict::Regressed;
                info.reason = format!(
                    "appeared after the marker: {}/{} exposed sessions affected, 0/{} before",
                    after.affected, after.exposed, before.exposed
                );
            } else {
                info.verdict = Verdict::Quiet;
                info.reason = format!(
                    "no hits before or after the marker ({} exposed sessions)",
                    total.exposed
                );
            }
            return info;
        }
        let pb = before.rate().unwrap_or(0.0);
        let pa = after.rate().unwrap_or(0.0);
        let needed = clean_run_needed(pb);
        if after.affected == 0 {
            let chance = (1.0 - pb).powi(after.exposed as i32);
            info.chance_p = Some(chance);
            if chance <= ALPHA {
                info.verdict = Verdict::Gone;
                info.reason = format!(
                    "0/{} exposed sessions affected since the marker (was {}); {:.1}% likely by chance",
                    after.exposed,
                    pct(Some(pb)),
                    chance * 100.0
                );
            } else {
                let need = needed.saturating_sub(after.exposed);
                info.sessions_needed = Some(need);
                info.reason = format!(
                    "clean so far (0/{}), needs {} more clean exposed session{} to confirm against the {} baseline",
                    after.exposed,
                    need,
                    if need == 1 { "" } else { "s" },
                    pct(Some(pb))
                );
            }
            return info;
        }
        // Exact binomial tests of the after-count against the before-rate.
        let p_up = binom_upper(after.exposed, after.affected, pb);
        let p_down = binom_lower(after.exposed, after.affected, pb);
        let counts = format!(
            "{} → {} ({}/{} before, {}/{} after)",
            pct(Some(pb)),
            pct(Some(pa)),
            before.affected,
            before.exposed,
            after.affected,
            after.exposed
        );
        if pa > pb && p_up <= ALPHA {
            info.verdict = Verdict::Regressed;
            info.chance_p = Some(p_up);
            info.reason = format!("{counts}; {:.1}% likely by chance", p_up * 100.0);
        } else if pa < pb && p_down <= ALPHA {
            info.verdict = Verdict::Improved;
            info.chance_p = Some(p_down);
            info.reason = format!(
                "{counts}; drop is {:.1}% likely by chance, but it still recurs",
                p_down * 100.0
            );
        } else if after.exposed >= needed {
            info.verdict = Verdict::Unchanged;
            info.reason = format!("{counts}; no significant change");
        } else {
            info.verdict = Verdict::Waiting;
            info.sessions_needed = Some(needed - after.exposed);
            info.reason = format!(
                "{counts}; too few sessions since the marker to tell ({} more needed)",
                needed - after.exposed
            );
        }
        return info;
    }

    // No marker: use the clean streak since the last hit as an automatic change point.
    let mut info = VerdictInfo {
        verdict: Verdict::Active,
        reason: String::new(),
        before: None,
        after: None,
        chance_p: None,
        sessions_needed: None,
    };
    if total.affected == 0 {
        info.verdict = Verdict::Quiet;
        info.reason = format!("no hits in {} exposed sessions", total.exposed);
        return info;
    }
    let streak = cells.iter().rev().take_while(|c| !c.affected).count();
    let active_span = total.exposed - streak;
    let p = total.affected as f64 / active_span.max(1) as f64;
    if streak > 0 {
        let chance = (1.0 - p).powi(streak as i32);
        info.chance_p = Some(chance);
        if streak >= MIN_QUIET_STREAK && chance <= ALPHA {
            info.verdict = Verdict::Quiet;
            info.reason = format!(
                "not seen in the last {streak} exposed sessions (was {} before); {:.1}% likely by chance — mark the fix to confirm",
                pct(Some(p)),
                chance * 100.0
            );
            return info;
        }
        info.sessions_needed = Some(
            clean_run_needed(p)
                .max(MIN_QUIET_STREAK)
                .saturating_sub(streak),
        );
    }
    // Emerged recently: every hit sits in the newest third and the older two-thirds had
    // enough clean exposure to have shown it.
    let first_hit = cells.iter().position(|c| c.affected).unwrap_or(0);
    let cutoff = cells.len() * 2 / 3;
    if first_hit >= cutoff && first_hit >= 5 {
        info.verdict = Verdict::New;
        info.reason = format!(
            "first appeared {} exposed sessions ago after {} clean ones",
            cells.len() - first_hit,
            first_hit
        );
        return info;
    }
    info.reason = format!(
        "{}/{} exposed sessions affected ({}); {}",
        total.affected,
        total.exposed,
        pct(Some(p)),
        if streak == 0 {
            "hit again in the latest one".to_string()
        } else {
            format!(
                "clean in the last {streak}, {} more needed to call it quiet",
                info.sessions_needed.unwrap_or(0)
            )
        }
    );
    info
}

// ----------------------------------------------------------------------------------------------
// Tracking
// ----------------------------------------------------------------------------------------------

struct Candidate {
    kind: String,
    target: String,
    scope: String,
    fix_target: String,
    headline: Option<String>,
}

fn build_track(c: &Candidate, sessions: &[SessionData], markers: &[IssueMarker]) -> IssueTrack {
    let key = issue_key(&c.kind, &c.target);
    let mut cells: Vec<SessionCell> = Vec::new();
    for sd in sessions {
        if let Some(o) = observe(&c.kind, &c.target, sd) {
            cells.push(SessionCell {
                session_id: sd.session.session_id.clone(),
                started_at: sd.session.started_at,
                harness: harness_key(Some(&sd.session.agent_kind)),
                harness_version: sd.harness_version.clone(),
                affected: o.affected,
                hits: o.hits,
                waste_tokens: o.waste_tokens,
                waste_ms: o.waste_ms,
            });
        }
    }
    let marker = marker_for(markers, &key).cloned();
    let verdict = compute_verdict(&cells, marker.as_ref().map(|m| m.at_ms));

    let affected = cells.iter().filter(|c| c.affected).count();
    let first = cells.iter().find(|c| c.affected);
    let last = cells.iter().rev().find(|c| c.affected);
    let clean_streak = cells.iter().rev().take_while(|c| !c.affected).count();

    let mut hmap: BTreeMap<String, Vec<&SessionCell>> = BTreeMap::new();
    for cell in &cells {
        hmap.entry(cell.harness.clone()).or_default().push(cell);
    }
    let marker_at = marker.as_ref().map(|m| m.at_ms);
    let mut by_harness: Vec<HarnessTrack> = hmap
        .into_iter()
        .map(|(h, cs)| HarnessTrack {
            verdict: compute_verdict(
                &cs.iter().map(|c| (*c).clone()).collect::<Vec<_>>(),
                marker_at,
            )
            .verdict,
            exposed: cs.len(),
            affected: cs.iter().filter(|c| c.affected).count(),
            last_seen: cs.iter().rev().find(|c| c.affected).map(|c| c.started_at),
            clean_streak: cs.iter().rev().take_while(|c| !c.affected).count(),
            harness: h,
        })
        .collect();
    by_harness.sort_by_key(|h| std::cmp::Reverse(h.exposed));

    let mut vmap: BTreeMap<(String, String), VersionRow> = BTreeMap::new();
    for cell in &cells {
        let v = cell
            .harness_version
            .clone()
            .unwrap_or_else(|| "?".to_string());
        let row = vmap
            .entry((cell.harness.clone(), v.clone()))
            .or_insert_with(|| VersionRow {
                harness: cell.harness.clone(),
                version: v,
                first_seen: cell.started_at,
                exposed: 0,
                affected: 0,
            });
        row.exposed += 1;
        if cell.affected {
            row.affected += 1;
        }
    }
    let mut by_version: Vec<VersionRow> = vmap.into_values().collect();
    by_version.sort_by(|a, b| {
        a.harness
            .cmp(&b.harness)
            .then_with(|| version_cmp(&a.version, &b.version))
    });

    IssueTrack {
        kind: c.kind.clone(),
        target: c.target.clone(),
        scope: c.scope.clone(),
        fix_target: c.fix_target.clone(),
        headline: c.headline.clone(),
        exposed: cells.len(),
        affected,
        first_seen: first.map(|c| c.started_at),
        last_seen: last.map(|c| c.started_at),
        last_seen_session: last.map(|c| c.session_id.clone()),
        last_seen_harness: last.map(|c| c.harness.clone()),
        last_seen_version: last.and_then(|c| c.harness_version.clone()),
        clean_streak,
        marker,
        verdict,
        by_harness,
        by_version,
        waste_tokens: cells.iter().map(|c| c.waste_tokens).sum(),
        waste_ms: cells.iter().map(|c| c.waste_ms).sum(),
        cells,
        key,
    }
}

/// Track every session-observable issue the detectors find in `range`, plus every issue with a
/// fix marker (so a fixed issue stays visible after the aggregate detector stops firing).
pub fn track_issues(conn: &Connection, repo_id: &str, range: &TimeRange) -> Result<IssuesReport> {
    let report = analyze_repo(conn, repo_id, range, 200)?;
    let markers = list_markers(conn, repo_id)?;

    let mut candidates: Vec<Candidate> = Vec::new();
    let mut aggregate_only: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for o in report
        .opportunities
        .iter()
        .chain(report.harness_overhead.iter())
    {
        let key = issue_key(&o.kind, &o.target);
        if !is_session_trackable(&o.kind) {
            aggregate_only.push(key);
            continue;
        }
        if seen.insert(key) {
            candidates.push(Candidate {
                kind: o.kind.clone(),
                target: o.target.clone(),
                scope: o.scope.clone(),
                fix_target: o.fix_target.clone(),
                headline: Some(o.impact_summary.clone()),
            });
        }
    }
    for m in &markers {
        let Some(key) = m.issue_key.as_deref() else {
            continue;
        };
        if seen.contains(key) {
            continue;
        }
        if let Some((kind, target)) = parse_issue_key(key) {
            seen.insert(key.to_string());
            candidates.push(Candidate {
                kind: kind.to_string(),
                target: target.to_string(),
                scope: default_scope(kind).to_string(),
                fix_target: String::new(),
                headline: None,
            });
        }
    }

    let sessions = load_sessions(conn, repo_id, range)?;
    let mut issues: Vec<IssueTrack> = candidates
        .iter()
        .map(|c| build_track(c, &sessions, &markers))
        .filter(|t| t.exposed > 0)
        .collect();
    issues.sort_by(|a, b| {
        a.verdict
            .verdict
            .cmp(&b.verdict.verdict)
            .then(b.last_seen.unwrap_or(0).cmp(&a.last_seen.unwrap_or(0)))
            .then(b.affected.cmp(&a.affected))
    });

    Ok(IssuesReport {
        repo_id: repo_id.to_string(),
        repo_name: report.repo_name,
        window: range.label.clone(),
        sessions: sessions.len(),
        issues,
        aggregate_only,
        markers,
    })
}

/// Resolve a user-supplied issue reference — exact key, key substring, or a current-window
/// `opp-N` / `h-N` id — to candidate keys. Exactly one candidate means a unique match.
pub fn resolve_issue_ref(
    conn: &Connection,
    repo_id: &str,
    range: &TimeRange,
    query: &str,
) -> Result<Vec<String>> {
    let q = query.trim();
    if parse_issue_key(q).is_some() {
        return Ok(vec![q.to_string()]);
    }
    let report = analyze_repo(conn, repo_id, range, 200)?;
    let all: Vec<_> = report
        .opportunities
        .iter()
        .chain(report.harness_overhead.iter())
        .collect();
    if let Some(o) = all.iter().find(|o| o.id.eq_ignore_ascii_case(q)) {
        return Ok(vec![issue_key(&o.kind, &o.target)]);
    }
    let mut matches: Vec<String> = all
        .iter()
        .filter(|o| is_session_trackable(&o.kind))
        .map(|o| issue_key(&o.kind, &o.target))
        .filter(|k| k.contains(q))
        .collect();
    matches.dedup();
    Ok(matches)
}

/// Turn candidates into a single key or a user-facing error message.
pub fn pick_issue_key(query: &str, candidates: Vec<String>) -> std::result::Result<String, String> {
    match candidates.len() {
        1 => Ok(candidates.into_iter().next().unwrap_or_default()),
        0 => Err(format!(
            "No trackable issue matches \"{query}\". Run `bottledeck issues` to list keys."
        )),
        _ => Err(format!(
            "\"{query}\" matches {} issues; use one of:\n{}",
            candidates.len(),
            candidates
                .iter()
                .map(|k| format!("  {k}"))
                .collect::<Vec<_>>()
                .join("\n")
        )),
    }
}

// ----------------------------------------------------------------------------------------------
// Rendering
// ----------------------------------------------------------------------------------------------

/// Text strip of the most recent exposed sessions: `●` affected, `○` clean, `│` marker.
pub fn strip(cells: &[SessionCell], marker_at: Option<i64>, max: usize) -> String {
    let start = cells.len().saturating_sub(max);
    let marker_idx = marker_at.map(|at| {
        cells
            .iter()
            .position(|c| c.started_at >= at)
            .unwrap_or(cells.len())
    });
    let mut s = String::new();
    if start > 0 {
        s.push('…');
        if marker_idx.is_some_and(|m| m < start) {
            s.push('│');
        }
    }
    for (i, c) in cells.iter().enumerate().skip(start) {
        if marker_idx == Some(i) {
            s.push('│');
        }
        s.push(if c.affected { '●' } else { '○' });
    }
    if marker_idx == Some(cells.len()) {
        s.push('│');
    }
    s
}

pub fn format_ts(ms: i64) -> String {
    DateTime::from_timestamp_millis(ms)
        .map(|d| d.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "-".into())
}

pub fn format_ago(ms: i64) -> String {
    let secs = (Utc::now().timestamp_millis() - ms).max(0) / 1000;
    match secs {
        s if s < 3600 => format!("{}m ago", s / 60),
        s if s < 86_400 => format!("{}h ago", s / 3600),
        s => format!("{}d ago", s / 86_400),
    }
}

fn short_sid(sid: &str) -> String {
    let tail = sid.rsplit(':').next().unwrap_or(sid);
    tail.chars().take(10).collect()
}

fn rate_cell(b: Option<RateBucket>) -> String {
    b.map_or("-".into(), |b| {
        format!("{}/{} ({})", b.affected, b.exposed, pct(b.rate()))
    })
}

pub fn format_issues_report(rep: &IssuesReport, format: &str) -> String {
    if format == "json" {
        return serde_json::to_string_pretty(rep).unwrap_or_default();
    }
    let mut out = String::new();
    out.push_str(&format!(
        "# Issue tracking — {} ({}, {} sessions)\n\n",
        rep.repo_name, rep.window, rep.sessions
    ));
    out.push_str("Each cell is one session that could have hit the issue (oldest → newest): `●` affected, `○` clean, `│` fix marker. Sessions that never did the relevant work are excluded.\n\n");
    if rep.issues.is_empty() {
        out.push_str("_No session-trackable issues in this window._\n");
    } else {
        out.push_str("| Verdict | Issue | Affected | Last seen | Recent sessions |\n");
        out.push_str("| :--- | :--- | ---: | :--- | :--- |\n");
        for t in &rep.issues {
            out.push_str(&format!(
                "| {} | `{}` | {}/{} | {} | `{}` |\n",
                t.verdict.verdict.label(),
                t.key.replace('|', "\\|"),
                t.affected,
                t.exposed,
                t.last_seen.map_or("-".into(), format_ago),
                strip(&t.cells, t.marker.as_ref().map(|m| m.at_ms), 20)
            ));
        }
        out.push('\n');
    }
    for t in &rep.issues {
        out.push_str(&format!("## {} `{}`\n\n", t.verdict.verdict.label(), t.key));
        out.push_str(&format!(
            "`{}`\n\n",
            strip(&t.cells, t.marker.as_ref().map(|m| m.at_ms), STRIP_CELLS)
        ));
        out.push_str(&format!("- **Verdict:** {}\n", t.verdict.reason));
        out.push_str(&format!(
            "- **Sessions:** {}/{} exposed affected · scope {}",
            t.affected, t.exposed, t.scope
        ));
        if t.waste_tokens > 0 {
            out.push_str(&format!(
                " · {} tokens wasted",
                super::format_compact(t.waste_tokens)
            ));
        }
        if t.waste_ms > 0 {
            out.push_str(&format!(
                " · {} waited",
                super::format_duration_human(t.waste_ms as f64 / 1000.0)
            ));
        }
        out.push('\n');
        if let Some(m) = &t.marker {
            out.push_str(&format!(
                "- **Marker #{}:** {}{} — before {}, after {}\n",
                m.marker_id,
                m.label,
                m.note
                    .as_deref()
                    .map(|n| format!(" “{n}”"))
                    .unwrap_or_default(),
                rate_cell(t.verdict.before),
                rate_cell(t.verdict.after)
            ));
        }
        if let (Some(ls), Some(sid)) = (t.last_seen, &t.last_seen_session) {
            out.push_str(&format!(
                "- **Last seen:** {} ({}) in `{}` · {}{}\n",
                format_ts(ls),
                format_ago(ls),
                short_sid(sid),
                t.last_seen_harness.as_deref().unwrap_or("?"),
                t.last_seen_version
                    .as_deref()
                    .map(|v| format!(" {v}"))
                    .unwrap_or_default()
            ));
        }
        if t.by_harness.len() > 1 {
            let parts: Vec<String> = t
                .by_harness
                .iter()
                .map(|h| {
                    format!(
                        "{} {}/{} {}",
                        h.harness,
                        h.affected,
                        h.exposed,
                        h.verdict.label().to_ascii_lowercase()
                    )
                })
                .collect();
            out.push_str(&format!("- **By harness:** {}\n", parts.join(" · ")));
        }
        let versioned: Vec<&VersionRow> =
            t.by_version.iter().filter(|v| v.version != "?").collect();
        if versioned.len() > 1 {
            let parts: Vec<String> = versioned
                .iter()
                .map(|v| format!("{} {} {}/{}", v.harness, v.version, v.affected, v.exposed))
                .collect();
            out.push_str(&format!("- **By version:** {}\n", parts.join(" · ")));
        }
        if let Some(h) = &t.headline {
            out.push_str(&format!("- **Detector:** {h}\n"));
        }
        out.push('\n');
    }
    if !rep.aggregate_only.is_empty() {
        let mut by_kind: BTreeMap<&str, usize> = BTreeMap::new();
        for k in &rep.aggregate_only {
            *by_kind.entry(k.split(':').next().unwrap_or(k)).or_insert(0) += 1;
        }
        let parts: Vec<String> = by_kind.iter().map(|(k, n)| format!("{k} ×{n}")).collect();
        out.push_str(&format!(
            "_Fleet-level findings not tracked per session: {} (see `bottledeck report`)._\n\n",
            parts.join(", ")
        ));
    }
    if !rep.markers.is_empty() {
        out.push_str("## Markers\n\n");
        for m in &rep.markers {
            out.push_str(&format!(
                "- #{} {} → {}{}\n",
                m.marker_id,
                m.label,
                m.issue_key.as_deref().unwrap_or("(all issues)"),
                m.note
                    .as_deref()
                    .map(|n| format!(" — {n}"))
                    .unwrap_or_default()
            ));
        }
    }
    out
}

// ----------------------------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn cells(pattern: &str) -> Vec<SessionCell> {
        pattern
            .chars()
            .enumerate()
            .map(|(i, ch)| SessionCell {
                session_id: format!("s{i}"),
                started_at: (i as i64 + 1) * 1000,
                harness: "codex".into(),
                harness_version: None,
                affected: ch == 'x',
                hits: usize::from(ch == 'x'),
                waste_tokens: 0,
                waste_ms: 0,
            })
            .collect()
    }

    #[test]
    fn gone_after_marker_needs_enough_clean_sessions() {
        // 4/5 before; 3 clean after: (0.2)^3 = 0.8% < 5% → gone
        let all = cells("xxoxxooo");
        let v = compute_verdict(&all, Some(6000));
        assert_eq!(v.verdict, Verdict::Gone, "{}", v.reason);
        // 1/5 before; 3 clean after: (0.8)^3 = 51% → waiting
        let v = compute_verdict(&cells("xooooooo"), Some(6000));
        assert_eq!(v.verdict, Verdict::Waiting, "{}", v.reason);
        assert!(v.sessions_needed.unwrap() > 0);
    }

    #[test]
    fn improved_unchanged_regressed() {
        // 6/6 before, 1/8 after
        let v = compute_verdict(&cells("xxxxxxooooxooo"), Some(7000));
        assert_eq!(v.verdict, Verdict::Improved, "{}", v.reason);
        let v = compute_verdict(&cells("xoxoxoxoxoxo"), Some(7000));
        assert_eq!(v.verdict, Verdict::Unchanged, "{}", v.reason);
        // 1/8 before, 4/4 after
        let v = compute_verdict(&cells("ooooxoooxxxx"), Some(9000));
        assert_eq!(v.verdict, Verdict::Regressed, "{}", v.reason);
        let v = compute_verdict(&cells("oooooox"), Some(6000));
        assert_eq!(v.verdict, Verdict::Regressed);
        // 1/2 before is no baseline: falls back to judging post-marker sessions alone
        let v = compute_verdict(&cells("xoxxoxx"), Some(3000));
        assert!(v.reason.contains("no baseline"), "{}", v.reason);
        // 3/4 before, 1/2 after: not enough sessions to tell
        let v = compute_verdict(&cells("xxoxxo"), Some(5000));
        assert_eq!(v.verdict, Verdict::Waiting, "{}", v.reason);
    }

    #[test]
    fn no_marker_uses_clean_streak() {
        let v = compute_verdict(&cells("xxxxxoooo"), None);
        assert_eq!(v.verdict, Verdict::Quiet, "{}", v.reason);
        let v = compute_verdict(&cells("xoxoxooxo"), None);
        assert_eq!(v.verdict, Verdict::Active, "{}", v.reason);
        let v = compute_verdict(&cells("ooooooooxx"), None);
        assert_eq!(v.verdict, Verdict::New, "{}", v.reason);
    }

    #[test]
    fn strip_places_marker() {
        let c = cells("xxoo");
        assert_eq!(strip(&c, Some(3000), 10), "●●│○○");
        assert_eq!(strip(&c, None, 10), "●●○○");
        assert_eq!(strip(&c, Some(99_000), 10), "●●○○│");
        assert_eq!(strip(&c, Some(4000), 2), "…○│○");
    }

    #[test]
    fn binomial_tails() {
        assert!((binom_upper(4, 4, 0.2) - 0.0016).abs() < 1e-6);
        assert!((binom_lower(3, 0, 0.5) - 0.125).abs() < 1e-9);
        assert!((binom_upper(10, 0, 0.3) - 1.0).abs() < 1e-12);
        let total: f64 = (0..=20).map(|k| binom_pmf(20, k, 0.37)).sum();
        assert!((total - 1.0).abs() < 1e-9);
    }

    #[test]
    fn versions_sort_naturally() {
        let mut v = vec![
            "2.1.10",
            "2.1.9",
            "0.171.0",
            "0.171.0-alpha.13",
            "0.171.0-alpha.2",
            "0.169.1",
        ];
        v.sort_by(|a, b| version_cmp(a, b));
        assert_eq!(
            v,
            vec![
                "0.169.1",
                "0.171.0-alpha.2",
                "0.171.0-alpha.13",
                "0.171.0",
                "2.1.9",
                "2.1.10"
            ]
        );
    }

    #[test]
    fn issue_keys_roundtrip() {
        let k = issue_key("polling_tax", "gh run view");
        assert_eq!(parse_issue_key(&k), Some(("polling_tax", "gh run view")));
        assert_eq!(parse_issue_key("harness_divergence:x"), None);
        assert_eq!(
            parse_issue_key("state_dir_bypass:.t3/state"),
            Some(("state_dir_bypass", ".t3/state"))
        );
    }
}
