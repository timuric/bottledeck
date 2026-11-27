//! Finding context: turns the raw occurrences behind a finding into per-session *episodes*
//! (the matched calls plus what the agent did around them) and, where the detector supports it,
//! *shapes* — distinct behaviours that share one finding row but need different fixes.

use crate::analyze::{Opportunity, TraceSample, match_finding_samples};
use crate::config::TimeRange;
use anyhow::Result;
use chrono::{DateTime, Local};
use regex::Regex;
use rusqlite::{Connection, params};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::OnceLock;

/// Matched calls rendered per episode before the rest collapse into a "more" line.
const MAX_MATCHES_PER_EPISODE: usize = 12;
/// Upper bound on sessions scanned to classify shapes.
const MAX_SHAPE_SESSIONS: usize = 80;

#[derive(Debug, Clone, Default, Serialize)]
pub struct FindingContext {
    /// Distinct sessions with at least one occurrence.
    pub affected_sessions: usize,
    pub total_matches: usize,
    /// Most-affected sessions first.
    pub episodes: Vec<Episode>,
    /// Behaviour variants, largest first. Empty when the finding kind has no shape detector.
    pub shapes: Vec<ShapeSummary>,
}

impl FindingContext {
    /// Largest shape that is an actual loop (ignores the "occasional checks" bucket).
    pub fn dominant_shape(&self) -> Option<&ShapeSummary> {
        self.shapes.iter().find(|s| s.key != "one_off")
    }

    /// The episode that best illustrates the finding: one of the dominant shape, if any.
    pub fn representative(&self) -> Option<&Episode> {
        let dominant = self.dominant_shape().map(|s| s.key.as_str());
        dominant
            .and_then(|k| self.episodes.iter().find(|e| e.shape.as_deref() == Some(k)))
            .or_else(|| self.episodes.first())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Episode {
    pub session_id: String,
    pub agent_kind: String,
    /// Local start time, `YYYY-MM-DD HH:MM`.
    pub started_at: String,
    pub git_branch: Option<String>,
    pub turn_count: i64,
    pub matched: usize,
    pub first_turn: i64,
    pub last_turn: i64,
    pub shape: Option<String>,
    pub lines: Vec<EpisodeLine>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LineRole {
    /// An occurrence of the finding.
    Match,
    /// A neighbouring call shown in full (what led into / out of a match).
    Context,
    /// Several unrelated calls folded into one summary line.
    Gap,
    /// Remaining matches not rendered.
    More,
}

#[derive(Debug, Clone, Serialize)]
pub struct EpisodeLine {
    pub role: LineRole,
    pub turn_idx: Option<i64>,
    pub text: String,
    pub exit_code: Option<i64>,
    pub stderr: Option<String>,
    /// For `Match` lines: 1-based repeat count of an identical earlier call in this episode.
    pub repeat: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShapeSummary {
    pub key: String,
    pub label: String,
    pub description: String,
    pub sessions: usize,
    pub calls: usize,
    pub fix: String,
}

#[derive(Debug, Clone)]
struct TimelineItem {
    turn_idx: i64,
    started_at: i64,
    seq: i64,
    text: String,
    /// Short label used when the item is folded into a gap summary.
    bin: String,
    key: String,
    exit_code: Option<i64>,
    stderr: Option<String>,
}

/// Context for a finding the caller already has (no full repo re-analysis).
pub fn finding_context(
    conn: &Connection,
    repo_id: &str,
    opp: &Opportunity,
    range: &TimeRange,
    max_episodes: usize,
) -> Result<FindingContext> {
    let matched = match_finding_samples(conn, repo_id, Some(opp), &opp.id, range)?;
    build_finding_context(conn, Some(opp), &matched, max_episodes)
}

pub fn build_finding_context(
    conn: &Connection,
    opp: Option<&Opportunity>,
    matched: &[TraceSample],
    max_episodes: usize,
) -> Result<FindingContext> {
    let mut by_session: HashMap<&str, Vec<&TraceSample>> = HashMap::new();
    for s in matched.iter().filter(|s| !s.session_id.is_empty()) {
        by_session.entry(s.session_id.as_str()).or_default().push(s);
    }
    let mut ctx = FindingContext {
        affected_sessions: by_session.len(),
        total_matches: matched.len(),
        ..Default::default()
    };

    // Session-level findings (cache, handoff, aborts) have no call sequence to show.
    let kind = opp.map(|o| o.kind.as_str()).unwrap_or("");
    if matches!(
        kind,
        "context_handoff_bloat"
            | "low_cache_efficiency"
            | "context_pressure"
            | "session_abort_rate"
    ) {
        return Ok(ctx);
    }

    let mut sessions: Vec<(&str, Vec<&TraceSample>)> = by_session.into_iter().collect();
    sessions.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(b.0)));

    let classify = kind == "polling_tax";
    let scan = if classify {
        sessions.len().min(MAX_SHAPE_SESSIONS)
    } else {
        sessions.len().min(max_episodes)
    };

    let mut shape_acc: BTreeMap<&'static str, (usize, usize)> = BTreeMap::new();
    for (sid, samples) in sessions.iter().take(scan) {
        let timeline = load_timeline(conn, sid)?;
        let marks = mark_matches(&timeline, samples);
        if marks.iter().all(|m| !m) {
            continue;
        }
        let shape = if classify {
            let sh = classify_polling(&timeline, &marks);
            let e = shape_acc.entry(sh).or_default();
            e.0 += 1;
            e.1 += marks.iter().filter(|m| **m).count();
            Some(sh)
        } else {
            None
        };
        if ctx.episodes.len() < max_episodes {
            ctx.episodes.push(build_episode(
                conn,
                sid,
                &timeline,
                &marks,
                shape.map(str::to_string),
            )?);
        }
    }

    if classify {
        let target = opp.map(|o| o.target.as_str()).unwrap_or("");
        let repo_scope = opp.is_some_and(|o| o.scope == "repo");
        ctx.shapes = shape_acc
            .into_iter()
            .map(|(key, (sessions, calls))| {
                let (label, description, fix) = polling_shape_text(key, target, repo_scope);
                ShapeSummary {
                    key: key.to_string(),
                    label: label.to_string(),
                    description,
                    sessions,
                    calls,
                    fix,
                }
            })
            .collect();
        ctx.shapes.sort_by_key(|s| {
            (
                s.key == "one_off",
                std::cmp::Reverse(s.calls),
                s.key.clone(),
            )
        });
    }
    Ok(ctx)
}

struct SpanCols {
    turn: i64,
    seq: i64,
    ts: i64,
    bin: String,
    raw: String,
    exit: Option<i64>,
    stderr: Option<String>,
    source: String,
    pipe: Option<String>,
}

fn load_timeline(conn: &Connection, session_id: &str) -> Result<Vec<TimelineItem>> {
    let mut items = Vec::new();

    let mut stmt = conn.prepare(
        "SELECT turn_idx, seq_idx, started_at, cmd_bin, raw_redacted, exit_code, stderr_preview,
                source_kind, piped_filter
         FROM command_spans WHERE session_id = ?1",
    )?;
    let rows: Vec<SpanCols> = stmt
        .query_map(params![session_id], |r| {
            Ok(SpanCols {
                turn: r.get(0)?,
                seq: r.get(1)?,
                ts: r.get(2)?,
                bin: r.get(3)?,
                raw: r.get(4)?,
                exit: r.get(5)?,
                stderr: r.get(6)?,
                source: r.get(7)?,
                pipe: r.get(8)?,
            })
        })?
        .flatten()
        .collect();
    // Wrapper-captured spans duplicate transcript spans when both exist.
    let has_transcript = rows.iter().any(|r| r.source != "wrap");
    for SpanCols {
        turn,
        seq,
        ts,
        bin,
        raw,
        exit,
        stderr,
        source,
        pipe,
    } in rows
    {
        if has_transcript && source == "wrap" {
            continue;
        }
        // The stored command stops before the pipe; show the filter the agent added.
        let mut text = one_line(&raw);
        if let Some(p) = pipe.filter(|p| !p.is_empty()) {
            text = format!("{text} | {p}");
        }
        items.push(TimelineItem {
            turn_idx: turn,
            started_at: ts,
            seq,
            key: format!("cmd:{raw}"),
            text,
            bin,
            exit_code: exit,
            stderr: stderr
                .as_deref()
                .map(crate::shell::clean_error_preview)
                .filter(|s| !s.is_empty()),
        });
    }

    let mut stmt = conn.prepare(
        "SELECT turn_idx, seq_idx, started_at, tool_name, target_path, is_error, error_preview
         FROM tool_calls WHERE session_id = ?1",
    )?;
    let rows = stmt.query_map(params![session_id], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, Option<String>>(4)?,
            r.get::<_, i64>(5)? != 0,
            r.get::<_, Option<String>>(6)?,
        ))
    })?;
    for (turn, seq, ts, name, target, is_err, err) in rows.flatten() {
        let label = short_tool(&name);
        let text = match &target {
            Some(t) if !t.is_empty() => format!("{label} {t}"),
            _ => label.clone(),
        };
        items.push(TimelineItem {
            turn_idx: turn,
            started_at: ts,
            seq,
            key: format!("tool:{name}"),
            text,
            bin: label,
            exit_code: if is_err { Some(1) } else { None },
            stderr: err
                .as_deref()
                .map(crate::shell::clean_error_preview)
                .filter(|s| !s.is_empty()),
        });
    }

    items.sort_by_key(|a| (a.turn_idx, a.started_at, a.seq));
    Ok(items)
}

fn one_line(text: &str) -> String {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let first = lines.next().unwrap_or("").trim_end().to_string();
    if lines.next().is_some() {
        format!("{first} …")
    } else {
        first
    }
}

fn short_tool(name: &str) -> String {
    if let Some(rest) = name.strip_prefix("mcp:")
        && let Some((srv, tool)) = rest.split_once(':')
    {
        return format!("{srv}/{tool}");
    }
    name.to_string()
}

/// Flags timeline items that correspond to a matched occurrence.
fn mark_matches(timeline: &[TimelineItem], samples: &[&TraceSample]) -> Vec<bool> {
    let mut marks = vec![false; timeline.len()];
    let mut by_instant: HashMap<(i64, i64), Vec<usize>> = HashMap::new();
    for (i, it) in timeline.iter().enumerate() {
        by_instant
            .entry((it.turn_idx, it.started_at))
            .or_default()
            .push(i);
    }
    for s in samples {
        let fits = |i: usize| -> bool {
            match s.match_text.as_deref() {
                None => true,
                // File reads are derived from a command or a Read tool call: match on the file name.
                Some(k) if k.starts_with("read:") => {
                    let path = &k[5..];
                    let base = path.rsplit('/').next().unwrap_or(path);
                    !base.is_empty() && timeline[i].text.contains(base)
                }
                Some(k) => timeline[i].key == k,
            }
        };
        let exact = by_instant
            .get(&(s.turn_idx, s.started_ms))
            .and_then(|c| c.iter().copied().find(|&i| !marks[i] && fits(i)));
        // Timestamps can drift between tables; fall back to the same turn.
        let pick = exact.or_else(|| {
            timeline
                .iter()
                .enumerate()
                .find(|(i, it)| it.turn_idx == s.turn_idx && !marks[*i] && fits(*i))
                .map(|(i, _)| i)
        });
        if let Some(i) = pick {
            marks[i] = true;
        }
    }
    marks
}

fn build_episode(
    conn: &Connection,
    session_id: &str,
    timeline: &[TimelineItem],
    marks: &[bool],
    shape: Option<String>,
) -> Result<Episode> {
    let (agent_kind, started_ms, git_branch, turn_count): (String, Option<i64>, Option<String>, i64) =
        conn.query_row(
            "SELECT agent_kind, started_at, git_branch, turn_count FROM sessions WHERE session_id = ?1",
            params![session_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap_or_else(|_| ("unknown".into(), None, None, 0));
    let started_at = started_ms
        .and_then(DateTime::from_timestamp_millis)
        .map(|d| d.with_timezone(&Local).format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_default();

    let match_idx: Vec<usize> = (0..timeline.len()).filter(|&i| marks[i]).collect();
    let shown_matches: Vec<usize> = match_idx
        .iter()
        .copied()
        .take(MAX_MATCHES_PER_EPISODE)
        .collect();

    // Show each match, the call right before it, and the call right after the last shown match.
    let mut show: Vec<usize> = Vec::new();
    for &m in &shown_matches {
        if m > 0 && !marks[m - 1] {
            show.push(m - 1);
        }
        show.push(m);
    }
    if let Some(&last) = shown_matches.last()
        && last + 1 < timeline.len()
        && !marks[last + 1]
        && shown_matches.len() == match_idx.len()
    {
        show.push(last + 1);
    }
    show.sort_unstable();
    show.dedup();

    let mut lines = Vec::new();
    let mut seen: HashMap<&str, usize> = HashMap::new();
    let mut prev: Option<usize> = None;
    for &i in &show {
        if let Some(p) = prev
            && i > p + 1
        {
            lines.push(gap_line(&timeline[p + 1..i]));
        }
        let it = &timeline[i];
        let is_match = marks[i];
        let repeat = if is_match {
            let n = seen.entry(normalize_call(&it.text)).or_insert(0);
            *n += 1;
            Some(*n)
        } else {
            None
        };
        lines.push(EpisodeLine {
            role: if is_match {
                LineRole::Match
            } else {
                LineRole::Context
            },
            turn_idx: Some(it.turn_idx),
            text: it.text.clone(),
            exit_code: it.exit_code,
            stderr: it.stderr.clone(),
            repeat,
        });
        prev = Some(i);
    }
    let hidden = match_idx.len() - shown_matches.len();
    if hidden > 0 {
        let from = timeline[match_idx[shown_matches.len()]].turn_idx;
        let to = timeline[*match_idx.last().unwrap()].turn_idx;
        lines.push(EpisodeLine {
            role: LineRole::More,
            turn_idx: None,
            text: format!("{hidden} more matched calls over turns {from}–{to}"),
            exit_code: None,
            stderr: None,
            repeat: None,
        });
    }

    Ok(Episode {
        session_id: session_id.to_string(),
        agent_kind,
        started_at,
        git_branch: git_branch.filter(|b| !b.is_empty()),
        turn_count,
        matched: match_idx.len(),
        first_turn: match_idx
            .first()
            .map(|&i| timeline[i].turn_idx)
            .unwrap_or(0),
        last_turn: match_idx.last().map(|&i| timeline[i].turn_idx).unwrap_or(0),
        shape,
        lines,
    })
}

fn gap_line(items: &[TimelineItem]) -> EpisodeLine {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for it in items {
        *counts.entry(it.bin.as_str()).or_default() += 1;
    }
    let mut top: Vec<(&str, usize)> = counts.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    let mut parts: Vec<String> = top
        .iter()
        .take(3)
        .map(|(b, n)| {
            if *n > 1 {
                format!("{b} ×{n}")
            } else {
                b.to_string()
            }
        })
        .collect();
    if top.len() > 3 {
        parts.push("…".into());
    }
    let noun = if items.len() == 1 { "call" } else { "calls" };
    EpisodeLine {
        role: LineRole::Gap,
        turn_idx: items.first().map(|i| i.turn_idx),
        text: format!("{} other {noun}: {}", items.len(), parts.join(", ")),
        exit_code: None,
        stderr: None,
        repeat: None,
    }
}

/// Collapses volatile flags so repeats of "the same call" compare equal.
fn normalize_call(text: &str) -> &str {
    text.trim()
}

fn timeout_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"--timeout[ =](\d+)").expect("valid regex"))
}

/// Strips flags so `wait <id> --done` and `wait <id> --timeout 1` count as the same target.
fn call_target(text: &str) -> String {
    text.split_whitespace()
        .filter(|t| !t.starts_with('-') && t.parse::<f64>().is_err())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Shape of one session's polling: why the agent called the wait/status command repeatedly.
fn classify_polling(timeline: &[TimelineItem], marks: &[bool]) -> &'static str {
    let idx: Vec<usize> = (0..timeline.len()).filter(|&i| marks[i]).collect();
    let n = idx.len();
    if n <= 2 {
        return "one_off";
    }
    let short_timeout = idx
        .iter()
        .filter(|&&i| {
            timeout_re()
                .captures(&timeline[i].text)
                .and_then(|c| c[1].parse::<u64>().ok())
                .is_some_and(|t| t <= 5)
        })
        .count();
    if short_timeout >= 2 && short_timeout * 2 >= n {
        return "short_timeout";
    }
    let targets: HashSet<String> = idx
        .iter()
        .map(|&i| call_target(&timeline[i].text))
        .collect();
    let gaps: Vec<usize> = idx.windows(2).map(|w| w[1] - w[0] - 1).collect();
    let tight = idx
        .windows(2)
        .zip(&gaps)
        .filter(|(w, g)| {
            **g <= 1 && call_target(&timeline[w[0]].text) == call_target(&timeline[w[1]].text)
        })
        .count();
    if n >= 3 && tight * 2 >= n - 1 {
        return "tight_retry";
    }
    let avg_gap = if gaps.is_empty() {
        0.0
    } else {
        gaps.iter().sum::<usize>() as f64 / gaps.len() as f64
    };
    if targets.len() >= 3 && avg_gap >= 2.0 {
        return "fan_out";
    }
    "repeat_check"
}

fn polling_shape_text(key: &str, target: &str, repo_scope: bool) -> (&'static str, String, String) {
    let t = if target.is_empty() {
        "the command"
    } else {
        target
    };
    match key {
        "short_timeout" => (
            "Short-timeout retry",
            "the call passes --timeout ≤ 5s, returns before the work finishes, and is called again"
                .into(),
            if repo_scope {
                format!(
                    "Make `{t}` reject or raise timeouts under ~30s (or warn loudly), and show the blocking form in AGENTS.md."
                )
            } else {
                "Give the harness a longer default exec timeout so it stops passing tiny timeouts."
                    .into()
            },
        ),
        "tight_retry" => (
            "Tight retry",
            "the same call is repeated back-to-back with no work in between".into(),
            if repo_scope {
                format!(
                    "Make `{t}` block until the work is done, or print when to check next, so one call is enough."
                )
            } else {
                "Avoid background/interactive jobs here, or raise the exec timeout so the harness waits once.".into()
            },
        ),
        "fan_out" => (
            "Fan-out check-ins",
            "several jobs are started and each is checked between other work".into(),
            if repo_scope {
                format!(
                    "Add a batch form of `{t}` (e.g. wait on all running jobs) so one call covers the fan-out."
                )
            } else {
                "Expected with parallel work; batch the checks where the harness allows.".into()
            },
        ),
        "one_off" => (
            "Occasional checks",
            "only 1–2 calls in the session; not a loop".into(),
            "No change needed for these sessions.".into(),
        ),
        _ => (
            "Repeated checks",
            "the call recurs across the session without a clearer pattern".into(),
            if repo_scope {
                format!("Make `{t}` block until done, or print a clear wait/notify hint.")
            } else {
                "Raise the exec timeout or avoid background jobs so the harness waits once.".into()
            },
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(turn: i64, text: &str) -> TimelineItem {
        TimelineItem {
            turn_idx: turn,
            started_at: turn,
            seq: 0,
            text: text.into(),
            bin: text.split_whitespace().next().unwrap_or("").into(),
            key: format!("cmd:{text}"),
            exit_code: None,
            stderr: None,
        }
    }

    #[test]
    fn classifies_short_timeout_polling() {
        let tl = vec![
            item(1, "mise run job -- wait a --timeout 1"),
            item(2, "rg foo"),
            item(3, "mise run job -- wait a --timeout 1"),
            item(4, "mise run job -- wait a --timeout 1"),
        ];
        let marks = vec![true, false, true, true];
        assert_eq!(classify_polling(&tl, &marks), "short_timeout");
    }

    #[test]
    fn classifies_fan_out_and_tight_retry() {
        let tl = vec![
            item(1, "job wait a --done"),
            item(2, "rg x"),
            item(3, "sed y"),
            item(4, "job wait b --done"),
            item(5, "git diff"),
            item(6, "cat z"),
            item(7, "job wait c --done"),
        ];
        let marks = vec![true, false, false, true, false, false, true];
        assert_eq!(classify_polling(&tl, &marks), "fan_out");

        let tl = vec![
            item(1, "codex-wait"),
            item(2, "codex-wait"),
            item(3, "codex-wait"),
        ];
        assert_eq!(classify_polling(&tl, &[true, true, true]), "tight_retry");
    }

    #[test]
    fn gap_summarises_bins() {
        let g = gap_line(&[item(1, "rg a"), item(1, "rg b"), item(2, "sed c")]);
        assert_eq!(g.role, LineRole::Gap);
        assert_eq!(g.text, "3 other calls: rg ×2, sed");
    }
}
