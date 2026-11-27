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
    /// Largest shape that needs a fix (ignores buckets such as "occasional checks").
    pub fn dominant_shape(&self) -> Option<&ShapeSummary> {
        self.shapes.iter().find(|s| !is_minor_shape(&s.key))
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

/// Shapes that are listed for completeness but need no fix of their own.
pub fn is_minor_shape(key: &str) -> bool {
    matches!(key, "one_off" | "per_item" | "other_filter")
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

    if kind == "output_filtering_tax" {
        return pipe_context(conn, opp, ctx, &sessions, max_episodes);
    }

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
                is_minor_shape(&s.key),
                std::cmp::Reverse(s.calls),
                s.key.clone(),
            )
        });
    }
    Ok(ctx)
}

/// Output-filtering findings: every piped call is classified by what its filter keeps, so shapes
/// cover all matches (no timeline needed) and episodes are picked to show each shape.
fn pipe_context(
    conn: &Connection,
    opp: Option<&Opportunity>,
    mut ctx: FindingContext,
    sessions: &[(&str, Vec<&TraceSample>)],
    max_episodes: usize,
) -> Result<FindingContext> {
    #[derive(Default)]
    struct Acc<'a> {
        sessions: usize,
        calls: usize,
        templates: HashMap<&'a str, usize>,
    }
    let mut acc: HashMap<&'static str, Acc> = HashMap::new();
    let purpose = |s: &TraceSample| pipe_purpose(s.piped_filter.as_deref().unwrap_or(""));
    let mut per_session: Vec<HashMap<&'static str, usize>> = Vec::with_capacity(sessions.len());
    for (_, samples) in sessions {
        let mut counts: HashMap<&'static str, usize> = HashMap::new();
        for s in samples {
            let key = purpose(s);
            *counts.entry(key).or_default() += 1;
            let a = acc.entry(key).or_default();
            a.calls += 1;
            *a.templates.entry(s.cmd_template.as_str()).or_default() += 1;
        }
        for k in counts.keys() {
            acc.entry(k).or_default().sessions += 1;
        }
        per_session.push(counts);
    }

    let rates = piped_rates(opp);
    let top_template: HashMap<&'static str, String> = acc
        .iter()
        .filter_map(|(k, a)| {
            a.templates
                .iter()
                .max_by(|x, y| x.1.cmp(y.1).then_with(|| y.0.cmp(x.0)))
                .map(|(t, _)| (*k, t.to_string()))
        })
        .collect();
    ctx.shapes = acc
        .into_iter()
        .map(|(key, a)| {
            let mut tpls: Vec<(&str, usize)> = a.templates.into_iter().collect();
            tpls.sort_by(|x, y| y.1.cmp(&x.1).then_with(|| x.0.cmp(y.0)));
            let examples: Vec<String> = tpls
                .iter()
                .take(2)
                .map(|(t, n)| match rates.get(*t) {
                    Some((_, runs)) => format!("{t} ({n} of {runs} runs)"),
                    None => format!("{t} ×{n}"),
                })
                .collect();
            let top = tpls.first().map(|(t, _)| *t).unwrap_or("the command");
            let (label, base, fix) = filter_shape_text(key, top);
            ShapeSummary {
                key: key.to_string(),
                label: label.to_string(),
                description: if examples.is_empty() {
                    base
                } else {
                    format!("{base}. Mostly {}", examples.join(", "))
                },
                sessions: a.sessions,
                calls: a.calls,
                fix,
            }
        })
        .collect();
    ctx.shapes.sort_by_key(|s| {
        (
            is_minor_shape(&s.key),
            std::cmp::Reverse(s.calls),
            s.key.clone(),
        )
    });

    // One episode per shape, from the session where that shape is strongest (many calls of the
    // shape's main command, and most of the session's piping), marking only that shape's calls.
    // Shapes repeat round-robin until the episode budget is spent.
    let strength = |i: usize, key: &str| -> (f64, f64) {
        let total = sessions[i].1.len().max(1) as f64;
        let top = top_template.get(key).map(String::as_str).unwrap_or("");
        let n_top = sessions[i]
            .1
            .iter()
            .filter(|s| s.cmd_template == top && purpose(s) == key)
            .count() as f64;
        let n = per_session[i].get(key).copied().unwrap_or(0) as f64;
        (n_top * n_top / total, n * n / total)
    };
    let mut picks: Vec<(usize, &str)> = Vec::new();
    let mut used: HashSet<usize> = HashSet::new();
    'outer: loop {
        let before = picks.len();
        for shape in &ctx.shapes {
            if picks.len() >= max_episodes {
                break 'outer;
            }
            let best = (0..sessions.len())
                .filter(|i| !used.contains(i) && per_session[*i].contains_key(shape.key.as_str()))
                .max_by(|&a, &b| {
                    let (sa, sb) = (strength(a, &shape.key), strength(b, &shape.key));
                    sa.0.total_cmp(&sb.0)
                        .then_with(|| sa.1.total_cmp(&sb.1))
                        .then_with(|| b.cmp(&a))
                });
            if let Some(i) = best {
                used.insert(i);
                picks.push((i, shape.key.as_str()));
            }
        }
        if picks.len() == before {
            break;
        }
    }
    for (i, key) in picks {
        let (sid, samples) = &sessions[i];
        let of_shape: Vec<&TraceSample> = samples
            .iter()
            .copied()
            .filter(|s| purpose(s) == key)
            .collect();
        let timeline = load_timeline(conn, sid)?;
        let marks = mark_matches(&timeline, &of_shape);
        if marks.iter().all(|m| !m) {
            continue;
        }
        ctx.episodes.push(build_episode(
            conn,
            sid,
            &timeline,
            &marks,
            Some(key.to_string()),
        )?);
    }
    Ok(ctx)
}

/// `template -> (piped, runs)` from the analyzer's per-task pipe breakdown.
fn piped_rates(opp: Option<&Opportunity>) -> HashMap<String, (u64, u64)> {
    opp.and_then(|o| o.evidence.get("piped_tasks"))
        .and_then(|v| v.as_array())
        .map(|rows| {
            rows.iter()
                .filter_map(|r| {
                    Some((
                        r.get("template")?.as_str()?.to_string(),
                        (r.get("piped")?.as_u64()?, r.get("runs")?.as_u64()?),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// What an agent wanted from a command's output, judged by the filter it piped into
/// (`tail -1`, `grep -v`, `jq` …). Keys: `few_lines`, `window`, `search`, `strip_noise`,
/// `parse`, `other_filter`.
pub fn pipe_purpose(filter: &str) -> &'static str {
    let mut toks = filter.split_whitespace();
    let bin = toks.next().unwrap_or("");
    let bin = bin.rsplit('/').next().unwrap_or(bin);
    let arg = toks.next().unwrap_or("");
    let short_flag = arg.starts_with('-') && !arg.starts_with("--");
    match bin {
        "jq" | "yq" | "gron" | "fx" | "awk" | "gawk" => "parse",
        "node" | "python" | "python3" | "ruby" | "perl" | "bun" | "deno"
            if short_flag && arg.len() <= 4 =>
        {
            "parse"
        }
        "grep" | "egrep" | "rg" | "ag" | "ack" => {
            if arg == "--invert-match" || (short_flag && arg.contains('v')) {
                "strip_noise"
            } else {
                "search"
            }
        }
        "sed" if arg == "-n" => "window",
        "sed" => "strip_noise",
        "tail" | "head" => match head_tail_lines(arg) {
            Some(n) if n <= 5 => "few_lines",
            _ => "window",
        },
        "cut" | "less" | "more" | "fold" | "column" => "window",
        _ => "other_filter",
    }
}

/// Line count of a `head`/`tail` argument; `None` when it is not visible (`-n` alone, `-c`).
fn head_tail_lines(arg: &str) -> Option<u64> {
    if arg.is_empty() {
        return Some(10);
    }
    let digits = arg
        .strip_prefix("-n")
        .or_else(|| arg.strip_prefix('-'))?
        .trim_start_matches('=');
    digits.parse().ok()
}

/// Short phrase for a [`pipe_purpose`] key, for one-line evidence.
pub fn pipe_purpose_label(key: &str) -> &'static str {
    match key {
        "few_lines" => "keeps ≤5 lines",
        "window" => "bounds long output",
        "search" => "searches output",
        "strip_noise" => "strips noise lines",
        "parse" => "parses output",
        _ => "other filter",
    }
}

fn filter_shape_text(key: &str, target: &str) -> (&'static str, String, String) {
    let t = target;
    match key {
        "few_lines" => (
            "Keeping a few lines",
            "only the last (or first) 1–5 lines are kept: the result is buried in banners, logs or progress"
                .into(),
            format!(
                "Make `{t}` end with one result line (or JSON) on stdout and send banners/progress to stderr{}.",
                if t.starts_with("mise ") {
                    "; set `quiet = true` on the mise task so its `[task] $ …` banner stays out of the output"
                } else {
                    ""
                }
            ),
        ),
        "window" => (
            "Bounding long output",
            "head/tail/sed -n keep a window of output that is too long to read whole".into(),
            format!(
                "Give `{t}` a short default output (a summary plus where the full log is) and a flag such as `--lines N` or `--verbose` for more."
            ),
        ),
        "search" => (
            "Searching output",
            "grep picks out specific lines (failures, names, ids)".into(),
            format!(
                "Add filters to `{t}` for what agents grep for (failures, a name, an id), or a `--json` mode."
            ),
        ),
        "strip_noise" => (
            "Stripping noise",
            "grep -v / sed delete known noise lines (banners, warnings, progress)".into(),
            format!(
                "Stop printing the lines agents strip from `{t}`: send banners, warnings and progress to stderr or behind `--verbose`."
            ),
        ),
        "parse" => (
            "Parsing in a script",
            "jq / awk / node -e / python -c pull fields out of the output".into(),
            format!(
                "Add flags to `{t}` that print the field or summary agents extract, so no script is needed."
            ),
        ),
        _ => (
            "Other filters",
            "pipes into tools that reshape output (sort, wc, tr …)".into(),
            "Look at the examples to see what the filter removes.".into(),
        ),
    }
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

    let keys = call_keys(timeline, marks);
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
        let repeat = match keys[i].as_deref() {
            Some(k) if is_match => {
                let n = seen.entry(k).or_insert(0);
                *n += 1;
                Some(*n)
            }
            _ => None,
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

fn var_ref_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?").expect("valid regex"))
}

fn assign_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?:^|[\s;&|(])([A-Za-z_][A-Za-z0-9_]*)=("(?:[^"\\]|\\.)*"|'[^']*'|\$\([^)]*\)|\S*)"#,
        )
        .expect("valid regex")
    })
}

fn has_substitution(text: &str) -> bool {
    text.contains("$(") || text.contains('`')
}

/// Identity of each matched call, for telling a repeat of the same call from a new one.
///
/// Shell variables are resolved by replaying the assignments seen earlier in the session. A value
/// that comes from command substitution (`SHA=$(git rev-parse …)`) is unknown, so it gets a fresh
/// identity each time it is assigned. A call with an inline `$(…)` matches only the identical call
/// directly before it, because nothing ran in between that could change the result.
fn call_keys(timeline: &[TimelineItem], marks: &[bool]) -> Vec<Option<String>> {
    let mut env: HashMap<String, String> = HashMap::new();
    let mut fresh = 0usize;
    let mut keys = vec![None; timeline.len()];
    let mut prev: Option<(usize, String)> = None;
    for (i, it) in timeline.iter().enumerate() {
        if marks[i] {
            let text = normalize_call(&it.text);
            let resolved = var_ref_re()
                .replace_all(text, |c: &regex::Captures| {
                    env.get(&c[1]).cloned().unwrap_or_else(|| c[0].to_string())
                })
                .into_owned();
            let key = if has_substitution(text) {
                match prev.as_ref() {
                    Some((p, k)) if *p + 1 == i && timeline[*p].text.trim() == text => k.clone(),
                    _ => {
                        fresh += 1;
                        format!("{resolved} \u{1}{fresh}")
                    }
                }
            } else {
                resolved
            };
            prev = Some((i, key.clone()));
            keys[i] = Some(key);
        }
        for c in assign_re().captures_iter(&it.text) {
            let rhs = &c[2];
            let value = if has_substitution(rhs) {
                fresh += 1;
                format!("\u{1}?{fresh}")
            } else {
                var_ref_re()
                    .replace_all(rhs.trim_matches(['"', '\'']), |v: &regex::Captures| {
                        env.get(&v[1]).cloned().unwrap_or_else(|| v[0].to_string())
                    })
                    .into_owned()
            };
            env.insert(c[1].to_string(), value);
        }
    }
    keys
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
    let keys = call_keys(timeline, marks);
    let key = |i: usize| keys[i].as_deref().unwrap_or("");
    let gaps: Vec<usize> = idx.windows(2).map(|w| w[1] - w[0] - 1).collect();
    let tight = idx
        .windows(2)
        .zip(&gaps)
        .filter(|(w, g)| **g <= 1 && call_target(key(w[0])) == call_target(key(w[1])))
        .count();
    if n >= 3 && tight * 2 >= n - 1 {
        return "tight_retry";
    }
    // Back-to-back calls on different targets: one call per job/target where one could cover all.
    let mut clustered: HashSet<usize> = HashSet::new();
    for (w, g) in idx.windows(2).zip(&gaps) {
        if *g <= 1 && call_target(key(w[0])) != call_target(key(w[1])) {
            clustered.insert(w[0]);
            clustered.insert(w[1]);
        }
    }
    if clustered.len() >= 3 && clustered.len() * 2 >= n {
        return "fan_out";
    }
    // (Almost) every call waits on something new: a new id, or a variable reassigned in between.
    let distinct_keys: HashSet<&str> = idx.iter().map(|&i| key(i)).collect();
    if (n - distinct_keys.len()) * 4 < n {
        return "per_item";
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
            "several jobs/targets are checked back to back, one call each, instead of one call for all"
                .into(),
            if repo_scope {
                format!(
                    "Make one call of `{t}` cover every job/target (a batch or `--all` form) and show that form in AGENTS.md."
                )
            } else {
                "Expected with parallel work; batch the checks where the harness allows.".into()
            },
        ),
        "per_item" => (
            "One wait per item",
            "(almost) every call waits on something new (a new id, or a variable like $SHA reassigned in between), one at a time: not a retry loop"
                .into(),
            "No change needed: each call already waits once per item.".into(),
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
        assert_eq!(classify_polling(&tl, &marks), "per_item");

        let tl = vec![
            item(1, "ci status --wait --target web"),
            item(1, "ci status --wait --target ios"),
            item(1, "ci status --wait --target desktop"),
            item(2, "git log"),
        ];
        assert_eq!(classify_polling(&tl, &[true, true, true, false]), "fan_out");

        let tl = vec![
            item(1, "codex-wait"),
            item(2, "codex-wait"),
            item(3, "codex-wait"),
        ];
        assert_eq!(classify_polling(&tl, &[true, true, true]), "tight_retry");
    }

    #[test]
    fn pipe_purpose_reads_the_filter() {
        for (f, want) in [
            ("tail -1", "few_lines"),
            ("tail -n1", "few_lines"),
            ("head -2", "few_lines"),
            ("tail -40", "window"),
            ("tail -n", "window"),
            ("head", "window"),
            ("sed -n", "window"),
            ("grep -E", "search"),
            ("grep -c", "search"),
            ("grep -v", "strip_noise"),
            ("grep -Ev", "strip_noise"),
            ("sed -e", "strip_noise"),
            ("jq .status", "parse"),
            ("node -e", "parse"),
            ("python3 -c", "parse"),
            ("wc -l", "other_filter"),
        ] {
            assert_eq!(pipe_purpose(f), want, "{f}");
        }
    }

    #[test]
    fn reassigned_variables_are_new_values_not_repeats() {
        // Each wait reads $SHA, which is re-derived from git right before: one wait per merge.
        let wait = r#"mise run ci:status -- --wait --revision "$SHA""#;
        let tl = vec![
            item(1, "SHA=$(git rev-parse origin/main)"),
            item(1, wait),
            item(5, "gh pr merge 1"),
            item(6, "SHA=$(git rev-parse origin/main)"),
            item(6, wait),
            item(9, "gh pr merge 2"),
            item(10, "SHA=$(git rev-parse origin/main)"),
            item(10, wait),
        ];
        let marks: Vec<bool> = tl.iter().map(|t| t.text == wait).collect();
        assert_eq!(classify_polling(&tl, &marks), "per_item");
        let ep = build_episode_for_test(&tl, &marks);
        let repeats: Vec<Option<usize>> = ep
            .iter()
            .filter(|l| l.role == LineRole::Match)
            .map(|l| l.repeat)
            .collect();
        assert_eq!(repeats, vec![Some(1), Some(1), Some(1)]);

        // A literal value, or a variable that is never reassigned, still repeats.
        let tl = vec![
            item(1, "S=/tmp/run"),
            item(2, "job wait $S/a"),
            item(3, "job wait $S/a"),
            item(4, "S=/tmp/run"),
            item(5, "job wait $S/a"),
        ];
        let marks = vec![false, true, true, false, true];
        assert_eq!(classify_polling(&tl, &marks), "tight_retry");

        // Inline substitution: only a back-to-back identical call is the same call.
        let tl = vec![
            item(1, "job wait $(cat id)"),
            item(2, "job wait $(cat id)"),
            item(3, "echo id > x"),
            item(4, "job wait $(cat id)"),
        ];
        let keys = call_keys(&tl, &[true, true, false, true]);
        assert_eq!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[3]);
    }

    fn build_episode_for_test(tl: &[TimelineItem], marks: &[bool]) -> Vec<EpisodeLine> {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE sessions (session_id TEXT, agent_kind TEXT, started_at INTEGER,
                                    git_branch TEXT, turn_count INTEGER);",
        )
        .unwrap();
        build_episode(&conn, "s", tl, marks, None).unwrap().lines
    }

    #[test]
    fn gap_summarises_bins() {
        let g = gap_line(&[item(1, "rg a"), item(1, "rg b"), item(2, "sed c")]);
        assert_eq!(g.role, LineRole::Gap);
        assert_eq!(g.text, "3 other calls: rg ×2, sed");
    }
}
