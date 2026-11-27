use crate::analyze::issues::{
    IssueTrack, IssuesReport, SessionCell, Verdict, add_marker, format_ago, issue_key,
    list_markers, remove_marker, track_issues,
};
use crate::analyze::{
    CommandStat, FleetReport, InspectResult, Opportunity, RepoReport, analyze_fleet, analyze_repo,
    format_compact, format_duration_human, inspect_finding,
};
use crate::config::{AdapterRoots, TimeRange, parse_window_ms};
use crate::ingest::sync_all;
use crate::patterns::{
    CrossSessionPatternsReport, HarnessBreakdown, ToolStat, analyze_cross_session_patterns,
};
use crate::report::{format_diagnosis_prompt, format_repo_report};
use crate::shell::clean_error_preview;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Clear, Padding, Paragraph, Row, Table, TableState, Wrap,
};
use rusqlite::Connection;
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

const WINDOWS: &[&str] = &["24h", "7d", "14d", "30d", "all"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Drawer,
    Main,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailTab {
    Insights = 0,
    Patterns = 1,
    Harnesses = 2,
    Commands = 3,
    Brief = 4,
    Issues = 5,
}

const TAB_COUNT: usize = 6;

impl DetailTab {
    fn titles() -> [&'static str; TAB_COUNT] {
        [
            "1 Insights",
            "2 Patterns",
            "3 Harnesses",
            "4 Commands",
            "5 Brief",
            "6 Issues",
        ]
    }

    fn next(self) -> Self {
        Self::from_index((self as usize + 1) % TAB_COUNT)
    }

    fn prev(self) -> Self {
        Self::from_index((self as usize + TAB_COUNT - 1) % TAB_COUNT)
    }

    fn from_index(i: usize) -> Self {
        match i % TAB_COUNT {
            0 => Self::Insights,
            1 => Self::Patterns,
            2 => Self::Harnesses,
            3 => Self::Commands,
            4 => Self::Brief,
            _ => Self::Issues,
        }
    }
}

/// Issue tracking needs history: never judge recurrence on less than 30 days.
fn issues_window(label: &str) -> &'static str {
    match label {
        "all" => "all",
        _ => "30d",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeFilter {
    All,
    Repo,
    Harness,
}

impl ScopeFilter {
    fn next(self) -> Self {
        match self {
            Self::All => Self::Repo,
            Self::Repo => Self::Harness,
            Self::Harness => Self::All,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::All => "All issues",
            Self::Repo => "Repo harness",
            Self::Harness => "Agent runtime",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternsView {
    Workflows,
    Storms,
    Drift,
}

impl PatternsView {
    fn next(self) -> Self {
        match self {
            Self::Workflows => Self::Storms,
            Self::Storms => Self::Drift,
            Self::Drift => Self::Workflows,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandsView {
    Tokens,
    Wait,
    Errors,
    Mcp,
}

impl CommandsView {
    fn next(self) -> Self {
        match self {
            Self::Tokens => Self::Wait,
            Self::Wait => Self::Errors,
            Self::Errors => Self::Mcp,
            Self::Mcp => Self::Tokens,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BriefMode {
    Prompt,
    Yaml,
}

impl BriefMode {
    fn toggle(self) -> Self {
        match self {
            Self::Prompt => Self::Yaml,
            Self::Yaml => Self::Prompt,
        }
    }
}

#[derive(Debug, Clone)]
struct MergedInsight {
    primary: Opportunity,
    related: Vec<Opportunity>,
}

#[derive(Debug, Clone)]
struct HarnessRowSummary {
    agent_kind: String,
    label: String,
    sessions: usize,
    commands: usize,
    tool_calls: usize,
    median_total_tokens: i64,
    est_cost_usd: f64,
    weighted_cache_hit: Option<f64>,
    avg_output_kb: f64,
    truncated_outputs: usize,
    truncated_sessions_pct: f64,
    median_tool_wait_s: f64,
    avg_api_wait_s: Option<f64>,
    error_rate: f64,
    rebound_rate: f64,
    top_friction_cmds: Vec<String>,
}

#[derive(Debug, Clone)]
enum HarnessIssueItem {
    Opp(MergedInsight),
    McpTool(ToolStat),
}

pub struct App {
    pub window_idx: usize,
    pub focus: Focus,
    pub sidebar_open: bool,
    pub tab: DetailTab,
    pub scope_filter: ScopeFilter,
    pub patterns_view: PatternsView,
    pub commands_view: CommandsView,
    pub brief_mode: BriefMode,
    pub harness_show_strata: bool,
    pub harness_focus_issues: bool,
    pub show_help: bool,
    pub fleet: FleetReport,
    pub repo_state: TableState,
    pub selected_repo: Option<RepoReport>,
    pub selected_patterns: Option<CrossSessionPatternsReport>,
    pub opp_state: TableState,
    pub pattern_state: TableState,
    pub harness_state: TableState,
    pub harness_issue_state: TableState,
    pub cmd_state: TableState,
    pub brief_scroll: u16,
    pub cached_brief: String,
    pub modal: Option<InspectResult>,
    pub modal_scroll: u16,
    /// Lazily computed when the Issues tab is first shown for the selected repo.
    pub issues: Option<IssuesReport>,
    pub issues_state: TableState,
    pub issues_open_only: bool,
    pub status_msg: String,
    pub update_available: Option<String>,
    pub should_quit: bool,
}

impl App {
    pub fn load(
        conn: &Connection,
        initial_window: &str,
        initial_repo_id: Option<&str>,
    ) -> Result<Self> {
        let window_idx = WINDOWS
            .iter()
            .position(|w| w.eq_ignore_ascii_case(initial_window))
            .unwrap_or(2);
        let win_label = WINDOWS[window_idx];
        let range = TimeRange::from_window(parse_window_ms(win_label)?, win_label);
        let fleet = analyze_fleet(conn, &range, false)?;

        let mut repo_state = TableState::default();
        let selected_idx =
            if let Some(target_id) = initial_repo_id {
                fleet.repos.iter().position(|r| r.repo_id == target_id).or(
                    if fleet.repos.is_empty() {
                        None
                    } else {
                        Some(0)
                    },
                )
            } else if fleet.repos.is_empty() {
                None
            } else {
                Some(0)
            };
        repo_state.select(selected_idx);

        let selected_repo = selected_idx
            .and_then(|i| fleet.repos.get(i))
            .and_then(|r| analyze_repo(conn, &r.repo_id, &range, 16).ok());
        let selected_patterns = selected_idx
            .and_then(|i| fleet.repos.get(i))
            .and_then(|r| analyze_cross_session_patterns(conn, &r.repo_id, &range).ok());

        let status_msg = format!(
            "{} repo(s) · {} sessions",
            fleet.totals.repos, fleet.totals.sessions
        );

        let mut app = Self {
            window_idx,
            focus: Focus::Main,
            sidebar_open: false,
            tab: DetailTab::Insights,
            scope_filter: ScopeFilter::All,
            patterns_view: PatternsView::Workflows,
            commands_view: CommandsView::Tokens,
            brief_mode: BriefMode::Prompt,
            harness_show_strata: false,
            harness_focus_issues: false,
            show_help: false,
            fleet,
            repo_state,
            selected_repo,
            selected_patterns,
            opp_state: TableState::default(),
            pattern_state: TableState::default(),
            harness_state: TableState::default(),
            harness_issue_state: TableState::default(),
            cmd_state: TableState::default(),
            brief_scroll: 0,
            cached_brief: String::new(),
            modal: None,
            modal_scroll: 0,
            issues: None,
            issues_state: TableState::default(),
            issues_open_only: false,
            status_msg,
            update_available: crate::update::cached_available_update(),
            should_quit: false,
        };
        app.reset_tab_selections();
        app.refresh_cached_brief();
        Ok(app)
    }

    pub fn window_label(&self) -> &'static str {
        WINDOWS[self.window_idx]
    }

    fn reset_tab_selections(&mut self) {
        self.brief_scroll = 0;
        self.harness_focus_issues = false;
        let insights_len = self.visible_insights().len();
        self.opp_state
            .select(if insights_len > 0 { Some(0) } else { None });
        let pat_len = self.visible_pattern_count();
        self.pattern_state
            .select(if pat_len > 0 { Some(0) } else { None });
        let h_len = self.visible_harness_rows().len();
        self.harness_state
            .select(if h_len > 0 { Some(0) } else { None });
        let hi_len = self.selected_harness_issues().len();
        self.harness_issue_state
            .select(if hi_len > 0 { Some(0) } else { None });
        let c_len = self.visible_command_count();
        self.cmd_state
            .select(if c_len > 0 { Some(0) } else { None });
    }

    fn refresh_cached_brief(&mut self) {
        self.cached_brief = match (
            self.brief_mode,
            &self.selected_repo,
            &self.selected_patterns,
        ) {
            (BriefMode::Prompt, Some(r), Some(p)) => format_diagnosis_prompt(r, p),
            (_, Some(r), _) => format_repo_report(r, "llm"),
            _ => "No repository selected.".to_string(),
        };
    }

    fn visible_insights(&self) -> Vec<MergedInsight> {
        let Some(repo) = &self.selected_repo else {
            return Vec::new();
        };
        let mut raw: Vec<&Opportunity> = match self.scope_filter {
            ScopeFilter::Repo => repo.opportunities.iter().collect(),
            ScopeFilter::Harness => repo.harness_overhead.iter().collect(),
            ScopeFilter::All => repo
                .opportunities
                .iter()
                .chain(repo.harness_overhead.iter())
                .collect(),
        };
        if self.scope_filter == ScopeFilter::All {
            raw.sort_by_key(|o| std::cmp::Reverse(o.score));
        }
        merge_opportunities(&raw)
    }

    fn visible_harness_rows(&self) -> Vec<HarnessRowSummary> {
        let Some(pat) = &self.selected_patterns else {
            return Vec::new();
        };
        if self.harness_show_strata {
            return pat
                .harness_comparison
                .iter()
                .map(|h| {
                    let short = short_harness(&h.agent_kind);
                    let label = if h.originator != "default" && !h.originator.is_empty() {
                        format!(
                            "{short} ({} · {})",
                            h.role,
                            truncate_ellipsis(&h.originator, 12)
                        )
                    } else {
                        format!("{short} ({})", h.role)
                    };
                    HarnessRowSummary {
                        agent_kind: h.agent_kind.clone(),
                        label,
                        sessions: h.sessions,
                        commands: h.commands,
                        tool_calls: h.tool_calls,
                        median_total_tokens: h.median_total_tokens,
                        est_cost_usd: h.est_cost_usd,
                        weighted_cache_hit: h.weighted_cache_hit,
                        avg_output_kb: h.avg_output_kb,
                        truncated_outputs: h.truncated_outputs,
                        truncated_sessions_pct: h.truncated_sessions_pct,
                        median_tool_wait_s: h.median_tool_wall_s,
                        avg_api_wait_s: h.avg_api_wait_s,
                        error_rate: h.error_rate,
                        rebound_rate: h.rebound_rate,
                        top_friction_cmds: h.top_friction_cmds.clone(),
                    }
                })
                .collect();
        }

        // Grouped view: 1 clean summary row per agent harness (codex, claude, antigravity, kimi)
        let mut by_ag: BTreeMap<String, Vec<&HarnessBreakdown>> = BTreeMap::new();
        for h in &pat.harness_comparison {
            by_ag.entry(h.agent_kind.clone()).or_default().push(h);
        }
        let mut rows: Vec<HarnessRowSummary> = by_ag
            .into_iter()
            .map(|(ag, list)| {
                let sessions: usize = list.iter().map(|h| h.sessions).sum();
                let commands: usize = list.iter().map(|h| h.commands).sum();
                let tool_calls: usize = list.iter().map(|h| h.tool_calls).sum();
                let total_ops = (commands + tool_calls).max(1) as f64;
                let weighted_err = list
                    .iter()
                    .map(|h| h.error_rate * (h.commands + h.tool_calls) as f64)
                    .sum::<f64>()
                    / total_ops;
                let weighted_rebound = if commands > 0 {
                    list.iter()
                        .map(|h| h.rebound_rate * h.commands as f64)
                        .sum::<f64>()
                        / commands as f64
                } else {
                    0.0
                };
                let weighted_out_kb = list
                    .iter()
                    .map(|h| h.avg_output_kb * (h.commands + h.tool_calls) as f64)
                    .sum::<f64>()
                    / total_ops;
                let truncated_outputs: usize = list.iter().map(|h| h.truncated_outputs).sum();
                let trunc_sess_pct = if sessions > 0 {
                    list.iter()
                        .map(|h| h.truncated_sessions_pct * h.sessions as f64)
                        .sum::<f64>()
                        / sessions as f64
                } else {
                    0.0
                };
                // Prefer main sessions for median tokens / wait / cache when present
                let main_only: Vec<&&HarnessBreakdown> =
                    list.iter().filter(|h| h.role == "main").collect();
                let ref_slice: Vec<&HarnessBreakdown> = if !main_only.is_empty() {
                    main_only.into_iter().copied().collect()
                } else {
                    list.clone()
                };
                let ref_sess = ref_slice.iter().map(|h| h.sessions).sum::<usize>().max(1);
                let median_total_tokens = (ref_slice
                    .iter()
                    .map(|h| h.median_total_tokens as f64 * h.sessions as f64)
                    .sum::<f64>()
                    / ref_sess as f64)
                    .round() as i64;
                let median_tool_wait_s = ref_slice
                    .iter()
                    .map(|h| h.median_tool_wall_s * h.sessions as f64)
                    .sum::<f64>()
                    / ref_sess as f64;
                let est_cost_usd: f64 = list.iter().map(|h| h.est_cost_usd).sum();
                let api_pairs: Vec<(f64, usize)> = ref_slice
                    .iter()
                    .filter_map(|h| h.avg_api_wait_s.map(|v| (v, h.sessions)))
                    .collect();
                let avg_api_wait_s = if api_pairs.is_empty() {
                    None
                } else {
                    let tot_s: usize = api_pairs.iter().map(|(_, s)| *s).sum::<usize>().max(1);
                    Some(
                        ((api_pairs.iter().map(|(v, s)| *v * (*s as f64)).sum::<f64>()
                            / tot_s as f64)
                            * 10.0)
                            .round()
                            / 10.0,
                    )
                };
                let cache_pairs: Vec<(f64, usize)> = ref_slice
                    .iter()
                    .filter_map(|h| h.weighted_cache_hit.map(|r| (r, h.sessions)))
                    .collect();
                let weighted_cache_hit = if cache_pairs.is_empty() {
                    None
                } else {
                    let tot_s: usize = cache_pairs.iter().map(|(_, s)| *s).sum::<usize>().max(1);
                    Some(
                        cache_pairs
                            .iter()
                            .map(|(r, s)| *r * (*s as f64))
                            .sum::<f64>()
                            / tot_s as f64,
                    )
                };
                let mut friction = Vec::new();
                for h in &ref_slice {
                    for c in &h.top_friction_cmds {
                        if !friction.contains(c) && friction.len() < 5 {
                            friction.push(c.clone());
                        }
                    }
                }
                let sub_cnt: usize = list
                    .iter()
                    .filter(|h| h.role != "main")
                    .map(|h| h.sessions)
                    .sum();
                let short = short_harness(&ag);
                let label = if sub_cnt > 0 {
                    format!("{short} ({} + {} sub)", sessions - sub_cnt, sub_cnt)
                } else {
                    short.to_string()
                };
                HarnessRowSummary {
                    agent_kind: ag,
                    label,
                    sessions,
                    commands,
                    tool_calls,
                    median_total_tokens,
                    est_cost_usd: (est_cost_usd * 100.0).round() / 100.0,
                    weighted_cache_hit,
                    avg_output_kb: (weighted_out_kb * 10.0).round() / 10.0,
                    truncated_outputs,
                    truncated_sessions_pct: (trunc_sess_pct * 10.0).round() / 10.0,
                    median_tool_wait_s: (median_tool_wait_s * 10.0).round() / 10.0,
                    avg_api_wait_s,
                    error_rate: weighted_err,
                    rebound_rate: weighted_rebound,
                    top_friction_cmds: friction,
                }
            })
            .collect();
        rows.sort_by(|a, b| {
            (b.commands + b.tool_calls)
                .cmp(&(a.commands + a.tool_calls))
                .then_with(|| b.sessions.cmp(&a.sessions))
        });
        rows
    }

    fn issues_for_harness(&self, agent_kind: &str) -> Vec<HarnessIssueItem> {
        let mut out: Vec<HarnessIssueItem> = Vec::new();
        let mut seen_targets: std::collections::HashSet<String> = std::collections::HashSet::new();

        if let Some(repo) = &self.selected_repo {
            // 1. All harness/runtime issues caused by this harness
            let h_opps: Vec<&Opportunity> = repo
                .harness_overhead
                .iter()
                .filter(|o| {
                    if agent_kind.is_empty() {
                        return true;
                    }
                    // For harness_divergence, only attribute to the lagging `top_harness`, not the low baseline
                    if o.kind == "harness_divergence"
                        && let Some(top) = ev_str(o, "top_harness")
                    {
                        return top == agent_kind;
                    }
                    o.by_harness.contains_key(agent_kind)
                })
                .collect();
            for m in merge_opportunities(&h_opps) {
                seen_targets.insert(m.primary.target.clone());
                out.push(HarnessIssueItem::Opp(m));
            }

            // 2. Repo issues where this harness is a major driver (>= 35% of occurrences)
            let r_opps: Vec<&Opportunity> = repo
                .opportunities
                .iter()
                .filter(|o| {
                    if agent_kind.is_empty() {
                        return true;
                    }
                    let total: usize = o.by_harness.values().sum();
                    let mine = o.by_harness.get(agent_kind).copied().unwrap_or(0);
                    total > 0 && (mine as f64 / total as f64) >= 0.35
                })
                .collect();
            for m in merge_opportunities(&r_opps) {
                if !seen_targets.contains(&m.primary.target) {
                    seen_targets.insert(m.primary.target.clone());
                    out.push(HarnessIssueItem::Opp(m));
                }
            }
        }

        // 3. Failing MCP tools for this harness (skip single-occurrence blips) not already surfaced
        if let Some(pat) = &self.selected_patterns {
            for t in &pat.top_mcp_errors {
                if t.error_count < 2 && t.truncated_count < 8 {
                    continue;
                }
                if !agent_kind.is_empty() && !t.by_harness.contains_key(agent_kind) {
                    continue;
                }
                if seen_targets.contains(&t.tool_name) {
                    continue;
                }
                seen_targets.insert(t.tool_name.clone());
                out.push(HarnessIssueItem::McpTool(t.clone()));
            }
        }

        out
    }

    fn selected_harness_agent(&self) -> String {
        let rows = self.visible_harness_rows();
        self.harness_state
            .selected()
            .and_then(|i| rows.get(i))
            .map(|r| r.agent_kind.clone())
            .unwrap_or_default()
    }

    fn selected_harness_issues(&self) -> Vec<HarnessIssueItem> {
        let ag = self.selected_harness_agent();
        self.issues_for_harness(&ag)
    }

    fn visible_pattern_count(&self) -> usize {
        let Some(p) = &self.selected_patterns else {
            return 0;
        };
        match self.patterns_view {
            PatternsView::Workflows => {
                if !p.repeating_sequences.is_empty() {
                    p.repeating_sequences.len()
                } else {
                    p.recurring_motifs.len()
                }
            }
            PatternsView::Storms => p.burst_storms.len(),
            PatternsView::Drift => {
                p.temporal_drift.len() + p.cold_start_errors.len() + p.post_cli_doc_reads.len()
            }
        }
    }

    fn visible_command_count(&self) -> usize {
        match self.commands_view {
            CommandsView::Mcp => self
                .selected_patterns
                .as_ref()
                .map_or(0, |p| p.top_mcp_errors.len()),
            _ => self
                .selected_repo
                .as_ref()
                .map_or(0, |r| r.top_commands.len()),
        }
    }

    fn sorted_commands(&self) -> Vec<CommandStat> {
        let Some(repo) = &self.selected_repo else {
            return Vec::new();
        };
        let mut cmds = repo.top_commands.clone();
        match self.commands_view {
            CommandsView::Tokens => {
                cmds.sort_by_key(|c| std::cmp::Reverse(c.total_stdout_tokens));
            }
            CommandsView::Wait => {
                cmds.sort_by(|a, b| b.total_wait_s.total_cmp(&a.total_wait_s));
            }
            CommandsView::Errors => {
                cmds.sort_by(|a, b| {
                    b.error_count
                        .cmp(&a.error_count)
                        .then_with(|| b.error_rate.total_cmp(&a.error_rate))
                });
            }
            CommandsView::Mcp => {}
        }
        cmds
    }

    fn reload_fleet(&mut self, conn: &Connection, keep_repo_id: Option<String>) -> Result<()> {
        let win_label = self.window_label();
        let range = TimeRange::from_window(parse_window_ms(win_label)?, win_label);
        self.fleet = analyze_fleet(conn, &range, false)?;

        let idx = keep_repo_id
            .and_then(|id| self.fleet.repos.iter().position(|r| r.repo_id == id))
            .or(if self.fleet.repos.is_empty() {
                None
            } else {
                Some(0)
            });
        self.repo_state.select(idx);
        self.reload_selected_repo(conn)?;
        Ok(())
    }

    fn reload_selected_repo(&mut self, conn: &Connection) -> Result<()> {
        let win_label = self.window_label();
        let range = TimeRange::from_window(parse_window_ms(win_label)?, win_label);
        self.selected_repo = self
            .repo_state
            .selected()
            .and_then(|i| self.fleet.repos.get(i))
            .and_then(|r| analyze_repo(conn, &r.repo_id, &range, 16).ok());
        self.selected_patterns = self
            .repo_state
            .selected()
            .and_then(|i| self.fleet.repos.get(i))
            .and_then(|r| analyze_cross_session_patterns(conn, &r.repo_id, &range).ok());
        self.issues = None;
        self.reset_tab_selections();
        self.refresh_cached_brief();
        Ok(())
    }

    fn visible_issues(&self) -> Vec<&IssueTrack> {
        self.issues
            .as_ref()
            .map(|r| {
                r.issues
                    .iter()
                    .filter(|t| !self.issues_open_only || t.verdict.verdict.is_open())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn selected_issue(&self) -> Option<&IssueTrack> {
        let idx = self.issues_state.selected()?;
        self.visible_issues().get(idx).copied()
    }

    /// Compute session-level issue tracking for the selected repo if it isn't cached yet.
    pub fn ensure_issues(&mut self, conn: &Connection) -> Result<()> {
        if self.issues.is_some() {
            return Ok(());
        }
        let Some(repo_id) = self.selected_repo.as_ref().map(|r| r.repo_id.clone()) else {
            return Ok(());
        };
        self.reload_issues(conn, &repo_id, None)
    }

    fn reload_issues(
        &mut self,
        conn: &Connection,
        repo_id: &str,
        keep: Option<String>,
    ) -> Result<()> {
        let win = issues_window(self.window_label());
        let range = TimeRange::from_window(parse_window_ms(win)?, win);
        let rep = track_issues(conn, repo_id, &range)?;
        self.issues = Some(rep);
        let vis = self.visible_issues();
        let idx = keep
            .and_then(|k| vis.iter().position(|t| t.key == k))
            .or(if vis.is_empty() { None } else { Some(0) });
        self.issues_state.select(idx);
        Ok(())
    }

    fn step_repo(&mut self, conn: &Connection, delta: isize) -> Result<()> {
        if self.fleet.repos.is_empty() {
            return Ok(());
        }
        let len = self.fleet.repos.len() as isize;
        let cur = self.repo_state.selected().unwrap_or(0) as isize;
        let next = (cur + delta).rem_euclid(len) as usize;
        if self.repo_state.selected() != Some(next) {
            self.repo_state.select(Some(next));
            self.reload_selected_repo(conn)?;
        }
        Ok(())
    }

    fn move_table(state: &mut TableState, len: usize, delta: isize) {
        if len == 0 {
            state.select(None);
            return;
        }
        let cur = state.selected().unwrap_or(0) as isize;
        let next = (cur + delta).clamp(0, len as isize - 1) as usize;
        state.select(Some(next));
    }

    fn handle_key(
        &mut self,
        code: KeyCode,
        modifiers: KeyModifiers,
        conn: &mut Connection,
        roots: &AdapterRoots,
    ) -> Result<()> {
        if modifiers.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('c') {
            self.should_quit = true;
            return Ok(());
        }

        if self.show_help {
            match code {
                KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') | KeyCode::Enter => {
                    self.show_help = false;
                }
                _ => {}
            }
            return Ok(());
        }

        if self.modal.is_some() {
            match code {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => {
                    self.modal = None;
                    self.modal_scroll = 0;
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.modal_scroll = self.modal_scroll.saturating_add(2);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.modal_scroll = self.modal_scroll.saturating_sub(2);
                }
                KeyCode::PageDown => {
                    self.modal_scroll = self.modal_scroll.saturating_add(10);
                }
                KeyCode::PageUp => {
                    self.modal_scroll = self.modal_scroll.saturating_sub(10);
                }
                _ => {}
            }
            return Ok(());
        }

        match code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Char('b') => {
                self.sidebar_open = !self.sidebar_open;
                self.focus = if self.sidebar_open {
                    Focus::Drawer
                } else {
                    Focus::Main
                };
            }
            KeyCode::Esc => {
                if self.sidebar_open {
                    self.sidebar_open = false;
                    self.focus = Focus::Main;
                }
            }
            KeyCode::Char('[') => self.step_repo(conn, -1)?,
            KeyCode::Char(']') => self.step_repo(conn, 1)?,
            KeyCode::Tab => {
                self.tab = self.tab.next();
                self.focus = Focus::Main;
            }
            KeyCode::BackTab => {
                self.tab = self.tab.prev();
                self.focus = Focus::Main;
            }
            KeyCode::Char('1') => {
                self.tab = DetailTab::Insights;
                self.focus = Focus::Main;
            }
            KeyCode::Char('2') => {
                self.tab = DetailTab::Patterns;
                self.focus = Focus::Main;
            }
            KeyCode::Char('3') => {
                self.tab = DetailTab::Harnesses;
                self.focus = Focus::Main;
            }
            KeyCode::Char('4') => {
                self.tab = DetailTab::Commands;
                self.focus = Focus::Main;
            }
            KeyCode::Char('5') => {
                self.tab = DetailTab::Brief;
                self.focus = Focus::Main;
            }
            KeyCode::Char('6') => {
                self.tab = DetailTab::Issues;
                self.focus = Focus::Main;
            }
            KeyCode::Char('o') if self.tab == DetailTab::Issues => {
                self.issues_open_only = !self.issues_open_only;
                let len = self.visible_issues().len();
                self.issues_state
                    .select(if len > 0 { Some(0) } else { None });
                self.status_msg = if self.issues_open_only {
                    "Issues: open only (regressed / new / active / unchanged / improved)".into()
                } else {
                    "Issues: all tracked".into()
                };
            }
            KeyCode::Char('m') if self.tab == DetailTab::Issues => {
                if let (Some(repo_id), Some(key)) = (
                    self.selected_repo.as_ref().map(|r| r.repo_id.clone()),
                    self.selected_issue().map(|t| t.key.clone()),
                ) {
                    let now = chrono::Utc::now();
                    let label = now.format("%Y-%m-%dT%H:%MZ (tui)").to_string();
                    let id = add_marker(
                        conn,
                        &repo_id,
                        Some(&key),
                        now.timestamp_millis(),
                        &label,
                        None,
                    )?;
                    self.reload_issues(conn, &repo_id, Some(key.clone()))?;
                    self.status_msg = format!(
                        "Marker #{id} set now for {key} — sessions from here on are compared with earlier ones (u = undo)"
                    );
                }
            }
            KeyCode::Char('u') if self.tab == DetailTab::Issues => {
                if let (Some(repo_id), Some(key)) = (
                    self.selected_repo.as_ref().map(|r| r.repo_id.clone()),
                    self.selected_issue().map(|t| t.key.clone()),
                ) {
                    let latest = list_markers(conn, &repo_id)?
                        .into_iter()
                        .filter(|m| m.issue_key.as_deref() == Some(key.as_str()))
                        .max_by_key(|m| m.marker_id);
                    if let Some(m) = latest {
                        remove_marker(conn, &repo_id, m.marker_id)?;
                        self.reload_issues(conn, &repo_id, Some(key.clone()))?;
                        self.status_msg = format!("Removed marker #{} from {key}", m.marker_id);
                    } else {
                        self.status_msg = format!("No issue-specific marker on {key}");
                    }
                }
            }
            KeyCode::Left | KeyCode::Char('h') => {
                if self.sidebar_open {
                    self.focus = Focus::Drawer;
                } else if self.tab == DetailTab::Harnesses {
                    self.harness_focus_issues = false;
                }
            }
            KeyCode::Right | KeyCode::Char('l') => {
                if self.focus == Focus::Drawer {
                    self.focus = Focus::Main;
                } else if self.tab == DetailTab::Harnesses {
                    self.harness_focus_issues = true;
                    let len = self.selected_harness_issues().len();
                    if len > 0 && self.harness_issue_state.selected().is_none() {
                        self.harness_issue_state.select(Some(0));
                    }
                }
            }
            KeyCode::Char(' ') if self.tab == DetailTab::Harnesses && self.focus == Focus::Main => {
                self.harness_focus_issues = !self.harness_focus_issues;
                if self.harness_focus_issues {
                    let len = self.selected_harness_issues().len();
                    if len > 0 && self.harness_issue_state.selected().is_none() {
                        self.harness_issue_state.select(Some(0));
                    }
                }
            }
            KeyCode::Char('d') if self.tab == DetailTab::Harnesses => {
                self.harness_show_strata = !self.harness_show_strata;
                let h_len = self.visible_harness_rows().len();
                self.harness_state
                    .select(if h_len > 0 { Some(0) } else { None });
                let hi_len = self.selected_harness_issues().len();
                self.harness_issue_state
                    .select(if hi_len > 0 { Some(0) } else { None });
                self.status_msg = if self.harness_show_strata {
                    "Harnesses: Detailed strata (originator/role)".into()
                } else {
                    "Harnesses: Grouped by agent".into()
                };
            }
            KeyCode::Down | KeyCode::Char('j') => self.navigate(conn, 1)?,
            KeyCode::Up | KeyCode::Char('k') => self.navigate(conn, -1)?,
            KeyCode::PageDown => self.navigate(conn, 10)?,
            KeyCode::PageUp => self.navigate(conn, -10)?,
            KeyCode::Char('g') => self.navigate(conn, -10_000)?,
            KeyCode::Char('G') => self.navigate(conn, 10_000)?,
            KeyCode::Char('f') if self.tab == DetailTab::Insights => {
                self.scope_filter = self.scope_filter.next();
                let len = self.visible_insights().len();
                self.opp_state.select(if len > 0 { Some(0) } else { None });
                self.status_msg = format!("Scope: {}", self.scope_filter.label());
            }
            KeyCode::Char('v') if self.tab == DetailTab::Patterns => {
                self.patterns_view = self.patterns_view.next();
                let len = self.visible_pattern_count();
                self.pattern_state
                    .select(if len > 0 { Some(0) } else { None });
            }
            KeyCode::Char('s') if self.tab == DetailTab::Commands => {
                self.commands_view = self.commands_view.next();
                let len = self.visible_command_count();
                self.cmd_state.select(if len > 0 { Some(0) } else { None });
            }
            KeyCode::Char('m') if self.tab == DetailTab::Brief => {
                self.brief_mode = self.brief_mode.toggle();
                self.brief_scroll = 0;
                self.refresh_cached_brief();
            }
            KeyCode::Enter => {
                if self.focus == Focus::Drawer {
                    self.focus = Focus::Main;
                    self.sidebar_open = false;
                } else if self.tab == DetailTab::Insights
                    && let Some(repo) = &self.selected_repo
                    && let Some(idx) = self.opp_state.selected()
                {
                    let merged = self.visible_insights();
                    if let Some(item) = merged.get(idx) {
                        let win_label = self.window_label();
                        let range = TimeRange::from_window(parse_window_ms(win_label)?, win_label);
                        let res =
                            inspect_finding(conn, &repo.repo_id, &item.primary.id, &range, 6)?;
                        self.modal = Some(res);
                        self.modal_scroll = 0;
                    }
                } else if self.tab == DetailTab::Harnesses
                    && let Some(repo) = &self.selected_repo
                {
                    if !self.harness_focus_issues {
                        self.harness_focus_issues = true;
                        let len = self.selected_harness_issues().len();
                        if len > 0 && self.harness_issue_state.selected().is_none() {
                            self.harness_issue_state.select(Some(0));
                        }
                    } else if let Some(idx) = self.harness_issue_state.selected() {
                        let issues = self.selected_harness_issues();
                        if let Some(issue) = issues.get(idx) {
                            let win_label = self.window_label();
                            let range =
                                TimeRange::from_window(parse_window_ms(win_label)?, win_label);
                            let q = match issue {
                                HarnessIssueItem::Opp(m) => m.primary.id.clone(),
                                HarnessIssueItem::McpTool(t) => t.tool_name.clone(),
                            };
                            let res = inspect_finding(conn, &repo.repo_id, &q, &range, 6)?;
                            self.modal = Some(res);
                            self.modal_scroll = 0;
                        }
                    }
                } else if self.tab == DetailTab::Issues
                    && let Some(repo) = &self.selected_repo
                    && let Some(t) = self.selected_issue()
                {
                    let q = repo
                        .opportunities
                        .iter()
                        .chain(repo.harness_overhead.iter())
                        .find(|o| issue_key(&o.kind, &o.target) == t.key)
                        .map(|o| o.id.clone())
                        .unwrap_or_else(|| t.target.clone());
                    let win_label = self.window_label();
                    let range = TimeRange::from_window(parse_window_ms(win_label)?, win_label);
                    match inspect_finding(conn, &repo.repo_id, &q, &range, 6) {
                        Ok(res) => {
                            self.modal = Some(res);
                            self.modal_scroll = 0;
                        }
                        Err(e) => self.status_msg = format!("No traces for {}: {e}", t.key),
                    }
                } else if self.tab == DetailTab::Commands
                    && self.commands_view != CommandsView::Mcp
                    && let Some(repo) = &self.selected_repo
                    && let Some(idx) = self.cmd_state.selected()
                {
                    let cmds = self.sorted_commands();
                    if let Some(c) = cmds.get(idx) {
                        let win_label = self.window_label();
                        let range = TimeRange::from_window(parse_window_ms(win_label)?, win_label);
                        let res = inspect_finding(conn, &repo.repo_id, &c.cmd_template, &range, 6)?;
                        self.modal = Some(res);
                        self.modal_scroll = 0;
                    }
                }
            }
            KeyCode::Char('w') => {
                let keep = self.selected_repo.as_ref().map(|r| r.repo_id.clone());
                self.window_idx = (self.window_idx + 1) % WINDOWS.len();
                self.reload_fleet(conn, keep)?;
                self.status_msg = format!("Window: {}", self.window_label());
            }
            KeyCode::Char('r') => {
                let keep = self.selected_repo.as_ref().map(|r| r.repo_id.clone());
                let stats = sync_all(conn, roots, false)?;
                self.reload_fleet(conn, keep)?;
                self.status_msg = format!(
                    "Synced {} updated file(s), +{} spans",
                    stats.files_ingested, stats.spans_inserted
                );
            }
            KeyCode::Char('c') => {
                if let Some(repo) = &self.selected_repo {
                    let brief = self.cached_brief.clone();
                    match copy_to_clipboard(&brief) {
                        Ok(()) => {
                            let kind = match self.brief_mode {
                                BriefMode::Prompt => "Diagnosis Prompt",
                                BriefMode::Yaml => "YAML Brief",
                            };
                            self.status_msg = format!(
                                "Copied {kind} for {} ({:.1} KB)",
                                repo.repo_name,
                                brief.len() as f64 / 1024.0
                            );
                        }
                        Err(e) => {
                            self.status_msg = format!("Clipboard copy failed: {e}");
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn navigate(&mut self, conn: &Connection, delta: isize) -> Result<()> {
        if self.focus == Focus::Drawer {
            if !self.fleet.repos.is_empty() {
                let prev_sel = self.repo_state.selected();
                Self::move_table(&mut self.repo_state, self.fleet.repos.len(), delta);
                if self.repo_state.selected() != prev_sel {
                    self.reload_selected_repo(conn)?;
                }
            }
            return Ok(());
        }

        match self.tab {
            DetailTab::Insights => {
                let len = self.visible_insights().len();
                Self::move_table(&mut self.opp_state, len, delta);
            }
            DetailTab::Patterns => {
                let len = self.visible_pattern_count();
                Self::move_table(&mut self.pattern_state, len, delta);
            }
            DetailTab::Harnesses => {
                if self.harness_focus_issues {
                    let len = self.selected_harness_issues().len();
                    Self::move_table(&mut self.harness_issue_state, len, delta);
                } else {
                    let prev = self.harness_state.selected();
                    let len = self.visible_harness_rows().len();
                    Self::move_table(&mut self.harness_state, len, delta);
                    if self.harness_state.selected() != prev {
                        let hi_len = self.selected_harness_issues().len();
                        self.harness_issue_state
                            .select(if hi_len > 0 { Some(0) } else { None });
                    }
                }
            }
            DetailTab::Commands => {
                let len = self.visible_command_count();
                Self::move_table(&mut self.cmd_state, len, delta);
            }
            DetailTab::Issues => {
                let len = self.visible_issues().len();
                Self::move_table(&mut self.issues_state, len, delta);
            }
            DetailTab::Brief => {
                if delta > 0 {
                    self.brief_scroll = self.brief_scroll.saturating_add(delta as u16);
                } else {
                    self.brief_scroll = self.brief_scroll.saturating_sub((-delta) as u16);
                }
            }
        }
        Ok(())
    }
}

fn copy_to_clipboard(text: &str) -> Result<()> {
    let candidates: &[(&str, &[&str])] = if cfg!(target_os = "macos") {
        &[("pbcopy", &[])]
    } else {
        &[("wl-copy", &[]), ("xclip", &["-selection", "clipboard"])]
    };

    for (bin, args) in candidates {
        if let Ok(mut child) = Command::new(bin)
            .args(*args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(text.as_bytes())?;
            }
            let status = child.wait()?;
            if status.success() {
                return Ok(());
            }
        }
    }
    anyhow::bail!("no clipboard utility found")
}

pub fn run_tui(
    conn: &mut Connection,
    roots: &AdapterRoots,
    initial_window: &str,
    initial_repo_id: Option<&str>,
) -> Result<()> {
    let mut app = App::load(conn, initial_window, initial_repo_id)?;
    let mut terminal = ratatui::init();

    let run_res = (|| -> Result<()> {
        while !app.should_quit {
            terminal.draw(|f| draw(f, &mut app))?;
            if event::poll(Duration::from_millis(200))?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                app.handle_key(key.code, key.modifiers, conn, roots)?;
            }
            if app.tab == DetailTab::Issues
                && let Err(e) = app.ensure_issues(conn)
            {
                app.status_msg = format!("Issue tracking failed: {e}");
            }
        }
        Ok(())
    })();

    ratatui::restore();
    run_res
}

// ---------------------------------------------------------------------------
// Human-Readable Formatting & Visual Helpers
// ---------------------------------------------------------------------------

pub fn format_duration(secs: f64) -> String {
    format_duration_human(secs)
}

fn format_int(n: usize) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(b as char);
    }
    out
}

fn truncate_ellipsis(s: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let count = s.chars().count();
    if count <= max_chars {
        s.to_string()
    } else if max_chars == 1 {
        "…".to_string()
    } else {
        format!("{}…", s.chars().take(max_chars - 1).collect::<String>())
    }
}

fn short_harness(name: &str) -> &str {
    match name {
        "claude-code" => "claude",
        other => other,
    }
}

fn harness_color(name: &str) -> Color {
    match short_harness(name) {
        "codex" => Color::LightBlue,
        "claude" => Color::LightMagenta,
        "antigravity" => Color::Cyan,
        "kimi" => Color::Yellow,
        _ => Color::Gray,
    }
}

fn compact_harness_cell(counts: &BTreeMap<String, usize>) -> (String, Color) {
    let total: usize = counts.values().sum();
    if total == 0 {
        return ("—".to_string(), Color::DarkGray);
    }
    let mut items: Vec<(&String, usize)> = counts.iter().map(|(k, &v)| (k, v)).collect();
    items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    let top_name = short_harness(items[0].0);
    let top_pct = ((items[0].1 as f64 / total as f64) * 100.0).round() as usize;
    if items.len() == 1 || top_pct >= 98 {
        (format!("{top_name} only"), harness_color(top_name))
    } else if top_pct >= 65 {
        (format!("{top_name} {top_pct}%"), harness_color(top_name))
    } else {
        let second = short_harness(items[1].0);
        (format!("{top_name}/{second}"), Color::Gray)
    }
}

fn bar_string(fraction: f64, width: usize) -> String {
    let clamped = fraction.clamp(0.0, 1.0);
    let filled = (clamped * width as f64).round() as usize;
    format!(
        "{}{}",
        "█".repeat(filled.min(width)),
        "░".repeat(width.saturating_sub(filled))
    )
}

fn harness_bar_lines(counts: &BTreeMap<String, usize>, bar_width: usize) -> Vec<Line<'static>> {
    let total: usize = counts.values().sum();
    if total == 0 {
        return vec![Line::from(Span::styled(
            "No per-harness attribution recorded",
            Style::default().fg(Color::DarkGray),
        ))];
    }
    let mut items: Vec<(String, usize)> = counts.iter().map(|(k, &v)| (k.clone(), v)).collect();
    items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    items
        .into_iter()
        .take(4)
        .map(|(k, v)| {
            let short = short_harness(&k);
            let frac = v as f64 / total as f64;
            let pct = (frac * 100.0).round() as usize;
            let col = harness_color(short);
            Line::from(vec![
                Span::styled(format!("{short:<11} "), Style::default().fg(col)),
                Span::styled(bar_string(frac, bar_width), Style::default().fg(col)),
                Span::raw(format!(" {:>3}%  ", pct)),
                Span::styled(
                    format!("({})", format_int(v)),
                    Style::default().fg(Color::Gray),
                ),
            ])
        })
        .collect()
}

fn human_problem(kind: &str) -> (&'static str, Color) {
    match kind {
        "broken_task_error_rate" => ("High fail rate", Color::Red),
        "lossy_task_rebound" => ("Shell fallback", Color::Red),
        "flag_thrash" => ("Flag guessing", Color::Red),
        "tool_friction" => ("Tool errors", Color::Red),
        "polling_tax" => ("Polling loop", Color::Yellow),
        "slow_task_latency" => ("Slow wait", Color::Yellow),
        "state_dir_bypass" => ("State scraping", Color::Yellow),
        "output_filtering_tax" => ("Noisy output", Color::Yellow),
        "noisy_task_output" => ("Verbose output", Color::Yellow),
        "repeated_file_reread" => ("File re-reads", Color::Yellow),
        "truncated_output_reread" => ("Spill re-reads", Color::Yellow),
        "file_edit_churn" => ("Edit churn", Color::Yellow),
        "context_handoff_bloat" => ("Handoff bloat", Color::Yellow),
        "context_pressure" => ("Context pressure", Color::Yellow),
        "session_abort_rate" => ("High aborts", Color::Red),
        "low_cache_efficiency" => ("Low cache hit", Color::Yellow),
        "orientation_tax" => ("Startup reads", Color::Cyan),
        "cli_help_tax" => ("Repeated --help", Color::Cyan),
        "missing_composite_task" => ("Manual workflow", Color::Cyan),
        "harness_divergence" => ("Harness gap", Color::Cyan),
        _ => ("Friction signal", Color::Cyan),
    }
}

fn merge_opportunities(raw: &[&Opportunity]) -> Vec<MergedInsight> {
    let mut order: Vec<(String, String)> = Vec::new();
    let mut map: HashMap<(String, String), MergedInsight> = HashMap::new();
    for opp in raw {
        let key = (opp.scope.clone(), opp.target.clone());
        if let Some(existing) = map.get_mut(&key) {
            existing.related.push((*opp).clone());
        } else {
            order.push(key.clone());
            map.insert(
                key,
                MergedInsight {
                    primary: (*opp).clone(),
                    related: Vec::new(),
                },
            );
        }
    }
    order.into_iter().filter_map(|k| map.remove(&k)).collect()
}

fn ev_u64(o: &Opportunity, key: &str) -> Option<u64> {
    o.evidence.get(key).and_then(|v| v.as_u64())
}

fn ev_f64(o: &Opportunity, key: &str) -> Option<f64> {
    o.evidence.get(key).and_then(|v| v.as_f64())
}

fn ev_str<'a>(o: &'a Opportunity, key: &str) -> Option<&'a str> {
    o.evidence.get(key).and_then(|v| v.as_str())
}

fn ev_str_list(o: &Opportunity, key: &str) -> Vec<String> {
    o.evidence
        .get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn clean_tool_label(name: &str) -> String {
    if let Some(rest) = name.strip_prefix("mcp:")
        && let Some((srv, tool)) = rest.split_once(':')
    {
        return format!("{srv}/{tool}");
    }
    name.to_string()
}

fn dominant_harness_label(counts: &BTreeMap<String, usize>) -> String {
    let total: usize = counts.values().sum();
    if total == 0 {
        return "multiple harnesses".to_string();
    }
    let mut items: Vec<(&String, usize)> = counts.iter().map(|(k, &v)| (k, v)).collect();
    items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    let top = short_harness(items[0].0);
    let pct = ((items[0].1 as f64 / total as f64) * 100.0).round() as usize;
    if items.len() == 1 || pct >= 95 {
        format!("{top} only")
    } else if pct >= 65 {
        format!("mostly {top} ({pct}%)")
    } else {
        let second = short_harness(items[1].0);
        format!("{top} ({pct}%) and {second}")
    }
}

/// Concise, plain-English headline that keeps the distinguishing target visible in narrow lists.
fn insight_headline(o: &Opportunity) -> String {
    match o.kind.as_str() {
        "polling_tax" => match o.target.as_str() {
            "codex-wait" => "Codex PTY polling (codex-wait)".to_string(),
            "codex-wait --spin" => "Codex tight-spin wait loop".to_string(),
            "codex-write-stdin" => "Codex stdin polling loop".to_string(),
            t => format!("Polling: {t}"),
        },
        "slow_task_latency" => match o.target.as_str() {
            "codex-wait" => "Slow Codex PTY waits".to_string(),
            "codex-write-stdin" => "Slow Codex stdin waits".to_string(),
            t => format!("Slow: {t}"),
        },
        "lossy_task_rebound" => format!("Fallbacks: {}", o.target),
        "state_dir_bypass" => {
            let short_dir = o.target.strip_prefix("~/.local/").unwrap_or(&o.target);
            format!("Scrape: {short_dir}")
        }
        "output_filtering_tax" => "CLI output piped to tail/grep/sed".to_string(),
        "noisy_task_output" => format!("Verbose: {}", o.target),
        "cli_help_tax" => "Repeated --help lookups".to_string(),
        "orientation_tax" => "Heavy startup reads (turns 1–3)".to_string(),
        "broken_task_error_rate" => format!("Failing: {}", o.target),
        "flag_thrash" => {
            if let Some((from, to)) = o.target.split_once(" -> ") {
                format!("Retry: {from} → {to}")
            } else {
                format!("Retries: {}", o.target)
            }
        }
        "tool_friction" => {
            let errs = ev_u64(o, "errors").unwrap_or(0);
            let tool = clean_tool_label(&o.target);
            if errs >= 3 {
                tool
            } else {
                format!("Truncated: {tool}")
            }
        }
        "repeated_file_reread" => format!("Re-reads: {}", o.target),
        "truncated_output_reread" => format!("Spill reads: {}", o.target),
        "file_edit_churn" => format!("Edit churn: {}", o.target),
        "context_pressure" => "Context window pressure & compactions".to_string(),
        "session_abort_rate" => "High aborted / interrupted session rate".to_string(),
        "context_handoff_bloat" => {
            let m = ev_f64(o, "multiplier").unwrap_or(0.0);
            format!("Resumed threads burn {m:.1}× tokens")
        }
        "low_cache_efficiency" => {
            let ag = o
                .target
                .strip_suffix(" cache hit rate")
                .unwrap_or(&o.target);
            format!("Low cache hit: {}", short_harness(ag))
        }
        "harness_divergence" => {
            if let (Some(metric), Some(top), Some(low)) = (
                ev_str(o, "metric"),
                ev_str(o, "top_harness"),
                ev_str(o, "low_harness"),
            ) {
                format!(
                    "{} > {} on {metric}",
                    short_harness(top),
                    short_harness(low)
                )
            } else {
                format!("Harness gap: {}", o.target)
            }
        }
        "missing_composite_task" => format!("Loop: {}", o.target),
        _ => o.target.clone(),
    }
}

/// Concise, data-backed plain-English explanation of what is actually happening.
fn insight_story(o: &Opportunity) -> Vec<String> {
    let who = dominant_harness_label(&o.by_harness);
    match o.kind.as_str() {
        "polling_tax" => {
            let calls = ev_u64(o, "total_calls").unwrap_or(0) as usize;
            let sess = ev_u64(o, "sessions").unwrap_or(0);
            let avg = ev_f64(o, "avg_calls_per_session").unwrap_or(0.0);
            let max_c = ev_u64(o, "max_calls_in_one_session").unwrap_or(0);
            let wait = ev_f64(o, "total_wait_s").unwrap_or(0.0);
            let subject = match o.target.as_str() {
                "codex-wait" | "codex-wait --spin" => {
                    "Codex is polling a background PTY command in a loop instead of blocking"
                        .to_string()
                }
                "codex-write-stdin" => {
                    "Codex is polling an interactive shell via `write_stdin` to check completion"
                        .to_string()
                }
                t => format!("Agents poll `{t}` in a loop ({who}) instead of waiting once"),
            };
            vec![format!(
                "{subject} — {avg:.1}×/session (max {max_c}×), burning {} across {} calls in {sess} sessions.",
                format_duration(wait),
                format_int(calls)
            )]
        }
        "slow_task_latency" => {
            let runs = ev_u64(o, "runs").unwrap_or(0) as usize;
            let wait = ev_f64(o, "total_wait_s").unwrap_or(0.0);
            let p50 = ev_f64(o, "p50_wait_s").unwrap_or(0.0);
            let p95 = ev_f64(o, "p95_wait_s").unwrap_or(0.0);
            vec![format!(
                "`{}` blocked agents for {} across {} runs ({who}) — typical run takes {}, slowest 5% take {}+.",
                o.target,
                format_duration(wait),
                format_int(runs),
                format_duration(p50),
                format_duration(p95)
            )]
        }
        "lossy_task_rebound" => {
            let count = ev_u64(o, "rebound_count").unwrap_or(0) as usize;
            let runs = ev_u64(o, "total_runs").unwrap_or(0) as usize;
            let rate = ev_f64(o, "rebound_rate").unwrap_or(0.0) * 100.0;
            let sess = ev_u64(o, "sessions").unwrap_or(0);
            let follows = ev_str_list(o, "top_fallback_cmds");
            let via = if follows.is_empty() {
                "raw shell commands".to_string()
            } else {
                follows.into_iter().take(2).collect::<Vec<_>>().join(", ")
            };
            vec![format!(
                "{rate:.0}% of `{}` runs ({}/{}) across {sess} sessions ({who}) are immediately followed by {via}.",
                o.target,
                format_int(count),
                format_int(runs)
            )]
        }
        "state_dir_bypass" => {
            let reads = ev_u64(o, "direct_reads").unwrap_or(0) as usize;
            let sess = ev_u64(o, "sessions").unwrap_or(0);
            let toks = ev_u64(o, "stdout_tokens").unwrap_or(0) as i64;
            let cmds = ev_str_list(o, "top_raw_cmds");
            let via = if cmds.is_empty() {
                "cat/tail/ls".to_string()
            } else {
                cmds.into_iter().take(2).collect::<Vec<_>>().join(", ")
            };
            vec![format!(
                "Agents read raw state files under `{}` {} times across {sess} sessions ({who}) via {via} ({} stdout tokens) instead of a repo CLI.",
                o.target,
                format_int(reads),
                format_compact(toks)
            )]
        }
        "output_filtering_tax" => {
            let n = ev_u64(o, "total_piped_cli_calls").unwrap_or(0) as usize;
            vec![format!(
                "Agents piped repo CLI stdout through tail/grep/sed {} times ({who}) to strip noise or bound output.",
                format_int(n)
            )]
        }
        "noisy_task_output" => {
            let runs = ev_u64(o, "runs").unwrap_or(0) as usize;
            let p50 = ev_u64(o, "p50_stdout_tokens").unwrap_or(0) as i64;
            let eff = ev_u64(o, "effective_context_tokens").unwrap_or(0) as i64;
            let noise = ev_str(o, "dominant_noise").unwrap_or("verbose_stdout");
            vec![format!(
                "`{}` emits ~{} tokens/run (p50, `{noise}`) across {} runs ({who}) — ~{} effective context tokens after downstream turn replay.",
                o.target,
                format_compact(p50),
                format_int(runs),
                format_compact(eff)
            )]
        }
        "broken_task_error_rate" => {
            let errs = ev_u64(o, "errors").unwrap_or(0);
            let runs = ev_u64(o, "runs").unwrap_or(0);
            let rate = ev_f64(o, "error_rate").unwrap_or(0.0) * 100.0;
            vec![format!(
                "Repo task `{}` failed on {errs} of {runs} runs ({rate:.0}% error rate, {who}).",
                o.target
            )]
        }
        "flag_thrash" => {
            let occ = ev_u64(o, "occurrences").unwrap_or(0);
            let sess = ev_u64(o, "sessions").unwrap_or(0);
            vec![format!(
                "Agents failed and retried `{}` {occ} times across {sess} sessions ({who}) before getting exit 0.",
                o.target
            )]
        }
        "tool_friction" => {
            let calls = ev_u64(o, "calls").unwrap_or(0);
            let sess = ev_u64(o, "sessions").unwrap_or(0);
            let errs = ev_u64(o, "errors").unwrap_or(0);
            let err_rate = ev_f64(o, "error_rate").unwrap_or(0.0) * 100.0;
            let trunc = ev_u64(o, "truncated").unwrap_or(0);
            let avg_kb = ev_f64(o, "avg_output_kb").unwrap_or(0.0);
            let tool = clean_tool_label(&o.target);
            if errs >= 3 {
                vec![format!(
                    "Tool `{tool}` failed on {errs}/{calls} calls ({err_rate:.0}% error rate, {trunc} truncated, avg {avg_kb:.1} KB) across {sess} sessions ({who})."
                )]
            } else {
                vec![format!(
                    "Tool `{tool}` had {trunc}/{calls} outputs truncated (avg {avg_kb:.1} KB) across {sess} sessions ({who})."
                )]
            }
        }
        "context_handoff_bloat" => {
            let hs = ev_u64(o, "handoff_sessions").unwrap_or(0);
            let fs = ev_u64(o, "fresh_sessions").unwrap_or(0);
            let h_tok = ev_u64(o, "handoff_avg_tokens").unwrap_or(0) as i64;
            let f_tok = ev_u64(o, "fresh_avg_tokens").unwrap_or(0) as i64;
            let mult = ev_f64(o, "multiplier").unwrap_or(0.0);
            vec![format!(
                "{hs} resumed/handoff threads averaged {} tokens vs {} for {fs} fresh threads ({mult:.1}× heavier, {who}).",
                format_compact(h_tok),
                format_compact(f_tok)
            )]
        }
        "low_cache_efficiency" => {
            let sess = ev_u64(o, "sessions").unwrap_or(0);
            let rate = ev_f64(o, "weighted_cache_hit").unwrap_or(0.0) * 100.0;
            let uncached = ev_u64(o, "uncached_input_tokens").unwrap_or(0) as i64;
            vec![format!(
                "Weighted prompt cache hit is {rate:.1}% across {sess} main sessions ({who}), leaving {} input tokens uncached.",
                format_compact(uncached)
            )]
        }
        "harness_divergence" => {
            let metric = ev_str(o, "metric").unwrap_or("this behavior");
            let top = ev_str(o, "top_harness")
                .map(short_harness)
                .unwrap_or("one harness");
            let low = ev_str(o, "low_harness")
                .map(short_harness)
                .unwrap_or("another");
            let tr = ev_f64(o, "top_rate").unwrap_or(0.0);
            let lr = ev_f64(o, "low_rate").unwrap_or(0.0);
            let cnt = ev_u64(o, "top_count").unwrap_or(0);
            vec![format!(
                "`{top}` triggers {metric} at {tr:.1}/1k commands ({cnt}×) vs {lr:.1}/1k in `{low}` on the same repo — pointing to `{top}`'s harness config or prompt/output rules."
            )]
        }
        "orientation_tax" => {
            let cmds = ev_u64(o, "early_commands").unwrap_or(0);
            let docs = ev_u64(o, "early_doc_reads").unwrap_or(0);
            vec![format!(
                "Sessions spend turns 1–3 running {cmds} discovery commands and {docs} doc reads ({who}) to locate files and commands."
            )]
        }
        "cli_help_tax" => {
            let calls = ev_u64(o, "help_calls").unwrap_or(0);
            let broken = ev_u64(o, "broken_help_calls").unwrap_or(0);
            vec![format!(
                "Agents ran `--help` {calls} times ({broken} nonzero exits, {who}) rediscovering repo CLI syntax."
            )]
        }
        "repeated_file_reread" => {
            let reads = ev_u64(o, "reads").unwrap_or(0);
            let sess = ev_u64(o, "sessions").unwrap_or(0);
            let max_r = ev_u64(o, "max_reads_in_session").unwrap_or(0);
            let toks = ev_u64(o, "total_tokens").unwrap_or(0) as i64;
            vec![format!(
                "`{}` was read {reads} times across {sess} sessions (up to {max_r}×/session, {} tokens, {who}).",
                o.target,
                format_compact(toks)
            )]
        }
        "missing_composite_task" => {
            let occ = ev_u64(o, "occurrences").unwrap_or(0);
            let sess = ev_u64(o, "sessions").unwrap_or(0);
            let wait = ev_f64(o, "combined_wait_s").unwrap_or(0.0);
            vec![format!(
                "Agents manually chain `{}` {occ} times across {sess} sessions ({} total wait, {who}).",
                o.target,
                format_duration(wait)
            )]
        }
        _ => vec![o.impact_summary.clone()],
    }
}

/// Plain-English fix guidance + human-readable success goal.
fn insight_fix_guidance(o: &Opportunity) -> (String, String) {
    match o.kind.as_str() {
        "polling_tax" if o.target.starts_with("codex-wait") || o.target == "codex-write-stdin" => (
            "Avoid interactive/background shell jobs in Codex or give commands a built-in `--wait` flag / higher exec timeout so Codex doesn't spin polling PTY output.".to_string(),
            "Drop polling calls to ≤ 1.5× per session".to_string(),
        ),
        "polling_tax" => (
            format!(
                "Make `{}` block until done (or print a clear wait/notify hint in {}) instead of returning immediately for agents to poll.",
                o.target, o.fix_target
            ),
            "Drop polling calls to ≤ 1.5× per session".to_string(),
        ),
        "context_handoff_bloat" => (
            "Start fresh threads for new tasks instead of continuing long compacted sessions, or trim handoff summaries to only active state.".to_string(),
            "Keep resumed sessions within 1.5× of fresh session tokens".to_string(),
        ),
        "low_cache_efficiency" => (
            format!(
                "Check {} for changing system-prompt prefixes, unstable tool definitions, or idle gaps exceeding prompt-cache TTL.",
                o.fix_target
            ),
            "Raise weighted prompt cache hit to ≥ 90%".to_string(),
        ),
        "harness_divergence" => (
            o.suggested_action.clone(),
            "Bring both harnesses within 1.5× of each other".to_string(),
        ),
        _ => (o.suggested_action.clone(), o.acceptance_metric.clone()),
    }
}

fn compact_opp_metric(o: &Opportunity) -> String {
    match o.kind.as_str() {
        "polling_tax" => {
            let calls = ev_u64(o, "total_calls").unwrap_or(0);
            let wait = ev_f64(o, "total_wait_s").unwrap_or(0.0);
            if wait >= 60.0 {
                format!(
                    "{} · {} polls",
                    format_duration(wait),
                    format_int(calls as usize)
                )
            } else {
                format!("{} polls", format_int(calls as usize))
            }
        }
        "slow_task_latency" => {
            let wait = ev_f64(o, "total_wait_s").unwrap_or(0.0);
            format!("{} wait", format_duration(wait))
        }
        "state_dir_bypass" => {
            let reads = ev_u64(o, "direct_reads").unwrap_or(0);
            format!("{} reads", format_int(reads as usize))
        }
        "output_filtering_tax" => {
            let n = ev_u64(o, "total_piped_cli_calls").unwrap_or(0);
            format!("{} piped", format_int(n as usize))
        }
        "lossy_task_rebound" => {
            let n = ev_u64(o, "rebound_count").unwrap_or(0);
            let rate = ev_f64(o, "rebound_rate").unwrap_or(0.0) * 100.0;
            format!("{rate:.0}% ({})", format_int(n as usize))
        }
        "orientation_tax" => {
            let cmds = ev_u64(o, "early_commands").unwrap_or(0)
                + ev_u64(o, "early_doc_reads").unwrap_or(0);
            format!("{} early calls", format_int(cmds as usize))
        }
        "broken_task_error_rate" => {
            let errs = ev_u64(o, "errors").unwrap_or(0);
            let rate = ev_f64(o, "error_rate").unwrap_or(0.0) * 100.0;
            format!("{rate:.0}% err ({errs})")
        }
        "noisy_task_output" => {
            let eff = ev_u64(o, "effective_context_tokens").unwrap_or(0) as i64;
            format!("{} eff toks", format_compact(eff))
        }
        "flag_thrash" => {
            let n = ev_u64(o, "occurrences").unwrap_or(0);
            format!("{} retries", format_int(n as usize))
        }
        "missing_composite_task" => {
            let n = ev_u64(o, "occurrences").unwrap_or(0);
            format!("{} chains", format_int(n as usize))
        }
        "cli_help_tax" => {
            let n = ev_u64(o, "help_calls").unwrap_or(0);
            format!("{} lookups", format_int(n as usize))
        }
        "tool_friction" => {
            let errs = ev_u64(o, "errors").unwrap_or(0);
            let trunc = ev_u64(o, "truncated").unwrap_or(0);
            if errs >= 3 {
                let r = ev_f64(o, "error_rate").unwrap_or(0.0) * 100.0;
                format!("{errs} errs ({r:.0}%)")
            } else {
                format!("{} trunc", format_int(trunc as usize))
            }
        }
        "repeated_file_reread" => {
            let n = ev_u64(o, "reads").unwrap_or(0);
            format!("{} re-reads", format_int(n as usize))
        }
        "file_edit_churn" => {
            let n = ev_u64(o, "edits").unwrap_or(0);
            format!("{} edits", format_int(n as usize))
        }
        "context_pressure" => {
            let c = ev_u64(o, "total_compactions").unwrap_or(0);
            format!("{c} compactions")
        }
        "session_abort_rate" => {
            let r = ev_f64(o, "abort_rate").unwrap_or(0.0) * 100.0;
            format!("{r:.0}% aborted")
        }
        "context_handoff_bloat" => {
            let m = ev_f64(o, "multiplier").unwrap_or(0.0);
            format!("{m:.1}× tokens")
        }
        "low_cache_efficiency" => {
            let r = ev_f64(o, "weighted_cache_hit").unwrap_or(0.0) * 100.0;
            format!("{r:.0}% cache hit")
        }
        "harness_divergence" => {
            let tr = ev_f64(o, "top_rate");
            let lr = ev_f64(o, "low_rate");
            match (tr, lr) {
                (Some(t), Some(l)) if l < 0.5 => format!("{t:.0} vs 0 /1k"),
                (Some(t), Some(l)) => format!("{t:.0} vs {l:.0} /1k"),
                _ => {
                    let r = ev_f64(o, "rate_ratio").unwrap_or(0.0);
                    format!("{r:.1}× gap")
                }
            }
        }
        _ => truncate_ellipsis(&o.impact_summary, 18),
    }
}

fn primary_metric_for(item: &MergedInsight) -> String {
    let base = compact_opp_metric(&item.primary);

    // If a sibling slow_task_latency merged into a non-wait primary, append duration concisely
    if !base.contains('h')
        && !base.contains('m')
        && !base.contains("wait")
        && let Some(sib) = item.related.iter().find(|r| r.kind == "slow_task_latency")
        && let Some(wait) = ev_f64(sib, "total_wait_s")
        && wait >= 60.0
    {
        return format!("{base} · {}", format_duration(wait));
    }
    base
}

fn rounded_block<'a>(title: impl Into<Line<'a>>, focused: bool) -> Block<'a> {
    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(if focused {
            Color::Cyan
        } else {
            Color::DarkGray
        }))
        .padding(Padding::horizontal(1))
}

fn row_highlight_style() -> Style {
    Style::default()
        .bg(Color::Indexed(236))
        .add_modifier(Modifier::BOLD)
}

// ---------------------------------------------------------------------------
// Top-Level Draw Layout
// ---------------------------------------------------------------------------

pub fn draw(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Header + tab strip
            Constraint::Min(10),   // Main workspace (+ optional drawer)
            Constraint::Length(1), // Footer keybind strip
        ])
        .split(area);

    draw_top_chrome(frame, outer[0], app);

    if app.sidebar_open {
        let drawer_w = 34u16.min(area.width / 3).max(24);
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(drawer_w), Constraint::Min(40)])
            .split(outer[1]);
        draw_fleet_drawer(frame, cols[0], app);
        draw_active_tab(frame, cols[1], app);
    } else {
        draw_active_tab(frame, outer[1], app);
    }

    draw_footer(frame, outer[2], app);

    if let Some(inspect) = &app.modal {
        draw_inspect_modal(frame, area, inspect, app.modal_scroll);
    } else if app.show_help {
        draw_help_modal(frame, area);
    }
}

fn draw_top_chrome(frame: &mut Frame, area: Rect, app: &App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(area);

    let repo_idx = app.repo_state.selected().unwrap_or(0);
    let repo_total = app.fleet.repos.len();
    let repo_label = app
        .selected_repo
        .as_ref()
        .map(|r| {
            if repo_total > 1 {
                format!(" ◀ {} ({}/{}) ▶ ", r.repo_name, repo_idx + 1, repo_total)
            } else {
                format!(" {} ", r.repo_name)
            }
        })
        .unwrap_or_else(|| " No repo ".to_string());

    let mut header_spans = vec![
        Span::styled(
            " ◆ bottledeck ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(
            repo_label,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" [{}] ", app.window_label()),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("  ", Style::default()),
        Span::styled(
            truncate_ellipsis(&app.status_msg, 38),
            Style::default().fg(Color::Gray),
        ),
        Span::raw("  "),
        Span::styled(
            if app.sidebar_open {
                "[b] Close Fleet"
            } else {
                "[b] Fleet Drawer"
            },
            Style::default().fg(Color::DarkGray),
        ),
    ];
    if let Some(ref latest) = app.update_available {
        header_spans.push(Span::raw("  "));
        header_spans.push(Span::styled(
            format!("⬆ {latest} (`bottledeck update`)"),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ));
    }
    let header = Line::from(header_spans);
    frame.render_widget(Paragraph::new(header), rows[0]);

    // Compact horizontal tab bar
    let mut tab_spans: Vec<Span> = vec![Span::raw(" ")];
    for (idx, title) in DetailTab::titles().iter().enumerate() {
        let active = idx == app.tab as usize;
        if idx > 0 {
            tab_spans.push(Span::styled("  │  ", Style::default().fg(Color::DarkGray)));
        }
        if active {
            tab_spans.push(Span::styled(
                format!(" {title} "),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            ));
        } else {
            tab_spans.push(Span::styled(
                format!(" {title} "),
                Style::default().fg(Color::Gray),
            ));
        }
    }
    frame.render_widget(Paragraph::new(Line::from(tab_spans)), rows[1]);
}

fn draw_fleet_drawer(frame: &mut Frame, area: Rect, app: &mut App) {
    let focused = app.focus == Focus::Drawer;
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
        .split(area);

    let header = Row::new(vec![
        Cell::from("Repo"),
        Cell::from(Line::from("Sess").right_aligned()),
        Cell::from(Line::from("Out").right_aligned()),
        Cell::from(Line::from("Err").right_aligned()),
    ])
    .style(
        Style::default()
            .fg(Color::Gray)
            .add_modifier(Modifier::BOLD),
    );

    let name_w = chunks[0].width.saturating_sub(22).max(10) as usize;
    let rows: Vec<Row> = app
        .fleet
        .repos
        .iter()
        .map(|r| {
            let err_col = if r.error_rate >= 0.15 {
                Color::Red
            } else if r.error_rate >= 0.05 {
                Color::Yellow
            } else {
                Color::Green
            };
            Row::new(vec![
                Cell::from(truncate_ellipsis(&r.repo_name, name_w)),
                Cell::from(Line::from(r.session_count.to_string()).right_aligned()),
                Cell::from(Line::from(format_compact(r.total_stdout_tokens)).right_aligned()),
                Cell::from(Line::from(format!("{:.0}%", r.error_rate * 100.0)).right_aligned())
                    .style(Style::default().fg(err_col)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Fill(1),
            Constraint::Length(4),
            Constraint::Length(5),
            Constraint::Length(4),
        ],
    )
    .header(header)
    .column_spacing(1)
    .block(rounded_block(
        format!(" Fleet Repos ({}) ", app.fleet.repos.len()),
        focused,
    ))
    .row_highlight_style(row_highlight_style())
    .highlight_symbol("▶ ");
    frame.render_stateful_widget(table, chunks[0], &mut app.repo_state);

    // Bottom: Cross-repo systemic patterns
    let sys_lines: Vec<Line> = if app.fleet.systemic_patterns.is_empty() {
        vec![Line::from(Span::styled(
            "No patterns across ≥2 repos in this window.",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        app.fleet
            .systemic_patterns
            .iter()
            .take(6)
            .map(|p| {
                Line::from(vec![
                    Span::raw(truncate_ellipsis(&p.cmd_template, name_w)),
                    Span::styled(
                        format!(
                            " · {}r · {}",
                            p.repo_count,
                            format_compact(p.total_stdout_tokens)
                        ),
                        Style::default().fg(Color::Gray),
                    ),
                ])
            })
            .collect()
    };
    let sys_box = Paragraph::new(sys_lines).block(rounded_block(
        format!(" Cross-Repo ({}) ", app.fleet.systemic_patterns.len()),
        false,
    ));
    frame.render_widget(sys_box, chunks[1]);
}

fn draw_active_tab(frame: &mut Frame, area: Rect, app: &mut App) {
    match app.tab {
        DetailTab::Insights => draw_insights_tab(frame, area, app),
        DetailTab::Patterns => draw_patterns_tab(frame, area, app),
        DetailTab::Harnesses => draw_harnesses_tab(frame, area, app),
        DetailTab::Commands => draw_commands_tab(frame, area, app),
        DetailTab::Brief => draw_brief_tab(frame, area, app),
        DetailTab::Issues => draw_issues_tab(frame, area, app),
    }
}

// ---------------------------------------------------------------------------
// Shared Diagnosis Card Renderer (Used by Tab 1 Insights & Tab 3 Harnesses)
// ---------------------------------------------------------------------------

fn render_opportunity_diagnosis(
    frame: &mut Frame,
    area: Rect,
    item: &MergedInsight,
    focused: bool,
) {
    let o = &item.primary;
    let (_, sev_col) = human_problem(&o.kind);
    let headline = insight_headline(o);
    let (scope_badge, scope_col) = if o.scope == "harness" {
        ("AGENT RUNTIME", Color::LightBlue)
    } else {
        ("REPO HARNESS", Color::Green)
    };

    let card_title = Line::from(vec![
        Span::styled(" ● ", Style::default().fg(sev_col)),
        Span::styled(
            format!(
                "{} ",
                truncate_ellipsis(&headline, area.width.saturating_sub(28).max(16) as usize)
            ),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("[{scope_badge}] "),
            Style::default().fg(scope_col).add_modifier(Modifier::BOLD),
        ),
    ]);

    let mut lines: Vec<Line<'static>> = Vec::new();

    // 1. Plain-English Diagnosis
    lines.push(Line::from(Span::styled(
        "WHAT'S HAPPENING",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));
    for para in insight_story(o) {
        lines.push(Line::from(para));
    }
    if !item.related.is_empty() {
        let also: Vec<String> = item
            .related
            .iter()
            .map(|r| {
                let (rl, _) = human_problem(&r.kind);
                let m = compact_opp_metric(r);
                format!("{rl} ({m})")
            })
            .collect();
        lines.push(Line::from(vec![
            Span::styled(
                "Related: ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(also.join(" · "), Style::default().fg(Color::Yellow)),
        ]));
    }

    // 2. Who hits this (visual harness bars)
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "WHICH HARNESS HITS THIS",
        Style::default()
            .fg(Color::LightMagenta)
            .add_modifier(Modifier::BOLD),
    )));
    let bar_w = if area.width >= 56 { 14 } else { 10 };
    lines.extend(harness_bar_lines(&o.by_harness, bar_w));

    // 3. Cleaned Concrete Evidence
    let cleaned_proofs: Vec<String> = o
        .trace_proof
        .iter()
        .map(|tp| {
            if let Some(rest) = tp.strip_prefix("Sample error: ") {
                let unquoted = rest.trim_matches('`');
                let c = clean_error_preview(unquoted);
                if c.is_empty() {
                    String::new()
                } else {
                    format!("Error: {c}")
                }
            } else {
                tp.clone()
            }
        })
        .filter(|s| !s.is_empty())
        .take(3)
        .collect();
    if !cleaned_proofs.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "REAL EVIDENCE FROM TRACES",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )));
        for tp in cleaned_proofs {
            lines.push(Line::from(Span::styled(
                format!("• {tp}"),
                Style::default().fg(Color::Gray),
            )));
        }
    }

    // 4. Actionable Fix & Plain-English Goal
    let (fix_text, goal_text) = insight_fix_guidance(o);
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(
            "HOW TO FIX ",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("({})", o.fix_target),
            Style::default().fg(Color::DarkGray),
        ),
    ]));
    lines.push(Line::from(fix_text));
    lines.push(Line::from(vec![
        Span::styled("Success target: ", Style::default().fg(Color::DarkGray)),
        Span::styled(goal_text, Style::default().fg(Color::Green)),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Press [Enter] to inspect full redacted command/tool trace samples",
        Style::default().fg(Color::DarkGray),
    )));

    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(rounded_block(card_title, focused)),
        area,
    );
}

// ---------------------------------------------------------------------------
// Tab 1: Insights (Executive Summary Strip + Master/Detail Diagnosis)
// ---------------------------------------------------------------------------

fn draw_insights_tab(frame: &mut Frame, area: Rect, app: &mut App) {
    let focused = app.focus == Focus::Main;
    let Some(repo) = app.selected_repo.clone() else {
        let empty = Paragraph::new(
            "No repository telemetry in this window.\nPress 'w' to widen the window or 'r' to sync transcripts.",
        )
        .block(rounded_block(" Insights ", focused));
        frame.render_widget(empty, area);
        return;
    };

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(10)])
        .split(area);

    // 1. Plain-English Executive KPI Strip
    let k = &repo.kpis;
    let cards = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(rows[0]);

    let merged = app.visible_insights();
    let repo_refs: Vec<&Opportunity> = repo.opportunities.iter().collect();
    let harn_refs: Vec<&Opportunity> = repo.harness_overhead.iter().collect();
    let repo_cnt = merge_opportunities(&repo_refs).len();
    let harn_cnt = merge_opportunities(&harn_refs).len();
    let top_issue_hint = merged
        .first()
        .map(|m| format!("Top: {}", primary_metric_for(m)))
        .unwrap_or_else(|| "No major bottlenecks".into());
    let card1 = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                format!("{}", repo_cnt + harn_cnt),
                Style::default()
                    .fg(if repo_cnt + harn_cnt > 0 {
                        Color::Yellow
                    } else {
                        Color::Green
                    })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" issues ({repo_cnt} repo · {harn_cnt} runtime)"),
                Style::default().fg(Color::Gray),
            ),
        ]),
        Line::from(Span::styled(
            top_issue_hint,
            Style::default().fg(Color::Gray),
        )),
    ])
    .block(rounded_block(" Bottlenecks Found ", false));

    let wait_sub = if k.latency.total_api_wait_s > 0.0 {
        format!(
            "API {} · med {}/sess",
            format_duration(k.latency.total_api_wait_s),
            format_duration(k.median_tool_wait_s)
        )
    } else {
        format!("{} median / session", format_duration(k.median_tool_wait_s))
    };
    let card2 = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                format_duration(k.latency.total_tool_wall_s),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                if k.latency.tool_parallelism_ratio > 1.05 {
                    format!(" tool wall ({:.1}×)", k.latency.tool_parallelism_ratio)
                } else {
                    " tool wait".to_string()
                },
                Style::default().fg(Color::Gray),
            ),
        ]),
        Line::from(Span::styled(wait_sub, Style::default().fg(Color::Gray))),
    ])
    .block(rounded_block(" Time Waiting ", false));

    let cache_str = k
        .cache_hit_rate
        .map(|v| format!("{:.0}% cache", v * 100.0))
        .unwrap_or_else(|| "no cache".into());
    let cost_str = if k.estimated_cost_usd > 0.0 {
        format!("~${:.2} est", k.estimated_cost_usd)
    } else {
        format!("{} stdout", format_compact(k.total_stdout_tokens))
    };
    let card3 = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                format_compact(k.median_tokens_per_session),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" med uncached", Style::default().fg(Color::Gray)),
        ]),
        Line::from(Span::styled(
            format!("{cache_str} · {cost_str}"),
            Style::default().fg(Color::Gray),
        )),
    ])
    .block(rounded_block(" Context & Cost ", false));

    let err_col = if k.command_error_rate >= 0.10 {
        Color::Red
    } else if k.command_error_rate >= 0.04 {
        Color::Yellow
    } else {
        Color::Green
    };
    let cli_str = k
        .cli_adoption_rate
        .map(|v| format!("{:.0}% repo CLI", v * 100.0))
        .unwrap_or_else(|| "no repo CLI".into());
    let card4 = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                format!("{:.1}%", k.command_error_rate * 100.0),
                Style::default().fg(err_col).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" cmd errors", Style::default().fg(Color::Gray)),
        ]),
        Line::from(Span::styled(
            format!(
                "{cli_str} · {:.0}% fallbacks",
                k.escape_hatch_rebound_rate * 100.0
            ),
            Style::default().fg(if k.escape_hatch_rebound_rate >= 0.30 {
                Color::Yellow
            } else {
                Color::Gray
            }),
        )),
    ])
    .block(rounded_block(" Reliability & CLI ", false));

    frame.render_widget(card1, cards[0]);
    frame.render_widget(card2, cards[1]);
    frame.render_widget(card3, cards[2]);
    frame.render_widget(card4, cards[3]);

    // 2. Master-Detail Layout (Side-by-Side on wide terminals, Stacked on narrow)
    let side_by_side = rows[1].width >= 104;
    let panes = if side_by_side {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
            .split(rows[1])
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
            .split(rows[1])
    };

    let filter_title = Line::from(vec![
        Span::styled(
            format!(" Issues ({}) ", merged.len()),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled("─ ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("[{}]", app.scope_filter.label()),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("  (f) ", Style::default().fg(Color::DarkGray)),
    ]);

    if merged.is_empty() {
        let p = Paragraph::new(
            "No friction issues in this scope & window.\nPress 'f' to cycle scope (All / Repo harness / Agent runtime) or 'w' to widen window.",
        )
        .block(rounded_block(filter_title, focused));
        frame.render_widget(p, panes[0]);
    } else {
        let max_score = merged
            .iter()
            .map(|m| m.primary.score.max(1))
            .max()
            .unwrap_or(1) as f64;
        let show_load_bar = panes[0].width >= 56;
        let issue_w = if show_load_bar {
            panes[0].width.saturating_sub(38).max(16) as usize
        } else {
            panes[0].width.saturating_sub(30).max(16) as usize
        };

        let header = if show_load_bar {
            Row::new(vec![
                Cell::from("Origin"),
                Cell::from("Issue"),
                Cell::from(Line::from("Impact").right_aligned()),
                Cell::from("Load"),
            ])
        } else {
            Row::new(vec![
                Cell::from("Origin"),
                Cell::from("Issue"),
                Cell::from(Line::from("Impact").right_aligned()),
            ])
        }
        .style(
            Style::default()
                .fg(Color::Gray)
                .add_modifier(Modifier::BOLD),
        );

        let table_rows: Vec<Row> = merged
            .iter()
            .map(|item| {
                let o = &item.primary;
                let (_, sev_col) = human_problem(&o.kind);
                let (tag, tag_col) = if o.scope == "harness" {
                    ("HARN", Color::LightBlue)
                } else {
                    ("REPO", Color::Green)
                };
                let origin_cell = Cell::from(Line::from(vec![
                    Span::styled("● ", Style::default().fg(sev_col)),
                    Span::styled(
                        tag,
                        Style::default().fg(tag_col).add_modifier(Modifier::BOLD),
                    ),
                ]));
                let headline = insight_headline(o);
                let issue_cell = Cell::from(truncate_ellipsis(&headline, issue_w));
                let metric = primary_metric_for(item);
                let impact_cell = Cell::from(Line::from(metric).right_aligned())
                    .style(Style::default().fg(Color::White));

                if show_load_bar {
                    let frac = (o.score.max(0) as f64 / max_score).sqrt().clamp(0.15, 1.0);
                    let bar_cell =
                        Cell::from(bar_string(frac, 6)).style(Style::default().fg(sev_col));
                    Row::new(vec![origin_cell, issue_cell, impact_cell, bar_cell])
                } else {
                    Row::new(vec![origin_cell, issue_cell, impact_cell])
                }
            })
            .collect();

        let constraints: Vec<Constraint> = if show_load_bar {
            vec![
                Constraint::Length(6),
                Constraint::Fill(1),
                Constraint::Length(17),
                Constraint::Length(6),
            ]
        } else {
            vec![
                Constraint::Length(6),
                Constraint::Fill(1),
                Constraint::Length(17),
            ]
        };

        let table = Table::new(table_rows, constraints)
            .header(header)
            .column_spacing(1)
            .block(rounded_block(filter_title, focused))
            .row_highlight_style(row_highlight_style())
            .highlight_symbol("▶ ");
        frame.render_stateful_widget(table, panes[0], &mut app.opp_state);
    }

    // 3. Full Plain-English Diagnosis Panel
    if let Some(idx) = app.opp_state.selected()
        && let Some(item) = merged.get(idx)
    {
        render_opportunity_diagnosis(frame, panes[1], item, false);
    } else {
        let p = Paragraph::new(
            "Select an issue on the left to read its plain-English diagnosis, harness split, real trace evidence, and fix guidance.",
        )
        .wrap(Wrap { trim: true })
        .block(rounded_block(" Diagnosis ", false));
        frame.render_widget(p, panes[1]);
    }
}

// ---------------------------------------------------------------------------
// Tab 2: Patterns & Loops (Pareto/Handoff Strip + Master/Detail Visualizer)
// ---------------------------------------------------------------------------

fn draw_patterns_tab(frame: &mut Frame, area: Rect, app: &mut App) {
    let focused = app.focus == Focus::Main;
    let Some(pat) = app.selected_patterns.clone() else {
        let p = Paragraph::new("No cross-session pattern data loaded for this repo.")
            .block(rounded_block(" Patterns ", focused));
        frame.render_widget(p, area);
        return;
    };

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(10)])
        .split(area);

    // Top summary: Pareto concentration + Handoff inflation
    let top_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(54), Constraint::Percentage(46)])
        .split(rows[0]);

    let p = &pat.pareto;
    let pareto_frac = p.top25_token_share_pct / 100.0;
    let pareto_box = Paragraph::new(vec![
        Line::from(vec![
            Span::raw("Top 25% sessions use  "),
            Span::styled(
                bar_string(pareto_frac, 14),
                Style::default().fg(Color::Yellow),
            ),
            Span::styled(
                format!("  {:.0}% of all tokens", p.top25_token_share_pct),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(Span::styled(
            format!(
                "Top 25% median: {} ({:.0} turns) vs Bottom 50%: {} ({:.0} turns) — {:.1}×",
                format_compact(p.top25_median_tokens),
                p.top25_avg_turns,
                format_compact(p.bottom50_median_tokens),
                p.bottom50_avg_turns,
                p.median_multiplier
            ),
            Style::default().fg(Color::Gray),
        )),
    ])
    .block(rounded_block(
        " Session Cost Concentration (Pareto) ",
        false,
    ));
    frame.render_widget(pareto_box, top_cols[0]);

    let handoff_line = if let Some(h) = &pat.handoff_summary {
        Line::from(vec![
            Span::raw("Resumed/handoff sessions burn "),
            Span::styled(
                format!("{:.1}×", h.token_multiplier),
                Style::default()
                    .fg(if h.token_multiplier >= 2.0 {
                        Color::Red
                    } else {
                        Color::Cyan
                    })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" more tokens ({} sess)", h.handoff_sessions)),
        ])
    } else {
        Line::from(Span::styled(
            "No handoff inflation detected in this window",
            Style::default().fg(Color::Gray),
        ))
    };
    let handoff_box = Paragraph::new(vec![
        handoff_line,
        Line::from(Span::styled(
            format!(
                "{} main · {} subagent sessions · err {:.1}% → {:.1}%",
                pat.main_sessions,
                pat.subagent_sessions,
                pat.early_error_rate * 100.0,
                pat.recent_error_rate * 100.0
            ),
            Style::default().fg(Color::Gray),
        )),
    ])
    .block(rounded_block(" Handoff & Session Split ", false));
    frame.render_widget(handoff_box, top_cols[1]);

    // Bottom master/detail split: Left selectable list (56%) | Right vertical visualizer (44%)
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(56), Constraint::Percentage(44)])
        .split(rows[1]);

    let wf_cnt = if !pat.repeating_sequences.is_empty() {
        pat.repeating_sequences.len()
    } else {
        pat.recurring_motifs.len()
    };
    let drift_cnt =
        pat.temporal_drift.len() + pat.cold_start_errors.len() + pat.post_cli_doc_reads.len();

    let pill = |active: bool, txt: String| {
        if active {
            Span::styled(
                format!("[{txt}]"),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled(txt, Style::default().fg(Color::DarkGray))
        }
    };
    let list_title = Line::from(vec![
        Span::raw(" "),
        pill(
            app.patterns_view == PatternsView::Workflows,
            format!("Workflows ({wf_cnt})"),
        ),
        Span::styled(" · ", Style::default().fg(Color::DarkGray)),
        pill(
            app.patterns_view == PatternsView::Storms,
            format!("Burst Storms ({})", pat.burst_storms.len()),
        ),
        Span::styled(" · ", Style::default().fg(Color::DarkGray)),
        pill(
            app.patterns_view == PatternsView::Drift,
            format!("Drift & Cold-Start ({drift_cnt})"),
        ),
        Span::styled("  (v) ", Style::default().fg(Color::DarkGray)),
    ]);

    let left_w = cols[0].width.saturating_sub(34).max(16) as usize;
    match app.patterns_view {
        PatternsView::Workflows => {
            let header = Row::new(vec![
                Cell::from("Steps"),
                Cell::from("Repeating Workflow"),
                Cell::from(Line::from("Sess").right_aligned()),
                Cell::from(Line::from("Runs").right_aligned()),
                Cell::from(Line::from("Wait").right_aligned()),
            ])
            .style(
                Style::default()
                    .fg(Color::Gray)
                    .add_modifier(Modifier::BOLD),
            );

            let using_seqs = !pat.repeating_sequences.is_empty();
            let table_rows: Vec<Row> = if using_seqs {
                pat.repeating_sequences
                    .iter()
                    .map(|s| {
                        Row::new(vec![
                            Cell::from(format!("{}-step", s.step_count))
                                .style(Style::default().fg(Color::Cyan)),
                            Cell::from(truncate_ellipsis(&s.sequence, left_w)),
                            Cell::from(
                                Line::from(format!("{:.0}%", s.session_prevalence * 100.0))
                                    .right_aligned(),
                            ),
                            Cell::from(Line::from(s.occurrences.to_string()).right_aligned()),
                            Cell::from(Line::from(format_duration(s.total_wait_s)).right_aligned())
                                .style(Style::default().fg(Color::Yellow)),
                        ])
                    })
                    .collect()
            } else {
                pat.recurring_motifs
                    .iter()
                    .map(|m| {
                        Row::new(vec![
                            Cell::from("2-step").style(Style::default().fg(Color::Cyan)),
                            Cell::from(truncate_ellipsis(&m.sequence, left_w)),
                            Cell::from(
                                Line::from(format!("{:.0}%", m.session_prevalence * 100.0))
                                    .right_aligned(),
                            ),
                            Cell::from(Line::from(m.occurrences.to_string()).right_aligned()),
                            Cell::from(Line::from(format_duration(m.total_wait_s)).right_aligned())
                                .style(Style::default().fg(Color::Yellow)),
                        ])
                    })
                    .collect()
            };

            let table = Table::new(
                table_rows,
                [
                    Constraint::Length(7),
                    Constraint::Fill(1),
                    Constraint::Length(5),
                    Constraint::Length(5),
                    Constraint::Length(7),
                ],
            )
            .header(header)
            .column_spacing(1)
            .block(rounded_block(list_title, focused))
            .row_highlight_style(row_highlight_style())
            .highlight_symbol("▶ ");
            frame.render_stateful_widget(table, cols[0], &mut app.pattern_state);

            // Right detail: vertical step-by-step workflow visualizer
            let mut detail_lines = Vec::new();
            let sel = app.pattern_state.selected().unwrap_or(0);
            if using_seqs && let Some(s) = pat.repeating_sequences.get(sel) {
                detail_lines.push(Line::from(Span::styled(
                    format!("STEP-BY-STEP CHAIN ({} calls)", s.step_count),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )));
                for (i, step) in s.steps.iter().enumerate() {
                    detail_lines.push(Line::from(vec![
                        Span::styled(format!(" {:>2}. ", i + 1), Style::default().fg(Color::Cyan)),
                        Span::raw(step.clone()),
                    ]));
                    if i + 1 < s.steps.len() && s.steps.len() <= 6 {
                        detail_lines.push(Line::from(Span::styled(
                            "      ↓",
                            Style::default().fg(Color::DarkGray),
                        )));
                    }
                }
                detail_lines.push(Line::from(""));
                detail_lines.push(Line::from(Span::styled(
                    "IMPACT",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )));
                detail_lines.push(Line::from(format!(
                    "Repeated {}× across {}/{} sessions ({:.0}%)",
                    s.occurrences,
                    s.sessions,
                    s.total_sessions,
                    s.session_prevalence * 100.0
                )));
                detail_lines.push(Line::from(Span::styled(
                    format!(
                        "Stdout: {} · Effective: {} · Wait: {}",
                        format_compact(s.total_stdout_tokens),
                        format_compact(s.total_effective_tokens),
                        format_duration(s.total_wait_s)
                    ),
                    Style::default().fg(Color::Gray),
                )));
                detail_lines.push(Line::from(""));
                detail_lines.push(Line::from(Span::styled(
                    "HARNESS SPLIT",
                    Style::default()
                        .fg(Color::LightMagenta)
                        .add_modifier(Modifier::BOLD),
                )));
                detail_lines.extend(harness_bar_lines(&s.by_harness, 10));
                if !s.sample_trace.is_empty() {
                    detail_lines.push(Line::from(""));
                    detail_lines.push(Line::from(Span::styled(
                        "SAMPLE TRACE",
                        Style::default()
                            .fg(Color::Gray)
                            .add_modifier(Modifier::BOLD),
                    )));
                    detail_lines.push(Line::from(Span::styled(
                        s.sample_trace.clone(),
                        Style::default().fg(Color::Gray),
                    )));
                }
            } else if let Some(m) = pat.recurring_motifs.get(sel) {
                detail_lines.push(Line::from(Span::styled(
                    "2-STEP TRAJECTORY",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )));
                for (i, part) in m.sequence.split(" -> ").enumerate() {
                    detail_lines.push(Line::from(format!("  {}. {part}", i + 1)));
                }
                detail_lines.push(Line::from(""));
                detail_lines.push(Line::from(format!(
                    "Repeated {}× across {}/{} sessions ({:.0}%)",
                    m.occurrences,
                    m.sessions,
                    m.total_sessions,
                    m.session_prevalence * 100.0
                )));
                detail_lines.push(Line::from(Span::styled(
                    format!(
                        "Stdout: {} · Effective: {} · Wait: {}",
                        format_compact(m.total_stdout_tokens),
                        format_compact(m.total_effective_tokens),
                        format_duration(m.total_wait_s)
                    ),
                    Style::default().fg(Color::Gray),
                )));
                detail_lines.push(Line::from(""));
                detail_lines.extend(harness_bar_lines(&m.by_harness, 10));
            } else {
                detail_lines.push(Line::from(Span::styled(
                    "No repeating multi-step workflows detected in this window.",
                    Style::default().fg(Color::DarkGray),
                )));
            }
            frame.render_widget(
                Paragraph::new(detail_lines)
                    .wrap(Wrap { trim: true })
                    .block(rounded_block(" Workflow Breakdown ", false)),
                cols[1],
            );
        }
        PatternsView::Storms => {
            let header = Row::new(vec![
                Cell::from("Command (≥5 calls / session)"),
                Cell::from(Line::from("Sess").right_aligned()),
                Cell::from(Line::from("Max").right_aligned()),
                Cell::from(Line::from("Calls").right_aligned()),
                Cell::from(Line::from("Wait").right_aligned()),
            ])
            .style(
                Style::default()
                    .fg(Color::Gray)
                    .add_modifier(Modifier::BOLD),
            );

            let table_rows: Vec<Row> = pat
                .burst_storms
                .iter()
                .map(|s| {
                    Row::new(vec![
                        Cell::from(truncate_ellipsis(&s.cmd_template, left_w)),
                        Cell::from(Line::from(s.storm_sessions.to_string()).right_aligned()),
                        Cell::from(
                            Line::from(format!("{}×", s.max_calls_in_session)).right_aligned(),
                        )
                        .style(Style::default().fg(Color::Yellow)),
                        Cell::from(Line::from(s.total_calls_in_storms.to_string()).right_aligned()),
                        Cell::from(Line::from(format_duration(s.total_wait_s)).right_aligned()),
                    ])
                })
                .collect();

            let table = Table::new(
                table_rows,
                [
                    Constraint::Fill(1),
                    Constraint::Length(5),
                    Constraint::Length(5),
                    Constraint::Length(6),
                    Constraint::Length(7),
                ],
            )
            .header(header)
            .column_spacing(1)
            .block(rounded_block(list_title, focused))
            .row_highlight_style(row_highlight_style())
            .highlight_symbol("▶ ");
            frame.render_stateful_widget(table, cols[0], &mut app.pattern_state);

            let sel = app.pattern_state.selected().unwrap_or(0);
            let mut detail_lines = Vec::new();
            if let Some(s) = pat.burst_storms.get(sel) {
                detail_lines.push(Line::from(Span::styled(
                    s.cmd_template.clone(),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )));
                detail_lines.push(Line::from(""));
                detail_lines.push(Line::from(format!(
                    "{} total storm calls across {} sessions (worst session: {}×)",
                    format_int(s.total_calls_in_storms),
                    s.storm_sessions,
                    s.max_calls_in_session
                )));
                detail_lines.push(Line::from(Span::styled(
                    format!(
                        "Stdout: {} · Effective context: {} · Wait: {}",
                        format_compact(s.total_stdout_tokens),
                        format_compact(s.total_effective_tokens),
                        format_duration(s.total_wait_s)
                    ),
                    Style::default().fg(Color::Gray),
                )));
                detail_lines.push(Line::from(""));
                detail_lines.push(Line::from(Span::styled(
                    "HARNESS SPLIT",
                    Style::default()
                        .fg(Color::LightMagenta)
                        .add_modifier(Modifier::BOLD),
                )));
                detail_lines.extend(harness_bar_lines(&s.by_harness, 10));
                if !pat.pareto.storm_lifts.is_empty() {
                    detail_lines.push(Line::from(""));
                    detail_lines.push(Line::from(Span::styled(
                        "WHAT DRIVES EXPENSIVE SESSIONS (TOP 25% VS TYPICAL)",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )));
                    for lift in pat.pareto.storm_lifts.iter().take(5) {
                        let frac = (lift.top25_pct_sessions / 100.0).clamp(0.0, 1.0);
                        let lift_clean = if lift.lift_str.starts_with("inf") {
                            "top-25% only".to_string()
                        } else {
                            lift.lift_str.clone()
                        };
                        detail_lines.push(Line::from(vec![
                            Span::styled(
                                format!("{:<16} ", truncate_ellipsis(&lift.family, 16)),
                                Style::default().fg(Color::White),
                            ),
                            Span::styled(bar_string(frac, 8), Style::default().fg(Color::Yellow)),
                            Span::styled(
                                format!(
                                    " {:>3.0}% vs {:>2.0}% ({lift_clean})",
                                    lift.top25_pct_sessions, lift.bottom50_pct_sessions
                                ),
                                Style::default().fg(Color::Gray),
                            ),
                        ]));
                    }
                }
            } else {
                detail_lines.push(Line::from(Span::styled(
                    "No serial burst storms detected.",
                    Style::default().fg(Color::DarkGray),
                )));
            }
            frame.render_widget(
                Paragraph::new(detail_lines)
                    .wrap(Wrap { trim: true })
                    .block(rounded_block(" Burst Storm Detail ", false)),
                cols[1],
            );
        }
        PatternsView::Drift => {
            let mut rows_vec: Vec<Row> = Vec::new();
            for d in &pat.temporal_drift {
                let (tag, col) = match d.status.as_str() {
                    "surging" => ("SURGING", Color::Red),
                    "regressing" => ("REGRESS", Color::Red),
                    "improving" => ("IMPROVE", Color::Green),
                    _ => ("CHRONIC", Color::Yellow),
                };
                let delta_str = if d.early_runs == 0 {
                    format!("NEW +{}", d.recent_runs)
                } else {
                    format!("{:.1}×", d.rate_ratio)
                };
                rows_vec.push(Row::new(vec![
                    Cell::from(tag).style(Style::default().fg(col).add_modifier(Modifier::BOLD)),
                    Cell::from(truncate_ellipsis(&d.cmd_family, left_w)),
                    Cell::from(Line::from(delta_str).right_aligned()),
                ]));
            }
            for c in &pat.cold_start_errors {
                rows_vec.push(Row::new(vec![
                    Cell::from("COLD-ERR")
                        .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                    Cell::from(truncate_ellipsis(&c.error_class, left_w)),
                    Cell::from(
                        Line::from(format!("{}/{}", c.failures_turns_1_3, c.total_failures))
                            .right_aligned(),
                    ),
                ]));
            }
            for pr in &pat.post_cli_doc_reads {
                rows_vec.push(Row::new(vec![
                    Cell::from("DOC-READ").style(
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Cell::from(truncate_ellipsis(&pr.cmd_template, left_w)),
                    Cell::from(
                        Line::from(format!("{:.0}%", pr.follow_up_rate * 100.0)).right_aligned(),
                    ),
                ]));
            }

            let header = Row::new(vec![
                Cell::from("Signal"),
                Cell::from("Command / Error Class"),
                Cell::from(Line::from("Delta").right_aligned()),
            ])
            .style(
                Style::default()
                    .fg(Color::Gray)
                    .add_modifier(Modifier::BOLD),
            );

            let table = Table::new(
                rows_vec,
                [
                    Constraint::Length(9),
                    Constraint::Fill(1),
                    Constraint::Length(8),
                ],
            )
            .header(header)
            .column_spacing(1)
            .block(rounded_block(list_title, focused))
            .row_highlight_style(row_highlight_style())
            .highlight_symbol("▶ ");
            frame.render_stateful_widget(table, cols[0], &mut app.pattern_state);

            // Right detail for selected drift / cold-start / post-doc item
            let sel = app.pattern_state.selected().unwrap_or(0);
            let n_drift = pat.temporal_drift.len();
            let n_cold = pat.cold_start_errors.len();
            let mut detail_lines = Vec::new();
            if sel < n_drift {
                let d = &pat.temporal_drift[sel];
                detail_lines.push(Line::from(Span::styled(
                    format!("{} ({})", d.cmd_family, d.status.to_uppercase()),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )));
                detail_lines.push(Line::from(""));
                detail_lines.push(Line::from(d.summary.clone()));
                detail_lines.push(Line::from(Span::styled(
                    format!(
                        "Early half: {} runs ({:.1}/1k, err {:.0}%, p50 {})",
                        d.early_runs,
                        d.early_per_1k,
                        d.early_error_rate * 100.0,
                        format_duration(d.early_p50_wait_s)
                    ),
                    Style::default().fg(Color::Gray),
                )));
                detail_lines.push(Line::from(Span::styled(
                    format!(
                        "Recent half: {} runs ({:.1}/1k, err {:.0}%, p50 {})",
                        d.recent_runs,
                        d.recent_per_1k,
                        d.recent_error_rate * 100.0,
                        format_duration(d.recent_p50_wait_s)
                    ),
                    Style::default().fg(Color::Gray),
                )));
                detail_lines.push(Line::from(""));
                detail_lines.extend(harness_bar_lines(&d.by_harness, 10));
            } else if sel < n_drift + n_cold {
                let c = &pat.cold_start_errors[sel - n_drift];
                detail_lines.push(Line::from(Span::styled(
                    format!("Cold-Start Error: {}", c.error_class),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )));
                detail_lines.push(Line::from(""));
                detail_lines.push(Line::from(format!(
                    "{}/{} failures happen in turns 1–3 ({:.0}%) across {} sessions ({} worktrees)",
                    c.failures_turns_1_3,
                    c.total_failures,
                    c.pct_in_turns_1_3,
                    c.sessions,
                    c.worktrees
                )));
                detail_lines.push(Line::from(""));
                detail_lines.extend(harness_bar_lines(&c.by_harness, 10));
                if !c.sample_stderr.is_empty() {
                    detail_lines.push(Line::from(""));
                    detail_lines.push(Line::from(Span::styled(
                        "SAMPLE STDERR",
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    )));
                    detail_lines.push(Line::from(Span::styled(
                        c.sample_stderr.clone(),
                        Style::default().fg(Color::Gray),
                    )));
                }
            } else if let Some(pr) = pat
                .post_cli_doc_reads
                .get(sel.saturating_sub(n_drift + n_cold))
            {
                detail_lines.push(Line::from(Span::styled(
                    format!("Post-CLI Doc Lookups: {}", pr.cmd_template),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )));
                detail_lines.push(Line::from(""));
                detail_lines.push(Line::from(format!(
                    "{:.1}% of {} runs ({}×) were followed within 2 turns by reading docs/config.",
                    pr.follow_up_rate * 100.0,
                    pr.runs,
                    pr.followed_by_doc_read
                )));
                detail_lines.push(Line::from(Span::styled(
                    format!("Top files read: {}", pr.top_doc_files.join(", ")),
                    Style::default().fg(Color::Yellow),
                )));
                detail_lines.push(Line::from(""));
                detail_lines.extend(harness_bar_lines(&pr.by_harness, 10));
            } else {
                detail_lines.push(Line::from(Span::styled(
                    "No drift or cold-start anomalies detected.",
                    Style::default().fg(Color::DarkGray),
                )));
            }
            frame.render_widget(
                Paragraph::new(detail_lines)
                    .wrap(Wrap { trim: true })
                    .block(rounded_block(" Anomaly Detail ", false)),
                cols[1],
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tab 3: Harnesses (Takeaways + Visual Scorecard + Interactive Harness Issues)
// ---------------------------------------------------------------------------

fn render_mcp_tool_diagnosis(frame: &mut Frame, area: Rect, t: &ToolStat) {
    let tool = clean_tool_label(&t.tool_name);
    let title = Line::from(vec![
        Span::styled(
            " ● ",
            Style::default().fg(if t.error_count > 0 {
                Color::Red
            } else {
                Color::Yellow
            }),
        ),
        Span::styled(
            format!("MCP Tool: {} ", truncate_ellipsis(&tool, 40)),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "[MCP TOOL] ",
            Style::default()
                .fg(Color::LightMagenta)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    let mut lines = vec![
        Line::from(Span::styled(
            "WHAT'S HAPPENING",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(format!(
            "`{tool}` failed on {} of {} calls ({:.0}% error rate) across {} sessions, with {} truncated outputs (avg {:.1} KB).",
            t.error_count,
            t.calls,
            t.error_rate * 100.0,
            t.sessions,
            t.truncated_count,
            t.avg_output_kb
        )),
        Line::from(""),
        Line::from(Span::styled(
            "WHICH HARNESS HITS THIS",
            Style::default()
                .fg(Color::LightMagenta)
                .add_modifier(Modifier::BOLD),
        )),
    ];
    lines.extend(harness_bar_lines(&t.by_harness, 12));

    if let Some(err) = &t.sample_error {
        let cleaned = clean_error_preview(err);
        if !cleaned.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "SAMPLE ERROR MESSAGE",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(Span::styled(
                cleaned,
                Style::default().fg(Color::Gray),
            )));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "HOW TO FIX",
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(
        "Inspect the MCP server schema, error handling, timeouts, or credentials for this tool — repeated tool errors stall agent turns and trigger manual shell fallbacks.",
    ));

    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(rounded_block(title, false)),
        area,
    );
}

fn draw_harnesses_tab(frame: &mut Frame, area: Rect, app: &mut App) {
    let focused = app.focus == Focus::Main;
    let Some(pat) = app.selected_patterns.clone() else {
        let p = Paragraph::new("No harness comparison data available.")
            .block(rounded_block(" Harnesses ", focused));
        frame.render_widget(p, area);
        return;
    };

    let harness_rows = app.visible_harness_rows();
    let mut issues_by_ag: HashMap<String, Vec<HarnessIssueItem>> = HashMap::new();
    for hr in &harness_rows {
        issues_by_ag
            .entry(hr.agent_kind.clone())
            .or_insert_with(|| app.issues_for_harness(&hr.agent_kind));
    }
    let table_h = (harness_rows.len() as u16 + 4).clamp(6, (area.height / 3).max(6));
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(table_h),
            Constraint::Min(10),
        ])
        .split(area);

    // 1. Auto-Synthesized Key Harness Takeaways
    let mut takeaway_lines: Vec<Line<'static>> = Vec::new();
    for hr in harness_rows.iter().take(2) {
        let issues = issues_by_ag
            .get(&hr.agent_kind)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let short = short_harness(&hr.agent_kind);
        let hcol = harness_color(short);
        let cache_txt = hr
            .weighted_cache_hit
            .map(|r| format!("{:.0}% cache", r * 100.0))
            .unwrap_or_else(|| "no cache data".into());
        let top_issue = issues
            .first()
            .map(|iss| match iss {
                HarnessIssueItem::Opp(m) => format!(
                    "{} ({})",
                    truncate_ellipsis(&insight_headline(&m.primary), 42),
                    primary_metric_for(m)
                ),
                HarnessIssueItem::McpTool(t) => format!(
                    "MCP {} failing ({:.0}%)",
                    clean_tool_label(&t.tool_name),
                    t.error_rate * 100.0
                ),
            })
            .unwrap_or_else(|| "no major harness issues flagged".into());
        takeaway_lines.push(Line::from(vec![
            Span::styled("● ", Style::default().fg(hcol)),
            Span::styled(
                format!("{short:<11} "),
                Style::default().fg(hcol).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(
                    "{} sess · {} cmds · {cache_txt}  →  ",
                    hr.sessions,
                    format_compact(hr.commands as i64)
                ),
                Style::default().fg(Color::Gray),
            ),
            Span::styled(top_issue, Style::default().fg(Color::White)),
        ]));
    }
    if takeaway_lines.is_empty() {
        takeaway_lines.push(Line::from(Span::styled(
            "No harness sessions recorded in this window.",
            Style::default().fg(Color::DarkGray),
        )));
    }
    frame.render_widget(
        Paragraph::new(takeaway_lines)
            .wrap(Wrap { trim: true })
            .block(rounded_block(" Harness Key Takeaways ", false)),
        rows[0],
    );

    // 2. Visual Harness Scorecard (Grouped by Agent by default, `d` toggles detailed strata)
    let max_wait = harness_rows
        .iter()
        .map(|h| h.median_tool_wait_s)
        .fold(1.0_f64, f64::max);
    let wide = rows[1].width >= 106;
    let header = if wide {
        Row::new(vec![
            Cell::from("Harness"),
            Cell::from(Line::from("Sess").right_aligned()),
            Cell::from(Line::from("Cmds").right_aligned()),
            Cell::from(Line::from("Med Toks").right_aligned()),
            Cell::from("Cache Hit"),
            Cell::from("Med Wait"),
            Cell::from(Line::from("Err%").right_aligned()),
            Cell::from(Line::from("Issues").right_aligned()),
        ])
    } else {
        Row::new(vec![
            Cell::from("Harness"),
            Cell::from(Line::from("Sess").right_aligned()),
            Cell::from(Line::from("Cmds").right_aligned()),
            Cell::from("Cache Hit"),
            Cell::from(Line::from("Err%").right_aligned()),
            Cell::from(Line::from("Issues").right_aligned()),
        ])
    }
    .style(
        Style::default()
            .fg(Color::Gray)
            .add_modifier(Modifier::BOLD),
    );

    let table_rows: Vec<Row> = harness_rows
        .iter()
        .map(|h| {
            let short = short_harness(&h.agent_kind);
            let hcol = harness_color(short);
            let issue_cnt = issues_by_ag.get(&h.agent_kind).map_or(0, Vec::len);
            let cache_cell = match h.weighted_cache_hit {
                Some(r) => {
                    let ccol = if r >= 0.85 {
                        Color::Green
                    } else if r >= 0.70 {
                        Color::Yellow
                    } else {
                        Color::Red
                    };
                    Cell::from(Line::from(vec![
                        Span::styled(bar_string(r, 8), Style::default().fg(ccol)),
                        Span::raw(format!(" {:>3.0}%", r * 100.0)),
                    ]))
                }
                None => Cell::from("n/a").style(Style::default().fg(Color::DarkGray)),
            };
            let wait_frac = (h.median_tool_wait_s / max_wait).clamp(0.0, 1.0);
            let wait_cell = Cell::from(Line::from(vec![
                Span::styled(bar_string(wait_frac, 6), Style::default().fg(Color::Yellow)),
                Span::raw(format!(" {:>5}", format_duration(h.median_tool_wait_s))),
            ]));
            let err_col = if h.error_rate >= 0.08 {
                Color::Red
            } else if h.error_rate >= 0.03 {
                Color::Yellow
            } else {
                Color::Green
            };
            let iss_col = if issue_cnt >= 4 {
                Color::Yellow
            } else if issue_cnt > 0 {
                Color::Cyan
            } else {
                Color::Green
            };

            if wide {
                Row::new(vec![
                    Cell::from(truncate_ellipsis(&h.label, 28))
                        .style(Style::default().fg(hcol).add_modifier(Modifier::BOLD)),
                    Cell::from(Line::from(h.sessions.to_string()).right_aligned()),
                    Cell::from(Line::from(format_compact(h.commands as i64)).right_aligned()),
                    Cell::from(Line::from(format_compact(h.median_total_tokens)).right_aligned()),
                    cache_cell,
                    wait_cell,
                    Cell::from(Line::from(format!("{:.1}%", h.error_rate * 100.0)).right_aligned())
                        .style(Style::default().fg(err_col)),
                    Cell::from(Line::from(issue_cnt.to_string()).right_aligned())
                        .style(Style::default().fg(iss_col).add_modifier(Modifier::BOLD)),
                ])
            } else {
                Row::new(vec![
                    Cell::from(truncate_ellipsis(&h.label, 24))
                        .style(Style::default().fg(hcol).add_modifier(Modifier::BOLD)),
                    Cell::from(Line::from(h.sessions.to_string()).right_aligned()),
                    Cell::from(Line::from(format_compact(h.commands as i64)).right_aligned()),
                    cache_cell,
                    Cell::from(Line::from(format!("{:.1}%", h.error_rate * 100.0)).right_aligned())
                        .style(Style::default().fg(err_col)),
                    Cell::from(Line::from(issue_cnt.to_string()).right_aligned())
                        .style(Style::default().fg(iss_col).add_modifier(Modifier::BOLD)),
                ])
            }
        })
        .collect();

    let constraints: Vec<Constraint> = if wide {
        vec![
            Constraint::Fill(1),
            Constraint::Length(5),
            Constraint::Length(6),
            Constraint::Length(8),
            Constraint::Length(14),
            Constraint::Length(13),
            Constraint::Length(6),
            Constraint::Length(6),
        ]
    } else {
        vec![
            Constraint::Fill(1),
            Constraint::Length(5),
            Constraint::Length(6),
            Constraint::Length(14),
            Constraint::Length(6),
            Constraint::Length(6),
        ]
    };

    let mode_lbl = if app.harness_show_strata {
        "Detailed Strata"
    } else {
        "By Harness"
    };
    let table_title = Line::from(vec![
        Span::styled(
            format!(" Harness Scorecard ({}) ", harness_rows.len()),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("─ [{mode_lbl}] (d)  ·  [Space/Enter] Focus issues below "),
            Style::default().fg(Color::DarkGray),
        ),
    ]);
    let table = Table::new(table_rows, constraints)
        .header(header)
        .column_spacing(2)
        .block(rounded_block(
            table_title,
            focused && !app.harness_focus_issues,
        ))
        .row_highlight_style(row_highlight_style())
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(table, rows[1], &mut app.harness_state);

    // 3. Bottom Master-Detail: Selectable Harness Issues (Left) + Full Plain-English Diagnosis (Right)
    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
        .split(rows[2]);

    let sel_h = app
        .harness_state
        .selected()
        .and_then(|i| harness_rows.get(i));
    let selected_ag = sel_h.map(|h| h.agent_kind.as_str()).unwrap_or("");
    let short_ag = short_harness(selected_ag);
    let issues = issues_by_ag
        .get(selected_ag)
        .map(Vec::as_slice)
        .unwrap_or(&[]);

    let iss_title = Line::from(vec![
        Span::styled(
            format!(" Issues in {short_ag} ({}) ", issues.len()),
            Style::default()
                .fg(harness_color(short_ag))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            if app.harness_focus_issues {
                "─ [j/k · Enter traces · Space back] "
            } else {
                "─ [Space/l to browse] "
            },
            Style::default().fg(Color::DarkGray),
        ),
    ]);

    if issues.is_empty() {
        let mut lines = vec![Line::from(Span::styled(
            format!("No major friction issues flagged for {short_ag} in this window."),
            Style::default().fg(Color::Green),
        ))];
        if let Some(h) = sel_h {
            lines.push(Line::from(""));
            lines.push(Line::from(format!(
                "Avg output: {:.1} KB · Truncated outputs: {} ({:.0}% of sessions)",
                h.avg_output_kb, h.truncated_outputs, h.truncated_sessions_pct
            )));
            if !h.top_friction_cmds.is_empty() {
                lines.push(Line::from(format!(
                    "Most active commands: {}",
                    h.top_friction_cmds.join(" · ")
                )));
            }
        }
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: true })
                .block(rounded_block(
                    iss_title,
                    focused && app.harness_focus_issues,
                )),
            bottom[0],
        );
    } else {
        let iss_w = bottom[0].width.saturating_sub(28).max(16) as usize;
        let iss_header = Row::new(vec![
            Cell::from("Type"),
            Cell::from("Issue"),
            Cell::from(Line::from("Impact").right_aligned()),
        ])
        .style(
            Style::default()
                .fg(Color::Gray)
                .add_modifier(Modifier::BOLD),
        );

        let iss_rows: Vec<Row> = issues
            .iter()
            .map(|item| match item {
                HarnessIssueItem::Opp(m) => {
                    let (_, sev_col) = human_problem(&m.primary.kind);
                    let (tag, tag_col) = if m.primary.scope == "harness" {
                        ("HARN", Color::LightBlue)
                    } else {
                        ("REPO", Color::Green)
                    };
                    Row::new(vec![
                        Cell::from(Line::from(vec![
                            Span::styled("● ", Style::default().fg(sev_col)),
                            Span::styled(
                                tag,
                                Style::default().fg(tag_col).add_modifier(Modifier::BOLD),
                            ),
                        ])),
                        Cell::from(truncate_ellipsis(&insight_headline(&m.primary), iss_w)),
                        Cell::from(Line::from(primary_metric_for(m)).right_aligned()),
                    ])
                }
                HarnessIssueItem::McpTool(t) => {
                    let err_unit = if t.error_count == 1 { "err" } else { "errs" };
                    Row::new(vec![
                        Cell::from(Line::from(vec![
                            Span::styled("● ", Style::default().fg(Color::Red)),
                            Span::styled(
                                "MCP ",
                                Style::default()
                                    .fg(Color::LightMagenta)
                                    .add_modifier(Modifier::BOLD),
                            ),
                        ])),
                        Cell::from(truncate_ellipsis(&clean_tool_label(&t.tool_name), iss_w)),
                        Cell::from(
                            Line::from(format!(
                                "{} {err_unit} ({:.0}%)",
                                t.error_count,
                                t.error_rate * 100.0
                            ))
                            .right_aligned(),
                        ),
                    ])
                }
            })
            .collect();

        let iss_table = Table::new(
            iss_rows,
            [
                Constraint::Length(6),
                Constraint::Fill(1),
                Constraint::Length(16),
            ],
        )
        .header(iss_header)
        .column_spacing(1)
        .block(rounded_block(
            iss_title,
            focused && app.harness_focus_issues,
        ))
        .row_highlight_style(row_highlight_style())
        .highlight_symbol("▶ ");
        frame.render_stateful_widget(iss_table, bottom[0], &mut app.harness_issue_state);
    }

    // Bottom-Right: Full Plain-English Diagnosis of Selected Harness Issue (or Harness Profile)
    let sel_issue = app
        .harness_issue_state
        .selected()
        .and_then(|i| issues.get(i));
    match sel_issue {
        Some(HarnessIssueItem::Opp(m)) => {
            render_opportunity_diagnosis(frame, bottom[1], m, false);
        }
        Some(HarnessIssueItem::McpTool(t)) => {
            render_mcp_tool_diagnosis(frame, bottom[1], t);
        }
        None => {
            let mut profile_lines = Vec::new();
            if let Some(h) = sel_h {
                profile_lines.push(Line::from(Span::styled(
                    format!("{} PROFILE", short_ag.to_uppercase()),
                    Style::default()
                        .fg(harness_color(short_ag))
                        .add_modifier(Modifier::BOLD),
                )));
                profile_lines.push(Line::from(format!(
                    "{} sessions · {} shell commands · {} tool calls",
                    h.sessions,
                    format_int(h.commands),
                    format_int(h.tool_calls)
                )));
                profile_lines.push(Line::from(format!(
                    "Est cost: ~${:.2}{} · Fallback rate: {:.0}% · Avg output: {:.1} KB · Truncated: {} ({:.0}% sess)",
                    h.est_cost_usd,
                    h.avg_api_wait_s
                        .map(|v| format!(" · Avg API: {v:.1}s"))
                        .unwrap_or_default(),
                    h.rebound_rate * 100.0,
                    h.avg_output_kb,
                    h.truncated_outputs,
                    h.truncated_sessions_pct
                )));
                if !pat.universal_friction_cmds.is_empty() {
                    profile_lines.push(Line::from(""));
                    profile_lines.push(Line::from(Span::styled(
                        "SHARED FRICTION ACROSS HARNESSES",
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    )));
                    profile_lines.push(Line::from(Span::styled(
                        pat.universal_friction_cmds
                            .iter()
                            .take(6)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(" · "),
                        Style::default().fg(Color::Gray),
                    )));
                }
            }
            frame.render_widget(
                Paragraph::new(profile_lines)
                    .wrap(Wrap { trim: true })
                    .block(rounded_block(" Issue Diagnosis ", false)),
                bottom[1],
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tab 4: Commands & Tools (Selectable Table with Inline Share Bars + Detail)
// ---------------------------------------------------------------------------

fn draw_commands_tab(frame: &mut Frame, area: Rect, app: &mut App) {
    let focused = app.focus == Focus::Main;
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(5)])
        .split(area);

    let pill = |active: bool, label: &str| {
        if active {
            Span::styled(
                format!("[{label}]"),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled(label.to_string(), Style::default().fg(Color::DarkGray))
        }
    };
    let title = Line::from(vec![
        Span::raw(" Sort/View: "),
        pill(app.commands_view == CommandsView::Tokens, "Token Sinks"),
        Span::styled(" · ", Style::default().fg(Color::DarkGray)),
        pill(app.commands_view == CommandsView::Wait, "Slowest"),
        Span::styled(" · ", Style::default().fg(Color::DarkGray)),
        pill(app.commands_view == CommandsView::Errors, "Most Errors"),
        Span::styled(" · ", Style::default().fg(Color::DarkGray)),
        pill(app.commands_view == CommandsView::Mcp, "MCP & Tools"),
        Span::styled("  (s) ", Style::default().fg(Color::DarkGray)),
    ]);

    if app.commands_view == CommandsView::Mcp {
        let tools = app
            .selected_patterns
            .as_ref()
            .map(|p| p.top_mcp_errors.as_slice())
            .unwrap_or(&[]);
        let header = Row::new(vec![
            Cell::from("MCP / Non-Shell Tool"),
            Cell::from(Line::from("Calls").right_aligned()),
            Cell::from(Line::from("Sess").right_aligned()),
            Cell::from(Line::from("Errs").right_aligned()),
            Cell::from(Line::from("Err%").right_aligned()),
            Cell::from(Line::from("Trunc").right_aligned()),
            Cell::from(Line::from("Avg KB").right_aligned()),
            Cell::from("Harness"),
        ])
        .style(
            Style::default()
                .fg(Color::Gray)
                .add_modifier(Modifier::BOLD),
        );

        let name_w = rows[0].width.saturating_sub(58).max(18) as usize;
        let t_rows: Vec<Row> = tools
            .iter()
            .map(|t| {
                let (htxt, hcol) = compact_harness_cell(&t.by_harness);
                let ecol = if t.error_rate >= 0.15 {
                    Color::Red
                } else if t.error_count > 0 {
                    Color::Yellow
                } else {
                    Color::Green
                };
                Row::new(vec![
                    Cell::from(truncate_ellipsis(&t.tool_name, name_w)),
                    Cell::from(Line::from(t.calls.to_string()).right_aligned()),
                    Cell::from(Line::from(t.sessions.to_string()).right_aligned()),
                    Cell::from(Line::from(t.error_count.to_string()).right_aligned())
                        .style(Style::default().fg(ecol)),
                    Cell::from(Line::from(format!("{:.0}%", t.error_rate * 100.0)).right_aligned())
                        .style(Style::default().fg(ecol)),
                    Cell::from(Line::from(t.truncated_count.to_string()).right_aligned()),
                    Cell::from(Line::from(format!("{:.1}", t.avg_output_kb)).right_aligned()),
                    Cell::from(htxt).style(Style::default().fg(hcol)),
                ])
            })
            .collect();

        let table = Table::new(
            t_rows,
            [
                Constraint::Fill(1),
                Constraint::Length(6),
                Constraint::Length(5),
                Constraint::Length(5),
                Constraint::Length(5),
                Constraint::Length(6),
                Constraint::Length(6),
                Constraint::Length(12),
            ],
        )
        .header(header)
        .column_spacing(1)
        .block(rounded_block(title, focused))
        .row_highlight_style(row_highlight_style())
        .highlight_symbol("▶ ");
        frame.render_stateful_widget(table, rows[0], &mut app.cmd_state);

        let sel_lines = if let Some(idx) = app.cmd_state.selected()
            && let Some(t) = tools.get(idx)
        {
            vec![
                Line::from(vec![
                    Span::styled(
                        "Tool: ",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!(
                        "{}  ·  Harnesses: {}",
                        t.tool_name, t.harness_summary
                    )),
                ]),
                Line::from(vec![
                    Span::styled(
                        "Sample error: ",
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(
                        t.sample_error
                            .clone()
                            .unwrap_or_else(|| "None (flagged for high truncation)".into()),
                    ),
                ]),
            ]
        } else {
            vec![Line::from(Span::styled(
                "No failing or heavily truncated MCP tools in this window.",
                Style::default().fg(Color::DarkGray),
            ))]
        };
        frame.render_widget(
            Paragraph::new(sel_lines)
                .wrap(Wrap { trim: true })
                .block(rounded_block(" Selected Tool ", false)),
            rows[1],
        );
        return;
    }

    let cmds = app.sorted_commands();
    let max_val: f64 = cmds
        .iter()
        .map(|c| match app.commands_view {
            CommandsView::Wait => c.total_wait_s,
            CommandsView::Errors => c.error_count as f64,
            _ => c.total_stdout_tokens as f64,
        })
        .fold(1.0_f64, f64::max);

    let wide = rows[0].width >= 106;
    let cmd_w = if wide {
        rows[0].width.saturating_sub(74).max(18) as usize
    } else {
        rows[0].width.saturating_sub(54).max(16) as usize
    };

    let header = if wide {
        Row::new(vec![
            Cell::from("Command"),
            Cell::from("CLI"),
            Cell::from(Line::from("Runs").right_aligned()),
            Cell::from(Line::from("Out Toks").right_aligned()),
            Cell::from("Share"),
            Cell::from(Line::from("Wait").right_aligned()),
            Cell::from(Line::from("Err%").right_aligned()),
            Cell::from("Harness"),
        ])
    } else {
        Row::new(vec![
            Cell::from("Command"),
            Cell::from(Line::from("Runs").right_aligned()),
            Cell::from(Line::from("Out Toks").right_aligned()),
            Cell::from("Share"),
            Cell::from("Harness"),
        ])
    }
    .style(
        Style::default()
            .fg(Color::Gray)
            .add_modifier(Modifier::BOLD),
    );

    let t_rows: Vec<Row> = cmds
        .iter()
        .map(|c| {
            let frac = match app.commands_view {
                CommandsView::Wait => c.total_wait_s / max_val,
                CommandsView::Errors => c.error_count as f64 / max_val,
                _ => c.total_stdout_tokens as f64 / max_val,
            };
            let bar_col = match app.commands_view {
                CommandsView::Wait => Color::Yellow,
                CommandsView::Errors => Color::Red,
                _ => Color::Cyan,
            };
            let (htxt, hcol) = compact_harness_cell(&c.by_harness);
            let ecol = if c.error_rate >= 0.15 {
                Color::Red
            } else if c.error_rate >= 0.05 {
                Color::Yellow
            } else {
                Color::Green
            };

            if wide {
                Row::new(vec![
                    Cell::from(truncate_ellipsis(&c.cmd_template, cmd_w)),
                    Cell::from(if c.is_repo_cli { "yes" } else { "—" }).style(Style::default().fg(
                        if c.is_repo_cli {
                            Color::Green
                        } else {
                            Color::DarkGray
                        },
                    )),
                    Cell::from(Line::from(format_int(c.runs)).right_aligned()),
                    Cell::from(Line::from(format_compact(c.total_stdout_tokens)).right_aligned()),
                    Cell::from(bar_string(frac, 10)).style(Style::default().fg(bar_col)),
                    Cell::from(Line::from(format_duration(c.total_wait_s)).right_aligned()),
                    Cell::from(Line::from(format!("{:.0}%", c.error_rate * 100.0)).right_aligned())
                        .style(Style::default().fg(ecol)),
                    Cell::from(htxt).style(Style::default().fg(hcol)),
                ])
            } else {
                Row::new(vec![
                    Cell::from(truncate_ellipsis(&c.cmd_template, cmd_w)),
                    Cell::from(Line::from(format_int(c.runs)).right_aligned()),
                    Cell::from(Line::from(format_compact(c.total_stdout_tokens)).right_aligned()),
                    Cell::from(bar_string(frac, 10)).style(Style::default().fg(bar_col)),
                    Cell::from(htxt).style(Style::default().fg(hcol)),
                ])
            }
        })
        .collect();

    let constraints: Vec<Constraint> = if wide {
        vec![
            Constraint::Fill(1),
            Constraint::Length(3),
            Constraint::Length(6),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(7),
            Constraint::Length(5),
            Constraint::Length(12),
        ]
    } else {
        vec![
            Constraint::Fill(1),
            Constraint::Length(6),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(12),
        ]
    };

    let table = Table::new(t_rows, constraints)
        .header(header)
        .column_spacing(2)
        .block(rounded_block(title, focused))
        .row_highlight_style(row_highlight_style())
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(table, rows[0], &mut app.cmd_state);

    let sel_lines = if let Some(idx) = app.cmd_state.selected()
        && let Some(c) = cmds.get(idx)
    {
        let pipe_info = if c.piped_count > 0 {
            format!(
                "Piped: {}× ({:.0}%, top: | {})",
                c.piped_count,
                (c.piped_count as f64 / c.runs.max(1) as f64) * 100.0,
                c.top_pipe_filter.as_deref().unwrap_or("pipe")
            )
        } else {
            "Piped: none".to_string()
        };
        vec![
            Line::from(vec![
                Span::styled(
                    "Category: ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(
                    "{} · Effective context: {} toks · p50 out: {} · p50 wait: {}",
                    c.category,
                    format_compact(c.effective_tokens),
                    format_compact(c.p50_stdout_tokens),
                    format_duration(c.p50_wait_s)
                )),
            ]),
            Line::from(vec![
                Span::styled(
                    "Harnesses: ",
                    Style::default()
                        .fg(Color::LightMagenta)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("{}  ·  {pipe_info}", c.harness_summary)),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            "Select a command to inspect its context cost, pipe-stripping, and harness split.",
            Style::default().fg(Color::DarkGray),
        ))]
    };
    frame.render_widget(
        Paragraph::new(sel_lines)
            .wrap(Wrap { trim: true })
            .block(rounded_block(" Selected Command ", false)),
        rows[1],
    );
}

// ---------------------------------------------------------------------------
// Tab 5: Brief / Export (Diagnosis Prompt vs YAML Brief)
// ---------------------------------------------------------------------------

fn draw_brief_tab(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Main;
    let total_lines = app.cached_brief.lines().count().max(1);
    let cur_line = (app.brief_scroll as usize + 1).min(total_lines);
    let kb = app.cached_brief.len() as f64 / 1024.0;

    let pill = |active: bool, label: &str| {
        if active {
            Span::styled(
                format!("[{label}]"),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled(label.to_string(), Style::default().fg(Color::DarkGray))
        }
    };
    let title = Line::from(vec![
        Span::raw(" Export Mode: "),
        pill(app.brief_mode == BriefMode::Prompt, "Diagnosis Prompt"),
        Span::styled(" · ", Style::default().fg(Color::DarkGray)),
        pill(app.brief_mode == BriefMode::Yaml, "Structured YAML"),
        Span::styled(
            format!("  (m)   [c] Copy ({kb:.1} KB) · Line {cur_line}/{total_lines} "),
            Style::default().fg(Color::DarkGray),
        ),
    ]);

    let p = Paragraph::new(app.cached_brief.as_str())
        .scroll((app.brief_scroll, 0))
        .wrap(Wrap { trim: false })
        .block(rounded_block(title, focused));
    frame.render_widget(p, area);
}

// ---------------------------------------------------------------------------
// Footer, Trace Drill-Down Modal & Keybind Help Overlay
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Tab 6: Issues — session-by-session recurrence
// ---------------------------------------------------------------------------

fn verdict_color(v: Verdict) -> Color {
    match v {
        Verdict::Regressed => Color::Red,
        Verdict::New => Color::LightMagenta,
        Verdict::Active | Verdict::Unchanged => Color::Yellow,
        Verdict::Improved => Color::LightGreen,
        Verdict::Waiting => Color::Gray,
        Verdict::Quiet | Verdict::Gone => Color::Green,
    }
}

/// Styled strip of the most recent exposed sessions that fit in `width` cells.
fn strip_spans(cells: &[SessionCell], marker_at: Option<i64>, width: usize) -> Vec<Span<'static>> {
    let has_marker = marker_at.is_some();
    let budget = width.saturating_sub(usize::from(has_marker)).max(1);
    // When truncating, the leading "…" takes one cell of the budget.
    let start = match cells.len().saturating_sub(budget) {
        0 => 0,
        s => s + 1,
    };
    let marker_idx = marker_at.map(|at| {
        cells
            .iter()
            .position(|c| c.started_at >= at)
            .unwrap_or(cells.len())
    });
    let mk = || {
        Span::styled(
            "│",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
    };
    let mut out = Vec::new();
    if start > 0 {
        out.push(Span::styled("…", Style::default().fg(Color::DarkGray)));
        if marker_idx.is_some_and(|m| m < start) {
            out.push(mk());
        }
    }
    for (i, c) in cells.iter().enumerate().skip(start) {
        if marker_idx == Some(i) {
            out.push(mk());
        }
        out.push(if c.affected {
            Span::styled("●", Style::default().fg(Color::Red))
        } else {
            Span::styled("○", Style::default().fg(Color::Green))
        });
    }
    if marker_idx == Some(cells.len()) {
        out.push(mk());
    }
    out
}

fn draw_issues_tab(frame: &mut Frame, area: Rect, app: &mut App) {
    let focused = app.focus == Focus::Main;
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Min(9)])
        .split(area);

    let Some(rep) = app.issues.as_ref() else {
        let msg = if app.selected_repo.is_some() {
            "Computing session-by-session issue tracking…"
        } else {
            "No repository selected."
        };
        frame.render_widget(
            Paragraph::new(msg).block(rounded_block(" Issues ", focused)),
            area,
        );
        return;
    };

    let title = Line::from(vec![
        Span::raw(" Issues by session "),
        Span::styled(
            format!("({}, {} sessions) ", rep.window, rep.sessions),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            if app.issues_open_only {
                "[open only] "
            } else {
                "[all] "
            },
            Style::default().fg(Color::Cyan),
        ),
        Span::styled("(o) ", Style::default().fg(Color::DarkGray)),
        Span::styled("● affected ", Style::default().fg(Color::Red)),
        Span::styled("○ clean ", Style::default().fg(Color::Green)),
        Span::styled("│ fix marker ", Style::default().fg(Color::Cyan)),
    ]);

    let visible = app.visible_issues();
    let strip_w = (rows[0].width as usize).saturating_sub(70).clamp(12, 48);
    let key_w = (rows[0].width as usize)
        .saturating_sub(strip_w + 38)
        .max(16);
    let header = Row::new(vec![
        Cell::from("Verdict"),
        Cell::from("Issue"),
        Cell::from(Line::from("Hit").right_aligned()),
        Cell::from("Last seen"),
        Cell::from("Recent exposed sessions"),
    ])
    .style(
        Style::default()
            .fg(Color::Gray)
            .add_modifier(Modifier::BOLD),
    );
    let t_rows: Vec<Row> = visible
        .iter()
        .map(|t| {
            let v = t.verdict.verdict;
            Row::new(vec![
                Cell::from(v.label()).style(
                    Style::default()
                        .fg(verdict_color(v))
                        .add_modifier(Modifier::BOLD),
                ),
                Cell::from(truncate_ellipsis(&t.key, key_w)),
                Cell::from(Line::from(format!("{}/{}", t.affected, t.exposed)).right_aligned()),
                Cell::from(t.last_seen.map_or("-".to_string(), format_ago)),
                Cell::from(Line::from(strip_spans(
                    &t.cells,
                    t.marker.as_ref().map(|m| m.at_ms),
                    strip_w,
                ))),
            ])
        })
        .collect();
    let empty = t_rows.is_empty();
    let table = Table::new(
        t_rows,
        [
            Constraint::Length(10),
            Constraint::Fill(1),
            Constraint::Length(8),
            Constraint::Length(9),
            Constraint::Length(strip_w as u16 + 2),
        ],
    )
    .header(header)
    .column_spacing(1)
    .block(rounded_block(title, focused))
    .row_highlight_style(row_highlight_style())
    .highlight_symbol("▶ ");
    let sel_key = app.selected_issue().map(|t| t.key.clone());
    let aggregate_note = if rep.aggregate_only.is_empty() {
        String::new()
    } else {
        format!(
            "{} fleet-level finding(s) are not tracked per session — see Insights.",
            rep.aggregate_only.len()
        )
    };
    frame.render_stateful_widget(table, rows[0], &mut app.issues_state);
    if empty {
        let inner = rows[0].inner(ratatui::layout::Margin::new(2, 2));
        frame.render_widget(
            Paragraph::new("No session-trackable issues in this window.")
                .style(Style::default().fg(Color::DarkGray)),
            inner,
        );
    }

    let label = |s: &str| {
        Span::styled(
            format!("{s:<11}"),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
    };
    let dim = |s: String| Span::styled(s, Style::default().fg(Color::DarkGray));
    let mut lines: Vec<Line> = Vec::new();
    if let Some(t) = sel_key
        .as_ref()
        .and_then(|k| app.issues.as_ref()?.issues.iter().find(|t| &t.key == k))
    {
        let v = t.verdict.verdict;
        lines.push(Line::from(vec![
            Span::styled(
                format!("{} ", v.label()),
                Style::default()
                    .fg(verdict_color(v))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(t.key.clone(), Style::default().add_modifier(Modifier::BOLD)),
            dim(format!("  · scope {}", t.scope)),
        ]));
        lines.push(Line::from(vec![
            label("Verdict"),
            Span::raw(t.verdict.reason.clone()),
        ]));
        let mut detail_w = rows[1].width.saturating_sub(16) as usize;
        detail_w = detail_w.max(20);
        let mut strip_line = vec![label("Sessions")];
        strip_line.extend(strip_spans(
            &t.cells,
            t.marker.as_ref().map(|m| m.at_ms),
            detail_w,
        ));
        lines.push(Line::from(strip_line));
        if let Some(m) = &t.marker {
            let b = t.verdict.before.unwrap_or_default();
            let a = t.verdict.after.unwrap_or_default();
            lines.push(Line::from(vec![
                label("Marker"),
                Span::raw(format!(
                    "#{} {}{} — before {}/{}, after {}/{}",
                    m.marker_id,
                    m.label,
                    m.note
                        .as_deref()
                        .map(|n| format!(" “{n}”"))
                        .unwrap_or_default(),
                    b.affected,
                    b.exposed,
                    a.affected,
                    a.exposed
                )),
            ]));
        }
        if let (Some(ls), Some(sid)) = (t.last_seen, &t.last_seen_session) {
            lines.push(Line::from(vec![
                label("Last seen"),
                Span::raw(format!(
                    "{} in {} · {}{}",
                    format_ago(ls),
                    truncate_ellipsis(sid.rsplit(':').next().unwrap_or(sid), 12),
                    t.last_seen_harness.as_deref().unwrap_or("?"),
                    t.last_seen_version
                        .as_deref()
                        .map(|v| format!(" {v}"))
                        .unwrap_or_default()
                )),
            ]));
        }
        let mut hs = vec![label("Harnesses")];
        for (i, h) in t.by_harness.iter().enumerate() {
            if i > 0 {
                hs.push(dim(" · ".into()));
            }
            hs.push(Span::styled(
                short_harness(&h.harness).to_string(),
                Style::default().fg(harness_color(&h.harness)),
            ));
            hs.push(Span::raw(format!(" {}/{} ", h.affected, h.exposed)));
            hs.push(Span::styled(
                h.verdict.label().to_ascii_lowercase(),
                Style::default().fg(verdict_color(h.verdict)),
            ));
        }
        lines.push(Line::from(hs));
        let versions: Vec<String> = t
            .by_version
            .iter()
            .filter(|v| v.version != "?")
            .map(|v| {
                format!(
                    "{} {} {}/{}",
                    short_harness(&v.harness),
                    v.version,
                    v.affected,
                    v.exposed
                )
            })
            .collect();
        if !versions.is_empty() {
            lines.push(Line::from(vec![
                label("Versions"),
                Span::raw(versions.join(" · ")),
            ]));
        }
        if let Some(h) = &t.headline {
            lines.push(Line::from(vec![label("Detector"), dim(h.clone())]));
        }
    } else {
        lines.push(Line::from(dim(
            "Select an issue to see its session history.".into(),
        )));
    }
    if !aggregate_note.is_empty() {
        lines.push(Line::from(dim(aggregate_note)));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(rounded_block(" Session history ", false)),
        rows[1],
    );
}

fn draw_footer(frame: &mut Frame, area: Rect, app: &App) {
    let mut spans = vec![
        Span::styled(
            " j/k ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Move  "),
    ];
    match app.tab {
        DetailTab::Insights => {
            spans.push(Span::styled(
                " f ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw("Scope  "));
            spans.push(Span::styled(
                " Enter ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw("Traces  "));
        }
        DetailTab::Patterns => {
            spans.push(Span::styled(
                " v ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw("View (Workflows/Storms/Drift)  "));
        }
        DetailTab::Commands => {
            spans.push(Span::styled(
                " s ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw("Sort/MCP  "));
            spans.push(Span::styled(
                " Enter ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw("Traces  "));
        }
        DetailTab::Brief => {
            spans.push(Span::styled(
                " m ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw("Prompt/YAML  "));
        }
        DetailTab::Issues => {
            for (k, l) in [
                (" m ", "Mark fix now  "),
                (" u ", "Undo mark  "),
                (" o ", "Open only  "),
                (" Enter ", "Traces  "),
            ] {
                spans.push(Span::styled(
                    k,
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ));
                spans.push(Span::raw(l));
            }
        }
        DetailTab::Harnesses => {
            spans.push(Span::styled(
                " Space ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw("Issues  "));
            spans.push(Span::styled(
                " d ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw("Strata  "));
            spans.push(Span::styled(
                " Enter ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw("Traces  "));
        }
    }
    spans.extend([
        Span::styled(
            " 1-6/Tab ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Tabs  "),
        Span::styled(
            " b ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Fleet  "),
        Span::styled(
            " [/] ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Repo  "),
        Span::styled(
            " w ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Window  "),
        Span::styled(
            " c ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Copy  "),
        Span::styled(
            " ? ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Help  "),
        Span::styled(
            " q ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Quit"),
    ]);
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_inspect_modal(frame: &mut Frame, area: Rect, res: &InspectResult, scroll: u16) {
    let popup = centered_rect(84, 80, area);
    frame.render_widget(Clear, popup);

    let mut lines = Vec::new();
    if let Some(opp) = &res.opportunity {
        let (_, sev_col) = human_problem(&opp.kind);
        let headline = insight_headline(opp);
        let badge = if opp.scope == "harness" {
            "AGENT RUNTIME"
        } else {
            "REPO HARNESS"
        };
        lines.push(Line::from(vec![
            Span::styled("● ", Style::default().fg(sev_col)),
            Span::styled(
                format!("{headline} "),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("[{badge}]"), Style::default().fg(Color::Gray)),
        ]));
        for para in insight_story(opp) {
            lines.push(Line::from(para));
        }
        lines.push(Line::from(vec![
            Span::styled(
                "Harnesses: ",
                Style::default()
                    .fg(Color::LightMagenta)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(opp.harness_summary.clone()),
        ]));
        let (fix_text, _) = insight_fix_guidance(opp);
        lines.push(Line::from(vec![
            Span::styled("How to fix: ", Style::default().fg(Color::Green)),
            Span::raw(fix_text),
        ]));
        lines.push(Line::from(""));
    }

    lines.push(Line::from(Span::styled(
        format!(
            "Showing {} of {} matching redacted span(s):",
            res.samples.len(),
            res.total_matching_spans
        ),
        Style::default().fg(Color::Gray),
    )));
    lines.push(Line::from(""));

    for (i, s) in res.samples.iter().enumerate() {
        let wait = s
            .duration_ms
            .map(|d| format_duration(d as f64 / 1000.0))
            .unwrap_or_else(|| "—".into());
        lines.push(Line::from(vec![
            Span::styled(
                format!("#{} ", i + 1),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{} ", short_harness(&s.agent_kind)),
                Style::default().fg(harness_color(&s.agent_kind)),
            ),
            Span::raw(format!(
                "· {} · turn {} · exit={} · {} toks · {wait}",
                &s.started_at[..s.started_at.len().min(19)],
                s.turn_idx,
                s.exit_code.map_or("n/a".into(), |c| c.to_string()),
                format_compact(s.stdout_tokens)
            )),
        ]));
        lines.push(Line::from(format!("   cmd:  {}", s.raw_redacted)));
        if let Some(err) = &s.stderr_preview {
            lines.push(Line::from(Span::styled(
                format!("   err:  {err}"),
                Style::default().fg(Color::Red),
            )));
        }
        if let Some(nx) = &s.next_cmd {
            lines.push(Line::from(Span::styled(
                format!("   next: {nx}"),
                Style::default().fg(Color::Yellow),
            )));
        }
        lines.push(Line::from(""));
    }

    let modal = Paragraph::new(lines)
        .scroll((scroll, 0))
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .title(format!(
                    " Trace Drill-Down: {} (Esc/Enter close · j/k scroll) ",
                    res.query
                ))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Cyan))
                .padding(Padding::uniform(1)),
        );
    frame.render_widget(modal, popup);
}

fn draw_help_modal(frame: &mut Frame, area: Rect) {
    let popup = centered_rect(64, 62, area);
    frame.render_widget(Clear, popup);

    let lines = vec![
        Line::from(Span::styled(
            "Global Controls",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(
            "  1–6 / Tab / Shift-Tab   Switch views (Insights, Patterns, Harnesses, Commands, Brief, Issues)",
        ),
        Line::from("  b                       Toggle Fleet Repos & Cross-Repo drawer"),
        Line::from("  [ / ]                   Previous / Next repository inline"),
        Line::from("  w                       Cycle time window (24h · 7d · 14d · 30d · all)"),
        Line::from("  r                       Sync new local transcripts into SQLite ledger"),
        Line::from("  c                       Copy active Brief (Prompt or YAML) to clipboard"),
        Line::from("  j/k, PgUp/PgDn, g/G     Navigate lists or scroll"),
        Line::from("  q / Ctrl-c              Quit"),
        Line::from(""),
        Line::from(Span::styled(
            "Tab-Specific Shortcuts",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(
            "  Insights:   f = Filter scope (All / Repo harness / Agent runtime)  ·  Enter = Traces",
        ),
        Line::from("  Patterns:   v = Switch view (Workflows / Burst Storms / Drift & Cold-Start)"),
        Line::from(
            "  Harnesses:  d = Toggle Grouped / Detailed strata  ·  Space/h/l = Focus issues  ·  Enter = Traces",
        ),
        Line::from(
            "  Commands:   s = Switch sort/view (Tokens / Slowest / Errors / MCP)  ·  Enter = Traces",
        ),
        Line::from("  Brief:      m = Toggle Diagnosis Prompt (Markdown) vs Structured YAML"),
        Line::from(
            "  Issues:     m = Mark fix now  ·  u = Undo last mark  ·  o = Open only  ·  Enter = Traces",
        ),
    ];

    let modal = Paragraph::new(lines).wrap(Wrap { trim: true }).block(
        Block::default()
            .title(" Keybindings (Esc / ? to close) ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan))
            .padding(Padding::uniform(1)),
    );
    frame.render_widget(modal, popup);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let vert = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vert[1])[1]
}
