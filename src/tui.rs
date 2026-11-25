use crate::analyze::{
    CommandStat, FleetReport, InspectResult, Opportunity, RepoReport, analyze_fleet, analyze_repo,
    format_compact, inspect_finding,
};
use crate::config::{AdapterRoots, TimeRange, parse_window_ms};
use crate::ingest::sync_all;
use crate::patterns::{CrossSessionPatternsReport, analyze_cross_session_patterns};
use crate::report::{format_diagnosis_prompt, format_repo_report};
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
}

impl DetailTab {
    fn titles() -> [&'static str; 5] {
        [
            "1 Insights",
            "2 Patterns",
            "3 Harnesses",
            "4 Commands",
            "5 Brief",
        ]
    }

    fn next(self) -> Self {
        Self::from_index((self as usize + 1) % 5)
    }

    fn prev(self) -> Self {
        Self::from_index((self as usize + 4) % 5)
    }

    fn from_index(i: usize) -> Self {
        match i % 5 {
            0 => Self::Insights,
            1 => Self::Patterns,
            2 => Self::Harnesses,
            3 => Self::Commands,
            _ => Self::Brief,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeFilter {
    Repo,
    All,
    Harness,
}

impl ScopeFilter {
    fn next(self) -> Self {
        match self {
            Self::Repo => Self::All,
            Self::All => Self::Harness,
            Self::Harness => Self::Repo,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Repo => "Repo fixes",
            Self::All => "All signals",
            Self::Harness => "Harness overhead",
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

pub struct App {
    pub window_idx: usize,
    pub focus: Focus,
    pub sidebar_open: bool,
    pub tab: DetailTab,
    pub scope_filter: ScopeFilter,
    pub patterns_view: PatternsView,
    pub commands_view: CommandsView,
    pub brief_mode: BriefMode,
    pub show_help: bool,
    pub fleet: FleetReport,
    pub repo_state: TableState,
    pub selected_repo: Option<RepoReport>,
    pub selected_patterns: Option<CrossSessionPatternsReport>,
    pub opp_state: TableState,
    pub pattern_state: TableState,
    pub harness_state: TableState,
    pub cmd_state: TableState,
    pub brief_scroll: u16,
    pub cached_brief: String,
    pub modal: Option<InspectResult>,
    pub modal_scroll: u16,
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
        let selected_idx = if let Some(target_id) = initial_repo_id {
            fleet
                .repos
                .iter()
                .position(|r| r.repo_id == target_id)
                .or_else(|| {
                    if fleet.repos.is_empty() {
                        None
                    } else {
                        Some(0)
                    }
                })
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
            scope_filter: ScopeFilter::Repo,
            patterns_view: PatternsView::Workflows,
            commands_view: CommandsView::Tokens,
            brief_mode: BriefMode::Prompt,
            show_help: false,
            fleet,
            repo_state,
            selected_repo,
            selected_patterns,
            opp_state: TableState::default(),
            pattern_state: TableState::default(),
            harness_state: TableState::default(),
            cmd_state: TableState::default(),
            brief_scroll: 0,
            cached_brief: String::new(),
            modal: None,
            modal_scroll: 0,
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
        let insights_len = self.visible_insights().len();
        self.opp_state
            .select(if insights_len > 0 { Some(0) } else { None });
        let pat_len = self.visible_pattern_count();
        self.pattern_state
            .select(if pat_len > 0 { Some(0) } else { None });
        let h_len = self
            .selected_patterns
            .as_ref()
            .map_or(0, |p| p.harness_comparison.len());
        self.harness_state
            .select(if h_len > 0 { Some(0) } else { None });
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
        let raw: Vec<&Opportunity> = match self.scope_filter {
            ScopeFilter::Repo => repo.opportunities.iter().collect(),
            ScopeFilter::Harness => repo.harness_overhead.iter().collect(),
            ScopeFilter::All => repo
                .opportunities
                .iter()
                .chain(repo.harness_overhead.iter())
                .collect(),
        };
        merge_opportunities(&raw)
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
            .or_else(|| {
                if self.fleet.repos.is_empty() {
                    None
                } else {
                    Some(0)
                }
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
        self.reset_tab_selections();
        self.refresh_cached_brief();
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
            KeyCode::Left | KeyCode::Char('h') => {
                if self.sidebar_open {
                    self.focus = Focus::Drawer;
                }
            }
            KeyCode::Right | KeyCode::Char('l') => {
                self.focus = Focus::Main;
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
                let len = self
                    .selected_patterns
                    .as_ref()
                    .map_or(0, |p| p.harness_comparison.len());
                Self::move_table(&mut self.harness_state, len, delta);
            }
            DetailTab::Commands => {
                let len = self.visible_command_count();
                Self::move_table(&mut self.cmd_state, len, delta);
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

fn human_problem(kind: &str) -> (&'static str, Color, &'static str) {
    match kind {
        "broken_task_error_rate" => (
            "High fail rate",
            Color::Red,
            "Command fails frequently and forces retries.",
        ),
        "lossy_task_rebound" => (
            "Shell fallback",
            Color::Red,
            "CLI output is missing info, forcing raw shell follow-ups.",
        ),
        "flag_thrash" => (
            "Flag guessing",
            Color::Red,
            "Agent repeatedly tries invalid CLI flags or arguments.",
        ),
        "tool_friction" => (
            "Tool errors",
            Color::Red,
            "Non-shell or MCP tool calls fail or return truncated output.",
        ),
        "polling_tax" => (
            "Polling loop",
            Color::Yellow,
            "Repeated status checks in a loop instead of blocking/waiting.",
        ),
        "slow_task_latency" => (
            "Slow wait",
            Color::Yellow,
            "High cumulative wall-clock wait time across sessions.",
        ),
        "state_dir_bypass" => (
            "State scraping",
            Color::Yellow,
            "Reads internal state files directly instead of using a CLI.",
        ),
        "output_filtering_tax" => (
            "Noisy output",
            Color::Yellow,
            "Agents pipe output through grep/tail/sed to strip clutter.",
        ),
        "noisy_task_output" => (
            "Verbose output",
            Color::Yellow,
            "Runs dump oversized stdout payloads into model context.",
        ),
        "repeated_file_reread" => (
            "File re-reads",
            Color::Yellow,
            "Same file is re-read repeatedly across sessions.",
        ),
        "context_handoff_bloat" => (
            "Handoff bloat",
            Color::Yellow,
            "Continued/handoff threads burn much more context than fresh ones.",
        ),
        "low_cache_efficiency" => (
            "Low cache hit",
            Color::Yellow,
            "Prompt cache hit rate is low, multiplying uncached token cost.",
        ),
        "orientation_tax" => (
            "Startup reads",
            Color::Cyan,
            "Heavy directory/doc discovery in turns 1–3 of sessions.",
        ),
        "cli_help_tax" => (
            "Repeated --help",
            Color::Cyan,
            "Agents keep calling --help to rediscover CLI syntax.",
        ),
        "missing_composite_task" => (
            "Manual workflow",
            Color::Cyan,
            "Multi-step command chain repeated manually across sessions.",
        ),
        "harness_divergence" => (
            "Harness gap",
            Color::Cyan,
            "One agent harness hits this friction far more often than others.",
        ),
        _ => (
            "Friction signal",
            Color::Cyan,
            "Recurring friction hotspot detected across sessions.",
        ),
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

fn compact_opp_metric(o: &Opportunity) -> String {
    match o.kind.as_str() {
        "polling_tax" => {
            let calls = ev_u64(o, "total_calls").unwrap_or(0);
            let wait = ev_f64(o, "total_wait_s").unwrap_or(0.0);
            if wait >= 60.0 {
                format!(
                    "{} polls · {}",
                    format_int(calls as usize),
                    format_duration(wait)
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
            format!("{} fallbacks", format_int(n as usize))
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
        "context_handoff_bloat" => {
            let m = ev_f64(o, "multiplier").unwrap_or(0.0);
            format!("{m:.1}× tokens")
        }
        "low_cache_efficiency" => {
            let r = ev_f64(o, "weighted_cache_hit").unwrap_or(0.0) * 100.0;
            format!("{r:.0}% cache hit")
        }
        "harness_divergence" => {
            let r = ev_f64(o, "rate_ratio").unwrap_or(0.0);
            format!("{r:.1}× gap")
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

fn sessions_label_for(o: &Opportunity) -> String {
    if let Some(s) = ev_u64(o, "sessions") {
        return format!("{s} sess");
    }
    if let Some(s) = ev_u64(o, "handoff_sessions") {
        return format!("{s} sess");
    }
    if let Some(r) = ev_u64(o, "runs") {
        return format!("{r} runs");
    }
    "—".to_string()
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
    }
}

// ---------------------------------------------------------------------------
// Tab 1: Insights (KPIs + Aligned Deduplicated Table + 2-Column Insight Card)
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

    let detail_h = if area.height >= 30 { 12 } else { 9 };
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(7),
            Constraint::Length(detail_h),
        ])
        .split(area);

    // 1. Plain-English KPI Cards
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

    let cache_str = k
        .cache_hit_rate
        .map(|v| format!("{:.0}% cache", v * 100.0))
        .unwrap_or_else(|| "no cache data".into());
    let card1 = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                format_compact(k.median_tokens_per_session),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" median toks", Style::default().fg(Color::Gray)),
        ]),
        Line::from(Span::styled(
            format!(
                "Top 5% hit {} · {cache_str}",
                format_compact(k.p95_tokens_per_session)
            ),
            Style::default().fg(Color::Gray),
        )),
    ])
    .block(rounded_block(" Session Size ", false));

    let card2 = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                format_duration(k.total_tool_wait_s),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" total wait", Style::default().fg(Color::Gray)),
        ]),
        Line::from(Span::styled(
            format!("{} median / session", format_duration(k.median_tool_wait_s)),
            Style::default().fg(Color::Gray),
        )),
    ])
    .block(rounded_block(" Tool Wait ", false));

    let cli_val = k
        .cli_adoption_rate
        .map(|v| format!("{:.0}%", v * 100.0))
        .unwrap_or_else(|| "n/a".into());
    let card3 = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                cli_val,
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" via repo CLI", Style::default().fg(Color::Gray)),
        ]),
        Line::from(Span::styled(
            format!(
                "{:.0}% fall back to shell",
                k.escape_hatch_rebound_rate * 100.0
            ),
            Style::default().fg(if k.escape_hatch_rebound_rate >= 0.30 {
                Color::Yellow
            } else {
                Color::Gray
            }),
        )),
    ])
    .block(rounded_block(" CLI Adoption ", false));

    let err_col = if k.command_error_rate >= 0.10 {
        Color::Red
    } else if k.command_error_rate >= 0.04 {
        Color::Yellow
    } else {
        Color::Green
    };
    let card4 = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                format!("{:.1}%", k.command_error_rate * 100.0),
                Style::default().fg(err_col).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" cmd errors", Style::default().fg(Color::Gray)),
        ]),
        Line::from(Span::styled(
            format!("{} startup discovery", format_compact(k.orientation_tokens)),
            Style::default().fg(Color::Gray),
        )),
    ])
    .block(rounded_block(" Errors & Startup ", false));

    frame.render_widget(card1, cards[0]);
    frame.render_widget(card2, cards[1]);
    frame.render_widget(card3, cards[2]);
    frame.render_widget(card4, cards[3]);

    // 2. Scannable, Deduplicated Signals Table
    let merged = app.visible_insights();
    let wide = rows[1].width >= 108;

    let filter_title = Line::from(vec![
        Span::styled(
            format!(" Signals ({}) ", merged.len()),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled("─ Filter: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("[{}]", app.scope_filter.label()),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(
                "  ({} repo · {} harness)  (f) ",
                repo.opportunities.len(),
                repo.harness_overhead.len()
            ),
            Style::default().fg(Color::DarkGray),
        ),
    ]);

    if merged.is_empty() {
        let p = Paragraph::new(
            "No friction signals in this scope & window.\nPress 'f' to switch scope (Repo / All / Harness) or 'w' to widen window.",
        )
        .block(rounded_block(filter_title, focused));
        frame.render_widget(p, rows[1]);
    } else {
        let target_w = if wide {
            rows[1].width.saturating_sub(74).max(20) as usize
        } else {
            rows[1].width.saturating_sub(54).max(18) as usize
        };

        let header = if wide {
            Row::new(vec![
                Cell::from("Problem"),
                Cell::from("Target"),
                Cell::from(Line::from("Impact").right_aligned()),
                Cell::from(Line::from("Scope").right_aligned()),
                Cell::from("Harness"),
                Cell::from("Area"),
            ])
        } else {
            Row::new(vec![
                Cell::from("Problem"),
                Cell::from("Target"),
                Cell::from(Line::from("Impact").right_aligned()),
                Cell::from("Harness"),
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
                let (label, sev_col, _) = human_problem(&o.kind);
                let problem_cell = Cell::from(Line::from(vec![
                    Span::styled("● ", Style::default().fg(sev_col)),
                    Span::styled(label, Style::default().add_modifier(Modifier::BOLD)),
                ]));
                let target_cell = Cell::from(truncate_ellipsis(&o.target, target_w));
                let metric = primary_metric_for(item);
                let impact_cell = Cell::from(Line::from(metric).right_aligned());
                let (h_txt, h_col) = compact_harness_cell(&o.by_harness);
                let harness_cell = Cell::from(h_txt).style(Style::default().fg(h_col));

                if wide {
                    let sess_or_scope = if app.scope_filter == ScopeFilter::All {
                        o.scope.clone()
                    } else {
                        sessions_label_for(o)
                    };
                    Row::new(vec![
                        problem_cell,
                        target_cell,
                        impact_cell,
                        Cell::from(Line::from(sess_or_scope).right_aligned())
                            .style(Style::default().fg(Color::Gray)),
                        harness_cell,
                        Cell::from(truncate_ellipsis(&o.fix_target, 16))
                            .style(Style::default().fg(Color::DarkGray)),
                    ])
                } else {
                    Row::new(vec![problem_cell, target_cell, impact_cell, harness_cell])
                }
            })
            .collect();

        let constraints: Vec<Constraint> = if wide {
            vec![
                Constraint::Length(17),
                Constraint::Fill(1),
                Constraint::Length(18),
                Constraint::Length(8),
                Constraint::Length(12),
                Constraint::Length(16),
            ]
        } else {
            vec![
                Constraint::Length(17),
                Constraint::Fill(1),
                Constraint::Length(18),
                Constraint::Length(12),
            ]
        };

        let table = Table::new(table_rows, constraints)
            .header(header)
            .column_spacing(2)
            .block(rounded_block(filter_title, focused))
            .row_highlight_style(row_highlight_style())
            .highlight_symbol("▶ ");
        frame.render_stateful_widget(table, rows[1], &mut app.opp_state);
    }

    // 3. Rich 2-Column Insight Card
    if let Some(idx) = app.opp_state.selected()
        && let Some(item) = merged.get(idx)
    {
        let o = &item.primary;
        let (label, sev_col, meaning) = human_problem(&o.kind);
        let card_title = Line::from(vec![
            Span::styled(" ● ", Style::default().fg(sev_col)),
            Span::styled(
                format!("{label}: {} ", truncate_ellipsis(&o.target, 52)),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("[{}] ", o.scope),
                Style::default().fg(if o.scope == "harness" {
                    Color::Blue
                } else {
                    Color::Green
                }),
            ),
            Span::styled(
                " [Enter] Inspect traces ",
                Style::default().fg(Color::DarkGray),
            ),
        ]);

        let card_block = rounded_block(card_title, false);
        let inner = card_block.inner(rows[2]);
        frame.render_widget(card_block, rows[2]);

        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(54),
                Constraint::Length(2),
                Constraint::Percentage(46),
            ])
            .split(inner);

        // Left column: Plain-English explanation + Where to look
        let mut left_lines = vec![
            Line::from(Span::styled(
                "WHAT'S HAPPENING",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(meaning),
            Line::from(Span::styled(
                format!("Impact: {}", o.impact_summary),
                Style::default().fg(Color::Gray),
            )),
        ];
        if !item.related.is_empty() {
            let also: Vec<String> = item
                .related
                .iter()
                .map(|r| {
                    let (rl, _, _) = human_problem(&r.kind);
                    let m = compact_opp_metric(r);
                    format!("{rl} ({m})")
                })
                .collect();
            left_lines.push(Line::from(Span::styled(
                format!("Also: {}", also.join(" · ")),
                Style::default().fg(Color::Yellow),
            )));
        }
        left_lines.push(Line::from(""));
        left_lines.push(Line::from(Span::styled(
            "WHERE TO LOOK",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )));
        left_lines.push(Line::from(o.suggested_action.clone()));
        left_lines.push(Line::from(Span::styled(
            format!("Goal: {}", o.acceptance_metric),
            Style::default().fg(Color::Gray),
        )));

        frame.render_widget(
            Paragraph::new(left_lines).wrap(Wrap { trim: true }),
            cols[0],
        );

        // Right column: Who does it (visual proportion bars) + Concrete evidence
        let mut right_lines = vec![Line::from(Span::styled(
            "WHO DOES IT",
            Style::default()
                .fg(Color::LightMagenta)
                .add_modifier(Modifier::BOLD),
        ))];
        right_lines.extend(harness_bar_lines(&o.by_harness, 10));
        if !o.trace_proof.is_empty() {
            right_lines.push(Line::from(""));
            right_lines.push(Line::from(Span::styled(
                "CONCRETE EVIDENCE",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )));
            for tp in o.trace_proof.iter().take(2) {
                right_lines.push(Line::from(Span::styled(
                    format!("• {tp}"),
                    Style::default().fg(Color::Gray),
                )));
            }
        }
        frame.render_widget(
            Paragraph::new(right_lines).wrap(Wrap { trim: true }),
            cols[2],
        );
    } else {
        let p = Paragraph::new("Select a signal above to inspect its plain-English breakdown.")
            .block(rounded_block(" Insight ", false));
        frame.render_widget(p, rows[2]);
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
                        "RUNAWAY SESSION DRIVERS (TOP-25% VS BOT-50%)",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )));
                    for lift in pat.pareto.storm_lifts.iter().take(4) {
                        detail_lines.push(Line::from(Span::styled(
                            format!(
                                "• {} — {:.0}% vs {:.0}% ({})",
                                lift.family,
                                lift.top25_pct_sessions,
                                lift.bottom50_pct_sessions,
                                lift.lift_str
                            ),
                            Style::default().fg(Color::Gray),
                        )));
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
                rows_vec.push(Row::new(vec![
                    Cell::from(tag).style(Style::default().fg(col).add_modifier(Modifier::BOLD)),
                    Cell::from(truncate_ellipsis(&d.cmd_family, left_w)),
                    Cell::from(Line::from(format!("{:.1}×", d.rate_ratio)).right_aligned()),
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
// Tab 3: Harnesses (Side-by-Side Comparison + Harness Overhead + MCP Tools)
// ---------------------------------------------------------------------------

fn draw_harnesses_tab(frame: &mut Frame, area: Rect, app: &mut App) {
    let focused = app.focus == Focus::Main;
    let Some(pat) = app.selected_patterns.clone() else {
        let p = Paragraph::new("No harness comparison data available.")
            .block(rounded_block(" Harnesses ", focused));
        frame.render_widget(p, area);
        return;
    };

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
        .split(area);

    let wide = rows[0].width >= 108;
    let header = if wide {
        Row::new(vec![
            Cell::from("Harness / Role"),
            Cell::from(Line::from("Sess").right_aligned()),
            Cell::from(Line::from("Cmds").right_aligned()),
            Cell::from(Line::from("Med Toks").right_aligned()),
            Cell::from(Line::from("Uncached").right_aligned()),
            Cell::from("Cache Hit"),
            Cell::from(Line::from("Med Wait").right_aligned()),
            Cell::from(Line::from("Err%").right_aligned()),
            Cell::from(Line::from("Fallback%").right_aligned()),
        ])
    } else {
        Row::new(vec![
            Cell::from("Harness / Role"),
            Cell::from(Line::from("Sess").right_aligned()),
            Cell::from(Line::from("Cmds").right_aligned()),
            Cell::from(Line::from("Med Toks").right_aligned()),
            Cell::from("Cache Hit"),
            Cell::from(Line::from("Err%").right_aligned()),
        ])
    }
    .style(
        Style::default()
            .fg(Color::Gray)
            .add_modifier(Modifier::BOLD),
    );

    let table_rows: Vec<Row> = pat
        .harness_comparison
        .iter()
        .map(|h| {
            let short = short_harness(&h.agent_kind);
            let hcol = harness_color(short);
            let role_label = if h.originator != "default" && !h.originator.is_empty() {
                format!(
                    "{short} ({} · {})",
                    h.role,
                    truncate_ellipsis(&h.originator, 10)
                )
            } else {
                format!("{short} ({})", h.role)
            };
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
            let err_col = if h.error_rate >= 0.08 {
                Color::Red
            } else if h.error_rate >= 0.03 {
                Color::Yellow
            } else {
                Color::Green
            };

            if wide {
                Row::new(vec![
                    Cell::from(truncate_ellipsis(&role_label, 28)).style(Style::default().fg(hcol)),
                    Cell::from(Line::from(h.sessions.to_string()).right_aligned()),
                    Cell::from(Line::from(format_compact(h.commands as i64)).right_aligned()),
                    Cell::from(Line::from(format_compact(h.median_total_tokens)).right_aligned()),
                    Cell::from(Line::from(format_compact(h.avg_uncached_tokens)).right_aligned())
                        .style(Style::default().fg(Color::Gray)),
                    cache_cell,
                    Cell::from(Line::from(format_duration(h.median_tool_wait_s)).right_aligned()),
                    Cell::from(Line::from(format!("{:.1}%", h.error_rate * 100.0)).right_aligned())
                        .style(Style::default().fg(err_col)),
                    Cell::from(
                        Line::from(format!("{:.0}%", h.rebound_rate * 100.0)).right_aligned(),
                    )
                    .style(Style::default().fg(Color::Gray)),
                ])
            } else {
                Row::new(vec![
                    Cell::from(truncate_ellipsis(&role_label, 24)).style(Style::default().fg(hcol)),
                    Cell::from(Line::from(h.sessions.to_string()).right_aligned()),
                    Cell::from(Line::from(format_compact(h.commands as i64)).right_aligned()),
                    Cell::from(Line::from(format_compact(h.median_total_tokens)).right_aligned()),
                    cache_cell,
                    Cell::from(Line::from(format!("{:.1}%", h.error_rate * 100.0)).right_aligned())
                        .style(Style::default().fg(err_col)),
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
            Constraint::Length(8),
            Constraint::Length(14),
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Length(9),
        ]
    } else {
        vec![
            Constraint::Fill(1),
            Constraint::Length(5),
            Constraint::Length(6),
            Constraint::Length(8),
            Constraint::Length(14),
            Constraint::Length(6),
        ]
    };

    let table = Table::new(table_rows, constraints)
        .header(header)
        .column_spacing(2)
        .block(rounded_block(
            format!(
                " Harness Comparison ({} strata) ",
                pat.harness_comparison.len()
            ),
            focused,
        ))
        .row_highlight_style(row_highlight_style())
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(table, rows[0], &mut app.harness_state);

    // Bottom split: Left = Harness-specific overhead | Right = Top friction & MCP errors
    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
        .split(rows[1]);

    let sel_h = app
        .harness_state
        .selected()
        .and_then(|i| pat.harness_comparison.get(i));
    let selected_ag = sel_h.map(|h| h.agent_kind.as_str()).unwrap_or("");
    let short_ag = short_harness(selected_ag);

    // Left: Harness overhead for selected agent
    let mut ov_lines = Vec::new();
    if let Some(repo) = &app.selected_repo {
        let filtered: Vec<&Opportunity> = repo
            .harness_overhead
            .iter()
            .filter(|o| selected_ag.is_empty() || o.by_harness.contains_key(selected_ag))
            .collect();
        let merged_ov = merge_opportunities(&filtered);
        if merged_ov.is_empty() {
            ov_lines.push(Line::from(Span::styled(
                format!("No harness-specific overhead flagged for {short_ag}."),
                Style::default().fg(Color::Green),
            )));
        } else {
            for item in merged_ov.iter().take(6) {
                let (lbl, col, _) = human_problem(&item.primary.kind);
                ov_lines.push(Line::from(vec![
                    Span::styled("● ", Style::default().fg(col)),
                    Span::styled(
                        format!("{lbl:<15} "),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!("{}  ", truncate_ellipsis(&item.primary.target, 24))),
                    Span::styled(primary_metric_for(item), Style::default().fg(Color::Yellow)),
                ]));
            }
        }
        if let Some(h) = sel_h {
            ov_lines.push(Line::from(""));
            ov_lines.push(Line::from(Span::styled(
                format!(
                    "Avg output: {:.1} KB · Truncated outputs: {} ({:.0}% of sessions)",
                    h.avg_output_kb, h.truncated_outputs, h.truncated_sessions_pct
                ),
                Style::default().fg(Color::Gray),
            )));
        }
    }
    frame.render_widget(
        Paragraph::new(ov_lines)
            .wrap(Wrap { trim: true })
            .block(rounded_block(
                format!(" Harness Overhead ({short_ag}) "),
                false,
            )),
        bottom[0],
    );

    // Right: Top friction commands, universal friction, and failing MCP tools
    let mut right_lines = Vec::new();
    if let Some(h) = sel_h
        && !h.top_friction_cmds.is_empty()
    {
        right_lines.push(Line::from(Span::styled(
            format!("TOP FRICTION COMMANDS ({short_ag})"),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        for (i, cmd) in h.top_friction_cmds.iter().take(4).enumerate() {
            right_lines.push(Line::from(format!("  {}. {cmd}", i + 1)));
        }
        right_lines.push(Line::from(""));
    }
    if !pat.universal_friction_cmds.is_empty() {
        right_lines.push(Line::from(Span::styled(
            "UNIVERSAL FRICTION (≥2 HARNESSES)",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )));
        right_lines.push(Line::from(Span::styled(
            pat.universal_friction_cmds
                .iter()
                .take(6)
                .cloned()
                .collect::<Vec<_>>()
                .join("  ·  "),
            Style::default().fg(Color::Gray),
        )));
        right_lines.push(Line::from(""));
    }
    let mcp_for_ag: Vec<_> = pat
        .top_mcp_errors
        .iter()
        .filter(|t| selected_ag.is_empty() || t.by_harness.contains_key(selected_ag))
        .take(4)
        .collect();
    if !mcp_for_ag.is_empty() {
        right_lines.push(Line::from(Span::styled(
            format!("FAILING / TRUNCATED MCP TOOLS ({short_ag})"),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
        for t in mcp_for_ag {
            right_lines.push(Line::from(vec![
                Span::raw(format!("• {} ", truncate_ellipsis(&t.tool_name, 30))),
                Span::styled(
                    format!(
                        "{} errs ({:.0}%) · {} trunc",
                        t.error_count,
                        t.error_rate * 100.0,
                        t.truncated_count
                    ),
                    Style::default().fg(if t.error_count > 0 {
                        Color::Red
                    } else {
                        Color::Yellow
                    }),
                ),
            ]));
        }
    }
    frame.render_widget(
        Paragraph::new(right_lines)
            .wrap(Wrap { trim: true })
            .block(rounded_block(" Friction & MCP Tools ", false)),
        bottom[1],
    );
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
        DetailTab::Harnesses => {}
    }
    spans.extend([
        Span::styled(
            " 1-5/Tab ",
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
        let (label, sev_col, meaning) = human_problem(&opp.kind);
        lines.push(Line::from(vec![
            Span::styled("● ", Style::default().fg(sev_col)),
            Span::styled(
                format!("{label} — {} ", opp.target),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("[{}]", opp.scope), Style::default().fg(Color::Gray)),
        ]));
        lines.push(Line::from(meaning));
        lines.push(Line::from(Span::styled(
            format!("Impact: {}", opp.impact_summary),
            Style::default().fg(Color::Gray),
        )));
        lines.push(Line::from(vec![
            Span::styled(
                "Harnesses: ",
                Style::default()
                    .fg(Color::LightMagenta)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(opp.harness_summary.clone()),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Where to look: ", Style::default().fg(Color::Cyan)),
            Span::raw(opp.suggested_action.clone()),
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
            "  1–5 / Tab / Shift-Tab   Switch views (Insights, Patterns, Harnesses, Commands, Brief)",
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
            "  Insights:  f = Scope filter (Repo fixes / All / Harness)  ·  Enter = Inspect traces",
        ),
        Line::from("  Patterns:  v = Switch view (Workflows / Burst Storms / Drift & Cold-Start)"),
        Line::from("  Commands:  s = Switch sort/view (Token Sinks / Slowest / Most Errors / MCP)"),
        Line::from("  Brief:     m = Toggle Diagnosis Prompt (Markdown) vs Structured YAML"),
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
