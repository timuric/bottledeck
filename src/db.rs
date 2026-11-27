use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::fs;
use std::path::Path;

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS ingest_files (
  file_path   TEXT PRIMARY KEY,
  adapter     TEXT NOT NULL,
  size_bytes  INTEGER NOT NULL,
  mtime_ms    INTEGER NOT NULL,
  line_count  INTEGER NOT NULL DEFAULT 0,
  updated_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS workspaces (
  workspace_id    TEXT PRIMARY KEY,
  repo_id         TEXT NOT NULL,
  repo_name       TEXT NOT NULL,
  worktree_path   TEXT NOT NULL UNIQUE,
  git_common_dir  TEXT,
  is_worktree     INTEGER NOT NULL DEFAULT 0,
  updated_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  session_id           TEXT PRIMARY KEY,
  agent_kind           TEXT NOT NULL,
  source_file          TEXT NOT NULL,
  model                TEXT,
  workspace_id         TEXT,
  repo_id              TEXT,
  repo_name            TEXT,
  cwd                  TEXT,
  git_branch           TEXT,
  started_at           INTEGER,
  ended_at             INTEGER,
  turn_count           INTEGER NOT NULL DEFAULT 0,
  user_turn_count      INTEGER NOT NULL DEFAULT 0,
  input_tokens         INTEGER NOT NULL DEFAULT 0,
  output_tokens        INTEGER NOT NULL DEFAULT 0,
  cached_tokens        INTEGER NOT NULL DEFAULT 0,
  cache_write_tokens   INTEGER NOT NULL DEFAULT 0,
  thinking_tokens      INTEGER NOT NULL DEFAULT 0,
  cost_usd             REAL,
  total_tool_ms        INTEGER NOT NULL DEFAULT 0,
  tool_wall_ms         INTEGER NOT NULL DEFAULT 0,
  api_duration_ms      INTEGER NOT NULL DEFAULT 0,
  api_retry_ms         INTEGER NOT NULL DEFAULT 0,
  thinking_duration_ms INTEGER NOT NULL DEFAULT 0,
  ttft_ms_sum          INTEGER NOT NULL DEFAULT 0,
  ttft_count           INTEGER NOT NULL DEFAULT 0,
  compaction_count     INTEGER NOT NULL DEFAULT 0,
  aborted_turns        INTEGER NOT NULL DEFAULT 0,
  api_errors           INTEGER NOT NULL DEFAULT 0,
  outcome              TEXT,
  parent_session_id    TEXT,
  lines_added          INTEGER NOT NULL DEFAULT 0,
  lines_removed        INTEGER NOT NULL DEFAULT 0,
  max_context_tokens   INTEGER NOT NULL DEFAULT 0,
  context_window       INTEGER,
  effort               TEXT,
  turn_origin          TEXT,
  is_subagent          INTEGER NOT NULL DEFAULT 0,
  originator           TEXT,
  subagent_kind        TEXT,
  is_handoff           INTEGER NOT NULL DEFAULT 0,
  harness_version      TEXT
);

CREATE TABLE IF NOT EXISTS command_spans (
  span_id          TEXT PRIMARY KEY,
  session_id       TEXT,
  source_file      TEXT NOT NULL,
  source_kind      TEXT NOT NULL,
  agent_kind       TEXT,
  tool_call_id     TEXT,
  turn_idx         INTEGER NOT NULL DEFAULT 0,
  seq_idx          INTEGER NOT NULL DEFAULT 0,
  workspace_id     TEXT,
  repo_id          TEXT,
  repo_name        TEXT,
  git_head         TEXT,
  actor            TEXT NOT NULL DEFAULT 'agent',
  category         TEXT NOT NULL,
  is_repo_cli      INTEGER NOT NULL DEFAULT 0,
  surface_version  TEXT,
  cmd_bin          TEXT NOT NULL,
  cmd_template     TEXT NOT NULL,
  raw_redacted     TEXT NOT NULL,
  exit_code        INTEGER,
  duration_ms      INTEGER,
  stdout_bytes     INTEGER NOT NULL DEFAULT 0,
  stdout_tokens    INTEGER NOT NULL DEFAULT 0,
  stderr_bytes     INTEGER NOT NULL DEFAULT 0,
  stderr_preview   TEXT,
  noise_kind       TEXT,
  is_orientation   INTEGER NOT NULL DEFAULT 0,
  piped_filter     TEXT,
  state_dir_hint   TEXT,
  is_truncated     INTEGER NOT NULL DEFAULT 0,
  is_chained       INTEGER NOT NULL DEFAULT 0,
  is_long_duration INTEGER NOT NULL DEFAULT 0,
  interrupted      INTEGER NOT NULL DEFAULT 0,
  started_at       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS file_reads (
  read_id        TEXT PRIMARY KEY,
  session_id     TEXT NOT NULL,
  source_file    TEXT NOT NULL,
  repo_id        TEXT,
  repo_name      TEXT,
  turn_idx       INTEGER NOT NULL DEFAULT 0,
  target_name    TEXT NOT NULL,
  target_path    TEXT,
  is_doc         INTEGER NOT NULL DEFAULT 0,
  output_tokens  INTEGER NOT NULL DEFAULT 0,
  started_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_calls (
  call_id        TEXT PRIMARY KEY,
  session_id     TEXT NOT NULL,
  source_file    TEXT NOT NULL,
  agent_kind     TEXT NOT NULL,
  repo_id        TEXT,
  repo_name      TEXT,
  turn_idx       INTEGER NOT NULL DEFAULT 0,
  seq_idx        INTEGER NOT NULL DEFAULT 0,
  tool_call_id   TEXT,
  tool_name      TEXT NOT NULL,
  target_path    TEXT,
  is_mcp         INTEGER NOT NULL DEFAULT 0,
  is_edit        INTEGER NOT NULL DEFAULT 0,
  is_error       INTEGER NOT NULL DEFAULT 0,
  interrupted    INTEGER NOT NULL DEFAULT 0,
  duration_ms    INTEGER,
  output_bytes   INTEGER NOT NULL DEFAULT 0,
  output_tokens  INTEGER NOT NULL DEFAULT 0,
  is_truncated   INTEGER NOT NULL DEFAULT 0,
  error_preview  TEXT,
  started_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS llm_calls (
  call_id            TEXT PRIMARY KEY,
  session_id         TEXT NOT NULL,
  source_file        TEXT NOT NULL,
  agent_kind         TEXT NOT NULL,
  repo_id            TEXT,
  turn_idx           INTEGER NOT NULL DEFAULT 0,
  model              TEXT,
  input_tokens       INTEGER NOT NULL DEFAULT 0,
  cache_read_tokens  INTEGER NOT NULL DEFAULT 0,
  cache_write_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens      INTEGER NOT NULL DEFAULT 0,
  thinking_tokens    INTEGER NOT NULL DEFAULT 0,
  duration_ms        INTEGER,
  ttft_ms            INTEGER,
  thinking_ms        INTEGER,
  stop_reason        TEXT,
  context_tokens     INTEGER NOT NULL DEFAULT 0,
  context_window     INTEGER,
  started_at         INTEGER NOT NULL
);

-- Fix markers: user-declared points in time (commit, date) after which an issue should stop recurring.
-- issue_key NULL = applies to every tracked issue in the repo.
CREATE TABLE IF NOT EXISTS issue_markers (
  marker_id   INTEGER PRIMARY KEY AUTOINCREMENT,
  repo_id     TEXT NOT NULL,
  issue_key   TEXT,
  at_ms       INTEGER NOT NULL,
  label       TEXT NOT NULL,
  note        TEXT,
  created_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_markers_repo ON issue_markers(repo_id, issue_key);
CREATE INDEX IF NOT EXISTS idx_sessions_repo_time ON sessions(repo_id, started_at);
CREATE INDEX IF NOT EXISTS idx_sessions_source ON sessions(source_file);
CREATE INDEX IF NOT EXISTS idx_spans_repo_time ON command_spans(repo_id, started_at);
CREATE INDEX IF NOT EXISTS idx_spans_session_seq ON command_spans(session_id, turn_idx, seq_idx);
CREATE INDEX IF NOT EXISTS idx_spans_source ON command_spans(source_file);
CREATE INDEX IF NOT EXISTS idx_reads_repo_time ON file_reads(repo_id, started_at);
CREATE INDEX IF NOT EXISTS idx_reads_source ON file_reads(source_file);
CREATE INDEX IF NOT EXISTS idx_tools_repo_time ON tool_calls(repo_id, started_at);
CREATE INDEX IF NOT EXISTS idx_tools_source ON tool_calls(source_file);
CREATE INDEX IF NOT EXISTS idx_llm_repo_time ON llm_calls(repo_id, started_at);
CREATE INDEX IF NOT EXISTS idx_llm_session ON llm_calls(session_id, turn_idx, started_at);
CREATE INDEX IF NOT EXISTS idx_llm_source ON llm_calls(source_file);
"#;

#[derive(Debug, Clone, Default)]
pub struct SessionRecord {
    pub session_id: String,
    pub agent_kind: String,
    pub source_file: String,
    pub model: Option<String>,
    pub workspace_id: Option<String>,
    pub repo_id: Option<String>,
    pub repo_name: Option<String>,
    pub cwd: Option<String>,
    pub git_branch: Option<String>,
    pub started_at: Option<i64>,
    pub ended_at: Option<i64>,
    pub turn_count: i64,
    pub user_turn_count: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cached_tokens: i64,
    pub cache_write_tokens: i64,
    pub thinking_tokens: i64,
    pub cost_usd: Option<f64>,
    pub total_tool_ms: i64,
    pub tool_wall_ms: i64,
    pub api_duration_ms: i64,
    pub api_retry_ms: i64,
    pub thinking_duration_ms: i64,
    pub ttft_ms_sum: i64,
    pub ttft_count: i64,
    pub compaction_count: i64,
    pub aborted_turns: i64,
    pub api_errors: i64,
    pub outcome: Option<String>,
    pub parent_session_id: Option<String>,
    pub lines_added: i64,
    pub lines_removed: i64,
    pub max_context_tokens: i64,
    pub context_window: Option<i64>,
    pub effort: Option<String>,
    pub turn_origin: Option<String>,
    pub is_subagent: bool,
    pub originator: Option<String>,
    pub subagent_kind: Option<String>,
    pub is_handoff: bool,
    /// Harness CLI/app version that produced the transcript (e.g. Claude Code `2.1.3`, Codex `0.171.0`).
    pub harness_version: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CommandSpanRecord {
    pub span_id: String,
    pub session_id: Option<String>,
    pub source_file: String,
    pub source_kind: String,
    pub agent_kind: Option<String>,
    pub tool_call_id: Option<String>,
    pub turn_idx: i64,
    pub seq_idx: i64,
    pub workspace_id: Option<String>,
    pub repo_id: Option<String>,
    pub repo_name: Option<String>,
    pub git_head: Option<String>,
    pub actor: String,
    pub category: String,
    pub is_repo_cli: bool,
    pub surface_version: Option<String>,
    pub cmd_bin: String,
    pub cmd_template: String,
    pub raw_redacted: String,
    pub exit_code: Option<i64>,
    pub duration_ms: Option<i64>,
    pub stdout_bytes: i64,
    pub stdout_tokens: i64,
    pub stderr_bytes: i64,
    pub stderr_preview: Option<String>,
    pub noise_kind: Option<String>,
    pub is_orientation: bool,
    pub piped_filter: Option<String>,
    pub state_dir_hint: Option<String>,
    pub is_truncated: bool,
    pub is_chained: bool,
    pub is_long_duration: bool,
    pub interrupted: bool,
    pub started_at: i64,
}

#[derive(Debug, Clone, Default)]
pub struct FileReadRecord {
    pub read_id: String,
    pub session_id: String,
    pub source_file: String,
    pub repo_id: Option<String>,
    pub repo_name: Option<String>,
    pub turn_idx: i64,
    pub target_name: String,
    pub target_path: Option<String>,
    pub is_doc: bool,
    pub output_tokens: i64,
    pub started_at: i64,
}

#[derive(Debug, Clone, Default)]
pub struct ToolCallRecord {
    pub call_id: String,
    pub session_id: String,
    pub source_file: String,
    pub agent_kind: String,
    pub repo_id: Option<String>,
    pub repo_name: Option<String>,
    pub turn_idx: i64,
    pub seq_idx: i64,
    pub tool_call_id: Option<String>,
    pub tool_name: String,
    pub target_path: Option<String>,
    pub is_mcp: bool,
    pub is_edit: bool,
    pub is_error: bool,
    pub interrupted: bool,
    pub duration_ms: Option<i64>,
    pub output_bytes: i64,
    pub output_tokens: i64,
    pub is_truncated: bool,
    pub error_preview: Option<String>,
    pub started_at: i64,
}

#[derive(Debug, Clone, Default)]
pub struct LlmCallRecord {
    pub call_id: String,
    pub session_id: String,
    pub source_file: String,
    pub agent_kind: String,
    pub repo_id: Option<String>,
    pub turn_idx: i64,
    pub model: Option<String>,
    pub input_tokens: i64,
    pub cache_read_tokens: i64,
    pub cache_write_tokens: i64,
    pub output_tokens: i64,
    pub thinking_tokens: i64,
    pub duration_ms: Option<i64>,
    pub ttft_ms: Option<i64>,
    pub thinking_ms: Option<i64>,
    pub stop_reason: Option<String>,
    pub context_tokens: i64,
    pub context_window: Option<i64>,
    pub started_at: i64,
}

pub fn open_db(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create state dir {}", parent.display()))?;
    }
    let conn = Connection::open(path)
        .with_context(|| format!("failed to open SQLite ledger at {}", path.display()))?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = OFF;
         PRAGMA busy_timeout = 5000;",
    )?;
    conn.execute_batch(SCHEMA_SQL)?;
    // Idempotent additive migrations for existing ledgers
    let migrations = [
        "ALTER TABLE command_spans ADD COLUMN piped_filter TEXT",
        "ALTER TABLE command_spans ADD COLUMN state_dir_hint TEXT",
        "ALTER TABLE command_spans ADD COLUMN is_truncated INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE command_spans ADD COLUMN is_chained INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE command_spans ADD COLUMN is_long_duration INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE command_spans ADD COLUMN interrupted INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN is_subagent INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN originator TEXT",
        "ALTER TABLE sessions ADD COLUMN subagent_kind TEXT",
        "ALTER TABLE sessions ADD COLUMN is_handoff INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN user_turn_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN cache_write_tokens INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN thinking_tokens INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN tool_wall_ms INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN api_duration_ms INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN api_retry_ms INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN thinking_duration_ms INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN ttft_ms_sum INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN ttft_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN compaction_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN aborted_turns INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN api_errors INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN outcome TEXT",
        "ALTER TABLE sessions ADD COLUMN parent_session_id TEXT",
        "ALTER TABLE sessions ADD COLUMN lines_added INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN lines_removed INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN max_context_tokens INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN context_window INTEGER",
        "ALTER TABLE sessions ADD COLUMN effort TEXT",
        "ALTER TABLE sessions ADD COLUMN turn_origin TEXT",
        "ALTER TABLE sessions ADD COLUMN harness_version TEXT",
        "ALTER TABLE file_reads ADD COLUMN target_path TEXT",
        "ALTER TABLE tool_calls ADD COLUMN seq_idx INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE tool_calls ADD COLUMN tool_call_id TEXT",
        "ALTER TABLE tool_calls ADD COLUMN target_path TEXT",
        "ALTER TABLE tool_calls ADD COLUMN is_edit INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE tool_calls ADD COLUMN interrupted INTEGER NOT NULL DEFAULT 0",
        "CREATE INDEX IF NOT EXISTS idx_sessions_parent ON sessions(parent_session_id)",
        "CREATE INDEX IF NOT EXISTS idx_tools_session_seq ON tool_calls(session_id, turn_idx, seq_idx)",
    ];
    for sql in migrations {
        let _ = conn.execute(sql, []);
    }
    Ok(conn)
}

pub fn delete_records_for_source(conn: &Connection, source_file: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM command_spans WHERE source_file = ?1",
        params![source_file],
    )?;
    conn.execute(
        "DELETE FROM file_reads WHERE source_file = ?1",
        params![source_file],
    )?;
    conn.execute(
        "DELETE FROM tool_calls WHERE source_file = ?1",
        params![source_file],
    )?;
    conn.execute(
        "DELETE FROM llm_calls WHERE source_file = ?1",
        params![source_file],
    )?;
    conn.execute(
        "DELETE FROM sessions WHERE source_file = ?1",
        params![source_file],
    )?;
    Ok(())
}

pub fn upsert_session(conn: &Connection, s: &SessionRecord) -> Result<()> {
    conn.execute(
        "INSERT INTO sessions (
          session_id, agent_kind, source_file, model, workspace_id, repo_id, repo_name,
          cwd, git_branch, started_at, ended_at, turn_count, user_turn_count, input_tokens,
          output_tokens, cached_tokens, cache_write_tokens, thinking_tokens, cost_usd,
          total_tool_ms, tool_wall_ms, api_duration_ms, api_retry_ms, thinking_duration_ms,
          ttft_ms_sum, ttft_count, compaction_count, aborted_turns, api_errors, outcome,
          parent_session_id, lines_added, lines_removed, max_context_tokens, context_window,
          effort, turn_origin, is_subagent, originator, subagent_kind, is_handoff, harness_version
        ) VALUES (
          ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19,
          ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36,
          ?37, ?38, ?39, ?40, ?41, ?42
        )
        ON CONFLICT(session_id) DO UPDATE SET
          model = COALESCE(excluded.model, sessions.model),
          workspace_id = COALESCE(excluded.workspace_id, sessions.workspace_id),
          repo_id = COALESCE(excluded.repo_id, sessions.repo_id),
          repo_name = COALESCE(excluded.repo_name, sessions.repo_name),
          cwd = COALESCE(excluded.cwd, sessions.cwd),
          git_branch = COALESCE(excluded.git_branch, sessions.git_branch),
          started_at = CASE
            WHEN sessions.started_at IS NULL THEN excluded.started_at
            WHEN excluded.started_at IS NULL THEN sessions.started_at
            ELSE MIN(sessions.started_at, excluded.started_at)
          END,
          ended_at = CASE
            WHEN sessions.ended_at IS NULL THEN excluded.ended_at
            WHEN excluded.ended_at IS NULL THEN sessions.ended_at
            ELSE MAX(sessions.ended_at, excluded.ended_at)
          END,
          turn_count = MAX(sessions.turn_count, excluded.turn_count),
          user_turn_count = MAX(sessions.user_turn_count, excluded.user_turn_count),
          input_tokens = MAX(sessions.input_tokens, excluded.input_tokens),
          output_tokens = MAX(sessions.output_tokens, excluded.output_tokens),
          cached_tokens = MAX(sessions.cached_tokens, excluded.cached_tokens),
          cache_write_tokens = MAX(sessions.cache_write_tokens, excluded.cache_write_tokens),
          thinking_tokens = MAX(sessions.thinking_tokens, excluded.thinking_tokens),
          cost_usd = COALESCE(excluded.cost_usd, sessions.cost_usd),
          total_tool_ms = MAX(sessions.total_tool_ms, excluded.total_tool_ms),
          tool_wall_ms = MAX(sessions.tool_wall_ms, excluded.tool_wall_ms),
          api_duration_ms = MAX(sessions.api_duration_ms, excluded.api_duration_ms),
          api_retry_ms = MAX(sessions.api_retry_ms, excluded.api_retry_ms),
          thinking_duration_ms = MAX(sessions.thinking_duration_ms, excluded.thinking_duration_ms),
          ttft_ms_sum = MAX(sessions.ttft_ms_sum, excluded.ttft_ms_sum),
          ttft_count = MAX(sessions.ttft_count, excluded.ttft_count),
          compaction_count = MAX(sessions.compaction_count, excluded.compaction_count),
          aborted_turns = MAX(sessions.aborted_turns, excluded.aborted_turns),
          api_errors = MAX(sessions.api_errors, excluded.api_errors),
          outcome = COALESCE(excluded.outcome, sessions.outcome),
          parent_session_id = COALESCE(excluded.parent_session_id, sessions.parent_session_id),
          lines_added = MAX(sessions.lines_added, excluded.lines_added),
          lines_removed = MAX(sessions.lines_removed, excluded.lines_removed),
          max_context_tokens = MAX(sessions.max_context_tokens, excluded.max_context_tokens),
          context_window = COALESCE(excluded.context_window, sessions.context_window),
          effort = COALESCE(excluded.effort, sessions.effort),
          turn_origin = COALESCE(excluded.turn_origin, sessions.turn_origin),
          is_subagent = MAX(sessions.is_subagent, excluded.is_subagent),
          originator = COALESCE(excluded.originator, sessions.originator),
          subagent_kind = COALESCE(excluded.subagent_kind, sessions.subagent_kind),
          is_handoff = MAX(sessions.is_handoff, excluded.is_handoff),
          harness_version = COALESCE(excluded.harness_version, sessions.harness_version)",
        params![
            s.session_id,
            s.agent_kind,
            s.source_file,
            s.model,
            s.workspace_id,
            s.repo_id,
            s.repo_name,
            s.cwd,
            s.git_branch,
            s.started_at,
            s.ended_at,
            s.turn_count,
            s.user_turn_count,
            s.input_tokens,
            s.output_tokens,
            s.cached_tokens,
            s.cache_write_tokens,
            s.thinking_tokens,
            s.cost_usd,
            s.total_tool_ms,
            s.tool_wall_ms,
            s.api_duration_ms,
            s.api_retry_ms,
            s.thinking_duration_ms,
            s.ttft_ms_sum,
            s.ttft_count,
            s.compaction_count,
            s.aborted_turns,
            s.api_errors,
            s.outcome,
            s.parent_session_id,
            s.lines_added,
            s.lines_removed,
            s.max_context_tokens,
            s.context_window,
            s.effort,
            s.turn_origin,
            if s.is_subagent { 1 } else { 0 },
            s.originator,
            s.subagent_kind,
            if s.is_handoff { 1 } else { 0 },
            s.harness_version,
        ],
    )?;
    Ok(())
}

pub fn insert_command_span(conn: &Connection, sp: &CommandSpanRecord) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO command_spans (
          span_id, session_id, source_file, source_kind, agent_kind, tool_call_id,
          turn_idx, seq_idx, workspace_id, repo_id, repo_name, git_head, actor,
          category, is_repo_cli, surface_version, cmd_bin, cmd_template, raw_redacted,
          exit_code, duration_ms, stdout_bytes, stdout_tokens, stderr_bytes,
          stderr_preview, noise_kind, is_orientation, piped_filter, state_dir_hint,
          is_truncated, is_chained, is_long_duration, interrupted, started_at
        ) VALUES (
          ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
          ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30,
          ?31, ?32, ?33, ?34
        )",
        params![
            sp.span_id,
            sp.session_id,
            sp.source_file,
            sp.source_kind,
            sp.agent_kind,
            sp.tool_call_id,
            sp.turn_idx,
            sp.seq_idx,
            sp.workspace_id,
            sp.repo_id,
            sp.repo_name,
            sp.git_head,
            sp.actor,
            sp.category,
            if sp.is_repo_cli { 1 } else { 0 },
            sp.surface_version,
            sp.cmd_bin,
            sp.cmd_template,
            sp.raw_redacted,
            sp.exit_code,
            sp.duration_ms,
            sp.stdout_bytes,
            sp.stdout_tokens,
            sp.stderr_bytes,
            sp.stderr_preview,
            sp.noise_kind,
            if sp.is_orientation { 1 } else { 0 },
            sp.piped_filter,
            sp.state_dir_hint,
            if sp.is_truncated { 1 } else { 0 },
            if sp.is_chained { 1 } else { 0 },
            if sp.is_long_duration { 1 } else { 0 },
            if sp.interrupted { 1 } else { 0 },
            sp.started_at,
        ],
    )?;
    Ok(())
}

pub fn insert_file_read(conn: &Connection, r: &FileReadRecord) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO file_reads (
          read_id, session_id, source_file, repo_id, repo_name, turn_idx,
          target_name, target_path, is_doc, output_tokens, started_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            r.read_id,
            r.session_id,
            r.source_file,
            r.repo_id,
            r.repo_name,
            r.turn_idx,
            r.target_name,
            r.target_path,
            if r.is_doc { 1 } else { 0 },
            r.output_tokens,
            r.started_at,
        ],
    )?;
    Ok(())
}

pub fn insert_tool_call(conn: &Connection, tc: &ToolCallRecord) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO tool_calls (
          call_id, session_id, source_file, agent_kind, repo_id, repo_name, turn_idx,
          seq_idx, tool_call_id, tool_name, target_path, is_mcp, is_edit, is_error,
          interrupted, duration_ms, output_bytes, output_tokens, is_truncated,
          error_preview, started_at
        ) VALUES (
          ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
          ?17, ?18, ?19, ?20, ?21
        )",
        params![
            tc.call_id,
            tc.session_id,
            tc.source_file,
            tc.agent_kind,
            tc.repo_id,
            tc.repo_name,
            tc.turn_idx,
            tc.seq_idx,
            tc.tool_call_id,
            tc.tool_name,
            tc.target_path,
            if tc.is_mcp { 1 } else { 0 },
            if tc.is_edit { 1 } else { 0 },
            if tc.is_error { 1 } else { 0 },
            if tc.interrupted { 1 } else { 0 },
            tc.duration_ms,
            tc.output_bytes,
            tc.output_tokens,
            if tc.is_truncated { 1 } else { 0 },
            tc.error_preview,
            tc.started_at,
        ],
    )?;
    Ok(())
}

pub fn insert_llm_call(conn: &Connection, lc: &LlmCallRecord) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO llm_calls (
          call_id, session_id, source_file, agent_kind, repo_id, turn_idx, model,
          input_tokens, cache_read_tokens, cache_write_tokens, output_tokens,
          thinking_tokens, duration_ms, ttft_ms, thinking_ms, stop_reason,
          context_tokens, context_window, started_at
        ) VALUES (
          ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
          ?17, ?18, ?19
        )",
        params![
            lc.call_id,
            lc.session_id,
            lc.source_file,
            lc.agent_kind,
            lc.repo_id,
            lc.turn_idx,
            lc.model,
            lc.input_tokens,
            lc.cache_read_tokens,
            lc.cache_write_tokens,
            lc.output_tokens,
            lc.thinking_tokens,
            lc.duration_ms,
            lc.ttft_ms,
            lc.thinking_ms,
            lc.stop_reason,
            lc.context_tokens,
            lc.context_window,
            lc.started_at,
        ],
    )?;
    Ok(())
}

/// Harness names as stored in `agent_kind`.
pub const HARNESSES: [&str; 4] = ["claude-code", "codex", "antigravity", "kimi"];

/// Restrict every later query on this connection to one harness by shadowing the telemetry
/// tables with TEMP views (SQLite resolves unqualified names in `temp` before `main`).
/// Call it after syncing: the views are read-only.
pub fn apply_harness_filter(conn: &Connection, harness: &str) -> Result<()> {
    anyhow::ensure!(
        HARNESSES.contains(&harness),
        "unknown harness \"{harness}\" (expected one of: {})",
        HARNESSES.join(", ")
    );
    // `harness` is one of the fixed names above, so inlining it is safe (views can't bind params).
    let by_kind = |t: &str| {
        format!(
            "DROP VIEW IF EXISTS temp.{t};
             CREATE TEMP VIEW {t} AS SELECT * FROM main.{t} WHERE agent_kind = '{harness}';"
        )
    };
    let mut sql = String::new();
    for t in ["sessions", "command_spans", "tool_calls", "llm_calls"] {
        sql.push_str(&by_kind(t));
    }
    sql.push_str(&format!(
        "DROP VIEW IF EXISTS temp.file_reads;
         CREATE TEMP VIEW file_reads AS SELECT * FROM main.file_reads
           WHERE session_id IN (SELECT session_id FROM main.sessions WHERE agent_kind = '{harness}');"
    ));
    conn.execute_batch(&sql)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harness_filter_shadows_every_telemetry_table() {
        let dir = tempfile::tempdir().unwrap();
        let conn = open_db(&dir.path().join("ledger.db")).unwrap();
        for (sid, kind) in [("s-codex", "codex"), ("s-claude", "claude-code")] {
            conn.execute(
                "INSERT INTO sessions (session_id, agent_kind, source_file) VALUES (?1, ?2, 'f')",
                params![sid, kind],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO tool_calls (call_id, session_id, source_file, agent_kind, tool_name, started_at)
                 VALUES (?1, ?1, 'f', ?2, 't', 0)",
                params![sid, kind],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO file_reads (read_id, session_id, source_file, target_name, started_at)
                 VALUES (?1, ?1, 'f', 'x.rs', 0)",
                params![sid],
            )
            .unwrap();
        }
        let count = |t: &str| -> i64 {
            conn.query_row(&format!("SELECT COUNT(*) FROM {t}"), [], |r| r.get(0))
                .unwrap()
        };
        apply_harness_filter(&conn, "codex").unwrap();
        assert_eq!(count("sessions"), 1);
        assert_eq!(count("tool_calls"), 1);
        assert_eq!(count("file_reads"), 1);
        assert_eq!(count("main.sessions"), 2);
        // Re-applying switches harness instead of failing on the existing views.
        apply_harness_filter(&conn, "claude-code").unwrap();
        let sid: String = conn
            .query_row("SELECT session_id FROM sessions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(sid, "s-claude");
        assert!(apply_harness_filter(&conn, "x'; DROP TABLE sessions; --").is_err());
    }
}
