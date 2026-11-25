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
  session_id      TEXT PRIMARY KEY,
  agent_kind      TEXT NOT NULL,
  source_file     TEXT NOT NULL,
  model           TEXT,
  workspace_id    TEXT,
  repo_id         TEXT,
  repo_name       TEXT,
  cwd             TEXT,
  git_branch      TEXT,
  started_at      INTEGER,
  ended_at        INTEGER,
  turn_count      INTEGER NOT NULL DEFAULT 0,
  input_tokens    INTEGER NOT NULL DEFAULT 0,
  output_tokens   INTEGER NOT NULL DEFAULT 0,
  cached_tokens   INTEGER NOT NULL DEFAULT 0,
  cost_usd        REAL,
  total_tool_ms   INTEGER NOT NULL DEFAULT 0,
  is_subagent     INTEGER NOT NULL DEFAULT 0,
  originator      TEXT,
  subagent_kind   TEXT,
  is_handoff      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS command_spans (
  span_id         TEXT PRIMARY KEY,
  session_id      TEXT,
  source_file     TEXT NOT NULL,
  source_kind     TEXT NOT NULL,
  agent_kind      TEXT,
  tool_call_id    TEXT,
  turn_idx        INTEGER NOT NULL DEFAULT 0,
  seq_idx         INTEGER NOT NULL DEFAULT 0,
  workspace_id    TEXT,
  repo_id         TEXT,
  repo_name       TEXT,
  git_head        TEXT,
  actor           TEXT NOT NULL DEFAULT 'agent',
  category        TEXT NOT NULL,
  is_repo_cli     INTEGER NOT NULL DEFAULT 0,
  surface_version TEXT,
  cmd_bin         TEXT NOT NULL,
  cmd_template    TEXT NOT NULL,
  raw_redacted    TEXT NOT NULL,
  exit_code       INTEGER,
  duration_ms     INTEGER,
  stdout_bytes    INTEGER NOT NULL DEFAULT 0,
  stdout_tokens   INTEGER NOT NULL DEFAULT 0,
  stderr_bytes    INTEGER NOT NULL DEFAULT 0,
  stderr_preview  TEXT,
  noise_kind      TEXT,
  is_orientation  INTEGER NOT NULL DEFAULT 0,
  piped_filter    TEXT,
  state_dir_hint  TEXT,
  is_truncated    INTEGER NOT NULL DEFAULT 0,
  started_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS file_reads (
  read_id        TEXT PRIMARY KEY,
  session_id     TEXT NOT NULL,
  source_file    TEXT NOT NULL,
  repo_id        TEXT,
  repo_name      TEXT,
  turn_idx       INTEGER NOT NULL DEFAULT 0,
  target_name    TEXT NOT NULL,
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
  tool_name      TEXT NOT NULL,
  is_mcp         INTEGER NOT NULL DEFAULT 0,
  is_error       INTEGER NOT NULL DEFAULT 0,
  duration_ms    INTEGER,
  output_bytes   INTEGER NOT NULL DEFAULT 0,
  output_tokens  INTEGER NOT NULL DEFAULT 0,
  is_truncated   INTEGER NOT NULL DEFAULT 0,
  error_preview  TEXT,
  started_at     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_repo_time ON sessions(repo_id, started_at);
CREATE INDEX IF NOT EXISTS idx_sessions_source ON sessions(source_file);
CREATE INDEX IF NOT EXISTS idx_spans_repo_time ON command_spans(repo_id, started_at);
CREATE INDEX IF NOT EXISTS idx_spans_session_seq ON command_spans(session_id, turn_idx, seq_idx);
CREATE INDEX IF NOT EXISTS idx_spans_source ON command_spans(source_file);
CREATE INDEX IF NOT EXISTS idx_reads_repo_time ON file_reads(repo_id, started_at);
CREATE INDEX IF NOT EXISTS idx_reads_source ON file_reads(source_file);
CREATE INDEX IF NOT EXISTS idx_tools_repo_time ON tool_calls(repo_id, started_at);
CREATE INDEX IF NOT EXISTS idx_tools_source ON tool_calls(source_file);
"#;

#[derive(Debug, Clone)]
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
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cached_tokens: i64,
    pub cost_usd: Option<f64>,
    pub total_tool_ms: i64,
    pub is_subagent: bool,
    pub originator: Option<String>,
    pub subagent_kind: Option<String>,
    pub is_handoff: bool,
}

#[derive(Debug, Clone)]
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
    pub started_at: i64,
}

#[derive(Debug, Clone)]
pub struct FileReadRecord {
    pub read_id: String,
    pub session_id: String,
    pub source_file: String,
    pub repo_id: Option<String>,
    pub repo_name: Option<String>,
    pub turn_idx: i64,
    pub target_name: String,
    pub is_doc: bool,
    pub output_tokens: i64,
    pub started_at: i64,
}

#[derive(Debug, Clone)]
pub struct ToolCallRecord {
    pub call_id: String,
    pub session_id: String,
    pub source_file: String,
    pub agent_kind: String,
    pub repo_id: Option<String>,
    pub repo_name: Option<String>,
    pub turn_idx: i64,
    pub tool_name: String,
    pub is_mcp: bool,
    pub is_error: bool,
    pub duration_ms: Option<i64>,
    pub output_bytes: i64,
    pub output_tokens: i64,
    pub is_truncated: bool,
    pub error_preview: Option<String>,
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
    let _ = conn.execute("ALTER TABLE command_spans ADD COLUMN piped_filter TEXT", []);
    let _ = conn.execute(
        "ALTER TABLE command_spans ADD COLUMN state_dir_hint TEXT",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE command_spans ADD COLUMN is_truncated INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE sessions ADD COLUMN is_subagent INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute("ALTER TABLE sessions ADD COLUMN originator TEXT", []);
    let _ = conn.execute("ALTER TABLE sessions ADD COLUMN subagent_kind TEXT", []);
    let _ = conn.execute(
        "ALTER TABLE sessions ADD COLUMN is_handoff INTEGER NOT NULL DEFAULT 0",
        [],
    );
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
        "DELETE FROM sessions WHERE source_file = ?1",
        params![source_file],
    )?;
    Ok(())
}

pub fn upsert_session(conn: &Connection, s: &SessionRecord) -> Result<()> {
    conn.execute(
        "INSERT INTO sessions (
          session_id, agent_kind, source_file, model, workspace_id, repo_id, repo_name,
          cwd, git_branch, started_at, ended_at, turn_count, input_tokens, output_tokens,
          cached_tokens, cost_usd, total_tool_ms, is_subagent, originator, subagent_kind, is_handoff
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)
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
          input_tokens = MAX(sessions.input_tokens, excluded.input_tokens),
          output_tokens = MAX(sessions.output_tokens, excluded.output_tokens),
          cached_tokens = MAX(sessions.cached_tokens, excluded.cached_tokens),
          cost_usd = COALESCE(excluded.cost_usd, sessions.cost_usd),
          total_tool_ms = MAX(sessions.total_tool_ms, excluded.total_tool_ms),
          is_subagent = MAX(sessions.is_subagent, excluded.is_subagent),
          originator = COALESCE(excluded.originator, sessions.originator),
          subagent_kind = COALESCE(excluded.subagent_kind, sessions.subagent_kind),
          is_handoff = MAX(sessions.is_handoff, excluded.is_handoff)",
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
            s.input_tokens,
            s.output_tokens,
            s.cached_tokens,
            s.cost_usd,
            s.total_tool_ms,
            if s.is_subagent { 1 } else { 0 },
            s.originator,
            s.subagent_kind,
            if s.is_handoff { 1 } else { 0 },
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
          stderr_preview, noise_kind, is_orientation, piped_filter, state_dir_hint, is_truncated, started_at
        ) VALUES (
          ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
          ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31
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
            sp.started_at,
        ],
    )?;
    Ok(())
}

pub fn insert_file_read(conn: &Connection, r: &FileReadRecord) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO file_reads (
          read_id, session_id, source_file, repo_id, repo_name, turn_idx,
          target_name, is_doc, output_tokens, started_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            r.read_id,
            r.session_id,
            r.source_file,
            r.repo_id,
            r.repo_name,
            r.turn_idx,
            r.target_name,
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
          tool_name, is_mcp, is_error, duration_ms, output_bytes, output_tokens,
          is_truncated, error_preview, started_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
            tc.call_id,
            tc.session_id,
            tc.source_file,
            tc.agent_kind,
            tc.repo_id,
            tc.repo_name,
            tc.turn_idx,
            tc.tool_name,
            if tc.is_mcp { 1 } else { 0 },
            if tc.is_error { 1 } else { 0 },
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
