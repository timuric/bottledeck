use crate::adapters::{ParsedFile, antigravity, claude, codex, kimi, spans};
use crate::config::AdapterRoots;
use crate::db::{
    delete_records_for_source, insert_command_span, insert_file_read, insert_llm_call,
    insert_tool_call, upsert_session,
};
use crate::workspace::WorkspaceResolver;
use anyhow::Result;
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

#[derive(Debug, Default, Serialize)]
pub struct AdapterSyncStats {
    pub files_found: usize,
    pub ingested: usize,
    pub skipped: usize,
    pub spans: usize,
}

#[derive(Debug, Serialize)]
pub struct SyncError {
    pub file_path: String,
    pub adapter: String,
    pub error: String,
}

#[derive(Debug, Default, Serialize)]
pub struct SyncStats {
    pub files_scanned: usize,
    pub files_ingested: usize,
    pub files_skipped: usize,
    pub sessions_upserted: usize,
    pub spans_inserted: usize,
    pub file_reads_inserted: usize,
    pub tool_calls_inserted: usize,
    pub llm_calls_inserted: usize,
    pub by_adapter: BTreeMap<String, AdapterSyncStats>,
    pub errors: Vec<SyncError>,
    /// Every file was re-ingested (`--force`, or a parser upgrade).
    pub full_reparse: bool,
}

enum AdapterKind {
    Claude,
    Codex,
    Antigravity,
    Kimi,
    Spans,
}

impl AdapterKind {
    fn name(&self) -> &'static str {
        match self {
            Self::Claude => "claude-code",
            Self::Codex => "codex",
            Self::Antigravity => "antigravity",
            Self::Kimi => "kimi",
            Self::Spans => "wrap-spans",
        }
    }

    fn parse(&self, path: &Path, resolver: &mut WorkspaceResolver<'_>) -> Result<ParsedFile> {
        match self {
            Self::Claude => claude::parse_file(path, resolver),
            Self::Codex => codex::parse_file(path, resolver),
            Self::Antigravity => antigravity::parse_file(path, resolver),
            Self::Kimi => kimi::parse_file(path, resolver),
            Self::Spans => spans::parse_file(path, resolver),
        }
    }
}

fn discover_multi<F>(roots: &[PathBuf], f: F) -> Vec<PathBuf>
where
    F: Fn(&Path) -> Vec<PathBuf>,
{
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for root in roots {
        for p in f(root) {
            if seen.insert(p.clone()) {
                out.push(p);
            }
        }
    }
    out
}

/// Bump when adapters change how transcripts are parsed or classified. The next sync on a ledger
/// written by an older parser then re-ingests every file once (tracked in `PRAGMA user_version`).
/// 1: JSON tool results are judged by their error markers, not by error-sounding payload text.
pub const PARSER_VERSION: i64 = 1;

pub fn sync_all(conn: &mut Connection, roots: &AdapterRoots, force: bool) -> Result<SyncStats> {
    let ledger_parser: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    let has_data: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM ingest_files)", [], |r| {
        r.get(0)
    })?;
    let upgrade_reparse = !force && has_data && ledger_parser < PARSER_VERSION;
    if upgrade_reparse {
        eprintln!(
            "bottledeck: re-parsing all transcripts once for this version's parser changes (this sync is slower)..."
        );
    }
    let force = force || upgrade_reparse;
    let mut stats = sync_sources(conn, roots, force)?;
    stats.full_reparse = force;
    conn.execute_batch(&format!("PRAGMA user_version = {PARSER_VERSION}"))?;
    Ok(stats)
}

fn sync_sources(conn: &mut Connection, roots: &AdapterRoots, force: bool) -> Result<SyncStats> {
    let sources: Vec<(AdapterKind, Vec<PathBuf>)> = vec![
        (
            AdapterKind::Claude,
            discover_multi(&roots.claude, claude::discover_files),
        ),
        (
            AdapterKind::Codex,
            discover_multi(&roots.codex, codex::discover_files),
        ),
        (
            AdapterKind::Antigravity,
            discover_multi(&roots.antigravity, antigravity::discover_files),
        ),
        (
            AdapterKind::Kimi,
            discover_multi(&roots.kimi, kimi::discover_files),
        ),
        (
            AdapterKind::Spans,
            if roots.spans.exists() {
                vec![roots.spans.clone()]
            } else {
                Vec::new()
            },
        ),
    ];

    let mut stats = SyncStats::default();
    let mut discovered_paths: HashSet<String> = HashSet::new();
    // Reuse a single pre-seeded WorkspaceResolver across the whole sync to avoid spawning
    // repeated `git rev-parse` subprocesses on every file.
    let mut shared_resolver = WorkspaceResolver::new_detached(conn);

    for (adapter, files) in sources {
        let adapter_name = adapter.name().to_string();
        let entry = stats.by_adapter.entry(adapter_name.clone()).or_default();
        entry.files_found = files.len();

        for file_path in files {
            stats.files_scanned += 1;
            let path_str = file_path.to_string_lossy().to_string();
            discovered_paths.insert(path_str.clone());
            let Ok(meta) = fs::metadata(&file_path) else {
                continue;
            };
            let size_bytes = meta.len() as i64;
            let mut mtime_ms = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            // For Kimi sessions, also incorporate sibling `state.json` mtime so metadata updates trigger re-ingest.
            if matches!(adapter, AdapterKind::Kimi)
                && let Some(state_path) = file_path
                    .parent()
                    .and_then(Path::parent)
                    .and_then(Path::parent)
                    .map(|d| d.join("state.json"))
                && let Ok(sm) = fs::metadata(&state_path)
                && let Ok(st) = sm.modified()
                && let Ok(dur) = st.duration_since(UNIX_EPOCH)
            {
                mtime_ms = mtime_ms.max(dur.as_millis() as i64);
            }

            let prev: Option<(i64, i64)> = conn
                .query_row(
                    "SELECT size_bytes, mtime_ms FROM ingest_files WHERE file_path = ?1",
                    params![path_str],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;

            if !force && prev == Some((size_bytes, mtime_ms)) {
                stats.files_skipped += 1;
                stats.by_adapter.get_mut(&adapter_name).unwrap().skipped += 1;
                continue;
            }

            let parsed_res = adapter.parse(&file_path, &mut shared_resolver);

            match parsed_res {
                Ok(parsed) => {
                    let tx = conn.transaction()?;
                    shared_resolver.flush_pending(&tx);
                    delete_records_for_source(&tx, &path_str)?;
                    // When upgrading from compact `transcript.jsonl` to `transcript_full.jsonl`,
                    // purge any previously ingested records from the sibling compact file.
                    if file_path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .is_some_and(|n| n == "transcript_full.jsonl")
                    {
                        let sibling = file_path.with_file_name("transcript.jsonl");
                        let sibling_str = sibling.to_string_lossy().to_string();
                        delete_records_for_source(&tx, &sibling_str)?;
                        tx.execute(
                            "DELETE FROM ingest_files WHERE file_path = ?1",
                            params![sibling_str],
                        )?;
                    }
                    for s in &parsed.sessions {
                        upsert_session(&tx, s)?;
                        stats.sessions_upserted += 1;
                    }
                    for sp in &parsed.spans {
                        insert_command_span(&tx, sp)?;
                        stats.spans_inserted += 1;
                        stats.by_adapter.get_mut(&adapter_name).unwrap().spans += 1;
                    }
                    for r in &parsed.file_reads {
                        insert_file_read(&tx, r)?;
                        stats.file_reads_inserted += 1;
                    }
                    for tc in &parsed.tool_calls {
                        insert_tool_call(&tx, tc)?;
                        stats.tool_calls_inserted += 1;
                    }
                    for lc in &parsed.llm_calls {
                        insert_llm_call(&tx, lc)?;
                        stats.llm_calls_inserted += 1;
                    }
                    tx.execute(
                        "INSERT INTO ingest_files (file_path, adapter, size_bytes, mtime_ms, line_count, updated_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                         ON CONFLICT(file_path) DO UPDATE SET
                           adapter = excluded.adapter,
                           size_bytes = excluded.size_bytes,
                           mtime_ms = excluded.mtime_ms,
                           line_count = excluded.line_count,
                           updated_at = excluded.updated_at",
                        params![
                            path_str,
                            adapter_name,
                            size_bytes,
                            mtime_ms,
                            parsed.line_count,
                            Utc::now().timestamp_millis(),
                        ],
                    )?;
                    tx.commit()?;
                    stats.files_ingested += 1;
                    stats.by_adapter.get_mut(&adapter_name).unwrap().ingested += 1;
                }
                Err(err) => {
                    stats.errors.push(SyncError {
                        file_path: path_str,
                        adapter: adapter_name.clone(),
                        error: err.to_string(),
                    });
                }
            }
        }
    }

    shared_resolver.flush_pending(conn);
    prune_deleted_sources(conn, &discovered_paths)?;
    reconcile_workspaces_and_sessions(conn)?;
    Ok(stats)
}

/// Remove ledger records for transcript files that were deleted from disk or superseded
/// (for example compact `transcript.jsonl` replaced by sibling `transcript_full.jsonl`).
fn prune_deleted_sources(conn: &mut Connection, discovered: &HashSet<String>) -> Result<()> {
    let existing: Vec<String> = {
        let mut stmt = conn.prepare("SELECT file_path FROM ingest_files")?;
        stmt.query_map([], |r| r.get::<_, String>(0))?
            .flatten()
            .collect()
    };
    let stale: Vec<String> = existing
        .into_iter()
        .filter(|fp| {
            if discovered.contains(fp) {
                return false;
            }
            let p = Path::new(fp);
            if !p.exists() {
                return true;
            }
            // Superseded compact Antigravity log when full log is now discovered
            if fp.ends_with("/transcript.jsonl") {
                let full = fp.replace("/transcript.jsonl", "/transcript_full.jsonl");
                if discovered.contains(&full) {
                    return true;
                }
            }
            false
        })
        .collect();
    if stale.is_empty() {
        return Ok(());
    }
    let tx = conn.transaction()?;
    for fp in &stale {
        delete_records_for_source(&tx, fp)?;
        tx.execute("DELETE FROM ingest_files WHERE file_path = ?1", params![fp])?;
    }
    tx.commit()?;
    Ok(())
}

/// General post-sync reconciliation:
/// 1. Merge deleted/inferred worktree workspaces (e.g. `inferred/<repo>-<branch>` or `/worktrees/<repo>/*`)
///    into their canonical `repo_id` once any real checkout of `<repo>` has been discovered.
/// 2. Re-attribute sessions whose initial `cwd` was a neutral directory (`~`, `~/.t3`, `~/code`)
///    when their command spans predominantly target a single canonical repository.
fn reconcile_workspaces_and_sessions(conn: &mut Connection) -> Result<()> {
    use crate::workspace::{is_ephemeral_or_neutral_path, is_neutral_home_dir};
    use std::collections::HashMap;

    // 1. Collect all canonical repos from real git checkouts in `workspaces`
    let mut canonical_by_short: HashMap<String, (String, String)> = HashMap::new();
    {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT repo_id, repo_name FROM workspaces
             WHERE repo_id NOT LIKE 'inferred/%' AND repo_id NOT LIKE 'dir:%'",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows.flatten() {
            let (rid, rname) = row;
            let short = rname
                .rsplit('/')
                .next()
                .unwrap_or(&rname)
                .to_ascii_lowercase();
            if short.len() >= 3 {
                canonical_by_short.entry(short).or_insert((rid, rname));
            }
        }
    }

    if canonical_by_short.is_empty() {
        return Ok(());
    }

    // 2. Find inferred/dir workspaces that clearly match a canonical repo (longest short name first so
    //    `app-server` isn't hijacked by `app`).
    let mut canon_sorted: Vec<(&String, &(String, String))> = canonical_by_short.iter().collect();
    canon_sorted.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(b.0)));

    let mut remaps: Vec<(String, String, String)> = Vec::new(); // (old_repo_id, new_repo_id, new_repo_name)
    {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT repo_id, repo_name, worktree_path FROM workspaces
             WHERE repo_id LIKE 'inferred/%' OR repo_id LIKE 'dir:%'",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for row in rows.flatten() {
            let (old_id, old_name, wt_path) = row;
            let lower_path = wt_path.replace('\\', "/").to_ascii_lowercase();
            let lower_name = old_name.to_ascii_lowercase();
            for (short, (canon_id, canon_name)) in &canon_sorted {
                let matches_worktree = lower_path.contains(&format!("/worktrees/{short}/"))
                    || lower_name == **short
                    || (lower_path.contains("/worktrees/")
                        && (lower_path.contains(&format!("/{short}-"))
                            || lower_path.contains(&format!("/{short}_"))
                            || lower_name.starts_with(&format!("{short}-"))
                            || lower_name.starts_with(&format!("{short}_"))));
                if matches_worktree {
                    remaps.push((old_id.clone(), canon_id.clone(), canon_name.clone()));
                    break;
                }
            }
        }
    }

    let tx = conn.transaction()?;
    for (old_id, new_id, new_name) in &remaps {
        tx.execute(
            "UPDATE workspaces SET repo_id = ?1, repo_name = ?2 WHERE repo_id = ?3",
            params![new_id, new_name, old_id],
        )?;
        tx.execute(
            "UPDATE sessions SET repo_id = ?1, repo_name = ?2 WHERE repo_id = ?3",
            params![new_id, new_name, old_id],
        )?;
        tx.execute(
            "UPDATE command_spans SET repo_id = ?1, repo_name = ?2 WHERE repo_id = ?3",
            params![new_id, new_name, old_id],
        )?;
        tx.execute(
            "UPDATE file_reads SET repo_id = ?1, repo_name = ?2 WHERE repo_id = ?3",
            params![new_id, new_name, old_id],
        )?;
        tx.execute(
            "UPDATE tool_calls SET repo_id = ?1, repo_name = ?2 WHERE repo_id = ?3",
            params![new_id, new_name, old_id],
        )?;
        tx.execute(
            "UPDATE llm_calls SET repo_id = ?1 WHERE repo_id = ?2",
            params![new_id, old_id],
        )?;
    }

    // 2b. Reconcile unprefixed wrap `session_id`s to their canonical prefixed session row
    tx.execute(
        "UPDATE command_spans
         SET session_id = (
           SELECT s.session_id FROM sessions s
           WHERE s.session_id = 'claude:' || command_spans.session_id
              OR s.session_id = 'codex:' || command_spans.session_id
              OR s.session_id = 'antigravity:' || command_spans.session_id
              OR s.session_id = 'kimi:' || command_spans.session_id
           LIMIT 1
         )
         WHERE source_kind = 'wrap'
           AND session_id IS NOT NULL
           AND instr(session_id, ':') = 0
           AND EXISTS (
             SELECT 1 FROM sessions s
             WHERE s.session_id = 'claude:' || command_spans.session_id
                OR s.session_id = 'codex:' || command_spans.session_id
                OR s.session_id = 'antigravity:' || command_spans.session_id
                OR s.session_id = 'kimi:' || command_spans.session_id
           )",
        [],
    )?;

    // 3. Re-attribute neutral-cwd sessions (e.g. `~`, `~/.t3`) whose spans or raw commands clearly target one canonical repo
    let mut neutral_sessions: Vec<(String, Option<String>)> = Vec::new();
    {
        let mut stmt = tx.prepare(
            "SELECT session_id, cwd FROM sessions
             WHERE repo_id LIKE 'dir:%' OR repo_id IS NULL",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
        })?;
        for row in rows.flatten() {
            if row.1.is_none()
                || row
                    .1
                    .as_deref()
                    .is_some_and(|c| is_neutral_home_dir(c) || is_ephemeral_or_neutral_path(c))
            {
                neutral_sessions.push(row);
            }
        }
    }

    for (sid, _) in neutral_sessions {
        let mut dominant: Option<(String, String)> = tx
            .query_row(
                "SELECT repo_id, repo_name FROM command_spans
                 WHERE session_id = ?1 AND repo_id IS NOT NULL
                   AND repo_id NOT LIKE 'dir:%' AND repo_id NOT LIKE 'inferred/%'
                 GROUP BY repo_id, repo_name
                 ORDER BY COUNT(*) DESC
                 LIMIT 1",
                params![sid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;

        // Fallback: check file_reads or path mentions inside command_spans for neutral sessions
        if dominant.is_none() {
            dominant = tx
                .query_row(
                    "SELECT repo_id, repo_name FROM file_reads
                     WHERE session_id = ?1 AND repo_id IS NOT NULL
                       AND repo_id NOT LIKE 'dir:%' AND repo_id NOT LIKE 'inferred/%'
                     GROUP BY repo_id, repo_name
                     ORDER BY COUNT(*) DESC
                     LIMIT 1",
                    params![sid],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
        }

        if dominant.is_none() {
            let mut best: Option<((String, String), usize)> = None;
            for (short, (rid, rname)) in &canonical_by_short {
                let pat1 = format!("%/{short}/%");
                let pat2 = format!("%/{short}-%");
                let hits: i64 = tx
                    .query_row(
                        "SELECT COUNT(*) FROM command_spans
                         WHERE session_id = ?1 AND (lower(raw_redacted) LIKE ?2 OR lower(raw_redacted) LIKE ?3)",
                        params![sid, pat1, pat2],
                        |r| r.get::<_, i64>(0),
                    )
                    .unwrap_or(0);
                let hits = hits.max(0) as usize;
                if hits >= 2 && best.as_ref().is_none_or(|(_, c)| hits > *c) {
                    best = Some(((rid.clone(), rname.clone()), hits));
                }
            }
            dominant = best.map(|(pair, _)| pair);
        }

        if let Some((rid, rname)) = dominant {
            tx.execute(
                "UPDATE sessions SET repo_id = ?1, repo_name = ?2 WHERE session_id = ?3",
                params![rid, rname, sid],
            )?;
            tx.execute(
                "UPDATE command_spans SET repo_id = ?1, repo_name = ?2
                 WHERE session_id = ?3 AND (repo_id IS NULL OR repo_id LIKE 'dir:%')",
                params![rid, rname, sid],
            )?;
            tx.execute(
                "UPDATE tool_calls SET repo_id = ?1, repo_name = ?2
                 WHERE session_id = ?3 AND (repo_id IS NULL OR repo_id LIKE 'dir:%')",
                params![rid, rname, sid],
            )?;
            tx.execute(
                "UPDATE file_reads SET repo_id = ?1, repo_name = ?2
                 WHERE session_id = ?3 AND (repo_id IS NULL OR repo_id LIKE 'dir:%')",
                params![rid, rname, sid],
            )?;
        }
    }

    // 4. Backfill any tool_calls / file_reads whose repo_id was null when their session resolved to a repo
    tx.execute(
        "UPDATE tool_calls
         SET repo_id = (SELECT s.repo_id FROM sessions s WHERE s.session_id = tool_calls.session_id),
             repo_name = (SELECT s.repo_name FROM sessions s WHERE s.session_id = tool_calls.session_id)
         WHERE repo_id IS NULL
           AND EXISTS (SELECT 1 FROM sessions s WHERE s.session_id = tool_calls.session_id AND s.repo_id IS NOT NULL)",
        [],
    )?;
    tx.execute(
        "UPDATE file_reads
         SET repo_id = (SELECT s.repo_id FROM sessions s WHERE s.session_id = file_reads.session_id),
             repo_name = (SELECT s.repo_name FROM sessions s WHERE s.session_id = file_reads.session_id)
         WHERE repo_id IS NULL
           AND EXISTS (SELECT 1 FROM sessions s WHERE s.session_id = file_reads.session_id AND s.repo_id IS NOT NULL)",
        [],
    )?;
    tx.execute(
        "UPDATE llm_calls
         SET repo_id = (SELECT s.repo_id FROM sessions s WHERE s.session_id = llm_calls.session_id)
         WHERE repo_id IS NULL
           AND EXISTS (SELECT 1 FROM sessions s WHERE s.session_id = llm_calls.session_id AND s.repo_id IS NOT NULL)",
        [],
    )?;

    tx.commit()?;
    Ok(())
}
