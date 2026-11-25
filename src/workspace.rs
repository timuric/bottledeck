use chrono::Utc;
use regex::Regex;
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct WorkspaceInfo {
    pub workspace_id: String,
    pub repo_id: String,
    pub repo_name: String,
    pub worktree_path: String,
    pub git_common_dir: Option<String>,
    pub is_worktree: bool,
}

fn short_hash(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let hex = format!("{:x}", hasher.finalize());
    hex[..12].to_string()
}

pub fn normalize_remote_url(raw_url: &str) -> Option<String> {
    let mut u = raw_url.trim().to_string();
    if u.is_empty() {
        return None;
    }
    static CRED_RE: OnceLock<Regex> = OnceLock::new();
    let cred_re = CRED_RE.get_or_init(|| Regex::new(r"(?i)^(https?://)[^@\s]+@").unwrap());
    u = cred_re.replace(&u, "$1").into_owned();

    static SSH_RE: OnceLock<Regex> = OnceLock::new();
    let ssh_re = SSH_RE.get_or_init(|| Regex::new(r"^[^@]+@([^:]+):(.+)$").unwrap());
    if let Some(caps) = ssh_re.captures(&u) {
        u = format!("{}/{}", &caps[1], &caps[2]);
    } else {
        static PROTO_RE: OnceLock<Regex> = OnceLock::new();
        let proto_re =
            PROTO_RE.get_or_init(|| Regex::new(r"(?i)^(?:https?://|ssh://[^@]+@)").unwrap());
        u = proto_re.replace(&u, "").into_owned();
    }

    if u.to_ascii_lowercase().ends_with(".git") {
        u.truncate(u.len() - 4);
    }
    while u.ends_with('/') {
        u.pop();
    }
    Some(u.to_ascii_lowercase())
}

fn repo_name_from_canonical(canonical: &str) -> String {
    let parts: Vec<&str> = canonical.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() >= 2 {
        format!("{}/{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        parts.first().copied().unwrap_or(canonical).to_string()
    }
}

fn run_git(cwd: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn safe_realpath(p: &Path) -> PathBuf {
    fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

pub fn is_ephemeral_or_neutral_path(p: &str) -> bool {
    let norm = p.replace('\\', "/");
    let lower = norm.to_ascii_lowercase();
    if lower.starts_with("/tmp/")
        || lower.starts_with("/private/tmp/")
        || lower.starts_with("/var/folders/")
        || lower.starts_with("/private/var/folders/")
        || lower.contains("/antigravity-tmp/")
        || lower.contains("/.t3/scratch")
        || lower.contains("/.local/state/")
        || lower.contains("/.cache/")
        || lower.contains("/scratchpad")
    {
        return true;
    }
    let leaf = norm
        .split('/')
        .rev()
        .find(|s| !s.is_empty())
        .unwrap_or("")
        .to_ascii_lowercase();
    leaf.starts_with("tmp.") || leaf.starts_with(".tmp") || leaf == "empty" || leaf == "scratchpad"
}

pub fn is_neutral_home_dir(p: &str) -> bool {
    let norm = p.replace('\\', "/").trim_end_matches('/').to_string();
    if let Some(home) = dirs::home_dir() {
        let h = home
            .to_string_lossy()
            .replace('\\', "/")
            .trim_end_matches('/')
            .to_string();
        if norm == h || norm == format!("{h}/.t3") || norm == format!("{h}/code") {
            return true;
        }
    }
    false
}

fn short_repo_key(repo_name: &str) -> String {
    repo_name
        .rsplit('/')
        .next()
        .unwrap_or(repo_name)
        .to_ascii_lowercase()
}

fn infer_deleted_worktree_name(dir_path: &str, known_short_names: &[String]) -> String {
    let norm = dir_path.replace('\\', "/");
    static WT_RE: OnceLock<Regex> = OnceLock::new();
    let wt_re = WT_RE.get_or_init(|| Regex::new(r"/worktrees/([^/]+)/[^/]+(?:/.*)?$").unwrap());
    if let Some(caps) = wt_re.captures(&norm) {
        return caps[1].to_string();
    }

    let leaf = norm
        .split('/')
        .rev()
        .find(|s| !s.is_empty())
        .unwrap_or("unknown");
    let leaf_lower = leaf.to_ascii_lowercase();
    for base in known_short_names {
        if !base.is_empty() && (leaf_lower == *base || leaf_lower.starts_with(&format!("{base}-")))
        {
            return base.clone();
        }
    }
    leaf.to_string()
}

pub struct WorkspaceResolver<'a> {
    db: Option<&'a Connection>,
    cache: HashMap<String, WorkspaceInfo>,
    known_repos: HashMap<String, (String, String)>, // short_name -> (repo_id, repo_name)
}

impl<'a> WorkspaceResolver<'a> {
    pub fn new(db: Option<&'a Connection>) -> Self {
        let mut me = Self {
            db,
            cache: HashMap::new(),
            known_repos: HashMap::new(),
        };
        me.load_existing();
        me
    }

    fn load_existing(&mut self) {
        let Some(conn) = self.db else { return };
        let Ok(mut stmt) = conn.prepare(
            "SELECT workspace_id, repo_id, repo_name, worktree_path, git_common_dir, is_worktree FROM workspaces",
        ) else {
            return;
        };
        let Ok(rows) = stmt.query_map([], |r| {
            Ok(WorkspaceInfo {
                workspace_id: r.get(0)?,
                repo_id: r.get(1)?,
                repo_name: r.get(2)?,
                worktree_path: r.get(3)?,
                git_common_dir: r.get(4)?,
                is_worktree: r.get::<_, i64>(5)? != 0,
            })
        }) else {
            return;
        };

        for row in rows.flatten() {
            let key = short_repo_key(&row.repo_name);
            if !row.repo_id.starts_with("inferred/") {
                self.known_repos
                    .entry(key)
                    .or_insert_with(|| (row.repo_id.clone(), row.repo_name.clone()));
            }
            self.cache.insert(row.worktree_path.clone(), row);
        }
    }

    pub fn resolve(&mut self, raw_cwd: &str) -> Option<WorkspaceInfo> {
        let trimmed = raw_cwd.trim();
        if trimmed.is_empty() {
            return None;
        }
        let cwd_path = PathBuf::from(trimmed);
        let cwd_str = cwd_path.to_string_lossy().to_string();

        if let Some(hit) = self.cache.get(&cwd_str) {
            return Some(hit.clone());
        }

        // Subdirectory hit ONLY inside an already-cached real git worktree (never hijack under non-git dirs like `~` or `~/.t3`!)
        let best_wt = self
            .cache
            .iter()
            .filter(|(wt, info)| {
                !info.repo_id.starts_with("dir:")
                    && !info.repo_id.starts_with("inferred/")
                    && (cwd_str == **wt || cwd_str.starts_with(&format!("{wt}/")))
            })
            .max_by_key(|(wt, _)| wt.len())
            .map(|(_, info)| info.clone());
        if let Some(info) = best_wt {
            return Some(info);
        }

        let resolved = if cwd_path.exists() {
            if let Some(top_raw) = run_git(&cwd_path, &["rev-parse", "--show-toplevel"]) {
                let top_path = safe_realpath(Path::new(&top_raw));
                let top_str = top_path.to_string_lossy().to_string();
                if let Some(hit) = self.cache.get(&top_str) {
                    let cloned = hit.clone();
                    self.cache.insert(cwd_str, cloned.clone());
                    return Some(cloned);
                }

                let common_dir = run_git(&cwd_path, &["rev-parse", "--git-common-dir"]).map(|p| {
                    safe_realpath(&cwd_path.join(p))
                        .to_string_lossy()
                        .to_string()
                });
                let git_dir = run_git(&cwd_path, &["rev-parse", "--git-dir"]).map(|p| {
                    safe_realpath(&cwd_path.join(p))
                        .to_string_lossy()
                        .to_string()
                });
                let is_worktree = matches!((&common_dir, &git_dir), (Some(c), Some(g)) if c != g);

                let remote = run_git(&top_path, &["remote", "get-url", "origin"])
                    .and_then(|u| normalize_remote_url(&u));

                let (repo_id, repo_name) = if let Some(canon) = remote {
                    let name = repo_name_from_canonical(&canon);
                    (canon, name)
                } else {
                    let base = common_dir
                        .as_deref()
                        .and_then(|c| Path::new(c).parent())
                        .and_then(|p| p.file_name())
                        .or_else(|| top_path.file_name())
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_else(|| "repo".to_string());
                    let root_commit = run_git(&top_path, &["rev-list", "--max-parents=0", "HEAD"]);
                    let id = match root_commit {
                        Some(sha) => format!("local/{base}@{}", &sha[..sha.len().min(10)]),
                        None => format!(
                            "local/{base}:{}",
                            short_hash(common_dir.as_deref().unwrap_or(&top_str))
                        ),
                    };
                    (id, base)
                };

                WorkspaceInfo {
                    workspace_id: format!("ws_{}", short_hash(&top_str)),
                    repo_id,
                    repo_name,
                    worktree_path: top_str,
                    git_common_dir: common_dir,
                    is_worktree,
                }
            } else {
                let canon = safe_realpath(&cwd_path);
                let canon_str = canon.to_string_lossy().to_string();
                let name = canon
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| canon_str.clone());
                WorkspaceInfo {
                    workspace_id: format!("ws_{}", short_hash(&canon_str)),
                    repo_id: format!("dir:{canon_str}"),
                    repo_name: name,
                    worktree_path: canon_str,
                    git_common_dir: None,
                    is_worktree: false,
                }
            }
        } else {
            let known_keys: Vec<String> = self.known_repos.keys().cloned().collect();
            let inferred = infer_deleted_worktree_name(&cwd_str, &known_keys);
            let key = short_repo_key(&inferred);
            let (repo_id, repo_name) = if let Some((rid, rname)) = self.known_repos.get(&key) {
                (rid.clone(), rname.clone())
            } else {
                (format!("inferred/{key}"), inferred)
            };
            WorkspaceInfo {
                workspace_id: format!("ws_{}", short_hash(&cwd_str)),
                repo_id,
                repo_name,
                worktree_path: cwd_str.clone(),
                git_common_dir: None,
                is_worktree: cwd_str.contains("/worktrees/"),
            }
        };

        if let Some(conn) = self.db {
            let _ = conn.execute(
                "INSERT INTO workspaces (
                  workspace_id, repo_id, repo_name, worktree_path, git_common_dir, is_worktree, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                ON CONFLICT(worktree_path) DO UPDATE SET
                  repo_id = excluded.repo_id,
                  repo_name = excluded.repo_name,
                  git_common_dir = COALESCE(excluded.git_common_dir, workspaces.git_common_dir),
                  is_worktree = excluded.is_worktree,
                  updated_at = excluded.updated_at",
                params![
                    resolved.workspace_id,
                    resolved.repo_id,
                    resolved.repo_name,
                    resolved.worktree_path,
                    resolved.git_common_dir,
                    if resolved.is_worktree { 1 } else { 0 },
                    Utc::now().timestamp_millis(),
                ],
            );
        }

        if !resolved.repo_id.starts_with("inferred/") {
            let key = short_repo_key(&resolved.repo_name);
            self.known_repos
                .entry(key)
                .or_insert_with(|| (resolved.repo_id.clone(), resolved.repo_name.clone()));
        }
        self.cache
            .insert(resolved.worktree_path.clone(), resolved.clone());
        self.cache.insert(cwd_str, resolved.clone());

        Some(resolved)
    }
}
