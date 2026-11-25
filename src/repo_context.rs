use regex::Regex;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

#[derive(Debug, Clone, Default)]
pub struct RepoContext {
    pub checkout_path: Option<String>,
    pub task_runner: Option<String>,
    pub config_files: Vec<String>,
    pub has_agents_md: bool,
    pub has_claude_md: bool,
    pub defined_tasks: Vec<String>,
    pub mentioned_tools: Vec<String>,
    pub branch_behind_notice: Option<String>,
}

fn parse_mise_tasks(content: &str) -> Vec<String> {
    static TASK_RE: OnceLock<Regex> = OnceLock::new();
    let re = TASK_RE.get_or_init(|| {
        Regex::new(r#"(?m)^\s*\[tasks\.(?:"([^"]+)"|'([^']+)'|([A-Za-z0-9:_-]+))\]"#).unwrap()
    });
    let mut set = BTreeSet::new();
    for caps in re.captures_iter(content) {
        if let Some(m) = caps.get(1).or_else(|| caps.get(2)).or_else(|| caps.get(3)) {
            set.insert(m.as_str().to_string());
        }
    }
    set.into_iter().collect()
}

fn parse_doc_mentioned_tools(content: &str) -> Vec<String> {
    // Generic extraction of backticked snake_case tool names (e.g. `foo_bar`, `mcp_tool_name`)
    // mentioned in AGENTS.md / CLAUDE.md
    static TOOL_RE: OnceLock<Regex> = OnceLock::new();
    let re = TOOL_RE.get_or_init(|| Regex::new(r"`([a-z][a-z0-9]*(?:_[a-z0-9]+)+)`").unwrap());
    let mut set = BTreeSet::new();
    for caps in re.captures_iter(content) {
        let tok = &caps[1];
        if tok.len() >= 6
            && !tok.starts_with("git_")
            && !tok.starts_with("node_")
            && !tok.ends_with("_md")
            && !tok.ends_with("_rs")
            && !tok.ends_with("_ts")
            && !tok.ends_with("_js")
            && !tok.ends_with("_mjs")
            && !tok.ends_with("_json")
            && !tok.ends_with("_toml")
        {
            set.insert(tok.to_string());
        }
    }
    set.into_iter().collect()
}

fn check_branch_behind_notice(dir: &Path) -> Option<String> {
    let branch_out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()?;
    if !branch_out.status.success() {
        return None;
    }
    let branch = String::from_utf8_lossy(&branch_out.stdout)
        .trim()
        .to_string();
    for default_ref in ["origin/main", "origin/master"] {
        let rev_out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["rev-list", "--count", &format!("HEAD..{default_ref}")])
            .output()
            .ok()?;
        if rev_out.status.success() {
            let behind: usize = String::from_utf8_lossy(&rev_out.stdout)
                .trim()
                .parse()
                .unwrap_or(0);
            if behind > 0 {
                return Some(format!(
                    "Local checkout `{}` is on branch `{branch}`, {behind} commit(s) behind `{default_ref}` (verify root causes against `{default_ref}`).",
                    dir.display()
                ));
            }
            return None;
        }
    }
    None
}

impl RepoContext {
    pub fn discover(worktree_paths: &[String]) -> Self {
        let Some(root) = worktree_paths.iter().find(|p| {
            Path::new(p).is_dir() && !p.contains("/tmp/") && !p.contains("/var/folders/")
        }) else {
            return Self::default();
        };

        let dir = Path::new(root);
        let mut config_files = Vec::new();
        let mut task_runner = None;

        let checks = [
            ("mise.toml", Some("mise")),
            (".mise.toml", Some("mise")),
            ("justfile", Some("just")),
            ("Makefile", Some("make")),
            ("package.json", Some("npm/pnpm")),
            ("Cargo.toml", Some("cargo")),
            ("pyproject.toml", Some("python")),
        ];

        for (file, runner) in checks {
            if dir.join(file).exists() {
                config_files.push(file.to_string());
                if task_runner.is_none()
                    && let Some(r) = runner
                {
                    task_runner = Some(r.to_string());
                }
            }
        }

        let has_agents_md = dir.join("AGENTS.md").exists();
        let has_claude_md = dir.join("CLAUDE.md").exists();
        if has_agents_md {
            config_files.push("AGENTS.md".to_string());
        }
        if has_claude_md {
            config_files.push("CLAUDE.md".to_string());
        }

        // Check if scripts/ directory exists
        if dir.join("scripts").is_dir()
            && fs::read_dir(dir.join("scripts"))
                .ok()
                .and_then(|mut d| d.next())
                .is_some()
        {
            config_files.push("scripts/".to_string());
        }

        let mut defined_tasks = Vec::new();
        for fname in ["mise.toml", ".mise.toml"] {
            if let Ok(text) = fs::read_to_string(dir.join(fname)) {
                defined_tasks.extend(parse_mise_tasks(&text));
            }
        }
        let mut mentioned_tools = Vec::new();
        for doc_name in ["AGENTS.md", "CLAUDE.md"] {
            if let Ok(text) = fs::read_to_string(dir.join(doc_name)) {
                mentioned_tools.extend(parse_doc_mentioned_tools(&text));
            }
        }
        let branch_behind_notice = check_branch_behind_notice(dir);

        Self {
            checkout_path: Some(root.clone()),
            task_runner,
            config_files,
            has_agents_md,
            has_claude_md,
            defined_tasks,
            mentioned_tools,
            branch_behind_notice,
        }
    }

    pub fn task_fix_target(&self) -> String {
        if self
            .config_files
            .iter()
            .any(|f| f == "mise.toml" || f == ".mise.toml")
        {
            if self.config_files.iter().any(|f| f == "scripts/") {
                return "mise.toml + scripts/".to_string();
            }
            return "mise.toml".to_string();
        }
        if self.config_files.iter().any(|f| f == "package.json") {
            return "package.json scripts".to_string();
        }
        if self.config_files.iter().any(|f| f == "Makefile") {
            return "Makefile".to_string();
        }
        if self.config_files.iter().any(|f| f == "justfile") {
            return "justfile".to_string();
        }
        if self.config_files.iter().any(|f| f == "scripts/") {
            return "scripts/".to_string();
        }
        "repo task runner / scripts".to_string()
    }

    pub fn docs_fix_target(&self) -> String {
        if self.has_agents_md {
            "AGENTS.md".to_string()
        } else if self.has_claude_md {
            "CLAUDE.md".to_string()
        } else {
            "AGENTS.md / README.md".to_string()
        }
    }
}
