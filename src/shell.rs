use regex::Regex;
use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

pub fn redact_secrets(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    static PATTERNS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| {
        vec![
            (
                Regex::new(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}").unwrap(),
                "$1 <redacted>",
            ),
            (
                Regex::new(r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{16,}|xox[baprs]-[A-Za-z0-9-]{12,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,})\b").unwrap(),
                "<redacted_key>",
            ),
            (
                Regex::new(r"(?i)(https?://)([^:@\s/]+):([^@\s/]+)@").unwrap(),
                "$1<user>:<redacted>@",
            ),
            (
                Regex::new(r#"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|AUTH|COOKIE|CREDENTIAL)[A-Z0-9_]*)=("[^"]*"|'[^']*'|[^\s;&|]+)"#).unwrap(),
                "$1=<redacted>",
            ),
            (
                Regex::new(r#"(?i)(--?(?:token|api-key|apikey|secret|password|passwd|auth|bearer)(?:=|\s+))("[^"]*"|'[^']*'|[^\s;&|]+)"#).unwrap(),
                "$1<redacted>",
            ),
        ]
    });

    let mut out = text.to_string();
    for (re, rep) in patterns {
        out = re.replace_all(&out, *rep).into_owned();
    }
    out
}

#[derive(Debug, Clone)]
pub struct ShellSegment {
    pub raw: String,
    pub tokens: Vec<String>,
    pub cd_hint: Option<String>,
    pub is_pipe_consumer: bool,
    pub piped_filter: Option<String>,
    pub separator: String,
}

#[derive(Debug, Clone)]
pub struct ParsedCommand {
    pub cmd_bin: String,
    pub cmd_template: String,
    pub category: &'static str,
    pub is_repo_cli: bool,
    pub is_orientation: bool,
    pub raw_redacted: String,
}

pub fn tokenize_shell(segment: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for ch in segment.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else {
                cur.push(ch);
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            continue;
        }
        if ch.is_whitespace() {
            if !cur.is_empty() {
                tokens.push(std::mem::take(&mut cur));
            }
            continue;
        }
        cur.push(ch);
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

fn strip_heredocs(input: &str) -> String {
    static HEREDOC_RE: OnceLock<Regex> = OnceLock::new();
    let re = HEREDOC_RE.get_or_init(|| Regex::new(r#"<<-?\s*['"]?([A-Za-z0-9_]+)['"]?"#).unwrap());

    let mut out = Vec::new();
    let mut end_marker: Option<String> = None;

    for line in input.lines() {
        if let Some(marker) = &end_marker {
            if line.trim() == marker.as_str() {
                end_marker = None;
            }
            continue;
        }
        out.push(line);
        if let Some(caps) = re.captures(line) {
            end_marker = Some(caps[1].to_string());
        }
    }
    out.join("\n")
}

pub fn split_shell_commands(command_line: &str) -> Vec<ShellSegment> {
    if command_line.trim().is_empty() {
        return Vec::new();
    }

    // Strip heredoc bodies before splitting so inline python/node/sql/applescript isn't parsed as commands
    let cleaned_lines = strip_heredocs(command_line);
    let chars: Vec<char> = cleaned_lines.chars().collect();
    let mut raw_segs: Vec<(String, String)> = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut paren_depth = 0usize;

    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        let next = chars.get(i + 1).copied();

        if escaped {
            cur.push(ch);
            escaped = false;
            i += 1;
            continue;
        }
        if ch == '\\' && quote != Some('\'') {
            cur.push(ch);
            escaped = true;
            i += 1;
            continue;
        }
        if let Some(q) = quote {
            cur.push(ch);
            if ch == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            cur.push(ch);
            i += 1;
            continue;
        }
        if ch == '(' {
            paren_depth += 1;
            cur.push(ch);
            i += 1;
            continue;
        }
        if ch == ')' && paren_depth > 0 {
            paren_depth -= 1;
            cur.push(ch);
            i += 1;
            continue;
        }

        if paren_depth == 0 {
            if (ch == '&' && next == Some('&')) || (ch == '|' && next == Some('|')) {
                let trimmed = cur.trim().to_string();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    raw_segs.push((trimmed, format!("{ch}{ch}")));
                }
                cur.clear();
                i += 2;
                continue;
            }
            if ch == ';' || ch == '\n' {
                let trimmed = cur.trim().to_string();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    raw_segs.push((trimmed, ch.to_string()));
                }
                cur.clear();
                i += 1;
                continue;
            }
            if ch == '&' && next != Some('&') && next != Some('>') && !cur.ends_with('>') {
                let trimmed = cur.trim().to_string();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    raw_segs.push((trimmed, "&".to_string()));
                }
                cur.clear();
                i += 1;
                continue;
            }
            if ch == '|' && next != Some('|') {
                let trimmed = cur.trim().to_string();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    raw_segs.push((trimmed, "|".to_string()));
                }
                cur.clear();
                i += 1;
                continue;
            }
        }

        cur.push(ch);
        i += 1;
    }

    let trimmed = cur.trim().to_string();
    if !trimmed.is_empty() && !trimmed.starts_with('#') {
        raw_segs.push((trimmed, String::new()));
    }

    static ENV_RE: OnceLock<Regex> = OnceLock::new();
    let env_re = ENV_RE.get_or_init(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*=").unwrap());

    let mut out = Vec::new();
    let mut active_dir: Option<String> = None;

    for (idx, (raw, sep)) in raw_segs.iter().enumerate() {
        let mut tokens = tokenize_shell(raw);
        // Strip leading shell control-flow keywords (`do`, `then`, `else`, `elif`) so loop/conditional
        // bodies like `for f in ...; do cargo test; done` are preserved rather than discarded.
        while let Some(first) = tokens.first() {
            if matches!(first.as_str(), "do" | "then" | "else" | "elif" | "{" | "!") {
                tokens.remove(0);
            } else {
                break;
            }
        }
        while let Some(last) = tokens.last() {
            if matches!(last.as_str(), "done" | "fi" | "}") {
                tokens.pop();
            } else {
                break;
            }
        }
        if tokens.is_empty() {
            continue;
        }
        if tokens[0] == "cd" {
            if let Some(dir) = tokens.get(1)
                && !dir.starts_with('-')
            {
                active_dir = Some(dir.clone());
            }
            continue;
        }
        if tokens.iter().all(|t| env_re.is_match(t)) {
            continue;
        }
        if matches!(
            tokens[0].as_str(),
            "if" | "fi" | "for" | "done" | "while" | "until" | "case" | "esac" | "{" | "}"
        ) {
            continue;
        }

        let is_pipe_consumer = idx > 0 && raw_segs[idx - 1].1 == "|";
        let piped_filter = if raw_segs[idx].1 == "|"
            && let Some((next_raw, _)) = raw_segs.get(idx + 1)
        {
            let next_toks = tokenize_shell(next_raw);
            next_toks.first().map(|b| {
                let bin = Path::new(b)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(b.as_str());
                if let Some(flag) = next_toks.get(1).filter(|f| f.starts_with('-')) {
                    format!("{bin} {flag}")
                } else {
                    bin.to_string()
                }
            })
        } else {
            None
        };
        out.push(ShellSegment {
            raw: raw.clone(),
            tokens,
            cd_hint: active_dir.clone(),
            is_pipe_consumer,
            piped_filter,
            separator: sep.clone(),
        });
    }

    out
}

fn is_redirection(tok: &str) -> bool {
    static REDIR_RE: OnceLock<Regex> = OnceLock::new();
    let re = REDIR_RE.get_or_init(|| Regex::new(r"^(?:\d?>&?\d?|\d?>>|\d?<|&>)").unwrap());
    re.is_match(tok)
}

fn is_separate_redir(tok: &str) -> bool {
    static SEP_RE: OnceLock<Regex> = OnceLock::new();
    let re = SEP_RE.get_or_init(|| Regex::new(r"^(?:\d?>|\d?>>|\d?<|&>)$").unwrap());
    re.is_match(tok)
}

fn normalize_arg(tok: &str) -> String {
    if tok.starts_with("http://") || tok.starts_with("https://") {
        return "<url>".to_string();
    }
    if (7..=40).contains(&tok.len()) && tok.chars().all(|c| c.is_ascii_hexdigit()) {
        return "<sha>".to_string();
    }
    if tok.chars().all(|c| c.is_ascii_digit()) {
        return "<num>".to_string();
    }
    // Keep recognizable script filenames (e.g. `scripts/deploy.sh` -> `deploy.sh`) so distinct scripts
    // don't all collapse into `python3 <path>` or `node <path>`.
    let lower = tok.to_ascii_lowercase();
    let is_script = lower.ends_with(".py")
        || lower.ends_with(".sh")
        || lower.ends_with(".mjs")
        || lower.ends_with(".cjs")
        || lower.ends_with(".js")
        || lower.ends_with(".ts")
        || lower.ends_with(".rb")
        || lower.ends_with(".pl")
        || lower.ends_with(".sql");
    if is_script
        && let Some(base) = Path::new(tok).file_name().and_then(|s| s.to_str())
        && !base.is_empty()
        && base.len() <= 40
    {
        return base.to_string();
    }
    if tok.contains('/') || tok.contains('.') {
        return "<path>".to_string();
    }
    if tok.len() > 32 {
        return "<str>".to_string();
    }
    tok.to_string()
}

pub fn parse_command_tokens(raw_tokens: &[String], raw_text: &str) -> Option<ParsedCommand> {
    static ENV_RE: OnceLock<Regex> = OnceLock::new();
    let env_re = ENV_RE.get_or_init(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*=").unwrap());

    // Unwrap `bash -c "..."` / `sh -c "..."` / `zsh -c "..."` into the inner command tokens
    let unwrapped_owned: Vec<String>;
    let raw_tokens: &[String] = if raw_tokens.len() >= 3 {
        let b0 = Path::new(&raw_tokens[0])
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(raw_tokens[0].as_str());
        if matches!(b0, "bash" | "sh" | "zsh") {
            if let Some(c_pos) = raw_tokens
                .iter()
                .skip(1)
                .position(|t| t == "-c" || t == "-lc" || t == "-ec" || t == "-euo")
            {
                let inner_idx = if raw_tokens[1 + c_pos] == "-euo" {
                    1 + c_pos + 3
                } else {
                    1 + c_pos + 1
                };
                if let Some(inner_cmd) = raw_tokens.get(inner_idx) {
                    let inner_segs = split_shell_commands(inner_cmd);
                    if let Some(first) = inner_segs.into_iter().next()
                        && !first.tokens.is_empty()
                    {
                        unwrapped_owned = first.tokens;
                        &unwrapped_owned
                    } else {
                        raw_tokens
                    }
                } else {
                    raw_tokens
                }
            } else {
                raw_tokens
            }
        } else {
            raw_tokens
        }
    } else {
        raw_tokens
    };

    let mut idx = 0usize;
    while idx < raw_tokens.len() {
        let t = &raw_tokens[idx];
        if env_re.is_match(t) {
            idx += 1;
            continue;
        }
        let base = Path::new(t)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(t.as_str());
        if matches!(
            base,
            "env" | "command" | "time" | "nice" | "nohup" | "sudo" | "exec" | "xargs"
        ) {
            idx += 1;
            while idx < raw_tokens.len() && raw_tokens[idx].starts_with('-') {
                if matches!(
                    raw_tokens[idx].as_str(),
                    "-u" | "-g" | "-I" | "-n" | "-P" | "-L"
                ) {
                    idx += 2;
                } else {
                    idx += 1;
                }
            }
            continue;
        }
        if base == "timeout" {
            idx += 1;
            while idx < raw_tokens.len() && raw_tokens[idx].starts_with('-') {
                if matches!(
                    raw_tokens[idx].as_str(),
                    "-s" | "-k" | "--signal" | "--kill-after"
                ) {
                    idx += 2;
                } else {
                    idx += 1;
                }
            }
            // Skip duration token (e.g. `10`, `30s`, `5m`)
            if idx < raw_tokens.len() {
                idx += 1;
            }
            continue;
        }
        break;
    }

    let mut tokens = Vec::new();
    let mut i = idx;
    while i < raw_tokens.len() {
        let t = &raw_tokens[i];
        if is_redirection(t) {
            if is_separate_redir(t) {
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        tokens.push(t.clone());
        i += 1;
    }

    if tokens.is_empty() {
        return None;
    }

    let raw_bin = &tokens[0];
    let cmd_bin = Path::new(raw_bin)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(raw_bin.as_str())
        .to_string();

    // Reject obvious non-command tokens (inline JS/Python/AppleScript leaked from multiline strings)
    if cmd_bin.is_empty()
        || cmd_bin.chars().any(|c| {
            matches!(
                c,
                '(' | ')' | '{' | '}' | '[' | ']' | '=' | ',' | ';' | '"' | '\'' | '`' | '<' | '>'
            )
        })
        || matches!(
            cmd_bin.as_str(),
            "const"
                | "let"
                | "var"
                | "function"
                | "async"
                | "await"
                | "return"
                | "import"
                | "export"
                | "class"
                | "try"
                | "catch"
                | "finally"
                | "throw"
                | "new"
                | "def"
                | "from"
                | "with"
                | "as"
                | "pass"
                | "break"
                | "continue"
                | "end"
                | "tell"
                | "repeat"
                | "set"
                | "true"
                | "false"
                | "null"
                | "undefined"
                | "echo"
                | "printf"
        )
    {
        return None;
    }

    let args = &tokens[1..];

    let is_local_script =
        raw_bin.starts_with("./") || raw_bin.contains("/scripts/") || raw_bin.contains("/bin/");
    let is_repo_task_bin = matches!(
        cmd_bin.as_str(),
        "mise" | "make" | "just" | "task" | "mage" | "rake" | "invoke" | "buck" | "bazel"
    );
    let is_js_runner = matches!(
        cmd_bin.as_str(),
        "npm" | "pnpm" | "yarn" | "bun" | "npx" | "pnpx" | "bunx"
    );
    let is_repo_cli = is_repo_task_bin
        || is_local_script
        || (is_js_runner
            && args
                .first()
                .is_some_and(|a| matches!(a.as_str(), "run" | "test" | "build" | "lint")));

    let is_subcmd_bin = matches!(
        cmd_bin.as_str(),
        "git"
            | "gh"
            | "jj"
            | "cargo"
            | "docker"
            | "kubectl"
            | "mise"
            | "npm"
            | "pnpm"
            | "yarn"
            | "bun"
            | "go"
            | "swift"
            | "uv"
            | "pip"
            | "poetry"
            | "terraform"
            | "aws"
            | "gcloud"
            | "flyctl"
            | "systemctl"
            | "journalctl"
            | "xcrun"
            | "brew"
            | "bottledeck"
            | "agent-pulse"
    );

    let mut template_parts = vec![if is_local_script {
        format!("./{cmd_bin}")
    } else {
        cmd_bin.clone()
    }];

    // Semantic unwrapping for common wrappers so metrics attribute to the real operation:
    // 1. `mise run job -- run --name <NAME> -- <inner>` -> `mise job:<NAME>` (or inner cmd)
    // 2. `mise run verify -- --scope <SCOPE>` -> `mise run verify --scope=<SCOPE>`
    // 3. `ssh <host> "<remote cmd>"` -> `ssh <host> <remote_bin>`
    if cmd_bin == "mise"
        && args.first().is_some_and(|a| a == "run" || a == "r")
        && let Some(task_name) = args.get(1)
    {
        if task_name == "job" {
            let mut job_action = None;
            let mut job_name = None;
            let mut inner_cmd = None;
            let mut k = 2usize;
            let mut dd_count = 0usize;
            while k < args.len() {
                if args[k] == "--" {
                    dd_count += 1;
                    if dd_count == 2 && k + 1 < args.len() {
                        inner_cmd = Some(args[k + 1].clone());
                        break;
                    }
                    k += 1;
                    continue;
                }
                if job_action.is_none() && !args[k].starts_with('-') {
                    job_action = Some(args[k].clone());
                } else if args[k] == "--name" && k + 1 < args.len() {
                    job_name = Some(args[k + 1].clone());
                    k += 2;
                    continue;
                } else if let Some(val) = args[k].strip_prefix("--name=") {
                    job_name = Some(val.to_string());
                }
                k += 1;
            }
            let action = job_action.unwrap_or_else(|| "run".to_string());
            let label = if let Some(name) = job_name {
                format!("mise job:{action}:{name}")
            } else if let Some(inner) = inner_cmd {
                format!(
                    "mise job:{action}:{}",
                    Path::new(&inner)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or(&inner)
                )
            } else {
                format!("mise run job {action}")
            };
            let mut raw_redacted = redact_secrets(raw_text);
            if raw_redacted.len() > 400 {
                raw_redacted = raw_redacted.chars().take(400).collect();
            }
            return Some(ParsedCommand {
                cmd_bin,
                cmd_template: label,
                category: if action == "wait" || action == "status" {
                    "polling"
                } else {
                    "repo_task"
                },
                is_repo_cli: true,
                is_orientation: false,
                raw_redacted,
            });
        }

        if task_name == "verify" {
            let mut scope_val = None;
            for k in 2..args.len() {
                if (args[k] == "--scope" || args[k] == "--task") && k + 1 < args.len() {
                    scope_val = Some(format!("{}={}", args[k], args[k + 1]));
                    break;
                }
                if args[k].starts_with("--scope=") || args[k].starts_with("--task=") {
                    scope_val = Some(args[k].clone());
                    break;
                }
            }
            let label = match scope_val {
                Some(s) => format!("mise run verify {s}"),
                None => "mise run verify".to_string(),
            };
            let mut raw_redacted = redact_secrets(raw_text);
            if raw_redacted.len() > 400 {
                raw_redacted = raw_redacted.chars().take(400).collect();
            }
            return Some(ParsedCommand {
                cmd_bin,
                cmd_template: label,
                category: "repo_task",
                is_repo_cli: true,
                is_orientation: false,
                raw_redacted,
            });
        }
    }

    if cmd_bin == "ssh" {
        let mut pos: Vec<&String> = Vec::new();
        let mut k = 0usize;
        while k < args.len() {
            let a = &args[k];
            if a.starts_with('-') {
                // Skip ssh flags that take a separate argument value
                if matches!(
                    a.as_str(),
                    "-o" | "-i"
                        | "-p"
                        | "-l"
                        | "-F"
                        | "-J"
                        | "-W"
                        | "-L"
                        | "-R"
                        | "-D"
                        | "-b"
                        | "-c"
                        | "-E"
                        | "-m"
                        | "-O"
                        | "-S"
                        | "-w"
                ) {
                    k += 2;
                } else {
                    k += 1;
                }
                continue;
            }
            pos.push(a);
            k += 1;
        }
        if pos.len() >= 2 {
            let host = pos[0];
            let remote_cmd_str = pos[1..]
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            let remote_tokens = tokenize_shell(&remote_cmd_str);
            // Skip leading env assignments or `sudo [-n] [-u user]` on the remote side to find the real remote binary
            let mut ridx = 0usize;
            while ridx < remote_tokens.len() {
                let rt = &remote_tokens[ridx];
                if rt.contains('=') && !rt.starts_with('-') {
                    ridx += 1;
                    continue;
                }
                if rt == "sudo" {
                    ridx += 1;
                    while ridx < remote_tokens.len() && remote_tokens[ridx].starts_with('-') {
                        if matches!(remote_tokens[ridx].as_str(), "-u" | "-g") {
                            ridx += 2;
                        } else {
                            ridx += 1;
                        }
                    }
                    continue;
                }
                break;
            }
            if let Some(first_remote) = remote_tokens.get(ridx) {
                let rbin = Path::new(first_remote)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(first_remote.as_str());
                let mut raw_redacted = redact_secrets(raw_text);
                if raw_redacted.len() > 400 {
                    raw_redacted = raw_redacted.chars().take(400).collect();
                }
                return Some(ParsedCommand {
                    cmd_bin,
                    cmd_template: format!("ssh {host} {rbin}"),
                    category: "vcs_ci",
                    is_repo_cli: false,
                    is_orientation: false,
                    raw_redacted,
                });
            }
        }
    }

    let mut subcommands_left: usize = if is_subcmd_bin { 1 } else { 0 };
    if (cmd_bin == "mise" && args.first().is_some_and(|a| a == "run" || a == "r"))
        || (is_js_runner && args.first().is_some_and(|a| a == "run"))
        || cmd_bin == "gh"
    {
        subcommands_left = 2;
    } else if matches!(cmd_bin.as_str(), "make" | "just") {
        subcommands_left = 1;
    }

    static VALUE_FLAG_RE: OnceLock<Regex> = OnceLock::new();
    let val_flag_re = VALUE_FLAG_RE.get_or_init(|| {
        Regex::new(r"^(?:-[a-zA-Z]|--(?:scope|filter|file|path|target|env|project|repo|branch|format|output|out|config|cwd|name|task|package|manifest-path|bin|test))$").unwrap()
    });
    static SUBCMD_RE: OnceLock<Regex> = OnceLock::new();
    let subcmd_re = SUBCMD_RE.get_or_init(|| Regex::new(r"^[a-zA-Z0-9:_-]+$").unwrap());

    let mut flags: Vec<String> = Vec::new();
    let mut after_dd = false;
    let mut positional_count = 0usize;
    let mut j = 0usize;
    while j < args.len() {
        let a = &args[j];
        if a == "--" {
            after_dd = true;
            j += 1;
            continue;
        }
        if !after_dd && a.starts_with('-') {
            if let Some(eq) = a.find('=') {
                flags.push(a[..eq].to_string());
            } else {
                flags.push(a.clone());
                if j + 1 < args.len() && !args[j + 1].starts_with('-') && val_flag_re.is_match(a) {
                    j += 1;
                }
            }
            j += 1;
            continue;
        }
        if !after_dd && subcommands_left > 0 && subcmd_re.is_match(a) && !a.contains('/') {
            template_parts.push(a.clone());
            subcommands_left -= 1;
            j += 1;
            continue;
        }
        if after_dd
            && cmd_bin == "mise"
            && positional_count == 0
            && a.len() <= 20
            && subcmd_re.is_match(a)
        {
            template_parts.push(a.clone());
            positional_count += 1;
            j += 1;
            continue;
        }
        positional_count += 1;
        j += 1;
    }

    let mut seen_flags = HashSet::new();
    let unique_flags: Vec<String> = flags
        .into_iter()
        .filter(|f| seen_flags.insert(f.clone()))
        .take(4)
        .collect();

    let is_script_interpreter = matches!(
        cmd_bin.as_str(),
        "python" | "python3" | "node" | "deno" | "bun" | "ruby" | "perl" | "bash" | "sh" | "zsh"
    );
    if is_script_interpreter
        && let Some(first_script) = args.iter().find(|a| {
            !a.starts_with('-') && {
                let l = a.to_ascii_lowercase();
                l.ends_with(".py")
                    || l.ends_with(".sh")
                    || l.ends_with(".mjs")
                    || l.ends_with(".cjs")
                    || l.ends_with(".js")
                    || l.ends_with(".ts")
                    || l.ends_with(".rb")
                    || l.ends_with(".pl")
                    || l.ends_with(".sql")
            }
        })
    {
        template_parts.push(normalize_arg(first_script));
    }

    if !unique_flags.is_empty() {
        template_parts.extend(unique_flags.iter().cloned());
    } else if positional_count > 0
        && !is_subcmd_bin
        && !is_local_script
        && !is_script_interpreter
        && let Some(first_pos) = args.iter().find(|a| !a.starts_with('-'))
    {
        template_parts.push(normalize_arg(first_pos));
    }

    let cmd_template = template_parts.join(" ");

    let category = if matches!(
        cmd_bin.as_str(),
        "sleep" | "watch" | "codex-wait" | "codex-write-stdin"
    ) {
        "polling"
    } else if is_repo_cli {
        "repo_task"
    } else if matches!(
        cmd_bin.as_str(),
        "cargo"
            | "rustc"
            | "pytest"
            | "vitest"
            | "jest"
            | "mocha"
            | "go"
            | "xcodebuild"
            | "swift"
            | "gradle"
            | "gradlew"
            | "mvn"
            | "dotnet"
            | "tsc"
            | "eslint"
            | "biome"
            | "ruff"
            | "mypy"
            | "flake8"
            | "next"
            | "vite"
            | "webpack"
            | "esbuild"
            | "turbo"
    ) {
        "build_test"
    } else if matches!(
        cmd_bin.as_str(),
        "git"
            | "gh"
            | "jj"
            | "glab"
            | "docker"
            | "podman"
            | "kubectl"
            | "helm"
            | "terraform"
            | "ssh"
            | "scp"
            | "rsync"
            | "flyctl"
            | "vercel"
            | "wrangler"
    ) {
        "vcs_ci"
    } else if matches!(
        cmd_bin.as_str(),
        "rg" | "grep"
            | "egrep"
            | "fgrep"
            | "ag"
            | "fd"
            | "find"
            | "cat"
            | "head"
            | "tail"
            | "less"
            | "sed"
            | "awk"
            | "ls"
            | "ll"
            | "tree"
            | "stat"
            | "wc"
            | "file"
            | "which"
            | "where"
            | "pwd"
            | "realpath"
            | "readlink"
    ) {
        "exploration"
    } else if is_js_runner || matches!(cmd_bin.as_str(), "pip" | "uv" | "poetry" | "brew") {
        "package_mgr"
    } else {
        "other"
    };

    let has_help = unique_flags.iter().any(|f| f == "--help" || f == "-h")
        || args.first().is_some_and(|a| a == "help" || a == "tasks");
    let reads_doc = matches!(cmd_bin.as_str(), "cat" | "head" | "tail" | "less" | "sed")
        && args.iter().any(|a| {
            let l = a.to_ascii_lowercase();
            l.contains("readme")
                || l.contains("agents")
                || l.contains("claude")
                || l.contains("contributing")
                || l.contains("makefile")
                || l.contains("mise.toml")
                || l.contains("package.json")
        });
    let is_dir_scan = matches!(cmd_bin.as_str(), "ls" | "ll" | "tree" | "find" | "fd");
    let is_orientation = has_help || reads_doc || is_dir_scan;

    let mut raw_redacted = redact_secrets(raw_text);
    if raw_redacted.len() > 400 {
        raw_redacted = raw_redacted.chars().take(400).collect();
    }

    Some(ParsedCommand {
        cmd_bin,
        cmd_template,
        category,
        is_repo_cli,
        is_orientation,
        raw_redacted,
    })
}

pub fn extract_state_dir_hint(command_text: &str, cd_hint: Option<&str>) -> Option<String> {
    static STATE_RE: OnceLock<Regex> = OnceLock::new();
    let re = STATE_RE.get_or_init(|| {
        Regex::new(
            r"(?:~|/Users/[^/\s]+|/home/[^/\s]+)/\.local/(?:state|share|cache)/([A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)?)|/var/(?:lib|log)/([A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)?)",
        )
        .unwrap()
    });
    for hay in [Some(command_text), cd_hint].into_iter().flatten() {
        if let Some(caps) = re.captures(hay) {
            if let Some(m) = caps.get(1) {
                return Some(format!("~/.local/state/{}", m.as_str()));
            }
            if let Some(m) = caps.get(2) {
                return Some(format!("/var/lib/{}", m.as_str()));
            }
        }
    }
    None
}

pub fn classify_output_noise(text: &str, exit_code: Option<i64>) -> Option<String> {
    if text.len() < 400 {
        return None;
    }
    let trimmed = text.trim();
    if (trimmed.starts_with('{') || trimmed.starts_with('[')) && text.len() > 1200 {
        return Some("json_dump".to_string());
    }

    let mut pass_lines = 0usize;
    let mut build_lines = 0usize;
    let mut warn_lines = 0usize;
    let mut diff_lines = 0usize;
    let mut log_lines = 0usize;
    let mut total = 0usize;

    for line in trimmed.lines().take(250) {
        total += 1;
        let l = line.trim_start();
        if line.contains("... ok")
            || l.starts_with("PASS")
            || l.starts_with("✓")
            || l.starts_with("✔")
            || l.starts_with("ok ")
        {
            pass_lines += 1;
        }
        if l.starts_with("Compiling ")
            || l.starts_with("Downloading ")
            || l.starts_with("Updating ")
            || l.starts_with("Installing ")
            || l.starts_with("Fetching ")
            || l.starts_with("Building ")
            || l.starts_with("Finished ")
            || l.starts_with("Checking ")
        {
            build_lines += 1;
        }
        if line.contains("warning:") || line.contains("WARN") || line.contains("deprecated") {
            warn_lines += 1;
        }
        if line.starts_with("+++ ")
            || line.starts_with("--- ")
            || line.starts_with("@@ ")
            || (line.starts_with('+') && line.len() > 1)
            || (line.starts_with('-') && line.len() > 1)
        {
            diff_lines += 1;
        }
        if line.len() >= 16
            && line.as_bytes()[4] == b'-'
            && line.as_bytes()[7] == b'-'
            && (line.as_bytes()[10] == b'T' || line.as_bytes()[10] == b' ')
        {
            log_lines += 1;
        }
    }

    let n = total.max(1) as f64;
    if (pass_lines as f64) / n >= 0.25 {
        Some("passing_test_lines".to_string())
    } else if (build_lines as f64) / n >= 0.25 {
        Some("build_progress".to_string())
    } else if (warn_lines as f64) / n >= 0.20 {
        Some("repeated_warnings".to_string())
    } else if (diff_lines as f64) / n >= 0.35 {
        Some("diff_or_source".to_string())
    } else if (log_lines as f64) / n >= 0.30 {
        Some("log_stream".to_string())
    } else if exit_code.is_some_and(|c| c != 0) {
        Some("error_dump".to_string())
    } else {
        Some("verbose_stdout".to_string())
    }
}

fn extract_json_str_field(s: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let pos = s.find(&needle)?;
    let mut out = String::new();
    let mut esc = false;
    for ch in s[pos + needle.len()..].chars() {
        if esc {
            out.push(if ch == 'n' || ch == 't' { ' ' } else { ch });
            esc = false;
        } else if ch == '\\' {
            esc = true;
        } else if ch == '"' {
            break;
        } else {
            out.push(ch);
        }
    }
    let cleaned = out.trim();
    (!cleaned.is_empty() && !cleaned.starts_with('{')).then(|| cleaned.chars().take(240).collect())
}

/// Strip harness wrapper envelopes (Codex chunk JSON, Antigravity timestamps, Wall time headers)
/// so error previews show the actual human-readable error message.
pub fn clean_error_preview(raw: &str) -> String {
    const WRAPPER_PREFIXES: &[&str] = &[
        "Script completed",
        "Wall time",
        "Chunk ID:",
        "Original token count:",
        "Total output lines:",
        "Created At:",
        "Completed At:",
        "Command exited with code",
        "Process exited with code",
        "{\"chunk_id\"",
        "[{\"status\":\"fulfilled\"",
        "{\"status\":\"fulfilled\"",
    ];
    const ERROR_MARKERS: &[&str] = &[
        "error",
        "failed",
        "fatal:",
        "command not found",
        "operation not permitted",
        "permission denied",
        "unknown argument",
        "unknown command",
        "unknown option",
        "no such column",
        "no such table",
        "choose --scope",
        "pass a single statement",
        "eperm",
        "could not resolve",
        "timed out",
        "forbidden:",
        "validation:",
        "conflict:",
        "no github credential",
    ];

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    if let Some(json_start) = trimmed.find('{') {
        let candidate = &trimmed[json_start..];
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(candidate) {
            if let Some(msg) = v
                .get("message")
                .and_then(|x| x.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let code = v.get("code").and_then(|x| x.as_str()).unwrap_or("");
                let s = if code.is_empty() {
                    msg.to_string()
                } else {
                    format!("{code}: {msg}")
                };
                return s.chars().take(240).collect();
            }
            if let Some(out) = v
                .get("output")
                .or_else(|| v.get("value").and_then(|x| x.get("output")))
                .or_else(|| v.get("response"))
                .and_then(|x| x.as_str())
                .filter(|s| !s.trim().is_empty())
            {
                return clean_error_preview(out);
            }
        } else {
            for key in ["message", "output", "response"] {
                if let Some(val) = extract_json_str_field(candidate, key) {
                    return val;
                }
            }
        }
    }

    let (mut high_signal, mut kept) = (Vec::new(), Vec::new());
    for p in trimmed
        .split('\n')
        .flat_map(|l| l.split(" | "))
        .flat_map(|l| l.split(" / "))
        .map(str::trim)
    {
        if p.is_empty()
            || matches!(p, "Output:" | "Command output:")
            || WRAPPER_PREFIXES.iter().any(|pre| p.starts_with(pre))
        {
            continue;
        }
        let pl = p.to_ascii_lowercase();
        if high_signal.len() < 3 && ERROR_MARKERS.iter().any(|m| pl.contains(m)) {
            high_signal.push(p);
        }
        if kept.len() < 3 {
            kept.push(p);
        }
    }

    let chosen = if !high_signal.is_empty() {
        high_signal
    } else {
        kept
    };
    if chosen.is_empty() {
        if trimmed.starts_with("Created At:") || trimmed.starts_with("Script completed") {
            String::new()
        } else {
            trimmed.chars().take(240).collect()
        }
    } else {
        chosen.join(" | ").chars().take(240).collect()
    }
}

pub fn extract_stderr_preview(text: &str, exit_code: Option<i64>) -> Option<String> {
    if exit_code == Some(0) || text.trim().is_empty() {
        return None;
    }
    let redacted = redact_secrets(text);
    let cleaned = clean_error_preview(&redacted);
    if !cleaned.is_empty() {
        return Some(cleaned);
    }
    let joined: String = redacted
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .take(6)
        .collect::<Vec<_>>()
        .join(" | ");
    if joined.is_empty() {
        None
    } else {
        Some(joined.chars().take(280).collect())
    }
}

pub fn extract_exit_code_from_text(text: &str, is_error: bool) -> i64 {
    static STRICT_PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    let strict = STRICT_PATTERNS.get_or_init(|| {
        vec![
            Regex::new(r"(?im)^(?:Command|Process) exited with code (\d+)").unwrap(),
            Regex::new(r"(?im)^Exit code:\s*(\d+)").unwrap(),
            Regex::new(r#""exit_code"\s*:\s*(\d+)"#).unwrap(),
        ]
    });
    // Check structured wrapper lines in the head (first 12 lines) or tail (last 8 lines) first
    // so passing test output quoting an inner subprocess failure isn't misclassified as an error.
    let lines: Vec<&str> = text.lines().collect();
    let head_end = lines.len().min(12);
    let tail_start = lines.len().saturating_sub(8);
    let edge_text = if head_end >= tail_start {
        text.to_string()
    } else {
        format!(
            "{}\n{}",
            lines[..head_end].join("\n"),
            lines[tail_start..].join("\n")
        )
    };
    for re in strict {
        if let Some(caps) = re.captures(&edge_text)
            && let Ok(code) = caps[1].parse::<i64>()
        {
            return code;
        }
    }
    static LOOSE_PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    let loose = LOOSE_PATTERNS.get_or_init(|| {
        vec![
            Regex::new(r"(?i)Command exited with code (\d+)").unwrap(),
            Regex::new(r"(?i)Process exited with code (\d+)").unwrap(),
            Regex::new(r"(?i)Exit code:\s*(\d+)").unwrap(),
            Regex::new(r"(?i)exit status (\d+)").unwrap(),
        ]
    });
    if is_error || lines.len() <= 16 {
        for re in loose {
            if let Some(caps) = re.captures(&edge_text)
                && let Ok(code) = caps[1].parse::<i64>()
            {
                return code;
            }
        }
    }
    if is_error { 1 } else { 0 }
}

pub fn extract_duration_ms_from_text(text: &str) -> Option<i64> {
    static WALL_RE: OnceLock<Regex> = OnceLock::new();
    let wall_re =
        WALL_RE.get_or_init(|| Regex::new(r"(?i)Wall time:?\s*([\d.]+)\s*seconds?").unwrap());
    if let Some(caps) = wall_re.captures(text)
        && let Ok(sec) = caps[1].parse::<f64>()
    {
        return Some((sec * 1000.0).round() as i64);
    }

    static JSON_WALL_RE: OnceLock<Regex> = OnceLock::new();
    let jwall_re =
        JSON_WALL_RE.get_or_init(|| Regex::new(r#""wall_time_seconds"\s*:\s*([\d.]+)"#).unwrap());
    if let Some(caps) = jwall_re.captures(text)
        && let Ok(sec) = caps[1].parse::<f64>()
    {
        return Some((sec * 1000.0).round() as i64);
    }

    static CREATED_RE: OnceLock<Regex> = OnceLock::new();
    static COMPLETED_RE: OnceLock<Regex> = OnceLock::new();
    let c1 = CREATED_RE.get_or_init(|| Regex::new(r"Created At:\s*([^\r\n]+)").unwrap());
    let c2 = COMPLETED_RE.get_or_init(|| Regex::new(r"Completed At:\s*([^\r\n]+)").unwrap());
    if let (Some(a), Some(b)) = (c1.captures(text), c2.captures(text))
        && let (Ok(t1), Ok(t2)) = (
            chrono::DateTime::parse_from_rfc3339(a[1].trim()),
            chrono::DateTime::parse_from_rfc3339(b[1].trim()),
        )
    {
        let diff = t2.timestamp_millis() - t1.timestamp_millis();
        if diff >= 0 {
            return Some(diff);
        }
    }
    None
}
