use anyhow::{Result, bail};
use chrono::Utc;
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct AdapterRoots {
    pub claude: Vec<PathBuf>,
    pub codex: Vec<PathBuf>,
    pub antigravity: Vec<PathBuf>,
    pub kimi: Vec<PathBuf>,
    pub spans: PathBuf,
}

#[derive(Debug, Clone)]
pub struct TimeRange {
    pub since_ms: i64,
    pub until_ms: Option<i64>,
    pub label: String,
}

impl TimeRange {
    pub fn from_window(window_ms: Option<i64>, label: &str) -> Self {
        let since_ms = window_ms
            .map(|w| Utc::now().timestamp_millis() - w)
            .unwrap_or(0);
        Self {
            since_ms,
            until_ms: None,
            label: label.to_string(),
        }
    }

    pub fn bounded(since_ms: i64, until_ms: Option<i64>, label: String) -> Self {
        Self {
            since_ms,
            until_ms,
            label,
        }
    }

    pub fn upper_bound(&self) -> i64 {
        self.until_ms.unwrap_or(i64::MAX)
    }
}

pub fn home_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

pub fn state_dir() -> PathBuf {
    if let Ok(v) = env::var("BOTTLEDECK_STATE_DIR").or_else(|_| env::var("AGENT_PULSE_STATE_DIR"))
        && !v.trim().is_empty()
    {
        return PathBuf::from(v);
    }
    home_dir().join(".local").join("state").join("bottledeck")
}

pub fn db_path() -> PathBuf {
    state_dir().join("ledger.db")
}

pub fn spans_path() -> PathBuf {
    state_dir().join("spans.jsonl")
}

fn env_paths(var: &str) -> Option<Vec<PathBuf>> {
    let raw = env::var(var).ok()?;
    let paths: Vec<PathBuf> = env::split_paths(&raw)
        .filter(|p| !p.as_os_str().is_empty())
        .collect();
    if paths.is_empty() { None } else { Some(paths) }
}

pub fn adapter_roots() -> AdapterRoots {
    let home = home_dir();
    AdapterRoots {
        claude: env_paths("BOTTLEDECK_CLAUDE_DIR")
            .or_else(|| env_paths("AGENT_PULSE_CLAUDE_DIR"))
            .unwrap_or_else(|| vec![home.join(".claude").join("projects")]),
        codex: env_paths("BOTTLEDECK_CODEX_DIR")
            .or_else(|| env_paths("AGENT_PULSE_CODEX_DIR"))
            .unwrap_or_else(|| {
                vec![
                    home.join(".codex").join("sessions"),
                    home.join(".codex").join("archived_sessions"),
                    home.join(".t3")
                        .join("userdata")
                        .join("providers")
                        .join("codex"),
                ]
            }),
        antigravity: env_paths("BOTTLEDECK_ANTIGRAVITY_DIR")
            .or_else(|| env_paths("AGENT_PULSE_ANTIGRAVITY_DIR"))
            .unwrap_or_else(|| {
                vec![
                    home.join(".t3").join("userdata"),
                    home.join(".gemini").join("antigravity"),
                    home.join(".gemini").join("antigravity-cli"),
                    home.join(".gemini").join("antigravity-ide"),
                ]
            }),
        kimi: env_paths("BOTTLEDECK_KIMI_DIR")
            .or_else(|| env_paths("AGENT_PULSE_KIMI_DIR"))
            .unwrap_or_else(|| {
                vec![
                    home.join(".kimi-code").join("sessions"),
                    home.join(".kimi").join("sessions"),
                ]
            }),
        spans: spans_path(),
    }
}

pub fn estimate_tokens_bytes(bytes: usize) -> i64 {
    bytes.div_ceil(4) as i64
}

pub fn estimate_tokens_str(s: &str) -> i64 {
    estimate_tokens_bytes(s.len())
}

pub fn parse_window_ms(window_str: &str) -> Result<Option<i64>> {
    let s = window_str.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("all") {
        return Ok(None);
    }
    if s.len() < 2 {
        bail!("Invalid --window \"{s}\". Use e.g. 24h, 7d, 14d, 30d, or all.");
    }
    let (num_part, unit_part) = s.split_at(s.len() - 1);
    let n: i64 = num_part.parse().map_err(|_| {
        anyhow::anyhow!("Invalid --window \"{s}\". Use e.g. 24h, 7d, 14d, 30d, or all.")
    })?;
    let mult: i64 = match unit_part.to_ascii_lowercase().as_str() {
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        "w" => 7 * 86_400_000,
        _ => bail!("Invalid --window \"{s}\". Use e.g. 24h, 7d, 14d, 30d, or all."),
    };
    Ok(Some(n.saturating_mul(mult)))
}
