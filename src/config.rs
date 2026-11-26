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

/// Model pricing rates in USD per 1M tokens: `(input, cache_read, cache_write, output)`.
pub fn model_pricing_per_million(model: Option<&str>, agent_kind: &str) -> (f64, f64, f64, f64) {
    let m = model.unwrap_or("").to_ascii_lowercase();
    if m.contains("opus") {
        (15.0, 1.5, 18.75, 75.0)
    } else if m.contains("haiku") {
        (0.8, 0.08, 1.0, 4.0)
    } else if m.contains("sonnet") || m.contains("fable") || m.contains("claude") {
        (3.0, 0.3, 3.75, 15.0)
    } else if m.contains("codex-mini") || m.contains("gpt-5-mini") || m.contains("o4-mini") {
        (0.75, 0.075, 0.75, 3.0)
    } else if m.contains("gpt-6")
        || m.contains("astra")
        || m.contains("codex")
        || m.contains("gpt-5")
        || m.contains("o3")
    {
        (2.5, 0.25, 2.5, 10.0)
    } else if m.contains("flash") {
        (0.3, 0.03, 0.3, 2.5)
    } else if m.contains("gemini")
        || m.contains("neon")
        || m.contains("carbon")
        || m.contains("argon")
    {
        (1.25, 0.125, 1.25, 10.0)
    } else if m.contains("kimi") {
        (0.6, 0.15, 0.6, 2.5)
    } else {
        match agent_kind {
            "claude-code" => (3.0, 0.3, 3.75, 15.0),
            "codex" => (2.5, 0.25, 2.5, 10.0),
            "antigravity" => (1.25, 0.125, 1.25, 10.0),
            "kimi" => (0.6, 0.15, 0.6, 2.5),
            _ => (2.0, 0.2, 2.0, 10.0),
        }
    }
}

/// Estimate USD cost from token counts using model pricing (thinking tokens billed at output rate).
pub fn estimate_cost_usd(
    model: Option<&str>,
    agent_kind: &str,
    input_tokens: i64,
    cache_read_tokens: i64,
    cache_write_tokens: i64,
    output_tokens: i64,
    thinking_tokens: i64,
) -> f64 {
    let (p_in, p_cr, p_cw, p_out) = model_pricing_per_million(model, agent_kind);
    let out_total = (output_tokens.max(0) + thinking_tokens.max(0)) as f64;
    (input_tokens.max(0) as f64 * p_in
        + cache_read_tokens.max(0) as f64 * p_cr
        + cache_write_tokens.max(0) as f64 * p_cw
        + out_total * p_out)
        / 1_000_000.0
}

/// Default context window size when not explicitly reported in the transcript.
pub fn default_context_window(model: Option<&str>, agent_kind: &str) -> Option<i64> {
    let m = model.unwrap_or("").to_ascii_lowercase();
    if m.contains("gemini") || m.contains("neon") || m.contains("carbon") || m.contains("argon") {
        Some(1_000_000)
    } else if m.contains("opus")
        || m.contains("sonnet")
        || m.contains("haiku")
        || m.contains("claude")
    {
        Some(200_000)
    } else if m.contains("codex")
        || m.contains("gpt-5")
        || m.contains("gpt-6")
        || m.contains("astra")
    {
        Some(258_400)
    } else if m.contains("kimi") {
        Some(128_000)
    } else {
        match agent_kind {
            "claude-code" => Some(200_000),
            "codex" => Some(258_400),
            "antigravity" => Some(1_000_000),
            "kimi" => Some(128_000),
            _ => None,
        }
    }
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
