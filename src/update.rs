use crate::config::state_dir;
use anyhow::{Context, Result, bail};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const GITHUB_REPO: &str = "timuric/bottledeck";
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const CHECK_TTL_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UpdateCache {
    checked_at_ms: i64,
    latest_tag: String,
}

fn cache_path() -> PathBuf {
    state_dir().join("update-check.json")
}

pub fn parse_semver(version: &str) -> Option<(u64, u64, u64)> {
    let clean = version.trim().trim_start_matches('v');
    let core = clean.split('-').next().unwrap_or(clean);
    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch = parts.next()?.parse::<u64>().ok()?;
    Some((major, minor, patch))
}

pub fn is_newer_version(latest: &str, current: &str) -> bool {
    match (parse_semver(latest), parse_semver(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

pub fn detect_target_triple() -> Result<&'static str> {
    match (env::consts::OS, env::consts::ARCH) {
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        ("macos", "x86_64") => Ok("x86_64-apple-darwin"),
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Ok("aarch64-unknown-linux-gnu"),
        (os, arch) => bail!(
            "No prebuilt release binary for {os}/{arch}. Upgrade via: cargo install --git https://github.com/{GITHUB_REPO}"
        ),
    }
}

/// Latest release tag. Follows the `releases/latest` web redirect first (no API rate limit:
/// unauthenticated API calls are capped at 60/hour per IP), then falls back to the REST API.
pub fn fetch_latest_release_tag() -> Result<String> {
    let redirect_err = match fetch_latest_tag_via_redirect() {
        Ok(tag) => return Ok(tag),
        Err(e) => e,
    };
    fetch_latest_tag_via_api().map_err(|api_err| {
        anyhow::anyhow!(
            "Could not determine the latest release ({redirect_err:#}; {api_err:#}). \
             Install a specific one with `bottledeck update --version <x.y.z>`."
        )
    })
}

fn fetch_latest_tag_via_redirect() -> Result<String> {
    let url = format!("https://github.com/{GITHUB_REPO}/releases/latest");
    let out = Command::new("curl")
        .args([
            "-fsSL",
            "--max-time",
            "8",
            "-o",
            "/dev/null",
            "-w",
            "%{url_effective}",
            "-H",
            "User-Agent: bottledeck-updater",
            &url,
        ])
        .output()
        .context("Failed to execute `curl` to check GitHub releases")?;
    if !out.status.success() {
        bail!(
            "release redirect failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    tag_from_release_url(&String::from_utf8_lossy(&out.stdout))
        .context("release redirect did not point at a tag")
}

/// `https://github.com/o/r/releases/tag/v1.2.3` -> `v1.2.3`
fn tag_from_release_url(url: &str) -> Option<String> {
    let tag = url.trim().rsplit_once("/releases/tag/")?.1;
    let tag = tag.split(['?', '#', '/']).next()?.trim();
    (!tag.is_empty()).then(|| tag.to_string())
}

fn fetch_latest_tag_via_api() -> Result<String> {
    let url = format!("https://api.github.com/repos/{GITHUB_REPO}/releases/latest");
    let out = Command::new("curl")
        .args([
            "-fsSL",
            "--max-time",
            "8",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "User-Agent: bottledeck-updater",
            &url,
        ])
        .output()
        .context("Failed to execute `curl` to check GitHub releases")?;
    if !out.status.success() {
        bail!(
            "releases API failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let val: serde_json::Value =
        serde_json::from_slice(&out.stdout).context("Invalid JSON from GitHub Releases API")?;
    let tag = val
        .get("tag_name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .context("GitHub release response missing tag_name")?;
    Ok(tag.to_string())
}

fn save_cache(tag: &str) {
    let path = cache_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let cache = UpdateCache {
        checked_at_ms: Utc::now().timestamp_millis(),
        latest_tag: tag.to_string(),
    };
    if let Ok(json) = serde_json::to_string_pretty(&cache) {
        let _ = fs::write(&path, json);
    }
}

/// Non-blocking cached update check (24h TTL). Returns `Some("vX.Y.Z")` if a newer
/// release is known; refreshes in a background thread when stale.
pub fn cached_available_update() -> Option<String> {
    if env::var("BOTTLEDECK_NO_UPDATE_CHECK").is_ok() || env::var("CI").is_ok() {
        return None;
    }
    let now = Utc::now().timestamp_millis();
    let cached = fs::read_to_string(cache_path())
        .ok()
        .and_then(|s| serde_json::from_str::<UpdateCache>(&s).ok());

    let needs_refresh = match &cached {
        Some(c) => now.saturating_sub(c.checked_at_ms) >= CHECK_TTL_MS,
        None => true,
    };

    if needs_refresh {
        std::thread::spawn(|| {
            if let Ok(tag) = fetch_latest_release_tag() {
                save_cache(&tag);
            }
        });
    }

    cached
        .map(|c| c.latest_tag)
        .filter(|tag| is_newer_version(tag, CURRENT_VERSION))
}

fn sha256_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let digest = Sha256::digest(&bytes);
    Ok(format!("{digest:x}"))
}

fn verify_checksum(archive_path: &Path, archive_name: &str, sums_text: &str) -> Result<()> {
    let expected = sums_text
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let hash = parts.next()?;
            let name = parts.next()?.trim_start_matches('*');
            Some((name, hash))
        })
        .find(|(name, _)| *name == archive_name)
        .map(|(_, hash)| hash.to_ascii_lowercase())
        .with_context(|| format!("Checksum for {archive_name} not found in SHA256SUMS.txt"))?;

    let actual = sha256_file(archive_path)?;
    if actual != expected {
        bail!("SHA256 mismatch for {archive_name}!\n  expected: {expected}\n  actual:   {actual}");
    }
    Ok(())
}

pub fn run_self_update(
    check_only: bool,
    requested_version: Option<&str>,
    force: bool,
) -> Result<()> {
    let target_tag = match requested_version {
        Some(v) => {
            let trimmed = v.trim();
            if trimmed.starts_with('v') {
                trimmed.to_string()
            } else {
                format!("v{trimmed}")
            }
        }
        None => {
            let tag = fetch_latest_release_tag()?;
            save_cache(&tag);
            tag
        }
    };

    let newer = is_newer_version(&target_tag, CURRENT_VERSION);
    if check_only {
        println!("bottledeck v{CURRENT_VERSION}");
        if newer {
            println!("Update available: {target_tag}");
            println!("Run `bottledeck update` to upgrade.");
        } else {
            println!("Up to date (latest: {target_tag}).");
        }
        return Ok(());
    }

    if !newer && requested_version.is_none() && !force {
        println!("bottledeck v{CURRENT_VERSION} is already up to date (latest: {target_tag}).");
        return Ok(());
    }

    let current_exe = env::current_exe().context("Could not resolve current executable path")?;
    let exe_str = current_exe.to_string_lossy();
    if !force && (exe_str.contains("/Cellar/") || exe_str.contains("/homebrew/")) {
        println!("bottledeck is managed by Homebrew ({exe_str}).");
        println!("Run: brew upgrade bottledeck");
        println!("(Pass `bottledeck update --force` to overwrite directly.)");
        return Ok(());
    }

    let target = detect_target_triple()?;
    let archive_name = format!("bottledeck-{target_tag}-{target}.tar.gz");
    let base_url = format!("https://github.com/{GITHUB_REPO}/releases/download/{target_tag}");
    let archive_url = format!("{base_url}/{archive_name}");
    let sums_url = format!("{base_url}/SHA256SUMS.txt");

    let tmp_dir = env::temp_dir().join(format!(
        "bottledeck-update-{}-{}",
        std::process::id(),
        Utc::now().timestamp_millis()
    ));
    fs::create_dir_all(&tmp_dir)?;
    let result = (|| -> Result<()> {
        let archive_path = tmp_dir.join(&archive_name);
        let sums_path = tmp_dir.join("SHA256SUMS.txt");

        println!("Downloading {archive_name}...");
        let st = Command::new("curl")
            .args(["-fsSL", "-o"])
            .arg(&archive_path)
            .arg(&archive_url)
            .status()
            .context("Failed to execute `curl`")?;
        if !st.success() {
            bail!("Failed to download {archive_url}");
        }

        let st_sums = Command::new("curl")
            .args(["-fsSL", "-o"])
            .arg(&sums_path)
            .arg(&sums_url)
            .status()
            .context("Failed to download SHA256SUMS.txt")?;
        if !st_sums.success() {
            bail!("Failed to download {sums_url}");
        }

        let sums_text = fs::read_to_string(&sums_path)?;
        verify_checksum(&archive_path, &archive_name, &sums_text)?;

        let extract_dir = tmp_dir.join("extract");
        fs::create_dir_all(&extract_dir)?;
        let st_tar = Command::new("tar")
            .args(["-xzf"])
            .arg(&archive_path)
            .arg("-C")
            .arg(&extract_dir)
            .status()
            .context("Failed to execute `tar`")?;
        if !st_tar.success() {
            bail!("Failed to extract {archive_name}");
        }

        let new_bin = extract_dir.join("bottledeck");
        if !new_bin.exists() {
            bail!("Release archive did not contain `bottledeck` binary");
        }

        let exe_dir = current_exe
            .parent()
            .context("Executable path has no parent directory")?;
        let staged = exe_dir.join(format!(".bottledeck.new.{}", std::process::id()));
        fs::copy(&new_bin, &staged).with_context(|| {
            format!(
                "Could not write to {} (try running with sudo or reinstall to ~/.local/bin)",
                exe_dir.display()
            )
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&staged, fs::Permissions::from_mode(0o755));
        }

        fs::rename(&staged, &current_exe).with_context(|| {
            let _ = fs::remove_file(&staged);
            format!("Failed to replace {}", current_exe.display())
        })?;

        println!(
            "Updated bottledeck: v{CURRENT_VERSION} -> {target_tag} ({})",
            current_exe.display()
        );
        Ok(())
    })();

    let _ = fs::remove_dir_all(&tmp_dir);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tag_from_release_redirect() {
        assert_eq!(
            tag_from_release_url("https://github.com/o/r/releases/tag/v0.4.1\n").as_deref(),
            Some("v0.4.1")
        );
        assert_eq!(
            tag_from_release_url("https://github.com/o/r/releases"),
            None
        );
        assert_eq!(
            tag_from_release_url("https://github.com/o/r/releases/tag/"),
            None
        );
    }

    #[test]
    fn semver_comparison_works() {
        assert!(is_newer_version("v0.2.0", "0.1.0"));
        assert!(is_newer_version("v1.0.0", "0.9.9"));
        assert!(!is_newer_version("v0.1.0", "0.1.0"));
        assert!(!is_newer_version("v0.0.9", "0.1.0"));
    }
}
