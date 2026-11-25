use crate::config::spans_path;
use crate::shell::{classify_output_noise, extract_stderr_preview};
use anyhow::{Result, bail};
use chrono::Utc;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{IsTerminal, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;

fn git_head_fast(cwd: &Path) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn detect_actor() -> (&'static str, Option<String>) {
    if let Ok(a) = env::var("BOTTLEDECK_ACTOR").or_else(|_| env::var("AGENT_PULSE_ACTOR")) {
        let lower = a.to_ascii_lowercase();
        if lower == "human" {
            return ("human", None);
        }
        if lower == "ci" {
            return ("ci", Some("ci".to_string()));
        }
        return ("agent", Some(lower));
    }
    if env::var("CI").is_ok() {
        return ("ci", Some("ci".to_string()));
    }
    if std::io::stdout().is_terminal() {
        ("human", None)
    } else {
        ("agent", None)
    }
}

pub fn run_wrapped_command(argv: &[String], surface_version: Option<&str>) -> Result<i32> {
    if argv.is_empty() {
        bail!("Usage: bottledeck wrap [--surface vN] -- <command> [args...]");
    }

    let started_at = Utc::now().timestamp_millis();
    let cwd = env::current_dir()?;
    let cmd = &argv[0];
    let args = &argv[1..];
    let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();

    let mut stdout_bytes: usize = 0;
    let mut stderr_bytes: usize = 0;
    let mut stdout_sample = Vec::new();
    let mut stderr_sample = Vec::new();

    let exit_code = if interactive {
        match Command::new(cmd).args(args).status() {
            Ok(st) => st.code().unwrap_or(1),
            Err(e) => {
                eprintln!("bottledeck wrap: failed to launch \"{cmd}\": {e}");
                127
            }
        }
    } else {
        let mut child = match Command::new(cmd)
            .args(args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("bottledeck wrap: failed to launch \"{cmd}\": {e}");
                return Ok(127);
            }
        };

        let mut child_out = child.stdout.take();
        let mut child_err = child.stderr.take();

        let out_handle = thread::spawn(move || -> (usize, Vec<u8>) {
            let mut total = 0usize;
            let mut sample = Vec::new();
            let mut buf = [0u8; 8192];
            if let Some(mut reader) = child_out.take() {
                let mut stdout = std::io::stdout().lock();
                while let Ok(n) = reader.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    let _ = stdout.write_all(&buf[..n]);
                    let _ = stdout.flush();
                    total += n;
                    if sample.len() < 8192 {
                        let remain = 8192 - sample.len();
                        sample.extend_from_slice(&buf[..n.min(remain)]);
                    }
                }
            }
            (total, sample)
        });

        let err_handle = thread::spawn(move || -> (usize, Vec<u8>) {
            let mut total = 0usize;
            let mut sample = Vec::new();
            let mut buf = [0u8; 8192];
            if let Some(mut reader) = child_err.take() {
                let mut stderr = std::io::stderr().lock();
                while let Ok(n) = reader.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    let _ = stderr.write_all(&buf[..n]);
                    let _ = stderr.flush();
                    total += n;
                    if sample.len() < 4096 {
                        let remain = 4096 - sample.len();
                        sample.extend_from_slice(&buf[..n.min(remain)]);
                    }
                }
            }
            (total, sample)
        });

        let status = child.wait();
        if let Ok((b, s)) = out_handle.join() {
            stdout_bytes = b;
            stdout_sample = s;
        }
        if let Ok((b, s)) = err_handle.join() {
            stderr_bytes = b;
            stderr_sample = s;
        }
        status.ok().and_then(|s| s.code()).unwrap_or(1)
    };

    let duration_ms = (Utc::now().timestamp_millis() - started_at).max(0);

    // Fail-open span append
    let _ = (|| -> Result<()> {
        let sp_path = spans_path();
        if let Some(parent) = sp_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let (actor, agent_kind) = detect_actor();
        let out_str = String::from_utf8_lossy(&stdout_sample);
        let err_str = String::from_utf8_lossy(&stderr_sample);
        let err_src = if err_str.is_empty() {
            out_str.as_ref()
        } else {
            err_str.as_ref()
        };

        let mut h = Sha256::new();
        h.update(started_at.to_string().as_bytes());
        h.update(std::process::id().to_string().as_bytes());
        h.update(cmd.as_bytes());
        let span_id = format!("wrap_{}", &format!("{:x}", h.finalize())[..12]);

        let rec = json!({
            "span_id": span_id,
            "session_id": env::var("BOTTLEDECK_SESSION_ID")
                .or_else(|_| env::var("AGENT_PULSE_SESSION_ID"))
                .or_else(|_| env::var("HARNESS_SESSION_ID"))
                .ok(),
            "tool_call_id": env::var("BOTTLEDECK_TOOL_CALL_ID")
                .or_else(|_| env::var("AGENT_PULSE_TOOL_CALL_ID"))
                .ok(),
            "actor": actor,
            "agent_kind": agent_kind,
            "surface_version": surface_version
                .map(str::to_string)
                .or_else(|| env::var("BOTTLEDECK_SURFACE").ok())
                .or_else(|| env::var("AGENT_PULSE_SURFACE").ok()),
            "cwd": cwd.to_string_lossy(),
            "git_head": git_head_fast(&cwd),
            "argv": argv,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "stdout_bytes": stdout_bytes,
            "stderr_bytes": stderr_bytes,
            "noise_kind": classify_output_noise(&out_str, Some(exit_code as i64)),
            "stderr_preview": extract_stderr_preview(err_src, Some(exit_code as i64)),
            "started_at": started_at,
        });

        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&sp_path)?;
        writeln!(f, "{rec}")?;
        Ok(())
    })();

    Ok(exit_code)
}
