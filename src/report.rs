use crate::analyze::{
    BypassReport, CommandStat, DiffReport, ErrorCluster, FleetReport, InspectResult, Opportunity,
    RepoReport, format_compact, format_duration_human,
};
use crate::patterns::CrossSessionPatternsReport;
use serde_json::Value;

pub fn format_commands_report(
    repo_name: &str,
    sort_by: &str,
    cmds: &[CommandStat],
    format: &str,
) -> String {
    if format == "json" {
        return serde_json::to_string_pretty(cmds).unwrap_or_default();
    }
    let mut lines = vec![
        format!("# Commands in `{repo_name}` (sorted by `{sort_by}`, showing {})", cmds.len()),
        String::new(),
        "| Command Template | Cat | CLI | Runs | Errs | Err% | Piped | Top Pipe | p50 Out | Eff Toks | p50/p95 Wait | Total Wait | Harnesses | Noise |".to_string(),
        "| :--- | :--- | :---: | ---: | ---: | ---: | ---: | :--- | ---: | ---: | :---: | ---: | :--- | :--- |".to_string(),
    ];
    for c in cmds {
        let p_wait = match c.p95_wait_s {
            Some(p95) => format!("{:.1}s/{p95:.1}s", c.p50_wait_s),
            None => format!("{:.1}s/-", c.p50_wait_s),
        };
        lines.push(format!(
            "| `{}` | {} | {} | {} | {} | {:.0}% | {} | {} | {} | {} | {} | {:.1}s | {} | {} |",
            c.cmd_template,
            c.category,
            if c.is_repo_cli { "yes" } else { "-" },
            c.runs,
            c.error_count,
            c.error_rate * 100.0,
            c.piped_count,
            c.top_pipe_filter.as_deref().unwrap_or("-"),
            format_compact(c.p50_stdout_tokens),
            format_compact(c.effective_tokens),
            p_wait,
            c.total_wait_s,
            c.harness_summary,
            c.dominant_noise.as_deref().unwrap_or("-")
        ));
    }
    lines.join("\n")
}

pub fn format_errors_report(repo_name: &str, errs: &[ErrorCluster], format: &str) -> String {
    if format == "json" {
        return serde_json::to_string_pretty(errs).unwrap_or_default();
    }
    let mut lines = vec![
        format!("# Error Clusters in `{repo_name}` (top {})", errs.len()),
        String::new(),
        "| Command Template | Cat | Errs | Runs | Err% | Sess | Codes | Harnesses | Sample Stderr |".to_string(),
        "| :--- | :--- | ---: | ---: | ---: | ---: | :--- | :--- | :--- |".to_string(),
    ];
    for e in errs {
        let codes = e
            .exit_codes
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        lines.push(format!(
            "| `{}` | {} | {} | {} | {:.0}% | {} | {} | {} | `{}` |",
            e.cmd_template,
            e.category,
            e.error_count,
            e.total_runs,
            e.error_rate * 100.0,
            e.sessions,
            codes,
            e.harness_summary,
            e.stderr_preview.replace('|', "/")
        ));
    }
    lines.join("\n")
}

pub fn format_bypasses_report(rep: &BypassReport, format: &str) -> String {
    if format == "json" {
        return serde_json::to_string_pretty(rep).unwrap_or_default();
    }
    let mut lines = vec![
        format!(
            "# Harness Bypass & Friction Audit — `{}` ({})",
            rep.repo_name, rep.window
        ),
        String::new(),
        "## 1. Direct State-Directory Scrapes (Non-CLI)".to_string(),
        String::new(),
    ];
    if rep.state_dir_scrapes.is_empty() {
        lines.push("_None detected._".to_string());
    } else {
        lines.push(
            "| State Directory | Calls | Sess | Out Toks | Wait | Harnesses | Top Raw Commands |"
                .to_string(),
        );
        lines.push("| :--- | ---: | ---: | ---: | ---: | :--- | :--- |".to_string());
        for s in &rep.state_dir_scrapes {
            lines.push(format!(
                "| `{}` | {} | {} | {} | {:.1}s | {} | {} |",
                s.state_dir,
                s.calls,
                s.sessions,
                format_compact(s.stdout_tokens),
                s.total_wait_s,
                s.harness_summary,
                s.top_cmds.join(", ")
            ));
        }
    }

    lines.push(String::new());
    lines.push("## 2. Repo CLI Output Pipe-Stripping".to_string());
    lines.push(String::new());
    if rep.pipe_stripping.is_empty() {
        lines.push("_None detected._".to_string());
    } else {
        lines.push(
            "| Repo CLI Command | Piped | Runs | Pipe% | Harnesses | Top Filters |".to_string(),
        );
        lines.push("| :--- | ---: | ---: | ---: | :--- | :--- |".to_string());
        for p in &rep.pipe_stripping {
            lines.push(format!(
                "| `{}` | {} | {} | {:.0}% | {} | {} |",
                p.cmd_template,
                p.piped_calls,
                p.total_runs,
                p.pipe_rate * 100.0,
                p.harness_summary,
                p.top_filters.join(", ")
            ));
        }
    }

    lines.push(String::new());
    lines.push("## 3. Repo CLI Help Lookups & Broken Help Flags".to_string());
    lines.push(String::new());
    if rep.help_lookups.is_empty() {
        lines.push("_None detected._".to_string());
    } else {
        lines.push(
            "| Command Template | Calls | Sess | Broken (Nonzero) | Out Toks | Harnesses |"
                .to_string(),
        );
        lines.push("| :--- | ---: | ---: | ---: | ---: | :--- |".to_string());
        for h in &rep.help_lookups {
            lines.push(format!(
                "| `{}` | {} | {} | {} | {} | {} |",
                h.cmd_template,
                h.calls,
                h.sessions,
                h.broken_calls,
                format_compact(h.stdout_tokens),
                h.harness_summary
            ));
        }
    }

    lines.push(String::new());
    lines.push("## 4. Grouped Raw Tool Bypass Families (Non-CLI)".to_string());
    lines.push(String::new());
    if rep.raw_bypass_families.is_empty() {
        lines.push("_None detected._".to_string());
    } else {
        lines.push("| Tool Family | Cat | Runs | Sess | Errs | Err% | Out Toks | Wait | Harnesses | Breakdown |".to_string());
        lines.push(
            "| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | :--- | :--- |".to_string(),
        );
        for f in &rep.raw_bypass_families {
            lines.push(format!(
                "| `{}` | {} | {} | {} | {} | {:.0}% | {} | {:.1}s | {} | {} |",
                f.cmd_bin,
                f.category,
                f.total_runs,
                f.sessions,
                f.error_count,
                f.error_rate * 100.0,
                format_compact(f.total_stdout_tokens),
                f.total_wait_s,
                f.harness_summary,
                f.top_templates.join(", ")
            ));
        }
    }

    lines.push(String::new());
    lines.push("## 5. Top Individual Raw Commands Bypassing Repo Tasks".to_string());
    lines.push(String::new());
    if rep.raw_tool_bypasses.is_empty() {
        lines.push("_None detected._".to_string());
    } else {
        lines.push("| Raw Command Template | Cat | Runs | Errs | Err% | Out Toks | Total Wait | Harnesses |".to_string());
        lines.push("| :--- | :--- | ---: | ---: | ---: | ---: | ---: | :--- |".to_string());
        for c in &rep.raw_tool_bypasses {
            lines.push(format!(
                "| `{}` | {} | {} | {} | {:.0}% | {} | {:.1}s | {} |",
                c.cmd_template,
                c.category,
                c.runs,
                c.error_count,
                c.error_rate * 100.0,
                format_compact(c.total_stdout_tokens),
                c.total_wait_s,
                c.harness_summary
            ));
        }
    }

    lines.join("\n")
}

fn escape_yaml(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', " ")
}

pub fn format_fleet_report(fleet: &FleetReport, format: &str) -> String {
    if format == "json" {
        return serde_json::to_string_pretty(fleet).unwrap_or_default();
    }

    if format == "llm" {
        let mut lines = vec![
            format!("window: {}", fleet.window),
            "totals:".to_string(),
            format!("  repos: {}", fleet.totals.repos),
            format!("  sessions: {}", fleet.totals.sessions),
            format!("  commands: {}", fleet.totals.commands),
            format!("  stdout_tokens: {}", fleet.totals.stdout_tokens),
            "repos:".to_string(),
        ];
        for r in fleet.repos.iter().take(15) {
            lines.push(format!("  - repo: \"{}\"", escape_yaml(&r.repo_name)));
            lines.push(format!("    sessions: {}", r.session_count));
            lines.push(format!("    commands: {}", r.command_count));
            lines.push(format!("    worktrees: {}", r.worktree_count));
            lines.push(format!(
                "    median_session_tokens: {}",
                r.median_session_tokens
            ));
            lines.push(format!("    stdout_tokens: {}", r.total_stdout_tokens));
            lines.push(format!("    median_tool_wait_s: {}", r.median_tool_wait_s));
            lines.push(format!("    error_rate: {}", r.error_rate));
            lines.push(format!(
                "    top_driver: \"{}\"",
                escape_yaml(&r.top_driver)
            ));
        }
        if !fleet.systemic_patterns.is_empty() {
            lines.push("systemic_cross_repo_patterns:".to_string());
            for p in &fleet.systemic_patterns {
                lines.push(format!("  - cmd: \"{}\"", escape_yaml(&p.cmd_template)));
                lines.push(format!("    repos: {}", p.repo_count));
                lines.push(format!("    runs: {}", p.runs));
                lines.push(format!("    stdout_tokens: {}", p.total_stdout_tokens));
                lines.push(format!("    wait_s: {}", p.total_wait_s));
                lines.push(format!("    error_rate: {}", p.error_rate));
                if let Some(n) = &p.dominant_noise {
                    lines.push(format!("    noise: {n}"));
                }
            }
        }
        return lines.join("\n");
    }

    let mut lines = vec![
        format!("# Bottledeck — Fleet Report ({})", fleet.window),
        String::new(),
        format!(
            "Analyzed **{}** sessions and **{}** commands across **{}** repo(s) ({} tool-output tokens).",
            fleet.totals.sessions,
            fleet.totals.commands,
            fleet.totals.repos,
            format_compact(fleet.totals.stdout_tokens)
        ),
        String::new(),
    ];

    if fleet.repos.is_empty() {
        lines.push(
            "_No sessions found in this window. Run `bottledeck sync` or try `--window all`._"
                .to_string(),
        );
        return lines.join("\n");
    }

    lines.push("| Repo | Sessions | Cmds | Worktrees | Med Session Toks | Tool Output Toks | Med Wait | Err % | Top Waste Driver |".to_string());
    lines.push("| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- |".to_string());
    for r in &fleet.repos {
        lines.push(format!(
            "| `{}` | {} | {} | {} | {} | {} | {:.1}s | {:.0}% | {} |",
            r.repo_name,
            r.session_count,
            r.command_count,
            r.worktree_count,
            format_compact(r.median_session_tokens),
            format_compact(r.total_stdout_tokens),
            r.median_tool_wait_s,
            r.error_rate * 100.0,
            r.top_driver
        ));
    }

    if !fleet.systemic_patterns.is_empty() {
        lines.push(String::new());
        lines.push("## Cross-Repo Systemic Patterns".to_string());
        lines.push(String::new());
        lines.push(
            "| Command Template | Repos | Runs | Output Toks | Total Wait | Err % | Noise |"
                .to_string(),
        );
        lines.push("| :--- | ---: | ---: | ---: | ---: | ---: | :--- |".to_string());
        for p in &fleet.systemic_patterns {
            lines.push(format!(
                "| `{}` | {} | {} | {} | {:.1}s | {:.0}% | {} |",
                p.cmd_template,
                p.repo_count,
                p.runs,
                format_compact(p.total_stdout_tokens),
                p.total_wait_s,
                p.error_rate * 100.0,
                p.dominant_noise.as_deref().unwrap_or("-")
            ));
        }
    }

    lines.push(String::new());
    lines.push("_Next: run `bottledeck report --repo <name> --format llm` to generate an LLM-ready infra brief, or `bottledeck` for the interactive TUI._".to_string());
    lines.join("\n")
}

fn push_yaml_opps(lines: &mut Vec<String>, opps: &[Opportunity]) {
    if opps.is_empty() {
        lines.push("  []".to_string());
        return;
    }
    for opp in opps {
        lines.push(format!("  - id: {}", opp.id));
        lines.push(format!("    scope: {}", opp.scope));
        lines.push(format!("    kind: {}", opp.kind));
        lines.push(format!(
            "    fix_target: \"{}\"",
            escape_yaml(&opp.fix_target)
        ));
        lines.push(format!("    target: \"{}\"", escape_yaml(&opp.target)));
        lines.push(format!(
            "    impact: \"{}\"",
            escape_yaml(&opp.impact_summary)
        ));
        lines.push(format!(
            "    harnesses: \"{}\"",
            escape_yaml(&opp.harness_summary)
        ));
        if !opp.trace_proof.is_empty() {
            lines.push("    trace_proof:".to_string());
            for t in &opp.trace_proof {
                lines.push(format!("      - \"{}\"", escape_yaml(t)));
            }
        }
        lines.push("    evidence:".to_string());
        for (ek, ev) in &opp.evidence {
            match ev {
                Value::Array(arr) => {
                    if arr.is_empty() {
                        continue;
                    }
                    lines.push(format!("      {ek}:"));
                    for item in arr {
                        let s = item
                            .as_str()
                            .map(str::to_string)
                            .unwrap_or_else(|| item.to_string());
                        lines.push(format!("        - \"{}\"", escape_yaml(&s)));
                    }
                }
                Value::String(s) => {
                    lines.push(format!("      {ek}: \"{}\"", escape_yaml(s)));
                }
                other => {
                    lines.push(format!("      {ek}: {other}"));
                }
            }
        }
        lines.push(format!(
            "    investigation_hint: \"{}\"",
            escape_yaml(&opp.suggested_action)
        ));
        lines.push(format!(
            "    acceptance_metric: \"{}\"",
            escape_yaml(&opp.acceptance_metric)
        ));
    }
}

pub fn format_diagnosis_prompt(
    report: &RepoReport,
    patterns: &CrossSessionPatternsReport,
) -> String {
    let k = &report.kpis;
    let mut lines = vec![
        format!(
            "# Open-Ended Agent Telemetry Diagnosis Bundle — `{}` ({})",
            report.repo_name, report.window
        ),
        String::new(),
        "## Instructions for the Reviewing Agent".to_string(),
        "Below is deterministic multi-harness telemetry extracted by `bottledeck` across real coding-agent sessions.".to_string(),
        "- **Do not restrict recommendations to canned templates.** Inspect the actual repository files, git history, tooling, docs, tests, MCP servers, and harness configs to identify root causes.".to_string(),
        "- Separate **repository/codebase/tooling fixes** from **agent-harness/runtime overhead** (listed separately below).".to_string(),
        "- Pay attention to **per-harness attribution** (`codex only` vs `claude-code` vs universal) — a single-harness anomaly often points to harness config, prompt/shell environment, or tool ergonomics rather than a repo bug.".to_string(),
        "- Propose concrete, prioritized improvements across *any* lever (architecture, module splits, test speed, CLI ergonomics, docs, MCP schemas, caching/handoff policy, or harness settings), citing exact telemetry numbers and verified repo paths.".to_string(),
        String::new(),
        "## Baseline Snapshot".to_string(),
        format!(
            "- **Sessions:** {} ({} main / {} subagent, {} worktrees, harnesses: {})",
            k.sessions_analyzed,
            patterns.main_sessions,
            patterns.subagent_sessions,
            k.worktrees_seen,
            if k.agents_seen.is_empty() {
                "none".to_string()
            } else {
                k.agents_seen.join(", ")
            }
        ),
        format!(
            "- **Commands:** {} ({} raw stdout / ~{} effective context toks, {:.1}% nonzero exit, {:.1}% CLI rebound)",
            k.total_commands,
            format_compact(k.total_stdout_tokens),
            format_compact(k.total_effective_tokens),
            k.command_error_rate * 100.0,
            k.escape_hatch_rebound_rate * 100.0
        ),
        format!(
            "- **Pareto concentration:** Top 25% main sessions ({}/{}) consume **{:.1}%** of total model tokens ({:.1}x median vs bottom 50%).",
            patterns.pareto.top25_count,
            patterns.pareto.main_sessions,
            patterns.pareto.top25_token_share_pct,
            patterns.pareto.median_multiplier
        ),
    ];
    if let Some(h) = &patterns.handoff_summary {
        lines.push(format!(
            "- **Handoff inflation:** {} handoff sessions avg {} model tokens vs {} fresh ({:.1}x).",
            h.handoff_sessions,
            format_compact(h.handoff_avg_tokens),
            format_compact(h.fresh_avg_tokens),
            h.token_multiplier
        ));
    }
    if let Some(cost) = k.total_cost_usd {
        lines.push(format!(
            "- **Cost:** ${cost:.2} reported ({} sess) | ~${:.2} total estimated across all harnesses ({} total model tokens, {} cache-write, {} thinking)",
            k.cost_sessions,
            k.estimated_cost_usd,
            format_compact(k.total_model_tokens),
            format_compact(k.total_cache_write_tokens),
            format_compact(k.total_thinking_tokens)
        ));
    } else if k.estimated_cost_usd > 0.0 {
        lines.push(format!(
            "- **Estimated API cost:** ~${:.2} ({} total model tokens, {} cache-write, {} thinking)",
            k.estimated_cost_usd,
            format_compact(k.total_model_tokens),
            format_compact(k.total_cache_write_tokens),
            format_compact(k.total_thinking_tokens)
        ));
    }
    lines.push(format!(
        "- **Latency decomposition:** session wall {} (p50 {}) | API wait {} ({} sess{}) | thinking {} | retries {} | tool wall {} vs {} serial ({:.1}x parallel)",
        format_duration_human(k.latency.total_session_wall_s),
        format_duration_human(k.latency.median_session_wall_s),
        format_duration_human(k.latency.total_api_wait_s),
        k.latency.sessions_with_api_timing,
        k.latency
            .avg_ttft_ms
            .map(|t| format!(", avg TTFT {t}ms"))
            .unwrap_or_default(),
        format_duration_human(k.latency.total_thinking_s),
        format_duration_human(k.latency.total_api_retry_s),
        format_duration_human(k.latency.total_tool_wall_s),
        format_duration_human(k.latency.total_tool_serial_s),
        k.latency.tool_parallelism_ratio
    ));
    lines.push(format!(
        "- **Context & outcomes:** {} compaction(s) ({} sess) | peak context {} ({} sess >=80%) | {} aborted ({:.1}%) | {} API errors | +{} / -{} lines",
        k.context_health.total_compactions,
        k.context_health.compacted_sessions,
        k.context_health
            .avg_peak_context_pct
            .map(|p| format!("avg {p:.0}%"))
            .unwrap_or_else(|| "n/a".into()),
        k.context_health.sessions_over_80_pct,
        k.outcomes.aborted_sessions,
        k.outcomes.abort_rate * 100.0,
        k.outcomes.total_api_errors,
        k.outcomes.total_lines_added,
        k.outcomes.total_lines_removed
    ));
    if let Some(notice) = &patterns.harness_mix_shift_notice {
        lines.push(format!("- **Harness Mix Shift:** {notice}"));
    }
    if let Some(notice) = &patterns.branch_behind_notice {
        lines.push(format!("- **Repo Ref Notice:** {notice}"));
    }

    lines.push(String::new());
    lines.push("## 1. Repo & Workflow Signals (Evidence-First)".to_string());
    lines.push(String::new());
    if report.opportunities.is_empty() {
        lines.push("_No high-signal repo anomalies detected in this range._".to_string());
    } else {
        for o in &report.opportunities {
            lines.push(format!("### {} · `{}` — `{}`", o.id, o.kind, o.target));
            lines.push(format!("- **Impact:** {}", o.impact_summary));
            lines.push(format!("- **Harnesses:** {}", o.harness_summary));
            for p in &o.trace_proof {
                lines.push(format!("- **Evidence:** {p}"));
            }
            lines.push(format!(
                "- **Where to look:** {} — {}",
                o.fix_target, o.suggested_action
            ));
            lines.push(String::new());
        }
    }

    if !report.harness_overhead.is_empty() {
        lines.push("## 2. Harness & Runtime Overhead (Separate from Repo Code)".to_string());
        lines.push(String::new());
        for o in &report.harness_overhead {
            lines.push(format!(
                "- **{} · `{}` (`{}`):** {} | **Harnesses:** {}",
                o.id, o.kind, o.target, o.impact_summary, o.harness_summary
            ));
            if let Some(p) = o.trace_proof.first() {
                lines.push(format!("  - Evidence: {p}"));
            }
        }
        lines.push(String::new());
    }

    if !patterns.repeating_sequences.is_empty() {
        lines.push("## 3. Top Repeating Multi-Step Call Sequences Across Sessions".to_string());
        lines.push(String::new());
        lines.push(
            "| Steps | Sessions | Runs | Out Toks | Eff Toks | Wait | Harnesses | Sequence |"
                .to_string(),
        );
        lines.push("| ---: | ---: | ---: | ---: | ---: | ---: | :--- | :--- |".to_string());
        for s in patterns.repeating_sequences.iter().take(8) {
            lines.push(format!(
                "| {} | {}/{} | {} | {} | {} | {:.1}s | {} | `{}` |",
                s.step_count,
                s.sessions,
                s.total_sessions,
                s.occurrences,
                format_compact(s.total_stdout_tokens),
                format_compact(s.total_effective_tokens),
                s.total_wait_s,
                s.harness_summary,
                s.sequence.replace('|', "/")
            ));
        }
        lines.push(String::new());
    }

    if !patterns.tool_trajectories.is_empty() {
        lines.push("## 3b. Unified Tool Trajectories (Shell + Read/Edit/MCP)".to_string());
        lines.push(String::new());
        for s in patterns.tool_trajectories.iter().take(6) {
            lines.push(format!(
                "- {}/{} sessions ({} runs, {:.1}s): `{}` | **Harnesses:** {}",
                s.sessions,
                s.total_sessions,
                s.occurrences,
                s.total_wait_s,
                s.sequence,
                s.harness_summary
            ));
        }
        lines.push(String::new());
    }

    if !patterns.file_edit_churn.is_empty() {
        lines.push("## 3c. File Edit Churn & Rework Hotspots".to_string());
        lines.push(String::new());
        for f in patterns.file_edit_churn.iter().take(6) {
            lines.push(format!(
                "- `{}`: {} edits across {} sessions (max {}x/session, {} edit->fail->edit rework cycles) | **Harnesses:** {}",
                f.target_path, f.edits, f.sessions, f.max_edits_in_session, f.rework_cycles, f.harness_summary
            ));
        }
        lines.push(String::new());
    }

    if !patterns.model_breakdown.is_empty() {
        lines.push("## 3d. Per-Model Breakdown".to_string());
        lines.push(String::new());
        for m in patterns.model_breakdown.iter().take(6) {
            lines.push(format!(
                "- `{}` ({}): {} sess, {} calls, {} toks, cache {}, est ~${:.2}{}",
                m.model,
                m.agent_kind,
                m.sessions,
                m.llm_calls,
                format_compact(m.total_tokens),
                m.cache_hit_rate
                    .map(|v| format!("{:.1}%", v * 100.0))
                    .unwrap_or_else(|| "n/a".into()),
                m.est_cost_usd,
                m.avg_api_wait_s
                    .map(|v| format!(", avg API {v:.1}s"))
                    .unwrap_or_default()
            ));
        }
        lines.push(String::new());
    }

    if !patterns.cold_start_errors.is_empty() {
        lines.push("## 4. Cold-Start (Turns 1–3) Failures".to_string());
        lines.push(String::new());
        for c in patterns.cold_start_errors.iter().take(6) {
            lines.push(format!(
                "- `{}`: {}/{} early fails ({} sessions, {} worktrees) | **Harnesses:** {}",
                c.error_class,
                c.failures_turns_1_3,
                c.total_failures,
                c.sessions,
                c.worktrees,
                c.harness_summary
            ));
        }
        lines.push(String::new());
    }

    if !patterns.temporal_drift.is_empty() {
        lines.push("## 5. Temporal Drift (Early vs Recent Half)".to_string());
        lines.push(String::new());
        for d in patterns.temporal_drift.iter().take(8) {
            lines.push(format!(
                "- `{}` `{}`: {} -> {} runs ({}) | **Harnesses:** {}",
                d.status, d.cmd_family, d.early_runs, d.recent_runs, d.summary, d.harness_summary
            ));
        }
        lines.push(String::new());
    }

    // Finding ids are ranks within this scope, so drill-downs must reuse the same time flags.
    let (window, harness) = match report.window.split_once(" · ") {
        Some((w, h)) => (w, h.strip_suffix(" only")),
        None => (report.window.as_str(), None),
    };
    let mut scope = if crate::config::parse_window_ms(window).is_ok() {
        format!("--window {window}")
    } else {
        format!("<same --since/--until as this report: {window}>")
    };
    if let Some(h) = harness {
        scope.push_str(&format!(" --harness {h}"));
    }
    let r = &report.repo_name;
    lines.push("## Drill-Down Commands".to_string());
    lines.push(
        "Run `bottledeck agent-guide` for the full command map, time scoping and verdict meanings."
            .to_string(),
    );
    lines.push(format!(
        "- Raw traces for a finding (ids are ranks in this report, so keep the scope): `bottledeck inspect <opp-id|h-id> --repo {r} {scope} --no-sync`"
    ));
    lines.push(format!(
        "- Is an issue still happening, session by session? `bottledeck issues --repo {r} --open --no-sync` (stable `kind:target` keys)"
    ));
    lines.push(format!(
        "- After a fix lands: `bottledeck mark <kind:target> --at <fix-commit> --repo {r} --note \"…\"`, then `bottledeck issues <kind:target> --repo {r} --no-sync`"
    ));
    lines.push(format!(
        "- Aggregate before/after a change: `bottledeck diff --since <commit|date> --repo {r} --no-sync`"
    ));
    lines.push(format!(
        "- Cross-session / MCP / sequence views: `bottledeck patterns --repo {r} {scope} --no-sync` | `bottledeck tools --repo {r} {scope} --no-sync` | `bottledeck sequences --repo {r} {scope} --no-sync`"
    ));

    lines.join("\n")
}

pub fn format_repo_report(report: &RepoReport, format: &str) -> String {
    if format == "json" {
        return serde_json::to_string_pretty(report).unwrap_or_default();
    }

    if format == "llm" {
        let k = &report.kpis;
        let agents = k
            .agents_seen
            .iter()
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let mut lines = vec![
            "# Infra Optimization Brief (generated by bottledeck)".to_string(),
            format!("repo: \"{}\"", escape_yaml(&report.repo_name)),
            format!("repo_id: \"{}\"", escape_yaml(&report.repo_id)),
            format!("window: {}", report.window),
            "baseline_kpis:".to_string(),
            format!("  sessions_analyzed: {}", k.sessions_analyzed),
            format!("  worktrees_seen: {}", k.worktrees_seen),
            format!("  agents: [{agents}]"),
            format!("  total_commands: {}", k.total_commands),
            format!("  total_stdout_tokens: {}", k.total_stdout_tokens),
            format!(
                "  total_effective_context_tokens: {}",
                k.total_effective_tokens
            ),
            format!(
                "  median_tokens_per_session: {}",
                k.median_tokens_per_session
            ),
            format!("  p95_tokens_per_session: {}", k.p95_tokens_per_session),
            format!(
                "  cache_hit_rate: {}",
                k.cache_hit_rate
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "null".to_string())
            ),
            format!("  median_tool_wait_s: {}", k.median_tool_wait_s),
            format!("  command_error_rate: {}", k.command_error_rate),
            format!(
                "  cli_adoption_rate: {}",
                k.cli_adoption_rate
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "null".to_string())
            ),
            format!(
                "  escape_hatch_rebound_rate: {}",
                k.escape_hatch_rebound_rate
            ),
            format!("  orientation_tokens: {}", k.orientation_tokens),
            format!(
                "  reported_cost_usd: {}",
                k.total_cost_usd
                    .map(|c| format!("{c:.2}"))
                    .unwrap_or_else(|| "null".to_string())
            ),
            format!("  estimated_cost_usd: {:.2}", k.estimated_cost_usd),
            format!("  total_model_tokens: {}", k.total_model_tokens),
            format!("  total_cache_write_tokens: {}", k.total_cache_write_tokens),
            format!("  total_thinking_tokens: {}", k.total_thinking_tokens),
            format!("  total_api_wait_s: {}", k.latency.total_api_wait_s),
            format!("  total_tool_wall_s: {}", k.latency.total_tool_wall_s),
            format!(
                "  tool_parallelism_ratio: {}",
                k.latency.tool_parallelism_ratio
            ),
            format!(
                "  avg_ttft_ms: {}",
                k.latency
                    .avg_ttft_ms
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "null".to_string())
            ),
            format!(
                "  total_compactions: {}",
                k.context_health.total_compactions
            ),
            format!("  abort_rate: {}", k.outcomes.abort_rate),
            format!(
                "  detected_config: [{}]",
                k.detected_config
                    .iter()
                    .map(|c| format!("\"{}\"", escape_yaml(c)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "top_opportunities:".to_string(),
        ];

        push_yaml_opps(&mut lines, &report.opportunities);
        if !report.harness_overhead.is_empty() {
            lines.push("harness_overhead:".to_string());
            push_yaml_opps(&mut lines, &report.harness_overhead);
        }
        lines.push(format!(
            "drill_down_hint: \"Run 'bottledeck inspect <opp-id|h-id> --repo {}' for redacted traces, or '--format prompt' for an open-ended diagnosis bundle.\"",
            escape_yaml(&report.repo_name)
        ));
        return lines.join("\n");
    }

    let k = &report.kpis;
    let mut lines = vec![
        format!("# Bottledeck — `{}` ({})", report.repo_name, report.window),
        String::new(),
        format!(
            "- **Sessions:** {} ({} worktree(s), agents: {})",
            k.sessions_analyzed,
            k.worktrees_seen,
            if k.agents_seen.is_empty() {
                "none".to_string()
            } else {
                k.agents_seen.join(", ")
            }
        ),
        format!(
            "- **Commands:** {} ({} raw stdout / ~{} effective context tokens, {:.1}% nonzero exit)",
            k.total_commands,
            format_compact(k.total_stdout_tokens),
            format_compact(k.total_effective_tokens),
            k.command_error_rate * 100.0
        ),
        format!(
            "- **Model tokens:** {} total ({} cache-write, {} thinking) | **Uncached+output/sess:** p50 **{}** / p95 **{}** | **Weighted cache hit:** {}",
            format_compact(k.total_model_tokens),
            format_compact(k.total_cache_write_tokens),
            format_compact(k.total_thinking_tokens),
            format_compact(k.median_tokens_per_session),
            format_compact(k.p95_tokens_per_session),
            k.cache_hit_rate
                .map(|v| format!("{:.1}%", v * 100.0))
                .unwrap_or_else(|| "n/a".to_string())
        ),
        format!(
            "- **Latency:** session wall **{}** (p50 {}) | API **{}**{} | thinking **{}** | retries **{}** | tool wall **{}** ({:.1}x parallel, p50 **{}**/sess)",
            format_duration_human(k.latency.total_session_wall_s),
            format_duration_human(k.latency.median_session_wall_s),
            format_duration_human(k.latency.total_api_wait_s),
            k.latency
                .avg_ttft_ms
                .map(|t| format!(", TTFT {t}ms"))
                .unwrap_or_default(),
            format_duration_human(k.latency.total_thinking_s),
            format_duration_human(k.latency.total_api_retry_s),
            format_duration_human(k.latency.total_tool_wall_s),
            k.latency.tool_parallelism_ratio,
            format_duration_human(k.median_tool_wait_s)
        ),
        format!(
            "- **Cost & outcomes:** est. **~${:.2}**{} | compactions **{}** ({} sess >=80% ctx) | aborts **{}** ({:.1}%) | API errs **{}**",
            k.estimated_cost_usd,
            k.total_cost_usd
                .map(|c| format!(" (${c:.2} reported across {} sess)", k.cost_sessions))
                .unwrap_or_default(),
            k.context_health.total_compactions,
            k.context_health.sessions_over_80_pct,
            k.outcomes.aborted_sessions,
            k.outcomes.abort_rate * 100.0,
            k.outcomes.total_api_errors
        ),
        format!(
            "- **Repo CLI adoption:** {} | **Escape-hatch rebound:** {:.1}% | **Orientation tax:** {} tokens",
            k.cli_adoption_rate
                .map(|v| format!("{:.0}%", v * 100.0))
                .unwrap_or_else(|| "n/a".to_string()),
            k.escape_hatch_rebound_rate * 100.0,
            format_compact(k.orientation_tokens)
        ),
        String::new(),
        "## Repo & Workflow Signals".to_string(),
        String::new(),
    ];

    let push_md_opps = |out: &mut Vec<String>, opps: &[Opportunity]| {
        for opp in opps {
            out.push(format!(
                "### {} · `{}` — `{}` *(area: {})*",
                opp.id, opp.kind, opp.target, opp.fix_target
            ));
            out.push(format!("- **Impact:** {}", opp.impact_summary));
            out.push(format!("- **Harnesses:** {}", opp.harness_summary));
            for tp in &opp.trace_proof {
                out.push(format!("- **Evidence:** {tp}"));
            }
            out.push(format!(
                "- **Investigation hint:** {}",
                opp.suggested_action
            ));
            out.push(format!("- **Target metric:** `{}`", opp.acceptance_metric));
            out.push(String::new());
        }
    };

    if report.opportunities.is_empty() {
        lines.push("_No high-friction repo signals detected in this window._".to_string());
        lines.push(String::new());
    } else {
        push_md_opps(&mut lines, &report.opportunities);
    }

    if !report.harness_overhead.is_empty() {
        lines.push("## Harness & Runtime Overhead".to_string());
        lines.push(String::new());
        push_md_opps(&mut lines, &report.harness_overhead);
    }

    if !report.top_commands.is_empty() {
        lines.push("## Top Commands by Output Tokens".to_string());
        lines.push(String::new());
        lines.push("| Command Template | Category | Runs | p50 Out Toks | Total Out Toks | p50/p95 Wait | Err % | Harnesses | Noise |".to_string());
        lines.push("| :--- | :--- | ---: | ---: | ---: | :---: | ---: | :--- | :--- |".to_string());
        for c in &report.top_commands {
            let p_wait = match c.p95_wait_s {
                Some(p95) => format!("{:.1}s/{p95:.1}s", c.p50_wait_s),
                None => format!("{:.1}s/-", c.p50_wait_s),
            };
            lines.push(format!(
                "| `{}` | {} | {} | {} | {} | {} | {:.0}% | {} | {} |",
                c.cmd_template,
                c.category,
                c.runs,
                format_compact(c.p50_stdout_tokens),
                format_compact(c.total_stdout_tokens),
                p_wait,
                c.error_rate * 100.0,
                c.harness_summary,
                c.dominant_noise.as_deref().unwrap_or("-")
            ));
        }
    }

    lines.join("\n")
}

pub fn format_diff_report(diff: &DiffReport, format: &str) -> String {
    if format == "json" {
        return serde_json::to_string_pretty(diff).unwrap_or_default();
    }
    let fmt_pct = |v: Option<f64>| match v {
        Some(n) if n > 0.0 => format!("+{n:.1}%"),
        Some(n) => format!("{n:.1}%"),
        None => "n/a".to_string(),
    };
    let mut lines = vec![
        format!("# Bottledeck — Before/After Diff for `{}`", diff.repo_name),
        String::new(),
        format!(
            "- **Split point:** {} ({})",
            diff.since,
            if diff.matched_window {
                "matched pre/post window"
            } else {
                "all-before fallback"
            }
        ),
        format!("- **Verdict:** `{}`", diff.verdict),
        String::new(),
        "| Metric | Before | After | Delta |".to_string(),
        "| :--- | ---: | ---: | ---: |".to_string(),
        format!(
            "| Sessions | {} | {} | - |",
            diff.before.sessions, diff.after.sessions
        ),
        format!(
            "| Commands | {} | {} | - |",
            diff.before.commands, diff.after.commands
        ),
        format!(
            "| Median session tokens | {} | {} | {} |",
            format_compact(diff.before.median_session_tokens),
            format_compact(diff.after.median_session_tokens),
            fmt_pct(diff.deltas.median_session_tokens_pct)
        ),
        format!(
            "| Median tool wait | {:.1}s | {:.1}s | {} |",
            diff.before.median_tool_wait_s,
            diff.after.median_tool_wait_s,
            fmt_pct(diff.deltas.median_tool_wait_pct)
        ),
        format!(
            "| Avg stdout tokens / cmd | {} | {} | {} |",
            format_compact(diff.before.avg_stdout_tokens_per_cmd),
            format_compact(diff.after.avg_stdout_tokens_per_cmd),
            fmt_pct(diff.deltas.avg_stdout_tokens_per_cmd_pct)
        ),
        format!(
            "| Command error rate | {:.1}% | {:.1}% | - |",
            diff.before.error_rate * 100.0,
            diff.after.error_rate * 100.0
        ),
        format!(
            "| Escape-hatch rebound | {:.1}% | {:.1}% | - |",
            diff.before.rebound_rate * 100.0,
            diff.after.rebound_rate * 100.0
        ),
        format!(
            "| Estimated cost | ${:.2} | ${:.2} | - |",
            diff.before.estimated_cost_usd, diff.after.estimated_cost_usd
        ),
        format!(
            "| Weighted cache hit | {} | {} | - |",
            diff.before
                .cache_hit_rate
                .map(|v| format!("{:.1}%", v * 100.0))
                .unwrap_or_else(|| "n/a".into()),
            diff.after
                .cache_hit_rate
                .map(|v| format!("{:.1}%", v * 100.0))
                .unwrap_or_else(|| "n/a".into())
        ),
        format!(
            "| Session abort rate | {:.1}% | {:.1}% | - |",
            diff.before.abort_rate * 100.0,
            diff.after.abort_rate * 100.0
        ),
    ];

    if !diff.by_harness.is_empty() {
        lines.push(String::new());
        lines.push("## Per-Harness Stratified Deltas".to_string());
        lines.push(String::new());
        lines.push(
            "| Harness | Sess (B -> A) | Cmds (B -> A) | Med Toks (B -> A) | Avg Out/Cmd (B -> A) | Err% (B -> A) |"
                .to_string(),
        );
        lines.push("| :--- | :---: | :---: | :---: | :---: | :---: |".to_string());
        for h in &diff.by_harness {
            lines.push(format!(
                "| `{}` | {} -> {} | {} -> {} | {} -> {} | {} -> {} | {:.1}% -> {:.1}% |",
                h.agent_kind,
                h.before_sessions,
                h.after_sessions,
                h.before_commands,
                h.after_commands,
                format_compact(h.before_median_tokens),
                format_compact(h.after_median_tokens),
                format_compact(h.before_avg_stdout_tokens),
                format_compact(h.after_avg_stdout_tokens),
                h.before_error_rate * 100.0,
                h.after_error_rate * 100.0
            ));
        }
    }

    if !diff.guardrails.is_empty() {
        lines.push(String::new());
        lines.push("## Guardrails".to_string());
        lines.push(String::new());
        for g in &diff.guardrails {
            lines.push(format!("- {g}"));
        }
    }

    if !diff.command_deltas.is_empty() {
        lines.push(String::new());
        lines.push("## Per-Command Output Deltas".to_string());
        lines.push(String::new());
        lines.push("| Command Template | Before p50 | After p50 | Delta |".to_string());
        lines.push("| :--- | ---: | ---: | ---: |".to_string());
        for c in &diff.command_deltas {
            lines.push(format!(
                "| `{}` | {} | {} | {} |",
                c.cmd_template,
                format_compact(c.before_p50_tokens),
                format_compact(c.after_p50_tokens),
                fmt_pct(c.delta_pct)
            ));
        }
    }

    lines.join("\n")
}

pub fn format_inspect_report(res: &InspectResult, format: &str) -> String {
    if format == "json" {
        return serde_json::to_string_pretty(res).unwrap_or_default();
    }
    let mut lines = vec![
        format!("# Inspect `{}` in `{}`", res.query, res.repo_name),
        String::new(),
        format!(
            "Matched **{}** span(s); showing top **{}**:",
            res.total_matching_spans,
            res.samples.len()
        ),
        String::new(),
    ];

    if let Some(opp) = &res.opportunity {
        lines.push(format!("> **{}**: {}", opp.kind, opp.impact_summary));
        lines.push(format!("> **Harnesses**: {}", opp.harness_summary));
        lines.push(format!("> **Action**: {}", opp.suggested_action));
        lines.push(String::new());
    }

    let ctx = &res.context;
    if !ctx.shapes.is_empty() {
        lines.push(format!(
            "### Shapes ({} sessions with a matching call)",
            ctx.affected_sessions
        ));
        lines.push(
            "One finding, several behaviours; fix the largest one that needs a fix (`-` = no fix needed)."
                .into(),
        );
        lines.push(String::new());
        for sh in &ctx.shapes {
            let minor = crate::context::is_minor_shape(&sh.key);
            lines.push(format!(
                "- **{}**{} — {} calls in {} sessions: {}.{}",
                sh.label,
                if minor { " (-)" } else { "" },
                sh.calls,
                sh.sessions,
                sh.description,
                if minor {
                    String::new()
                } else {
                    format!(" Fix: {}", sh.fix)
                }
            ));
        }
        lines.push(String::new());
    }

    for (i, s) in res.samples.iter().enumerate() {
        lines.push(format!(
            "### Sample {} ({}, {}, turn {})",
            i + 1,
            s.started_at,
            s.agent_kind,
            s.turn_idx
        ));
        lines.push(format!("- **Command:** `{}`", s.raw_redacted));
        lines.push(format!(
            "- **Result:** exit={} | stdout={} toks ({}) | wait={}",
            s.exit_code.map_or("n/a".into(), |c| c.to_string()),
            format_compact(s.stdout_tokens),
            s.noise_kind.as_deref().unwrap_or("clean"),
            s.duration_ms
                .map(|d| format!("{:.2}s", d as f64 / 1000.0))
                .unwrap_or_else(|| "n/a".into())
        ));
        if let Some(err) = &s.stderr_preview {
            lines.push(format!("- **Stderr:** `{err}`"));
        }
        if let Some(nx) = &s.next_cmd {
            lines.push(format!("- **Immediate next cmd:** `{nx}`"));
        }
        lines.push(String::new());
    }

    lines.join("\n")
}
