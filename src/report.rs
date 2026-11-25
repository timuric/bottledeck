use crate::analyze::{
    BypassReport, CommandStat, DiffReport, ErrorCluster, FleetReport, InspectResult, Opportunity,
    RepoReport, format_compact,
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
        "| Command Template | Cat | CLI | Runs | Errs | Err% | Piped | Top Pipe | p50 Out | Eff Toks | Total Wait | Harnesses | Noise |".to_string(),
        "| :--- | :--- | :---: | ---: | ---: | ---: | ---: | :--- | ---: | ---: | ---: | :--- | :--- |".to_string(),
    ];
    for c in cmds {
        lines.push(format!(
            "| `{}` | {} | {} | {} | {} | {:.0}% | {} | {} | {} | {} | {:.1}s | {} | {} |",
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

    lines.push("## Drill-Down Commands".to_string());
    lines.push(format!(
        "- Inspect raw traces for any finding: `bottledeck inspect <opp-id|h-id> --repo {} --no-sync`",
        report.repo_name
    ));
    lines.push(format!(
        "- Verify whether an issue persists after a fix commit: `bottledeck report --repo {} --since <commit-sha> --no-sync`",
        report.repo_name
    ));
    lines.push(format!(
        "- Full cross-session / MCP / sequence views: `bottledeck patterns --repo {} --no-sync` | `bottledeck tools --repo {} --no-sync` | `bottledeck sequences --repo {} --no-sync`",
        report.repo_name, report.repo_name, report.repo_name
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
            "- **Uncached+output session tokens:** p50 **{}** / p95 **{}** | **Weighted cache hit:** {}",
            format_compact(k.median_tokens_per_session),
            format_compact(k.p95_tokens_per_session),
            k.cache_hit_rate
                .map(|v| format!("{:.1}%", v * 100.0))
                .unwrap_or_else(|| "n/a".to_string())
        ),
        format!(
            "- **Tool wait:** p50 **{:.1}s**/session ({:.1}s total)",
            k.median_tool_wait_s, k.total_tool_wait_s
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
        lines.push("| Command Template | Category | Runs | p50 Out Toks | Total Out Toks | p50 Wait | Err % | Harnesses | Noise |".to_string());
        lines.push("| :--- | :--- | ---: | ---: | ---: | ---: | ---: | :--- | :--- |".to_string());
        for c in &report.top_commands {
            lines.push(format!(
                "| `{}` | {} | {} | {} | {} | {:.1}s | {:.0}% | {} | {} |",
                c.cmd_template,
                c.category,
                c.runs,
                format_compact(c.p50_stdout_tokens),
                format_compact(c.total_stdout_tokens),
                c.p50_wait_s,
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
        format!("- **Split point:** {}", diff.since),
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
    ];

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
