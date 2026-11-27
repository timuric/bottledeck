# bottledeck: agent guide

bottledeck reads local coding-agent transcripts (Claude Code, Codex, Antigravity, Kimi)
into a SQLite ledger and reports where agent sessions lose tokens, time and turns.
Everything is local and read-only, except `bottledeck mark`, which records fix markers.

## Five rules

1. **Sync once, then pass `--no-sync`.** Every query command re-syncs transcripts first
   unless given `--no-sync`. Run `bottledeck sync` once, then add `--no-sync` to every
   query in the same task.
2. **Name the repo.** `--repo` defaults to `.` (the git repo of the current directory).
   From anywhere else, list repos with `bottledeck repos --no-sync --format json` and pass
   `repo_name` (e.g. `owner/name`) or `repo_id`. Paths (`/…`, `~/…`, `./…`) also work. A
   bare substring picks the most active matching repo, so check the name in the output
   header. Worktrees roll up into their repo.
3. **Set the time scope on purpose.** The default window is 14d (30d for `issues`). See
   "Time scoping".
4. **Read `md`, parse `json`.** Every query takes `--format md|json`. `report --repo X`
   also takes `llm` (compact YAML brief) and `prompt` (a diagnosis bundle for a reviewing
   agent).
5. **Finding ids are not stable.** `opp-N` (repo/workflow findings) and `h-N` (harness
   overhead) are ranks within one report. Pass `inspect` the same `--repo` and time flags
   as the `report` that produced the id. To follow an issue over time, use its stable key
   `kind:target` from `bottledeck issues`.

## Time scoping

These flags work on report, inspect, issues, commands, errors, bypasses, patterns,
sessions, sequences, tools and repos:

| Flag | Meaning |
| :--- | :--- |
| `--window 24h` / `7d` / `2w` / `all` | trailing window (units s m h d w) |
| `--since X` | sessions that started at or after X |
| `--until X` | sessions that started strictly before X |

X can be an ISO date (`2026-11-01`), an RFC 3339 timestamp, a relative duration (`48h`
means 48 hours ago), or a **git commit/ref** (`abc1234`, `v0.4.0`, `HEAD~5`), which
resolves to its commit time in the repo's worktrees.
`--since` without `--window` means "everything after X", and combining both bounds gives
a slice: `--since v0.3.0 --until v0.4.0`. Sessions are bucketed by start time, so a
session that began before a fix counts as "before" even if it ran past it.

## Which command answers which question

| Question | Command |
| :--- | :--- |
| Which repos have data? | `repos --format json` |
| What costs agents most here? | `report --repo R` (`--format prompt` for a full bundle) |
| Show raw evidence for a finding | `inspect opp-3 --repo R <same time flags>` (also takes a command template or an issue key) |
| Did my fix work? Is the issue still happening? | `issues --repo R` / `issues <key> --repo R` |
| Record when a fix landed | `mark <key> --at <commit> --note "…" --repo R` |
| Aggregate before/after around a change | `diff --since <commit or date> --repo R` |
| Most expensive / slowest / failing commands | `commands --repo R --sort effective/tokens/wait/runs/errors/pipes` |
| Recurring command errors | `errors --repo R` |
| MCP and other non-shell tool failures, big outputs | `tools --repo R --sort errors/calls/bytes/truncated [--mcp-only]` |
| Heaviest sessions | `sessions --repo R --sort tokens/wait/stdout/errors` |
| Repeated multi-step loops across sessions | `sequences --repo R --sort impact/sessions/len/tokens/wait` |
| Drift, harness differences, cold starts, bursts | `patterns --repo R` |
| Agents bypassing the repo CLI (scraping state, stripping output, help lookups) | `bypasses --repo R` |
| Cross-repo overview | `report --all` |

`commands --category` takes exploration, vcs_ci, repo_task, build_test, polling,
package_mgr or other.

## Workflows

**Find what's costing agents in a repo.**
```
bottledeck sync
bottledeck report --repo R --window 30d --no-sync
bottledeck inspect opp-1 --repo R --window 30d --no-sync
```
Then read the files and commands named in "Where to look" before proposing a fix.

**Check whether a fix worked (per session).**
```
bottledeck issues --repo R --no-sync --open                  # what still needs attention
bottledeck mark "<kind:target>" --at <fix-commit> --repo R --note "what changed"
bottledeck issues "<kind:target>" --repo R --no-sync         # verdict + session strip
```
Use `mark --all --at <ref>` for a change that affects every issue, such as a harness
upgrade. Markers are written to the ledger: list them with `mark --list` and undo one
with `mark --remove <id>`. Don't add markers unless the user asked for it.

**Compare before and after a change (aggregate).**
`diff --since <ref>` compares sessions after the ref with a matched window of the same
length before it. It covers session-level and shell-command metrics, not MCP/tool errors.
For any other view, run the command twice: `--until <ref>` vs `--since <ref>`. For example,
`tools --mcp-only --since <ref>` against the same command with `--until <ref>`. Each prints a
totals line, so you can compare error rates without summing rows. Add the same
`--window`/`--since` lower bound to the "before" run when you want equal-length windows.
Check the harness mix on both sides: a "fix" can just be one harness disappearing.

**Rank waste across tokens and time.**
`report` findings mix units (tokens, wait, call counts). For a ranking, use
`commands --sort effective` for token cost and `commands --sort wait` for time, then map
the top rows back to findings.

**Investigate one command, tool or file.**
`inspect "<command template>" --repo R`, `commands --repo R --sort errors`,
`tools --repo R --sort truncated`.

## Reading the output

- **opp-N vs h-N.** opp findings are things the repo can fix (docs, CLI, file layout,
  tests). h findings are harness or runtime overhead (cache misses, context pressure,
  latency).
- **Harness attribution.** "codex only" or "claude-code only" points at harness config,
  prompts or tool ergonomics, not the repo.
- **Effective tokens** estimate what tool output costs while it stays in context.
  Raw stdout tokens are the output size alone.
- **`issues` verdicts.** With a fix marker: GONE (no hits after the fix), IMPROVED,
  REGRESSED, UNCHANGED, WAITING (too few sessions since the fix; the reason says how many
  more are needed). Without a marker: QUIET (clean streak of ≥3 sessions), ACTIVE, NEW.
  Each row has a session strip (`·` not exposed, `○` exposed and clean, `●` affected,
  `|` marker), plus per-harness and per-harness-version rates.
- **`sessions`** rows start with a short session id (first 10 chars), the same id
  `issues` prints in "Last seen".
- **Small samples.** Verdicts use exact binomial tests (p ≤ 0.05). Treat anything with
  fewer than about 3 sessions on either side as anecdotal and say so.
- `issues` lists aggregate-only kinds (cache efficiency, latency, handoff bloat)
  separately because they can't be scored per session. Use `report` and `diff` for those.

## Gotchas

- When an issue query matches several keys, the CLI lists them. Rerun it with the full key.
- If you get "No telemetry found for repo", run `bottledeck repos --no-sync` and pass a
  listed name. Fixture and temp repos are hidden from `report --all` unless you add
  `--include-temp`.
- Antigravity and Kimi transcripts don't record a harness version.
- Traces from `inspect` are redacted but still come from real sessions. Quote them
  sparingly.
- `bottledeck doctor` shows transcript roots and the ledger path. `sync --force`
  re-ingests everything (slow; only needed after an upgrade that changes parsing).
