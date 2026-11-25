# Contributing to bottledeck

Thanks for helping improve `bottledeck`. This project aims to stay fast, single-binary, offline-first, and easy to reason about.

## Prerequisites

- Rust stable toolchain (Edition 2024) with `rustfmt` and `clippy`
- macOS or Linux (`sqlite3` is bundled via `rusqlite`, so no system SQLite headers are required)

## Development Workflow

```sh
# Inspect detected local transcript roots
cargo run -- doctor

# Launch the TUI against your local ledger
cargo run -- tui

# Run the exact checks enforced by CI (.github/workflows/ci.yml)
cargo fmt --all -- --check
cargo test --locked
cargo clippy --all-targets --locked
```

## Codebase Map

| Path | Responsibility |
| :--- | :--- |
| `src/main.rs` | CLI definitions (`clap`) and command dispatch |
| `src/config.rs` | State paths, auto-discovered harness roots, time windows, env vars |
| `src/adapters/` | Read-only parsers for Claude Code, Codex, Antigravity, Kimi, and `spans.jsonl` |
| `src/ingest.rs` | Incremental file-watermark scanning and ledger writes |
| `src/db.rs` | SQLite WAL schema and migrations |
| `src/workspace.rs` | `git-common-dir` & remote URL repo normalization across worktrees |
| `src/shell.rs` | POSIX shell command parsing, templating, noise classification, secret redaction |
| `src/analyze.rs` | Repo/fleet aggregation, bottleneck detectors, `inspect`, and `diff` |
| `src/patterns.rs` | Cross-session motifs, repeating sequences, Pareto concentration, harness comparison |
| `src/report.rs` | Markdown, YAML (`llm`), diagnosis `prompt`, and JSON renderers |
| `src/tui.rs` | Interactive Ratatui dashboard |
| `src/wrap.rs` | Optional fail-open `bottledeck wrap` command recorder |
| `src/update.rs` | Self-updater with SHA256 verification and 24h cached release check |

## Adding a Harness Adapter

1. Add a parser under `src/adapters/<harness>.rs` and expose it in `src/adapters/mod.rs`.
2. Add default discovery roots and a `BOTTLEDECK_<HARNESS>_DIR` override in `src/config.rs`.
3. Wire ingestion into `src/ingest.rs` and status reporting into `bottledeck doctor` (`src/main.rs`).
4. Ensure all extracted commands and stderr previews pass through `crate::shell::redact_secrets`.
5. Add unit/integration tests using **small synthetic transcript fixtures** (never commit real personal transcripts or private repo paths).

## Pull Request Checklist

- Keep changes focused and offline-first (no telemetry or network calls outside `src/update.rs`).
- Never commit personal transcripts, credentials, or local state files.
- Run `cargo fmt --all -- --check`, `cargo clippy --all-targets --locked`, and `cargo test --locked` before opening a PR.
- Update `README.md` if you add a CLI subcommand, flag, TUI shortcut, harness adapter, or `BOTTLEDECK_*` env var.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
