# CLAUDE.md — sbx

## Environment

- A Rust LSP (rust-analyzer) is available for code analysis.
- Golden rule: never assume, ALWAYS verify!

## Development rules

- Before writing any new code, ALWAYS review what already exists in the codebase in order to produce clean, optimized code. If necessary, refactor before creating code to avoid code duplication.
- In comments and documentation, never include test results or personal thoughts: write real comments and professional documentation.
- After any code change, ALWAYS check the state of the documentation (update/keep it consistent if needed). The concrete guard is `src/docs_coverage.rs`: it asserts every CLI verb has a reference page, every config field a launch accepts is named in the guide, and every shipped app profile appears in the catalogue. When you add a verb, a config field, or a profile, the failing test will tell you which page is missing — write the prose, do not weaken the guard.
- When adding a verb, argument, or option, ALWAYS verify the autocompletion (`src/cli/completion.rs` and `tests/completion.rs`) still works for the new surface — completion is auto-derived from the CLI definition but the tests exercise the emitted scripts and the `__complete` oracle on every code path, so a new entry must not break the tree walk, the bash/zsh drives, or the help/completion parity.
- Every command and subcommand MUST have a `Page` in `src/help.rs` (synopsis, one-line summary, option list, prose). That table is the single source of truth: `--help`, the help listings, the error-message synopses, and the completion surface all derive from it. A new command without a page breaks the help/completion parity and the dispatcher's page-resolution tests.

## Tests

- ALWAYS prefer targeted tests over the full suite, which is very long. Run only the test binary or filter relevant to the change (e.g. `cargo test --test <file> <filter>`, `cargo test --lib <module>::<test>`, or `cargo test --doc` for doctests). Only run the whole `cargo test` when the change has cross-cutting impact that demands it.
- Before any push (and at the end of a task), ALWAYS run `mise run ci` — it chains `fmt` + `lint` + `rustdoc` + `test` and is the local reproduction of `.github/workflows/ci.yml`. If `mise run ci` passes locally, CI passes; if it fails here, push nothing and fix it first.

## Authorization

- This file must NOT be modified without explicit authorization.
