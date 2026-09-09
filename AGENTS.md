# CLAUDE.md — sbx

## Environment

- LSP and `cargo-callgraph` are DEFERRED tools: absent from the
  tool list until loaded. Load them before use, e.g.
  `ToolSearch("select:LSP")`. A tool you cannot see in the list
  is not a tool that is unavailable here.
- A fresh rust-analyzer is spawned by the first LSP call and
  answers nothing for about a minute. "not indexed" means wait
  and re-probe; it never means the LSP is broken.
- These questions REQUIRE the LSP, `rg` cannot answer them: who
  calls X, is X dead, has X another impl, what does this symbol
  resolve to. `rg` locates a candidate (5ms) — blind to
  re-exports and aliases, and it matches comments. Use it to
  find, never to conclude.
- LSP call-hierarchy positions point at the start of the item's
  block, doc-comment included, not at the signature. Cross-check
  with `grep -n` before citing a line.
- `cargo-callgraph` MCP answers the one question the LSP cannot:
  everything that reaches X, at ≥2 hops. Use
  `traverse_incoming`/`traverse_outgoing` with depth ≤3 — one call
  replaces a chain of `incomingCalls`. Confirm a hop at the LSP
  before acting on it, and never dump the full JSON (10MB+).
- Do NOT use `find_dead_code`: it reports live functions as
  orphaned, and `-D warnings` already fails the build on code that
  is really dead. `find_call_paths` returns less than a single
  `incomingCalls` — prefer the traversals.
- Free functions are stored qualified
  (`proc_policy::shebang_interpreter`), but impl METHODS are
  stored BARE (`matches`, never `ProcRule::matches`) and collide
  across types: a qualified pattern returning nothing proves
  nothing — re-probe with the bare name.
- The graph caches on Cargo.toml's mtime alone, so it is normally
  stale and line numbers drift, per file. `reload: true` rebuilds
  nothing and costs seconds — prefer it to doubting the answer.
- Golden rule: never assume, ALWAYS verify!

## Development rules

- Before writing any new code, ALWAYS review what already exists in the codebase in order to produce clean, optimized code. If necessary, refactor before creating code to avoid code duplication.
- In comments and documentation, never include test results or personal thoughts: write real comments and professional documentation.
- After any code change, ALWAYS check the state of the documentation (update/keep it consistent if needed). The concrete guard is `src/docs_coverage.rs`: it asserts every CLI verb has a reference page, every config field a launch accepts is named in the guide, and every shipped app profile appears in the catalogue. When you add a verb, a config field, or a profile, the failing test will tell you which page is missing — write the prose, do not weaken the guard. The same holds inside the code: when you rename or move a symbol, carry its doc references with it, because `mise run rustdoc` denies rustdoc warnings and a ``[`symbol`]`` that no longer resolves fails the build. Fix the reference; never silence it with `#[allow(rustdoc::broken_intra_doc_links)]`, which rustdoc itself offers in the error.
- When adding a verb, argument, or option, ALWAYS verify the autocompletion (`src/cli/completion.rs` and `tests/completion.rs`) still works for the new surface — completion is auto-derived from the CLI definition but the tests exercise the emitted scripts and the `__complete` oracle on every code path, so a new entry must not break the tree walk, the bash/zsh drives, or the help/completion parity.
- Every command and subcommand MUST have a `Page` in `src/help.rs` (synopsis, one-line summary, option list, prose). That table is the single source of truth: `--help`, the help listings, the error-message synopses, and the completion surface all derive from it. A new command without a page breaks the help/completion parity and the dispatcher's page-resolution tests.

## Tests

- ALWAYS prefer targeted tests over the full suite, which is very long. Run only the filter relevant to the change. This crate is a `[[bin]]` with no library target, so `cargo test --lib` fails with `no library targets found` — use `cargo test --bins <filter>` for the unit tests (e.g. `cargo test --bins version::`), `cargo test --test <file> <filter>` for an integration suite, or `cargo test --doc` for doctests.
- NEVER run `mise run ci`, or a whole `cargo test`, on your own initiative. The full suite is the maintainer's to run, and when. After a change, run the three cheap gates on their own — `mise run fmt`, `mise run lint`, `mise run rustdoc`, together around thirty seconds, and the latter two deny warnings — plus the targeted filter for what the change touched. Then report which filters were exercised and which were not, rather than implying the suite passed.
- `mise run ci` chains those three gates with `test` and is the local reproduction of `.github/workflows/ci.yml`. It must pass before a push; whether to run it is the maintainer's call, never the assistant's.

## Authorization

- This file must NOT be modified without explicit authorization.
