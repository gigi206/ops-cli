# Deep audit of `sbx` — glm-5.3-flash

- Date: 2026-09-08
- Scope: local checkout, branch `ops-v2`, HEAD `e8723ae` (`test(trust): the re-trust inventory counts the proc-learn write it gained`)
- Volume: `src/` 253,633 lines (237 `.rs` files), `tests/` 28,140 lines (27 files), `build.rs` 261 lines — total Rust ≈ 282,000 lines
- Method: multi-angle static analysis (CLI/help parity, `unwrap`/`panic` in production, 245 `unsafe` sites, discarded errors `let _ = fs::…`, parsing of untrusted network inputs, concurrency park/join/accept) + **cross-check of the previous audit** (`audit_spark_13.md`, untracked at the repo root).
- Environment constraints: no Rust toolchain (`cargo` missing, mise untrusted → `mise run lint` unavailable to the agent), no `tar`, no python. Clippy not run; the glibc/tar empirical checks could not execute — the corresponding items are classified "plausible, unconfirmed". No code was modified.

## 🐛 Confirmed bugs

### 1. `src/sandbox/mise.rs:217-231` — `stage_files()` crashes on mise files in a subdirectory

`mise_inputs_for` (`src/trust.rs:104-112`) produces **slash-containing relative names** — its own test asserts it (`".config/mise"`, `".mise"`, `"mise"` at `src/trust.rs:948`). But `stage_files` does `stage_dir.join(name)` for both the temp file and the destination, never creating parent directories:

```rust
let src = stage_dir.join(name);                          // name = ".config/mise/config.toml"
let tmp = stage_dir.join(format!("{name}.{}.tmp", std::process::id()));  // slash included
OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
std::fs::rename(&tmp, &src)?;                            // ENOENT: no parent created
```

Consequence: `ENOENT` → launch aborted for any project with `.config/mise/config.toml` (a form mise itself documents and `mise_files_for` discovers). Aggravating detail: `create(true).truncate(true)` follows a pre-existing symlink inside the stage dir (no `create_new`/`O_NOFOLLOW`), and there is no `fsync`.

**Suggested fix**: create the parents (`DirBuilder` recursive per name component), temp file **without slashes** (`name.replace('/', "_")` + pid), and `create_new` or `O_NOFOLLOW`.

### 2. `src/config/mod.rs:3531` + `src/sandbox/broker.rs:1361` — `tcp://[::1]:port` endpoints are born dead

`parse_tcp_endpoint` keeps the host verbatim:

```rust
let (host, port) = endpoint.rsplit_once(':')...;
Ok(BrokerTarget::Tcp { host: host.to_string(), .. })   // "[::1]" kept as-is
```

Then `TcpStream::connect((host.as_str(), *port))` (broker.rs:1361) never strips the brackets — both glibc and musl return `EAI_NONAME` for a bracketed host (brackets are URL syntax, not a hostname). The example `tcp://[::1]:22` is **quoted in the official completion** (`src/cli/completion.rs:2021`). Aggravating: `Display` (`src/config/mod.rs:428`) re-serializes the brackets, so the reconnect error message shows a target that looks right yet can never work — the round-trip hides the bug.

The `getaddrinfo` empirical check was impossible on this machine (no compiler); classification: "confirmed by reading, to be re-proven by test".

**Suggested fix**: strip `[...]` in `parse_tcp_endpoint` + a `tcp://[::1]:22` round-trip test.

### 3. `src/config/load.rs:706-728` — the global config layer fails open

`read_layer`: any `Err` other than NotFound → warning + layer dropped:

```rust
Err(e) if e.kind() == io::ErrorKind::NotFound => None,
Err(e) => { warnings.push(format!("ignoring {e}")); None }
```

For the **project** layer the direction is safe (`read_project` falls back to `TrustState::Untrusted`). But for the **global** layer (`read_global`, line 443): `EMFILE`/`ENOSPC`/`EACCES`/`EINTR` on `~/.config/sbx/sbx.toml` where the user pinned `network = "none"` → the launch proceeds with the default posture, one more warning lost in the noise. This is the only spot in the trust chain where a read failure *widens* permissions.

**Suggested fix**: distinguish NotFound from transient errors → fail closed (hard `Err`) for the global layer only.

## ❌ False positive in the previous audit (spark-1.3)

**`src/storage.rs:801` + `:854` — "symlinks never detected" is wrong.** `DirEntry::metadata()` does **not** follow symlinks (that is `fs::metadata(path)`): the `census()`/`copy_tree()` code is correct, `is_symlink()` is reachable, and `copy_tree` recreates links via `read_link` (`src/storage.rs:857-859`). Spark-1.3's priority item 1 (and the claim that `copy_tree` exfiltrates `/etc/shadow`) is moot. Note: `first`/`skip` (lines 794-798) applies to the root directory only, which matches the doc comment.

## ⚠️ Plausible, unconfirmed (missing tooling)

- **`bounded_unpack` / tar symlinks** (`src/sandbox/prebuilt.rs:229`): the script feeds an arbitrary tar stream into `tar -x --no-same-permissions --no-same-owner` — `--no-same-owner` is present, but **no** symlink protection is visible at the script level (recent GNU tar refuses writing through a member symlink, but the exact guarantee depends on the nix host's tar version). Not testable here (no tar). The invariant "no write through a member symlink" should be proven by a dedicated test rather than assumed. A volume ceiling is present (`MAX_UNPACKED_BYTES = 8 GiB`, `head -c`).
- **Park without deadline** (`src/sandbox/control/mod.rs:173`): `None => rx.recv()` — every `ask` request without a timeout parks a proxy thread until a human decides; the cap (immediate refusal beyond it, line 129) contains the blow-up and the behaviour is documented as intentional. Verified: not a bug, a decision. Contradicts spark-1.3's "leak" classification.
- **`Drop { join() }` on the D-Bus relays** (`notify_sink.rs`, `notify_relay.rs`, `theme_relay.rs`): the pattern exists; without execution, no verdict between a real hang and an effective bound via the socket.

## 🟡 CLI hygiene (inherited from spark-1.3, not exhaustively re-checked)

Spark-1.3 documented broken help/pages parity (`proc pending allow/deny` without a dedicated `Page`, `--source manual` missing from completion and from the error message, the `sbx projects` hint that exits 2, `sbx search` silently ignoring extra words). Not re-audited in this pass; the project's own `docs_coverage.rs`/`help/tests.rs` guards cover part of those classes.

## ✅ Hygiene findings (angles that came back clean)

- Zero `panic!`/`unreachable!`/`todo!` in production code (all inside `#[cfg(test)]`); of the ~250 `unwrap` sites seen, 99% are in tests.
- The 245 `unsafe` sites carry real, specific SAFETY comments (no boilerplate) — rare at this volume.
- `overflow-checks = true` in release, parsers use `checked_`/`saturating_` arithmetic, fail-closed paths on the seccomp/netns side; the network tap's degrade is a documented choice, not a hole.
- Git history: the "trust inventory 3→4" diff seen at session start was committed in parallel elsewhere (`bac8a27`, `e8723ae`) — HEAD is consistent. Remaining: `.claude/settings.local.json` (tool config, benign) and `audit_spark_13.md` (untracked).

## Priorities

1. `stage_files`: parents + slash-free temp name + no symlink following (bug 1).
2. `parse_tcp_endpoint`: strip brackets + IPv6 round-trip test (bug 2).
3. `read_global`: fail closed on non-NotFound errors (bug 3).
4. Empirical proof of GNU tar's symlink behaviour in the `bounded_unpack` pipeline, plus a clippy/test campaign once the toolchain is installed.
