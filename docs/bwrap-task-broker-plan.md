# Declared tasks: the `[task]` broker (plan)

> Status: **plan**, locked in a design discussion (2026-07-30). It implements what
> [`bwrap-secrets-architecture.md`](bwrap-secrets-architecture.md) §4 calls the *declared
> operation* tier and **amends** that document's §4.1 (see [Naming and the amended
> doc](#naming-and-the-amended-doc)). Read with
> [`bwrap-security-stack.md`](bwrap-security-stack.md).

## 1. What this adds

A **declared task**: a named, fixed command that sbx runs **outside the agent's cage**, with a
credential the agent never holds, returning a structured result (exit code, and stdout/stderr
only where the declaration allows it).

```toml
[task.db-query]
description = "Read-only SQL against staging"
cmd    = ["psql", "-h", "db.staging.internal", "-c", "{sql}"]
params = { sql = { match = "^SELECT [A-Za-z0-9_,.*= '\"]{1,400}$" } }
stdout = "show"      # show | hide — a returned value always has its secrets named out (§9.2)
stderr = "show"

# The credential: the key IS the environment variable the command reads, so the name that
# appears in `${NAME}` is the name the declaration already gives it. The value is a resolver
# ref (or a terse `key` expanded through `[secret.defaults]`), resolved host-side per call.
[task.db-query.secret]
PGPASSWORD = "sops://secrets.enc.yaml#db.password"
```

Why a sub-table rather than `secret = "<name>"` pointing at `[secret."host"]`: that table is keyed
by **destination host** and requires `header`/`type` — it is the HTTP-header broker, and it cannot
express a `psql` password. Declaring the credential on the task also keeps it **out of the session
proxy's injection table** by construction, which is the property §6 needs. For an HTTP task that
*should* be brokered on the wire, the task declares an injection instead (§6) and the secret then
never enters the task cage at all.

The agent asks for the *operation*; it never composes the program. That is the whole security
property: **safe ⟺ sbx controls the program that touches the plaintext.**

## 2. Locked decisions

| Decision | Choice | Why |
|---|---|---|
| Where the command runs | **always an ephemeral sibling cage** — no option | in the agent's cage the agent *controls the program* (§3), so a fixed `cmd` would guarantee nothing |
| Agent-facing surface | **in-cage CLI shim first**, MCP façade later | an MCP must be wired per agent to exist at all; a CLI works the moment the cage starts (§5) |
| Egress for the task cage | **a task-scoped proxy per invocation** | same-uid gives no per-process identity, so the socket is the only authority boundary (§6) |
| Where `[task]` may be declared | **global, app, and bundle** — trusted-only | bundles already fold `[secret]` into an app; an untrusted project can never declare one |
| Which binaries a task may run | **any `[packages]` backend, `mise:` included** — from a tree no cage can write (§4.1) | integrity of the program, not a backend restriction |
| Credential sources | **reuse the existing resolvers** (`env://`, `file://`, `sops://f#k`, plugins) | one source path, no duplication (§7) |
| Timeouts / output caps | **global default + per-task override** | |

## 3. Why never the agent's cage

In the agent's cage `/nix` is the **per-project store, mounted read-write** (`launch.rs`, the
`NixMount { writable: true }` the launcher builds), and the seed places a **distinct writable
inode** per project (proven by the `place_file` test in `projectstore.rs`). `mise`-installed
tools live under a read-write `$HOME`. Therefore:

- the agent can **overwrite the binary** sbx is about to exec — a fixed `cmd` degrades to a
  command the agent chose;
- `/proc/<pid>/environ` is readable same-uid, so a secret passed through the environment is
  readable by the agent;
- `ptrace` is on the seccomp denylist but is **relaxable** by a trusted `[seccomp] allow`;
- a mount cannot be re-mounted read-only for one process — the mount namespace is shared, and a
  new namespace *is* a new cage.

## 4. The task cage — equivalent, not identical

Modelled on the **project cage's assembly** (`binds::assemble`), *not* on `resolver::cage_spec`
(which binds the host's `/usr` read-only — the opposite of hermetic).

Same as the project cage: hermetic FHS, synthesized `/etc` (passwd/group/hosts/machine-id),
locales, `PATH`, the resolved `[env]`, the same nix packages, cgroup limits.

Deliberately different:

- **`/nix` read-only from the shared store** — immutable, built host-side, never in the agent's
  cage;
- **the project read-only**, a **fresh `$HOME`**, its **own PID namespace** (so the agent cannot
  read the task process's `environ`), its own empty netns;
- no tty, no inherited stdin.

Hence the rule this produces — stated about *integrity*, not about a backend:

> **A task may only invoke a binary from a tree the agent cannot write.** Every `[packages]`
> backend qualifies, `mise:` included — what must change for `mise:` is *where the tool is
> installed*, not whether a task may use it.

So the cage is **equivalent but not identical**: same environment, minus any tree the agent can
write into.

### 4.1 `mise:` tools — a third mise scope (**SHIPPED**, `src/sandbox/taskpool.rs`)

Host-side backends (`nix:`, a **remote** `flake:`, `deb:`, `appimage:`, `tarball:`, `prebuilt:`)
build into the shared store, so they already satisfy the rule. Two do not: a `mise:` tool is
installed **in-cage** under a read-write `$HOME`, and an **inline** `[flakes.<name>]` builds in-cage
to an out-link under the agent's `$HOME` (which a task cage does not have — use a remote ref).
Excluding `mise:` outright would cut off npm/pipx-backed CLIs — too big a loss.

So: a **third mise scope**, beside the per-project pool (`MISE_DATA_DIR`) and the app-global one
(`MISE_SHARED_INSTALL_DIRS`) — a **task pool**, filled host-side by sbx, never mounted writable by
any cage, bound **read-only** into the task cage. Declared per task: `[task.<name>] packages =
["mise:<token>"]`, `mise:` only (every other backend needs no declaration) and `mise:nix:…` refused
(it builds into the store the cage writes — the very problem the pool solves).

Three things the plan had wrong before it was built, corrected here so they are not re-derived:

1. **`mise::bwrap_argv` is not merely offline.** It runs `--clearenv` with no `PATH` and no
   userland — only `HOME` and the `MISE_*` dirs. Flipping `--unshare-net` there would give a cage
   where `mise install` has no node, python or git for its backends. The install needs the **task
   cage's own skeleton** (hermetic FHS, `/nix` read-only from the shared store, the base userland on
   `PATH` — `curl` and `git` are in it) with the pool bound read-write. That is what shipped; the
   engine-provisioning cage in `mise.rs` is untouched.

2. **The install gets the host network, not a proxy.** The precedent is `store::provision`, which
   runs `nix build` as a plain host subprocess: a cage's `network` allowlist governs what the
   *agent* may reach, it is not a budget for sbx's own host-side setup. Routing an install through a
   proxy would demand the author allowlist registries they never asked to talk to.

3. **The pool is not a `KEPT_DESTS` entry.** That list filters mounts *inherited from the agent
   cage*, and the pool is not one of them — it is an extra mount the engine pushes in
   `TaskEngine::build_spec`, like the per-invocation proxy binds.

And the invariant the whole thing rests on, which the plan did not state: **the install cage and the
task cage must bind the pool at the same in-cage path** (`/opt/sbx/task-mise`). The install bakes
absolute paths into what it writes — the shims, the recorded config, npm wrappers, python
console-script shebangs, venv `pyvenv.cfg` — so a pool filled under one path and read under another
yields tools that fail on their own interpreter, a failure that reads as "the install broke". Pinned
by `the_install_and_task_cages_agree_on_the_pool_path`.

Two things only a real run revealed, both since fixed:

- **A task's `PATH` gets the pool's `shims/`, not its install directories.** Resolving
  `installs/<tool>/<version>/bin` looked obvious and is wrong: the layout inside an install is the
  *backend's*. A real `aqua:ripgrep` lands at
  `installs/ripgrep/15.2.0/ripgrep-15.2.0-x86_64-unknown-linux-musl/rg` — no `bin/` at any level.
  mise's shim is the one mechanism that spans backends, so the install runs `mise use -g` (which
  installs, records the version, and writes the shims) and the task cage gets `shims/` on `PATH`
  plus the mise environment a shim needs, with mise's *writable* dirs redirected to the tmpfs home.
- **`KEPT_DESTS` named destinations the cage does not emit.** `/bin`, `/usr`, `/lib64`, `/etc/ssl`
  match *nothing* — the cage emits `/bin/sh`, `/usr/bin/env`, `/lib64/ld-linux-x86-64.so.2`,
  `/etc/ssl/certs/ca-bundle.crt` — so a task cage had no shell, no `env`, no nix-ld shim and no CA
  bundle, and `NIX_LD`/`NIX_LD_LIBRARY_PATH` were filtered out of its environment too. Harmless
  while every task ran a nix binary by absolute path; fatal for a pool tool, which is typically a
  foreign binary behind a `#!/usr/bin/env …` shebang. The entries now come from `binds`'s own
  constants and `every_kept_destination_is_one_the_cage_emits` fails on any that names nothing.
- **Satisfaction is gated on the pool's recorded config, not only on `installs/`.** The shim resolves
  a version through `<pool>/config/config.toml`, so checking the install tree alone drifts: declare
  `node@24`, switch to `node@22`, switch back — 24 is still installed, the launch short-circuits, and
  the task keeps running 22 with nothing to warn you. `bins_for` now requires the record to name the
  version the declaration asks for. A mismatch costs one install-cage run that finds everything
  downloaded and just re-pins.
- **`sbx upgrade mise` rolls the pool** (`roll_task_pool` in `launch.rs` → `taskpool::upgrade`),
  under its own `task pool` line. Without it a pool tool is frozen for good, since once the
  declaration and the record agree nothing re-resolves — and every backend must be upgradable.
- Also fixed while there: the task cage mounted its `/tmp` tmpfs **after** the project bind and the
  proxy socket, so both were shadowed — a project living under `/tmp` was unusable.

Verified live, against a real pool: install → read-only in the cage → the tool resolves by name; the
three-step version-drift scenario re-pins; two tools coexist (`mise use -g` **merges** the config,
and a bare token records `latest`); a warm relaunch is silent; `missing-tools=` marks a task whose
tool would not install; `sbx projects rm` reclaims the pool with the tree. `sbx upgrade mise` prints
its `task pool … rolled` line and the recap follows with `1 rolled: task pool.`

Verifying that last one needs a config with **no apps**, or the roll drags every app on the machine
through a cage. `XDG_CONFIG_HOME=<empty dir>` isolates it: the global config is read from there,
while the data directory (and therefore the warm shared store) stays put. Pick a tool from a core
mise plugin (`node`, `python`) rather than an `aqua:` one — aqua reads the GitHub API, whose
anonymous quota is 60/hour and which a few install cycles exhaust.

Because the in-cage path is fixed, the **host** path is free: it is per project
(`<data>/projects/<id>/task-mise`), so `sbx projects rm` and the dead-tree reap reclaim it with no
pool-specific housekeeping. The cost is duplication of a heavy runtime across projects; a shared
pool remains a later option that changes nothing in the cages.

Rejected alternative, and why: *snapshot the project pool at launch* (reflink the tool's tree
before exec'ing the agent) needs no new networking, but the per-project pool **persists across
sessions**, so a snapshot can copy a tree an earlier session already tampered with. It buys
"unmodified during this session", not integrity. Acceptable only as an explicitly labelled
degraded mode, never the default.

## 5. The agent-facing surface: CLI first

The deciding criterion is **graceful degradation**:

| | MCP | in-cage CLI shim |
|---|---|---|
| with no wiring | does not exist | works |
| per agent | a different config format each | nothing to do |
| Mode A (human), scripts, `sbx run` | unusable | works |
| discoverability | self-describing (its real strength) | must be announced |

Discoverability — the MCP's only genuine advantage — is reachable from both sides, because **sbx
owns each app's isolated `$HOME`**: it can write the MCP config file *or* the instructions file
the agent already reads. The asymmetry that decides it: without that file the MCP is dead, the
CLI still works.

Shape: **one host-side policy engine**, reached over a dedicated per-session Unix socket; the
in-cage shim is a thin client, never the policy. The MCP façade lands later as a **second
transport on the same engine** — never a second policy engine.

### 5.1 The honest residual: the socket's authority is cage-wide

Every existing control plane (egress, `proc`, `fs`) is **never** bound into the cage, precisely so
the agent cannot answer its own asks. This one must cross. Same-uid gives **no per-process
identity**, so *any* process in the cage — including a subprocess of whatever the agent spawned —
can invoke a task. The authority is the **cage's**, not the agent's. This is why the choice of
`cmd` and of `params` bounds carries the security, and why the free-command tier (§10, increment
3) stays gated on a per-secret `exposable` flag.

## 6. Egress: a task-scoped proxy per invocation

Required, not merely tidier. Today a `[secret."host"]` is injected for the agent — that is tier 1,
by design. But a **task-only credential must not be reachable from the agent's lane**, and a
shared session proxy cannot separate the two: with no per-process identity, the proxy cannot tell
a task connection from an agent connection. The **socket is the only authority boundary
available** — the same reasoning that puts the control sockets under a `0700` data dir. Registering
a task's secret in the session proxy's injection table would let the agent trigger the injection
itself by aiming at that host.

Three ordinary reasons on top: the session proxy exists only under an allowlist posture (sharing
would need a second code path anyway); lifetimes decouple (a task does not keep the session alive,
a dying session does not break a task); a task's rule set is narrower than the project's.

Cheap to build: `egress::start(layout, policy, secrets, …)` already takes the policy **and** the
injection table as arguments, so "a proxy with other rules and other injections" is a call, not a
refactor. The session's ephemeral CA (`proxy/ca.rs`) is reused where one exists.

**The best property this unlocks:** for an HTTP task the secret need not enter the argv, the
environment, or the task cage at all — the task-scoped proxy injects it on the wire. `curl` runs
knowing nothing. That is tier 1 inside a task.

**Assumption to validate, not a fact:** the cost of one extra listener + thread (+ possibly a CA
mint) per invocation is expected to be dominated by the bwrap spawn. Measure it in the increment-2
tests.

## 7. Credential sources — already built

`env://`, `file://`, `sops://file#key` and "something else via a script" already exist:
`SecretSource::{Env, File, Sops, Plugin}` (`config/secrets.rs`), with resolver plugins run
host-side under bwrap (`sandbox/resolver.rs`), plus the terse `key` form expanded through
`[secret.defaults] order` with a fallback chain. A task reuses that resolution **unchanged** — one
source path. Resolved **per invocation** (never held for the session) and zeroized after use.

## 8. What actually bounds a command

### 8.1 Rejecting `;`, `&&`, `||` is theater

With **no shell** — `execve` on an argv vector — those are not metacharacters; they are literal
bytes inside one argument. Filtering them protects nothing and advertises a guarantee that is not
there. What bounds a command:

1. **never a shell** — an argv list, never a concatenated string;
2. **argv0 = an absolute path resolved host-side in the read-only store** (otherwise a PATH hijack
   needs no metacharacter at all);
3. **a `*` stays inside one argument** — a glob can never cross an argument boundary, so it can
   never produce an extra argument;
4. **no free options** — a param slot refuses a value starting with `-` unless explicitly declared
   (else `--upload-file`, `-o ProxyCommand`, …);
5. **command allow/deny via the existing grammar** — reuse `ProcRule` (`proc_policy.rs`): `*`/`?`,
   a rule containing `/` matches the whole path, one without matches the basename, **deny wins**.
   One grammar across the product.

### 8.2 Where metacharacters do come back

When a bounded param reaches a callee that itself invokes a shell: `ssh host <cmd>`,
`git -c core.sshCommand=…`, `bash -c`, `find -exec`, `tar --to-command`. That is the sudoers
residual; it is won by the choice of command and the egress allowlist, never by a character
filter.

### 8.3 Bounded params are load-bearing

A param loose enough to embed a comparison (`SELECT CASE WHEN substr(:tok,1,1)='a' …`) rebuilds
the oracle of §9. `match`/enum bounds are part of the security, not ergonomics.

## 9. Output disposition, and what it can and cannot promise

`stdout`/`stderr` take `show | hide`, and **substitution is unconditional** — not a disposition
(§9.2). Two truths to keep in the docs:

- **The exit code is an exfiltration oracle.** With a command the *agent* composes, masked output
  is irrelevant: `[ "${SECRET:0:1}" = "a" ]` leaks through the exit status, a handful of calls per
  character. A rate limit makes it slower, not impossible. This is why the free-command tier is a
  labelled step down (§10) and why `hide` never appears as a security claim there.
- **Substitution is a backstop, not a boundary** — any transformation the command itself applies
  (hash, encrypt, truncate, split across chunks) passes through. Its real value is the dominant
  accident: a credential echoed in an error message (`psql: … password=hunter2`). Worth having;
  not what contains the secret.

### 9.2 Named substitution: `${NAME}`, always

A secret's value found in a task's stdout, stderr, error message, or log line is replaced by
**`${<logical-name>}`** — the secret's own name, not an opaque mask. It reads as what it is,
tells the reader what was withheld, and doubles as a placeholder a later invocation can reuse.
It applies to the plaintext **and to every registered encoding variant** (§9.1), all rendering
the same name.

Why the wire keeps its own rendering: the proxy substitutes **in place, length-preserving**
(`redact_in_place` fills with `*`, and a test pins "masking preserves length") because changing a
byte count would break `Content-Length`, HTTP/2 frames, and mid-stream relaying. A task's output
has no such constraint — it is buffered up to `max_output` before it is returned, so a
variable-length replacement is safe there and a needle can never straddle a chunk boundary. **Two
renderings, one needle set**: `*`×len on the wire, `${NAME}` on the text sinks.

This needs the needle to **carry its name**: `SecretNeedle` holds only bytes today, so it gains
the logical name from increment 1 — which is what makes increment 2 depend on increment 1.

Three consequences to keep honest:

- **The name is itself information.** `${STAGING_DB}` tells the agent *which* credential passed
  through there, and how many times. That is the point (it is what makes the output readable), but
  it means a secret's *name* must not be sensitive.
- **A minimum length already exists — reuse it, and its reasoning is stronger here.**
  `REDACT_MIN_LEN = 8` (`egress.rs`) keeps a short value out of the needle set because it would
  match benign traffic and refuse legitimate egress; the value is still injected, and the skip is
  warned, never silent. On a text sink the same threshold prevents a 3-byte secret from peppering
  the output with `${TOKEN}` and *leaking the value* through the positions and frequency of the
  substitutions. One threshold, both sinks.
- **`${NAME}` in the output is not proof of a substitution.** The agent can print that literal
  itself; the two are indistinguishable. The trustworthy signal is the host-side count in the log
  (`redacted=<n>`), which the agent does not control — and a task that redacts often is either
  badly declared or being probed.

### 9.3 Why escaping does not disambiguate, and what does

The obvious fix — escape whatever the command printed (`$${NAME}`, or backquote it) before
inserting the real substitutions — **does not work here**, for two independent reasons:

1. **It is imitable.** The agent can print `$${NAME}` itself. A reader that de-escapes turns it
   back into `${NAME}` and the ambiguity returns; a reader that does not de-escape sees a stray
   `$$`. Escaping only disambiguates for a **strict parser that always de-escapes** — and the
   consumer here is a language model reading text, which is precisely a *non-strict* reader.
2. **It corrupts legitimate data.** `${…}` is everywhere in the payloads a task plausibly returns
   (shell, CI YAML, Terraform, compose files, templates). Rewriting it makes the output no longer
   the command's output.

What does work, when in-text disambiguation is genuinely wanted, is a **per-invocation nonce**:

```
${STAGING_DB@a91f3c}      # a91f3c drawn fresh per call, reported in the structured result + log
```

The agent cannot predict this call's nonce, so it cannot forge a placeholder for **this** output;
and because the nonce is fresh per call, a placeholder copied from an earlier result is detectable
as stale. It needs no de-escaping — it works with a careless reader, which is the whole point —
and it leaves every other byte of the output untouched. `ring` is already in the dependency tree
(via `rustls`/`rcgen`), so `SystemRandom` covers this with no new dependency.

Default: plain `${NAME}` (readable, which is the reason for naming it at all), with the nonce an
opt-in (`[task] nonce = true`). Keep it in proportion: **inside the returned body the only reader
is the agent, so there is nobody to deceive**; the audit trail lives in the host-side log where
sbx writes the count itself and no ambiguity exists. The nonce is a forensics nicety at near-zero
cost, never a boundary.

### 9.1 Redaction must cover the new sink

The existing redaction lives in the **proxy** (`proxy/inject.rs`, `ctx.rs`, `h2mitm.rs`) — it sits
on the wire. A task's stdout returning to the agent is a **different sink** that machinery never
touches. Therefore **task output and task logs both pass through the same variant redactor**,
which is also why the encoding set is closed:

`encode = raw | base64 | url | json-string`

Each encoding **registers its rendered form with the redactor at construction**, so adding an
encoding without its redaction variant is *unrepresentable* rather than a review item — the shape
`SandboxSpec::to_argv` uses for hardening. The precedent exists: `HeaderSecret` already redacts
the plaintext *and* its base64 form for `basic` (`config/secrets.rs`).

## 10. Increments

> **Status (2026-07-30): 1 and 2 are SHIPPED in full**, §4.1's task mise pool included; tests green
> (`cargo test --bins`, clippy clean). Increment 3 (free command) and 4 (MCP façade) are deliberately
> not built.

### Where the shipped code lives

| Piece | File |
|---|---|
| `[task]` schema + validation | `src/config/schema.rs`, `src/config/tasks.rs`, `src/config/types.rs` |
| Layering / trust gate (global, project, app, bundle) | `src/config/mod.rs`, `src/config/load.rs` |
| Named needles + `${NAME}` substitution | `src/sandbox/redact.rs`, `src/sandbox/proxy/inject.rs` |
| Ephemeral cage + engine + per-invocation proxy | `src/sandbox/task.rs` |
| Crossing socket, host-only log, quota | `src/sandbox/task_control.rs` |
| Launcher wiring (socket bind, client bind, guard, pool fill) | `src/sandbox/launch.rs` (search `task_socket`) |
| Task mise pool (§4.1) | `src/sandbox/taskpool.rs` |
| CLI | `src/cli/task.rs`, `src/cli/secret.rs`, `src/help.rs` |
| User docs | `docs/guide/configuration/task.md`, `docs/guide/cli/{task,secret}.md` |

1. **Schema + discovery.** A logical **name** and a `description` on `[secret]` (today the table is
   keyed by destination host, with neither), the per-secret `exposable` flag (§5 of the secrets
   doc requires it and it does not exist yet), `encode`, and `sbx secret list` (names +
   descriptions, never values). No new channel.
2. **Declared tasks.** `[task.<name>]`, the ephemeral cage (own PID ns, read-only shared store,
   read-only task mise pool per §4.1 — which brings the online host-side mise install with it),
   the host-side policy engine + its socket + the in-cage shim, the task-scoped proxy, the
   variant redactor on output *and* logs, a bounded in-RAM log ring with `sbx task logs` (modelled
   on `proc_control.rs`/`fs_control.rs` — never bound into the cage, never written to disk), and
   `sbx task run` host-side so a task is testable without an agent. Plus: a per-session call
   quota, and fail-closed when an approval is required but the session is detached/headless.
3. **Free command.** Opt-in, off by default, `exposable` required on the secret, egress allowlist
   mandatory, loud launch warning, documented as *"the secret is deemed disclosed to the agent;
   only the egress allowlist and the empty netns contain it"*.
4. **MCP façade**, auto-wired per app profile where the format is known.

With `where` gone, `exposable` gates exactly one thing: increment 3. A `broker-only` secret stays
usable by a fixed-command declared task, never by a command the agent composes.

## 11. Naming and the amended doc

- **`[task.<name>]`** was chosen over `[op]` / `[action]` / `[capability]`. **Known collision:**
  mise has its own `[tasks.*]` (this repo uses `mise run build`) and sbx exposes `sbx mise` as a
  passthrough, so `sbx mise run build` (a mise task) will sit beside `sbx task run db-query` (a
  brokered operation) — two senses of "task" one word apart. Accepted consciously; a rename is
  mechanical.
- **Amendment to [`bwrap-secrets-architecture.md`](bwrap-secrets-architecture.md) §4.1**: that
  section says *"do not reinvent a bespoke socket/CLI RPC"* for the declared-operation rung. The
  warning holds against a second **policy engine**; it does not hold against a second **transport**
  over one host-side engine, and the wiring asymmetry in §5 above decides the order: the CLI shim
  ships first, the MCP façade second. §4.1 is amended accordingly, not drifted from.
