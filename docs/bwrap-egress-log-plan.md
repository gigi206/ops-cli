# Egress event log (`ops net logs`) — design plan

Status: **decided (live-only, zero-disk); implementing incrementally.**
Owner cadence: plan → advisor review → incremental impl with tests, validated with the user.

## Motivation — the gap

Two egress-observability surfaces exist today, with a hole between them:

- `ops net stats [-a <app>]` — **aggregate** per-host counters (allow / deny / blocked).
  No timestamp, no URL/path, no method, no ordering. (`src/sandbox/egress_stats.rs`.)
- `ask`-mode stderr line + the in-cage `X-Ops-Egress-Reason` header — **per-request but
  ephemeral**: nothing is persisted or queryable host-side.

There is **no chronological, per-request record** (when, host:port, path, method, verdict,
reason) that a second terminal can watch. That is what a proxy access log gives and what
answers "why did it fail just now?" and "what is the untrusted agent trying to reach?".

## The decision — live-only, zero disk

Settled with the user (2026-07-01): the log is **never written to disk**. It is a
**live view of a running session**, read from another terminal over the existing per-session
control channel; when the session exits, nothing remains.

This is strictly safer than a persisted log and **dissolves the entire secret-at-rest
constraint** that dominated the first draft of this plan — no 0600 file, no rotation, no
opt-in-for-minimization, no redaction-at-write. The event data lives at the same trust level
as the injected secret the proxy already holds in RAM: **owner-only, host-side, ephemeral,
never in the cage**.

Locked answers to the four original open questions:

1. **Opt-in mechanism** → **none.** The in-memory ring is always available while the proxy
   runs; a bounded ring costs a few KB. No `[network]` field, no env var.
2. **Redaction depth** → **drop the query string by default in the display**; an explicit
   `--with-query` shows it after running the 6.3b outbound-secret needles over it (so a
   *configured* secret is masked). Applied at read time, server-side.
3. **Retention** → a **bounded in-memory ring per session** (newest-N), evicting oldest.
   Dies with the session. No files, so no rotation policy.
4. **"blocked" detail** → record the **reason category + `host:port`** only. Never a secret
   name, never an SSRF target IP beyond the category token.

**Scope consequence (accepted):** no post-session forensics — you observe a session while it
runs, not afterwards. Also: the log only exists where a proxy exists — `[network] mode =
"allowlist"` or `"ask"`. `shared`/`none` have no proxy (direct or no egress), so nothing to log.

## How it reuses what exists

- **The control channel** (`src/sandbox/control.rs`): a per-session owner-only Unix socket at
  `<data>/egress/control-<pid>.sock`, **never bound into the cage**, that `ops net pending`
  already reaches from another terminal. Today it is stood up only for `ask` posture; the log
  makes it stand up whenever the **proxy** runs (also `allowlist`). The wire protocol is
  line-based, one command per connection — a new `LOG <after-seq>` command joins
  `LIST`/`ALLOW`/`DENY`/`RULES`.
- **The proxy verdict chokepoint** (`src/sandbox/proxy.rs`): `ctx.record(host, kind)` already
  classifies every request into `StatKind::{Allow,Deny,Blocked}` at ~13 decision sites. The
  log event is emitted at those same sites, enriched with the port, method, path, and the
  `X-Ops-Egress-Reason` category the site already knows.
- **Shared state via `Arc`**: the ring is shared between the proxy serve threads and the
  control serve thread exactly like `PendingState`/`ManualRules` (`ctx.with_control`).
- **Session addressing**: `ops net log -a <app>` resolves the running session's pid via the
  same egress-dir discovery `ops net pending` uses (`control-<pid>.sock` glob).

## CLI surface (`ops net logs`, NOT a top-level `ops logs`)

The verb is **`ops net logs`** (plural), a sibling of `ops net stats`/`ops net pending`. The
singular **`ops net log` is accepted as an alias** (the dispatch matches `"logs" | "log"`), so a
typo does not error.

```
ops net logs [-a|--app <name>] [--host <h>] [--verdict allow|deny|blocked]
             [-n <N>] [--with-query] [--follow] [--json]
```

- default: recent events (newest-last), one line each, query dropped.
- `--follow`: live tail — poll `LOG <last-seq>` on an interval (mirrors `ops net pending
  watch`), printing only events past the cursor. Needs a terminal.
- filters: `--host`, `--verdict`; `-n` limit; `--with-query` (needle-redacted); `--json`.

### Record fields (per event)

`timestamp · host:port · method · path(query-dropped) · verdict · reason`

- verdict ∈ {allow, deny, blocked, **error**}. A **superset** of the stats taxonomy — the log is a
  diagnostic record, not a counter (settled with the user 2026-07-01, "tout inclus"):
  - `allow` — permitted and egressed.
  - `deny` — ops refused it by rule / method scope / `ask` decision.
  - `blocked` — a security or protocol guard refused it (SSRF, host/SNI mismatch, outbound-secret,
    splice cap, an **IP-literal** target, a **malformed/smuggling** request).
  - `error` — the request was **allowed but did not complete**: `dns-failure`,
    `upstream-unreachable`, `upstream-cert-rejected`. Kept distinct from `blocked` on purpose:
    "allowed but it failed" reads differently from "we said no", which is the log's whole job.
- reason = the `X-Ops-Egress-Reason` category (denied-by-rule, denied-default, denied-method,
  asked-denied, ssrf-blocked, host-mismatch, outbound-secret, ip-literal, bad-request, splice-cap,
  dns-failure, upstream-unreachable, upstream-cert-rejected). `allowed` for a permitted request.
- method/path present only for the inspected L7 path; empty for early-CONNECT blocks and L4
  (`tcp://`) splices (no HTTP parse). Emission folds into the stats chokepoint for policy verdicts
  (`outcome`) and a stats-free `push_log` for the error/malformed sites stats does not count.
- a **malformed-handshake** attempt with no clean `host:port` (a plain-HTTP request, a bad CONNECT
  authority, an unparseable request line) is still logged — with a **blank host** and the raw
  method/target as the identifier — so the agent's attempts are never dark (settled 2026-07-01).
- timestamp: an epoch-ms stamp on each event (clean for `--json`); the human view renders a relative
  age ("12s ago").

**Boundary — egress decision, not application response (settled 2026-07-01):** the log records
whether a request was *allowed to leave* and ops's own errors. A **real upstream 4xx/5xx** (a 404/500
from the allowed server) is **not** logged as a status — it is the application's answer to a
successfully-delivered request, relayed verbatim and already visible to the agent. Capturing it would
mean the proxy parsing every response's status line (L7-only, hot path); the user chose to keep the
log on the egress axis.

## Increment sketch (each: tests + advisor + user validation)

1. **The ring + protocol + emission, end-to-end through the proxy. — DONE.** `LogEvent` + bounded
   `LogRing` (monotonic seq, `push`, `snapshot(after)` with a surfaced eviction `dropped=` gap) in
   `control.rs`; the `LOG [after=<seq>]` command in `serve` + a client `read_log`/`log_all`; stand
   the ring + socket up whenever the proxy runs (`egress::start`, also `allowlist` now), share it
   into `ProxyCtx`; emit one event at every decision site through `outcome` (stats+log) and the
   transport/malformed sites through `push_log` (log-only). Query redacted at push. 718 `--bins`
   green + 2 e2e (allowlist, L4 splice); fmt/clippy clean.
2. **`ops net logs` reader** (`log`/`logs` alias) — dispatch + session discovery (reuse `pending`'s
   `-a <app>` → pid) + **filters** (`--host`, `--verdict allow|deny|blocked|error`, `-n`) + render +
   **`--json`** + the query-drop / `--with-query` (needle-redacted) display.
3. **`--follow`** live tail (poll with a per-session seq cursor, mirror `net_pending_watch`, print
   the `dropped=` gap marker) + help text.

## Non-goals

- Not a top-level `ops logs` (no lifecycle/provisioning log aggregation).
- Not persisted. No post-session history. Not a raw-URL dump (query dropped by default).
- **Not upstream response-status monitoring** — a real upstream 4xx/5xx is relayed verbatim and
  agent-visible; the log stays on the egress-decision axis.
- Never a bypass of the no-plaintext-secret invariant.
