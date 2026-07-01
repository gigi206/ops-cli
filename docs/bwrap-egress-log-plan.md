# Egress event log (`ops net log`) — design plan

Status: **proposed, not started** (design agreed to be worth doing; no code yet).
Owner cadence: plan → advisor review → incremental impl with tests, validated with the user.

## Motivation — the gap

Two egress-observability surfaces exist today, with a hole between them:

- `ops net stats [-a <app>]` — **aggregate** per-host counters (allow / deny / blocked).
  No timestamp, no URL/path, no method, no ordering. (`src/sandbox/egress_stats.rs`.)
- `ask`-mode stderr line + the in-cage `X-Ops-Egress-Reason` header — **per-request but
  ephemeral**: nothing is persisted or queryable host-side.

There is **no chronological, persistent, per-request record** (when, host:port, path,
method, verdict, reason). That is what a proxy access log gives (squid access.log, Envoy
access logs, mitmproxy flows) and what would answer "why did it fail at 14:32?" and
"what did the untrusted agent try to reach / exfiltrate?".

## Hard design constraint — secret-at-rest (the crux)

Logging **full URLs** creates a NEW "plaintext secret at rest" surface that contradicts the
project invariant *no plaintext secret*:

- Query strings routinely carry tokens (`?key=…`, session tokens) — exactly what the 6.3b
  outbound-secret redaction exists to keep OUT of any record.
- The current `stats` deliberately store **host + counters only** (no path/query) to avoid this.

So an event log is only acceptable with ALL of:

1. **Redaction on what is written** — reuse the 6.3b secret needles against the logged URL,
   and/or drop the query string entirely (decision below). Never write a raw credential.
2. **Owner-only file (0600), outside every cage mount** — like the CA and the stats files.
3. **Bounded + rotated** — an agent can emit thousands of requests; unlike stats (one line
   per host), an event log is unbounded. Need a max size / line cap + rotation or ring.
4. **OFF by default (opt-in)** — least data at rest. Opt-in via config (`[network]`) or env.

## CLI surface (scoped under `ops net`, NOT a top-level `ops logs`)

`ops logs` would over-promise (ops does not centralize lifecycle/provisioning logs). Keep it
on the egress surface:

```
ops net log [-a|--app <name>] [--host <h>] [--verdict allow|deny|blocked]
            [-n <N>] [--since <ts>] [--follow] [--json]
```

- default: recent events, newest-last, one line each.
- `--follow`: live tail (mirror `ops net pending watch`'s loop; needs a terminal).
- filters: `--app`, `--host`, `--verdict`; `-n` limit; `--json` machine-readable.

### Record fields (per event)

`timestamp · project/app/session-id · host:port · method · path(redacted) · verdict · reason`

- verdict ∈ {allow, deny, blocked} (same taxonomy as stats).
- reason = the `X-Ops-Egress-Reason` category (denied-by-rule, denied-default, ssrf-blocked,
  host-mismatch, dns-failure, upstream-unreachable, outbound-secret, …).
- path: **redacted** (see constraint #1) — leading path kept, query dropped or needle-redacted.

## Feasibility — infra is largely there (additive)

- The proxy (`src/sandbox/proxy.rs`) already computes **verdict + reason per request** at the
  chokepoint — the event log is one append at that point.
- `src/sandbox/egress_stats.rs` already writes **per-session files** (`project=`/`app=` header +
  `host\tallow\tdeny\tblocked` lines) under the data dir and **aggregates** them for `ops net
  stats`. The event log is the same plumbing at **event granularity** instead of counters:
  per-session append file, aggregated/tailed by `ops net log`. Reuse the session-file location,
  metadata header, owner-only creation, and the aggregation walk.

## Open questions to settle with the user BEFORE coding

1. **Opt-in mechanism**: a `[network]` config field (e.g. `log = true`, trusted/global-gated
   like other security fields) vs an env (`OPS_EGRESS_LOG=1`) vs both. Config is discoverable and
   gate-able; env is quick for a one-off debug session.
2. **Redaction depth**: drop the query string entirely (simplest, safest) vs keep it but run the
   secret needles over it (more useful, more risk). Recommendation: **drop query by default**,
   with an explicit `--with-query` opt-in that still needle-redacts.
3. **Retention**: max size / max lines / rotation policy; per-session vs a single rolling file.
4. **Scope of "blocked" detail**: how much of the security-guard reason to record (SSRF target IP?
   secret name? — the latter must never be logged).

## Increment sketch (each: tests + advisor + user validation)

1. Event record type + per-session append writer in `egress_stats` (or a sibling module),
   owner-only, with redaction applied at write time. Off unless opted in.
2. Wire the proxy chokepoint to emit one event per decision (allow/deny/blocked), carrying the
   already-computed verdict + reason.
3. `ops net log` reader: aggregate + filter + render (+ `--json`), reusing the stats walk.
4. `--follow` live tail (mirror `net_pending_watch`).
5. Docs + help; the opt-in field surfaced in `ops config`.

## Non-goals

- Not a top-level `ops logs` (no lifecycle/provisioning log aggregation).
- Not on by default. Not a raw-URL dump. Not a bypass of the redaction invariant.
