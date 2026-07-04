# Observability

Four host-side surfaces let you see the egress policy and what it decided. None of
them launches a sandbox or touches nix or the network — they read the resolved
policy and the live/recorded state:

| Command | Answers | When |
|---|---|---|
| [`ops net rules`](#ops-net-rules) | *what is the effective policy?* | before a launch — the static rules |
| [`ops test net <url>`](#ops-test-net) | *would this exact request be allowed, and why?* | before a launch — a what-if against the policy |
| [`ops net stats`](#ops-net-stats) | *how many requests did each host get allowed/denied/blocked?* | during and after — persisted counters |
| [`ops net logs`](#ops-net-logs) | *what did the proxy decide, request by request, right now?* | **only while a session runs** — a live, zero-disk log |

They form a natural progression: `rules`/`test net` are the *static* view (the
policy as authored), `stats`/`logs` are the *dynamic* view (what actually happened).
`stats` persists aggregate counters; `logs` is an ephemeral, per-request record you
watch live.

---

## `ops net rules`

Lists the effective allow/deny rules of the filtering posture, each tagged by
source, reflecting the trust gate (an untrusted project's rules are dropped):

```bash
ops net rules                        # the baseline effective rules
ops net rules -a claude              # what `ops app claude` would launch with
ops net rules --source config        # only the .ops.toml/global rules
ops net rules --source builtin       # only the always-allowed self-equip set
ops net rules --source session        # rules a live ask-session remembered (--session)
ops net rules --expand               # unfold each @group to its hosts
ops net rules --filter github        # only rules whose text contains "github"
ops net rules --json
```

Each rule names its layer: an inspected **L7** rule shows `https://` (a bare host is
https on 443), a raw **L4** rule shows `tcp://`; a `re:` regex shows neither (its
pattern carries its own scheme). A rule that came from a [`[net.groups]`](groups.md)
group shows as a single `@name` reference; `--expand` unfolds it to its hosts, each
tagged with its `@group` origin. `--filter <substr>` implies `--expand`, so a host
*inside* a group still matches.

The **sources**:

- `config` — the rules your `.ops.toml`/global config declared.
- `builtin` — the [always-allowed self-equip hosts](modes.md#the-built-in-self-equip-set),
  unioned into every filtering policy regardless of trust.
- `manual` — this project's live `ask`-mode sessions' remembered rules (from
  [`--session` answers](ask.md#remembering-vs-persisting-an-answer)). Does not
  combine with `-a`.

Under `shared`/`none` there are no rules (no proxy). `-a <name>` shows an app's
effective policy — the same policy [`ops test net --app`](#ops-test-net) tests a URL
against.

### Persisting rules

`ops net allow` / `ops net deny` write a rule to a config file (the write side of
the same policy):

```bash
ops net allow api.anthropic.com        # to the project .ops.toml (default)
ops net allow "*.nixos.org" -g         # to the global config
ops net deny  telemetry.example.com    # deny always wins
ops net allow "{POST} api.example.com/submit" -a writer   # under an app
```

`allow` bootstraps a deny-by-default allowlist if there is no posture yet; `deny`
needs an existing filtering posture (it will not open one). Writing the project
config re-trusts it (it must be absent or already trusted first); the global config
and app profiles are trusted by location.

---

## `ops test net`

Tests one URL (or a `tcp://` target) against the resolved policy — a what-if with no
launch:

```bash
ops test net https://api.github.com/repos/acme/proj   # → ALLOWED / DENIED / WOULD ASK + the deciding rule
ops test net api.github.com                           # a bare host is completed to https
ops test net -X POST api.example.com/submit           # test a specific method
ops test net --app claude api.anthropic.com           # against an app's effective policy
ops test net tcp://ssh.example.com:22                 # → SPLICED / NOT SPLICED (an L4 target)
```

It reports **ALLOWED / DENIED / WOULD ASK** and the rule that decides it, against
the effective policy a launch would serve — the [built-in self-equip set](modes.md#the-built-in-self-equip-set)
is included, and a declared [credential injection](../secrets/injection.md) is noted
(by header and source, never the value, and not resolved). It reflects the trust
gate: an untrusted project's policy is dropped, so `test net` predicts exactly what a
launch would do.

`-X/--method` sets the HTTP method to test (default GET): a method-scoped rule like
`{GET} host` only matches that verb. For a `tcp://host:port` target it instead
reports **SPLICED / NOT SPLICED** — whether a `tcp://` rule would tunnel it raw
(uninspected) or it would take the inspected L7 path (`-X` is ignored — a raw stream
has no method).

`ops test net` and [`ops net logs`](#ops-net-logs) decide through the *same*
matcher the proxy uses, so a test can never mispredict what a launch enforces.

---

## `ops net stats`

Per-host **decision counters** the proxy records — an aggregate audit that persists
after a session:

```bash
ops net stats                 # allow / deny / blocked, per destination host
ops net stats -a claude       # scope to one app's sessions
ops net stats --json
ops net stats --reset         # clear this project's recorded stat files
```

For each destination host it reports how many requests this project's launches:

- **allowed**,
- **denied** by a rule (or an `ask` decision), or
- had **blocked** by a security guard — [SSRF](architecture.md#the-ssrf-guard), the
  outbound-secret tripwire, or a domain-fronting host mismatch.

Each request is counted once. Counters accrue while a filtering posture
(`deny`/`allow`/`ask`) runs and **persist after the session** (owner-only, under the
data dir). Transport/protocol failures (DNS, an unreachable upstream, a malformed
request) are **not** a policy verdict and are not counted — that is the axis
`ops net logs` adds with its `error` verdict.

Recording is **on by default**; a trusted `[network] stats = false` turns it off
(`true` re-enables it). `--reset` clears the recorded files of *ended* sessions; a
live session's counters reappear on its next request.

---

## `ops net logs`

The **live, per-request** egress log of a running session — a chronological record
of every decision the proxy made, watchable from another terminal:

```bash
ops net logs                         # recent events (newest last), one line each
ops net logs -a claude               # one app's sessions
ops net logs --host api.github.com   # only this destination
ops net logs --verdict deny          # only denials
ops net logs -n 50                   # the most recent 50 (per session)
ops net logs --follow                # tail -f: keep appending new events until Ctrl-C
ops net logs --with-status           # also show the upstream HTTP status (200/404/…)
ops net logs --with-query            # keep the URL query (already secret-redacted)
ops net logs --json
```

Each line carries the session id (the PID `ops ls` shows), the local `hh:mm:ss`
time, `host:port`, method, path, verdict, and a reason category. `log` is an
accepted alias.

### Live-only — never written to disk

> **The log lives in the running session's memory and is NEVER written to disk.**
> It shows a session *while it runs* — watch it from another terminal — and once the
> session exits, nothing remains. There is no post-session forensics, no log file, no
> rotation.

This is deliberate: the event data lives at the same trust level as the injected
secret the proxy already holds in RAM (owner-only, host-side, ephemeral, never in
the cage). Only a **filtering** posture has a proxy, so only `deny`/`allow`/`ask`
sessions have a log — `shared`/`none` have nothing to log.

### Verdicts — a superset of `stats`

The log's verdicts are a **superset** of the `stats` counters:

- **allow** — permitted and egressed.
- **deny** — refused by a rule, a method scope, or an `ask` decision.
- **blocked** — refused by a security or protocol guard (SSRF, host/SNI mismatch,
  outbound-secret, an IP-literal target, a malformed/smuggling request, a splice
  cap).
- **error** — the request was **allowed but did not complete**: a DNS failure, an
  unreachable upstream, a rejected certificate.

`error` is the extra one — it is **not** a `stats` counter (stats count policy
verdicts, not transport failures), so *the log's lines do not reconcile with
`ops net stats` totals*. "Allowed but it failed" reads differently from "we said
no," which is the log's whole job: answering *why did it fail just now?*

### `--with-status` and `--with-query`

- **`--with-status`** adds the upstream HTTP status (200/404/5xx) the server
  answered — for a completed **L7** (inspected `https://`) request only; an L4
  (`tcp://`) splice, a refusal, or an `error` shows `-` (no HTTP response to read).
  This is the server's answer to a *delivered* request, distinct from the egress
  verdict: an allowed request can still get a 404. Under `--follow --with-status`, an
  event whose response has not yet returned first appears with no status, then
  reappears once carrying its status (a live tail cannot un-print a line); the
  one-shot listing shows each status directly.
- **`--with-query`** keeps the URL query in the shown path (dropped by default, since
  a token can ride in a query). It is already redacted — the proxy masks configured
  secret values before an event enters the log.

### `--follow`

`--follow` prints the current listing, then appends new events as they happen (a
`tail -f`) until Ctrl-C, polling every `--interval` seconds (default 1). If the
in-memory ring overflowed between polls, the dropped count is announced, never
silently skipped; a session that ends is noted, and a new one is picked up. The
append shape is pipe-friendly, and `--json` streams one event object per line.

---

## Which surface answers which question

- *"What can this app reach?"* → `ops net rules -a <app>` (static, expanded).
- *"Would this exact URL be allowed?"* → `ops test net <url>` (a what-if).
- *"What has this project's egress looked like over time?"* → `ops net stats`
  (persisted aggregate).
- *"Why did the agent's request just fail?"* / *"What is it trying to reach right
  now?"* → `ops net logs --follow` (live, per-request, incl. `error`).

---

## See also

- [Network modes](modes.md) — the postures these surfaces describe.
- [Rule grammar](rules.md) — how a rule is written, tested, and rendered.
- [Ask mode](ask.md) — `ops net rules --source session` and the parked-request flow.
- [Architecture](architecture.md) — the SSRF guard and anti-fronting checks behind
  the `blocked` verdicts.
- Design: [egress event log plan](../../bwrap-egress-log-plan.md) — the live-only
  log's design and rationale.
- [`ops net` CLI reference](../cli/net.md) · [`ops test` CLI reference](../cli/test.md)
