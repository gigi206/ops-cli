# Observability

Five host-side surfaces let you see the egress policy and what it decided. None of
them launches a sandbox or touches nix or the network — they read the resolved
policy and the live/recorded state:

| Command | Answers | When |
|---|---|---|
| [`sbx net rules`](#sbx-net-rules) | *what is the effective policy?* | before a launch — the static rules |
| [`sbx test net <url>`](#sbx-test-net) | *would this exact request be allowed, and why?* | before a launch — a what-if against the policy |
| [`sbx net stats`](#sbx-net-stats) | *how many requests did each host get allowed/denied/blocked?* | during and after — persisted counters |
| [`sbx net logs`](#sbx-net-logs) | *what did the proxy decide, request by request, right now?* | **only while a session runs** — a live, zero-disk log |
| [`sbx net live`](#sbx-net-live) | *what tunnels are open right now, and how much is flowing?* | **only while a session runs** — a live, `top`-style view |

They form a natural progression: `rules`/`test net` are the *static* view (the
policy as authored), `stats`/`logs`/`live` are the *dynamic* view (what actually
happened). `stats` persists aggregate counters; `logs` is an ephemeral, per-request
record you watch live; `live` shows the connections open at this very instant.

---

## `sbx net rules`

Lists the effective allow/deny rules of the filtering posture, each tagged by
source, reflecting the trust gate (an untrusted project's rules are dropped):

```bash
sbx net rules                        # the baseline effective rules
sbx net rules -a claude              # what `sbx app run claude` would launch with
sbx net rules --source config        # only the .sbx.toml/global rules
sbx net rules --source builtin       # only the always-allowed self-equip set
sbx net rules --source session        # rules a live ask-session remembered (--session)
sbx net rules --expand               # unfold each @group to its hosts
sbx net rules --filter github        # only rules whose text contains "github"
sbx net rules --json
```

Each rule names its layer: an inspected **L7** rule shows `https://` (a bare host is
https on 443), a raw **L4** rule shows `tcp://`; a `re:` regex shows neither (its
pattern carries its own scheme). A rule that came from a [`[net.groups]`](groups.md)
group shows as a single `@name` reference; `--expand` unfolds it to its hosts, each
tagged with its `@group` origin. `--filter <substr>` implies `--expand`, so a host
*inside* a group still matches.

The **sources**:

- `config` — the rules your `.sbx.toml`/global config declared.
- `builtin` — the [always-allowed self-equip hosts](modes.md#the-built-in-self-equip-set),
  unioned into every filtering policy regardless of trust.
- `manual` — this project's live `ask`-mode sessions' remembered rules (from
  [`--session` answers](ask.md#remembering-vs-persisting-an-answer)). Does not
  combine with `-a`.

Under `shared`/`none` there are no rules (no proxy). `-a <name>` shows an app's
effective policy — the same policy [`sbx test net --app`](#sbx-test-net) tests a URL
against.

### Persisting rules

`sbx net allow` / `sbx net deny` write a rule to a config file (the write side of
the same policy):

```bash
sbx net allow api.anthropic.com        # to the project .sbx.toml (default)
sbx net allow "*.nixos.org" -g         # to the global config
sbx net deny  telemetry.example.com    # deny always wins
sbx net allow "{POST} api.example.com/submit" -a writer   # under an app
```

`allow` bootstraps a deny-by-default allowlist if there is no posture yet; `deny`
needs an existing filtering posture (it will not open one). Writing the project
config re-trusts it (it must be absent or already trusted first); the global config
and app profiles are trusted by location.

---

## `sbx test net`

Tests one URL (or a `tcp://` target) against the resolved policy — a what-if with no
launch:

```bash
sbx test net https://api.github.com/repos/acme/proj   # → ALLOWED / DENIED / WOULD ASK + the deciding rule
sbx test net api.github.com                           # a bare host is completed to https
sbx test net -X POST api.example.com/submit           # test a specific method
sbx test net --app claude api.anthropic.com           # against an app's effective policy
sbx test net tcp://ssh.example.com:22                 # → SPLICED / NOT SPLICED (an L4 target)
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

`sbx test net` and [`sbx net logs`](#sbx-net-logs) decide through the *same*
matcher the proxy uses, so a test can never mispredict what a launch enforces.

---

## `sbx net stats`

Per-host **decision counters** the proxy records — an aggregate audit that persists
after a session:

```bash
sbx net stats                 # allow / deny / blocked, per destination host
sbx net stats -a claude       # scope to one app's sessions
sbx net stats --json
sbx net stats --reset         # clear this project's recorded stat files
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
`sbx net logs` adds with its `error` verdict.

Recording is **on by default**; a trusted `[network] stats = false` turns it off
(`true` re-enables it). `--reset` clears the recorded files of *ended* sessions; a
live session's counters reappear on its next request.

---

## `sbx net logs`

The **live, per-request** egress log of a running session — a chronological record
of every decision the proxy made, watchable from another terminal:

```bash
sbx net logs                         # recent events (newest last), one line each
sbx net logs -a claude               # one app's sessions
sbx net logs --host api.github.com   # only this destination
sbx net logs --verdict deny          # only denials
sbx net logs -n 50                   # the most recent 50 (per session)
sbx net logs --follow                # tail -f: keep appending new events until Ctrl-C
sbx net logs --with-status           # also show the upstream HTTP status (200/404/…)
sbx net logs --with-query            # keep the URL query (already secret-redacted)
sbx net logs --all                   # also show refusals a `mute` rule suppressed (tagged)
sbx net logs --json
```

Each line carries the session id (the PID `sbx session ls` shows), the local `hh:mm:ss`
time, the **transport**, the `host:port`, method, path, an optional **RPC tag**, the
verdict, and a reason category. `log` is an accepted alias.

The **transport** column is `https` (inspected TLS), `http` (inspected cleartext), `tcp`
(a raw `tcp://` splice), or `-` (refused before it was known). For an inspected request it
is **suffixed with the HTTP version** — `https/h1` vs `https/h2` — so you can see whether a
`[network] http2`-designated host is actually being carried as HTTP/2 (the security axis
is never dropped: it stays `https`, never a bare `h2`).

The **RPC tag** (`grpc`, `grpc-web`, or `connect`) appears when the request's `Content-Type`
names a gRPC-family framing, so streaming/RPC traffic reads at a glance. It is **recognized
from the header, never guessed from the path** — a request whose content-type does not name
an RPC framing carries no tag, *including* **Connect *unary*** calls, which ride a bare
`application/proto` that is byte-for-byte indistinguishable from a plain protobuf POST. So a
missing tag means "not self-identified as RPC", not "not an RPC". Both the version and the
tag are also in `--json` (`http_version`, `rpc`; `null` when absent).

### Muting noisy refusals — `[network] mute` (SELinux `dontaudit`)

A busy agent often hammers hosts you have **deliberately left denied** — telemetry,
feature flags, an optional CDN — and those refusals drown the ones worth acting on.
A `[network] mute` rule (the analogue of SELinux's `dontaudit`) keeps a **denied**
request's line **out of the default log**, without changing anything else:

```toml
[network]
mode  = "deny"
allow = ["api.example.com"]
mute  = ["play.googleapis.com", "*.datadoghq.com", "antigravity-unleash.goog"]
```

- **It never changes the verdict.** A muted host is still denied — `mute` is a log
  filter, not a third posture. It cannot open egress.
- **It never hides a count.** A muted refusal is still tallied in
  [`sbx net stats`](#sbx-net-stats), so you always know *how many* happened.
- **It only suppresses refusals** (`deny`) — a security-guard `blocked`, an `error`,
  and every `allow` are always shown.
- **`--all` brings them back**, each tagged `muted`. Muted refusals live in a
  **separate** ring, so a chatty muted host can never push a real event off the log.

`mute` uses the **same grammar** as `allow`/`deny` — a host, `*.domain`, an exact
`host/path`, a `{VERB}` method prefix, a `re:` regex, ports, and `@group` references
— and is **trusted/global-only** like the rest of the `[network]` table (an untrusted
project cannot blind you to what its agent tried to reach). `sbx net rules` and
`sbx config show` both list the mute rules, so the suppression is never silent.

You can edit the list from the CLI instead of the TOML, with the same scopes as
`allow`/`deny` (a project write re-trusts; `-a <app>`/`-g` target a profile or the global
config):

```bash
sbx net mute   play.googleapis.com -a agy   # add — quiet a profile's telemetry host
sbx net unmute play.googleapis.com -a agy   # remove (idempotent)
```

A config write needs an existing filtering posture (there is nothing to suppress under
`shared`/`none`), so set one first. You can also mute a **running** session live —
`sbx net mute <host> --session [-a <app>] [--all]` folds the rule into the session's
effective policy immediately (writes no file, dies with the session); it is the log-filter
sibling of `sbx net allow|deny --session`. A live mute is not un-loaded by `unmute` (a log
filter has no counter-verdict) — it simply ends with the session.

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
`sbx net stats` totals*. "Allowed but it failed" reads differently from "we said
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

## `sbx net live`

The **live, `top`-style** view of the egress tunnels **currently open** — one line per
flow, redrawn in place, watchable from another terminal:

```bash
sbx net live               # every open tunnel, redrawn every 1s until Ctrl-C
sbx net live -a claude     # only one app's sessions
sbx net live -i 2          # redraw every 2 seconds
sbx net live --json        # one snapshot object per tick (NDJSON) — for a pipe
```

Each line is `host:port · transport · age · ↑up ↓down`, grouped by session (the PID
`sbx session ls` shows):

```
open egress flows:
  session 4242 [claude] /home/you/project
    api.anthropic.com:443  https  8s  ↑1.2 KiB ↓380 KiB
```

This is the **open connections**, distinct from [`sbx net logs`](#sbx-net-logs) (the
*history of decided requests*): `logs` records every decision, one line per request;
`live` shows what is *carrying bytes right now*.

- **Transport** — `https` (inspected TLS), `http` (inspected cleartext), or `tcp` (a raw
  L4 [`tcp://`](rules.md) splice).
- **Bytes** — `↑` client→upstream, `↓` upstream→client. **Application bytes** on an
  inspected `https`/`http` flow (the proxy sees the plaintext); **encrypted bytes** on a
  raw `tcp` splice (the tunnel is opaque). A value climbing between two frames is a
  transfer in progress.
- **What you'll see** — because the proxy closes each inspected request after one
  response, short API calls flash by in under a second; the durable rows are raw `tcp://`
  tunnels (SSH, a database wire), WebSockets, and large L7 transfers in progress (a
  download, a streamed completion). An idle session shows an empty list — that is normal.

Like the log, it is **live-only and never written to disk**, read from the same
per-session control socket, and only a **filtering** posture (`deny`/`allow`/`ask`) runs a
proxy — so only those sessions have flows. The redraw needs a terminal; `--json` works in
a pipe (one snapshot per tick, since a live view is a *state*, not an event stream).

---

## Which surface answers which question

- *"What can this app reach?"* → `sbx net rules -a <app>` (static, expanded).
- *"Would this exact URL be allowed?"* → `sbx test net <url>` (a what-if).
- *"What has this project's egress looked like over time?"* → `sbx net stats`
  (persisted aggregate).
- *"Why did the agent's request just fail?"* → `sbx net logs --follow` (live,
  per-request, incl. `error`).
- *"What connections are open right now, and how much is flowing?"* → `sbx net live`
  (a `top` for the open tunnels).

---

## See also

- [Network modes](modes.md) — the postures these surfaces describe.
- [Rule grammar](rules.md) — how a rule is written, tested, and rendered.
- [Ask mode](ask.md) — `sbx net rules --source session` and the parked-request flow.
- [Architecture](architecture.md) — the SSRF guard and anti-fronting checks behind
  the `blocked` verdicts.
- Design: [egress event log plan](../../bwrap-egress-log-plan.md) — the live-only
  log's design and rationale.
- [`sbx net` CLI reference](../cli/net.md) · [`sbx test` CLI reference](../cli/test.md)
