# Egress observability

Five host-side surfaces let you see the egress policy and what it decided. None of
them launches a sandbox or touches nix or the network: they read the resolved
policy and the live/recorded state:

| Command | Answers | When |
|---|---|---|
| [`sbx net rules`](#sbx-net-rules) | *what is the effective policy?* | before a launch: the static rules |
| [`sbx test net <url>`](#sbx-test-net) | *would this exact request be allowed, and why?* | before a launch: a what-if against the policy |
| [`sbx net stats`](#sbx-net-stats) | *how many requests did each host get allowed/denied/blocked?* | during and after: persisted counters |
| [`sbx net logs`](#sbx-net-logs) | *what did the proxy decide, request by request, right now?* (and, with [`capture`](#seeing-the-traffic-network-capture) on, *what actually crossed*) | **only while a session runs**: a live, zero-disk log |
| [`sbx net live`](#sbx-net-live) | *what tunnels are open right now, and how much is flowing?* | **only while a session runs**: a live, `top`-style view |

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
pattern carries its own scheme). A rule that came from a [`[network.groups]`](groups)
group shows as a single `@name` reference; `--expand` unfolds it to its hosts, each
tagged with its `@group` origin. `--filter <substr>` implies `--expand`, so a host
*inside* a group still matches.

The **sources**:

- `config`: the rules your `.sbx.toml`/global config declared.
- `builtin`, the [always-allowed self-equip hosts](modes#the-built-in-self-equip-set),
  unioned into every filtering policy regardless of trust.
- `manual`, this project's live `ask`-mode sessions' remembered rules (from
  [`--session` answers](ask#remembering-vs-persisting-an-answer)). Does not
  combine with `-a`.

Under `shared`/`none` there are no rules (no proxy). `-a <name>` shows an app's
effective policy, the same policy [`sbx test net --app`](#sbx-test-net) tests a URL
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

Tests one URL (or a `tcp://` target) against the resolved policy: a what-if with no
launch:

```bash
sbx test net https://api.github.com/repos/acme/proj   # → ALLOWED / DENIED / WOULD ASK + the deciding rule
sbx test net api.github.com                           # a bare host is completed to https
sbx test net -X POST api.example.com/submit           # test a specific method
sbx test net --app claude api.anthropic.com           # against an app's effective policy
sbx test net tcp://ssh.example.com:22                 # → SPLICED / NOT SPLICED (an L4 target)
```

It reports **ALLOWED / DENIED / WOULD ASK** and the rule that decides it, against
the effective policy a launch would serve, the [built-in self-equip set](modes#the-built-in-self-equip-set)
is included, and a declared [credential injection](../secrets/injection) is noted
(by header and source, never the value, and not resolved). It reflects the trust
gate: an untrusted project's policy is dropped, so `test net` predicts exactly what a
launch would do.

`-X/--method` sets the HTTP method to test (default GET): a method-scoped rule like
`{GET} host` only matches that verb. For a `tcp://host:port` target it instead
reports **SPLICED / NOT SPLICED**: whether a `tcp://` rule would tunnel it raw
(uninspected) or it would take the inspected L7 path (`-X` is ignored: a raw stream
has no method).

`sbx test net` and [`sbx net logs`](#sbx-net-logs) decide through the *same*
matcher the proxy uses, so a test can never mispredict what a launch enforces.

---

## `sbx net stats`

Per-host **decision counters** the proxy records: an aggregate audit that persists
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
- had **blocked** by a security guard: [SSRF](architecture#the-ssrf-guard), the
  outbound-secret tripwire, or a domain-fronting host mismatch.

Each request is counted once. Counters accrue while a filtering posture
(`deny`/`allow`/`ask`) runs and **persist after the session** (owner-only, under the
data dir). Transport/protocol failures are **not** a policy verdict and are not counted:
that is the axis `sbx net logs` adds. A host that did not resolve, one that could not be
reached, and one whose certificate was rejected land there under the `error` verdict; a
request the proxy refused as malformed lands there too, under `blocked`, which is the
verdict for a request a protocol or security check refused rather than the policy.

Recording is **on by default**; a trusted `[network] stats = false` turns it off
(`true` re-enables it). `--reset` clears the recorded files of *ended* sessions; a
live session's counters reappear on its next request.

A listing keeps a row for a bounded number of destinations. Past that, further hosts are
counted together under a single `(other hosts)` row rather than each getting one of their
own; `--json` carries the same figures under an `overflow` key, which is `null` when
nothing was folded. The counts are never dropped, so what the listing adds up to is still
every request the proxy decided. A real workload reaches a handful of hosts and never
sees that row; what it bounds is an agent walking through thousands of destinations,
since the destination is chosen inside the sandbox and a refused request is counted like
any other.

---

## `sbx net logs`

The **live, per-request** egress log of a running session: a chronological record
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
sbx net logs --with-headers          # the request/response heads, if the session captured them
sbx net logs --with-body             # those plus the leading bytes of each body
sbx net logs --all                   # also show refusals a `mute` rule suppressed (tagged)
sbx net logs --json
```

Each line carries the session id (the PID `sbx session ls` shows), the local `hh:mm:ss`
time, the **transport**, the `host:port`, method, path, an optional **RPC tag**, the
verdict, and a reason category. `log` is an accepted alias.

The **transport** column is `https` (inspected TLS), `http` (inspected cleartext), `tcp`
(a raw `tcp://` splice), or `-` (refused before it was known). For an inspected request it
is **suffixed with the HTTP version**, `https/h1` vs `https/h2`, so you can see whether a
`[network] http2`-designated host is actually being carried as HTTP/2 (the security axis
is never dropped: it stays `https`, never a bare `h2`).

The **RPC tag** (`grpc`, `grpc-web`, or `connect`) appears when the request's `Content-Type`
names a gRPC-family framing, so streaming/RPC traffic reads at a glance. It is **recognized
from the header, never guessed from the path**: a request whose content-type does not name
an RPC framing carries no tag, *including* **Connect *unary*** calls, which ride a bare
`application/proto` that is byte-for-byte indistinguishable from a plain protobuf POST. So a
missing tag means "not self-identified as RPC", not "not an RPC". Both the version and the
tag are also in `--json` (`http_version`, `rpc`; `null` when absent).

### Muting noisy refusals: `[network] mute` (SELinux `dontaudit`)

A busy agent often hammers hosts you have **deliberately left denied** (telemetry,
feature flags, an optional CDN), and those refusals drown the ones worth acting on.
A `[network] mute` rule (the analogue of SELinux's `dontaudit`) keeps a **denied**
request's line **out of the default log**, without changing anything else:

```toml
[network]
mode  = "deny"
allow = ["api.example.com"]
mute  = ["play.googleapis.com", "*.datadoghq.com", "antigravity-unleash.goog"]
```

- **It never changes the verdict.** A muted host is still denied: `mute` is a log
  filter, not a third posture. It cannot open egress.
- **It never hides a count.** A muted refusal is still tallied in
  [`sbx net stats`](#sbx-net-stats), so you always know *how many* happened.
- **It only suppresses refusals** (`deny`): a security-guard `blocked`, an `error`,
  and every `allow` are always shown.
- **`--all` brings them back**, each tagged `muted`. Muted refusals live in a
  **separate** ring, so a chatty muted host can never push a real event off the log.

`mute` uses the **same grammar** as `allow`/`deny`: a host, `*.domain`, an exact
`host/path`, a `{VERB}` method prefix, a `re:` regex, ports, and `@group` references, and is **trusted/global-only** like the rest of the `[network]` table (an untrusted
project cannot blind you to what its agent tried to reach). `sbx net rules` and
`sbx config show` both list the mute rules, so the suppression is never silent.

That includes the [rejected bare `*`](rules#no-catch-all): a mute list has no
catch-all spelling either. To silence everything on purpose, write `re:.*` and read it
back in `sbx net rules` (`--all` still brings every muted line back).

You can edit the list from the CLI instead of the TOML, with the same scopes as
`allow`/`deny` (a project write re-trusts; `-a <app>`/`-g` target a profile or the global
config):

```bash
sbx net mute   play.googleapis.com -a agy   # add: quiet a profile's telemetry host
sbx net unmute play.googleapis.com -a agy   # remove (idempotent)
```

A config write needs an existing filtering posture (there is nothing to suppress under
`shared`/`none`), so set one first. You can also mute a **running** session live, `sbx net mute <host> --session [-a <app>] [--all]` folds the rule into the session's
effective policy immediately (writes no file, dies with the session); it is the log-filter
sibling of `sbx net allow|deny --session`. A live mute is not un-loaded by `unmute` (a log
filter has no counter-verdict): it simply ends with the session.

### Live-only: never written to disk

> **The log lives in the running session's memory and is NEVER written to disk.**
> It shows a session *while it runs*, watch it from another terminal, and once the
> session exits, nothing remains. There is no post-session forensics, no log file, no
> rotation.

This is deliberate: the event data lives at the same trust level as the injected
secret the proxy already holds in RAM (owner-only, host-side, ephemeral, never in
the cage). Only a **filtering** posture has a proxy, so only `deny`/`allow`/`ask`
sessions have a log: `shared`/`none` have nothing to log.

### Verdicts: a superset of `stats`

The log's verdicts are a **superset** of the `stats` counters:

- **allow**: permitted and egressed.
- **deny**: refused by a rule, a method scope, or an `ask` decision.
- **blocked**, refused by a security or protocol guard (SSRF, host/SNI mismatch,
  outbound-secret, an IP-literal target, a malformed/smuggling request, a splice
  cap).
- **error**: the request was **allowed but did not complete**: a DNS failure, an
  unreachable upstream, a rejected certificate.

`error` is the extra one: it is **not** a `stats` counter (stats count policy
verdicts, not transport failures), so *the log's lines do not reconcile with
`sbx net stats` totals*. "Allowed but it failed" reads differently from "we said
no," which is the log's whole job: answering *why did it fail just now?*

### `--with-status` and `--with-query`

- **`--with-status`** adds the upstream HTTP status (200/404/5xx) the server
  answered, for a completed **L7** (inspected `https://`) request only; an L4
  (`tcp://`) splice, a refusal, or an `error` shows `-` (no HTTP response to read).
  This is the server's answer to a *delivered* request, distinct from the egress
  verdict: an allowed request can still get a 404. Under `--follow --with-status`, an
  event whose response has not yet returned first appears with no status, then
  reappears once carrying its status (a live tail cannot un-print a line); the
  one-shot listing shows each status directly.
- **`--with-query`** keeps the URL query in the shown path (dropped by default, since
  a token can ride in a query). It is already redacted: the proxy masks configured
  secret values before an event enters the log.

### Seeing the traffic: `[network] capture`

The log answers *which* requests crossed. With `[network] capture` on, it also
answers *what* crossed: the request and response heads, and optionally the leading
bytes of each body.

It is **off by default** and is a **trusted/global-only** setting, like the rest of
the `[network]` table: an untrusted project's `.sbx.toml` cannot start capturing its
own traffic. For a one-off debugging run, turn it on for that launch only:

```bash
sbx run --config '[network] capture = "bodies"'
sbx net logs --with-body --follow    # from another terminal
```

Or, in a trusted config file:

```toml
[network]
mode = "deny"
allow = ["api.example.com"]
capture = "bodies"       # "off" (default) | "headers" | "bodies"
capture_max_kb = 32      # per body; default 8, ceiling 1024
```

The traffic prints as an indented block under its event line, `>` for what the cage
sent and `<` for what came back:

```
  1234  12:04:31  https/h1  api.example.com:443  POST /v1/messages  allow  200
      > POST /v1/messages HTTP/1.1
      > host: api.example.com
      > content-type: application/json
      > authorization: <injected by sbx>
      > {"model":"…","messages":[{"role":"user","content":"hi"}]}
      < HTTP/1.1 200 OK
      < content-type: text/event-stream
      < data: {"type":"message_start", …
      < … truncated, more followed (8192 byte(s) shown)
```

`--with-body` implies `--with-headers` (a body without its head names nothing).

#### What a capture never contains

- **Any configured secret.** Every value is masked to an equal-length run of `*`
  before the bytes are stored, so the capture ring never holds a credential: not in a
  request, and not in a response that reflects one back.
- **Any credential sbx injects.** The head recorded is the **client's own** as it stood
  *before* the [injection](../configuration/secret) happens, so an injected value
  cannot reach the capture even in principle. The injected headers are listed by
  **name** only, marked `<injected by sbx>`, so the capture is not mistaken for the
  whole of what the upstream received.

#### What a capture covers

Every exchange sbx inspects:

- **HTTPS** (`https://`, the MITM'd `CONNECT`) and inspected **cleartext**
  (`http://`): the request and response heads exactly as they crossed, plus the
  leading bytes of each body. One header is an exception, and only under
  [`[network] pool`](../configuration/network#reusing-connections-pool): the
  capture records the response's `Connection` as the **upstream** sent it, while the
  cage is always told `close`, because the two connections have separate lifetimes. So
  a capture may read `keep-alive` on an exchange whose client was told to close. That
  is the honest record of what each side said, not a discrepancy.
- **HTTP/2 and gRPC** ([`[network] http2`](rules)): the same, per stream. HTTP/2
  carries a head as compressed pseudo-headers rather than as text, so sbx renders it
  instead of copying it. The pseudo-headers keep their real names, so what you read is
  what crossed:

  ```
  > POST /pkg.Greeter/SayHello HTTP/2
  > :authority: grpc.example.com
  > content-type: application/grpc
  < HTTP/2 200
  < content-type: application/grpc
  ```

  There is no reason phrase (`HTTP/2 200`, not `200 OK`) because HTTP/2 sends none.
- A **WebSocket**, handshake and traffic. The upgrade `GET` and the upstream's
  `101 Switching Protocols` land as the two heads; the messages that cross afterwards
  land as two more parts, one per direction:

  ```
  > GET /realtime HTTP/1.1
  < HTTP/1.1 101 Switching Protocols
  > {"type":"session.update"}{"type":"input_audio_buffer.append", …
  < {"type":"session.created"}{"type":"response.delta", …
  ```

  A frame the cage sends is XOR-masked on the wire (the protocol requires it), so what
  is captured is the payload **unmasked**: exactly what the sender sent. A peer that
  negotiated `permessage-deflate` compresses each message, and those are **decompressed**
  too, so a compressed tunnel reads the same as a plain one. Message boundaries are not
  kept, so successive messages read run together, which for the JSON-per-message
  protocols this is used on stays readable. Control frames (ping, pong, close) carry no
  application data and are skipped.

  **When it appears.** A WebSocket is the one exchange shown in steps, because a tunnel
  outlives its handshake: the handshake appears immediately at the `101`, then **each
  direction** as its own capture fills, and once more when the tunnel closes. Each
  direction has its own trigger on purpose, since one side of a live stream can fill in
  seconds while the other trickles for hours. So a busy tunnel shows its traffic within
  seconds of opening rather than only at teardown. A transcript shown while the tunnel is
  still open is marked cut, because more may still cross.

### A secret crossing a WebSocket

Separately from the capture, and shown **with no flag asked for**, `sbx net logs` reports a
configured secret seen crossing an exchange's WebSocket tunnel:

```
14:22:07  allow   chat.example.com:443  GET /realtime
      ! secret `openai-key` crossed this websocket (upstream → cage); it was NOT blocked or masked
```

Read the second half of that line literally. Unlike the two HTTP tripwires in
[Redaction](../secrets/redaction), which refuse an outbound request with a `403` and mask a
reflected value out of a response, **nothing was stopped here**. An open tunnel is a
byte-exact pipe between two peers that agreed their own framing, masking and compression, so
the frame reached its destination exactly as it was sent. What sbx does is tell you that it
did, while the tunnel is still open.

- **Both directions.** `cage → upstream` is the agent sending a credential out;
  `upstream → cage` is the far side sending one back.
- **By name, never by value.** The credential's configured name is printed; its value stays
  on the host, as everywhere else.
- **Once per credential per direction.** A value that keeps crossing says nothing new, and
  repeating it would turn an alarm into noise.
- **Independent of `capture`.** It runs whenever a secret is configured, whether or not the
  launch captures. A check that followed a debugging setting would be missing exactly when it
  mattered. It sees the same decoded payloads a capture would, so a masked frame and a
  `permessage-deflate` message are both scanned as the text they carry.
- **Byte-exact, per message.** Like the other tripwires it matches a verbatim value; a
  re-encoded one, or one split across two separate messages, is out of scope by design.
  Within one message a value spanning several frames is still seen.

Under `--json` the same fact rides on every event as `secrets_seen`, a possibly-empty list of
`{"name": …, "way": "out"|"back"}`.

#### What a capture does not cover

- A raw **`tcp://` splice**: there is no HTTP head to read, so a method and a body are
  not merely unimplemented there, they do not exist. Byte counts only:
  see [`sbx net live`](#sbx-net-live).
- A **refused** request: nothing was forwarded, so there is no traffic to show. The
  refusal itself is the log line.

A body is printed as text when it is text, and summarized as
`<N byte(s) of binary data>` when it is not. A `Content-Encoding: gzip` body is
captured **compressed** and reads that way: sbx does not decompress it. Under
`--json` every part is base64-encoded, so a binary body survives the round trip
intact.

#### Bounds

A capture is bounded three ways, and never trims in silence:

- **Per body**: `capture_max_kb` (default 8 KiB, ceiling 1024). A body that was cut is
  marked `… truncated, more followed`. The marker names the fact, not a cause: a body
  is also marked when the exchange was filed while more was still arriving, which an
  HTTP/2 request body can be (its pump runs concurrently with the response, and a
  server may answer without draining it). A prefix is never shown as if it were whole.
- **Per exchange count** and **by a total byte budget**: past it, the *oldest*
  captures are dropped and the count is reported (`N earlier capture(s) evicted`).

Like the log itself, a capture lives **only in the running session's memory**: never
written to disk, never bound into the cage, gone when the session exits. The relay is
untouched by it: the capture is a tee, so the cage receives every byte exactly as it
would with the capture off, streaming included.

### `--follow`

`--follow` prints the current listing, then appends new events as they happen (a
`tail -f`) until Ctrl-C, polling every `--interval` seconds (default 1). If the
in-memory ring overflowed between polls, the dropped count is announced, never
silently skipped; a session that ends is noted, and a new one is picked up. The
append shape is pipe-friendly, and `--json` streams one event object per line. An
exchange whose traffic is being captured appears first as a bare line, then **once**
more: complete, with its status and its traffic, when it finishes. A followed
exchange is never printed piecemeal.

The one exception is a **WebSocket**, which is genuinely several events rather than one:
it appears when the tunnel opens (with its handshake), then as each direction's transcript
fills, then once more at close if that changed anything. **Four lines of traffic** over the
tunnel's whole life is the ceiling, and it is never re-emitted showing what it already
showed. A [secret sighting](#a-secret-crossing-a-websocket) adds at most one line per
credential per direction on top of that, since it re-emits the event too. Nothing else is
ever re-emitted more than once.

---

## `sbx net live`

The **live, `top`-style** view of the egress tunnels **currently open**: one line per
flow, redrawn in place, watchable from another terminal:

```bash
sbx net live               # every open tunnel, redrawn every 1s until Ctrl-C
sbx net live -a claude     # only one app's sessions
sbx net live -i 2          # redraw every 2 seconds
sbx net live --json        # one snapshot object per tick (NDJSON), for a pipe
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

- **Transport**, `https` (inspected TLS), `http` (inspected cleartext), or `tcp` (a raw
  L4 [`tcp://`](rules) splice).
- **Bytes**: `↑` client→upstream, `↓` upstream→client. **Application bytes** on an
  inspected `https`/`http` flow (the proxy sees the plaintext); **encrypted bytes** on a
  raw `tcp` splice (the tunnel is opaque). A value climbing between two frames is a
  transfer in progress.
- **What you'll see**: a row is one inspected *request* in flight, not the tunnel carrying
  it, so short API calls flash by in under a second even when the tunnel that served them
  stays open for the next one. The durable rows are raw `tcp://` tunnels (SSH, a database
  wire), WebSockets, and large L7 transfers in progress (a download, a streamed
  completion). An idle session shows an empty list: that is normal.

Like the log, it is **live-only and never written to disk**, read from the same
per-session control socket, and only a **filtering** posture (`deny`/`allow`/`ask`) runs a
proxy, so only those sessions have flows. The redraw needs a terminal; `--json` works in
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

- [The four lenses](../concepts/observability#the-four-lenses): this is the egress one; the others watch exec, file writes, and ssh signatures.
- [Network modes](modes): the postures these surfaces describe.
- [Rule grammar](rules): how a rule is written, tested, and rendered.
- [Ask mode](ask): `sbx net rules --source session` and the parked-request flow.
- [Architecture](architecture): the SSRF guard and anti-fronting checks behind
  the `blocked` verdicts.
- The egress event log's live-only design + rationale now lives in this page and in [`architecture.md`](architecture).
- [`sbx net` CLI reference](../cli/net) · [`sbx test` CLI reference](../cli/test)
