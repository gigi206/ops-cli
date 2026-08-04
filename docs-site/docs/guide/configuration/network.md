# `network`: the egress posture

The sandbox's network posture. This page documents the **config shape**; for what each
mode does, the rule grammar, ask mode, and observability, see the
[Networking](../networking/) section.

`network` is a **security field**: honored from the global config or a trusted
project, ignored from an untrusted one: since narrowing or widening the network is a
confidentiality choice an untrusted project may not make.

See also: [Network modes](../networking/modes) · [Rule grammar](../networking/rules) · [`[net.groups]`](../networking/groups) · [`[secret]`](secret).

## The two forms

`network` accepts either a **bare string** or a **table**.

```toml
# string form: a bare posture
network = "none"
# network = "shared"
# network = "deny"
# network = "allow"
# network = "ask"
```

```toml
# table form: a filtering mode plus carve-out lists
[network]
mode  = "deny"
allow = ["api.github.com", "*.nixos.org", "@ci-hosts"]
deny  = ["evil.example.com"]
```

## The modes

| Mode | What reaches |
|---|---|
| `none` | nothing (an empty network namespace) |
| `shared` | the host network (the default when unset) |
| `deny` | **deny-by-default**: only `allow`-listed hosts reach (an allowlist) |
| `allow` | **allow-by-default**: every host reaches except `deny`-listed ones (a denylist) |
| `ask` | park-and-confirm: an undecided host blocks until you answer |

`deny` always wins over `allow` within a table. See [Network modes](../networking/modes)
for the full semantics.

## Table fields

| Field | Meaning |
|---|---|
| `mode` | the egress mode; **absent** = inherit a filtering mode from the parent layer |
| `allow` | egress rules that may reach (under `deny`) / auto-pass (under `ask`) |
| `deny` | egress rules that may not reach (under `allow`) / auto-fail (under `ask`) |
| `mute` | egress rules whose **denied** requests are kept out of the default [`sbx net log`](../networking/observability#muting-noisy-refusals-network-mute-selinux-dontaudit) (SELinux `dontaudit`): a log filter, never a verdict change; still counted in `stats`, shown by `sbx net log --all` |
| `ask_timeout` | a duration (`"90s"`, `"5m"`) bounding a parked `ask` request; absent = indefinite |
| `ask_notice` | `false` silences the inline stderr park alert (the request still parks) |
| `stats` | `false` turns off the per-host decision counters ([`sbx net stats`](../networking/observability)) |
| `dns_cache_ttl` | seconds the proxy caches a host's resolved address (default `60`; `0` disables the cache) |
| `pool` | `true` lets the proxy carry a request over an upstream connection an earlier request left behind (default `false`): see below |
| `http2` | hosts the proxy man-in-the-middles as **HTTP/2** (ALPN `h2`, for gRPC) instead of HTTP/1.1: see below |
| `capture` | how much of each inspected exchange to keep for [`sbx net logs --with-body`](../networking/observability#seeing-the-traffic-network-capture): `"off"` (default), `"headers"`, `"bodies"` |
| `capture_max_kb` | bytes kept per captured body, in KiB (default `8`, ceiling `1024`); inert unless `capture = "bodies"` |
| `default_methods` | an **app's** read-by-default verbs (see below) |

The `allow`/`deny` entries follow the [rule grammar](../networking/rules): a host,
`*.domain`, `host/path`, an IP, `re:<regex>`, `http://host` (inspected cleartext),
`tcp://host:port` (raw), an optional `{GET,POST}` verb prefix, or `@<group>`
referencing a [`[net.groups]`](../networking/groups).

## Seeing the traffic (`capture`)

`capture` turns the egress log from *which requests crossed* into *what crossed*: the
request and response heads, and optionally the leading bytes of each body, readable with
[`sbx net logs --with-headers` / `--with-body`](../networking/observability#seeing-the-traffic-network-capture).

```toml
[network]
mode = "deny"
allow = ["api.example.com"]
capture = "bodies"       # "off" (default) | "headers" | "bodies"
capture_max_kb = 32      # per body; default 8, ceiling 1024
```

For a one-off debugging run, prefer the one-shot override, which needs no file edit and
is trusted by invocation:

```bash
sbx run --config '[network] capture = "bodies"'
```

Every inspected path is captured: HTTPS, inspected cleartext,
[HTTP/2 and gRPC](#http2-and-grpc) per stream, and a WebSocket — its handshake, then
the messages each direction carried, unmasked. A raw [`tcp://`](../networking/rules)
splice has no head to read and is the one exception.

Three properties, covered in full on the [observability page](../networking/observability#seeing-the-traffic-network-capture):
every configured secret is masked out of a capture before it is stored (and an
sbx-injected credential never enters one at all); a capture lives only in the running
session's memory, never on disk and never inside the cage; and it is bounded per body,
per exchange count, and by a total byte budget, reporting whatever it drops.

## DNS resolution (`dns_cache_ttl`)

Because the cage runs in an empty network namespace, the host-side proxy resolves each allowed
host's name. A long build (a `nix`/flake build fetching from `cache.nixos.org` thousands of times)
would otherwise re-resolve the same host on every request. The proxy therefore **caches** each host's
address for `dns_cache_ttl` seconds (default 60; `0` disables it, resolving every request). The
per-request SSRF address check still runs on the cached address: the cache only skips re-resolving,
never the security check. It is trusted/global-only like the rest of the table, and invisible from
inside the cage in the same way, so [`sbx config`](../cli/config) names it whenever a layer set one.
(There is no proxy-level retry: the client, `nix`/`git`/`curl`, already retries the whole request,
which re-triggers resolution, so a retry here would be redundant.)

```toml
[network]
mode = "deny"
allow = ["cache.nixos.org"]
dns_cache_ttl = 60   # seconds (0 = resolve every request)
```

## Reusing upstream connections (`pool`)

By default every permitted request opens its own connection to the real server and validates
its certificate before a byte is forwarded. That is one TLS handshake per request, and on a
workload of many small fetches (a `nix` build pulling thousands of paths from
`cache.nixos.org`) it is where most of the time goes. Setting `pool = true` lets a request
that has finished hand its connection to the next one instead of closing it.

```toml
[network]
mode  = "deny"
allow = ["cache.nixos.org", "api.example.com"]
pool  = true
```

Measured on loopback, with the client side unchanged, a small request costs about **470 µs**
with reuse against **730 µs** without it: roughly a third of the per-request cost. Against a
real host the saving is in milliseconds rather than microseconds, because each avoided
handshake also avoids its round trips. Measured against a CDN it ran between **5 and 16 ms**
per request across two runs of the same test. That spread is the link's rather than the
proxy's, which is the useful thing to know about it: the setting is worth measuring on the
workload you actually have, not assuming from a number here.

Like the rest of the table this is trusted and global-only, so a global config can set it for
a project that has no way to observe it: nothing in the cage can tell that a connection was
reused. Whenever a layer set it, [`sbx config`](../cli/config) says so.

### What it does not change

Reuse decides how a permitted request is carried, never whether it is permitted. Every check
runs on every request exactly as before: the allowlist verdict, the `Host`/SNI agreement, the
address guard, the secret tripwires. A reused connection shortens the handshake and nothing
else.

Which connection a request may be given is deliberately narrow. A connection is offered only
to a request that matches on **all** of:

- the same **host and port**, with the certificate that was validated for that name;
- the same **injected credentials**. A connection that carried a
  [credential](../secrets/injection) is never offered to a request that does not receive the
  same one, so reuse cannot widen where a secret has been. Two paths on one host, one of them
  the scope of a `[secret]`, are two separate connections.

And a connection is only kept at all when the response it just carried left it in a known
state: the body ended exactly where its framing said it would, nothing arrived after it, and
the response did not announce a close or a connection-bound authentication scheme (`NTLM`,
`Negotiate`). Anything else closes.

A connection that has waited more than **10 seconds** is dropped rather than reused, and no
more than 64 are held at once (4 per host and credential set), so reuse never turns into an
unbounded set of open sockets. The count is the guarantee; the delay only decides what is
still fresh enough to hand over.

### What it does move

One thing, said here because the list above reads as an exhaustive one. A connection that is
handed over travels to the address that was validated when it was opened, not to a fresh
resolution of the name. The address guard still runs on every request, so a name that starts
resolving to a disallowed address is refused before any connection is taken, and the
certificate was validated for the name, so a reused connection still reaches a server
authenticated for exactly it. What persists is the choice among the addresses a name
legitimately has, for at most the ten seconds above. [`dns_cache_ttl`](#dns-resolution-dns_cache_ttl)
already does the same for sixty by default.

### The residual

A server may close a waiting connection at any moment. The proxy checks before it hands one
over, which catches this whenever the close has already arrived, and it retries once on a
fresh connection when it can. The window it cannot close is the one between that check and
the write, measured in microseconds against a wait measured in seconds. A request that loses
that race gets a `502` named `upstream-closed` rather than a silent empty response.

That residual is why `pool` is off by default. Turn it on when a workload's cost is
per-request rather than per-byte.

## HTTP/2 and gRPC

By default the filtering proxy speaks **HTTP/1.1** to every host. A **gRPC** service needs
**HTTP/2**, so list its host in `http2` and the proxy man-in-the-middles that host as HTTP/2
(ALPN `h2`) instead, decrypting and inspecting every gRPC stream, exactly like the HTTP/1.1 path:
the request's method and `:path` (`/package.Service/Method`) are matched against your `allow`/`deny`
rules, so you can allow a gRPC endpoint whole **or method by method**.

```toml
[network]
mode  = "deny"
allow = [
  "{POST} grpc.example.com:443/helloworld.Greeter/SayHello",  # one RPC…
  "{POST} grpc.example.com:443/health.Health/*",              # …or a whole service
]
http2 = ["grpc.example.com:443"]                              # speak HTTP/2 to this host
```

Notes:

- **`{POST}` is required.** gRPC uses `POST`, but a bare `allow = ["grpc.example.com"]` is
  read-by-default (`{GET,HEAD}`) for an **app**, so every RPC would be refused. Prefix the rule with
  `{POST}` (or `{*}`). (`sbx run` are all-verbs, so the baseline is less strict, but be
  explicit.)
- **`http2` selects the transport, not the verdict.** A host must still be permitted by an `allow`
  rule; `http2` only decides HTTP/2-vs-HTTP/1.1. It is `host` or `host:port` (a bare host matches any
  port). HTTP/2 is negotiated per `host:port` at the TLS handshake, so it is always whole-endpoint: there is no per-path HTTP/2.
- **Designated hosts are HTTP/2-only.** The proxy offers only `h2` to an `http2` host, so an
  HTTP/1.1-only client reaching it fails the handshake (deliberate: designate only gRPC endpoints).
- **Secrets work on HTTP/2 too.** A [`[secret]`](secret) scoped to a gRPC host is injected into the
  request (host-side, never in the cage), the outbound tripwire refuses a request that carries a secret
  value verbatim, and a reflected secret is masked out of the response: exactly like the HTTP/1.1 path.
  One honest limit: response masking is a byte scan, so a secret inside a **gzip-compressed** gRPC
  message (gRPC compresses more often than plain HTTP) is not masked: the same limit gzip already
  imposes on the HTTP/1.1 path.
- **The traffic capture works on HTTP/2 too.** With [`capture`](#seeing-the-traffic-capture)
  on, each stream carries its heads and the leading bytes of each body into
  [`sbx net logs --with-body`](../networking/observability#seeing-the-traffic-network-capture).
  An HTTP/2 head is compressed pseudo-headers rather than text, so sbx renders it under
  the real names (`:authority`, and `HTTP/2 200` with no reason phrase, because HTTP/2
  sends none). A gRPC message is length-prefixed protobuf, so a body usually shows as
  `<N byte(s) of binary data>` unless the service speaks gRPC-Web or JSON.
- **mTLS / certificate-pinned** gRPC cannot be man-in-the-middled; those need a raw
  [`tcp://`](../networking/rules) passthrough (a separate capability).
- Trusted/global-only like the rest of the table; a malformed entry is dropped with a warning
  (that host keeps HTTP/1.1).

## When a host is refused

Under `mode = "deny"`, a request to a host **no allow rule matched** is refused with a
`403` whose body names the host and suggests how to permit it: e.g.
`… is not allowed by the network policy. Allow it: sbx net allow github.com`. The hint
rides the response the client already receives (scoped `--app <name>` under an
[`sbx app`](../cli/app) launch), so it reaches whoever made the request. It appears only
for a host nothing allowed: an **explicit** `deny` rule or a security refusal (an SSRF
target, a leaked credential) never suggests allowing it.

A refused request is *not* a rule, so it does **not** appear in
[`sbx net rules`](../cli/net) (which lists the policy). To see what was refused, use
[`sbx net logs`](../networking/observability) (each request and its verdict) or
[`sbx net stats`](../networking/observability) (per-host deny counters): both take
`-a <app>`. Once you run the suggested `sbx net allow`, the host becomes an allow rule and
*then* shows in `sbx net rules`.

## Mode inheritance

A table may **omit** `mode` to inherit it from the parent config layer (an app takes
the baseline's, a project takes the global's) while keeping its own `allow`/`deny`
rules. Only a *filtering* mode (`deny`/`ask`) is inherited: an `allow` denylist,
`shared`/`none`, or no parent posture all fall back to the safe `deny`. This lets a
profile add rules without re-declaring the mode.

## `default_methods` (apps)

A Mode-B app's unscoped (`{...}`-less) `allow` rules default to `["GET", "HEAD"]`: an
agent reads but does not write unless a rule opts a host out with `{*}`/`{VERB}`. This
field overrides that default for the app (e.g. `["GET", "POST"]`, or `["*"]` for all
verbs). It is **ignored on the baseline `[network]`**: `sbx run` (Mode A)
stay all-verbs.

## Editing

`network` as a table is edited with [`sbx config edit`](../cli/config), or a rule
is added with [`sbx net allow`/`deny`](../cli/net):

```sh
sbx net allow api.github.com          # bootstrap a deny-by-default allowlist
sbx net deny evil.example.com --global
sbx config edit --trust               # edit the table by hand, then re-trust
```

## One-shot override

To set the posture for a single launch without editing the file, use `--net` or
`SBX_NET`:

```sh
sbx run --net none -- ./build.sh                # cut the network for one run
sbx run --net allow=api.github.com -- ./ci.sh   # a one-shot allowlist
SBX_NET=shared sbx run
```

`--net` takes `none | shared | ask | allow=h1,h2 | deny=h1,h2` (a bare `allow`/`deny`
is refused as ambiguous). The command line beats the environment, and both beat the
config file. For the full grammar and the four-tier precedence, see
[One-shot overrides](overrides).
