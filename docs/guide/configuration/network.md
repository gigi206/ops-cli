# `network` — the egress posture

The sandbox's network posture. This page documents the **config shape**; for what each
mode does, the rule grammar, ask mode, and observability, see the
[Networking](../networking/README.md) section.

`network` is a **security field** — honored from the global config or a trusted
project, ignored from an untrusted one — since narrowing or widening the network is a
confidentiality choice an untrusted project may not make.

See also: [Network modes](../networking/modes.md) · [Rule grammar](../networking/rules.md) · [`[net.groups]`](net-groups.md) · [`[secret]`](secret.md).

## The two forms

`network` accepts either a **bare string** or a **table**.

```toml
# string form — a bare posture
network = "none"
# network = "shared"
# network = "deny"
# network = "allow"
# network = "ask"
```

```toml
# table form — a filtering mode plus carve-out lists
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
| `deny` | **deny-by-default** — only `allow`-listed hosts reach (an allowlist) |
| `allow` | **allow-by-default** — every host reaches except `deny`-listed ones (a denylist) |
| `ask` | park-and-confirm — an undecided host blocks until you answer |

`deny` always wins over `allow` within a table. See [Network modes](../networking/modes.md)
for the full semantics.

## Table fields

| Field | Meaning |
|---|---|
| `mode` | the egress mode; **absent** = inherit a filtering mode from the parent layer |
| `allow` | egress rules that may reach (under `deny`) / auto-pass (under `ask`) |
| `deny` | egress rules that may not reach (under `allow`) / auto-fail (under `ask`) |
| `mute` | egress rules whose **denied** requests are kept out of the default [`sbx net log`](../networking/observability.md#muting-noisy-refusals--network-mute-selinux-dontaudit) (SELinux `dontaudit`) — a log filter, never a verdict change; still counted in `stats`, shown by `sbx net log --all` |
| `ask_timeout` | a duration (`"90s"`, `"5m"`) bounding a parked `ask` request; absent = indefinite |
| `ask_notice` | `false` silences the inline stderr park alert (the request still parks) |
| `stats` | `false` turns off the per-host decision counters ([`sbx net stats`](../networking/observability.md)) |
| `dns_cache_ttl` | seconds the proxy caches a host's resolved address (default `60`; `0` disables the cache) |
| `http2` | hosts the proxy man-in-the-middles as **HTTP/2** (ALPN `h2`, for gRPC) instead of HTTP/1.1 — see below |
| `default_methods` | an **app's** read-by-default verbs (see below) |

The `allow`/`deny` entries follow the [rule grammar](../networking/rules.md): a host,
`*.domain`, `host/path`, an IP, `re:<regex>`, `http://host` (inspected cleartext),
`tcp://host:port` (raw), an optional `{GET,POST}` verb prefix, or `@<group>`
referencing a [`[net.groups]`](net-groups.md).

## DNS resolution (`dns_cache_ttl`)

Because the cage runs in an empty network namespace, the host-side proxy resolves each allowed
host's name. A long build (a `nix`/flake build fetching from `cache.nixos.org` thousands of times)
would otherwise re-resolve the same host on every request. The proxy therefore **caches** each host's
address for `dns_cache_ttl` seconds (default 60; `0` disables it, resolving every request). The
per-request SSRF address check still runs on the cached address — the cache only skips re-resolving,
never the security check. It is trusted/global-only like the rest of the table. (There is no
proxy-level retry: the client — `nix`/`git`/`curl` — already retries the whole request, which
re-triggers resolution, so a retry here would be redundant.)

```toml
[network]
mode = "deny"
allow = ["cache.nixos.org"]
dns_cache_ttl = 60   # seconds (0 = resolve every request)
```

## HTTP/2 and gRPC

By default the filtering proxy speaks **HTTP/1.1** to every host. A **gRPC** service needs
**HTTP/2**, so list its host in `http2` and the proxy man-in-the-middles that host as HTTP/2
(ALPN `h2`) instead — decrypting and inspecting every gRPC stream, exactly like the HTTP/1.1 path:
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
  `{POST}` (or `{*}`). (`sbx run`/`sbx shell` are all-verbs, so the baseline is less strict — but be
  explicit.)
- **`http2` selects the transport, not the verdict.** A host must still be permitted by an `allow`
  rule; `http2` only decides HTTP/2-vs-HTTP/1.1. It is `host` or `host:port` (a bare host matches any
  port). HTTP/2 is negotiated per `host:port` at the TLS handshake, so it is always whole-endpoint —
  there is no per-path HTTP/2.
- **Designated hosts are HTTP/2-only.** The proxy offers only `h2` to an `http2` host, so an
  HTTP/1.1-only client reaching it fails the handshake (deliberate — designate only gRPC endpoints).
- **Secrets work on HTTP/2 too.** A [`[secret]`](secret.md) scoped to a gRPC host is injected into the
  request (host-side, never in the cage), the outbound tripwire refuses a request that carries a secret
  value verbatim, and a reflected secret is masked out of the response — exactly like the HTTP/1.1 path.
  One honest limit: response masking is a byte scan, so a secret inside a **gzip-compressed** gRPC
  message (gRPC compresses more often than plain HTTP) is not masked — the same limit gzip already
  imposes on the HTTP/1.1 path.
- **mTLS / certificate-pinned** gRPC cannot be man-in-the-middled; those need a raw
  [`tcp://`](../networking/rules.md) passthrough (a separate capability).
- Trusted/global-only like the rest of the table; a malformed entry is dropped with a warning
  (that host keeps HTTP/1.1).

## When a host is refused

Under `mode = "deny"`, a request to a host **no allow rule matched** is refused with a
`403` whose body names the host and suggests how to permit it — e.g.
`… is not allowed by the network policy. Allow it: sbx net allow github.com`. The hint
rides the response the client already receives (scoped `--app <name>` under an
[`sbx app`](../cli/app.md) launch), so it reaches whoever made the request. It appears only
for a host nothing allowed — an **explicit** `deny` rule or a security refusal (an SSRF
target, a leaked credential) never suggests allowing it.

A refused request is *not* a rule, so it does **not** appear in
[`sbx net rules`](../cli/net.md) (which lists the policy). To see what was refused, use
[`sbx net logs`](../networking/observability.md) (each request and its verdict) or
[`sbx net stats`](../networking/observability.md) (per-host deny counters) — both take
`-a <app>`. Once you run the suggested `sbx net allow`, the host becomes an allow rule and
*then* shows in `sbx net rules`.

## Mode inheritance

A table may **omit** `mode` to inherit it from the parent config layer (an app takes
the baseline's, a project takes the global's) while keeping its own `allow`/`deny`
rules. Only a *filtering* mode (`deny`/`ask`) is inherited — an `allow` denylist,
`shared`/`none`, or no parent posture all fall back to the safe `deny`. This lets a
profile add rules without re-declaring the mode.

## `default_methods` (apps)

A Mode-B app's unscoped (`{...}`-less) `allow` rules default to `["GET", "HEAD"]` — an
agent reads but does not write unless a rule opts a host out with `{*}`/`{VERB}`. This
field overrides that default for the app (e.g. `["GET", "POST"]`, or `["*"]` for all
verbs). It is **ignored on the baseline `[network]`** — `sbx run`/`sbx shell` (Mode A)
stay all-verbs.

## Editing

`network` as a table is edited with [`sbx config edit`](../cli/config.md), or a rule
is added with [`sbx net allow`/`deny`](../cli/net.md):

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
SBX_NET=shared sbx shell
```

`--net` takes `none | shared | ask | allow=h1,h2 | deny=h1,h2` (a bare `allow`/`deny`
is refused as ambiguous). The command line beats the environment, and both beat the
config file. For the full grammar and the four-tier precedence, see
[One-shot overrides](overrides.md).
