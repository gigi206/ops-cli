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
| `ask_timeout` | a duration (`"90s"`, `"5m"`) bounding a parked `ask` request; absent = indefinite |
| `ask_notice` | `false` silences the inline stderr park alert (the request still parks) |
| `stats` | `false` turns off the per-host decision counters ([`ops net stats`](../networking/observability.md)) |
| `refusal_notice` | how often to print the stderr refusal notice under `deny`: `"off"` / `"once"` (default) / `"each"` (see below) |
| `default_methods` | an **app's** read-by-default verbs (see below) |

The `allow`/`deny` entries follow the [rule grammar](../networking/rules.md): a host,
`*.domain`, `host/path`, an IP, `re:<regex>`, `tcp://host:port`, an optional
`{GET,POST}` verb prefix, or `@<group>` referencing a [`[net.groups]`](net-groups.md).

## The refusal notice

Under `mode = "deny"`, when a request is refused because **no allow rule matched** the
host, the proxy prints a one-line alert to the host's stderr — a red `ops: egress refused
<host>:<port>` plus a yellow copy-paste `ops net allow <host>` — so an interactive user
sees *what* was blocked and *how* to permit it, in the spirit of `ask` mode:

```toml
[network]
mode = "deny"
allow = ["cache.nixos.org"]
refusal_notice = "once"   # "off" | "once" (default) | "each"
```

- `"once"` (default) prints the alert the **first** time a given `host:port` is refused
  in a session, then stays silent for it — visible without an agent's retries spamming it.
- `"each"` prints on every refused request; `"off"` prints nothing (only the `403` reaches
  the in-cage client).

The suggestion is shown **only** for a host nothing allowed. An **explicit** `deny` rule,
or a security refusal (a leaked credential, an SSRF target), never prints it — blocking
those is deliberate, and `ops net allow` is not the answer. The colour auto-detects
(plain when stderr is piped or `NO_COLOR` is set). Meaningful only under `deny` — the only
mode that produces such a refusal; set elsewhere it is ignored with a warning.

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
verbs). It is **ignored on the baseline `[network]`** — `ops run`/`ops shell` (Mode A)
stay all-verbs.

## Editing

`network` as a table is edited with [`ops config edit`](../cli/config.md), or a rule
is added with [`ops net allow`/`deny`](../cli/net.md):

```sh
ops net allow api.github.com          # bootstrap a deny-by-default allowlist
ops net deny evil.example.com --global
ops config edit --trust               # edit the table by hand, then re-trust
```

## One-shot override

To set the posture for a single launch without editing the file, use `--net` or
`OPS_NET`:

```sh
ops run --net none -- ./build.sh                # cut the network for one run
ops run --net allow=api.github.com -- ./ci.sh   # a one-shot allowlist
OPS_NET=shared ops shell
```

`--net` takes `none | shared | ask | allow=h1,h2 | deny=h1,h2` (a bare `allow`/`deny`
is refused as ambiguous). The command line beats the environment, and both beat the
config file. For the full grammar and the four-tier precedence, see
[One-shot overrides](overrides.md).
