# `[secret]` — credential injection

Credentials the [egress proxy](../networking/architecture.md) injects into matching
outbound requests, keyed by destination host. This page documents the **config
shape**; for the architecture (the never-in-cage invariant, resolvers, redaction) see
the [Secrets](../secrets/README.md) section.

`[secret]` is a **security field** — honored from the global config or a trusted
project, ignored from an untrusted one — and **effective only under a filtering
network posture** (`deny`/`allow`/`ask`), because the filtering proxy is what performs
the injection.

See also: [Secrets architecture](../secrets/README.md) · [Resolvers](../secrets/resolvers.md) · [Injection](../secrets/injection.md) · [`network`](network.md).

## The invariant

`ops` **never places a plaintext secret in the cage**. The value is read **host-side**
and injected into the matching outbound request on the wire; the plaintext never
enters the sandbox. So a credential belongs in `[secret]`, **not** in
[`env`](env.md) (which is visible inside the cage).

## Keyed by host

`secret` is a TOML *table* keyed by destination host, not an array — the host is the
section, so a credential's destination reads at a glance:

```toml
# one credential for a host
[secret."api.github.com"]
from   = "env://GITHUB_TOKEN"
header = "Authorization"
type   = "bearer"

# several credentials to one host (an array of tables)
[[secret."registry.example.com"]]
key = "reg_a"
header = "X-A"
type = "raw"
[[secret."registry.example.com"]]
key = "reg_b"
header = "X-B"
type = "raw"
```

## A secret entry's fields

| Field | Meaning |
|---|---|
| `kind` | the broker kind; defaults to the only kind today, `"http-header"` |
| `key` | a **terse** source name, expanded through `[secret.defaults]` (optionally pinned `key@resolver`) |
| `from` | an **explicit** source: one `scheme://locator` ref, or an array = a fallback chain |
| `header` | the header name to set (e.g. `Authorization`, `x-api-key`) |
| `type` | how to shape the value: `bearer`, `basic`, or `raw` |
| `prefix` | override the type's default prefix (`Bearer ` / `Basic ` / empty) |

A secret must have **exactly one** of `key` or `from`. It must have a `header` and a
`type`, either on itself or from `[secret.defaults]` — a secret that names neither is
an **explicit error**, never a silent (and likely wrong) default.

## `[secret.defaults]`

A reserved `defaults` table holds the resolver order and per-resolver bindings the
terse `key` form expands through, plus a default `header`/`type` any entry may omit:

```toml
[secret.defaults]
order  = ["env", "sops"]   # try env:// first, then sops://
header = "Authorization"
type   = "bearer"
[secret.defaults.sops]
file = "secrets/prod.yaml"
[secret.defaults.env]
case = "upper"             # a terse key `k` → env var UPPER(k)
[secret.defaults.file]
dir  = "/run/secrets"

[secret."api.github.com"]
key = "github_token"       # → env://GITHUB_TOKEN, else sops://secrets/prod.yaml#github_token
```

Because `defaults` is reserved, a host cannot be named `defaults`.

## The source: `key` vs `from`

- **`from`** is explicit — one resolver ref (`from = "env://VAR"`) or a fallback chain
  (`from = ["env://VAR", "sops://f#k"]`, tried in order, first to resolve wins).
- **`key`** is terse — a bare key expanded through the `[secret.defaults] order` and
  per-resolver bindings, optionally pinned to a resolver with `key@resolver`.

Built-in resolvers are `env://`, `file://`, `sops://`; more come from
[resolver plugins](../secrets/plugins.md). See [Resolvers](../secrets/resolvers.md).

## Per-app secrets

An `[app.<name>.secret]` section declares credentials for that app, gated and
effective the same way. Since an app's home is isolated and its egress bounded, a
credential is injected on the wire to the allowlisted host and never persists in the
cage. See [`[app.<name>]`](apps.md) and [the app framework](../apps/README.md).

## Viewing

```sh
ops config show           # "secrets: N injected host-side" (the value is never shown)
ops config show --details # each credential by destination host and source
ops test net <url>        # notes a declared injection for that host (by header/source)
```
