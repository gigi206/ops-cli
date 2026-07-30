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

`sbx` **never places a plaintext secret in the cage**. The value is read **host-side**
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
| `name` | a logical name for the inventory, defaulting to the section key (the destination host) |
| `description` | one line saying what the credential is for, printed beside the name |
| `kind` | the broker kind; defaults to the only kind today, `"http-header"` |
| `key` | a **terse** source name, expanded through `[secret.defaults]` (optionally pinned `key@resolver`) |
| `from` | an **explicit** source: one `scheme://locator` ref, or an array = a fallback chain |
| `header` | the header name to set (e.g. `Authorization`, `x-api-key`) |
| `type` | how to shape the value: `bearer`, `basic`, or `raw` |
| `prefix` | override the type's default prefix (`Bearer ` / `Basic ` / empty) |

A secret must have **exactly one** of `key` or `from`. It must have a `header` and a
`type`, either on itself or from `[secret.defaults]` — a secret that names neither is
an **explicit error**, never a silent (and likely wrong) default.

`name` and `description` are what [`sbx secret list`](../cli/secret.md) prints, and the name matters
for more than tidiness: it is what a substituted value is reported as (`${NAME}`) if a credential ever
reaches a [task's](task.md) output. Two credentials sharing a name are both kept but warned about — a
reader could not tell which one was withheld. Keep a name non-sensitive: it is a label, and it is
shown to the caller. Its character set is narrow (letters, digits, `_`, `-`, `.`) precisely because it
is rendered into output.

For a credential a *declared operation* reads from its environment, see
[`[task.<name>.secret]`](task.md#credentials): there the key **is** the variable, so the reported name
is the variable's own.

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

## Worked example: authenticating the GitHub API

The one most installations end up needing. mise's `aqua:` backend reads the GitHub API to
resolve a tool's release, and **anonymously that is 60 requests an hour per IP** — which a
couple of [`sbx upgrade mise`](../cli/upgrade.md) runs across several apps exhausts. The
symptom is a roll that fails mid-way:

```
mise ERROR Failed to install aqua:owner/tool@latest: HTTP status client error
           (403 rate limit exceeded) for url (https://api.github.com/…)
       github auth: no
       github rate limit: 0/60 (core)
```

`github auth: no` is not a misconfiguration — a cage inherits **three** variables from the
host (`TERM`, `LANG`, `LC_ALL`) and nothing else, so a `GITHUB_TOKEN` set in your shell is
correctly invisible inside it. The fix is not to let it in, but to inject it on the wire:

```toml
[secret."api.github.com"]
from   = "env://GITHUB_TOKEN"
header = "Authorization"
type   = "bearer"
```

`env://` is read **host-side**, from sbx's own environment — where your token already is.
The authenticated ceiling is 5000/hour, and it is a *separate* counter from the anonymous
one, so this takes effect immediately rather than at the next hourly reset. Verify it from
inside a cage:

```sh
$ sbx run -- curl -sS https://api.github.com/rate_limit
{"resources":{"core":{"limit":5000,"used":0,"remaining":5000, …
```

`"limit": 5000` means the header arrived; `60` means it did not — check that the cage is
under a filtering `network` posture (the proxy is what injects) and that its allowlist
reaches `api.github.com`.

**Scope it deliberately.** Declared globally, every cage whose allowlist reaches that host
has its requests authenticated *as you*. It still never sees the token, but it acts with
your identity on that API within whatever its allowlist permits. Put the block in a single
app profile (below) to narrow that to one tool.

## Per-app secrets

An `[app.<name>.secret]` section declares credentials for that app, gated and
effective the same way. Since an app's home is isolated and its egress bounded, a
credential is injected on the wire to the allowlisted host and never persists in the
cage. See [`[app.<name>]`](apps.md) and [the app framework](../apps/README.md).

## Viewing

```sh
sbx config show           # "secrets: N injected host-side" (the value is never shown)
sbx config show --details # each credential by destination host and source
sbx test net <url>        # notes a declared injection for that host (by header/source)
```
