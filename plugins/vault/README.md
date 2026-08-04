# `vault://` — a HashiCorp Vault KV field

Fetches one **field** of a Vault KV secret and prints its value.

```
vault://<path>#<field>
```

| Reference | Resolves to |
|---|---|
| `vault://secret/myapp#password` | the `password` field of `secret/myapp` |
| `vault://secret/data/ci#token` | the `token` field of `secret/data/ci` |

The `#<field>` part is **required** — a KV secret holds several fields, and guessing which one is
meant is exactly the kind of silent choice a secret resolver must not make.

Used in a project's `.sbx.toml`:

```toml
[secret.DB_PASSWORD]
from = "vault://secret/myapp#password"
```

## Installing

```
sbx plugins install ./plugins/vault
```

Or from a signed store that publishes it — see [the plugins
README](../README.md) for both paths and what each guarantees.

## What it needs on the host

The `vault` CLI must be on sbx's `PATH`, and the resolver reads its own credentials from sbx's
environment:

| Granted | Why |
|---|---|
| `VAULT_ADDR` | the server to reach |
| `VAULT_TOKEN` | the resolver's own credential |
| `VAULT_NAMESPACE` | the namespace, on Vault Enterprise |
| `network = true` | the server is remote |

Each is passed through **only when set** in sbx's environment. That is how a resolver receives its
own credential without it travelling anywhere another user could read it — see [the cage's
environment is not readable by other
users](../../docs-site/docs/guide/concepts/security-model.md#the-cages-environment-is-not-readable-by-other-users).

`network = true` means the **host** network, not a cage's egress allowlist: a resolver runs
host-side, outside the agent's sandbox, so its reachability is not governed by a project's
`[network]` rules. That is the trade for talking to a remote secret engine, and it is worth
knowing before granting it.

## Behaviour

| Situation | Exit | stdout |
|---|---|---|
| the field is found | `0` | its value |
| the ref is not `vault://…`, or names no `#field` | non-zero | — (the reason goes to stderr) |
| `vault kv get` fails (no token, no such path or field, unreachable server) | non-zero | — |

A non-zero exit is a **hard** failure: sbx names the resolver, folds in its stderr, and never
falls through to a weaker source in a `from = [...]` chain — a Vault that is merely unreachable
must not silently downgrade a secret to something else.
