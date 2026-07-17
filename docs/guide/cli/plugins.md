# `sbx plugins`

```
sbx plugins <subcommand> [args...]
sbx plugins store <subcommand> [args...]
```

Inspect and manage **resolver plugins** and **plugin stores**. Host-level — reads the
data directory, not a project's config. A resolver plugin declares a `scheme://`
`sbx` can route a secret [`from`](../configuration/secret.md) reference to.

See also: [Resolver plugins and stores](../secrets/plugins.md) · [Resolvers](../secrets/resolvers.md) · [Secrets architecture](../secrets/README.md).

## Plugins

| Subcommand | Purpose |
|---|---|
| `list` | list installed resolver plugins and the built-in schemes |
| `info <scheme>` | show a plugin's manifest and sandbox grant |
| `install <name\|dir>` | install a built-in (bundled) or local plugin directory |
| `rm <name>` | remove an installed resolver plugin |

`install` is a deliberate user act (an agent in the cage cannot run it); the staged
copy is validated exactly as the launcher will and refused, fail-closed, on any flaw.

## Stores

A **remote signed store** is a git repository whose catalogue is verified against a
pinned Ed25519 public key, with anti-rollback on the revision.

```
sbx plugins store list
sbx plugins store add --name <n> --url <git-url> (--key <hex|@file> | --trust)
sbx plugins store update [name]
sbx plugins store install <store> <plugin>
sbx plugins store info <name>
sbx plugins store rm <name>
sbx plugins store publish <dir> --key <key-file> [--rev <n>]
```

| Subcommand | Purpose |
|---|---|
| `list` | the built-in store, then configured remote stores |
| `add` | configure and fetch a store; exactly one of `--key` (pin out-of-band) or `--trust` (trust-on-first-use) is required |
| `update [name]` | re-fetch and re-verify one or all stores (refuses a rollback) |
| `install <store> <plugin>` | install a plugin the store lists (pinned by content hash) |
| `info <name>` | detail a configured store |
| `rm <name>` | remove a configured store |
| `publish <dir> --key <key-file>` | **operator tool** — sign a directory of plugins into a store |

`publish` is the producing counterpart of `add`; the signing key is the store's secret
and never leaves the operator's host. See
[Resolver plugins and stores](../secrets/plugins.md).
