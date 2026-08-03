# `sbx plugins`

```
sbx plugins <subcommand> [args...]
sbx plugins store <subcommand> [args...]
```

Inspect and manage **resolver plugins** and **plugin stores**. Host-level: reads the
data directory, not a project's config. A resolver plugin declares a `scheme://`
`sbx` can route a secret [`from`](../configuration/secret.md) reference to.

See also: [Resolver plugins and stores](../secrets/plugins.md) · [Resolvers](../secrets/resolvers.md) · [Secrets architecture](../secrets/README.md).

## Plugins

| Subcommand | Purpose |
|---|---|
| `list` (alias `ls`) | list installed resolver plugins (with their origin) and the built-in schemes |
| `info <scheme>` | show a plugin's manifest, sandbox grant, and origin |
| `install <dir>` | install a local plugin directory (`<data>/plugins/<name>`); the built-in schemes are always present, not installed |
| `rm <name>` | remove an installed resolver plugin |
| `verify [name]` | check installed plugins against the digest recorded at install |
| `upgrade [name] [--dry-run]` | replace installed plugins with what their store lists now |

`install` is a deliberate user act (an agent in the cage cannot run it); the staged
copy is validated exactly as the launcher will and refused, fail-closed, on any flaw.

Each listing reports where a plugin came from: a named store (with its URL) or a
local directory (with its path). A plugin installed before origins were recorded
reads as unknown.

Every install records the **digest of the tree it placed**. `verify` re-hashes and
compares, `list` marks a changed plugin `[modified since install]`, and `info` states
it on an `integrity:` line. This is **drift detection, not a security control**: see
[Resolver plugins and stores](../secrets/plugins.md#a-plugin-edited-after-it-was-installed).

A `scheme://` belongs to **one** plugin. Every install path refuses a scheme that is
already claimed, so the only way to two claimants is to place a plugin directory by
hand, and then the scheme resolves to **nothing** and *both* are disabled. `list`
reports it under `scheme conflicts`, `info <scheme>` names every claimant and exits
non-zero, and a further install is refused too. Removing all but one restores it.

## Stores

A **remote signed store** is a git repository whose catalogue is verified against a
pinned Ed25519 public key, with anti-rollback on the revision.

```
sbx plugins store list
sbx plugins store add --name <n> --url <git-url> (--key <hex|@file> | --trust)
sbx plugins store update [name]
sbx plugins store install <store> <plugin>
sbx plugins store verify <name> --key <hex|@file>
sbx plugins store rekey <name> (--key <hex|@file> | --trust) [--yes]
sbx plugins store info <name>
sbx plugins store rm <name>
sbx plugins store publish <dir> --key <key-file> [--rev <n>]
```

| Subcommand | Purpose |
|---|---|
| `list [--installed]` (alias `ls`) | every configured store, expanded to the plugins it lists; `--installed` keeps only what is already in place |
| `add` | configure and fetch a store; exactly one of `--key` (pin out-of-band) or `--trust` (accept the shipped key on first use) is required. With neither, sbx shows the key the store ships and stops without configuring anything |
| `update [name]` | re-fetch and re-verify one or all stores (refuses a rollback) |
| `install <store> <plugin>` | install a plugin the store lists (pinned by content hash) |
| `verify <name> --key <hex\|@file>` | confirm a store's pinned key against one obtained from a source the store does not control |
| `rekey <name> (--key \| --trust) [--yes]` | replace the pinned key when a store rotated its signing key: prints a security alert and asks a terminal to confirm |
| `info <name>` | detail a configured store, how its key was trusted, and the plugins it lists |
| `rm <name>` | remove a configured store |
| `publish <dir> --key <key-file>` | **operator tool**: sign a directory of plugins into a store |

A store whose key was accepted rather than supplied is flagged
`[key not confirmed elsewhere]`, with the `verify` command to close it on the next line. The catalogue's
signature *is* verified against that key on every fetch: what is missing is a second
source for the key, since the store shipped both. Once pinned, a later key change is
refused either way. `verify` is how that flag ends: it matches the pinned key against
one you supply, and changes no enforcement: only the record of what you confirmed.

Both listings mark each entry: `[installed]` when it is in place *from that store*,
`[update available: vX → vY]` (or another wording when the versions cannot be
ordered) when the catalogue pins a **different tree** than the one installed,
`[name taken by …]` or `[scheme x:// taken by …]` when something else holds the
name or the scheme (two stores may list a plugin of the same name, but only one can
hold it), `[… in conflict …]` when the scheme is contested: the entry cannot be
installed, and an installed claimant resolves nothing: and nothing at all when it
simply installs.

What decides is the digest the catalogue pins against the one the install
recorded, never the version string: so a republish under an unchanged version is
seen. `sbx plugins upgrade` acts on it, keeping the installed plugin until the new
tree is in place. Comparisons read the *cached* catalogue: run
`sbx plugins store update` first.

`publish` is the producing counterpart of `add`; the signing key is the store's secret
and never leaves the operator's host. See
[Resolver plugins and stores](../secrets/plugins.md).
