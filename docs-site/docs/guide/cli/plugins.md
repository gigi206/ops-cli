# `sbx plugins`

```
sbx plugins <subcommand> [args...]
sbx plugins store <subcommand> [args...]
```

Inspect and manage **resolver plugins** and **plugin stores**. Host-level: reads the
data directory, not a project's config. A resolver plugin declares a `scheme://`
`sbx` can route a secret [`from`](../configuration/secret) reference to.

See also: [Resolver plugins](../secrets/plugins) · [Signed plugin stores](../secrets/stores) · [Resolvers](../secrets/resolvers) · [Secrets architecture](../secrets/).

## Plugins

| Subcommand | Purpose |
|---|---|
| `list` (alias `ls`) | list installed plugins of both kinds (with their origin) and the built-in schemes |
| `info <scheme\|name>` | show a plugin's manifest, sandbox grant, and origin |
| `install <dir>` | install a local plugin directory (`<data>/plugins/<name>`); the built-in schemes are always present, not installed |
| `rm <name>...` | remove installed resolver plugins; several names may be given, each removed on its own |
| `verify [name]` | check installed plugins against the digest recorded at install |
| `upgrade [name] [--dry-run]` | replace installed plugins with what their store lists now |

`install` is a deliberate user act (an agent in the cage cannot run it); the staged
copy is validated exactly as the launcher will and refused, fail-closed, on any flaw.

A resolver is named by the `scheme://` it claims. A [broker](../configuration/broker)
claims none, so `info` takes the name `[broker.<name>]` binds, and its page adds the
protocol facts a launch acts on — the framing, the frame ceiling, how long `sbx` waits
on the host resource, how the cage finds the socket — and whether the global config
binds it at all.

Each listing reports where a plugin came from: a named store (with its URL) or a
local directory (with its path). A plugin installed before origins were recorded
reads as unknown.

Every install records the **digest of the tree it placed**. `verify` re-hashes and
compares, `list` marks a changed plugin `[modified since install]`, and `info` states
it on an `integrity:` line. This is **drift detection, not a security control**: see
[Resolver plugins](../secrets/plugins#a-plugin-edited-after-it-was-installed).

A `scheme://` belongs to **one** plugin. Every install path refuses a scheme that is
already claimed, so the only way to two claimants is to place a plugin directory by
hand, and then the scheme resolves to **nothing** and *both* are disabled. `list`
reports it under `scheme conflicts`, `info <scheme>` names every claimant and exits
non-zero, and a further install is refused too. Removing all but one restores it.

## Stores

A **remote signed store** is a git repository whose catalogue is verified against a
pinned Ed25519 public key, with anti-rollback on the revision.

```
sbx plugins store list [<name>]
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
installed, and an installed claimant resolves nothing, and nothing at all when it
simply installs.

What decides is the digest the catalogue pins against the one the install
recorded, never the version string: so a republish under an unchanged version is
seen. `sbx plugins upgrade` acts on it, keeping the installed plugin until the new
tree is in place. Comparisons read the *cached* catalogue: run
`sbx plugins store update` first.

`publish` is the producing counterpart of `add`; the signing key is the store's secret
and never leaves the operator's host. See
[Signed plugin stores](../secrets/stores).

## Examples

### Install a plugin from a local directory

The shortest path: a plugin directory you have on disk (a checkout of one, or one
you wrote), then the `from` reference it unlocks.

```sh
sbx plugins install ./my-pass-plugin   # the local directory is copied in
sbx plugins list                       # built-in schemes + what is now installed
sbx plugins info pass                  # its manifest, sandbox grant, and origin
```

```toml
# now usable in a trusted config
[secret."api.github.com"]
from   = "pass://github/token"
header = "Authorization"
type   = "bearer"
```

### Install from a signed store

The strong form pins the key out of band, so the store cannot vouch for itself:

```sh
sbx plugins store add --name mine --url https://git.example.com/plugins.git --key @store.pub
sbx plugins store list <name>          # what one store offers, each entry marked
sbx plugins store install mine kp      # pinned by content hash; no network
sbx plugins list                       # kp:// now present, origin: store 'mine'
```

Trust-on-first-use instead, then close the gap when you can get the key elsewhere:

```sh
sbx plugins store add --name mine --url https://git.example.com/plugins.git --trust
# listing shows: [key not confirmed elsewhere]
sbx plugins store verify mine --key 3f8a…   # a key obtained from a source the store does not control
```

Or inspect before committing to anything: with **neither** `--key` nor `--trust`,
`add` fetches into a throwaway clone, prints the key the store ships, and configures
nothing.

```sh
sbx plugins store add --name mine --url https://git.example.com/plugins.git
```

### Keep them current

```sh
sbx plugins store update               # re-fetch every store (refuses a rollback)
sbx plugins upgrade --dry-run          # what would change, installing nothing
sbx plugins upgrade                    # …apply it
sbx plugins upgrade kp                 # one plugin only
```

`upgrade` compares the **digest**, not the version string, and reads the *cached*
catalogue: hence `store update` first. The installed tree is kept until the new one
verifies, so a failed upgrade leaves what you had.

### Audit and clean up

```sh
sbx plugins verify                     # every plugin, against the digest recorded at install
sbx plugins verify kp                  # one; exit 1 means its tree changed
sbx plugins rm kp                      # remove the plugin
sbx plugins rm kp pass-old             # several in one call, each removed on its own
sbx plugins store rm mine              # remove the store (installed plugins stay)
```

A `verify` failure is **drift**, not an attack signal: the digest record lives in the
same owner-only directory as the plugin, so whatever can rewrite one can rewrite the
other. It catches a plugin edited in place and forgotten.

`rm` takes several names. Each plugin is removed independently: a name that fails (not
installed, or a directory carrying no `plugin.toml`) leaves the others removed and only
makes the exit code non-zero, while an unsafe name is rejected before anything is
removed at all.

### Resolve a scheme conflict

Two plugins claiming one scheme disable **both**, and the scheme resolves to nothing:

```sh
sbx plugins list                       # reports it under `scheme conflicts`
sbx plugins info pass                  # names every claimant, exits non-zero
sbx plugins rm pass-old                # removing all but one restores the scheme
```

Every install path already refuses a claimed scheme, so this state only arises from a
plugin directory placed by hand.

### Publish a store (operator side)

```sh
sbx plugins store publish ./my-plugins --key ~/.sbx/store-key
sbx plugins store publish ./my-plugins --key ~/.sbx/store-key --rev 7
```

The signing key is the store's secret and never leaves the operator's host;
publishing the resulting git repository is the operator's own step.
