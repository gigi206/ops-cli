# `[tools]`: a project's mise toolchain

`sbx` honors a project's [mise](https://mise.jdx.dev/) configuration
(`.mise.toml` / `mise.toml` / `.tool-versions`) as its per-project dev toolchain.
This is distinct from the trusted-only [`[packages]`](packages) field: `[tools]`
is the **open, local, self-equip** path, the way an agent equips a project's tools
from inside the cage.

See also: [`packages`](packages) · [Provisioning](../concepts/provisioning) · [`sbx mise`](../cli/mise) · [`sbx upgrade mise`](../concepts/upgrade).

## The `nix:` prefix: an exact, pinned dev toolchain

A tool prefixed `nix:` in a mise `[tools]` table is resolved to the nixpkgs revision
that shipped that version and realised through `sbx`'s own store:

```toml
# .mise.toml
[tools]
"nix:nodejs" = "20"
"nix:jq"     = "latest"
```

The part after `nix:` **is** the nixhub package name (there is no `node → nodejs`
alias table). Each pinned tool can resolve to its *own* nixpkgs revision: the
[nix-ld shim](../concepts/provisioning) lets a tool run on a different glibc than
the base userland, so cross-channel pins work. Resolution is cached in a per-project
`tools.lock` so nixhub is queried once, not per launch.

A project's `nix:` tools are host-provisioned and **trusted-only** (like
`[packages]`); an untrusted project's `nix:` tools are withheld with a warning.

## Non-`nix:` backends: auto-equipped in-cage

A project's non-`nix:` mise tools (`aqua:`, `github:`, `npm:`, `cargo:`, a plain
registry token, …) are **auto-installed in-cage at launch**, so `sbx run`
/ `sbx app` start with them on `PATH` without a manual `sbx mise install`:

```toml
# .mise.toml
[tools]
"aqua:BurntSushi/ripgrep" = "latest"
node                       = "20"
```

This is **open by design**: it runs whether or not the project is trusted (the agent
self-equip path). The real gate is that opening the *network* to fetch the tool is a
trusted/global-only choice: an untrusted project may *declare* `aqua:evil/x` but
cannot *open* egress to fetch it. Under `network = "none"` the install is skipped with
a by-name warning; under a filtering posture the fetch rides the allowlist.

A non-`nix:` tool fetches upstream at first install, so it **kills offline
first-launch**: the price of freshness versus the nix seed's offline reuse.

## Trust and mise files

The trust gate hashes a project's mise files **together** with `.sbx.toml`, so editing
either re-arms it (see [The trust gate](../concepts/trust)). `sbx` binds exactly
the hashed mise files into the cage and runs mise with
`MISE_TRUSTED_CONFIG_PATHS` naming only them: the mount layout is the containment, so
an unhashed file mise might otherwise discover (a parent-directory or user-global
config) never reaches resolution.

A trusted project's mise `[env]` also maps into the cage, extracted by provenance so
only variables whose source is an authorized mise file are kept.

## `[tools]` vs `[packages]`

| | `[tools]` (mise file) | [`[packages]`](packages) |
|---|---|---|
| Scope | project-local (`mise install`) | global/durable (`mise use -g`, `nix:` store, `flake:` build) |
| `nix:` tools | trusted-only, host-side, pinned | trusted-only, host-side |
| non-`nix:` tools | auto-equipped at launch (open) | trusted-only |
| Reproducible-in-git | yes (committed mise file) | yes (committed `.sbx.toml`) |

## Self-equipping from inside the cage

An agent can equip tools live with [`sbx mise`](../cli/mise):

```sh
sbx mise install nix:jq                 # build into the project's own store
sbx mise use -g aqua:BurntSushi/ripgrep # activate (auto-on-PATH next launch)
```

A tool the agent **activates** (`mise use`) is auto-on-`PATH` in later launches; a
bare `mise install` (not activated) stays reachable via `mise exec`/`mise which`. See
[`sbx mise`](../cli/mise) and [Provisioning](../concepts/provisioning).

## Examples

A polyglot project, mixing the two backends deliberately: `nix:` where the version
must be exact and reproducible offline, a registry backend where freshness matters
more.

```toml
# .mise.toml
[tools]
"nix:nodejs"              = "20"        # pinned, host-provisioned, offline-reusable
"nix:python"              = "3.12"
"nix:jq"                  = "latest"
"aqua:BurntSushi/ripgrep" = "latest"    # auto-equipped in-cage at launch
"npm:prettier"            = "3"
```

```sh
sbx run -- node --version      # the toolchain is already on PATH
sbx run -- rg --version
sbx config show                # what survived the trust gate
```

Untrusted, the same file behaves differently, and visibly so: the `nix:` tools are
withheld by name, while the others are declared but cannot be fetched unless egress is
open (which an untrusted project cannot open either).

```sh
sbx trust                      # …then the nix: tools are provisioned
```

Equipping a tool from inside the cage, which is the path this field exists for:

```sh
sbx mise install nix:jq                   # build it into this project's own store
sbx mise use -g aqua:BurntSushi/ripgrep   # activate it: on PATH from the next launch
sbx mise ls                               # what this project has
sbx mise exec -- jq --version             # run one that is installed but not activated
```

And the upgrade path, which is a separate verb because a binary update does not move
a pinned toolchain:

```sh
sbx upgrade mise               # move the non-nix: tools to their newest release
sbx upgrade nix                # move the base userland's channel
```
