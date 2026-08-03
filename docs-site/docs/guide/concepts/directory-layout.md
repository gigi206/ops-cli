# Directory layout

`sbx` follows the [XDG base-directory](https://specifications.freedesktop.org/basedir-spec/latest/)
convention. It keeps three trees: **config** (what you declare), **data** (what it
provisions and runs), and **state** (the trust records). A relative `XDG_*` value is
ignored, as the spec requires, and `sbx` falls back to `$HOME`.

See also: [The trust gate](trust) · [Provisioning](provisioning) · [Configuration overview](../configuration/).

## Config: what you declare

`$XDG_CONFIG_HOME/sbx/` (else `$HOME/.config/sbx/`):

| Path | Contents |
|---|---|
| `sbx.toml` | the **global** config: [trusted by location](trust) |
| `apps/<name>.toml` | imported **app profiles**: trusted by location |

A project's `.sbx.toml` lives in the project directory itself, not here, and is
[trusted by content](trust).

## Data: what sbx provisions and runs

`$SBX_DATA_DIR`, else a volume adopted with [`sbx storage use`](../cli/storage), else
`$XDG_DATA_HOME/sbx/` (else `$HOME/.local/share/sbx/`). Owner-only.

This is the tree that grows: the store, the per-project runtime trees and the app homes
all live here. [`sbx store`](../cli/store) reports its size and inode count.
[`sbx storage`](../cli/storage) moves it whole into a compressed volume that sbx mounts
by itself; [`SBX_DATA_DIR`](../reference/environment-variables#sbx_data_dir) relocates it
for a one-off.

The important subtrees:

| Path | Contents |
|---|---|
| `store/` | the **shared** user-owned nix store (`store/nix/store`), read-only to a cage |
| `engine/` | the bundled `nix` / `bwrap` engines a self-contained release materializes |
| `gcroots/` | gcroots keeping provisioned closures alive (base, mise, gui, per-project) |
| `projects/<id>/` | the **per-project** writable store and its locks |
| `projects/<id>/apps/<name>/mise/` | a global app's **per-project mise pool**: its `nix:`-via-mise self-equips, kept `/nix`-aligned |
| `apps/<name>/home/` | an app's persistent isolated `$HOME` (`home_scope = "global"`) |
| `sessions/` | the daemonless session registry ([`sbx session ls`](../housekeeping/sessions)) |
| `egress/` | per-launch egress proxy sockets and CA material |
| `mise/`, `mise-plugin/` | the host-side mise home and the embedded `nix:` backend plugin |
| `plugins/` | installed [resolver plugins](../secrets/plugins) |
| `stores/<name>/` | cached, verified remote [plugin stores](../secrets/plugins) |
| `nixpkgs.lock` | the global base channel revision (see [Upgrading](../housekeeping/upgrade)) |
| `mise-engine.lock` | the mise engine revision, independent of the base channel |

The **per-project** directory `projects/<id>/` holds the project's own writable nix
store (seeded from the shared store) plus its resolution locks, `nixpkgs.lock` (a project pin), `tools.lock` (resolved `nix:` mise tools), and
`flake-packages.lock` (pinned `flake:` packages): and, under `apps/<name>/mise/`, a
global app's [per-project mise pool](../apps/home#two-mise-pools-keep-a-global-apps-self-equips-aligned)
(its `nix:`-via-mise self-equips, kept aligned with this project's store). See
[Provisioning](provisioning) for how the per-project store works.

## State: the trust records

`$XDG_STATE_HOME/sbx/trusted/` (else `$HOME/.local/state/sbx/trusted/`): one marker
per trusted project config, holding the SHA-256 of the file's contents, keyed by the
config's canonical path. See [The trust gate](trust).

The trust store dir is required to be an **absolute** path: a relative base would
let a cloned repository pre-approve itself.

## Why the control plane is under `$HOME`

All three trees live under your home directory, which means a broad read-write
[`binds`](../configuration/binds) could in principle expose them to a cage. `sbx`
prevents that: a read-write bind at or inside one of these directories is forced
read-only, and a broad bind that merely contains them keeps each pinned read-only in
place. See [Security model](security-model#the-control-plane-is-pinned).

## Locating the files from the CLI

```sh
sbx config path           # list every config layer in resolution order
sbx config path -g        # just the global config path
sbx doctor                # reports the store location and channel revision
```
