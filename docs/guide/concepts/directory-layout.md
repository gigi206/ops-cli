# Directory layout

`ops` follows the [XDG base-directory](https://specifications.freedesktop.org/basedir-spec/latest/)
convention. It keeps three trees: **config** (what you declare), **data** (what it
provisions and runs), and **state** (the trust records). A relative `XDG_*` value is
ignored, as the spec requires, and `ops` falls back to `$HOME`.

See also: [The trust gate](trust.md) · [Provisioning](provisioning.md) · [Configuration overview](../configuration/README.md).

## Config — what you declare

`$XDG_CONFIG_HOME/ops/` (else `$HOME/.config/ops/`):

| Path | Contents |
|---|---|
| `ops.toml` | the **global** config — [trusted by location](trust.md) |
| `apps/<name>.toml` | imported **app profiles** — trusted by location |

A project's `.ops.toml` lives in the project directory itself, not here, and is
[trusted by content](trust.md).

## Data — what ops provisions and runs

`$XDG_DATA_HOME/ops/` (else `$HOME/.local/share/ops/`). Owner-only. The important
subtrees:

| Path | Contents |
|---|---|
| `store/` | the **shared** user-owned nix store (`store/nix/store`), read-only to a cage |
| `engine/` | the bundled `nix` / `bwrap` engines a self-contained release materializes |
| `gcroots/` | gcroots keeping provisioned closures alive (base, mise, gui, per-project) |
| `projects/<id>/` | the **per-project** writable store and its locks |
| `apps/<name>/home/` | an app's persistent isolated `$HOME` (`home_scope = "global"`) |
| `sessions/` | the daemonless session registry ([`ops ls`](../housekeeping/sessions.md)) |
| `egress/` | per-launch egress proxy sockets and CA material |
| `mise/`, `mise-plugin/` | the host-side mise home and the embedded `nix:` backend plugin |
| `plugins/` | installed [resolver plugins](../secrets/plugins.md) |
| `stores/<name>/` | cached, verified remote [plugin stores](../secrets/plugins.md) |
| `nixpkgs.lock` | the global base channel revision (see [Upgrading](../housekeeping/upgrade.md)) |
| `mise-engine.lock` | the mise engine revision, independent of the base channel |

The **per-project** directory `projects/<id>/` holds the project's own writable nix
store (seeded from the shared store) plus its resolution locks —
`nixpkgs.lock` (a project pin), `tools.lock` (resolved `nix:` mise tools), and
`flake-packages.lock` (pinned `flake:` packages). See
[Provisioning](provisioning.md) for how the per-project store works.

## State — the trust records

`$XDG_STATE_HOME/ops/trusted/` (else `$HOME/.local/state/ops/trusted/`): one marker
per trusted project config, holding the SHA-256 of the file's contents, keyed by the
config's canonical path. See [The trust gate](trust.md).

The trust store dir is required to be an **absolute** path — a relative base would
let a cloned repository pre-approve itself.

## Why the control plane is under `$HOME`

All three trees live under your home directory, which means a broad read-write
[`binds`](../configuration/binds.md) could in principle expose them to a cage. `ops`
prevents that: a read-write bind at or inside one of these directories is forced
read-only, and a broad bind that merely contains them keeps each pinned read-only in
place. See [Security model](security-model.md#the-control-plane-is-pinned).

## Locating the files from the CLI

```sh
ops config path           # list every config layer in resolution order
ops config path -g        # just the global config path
ops doctor                # reports the store location and channel revision
```
