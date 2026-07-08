# `packages` — tools by backend

Tools to provision into the sandbox, declared as `name = "<backend>:<locator>"`.

```toml
[packages]
jq       = "nix:jq"
ripgrep  = "mise:aqua:BurntSushi/ripgrep"
myagent  = "flake:github:owner/repo#default"
```

The **name** is a free label — the merge key across layers and the on-disk root name.
The **value carries a mandatory backend prefix**. `packages` is a **security field**:
honored only from a trusted source (all three backends).

See also: [Provisioning](../concepts/provisioning.md) · [`[tools]` (mise)](tools.md) · [`ops search`](../cli/search.md) · [`ops upgrade`](../housekeeping/upgrade.md).

## The mandatory backend prefix

There is **no bare form**. A value with no recognized prefix is **dropped with a
warning** naming the fix — this is fail-closed, so a typo never silently mis-routes to
nix.

| Prefix | Where it is built | Freshness | Offline |
|---|---|---|---|
| `nix:<attribute>` | host-side, into the shared store | tracks the nixpkgs channel | yes (seeded, durable) |
| `mise:<token>` | in-cage, via `mise use -g` | upstream-direct, fetched at launch | first launch needs network |
| `flake:<ref>` | in-cage, via `nix build` | floats, or pinned by `ops upgrade flake` | after a warm build |
| `deb:<url>` | host-side, from a prebuilt `.deb` | pin-on-first-use, rolled by `ops upgrade deb` | yes (seeded, durable) |

### `nix:` — a nixpkgs attribute

```toml
[packages]
node = "nix:nodejs_20"
jq   = "nix:jq"
```

Provisioned **host-side** from the pinned nixpkgs channel into `ops`'s store, its
`bin/` prepended to the cage `PATH`. Durable and offline-reusable (seeded into the
per-project store). Use [`ops search <query>`](../cli/search.md) to find attribute
names. Advances with [`ops upgrade nix`](../housekeeping/upgrade.md).

`mise:nix:<pkg>` routes to mise's nixhub resolver — a way to get a nix package with
mise's own version selection, not a third nix path.

### `mise:` — a mise backend

```toml
[packages]
codex = "mise:aqua:openai/codex"
tool  = "mise:npm:some-cli"
```

Equipped **in-cage** with `mise use -g <token>` at launch, fetched upstream-direct
(so it is fresher than nixpkgs but the first launch needs network). Any mise backend
works: `aqua:`, `github:`, `npm:`, `cargo:`, a plain registry token, etc. Advances
with [`ops upgrade mise`](../housekeeping/upgrade.md).

Note: an `npm:` tool needs `/usr/bin/env` (the cage provides a synthetic one) and, if
it is pure JS, a node runtime — declare `nodejs = "nix:nodejs"` alongside it.

### `flake:` — a nix flake output

```toml
[packages]
agent = "flake:github:owner/repo#default"
```

Built **in-cage** with `nix build <ref>` into the project's own store, the out-link's
`bin/` prepended to `PATH`. A warm/offline second launch short-circuits. The flake ref
must carry an explicit scheme — **every local-source form is rejected**
(`path:`/`git+file:`, a leading `/`·`.`·`~`, the bare indirect `nixpkgs`) so a config
cannot aim the in-cage build at a host path. The first launch needs network **and**
the build's own fetch hosts in the [egress allowlist](../networking/rules.md). A flake
build step that fetches with its own HTTP client (e.g. `bun install`) rather than
nix's fetcher is blocked under a filtering posture — prefer a release binary via
`mise:github:` for such tools. Pins advance with
[`ops upgrade flake`](../housekeeping/upgrade.md).

### `deb:` — a prebuilt Debian package

```toml
[packages]
opencode-desktop = "deb:https://github.com/owner/repo/releases/latest/download/app-linux-amd64.deb"
```

For a GUI/desktop app distributed **only as a `.deb`** (no release binary, no nixpkgs
attribute, no buildable flake). ops resolves the URL to a content hash (pinned in a
per-project `deb-packages.lock`) and builds a generated derivation that `dpkg-deb -x`-unpacks
the `.deb` and `autoPatchelfHook`s its Electron/Chromium binaries against a curated library
set — **host-side** (like `nix:`, seeded and offline-reusable), because a `.deb` runs no build
script so evaluating it host-side is safe. The URL must be `https://` and end in `.deb`. A
`…/releases/latest/download/…` URL tracks upstream; the build uses the **host** network (not the
cage allowlist), and `ops upgrade deb` re-resolves it forward. Pairs with
[`gui = "wayland"`](gui.md) for the display; ops seeds its MITM CA into the cage's NSS store so
the Chromium app trusts a filtering posture's proxy.

## Why all four are trusted-only

Loosening `packages` to an untrusted project would let it override a trusted app's
package and run attacker code under that app's posture — the same class of hole as
overriding a trusted app's command. So all four backends are gated. A trusted app's
package **survives an untrusted project's override attempt** (the flagship "agent on
untrusted code" property). The open self-equip path stays [`ops mise`](../cli/mise.md)
and a project's [`[tools]`](tools.md).

## `[packages]` vs `[tools]`

- `[packages]` is a **global, durable declaration** (`mise use -g`, `nix:` into the
  store, `flake:` build). It is trusted-only.
- [`[tools]`](tools.md) (a project mise file) is the **local, project-scoped**
  self-equip path (`mise install`), auto-equipped at launch under an open posture.

## Viewing the resolved set

```sh
ops config show          # each package with its backend and gating
ops config show --json   # machine-readable
```

## One-shot override

To add a package for a single launch without editing the file, use `--package
<name>=<backend:locator>` (repeatable) or `OPS_PACKAGE_<name>`:

```sh
ops run --package jq=nix:jq -- ./tool
OPS_PACKAGE_ripgrep=mise:aqua:BurntSushi/ripgrep ops shell
```

The value carries the same mandatory backend prefix as the field
(`nix:`/`mise:`/`flake:`/`deb:`). A one-shot package *adds* to whatever the config declares.
The command line beats the environment, and both beat the config file. See
[One-shot overrides](overrides.md).
