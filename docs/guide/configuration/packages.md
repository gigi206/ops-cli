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

## Why all three are trusted-only

Loosening `packages` to an untrusted project would let it override a trusted app's
package and run attacker code under that app's posture — the same class of hole as
overriding a trusted app's command. So all three backends are gated. A trusted app's
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
