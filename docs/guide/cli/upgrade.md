# `sbx upgrade`

```
sbx upgrade [all|nix|mise|flake|deb|appimage|tarball]
```

Roll managed channels forward by re-resolving and rewriting their locks, so versions
advance **only here**, never on an `sbx` binary update.

| Target | Rolls |
|---|---|
| `all` | every managed channel (the default) |
| `nix` | the nixpkgs channel (base userland + native `nix:` packages) |
| `mise` | the mise engine, the project's `nix:` tools, and `mise:` packages |
| `flake` | the project's and apps' `flake:` packages |
| `deb` | the project's and apps' `deb:` packages |
| `appimage` | the project's and apps' `appimage:` packages |
| `tarball` | the project's and apps' `tarball:` packages |

See also: [Upgrading toolchains](../housekeeping/upgrade.md) · [Provisioning](../concepts/provisioning.md) · [`nixpkgs`](../configuration/nixpkgs.md) · [`packages`](../configuration/packages.md).

## Behavior

`sbx upgrade` is **context-aware** — it re-resolves the source the current directory
tracks and rewrites *that* lock (a trusted project pin → the per-project lock, else the
global one). This is the only way a *channel* pin (`nixos-23.11`) advances within
itself. Lock writes are atomic (a reader sees old-or-new, never torn).

- `sbx upgrade nix` rolls the base channel, leaving the mise engine lock untouched.
- `sbx upgrade mise` rolls the mise engine + the project's `nix:` tools + `mise:`
  packages (an in-cage `mise upgrade` per home), leaving `nixpkgs.lock` intact.
- `sbx upgrade flake` re-pins the project's and apps' `flake:` packages.

## Examples

```sh
sbx upgrade              # roll everything
sbx upgrade nix          # just the nixpkgs channel
sbx upgrade mise         # the mise engine + tools/packages
```

See [Upgrading toolchains](../housekeeping/upgrade.md) for the lock model and the
"seeded not baked" contract.
