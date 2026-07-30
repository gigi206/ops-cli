# `sbx upgrade`

```
sbx upgrade [all|nix|mise|flake|deb|appimage|tarball] [--project <path>]
```

Roll managed channels forward by re-resolving and rewriting their locks, so versions
advance **only here**, never on an `sbx` binary update.

| Target | Rolls |
|---|---|
| `all` | every managed channel (the default) |
| `nix` | the nixpkgs channel (base userland + native `nix:` packages) |
| `mise` | the mise engine, the project's `nix:` tools, `mise:` packages, and the [task tool pool](../configuration/task.md#the-task-tool-pool) |
| `flake` | the project's and apps' `flake:` packages |
| `deb` | the project's and apps' `deb:` packages |
| `appimage` | the project's and apps' `appimage:` packages |
| `tarball` | the project's and apps' `tarball:` packages |

| Flag | Effect |
|---|---|
| `--project <path>` | roll another project instead of the current directory |

See also: [Upgrading toolchains](../housekeeping/upgrade.md) · [Provisioning](../concepts/provisioning.md) · [`nixpkgs`](../configuration/nixpkgs.md) · [`packages`](../configuration/packages.md).

## Behavior

`sbx upgrade` is **context-aware** — it re-resolves the source the target directory
tracks and rewrites *that* lock (a trusted project pin → the per-project lock, else the
global one). This is the only way a *channel* pin (`nixos-23.11`) advances within
itself. Lock writes are atomic (a reader sees old-or-new, never torn).

- `sbx upgrade nix` rolls the base channel, leaving the mise engine lock untouched.
- `sbx upgrade mise` rolls the mise engine + the project's `nix:` tools + `mise:`
  packages (an in-cage `mise upgrade` per home) + the declared operations' tool pool
  (host-side, under a `task pool` line), leaving `nixpkgs.lock` intact.
- `sbx upgrade flake` re-pins the project's and apps' `flake:` packages.

### Targeting another project

By default a roll acts on the project in the current directory. `--project <path>` runs
the whole command against another project instead — identical to `cd <path> && sbx
upgrade`, with the same trust gate, pin, and per-project locks. The path must be an
existing directory. This matters for the per-project backends (`flake:`, `deb:`,
`appimage:`, `tarball:`, the `nix:` tools, and the in-cage `mise:` roll): an app's pins
and equipped tools live in the store and lock of the project it is launched from, so
rolling that project is how they advance. The host-global parts (the nixpkgs channel
when no project pin, and the mise engine) roll the same regardless.

## Examples

```sh
sbx upgrade                        # roll everything, current directory
sbx upgrade nix                    # just the nixpkgs channel
sbx upgrade mise                   # the mise engine + tools/packages
sbx upgrade --project ~/work/api   # roll everything for another project
sbx upgrade deb --project ~/work/api   # just its deb: packages
```

See [Upgrading toolchains](../housekeeping/upgrade.md) for the lock model and the
"seeded not baked" contract.
