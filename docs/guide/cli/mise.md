# `ops mise`

```
ops mise <args...>
```

Pass arguments through to the [mise](https://mise.jdx.dev/) that runs **inside the
cage**, so an agent can self-equip a project's tools into the project's **own** store.

See also: [`[tools]` (mise)](../configuration/tools.md) · [`packages`](../configuration/packages.md) · [Provisioning](../concepts/provisioning.md) · [`ops upgrade`](upgrade.md).

## Behavior

- The in-cage mise builds a `nix:` tool into the **per-project** writable store (never
  the host), or installs any other mise backend.
- **Open by design** — `ops mise` works whether or not the project is trusted (the
  documented Mode-B self-equip inversion), unlike `ops run`'s host-side `nix:`
  provisioning which is trusted-only.
- For mise's own help, run `ops mise help`.

## Install vs activate

- `ops mise install <token>` — builds/installs the tool. A bare install (not
  activated) stays reachable via `mise exec`/`mise which`; with shims on `PATH` it
  reports `No version is set`, pointing you to `mise use`.
- `ops mise use -g <token>` — **activates** the tool, so it is auto-on-`PATH` in later
  launches (via shims for `ops run`, `mise activate` for `ops shell`).

## Examples

```sh
ops mise install nix:jq                       # build jq into the project's store
ops mise use -g aqua:BurntSushi/ripgrep       # activate ripgrep for later launches
ops mise ls                                    # what is installed
ops mise exec -- jq --version                  # run an installed-but-not-activated tool
```

A tool activated with `ops mise use` persists across launches (the per-project store
and mise data dir are durable). To make a toolchain reproducible in git instead, put
the tool in the project's mise [`[tools]`](../configuration/tools.md) file.
