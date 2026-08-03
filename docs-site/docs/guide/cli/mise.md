# `sbx mise`

```
sbx mise <args...>
```

Pass arguments through to the [mise](https://mise.jdx.dev/) that runs **inside the
cage**, so an agent can self-equip a project's tools into the project's **own** store.

See also: [`[tools]` (mise)](../configuration/tools) · [`packages`](../configuration/packages) · [Provisioning](../concepts/provisioning) · [`sbx upgrade`](upgrade).

## Behavior

- The in-cage mise builds a `nix:` tool into the **per-project** writable store (never
  the host), or installs any other mise backend.
- **Open by design**: `sbx mise` works whether or not the project is trusted (the
  documented Mode-B self-equip inversion), unlike `sbx run`'s host-side `nix:`
  provisioning which is trusted-only.
- For mise's own help, run `sbx mise help`.

## Install vs activate

- `sbx mise install <token>`: builds/installs the tool. A bare install (not
  activated) stays reachable via `mise exec`/`mise which`; with shims on `PATH` it
  reports `No version is set`, pointing you to `mise use`.
- `sbx mise use -g <token>`, **activates** the tool, so it is auto-on-`PATH` in later
  launches (via shims for `sbx run`, `mise activate` for an interactive `sbx run`).

## Examples

```sh
sbx mise install nix:jq                       # build jq into the project's store
sbx mise use -g aqua:BurntSushi/ripgrep       # activate ripgrep for later launches
sbx mise ls                                    # what is installed
sbx mise exec -- jq --version                  # run an installed-but-not-activated tool
```

A tool activated with `sbx mise use` persists across launches (the per-project store
and mise data dir are durable). To make a toolchain reproducible in git instead, put
the tool in the project's mise [`[tools]`](../configuration/tools) file.
