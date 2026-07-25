# Environment variables

The environment variables `sbx` reads (on the host) and sets (inside the cage).

See also: [One-shot overrides](../configuration/overrides.md) · [Directory layout](../concepts/directory-layout.md) · [`env`](../configuration/env.md).

## One-shot override variables (host)

Each mirrors a [one-shot override](../configuration/overrides.md) flag. The command line
beats the environment; a security field set from the environment prints a stderr notice.

| Variable | Equivalent flag | Sets |
|---|---|---|
| `SBX_CONFIG` | `--config` | a whole-schema TOML overlay |
| `SBX_ENV_<KEY>` | `--env KEY=…` | one cage environment variable |
| `SBX_NET` | `--net` | the network posture (`none`/`shared`/`ask`/`allow=…`/`deny=…`) |
| `SBX_GUI` | `--gui` | the display posture (`none`/`offscreen`/`wayland`) |
| `SBX_NIXPKGS` | `--nixpkgs` | the nixpkgs channel or revision |
| `SBX_BIND` | `--bind` | a host bind (`/path[:ro\|:rw]`) |
| `SBX_LIMIT_<key>` | `--limit key=…` | a cgroup limit (`SBX_LIMIT_tasks_max=…`) |
| `SBX_PACKAGE_<name>` | `--package name=…` | a package (`SBX_PACKAGE_hello=nix:hello`) |

Precedence, lowest to highest:
`SBX_CONFIG < SBX_* typed < --config < --* typed`.

## Engine override variables (host)

| Variable | Meaning |
|---|---|
| `SBX_NIX_BIN` | use this `nix` binary instead of the bundled/host one |
| `SBX_BWRAP_BIN` | use this `bwrap` binary instead of the bundled/host one |

These take precedence over the bundled engine and the host `PATH`. A resolved engine
must still pass an ownership/permission gate before it is executed. See
[Provisioning](../concepts/provisioning.md).

## Directory variables (host)

`sbx` follows the XDG base-directory convention. A relative value is ignored (the spec
requires an absolute base), and `sbx` falls back to `$HOME`.

| Variable | Selects | Fallback |
|---|---|---|
| `XDG_CONFIG_HOME` | the config dir (`sbx/sbx.toml`, `sbx/apps/`) | `$HOME/.config` |
| `XDG_DATA_HOME` | the data dir (store, engines, sessions, …) | `$HOME/.local/share` |
| `XDG_STATE_HOME` | the trust store (`sbx/trusted/`) | `$HOME/.local/state` |
| `XDG_RUNTIME_DIR` | the Wayland socket (for `gui = "wayland"`) and the systemd user session | — |

### `SBX_DATA_DIR`

| Variable | Selects | Fallback |
|---|---|---|
| `SBX_DATA_DIR` | the data directory itself | a volume adopted with [`sbx storage use`](../cli/storage.md), else `$XDG_DATA_HOME/sbx` |

The data directory is the one sbx tree that grows without bound — the shared nix store,
the per-project runtime trees and the app homes all live there, and it is routinely tens
of gigabytes across hundreds of thousands of inodes ([`sbx store`](../cli/store.md)
reports both). `SBX_DATA_DIR` puts it on a filesystem of your choosing.

It differs from `XDG_DATA_HOME` in two ways, because it is sbx's own variable rather than
a base shared with every application:

- It names the directory **itself** — nothing is appended. `SBX_DATA_DIR=/vol/sbx` uses
  `/vol/sbx`, where `XDG_DATA_HOME=/vol` would use `/vol/sbx`.
- A **relative** value is **refused**, not ignored: sbx reports the error and stops. A
  relative path would resolve against whatever directory sbx was launched from, so falling
  back quietly would put your projects and apps somewhere you never look. Unset or empty
  reads as absent, so clearing the variable restores the default.

It also has a **length limit — 74 bytes**, and a longer path is refused with that figure in
the message. Egress filtering, the D-Bus filter, port forwarding and exec enforcement each
bind a Unix-domain socket *under* the data directory, and the kernel caps a socket path at
108 bytes. Without the check those features would fail at launch, reporting a socket
problem rather than the directory that caused it.

The **same limit applies to the directory sbx derives** when you set no `SBX_DATA_DIR` — a very
long `$HOME` or `$XDG_DATA_HOME` can push `$HOME/.local/share/sbx` past it. sbx then stops with
the same message: set `SBX_DATA_DIR` to a shorter path, or adopt a [storage volume](../cli/storage.md)
— its mount point under `/run` is short, so it clears the limit on its own. `sbx storage` keeps
working while the plain directory is over the limit, so the volume remedy is always reachable.

It also **overrides an adopted volume**, so it stays the way to run one-off against another
data directory. To move sbx's data permanently, [`sbx storage use`](../cli/storage.md) is the
better route: it needs no variable at all and mounts the volume by itself.

Pointing it at a filesystem that shares storage between files (copy-on-write) is worth
knowing about: sbx seeds each per-project store from the shared one by cloning, which on
such a filesystem shares blocks instead of copying them, and compression — where the
filesystem offers it — applies on top. `sbx store` reports which case your filesystem is.

See [Directory layout](../concepts/directory-layout.md).

## Editor variables (host)

[`sbx config edit`](../cli/config.md) opens the target file in `$VISUAL`, then
`$EDITOR`, falling back to `vi`.

## Variables sbx sets inside the cage

A cage does **not** inherit your host environment. `sbx` sets a small structural set,
including:

| Variable | Meaning |
|---|---|
| `SBX_SANDBOX=1` | a marker that the process is running inside an `sbx` cage |
| `SBX_EGRESS_CONTRACT` | the in-cage path to the generated egress contract (`/opt/sbx/egress-contract.md`), describing what the cage can reach |
| `no_proxy`/`NO_PROXY` | set to `localhost,127.0.0.1,::1` so in-cage loopback does not route through the egress proxy |
| `HOME`, `PATH`, `TERM`, `LANG` | the synthetic identity's home, the tool paths, and the two passthrough values |

Under a [filtering network posture](../networking/modes.md), `sbx` also sets the proxy
variables (`http_proxy`/`https_proxy`) and the CA-bundle variables so in-cage tools
trust the egress proxy's per-session CA. These are managed by `sbx`; a trusted
[`env`](../configuration/env.md) can override a cage variable, but the loader-control and
proxy-control keys are on the [untrusted-only denylist](../configuration/env.md#the-reserved-key-denylist-untrusted-only).

## Tool-behavior variables (in-cage, via `env`)

A trusted [`env`](../configuration/env.md) entry can also tune a tool `sbx` runs in the
cage. The one worth knowing:

| Variable | Effect |
|---|---|
| `MISE_MINIMUM_RELEASE_AGE` | overrides mise's built-in 24 h fresh-release hold; `"0"` installs the newest upstream release immediately. See [Upgrading toolchains](../housekeeping/upgrade.md#installing-the-newest-release-immediately). |

Set it in the **global** config to apply to every app — edit `sbx/sbx.toml` or run
`sbx config set --global env.MISE_MINIMUM_RELEASE_AGE 0` (`--local` for one project). A
host `export` does **not** reach the cage, and `sbx upgrade` takes no override flags — a
config `env` entry is the only channel.

## Credential variables (host, user-defined)

An app [profile](../apps/catalog.md) references a provider key by
[`from = "env://VAR"`](../secrets/resolvers.md) — e.g. `ANTHROPIC_API_KEY`,
`OPENAI_API_KEY`, `OPENROUTER_API_KEY`. You export these on the host; the
[egress proxy injects](../secrets/injection.md) them on the wire, so they **never enter
the cage**.
