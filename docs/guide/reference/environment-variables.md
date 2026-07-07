# Environment variables

The environment variables `ops` reads (on the host) and sets (inside the cage).

See also: [One-shot overrides](../configuration/overrides.md) · [Directory layout](../concepts/directory-layout.md) · [`env`](../configuration/env.md).

## One-shot override variables (host)

Each mirrors a [one-shot override](../configuration/overrides.md) flag. The command line
beats the environment; a security field set from the environment prints a stderr notice.

| Variable | Equivalent flag | Sets |
|---|---|---|
| `OPS_CONFIG` | `--config` | a whole-schema TOML overlay |
| `OPS_ENV_<KEY>` | `--env KEY=…` | one cage environment variable |
| `OPS_NET` | `--net` | the network posture (`none`/`shared`/`ask`/`allow=…`/`deny=…`) |
| `OPS_GUI` | `--gui` | the display posture (`none`/`wayland`) |
| `OPS_NIXPKGS` | `--nixpkgs` | the nixpkgs channel or revision |
| `OPS_BIND` | `--bind` | a host bind (`/path[:ro\|:rw]`) |
| `OPS_LIMIT_<key>` | `--limit key=…` | a cgroup limit (`OPS_LIMIT_tasks_max=…`) |
| `OPS_PACKAGE_<name>` | `--package name=…` | a package (`OPS_PACKAGE_hello=nix:hello`) |

Precedence, lowest to highest:
`OPS_CONFIG < OPS_* typed < --config < --* typed`.

## Engine override variables (host)

| Variable | Meaning |
|---|---|
| `OPS_NIX_BIN` | use this `nix` binary instead of the bundled/host one |
| `OPS_BWRAP_BIN` | use this `bwrap` binary instead of the bundled/host one |

These take precedence over the bundled engine and the host `PATH`. A resolved engine
must still pass an ownership/permission gate before it is executed. See
[Provisioning](../concepts/provisioning.md).

## Directory variables (host)

`ops` follows the XDG base-directory convention. A relative value is ignored (the spec
requires an absolute base), and `ops` falls back to `$HOME`.

| Variable | Selects | Fallback |
|---|---|---|
| `XDG_CONFIG_HOME` | the config dir (`ops/ops.toml`, `ops/apps/`) | `$HOME/.config` |
| `XDG_DATA_HOME` | the data dir (store, engines, sessions, …) | `$HOME/.local/share` |
| `XDG_STATE_HOME` | the trust store (`ops/trusted/`) | `$HOME/.local/state` |
| `XDG_RUNTIME_DIR` | the Wayland socket (for `gui = "wayland"`) and the systemd user session | — |

See [Directory layout](../concepts/directory-layout.md).

## Editor variables (host)

[`ops config edit`](../cli/config.md) opens the target file in `$VISUAL`, then
`$EDITOR`, falling back to `vi`.

## Variables ops sets inside the cage

A cage does **not** inherit your host environment. `ops` sets a small structural set,
including:

| Variable | Meaning |
|---|---|
| `OPS_SANDBOX=1` | a marker that the process is running inside an `ops` cage |
| `OPS_EGRESS_CONTRACT` | the in-cage path to the generated egress contract (`/opt/ops/egress-contract.md`), describing what the cage can reach |
| `no_proxy`/`NO_PROXY` | set to `localhost,127.0.0.1,::1` so in-cage loopback does not route through the egress proxy |
| `HOME`, `PATH`, `TERM`, `LANG` | the synthetic identity's home, the tool paths, and the two passthrough values |

Under a [filtering network posture](../networking/modes.md), `ops` also sets the proxy
variables (`http_proxy`/`https_proxy`) and the CA-bundle variables so in-cage tools
trust the egress proxy's per-session CA. These are managed by `ops`; a trusted
[`env`](../configuration/env.md) can override a cage variable, but the loader-control and
proxy-control keys are on the [untrusted-only denylist](../configuration/env.md#the-reserved-key-denylist-untrusted-only).

## Tool-behavior variables (in-cage, via `env`)

A trusted [`env`](../configuration/env.md) entry can also tune a tool `ops` runs in the
cage. The one worth knowing:

| Variable | Effect |
|---|---|
| `MISE_MINIMUM_RELEASE_AGE` | overrides mise's built-in 24 h fresh-release hold; `"0"` installs the newest upstream release immediately. See [Upgrading toolchains](../housekeeping/upgrade.md#installing-the-newest-release-immediately). |

Set it in the **global** config to apply to every app — edit `ops/ops.toml` or run
`ops config set --global env.MISE_MINIMUM_RELEASE_AGE 0` (`--local` for one project). A
host `export` does **not** reach the cage, and `ops upgrade` takes no override flags — a
config `env` entry is the only channel.

## Credential variables (host, user-defined)

An app [profile](../apps/catalog.md) references a provider key by
[`from = "env://VAR"`](../secrets/resolvers.md) — e.g. `ANTHROPIC_API_KEY`,
`OPENAI_API_KEY`, `OPENROUTER_API_KEY`. You export these on the host; the
[egress proxy injects](../secrets/injection.md) them on the wire, so they **never enter
the cage**.
