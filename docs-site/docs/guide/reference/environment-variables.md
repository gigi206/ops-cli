---
description: "Every variable sbx reads on the host, and every one it sets inside the cage."
---

# Environment variables

The environment variables `sbx` reads (on the host) and sets (inside the cage).

See also: [One-shot overrides](../configuration/overrides) · [Directory layout](../concepts/directory-layout) · [`env`](../configuration/env).

## One-shot override variables (host)

Each mirrors a [one-shot override](../configuration/overrides) flag. The command line
beats the environment; a security field set from the environment prints a stderr notice.

| Variable | Equivalent flag | Sets |
|---|---|---|
| `SBX_CONFIG` | `--config` | a whole-schema TOML overlay |
| `SBX_ENV_<KEY>` | `--env KEY=…` | one cage environment variable |
| `SBX_NET` | `--net` | the network posture (`none`/`shared`/`ask`/`allow`/`deny`, or the `allow=…`/`deny=…` list forms) |
| `SBX_GUI` | `--gui` | the display posture (`none`/`offscreen`/`wayland`) |
| `SBX_PROC` | `--proc` | the [process/exec](../configuration/proc) posture (`off`/`observe`/`enforce`/`ask`) |
| `SBX_NOTIFY` | `--notify` | how loudly a refusal is [announced](../configuration/notify) (`off`/`once`/`always`) |
| `SBX_NIXPKGS` | `--nixpkgs` | the nixpkgs channel or revision |
| `SBX_BIND` | `--bind` | a host bind (`/path[:ro\|:rw]`) |
| `SBX_FORWARD` | `--forward` | host loopback TCP forward(s) into the cage, a comma-list of ports or `host:cage` remaps (`SBX_FORWARD=1455,9200:9119`) |
| `SBX_LIMIT_<key>` | `--limit key=…` | a cgroup limit (`SBX_LIMIT_tasks_max=…`) |
| `SBX_PACKAGE_<name>` | `--package name=…` | a package (`SBX_PACKAGE_hello=nix:hello`) |
| `SBX_SECCOMP` | `--seccomp` | relax the syscall denylist, a comma-list of [`[seccomp]`](../configuration/seccomp) tokens (`SBX_SECCOMP=ptrace,unshare`) |
| `SBX_DEVICE` | `--device` | grant one host [device node](../configuration/devices) (`SBX_DEVICE=/dev/kvm`) |
| `SBX_GPU` | `--gpu` | the [GPU](../configuration/gpu) posture (`true`/`false`) |
| `SBX_AUDIO` | `--audio` | the [audio](../configuration/audio) posture (`true`/`false`) |
| `SBX_DBUS` | `--dbus` | the in-cage [desktop portal](../configuration/dbus) (`true`/`false`) |

`SBX_GPU`, `SBX_AUDIO` and `SBX_DBUS` accept only `true` or `false`; any other value is a
structural error and the launch is refused (exit 2), like a mistyped flag. `SBX_BIND` and
`SBX_DEVICE` each carry exactly one value (a list is a `--config`/`SBX_CONFIG` concern),
while `SBX_SECCOMP` and `SBX_FORWARD` take a comma-separated list in a single value.

Precedence, lowest to highest:
`SBX_CONFIG < SBX_* typed < --config < --* typed`.

### Examples

One field at a time, for one launch:

```sh
SBX_NET=none sbx run -- ./build.sh                    # cut egress
SBX_NET=allow sbx run -- ./deploy.sh                  # allow-by-default for one run
SBX_NET=allow=api.example.com sbx run -- ./deploy.sh  # a one-shot allowlist
SBX_GUI=wayland sbx app run some-editor               # a display for one run
SBX_PROC=enforce sbx run -- ./untrusted.sh            # stand exec enforcement up
SBX_ENV_RUST_LOG=debug sbx run -- cargo test          # one cage variable
SBX_BIND=/opt/data:ro sbx run -- ./ingest.sh          # one read-only bind
SBX_LIMIT_tasks_max=8192 sbx run -- ./many-procs.sh
SBX_PACKAGE_jq=nix:jq sbx run -- ./report.sh
SBX_SECCOMP=ptrace sbx run -- gdb ./a.out             # relax the denylist for a debug run
SBX_DEVICE=/dev/kvm sbx run -- ./vm.sh
```

Combining them, and the whole-schema form for anything the typed variables do not
cover:

```sh
SBX_NET=none SBX_GUI=offscreen SBX_NOTIFY=off sbx run -- ./ci.sh

SBX_CONFIG='[limits]
tasks_max = 4096' sbx run -- ./build.sh

SBX_CONFIG=@ci-override.toml sbx run -- ./build.sh    # from a file
```

Two behaviours to keep in mind, both of which exist to stop a stale shell variable
from quietly widening a posture:

```sh
export SBX_NET=shared          # every later launch prints a stderr notice about it
sbx run --net none -- ./x.sh   # the command line wins: the flag beats the variable
export SBX_NET=nonee           # a typo is a hard error, exit 2, no launch
```

A variable exported in a shell rc is the case the notice is for: it applies to every
launch from that shell, long after you have forgotten it.

## Engine override variables (host)

| Variable | Meaning |
|---|---|
| `SBX_NIX_BIN` | use this `nix` binary instead of the bundled/host one |
| `SBX_BWRAP_BIN` | use this `bwrap` binary instead of the bundled/host one |

These take precedence over the bundled engine and the host `PATH`. A resolved engine
must still pass an ownership/permission gate before it is executed. See
[Provisioning](../concepts/provisioning).

Two more are read **at build time**, not at run time, and only when the matching
[self-contained feature](../getting-started/installation#self-contained-engines-optional)
is on. Each supplies the static binary to embed, and the build verifies its SHA-256
against the pinned expectation, so a drifted engine fails the build loudly:

| Variable | Supplies | Required by |
|---|---|---|
| `SBX_BUNDLED_NIX` | the static `nix` to embed | the `bundled-nix` feature |
| `SBX_BUNDLED_BWRAP` | the static `bwrap` to embed | the `bundled-bwrap` feature |

`mise run build-bundled` sets both from the pinned engine builds; you never set them by
hand for an ordinary build.

## Directory variables (host)

`sbx` follows the XDG base-directory convention. A relative value is ignored (the spec
requires an absolute base), and `sbx` falls back to `$HOME`.

| Variable | Selects | Fallback |
|---|---|---|
| `XDG_CONFIG_HOME` | the config dir (`sbx/sbx.toml`, `sbx/apps/`) | `$HOME/.config` |
| `XDG_DATA_HOME` | the data dir (store, engines, sessions, …) | `$HOME/.local/share` |
| `XDG_STATE_HOME` | the trust store (`sbx/trusted/`) | `$HOME/.local/state` |
| `XDG_RUNTIME_DIR` | the Wayland socket (for `gui = "wayland"`) and the systemd user session | n/a |

### `SBX_DATA_DIR`

| Variable | Selects | Fallback |
|---|---|---|
| `SBX_DATA_DIR` | the data directory itself | a volume adopted with [`sbx storage use`](../cli/storage), else `$XDG_DATA_HOME/sbx` |

The data directory is the one sbx tree that grows without bound: the shared nix store,
the per-project runtime trees and the app homes all live there, and it is routinely tens
of gigabytes across hundreds of thousands of inodes ([`sbx store`](../cli/store)
reports both). `SBX_DATA_DIR` puts it on a filesystem of your choosing.

It differs from `XDG_DATA_HOME` in two ways, because it is sbx's own variable rather than
a base shared with every application:

- It names the directory **itself**: nothing is appended. `SBX_DATA_DIR=/vol/sbx` uses
  `/vol/sbx`, where `XDG_DATA_HOME=/vol` would use `/vol/sbx`.
- A **relative** value is **refused**, not ignored: sbx reports the error and stops. A
  relative path would resolve against whatever directory sbx was launched from, so falling
  back quietly would put your projects and apps somewhere you never look. Unset or empty
  reads as absent, so clearing the variable restores the default.

It also has a **length limit, 74 bytes**, and a longer path is refused with that figure in
the message. Egress filtering, the D-Bus filter, port forwarding and exec enforcement each
bind a Unix-domain socket *under* the data directory, and the kernel caps a socket path at
108 bytes. Without the check those features would fail at launch, reporting a socket
problem rather than the directory that caused it.

The **same limit applies to the directory sbx derives** when you set no `SBX_DATA_DIR`: a very
long `$HOME` or `$XDG_DATA_HOME` can push `$HOME/.local/share/sbx` past it. sbx then stops with
the same message: set `SBX_DATA_DIR` to a shorter path, or adopt a [storage volume](../cli/storage), its mount point under `/run` is short, so it clears the limit on its own. `sbx storage` keeps
working while the plain directory is over the limit, so the volume remedy is always reachable.

It also **overrides an adopted volume**, so it stays the way to run one-off against another
data directory. To move sbx's data permanently, [`sbx storage use`](../cli/storage) is the
better route: it needs no variable at all and mounts the volume by itself.

Pointing it at a filesystem that shares storage between files (copy-on-write) is worth
knowing about: sbx seeds each per-project store from the shared one by cloning, which on
such a filesystem shares blocks instead of copying them, and compression: where the
filesystem offers it, applies on top. `sbx store` reports which case your filesystem is.

See [Directory layout](../concepts/directory-layout).

## Editor variables (host)

[`sbx config edit`](../cli/config) opens the target file in `$VISUAL`, then
`$EDITOR`, falling back to `vi`.

## Variables sbx sets inside the cage

A cage does **not** inherit your host environment. `sbx` sets a small structural set,
including:

| Variable | Meaning |
|---|---|
| `SBX_SANDBOX=1` | a marker that the process is running inside an `sbx` cage |
| `SBX_EGRESS_CONTRACT` | the in-cage path to the generated contract (`/opt/sbx/egress-contract.md`): what the cage can reach, and the [declared operations](../cli/task#how-an-agent-finds-them) it may invoke |
| `no_proxy`/`NO_PROXY` | set to `localhost,127.0.0.1,::1` so in-cage loopback does not route through the egress proxy |
| `HOME`, `PATH`, `TERM`, `LANG` | the synthetic identity's home, the tool paths, and the two passthrough values |

A configuration that declares a [task](../tasks/) adds two more, so an in-cage caller
finds the operation plane without being told where it is:

| Variable | Meaning |
|---|---|
| `SBX_TASK_CLI` | the in-cage path of the task client (`/opt/sbx/bin/sbx`), a [generated script](../cli/task#what-the-cage-actually-holds) that speaks the plane's protocol and refuses every other word |
| `SBX_TASK_SOCKET` | the in-cage path of the plane's socket (`/tmp/sbx-task.sock`), which is also how `sbx task` knows it is running inside a cage |

Inside a **task** cage (the ephemeral sibling an invocation runs in) the set is different:

| Variable | Meaning |
|---|---|
| `SBX_TASK` | the name of the operation being run. A task is never interactive, so a tool that would otherwise prompt can fail fast instead of hanging until the timeout |
| `SBX_TASK_OUT` | the writable [output directory](../tasks/output#producing-a-file-output) (`/opt/sbx/out`), set only when the declaration carries `output = true`. The calling cage reads the same artifacts at `/opt/sbx/task-out/<task>/` |

Under a [filtering network posture](../networking/modes), `sbx` also sets the proxy
variables (`http_proxy`/`https_proxy`) and the CA-bundle variables so in-cage tools
trust the egress proxy's per-session CA. These are managed by `sbx`; a trusted
[`env`](../configuration/env) can override a cage variable, but the loader-control and
proxy-control keys are on the [untrusted-only denylist](../configuration/env#the-reserved-key-denylist-untrusted-only).

## Tool-behavior variables (in-cage, via `env`)

A trusted [`env`](../configuration/env) entry can also tune a tool `sbx` runs in the
cage. The one worth knowing:

| Variable | Effect |
|---|---|
| `MISE_MINIMUM_RELEASE_AGE` | overrides mise's built-in 24 h fresh-release hold; `"0"` installs the newest upstream release immediately. See [Upgrading toolchains](../housekeeping/upgrade#installing-the-newest-release-immediately). |

Set it in the **global** config to apply to every app: edit `sbx/sbx.toml` or run
`sbx config set --global env.MISE_MINIMUM_RELEASE_AGE 0` (`--local` for one project). A
host `export` does **not** reach the cage, and `sbx upgrade` takes no override flags: a
config `env` entry is the only channel.

## Credential variables (host, user-defined)

An app [profile](../apps/catalog) references a provider key by
[`from = "env://VAR"`](../secrets/resolvers): e.g. `ANTHROPIC_API_KEY`,
`OPENAI_API_KEY`, `OPENROUTER_API_KEY`. You export these on the host; the
[egress proxy injects](../secrets/injection) them on the wire, so they **never enter
the cage**.
