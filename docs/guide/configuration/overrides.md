# One-shot overrides

A one-shot override changes **any** configuration field for a **single launch**,
without editing a file. It is carried on the command line (or the environment) and is
the **authoritative final word** — it beats a trusted project config *and* an app's own
posture.

See also: [Configuration overview](README.md) · [`sbx run`](../cli/run.md) · [`sbx app`](../cli/app.md) · [Environment variables](../reference/environment-variables.md).

## Why it is authoritative (trusted by invocation)

An override comes from the **invoker** — whoever runs `sbx` — whose authority over the
host process's argv and environment no lower-trust context can reach. So it is
**trusted by invocation** (it touches no trust marker) and beats even a trusted project
config or a named app's overlay. This is distinct from the direnv content-trust of a
project config.

## The two surfaces

### Whole-schema blob — `--config` / `SBX_CONFIG`

Inline TOML (or `@<file>`) shaped exactly like an `sbx.toml`, so it can set **any**
field. Repeatable (later wins).

```sh
sbx run --config 'network = "none"' -- ./build.sh
sbx run --config @override.toml -- ./build.sh
SBX_CONFIG='[limits]
tasks_max = 4096' sbx run -- ./build.sh
```

### Typed flags — one field each

Ergonomic shorthands for a single field, each with an `SBX_*` environment equivalent:

| Flag | Environment | Sets |
|---|---|---|
| `--env KEY=VALUE` | `SBX_ENV_<KEY>` | one cage environment variable |
| `--net <posture>` | `SBX_NET` | the network posture (below) |
| `--gui <none\|wayland>` | `SBX_GUI` | the display posture |
| `--nixpkgs <ref>` | `SBX_NIXPKGS` | the nixpkgs channel or revision |
| `--bind <path[:ro\|:rw]>` | `SBX_BIND` | a host bind (read-only by default); repeatable |
| `--forward <port[,port…]>` | `SBX_FORWARD` | host loopback TCP port(s) into the cage; repeatable |
| `--limit <key>=<value>` | `SBX_LIMIT_<key>` | a cgroup limit (`memory_high`/`memory_max`/`tasks_max`) |
| `--package <name>=<backend:locator>` | `SBX_PACKAGE_<name>` | a package |
| `--seccomp <token[,token…]>` | `SBX_SECCOMP` | relax the syscall denylist ([`[seccomp]`](seccomp.md) grammar); repeatable |
| `--device <path>` | `SBX_DEVICE` | grant a host device node ([`[devices]`](devices.md)); repeatable |
| `--gpu[=true\|false]` | `SBX_GPU` | the [GPU](gpu.md) posture (bare `--gpu` means `true`) |
| `--dbus[=true\|false]` | `SBX_DBUS` | the in-cage [desktop portal](dbus.md) (bare `--dbus` means `true`) |

```sh
sbx run --net none --limit tasks_max=8192 -- ./build.sh
sbx app run claude-code --net none        # cut the app's network for one run
sbx run --seccomp ptrace -- gdb ./a.out   # relax the denylist for one debug session
sbx run --device /dev/kvm -- ./vm.sh      # grant a device for one run
SBX_NET=none SBX_BIND=/opt/data:ro sbx run
```

#### `--seccomp` / `--device` — relaxing the cage for one launch

A config file gates [`[seccomp]`](seccomp.md) and [`[devices]`](devices.md)
**trusted-only** (an untrusted project's is dropped). A one-shot override is **trusted by
invocation** — the person running `sbx` already commands the host process's argv and
environment, and so **outranks any config layer**. So `--seccomp`/`--device` *may* relax the
denylist and grant a device: exactly the relaxation/grant a *trusted config* can already
declare, extended to the more-trusted invoker (parity with the trusted config — not the
`--net`/`--bind` axis). Note relaxing the denylist re-permits a syscall whose only
containment was the filter, widening the **in-cage kernel attack surface** — so a stale
`SBX_SECCOMP` matters more than a stale `SBX_NET` (both print an ambient-source notice).
`--device` takes one path per flag (not comma-split). A bad token or a non-`/dev/` path is
warned and skipped (less relaxation/no device — fail-closed), never fatal. Granting a device
node exposes it; it does not confer a Linux capability, so a device that needs one (a VPN
tun) is not made *usable* this way.

#### The `--net` posture

`--net` takes `none | shared | ask | allow=h1,h2 | deny=h1,h2`. The `allow=`/`deny=`
DSL builds the common one-shot egress shapes:

- `allow=h1,h2` → a default-**deny** allowlist (only `h1,h2` reach).
- `deny=h1,h2` → a default-**allow** denylist (everything except `h1,h2`).

A bare `allow`/`deny` (no `=`) is **refused as ambiguous** — it reads like the list
forms but would mean the opposite wide-open posture.

#### The `--bind` mode

The mode is the suffix after the **last** `:`, and only when it is exactly `ro` or
`rw` — so `/my:dir` is not mis-parsed as a mode. Read-only by default.

## Precedence — four tiers

Lowest to highest:

```
SBX_CONFIG  <  SBX_* typed (env)  <  --config (cli blob)  <  --* typed (cli)
```

The **command line always beats the environment**, and a **typed flag beats the
blob**. Within that, an override beats the trusted project config and the app overlay.

## The merge rule

One uniform rule across all four tiers:

- **Scalars** (`nixpkgs`, `network`, `gui`) are **replaced** by the highest tier that
  sets them.
- **Collections** (`env`, `packages`, `binds`, `forward`, `limits`, `seccomp`,
  `devices`) are **unioned**, the higher tier winning per key/entry — so `--bind` *adds*
  to whatever the blobs bound, and `--limit tasks_max=…` tunes one limit without dropping
  a blob's `memory_max`.

## Fail-closed on an invalid value

An override is the final word, so a mistake must never silently launch a *different*
posture:

- A **set-but-invalid** security value (a `--net nonee` typo, a `--gui bogus`, a bad
  `[limits]` value, a bad `nixpkgs`) is a **hard error — exit 2, no launch**. Silently
  keeping the baseline could leave a *wider* posture than the mistyped intent.
- A **structural** error (a `--limit` with no `=`, a `--bind` with an empty path, a bad
  `--net` keyword, an unknown limit key) is likewise a hard error.
- The **additive** fields (`env`/`binds`/`packages`/`forward`/`seccomp`/`devices`) fail
  *closed* by dropping a bad entry (a missing bind or tool, an unknown syscall token, a
  malformed device path — less capability/relaxation, never a wider posture), so they
  warn and skip.

## Environment footgun notice

The environment *can* set security fields, but each security field sourced from the
**environment** prints a stderr notice — guarding against a stale `SBX_NET=shared` in
your shell rc silently widening every launch. The command line is silent (it is
explicit per-invocation).

## What `sbx config show` reflects

`sbx config show` reflects the **ambient** override (the `SBX_*` environment, not the
CLI flags, which are per-command) in the full view, tagging affected values
`(override)`. A set-but-invalid ambient override surfaces as an error note (the
baseline stands for display). So `config show` never lies about what a launch in this
environment would do.

## Residuals

- Overriding an app's `network` drops the app's read-by-default
  [`default_methods`](network.md#default_methods-apps) → all-verbs (an override posture
  is Mode-A-like). Scope it with `{GET,HEAD}` rules in a `--config` `[network]` if you
  need to keep the read-only default.
- `[net.groups]` and `[app.*]` in an override are ignored with a notice (they are not
  single-launch concepts).
