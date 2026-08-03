# `[limits]`: cgroup resource limits

Override the cage's cgroup v2 resource limits (the anti-DoS control), which otherwise
use `sbx`'s built-in defaults.

```toml
[limits]
memory_high = "70%"
memory_max  = "16G"
tasks_max   = 8192
```

`[limits]` is a **security field**: honored from the global config or a trusted
project, ignored from an untrusted one: because loosening a limit (a higher
`tasks_max`, an unbounded ceiling) reduces the anti-DoS protection.

See also: [Enforcement stack](../concepts/enforcement.md) · [The trust gate](../concepts/trust.md) · [`[app.<name>]`](apps.md).

## The fields

| Field | Meaning | Default | Accepts |
|---|---|---|---|
| `memory_high` | soft throttle threshold (reclaim/slow) | 80% | a percentage, a byte size, or `infinity` |
| `memory_max` | hard per-cage OOM ceiling | 90% | a percentage, a byte size, or `infinity` |
| `tasks_max` | process/thread cap (fork-bomb guard) | 16384 | a count, or `infinity` |

Each field is independent and falls back to its default when unset. The three fields
**layer per field** across config layers: a global `tasks_max` and a project
`memory_max` compose, neither reverting the other to a constant.

## Value syntax

Values are validated against **exactly** what `systemd` accepts, because a launch runs
inside a `systemd-run` scope and a rejected value would fail the launch. A malformed
value is **dropped with a warning** (falling back to the default) rather than reaching
`systemd-run`:

- **Memory**, `infinity`, a percentage `N%` in `(0, 100]`, or a byte size: a decimal
  number with an **uppercase** `K`/`M`/`G`/`T`/`P`/`E` suffix. No lowercase, no `B`
  suffix, no `i` (so `16G`, not `16GiB` or `16g`).
- **Tasks**, `infinity`, or a positive integer (`0` is rejected). A percentage is
  **not** accepted for tasks (systemd rejects `TasksMax=100%`).

### The bare-number footgun

A **bare** memory number is *bytes*, so `memory_max = 90` means 90 **bytes**: a
percentage written without its `%`, below the kernel floor, which would brick every
launch. `sbx` catches a bare small memory integer (< 1 MiB) at config time, dropping it
with a `did you mean "90%"?` hint and falling back to the default. (A bare `tasks_max`
integer is a valid task count, not bytes.)

## How limits are enforced

The cage runs inside a transient systemd user scope
(`systemd-run --user --scope`) carrying these as cgroup v2 properties. This is
**best-effort**: on a host with no cgroup v2, no reachable systemd user session, or no
delegated controller, the cage launches **without** limits rather than failing: the
limits are hardening, never the boundary. See [Enforcement stack](../concepts/enforcement.md).

The memory ceiling is honestly **per-cage**, not host-global (N concurrent cages can
sum past total RAM); the task cap is the clean host-wide anti-DoS guarantee.

## Per-app limits

An `[app.<name>.limits]` table (or a `[limits]` table in an imported profile)
overrides the baseline limits **for that app's launches**, layered per field and gated
the same way. An untrusted project's app `[limits]` is dropped whole. See
[`[app.<name>]`](apps.md).

```toml
[app.build.limits]
tasks_max = 4096
```

## Viewing the effective limits

```sh
sbx config show            # a `limits:` line only when a field is overridden
sbx config show --app cap  # an app's effective limits, tagged inherited or set
sbx doctor                 # the host's resource-limiting capability
```

## One-shot override

To tune a single limit for one launch without editing the file, use `--limit
<key>=<value>` (repeatable) or `SBX_LIMIT_<key>`:

```sh
sbx run --limit tasks_max=8192 -- ./build.sh
SBX_LIMIT_MEMORY_MAX=16G sbx run
```

The key is one of `memory_high` / `memory_max` / `tasks_max` (the `SBX_LIMIT_` suffix
is case-insensitive). A one-shot limit tunes that field without dropping the others.
The command line beats the environment, and both beat the config file. See
[One-shot overrides](overrides.md).
