---
sidebar_label: "[limits]"
description: "Overriding the cage's cgroup v2 resource limits, the anti-DoS control."
---

# `[limits]`: cgroup resource limits

Override the cage's cgroup v2 resource limits (the anti-DoS control), which otherwise
use `sbx`'s built-in defaults. The threat is mundane: untrusted code that fork-bombs
(`tasks_max`), eats memory (`memory_high`/`memory_max`), or grinds the host, by malice
or by a runaway build. These limits do not isolate (that is the bind layout and the
namespaces); they cap the blast radius, best-effort, where the host supports cgroup v2.

```toml
[limits]
memory_high = "70%"
memory_max  = "16G"
tasks_max   = 8192
```

`[limits]` is a **security field**: honored from the global config or a trusted
project, ignored from an untrusted one: because loosening a limit (a higher
`tasks_max`, an unbounded ceiling) reduces the anti-DoS protection.

What it bounds is every cage a launch stands up, not only the session: a task, a task pool install,
a userland build under [`[distro] run`](distro), a `<backend>:resolve` command and the `mise` run
that resolves a project's `[env]` each get a scope carrying these ceilings. A **plugin** cage is the
one exception and takes the global `[limits]` wherever it runs, since it is sbx's own machinery
rather than the project's. See
[the enforcement stack](../concepts/enforcement#which-cages-run-inside-a-scope).

See also: [Enforcement stack](../concepts/enforcement) · [The trust gate](../concepts/trust) · [`[app.<name>]`](apps).

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
  **not** accepted for tasks (systemd rejects `TasksMax=100%`). A negative number is
  dropped per field with a warning: values parse signed precisely so one bad field
  cannot invalidate the whole layer.

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
limits are hardening, never the boundary. See [Enforcement stack](../concepts/enforcement).

The memory ceiling is honestly **per-cage**, not host-global (N concurrent cages can
sum past total RAM); the task cap is the clean host-wide anti-DoS guarantee.

## Inspecting the scopes

Each cage owns one transient unit named after it, so the running cages are visible from
the host:

```sh
systemctl --user list-units --all 'sbx-*' --plain --no-pager
```

The unit is named `sbx-<slug>-<n>-<pid>.scope`, where the pid is the `sbx` process that launched
the cage and `n` counts the cages that process has stood up. Two numbers, because a transient unit
name must be free when it is asked for and neither alone is enough: the pid separates two
concurrent launches, while `n` separates the cages of one launch (its session, its tasks, a
userland build, a resolve command, a plugin), which follow each other closely enough that the
previous name is not always released yet. `ps` and `systemd-cgls` show the same name, and
[`sbx session ls`](../cli/session) is the same view from sbx's side.

A launch owns more than one unit, because a launch stands up more than one cage. Which ones, and
which ceilings each takes, is in
[the enforcement stack](../concepts/enforcement#which-cages-run-inside-a-scope).

A scope normally disappears on its own once its cage exits: systemd watches the scope's
cgroup and reclaims the unit when it empties. That watch is an inotify watch, and a
session's inotify budget is shared with every other watcher on the host, so installing it
can fail. systemd treats that failure as non-fatal, the notification then never arrives,
and the scope stays `active running` over an empty cgroup with no path to a terminal
state. Left alone, those units accumulate for the life of the login session.

`sbx` reclaims them. Every launch stops the scopes whose launcher is gone **and** whose
cgroup holds no process, before creating its own. Both conditions are required, and a
cgroup that cannot be read counts as in use: the sweep leaves a leftover behind rather
than risk touching a running cage. It never delays the launch behind it, and it says
nothing, so a clean host looks exactly like a swept one.

A leftover is recognisable by an empty cgroup under a unit systemd still calls running:

```sh
systemctl --user show <unit> -p TasksCurrent --value   # 0 on a leftover
```

## Per-app limits

An `[app.<name>.limits]` table (or a `[limits]` table in an imported profile)
overrides the baseline limits **for that app's launches**, layered per field and gated
the same way. An untrusted project's app `[limits]` is dropped whole. See
[`[app.<name>]`](apps).

```toml
[app.build.limits]
tasks_max = 4096
```

## Viewing the effective limits

```sh
sbx config show            # a `limits:` line only when a field is overridden
sbx config show --app cap            # tagged default, inherited or set by the app
sbx config show --app cap --details  # plus the limits no layer set (folded by default)
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
[One-shot overrides](overrides).

## Examples

Three postures, each of which is really one question: what should this workload be
allowed to consume before the host suffers?

```toml
# a heavy parallel build: many processes, a generous but finite memory ceiling
[limits]
memory_high = "70%"
memory_max  = "24G"
tasks_max   = 32768
```

```toml
# an untrusted agent: a tight fork-bomb guard, throttled well before the host notices
[limits]
memory_high = "40%"
memory_max  = "50%"
tasks_max   = 2048
```

```toml
# a measurement run where the limits would distort the result
[limits]
memory_high = "infinity"
memory_max  = "infinity"
tasks_max   = "infinity"
```

The third one removes the anti-DoS control this field exists for: an `infinity`
`tasks_max` is a cage a fork bomb can take the host down from. It is a deliberate
posture for a benchmark you are watching, not a baseline, and it is the reason
`[limits]` is a trusted-only field.

Per app, layered per field over whichever of those is the baseline:

```toml
[app.build.limits]
tasks_max = 4096          # memory_high / memory_max keep the baseline's values

[app.review.limits]
memory_max = "4G"
```

And for one launch, without editing anything:

```sh
sbx run --limit tasks_max=8192 -- ./build.sh
sbx run --limit memory_max=8G --limit tasks_max=1024 -- ./untrusted.sh
SBX_LIMIT_MEMORY_MAX=16G sbx run -- ./build.sh
```

Values that are refused, and what they should have been:

| Written | Why it is dropped | Write instead |
|---|---|---|
| `memory_max = 90` | a bare memory number is **bytes**: 90 bytes | `memory_max = "90%"` |
| `memory_max = "16GiB"` | no `i`, no `B` suffix | `memory_max = "16G"` |
| `memory_max = "16g"` | the suffix is uppercase | `memory_max = "16G"` |
| `tasks_max = "100%"` | systemd rejects a percentage for tasks | `tasks_max = 16384` |
| `tasks_max = 0` | a positive integer, or `infinity` | `tasks_max = 1` |

Each is dropped with a warning and falls back to its default, which is why
`sbx config show` is worth a look after editing: a `limits:` line appears only for a
field that actually took effect.

```sh
sbx config show            # what survived, and from which layer
sbx doctor                 # whether this host can apply limits at all
```

On a host with no cgroup v2 or no reachable systemd user session, the cage launches
**without** limits rather than failing. That is deliberate (they are hardening, never
the boundary), and `doctor` is where you see it.
