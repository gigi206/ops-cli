---
sidebar_label: "Observability"
description: "The process and filesystem lenses on a running cage, what they record, and what they cannot see."
---

# Observability: the feeds of a session

The **observability stack** lets you inspect and stream the activity of a running
agent's cage. It is host-side, read-only, unprivileged, and entirely separate from
the security boundary (the namespaces, capabilities, seccomp denylist, the bind
layout: those still bound what an agent can do; observability only **sees** what it
does).

## The feeds

A session is watched through seven independent feeds, each answering a different
question and each read with the same `<id>`: the session's pid, as
[`sbx session ls`](../cli/session) shows it.

| Feed | Question | Reader | Needs |
|---|---|---|---|
| **exec** | what did it run? | [`sbx proc logs`](../cli/proc#logs), [`sbx proc ls`](../cli/proc#ls) | [`--observe`](../cli/run#observing-a-run---observe), or `[proc] mode = enforce`/`ask` |
| **filesystem** | what did it write? | [`sbx fs logs`](../cli/fs#logs) | `--observe` |
| **egress** | where did it go? | [`sbx net logs`](../cli/net#sbx-net-logs), [`sbx net live`](../cli/net#sbx-net-live) | a filtering network posture |
| **ssh-agent** | what did it ask your keys to sign? | [`sbx ssh-agent logs`](../cli/ssh-agent#logs) | an [`[ssh_agent] allow`](../configuration/ssh-agent) grant |
| **broker** | what did a broker plugin rule on? | [`sbx logs --feed broker`](../cli/logs#the-two-plugin-feeds) | a [`[broker.<name>]`](../configuration/broker) binding |
| **signer** | what did a signer plugin form for a request? | [`sbx logs --feed signer`](../cli/logs#the-two-plugin-feeds) | a credential that declares [`sign`](../configuration/secret#sign-a-credential-computed-from-the-request) |
| **task** | which declared operations did it invoke? | [`sbx task logs`](../cli/task#logs) | a [`[task.<name>]`](../configuration/task) |

Five of them are **lenses**: each keeps one bounded ring of events and serves it as it is. The
**egress plane** and the **task plane** are the other two. The egress plane revises what it
recorded, since a request's upstream status arrives after the decision, and the task plane records
an invocation once, when it finishes; [`[observe]`](../configuration/observe#the-two-feeds-that-are-not-lenses)
says what that changes on disk.

They compose into one account of a run, which is the point of the shared id:

```sh
sbx run --detach --observe -- claude   # the launch prints the session id
sbx proc logs 12345 -f                 # what it executed
sbx fs logs 12345 -f                   # what it wrote
sbx net logs -f                        # where it went
sbx ssh-agent logs 12345 -f            # what it signed
sbx task logs --session 12345          # the operations it invoked
```

Each of those shows the most of its own feed. When the question is what happened in what **order**,
read them together instead: [`sbx logs`](../cli/logs) interleaves all seven by time, is the only
reader of the two plugin feeds, and names any feed that is not recording so an empty column is
never mistaken for a quiet one.

```sh
sbx logs 12345 -f                      # all of it, in one column of time
```

Three properties hold across all seven. Each lives in the **supervisor's memory** and is
gone when the session exits, unless [`record = true`](../configuration/observe) also
appends it to a file under the data directory ([`sbx net stats`](../cli/net#sbx-net-stats)
is apart, a durable per-host counter). Each is
read over a per-session control socket that is **never bound into the cage**, and that refuses
a connection from one, so the agent can neither read the record of what it did nor amend it (a
[bind that shows the data directory](../configuration/observe#what-is-written-and-where) shows
the files `record = true` writes, read-only). And none is a fence: where an
event records a decision, the decision was made elsewhere, by
[`[proc] mode`](../configuration/proc) for exec, [`[network]`](../configuration/network) for
egress, the [`[ssh_agent]`](../configuration/ssh-agent) grant, the plugin a broker or signer line
names, or the declaration of a task.

The rest of this page covers the two lenses `--observe` turns on. The egress plane has
[its own page](../networking/observability); the ssh-agent lens is documented with
[its grant](../configuration/ssh-agent), the two plugin feeds with
[`sbx logs`](../cli/logs#the-two-plugin-feeds), and the task plane with
[`sbx task`](../cli/task#logs).

## The two `--observe` lenses

Both are enabled for the lifetime of a single supervised launch:

- **the exec lens**: polls `/proc` for newly-spawned processes under the cage's root
  every 300 ms and pushes each new entry (excluding `bwrap` / `systemd-run` /
  `socat` plumbing) into a per-session **exec ring**.
- **the filesystem lens**: inotify-watches the project tree and pushes every write
  into a per-session **fs ring**.

Both rings are private in-memory ring buffers: the supervisor writes, the host-side
[`sbx proc logs`](../cli/proc) and [`sbx fs logs`](../cli/fs) readers attach
out-of-band, no rewriting of the cage. Each lens is best-effort and degrades
independently: a failure to stand up the filesystem lens warns and leaves the exec
lens running; the launch never fails for it.

See also: [`sbx proc ls`](../cli/proc) · [`sbx proc logs`](../cli/proc) ·
[`sbx fs logs`](../cli/fs) · [`sbx run`](../cli/run).

## Enabling observation

A non-interactive launch enables the exec lens when invoked with `--observe`:

```sh
sbx run --observe -- rg pattern /path   # foreground non-tty: rings + inline `[sbx:exec] <cmd>` line
sbx run --observe --detach --agent     # detached: rings only, no inline echo
```

`--observe` forces the launch onto a **supervised path**: sbx stays alive across the
cage's lifetime, the only path that owns the per-session rings and control sockets.
An interactive `sbx run` (a shell or an interactive command) already supervises; the
flag has the same effect.

A launch that is **enforcing** exec policy (`[proc] mode = "enforce"` or
`"ask"`) does not enable the exec poll: the seccomp user-notification supervisor is
the exec source then, and it owns the proc control socket. The filesystem lens still
runs.

## What you see

### The exec ring

Every newly-seen cage process under the cage's root is recorded with its pid and argv.
It is a **polling** view: precise, per-`execve` capture comes later with the seccomp
user-notification path; this lens catches what lives at least one tick (~300 ms) past
spawn. Very-short-lived commands (one-shot probes that exit before the next tick) are
missed.

The command's argv is **sanitised** before it leaves the lens: ASCII/Unicode control
characters (`\n`, `\r`, `\t`, …) are replaced with spaces, and the value is capped at
512 graphemes. A hostile argv cannot forge a second event line on the line-based
control wire, and a 5 KiB argv cannot bloat the ring.

### The filesystem ring

Every write in the watched project tree is recorded with its path. It is inotify-based
on the project root; subdirectories are watched recursively by default.

Only **writes** (and directory creations / moves / chmod / … that change the tree)
are recorded; pure reads do not fire inotify. A noisy editor (a `git pull`, a build
that rebuilds a 10 000-file `target/`) emits a lot, and the read interfaces (`sbx fs
logs --follow`, `--json` for a pipe) are designed to filter that down.

The filesystem feed is **never inlined** to the run's stderr: it is far too chatty
for that. It is only readable out-of-band (`sbx fs logs`).

### The control sockets

Each supervised launch binds two per-session sockets under
`<data>/proc/control-<pid>.sock` and `<data>/fs/control-<pid>.sock`. The reader
commands (`sbx proc logs`, `sbx fs logs`) connect to those sockets and pull from the
rings on demand; the supervisor unlinks them on exit.

A `SIGKILL` of the supervisor skips the unlink, so a stale socket left from a crashed
predecessor that reused the pid is cleared by the next launch that reuses it.

## Reading the rings

Live the way `tail -f` lives:

```sh
sbx proc logs <pid> --follow        # every new cage process, since launch
sbx fs logs <pid> --follow          # every new write to the project tree
sbx proc logs <pid> --json          # one event per line, machine-readable
```

`sbx proc ls <pid>` shows the **process tree** of the cage at one instant:

```
4218  bwrap --unshare-all
└── 4219  bash /run/current-system/sw/bin/bash
    ├── 4220  ripgrep pattern
    └── 4221  node /nix/store/…/agent
        └── 4222  axios /healthcheck
```

with `--json` for a machine-readable tree. It reads host-side `/proc/<pid>/stat` and
walks the cage's descendant set in host pid-space, the same vantage point the exec
lens uses.

## Honest limits

- **The exec lens has two capture paths.** Under `[proc] mode = enforce|ask` the
  seccomp user-notification supervisor captures *every* `execve` as it happens, so
  nothing short-lived is missed. The cheap `/proc` poll (used by a non-enforcing
  `observe` run) only sees a process that outlives a tick, so a command that exits in
  under one tick is missed there.
- The filesystem lens is **inotify-based, not recursive across filesystems**: a
  `bind`-mounted sub-tree with a different device is its own watch.
- A cage that is no longer alive cannot be observed: the rings are torn down with
  the supervisor, and what is left to read is the file
  [`record = true`](../configuration/observe) wrote, when it was on.
- The observation paths expand **what an operator can see**: they do not change
  what the agent can do. The posture is: same-uid, same-uid's read of `/proc`, which
  needs nothing the agent does not already need on its own host. So they are not a
  new attack surface; they are a lens on the existing one.

## See also

- [`sbx run --observe`](../cli/run): enabling observation on a launch
- [`sbx proc`](../cli/proc): `ls`, `logs`, `logs --follow --json`
- [`sbx fs`](../cli/fs): `logs` (the filesystem lens reader)
- [Egress observability](../networking/observability): the egress plane, in full
- [`sbx ssh-agent`](../cli/ssh-agent): the ssh-agent lens, and what its record is worth
- [`sbx logs`](../cli/logs): every feed in one column of time, and the reader of the two plugin feeds
- [Sessions](../housekeeping/sessions): the registry the shared `<id>` comes from
- [The trust gate](trust): observation is a host-side lens, not a security field
- Design rationale is recorded in this page (process tree + filesystem lens, host-side only, no new attack surface).
