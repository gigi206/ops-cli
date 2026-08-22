---
sidebar_label: "Observability"
description: "The process and filesystem lenses on a running cage, what they record, and what they cannot see."
---

# Observability: the four lenses

The **observability stack** lets you inspect and stream the activity of a running
agent's cage. It is host-side, read-only, unprivileged, and entirely separate from
the security boundary (the namespaces, capabilities, seccomp denylist, the bind
layout: those still bound what an agent can do; observability only **sees** what it
does).

## The four lenses

A session is watched through four independent lenses, each answering a different
question and each read with the same `<id>`: the session's pid, as
[`sbx session ls`](../cli/session) shows it.

| Lens | Question | Reader | Needs |
|---|---|---|---|
| **exec** | what did it run? | [`sbx proc logs`](../cli/proc#logs), [`sbx proc ls`](../cli/proc#ls) | [`--observe`](../cli/run#observing-a-run---observe), or `[proc] mode = enforce`/`ask` |
| **filesystem** | what did it write? | [`sbx fs logs`](../cli/fs#logs) | `--observe` |
| **egress** | where did it go? | [`sbx net logs`](../cli/net#sbx-net-logs), [`sbx net live`](../cli/net#sbx-net-live) | a filtering network posture |
| **ssh-agent** | what did it ask your keys to sign? | [`sbx ssh-agent logs`](../cli/ssh-agent#logs) | an [`[ssh_agent] allow`](../configuration/ssh-agent) grant |

They compose into one account of a run, which is the point of the shared id:

```sh
sbx run --detach --observe -- claude   # the launch prints the session id
sbx proc logs   12345 -f               # what it executed
sbx fs   logs   12345 -f               # what it wrote
sbx net  logs        -f                # where it went
sbx ssh-agent logs 12345 -f            # what it signed
```

Each of those shows the most of its own lens. When the question is what happened in what **order**,
read them together instead: [`sbx logs`](../cli/logs) interleaves all four by time, plus the feeds
with no verb of their own (what a broker plugin ruled on, what a signer plugin formed, and the
declared operations the session invoked), and names any feed that is not recording so an empty
column is never mistaken for a quiet one.

```sh
sbx logs 12345 -f                      # all of it, in one column of time
```

Three properties hold across all four. Each lives in the **supervisor's or the
proxy's memory**, never on disk, and is gone when the session exits (the one exception
is [`sbx net stats`](../cli/net#sbx-net-stats), a durable per-host counter). Each is
read over a per-session control socket that is **never bound into the cage**, so the
agent can neither read the record of what it did nor amend it. And each is a lens,
not a fence: only the exec lens has an enforcing sibling
([`[proc] mode`](../configuration/proc)), and only the egress one has a policy behind
it ([`[network]`](../configuration/network)).

The rest of this page covers the two lenses `--observe` turns on. The egress lens has
[its own page](../networking/observability); the ssh-agent one is documented with
[its grant](../configuration/ssh-agent).

## The two `--observe` lenses

Both are enabled for the lifetime of a single supervised launch:

- **the exec lens**: polls `/proc` for newly-spawned processes under the cage's root
  every 300 ms and pushes each new entry (excluding `bwrap` / `systemd-run` /
  `socat` plumbing) into a per-session **exec ring**.
- **the filesystem lens**: inotify-watches the project tree and pushes every write
  into a per-session **fs ring**.

Both rings are private memmap'd ring buffers: the supervisor writes, the host-side
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
logs --tail`, `--follow`, `--path` filters) are designed to filter that down.

The filesystem feed is **never inlined** to the run's stderr: it is far too chatty
for that. It is only readable out-of-band (`sbx fs logs`).

### The control sockets

Each supervised launch binds two per-session sockets under
`<data>/sessions/<pid>/proc.sock` and `<data>/sessions/<pid>/fs.sock`. The reader
commands (`sbx proc logs`, `sbx fs logs`) connect to those sockets and pull from the
rings on demand; the supervisor unlinks them on exit.

A `SIGKILL` of the supervisor skips the unlink, so a stale socket left from a crashed
predecessor that reused the pid is cleared by the next launch that reuses it.

## Reading the rings

Live the way `tail -f` lives:

```sh
sbx proc logs <pid> --follow        # every new cage process, since launch
sbx fs   logs <pid> --follow        # every new write to the project tree
sbx proc logs <pid> --tail 200      # the last 200 events
sbx proc logs <pid> --json          # one event per line, machine-readable
sbx proc logs <pid> --path src/     # fs lens only: filter by path prefix
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
  the supervisor.
- The observation paths expand **what an operator can see**: they do not change
  what the agent can do. The posture is: same-uid, same-uid's read of `/proc`, which
  needs nothing the agent does not already need on its own host. So they are not a
  new attack surface; they are a lens on the existing one.

## See also

- [`sbx run --observe`](../cli/run): enabling observation on a launch
- [`sbx proc`](../cli/proc): `ls`, `logs`, `logs --follow --json`
- [`sbx fs`](../cli/fs): `logs` (the filesystem lens reader)
- [Egress observability](../networking/observability): the third lens, in full
- [`sbx ssh-agent`](../cli/ssh-agent): the fourth, and what its record is worth
- [Sessions](../housekeeping/sessions): the registry the shared `<id>` comes from
- [The trust gate](trust): observation is a host-side lens, not a security field
- Design rationale is recorded in this page (process tree + filesystem lens, host-side only, no new attack surface).
