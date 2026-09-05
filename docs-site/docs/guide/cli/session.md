---
description: "List, attach to and stop the live sandbox sessions, and read what each printed."
---

# `sbx session`

```
sbx session ls
sbx session logs <id> [-f|--follow] [-n|--lines <N>] [--all]
sbx session attach <id> [-- command [args...]]
sbx session stop <id>...|--all [--delay <secs>]
```

Inspect and control the **live sandbox sessions**: the running cages. `sbx session ls`
lists them, `sbx session logs` shows a detached one's output, `sbx session attach` runs a shell
or a command inside one, and `sbx session stop` ends them.
Host-side: reads the on-disk session registry (daemonless), launches nothing. `sbx sessions`
is an alias.

See also: [Sessions](../housekeeping/sessions) · [`sbx projects`](projects) · [`sbx gc`](gc).

## `ls`

```
sbx session ls
```

List the live sandbox sessions from the on-disk registry. Reading the registry
**re-validates and prunes dead records**, so the list is always current: a crashed or
killed session self-heals rather than lingering. An app session shows its app name, so you
can tell which sessions are agents. `sbx session list` is an accepted alias.

Sessions are created by [`sbx run --detach`](run), [`sbx app run --detach`](app), and
interactive [`sbx run`](run) / [`sbx app`](app) launches. The registry is
liveness-validated by `(pid, start_time)` to defeat pid reuse. See
[Sessions](../housekeeping/sessions).

```sh
sbx session ls
# NAME       KIND          MODE        PID     AGE  PROJECT
# sbx-web    app:claude    detached    12345   2m   /home/me/web
# sbx-web    shell         foreground  12377   1m   /home/me/web
```

The `PID` column is the `<id>` used by `sbx session attach <id>`, `sbx session logs <id>` and
`sbx session stop <id>`.

`MODE` says how the session was launched, which is also where its output went:

| `MODE` | Launched with | Its output |
|---|---|---|
| `detached` | `--detach` | redirected to a log: read it with [`logs`](#logs) |
| `foreground` | no `--detach` | on the terminal that started it |

## `logs`

```
sbx session logs <id> [-f|--follow] [-n|--lines <N>] [--all]
```

Show a **detached** session's output. A session started with `--detach` has no terminal, so
its stdout and stderr are redirected to `<data>/logs/<id>.log`; this reads that file back. A
foreground session has no log, its output is on the terminal that started it, and the
[`MODE` column](#ls) says which is which. `sbx session log` is an accepted alias.

| Operand / flag | Meaning |
|---|---|
| `<id>` | the PID reported when the session was detached (required) |
| `-f`, `--follow` | keep streaming until the session exits |
| `-n, --lines <N>` | show only the last N lines of the initial listing |
| `--all` | show every session that wrote to this log, not just the most recent |

The id is **required** and is resolved straight to the log file, never through the session
registry. That is deliberate: the registry drops a record the moment its process dies, so a
lookup would fail in exactly the case this command exists for: finding out why a background
agent stopped. Reading an exited session works the same as reading a running one.

```sh
sbx app run claude --detach
# sbx: started `app:claude` as detached session 12345 (logs: ~/.local/share/sbx/logs/12345.log)
# sbx: `sbx session logs 12345` shows its output (`-f` to follow), …

sbx session logs 12345 -f      # follow it live; returns when the session exits
sbx session logs 12345 -n 50   # just the tail
sbx session logs 12345 > run.txt   # the agent's bytes, as it wrote them
```

The log's bytes go to **stdout** unchanged, so redirecting captures the agent's output as it
wrote it; the context line goes to stderr. `--follow` on a session that has already exited prints
what is there and returns rather than waiting for output that will never come.

Logs are keyed by PID and appended to, so a PID the kernel later reuses writes into the same
file. A header line separates the sessions and only the most recent one is shown; pass `--all`
for the whole file.

### The two lines sbx writes itself

Everything in the file is the agent's, except two kinds of line. Both are marked `=== … ===`
and both are written before the agent's first byte:

```
=== sbx session 12345 started=1786539487 ===
=== sbx trust-drop: .sbx.toml: ignoring `gpu` posture (untrusted — run `sbx trust`) ===
```

The first is the session header described above. The second appears once per security field
[the trust gate](../concepts/trust) dropped from that launch, and it is there because
otherwise nothing would keep it: sbx states its dropped fields on the terminal that started the
session, before redirecting to this file, so a session detached overnight announces them to a
terminal nobody is watching. This note is the only record that outlives it. A foreground
session needs none of this, its warnings go to a stderr you own.

Both are written before the agent's first byte, so `-n <N>` will not show them once the
agent has printed more than N lines: it is a tail, and the notes are at the head. Read
without `-n` when you want them.

The honest limit: the agent writes into this same file and can print a line that looks like
either marker. That hides its own earlier output from the default view, which `--all` still
shows; it is not a boundary the agent can cross.

> **Note.** Nothing prunes `<data>/logs` yet: neither [`sbx gc`](gc) nor session teardown.
> A long-lived install accumulates one small file per detached launch; remove them by hand if
> they add up.

If you lose the id, the launch message is the only place it is reported: `sbx session ls` can
only show sessions that are still alive. Failing that, list the directory:
`ls ~/.local/share/sbx/logs` (or see [`sbx path`](path) for your data directory).

## `attach`

```
sbx session attach <id> [-- command [args...]]
```

Join a **running** session's cage the way `docker exec` does: the agent's live processes, its
real `/tmp`, and its network: the host-side join of the running cage (via `setns`),
not a fresh cage that merely shares the home. With no command it opens an **interactive shell**
(an interactive attach); with `-- command` it **runs that command** inside the cage.

| Operand | Meaning |
|---|---|
| `<id>` | the PID `sbx session ls` shows for the session (exactly one) |
| `-- command [args...]` | run this command in the cage instead of an interactive shell |

A `--` with nothing after it is refused (usage, exit 2): attach either takes a command
or opens a shell.

A bare `sbx session attach` needs a terminal on stdin. A `-- command` adapts to its stdin: from
a terminal it runs through a **pty** (interactive tools keep job control and resize), from a pipe
or script through **inherited stdio** (bytes pass through clean in both directions, so it composes
with pipes and redirection). The command's exit status becomes sbx's, so it scripts cleanly. The
command is run via the cage's own `bash` so it resolves on the cage `PATH`, and it is passed
positionally: no argument is ever interpreted as shell syntax.

A `-- command` runs in the agent's **environment as the cage was launched**: its `PATH`, proxy,
and CA settings, read from the live agent process, the same path the interactive shell inherits
(so it does not carry any host secret). Unlike the interactive shell, it does **not** source the
in-cage rc, so it does not re-run `mise activate`; declared tools and the base toolset are on the
launch `PATH` and resolve, but a tool the agent activated purely at runtime may not be.

`attach` provisions nothing and reads no config: it enters namespaces the cage already built.
The joined shell or command **re-applies the cage's confinement**: the same seccomp denylist,
`no_new_privs`, and dropped capabilities (none of that is inherited across `setns`): so
attaching never opens a wider hole than the agent already has. The one thing it does **not**
share is the cage's cgroup resource limits (memory/task caps): an inspection shell runs in
its own scope, so it is not bounded by the agent's OOM ceiling. It needs a live session; if
the session has exited, `attach` says so (run `sbx session ls` to list live ones). Type
`exit` to leave a bare shell: the agent keeps running.

The status `attach` returns is the joined command's own, and `128 + N` for one a signal
ended. Three codes are the join itself failing rather than the command: `125` the
confinement could not be re-applied, `126` the cage could not be joined, `127` the cage
has no such program. See [Exit codes](../reference/exit-codes#sbx-session-attach-has-three-failures-of-its-own).

```sh
sbx session ls                        # find the id
sbx session attach 12345              # drop into a shell inside that running agent's cage
# … inspect: ps, look at /tmp, curl through its egress …
exit                                  # leave; the agent keeps running

sbx session attach 12345 -- ps aux    # run one command and print its output
sbx session attach 12345 -- cat /tmp/agent.log | grep ERROR   # pipe it (clean bytes)
sbx session attach 12345 -- python3   # interactive tool through a pty
```

Everything runs from the agent's own view of the filesystem, so `attach` is a tool for
**inspecting and interacting with a running agent**, not a pristine environment. The shell or
command binary comes from the cage's mount namespace (so any path the agent could resolve, the join passes through);
the re-applied confinement bounds what it can do.

## `stop`

```
sbx session stop <id>...|--all [--delay <secs>]
```

Stop running sessions. Sends `SIGTERM`, then `SIGKILL` after the grace delay, tearing down
the whole cage subtree. Either ids or `--all` is required, not both.

| Option | Meaning |
|---|---|
| `<id>...` | the PIDs `sbx session ls` shows for the sessions to stop |
| `--all` | stop every live session (mutually exclusive with explicit ids) |
| `--delay <secs>` | seconds to wait after `SIGTERM` before `SIGKILL` (default 10; `0` = at once) |

A bare `--` ends the options: everything after it is read as an id, even `--all`
(ids are PIDs, so `sbx session stop -- --all` reports an unknown session rather than
stopping everything).

`--all` targets every session, interactive shells included.

```sh
sbx session stop 12345
sbx session stop 12345 12377 --delay 3
sbx session stop --all
```

A session sbx could not get a handle on is a separate outcome from one that had already
exited. Nothing was signalled, so the cage may still be running: the line names the reason,
the session keeps its place in `sbx session ls` so a second attempt can still address it, and
the command exits 1. An id that matched no live session still exits 2.

## Examples: the life of a background agent

The four subcommands are one workflow. Launch it, find it, watch it, look inside it,
end it:

```sh
sbx app run claude-code --detach --observe   # start it; the launch prints the id
sbx session ls                               # …or find it later, by app name

sbx session logs 12345 -f                    # its output, as it comes
sbx fs logs   12345 -f                       # what it writes (needs --observe)
sbx proc logs 12345 -f                       # what it executes (needs --observe)
sbx net logs -f                              # where it goes

sbx session attach 12345                     # step inside the running cage
sbx session attach 12345 -- ps aux           # …or just ask it one question

sbx session stop 12345                       # SIGTERM, then SIGKILL after 10s
```

Two things worth separating: `logs` reads what the agent *printed* (plus [the two lines sbx
writes itself](#the-two-lines-sbx-writes-itself)), which survives on disk for a detached
session; `fs`/`proc`/`net logs` read what it *did*, which lives in the supervisor's memory
and is gone when the session exits. If a run needs a durable record of its actions, pipe the
`--json` feed to a file while it runs.

Ending everything at once, for instance before a machine goes to sleep:

```sh
sbx session ls                               # see what is live first
sbx session stop --all --delay 3             # interactive shells included
sbx gc --all --prune                         # …then reclaim what they left
```
