# `sbx session`

```
sbx session ls
sbx session logs <id> [-f] [-n <N>] [--all]
sbx session attach <id> [-- command [args...]]
sbx session stop <id>...|--all [--delay <secs>]
```

Inspect and control the **live sandbox sessions**: the running cages. `sbx session ls`
lists them, `sbx session logs` shows a detached one's output, `sbx session attach` runs a shell
or a command inside one, and `sbx session stop` ends them.
Host-side: reads the on-disk session registry (daemonless), launches nothing. `sbx sessions`
is an alias.

See also: [Sessions](../housekeeping/sessions.md) · [`sbx projects`](projects.md) · [`sbx gc`](gc.md).

## `ls`

```
sbx session ls
```

List the live sandbox sessions from the on-disk registry. Reading the registry
**re-validates and prunes dead records**, so the list is always current: a crashed or
killed session self-heals rather than lingering. An app session shows its app name, so you
can tell which sessions are agents.

Sessions are created by [`sbx run --detach`](run.md), [`sbx app run --detach`](app.md), and
interactive [`sbx run`](run.md) / [`sbx app`](app.md) launches. The registry is
liveness-validated by `(pid, start_time)` to defeat pid reuse. See
[Sessions](../housekeeping/sessions.md).

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
sbx session logs <id> [-f] [-n <N>] [--all]
```

Show a **detached** session's output. A session started with `--detach` has no terminal, so
its stdout and stderr are redirected to `<data>/logs/<id>.log`; this reads that file back. A
foreground session has no log, its output is on the terminal that started it, and the
[`MODE` column](#ls) says which is which.

| Operand / flag | Meaning |
|---|---|
| `<id>` | the PID reported when the session was detached (required) |
| `-f`, `--follow` | keep streaming until the session exits |
| `-n <N>` | show only the last N lines of the initial listing |
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
sbx session logs 12345 > run.txt   # the agent's bytes, exactly as written
```

The log's bytes go to **stdout** unchanged, so redirecting captures exactly what the agent
wrote; the context line goes to stderr. `--follow` on a session that has already exited prints
what is there and returns rather than waiting for output that will never come.

Logs are keyed by PID and appended to, so a PID the kernel later reuses writes into the same
file. A header line separates the sessions and only the most recent one is shown; pass `--all`
for the whole file.

> **Note.** Nothing prunes `<data>/logs` yet: neither [`sbx gc`](gc.md) nor session teardown.
> A long-lived install accumulates one small file per detached launch; remove them by hand if
> they add up.

If you lose the id, the launch message is the only place it is reported: `sbx session ls` can
only show sessions that are still alive. Failing that, list the directory:
`ls ~/.local/share/sbx/logs` (or see [`sbx path`](path.md) for your data directory).

## `attach`

```
sbx session attach <id> [-- command [args...]]
```

Join a **running** session's cage: the agent's live processes, its real `/tmp`, and its
the real-time cage state: the host-side join of the running cage (via `setns`)
not a fresh cage that merely shares the home. With no command it opens an **interactive shell**
(an interactive attach); with `-- command` it **runs that command** inside the cage.

| Operand | Meaning |
|---|---|
| `<id>` | the PID `sbx session ls` shows for the session |
| `-- command [args...]` | run this command in the cage instead of an interactive shell |

A bare `sbx session attach` needs a terminal on stdin. A `-- command` adapts to its stdin: from
a terminal it runs through a **pty** (interactive tools keep job control and resize), from a pipe
or script through **inherited stdio** (bytes pass through clean in both directions, so it composes
with pipes and redirection). The command's exit status becomes sbx's, so it scripts cleanly. The
command is run via the cage's own `bash` so it resolves on the cage `PATH`, and it is passed
positionally: no argument is ever interpreted as shell syntax.

A `-- command` runs in the agent's **environment as the cage was launched**: its `PATH`, proxy,
and CA settings, read from the live agent process — the same path the interactive shell inherits,
shell it does not carry any host secret). Unlike the interactive shell, it does **not** source the
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

`--all` targets every session, interactive shells included.

```sh
sbx session stop 12345
sbx session stop 12345 12377 --delay 3
sbx session stop --all
```
