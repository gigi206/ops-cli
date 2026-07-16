# `ops session`

```
ops session ls
ops session attach <id> [-- command [args...]]
ops session stop <id>...|--all [--delay <secs>]
```

Inspect and control the **live sandbox sessions** — the running cages. `ops session ls`
lists them, `ops session attach` runs a shell or a command inside one, and `ops session stop` ends them.
Host-side: reads the on-disk session registry (daemonless), launches nothing. `ops sessions`
is an alias.

See also: [Sessions](../housekeeping/sessions.md) · [`ops projects`](projects.md) · [`ops gc`](gc.md).

## `ls`

```
ops session ls
```

List the live sandbox sessions from the on-disk registry. Reading the registry
**re-validates and prunes dead records**, so the list is always current — a crashed or
killed session self-heals rather than lingering. An app session shows its app name, so you
can tell which sessions are agents.

Sessions are created by [`ops run --detach`](run.md), [`ops app --detach`](app.md), and
interactive [`ops shell`](shell.md) / [`ops app`](app.md) launches. The registry is
liveness-validated by `(pid, start_time)` to defeat pid reuse. See
[Sessions](../housekeeping/sessions.md).

```sh
ops session ls
# NAME       KIND          PID     AGE  PROJECT
# ops-web    app:claude    12345   2m   /home/me/web
# ops-web    shell         12377   1m   /home/me/web
```

The `PID` column is the `<id>` used by `ops session attach <id>` and `ops session stop <id>`.

## `attach`

```
ops session attach <id> [-- command [args...]]
```

Join a **running** session's cage — the agent's live processes, its real `/tmp`, and its
network — the way `docker exec` does. This is a real join of the running cage (via `setns`),
not a fresh cage that merely shares the home. With no command it opens an **interactive shell**
(like `docker exec -it`); with `-- command` it **runs that command** inside the cage.

| Operand | Meaning |
|---|---|
| `<id>` | the PID `ops session ls` shows for the session |
| `-- command [args...]` | run this command in the cage instead of an interactive shell |

A bare `ops session attach` needs a terminal on stdin. A `-- command` adapts to its stdin: from
a terminal it runs through a **pty** (interactive tools keep job control and resize), from a pipe
or script through **inherited stdio** (bytes pass through clean in both directions, so it composes
with pipes and redirection). The command's exit status becomes ops's, so it scripts cleanly. The
command is run via the cage's own `bash` so it resolves on the cage `PATH`, and it is passed
positionally — no argument is ever interpreted as shell syntax.

A `-- command` runs in the agent's **environment as the cage was launched** — its `PATH`, proxy,
and CA settings, read from the live agent process (like `docker exec`, and like the interactive
shell it does not carry any host secret). Unlike the interactive shell, it does **not** source the
in-cage rc, so it does not re-run `mise activate`; declared tools and the base toolset are on the
launch `PATH` and resolve, but a tool the agent activated purely at runtime may not be.

`attach` provisions nothing and reads no config: it enters namespaces the cage already built.
The joined shell or command **re-applies the cage's confinement** — the same seccomp denylist,
`no_new_privs`, and dropped capabilities (none of that is inherited across `setns`) — so
attaching never opens a wider hole than the agent already has. The one thing it does **not**
share is the cage's cgroup resource limits (memory/task caps): an inspection shell runs in
its own scope, so it is not bounded by the agent's OOM ceiling. It needs a live session; if
the session has exited, `attach` says so (run `ops session ls` to list live ones). Type
`exit` to leave a bare shell — the agent keeps running.

```sh
ops session ls                        # find the id
ops session attach 12345              # drop into a shell inside that running agent's cage
# … inspect: ps, look at /tmp, curl through its egress …
exit                                  # leave; the agent keeps running

ops session attach 12345 -- ps aux    # run one command and print its output
ops session attach 12345 -- cat /tmp/agent.log | grep ERROR   # pipe it (clean bytes)
ops session attach 12345 -- python3   # interactive tool through a pty
```

Everything runs from the agent's own view of the filesystem, so `attach` is a tool for
**inspecting and interacting with a running agent**, not a pristine environment. The shell or
command binary comes from the cage's mount namespace (as with any `docker exec`-style entry);
the re-applied confinement bounds what it can do.

## `stop`

```
ops session stop <id>...|--all [--delay <secs>]
```

Stop running sessions. Sends `SIGTERM`, then `SIGKILL` after the grace delay, tearing down
the whole cage subtree. Either ids or `--all` is required, not both.

| Option | Meaning |
|---|---|
| `<id>...` | the PIDs `ops session ls` shows for the sessions to stop |
| `--all` | stop every live session (mutually exclusive with explicit ids) |
| `--delay <secs>` | seconds to wait after `SIGTERM` before `SIGKILL` (default 10; `0` = at once) |

`--all` targets every session, interactive shells included.

```sh
ops session stop 12345
ops session stop 12345 12377 --delay 3
ops session stop --all
```
