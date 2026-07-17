# `sbx session`

```
sbx session ls
sbx session attach <id> [-- command [args...]]
sbx session stop <id>...|--all [--delay <secs>]
```

Inspect and control the **live sandbox sessions** — the running cages. `sbx session ls`
lists them, `sbx session attach` runs a shell or a command inside one, and `sbx session stop` ends them.
Host-side: reads the on-disk session registry (daemonless), launches nothing. `sbx sessions`
is an alias.

See also: [Sessions](../housekeeping/sessions.md) · [`sbx projects`](projects.md) · [`sbx gc`](gc.md).

## `ls`

```
sbx session ls
```

List the live sandbox sessions from the on-disk registry. Reading the registry
**re-validates and prunes dead records**, so the list is always current — a crashed or
killed session self-heals rather than lingering. An app session shows its app name, so you
can tell which sessions are agents.

Sessions are created by [`sbx run --detach`](run.md), [`sbx app run --detach`](app.md), and
interactive [`sbx shell`](shell.md) / [`sbx app`](app.md) launches. The registry is
liveness-validated by `(pid, start_time)` to defeat pid reuse. See
[Sessions](../housekeeping/sessions.md).

```sh
sbx session ls
# NAME       KIND          PID     AGE  PROJECT
# sbx-web    app:claude    12345   2m   /home/me/web
# sbx-web    shell         12377   1m   /home/me/web
```

The `PID` column is the `<id>` used by `sbx session attach <id>` and `sbx session stop <id>`.

## `attach`

```
sbx session attach <id> [-- command [args...]]
```

Join a **running** session's cage — the agent's live processes, its real `/tmp`, and its
network — the way `docker exec` does. This is a real join of the running cage (via `setns`),
not a fresh cage that merely shares the home. With no command it opens an **interactive shell**
(like `docker exec -it`); with `-- command` it **runs that command** inside the cage.

| Operand | Meaning |
|---|---|
| `<id>` | the PID `sbx session ls` shows for the session |
| `-- command [args...]` | run this command in the cage instead of an interactive shell |

A bare `sbx session attach` needs a terminal on stdin. A `-- command` adapts to its stdin: from
a terminal it runs through a **pty** (interactive tools keep job control and resize), from a pipe
or script through **inherited stdio** (bytes pass through clean in both directions, so it composes
with pipes and redirection). The command's exit status becomes sbx's, so it scripts cleanly. The
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
the session has exited, `attach` says so (run `sbx session ls` to list live ones). Type
`exit` to leave a bare shell — the agent keeps running.

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
command binary comes from the cage's mount namespace (as with any `docker exec`-style entry);
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
