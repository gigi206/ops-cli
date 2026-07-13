# `ops attach`

```
ops attach <id>
```

Join a **running** session's cage and open an interactive shell **inside** it — the agent's
live processes, its real `/tmp`, and its network — the way `docker exec -it` does. This is a
real join of the running cage (via `setns`), not a fresh cage that merely shares the home.

| Operand | Meaning |
|---|---|
| `<id>` | the PID [`ops ls`](ls.md) shows for the session |

`attach` provisions nothing and reads no config: it enters namespaces the cage already built.
The joined shell **re-applies the cage's confinement** — the same seccomp denylist,
`no_new_privs`, and dropped capabilities (none of that is inherited across `setns`) — so
attaching never opens a wider hole than the agent already has. The one thing it does **not**
share is the cage's cgroup resource limits (memory/task caps): an inspection shell runs in
its own scope, so it is not bounded by the agent's OOM ceiling. It needs a live session; if the
session has exited, `attach` says so (run [`ops ls`](ls.md) to list live ones). Type `exit` to
leave — the agent keeps running.

See also: [`ops ls`](ls.md) · [`ops stop`](stop.md) · [Sessions](../housekeeping/sessions.md).

## Example

```sh
ops ls                 # find the id
ops attach 12345       # drop into a shell inside that running agent's cage
# … inspect: ps, look at /tmp, curl through its egress …
exit                   # leave; the agent keeps running
```

## What it is not

The shell you get runs from the agent's own view of the filesystem, so it is a tool for
**inspecting and interacting with a running agent**, not a pristine environment. The shell
binary comes from the cage's mount namespace (as with any `docker exec`-style entry); the
re-applied confinement bounds what it can do.
