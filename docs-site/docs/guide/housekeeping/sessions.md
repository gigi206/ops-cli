# Sessions

`sbx` keeps a **daemonless** on-disk registry of live sandbox sessions. There is no
background process, a session writes a record, and reading the registry validates and
prunes it.

See also: [`sbx session`](../cli/session) · [Directory layout](../concepts/directory-layout).

## The registry

Each sandbox writes a record under [`<data>/sessions/`](../concepts/directory-layout).
A record is a **liveness-validated hint**, never trusted to be cleaned up:
[`sbx session ls`](../cli/session#ls) prunes by liveness, so a crash or `SIGKILL` self-heals rather
than leaving a stale entry.

Liveness is `(pid, start_time)`: the process start time from `/proc/<pid>/stat`, which
survives an `execve`, defeats pid reuse (a `kill(pid, 0)` alone could match a recycled
pid; the start-time match is decisive).

The record stores the **canonical** project path: the same identity the sandbox
derives its runtime id from: so the registry and the runtime never disagree.

## Which launches register

| Launch | Registers |
|---|---|
| [`sbx run --detach`](../cli/run) | a background session |
| [`sbx app run --detach`](../cli/app) | a background agent session |
| [`sbx run`](../cli/run) | while the shell runs (unlinked on exit) |
| interactive [`sbx app`](../cli/app) | while the app runs |

## Listing, attaching, stopping

```sh
sbx session ls          # the live sessions (app sessions show their app name)
sbx session attach <id> # open a shell inside a session's live cage
sbx session stop <id>   # SIGTERM, then SIGKILL after the grace delay
sbx session stop --all  # every session
```

- [`sbx session attach <id>`](../cli/session#attach) joins the running cage and opens a shell **inside**
  it (the agent's live processes, its real `/tmp`, its network): a host-side join of the cage's namespaces,
  and the shell re-applies the cage's confinement (seccomp denylist, `no_new_privs`, dropped
  capabilities), so it is never a wider hole than the agent.
- [`sbx session stop`](../cli/session#stop) tears down the whole cage subtree (SIGTERM → SIGKILL after
  `--delay`, default 10s).

The `<id>` is the PID `sbx session ls` shows.

## Background agents

`--detach` runs an agent in the background as a session you can later `attach` to or
`stop`. This is how you launch a long-running autonomous agent and check on it from
another terminal:

```sh
sbx app run claude-code --detach
sbx session ls
sbx session attach <id>   # look in
sbx session stop <id>     # done
```

## The "second terminal"

Because a project's runtime is deterministic (derived from the canonical project path),
a second sandbox launched in the same project shares its persistent `$HOME`: so opening
a second `sbx run` in the same project "just works" without any session coordination.
