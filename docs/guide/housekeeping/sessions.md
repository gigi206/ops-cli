# Sessions

`ops` keeps a **daemonless** on-disk registry of live sandbox sessions. There is no
background process — a session writes a record, and reading the registry validates and
prunes it.

See also: [`ops ls`](../cli/ls.md) · [`ops attach`](../cli/attach.md) · [`ops stop`](../cli/stop.md) · [Directory layout](../concepts/directory-layout.md).

## The registry

Each sandbox writes a record under [`<data>/sessions/`](../concepts/directory-layout.md).
A record is a **liveness-validated hint**, never trusted to be cleaned up:
[`ops ls`](../cli/ls.md) prunes by liveness, so a crash or `SIGKILL` self-heals rather
than leaving a stale entry.

Liveness is `(pid, start_time)` — the process start time from `/proc/<pid>/stat`, which
survives an `execve`, defeats pid reuse (a `kill(pid, 0)` alone could match a recycled
pid; the start-time match is decisive).

The record stores the **canonical** project path — the same identity the sandbox
derives its runtime id from — so the registry and the runtime never disagree.

## Which launches register

| Launch | Registers |
|---|---|
| [`ops run --detach`](../cli/run.md) | a background session |
| [`ops app --detach`](../cli/app.md) | a background agent session |
| [`ops shell`](../cli/shell.md) | while the shell runs (unlinked on exit) |
| interactive [`ops app`](../cli/app.md) | while the app runs |

## Listing, attaching, stopping

```sh
ops ls                 # the live sessions (app sessions show their app name)
ops attach <id>        # open a shell in a session's environment
ops stop <id>          # SIGTERM, then SIGKILL after the grace delay
ops stop --all         # every session
```

- [`ops attach <id>`](../cli/attach.md) reproduces a session's environment — for an app,
  its isolated [home](../apps/home.md).
- [`ops stop`](../cli/stop.md) tears down the whole cage subtree (SIGTERM → SIGKILL after
  `--delay`, default 10s).

The `<id>` is the PID `ops ls` shows.

## Background agents

`--detach` runs an agent in the background as a session you can later `attach` to or
`stop`. This is how you launch a long-running autonomous agent and check on it from
another terminal:

```sh
ops app claude-code --detach
ops ls
ops attach <id>       # look in
ops stop <id>         # done
```

## The "second terminal"

Because a project's runtime is deterministic (derived from the canonical project path),
a second sandbox launched in the same project shares its persistent `$HOME` — so opening
a second `ops shell` in the same project "just works" without any session coordination.
