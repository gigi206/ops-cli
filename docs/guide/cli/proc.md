# `sbx proc`

```
sbx proc ls   [<id>] [--json]
sbx proc live [<id>] [-i|--interval <secs>] [--json]
sbx proc logs [<id>] [-f|--follow] [--json]
```

Observe what a running sandbox is doing **inside its cage** — the observability sibling of
[`sbx net`](net.md). `sbx proc ls` snapshots a session's **process tree** (the programs the
agent has spawned) and `sbx proc live` watches it redraw in real time — both always available,
reading `/proc` with no privilege and no cooperation from the cage, launching nothing.
`sbx proc logs` is the **exec-event feed**: the processes the agent spawns, in order, for a
session started with observation on ([`sbx run --observe`](run.md#observing-a-run-observe)).

See also: [`sbx net`](net.md) · [`sbx session`](session.md).

## `ls`

```
sbx proc ls [<id>] [--json]
```

Snapshot the process tree of a running session. The launcher process — or bubblewrap itself on
the [`sbx run`](run.md) exec path — is the root, and every process the agent spawned is one of
its descendants in host pid-space, so a plain `/proc` walk from that root shows the whole tree.

| Operand / option | Meaning |
|---|---|
| `<id>` | the PID [`sbx session ls`](session.md) shows; omit it when only one session is live |
| `--json` | emit the tree as JSON instead of the indented view |

With no `<id>` the sole live session is used; if several are live, they are listed so you can
name one by its PID.

```sh
sbx session ls                 # find the id
sbx proc ls 12345
# process tree — session 12345 [app:claude-code] /home/me/web
#   12345  bwrap --unshare-all …
#     12346  node /nix/store/…/claude
#       12400  rg --json TODO src/
#       12511  git commit -m "…"

sbx proc ls                    # only one session live → no id needed
sbx proc ls --json 12345 | jq .tree   # machine-readable
```

Reading `/proc` needs **no privilege** — unlike kernel-tracing observability it requires no
`CAP_BPF` or root. `ls` is a **snapshot**; for a continuously updating view use
[`live`](#live). The pids shown are host-side.

## `live`

```
sbx proc live [<id>] [-i|--interval <secs>] [--json]
```

The `top`-style live view of `ls`: the process tree redrawn in place on an interval (default 1s)
until the session ends or you interrupt (`Ctrl-C`), so you **see the agent spawn and finish
processes in real time**.

| Operand / option | Meaning |
|---|---|
| `<id>` | the PID [`sbx session ls`](session.md) shows; omit it when only one session is live |
| `-i`, `--interval <secs>` | redraw interval in seconds (default 1) |
| `--json` | emit one snapshot object per tick (NDJSON) — for a pipe, not a terminal |

```sh
sbx proc live 12345            # watch the agent's process tree update every second
sbx proc live -i 2            # slower refresh, sole live session
sbx proc live --json 12345 | jq .tree   # one snapshot object per tick
```

The human view **requires a terminal** (the frame redraws in place); use `--json` to script it.
Like `ls` it is read-only, host-side, and unprivileged — it just polls `/proc` on each tick.

## `logs`

```
sbx proc logs [<id>] [-f|--follow] [--json]
```

The **exec-event feed** — the processes an agent spawns inside its cage, in order, each stamped
with the time it was first seen. Where `ls`/`live` snapshot the *current* tree of any session,
`logs` reads a recorded event stream, so the session must have been launched with **observation
on**: [`sbx run --observe`](run.md#observing-a-run-observe) or
[`sbx app run <name> --observe`](app.md). A session without it is reported as *unobserved*, not
shown empty.

| Operand / option | Meaning |
|---|---|
| `<id>` | the PID [`sbx session ls`](session.md) shows; omit it when only one session is live |
| `-f`, `--follow` | stream new events until the session ends (`Ctrl-C` to stop) |
| `--json` | emit one object per event (NDJSON) — works in a pipe |

```sh
sbx run --detach --observe -- claude   # a background agent, observed
sbx proc logs 12345 -f                  # …watch what it spawns, from here
# process feed — session 12345 [run] /home/me/web
#   14:02:11  12346  node /nix/store/…/claude
#   14:02:13  12400  rg --json TODO src/
#   14:02:14  12511  git commit -m "…"

sbx proc logs 12345 --json | jq .command   # machine-readable
```

This is the way to watch an observed session **from another terminal** — and the **only** way to
watch a [detached](run.md) (`--detach`) one, which has no terminal for the inline `[sbx:exec]`
feed. The events are held in the supervisor's memory for the session's lifetime, read over a
per-session control socket that is never exposed inside the cage; nothing is written to disk or
kept after the session exits.

Honest limit: the feed is populated by a short-interval `/proc` poll, so a process that starts and
exits within one tick can be missed. Precise per-spawn capture — and the ability to **block** a
spawn — is a later increment (seccomp user-notification); this is the cheap, unprivileged first cut.
