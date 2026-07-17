# `sbx proc`

```
sbx proc ls   [<id>] [--json]
sbx proc live [<id>] [-i|--interval <secs>] [--json]
```

Observe what a running sandbox is doing **inside its cage** — the observability sibling of
[`sbx net`](net.md). `sbx proc ls` snapshots a session's **process tree** (the programs the
agent has spawned); `sbx proc live` watches it redraw in real time. Read-only and host-side —
it reads `/proc` with no privilege and no cooperation from the cage, and launches nothing.

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
