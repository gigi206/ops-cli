# `sbx proc`

```
sbx proc ls [<id>] [--json]
```

Observe what a running sandbox is doing **inside its cage** — the observability sibling of
[`sbx net`](net.md). `sbx proc ls` snapshots a session's **process tree**: the programs the
agent has spawned. Read-only and host-side — it reads `/proc` with no privilege and no
cooperation from the cage, and launches nothing.

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
`CAP_BPF` or root. It is a **snapshot**, not a live feed: run it again for the current state.
The pids shown are host-side.
