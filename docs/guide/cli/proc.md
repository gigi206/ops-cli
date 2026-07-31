# `sbx proc`

```
sbx proc ls      [<id>] [--json]
sbx proc live    [<id>] [-i|--interval <secs>] [--json]
sbx proc logs    [<id>] [-f|--follow] [--json]
sbx proc pending [allow|deny <id>]
sbx proc allow   <rule> [-l|-g] [-a <app>] [--session [--all]]
sbx proc deny    <rule> [-l|-g] [-a <app>] [--session [--all]]
sbx proc rules   [-a <app>] [--all]
```

Observe — and, under [`[proc]`](../configuration/proc.md) enforcement, **block** — what a running
sandbox is doing **inside its cage**, the process/exec sibling of [`sbx net`](net.md). `sbx proc ls`
snapshots a session's **process tree** (the programs the agent has spawned) and `sbx proc live`
watches it redraw in real time — both always available, reading `/proc` with no privilege and no
cooperation from the cage, launching nothing. `sbx proc logs` is the **exec-event feed**: the
processes the agent spawns, in order, each with its enforcement verdict when the session is
enforcing. `sbx proc pending` lists — and decides — the `execve`s an `ask`-mode session has parked.
`sbx proc allow`/`deny` persist an exec rule to a config file's [`[proc]`](../configuration/proc.md)
list — the sibling of [`sbx net allow`/`deny`](net.md).

To set the posture for a **single launch** without editing a config, use the one-shot
[`--proc <mode>` / `SBX_PROC`](../configuration/overrides.md) override — e.g. `sbx run --proc off`
disables a trusted project's enforcement for one run, and a `--config` blob's `[proc]` table carries
one-shot allow/deny lists.

See also: [`sbx fs`](fs.md) (the file-write sibling) · [`sbx net`](net.md) · [`sbx session`](session.md).

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

Under a non-enforcing `--observe` run the feed is populated by a short-interval `/proc` poll, so a
process that starts and exits within one tick can be missed — and each line's verdict reads
`observe` (it records what ran, not a decision). Under [`[proc] mode = enforce`/`ask`](../configuration/proc.md)
the feed comes from the seccomp user-notification supervisor instead: **every** `execve` is captured
exactly, and each carries its real verdict — `allow`, `deny`, `ask`, or `absent`.

```
#   14:02:11  deny     12346  /nix/store/…/bin/curl
#   14:02:13  allow    12400  /nix/store/…/bin/rg
#   14:02:13  absent   12400  /nix/store/…/bin/rg
```

`absent` is a refusal of a file that was not there. Looking up a program by name issues one `execve`
per `PATH` entry until one succeeds, so a program found in the fourth directory leaves three of
these behind it — nothing was kept from the run, and the same lines would appear with no policy at
all. They are shown because the feed shows every `execve`, and set apart because `deny` is the one
that stopped something.

## `pending`

```
sbx proc pending [allow|deny <id>]
```

Under [`[proc] mode = "ask"`](../configuration/proc.md), an `execve` that matches neither the
`allow` nor the `deny` list is **parked** — the process is blocked in the syscall — awaiting your
decision. `sbx proc pending` lists every parked `execve` across the live sessions; `sbx proc pending
allow <id>` lets it run (the syscall continues), `deny <id>` refuses it (the syscall returns
`EPERM`, never running).

| Operand | Meaning |
|---|---|
| *(none)* | list every parked `execve` — `<session-pid>.<notif-id>`, the cage pid, how long parked, and the exec path |
| `allow <id>` / `deny <id>` | decide one parked `execve` by its `<session-pid>.<notif-id>` id |
| `allow <pid>.*` / `deny <pid>.*` | decide **every** parked `execve` in session `<pid>` at once |

```sh
sbx proc pending
# parked exec — awaiting a decision
#   12345.4211  pid 12400 · 3s  /nix/store/…/bin/ssh
sbx proc pending deny 12345.4211      # refuse it (EPERM)
```

A parked `execve` that is not decided within the ask timeout is auto-denied (fail-closed), so a
process tree never hangs indefinitely on a stalled decision. Because a coding agent spawns
constantly, `ask` is meant to run against a populated `allow` list — see
[`[proc]`](../configuration/proc.md).

## `allow` / `deny`

```
sbx proc allow <rule> [-l|--local|-g|--global] [-a|--app <name>] [--session [--all]]
sbx proc deny  <rule> [-l|--local|-g|--global] [-a|--app <name>] [--session [--all]]
```

Persist an exec rule to a config file's [`[proc]`](../configuration/proc.md) `allow`/`deny` list —
the sibling of [`sbx net allow`/`deny`](net.md). The `<rule>` is an exec-target glob (`*`/`?`):
without a `/` it matches the **basename** (`curl` blocks any `curl` on `PATH`), with a `/` it matches
the **full exec path** (`/usr/bin/*`, `/nix/store/*/bin/git`). `deny` always wins over `allow`.

| Operand / option | Meaning |
|---|---|
| `<rule>` | an exec-target glob (basename, or a full path when it contains `/`) |
| `-l`, `--local` | write the project `.sbx.toml` (the default) |
| `-g`, `--global` | write the global `sbx.toml` |
| `-a`, `--app <name>` | write the rule under that app's `[app.<name>.proc]`; with `--session`, scope the live load to that app |
| `--session` | load the rule into the running session(s) live, writing no config (see below) |
| `--all` | with `--session`, widen the live load to every reachable session (all projects) |

The posture guard matches `[proc]`'s denylist-by-default. On a fresh project a `deny` **bootstraps**
`mode = "enforce"` (a denylist) so it takes effect at once; an `allow` requires `mode = "ask"` — under
`enforce` everything not denied already runs, so an allow there is inert and is refused. A rule added
to an `off`/`observe` mode is likewise refused (it would do nothing).

```sh
sbx proc deny curl                 # fresh project → sets [proc] mode="enforce", deny=["curl"]
sbx proc deny ssh -a claude-code   # under that app's [app.claude-code.proc]
sbx proc allow git                 # only valid once mode = "ask"
```

Writing the project `.sbx.toml` **re-trusts** it (it must be absent or already trusted first), so the
rule takes effect on the next launch; the global config and app profiles are trusted by location.
Removing a rule is done by editing the config ([`sbx config edit`](config.md)).

### `--session` — load a rule into a running session

`--session` loads the rule into the **live overlay** of the running enforcing session(s) instead of a
config file — the proactive sibling of [`pending`](#pending), and the analogue of
[`sbx net allow`/`deny --session`](net.md). The supervisor folds the overlay into every decision
(deny wins over any allow), so it takes effect **immediately** and dies with the session:

```sh
sbx proc deny curl --session         # cut `curl` in this project's live enforcing session(s) now
sbx proc allow git --session -a claude-code   # un-park `git` in that app's ask session(s)
```

It writes **no config** (so, unlike a config write, it never re-trusts the project) and scopes to the
current project by default; `-a <app>` / `--all` widen it, and the config-scope flags (`-l`/`-g`) do
not apply. A `--session allow` only loads into an `ask` session (it is inert under `enforce`, and is
reported as such). It governs **future** execs — it does not un-park (`allow`) or retroactively
refuse (`deny`) an `execve` already parked; decide those with [`pending`](#pending).

## `rules`

```
sbx proc rules [-a|--app <name>] [--all]
```

List the live `--session` rule overlay of the running enforcing session(s) — the rules loaded with
`sbx proc allow`/`deny --session`, which nothing else surfaces (the config-file `[proc]` rules are
shown by [`sbx config show`](config.md)). Scopes to the current project by default; `-a <app>`/`--all`
widen it.

```sh
sbx proc rules
# live session rules
#   479989  deny  curl
```

Honest limit: exec-blocking is a **guardrail, not a containment boundary** — it catches every
`execve`, but an agent can still do harmful work *in-process* (in its own interpreter) without
spawning. It adds visibility and a veto, on top of the cage's real boundaries (confinement by
absence, the read-only store, the network allowlist).
