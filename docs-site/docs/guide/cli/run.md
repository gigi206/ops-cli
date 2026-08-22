---
description: "Run a command inside the project sandbox, or open the project's sandboxed shell."
---

# `sbx run`

```
sbx run [--detach] [--observe] [override flags] [--] [command [args...]]
```

Run `<command>` inside the project sandbox and propagate its exit status, or, with no
command, open the project's sandboxed shell. A `--` separates `sbx`'s flags from the
command's, so `sbx run -- --detach` runs the literal `--detach`.

See also: [Quick start](../getting-started/quickstart) · [`sbx app`](app) · [One-shot overrides](../configuration/overrides) · [Sessions](../housekeeping/sessions).

## Options

| Option | Meaning |
|---|---|
| `--detach` | run in the background as a session [`sbx session`](session) can see |
| `--observe` | record what the command does, its processes ([`sbx proc logs`](proc#logs)) and file writes ([`sbx fs logs`](fs#logs)); see [Observing a run](#observing-a-run---observe) |
| `--config <toml\|@file>` | one-shot config override (any field); repeatable, later wins |
| `--env KEY=VALUE` | one-shot override of a single cage environment variable; repeatable |
| `--net <posture>` | one-shot network posture: `none` \| `shared` \| `ask` \| `allow` \| `deny`, or the list forms `allow=host1,host2` \| `deny=host1,host2`, which mean the [opposite of the bare word](../configuration/overrides#the---net-posture); to open everything see [Opening the network wide](../networking/modes#opening-the-network-wide) |
| `--gui <none\|offscreen\|wayland>` | one-shot display posture |
| `--nixpkgs <ref>` | one-shot nixpkgs channel or revision |
| `--bind <path[:ro\|:rw]>` | one-shot host bind (read-only by default); repeatable |
| `--limit <key>=<value>` | one-shot cgroup limit: `memory_high` \| `memory_max` \| `tasks_max`; repeatable |
| `--package <name>=<backend:locator>` | one-shot package (e.g. `hello=nix:hello`); repeatable |
| `--proc <off\|observe\|enforce\|ask>` | one-shot process/exec posture (bare mode); `--config` sets the allow/deny lists |
| `--notify <off\|once\|always>` | one-shot refusal-notification mode for every event; `--config` sets the per-event table |
| `--forward <port\|host:cage[,…]>` | one-shot host loopback forward into the cage: a port (`1455`, an OAuth callback) or a `host:cage` remap (`9200:9119`); repeatable, folds onto the config by cage port |
| `--seccomp <token[,token…]>` | one-shot relaxation of the syscall denylist (e.g. `ptrace`, `clone:newuser`); repeatable |
| `--device <path>` | one-shot host device grant, one path per flag (e.g. `/dev/kvm`); repeatable |
| `--gpu[=true\|false]` | one-shot GPU posture (bare `--gpu` = true; `=false` disables) |
| `--audio[=true\|false]` | one-shot audio posture (bare `--audio` = true; `=false` disables) |
| `--dbus[=true\|false]` | one-shot in-cage desktop portal (bare `--dbus` = true) |
| `--` | end `sbx`'s own flags; everything after runs literally |

Every flag has an `SBX_*` environment equivalent. See
[One-shot overrides](../configuration/overrides) for the full precedence and merge
rules.

## Behavior

- The command (or shell) runs in the project sandbox with a
  [synthetic identity](../concepts/security-model); the host home and the rest of
  the host filesystem are absent (confidentiality by absence).
- The exit status is propagated (`sbx run -- sh -c 'exit 7'` exits 7).
- This is a Mode-A launch (an interactive/user context): egress rules stay all-verbs.
  For the locked-down agent posture, use [`sbx app`](app).

### No command: the project shell

With no command, `sbx run` opens the project shell:

- **On a terminal**, an interactive shell with **job control** (a controlling terminal
  is present; no "no job control" warning). If a project's mise toolchain is
  [activated](../configuration/tools), `mise activate` runs in the shell so activated
  tools are on `PATH`.
- **On a pipe** (non-terminal stdin), a non-interactive shell that reads its script from
  stdin (`echo 'ls' | sbx run`).

`sbx run --detach` with no command is refused: a detached shell has no terminal.

### Launch mode follows stdin

- A **real terminal** on stdin (and not `--detach`) runs under a private controlling
  terminal, so a shell or a TUI gets job control and live terminal-resize propagation.
- A **piped/non-tty** stdin, or `--detach`, keeps inherited stdio and propagates the
  exit status: the shape you want for scripts and CI.

### Observing a run (`--observe`)

`--observe` records what the command does inside the cage: so you see the agent work as it works.
It is read-only, host-side, and **unprivileged** (no `CAP_BPF`, no root), and it forces the
supervised launch path so a host-side observer can watch the cage for its lifetime. It stands up two
lenses, each read from another terminal:

- the **process feed**, every process the command spawns, via a `/proc` poll, read with
  [`sbx proc logs`](proc#logs);
- the **file-write feed**, every file it creates, writes, deletes, or moves in the project tree,
  via inotify: read with [`sbx fs logs`](fs#logs).

On a **non-interactive foreground run** the process events are *also* echoed inline to **stderr** as
`[sbx:exec]` lines (the file feed is never inline: it is far too chatty for a run's output).

- Scope: observation runs on any launch: a non-interactive run, an **interactive terminal**, or a
  **detached** (`--detach`) one. Only the inline stderr echo is limited, to a non-interactive
  foreground run under a non-enforcing `[proc]` mode: an interactive `[sbx:exec]` stream would fight
  a TUI for the screen, a detached session has no terminal at all, and an enforcing mode reads exec
  through the seccomp lens described below rather than the poll that feeds this echo. A launch that
  cannot show the echo says so rather than accepting the flag silently. In every other case watch
  the session from another
  terminal with [`sbx proc logs <id> -f`](proc#logs) / [`sbx fs logs <id> -f`](fs#logs), which, for a detached run, is the only way to see what it does.
- Honest limit: the process feed polls, so a process shorter than a tick (~300 ms) is missed; the
  file feed sees a completed write-and-close, and only in the project tree (not `/tmp`, the store,
  or the home).
- For **precise per-exec capture and blocking**, set [`[proc] mode = "enforce"`/`"ask"`](../configuration/proc)
  (a trusted-only security field): the process feed then comes from a seccomp user-notification
  supervisor that captures every exec exactly and can refuse a denied one before it runs. The
  `--observe` poll above costs nothing and needs no trust; `[proc]` is the one that can refuse.

```sh
sbx run --observe -- ./build.sh
# [sbx:exec] sh -c ./build.sh
# [sbx:exec] cc -c main.c
# [sbx:exec] ld -o app …
```

## Examples

```sh
sbx run                                # an interactive project shell
sbx run -- id                          # a synthetic identity
sbx run -- cargo test
echo 'rg --version' | sbx run          # a non-interactive shell reading stdin
sbx run --net none -- ./offline-build.sh
sbx run --net shared -- ./x.sh         # open everything: no proxy at all
sbx run --net allow -- ./x.sh          # open everything, still through the proxy
sbx run --bind /opt/data:rw -- ./process.sh
sbx run --observe -- ./build.sh        # stream a [sbx:exec] feed of what it spawns
sbx run --detach -- ./long-task.sh     # background; see `sbx session ls`
```
