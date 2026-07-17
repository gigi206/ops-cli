# `sbx run`

```
sbx run [--detach] [override flags] [--] [command [args...]]
```

Run `<command>` inside the project sandbox and propagate its exit status — or, with no
command, open the project's sandboxed shell. A `--` separates `sbx`'s flags from the
command's, so `sbx run -- --detach` runs the literal `--detach`.

See also: [Quick start](../getting-started/quickstart.md) · [`sbx app`](app.md) · [One-shot overrides](../configuration/overrides.md) · [Sessions](../housekeeping/sessions.md).

## Options

| Option | Meaning |
|---|---|
| `--detach` | run in the background as a session [`sbx session`](session.md) can see |
| `--config <toml\|@file>` | one-shot config override (any field); repeatable, later wins |
| `--env KEY=VALUE` | one-shot override of a single cage environment variable; repeatable |
| `--net <posture>` | one-shot network posture: `none` \| `shared` \| `ask` \| `allow=h1,h2` \| `deny=h1,h2` |
| `--gui <none\|wayland>` | one-shot display posture |
| `--nixpkgs <ref>` | one-shot nixpkgs channel or revision |
| `--bind <path[:ro\|:rw]>` | one-shot host bind (read-only by default); repeatable |
| `--limit <key>=<value>` | one-shot cgroup limit: `memory_high` \| `memory_max` \| `tasks_max`; repeatable |
| `--package <name>=<backend:locator>` | one-shot package (e.g. `hello=nix:hello`); repeatable |
| `--` | end `sbx`'s own flags; everything after runs literally |

Every flag has an `SBX_*` environment equivalent. See
[One-shot overrides](../configuration/overrides.md) for the full precedence and merge
rules.

## Behavior

- The command (or shell) runs in the project sandbox with a
  [synthetic identity](../concepts/security-model.md); the host home and the rest of
  the host filesystem are absent (confidentiality by absence).
- The exit status is propagated (`sbx run -- sh -c 'exit 7'` exits 7).
- This is a Mode-A launch (an interactive/user context) — egress rules stay all-verbs.
  For the locked-down agent posture, use [`sbx app`](app.md).

### No command: the project shell

With no command, `sbx run` opens the project shell:

- **On a terminal**, an interactive shell with **job control** (a controlling terminal
  is present; no "no job control" warning). If a project's mise toolchain is
  [activated](../configuration/tools.md), `mise activate` runs in the shell so activated
  tools are on `PATH`.
- **On a pipe** (non-terminal stdin), a non-interactive shell that reads its script from
  stdin (`echo 'ls' | sbx run`).

`sbx run --detach` with no command is refused — a detached shell has no terminal.

### Launch mode follows stdin

- A **real terminal** on stdin (and not `--detach`) runs under a private controlling
  terminal, so a shell or a TUI gets job control and live terminal-resize propagation.
- A **piped/non-tty** stdin, or `--detach`, keeps inherited stdio and propagates the
  exit status — the shape you want for scripts and CI.

## Examples

```sh
sbx run                                # an interactive project shell
sbx run -- id                          # a synthetic identity
sbx run -- cargo test
echo 'rg --version' | sbx run          # a non-interactive shell reading stdin
sbx run --net none -- ./offline-build.sh
sbx run --bind /opt/data:rw -- ./process.sh
sbx run --detach -- ./long-task.sh     # background; see `sbx session ls`
```
