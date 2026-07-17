# `sbx run`

```
sbx run [--detach] [override flags] [--] <command> [args...]
```

Run `<command>` inside the project sandbox and propagate its exit status. A `--`
separates `sbx`'s flags from the command's, so `sbx run -- --detach` runs the literal
`--detach`.

See also: [Quick start](../getting-started/quickstart.md) · [`sbx shell`](shell.md) · [One-shot overrides](../configuration/overrides.md) · [Sessions](../housekeeping/sessions.md).

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

- The command runs in the project sandbox with a [synthetic identity](../concepts/security-model.md);
  the host home and the rest of the host filesystem are absent.
- The exit status is propagated (`sbx run -- sh -c 'exit 7'` exits 7).
- This is a Mode-A launch (an interactive/user context) — egress rules stay all-verbs.
  For the locked-down agent posture, use [`sbx app`](app.md).

## Examples

```sh
sbx run -- id                          # a synthetic identity
sbx run -- cargo test
sbx run --net none -- ./offline-build.sh
sbx run --bind /opt/data:rw -- ./process.sh
sbx run --detach -- ./long-task.sh     # background; see `sbx session ls`
```
