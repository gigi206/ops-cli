# `ops stop`

```
ops stop <id>...|--all [--delay <secs>]
```

Stop running sessions. Sends `SIGTERM`, then `SIGKILL` after the grace delay, tearing
down the whole cage subtree. Either ids or `--all` is required, not both.

| Option | Meaning |
|---|---|
| `<id>...` | the PIDs [`ops ls`](ls.md) shows for the sessions to stop |
| `--all` | stop every live session (mutually exclusive with explicit ids) |
| `--delay <secs>` | seconds to wait after `SIGTERM` before `SIGKILL` (default 10; `0` = at once) |

`--all` targets every session, interactive shells included.

See also: [`ops ls`](ls.md) · [`ops attach`](attach.md) · [Sessions](../housekeeping/sessions.md).

## Examples

```sh
ops stop 12345
ops stop 12345 12377 --delay 3
ops stop --all
```
