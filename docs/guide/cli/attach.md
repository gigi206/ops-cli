# `ops attach`

```
ops attach <id>
```

Open a shell in a running session's environment. For an app session, that is the app's
isolated environment (its own home, packages, and posture).

| Operand | Meaning |
|---|---|
| `<id>` | the PID [`ops ls`](ls.md) shows for the session |

See also: [`ops ls`](ls.md) · [`ops stop`](stop.md) · [Sessions](../housekeeping/sessions.md).

## Example

```sh
ops ls                 # find the id
ops attach 12345       # open a shell in that session's environment
```

`attach` reproduces the session's environment (for an app, its isolated home via the
session runtime), so you can inspect or interact with what a detached agent is doing.
