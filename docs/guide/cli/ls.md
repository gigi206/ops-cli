# `ops ls`

```
ops ls
```

List the live sandbox sessions from the on-disk registry (daemonless).

See also: [Sessions](../housekeeping/sessions.md) · [`ops attach`](attach.md) · [`ops stop`](stop.md).

## Behavior

Reading the registry **re-validates and prunes dead records**, so the list is always
current — a crashed or killed session self-heals rather than lingering. An app session
shows its app name, so you can tell which sessions are agents.

Sessions are created by [`ops run --detach`](run.md), [`ops app --detach`](app.md),
and interactive [`ops shell`](shell.md) / [`ops app`](app.md) launches. The registry is
liveness-validated by `(pid, start_time)` to defeat pid reuse. See
[Sessions](../housekeeping/sessions.md).

## Example

```sh
ops ls
# PID    APP           …
# 12345  claude-code   …
# 12377  (shell)       …
```

The `PID` column is the `<id>` used by [`ops attach <id>`](attach.md) and
[`ops stop <id>`](stop.md).
