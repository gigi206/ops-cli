# `sbx task`

```
sbx task list [<id>]
sbx task secrets [<id>]
sbx task run <name> [--param KEY=VALUE]... [--env KEY=VALUE]... [--session <id>]
sbx task logs [<id>]
```

Use the **declared operations** a session offers — fixed commands sbx runs on a caller's behalf, in
an ephemeral sibling cage, with a credential the caller never holds. Declared as
[`[task.<name>]`](../configuration/task.md).

These verbs work **both inside the cage** (where the agent uses them, through the socket sbx binds
there) **and on the host**, so an operation is testable exactly as the agent sees it. `logs` is
host-only.

See also: [`[task]`](../configuration/task.md) · [`sbx secret list`](secret.md) ·
[`sbx session`](session.md).

## `list`

```
sbx task list [<id>]
```

One line per operation: its name, its parameter names, whether each stream is shown or hidden, its
timeout, and its description.

```
$ sbx task list
db-query  params=sql  stdout=show  stderr=show  timeout=20s  Read-only SQL against staging
gh-issue  params=repo  stdout=show  stderr=show  timeout=30s  List a repository's issues
```

A `missing-tools=<token>,…` field appears when a task declares
[`packages`](../configuration/task.md#the-task-tool-pool) the pool does not hold — that task will
fail at exec, and the pool is filled best-effort, so this is where you find out before invoking it.

Inside the cage the session is implicit — a caller may only reach its own. On the host, name the
session's PID when more than one is offering operations.

## `secrets`

```
sbx task secrets [<id>]
```

The credentials the operations carry: the variable name, the operation it belongs to, the encoding it
is rendered with, and its description. **Never a value, and never a source locator** — what a caller
needs to know is which credentials an operation carries, not where they come from.

```
$ sbx task secrets
secret PGPASSWORD  task=db-query  encode=raw  staging database password
secret gh_token    task=gh-issue  wire-injected for api.github.com
```

A credential's name is what a substituted value is reported as (`${PGPASSWORD}`) if it ever reaches
the output, so keep names non-sensitive.

## `run`

```
sbx task run <name> [--param KEY=VALUE]... [--env KEY=VALUE]... [--session <id>]
```

Invoke one operation.

| Flag | Meaning |
|---|---|
| `-p`, `--param KEY=VALUE` | a declared parameter's value; repeatable |
| `-e`, `--env KEY=VALUE` | a variable the declaration's `env_allow` permits; repeatable |
| `--session <id>` | which session to run in (host-side, when several offer operations) |

```
$ sbx task run db-query --param sql="SELECT id FROM users"
id
1
2
```

**Exit codes.** The command's own exit code is returned, so an operation composes in a script like
the program it wraps. A **refusal** is exit **125** and runs nothing: an unknown operation, a value
outside its declared bound, a variable not in `env_allow`, or an exhausted session quota. 125 rather
than 2 so it stays distinguishable from the wrapped command exiting 2 itself — the same convention
`env` and `docker` use.

**Output.** stdout and stderr come back only if the declaration shows them, and every credential
value found in either is replaced by `${NAME}` first. sbx reports, on stderr, when the output was
truncated at `max_output`, when the timeout fired, and how many values were substituted — that count
is host-side, which is what makes it trustworthy (a `${NAME}` in the text could have been printed by
the command itself).

## `logs`

```
sbx task logs [<id>]
```

The session's invocation log — **host-only**, because the recorded party does not get to read the
record.

```
$ sbx task logs
event seq=1 at=1769812800 exit=0 redacted=1 truncated=0 timed_out=0 elapsed_ms=214 task=db-query
event seq=2 at=1769812815 exit=-1 redacted=0 truncated=0 timed_out=0 elapsed_ms=0 task=db-query refused=parameter `sql` does not match its declared pattern
```

| Field | Meaning |
|---|---|
| `seq` | a per-session sequence number, assigned host-side |
| `at` | Unix seconds when the invocation finished |
| `exit` | the command's exit code, or `-1` for a refusal |
| `redacted` | how many credential values were substituted out |
| `truncated` / `timed_out` | whether a ceiling fired |
| `elapsed_ms` | how long it took |
| `task` | the operation's name |
| `refused` | why it never ran (refusals are recorded too) |

Neither the command nor any parameter value is recorded: the command is fixed by the declaration, and
a value can carry a secret. The log is in-RAM, bounded (512 invocations, and it says how many older
ones fell out), and dies with the session.
