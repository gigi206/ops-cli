# `sbx task`

```
sbx task list [<operation>] [--session <id>]
sbx task secrets [<operation>] [--session <id>]
sbx task run <operation> [--param KEY=VALUE]... [--env KEY=VALUE]... [--session <id>]
sbx task status [<invocation>|<operation>] [--session <id>]
sbx task stop <invocation>|<operation> [--session <id>]
sbx task logs [<invocation>|<operation>] [--session <id>]
```

Use the **declared operations** a session offers — fixed commands sbx runs on a caller's behalf, in
an ephemeral sibling cage, with a credential the caller never holds. Declared as
[`[task.<name>]`](../configuration/task.md).

`list`, `secrets` and `run` work **both inside the cage** (where the agent uses them, through the
socket sbx binds there) **and on the host**, so an operation is testable exactly as the agent sees
it. `status`, `stop` and `logs` are **host-only**, and by construction rather than by check: they
live on a second socket that is never bound into a cage. The record is not for the recorded party to
read, and an invocation id is per session — a cage able to stop one could stop the invocation *you*
started, and same-uid leaves no way to tell the two callers apart.

## How an agent finds them

A declared operation the agent never learns about is worth exactly as much as one you never
declared. So when a session offers any, they are written into the contract the cage already reads —
`/opt/sbx/egress-contract.md`, named by `$SBX_EGRESS_CONTRACT` — beside the network posture:

```markdown
## Declared operations

This sandbox offers fixed operations that sbx runs on your behalf, in a separate cage, with
credentials this process never holds and cannot read. Invoke one with:

    sbx task run <name> --param KEY=VALUE

Prefer them over reaching for the underlying tool: the tool is usually absent here, and the
credential is attached host-side, so an operation succeeds where a direct attempt cannot.

- `db-query` — Read-only SQL against staging
    parameter `sql`: matching `^SELECT [a-z, ]+$`, required
    credentials: PGPASSWORD
```

It is the same file rather than a second one on purpose: another file would only be read by a
process that already knew to look for it, which is the problem being solved.

This discloses nothing new. Every line of it is what [`list`](#list) and [`secrets`](#secrets)
already answer to anyone in the cage — names, descriptions, parameter bounds, and the **names** of
the credentials an operation carries. Never a value, and never a source locator: a `sops://` path
would be a disclosure the socket itself refuses to make.

The listing is written at launch; `sbx task list` stays the live view (it is where a
`missing-tools=` warning appears, since the tool pool is filled after the file is written).

## What the cage actually holds

Inside the sandbox `sbx` is **not the sbx binary** — it is a small generated client that speaks the
task plane's protocol and understands nothing else. `sbx task list`, `secrets` and `run` read
exactly as they do here; every other word is refused:

```sh
$ sbx config show          # inside the cage
sbx: only the task plane is exposed inside the sandbox — try `sbx task list`
```

This is deliberate. The socket has to cross into the cage — an agent that cannot reach it cannot
invoke an operation at all — but nothing else needs to. A binary able to act on sbx's own state
would have been safe only for as long as none of sbx's state happened to be mounted, which is a
property nothing could check. A client that cannot express the request is a property you can read.

The client is written fresh for each session, so it always matches the plane it talks to. It is
bound read-only, and it disappears with the session.

See also: [`[task]`](../configuration/task.md) · [`sbx secret list`](secret.md) ·
[`sbx session`](session.md).

## `list`

```
sbx task list [<operation>] [--session <id>]
```

One row per operation. The line above the table says which session answered and what project it runs
in — with two sessions open, the rows alone cannot tell you.

```
$ sbx task list
session 318106 — /home/you/work/api
NAME      PARAMS  TIMEOUT  DESCRIPTION
db-query  sql         20s  Read-only SQL against staging
gh-issue  repo        30s  List a repository's issues
```

**A column appears only when some operation makes it worth showing.** Above, every operation shows
both streams and none writes a file, so those columns are absent; below, one operation hides its
stderr and another declares an output directory, and they come back for every row:

```
$ sbx task list
session 318106 — /home/you/work/api
NAME       PARAMS  TIMEOUT  STDOUT  STDERR  OUTPUT  DESCRIPTION
db-query   sql         20s  show    show    -       Read-only SQL against staging
nightly    -           1h   show    hide    yes     Dump the reporting tables
sbx: note: an operation marked OUTPUT writes into /opt/sbx/task-out/<operation>
```

A column that reads the same on every line is not information — it is the noise that makes a listing
unreadable. `MISSING TOOLS` appears when an operation declares
[`packages`](../configuration/task.md#the-task-tool-pool) the pool does not hold: that operation will
fail at exec, and the pool is filled best-effort, so this is where you find out before invoking it.

Name an operation to show only that one. Inside the cage the session is implicit — a caller may only
reach its own; on the host, `--session` names it when more than one is offering operations.

## `secrets`

```
sbx task secrets [<operation>] [--session <id>]
```

The credentials the operations carry: the variable name, the operation it belongs to, the encoding it
is rendered with, and its description. **Never a value, and never a source locator** — what a caller
needs to know is which credentials an operation carries, not where they come from.

```
$ sbx task secrets
session 318106 — /home/you/work/api
NAME        OPERATION  DELIVERY               DESCRIPTION
PGPASSWORD  db-query   env (raw)              staging database password
gh_token    gh-issue   wire -> api.github.com
```

`DELIVERY` is the field to read: `env (…)` means the command's own environment carries the value,
while `wire -> <host>` means sbx attaches it to the request and the command never holds it at all.

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
truncated at `max_output`, when the timeout fired, when [`stop`](#stop) ended it, and how many values
were substituted — that count is host-side, which is what makes it trustworthy (a `${NAME}` in the
text could have been printed by the command itself).

## `status`

```
sbx task status [<invocation>|<operation>] [--session <id>]
```

What the session is running **right now** — host-only.

```
$ sbx task status
session 318106 — /home/you/work/api
ID  OPERATION      ELAPSED      PID  STATE
 7  nightly-dump     42.3s   318204  running
```

| Column | Meaning |
|---|---|
| `ID` | the **invocation id** — what `stop` takes, and what its log line will carry |
| `OPERATION` | which operation it is |
| `ELAPSED` | how long it has been running |
| `PID` | the cage's process, for `ps` and `systemd-cgls` |
| `STATE` | `running`, or `stopping` once it has been asked to stop |

Narrow it with an invocation id or an operation name. A caller blocked on its own `sbx task run`
cannot see this — it is waiting for the answer. This is the view from another terminal, which is also
the only place a stop can come from.

**The three verbs share one number.** The id `status` shows is the id `stop` takes, the id `logs`
carries once the invocation is over, and the id a stopped `run` names in its report — so `sbx task
status 7` while it runs and `sbx task logs 7` afterwards are the same invocation.

## `stop`

```
sbx task stop <invocation|operation> [--session <id>]
```

End one running invocation — named by the id `status` shows, or by the operation's own name when
only one of its invocations is running. A number is read as an id first, and a name matching several
running invocations is an error listing them rather than a guess at which to end.

```
$ sbx task stop 7
stopped invocation 7
```

The cage is torn down, so nothing the operation started outlives it. The caller gets its result with
whatever the command produced up to that point, marked **stopped** — which stays distinct from the
`timed_out` that ends an invocation the same way: one is the declaration's ceiling firing, the other
is you deciding.

**Stopping is not instant, and the answer says which happened.** A request that lands while the
invocation is still resolving a credential or standing up its proxy is honored once that step
returns:

| Answer | Meaning | Exit |
|---|---|---|
| `stopped invocation <id>` | it ended | 0 |
| `<id> was asked to stop and is still finishing` | accepted, not yet done | 1 |
| `invocation <id> had already finished` | too late, and nothing to do | 0 |
| `no invocation <id>` | this session never issued that id | 1 |

An artifact in an [`output = true`](../configuration/task.md#producing-a-file-output) directory stays
as the stopped command left it: partial, and only the next invocation clears it.

## `logs`

```
sbx task logs [<invocation>|<operation>] [--session <id>]
```

The session's invocation log — **host-only**, because the recorded party does not get to read the
record.

```
$ sbx task logs
session 318106 — /home/you/work/api
ID  TIME      OPERATION  EXIT   TOOK  NOTE
 1  17:00:00  db-query      0  214ms  1 credential value(s) substituted
 2  17:00:15  db-query      -    0ms  refused: parameter `sql` does not match its declared pattern
 3  17:04:49  nightly       -   3.0s  stopped
```

| Column | Meaning |
|---|---|
| `ID` | the **invocation id** — the one `sbx task status` showed while it ran |
| `TIME` | local time of day when the invocation finished |
| `OPERATION` | the operation's name |
| `EXIT` | the command's exit code, or `-` when nothing ran |
| `TOOK` | how long it took |
| `NOTE` | the refusal reason, or what happened to it: stopped, timed out, output truncated, credential values substituted |

The id is drawn when an invocation **starts** and its line is written when it **ends**, so two
overlapping invocations appear in the order they finished and their ids can read out of order. A
blank id marks a request refused before it was admitted at all — the session's quota was exhausted,
so no invocation exists for an id to name.

Name an operation to see only its invocations, or an invocation id to see just that one.

Neither the command nor any parameter value is recorded: the command is fixed by the declaration, and
a value can carry a secret. The log is in-RAM, bounded (512 invocations, and it says how many older
ones fell out), and dies with the session.
