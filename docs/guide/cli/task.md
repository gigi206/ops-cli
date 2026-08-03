# `sbx task`

```
sbx task list [<operation>] [--session <id>]
sbx task secrets [<operation>] [--session <id>]
sbx task run <operation> [--param KEY=VALUE]... [--env KEY=VALUE]... [--detach] [--session <id>]
sbx task result <invocation> [--session <id>]
sbx task status [<invocation>|<operation>] [--session <id>]
sbx task show <invocation>|<operation> [--session <id>]
sbx task stop <invocation>|<operation> [--session <id>]
sbx task logs [<invocation>|<operation>] [--session <id>]
```

Use the **declared operations** a session offers: fixed commands sbx runs on a caller's behalf, in
an ephemeral sibling cage, with a credential the caller never holds. Declared as
[`[task.<name>]`](../configuration/task.md). `sbx tasks` is an alias.

`list`, `secrets` and `run` work **both inside the cage** (where the agent uses them, through the
socket sbx binds there) **and on the host**, so an operation is testable exactly as the agent sees
it. `status`, `stop`, `result`, `logs` and `run --detach` are **host-only**, and by construction
rather than by check: they live on a second socket that is never bound into a cage. The record is not
for the recorded party to read, and an invocation id is per session: a cage able to stop one could
stop the invocation *you* started, and same-uid leaves no way to tell the two callers apart. Starting
a detached invocation is on that socket for the same reason: it is only reachable through those
verbs, so a caller that could start one without being able to watch or end it would be creating
invocations nobody owns.

## How an agent finds them

A declared operation the agent never learns about is worth exactly as much as one you never
declared. So when a session offers any, they are written into the contract the cage already reads, `/opt/sbx/egress-contract.md`, named by `$SBX_EGRESS_CONTRACT`: beside the network posture:

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
already answer to anyone in the cage: names, descriptions, parameter bounds, and the **names** of
the credentials an operation carries. Never a value, and never a source locator: a `sops://` path
would be a disclosure the socket itself refuses to make.

The listing is written at launch; `sbx task list` stays the live view (it is where a
`missing-tools=` warning appears, since the tool pool is filled after the file is written).

## What the cage actually holds

Inside the sandbox `sbx` is **not the sbx binary**: it is a small generated client that speaks the
task plane's protocol and understands nothing else. `sbx task list`, `secrets` and `run` read
exactly as they do here; every other word is refused:

```sh
$ sbx config show          # inside the cage
sbx: only the task plane is exposed inside the sandbox — try `sbx task list`
```

This is deliberate. The socket has to cross into the cage: an agent that cannot reach it cannot
invoke an operation at all, but nothing else needs to. A binary able to act on sbx's own state
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
in: with two sessions open, the rows alone cannot tell you.

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

A `RUNNING` column joins them while something is running, holding **how many** invocations of that
operation are live, several at once is ordinary, and [`status`](#status) shows them individually.
It is host-side only: a cage cannot reach the socket that knows.

A column that reads the same on every line is not information: it is the noise that makes a listing
unreadable. `MISSING TOOLS` appears when an operation declares
[`packages`](../configuration/task.md#the-task-tool-pool) the pool does not hold: that operation will
fail at exec, and the pool is filled best-effort, so this is where you find out before invoking it.

**`DECLARED IN` says which config holds each operation's `[task.<name>]` block**, and appears by the
same rule, only when they do not all agree. One session can be offered operations by four different
places at once: your global `sbx.toml`, the project's `.sbx.toml`, the app profile you launched, and
each [bundle](../configuration/bundles.md) that profile names in `use`. The name alone does not say
which, and the answer is where you go to change it:

```
$ sbx task ls
session 318106 — /home/you/work/api
NAME       PARAMS  TIMEOUT  DECLARED IN  DESCRIPTION
db-query   sql         20s  project      Read-only SQL against staging
gh-issue   repo        30s  bundle:gh    List a repository's issues
deploy     env         5m   app:agent    Roll the staging deployment
```

The values are `global`, `project`, `app:<name>` and `bundle:<name>`: the `kind:name` spelling
[`sbx session ls`](session.md) already uses in its `KIND` column. A bundle keeps its own name even
though its entries fold into the app that names them: "which app" and "which tool the app pulled
it in with" are different answers, and the second is the one that tells you which file to open.
[`show`](#show) gives it whether or not the column is there.

This does **not** duplicate [`sbx session ls`](session.md), which names the app and the project but
no bundle. The two never overlap: the rows disagree exactly when more than one source contributed,
which is exactly when knowing the session's app and project cannot tell you which of them declared a
given operation. Where one source explains everything, the column is not shown.

It claims where the *block* is, and nothing more. An operation is genuinely composed of two layers, its own block, plus whatever [`[task.defaults]`](../configuration/task.md) it inherits: and those
can be different files. [`show`](#show) is where that is spelled out.

**With several sessions, all of them are listed** and a `SESSION` column says which row came from
which:

```
$ sbx task ls
session 4081336 — /home/you/work/api
session 4170408 — /home/you/work/web
SESSION  NAME        PARAMS  TIMEOUT  RUNNING  DESCRIPTION
4081336  db-query    sql         20s        -  Read-only SQL against staging
4081336  slow-count  -          120s        2  counts for a minute
4170408  build       -           30s        -  another project's operation
```

`--session <id>` narrows it to one. Reading across sessions is harmless, which is why it is the
default here, [`run`](#run) and [`stop`](#stop) still make you name one, because guessing which
session to *run* in would use the wrong credential.

Name an operation to show only that one. Inside the cage the session is implicit: a caller may only
reach its own.

## `secrets`

```
sbx task secrets [<operation>] [--session <id>]
```

The credentials the operations carry: the variable name, the operation it belongs to, the encoding it
is rendered with, and its description. **Never a value, and never a source locator**: what a caller
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
sbx task run <name> [--param KEY=VALUE]... [--env KEY=VALUE]... [--detach] [--session <id>] [--json]
```

Invoke one operation.

| Flag | Meaning |
|---|---|
| `-p`, `--param KEY=VALUE` | a declared parameter's value; repeatable |
| `-e`, `--env KEY=VALUE` | a variable the declaration's `env_allow` permits; repeatable |
| `--detach` | start it and print its invocation id instead of waiting (host-side only) |
| `--session <id>` | which session to run in (host-side, when several offer operations) |
| `--json` | print the whole result as one JSON document on stdout, streams included |

```
$ sbx task run db-query --param sql="SELECT id FROM users"
id
1
2
```

**Exit codes.** The command's own exit code is returned, so an operation composes in a script like
the program it wraps. A **refusal** is exit **125** and runs nothing: an unknown operation, a value
outside its declared bound, a variable not in `env_allow`, or an exhausted session quota. 125 rather
than 2 so it stays distinguishable from the wrapped command exiting 2 itself: the same convention
`env` and the like.

**Output.** stdout and stderr come back only if the declaration shows them, and every credential
value found in either is replaced by `${NAME}` first. sbx reports, on stderr, when the output was
truncated at `max_output`, when the timeout fired, when [`stop`](#stop) ended it, and how many values
were substituted, that count is host-side, which is what makes it trustworthy (a `${NAME}` in the
text could have been printed by the command itself).

**`--json`.** One document on stdout and nothing else: the streams travel *inside* it, so a command
that writes to stdout cannot interleave with it, and everything sbx says as prose otherwise becomes a
field:

```
$ sbx task run db-query --param sql="SELECT id FROM users" --json
{
  "task": "db-query",
  "id": 7,
  "exit": 0,
  "stdout": "id\n1\n2\n",
  "stderr": "",
  "timed_out": false,
  "stopped": false,
  "truncated": false,
  "elapsed_ms": 412,
  "redacted": 0,
  "nonce": null,
  "refused": [],
  "output": null,
  "error": null
}
```

A stream the declaration **withholds** is `null`; one that ran and printed nothing is `""`. `redacted`
is the substitution count **over the streams you received**: a withheld stream's substitutions are
recorded in `sbx task logs` and are not reported here, because a count over output that was never
handed over is a number the command could choose and you could read. `refused` lists what
[`spawn`](../configuration/task.md) blocked: its paths
are substituted exactly as the output is, so a credential a command spelled into a program name comes
back named rather than in the clear: and `output` is
`{"path": …, "bytes": …}` when the operation declares one. A refusal is a document too: `error` says
why and `exit` is `null`, because nothing ran; the exit code is still 125. `id` is `null` only when
the plane declined before admitting the request (an exhausted quota), where no invocation exists to
name.

Inside a cage the client stays as it is: it prints the same raw fields it always has, one per line.
An agent parses that; a person reads this.

### `--detach`

Start the operation and get its invocation id back instead of its result. The id is the whole of
stdout, so it assigns directly:

```
$ id=$(sbx task run nightly-dump --detach)
invocation 7 is running detached — `sbx task status` watches it, `sbx task result 7` collects what it produced
$ sbx task result "$id"
wrote 41822 rows
```

Everything you could act on is still decided **before** the id comes back: an unknown operation, a
value outside its bound, a variable not in `env_allow`, or an [output directory](../configuration/task.md)
another invocation of the same operation is already using. So an id means it is running. What can
only fail once it is under way, a credential that will not resolve, a proxy that will not start: is held and reported by [`result`](#result), not lost.

**Host-side only.** A detached invocation is watched with `status`, ended with `stop`, and collected
with `result`, and all three are host-only. A cage that could start one would be creating invocations
it can neither see nor end, and could hold several at once, which having to wait for each is exactly
what prevents.

**At most four run at once.** Separate from the session's call quota, which bounds how many
invocations are ever *started*, not how many run *together*: each live one holds a cage, a proxy and
a scope of its own. An attached invocation needs no such cap, because its caller waiting for it is
already a limit of one.

**It dies with its session.** The plane that runs a detached invocation is part of the session
process, so closing the session ends it. Detaching frees the *terminal*, not the session.

With `--json` the start is its own small document: nothing has run yet, so there is no exit code to
report:

```
$ sbx task run nightly-dump --detach --json
{
  "task": "nightly-dump",
  "id": 7,
  "detached": true,
  "error": null
}
```

## `result`

```
sbx task result <invocation> [--session <id>] [--json]
```

What a detached invocation produced: host-only.

The output is **identical** to what a foreground `run` would have printed, down to the exit code:
detaching changes when a result arrives, not what it is. The streams are already substituted and
truncated exactly as they would have been, and `--json` prints the same document as `run --json`.

It takes an **invocation id**, never an operation name: a result belongs to one run, and a name
would name several.

Reading a result does not consume it: a session holds the last **32**, so collecting one twice is
fine, and older ones are dropped to make room once past that. Four answers are kept apart, because
they call for different things:

| Answer | What it means |
|---|---|
| the result | it finished, and this is what it produced |
| `invocation 7 is still running` | give it time; [`status`](#status) is watching it |
| `its result is no longer held` | it finished, but 32 newer ones have since replaced it |
| `no invocation 7` | this session has never seen that id |

An invocation that ran in the **foreground** is named as such: its result went to the caller that
waited for it, and was never kept here.

## `status`

```
sbx task status [<invocation>|<operation>] [--session <id>]
```

What the session is running **right now**: host-only.

```
$ sbx task status
session 318106 — /home/you/work/api
ID  OPERATION      ELAPSED      PID  STATE
 7  nightly-dump     42.3s   318204  detached
```

| Column | Meaning |
|---|---|
| `ID` | the **invocation id**: what `stop` takes, and what its log line will carry |
| `OPERATION` | which operation it is |
| `ELAPSED` | how long it has been running |
| `PID` | the cage's process, for `ps` and `systemd-cgls` |
| `STATE` | `running`, `detached` when nobody is waiting for it, or `stopping` once it has been asked to stop |

Every session offering operations is shown, with a `SESSION` column when there is more than one.
Narrow it with an invocation id, an operation name, or `--session`. A caller blocked on its own
`sbx task run` cannot see this, it is waiting for the answer. This is the view from another terminal, which is also
the only place a stop can come from, and where a [detached](#--detach) invocation is watched from
start to finish.

**The verbs share one number.** The id `status` shows is the id `stop` takes, the id `result`
collects a detached one by, the id `logs` carries once the invocation is over, and the id a stopped
`run` names in its report, so `sbx task status 7` while it runs and `sbx task logs 7` afterwards are
the same invocation.

## `show`

```
sbx task show <invocation>|<operation> [--session <id>]
```

Everything about **one** of them, host-only. The listings answer "what is there" a line at a time;
this answers "what is *that*".

```
$ sbx task show 7
session 4081336 — /home/you/work/api
id           7
operation    nightly-dump
state        running
elapsed_ms   42310
pid          318204
command      /nix/store/…/pg_dump --schema-only reporting
description  Dump the reporting tables
declared     /nix/store/…/pg_dump --schema-only {schema}
declared in  project
parameters   schema
timeout      1h
max_output   65536  (sbx default)
stdout       show
stderr       hide
credentials  PGPASSWORD
network      tcp://db.staging.internal:5432
output       /opt/sbx/task-out/nightly-dump
```

For an invocation that is over it reports what the log kept, how it ended, when, what it cost, and
then the same declaration, because an invocation *is* its declaration plus what one run of it did.
Naming an operation rather than an id gives the declaration alone.

A [detached](#--detach) invocation reads as `state detached` while it runs, and once it is over its
state is how it *ended* (`finished`, `stopped`, `timed out`) with a separate `detached yes` line, detaching is orthogonal to how an invocation ends, and that line is what says its result went to
[`result`](#result) rather than to a caller.

**`declared in` is always here**, unlike the [listing's column](#list) which appears only when the
rows disagree: a reader asking about *one* operation is often asking exactly that.

**A value the operation did not set itself says where it came from**, in parentheses beside it. An
operation is composed of its own `[task.<name>]` block plus whatever
[`[task.defaults]`](../configuration/task.md) it inherits, and those can live in different files, `declared in project` with a ceiling from your global `sbx.toml` is an ordinary situation, and being
told only the block would send you to edit a file that does not contain the value you are reading:

```
declared in  project
timeout      1m30s  (global [task.defaults])
max_output   65536  (sbx default)
```

Nothing in parentheses means the operation's own block set it: the case a reader already assumes.

**Never an environment value.** A task's credentials are resolved for one invocation and held nowhere
this can reach, so their absence is structural rather than a filter that could be forgotten; what is
shown is their names, which is what a substituted value is reported as anyway. The `command` line is
the task's own, with this invocation's parameters substituted in: a credential never travels there.

A field with nothing to say is left out rather than printed blank.

## `stop`

```
sbx task stop <invocation|operation> [--session <id>]
```

End one running invocation, named by the id `status` shows, or by the operation's own name when
only one of its invocations is running. A number is read as an id first, and a name matching several
running invocations is an error listing them rather than a guess at which to end.

```
$ sbx task stop 7
stopped invocation 7
```

The cage is torn down, so nothing the operation started outlives it. The caller gets its result with
whatever the command produced up to that point, marked **stopped**: which stays distinct from the
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

The session's invocation log, **host-only**, because the recorded party does not get to read the
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
| `ID` | the **invocation id**: the one `sbx task status` showed while it ran |
| `TIME` | local time of day when the invocation finished |
| `OPERATION` | the operation's name |
| `EXIT` | the command's exit code, or `-` when nothing ran |
| `TOOK` | how long it took |
| `NOTE` | the refusal reason, or what happened to it: detached, stopped, timed out, output truncated, credential values substituted |

The id is drawn when an invocation **starts** and its line is written when it **ends**, so two
overlapping invocations appear in the order they finished and their ids can read out of order. A
blank id marks a request refused before it was admitted at all: the session's quota was exhausted,
so no invocation exists for an id to name.

Name an operation to see only its invocations, or an invocation id to see just that one.

Neither the command nor any parameter value is recorded: the command is fixed by the declaration, and
a value can carry a secret. The log is in-RAM, bounded (512 invocations, and it says how many older
ones fell out), and dies with the session.
