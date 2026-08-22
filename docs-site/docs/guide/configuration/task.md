---
sidebar_label: "[task]"
description: "The field reference for a declared operation: every key of a `[task.<name>]` table."
---

# `[task]`: declared operations

A **declared operation** is a fixed command sbx runs *on a caller's behalf*, in an ephemeral sibling
cage, with a credential the caller never holds. This page is the field reference; the
[Declared operations](../tasks/) section is where the model, the bounds and the trade-offs are
explained.

```toml
[task.db-query]
description = "Read-only SQL against staging"
cmd     = ["psql", "-h", "db.staging.internal", "-c", "{sql}"]
params  = { sql = "^SELECT [A-Za-z0-9_,.*= ']{1,400}$" }
network = ["tcp://db.staging.internal:5432"]

[task.db-query.secret]
PGPASSWORD = "sops://secrets.enc.yaml#db.password"
```

Trusted-only, like `[binds]`/`[seccomp]`/`[devices]`: an untrusted project may neither declare a task
nor loosen one. Declarable in the global config, a project's `.sbx.toml`, an app profile
(`[app.<name>.task.<task>]`) and a bundle (`[bundle.<name>.task.<task>]`).

See also: [Declared operations](../tasks/) · [`sbx task`](../cli/task) · [`[secret]`](secret) ·
[Secrets](../secrets/).

## Fields

| Field | Meaning |
|---|---|
| `description` | one line, listed to the caller: this is the operation's documentation |
| `cmd` | the argv list; `{param}` substitutes **inside** one element, never into extra elements |
| `params` | the caller-supplied values, each [bounded](../tasks/parameters) |
| `env` | fixed environment for the command |
| `env_allow` | the variable **names** a caller may set for one invocation, names only, [values are not bounded](../tasks/parameters#caller-set-variables) |
| `stdout` / `stderr` | `"show"` (default) or `"hide"` |
| `timeout` | this task's wall-clock ceiling (`"20s"`), overriding `[task.defaults]` |
| `max_output` | this task's per-stream capture ceiling (`"64KiB"`), overriding `[task.defaults]` |
| `network` | the egress this task's cage gets, as allowlist entries (empty = no network); a [`tcp://` rule](../tasks/network) also gets a listener |
| `secret` | the credentials the command's environment carries, [by name](../tasks/credentials) |
| `inject` | the credentials [injected on the wire](../tasks/credentials#wire-injected-credentials-the-strongest-form), which never enter the cage |
| `packages` | the `mise:` tools the command needs (the [task tool pool](../tasks/execution#the-task-tool-pool)) |
| `spawn` | the programs the command may run [beside itself](../tasks/execution#what-the-command-may-run-spawn), absent means no supervision |
| `[exec.<program>]` | what one of those programs may run [in turn](../tasks/execution#what-each-program-may-run-in-turn-execprogram) |
| `output` | give the invocation a [writable directory](../tasks/output#producing-a-file-output) whose contents outlive it |
| `unmask` | the [`[fs] deny`](fs#opening-a-path-for-one-operation) paths **this** task may read, and it alone |

`allow` and `deny` are **not** task controls, and a declaration carrying either is refused
rather than ignored: they are `[proc]`'s key names, and a task's command is bounded by
something else entirely, its fixed `cmd`, its `params` patterns, `spawn` for what it may run
beside itself, and a cage with no network unless `network` declares one. Two spellings of one
control, each with a different unmatched default, is the outcome the refusal avoids.

## Section defaults

```toml
[task.defaults]
timeout    = "30s"     # built-in default
max_output = "64KiB"   # built-in default, per stream
nonce      = false     # unforgeable substitution placeholders, see Output
```

Declared as a `[task.defaults]` sub-table rather than bare keys beside the entries, so a setting can
never be swallowed by whichever task table happens to precede it in the file. A task can therefore
not be named `defaults`.

The per-session invocation quota (500) and the 512-invocation log ring behind
[`sbx task logs`](../cli/task#logs) are **fixed**, unlike the ceilings above: they are not
`[task.defaults]` knobs. See [the quota, and the honest residual](../tasks/#the-quota-and-the-honest-residual).

## Examples by shape

Six declarations, from the smallest to the most bounded. Each adds exactly one field
family, so the difference between them is the interesting part.

**No parameters, no network, no credential.** The floor: a fixed command, run on
request.

```toml
[task.fmt-check]
description = "Report formatting drift without writing"
cmd         = ["cargo", "fmt", "--check"]
spawn       = []              # a supervisor that permits nothing beyond the command
```

**A bounded parameter.** The caller supplies a value; the pattern is what makes it
safe, and it must match the whole value.

```toml
[task.gh-issue]
description = "List a repository's open issues"
cmd         = ["gh", "issue", "list", "--repo", "{repo}"]
params      = { repo = "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$" }
packages    = ["mise:aqua:cli/gh"]
network     = ["api.github.com"]
```

**A credential in the command's environment.** The value reaches the task cage, and
only it: the calling agent never holds it.

```toml
[task.db-query]
description = "Read-only SQL against staging"
cmd         = ["psql", "-h", "db.staging.internal", "-c", "{sql}"]
params      = { sql = "^SELECT [A-Za-z0-9_,.*= ']{1,400}$" }
network     = ["tcp://db.staging.internal:5432"]
timeout     = "20s"
spawn       = []

[task.db-query.secret]
PGPASSWORD = { from = "sops://secrets.enc.yaml#db.password", description = "staging DB password" }
```

**A credential that enters no cage at all.** Where the operation is an HTTP call,
`inject` is strictly stronger than `secret`: the task's own proxy adds the header on
the wire.

```toml
[task.gh-comment]
description = "Post a comment on an issue"
cmd         = ["curl", "-sS", "-XPOST", "-d", "{body}",
               "https://api.github.com/repos/demo-org/demo-app/issues/{n}/comments"]
params      = { n = "^[0-9]{1,7}$", body = "^.{1,2000}$" }
network     = ["api.github.com"]

[task.gh-comment.inject."api.github.com"]
from   = "sops://secrets.enc.yaml#github.token"
header = "Authorization"
type   = "bearer"
```

**A file to bring back.** `output = true` is the one writable path that outlives the
invocation; `{out}` is filled by sbx, never by the caller.

```toml
[task.dump]
description = "Dump the staging schema"
cmd         = ["pg_dump", "-h", "db.internal", "-f", "{out}/staging.sql", "appdb"]
network     = ["tcp://db.internal:5432"]
output      = true
max_output  = "8KiB"          # the command's chatter; the file is not capped by this
spawn       = []

[task.dump.secret]
PGPASSWORD = "sops://db.yaml#pg"
```

**A chain of programs, without a shortcut.** Each link needs its own section, because
inheritance would hand the command the shortcut the form exists to remove.

```toml
[task.release]
description = "Cut a release"
cmd         = ["make", "release"]
spawn       = ["git"]         # the command may run git, and nothing else
env_allow   = ["MAKEFLAGS"]   # the caller may set this one name; its value is unbounded

[task.release.exec.git]
spawn = ["ssh"]               # git may run ssh

[task.release.exec.ssh]
spawn = ["gpg"]               # ssh may run gpg
```

## Where each one can be declared

The same table works in four places, so an operation follows whatever it belongs to:

```toml
[task.fmt-check]              # a project .sbx.toml, or the global config
cmd = ["cargo", "fmt", "--check"]

[app.reviewer.task.fmt-check] # …only for that app's launches
cmd = ["cargo", "fmt", "--check"]

[bundle.rust.task.fmt-check]  # …for every app that names the bundle in `use`
cmd = ["cargo", "fmt", "--check"]
```

Then, from the host:

```sh
sbx task list                 # what this configuration declares
sbx task show db-query        # one operation in full, with where it was declared
sbx task secrets              # the credentials the plane would hand out
sbx task run gh-issue -p repo=demo-org/demo-app
```

## See also

- [Declared operations](../tasks/): what makes a task safe, and what it does not promise.
- [`sbx task`](../cli/task): list, invoke, and read the invocation log.
- [`sbx secret list`](../cli/secret): the credential inventory, by name.
- [`[secret]`](secret): the wire-injection broker for the session itself.
- [Secrets](../secrets/): the resolvers, the redaction, and the invariant behind all of it.
