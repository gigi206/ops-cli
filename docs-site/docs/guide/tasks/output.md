# What a task returns

An invocation returns an exit status, its captured streams, and, when the declaration
asks for one, a directory of artifacts. What crosses back is substituted first.

See also: [Declared operations](./) · [Parameters](parameters) · [Credentials](credentials) ·
[`sbx task result`](../cli/task#result).

## What substitution does and does not promise

Every credential value found in a returned stream, in an error message sbx composes, in a log line, or
in the paths an exec refusal names is replaced by **`${NAME}`**: the credential's own name, so the
output stays readable and says what was withheld. It covers the plaintext *and* each registered
encoding of it. Values shorter than the redaction floor are not substituted: such a needle would match
benign text and leak the value through the positions of its own placeholders. The floor is 8 bytes
unless a trusted layer set [`[redact] min_len`](../secrets/redaction#the-length-floor), and it is the
same one the egress tripwires use, so a value watched for on the wire is watched for here too. A
spelling left below the floor is named at launch: the command still receives the credential, and it
would otherwise look substituted without being.

The refusal paths are on that list because they are text the **command** composed rather than text it
printed: a program name is chosen by whoever calls `execve`, so a command that built one out of its
credential would otherwise hand the caller that spelling untouched. What is promised is about the
spelling, not about who wrote the command.

Two things to keep in mind:

- **It is hygiene, not a boundary.** It catches the dominant accident: a credential echoed into an
  error message (`psql: … password=hunter2`), and cannot catch a value the command itself
  transformed (hashed, encrypted, split).
- **`${NAME}` in the text is not proof.** The command can print that literal itself. The trustworthy
  signal is the substitution **count**, computed host-side and reported with the result (and in
  `sbx task logs`). The count returned to the caller covers **the streams the caller received**; a
  withheld stream's substitutions are recorded only in the log, which never crosses into a cage.
  Otherwise a declaration that hides its output would still hand back a number the command chooses
  by printing the credential as many times as it likes: a channel out of a cage whose streams were
  hidden to close one. The log holds the total, so hiding a stream is not a blind spot for you.

`nonce = true` makes each invocation's placeholders unforgeable: they read `${NAME@a91f3c}` where the
nonce is drawn per call and reported out of band, so the command could not have predicted it, and a
placeholder copied from an earlier result is detectably stale. Escaping the command's own `${…}` was
considered and rejected, it is imitable, and it would corrupt legitimate payloads (shell, CI YAML,
templates are full of `${…}`).

## Producing a file: `output`

A task cage keeps nothing. `$HOME` and `/tmp` are fresh tmpfs that die with the invocation, the
project is read-only, and the store is read-only: so a command that produces a file has nowhere to
leave it, and the only way out is `stdout` (capped at `max_output`).

`output = true` gives the invocation **one** writable directory whose contents survive it:

```toml
[task.dump]
cmd     = ["pg_dump", "-h", "db.internal", "-f", "{out}/staging.sql", "appdb"]
secret  = { PGPASSWORD = "sops://db.yaml#pg" }
network = ["tcp://db.internal:5432"]
spawn   = []
output  = true
```

`{out}` substitutes to that directory, and `$SBX_TASK_OUT` names it for a command that takes its
destination from the environment instead. **`{out}` is not a parameter**, sbx fills it, because a
caller who could choose where a credential-bearing command writes would choose the project. A
parameter named `out` is refused for the same reason, and `{out}` without `output = true` is refused
at load rather than substituting from nothing.

**The path is predictable, so the caller does not have to be told it.** Each task gets *its own*
directory, readable from the session's cage at:

```
/opt/sbx/task-out/<task>/
```

The invocation reports it anyway, with the size, so "it produced something" is visible at the point
of use:

```console
$ sbx task run dump
sbx: the operation wrote 41231872 byte(s) to /opt/sbx/task-out/dump
```

**Read-only for the agent, writable for the task.** The inverse of the intuition, and deliberate: an
agent that could write there would plant the input a credential-bearing command later reads back
(`psql -f {out}/script.sql`), taking back control of what the privileged operation does.

**It is emptied when the invocation claims it.** A predictable path is only honest if what sits there
is *this* invocation's work; otherwise a caller reads the previous artifact and cannot tell. If you
want to keep an artifact, copy it out. For the same reason, a second invocation of the same task is
**refused** while the first still holds the directory: two would interleave in one place.

**It is a real directory, never a tmpfs.** A tmpfs is RAM: a 300 MiB dump would be 300 MiB of memory,
and the cage's own cgroup would kill it. The directory lives under the project's runtime tree, so
`sbx gc` and `sbx projects rm` reclaim it with everything else that belongs to the project.

**This channel is not redacted.** Secret substitution covers `stdout` and `stderr`; a *file* the
command writes is not scanned. What bounds the risk is the choice of command by a trusted
declaration, `pg_dump` does not write its environment into its dump, but that is a property of the
program, not a guarantee sbx makes.
