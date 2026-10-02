---
description: "What each exit status means, and which of them a script may branch on."
---

# Exit codes

`sbx` follows conventional Unix exit-code semantics.

See also: [`sbx run`](../cli/run) · [One-shot overrides](../configuration/overrides) · [Command reference](../cli/).

## The conventions

| Code | Meaning |
|---|---|
| `0` | success |
| `1` | a runtime failure, an operation that ran but did not succeed (e.g. `sbx config get` on an unset key, a store/network operation that failed) |
| `2` | a **usage or fail-closed** error, a bad argument, a missing operand, a name that names nothing (an app, a plugin, a store, a bundle, an egress group, a project tree, a session, a declared operation, a task invocation), or a rejected [one-shot override](../configuration/overrides) value |
| `125` | nothing was run, deliberately: [`sbx task run`](../cli/task#run) refused the invocation, or [`sbx session attach`](../cli/session#attach) could not re-apply the cage's confinement |
| `126` | [`sbx session attach`](../cli/session#attach) could not join the running cage, or could not reap the shell it started |
| `127` | [`sbx session attach`](../cli/session#attach) reached the cage but could not start the shell in it |
| `128 + N` | the launched or attached command was terminated by signal `N` |
| *other* | for a launch verb, the **launched command's** own exit status |

## A name that names nothing exits 2

A verb handed the name of an app, a plugin, a plugin store, a bundle, an egress group, a
project tree, a session, a declared operation or a task invocation that does not exist refuses
it as a usage error and exits 2: `sbx app show nope`, `sbx config show --app nope`, `sbx plugins
info nope` and `sbx bundle rm nope` exit 2 like `sbx net groups nope`, `sbx session stop 999999`
and `sbx task stop nope`. A script can tell a mistyped name from a run that failed by the code
alone. A batch that names several things keeps the stronger answer: when one name is unknown and
another one's removal fails, it exits 1.

Some answers about a name stay at 1, because they are about what is there rather than about
a typo. `sbx app rm <name> --purge` exits 1 when nothing came off disk, which covers a name
with nothing under it and an app whose live session refused the purge alike. `sbx plugins
info <name>` exits 1 when several installed plugins claim the name. `sbx task stop <operation>`
exits 1 when the operation is declared and not running, and every `sbx task` verb exits 1 when no
session offers operations at all. [`sbx task run`](../cli/task#run) and `sbx task result` are
the exception the other way: they answer an unknown operation or invocation with 125, the code
every refusal of theirs gets, because 2 is a code the command they wrap can return itself.

An `--app` that filters live sessions is not a name to look up. `sbx net pending`, `sbx net
logs`, `sbx net stats`, `sbx proc rules` and `sbx net rules --source session` show what the
sessions of that app hold, so an app with none running, whatever its name, is an empty answer at
0, and `sbx net live --json` streams empty snapshots for it until it is stopped. Where `--app`
reads the config instead, as `sbx net rules` and `sbx config show` do, it names a declared app,
and one that is not declared exits 2.

## Launch verbs propagate the command's status

[`sbx run`](../cli/run) and [`sbx app`](../cli/app)
propagate the status of the program they launched:

```sh
sbx run -- sh -c 'exit 7'   # sbx exits 7
sbx run -- true             # sbx exits 0
sbx run -- false            # sbx exits 1
```

So a non-zero exit from a launch verb is the tool's result, not an `sbx` error: unless
it is `2` from an argument/override problem `sbx` caught before launching.

## Fail-closed overrides exit 2

A [one-shot override](../configuration/overrides) with a **set-but-invalid** security
value (a `--net nonee` typo, a bad `[limits]` value, a bad `nixpkgs`) or a **structural**
error (a `--limit` with no `=`, a `--bind` with an empty path) is a **hard error, exit 2,
no launch**, because silently keeping the baseline could leave a wider posture than the
mistyped intent. See [One-shot overrides](../configuration/overrides#fail-closed-on-an-invalid-value).

The code does not depend on what the host has installed. `sbx` reads and validates the
project's configuration, and resolves which app a launch names, *before* it looks for
bubblewrap or nix. A mistyped override therefore exits 2 on a machine with no sandbox
engine exactly as it does on a capable one, and an undeclared app is reported as
undeclared rather than as a missing engine. The engine's own "not found" message is a
different failure and comes after: it is reported once there is nothing left in the
request itself to refuse.

## A refused operation exits 125

[`sbx task run`](../cli/task#run) exits **125** when it refuses the invocation and runs
nothing: an unknown operation, a value outside its declared bound, a variable not in
`env_allow`, or an exhausted session quota. 125 rather than 2, so a refusal stays
distinguishable from the wrapped command exiting 2 on its own.

## `sbx session attach` has three failures of its own

[`attach`](../cli/session#attach) joins a live cage and runs a shell inside it, so its
status is the shell's whenever there is a shell to have one: it propagates the exit
status like a launch verb, and reports `128 + N` for a shell a signal ended. Three codes
are the join itself failing, and they are distinguishable because what to do about each
differs:

| Code | What failed | What it usually means |
|---|---|---|
| `125` | the cage's confinement could not be re-applied to the joining shell | the kernel refused the seccomp filters; nothing was started, deliberately, since a shell inside the cage that is not confined like the cage would be a wider hole than the agent |
| `126` | the namespaces could not be joined, or the shell could not be reaped | the session ended between `sbx session ls` and the join, or the host refused the `setns` |
| `127` | the join worked, the shell did not start | the cage has no such program: its `/bin/bash` is absent, or the command passed after `--` is not in the cage's `PATH` |

## `sbx doctor` fails hard on a missing prerequisite

[`sbx doctor`](../cli/doctor) exits non-zero when a load-bearing requirement
(capability-bearing user namespaces, the engines) is absent: it never reports success on
a host where a launch could not be secured. See
[prerequisites](../getting-started/doctor).
