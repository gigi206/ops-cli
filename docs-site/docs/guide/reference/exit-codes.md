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
| `1` | a runtime failure, an operation that ran but did not succeed (e.g. `sbx config get` on an unset key, a store/network operation that failed, an answer that could not be written to standard output) |
| `2` | a **usage or fail-closed** error, a bad argument, a missing operand, a name that names nothing (an app, a plugin, a store, a bundle, an egress group, a project tree, a session, a declared operation, a task invocation), or a rejected [one-shot override](../configuration/overrides) value |
| `125` | nothing was run, deliberately: [`sbx task run`](../cli/task#run) refused the invocation, or [`sbx session attach`](../cli/session#attach) could not re-apply the cage's confinement |
| `126` | [`sbx session attach`](../cli/session#attach) could not join the running cage, or could not reap the shell it started |
| `127` | [`sbx session attach`](../cli/session#attach) reached the cage but could not start the shell in it |
| `128 + N` | the launched or attached command was terminated by signal `N` |
| *other* | for a launch verb, the **launched command's** own exit status (a [learning run](#a-learning-run-answers-for-its-learning) answers for its learning instead) |

## Output that cannot be written

An answer that cannot be written to standard output turns a success into `1`, said once on
standard error: what reached a full disk under `> file` is not what the verb produced. A reader
that has gone away, the end of `sbx … | head`, is not a failure and changes nothing.

A diagnostic that cannot be written to standard error changes nothing either, whatever the
cause: standard error is where a failure would be reported, and the exit code is the answer.
`sbx app show nope 2>/dev/full` still exits 2. The one exception is a `[y/N]` question: one
that cannot be shown is answered no.

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

A `--session` rule load is not a name either. `sbx net allow|deny|mute --session` and `sbx proc
allow|deny --session` load a rule into the live sessions in scope, and exit 1 when that reached
none or a session refused the rule, since the rule is then not in force where it was meant to
be. A session whose proxy kept an egress rule without confirming it exits 2, as the
[`sbx net pending`](../cli/net#sbx-net-pending) answers do.

A view given no session id reads the session of the project it runs in: `sbx logs`, `sbx proc
ls|live|logs`, `sbx fs logs` and `sbx ssh-agent logs`. When that project has no session to
read (none live and, for the log views, no record of a finished one), or several live ones to
choose between, the view has nothing it was named to show and exits 2, as a name that names
nothing does; name one by the PID [`sbx session ls`](../cli/session#ls) shows.

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

### A learning run answers for its learning

`sbx app run <name> --net-learn` or `--proc-learn` launches the app to find out what it
reaches for, so an app that fails on what it has no rule for is expected, and its status
is not the run's result. Once the app is launched, the run exits 0 unless writing what
it learned failed. A learning run stopped before its launch learned nothing, and exits
with the code the same launch without the flag stops with (2 for an undeclared app, 1 for
an app that declares no command), or with 2 for a posture the flag cannot learn under.

A cage that never started is no launch either. When the sandbox could not be prepared or
spawned, or its terminal could not be set up, the run exits 1 as the launch without the flag
does. bubblewrap is also asked to report on its own setup, and a cage it refused to set up, or
a program it could not run, says it never reached its command and exits with the failure's
code (1). Under `--proc-learn` the exec record tells the rest: a run that recorded no program
and ended in a failure never reached its command either (the command is nowhere on the cage's
`PATH`, the exec supervisor stopped it), says so, and exits with that code. What neither
witness sees is a startup step inside the cage failing before the app, a tool being equipped
or a bundle's install: under `--net-learn` alone either still reads as a run that learned
nothing, and exits 0, with the step's own message above it on standard error. Under
`--proc-learn` a tool being equipped is seen, since it runs ahead of the exec supervisor and
records nothing, but a bundle's install runs under it: its programs are recorded, and the run
reads as one that ran. A declared service never stops the app, since it starts in the
background.

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
