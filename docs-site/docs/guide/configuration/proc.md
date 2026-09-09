---
sidebar_label: "[proc]"
description: "The process and exec lens: observing what the agent runs, and blocking it."
---

# `[proc]`: process/exec observation and enforcement

```toml
[proc]
mode  = "off"            # off | observe | enforce | ask
allow = ["git", "rg"]    # exec targets that always run; only bites under `ask`
deny  = ["curl", "ssh"]  # exec targets that are blocked
```

The `[proc]` field governs the **process/exec lens**: what `sbx proc` sees, and: under `enforce`
or `ask`, what an in-cage agent is allowed to `execve`. It is the exec analogue of
[`network`](network): a **security field**, honored from the global config or a **trusted**
project and dropped (with a warning) from an untrusted one: an untrusted project may neither forge
nor loosen the enforcement of its own agent. It can be set on the baseline **or** per app
([`[app.<name>.proc]`](apps)); an app's policy replaces the baseline's for that app.

A table without a `mode` keeps its `allow`/`deny` lists and inherits the posture from the
parent layer; an unrecognized `mode` drops the table with a warning, keeping the parent
posture rather than guessing.

## Why observe or enforce exec

Egress controls where an agent may connect; `[proc]` controls what it may run. An agent that may execute anything can pipe a secret into `curl`, open an `ssh` session, or run a compiler as a download proxy, all without touching a blocked host. `observe` answers the audit question (`sbx proc logs`: what did it spawn), `enforce` blocks the named programs before the syscall runs, and `ask` parks anything undecided for a live decision. Reach for it when the risk is the program, not the destination.

## Modes

| Mode | What it does |
|---|---|
| `off` (default) | no capture, no enforcement |
| `observe` | capture spawns via a cheap `/proc` poll (`sbx proc logs`), no blocking, the same feed as [`--observe`](../cli/run#observing-a-run---observe) |
| `enforce` | **block** a `deny` exec target before the syscall runs; everything else runs (a denylist) |
| `ask` | block `deny`, run `allow`, and **park** an unmatched target for a live [`sbx proc pending`](../cli/proc#pending) decision |

Under `enforce`/`ask` the lens uses a **seccomp user-notification** gate: every `execve`/`execveat`
traps to a host-side supervisor that decides it. A `deny` returns `EPERM`: the syscall **never
runs** (there is no time-of-check/time-of-use window on a refusal). Capture is then exact (no poll
gap), and `sbx proc logs` shows each spawn with its verdict.

The gate covers the whole process **tree**, not just the command sbx starts: the filter is inherited
across `fork` **and** `exec`, so a program an allowed one runs, and one *that* runs in turn, traps
the same supervisor. A rule therefore reads as *"this may run in this cage"*, at any depth, rather
than *"the agent may run this"*.

## Rule grammar

Each `allow`/`deny` entry is a shell-style glob (`*` = any run, `?` = one character):

- a rule **without** `/` matches the exec target's **basename**: `curl` blocks `/usr/bin/curl`
  and any other `curl` on `PATH`;
- a rule **with** `/` matches the **full exec path**: `/usr/bin/*`, `/nix/store/*/bin/git`.

Matching is otherwise exact (`curl` never matches `curlish`), and **`deny` always wins** over
`allow` (an entry in both is denied).

### Prefer a basename, and what a path rule costs

Both shapes are accepted, and a launch **warns** when a rule that decides something is written as
a path, because the shape promises more than the lens delivers. The two limits differ by direction:

- A path `deny` matches that spelling and no other. No symlink is resolved, so `deny = ["/usr/bin/*"]`
  says nothing about the same program reached as `/tmp/mycurl` or through a bind mount. A basename
  rule (`curl`) holds wherever the program is spelled *from*, which is the form to reach for, and
  the word to read closely is *from*: it is the directory that stops mattering, not the name. A
  rule names, and a copy renames, so `cp /usr/bin/curl ./x` produces a program no rule about `curl`
  speaks about. That is not a hole a stricter rule closes, it is what deciding by name is; see
  [Honest scope](#honest-scope). sbx ships no `[proc]` rules of its own: the rules in force are the
  ones you write, so there is no worked denylist to copy the shape from.
- A path `allow` is a guard-rail rather than a guarantee. The supervisor reads the target, decides,
  and then the kernel **re-resolves** it to run it, so a second thread in the cage can point the name
  elsewhere in between. Refusing a path is not exposed to this (the syscall never runs); allowing one
  is. Write an `allow` to keep a program working, not to prove that only that program ran.

Neither warning stops the launch: a path rule is sometimes exactly what you mean, and the warning is
there so the choice is made knowingly.

## Posture: a denylist, by design

`enforce` is a **denylist**: everything runs except an explicit `deny`. A coding agent spawns
constantly (compilers, `git`, language servers), so a default-deny allowlist would brick it; the
denylist lets you block the specific things you don't want an agent reaching for: `ssh`, `curl`,
`sudo`, a package manager: while it works normally otherwise.

`ask` is stricter: an unmatched target parks. Because a coding agent spawns so much, `ask` is meant
to run against a **populated `allow` list** (the tools you trust it to use), with `deny` for the
ones to always refuse and the interactive prompt for the genuinely-new. A parked `execve` that is
not decided within the ask timeout is **auto-denied** (fail-closed), so a process tree never hangs
on a stalled decision.

## Honest scope

A `deny` is a **hard stop on the `execve` it names**, even against a hostile agent. Two ways around
a seccomp exec gate are closed by the kernel: a foreign-ABI `execve` (the i386 compat call from a
64-bit process) is *killed* by the mandatory syscall denylist's architecture guard rather than
slipping through, and an agent cannot install its own notification filter to intercept its own
`execve`s (the kernel allows only one such listener, held here by the launcher). Three more, where
one `execve` runs a program it does not name, are closed by sbx and described under
[what one `execve` can run](#what-one-execve-can-run). So `deny = "curl"` stops every `execve`
whose target is *named* `curl`, from whatever directory, and behind whatever interpreter.

What it does not stop is a *different* program, and that is the first of the four reasons this is a
guardrail rather than a full containment boundary:

- a rule decides a **name**, and a cage that can write a file can give the same bytes another one:
  `cp /usr/bin/curl ./x && ./x` is a program no rule about `curl` names. Nothing decided by name
  reaches that, which is why `[proc]` is a way to keep an agent off the tools you did not mean it
  to reach, and not a way to bound what it can do with the ones it has;
- an agent can do harm **in-process** (in its own interpreter) without `execve`ing anything at all, which is also why `allow`ing a shell or a language runtime concedes most of the gate: what it does
  with its own builtins never reaches a syscall to decide;
- `allow`/approval re-runs the real syscall, which is **TOCTOU-racy** against an adversary that swaps
  the path argument after the check, so *refusing* a path is hard, but *approving* a specific one is
  a guardrail;
- deciding by **name** means reading the target out of the process that is parked in the `execve`,
  which the kernel grants only to that process's ancestor. A launch is one, so this holds in the
  ordinary case; on a host that restricts `ptrace` further than the usual scope, nothing can be read
  and every decision falls to the mode's default, which under the denylist posture is an allow. sbx
  does not go quiet about it: the first such decision warns, and the total is reported when the run
  ends, so a policy that decided nothing by name says so instead of reading like a run in which
  nothing needed refusing.

So the cage's real confidentiality/integrity boundaries stay what they always were: confinement by
absence (a secret that isn't mounted can't be read) and the [network allowlist](network). The store
at `/nix` is not one of them: a launch binds a per-project copy of it read-write, under the uid that
owns its files, so the programs a rule may name sit in a tree the cage may also rewrite. What that
per-project copy protects is the *shared* store behind it, which no cage ever writes into. `[proc]`
adds **visibility and a hard veto on what the agent execs** on top of the two that are boundaries.

The `enforce`/`ask` feed (`sbx proc logs`) shows the resolved **exec path** the agent is running (the
thing policy matches on), not the full argv: a `curl https://…` appears as `…/bin/curl`.

### A program named through another program

## What one `execve` can run

One `execve` can run a program other than the one it names, and sbx decides both. Two shapes reach
that far:

- **A dynamic loader on the command line.** `ld-linux-x86-64.so.2 /usr/bin/curl` is a single
  `execve` whose path is the loader's, so a `deny = "curl"` matched on that path alone would not
  fire. sbx reads the loader's own argument list and decides the program it names too, taking the
  stricter of the two answers. Options that consume the next word (`--library-path`, `--preload`)
  are stepped over rather than mistaken for the program.
- **A `#!` line.** `./deploy.sh` starting with `#!/bin/sh` is a single `execve` as well: the kernel
  reads the line and runs `/bin/sh` inside that same call, with no second syscall to notify. sbx
  reads the first 256 bytes of the target, the amount the kernel itself reads, and decides the
  interpreter too. So `deny = "sh"` stops a shell script, not only a shell typed at a prompt.

In both shapes the interpreter's **arguments** are not decided, only the program: `#!/usr/bin/env
python3` is decided as `/usr/bin/env`, and `ld.so /bin/grep curl` is not refused by a rule about
`curl`. A payload written in an argument therefore runs only under an interpreter a rule already
allows.

Three more things follow, and all are deliberate:

- **A file sbx can execute but not read is refused.** A script in mode `0111` is unreadable even to
  its owner, yet the kernel still runs its interpreter, and a payload spelled in the interpreter's
  argument never needs the script at all. Since what the `#!` line would have said is exactly what
  could not be established, the answer is a refusal. The cost: an execute-only file does not run
  under an exec policy, however it is spelled.
- **A `binfmt_misc` handler.** A handler registered for `.jar`, `.py`, a wine binary or a
  foreign-architecture executable makes the kernel run an interpreter that nothing in the file
  names. sbx reads the registered handlers instead of the file, once per launch, and decides the
  interpreter of every handler whose magic or extension claims the target. A handler enrolled while
  a cage is already running is not seen by it, which takes a privilege the cage does not have.
- **A program run from a descriptor.** An exec can name its target by descriptor rather than by
  path, and the object behind it need not exist on any filesystem: an in-memory file carrying a
  `#!` line runs its interpreter just the same. sbx reads such a target through the descriptor the
  caller already holds, so these are decided like any other.

## What enforcement puts inside the cage

Only the kernel can hand out the descriptor that lets a supervisor decide an `execve`, and only the
process being filtered can ask for it: bubblewrap cannot. So under `enforce`/`ask` one program is
bound read-only into the sandbox to install the filter, pass the descriptor out, and become your
command.

That program is a **dedicated binary**, not sbx. It is carried inside sbx, laid down at
`<data>/engine/proc-shim` (see [`sbx path`](../cli/path)), and it links the C library and nothing
else, it can install a filter, send a descriptor and `exec`, and cannot express anything further.
Binding a general-purpose binary instead would make the sandbox's safety rest on none of that
binary's state happening to be reachable from inside: true today, unchecked, and quietly false the
first time a bind is added.

It is **fail-closed** in the direction that matters. A shim that cannot install the filter, or cannot
reach the supervisor, exits without running your command: enforcement that could not be established
means the command does not run, never that it runs unenforced.

The socket the descriptor crosses is reachable from inside the sandbox, so the first thing to
connect to it is not necessarily the shim. The supervisor asks the kernel whether what it was handed
is a notification descriptor at all, and a connection that hands over anything else is refused and
reported, without ending the wait: the shim's own handoff, arriving behind it, is still served. What
that check cannot supply is a bound on how often something may connect, so a caller determined to
occupy the socket for the second the shim spends retrying can still cost itself its own launch.

### What the agent is told

The cage's generated contract (`/opt/sbx/egress-contract.md`, named by `SBX_EGRESS_CONTRACT`)
carries a section for this lens, and it states the **posture only**: that execution is mediated,
under which mode, and, under `ask`, that a program no rule settles is parked for a person to allow
or refuse. It names **no program**, in any mode.

That is a deliberate limit, and the reason is `ask`. The rule the contract follows elsewhere is to
state what the cage could discover by trying and withhold what it could not, which is why the
reachable hosts are listed and the deny rules are not. A list of programs that run would fail that
rule in the one mode where it matters: it would name, by complement, exactly what reaches the
person deciding, and a process cannot discover that by trying without triggering the review the
list would teach it to avoid.

What the section does say is the part that prevents honest damage: a refused program fails with a
permission error, not a "command not found". Without that line a process reads a refusal as a
broken toolchain and starts reinstalling, copying binaries elsewhere, or reaching for an
interpreter to run the program indirectly, which is indistinguishable from evasion and drowns the
real signal.

## Watching and deciding

- [`sbx proc logs [<id>] [-f]`](../cli/proc#logs): the exec feed, each line carrying its verdict
  (`allow`/`deny`/`ask`, or `observe` for a non-enforcing run).
- [`sbx proc pending`](../cli/proc#pending): list, and `allow`/`deny`, the `execve`s an `ask`
  session has parked.

## Example

```toml
# A trusted project: let the agent build and use its toolchain, but never reach the network by
# shelling out, and prompt for anything unexpected.
[proc]
mode  = "ask"
allow = ["git", "rg", "cargo", "rustc", "node", "sh", "bash", "/nix/store/*"]
deny  = ["ssh", "scp", "sudo", "curl", "wget"]
```

See also: [`sbx proc`](../cli/proc) · [`network`](network) · [Enforcement stack](../concepts/enforcement).
