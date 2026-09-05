---
description: "`spawn`, `[exec.<program>]` and the task tool pool: what program a declared operation may run."
---

# What a task may run

sbx fixes the program a [declared operation](./) runs. These fields bound what that
program may run **beside** itself, and where its binaries come from.

See also: [Declared operations](./) · [Output](output) · [`[proc]`](../configuration/proc) ·
[`sbx upgrade mise`](../cli/upgrade).

## Which binaries a task may run

A task's program must come from a tree **no cage can write**, or "sbx fixes the program" is a
fiction. Most `[packages]` backends already satisfy that with nothing to declare here: `nix:`, a
remote `flake:`, and the four prebuilt ones (`deb:`, `appimage:`, `tarball:`, `binary:`) all build
**host-side into the shared store**, which a task cage mounts read-only, so their binaries are on a
task's path already.

Two are different:

- **`mise:`** installs *in-cage*, under a writable `$HOME`: so the pool the agent uses is
  agent-mutable and cannot back a task. Declare the tool in the task's own `packages` and sbx
  installs it into a pool of its own (below).
- an **inline `[flakes.<name>]`** flake builds in-cage to an out-link under the agent's `$HOME`,
  which a task cage does not have. Use a remote `flake:` reference, which builds host-side.

## What the command may run: `spawn`

sbx fixes the program a task runs. `spawn` declares what that program may run **beside itself**:

```toml
[task.gh-issue]
cmd   = ["gh", "issue", "list", "--repo", "{repo}"]
spawn = ["git"]
```

What `git` may then run is [a section of its own](#what-each-program-may-run-in-turn-execprogram), naming it here would let the command run it directly instead.

**Why it matters where a credential is involved.** A child of the command inherits its environment,
so it inherits the credential. The output that comes back to the caller is redacted, but redaction
matches the credential's **exact bytes**: a child that encodes it first is not caught. Confining
what may run closes that.

**Leaving `spawn` out is not the same as `spawn = []`.** Absent means no exec supervision at all: the
command runs as it always has. Present, including empty, stands up a supervisor for that
invocation, after which **only the command, what it lists, and what a section below allows may
run**. `spawn = []` is therefore the strictest form: a command that must run nothing else.

**A name is resolved to the program, not to a filename.** Each entry is looked up on the cage's own
`PATH` and becomes the absolute path it will run as, in the read-only store. A rule matching a bare
name would admit any file so called, including one written into the invocation's own tmpfs; the
resolved path does not. Write an entry with a `/` and it is kept as you wrote it, globs included
(`/nix/store/*/bin/git`). A name that is nowhere in the cage refuses the launch rather than becoming
a rule that matches nothing.

**A refusal is reported, never silent.** The `execve` comes back as an error to a program that
decides for itself whether to mention it, and many say nothing at all, leaving an empty result and a
success code. So the invocation reports what it refused, by name:

```console
$ sbx task run db-query -p 'sql=…'
sbx: warning: the operation was not allowed to run:
  /bin/sh
sbx: note: this operation declares `spawn`; a program it needs must be listed there.
```

That is how a missing entry reads as a missing entry rather than as a command that mysteriously
returned nothing.

**It governs the whole tree, at any depth.** The filter is inherited across `fork` and `exec`, so a
program run by a program run by the command traps the same supervisor. What decides is then *who is
running*, which is what the next section is about.

**Listing an interpreter concedes most of the guard**, and sbx says so at load. `sh`, `python`, `awk`
and the like can take a credential apart and put it back together with builtins alone, and nothing
they do that way is an `execve` to decide. The same is true if `cmd` is itself a shell script.
(The warned set is `sh`, `bash`, `dash`, `zsh`, `ksh`, `fish`, `env`, `python`, `python3`,
`perl`, `ruby`, `node`, `awk`, `gawk`, `xargs`.)

## What each program may run in turn: `[exec.<program>]`

`spawn` says what the **command** may run. A section says what one of those programs may run once it
is running:

```toml
[task.release]
cmd   = ["make", "release"]
spawn = ["git"]

[task.release.exec.git]
spawn = ["ssh"]

[task.release.exec.ssh]
spawn = ["gpg"]
```

**This permits a chain without granting a shortcut**, which is the whole reason the form exists. To
let `make → git → ssh → gpg` happen with one flat list you would have to write
`spawn = ["git", "ssh", "gpg"]`, and then the command may run `gpg` **itself**, with the credential
in hand and nothing in between. Above, the command may run `git` and nothing else.

**A program with no section of its own may run nothing.** There is no inheritance down the chain:
inheritance would hand back the shortcut. So a program that needs to run something needs a section
naming it, and `spawn = ["git"]` alone means git runs on its own or not at all.

**A section addresses a program, wherever that program was reached from.** `[exec.ssh]` is *ssh*, not
"the ssh git ran", so an ssh reached some other way is governed by the same rule, and a program
reachable three ways is declared once. There is nothing deeper to address, and a deeper section
(`[exec.git.ssh]`) is refused rather than quietly ignored.

`exec` is a namespace rather than the program's own name at the top: `[task.release.env]` is already
the task's environment, and `env`, `network`, `output` and `secret` are all programs a command
plausibly runs.

**What is refused at load**, each by name, with the rest of the file left standing:

| Written | Why |
|---|---|
| a section with no `spawn` on the task | nothing enforces it: `spawn` is what stands the supervisor up |
| a section nothing can reach | it says what a program may run when no program may run that program |
| `[exec.git]` where the list says `/nix/store/…/bin/git` | reachability is by **spelling**: the cage's `PATH` is what resolves a name, and there is no cage yet at load. Write the section key the way the list writes it |
| a section for the command itself | what the command may run is `spawn`; two declarations would each be half of one |
| `[exec.git.ssh]` | a program is the whole address |
| `[exec.git] spawn = []` | that is what having no section already means |
| `[exec.git*]` | a caller is one executable, so two patterns matching it would both claim it |
| `spawn = { git = [...] }` or `spawn = ["git", { ssh = [...] }]` | the per-parent graph: parsed only to be refused by name, since the filter governs the whole tree at any depth |

A pattern may still appear in a `spawn` list, where the answer is only yes or no. It just cannot
*address* a node, the program it admits then has no section, and may run nothing.

**Several names, one binary.** A caller is addressed by the executable it **is**, and some programs
are one file behind many names: every coreutils tool is a symlink to `coreutils`, and `/bin/sh` is
`bash`. So `[exec.ls]` governs every coreutils program, and sbx says so when a name resolves to a
different binary. What bounds it is that only a program that is **allowed to run** can ever be a
caller, so the over-grant never reaches past what the declaration already admits. Two sections that
turn out to be the same executable are refused: nothing could tell them apart.

That refusal, and the one for a program that is nowhere in the cage, arrives **when the operation
is invoked**, not at load: which binary a name reaches is a fact about the cage, and there is no cage
until then. So a task can list cleanly and refuse on its first run, naming the program either way.

**A refusal names who reached and what for**, because under this model the target alone misleads: a
program can be declared and still refused, to whoever reached for it:

```console
sbx: warning: the operation was not allowed to run:
  /nix/store/…/bin/git  →  /nix/store/…/libexec/git-core/git-remote-https
sbx: note: this operation declares `spawn`; list the target there when the caller is the command
       itself, and under `[task.<name>.exec.<caller>]` otherwise.
```

Only what was **there** is reported. Looking up a program by name issues one `execve` per `PATH`
entry until one succeeds, so a program found in the fourth directory leaves three refusals of files
that never existed: those are what a cage with no policy at all would produce.

## When the command is a script

A `#!` line is read by the kernel **inside** the `execve` that named the script: there is no second
call, and nothing ever observes the script as a running program. Only the interpreter runs. So
`spawn` on a script task says what its **interpreter** may run, and sbx keys it that way: a node on
the file would govern a caller that never exists.

With the interpreter named by path, that is invisible and everything reads as expected:

```toml
[task.report]
cmd   = ["/srv/repo/report.sh"]   # #!/bin/sh
spawn = ["git"]                   # what the shell running it may run
```

`#!/usr/bin/env bash` has one more step, and it is a real one, Linux runs **`env`**, passing `bash`
as its argument, and it is `env` that goes on to run bash:

```toml
[task.report]
cmd   = ["/srv/repo/report.sh"]   # #!/usr/bin/env bash
spawn = ["bash"]                  # env runs bash

[task.report.exec.bash]
spawn = ["git"]                   # bash runs git
```

Leave the second line out and the refusal reads
`/nix/store/…/bin/coreutils  →  /nix/store/…/bin/bash`: `coreutils` because `env` is one of its
hundred names, as [above](#what-each-program-may-run-in-turn-execprogram). That caller is the
command's own entry point, so what it may run is `spawn`.

**What it is not.** It bounds what the command *runs*; it does not bound what the command *itself*
does with the values the caller supplies. Both come back to `params` being the caller's lever, which
is why the bounds there are the first line and this is the second.

The rest of what bounds a task is its shape. The command is fixed by a trusted declaration, every
caller-supplied value is bounded by `params`, the cage has **no network** unless `network` declares
one (an empty netns, so a spawned child has nowhere to send anything), the project is read-only, and
the `$HOME` is a fresh tmpfs that dies with the invocation. And where the credential is an HTTP one,
[`inject`](credentials#wire-injected-credentials-the-strongest-form) removes the question entirely: the plaintext never enters the cage, so
there is nothing for a spawned child to inherit.

## The task tool pool

```toml
[task.gh-issue]
cmd      = ["gh", "issue", "list", "--repo", "{repo}"]
params   = { repo = "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$" }
packages = ["mise:aqua:cli/gh"]
```

`packages` takes **`mise:` entries only**: every other backend is already covered above, and the
error message says so if you write one. `mise:nix:…` is refused too: mise's `nix:` backend builds
into the store the cage writes, which is the very problem the pool exists to solve; declare it as
`[packages] nix:…` instead.

What sbx does with it:

- installs the tools **host-side at launch**, in a cage of its own: the task cage's skeleton with
  the pool read-write and the host network (like every other host-side provisioning step, a cage's
  `network` allowlist governs the *agent*, not sbx's own setup);
- mounts the pool **read-only** into the task cage, at the same in-cage path the install used;
- puts the pool's **shims** directory at the front of that task's `PATH`, so the tool resolves by
  name. (Shims rather than install directories because the layout inside an install belongs to the
  backend, not to mise: an `aqua:` tarball extracts to a vendor-named subdirectory, an `npm:` tool
  to `bin/`, a `pipx:` one into a venv. The shim is mise's own answer to that, and it is what the
  agent's cage already uses.)

A version is honoured as declared: `mise:node@22` uses that version, a bare `mise:node` takes what
mise resolved for it. Changing the declared version re-pins the pool even when the old install is
still on disk, so what runs is always what the declaration says. A tool whose runtime is another tool
(an `npm:` CLI needs node) means declaring both: the pool holds what you ask for, nothing implicit.

`sbx upgrade mise` rolls the pool forward with everything else, under a `task pool` line. A pinned
`mise:node@22` stays where you pinned it; a bare `mise:node` moves to the current release.

Three things to know:

- **The pool is per project**, under its runtime tree, so `sbx projects rm` and the dead-tree sweep
  reclaim it with everything else. The cost is duplication: a heavy runtime is installed once per
  project a global app launches in.
- **It is filled best-effort.** A tool that will not install warns at launch and does not abort the
  session, one task's missing tool should not take the agent down with it. `sbx task list` then
  flags that task with `missing-tools=…`, and invoking it fails with a plain "not found".
- **The pool is shared by the config's tasks**, even though `packages` is declared per task: the
  field scopes what goes on a task's `PATH`, not what exists on disk. Every task is trusted config,
  so this is a scoping convenience, not a boundary.
