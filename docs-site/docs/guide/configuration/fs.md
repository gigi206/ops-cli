---
sidebar_label: "[fs]"
description: "Closing a project path off inside the cage: the one table whose masks apply from an untrusted source, because they only take away."
---

# `[fs]`: closing project paths off inside the cage

A project usually holds a few files the agent working in it has no business reading: a
`.env`, a private key, a certificate, a token. Moving them out of the tree is one answer,
but often they belong exactly where they are: the build reads them, git tracks the
directory, a colleague's checkout expects them. `[fs]` is the other answer. It closes a
path **inside the cage** and leaves the file untouched on your disk.

```toml
[fs]
deny     = ["prod.key", "certs/*.pem", "secrets/"]
readonly = ["Cargo.lock", "docs/generated/"]
```

What the cage sees:

```
$ ls -l
----------  0  prod.key         # the name is still there
-rw-rw-r--  5  Cargo.lock
$ cat prod.key
cat: prod.key: Permission denied
$ ls secrets/
                                # empty, whatever is really in it
$ echo x >> Cargo.lock
sh: Cargo.lock: Read-only file system
```

The name stays visible on purpose. Removing it would change the shape of the project the
agent is working in, and a tool that expects the file to exist would fail in a way nobody
can read. Only the *content* is closed.

`[fs]` is the one table whose **masks** are honored from any source, an untrusted project
included. Every other security field can grant something, so an untrusted project may not
set it; a mask here can only take access away from the cage the project itself declares,
and there is no syntax for reopening anything. Layers **union**: a project adds to what the
global config closed, an app adds to what the project closed, and no layer can undo one
below it.

Two keys are the exception, and they are gated like any other security field, because each
widens what the cage may do. `scan_max_kb` (see [`scan`](#scan-closing-a-file-by-what-it-holds))
is a ceiling on how much of a file is *read*, not a mask, so lowering it closes fewer files.
`git_writable` (see [below](#read-only-without-an-entry-the-project-config-and-git)) lifts the
read-only default on `.git/hooks/` and `.git/config`. An untrusted project setting either,
whether on the project itself or on an app it declares, is refused and told so; the masks and
scan patterns it listed still apply.

See also: [Declared operations](../tasks/) · [`binds`](binds) · [The trust gate](../concepts/trust) · [Enforcement stack](../concepts/enforcement)

## `deny` and `readonly`

| | What the cage sees | What it is for |
|---|---|---|
| `deny` on a file | the name, and `EACCES` on open. `stat` reports size 0 and mode 000 | a key, a token, a `.env` |
| `deny` on a directory | an empty directory; everything inside is `ENOENT` | a whole `secrets/` tree |
| `readonly` | the real content, and `EROFS` on write | a lockfile, a generated file |

Both work by mounting over the path inside the cage. Your file is never modified, moved or
copied, and the rest of the project stays writable. Removing a masked path from inside the
cage fails with `EBUSY` (it is a mount point), and hard-linking around one fails with
`EXDEV` (the link would cross the mask's own mount boundary), so in-cage code cannot take a
mask apart. Neither can it unmount one: `umount2`, `mount` and `unshare` are refused by the
[mandatory seccomp filter](seccomp), and the cage holds no capability in its user namespace.

### Entries that overlap

An entry inside a denied **directory** is dropped, with a warning: the directory is already empty
inside the cage, so there is nothing left for a second mask to cover. This includes a `readonly`
entry, since `deny` closing a path outright beats `readonly` protecting it.

The other direction works and is a real policy: `readonly = ["config/"]` alongside
`deny = ["config/prod.key"]` leaves the directory readable, refuses every write in it, and closes
the one file inside it that the cage may not read.

Be careful pointing `readonly` at `.git/` itself, though: git needs to write `.git/index.lock` to
commit, so `readonly = [".git/"]` leaves `git log`, `git status` and `git diff` working while making
every `git add` and `git commit` fail. The two files that matter, `.git/config` and `.git/hooks/`,
are already read-only [without an entry](#read-only-without-an-entry-the-project-config-and-git).

### Read-only without an entry: the project config and git

One protection needs no `[fs]` line. When the project has a `.sbx.toml`, it is read-only in
every agent cage, and so is each [mise file the trust gate hashes](../concepts/trust) beside
it (`mise.toml`, `.mise.toml`, `.tool-versions` and the rest) that is present at launch. The
effect is exactly a `readonly` entry: the real content, `EROFS` on write, `EBUSY` on removal
or rename.

These are the files that govern the cage, sitting in a tree the cage can write. A write to
one does not grant anything by itself, since the trust gate drops a changed file's security
fields, but it asks you to re-approve, and a re-approval made to silence a warning is how an
addition you never wrote gets granted. Refusing the write takes that step away from the
agent. A file the cage *creates* cannot be protected this way (a mount needs something to
land on), which is why [`sbx trust`](../cli/trust) shows the diff of what it approves.

Without a `.sbx.toml`, sbx honors no mise file, so nothing is protected and a project that
only uses mise keeps writing its own config. The verbs that edit `.sbx.toml` for you
(`sbx net allow`, `sbx config set`, …) run on the host and are unaffected; a cage already
running keeps seeing the contents it started with.

The same holds, with or without a `.sbx.toml`, for **`.git/hooks/` and `.git/config`** when the
project's `.git` is a directory. A hook, or a key of the config that names a program
(`core.hooksPath`, `core.fsmonitor`, `core.pager`, a filter, an alias), runs on the host at
your next git command, outside any cage: it is the sharpest of the carriers in [where the
protection stops](../concepts/security-model#where-the-protection-stops). The hooks
*directory* is protected, so a hook created halfway through the session is refused too.

The hooks directory is the one git will run hooks from: `.git/hooks`, and also the directory
`core.hooksPath` names when it is inside the project. husky, for one, points it at `.husky/_`,
a directory git ignores, where a rewritten hook would not even show in `git status`. The value
is read from your host's own `git` at launch, so an include file or your global config counts;
a directory outside the project is left alone, since the cage does not hold it, and with no
`git` on the host there is nothing to ask and no hook to run. A hooks directory that does not
exist yet is **created empty at launch** and then protected, which is what `git init` makes:
otherwise the cage could create it and fill it. It is made one component at a time, and a
symbolic link found on the way refuses the launch rather than being followed.

**What this does not close: the hooks a project already has run its code.** The protection
closes the hooks git would run without a trace: an untracked script in the hooks directory, a
configuration key that names a program. It cannot close the hooks a project already uses,
because they run the project's own code: husky's `.husky/pre-commit` running `npm test`, a
pre-commit `repo: local` entry, a lefthook `run:` line, lint-staged and a linter's JavaScript
configuration, a test suite's `conftest.py`. The agent writes that code as part of its work,
and the hook runs it on the host at your next `git commit`, and `post-checkout` or
`post-merge` at your next `git switch` or `git pull`. It is the same carrier as `npm install`
or `make` in [where the protection stops](../concepts/security-model#where-the-protection-stops),
and no mount can close it without closing the work. What keeps those hooks off the host is
how you run git on the agent's work:

| How git runs on the agent's work | Hooks that run |
|---|---|
| `git commit --no-verify`, on the host | `post-commit` still runs: not enough |
| `git -c core.hooksPath=/dev/null commit`, on the host (the same `-c` before `switch`, `pull`, `merge`) | none |
| `sbx run -- git commit …` | all of them, inside a cage |

A commit from a cage works with `.git` protected. The cage's git needs an identity, which
`git config --global user.name …` inside the cage records in the cage's own home.

Everyday git keeps working: `status`, `add`, `commit`, `switch`, `stash`, `tag`, `fetch`,
`pull` and `push` with their arguments, and a worktree created inside the cage. What writes
the config is refused: `git remote add`, `git config user.*`, and the upstream a
`push -u` (or `switch` to a remote branch) records. The push itself succeeds, and git
prints `could not write config file .git/config`. So that a bare `git push` still works
without that upstream, sbx gives the cage's git `push.autoSetupRemote=true` through the
environment (`GIT_CONFIG_COUNT`, after any pair a trusted `[env]` passes, and never over a
value it sets for that key): a branch is pushed to its namesake, and nothing is written to
the repository. A bare `git pull` still asks for the remote and branch
(`git pull origin <branch>`). Installing a hook from inside the cage (husky,
`pre-commit install`, `lefthook install`) is refused.

A project that needs those opens them from a trusted layer:

```toml
[fs]
git_writable = true
```

It is the one key in `[fs]` that opens rather than closes, so it is honored only from a
trusted project (where it appears in the diff [`sbx trust`](../cli/trust) shows), from the
global config, or from an app profile; from an untrusted project it is dropped with a warning.
A layer above decides in either direction: `git_writable = false` in a trusted project
restores the protection the global config lifted. A `.git` that is a file (a linked worktree
or a submodule) points at a directory outside the project, which the cage does not hold, so
nothing is added for it.

[`sbx test fs`](#seeing-what-is-closed) reports all of these as `READ-ONLY`, protected by sbx
itself, and [`sbx config show`](../cli/config) prints `fs git: writable` when a layer lifted
the git pair.

## The grammar

Each entry is a path **relative to the project root**:

| Entry | Matches |
|---|---|
| `prod.key` | that file |
| `config/prod.key` | that file |
| `secrets/` | that directory, and everything in it |
| `certs/*.pem` | the `.pem` files directly in `certs/` |
| `*.key` | the `.key` files at the project root |

The rules, and why each one is there:

- **A wildcard may appear only in the last component.** `certs/*.pem` is fine, `*/prod.key`
  is not. Every component above the last being a literal name is what lets a match read one
  directory instead of walking the project.
- **`**` is refused.** A recursive match walks the whole tree: on a large repository that is
  9 to 23 seconds of launch time, against hundredths of a second for an anchored pattern.
  Name the directory instead, which is also the stronger answer (see below).
- **An absolute path is refused.** What the cage sees of the host outside the project is
  [`binds`](binds), a trusted field with its own gate. An `[fs]` mask is honored from any source, so
  letting it name a path outside the project would make it a second way to reach one.
- **A `..` component is refused**, and so is a path that resolves outside the project through
  a symlink.
- **A trailing `/` means "this is a directory"**, and an entry that ends in one but names a
  file is refused rather than guessed at.
- **An entry matching nothing is a warning**, never a failed launch: a profile may name a
  file only some checkouts carry.
- **An entry that cannot be looked at stops the launch**, which is a different answer from
  matching nothing. The cage runs as your own uid and holds the project writable, so it can
  close a directory of its own and have the next launch read its masked path as absent: the
  entry would match nothing, the warning would read like a stale config line, no mount would
  be laid, and the session after that could put the mode back and read the file. So "not
  there" is the only error that warns. Every other one refuses, whether it came from the
  entry itself, from listing the directory a pattern sits in, or from following a link.
- **A `*` also matches a name starting with a dot**, unlike a shell glob. `secrets/*` covers
  `secrets/.env`. The difference is deliberate: for a mask, covering more is the safe direction.

A refused entry is dropped with a warning that says the path **stays open**, because that
is what the drop costs.

## Prefer a directory

A denied *directory* is the only shape that stays closed for the whole session. Mounts are
resolved once, at launch, so a file pattern covers what exists at that moment: a file
written into the project from outside the cage half an hour later is not covered. Inside a
denied directory it is, because nothing there is reachable at all.

Directories are also the cheap shape. Each mask is one mount, and the launch cost grows
faster than one-for-one with the count: 100 masks cost about 32 ms, 500 about 384 ms. One
entry naming a directory closes it whatever it contains, at constant cost. Past 64 masks
`sbx` says so; past 256 it refuses the launch rather than quietly dropping the tail.

## `scan`: closing a file by what it holds

`deny` needs you to know the path. `scan` does not: it names the **shapes a credential takes**,
and every project file the cage opens is checked against them at the moment it is opened.

```toml
[fs]
scan = [
  "sk-[A-Za-z0-9]{20,}",
  "AKIA[0-9A-Z]{16}",
  "-----BEGIN [A-Z ]*PRIVATE KEY-----",
]
scan_max_kb = 256
```

A file whose content matches is refused with `EACCES`, and the refusal happens **before the
open returns**, so not one byte of it reaches the cage. The launch says which pattern closed
which file, so a refusal can be told apart from a broken build.

The difference from `deny` is *when* the question is asked. A mask is resolved once, at launch;
`scan` is asked at every open, so a file that acquires a secret in the middle of a session is
closed from the next open onwards, with no relaunch. This is what closes the second hole listed
below, for content it recognises.

Because the check happens at the open rather than at the read, it also covers a file the cage
maps into memory: there is no descriptor to map without an open, and the open is what was
refused. A symbolic link is followed the way the kernel is about to follow it, so pointing a
link at a closed file does not reopen it.

**Bounded on purpose.** Only files under the project are scanned: the read-only store, the
system libraries and `/proc` are where the volume is and where your secrets are not.
`scan_max_kb` bounds how much of one file is read, and a file longer than that is judged on its
start. The launch says so when it happens, rather than presenting a prefix as a whole-file
result. Leave it unset for the built-in ceiling; `0` is refused, since a scan that reads nothing
would pass everything while still looking like a scan, and so is a negative number, which is no
ceiling at all. Where two layers both set it, the **larger** window is the one that applies: a
bigger number closes more files.

An **empty** pattern is refused for the mirror-image reason, and named in the launch warnings
with the rest of the line kept: it is a valid regex that every file matches, so a list holding
one would close everything under `enforce` and report every open under `observe`, while the
shapes beside it stopped deciding anything. A pattern that does not compile is refused the same
way, for its own reason. In both cases the remaining patterns still apply, so one bad line does
not cost you the list.

A pattern carrying a **control character** is refused for a reason about the terminal rather than
about the scan. `[fs]` is honoured from an untrusted project, and an accepted pattern is printed
back: `sbx config show` lists it under `fs scan`, and the launch warnings name it. A newline in one
forges a line that reads like a mask which is not in force, and an escape sequence rewrites what the
screen already shows. Nothing is lost by the refusal, since content that really holds such a byte is
matched by spelling it as a regex escape (`\n`, `\t`, `\x1b`), which is plain text on the way back.

This is the one key in the table that a trust gate holds. The rest of `[fs]` is honoured from an
untrusted project because nothing in it can widen what another layer closed; a ceiling can, by
being lowered, so an untrusted layer's `scan_max_kb` is refused rather than merely out-voted, and
the refusal is named in the launch warnings. The patterns that layer listed are unaffected. A
trusted project sets the ceiling as before.

**One scanner per layer.** Every pattern a layer lists is compiled into a single scanner, so the
cost of a scan does not grow with the length of the list; that scanner has a size ceiling, though,
and a list too large to fit it compiles into nothing. Such a list is dropped at config time, named,
and only for the layer that wrote it: the shapes another layer declared keep scanning, and a project
that piles on patterns loses its own scan rather than the launch.

**What it costs you.** Every open of a project file goes through the supervisor, so a build is
slower than it is without a scan. `scan` also brings that supervisor up on its own, without
`[proc]`, because it is the same notification listener read for a different syscall.

**What an allow hands over.** When a scan comes back clean, `sbx` gives the cage a descriptor for
the file it just read, rather than letting the open run a second time from the path the cage wrote.
That distinction matters against a cage with more than one thread: an open that re-runs re-walks its
path argument, and a sibling thread is free to have pointed it somewhere else while the scan was in
progress, so the file that arrives would not be the file that was read. Serving the descriptor
removes the second walk, and the descriptor carries no more authority than the cage had: a read-only
bind refuses a write through it exactly as it refuses the cage.

Nearly every open a cage makes is answered this way, not only the ones under your project and not
only the ones that hold a file. That breadth is the point rather than thoroughness for its own sake:
the cage chooses what its path names **first**, so any shape `sbx` could not answer for would be the
shape to name. A pipe, a device and a socket are each served or replied to on their own terms, and a
path that is not there is answered with the same error the cage would have received, rather than
being looked up a second time once something has been moved into place behind it.

Two gaps are left, and the second one **is** a shape a cage can arrange.

The first is a kernel older than 5.14, which does not offer the operation in the form `scan` needs;
there `scan` behaves as it did before, swap included. (The `ADDFD` ioctl itself arrived in 5.9, but
the flag that installs the descriptor and answers the call in one step arrived in 5.14, so a 5.9 to
5.13 kernel falls back too.) That fallback is not silent. The first allowed open the
kernel declines to serve this way prints a warning naming the missing operation, once for the
session, so a weaker `scan` is something you are told about rather than something you have to infer
from a kernel version.

The second is `openat2` carrying a non-zero `resolve` word, and it is worth stating plainly because
it is chosen rather than suffered. Such a call asks the kernel for a **stricter** path walk than the
supervisor performed: the scan follows symlinks on purpose, since one that stopped at a link would
be walked around with a single `ln -s`. Handing that descriptor to a caller that asked for
`RESOLVE_NO_SYMLINKS` would silently remove the hardening that caller asked for, so `sbx` declines
to serve the open and lets the real syscall run with the real `resolve` semantics. The verdict is
unaffected, and a refusal still refuses: what returns is the second walk, and with it the swap
window this section otherwise closes. A cage reaches it by choosing the form of its own system call,
which needs no privilege and no race to arrange, and unlike the kernel fallback above it is not
announced. The scan remains a backstop against a file whose content matches; it is not a guarantee
about which file arrives when the cage asks in that form.

**What it does not do.** A pattern only finds the shapes you wrote: a password that looks like
ordinary prose is not one of them, and a scan is a backstop rather than a proof. Rewriting a file
that currently holds a matching secret is refused too, because a truncating write opens it first;
the file has to be closed to the cage or the pattern narrowed. And a file already open when its
content changes keeps the descriptor it was granted.

One shape to know about if your project tree spans a network or FUSE mount: the scan reads the
file on the host side, and that read is bounded in size but not in time. A backing store that
stalls holds up the open being decided, and the others queued behind it. A project on local disk
is not affected.

## What it does not cover

`[fs] deny` is **a reduction of exposure**, not a boundary of the same class as
[`[network] deny`](network). Egress is fail-closed: what is not allowed does not pass.
This is different, and it has three named holes:

1. **A second hard link.** A mask covers a *path*, not an inode. If another name in the
   project points at the same file, the content is readable through it. `sbx` warns at
   launch when a masked file has more than one link. That holds for a `readonly` entry too,
   where the alias is not merely readable but *writable*: the re-bind refuses writes on the
   path it covers, and the second name reaches the same inode around it.
2. **A file that appears mid-session**, outside a denied directory. The masks are resolved
   at launch; a file created afterwards matching a file pattern is not covered. A denied
   directory does not have this hole.
3. **A path nobody listed.** There is no allowlist form: what you did not name is open.

The cage cannot open any of these itself: it cannot create a hard link across a mask, and
it cannot write a file into a denied directory. They are ways the *host side* can leave a
path open, which is why they are worth knowing rather than worth panicking about.

The [git protection](#read-only-without-an-entry-the-project-config-and-git) has a hole of
the other kind, one the cage *can* use when your repository already opens it:
`.git/config` is read-only, but an `include.path` or `includeIf` in it that names a file
inside the working tree makes that file part of the effective configuration, and the cage
can write that file. Keep included configuration outside the project. The larger case of
the same family, the hooks a project already has, is described
[with the protection](#read-only-without-an-entry-the-project-config-and-git).

Nor can it hide a masked path from the resolver. The cage owns the project tree under your
own uid, so it can make a directory untraversable; a path that cannot be looked at is then
indistinguishable from one hidden on purpose, so the launch is **refused** naming the entry
rather than reported as matching nothing. An entry that is genuinely absent still only
warns, since that is an ordinary thing for a config to name.

The second one is structural rather than an omission. A mask is a mount, and a cage's mounts
are fixed when it is built, so a pattern cannot cover a name that did not exist yet. Three
things answer it, and all three are already here: **name the directory**, which closes it
whatever appears inside; **[`scan`](#scan-closing-a-file-by-what-it-holds)**, which asks at
every open instead of at launch and so covers a file that appears or changes mid-session, for
the content it recognises; or **relaunch** the session after adding a secret the pattern should
have caught.

## git

Masking a file git **tracks** breaks git wholesale: git compares the worktree against its
index, the masked file reads as modified and unreadable, and then `git commit` fails for
*everything*, not just for that file. Nothing is corrupted, but the agent cannot commit at
all.

Masking a **gitignored** file (the usual case for a key or a `.env`) is completely
transparent: `git status` is clean and commits work.

If you do need to mask a tracked file, run this once in the project:

```bash
git update-index --skip-worktree prod.key
```

git then stops comparing that path against the worktree. The mask still closes the file,
`git status` reads clean, and commits succeed. `sbx` warns with this exact command when it
sees a masked path in the index, and stops warning once the flag is set. It never runs it
for you: it is a local flag on your own clone, and a launcher that silently reconfigured a
repository would be the worse surprise.

The flag is per-clone and is not committed, and a `checkout` or `pull` touching that file
can drop it.

## Opening a path for one operation

A masked path is closed in **every** cage the session builds: the agent's, and each
[declared operation](../tasks/)'s. That is the safe default, and it is usually not what you
want for the one operation whose whole job is to use the file. `[task.<name>] unmask` lifts
a mask for that task and no other:

```toml
[fs]
deny = ["prod.key", "certs/*.pem"]

[task.decrypt]
description = "Decrypt a project file"
cmd    = ["sops", "-d", "{file}"]
params = { file = '^[A-Za-z0-9_./-]+\.enc$' }
unmask = ["prod.key"]          # this task, and it alone, reads the key
output = true

[task.check-cert]
description = "Check a certificate's validity dates"
cmd    = ["openssl", "x509", "-noout", "-dates", "-in", "{cert}"]
params = { cert = '^certs/[A-Za-z0-9_.-]+\.pem$' }
unmask = ["certs/client.pem"]  # that one certificate, not the key, not the others

[task.fmt]
description = "Format the code"
cmd = ["cargo", "fmt"]
                               # no unmask: this task sees the masks like the agent does
```

The agent runs `sbx task run decrypt -p file=config/db.enc`, reads the result, and never
sees the key. `check-cert` shows the granularity: `unmask` is per **path**, so the same
task reads `certs/client.pem` and is refused `certs/server.pem`, both of which the one
`certs/*.pem` entry closed.

An `unmask` entry may only name a path `[fs] deny` already closed. One naming anything else
lifts nothing and is reported: it is an unmask, never a second `binds`. Like the rest of
`[task]`, it is honored only from a trusted source.

One rule to know: an `unmask` lifts a mask **whole**. A wildcard entry closes each matching file
separately, so one of them can be lifted on its own; a `deny` on a *directory* closes the directory
itself, so `unmask` has to name that directory to lift it, and naming a file inside lifts nothing.
If a task needs one file out of a directory you want closed, close the files rather than the
directory:

```toml
[fs]
deny = ["secrets/*"]           # each file closed separately...

[task.read-token]
cmd    = ["cat", "secrets/token"]
unmask = ["secrets/token"]     # ...so this one can be lifted alone
```

## Writing a mask

`sbx fs deny <path>` and `sbx fs readonly <path>` write the lists above, and
`sbx fs undeny` / `sbx fs unreadonly` take an entry back out:

```bash
sbx fs deny prod.key
sbx fs deny 'certs/*.pem'          # quote a glob so the shell does not expand it first
sbx fs readonly Cargo.lock
```

They write the project `.sbx.toml` by default, the global config with `-g`, and an app's table
with `-a <name>`; a project write re-trusts the file, on the terms
[`sbx fs deny`](../cli/fs#deny--readonly) states. Entries are lists, so the generic
`sbx config set` does not reach them: before these verbs the only way in was
[`sbx config edit`](../cli/config#sbx-config-edit), which is still how you rewrite several at once.

There is no `--session` form and no `sbx fs rules`, and both absences are the same fact: a mask is
a mount, resolved at launch, so there is no live overlay to load into or to list. The effective
masks are in `sbx config show`, below.

## Closing a path for one launch

A mask you want for a single run travels in the typed `--fs` flag, one entry per flag:

```bash
sbx run --fs deny=.env -- pytest
sbx run --fs deny=.env --fs readonly=Cargo.lock -- pytest
```

The side has to be named (`deny=` or `readonly=`) because the table holds two lists, and a bare
path could only be guessed into one of them. A value naming neither is refused rather than guessed.

`--fs` is the one typed flag that **accumulates** instead of last-wins: every other names a single
setting, while this one names an entry in a list that unions across every layer. So the flag adds
to whatever the config files already closed, `SBX_FS` carries one mask from the environment and the
two accumulate as well, and no spelling of any of them lifts a mask.

The `[fs]` table also travels in a [one-shot `--config` blob](overrides), which is how you set
`scan` or `scan_max_kb` for a single run:

```bash
sbx run --config '[fs]
deny = [".env"]' -- pytest
```

## Seeing what is closed

`sbx config show` lists the effective masks and which layer set them:

```
  fs deny: prod.key, certs/*.pem, secrets/  (closed to the cage; the name stays visible)  (project)
  fs readonly: Cargo.lock  (readable in the cage, not writable)  (project)
```

`sbx test fs <path>` answers the same question for one path, including a name that does not exist
yet under a denied directory. See [`sbx test`](../cli/test#sbx-test-fs).

### What the agent is told

The cage carries a generated contract at `/opt/sbx/egress-contract.md`, named by
`SBX_EGRESS_CONTRACT`, and the masks have a section in it. This is not a second enforcement point:
it exists because one of the three shapes is invisible from inside. A denied **file** keeps its
name and answers `EACCES`, so a process discovers it by trying; a **read-only** path refuses the
write, so a process discovers that too, though only after producing the bytes. A denied
**directory** lists **empty**, so trying teaches a process something false, and it acts on that
instead of on a refusal.

The section is shared with [`binds`](binds): a bind mounted read-only refuses a write the way a
read-only mask does, so the two are listed together, sorted, under one heading. Which table
closed a path is the host's business, while what a process needs to know is whether this path
takes a write.

The section therefore names the resolved paths and what each looks like from inside, never the
`[fs]` entries that produced them: a path's name is already visible in a listing, so naming it
discloses nothing new, while a pattern would describe files that do not exist. It also states its
own limits, so the list is not read as the whole of `[fs]`: a path nobody listed is covered by
neither a mask nor a configured read-only bind, and an open may still be refused by
[`scan`](#scan-closing-a-file-by-what-it-holds), whose shapes stay out of the document. The
read-only paths `sbx` mounts for itself (the control plane inside a writable bind, the task
output directory and client, the contract file) are not listed either, and the document says so
rather than let an unlisted path read as writable.

## Related

`[fs]` closes paths. Two neighbours do different jobs on the same subject:

- [`binds`](binds) **adds** host paths to the cage. It is the opposite direction, and it is
  trusted-only for that reason.
- [`sbx fs logs`](../cli/fs) **reports** what the agent wrote in the project. It observes;
  it closes nothing.
