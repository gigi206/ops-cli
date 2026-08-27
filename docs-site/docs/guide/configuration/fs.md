---
sidebar_label: "[fs]"
description: "Closing a project path off inside the cage: the one field that applies from an untrusted source, because it only takes away."
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
readonly = ["Cargo.lock", ".git/config"]
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

`[fs]` is the one table honored from **any** source, an untrusted project included. Every
other security field can grant something, so an untrusted project may not set it; this one
can only take access away from the cage the project itself declares, and there is no
syntax for reopening anything. Layers **union**: a project adds to what the global config
closed, an app adds to what the project closed, and no layer can undo one below it.

See also: [Declared operations](../tasks/) · [`binds`](binds) · [The trust gate](../concepts/trust) · [Enforcement stack](../concepts/enforcement)

## `deny` and `readonly`

| | What the cage sees | What it is for |
|---|---|---|
| `deny` on a file | the name, and `EACCES` on open. `stat` reports size 0 and mode 000 | a key, a token, a `.env` |
| `deny` on a directory | an empty directory; everything inside is `ENOENT` | a whole `secrets/` tree |
| `readonly` | the real content, and `EROFS` on write | a lockfile, `.git/config`, a generated file |

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
every `git add` and `git commit` fail. Naming the files you actually mean (`.git/config`,
`.git/hooks`) does what you want and leaves committing alone.

Those two are worth setting even when nothing in the project is secret, and for a different
reason than the rest of this page: they are what stops an agent from leaving a hook that your
next `commit` runs on the host, outside any cage. See [where the protection
stops](../concepts/security-model#where-the-protection-stops).

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
  [`binds`](binds), a trusted field with its own gate. `[fs]` is honored from any source, so
  letting it name a path outside the project would make it a second way to reach one.
- **A `..` component is refused**, and so is a path that resolves outside the project through
  a symlink.
- **A trailing `/` means "this is a directory"**, and an entry that ends in one but names a
  file is refused rather than guessed at.
- **An entry matching nothing is a warning**, never a failed launch: a profile may name a
  file only some checkouts carry.
- **An entry whose path cannot be read at all refuses the launch.** Matching nothing and being
  unable to look are different answers, and only one of them is safe to run past. The cage runs
  as your uid in a project bound read-write, so a directory it closed off in an earlier session
  would otherwise make every entry naming a path below it expand to nothing, closing nothing.
  `sbx` names the entry and stops, the way it stops past the mask ceiling.
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
bigger number closes more files, and `[fs]` is honoured from an untrusted project precisely because
nothing in it can widen what another layer closed.

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

Every open a cage makes is answered this way, not only the ones under your project and not only the
ones that hold a file. That breadth is the point rather than thoroughness for its own sake: the cage
chooses what its path names **first**, so any shape `sbx` could not answer for would be the shape to
name. A pipe, a device and a socket are each served or replied to on their own terms, and a path
that is not there is answered with the same error the cage would have received, rather than being
looked up a second time once something has been moved into place behind it.

Two gaps are left. The first is not one a cage can arrange: a kernel older than 5.9 does not offer
the operation at all, and there `scan` behaves as it did before, swap included. That fallback is not
silent. The first allowed open the kernel declines to serve this way prints a warning naming the
missing operation, once for the session, so a weaker `scan` is something you are told about rather
than something you have to infer from a kernel version.

The second one a cage can arrange, and it costs less than it reads. An `openat2` may ask for a
stricter walk than the one the scan performed (`RESOLVE_NO_SYMLINKS`, `RESOLVE_BENEATH` and
`RESOLVE_IN_ROOT`), and the descriptor `sbx` holds was resolved with symlinks followed on purpose,
since a scan that stopped at a link would be walked around with one `ln -s`. Serving from it would
hand such a caller the resolution its own flags were meant to refuse, so that open is declined
rather than served: the real `openat2` runs, with the real `resolve` semantics, and with it the
second walk a sibling thread is free to redirect. What is lost is the handover, not the verdict.
The scan judged the target the path resolved to, and only an open it allowed reaches this point, so
a cage that reissues its opens this way buys back the redirect window it would have had without
`scan` at all, and nothing beyond it.

Those three are the whole of it, and the rest of the `resolve` word is not a way in. The bits that
only restrict how the walk runs (`RESOLVE_NO_XDEV`, `RESOLVE_NO_MAGICLINKS`, `RESOLVE_CACHED`) are
served from the scanned descriptor like any other open, because declining on them would let a cage
take every allowed open off the handover by asking for one harmless-looking flag. A `resolve` bit
`sbx` does not know is declined as well, since the kernel refuses an unknown one with `EINVAL` and
there is then no syscall for a served descriptor to be the answer to.

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

## Closing a path for one launch

`[fs]` has no typed flag of its own, so a mask you want for a single run travels in a
[one-shot `--config` blob](overrides):

```bash
sbx run --config '[fs]
deny = [".env"]' -- pytest
```

It unions with whatever the config files already closed, exactly like a layer: the blob adds a
mask for this launch, and no spelling of it lifts one. `SBX_CONFIG` carries the same blob from
the environment.

## Seeing what is closed

`sbx config show` lists the effective masks and which layer set them:

```
  fs deny: prod.key, certs/*.pem, secrets/  (closed to the cage; the name stays visible)  (project)
  fs readonly: Cargo.lock  (readable in the cage, not writable)  (project)
```

## Related

`[fs]` closes paths. Two neighbours do different jobs on the same subject:

- [`binds`](binds) **adds** host paths to the cage. It is the opposite direction, and it is
  trusted-only for that reason.
- [`sbx fs logs`](../cli/fs) **reports** what the agent wrote in the project. It observes;
  it closes nothing.
