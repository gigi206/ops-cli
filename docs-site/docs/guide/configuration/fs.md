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

## What it does not cover

`[fs] deny` is **a reduction of exposure**, not a boundary of the same class as
[`[network] deny`](network). Egress is fail-closed: what is not allowed does not pass.
This is different, and it has three named holes:

1. **A second hard link.** A mask covers a *path*, not an inode. If another name in the
   project points at the same file, the content is readable through it. `sbx` warns at
   launch when a masked file has more than one link.
2. **A file that appears mid-session**, outside a denied directory. The masks are resolved
   at launch; a file created afterwards matching a file pattern is not covered. A denied
   directory does not have this hole.
3. **A path nobody listed.** There is no allowlist form: what you did not name is open.

The cage cannot open any of these itself: it cannot create a hard link across a mask, and
it cannot write a file into a denied directory. They are ways the *host side* can leave a
path open, which is why they are worth knowing rather than worth panicking about.

The second one is structural rather than an omission. A mask is a mount, and a cage's mounts
are fixed when it is built, so a pattern cannot cover a name that did not exist yet. There are
only two ways around it, and both are already here: **name the directory**, which closes it
whatever appears inside, or **relaunch** the session after adding a secret the pattern should
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
