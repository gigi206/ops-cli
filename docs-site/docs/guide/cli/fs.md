---
description: "Observe the files a running sandbox writes in its project tree, and close project paths off inside the cage."
---

# `sbx fs`

```
sbx fs logs       [<id>] [-f|--follow] [--json]
sbx fs deny       <path> [-l|--local|-g|--global] [-a|--app <name>]
sbx fs undeny     <path> [-l|--local|-g|--global] [-a|--app <name>]
sbx fs readonly   <path> [-l|--local|-g|--global] [-a|--app <name>]
sbx fs unreadonly <path> [-l|--local|-g|--global] [-a|--app <name>]
```

The filesystem lens of a running session, sibling of [`sbx proc`](proc) (processes) and
[`sbx net`](net) (egress), and the verbs that write its policy.

`sbx fs logs` is the **file-write feed**: the files the agent creates, writes, deletes, or moves,
in order, for a session started with observation on
([`sbx run --observe`](run#observing-a-run---observe)). It reports what the agent wrote.

The other four write the [`[fs]` config table](../configuration/fs), which decides what the agent
can **read**: `deny` closes a project path inside the cage, `readonly` leaves it readable and
refuses writes, and each has the inverse spelled after it.

See also: [The four lenses](../concepts/observability#the-four-lenses) · [`sbx proc`](proc) · [`sbx net`](net) · [`sbx session`](session).

## `deny` / `readonly`

```
sbx fs deny     <path> [-l|--local|-g|--global] [-a|--app <name>]
sbx fs readonly <path> [-l|--local|-g|--global] [-a|--app <name>]
```

Persist a path mask to a config file's [`[fs]`](../configuration/fs) `deny`/`readonly` list.
`deny` closes the path to the cage: the name stays visible, opening it is refused, and a denied
directory reads empty. `readonly` keeps the real content readable and refuses writes. Both mask by
mounting over the path **inside the cage**, so the host file is never modified, moved, or copied.

| Operand / option | Meaning |
|---|---|
| `<path>` | a project-relative path or glob (`prod.key`, `certs/*.pem`, `secrets/`). A trailing `/` names a directory, which closes whatever appears inside it later |
| `-l`, `--local` | write the project `.sbx.toml` (the default) |
| `-g`, `--global` | write the global `sbx.toml`, or the app's profile when `-a` names one |
| `-a`, `--app <name>` | write the mask under that app's `[app.<name>.fs]` |

```sh
sbx fs deny prod.key               # fresh project: writes [fs] deny = ["prod.key"]
sbx fs deny 'certs/*.pem'          # quote a glob so the shell does not expand it first
sbx fs readonly Cargo.lock         # readable, not writable
sbx fs deny .env -a claude-code    # under that app's [app.claude-code.fs]
```

There is **no posture to bootstrap**, unlike [`sbx proc deny`](proc#allow--deny): `[fs]` carries no
mode, so writing a mask cannot leave another field meaning something else, and no mask is ever
inert.

Writing the project `.sbx.toml` **re-trusts** it (it must be absent or already trusted first), so
the mask takes effect on the next launch; the global config and app profiles are trusted by
location. That gate is about the re-trust and not about the mask: a project trust marker covers the
whole file, so blessing it for one appended line would also bless the `binds` and `network` beside
it. `[fs]` itself is honored from an untrusted project, because a mask can only take access away.

### There is no `--session` form, and no `rules`

Both absences are structural rather than omissions, and they are the same fact twice.

A mask is a **mount**, and a cage's mounts are fixed when it is built. `[fs]` resolves at launch, so
there is no live overlay to load a mask into the way
[`sbx proc deny --session`](proc#--session-load-a-rule-into-a-running-session) does, and nothing for
a `rules` verb to list: what its two siblings' `rules` shows is exactly that overlay. The effective
masks and the layer each came from are already in [`sbx config show`](config#show).

To close a path in a session that is already running, add the mask and relaunch. To cover a file
that appears or changes **mid-session**, reach for
[`[fs] scan`](../configuration/fs#scan-closing-a-file-by-what-it-holds) instead, which asks at every
open rather than at launch.

## `undeny` / `unreadonly`

```
sbx fs undeny     <path> [-l|--local|-g|--global] [-a|--app <name>]
sbx fs unreadonly <path> [-l|--local|-g|--global] [-a|--app <name>]
```

Remove a mask added by its namesake, so an entry is undone with the vocabulary it was written in.
The `<path>` is an **exact-string** match of what was written, as
[`sbx config show`](config#show) lists it. Idempotent: removing an entry that is not there is a
reported no-op, not an error. The two do not reach each other's list.

```sh
sbx fs undeny prod.key             # the cage can read it again from the next launch
sbx fs unreadonly Cargo.lock       # writable again
```

This is the removal that **widens what the cage can read**, and it widens only within the layer it
edits. Masks union across layers and no layer can undo one below it, so taking an entry out of the
project config leaves a global or app entry for the same path in force.

## `logs`

```
sbx fs logs [<id>] [-f|--follow] [--json]
```

The **file-write feed**, each change the agent makes in its project tree, in order, stamped with
the time it was seen. `sbx fs log` is an accepted alias. The change kinds are:

| Kind | Meaning |
|---|---|
| `write` | a file was written and closed (the primary "the agent wrote this") |
| `create` | a file or directory appeared (created, or moved in) |
| `remove` | a file or directory was deleted |
| `rename` | a path was moved out |

It is observed **host-side with inotify**: the cage binds the project read-write at its own host
path, so a write the agent makes lands on the same host inode `sbx` watches, visible across the
mount namespace with **no privilege and no cooperation from the cage**. Because it reads a recorded
event stream, the session must have been launched with **observation on**:
[`sbx run --observe`](run#observing-a-run---observe) or
[`sbx app run <name> --observe`](app): the same `--observe` that feeds
[`sbx proc logs`](proc#logs). A session without it is reported as *unobserved*, not shown empty.

| Operand / option | Meaning |
|---|---|
| `<id>` | a session PID, live or finished; omit it to use the sole live session, or to list this project's finished ones |
| `-f`, `--follow` | stream new events until the session ends (`Ctrl-C` to stop) |
| `--json` | emit one object per event (NDJSON): works in a pipe |

```sh
sbx run --detach --observe -- claude   # a background agent, observed
sbx fs logs 12345 -f                    # …watch what it writes, from here
# file-write feed — session 12345 [run] /home/me/web
#   14:02:12  write   src/main.rs
#   14:02:13  create  src/new_module.rs
#   14:02:15  remove  scratch.txt

sbx fs logs 12345 --json | jq .path     # machine-readable
```

This is the way to watch an observed session **from another terminal**, and, like
[`sbx proc logs`](proc#logs), the **only** way to watch a [detached](run) (`--detach`) one.
The events are held in the supervisor's memory for the session's lifetime (the last 1000),
read over a per-session
control socket that is never exposed inside the cage; nothing is written to disk or kept after the
session exits.

### Examples

Each event is `{session_pid, seq, at_epoch_ms, kind, path}`, so the feed answers
questions a scrollback cannot:

```sh
sbx fs logs -f                                   # the only live session, streamed
sbx fs logs 12345                                # what it has written so far
sbx fs logs 12345 --json | jq -r 'select(.kind=="remove") | .path'   # what it deleted
sbx fs logs 12345 --json | jq -r .path | sort -u                     # every file touched
sbx fs logs 12345 --json | jq -r 'select(.path|test("^src/")) | "\(.kind)\t\(.path)"'
sbx fs logs 12345 --json > run.ndjson &          # keep a record; nothing is written to disk otherwise
```

The four lenses share one session id, so they compose into a single account of what a
run did:

```sh
sbx run --detach --observe -- claude    # prints the session id
sbx fs logs   12345 -f                  # what it wrote
sbx proc logs 12345 -f                  # what it executed
sbx net logs        -f                  # where it went
```

Watching a **detached** session is exactly what these are for: it has no terminal, so
the feed is the only account of it.

### Scope

Only the **project tree** is watched: the writes you care about. Deliberately excluded:

- the per-project **nix store** and the **app home**, as provisioning/state noise;
- **build/VCS/vendor trees**, `.git`, `node_modules`, `target`, `.venv`, the way
  [`sbx proc`](proc) filters `bwrap`/`systemd-run` plumbing (a single `git commit` writes hundreds
  of internal objects, and these machine-managed trees are huge and not the agent's authored work;
  filtering them also keeps the launch fast, since the initial watch install walks the tree);
- the cage's **`/tmp`**, which is a private tmpfs: structurally invisible to the host, so it cannot
  be watched at all.

Honest limits:

- inotify reports a completed write-and-close, not each in-progress write, and if the project tree is
  very large the kernel's watch limit (`fs.inotify.max_user_watches`) can be reached: either is
  surfaced with a one-time warning rather than hidden.
- The filtered trees are an **observation blind spot**, not just noise: because the cage runs an
  untrusted agent, anything it writes under `.git`, `node_modules`, `target`, or `.venv` is not shown.
  They are filtered because they would flood the feed and slow the launch. The cage is still the
  boundary while the session runs, so this is visibility rather than enforcement, but the gap has a
  sharp edge: a hook the agent leaves in `.git/hooks/` is run by your next `commit`, outside the cage,
  and this feed will not have shown it. See [where the protection
  stops](../concepts/security-model#where-the-protection-stops), which names the `[fs]` entry that
  closes that one.
- A **directory renamed** while the session runs keeps its old path in the feed for later writes
  under it: the event still fires, only its reported path can be stale.
- The feed watches the **project tree on disk**, so it reports every writer to it: if two sessions
  share one project, each also sees the other's writes. For the intended single-agent run this is
  exactly "what the agent wrote".

The feed observes; it never blocks. What a cage may **not** write is decided by its mount set and
by [`[fs]`](../configuration/fs), not here.
