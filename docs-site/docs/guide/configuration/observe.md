---
sidebar_label: "[observe]"
description: "Keeping what a lens saw after the session that saw it has ended."
---

# `[observe]`: keeping what a lens saw

```toml
[observe]
record = true            # keep each lens's session record on disk (default: false)
```

See also: [`[proc]`](proc) · [`[fs]`](fs) · [`[ssh_agent]`](ssh-agent) ·
[`[broker.<name>]`](broker) · [Redaction](../secrets/redaction)

Every observation lens records into a bounded ring in the supervisor's memory. That ring answers
"what is this agent doing right now", which is what `sbx proc logs`, `sbx fs logs` and
`sbx ssh-agent logs` read while a session runs. It cannot answer "what did it do yesterday": the
ring dies with the session.

`record = true` adds the second answer. Each lens also appends its events to a file under the data
directory, in the same directory as the socket that serves the live view, so a session that has
ended still has a record.

## What is written, and where

One file per feed per session, named `record-<pid>-<incarnation>.log` under that feed's own
directory (`proc/`, `fs/`, `ssh-agent/`, `broker/`, `signer/`, `egress/`, `tasks/`). It opens with the project and app
the session ran for, then carries one line per event, in the order the events happened. The lines
are the ones the live view already shows.

The file is mode `0600` inside a `0700` directory, and that directory is **never** bound into the
cage. This is the property the record rests on: not that events are unwritten, but that the
recorded party cannot reach the record. An agent under `enforce` can no more read its own exec
record than it can read the live ring behind the control socket.

## Reading one back

`sbx proc logs`, `sbx fs logs`, `sbx ssh-agent logs` and the merged `sbx logs` read a finished
session from its record with no extra flag. Which source answers is decided by whether the session
is still running: while it runs, its ring holds what its record does and what has not reached the
disk yet, so the socket is read; once it is gone, the file is.

A finished session is no longer in `sbx session ls`, and a foreground `sbx run` never printed its
PID, so with none of this project's sessions live these views **list its records** with their dates,
and one can be named:

```
sbx: proc logs: no live session in this project — 2 finished session(s) recorded here:
       148820  2026-09-09
       147311  2026-09-08
     read one with `sbx proc logs <id>`.
```

Only this project's records are listed or resolved. The data directory holds every project's, and
the same user owns them all, so this is not a boundary: it is that a view of "this project's
sessions" has no business naming a neighbouring project's paths.

The same scope decides which **live** session answers when no PID is given: another project's is not
it, or the listing above would be out of reach on any machine where something else is running. A PID
given explicitly is answered whichever project's session it is, because `sbx session ls` shows every
live session with its project beside it, so that is one you were shown and chose.

`--follow` on a finished session says there is nothing writing the record any more and shows it
once. A record that hit the size cap says its last events are missing, the way a live view says how
many events fell off the ring. A PID the kernel wrapped round onto names more than one record; the
newest is shown, and the view says that a choice was made.

`sbx logs` looks a session up across **every** feed's records, not just one: a launch with a broker
and no `--observe` writes a broker record and no exec record, and resolving on a single feed would
make that session unnameable.

### The two feeds that are not lenses

The **egress plane** is the one feed that revises what it already said: a request's upstream status
arrives after the decision was recorded, and an append-only file cannot rewrite the line it landed
on. It writes a second `amend` line instead, which the reader replays onto the event it names; a
credential noticed crossing an open tunnel is written the same way, the moment it is noticed. The
traffic capture is not in the record: it lives in its own store and stays there.

A **muted** refusal (`mute`, the `dontaudit` rule) is counted and never written. In memory a muted
flood is kept in a ring of its own so it cannot evict a real event; on disk it would evict nothing
and fill instead, truncating the end of the session. `sbx net stats` keeps its counters either way,
which is the contract `mute` already had.

`sbx net logs` is a **live, multi-session** view and is unchanged: it globs the sessions that are
running. A finished session's egress record is read through `sbx logs <id>`.

The **task plane** is the simple case: an invocation is recorded once, when it finishes, and nothing
ever revises it. `sbx task logs` is the live view, like `sbx net logs`: it reads the planes of a
running session, so a finished one's invocations are read through `sbx logs <id>` as well.

## Discarding one

There is no verb for it. A record lives at `<data>/<dir>/record-<pid>-<incarnation>.log` (`sbx
storage status` prints where `<data>` is), and `rm` on that path is the way. The directory is the
feed's own, and two of them are not named after the feed: `proc/`, `fs/`, `ssh-agent/`, `broker/`,
`signer/`, then `egress/` for `net` and `tasks/` for `task`. `sbx gc` deliberately
leaves records alone: a sweep keyed on liveness would delete one at the moment it became the only
answer left.

## Why it is off by default

Two reasons, and the first is about credentials.

The process lens records the cage's own command lines. A secret passed as an argument is in one,
and in memory that secret died when the session did. On disk it does not, so every line is
substituted against the credentials this launch knows before it is written: a value the launch
resolved appears as `${NAME}`, never as itself.

That substitution is against what is known **at the moment of the write**. A credential the launch
resolves later cannot reach back into a line already on disk. The window is small (secrets are
resolved as the egress proxy starts, before an agent runs) but it is real, and it is the reason
keeping the record is a choice rather than the default meaning of `observe`.

The second reason is the disk. A session's record stops at 4 MiB and ends with a `truncated=` line
saying so, which a busy egress session reaches sooner than a quiet one; a feed's directory keeps the
32 most recent finished sessions and drops the rest when a
new session opens its own. A running session's record is never dropped, whatever its age.
`sbx gc` does not sweep records: a sweep keyed on liveness would delete a record at the moment it
became the only answer left.

## Layering and trust

A security field. Honored from the global config or a **trusted** project, and dropped with a
warning from an untrusted one: whether an agent's command lines are kept on the owner's disk is
not a decision a project that sbx does not trust gets to make.

Baseline-only, like [`[redact]`](../secrets/redaction#the-length-floor). The record is a property
of the session, so an `[app.<name>]` profile does not carry one.

`sbx config` shows the setting only when a layer stated it, with the layer that did.
