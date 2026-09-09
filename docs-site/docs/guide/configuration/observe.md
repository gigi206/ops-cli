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

One file per lens per session, named `record-<pid>-<incarnation>.log` under that lens's own
directory (`proc/`, `fs/`, `ssh-agent/`, `broker/`, `signer/`). It opens with the project and app
the session ran for, then carries one line per event, in the order the events happened. The lines
are the ones the live view already shows.

The file is mode `0600` inside a `0700` directory, and that directory is **never** bound into the
cage. This is the property the record rests on: not that events are unwritten, but that the
recorded party cannot reach the record. An agent under `enforce` can no more read its own exec
record than it can read the live ring behind the control socket.

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
saying so; a lens directory keeps the 32 most recent finished sessions and drops the rest when a
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
