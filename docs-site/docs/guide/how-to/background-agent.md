---
sidebar_label: "Background agent"
description: "Launch an agent detached, read its four observation feeds, step inside the live cage, and end it."
---

# Run an agent in the background and check on it

An autonomous agent that runs for an hour should not hold a terminal for an hour. This
recipe launches one detached, then uses the four observation surfaces to answer the
only questions that matter while it works: is it alive, what is it saying, what is it
doing, and where is it going.

Everything here reads a **live** session. The model is [Sessions](../housekeeping/sessions);
the flags are [`sbx session`](../cli/session).

## 1. Launch it detached, with observation on

```sh
sbx app run claude-code --detach --observe
```

`--detach` registers a background session and prints its id; `--observe` turns on the
process and filesystem lenses, which cost nothing when nobody reads them but cannot be
switched on later. If you forget it, the session still runs: you simply get output and
egress, not exec and writes.

## 2. Find it again

```sh
sbx session ls          # the live sessions; app sessions show their app name
```

The id is the PID that listing shows. The registry is daemonless and validated on read,
so a crashed session prunes itself rather than lingering as a stale row.

## 3. Watch the four feeds

```sh
sbx session logs <id> -f     # what it printed
sbx proc    logs <id> -f     # what it executed        (needs --observe)
sbx fs      logs <id> -f     # what it wrote           (needs --observe)
sbx net     logs -f          # where it went
```

One distinction is worth internalising before you rely on it: `session logs` reads what
the agent *printed*, and that survives on disk for a detached session. The other three
read what it *did*, and they live in the supervisor's memory: when the session exits,
they are gone. If a run needs a durable record of its actions, pipe a `--json` feed to
a file while it is still running.

## 4. Look inside, without widening anything

```sh
sbx session attach <id>              # a shell inside the live cage
sbx session attach <id> -- ps aux    # …or one question, answered
```

`attach` joins the running cage's namespaces and re-applies its confinement, so the
shell you get is never a wider hole than the agent it joins.

## 5. End it

```sh
sbx session stop <id>                # SIGTERM, then SIGKILL after the grace delay
sbx session stop --all --delay 3     # everything, interactive shells included
sbx gc --all --prune                 # …then reclaim what the runs left behind
```

## Where to go next

- [Run an agent on an untrusted project, safely](run-agent-safely): the posture to
  launch it with in the first place.
- [Egress observability](../networking/observability): which network surface answers
  which question.
- [Garbage collection](../housekeeping/gc): what `--prune` actually reclaims.
