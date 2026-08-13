# `sbx logs`

```
sbx logs [<id>] [--feed <a,b,...>] [-n <N>] [-f|--follow] [--json]
```

One running session's **six feeds in one column of time**: what it execs, where it goes, what it
writes, what it asked your keys to sign, and the declared operations it invoked. `sbx log` is an
accepted alias.

Each feed is also readable on its own, and those views show more of their own detail. This one
answers the question none of them can on its own: **what happened in what order**.

See also: [The four lenses](../concepts/observability#the-four-lenses) · [`sbx proc`](proc) ·
[`sbx net`](net) · [`sbx fs`](fs) · [`sbx ssh-agent`](ssh-agent) · [`sbx task`](task).

## What it shows

```
$ sbx logs
feeds — session 4019373 [demo-app] ~/dev/demo-app
  recording: proc, net, fs
  ssh: no ssh-agent broker — this config has no `[ssh_agent] allow`
  task: no declared operations — this config has no `[task]`

  12:04:31.204  proc  observe   curl -s https://api.example.com
  12:04:31.887  net   deny      api.example.com:443  (no-rule)
  12:04:32.019  fs    write     ./retry.sh
  12:04:33.550  proc  observe   sh ./retry.sh
```

| Column | Meaning |
|---|---|
| time | local time of day, to the millisecond, of when the event happened |
| feed | which feed saw it: `proc`, `net`, `fs`, `ssh`, `broker`, `task` |
| token | that feed's own verdict or kind, unchanged |
| subject | that feed's own free-text field: a command, a host, a path, a key, an operation |

The tokens are each feed's own, not a vocabulary invented here:

| Feed | Tokens |
|---|---|
| `proc` | `allow`, `deny`, `ask` under enforcement; `observe` for the poll observer, which records what ran rather than a decision |
| `net` | `allow`, `deny`, `blocked`, `error` |
| `fs` | `write`, `create`, `remove`, `rename` |
| `ssh` | `list`, `sign`, `refuse` |
| `broker` | `forward`, `answer`, `refuse`: what `sbx` observed, with the plugin's own reason appended |
| `task` | `exit=<n>`, or `refused` |

## A feed that is not recording says so

The lines above the events are the point of this view. A feed nothing stood up and a feed with
nothing to say both come back empty, and only that line tells them apart.

Most sessions record two or three. Each feed needs something to have been decided at launch:

| Feed | Needs |
|---|---|
| `proc`, `fs` | observation on: [`sbx run --observe`](run#observing-a-run---observe) |
| `net` | a filtering [`[network] mode`](../configuration/network) (`deny`, `allow` or `ask`) |
| `ssh` | an [`[ssh_agent] allow`](../configuration/ssh-agent) grant |
| `broker` | a [`[broker.<name>]`](../configuration/broker) binding that started |
| `task` | a [`[task]`](../configuration/task) table declaring operations |

If none of them is recording, the command says so and exits non-zero rather than printing an empty
view that would read as a quiet session.

## Ordering

Rows are ordered by when each event **happened**, not by when it was recorded. That distinction
only bites in one place, and it is the reason a task invocation carries two stamps: an invocation's
record is written when it **ends**, so filing it there would put a slow operation after everything
that ran while it was still going. `sbx logs` places it where it **began**.

Two events that share a millisecond keep feed order, which puts what the agent reached for before
what was decided about it.

## Flags

```
sbx logs 4019373 --feed net,proc     # only those two feeds
sbx logs -n 50                       # the last 50 events across all feeds
sbx logs -f                          # follow until the last feed ends
sbx logs --json | jq 'select(.feed == "net")'
```

`--feed` takes a comma-separated list. A name no feed answers to is an error, not a silently
narrower view: reading absence as quiet is exactly the failure this command exists to prevent.

`--follow` polls every live feed past its own cursor and returns when the last one ends. The feeds
are independent, so one ending is not the session ending.

`--json` emits one object per line (NDJSON), each with a `feed` field:

```json
{"session_pid":4019373,"at_epoch_ms":1786539871204,"feed":"net","token":"deny","subject":"api.example.com:443  (no-rule)"}
```

## What this is not

`sbx logs` is not [`sbx session logs`](session#logs). That one reads the agent's own stdout and
stderr, held on disk for a detached session. This one reads what **sbx observed** about the agent,
which lives in the supervisor's memory and is gone when the session exits.

> **Note.** If a run needs a durable record of what it did, pipe `sbx logs --json` to a file while
> it runs. Nothing here is written to disk.

Host-side and read-only. It stands nothing up, and reaches the same owner-only control sockets the
per-feed verbs use. None of those is ever bound into the cage, so what is recorded here is out of
reach of what is being recorded.
