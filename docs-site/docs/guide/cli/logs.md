# `sbx logs`

```
sbx logs [<id>] [--feed <a,b,...>] [-n <N>] [-f|--follow] [--json]
```

One running session's **seven feeds in one column of time**: what it execs, where it goes, what it
writes, what it asked your keys to sign, what its plugins decided and formed, and the declared
operations it invoked. `sbx log` is an accepted alias.

Most feeds are also readable on their own, and those views show more of their own detail. This one
answers the question none of them can on its own: **what happened in what order**. It is also the
only reader for the two plugin feeds, `broker` and `signer`.

See also: [The four lenses](../concepts/observability#the-four-lenses) · [`sbx proc`](proc) ·
[`sbx net`](net) · [`sbx fs`](fs) · [`sbx ssh-agent`](ssh-agent) · [`sbx task`](task).

## What it shows

```
$ sbx logs
feeds — session 4019373 [demo-app] ~/dev/demo-app
  recording: proc, net, fs
  ssh: no ssh-agent broker — this config has no `[ssh_agent] allow`
  broker: no broker plugin — this config has no `[broker.<name>]`
  signer: no signer plugin — no credential in this config declares `sign`
  task: no declared operations — this config has no `[task]`
  12:04:31  proc  observe   curl -s https://api.example.com
  12:04:31  net   deny      api.example.com:443  (no-rule)
  12:04:32  fs    write     ./retry.sh
  12:04:33  proc  observe   sh ./retry.sh
```

| Column | Meaning |
|---|---|
| time | local time of day of when the event happened |
| feed | which feed saw it: `proc`, `signer`, `net`, `fs`, `ssh`, `broker`, `task` |
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
| `signer` | `sign`, `refuse`: what `sbx` observed of one request's credential, with the plugin's own account appended |
| `task` | `exit=<n>`, or `refused` |

### The two plugin feeds

`broker` and `signer` carry text a plugin wrote, and they are framed so that what `sbx` observed
comes first and what the plugin claimed follows it. A plugin cannot make a refusal read as a
success by choosing its words, and on the `signer` feed the whole line is scrubbed of every
credential the launch declared before it is recorded:

```
$ sbx logs 4019373 --feed signer
feeds — session 4019373 [demo-app] ~/dev/demo-app
  recording: signer
  12:04:31  signer  sign      demo-sigv4: PUT s3.example.com/bucket/key set Authorization, X-Amz-Date — us-east-1 s3
  12:05:02  signer  refuse    demo-sigv4: GET s3.example.com/bucket — the plugin refused to sign: no credentials for that region
```

A `sign` line names the signer, the request it formed a credential for, and the header names it
put on it. The values are never shown. A `refuse` line is the request that was **not sent**: a
credential that could not be formed refuses the request rather than letting it leave unsigned, and
[`sbx net logs`](net#sbx-net-logs) records the same request as `blocked (signer-refused)`.

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
| `signer` | a [credential](../configuration/secret) declaring `sign = "<plugin>"` |
| `task` | a [`[task]`](../configuration/task) table declaring operations |

If none of them is recording, the command says so and exits non-zero rather than printing an empty
view that would read as a quiet session.

## Ordering

Rows are ordered by when each event **happened**, not by when it was recorded. That distinction
only bites in one place, and it is the reason a task invocation carries two stamps: an invocation's
record is written when it **ends**, so filing it there would put a slow operation after everything
that ran while it was still going. `sbx logs` places it where it **began**.

Two events that share a millisecond keep feed order, which puts what the agent reached for before
what was decided about it. That is why `signer` sits ahead of `net`: a request's credential is
formed before its verdict is recorded, so the pair reads as cause then effect even when both land
in the same millisecond.

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
