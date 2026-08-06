# `sbx ssh-agent`

```
sbx ssh-agent logs [<id>] [-f|--follow] [--json]
```

What a running sandbox asked your **ssh keys** to sign: the credential lens of a session, sibling
of [`sbx net`](net) (egress), [`sbx fs`](fs) (files) and [`sbx proc`](proc) (processes).

A cage granted a key with [`[ssh_agent] allow`](../configuration/ssh-agent) never holds it: it
asks a **filtering broker**, which asks your own agent. `sbx ssh-agent logs` is the record of those
asks.

See also: [The four lenses](../concepts/observability#the-four-lenses) · [`[ssh_agent]`](../configuration/ssh-agent) · [`sbx session`](session) ·
[`sbx net`](net).

## `logs`

```
sbx ssh-agent logs [<id>] [-f|--follow] [--json]
```

One line per decision the broker made, in order, stamped with the time it was made.
`sbx ssh-agent log` is an accepted alias.

| Kind | Meaning |
|---|---|
| `list` | which granted keys were offered to the cage, and how many were withheld |
| `sign` | a signature was produced: with which key, and toward which server |
| `refuse` | a request was turned away, and why |

| Operand / option | Meaning |
|---|---|
| `<id>` | the PID [`sbx session ls`](session) shows; omit it when only one session is live |
| `-f`, `--follow` | stream new decisions until the session ends (`Ctrl-C` to stop) |
| `--json` | emit one object per event (NDJSON): works in a pipe |

```sh
sbx run --detach -- claude              # a background agent with a granted key
sbx ssh-agent logs 12345 -f             # …watch what it signs, from here
# ssh-agent feed — session 12345 [run] /home/me/web
#   14:02:11  list     offered deploy@example (5 withheld)
#   14:02:11  sign     deploy@example toward the server holding SHA256:nThbg6kXUp…
#   14:07:45  refuse   an attempt to remove every key from your agent
#   14:09:02  refuse   a signature with a key the grant does not name

sbx ssh-agent logs 12345 --json | jq 'select(.kind=="sign")'
```

### Examples

The feed only exists once a grant does, so the two halves belong together. Name the key
by either spelling `ssh-add -l` prints, in a trusted config:

```toml
[ssh_agent]
allow   = ["deploy@example"]   # or its SHA256:… fingerprint
confirm = true                 # ask, on the host, before every signature
```

```sh
ssh-add -l                              # what your agent holds, and how to name it
sbx run --detach -- claude              # launch: sbx prints which keys the cage may use
sbx ssh-agent logs 12345 -f             # every ask, as it happens
```

Then the questions the record answers:

```sh
sbx ssh-agent logs 12345 --json | jq 'select(.kind=="sign")'      # what was signed
sbx ssh-agent logs 12345 --json | jq 'select(.kind=="refuse")'    # what was turned away
sbx ssh-agent logs 12345 --json | jq -r 'select(.kind=="sign") | .at_epoch_ms' | wc -l
sbx ssh-agent logs                                                # the sole live session
```

A `refuse` line is not an incident by itself: an ssh client routinely offers keys it does
not end up using. What is worth reading is a refusal naming a key the grant does not
include, or an attempt to *modify* your agent, both of which mean something in the cage
tried more than signing.

Two states read differently, on purpose: a session whose config grants no key has **no
broker at all** and says so, which is distinct from a broker that was simply never asked
for anything.

### The destination, and what it is worth

A signature request names a key and a session: never a host. That is the broker's structural blind
spot: it can bound *which key* and *which operation*, not *where the signature is spent*.

The record narrows it anyway. An ssh client binds its agent connection to the **server's host key**
before asking for a signature (that is the mechanism an `ssh-add -h` constraint is enforced
through), so a signature is recorded `toward the server holding SHA256:…`: the same spelling
[`known_hosts`](../configuration/ssh-agent) and `ssh-keyscan` use, so you can match it to a host.

It is what the **client said**, not something sbx verified, and a client that never binds simply
yields a signature line with no destination on it. Read it as evidence, not as a fence.

### Where it lives

The feed is held in the launcher's memory for the session's lifetime and read over a per-session
control socket under the data directory that is **never bound into the cage**: so the agent can
neither read the record of what it asked for nor amend it. Nothing is written to disk, and nothing
is kept after the session exits: this answers *what has this session done*, not *what did last
week's session do*.

A session whose config grants no key has **no broker at all**, and is reported as such: distinct
from a broker that has been asked for nothing.
