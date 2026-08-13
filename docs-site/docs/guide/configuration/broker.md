# `[broker]`: putting a plugin in front of a host resource

`[ssh_agent]` fences one protocol with code `sbx` ships. `[broker.<name>]` does the same
for a protocol it does not implement, by putting an installed
[broker plugin](../secrets/plugins#the-broker-type) between the cage and a host socket.

```toml
# global config only: which host resource is being brokered
[broker.gpg-agent]
socket = "$XDG_RUNTIME_DIR/gnupg/S.gpg-agent"
```

```toml
# .sbx.toml, trusted project: the policy that resource is brokered under
[broker.gpg-agent]
allow = ["sign"]
```

The cage never receives the host socket. `sbx` serves a socket of its own, connects to the
host resource itself, cuts the byte stream into messages, and asks the plugin about each
one. The plugin answers a verdict and holds nothing: no listening socket, no network, no
access to the resource. What it can grant is therefore bounded by what binding the host
socket into the cage would have granted, and it exists to grant far less.

See also: [Broker plugins](../secrets/plugins#the-broker-type) ·
[`[ssh_agent]`](ssh-agent) · [The trust gate](../concepts/trust) ·
[Secrets](../secrets/).

## The host resource: a Unix socket, or a TCP endpoint

```toml
[broker.gpg-agent]
socket = "$XDG_RUNTIME_DIR/gnupg/S.gpg-agent"   # a socket on this machine

[broker.pg]
socket = "tcp://db.internal:5432"               # an endpoint, subject to the allowlist
```

A Unix socket is a resource of this machine. A **TCP endpoint is a way out of the cage**, so
it is admitted only where [`[network]`](network) already admits it: `sbx` asks the very
function the filtering proxy and `sbx test net` decide through, so the three cannot drift
apart. A broker pointed at an endpoint the allowlist does not carry is not started, and the
message names the rule to add.

Without that rule there would be two different answers to *where may this cage go*, and the
one a reader checks would not be the one that decides.

The cage still reaches nothing itself: it connects to a socket `sbx` serves, and `sbx` opens
the connection on the host side. The empty network namespace is untouched.

## Why the table is split across two layers

The two halves answer different questions, and they are gated differently on purpose.

| Key | Answers | Read from |
|---|---|---|
| `socket` | *which host resource is exposed* | the **global** config only |
| `allow` | *what may be done with it* | the global config, or a **trusted** project |

`socket` is a fact about the machine, and pointing a broker at a different one changes what
is being brokered. That decision belongs beside the plugin's installation, not inside a
project tree, so a `socket` written in a project config is dropped and named. A project
also cannot introduce a broker the global config never bound: naming `[broker.x]` with no
global `[broker.x] socket` is reported and nothing is started.

`allow` is handed to the plugin verbatim at the start of every connection. `sbx` does not
interpret it: what an entry means belongs to the protocol the plugin speaks, exactly as
`[ssh_agent] allow` names keys rather than describing them. An **untrusted** project's
whole `[broker.*]` section is dropped with a warning naming it, so "not configured" and
"not trusted" never look alike.

## What happens when something is missing

Every one of these degrades to **no broker**, and says so. A cage without a broker cannot
reach that resource, which is the safe direction; a broker started against the wrong thing
is one pointed somewhere nobody chose.

- **No installed plugin of that name.** Reported with the remedy (`sbx plugins install`).
  A name claimed by more than one installed plugin is reported differently, because the
  remedy differs: remove all but one.
- **The socket does not exist.** Checked before anything is stood up. A broker in front of
  nothing would accept the cage's connections and fail every message, which reads as the
  resource misbehaving rather than as a configuration that does not hold.
- **The path is not absolute, or its `$VAR` does not expand.** Only `~`, `$HOME` and
  `$XDG_RUNTIME_DIR` expand, the same vocabulary [`binds`](binds) uses.

The one fatal case is a broker that was asked for, could be provided, and still could not
be stood up: the socket cannot be bound. That fails the launch rather than silently
running without the fence the config asked for.

## Placing a credential the cage does not have

A broker holds no secret, and that is what bounds it. To let one **authenticate** on the
cage's behalf without breaking that, `sbx` hands the plugin a **marker** and substitutes the
real value itself:

```toml
# global config only, like the socket
[broker.pg]
socket = "$XDG_RUNTIME_DIR/postgres/.s.PGSQL.5432"
secret = "env://PGPASSWORD"        # or a fallback chain, like a [secret] `from`
```

The plugin's manifest must declare `uses_secret` for this to apply: which plugin may be
handed a credential is a property of the code that was installed, not of the machine that
configures it. A `secret` named for a plugin that does not declare it is reported and
dropped.

At the start of every connection the plugin receives a **random marker**, places it where
the protocol wants the value, and `sbx` replaces it on the way to the host resource. The
plugin can decide *where* the credential goes; it can never read it.

Four rules make that true, and each closes a specific hole:

| Rule | What it prevents |
|---|---|
| substitution only toward the host resource | the secret entering the cage, which is the invariant itself |
| never inside a `query` | the plugin reading its own answer from a service that echoes |
| only in bytes the plugin **wrote** | the cage's own bytes being scanned for a marker |
| the marker never travels toward the cage | the cage learning the marker, which the other rules rest on |

Both surfaces say so. `sbx config show` lists the credential's **locator** under the broker
that places it (the variable name or file path, never the value), and the session's
[`broker` feed](../cli/logs) marks the frames that carried it: a frame bearing a
credential is not the same event as one merely rewritten, and an audit should not have to
guess which was which.

On the way back, a reply carrying the credential is **refused, not stripped**: a partial
strip gives false confidence, and an encoded value defeats it anyway. It is a tripwire, not
a wall, exactly as on the [egress side](../secrets/redaction). A credential shorter than the
[`[redact] min_len`](../configuration/network) floor is placed but **not** watched, and the
launch says so: a scan that short refuses innocent traffic more often than it catches a leak.

### What this does and does not cover

It covers secrets that are **transmitted**: a password sent in the clear under TLS, a token,
an API key. It does **not** cover a challenge-response exchange, where nothing is
transmitted and everything is computed.

For PostgreSQL specifically, that line falls where `pg_hba.conf` does. The documentation is
explicit that a password stored as a SCRAM verifier can still be used by the `password`
method (`"but password transmission will be in plain text in the latter case"`), so this
works wherever the server is configured for `password`, and not where it requires
`scram-sha-256`, which is the recommended setting.

## Protocols that answer in several messages

`sbx` transmits one message and reads the answer, but "the answer" is not always one message.
gpg-agent replies to `GETINFO version` with two lines (`D 2.4.8`, then `OK`), and to many
commands with a run of them ending in `OK`, `ERR` or `INQUIRE`.

Only something that reads the protocol can say where a run ends, so **the plugin says it**:
it sees each reply frame and answers `more` until it recognises the terminator. That has two
consequences a manifest has to live with:

- such a protocol needs `inspect_replies`, because a broker that never sees the replies
  cannot know when to stop reading;
- a ceiling bounds what one exchange may take from the host resource, so a resource that
  never stops talking ends the exchange as a refusal rather than holding the cage's
  connection open.

Two other shapes a protocol may have, each declared by the plugin rather than guessed:

- **A message the host never answers**: PostgreSQL's `Terminate`, the close of many
  protocols. The plugin says so on the verdict, and `sbx` sends it without waiting.
  Waiting would end the connection on a read that can only fail, and the session record
  would call a normal goodbye a refusal.
- **A framing whose length counts itself**, and whose first message has no type byte:
  that is `pgwire`. A plugin is handed the type byte and the body, never the byte count,
  because a plugin that rewrites a body must not have to fix a count, so `sbx` recomputes
  it.

Some protocols also have the **host speak first**: gpg-agent greets every connection with
`OK Pleased to meet you` before the cage has said anything. A manifest declares that with
`host_greets`, and without it `sbx` would read the greeting as the answer to the cage's first
message and every exchange after that would be off by one. It requires `inspect_replies` too:
the greeting reaches the cage, so the broker has to be able to rule on it.

## What the cage sees

The plugin's manifest names the variables that must point at the broker, and `sbx` sets
each of them. Two forms, because clients differ:

- `cage_env`: the variable takes the **socket file** (`SSH_AUTH_SOCK`, `GPG_AGENT_SOCK`);
- `cage_env_dir`: it takes the **directory holding it**, for a client that derives the
  file name itself. libpq reads `PGHOST` as a directory and looks for `.s.PGSQL.<port>`
  inside, so a broker for PostgreSQL uses this form and names the file with `socket_name`.

`socket_name` is a **file name, never a path**: the directory stays `sbx`'s to choose, which
is what keeps a manifest from placing a socket over something the cage needs and keeps two
brokers from colliding. Without these two, a client with its own naming convention could
only be served by linking the socket into place by hand, the difference between a
mechanism that works and one that works for whoever knows the trick.

A manifest also cannot name a variable that loads code (`LD_*`, `PATH`, and the rest of the
reserved set), nor one `sbx` sets for a broker of its own: a broker points a client at its
socket, it does not arrange for something to be executed, and it does not stand in for
another broker.

### Clients that compute the path themselves

Some protocols never read a variable. A GnuPG client derives
`/run/user/<uid>/gnupg/S.gpg-agent` from the uid and the home directory, and has done since
`GPG_AGENT_INFO` stopped naming anything in GnuPG 2.1. Pointing at such a broker with a
variable is pointing at nothing.

A manifest says so with `at_host_path = true`, and the fenced socket is then bound **at the
address of the resource it stands in front of**: the path `[broker.<name>] socket` names.
A client that would have found the raw socket finds the fence, and needs no telling:

```toml
[broker]
framing         = "line"
max_frame       = 2048
at_host_path    = true
host_deadline   = 300
host_greets     = true
inspect_replies = true
```

`host_deadline` is the other thing that manifest is saying, and it belongs to the same protocol
rather than to any machine: a key with a passphrase makes the agent stop mid-exchange and open a
pinentry, and it answers when the person does. The default `sbx` waits on a host resource is thirty
seconds (a typing speed, not a fault), so a protocol that asks a person raises it, up to ten
minutes. Past that, whatever is on the other side is wedged rather than thinking, and letting go is
what keeps a thread, a plugin process and two connections from being held indefinitely.

This is still not a path in a manifest. It says how the protocol locates a socket; the path
itself comes from the config that named the resource. A `tcp://` target has no such address,
so the two declarations together are refused rather than one quietly ignoring the other, and
a manifest that declares `at_host_path` needs no `cage_env` at all.

## Giving a resolver plugin the fence

A [resolver plugin](../secrets/plugins) can be put behind a broker instead of being handed
the host resource. This is the one grant in `sbx` that only ever **takes something away**:

```toml
# in the resolver's plugin.toml
[sandbox]
brokers = ["gpg-agent"]
```

The published `pass` resolver is the worked example. Reading a password store means asking
the GnuPG agent to decrypt, and the only way to ask used to be `allow_paths` on the agent's
socket, which carries every operation the agent can perform, signing included. Naming the
broker binds the filtered socket at that same address instead, so `pass(1)` finds what it
always looked for and the connection carries only what `[broker.gpg-agent] allow` admits.

Both sides consent. The manifest asks by name; the grant is answered only where a **global**
`[broker.<name>]` binds that name and the broker actually comes up. A name nothing binds is
a warning and no socket, never a fall back to the raw resource:

```
sbx: warning: the `pass` plugin needs the `gpg-agent` broker, which this launch has not
     stood up — bind it with `[broker.gpg-agent] socket` in the global config, or the
     plugin runs without it
```

`sbx plugins info <scheme>` shows the grant and whether this machine answers it, so the
question can be settled before a secret is resolved rather than during it.

Two limits are worth stating plainly. A **broker** plugin may not declare `brokers`: a fence
behind a fence is a chain nothing bounds, and what the outer one admits would come to depend
on a plugin rather than on the config that bound it. And a broker's **own** `secret` is
resolved before any broker is standing, so a credential for a broker cannot itself be read
through one: the launch says which declaration made it impossible rather than leaving the
tool's own error to stand for it.

## Seeing what is bound

`sbx config show` lists every broker a launch would stand up, and leads each line with the
**socket**: that path is the whole of what is exposed, so it is what a reader auditing a
config checks first. The plugin it feeds and the policy follow, and the provenance tag is
the **policy's** layer, since the socket is always the global config's.

## The honest limits

- **A broker plugin is in the trusted computing base.** It sees the traffic in both
  directions in the clear, and installing one is a deliberate act, like installing a
  resolver.
- **The bound is the hole it replaces**, not perfection. A plugin that decides badly can
  allow whatever the host resource would have allowed. It can never allow more.
- **A [task](task)'s own cage does not get the socket.** A task cage keeps a named set of
  destinations and drops every channel (the ssh-agent socket and the display go the same
  way), so a task's *command* cannot speak to a brokered resource. What a task does get is
  a credential resolved through one: `[task.<name>.secret]` runs the same resolver layer a
  wire injection does, host-side, so a `pass://` credential means the same thing in both.
- **The record says what `sbx` observed, not what the plugin claims.** Every decision goes
  to the session's log, readable with [`sbx logs --feed broker`](../cli/logs). One record
  holds every broker of a session, and each line names the one that decided. The verdict
  (`forward`, `answer`, `refuse`) is `sbx`'s own account and leads each line, after that
  name; the plugin's reason is appended after it, sanitised. A plugin cannot make a forward *read* as a
  refusal by choosing its words. On top of that, the **first** refusal of a connection is
  printed at the terminal, and a plugin that stops answering has its request refused and
  its connection ended, since a broker that stopped deciding is not one to keep asking.
