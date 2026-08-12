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

Some protocols also have the **host speak first**: gpg-agent greets every connection with
`OK Pleased to meet you` before the cage has said anything. A manifest declares that with
`host_greets`, and without it `sbx` would read the greeting as the answer to the cage's first
message and every exchange after that would be off by one. It requires `inspect_replies` too:
the greeting reaches the cage, so the broker has to be able to rule on it.

## What the cage sees

The plugin's manifest names the variables that must point at the broker's socket, and
`sbx` sets each of them to the path it chose. A manifest cannot name that path, and it
cannot name a variable that loads code (`LD_*`, `PATH`, and the rest of the reserved set):
a broker points a client at its socket, it does not arrange for something to be executed.

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
- **The record says what `sbx` observed, not what the plugin claims.** Every decision goes
  to the session's log, readable with [`sbx logs --feed broker`](../cli/logs). The verdict
  (`forward`, `answer`, `refuse`) is `sbx`'s own account and leads each line; the plugin's
  reason is appended after it, sanitised. A plugin cannot make a forward *read* as a
  refusal by choosing its words. On top of that, the **first** refusal of a connection is
  printed at the terminal, and a plugin that stops answering has its request refused and
  its connection ended, since a broker that stopped deciding is not one to keep asking.
