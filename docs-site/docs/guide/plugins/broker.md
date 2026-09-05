---
description: "Standing in front of a host socket the cage must use without ever holding it, under a contract that leaves sbx the socket."
---

# The broker type

A resolver answers *where a value comes from*. A **broker** answers *how the cage
uses a host resource without holding it*: the filtering ssh-agent
([`[ssh_agent]`](../configuration/ssh-agent)) is the first-party example, standing
between the cage and the user's own agent so a signature is possible and a key is
never handed over.

`type = "broker"` is the second plugin type, for protocols that will never justify
first-party code of their own. What makes it admissible is that the plugin holds
nothing:

- **sbx keeps the cage-facing socket, the connection to the host resource, the
  framing, the decision record and the timeouts.** The plugin speaks to `sbx`
  alone, over stdin and stdout, from a host-side cage with an empty network
  namespace. It sees frames and answers verdicts.
- **A broker plugin can therefore never grant more than binding the host socket
  into the cage would have granted.** That bound is the whole reason the type
  exists in this shape rather than as a plugin that owns the socket. It holds
  because the bound is enforced on both sides: sbx keeps the resource, and the
  plugin's own `[sandbox]` grant may name only regular files, so a manifest
  cannot reach a *second* host socket past the one it is fenced in front of.

```toml
name = "gpg-agent"
type = "broker"                    # no `scheme`: a broker claims no ref namespace
exec = "bin/broker"

[broker]
cage_env  = ["MYTOOL_SOCK"]        # cage variables pointed at the socket sbx places
cage_env_dir = []                  # …or at the directory holding it (libpq's PGHOST)
socket_name  = "agent.sock"        # the file name inside it; the directory is sbx's
at_host_path = false               # true = stand at the host resource's own address instead
framing   = "line"                 # `line`, `length-u32-be` or `pgwire`
max_frame = 2048                   # the largest frame sbx reads on this channel
host_deadline = 30                 # seconds sbx waits on the host resource for one exchange
deny_frame = [5]                   # optional: a refusal frame that needs no request context
uses_secret = true                 # may be handed a marker standing in for a credential
host_greets = true                 # the host speaks first, before the cage asks anything
inspect_replies = true             # also rule on what the host resource answers
```

Seven rules a broker manifest is held to, each refused at load rather than at
launch:

- **`network` and `state` are refused.** `sbx` opens the connection for the
  plugin, so network reach on the component brokering a credential would be an
  exfiltration path for that credential. A broker holds nothing across runs.
- **The manifest does not name where the socket lands.** `sbx` picks the location,
  for the reason `state` is a boolean and never a path, and sets every name in
  `cage_env` to it. A protocol whose clients compute the path themselves says so
  with `at_host_path`, and the socket is then stood at the address of the resource
  it fences: the one the config named, still never one the manifest chose.
- **`cage_env` passes the reserved-key barrier** an untrusted project's `[env]`
  meets. A broker points a client at its socket; names like `LD_PRELOAD` or `PATH`
  load code in the cage instead.
- **`framing` is a closed set** implemented in `sbx`: `length-u32-be` (a four-byte
  big-endian length, then the body, which carries the protocol's own type byte),
  `line` (one message per line, the newline being the boundary rather than part of the
  message), and `pgwire` (PostgreSQL's: a type byte, then a length that **counts itself**,
  except for the startup packet which has no type byte at all, so the reader is stateful). A plugin handed an uncut stream would be the broker rather than rule on its
  messages. An over-long frame is an error, never a truncation.
- **`uses_secret` is what lets a broker place a credential it never sees.** The plugin is
  handed a random marker and `sbx` substitutes the value on the way to the host resource;
  see [`[broker]`](../configuration/broker#placing-a-credential-the-cage-does-not-have).
  Declared here rather than only in the config, because which plugin may be handed one is a
  property of the code that was installed and reviewed.
- **`host_deadline` is how long the protocol may take, not how long the machine takes.** A
  deadline exists so a wedged resource cannot wedge the cage: it holds a thread, a plugin
  process and two connections while it waits. Thirty seconds suits a resource answering at
  machine speed and is wrong for one that stops to **ask a person**: a gpg-agent opening a
  pinentry answers when the human does. A manifest raises it up to ten minutes; past that,
  whatever is on the other side is wedged rather than thinking.
- **`host_greets` and multi-message answers both need `inspect_replies`.** A protocol
  whose reply is a run of messages needs the plugin to say where the run ends, and a
  greeting is a frame from the host that must not reach the cage unseen.

`deny_frame` is optional because it does not generalise: it fits a protocol whose
refusal is the same whatever was refused, and a protocol whose refusal must echo a
request id has none. The refusal that always works is closing the connection.

:::note What a broker plugin does not reach
A broker plugin is given no `scheme`, so nothing a secret's `from` names routes to it,
and it may not declare `brokers` of its own: a fence behind a fence is a chain nothing
bounds. It also cannot be handed a credential unless its manifest says `uses_secret`,
and what it is handed then is a marker, never the value.
:::

The rest of `[sandbox]` is declared exactly as it is on a resolver, because one function
builds all three cages from it: `programs`, `allow_paths`, `mask_paths`, `allow_env` and
`allow_env_paths` reach the same places, and `sbx plugins info <name>` shows them on a
broker's page with each declared program resolved against this host's `PATH`.

One rule is narrower here than on a resolver, and it is the one that keeps the bound
above true. A path a broker grants, whether written in `allow_paths` or reached through
`allow_env_paths`, must be a **regular file**. A socket, a FIFO and a directory are each
refused, naming the entry, before the cage is built:

```
sbx: refusing to run the `gpg-agent` plugin: a broker plugin's `allow_paths` entry
`/run/user/1000/gnupg` is a directory, and only a regular file may be bound into this
cage — a socket carries in both directions whatever the mount is read-only, and a
directory grants every socket inside it
```

Read-only is a rule about writing to a filesystem: it does not narrow what a connected
socket carries, which is the premise the `brokers` grant itself rests on. A directory is
that same grant one level up, since an agent socket is one entry inside one. What is left
is what the field is for on this type: a configuration or data file the plugin reads.

## See also

- [`[broker]`](../configuration/broker): binding a broker to a host resource, and the
  config side of everything above.
- [The `plugin.toml` manifest](manifest): the `[sandbox]` grant a broker shares with the
  other two types.
