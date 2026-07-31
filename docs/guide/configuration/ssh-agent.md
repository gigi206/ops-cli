# `[ssh_agent]` — signing with a key the cage never holds

A cage that must `git push` over ssh needs a **signature** from one of your keys. It must
not need the key. `[ssh_agent] allow` names the keys your running agent may sign with on
the cage's behalf — and sbx puts a **filtering agent** in front of the host's, rather than
handing the cage the host agent's socket.

```toml
[ssh_agent]
allow = ["deploy@example", "SHA256:asAp51067jpFuXnlqkJj32f+5u0IhJDux0qGku0+XHs"]
```

`[ssh_agent]` is a **security field** — honored from the global config or a trusted
project, ignored from an untrusted one — because a key the cage can sign with
authenticates as you on every host that trusts it. An empty or absent `allow` leaves the
cage with **no agent at all** (not an agent holding no keys): `$SSH_AUTH_SOCK` is unset
inside, and the host agent's socket is in no mount the cage holds.

See also: [Secrets](../secrets/README.md) · [The trust gate](../concepts/trust.md) ·
[`[network]`](network.md) · [`[devices]`](devices.md).

## Naming a key

An entry names **one** key, by either spelling `ssh-add -l` prints:

```
$ ssh-add -l
256 SHA256:asAp51067jpFuXnlqkJj32f+5u0IhJDux0qGku0+XHs deploy@example (ED25519)
    └───────────────── the fingerprint ──────────────┘ └── the comment ─┘
```

- the **`SHA256:…` fingerprint** — exact, and unchanged if you re-comment the key;
- the **comment** — what a human recognises; free-form, spaces and all.

Both are matched by exact equality. There is **no wildcard**: a `"*"` entry is dropped with
a warning, as is a `SHA256:` fingerprint that lost its tail to a copy-paste (a real one is
43 characters). A grant you could not read off a listing would not be a grant anyone could
audit.

The keys the grant resolves to are settled **at launch**, against what your agent is
actually holding then:

```
sbx: ssh-agent: the cage may sign with deploy@example (5 other keys withheld)
```

If no agent is running, or no key it holds matches, sbx **warns and gives the cage no
agent** — it never falls back to a wider grant.

## What the broker allows

The cage talks to a socket sbx serves, not to your agent. Every message is checked against
an **allowlist of message types**:

| The cage asks | Answer |
|---|---|
| list identities | the keys `allow` names — the rest are **absent from the listing**, not merely unusable |
| sign with a listed key | forwarded to your agent; the signature comes back |
| sign with any other key | refused, **without contacting your agent** |
| add a key, remove one, remove all | refused — the cage cannot plant a key in your agent, or wipe it |
| lock / unlock / smartcard | refused |
| any other extension, or a message type sbx has never seen | refused |

The one exception is `session-bind@openssh.com`, which is **forwarded** — see the next
section, where it does real work.

Admission is re-derived from your agent on **every** request, so a key you `ssh-add -d`
mid-session stops working immediately, and one you add mid-session is picked up without
relaunching — provided the grant names it *and* the broker is running. If nothing matched
at launch there is no broker to pick anything up, and a later `ssh-add` changes nothing
until the next launch.

## What this does *not* contain

Any code in the cage can authenticate as an allowed key to **any host that trusts that
key**, for as long as the cage runs. The broker bounds *which key* and *which operation* —
never *which destination*. A signature request names the session it belongs to, not the
host it will be spent on.

So this is a labelled step down from confidentiality-by-absence, and the mitigation is at
the source: grant a key whose **own** authority is narrow.

- Prefer a **deploy key** scoped to one repository over your personal key.
- Load a key with a **destination constraint** and the constraint holds, because sbx
  forwards the binding message OpenSSH's agent needs to check it:

  ```bash
  ssh-add -h 'git@github.com' ~/.ssh/id_deploy
  ```

  That check runs in **your agent**, not in sbx — sbx's part is not to break it. Verified
  both directions through the broker: toward `github.com` the key is offered and signs;
  toward any other host the agent withholds it entirely once the client binds the session
  to that host's key, so it is never even offered. The grant still lists it (an *unbound*
  listing shows every key), so the launch note and `sbx config show` read the same either
  way — the constraint bites at use, not at admission.

- Require a **confirmation for every use**, and each signature the cage asks for becomes a
  prompt **on your desktop**:

  ```bash
  ssh-add -c ~/.ssh/id_deploy
  ```

  Verified both directions through the broker: approving yields the signature; refusing
  gives the cage `agent refused operation` and no signature. The prompt is raised by your
  agent, on the host — the cage has no way to see it, answer it, or suppress it. Note it
  fires on the **signature**, not on the offer: an ssh login where the server rejects the
  key outright never reaches the signing step, so no prompt appears.

## There is no password to set — and that is the point

There is no field for one, in either direction:

- **The key's passphrase stays on the host.** You type it once into `ssh-add`, and your
  agent holds the unlocked key from then on. sbx never sees the passphrase, never asks for
  it, and has nowhere to store it — putting it in a config file would move the secret to
  exactly the place this feature exists to keep it out of.
- **The broker socket has no password**, and one would buy nothing: it is a socket in a
  `0700` directory, and the cage runs as your own uid. Anything on the host running as you
  can already talk to your real agent directly.
- **Password-based ssh login is a different thing entirely.** The proxy splices port 22
  byte for byte, so there is no request head to inject into and a `tcp://` host is refused
  as a `[secret]` destination. If a destination only takes passwords, the agent cannot
  help — use a key where you can, and a [declared operation](task.md) where you cannot:

  ```toml
  [packages]
  sshpass = "nix:sshpass"      # a task's own `packages` takes `mise:` only
  openssh = "nix:openssh"

  [task.deploy]
  cmd     = ["sshpass", "-e", "ssh", "-o", "PubkeyAuthentication=no",
             "-o", "PreferredAuthentications=password",
             "-p", "2222", "deploy@localhost", "{action}"]
  params  = { action = "^(systemctl restart myapp|id -un)$" }
  network = ["tcp://localhost:2222"]

  [task.deploy.secret]
  SSHPASS = "env://DEPLOY_PASSWORD"
  ```

  Verified against a real sshd: the password is resolved host-side and materialised only
  in the ephemeral task cage, the agent's own cage holds no trace of it, and an
  invocation whose credential cannot be resolved is refused before anything runs. The
  `PubkeyAuthentication=no` pair is not decoration — without it ssh burns its
  authentication attempts offering keys and the server disconnects on `Too many
  authentication failures` before password auth is ever tried. This is the template tier,
  weaker than the broker: keep `action` genuinely bounded, since a pattern that admits an
  arbitrary command hands the password to whoever calls it.

The nearest thing to "ask me for a password each time" is `ssh-add -c` above: not a secret
to declare, a confirmation you give.

## It needs egress too — and port 22 needs a `ProxyCommand`

The broker rides a Unix socket, so it is independent of the network posture — and equally,
it opens no network. A signature with nowhere to go is no use: under an allowlist posture
the cage reaches ssh only through a raw `tcp://` rule.

```toml
[packages]
openssh = "nix:openssh"
socat   = "nix:socat"

[ssh_agent]
allow = ["deploy@example"]

[network]
mode  = "allow"
allow = ["tcp://github.com:22"]
```

For most `tcp://` destinations sbx also plants an **in-cage listener** and an `/etc/hosts`
entry, so the client dials the name unchanged. **Port 22 is not one of them.** A port below
1024 is privileged and the cage holds no capability, so that listener cannot exist — sbx
says so at launch rather than leaving the name pointing at a dead address:

```
sbx: warning: no in-cage listener for tcp://github.com:22 — a port below 1024 cannot be
     bound inside the cage, which holds no capability; reach it with an explicit CONNECT …
```

The rule still governs the proxy, so the route is there — the client just has to ask for it
explicitly, through the in-cage CONNECT proxy:

```bash
ssh -o 'ProxyCommand=socat - PROXY:127.0.0.1:%h:%p,proxyport=18043' git@github.com
```

Put it in the cage's ssh config to keep `git push` verbatim:

```bash
mkdir -p ~/.ssh
cat > ~/.ssh/config <<'EOF'
Host github.com
    ProxyCommand socat - PROXY:127.0.0.1:%h:%p,proxyport=18043
EOF
chmod 600 ~/.ssh/config      # ssh refuses a group- or world-readable config
```

The `chmod` is not optional: without it ssh stops at `Bad owner or permissions on
~/.ssh/config` and never dials.

Verified end to end, both forms: the cage reaches `github.com:22`, completes the key
exchange, binds the agent to the server's host key, and offers the granted key — the whole
path, with the private key never leaving the host agent. See [`[network]`](network.md).

## Seeing the grant

`sbx config show` reports it with its provenance, like every other resolved value:

```
  ssh-agent: deploy@example (keys the cage may sign with) (global)
```

An app inherits the baseline grant; there is no per-app `ssh_agent` field.

## A task cage gets no agent

The grant is the agent cage's. A [declared operation](task.md) runs in its own ephemeral
sibling cage, which inherits only an allowlist of mounts and environment variables — the
broker socket and `SSH_AUTH_SOCK` are in neither. So a task cannot sign, even one declared
by the same config, unless a future field says otherwise.

## Residuals

- **No per-signature prompt from sbx.** Every request from an admitted key is granted
  silently by the broker. Per-use confirmation exists, but it is your agent's
  (`ssh-add -c`, above), not a field here.
- **No per-destination fence in sbx.** Destination constraints exist, enforced by your own
  agent, as above.
- **No signature counter.** The grant is reported at launch; individual signatures are not
  logged.
