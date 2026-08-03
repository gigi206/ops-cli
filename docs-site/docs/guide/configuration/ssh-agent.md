# `[ssh_agent]`: signing with a key the cage never holds

A cage that must `git push` over ssh needs a **signature** from one of your keys. It must
not need the key. `[ssh_agent] allow` names the keys your running agent may sign with on
the cage's behalf, and sbx puts a **filtering agent** in front of the host's, rather than
handing the cage the host agent's socket.

```toml
[ssh_agent]
allow   = ["deploy@example", "SHA256:asAp51067jpFuXnlqkJj32f+5u0IhJDux0qGku0+XHs"]
confirm = true      # optional: ask before every signature the cage requests
```

`[ssh_agent]` is a **security field**: honored from the global config or a trusted
project, ignored from an untrusted one: because a key the cage can sign with
authenticates as you on every host that trusts it. An empty or absent `allow` leaves the
cage with **no agent at all** (not an agent holding no keys): `$SSH_AUTH_SOCK` is unset
inside, and the host agent's socket is in no mount the cage holds.

See also: [Secrets](../secrets/) · [The trust gate](../concepts/trust) ·
[`[network]`](network) · [`[devices]`](devices).

## Naming a key

An entry names **one** key, by either spelling `ssh-add -l` prints:

```
$ ssh-add -l
256 SHA256:asAp51067jpFuXnlqkJj32f+5u0IhJDux0qGku0+XHs deploy@example (ED25519)
    └───────────────── the fingerprint ──────────────┘ └── the comment ─┘
```

- the **`SHA256:…` fingerprint**: exact, and unchanged if you re-comment the key;
- the **comment**: what a human recognises; free-form, spaces and all.

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
agent**: it never falls back to a wider grant.

## What the broker allows

The cage talks to a socket sbx serves, not to your agent. Every message is checked against
an **allowlist of message types**:

| The cage asks | Answer |
|---|---|
| list identities | the keys `allow` names, the rest are **absent from the listing**, not merely unusable |
| sign with a listed key | forwarded to your agent; the signature comes back |
| sign with any other key | refused, **without contacting your agent** |
| add a key, remove one, remove all | refused: the cage cannot plant a key in your agent, or wipe it |
| lock / unlock / smartcard | refused |
| any other extension, or a message type sbx has never seen | refused |

The one exception is `session-bind@openssh.com`, which is **forwarded**: see the next
section, where it does real work.

Admission is re-derived from your agent on **every** request, so a key you `ssh-add -d`
mid-session stops working immediately, and one you add mid-session is picked up without
relaunching, provided the grant names it *and* the broker is running. If nothing matched
at launch there is no broker to pick anything up, and a later `ssh-add` changes nothing
until the next launch.

## What this does *not* contain

Any code in the cage can authenticate as an allowed key to **any host that trusts that
key**, for as long as the cage runs. The broker bounds *which key* and *which operation*, never *which destination*. A signature request names the session it belongs to, not the
host it will be spent on.

So this is a labelled step down from confidentiality-by-absence, and the mitigation is at
the source: grant a key whose **own** authority is narrow.

- Prefer a **deploy key** scoped to one repository over your personal key.
- Load a key with a **destination constraint** and the constraint holds, because sbx
  forwards the binding message OpenSSH's agent needs to check it:

  ```bash
  ssh-add -h 'git@github.com' ~/.ssh/id_deploy
  ```

  That check runs in **your agent**, not in sbx: sbx's part is not to break it. Verified
  both directions through the broker: toward `github.com` the key is offered and signs;
  toward any other host the agent withholds it entirely once the client binds the session
  to that host's key, so it is never even offered. The grant still lists it (an *unbound*
  listing shows every key), so the launch note and `sbx config show` read the same either
  way: the constraint bites at use, not at admission.

- Require a **confirmation for every signature the cage asks for**: see
  [below](#asking-before-every-signature). Unlike the next option it is scoped to the
  sandbox: your own `git push` outside it is unaffected.

- Require a **confirmation for every use of the key, sandbox or not**, by loading it that
  way: each signature becomes a prompt **on your desktop**:

  ```bash
  ssh-add -c ~/.ssh/id_deploy
  ```

  Verified both directions through the broker: approving yields the signature; refusing
  gives the cage `agent refused operation` and no signature. The prompt is raised by your
  agent, on the host, the cage has no way to see it, answer it, or suppress it. Note it
  fires on the **signature**, not on the offer: an ssh login where the server rejects the
  key outright never reaches the signing step, so no prompt appears.

## Asking before every signature

`confirm = true` puts a prompt on your desktop for **every signature the cage asks for**,
and forwards the request to your agent only if you approve it:

```toml
[ssh_agent]
allow   = ["deploy@example"]
confirm = true
```

```
sbx: note: ssh-agent: the cage may sign with deploy@example — each signature asks you first
```

The prompt names the key, and the server when the client bound one:

```
sbx: the sandbox is asking to sign with deploy@example toward the server
     holding SHA256:nThbg6kXUp….

Allow it?
```

This is the sandbox-scoped counterpart of `ssh-add -c`: it asks for what the **cage**
requests and nothing else, so your own `git push` outside the sandbox is untouched. The two
compose: a key loaded with `ssh-add -c` prompts for both.

What makes it a control rather than a suggestion:

- **The cage cannot reach the prompt.** It is raised by a helper sbx starts on the host, in
  your session. The cage cannot see it, answer it, or suppress it: it only waits.
- **The helper is sbx's, not the config's.** It comes from sbx's own `$SSH_ASKPASS`, then
  from `ssh-askpass` on `PATH`, then from OpenSSH's own packaged helpers. It is never read
  from the cage's `[env]`, which a project can write: a config that could name the program
  whose exit status means "yes" would be a config that approves its own requests.
- **No helper means no agent.** If none is found the launch says so and gives the cage
  **no agent at all**, rather than a grant whose promised confirmation would never appear:

  ```
  sbx: warning: `[ssh_agent] confirm` asks for a prompt on every signature, but no askpass
       helper was found on the host … — the cage gets no agent rather than a grant whose
       confirmation would never appear.
  ```

- **Anything but a clean approval is a refusal.** Cancelled, closed, crashed, or a helper
  that will not start all mean no signature.
- **A key you never granted never prompts.** An unlisted key is refused before any dialog,
  so a cage cannot make your desktop ask questions by asking for keys it does not have.
- **One prompt at a time.** Confirmations are serialised, so a burst of requests is a queue
  of one dialog, not a screenful.

`confirm` **ORs across layers**: the global config, the project, an app, and a `--config`
override may each turn it on, and none of them can turn it off. Declining costs the cage a
signature and nothing else, the request fails as `agent refused operation`, exactly as an
unlisted key does. Every decision, approved or not, lands in
[`sbx ssh-agent logs`](#seeing-what-it-actually-did).

There is no timeout: an unanswered prompt leaves the cage's ssh client waiting, the same way
`ssh-add -c` does.

## There is no password to set: and that is the point

There is no field for one, in either direction:

- **The key's passphrase stays on the host.** You type it once into `ssh-add`, and your
  agent holds the unlocked key from then on. sbx never sees the passphrase, never asks for
  it, and has nowhere to store it: putting it in a config file would move the secret to
  exactly the place this feature exists to keep it out of.
- **The broker socket has no password**, and one would buy nothing: it is a socket in a
  `0700` directory, and the cage runs as your own uid. Anything on the host running as you
  can already talk to your real agent directly.
- **Password-based ssh login is a different thing entirely.** The proxy splices port 22
  byte for byte, so there is no request head to inject into and a `tcp://` host is refused
  as a `[secret]` destination. If a destination only takes passwords, the agent cannot
  help, use a key where you can, and a [declared operation](task) where you cannot:

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
  `PubkeyAuthentication=no` pair is not decoration: without it ssh burns its
  authentication attempts offering keys and the server disconnects on `Too many
  authentication failures` before password auth is ever tried. This is the template tier,
  weaker than the broker: keep `action` genuinely bounded, since a pattern that admits an
  arbitrary command hands the password to whoever calls it.

The nearest thing to "ask me for a password each time" is `ssh-add -c` above: not a secret
to declare, a confirmation you give.

## It needs egress too

The broker rides a Unix socket, so it is independent of the network posture: and equally,
it opens no network. A signature with nowhere to go is no use: under an allowlist posture
the cage reaches ssh only through a raw `tcp://` rule.

```toml
[packages]
openssh = "nix:openssh"

[ssh_agent]
allow = ["deploy@example"]

[network]
mode  = "allow"
allow = ["tcp://github.com:22"]
```

That is the whole configuration: `git push` then works as written:

```bash
git push        # or ssh git@github.com, git clone git@…, scp, rsync -e ssh
```

Port 22 needs one thing the other destinations do not, and sbx supplies it. For most
`tcp://` destinations sbx plants an **in-cage listener** and an `/etc/hosts` entry, so the
client dials the name unchanged; a port below 1024 is privileged and the cage holds no
capability, so that listener cannot exist. Instead sbx writes a `ProxyCommand` for the host
into the cage's system-wide `/etc/ssh/ssh_config`, pointing at the cage's own `CONNECT`
proxy, the route the rule already governs. It notes it at launch, because a **non-ssh**
client on such a port still has to ask for that `CONNECT` itself:

```
sbx: note: tcp://github.com:22 is a privileged port, which the cage cannot listen on — ssh
     reaches it through the cage's CONNECT proxy (wired in /etc/ssh/ssh_config); another
     client has to ask for that CONNECT itself
```

The generated file is read-only and contains nothing but a `Host` block per declared
destination. It is the **system-wide** config, the last file ssh reads, so a `~/.ssh/config`
you write inside the cage takes precedence over it: measured both ways. Nothing about the
fence changes: an undeclared host or port is refused whether or not a client reads this file.

Verified end to end: the cage reaches `github.com:22` through the generated `ProxyCommand`,
completes the key exchange, binds the agent to the server's host key, and offers the granted
key, the whole path, with the private key never leaving the host agent. See
[`[network]`](network).

## Seeing the grant

`sbx config show` reports it with its provenance, like every other resolved value:

```
  ssh-agent: deploy@example (keys the cage may sign with) (global)
```

## Granting a key to one app only

An `[app.<name>.ssh_agent]` table (or an `[ssh_agent]` table in an imported profile) grants
keys **for that app's launches only**, **unioned** onto the baseline and gated the same way:

```toml
[app.deployer]
cmd = "deploy-agent"

[app.deployer.ssh_agent]
allow = ["deploy@example"]
```

That is the point of the field. A baseline grant is held by *every* cage the project
launches, an interactive `sbx run`, every other app, whatever else is configured. A
per-app grant is held by one, so a deploy key can be given to the thing that deploys and to
nothing else.

The union runs one way: an app **adds** a key, and can never take away one the baseline
granted. And an untrusted project's app `[ssh_agent]` is dropped, so a globally-declared
app's grant cannot be widened by the code it runs on.

```
$ sbx config show --app deployer
  ssh-agent: deploy@example, work@example (keys the cage may sign with) (app:global)
```

A bundle cannot carry one. A `[bundle.<name>]` deliberately holds only what a *tool* needs, its packages, environment, egress and credential: and never anything that widens what the
cage exposes of the host; `ssh_agent`, `binds`, `devices` and `seccomp` are all excluded by
the same rule, so using a bundle can never quietly grant a key.

An imported profile can, though: it lands in the global config, which is trusted by
location. So `sbx app import` states the grant before writing anything:

```
ssh-agent: deploy@example — this app's cage may ask your agent to sign with that key
```

## Seeing what it actually did

A grant says what the cage *may* do. `sbx ssh-agent logs` says what it **did**: every key
offered, every signature produced, and everything the broker turned away:

```
$ sbx ssh-agent logs
ssh-agent feed — session 48213 [demo-agent] /home/you/project
  14:02:11  list     offered deploy@example (5 withheld)
  14:02:11  sign     deploy@example toward the server holding SHA256:nThbg6kXUp…
  14:07:45  refuse   an attempt to remove every key from your agent
  14:09:02  refuse   a signature with a key the grant does not name
```

`-f`/`--follow` streams it from another terminal: the way to watch a `--detach`ed agent: and `--json` emits one NDJSON object per event, for a pipe.

**The destination is there, with a caveat.** A signature request names a key and a session,
never a host. But an ssh client binds the connection to the **server's host key** before
asking for a signature (that is how an `ssh-add -h` constraint gets enforced), so the record
names the server in the same `SHA256:…` spelling `known_hosts` and `ssh-keyscan` print, compare them to identify the host. It is what the client said, not something sbx verified;
a client that never binds simply yields a signature line with no destination on it.

Where it lives matters as much as what it says. The feed is read over a socket under the
data directory that is **never** bound into the cage, so the agent can neither read the
record of what it asked for nor amend it. The ring lives in the launcher's memory for the
life of the session and is never written to disk: so it is a live view: read it while the
session runs, or follow it. A session whose config grants no key has no broker at all, and
says so rather than showing an empty feed.

## A task cage gets no agent

The grant is the agent cage's. A [declared operation](task) runs in its own ephemeral
sibling cage, which inherits only an allowlist of mounts and environment variables: the
broker socket and `SSH_AUTH_SOCK` are in neither. So a task cannot sign, even one declared
by the same config, unless a future field says otherwise.

## Residuals

- **Silent by default.** Without `confirm = true`, every request from an admitted key is
  granted without asking. The prompt is opt-in, not the default posture.
- **No per-destination fence in sbx.** Destination constraints exist, enforced by your own
  agent, as above. The log *names* the destination; it does not bound it.
- **The record is live, not durable.** `sbx ssh-agent logs` reads a ring in the launcher's
  memory, so it answers "what has this session done" and not "what did last week's session
  do". That is deliberate, a credential journal on disk is a new thing to protect, but it
  means an unattended session's history goes with it.
