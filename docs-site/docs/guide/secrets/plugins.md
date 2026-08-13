# Resolver plugins

The secret-source space is open-ended: any well-known secret-manager backend,
a cloud KMS, a third-party vault app, a
keyring, so `sbx` keeps the **resolver** (SOURCE) layer *pluggable*. A resolver
plugin adds a new `scheme://` that a secret's `from` reference can route to. The
**broker** (SINK) layer of a secret, which terminates TLS and injects on the wire,
stays first-party: a bug where a request is decrypted and decided is a boundary
breach, so that one is never a plugin. A broker that terminates nothing, and
stands in front of a host socket instead, is a second plugin type under a contract
that leaves `sbx` holding the socket: see [The broker type](#the-broker-type).

A resolver plugin still obeys the invariant: it runs **host-side, sandboxed under
bubblewrap, never in the cage**, and returns the plaintext to `sbx`'s host
process, which hands it to the broker. Because a resolver sees plaintext, it is
in the trusted computing base: which is exactly why installing one, or trusting
a store to install from, is a deliberate act.

## What a resolver plugin is

A plugin is a directory containing a `plugin.toml` manifest and an executable.
Run with a `scheme://locator` reference as its single argument, the executable
prints the secret's plaintext to stdout. `sbx` discovers installed plugins under
its owner-only data directory (`<data>/plugins/<name>/`) and builds a
`scheme → plugin` map the secret validator consults.

### The `plugin.toml` manifest

```toml
name        = "vault"          # optional; defaults to the directory name
type        = "resolver"       # required; "resolver" or "broker" (see below)
scheme      = "vault"          # the scheme:// this plugin claims; unique in the registry
exec        = "bin/resolve"    # directory-relative, traversal-free path to the executable
version     = "1.2.0"          # optional, display-only
description = "Generic KV-store resolver"   # optional, display-only

[sandbox]                      # the least-privilege grant the runner gives the plugin
programs    = ["vault"]            # host programs to locate on sbx's PATH and bind into the cage
allow_paths = ["~/.vault-token"]   # extra host paths bound read-only (data, not binaries)
mask_paths  = []                   # paths inside a granted one to hide again (an empty tmpfs)
allow_env   = ["VAULT_ADDR"]       # host env vars passed into the otherwise-cleared environment
allow_env_paths = ["VAULT_CACERT"] # env vars whose VALUE is a path: passed through, and bound
network     = false                # true = reach the network; false = empty network namespace
state       = false                # true = a private writable directory that survives the run
brokers     = []                   # broker plugins whose fenced socket replaces the resource
```

- `type` is `"resolver"` here. The discriminator is explicit so a second type
  could be added without breaking the registry, and one has been: see
  [The broker type](#the-broker-type) below.
- `scheme` cannot be a built-in (`env`, `file`, `sops`): the built-in always
  wins, and a plugin claiming one is dropped.
- `exec` is resolved against the plugin directory and must be traversal-free.
- `version`/`description` are display-only: `sbx` never compares or acts on the
  version.
- `[sandbox]` declares only the resolver-specific extra; the runner supplies the
  structural environment (a minimal `PATH`, a read-only host userland, `HOME`,
  and, under `network`, DNS/TLS files) on top of it.
- `state` grants the plugin a private **writable** directory that survives the
  run, and is the only thing in the cage that does (`HOME` is a tmpfs that dies
  with it). It exists for one situation: a credential whose refresh token is
  **single-use**. Each exchange invalidates the token that bought it, so a
  resolver unable to keep what it just received destroys the session it was
  resolving, and providers that detect the reuse revoke everything. Leave it
  `false` for a resolver that only reads.

  The grant is a boolean, never a path. `sbx` picks the location, one per
  plugin, keeps it owner-only, and tells the plugin where it landed through
  **`SBX_PLUGIN_STATE`**. A plugin cannot name the directory, cannot reach
  another plugin's, and nothing in the agent's cage ever sees any of them.

  One consequence to plan for: a resolver that refreshes must be the **only**
  refresher. If the application also holds a working refresh token, both will
  eventually exchange, the provider will see a reused token, and the session
  dies. Give the application a placeholder before its first run.
- `programs` names the host tools the plugin runs, **by name, never by path**.
  For each one sbx searches its own `PATH` (the one your shell gives it), so a
  tool you can run is a tool the plugin can run, whatever installed it: a
  package manager, Homebrew, a nix profile, `~/.local/bin`. The binary is bound
  read-only under `/run/sbx-programs/`, which leads the cage's `PATH`, so the
  script simply calls it by name.
  - Where a tool lives is a property of the machine, not of the plugin. Listing
    install locations in `allow_paths` was at once too wide (a nix profile's
    binaries are symlinks into the store, so the whole store had to be bound to
    reach one of them) and too narrow (no list covers every package manager).
  - The binary is `execve`d inside the resolver's cage, on the plaintext path,
    so it is held to the check sbx applies to its own engines: a regular file,
    owned by you or by root, not world-writable. Every match on `PATH` is
    scanned, so a world-writable early entry is skipped with a warning rather
    than shadowing a legitimate one further down.
  - A declared program that resolves to nothing **fails the launch**, naming it.
    `sbx plugins info <name>` shows where each one resolves right now, so the
    answer comes before the first secret rather than during it.
  - A program that resolves **under `/nix/store`** is not a self-contained file:
    its interpreter line, its libraries and the helpers it runs are other store
    paths. sbx reads exactly which ones it needs and binds those, so a nix build
    works with no `/nix/store` in the manifest, and the grant is that program's
    closure rather than the whole store. A host with no nix package is never
    asked the question, and a store path whose closure cannot be read fails the
    launch naming why, rather than binding nothing and dying later at `execve`.
- `allow_paths` is for the plugin's **data**: a token file, a database, a
  socket. `HOME` in the cage is a private tmpfs, so a tool that derives a
  location from it (a password store, a GnuPG keyring, a token file) looks where
  nothing exists: bind the host path and point the tool at it. Naming `PATH` in `allow_env` has no effect; the structural value wins.
- `mask_paths` takes something back out of a path `allow_paths` granted, by
  covering it with an empty filesystem. It exists because a grant is sometimes
  wide for a reason unrelated to what the plugin needs: the `pass` plugin binds
  `~/.gnupg` whole, since the public material it wants has no single name (a
  keyring is `pubring.kbx`, or `pubring.gpg`, or `public-keys.d/` under keyboxd,
  and `gpg` reads its `.conf` files from there too), and a list of files would
  break on the next layout. Naming `~/.gnupg/private-keys-v1.d` here removes the
  secret keys again, and the resolver never misses them: it only ever needed the
  host `gpg-agent` to decrypt, reached through the broker it names in `brokers`.
  - A mask can only ever *subtract*, so unlike the other grant fields it needs no
    trust of its own: the widest thing a manifest can do with one is hide
    something from itself.
  - It is applied after every bind, since a filesystem laid down first would
    simply be covered by the bind that follows it. The masked path exists inside
    the cage and is empty, rather than being absent, so a tool that stats it
    before reading finds what it expects.
  - What a mask buys is that the material cannot be **copied out**. It does not
    put it beyond **use**: in the example above the agent is still reachable
    through the broker, so code in that cage can ask it to decrypt while it runs.
    Copying is the capability worth removing, being the one that outlives the run.
  - A mask is a **fixed path in a signed manifest**, so it cannot follow a path
    that `allow_env_paths` supplies: if `GNUPGHOME` names another home, that home
    is bound whole and nothing in it is masked. Expanding a mask against the
    variable was considered and rejected: the value can come from the
    environment or from `[plugin.<name>]`, and a protection that holds for one
    source and not the other is worse than one whose limit is stated.
- `allow_env` is how a resolver receives *its own* credential (`VAULT_TOKEN`, an
  age identity), so the value never travels where another user could read it:
  see [the cage's environment is not readable by other
  users](../concepts/security-model#the-cages-environment-is-not-readable-by-other-users).
- `allow_env_paths` is for a variable whose **value is a path to bind**
  (`PASSWORD_STORE_DIR`, `GNUPGHOME`, `VAULT_CACERT`). A manifest can only name
  the paths it knows in advance, yet every tool it drives offers a way to move
  them, and passing the variable without binding what it names is worse than not
  passing it: the tool is told to look somewhere the cage does not have, so it
  fails where it would otherwise have worked.
  - This is what makes a published plugin usable without editing it. Adjusting
    an installed `plugin.toml` changes the tree digest, so `sbx plugins list`
    reports the plugin as MODIFIED and the next reinstall drops the change.
    Setting the variable moves the grant instead, and the plugin stays the
    signed one.
  - Listing a name here **implies** the pass-through, so it must not also appear
    in `allow_env`. A manifest that lists it in both is refused, rather than
    carrying two declarations of one grant that a later edit can make disagree.
  - The value is the user's, so it is checked at invocation: it must be
    **absolute**, since a relative bind argument would silently mean something
    other than what it says inside a cage that shares no working directory. A
    relative value is dropped with a warning, and the variable with it. An unset
    variable simply leaves the manifest's own `allow_paths` in force.
  - `sbx plugins info <name>` prints what each variable currently names, so a
    relocated store can be confirmed reachable before the first secret.
- `brokers` names [broker plugins](../configuration/broker) whose **filtered**
  socket the resolver is given, in place of the host resource behind it. It is
  the only entry here that takes something away: reading a password store means
  asking the GnuPG agent to decrypt, and the only way to ask was `allow_paths`
  on the agent's own socket, which is every operation the agent can perform, signing
  included.
  - Both sides consent. The manifest asks by name; the grant is answered only
    where a **global** `[broker.<name>]` binds that name and the broker comes
    up. A name nothing binds is a warning and no socket, never a fall back to
    the raw resource.
  - `sbx plugins info <scheme>` shows the grant and whether this machine
    answers it.

## Configuring a plugin from your own config

A manifest says what a resolver *needs*. What this machine *supplies* is declared on your side,
in a `[plugin.<name>]` table in the global config or a trusted project's:

```toml
[plugin.vault]
env      = { VAULT_ADDR = "https://vault.example.com", VAULT_NAMESPACE = "team-a" }
programs = { vault = "nix:vault" }

[plugin.pass]
env = { PASSWORD_STORE_DIR = "/data/secrets" }
```

This is why the variables exist at all. `VAULT_ADDR` had to be exported by whatever shell
launched `sbx`; now it can live in the project that needs it, versioned with the rest of the
configuration.

- **Only a variable the manifest reads may be set.** A name that appears in neither `allow_env`
  nor `allow_env_paths` is dropped with a warning naming it, so a config can never put an
  arbitrary variable into the environment of a third-party binary that runs host-side on the
  plaintext path.
- **A path-valued variable is bound as well as passed.** `PASSWORD_STORE_DIR` above both tells
  `pass` where the store is and gives the sandbox access to it, since the manifest declares that
  name in `allow_env_paths`.
- **A value here wins over the same name in sbx's environment.** A config that names a value is
  more deliberate than whatever the invoking shell happened to export.
- **It is a security field**, gated like `[packages]`: honored from the global config or a
  trusted project, dropped with a warning from an untrusted one, and ignored in a one-shot
  `--config` blob.
- **Not for secrets.** A value here sits in plaintext in a config file. A credential belongs in
  [`[secret]`](../configuration/secret), whose sources are resolved at launch.

`sbx plugins info <name>` prints the table under the grant, marking any variable that will be
ignored, so the answer to "why is my setting not applying" is in the same place as the setting.

#### `programs`: where to get a tool this machine does not have

A manifest names the tools its resolver runs and `sbx` finds each on its own `PATH`, which is
what makes a published plugin work whatever installed them. `programs` is the answer for the
machine where one of them is simply not installed: name a nixpkgs attribute, and `sbx` builds it
into its own store and binds that.

- **`PATH` always wins.** This is a fallback, never a redirection. If you have the tool, you get
  the tool you have, and the entry is reported as unused.
- **Only a program the manifest runs may appear**, and **only `nix:`**. Anything else is dropped
  with a warning naming it. `nix:` is the one backend that can be built host-side and
  project-independently at the moment a plugin is installed: a `mise:` tool is equipped *inside* a
  cage, and the prebuilt backends are pinned per project.
- **The build happens at `sbx plugins install`**, not at launch. A plugin is installed once and
  any project may route a secret through it, so its program belongs to the plugin rather than to
  a project, and a launch only reads the result. The consequence is worth knowing: adding
  `programs` **after** installing takes one command, `sbx plugins install` again. The error a
  launch raises for a missing program says so.
- It uses the **global** nixpkgs pin, never a project's, so one plugin's tool cannot differ
  between the projects that share it.
- Removing the plugin removes what was built for it.

`sbx plugins info <name>` distinguishes all four states: found on `PATH`, provisioned, configured
but not yet built, and neither.

### The execution contract

The runner passes the **full reference** as the executable's single argument
(`argv[1]`, e.g. `vault://secret/data/ci#token`) and reads the outcome from the
exit status and the output streams:

| Outcome | Exit | stdout | Effect |
| --- | --- | --- | --- |
| resolved | `0` | the plaintext | the secret is used (one trailing line ending is stripped) |
| absent | `0` | empty | a clean fall-through to the next source in the `from` chain |
| failed | non-zero | ignored | a hard, fail-closed error: the launch aborts, and the next source is **not** tried |

`stdin` is closed, so a resolver can never prompt for anything: everything it
needs must come from its `[sandbox]` grant.

**stderr is the diagnostic channel, and must never carry the value.** It is
folded into the error of a failed run, and relayed as an `sbx: warning:` line
when a run resolves *nothing*: so a plugin can explain a misspelled locator or
an empty field without turning a fall-through into a hard failure. A run that
returns a value stays silent, so a plugin that logs to stderr cannot echo a
plaintext back at you. What is relayed is first reduced to a single bounded line
with control characters removed, since a plugin's own text must not be able to
drive your terminal.

### The registry is trusted by location, and fail-closed

Plugins live under the owner-only (`0700`) data directory, which a project (which
writes only the project directory) cannot plant into: so the registry is
**trusted by location**. Loading a plugin *neither runs nor provisions* anything;
before it execs a resolver, the runner re-checks the executable is a regular file
owned by you and not writable by group or other (stricter than the config-file
safety gate, because this is code about to run in the TCB).

Loading is **infallible and fail-closed**. A malformed manifest, an unsupported
type or a reserved or ill-formed scheme produces a warning and skips that plugin, never a failed launch, and never a silently-honored bad plugin. **Two plugins
claiming one scheme** drops *both* (never an arbitrary winner) and is reported
rather than merely warned about: see below. A project's `.sbx.toml` may only
*reference* a scheme, and only if the project is trusted (an untrusted project's
whole `[secret]` section is dropped before any scheme is looked up).

### A plugin edited after it was installed

Every install records the **digest of the tree it placed** (in
`<data>/plugins/.origins/<name>.toml`, alongside the origin). Three paths compare
against it:

```
sbx plugins verify [name]     # re-hash one plugin, or every one; non-zero if a tree changed
sbx plugins list              # a changed plugin is marked [modified since install]
sbx plugins info <scheme>     # an `integrity:` line, in all four states
```

The digest covers exactly what git records: the set of regular files, their
paths, the executable bit, and their bytes: so it catches an edited resolver
script **and** an edited `plugin.toml`. The manifest is the sharper of the two:
it carries the `[sandbox]` grant, so editing it in place widens what the plugin
may reach, and the registry would otherwise honor that without a word.

Four states, deliberately distinct:

| State | What it means |
|---|---|
| `unchanged since install` | the tree hashes to what was recorded |
| `MODIFIED since install` | it does not: reinstall to restore a known tree |
| `no digest recorded` | installed before sbx recorded digests, or **placed by hand**, nothing was attested, which is not the same as "unchanged" |
| `cannot be hashed` | a symlink or unreadable file appeared in the tree, which is itself a change |

`verify` exits non-zero only for the two that say something is wrong. An
unattested plugin is reported plainly and does not fail the command: the fix is
different (reinstall, which records a digest).

> **This is drift detection, not a security control.** The record lives in the
> **same owner-only directory** as the plugin, so anything able to rewrite the
> plugin can rewrite the record. It is worthless against an adversary and never
> claimed otherwise; what it catches is the accident: a plugin edited in place
> to debug it and forgotten, a careless third-party process. For that reason it
> is a verb you run and a marker you read, **never** a gate on the launch path:
> hashing every plugin at every launch would buy no safety and cost real time.

The actual boundary is elsewhere, and it is the bind layout: `<data>/plugins` is
`0700` and is **never mounted into the cage**, so the in-cage agent (the adversary of
the threat model) cannot reach a plugin at all. While a resolver
runs, its own directory is bound **read-only** at its real path, so it cannot
rewrite itself.

### A scheme belongs to one plugin

Every install path refuses a scheme another installed plugin claims, and refuses
one that is *already* contested, so an install can never add to the mess:

```
sbx: cannot install plugin: scheme `vault://` is claimed by more than one
installed plugin (`vault-a`, `vault-b`) — they are all disabled; remove all but
one with `sbx plugins rm <name>` first
```

So the only route to a conflict is placing a plugin directory under
`<data>/plugins/` **by hand**. When that happens the scheme resolves to *nothing*
and **every** claimant is disabled: never an arbitrary winner, and never a
silent one. It is shown, not just warned about:

```
$ sbx plugins list
built-in schemes (always resolve, never a plugin): env, file, sops
installed resolver plugins: (none resolving — see the scheme conflicts below)
scheme conflicts (every claimant below is disabled):
  vault://  claimed by 2 plugins
    vault-a  from: local directory /home/u/src/vault-a
    vault-b  from: unknown (installed before sbx recorded plugin origins, or placed by hand)
(a scheme must be unique: remove all but one with sbx plugins rm <name>)

$ sbx plugins info vault
… the same block, for that scheme only …
sbx: the scheme 'vault' is claimed by 2 installed plugins and resolves to nothing
until exactly one remains
```

`info` exits non-zero: the scheme is unusable, and a secret referencing it fails
the config with `unknown secret resolver scheme`. Removing all but one claimant
(`sbx plugins rm <name>`: the **directory** name, which is what the conflict
lists) restores it immediately.

## The reference plugins

Ready-made resolvers are published in the signed
[sbx-plugins](https://github.com/sbx-labs/sbx-plugins) store, not carried in this
repository. A plugin is trusted by *location*, so none is installed by default:
it only counts once it sits in `<data>/plugins/<name>/`.

```sh
sbx plugins store install sbx-plugins pass    # then: from = "pass://github/token"
sbx plugins store install sbx-plugins vault   # then: from = "vault://secret/myapp#password"
```

| Plugin | Reference form | Resolves to | Sandbox grant |
|---|---|---|---|
| `pass` | `pass://<path>[#<field>]` | the **first line** of `~/.password-store/<path>.gpg` (the password by convention), or a named `key: value` field below it | `programs = ["pass"]`; `allow_paths` on the store and `~/.gnupg`; `brokers = ["gpg-agent"]` for the agent; **no network** |
| `vault` | `vault://<mount>/<path>[?version=<n>]#<field>` | one field of a HashiCorp Vault KV secret, optionally at a past version | `programs = ["vault"]`; `allow_env` for `VAULT_ADDR`/`VAULT_TOKEN`/`VAULT_NAMESPACE`; `allow_paths` on `~/.vault-token`; `network = true` |
| `openbao` | `openbao://<mount>/<path>[?version=<n>]#<field>` | the same, against an OpenBao server (`bao`) | `programs = ["bao"]`; the `BAO_*` equivalents; `network = true` |
| `infisical` | `infisical://<project>/<env>[/<folder>][?<opts>]#<secret>` | one secret of an Infisical project | `programs = ["infisical"]`; `allow_env` for the `INFISICAL_*` credentials; `network = true` |
| `bitwarden` | `bitwarden://<item>[#<field>]` | one field of an item in the Bitwarden vault the `bw` CLI keeps on disk: `password` by default, or `username`, `uri`, `totp`, `notes`, `field:<name>` | `programs = ["bw", "jq"]`; `allow_env` for `BW_SESSION`/`BW_PASSWORD`; `allow_paths` on the CLI's application directory; **no network** |
| `keepassxc` | `keepassxc://<database>/<entry>[#<attribute>]` | one attribute of an entry in a `.kdbx` on disk, unlocked by a key file or password file beside it | `programs = ["keepassxc-cli"]`; `allow_paths` on the vault directories; **no network** |
| `keepassxc-browser` | `keepassxc-browser://<url>[#<login>]` | a credential out of the database KeePassXC currently holds **unlocked**, over its browser-integration socket | `allow_paths` on that socket and the association; **no network** |

### The OAuth session holders

Three more are published, and they are a different kind of resolver. A vault
reader answers from something you already keep; these **hold the session
themselves**, so that an application which signed in for itself no longer has to.
Each mints a fresh access token from a refresh token that stays host-side, and
each is the only party allowed to refresh its account.

| Plugin | Reference form | Holds | Sandbox grant |
|---|---|---|---|
| `anthropic` | `anthropic://<account>` | a Claude.ai session, as `claude-code` obtains it | `programs = ["curl", "jq"]`; `network = true`; `state = true` |
| `openai` | `openai://<account>` | an OpenAI session, as `codex` obtains it | `programs = ["curl", "jq"]`; `network = true`; `state = true` |
| `nous` | `nous://<account>` | a Nous Portal session | `programs = ["curl", "jq"]`; `network = true`; `state = true` |

They are the only published plugins that declare `state = true`, because a
rotated refresh token that is not kept costs an interactive re-login. Setting one up takes two steps a
vault reader does not need: seeding the session once, and taking the application's
own copy away from it. Both are on [OAuth sessions](oauth), which also carries the
per-application traps.

Each is also a worked example of the manifest and the execution contract above:
read its `plugin.toml`, its `resolve` script and its README when writing your own.
They show what the structural cage forces on a resolver (declaring the host tools
it runs, and restoring the host `HOME` a tool derives its paths from), and each
reports a reference it does not hold as a clean absent, so any of them is safe to
place ahead of another source in a `from` chain.

Two conventions are worth copying. A reference is read as a URI, so the container
is the authority, the item is the path, options are the query and the selector is
the fragment. And where a `#` could belong to either side, the split follows the
side the source constrains: `sops://` and `vault://` split at the **last** `#`
because a path may hold one, while `infisical://` splits at the **first**, since
an Infisical secret name may hold a `#` and the project, environment and folder
before it cannot.

If a launch refuses because a declared program is not on `PATH`, the tool the
plugin runs is not installed, or not where the shell that starts sbx looks for
it. `sbx plugins info <name>` resolves each declared program the way a launch
would and shows the answer.

## Managing plugins

```
sbx plugins list              # built-in schemes + every installed plugin
                              #   (scheme, name, version, network grant, runnable?, origin)
sbx plugins info <scheme|name>  # a plugin's manifest, sandbox grant, and origin
                              #   (a resolver by its scheme, a broker by its name;
                              #    a built-in scheme is reported as such)
sbx plugins install <name|dir>  # install a bundled plugin by name, or copy a local ./dir
sbx plugins rm <name>...      # remove installed plugins (several names in one call)
sbx plugins verify [name]     # re-hash installed plugins against the digest recorded at install
sbx plugins upgrade [name] [--dry-run]   # replace with what the store lists now (digest-decided)
```

Installing is **a deliberate user act**: an agent inside the cage cannot run it.
The staged copy is validated exactly as the launcher will validate it and
refused, fail-closed, on any flaw. `sbx plugins` is host-level: it reads the data
directory, not a project's config.

### Where a plugin came from

A manifest is byte-identical whatever the source, so the install records the
plugin's **origin** and every listing reports it:

```
installed resolver plugins:
  kp://  kp  v1.0.0  no-network
    Resolve a secret from a local database
    from: store 'mine' (https://example.invalid/plugins.git)
```

The origin is either a local directory (by path) or a named store (with its URL, so
the answer survives `store rm`). A plugin installed before origins were recorded, or placed by hand: reads as **unknown**; reinstalling it records the source.

The record lives in `<data>/plugins/.origins/<name>.toml`, **outside** the
plugin's own directory: a store pins a plugin by a hash over its whole tree, so a
file added inside would put every installed plugin permanently out of agreement
with what was signed. It is display-only provenance and never a trust input, what makes an installed plugin trusted is the owner-only data directory it sits
in.

## Installing from a signed store

The other way a plugin arrives is a **signed store**: a git repository whose catalogue
is verified against a pinned Ed25519 key, with anti-rollback on the revision. Everything
on this page still applies to a plugin that came from one, since a store install
re-validates the manifest exactly as a local install does; what a store adds is where
the tree came from and how its authenticity is established. See
[Signed plugin stores](stores).

## Running a plugin's tests

A plugin may ship its own behaviour tests, as an executable `tests/run` inside its
directory. They are covered by the hash a store pins the plugin with, so they arrive
with it and are checked with it: what you run is the copy you installed, not a
checkout you would have to trust separately.

```sh
"$(sbx plugins info <name> | sed -n 's/^  exec: *//p' | xargs dirname)/tests/run"
```

sbx neither runs them nor requires them, and a plugin without a `tests/` directory
installs and resolves exactly the same. What they are worth is evidence: a resolver
decides whether a missing credential is *absent* (your chain falls through to a
weaker source) or *failed* (the launch aborts), and getting that line wrong is
silent. A suite that pins it lets you check the distinction rather than read the
code for it.

Expect a suite to exit **77** when a tool it needs is not installed, rather than
reporting a pass it never ran, and expect it to leave the plugin's own directory
untouched: a file written there would put the tree out of agreement with what was
signed, and `sbx plugins list` would report the plugin as MODIFIED.

If you write a plugin, keep its tests inside its directory for the same reason, and
do not rebuild sbx's sandbox in them. A hand-written cage is a second copy of what
sbx builds, and it stops testing what ships as soon as the two drift. Stand in for
the service a resolver talks to, not for the tool it runs.

## The broker type

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
  exists in this shape rather than as a plugin that owns the socket.

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
max_frame = 2048                   # the largest frame this protocol admits
host_deadline = 30                 # seconds sbx waits on the host resource for one exchange
deny_frame = [5]                   # optional: a refusal frame that needs no request context
uses_secret = true                 # may be handed a marker standing in for a credential
host_greets = true                 # the host speaks first, before the cage asks anything
inspect_replies = true             # also rule on what the host resource answers
```

Four rules a broker manifest is held to, each refused at load rather than at
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

## The signer type

A resolver answers *where a value comes from*. A broker answers *how the cage uses a
host resource without holding it*. A **signer** answers the question neither can:
*what does authenticating this request look like?*

[Credential injection](injection) already puts a credential on an outbound request:
a header name, and a value formed once at launch from the resolved plaintext. That
covers every auth point whose value is a constant, such as a bearer token, a Basic
pair or an API key. It cannot cover one whose value depends on the request itself:
a signature over the method, the path and the query, a per-request nonce, a
challenge answered in kind. `type = "signer"` is the third plugin type, for exactly
those.

```toml
name = "example-sigv4"
type = "signer"                       # no `scheme`: a signer claims no ref namespace
exec = "bin/sign"

[signer]
sets_headers = ["Authorization", "X-Example-Date"]   # every header it may put on a request
sees_headers = ["Content-Type"]                      # beyond the method, host and target
reads_secret = false                                 # true = handed the plaintext, not a marker
```

What bounds a signer is not a new argument, it is an inherited one:

- **The window is one host.** A signer is named by a `[[secret]]`, and a secret's
  `to` is a single concrete destination (a `*.` wildcard or a `re:` regex is refused
  at validation). So a signer is shown the requests of exactly the host its own
  declaration names, which is the host that already receives that credential on
  every request. No spelling of a manifest widens that: the destination comes from
  the config, never from the plugin.
- **The plugin is a pure filter**, on the same terms as a broker: no listening
  socket, no network descriptor, no host resource. It speaks to `sbx` alone, over
  stdin and stdout, from a host-side cage with an empty network namespace.

Together those are the ceiling: **a signer plugin can never see or place more than
the `[[secret]]` naming it already puts on the wire.** It is meant to place it far
better, bound to one request instead of replayable on any.

The rules a signer manifest is held to, each refused at load rather than at launch:

- **`network` and `state` are refused**, for the reason a broker's are. A signer is
  shown a credential's requests and, where it reads one, the credential itself.
- **`sets_headers` is required and non-empty.** A signer that sets nothing
  authenticates nothing, and the list is what makes the manifest a review surface:
  reading it tells you every header this plugin can write.
- **Some headers no manifest may declare.** `Host` chooses where the credential
  lands; `Content-Length`, `Transfer-Encoding` and `Trailer` choose where `sbx`
  thinks the request ends; `Connection`, `Upgrade`, `TE`, `Expect` and the
  `Proxy-*` family belong to the hop rather than to the request. Where a request
  goes, where it ends and what the connection becomes are sbx's, never a plugin's.
  The refusal is case-insensitive, since a header name is.
- **`sees_headers` is empty by default.** A request carries whatever the cage put on
  it, including credentials an app obtained by its own sign-in, which belong to no
  declaration. A plugin that must see one says which.
- **`reads_secret` is the step down, and it is labelled.** Off, the plugin is handed
  a marker standing in for the credential rather than the credential: it can place a
  secret it can never read, which is enough for one that is *carried*. It is not
  enough for one that is *computed*, since an HMAC over the canonical request is a
  function of the key. On, the plugin gets the key material, and it says so in the
  manifest that was reviewed rather than in the config of the machine that runs it.

:::note What a signer plugin does not reach
A signer is given no `scheme`, so nothing a secret's `from` names routes to it, and
it may not declare `brokers` of its own: a broker fences a cage's access to a host
resource, and a signer has no cage and reaches no resource.
:::

A declaration reaches it with [`sign`](../configuration/secret#sign-a-credential-computed-from-the-request):

```toml
[secret."s3.eu-west-1.amazonaws.com"]
from = "env://AWS_SECRET_ACCESS_KEY"
sign = "example-sigv4"
```

The plugin is started once for the launch and asked once per request. It is told the
destination the config named, the method, the target and the headers it declared in
`sees_headers`, and it answers with headers. **Any failure refuses the request** with a
`403` and the reason `signer-refused`: a request that could not be signed is never sent
unsigned.

What the tripwires watch also changes, and deliberately: for a signed credential the
[needle](redaction) is the **key**, not the signature. A signature is derived,
request-bound and single-use, while the key is the thing that must never leave the cage
verbatim.

Where a signer is visible: a refused request appears in
[`sbx net logs`](../cli/net) with the verdict `blocked` and the reason
`signer-refused`, and is counted under `BLOCKED` in `sbx net stats`. Unlike a broker,
a signer has **no feed of its own** in [`sbx logs`](../cli/logs): a signed request is
one line of the egress log like any other request, and there is nothing per-frame to
show. A plugin's own words reach you on a refusal, where the `403` repeats them.

## An honest residual: a networked resolver reaches the host network

- **A `network = true` resolver reaches the host network, not the cage's
  allowlist.** A resolver runs host-side (outside the agent's cage), so a manifest
  that declares `network = true`, to reach a remote secret-manager / KMS / third-party-vault engine, shares
  the **host** network and is **not** behind the cage's egress allowlist. This is
  accepted because resolvers are in the TCB (first-party, or trust-installed and
  signed from a store) and an engine resolver needs real network to do its job.
  The lever is keeping the resolver *set* trusted and scoping the secret at the
  source, not bounding the resolver's own egress. A `network = false` resolver
  runs in an empty network namespace and has no such reach.

## See also

- [Resolvers](resolvers): the built-in `env://`/`file://`/`sops://`
  schemes a plugin extends.
- [Secrets architecture](../secrets/): the never-in-cage invariant and why brokers stay
  first-party while resolvers are pluggable.
- [Signed plugin stores](stores): distributing and installing plugins from a
  verified remote.
- [`sbx plugins`](../cli/plugins): the `sbx plugins` command reference.
- [Security model](../concepts/security-model) /
  [The trust gate](../concepts/trust): the TCB and trust gates a plugin
  rests on.
  plugin model, the typed registry, and the store design.
