---
sidebar_label: "plugin.toml"
description: "The field reference all three plugin types share, and the `[sandbox]` grant that bounds each one."
---

# The `plugin.toml` manifest

Every plugin is a directory holding this manifest and an executable, whatever its type.
The fields below are the resolver's; [a broker](broker) and [a signer](signer) each add
a table of their own and refuse some of what follows, and each says so on its own page.

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
  [The broker type](broker).
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

## See also

- [`[plugin.<name>]`](configuring): the other half, what this machine supplies for the
  names declared above.
- [The broker type](broker) / [The signer type](signer): the `[broker]` and `[signer]`
  tables, and the grants each type refuses.
