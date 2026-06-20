# ops resolver plugins

A resolver plugin turns a secret *reference* into the secret's plaintext, **host-side**.
ops runs the plugin in its own sandbox, captures its stdout, and hands the value to a
(first-party) broker — the plaintext never enters the cage.

## Installing and inspecting

A plugin lives in its own directory under the ops data dir, `<data>/plugins/<name>/`
(`<data>` is `$XDG_DATA_HOME/ops` or `~/.local/share/ops`). The directory being owner-only
is what makes a plugin trusted by location — a project cannot plant one.

A curated set of resolver plugins is **built into the binary** (the default store). List what is
available and install one by name:

    ops plugins store list      # the resolver plugins bundled in the binary
    ops plugins install <name>  # place a built-in plugin (e.g. `ops plugins install pass`)

Or install your own from a local source directory, and remove by name:

    ops plugins install <dir>   # copy a local plugin directory in (e.g. `ops plugins install ./mine`)
    ops plugins rm <name>       # remove an installed plugin

`install` reads its argument syntactically: a bare `name` is a built-in store plugin, while a
path-like argument (one that contains a `/` or starts with `.`, such as `./mine` or `/abs/mine`)
is a local directory — so the command never depends on the current directory's contents. Either
way it is a deliberate user act (an agent inside the cage cannot run it). It copies the whole tree
(refusing symlinks or special files), validates the staged copy exactly as the launcher will — a
sound manifest, an owner-only regular-file executable — and refuses, without placing anything, if
the manifest is bad, the executable is not runnable, a plugin of that name already exists, or
another installed plugin already claims the scheme. The plugin is placed under its manifest `name`
(not the source directory name). The built-in store needs no fetch, network, or signature — trust
is the binary itself; a remote, signed store (catalogue + signature verification + `update`) comes
later. (A plugin may also still be staged by hand into `<data>/plugins/<name>/`.)

Inspect what is installed:

    ops plugins list            # the built-in schemes and every installed resolver plugin
    ops plugins info <scheme>   # one plugin's manifest and sandbox grant

`list` flags a plugin whose executable the runner would refuse (not owner-only, not a regular
file) and explains, on stderr, any plugin that was discovered but dropped (a malformed
manifest, or two plugins claiming one scheme).

## Contract

- ops invokes the plugin's `exec` program with the **full ref as `argv[1]`**.
- the program prints the **plaintext to stdout and nothing else** (ops trims one trailing
  newline).
- the exit code and stdout together say what happened:
  - **exit 0, non-empty stdout** → the resolved plaintext.
  - **exit 0, empty stdout** → a clean *absent*: the reference is simply not held by this
    resolver. In a fallback chain (`from = [...]`) ops then tries the next source — so a plugin
    is safe to place before others. (A secret with no other source then fails closed, named.)
  - **non-zero exit** → a hard error: ops fails closed, names the resolver, folds in **stderr**,
    and **never** falls through to a weaker source (a resolver error must not silently downgrade).
- stdout is **never logged**; only stderr appears in an error. A value containing a newline or
  NUL is rejected (it cannot be carried as a header).

A resolver is in the trusted computing base (it sees the plaintext), so ops runs it under
least privilege: in its own sandbox with only the filesystem, environment, and network the
manifest declares — on top of a structural base (see below).

## Manifest (`plugin.toml`)

    name        = "pass"
    type        = "resolver"    # the only supported plugin type; ops refuses anything else
    scheme      = "pass"        # the ref scheme this plugin claims — one scheme, one plugin
    exec        = "resolve"     # program to run, relative to the plugin directory (no `..`)
    version     = "0.1.0"
    description = "..."

    [sandbox]                                       # least privilege granted to the plugin
    allow_paths = ["~/.password-store",             # extra paths, bound READ-ONLY
                   "$XDG_RUNTIME_DIR/gnupg"]
    allow_env   = ["GNUPGHOME"]                      # host env vars to pass through
    network     = false                             # whether the resolver may reach the network

`allow_paths` entries are bound **read-only**, and **only if present** — a path that names a
runtime artifact (such as the gpg-agent socket directory, which exists only once an agent has
run) is simply skipped where it is absent, so one manifest stays portable across hosts; the
resolver then fails closed inside if it genuinely needed what was missing. A leading `~` or
`$HOME` expands to the home directory and a leading `$XDG_RUNTIME_DIR` to the runtime directory
(where runtime sockets such as the gpg-agent socket live); **any other `$VARIABLE` is rejected**
— there is no arbitrary environment interpolation into a bind path. A literal path must be
absolute.

ops supplies a **structural environment and filesystem** on top of the grant, so a resolver
declares only the *extra* it needs: a minimal `PATH`, a read-only host userland (`/usr` and the
system libraries), a private `HOME` on a tmpfs, fresh `/proc` and `/dev`, and — under
`network = true` — the host network plus its DNS and TLS trust files
(`/etc/resolv.conf`, `/etc/ssl`, …). Without `network = true` the resolver runs in an empty
network namespace (no egress at all). The environment is otherwise cleared, the capabilities
dropped, and every namespace unshared; only the variables in `allow_env` are passed through, and
ops's structural `HOME`/`PATH` take precedence over any the manifest names.

The built-in schemes `env`, `file`, and `sops` can never be claimed by a plugin — they always
win. A scheme claimed by more than one installed plugin is ambiguous, so **every** plugin
claiming it is dropped (fail-closed, never an arbitrary winner); the scheme is the namespace, so
a second implementation must use a different one.
