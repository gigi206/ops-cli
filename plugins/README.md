# sbx resolver plugins

A resolver plugin turns a secret *reference* into the secret's plaintext, **host-side**.
sbx runs the plugin in its own sandbox, captures its stdout, and hands the value to a
(first-party) broker — the plaintext never enters the cage.

## Installing and inspecting

A plugin lives in its own directory under the sbx data dir, `<data>/plugins/<name>/`
(`<data>` is `$XDG_DATA_HOME/sbx` or `~/.local/share/sbx`). The directory being owner-only
is what makes a plugin trusted by location — a project cannot plant one.

There are exactly two ways in, and a listing always says which one a plugin came through:

    sbx plugins install <dir>                      # copy a local directory in
    sbx plugins store install <store> <plugin>     # from a configured signed store
    sbx plugins rm <name>                          # remove an installed plugin

The plugins in *this* directory are the first kind: they are ordinary plugin directories, carried
in the repository as working examples rather than embedded in the binary. Install one straight
from a checkout:

    sbx plugins install ./plugins/pass

Both paths do the same placement. It is a deliberate user act (an agent inside the cage cannot run
it): the whole tree is copied (symlinks and special files refused), the staged copy is validated
exactly as the launcher will — a sound manifest, an owner-only regular-file executable — and the
install refuses, without placing anything, if the manifest is bad, the executable is not runnable,
a plugin of that name is already installed, or another installed plugin already claims the scheme.
The plugin is placed under its manifest `name`, not the source directory name.

A **store** install adds two things a local one cannot have: the catalogue is verified against the
store's pinned Ed25519 key, and the plugin's directory must reproduce the content hash that
catalogue pins. See [the guide](../docs/guide/secrets/plugins.md) for adding, verifying, and
rotating a store's key. To publish these examples (or your own) as a store:

    sbx plugins store publish <dir> --key <key-file>

(A plugin may also still be staged by hand into `<data>/plugins/<name>/`.)

Inspect what is installed:

    sbx plugins list            # the built-in schemes and every installed resolver plugin
    sbx plugins info <scheme>   # one plugin's manifest, sandbox grant, and origin
    sbx plugins verify [name]   # re-hash installed plugins against the digest recorded at install
    sbx plugins upgrade [name]  # replace with what the store lists now (the digest decides)

Both name where each plugin came from — a store (with its URL) or a local directory (with its
path) — which the manifest cannot say, since it is identical whatever the source. `list` also
flags a plugin whose executable the runner would refuse (not owner-only, not a regular file),
explains on stderr any plugin dropped as malformed, and reports in the listing itself any scheme
claimed by more than one plugin, naming the claimants to remove.

Every install records the digest of the tree it placed, and `verify` re-hashes and compares —
a plugin edited in place (its script *or* its manifest, which carries the sandbox grant) reads
`[modified since install]`. This is drift detection, not a security control: the record sits in
the same owner-only directory as the plugin. The boundary is that the directory is never mounted
into the cage.

## Contract

- sbx invokes the plugin's `exec` program with the **full ref as `argv[1]`**.
- the program prints the **plaintext to stdout and nothing else** (sbx trims one trailing
  newline).
- the exit code and stdout together say what happened:
  - **exit 0, non-empty stdout** → the resolved plaintext.
  - **exit 0, empty stdout** → a clean *absent*: the reference is simply not held by this
    resolver. In a fallback chain (`from = [...]`) sbx then tries the next source — so a plugin
    is safe to place before others. (A secret with no other source then fails closed, named.)
  - **non-zero exit** → a hard error: sbx fails closed, names the resolver, folds in **stderr**,
    and **never** falls through to a weaker source (a resolver error must not silently downgrade).
- stdout is **never logged**; only stderr appears in an error. A value containing a newline or
  NUL is rejected (it cannot be carried as a header).

A resolver is in the trusted computing base (it sees the plaintext), so sbx runs it under
least privilege: in its own sandbox with only the filesystem, environment, and network the
manifest declares — on top of a structural base (see below).

## Manifest (`plugin.toml`)

    name        = "pass"
    type        = "resolver"    # the only supported plugin type; sbx refuses anything else
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

sbx supplies a **structural environment and filesystem** on top of the grant, so a resolver
declares only the *extra* it needs: a minimal `PATH`, a read-only host userland (`/usr` and the
system libraries), a private `HOME` on a tmpfs, fresh `/proc` and `/dev`, and — under
`network = true` — the host network plus its DNS and TLS trust files
(`/etc/resolv.conf`, `/etc/ssl`, …). Without `network = true` the resolver runs in an empty
network namespace (no egress at all). The environment is otherwise cleared, the capabilities
dropped, and every namespace unshared; only the variables in `allow_env` are passed through, and
sbx's structural `HOME`/`PATH` take precedence over any the manifest names.

The built-in schemes `env`, `file`, and `sops` can never be claimed by a plugin — they always
win. A scheme claimed by more than one installed plugin is ambiguous, so **every** plugin
claiming it is dropped (fail-closed, never an arbitrary winner) and the conflict is reported by
`plugins list` and `plugins info <scheme>` until all but one claimant is removed; the scheme is
the namespace, so a second implementation must use a different one. Installing is refused on a
scheme that is claimed *or* contested, so only a hand-placed directory can create a conflict.
