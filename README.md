# sbx — a sandbox launcher for tools and AI agents

[![CI](https://github.com/gigi206/ops-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/gigi206/ops-cli/actions/workflows/ci.yml)

`sbx` is a **sandbox launcher**: a single static Rust binary that runs tools —
including **encapsulated AI agents** — inside a [bubblewrap](https://github.com/containers/bubblewrap)
sandbox where they can install a project's full dependency set via single-user,
daemonless [Nix](https://nixos.org/) **without mutating the host OS**.

It is **not** a container manager — no OCI runtime wrapping, no image to build,
no shared host kernel. The reference class is bubblewrap-based sandboxes —
tools whose job is isolation under namespace boundaries — not environment
managers that only set variables and isolate nothing.

## Why

Running an autonomous coding agent on a project means letting untrusted code
install dependencies and execute. `sbx` gives that agent a real boundary: it runs
as your user, but the **bind layout is the security control** — the host
filesystem and your secrets are absent from the cage unless explicitly and
trustedly granted. The agent self-equips a per-project Nix store it cannot use to
escape, behind an always-on seccomp filter and best-effort resource limits; egress
is a deny-by-default allowlist and can be opened back up to the host network.

## Security model (the essentials)

- **The default posture is the locked-down agent** (untrusted actions), not the
  interactive shell.
- **Hard requirement: capability-bearing unprivileged user namespaces.** Without
  them there is no boundary, so `sbx doctor` hard-fails rather than falling back
  to emulation.
- The cage runs **as your uid** (same-uid), so the bind layout *is* the control:
  a secret is protected by being **absent**, not merely read-only.
- Always-on enforcement: bubblewrap (all namespaces + `no_new_privs` + drop all
  capabilities) and a **seccomp** denylist; **cgroup v2** resource limits where the
  host supports them (best-effort, never the boundary).
- Network egress is a **deny-by-default allowlist**, enforced by a host-side
  TLS-terminating proxy reached over a bound socket from an empty network namespace.
  A cage nobody configured reaches only the built-in self-equip set; `network = "shared"`
  opts back into the unfiltered host network.
- An untrusted project's `.sbx.toml` **cannot** touch security-relevant fields
  (binds, network, secrets, packages, app definitions); the trust gate binds
  approval to the file's content hash — the direnv model (`sbx trust`).

## Documentation

The complete, task-oriented **user guide** lives in
[`docs-site/docs/guide/`](docs-site/docs/guide/index.md) — split into small,
cross-linked pages covering the concepts, the full `.sbx.toml` configuration reference,
every command, apps and profiles, networking/egress, and secrets. Start there.

It is also a Docusaurus site: `mise run docs` serves it locally with live reload, and
`mise run docs-serve` serves the built site, which is what the search index needs.

For the design rationale and threat analysis, see the `docs/*.md` design documents (the
architecture, threat model, and security stack), linked from the guide.

## Build

The shipping artifact is a **static musl binary**. Some dependencies carry
C/asm, so the musl target is built with
[`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild) (a self-contained
musl cross-cc via zig), wired up through [mise](https://mise.jdx.dev/):

```sh
mise install        # zig + cargo-zigbuild
mise run build      # cargo zigbuild --release --target x86_64-unknown-linux-musl
```

For a normal development build:

```sh
cargo build
cargo run -- doctor   # preflight: user namespaces, bwrap, …
```

## Usage

```sh
sbx doctor                       # check the sandbox prerequisites
sbx run -- <cmd> [args…]         # run a command in the sandbox
sbx run                          # an interactive shell in the sandbox (no command)
sbx app run <name>               # launch a named agent profile (its own isolated $HOME)
sbx config show [--details]      # the resolved configuration for the current project
sbx search <query>               # discover Nix tools to declare
sbx upgrade [nix|mise|flake]     # roll managed toolchains forward
sbx trust .sbx.toml              # vouch for a project config's security fields
sbx ls | attach | stop | gc      # session registry + housekeeping
```

A project is configured by an optional `.sbx.toml`. Free fields (e.g. `env`)
apply from any project; security fields (`binds`, `network`, `secret`,
`packages`, `[app.<name>]`, …) apply only once the file is **trusted**
(`sbx trust`), and the trust is re-armed whenever the file changes.

### App profiles

A `[app.<name>]` table — or a standalone profile file under
`<config>/sbx/apps/<name>.toml` — defines a named, reusable agent launcher with
its own isolated `$HOME`, package set, network allowlist, and host-side credential
injection. The [`examples/app/`](examples/app/) directory ships importable starter
profiles (`sbx app import <file>`); see [`examples/README.md`](examples/README.md).

## Development

```sh
mise run fmt     # cargo fmt --check
mise run lint    # cargo clippy --all-targets -- -D warnings
mise run test    # cargo test (the heavy sandbox e2e skip without userns/nix/network)
mise run ci      # all of the above
```

A test whose prerequisites are absent returns early, and `cargo test` counts that as a
pass — so `mise run test` ends by naming how many of its green tests did nothing, and
why. On a host that is supposed to have userns, bwrap and nix, make it prove it:

```sh
SBX_REQUIRE_CAPABLE=1 mise run test   # a missing host capability fails instead of skipping
```

## License

See [LICENSE](LICENSE).
