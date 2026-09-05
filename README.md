# sbx: a sandbox launcher for tools and AI agents

[![CI](https://github.com/gigi206/ops-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/gigi206/ops-cli/actions/workflows/ci.yml)

`sbx` is a **sandbox launcher**: a single static Rust binary that runs tools,
including **encapsulated AI agents**, inside a [bubblewrap](https://github.com/containers/bubblewrap)
sandbox where they can install a project's full dependency set via single-user,
daemonless [Nix](https://nixos.org/) **without mutating the host OS**.

It is **not** a container manager: there is no OCI runtime wrapping the cage, and the
default cage carries no image at all. A project may name one, and then `sbx` consumes a
published image from a registry; what it never does is produce one. The reference class is
bubblewrap-based sandboxes, tools whose job is isolation under namespace boundaries, not
environment managers that only set variables and isolate nothing.

## Why

Running an autonomous coding agent on a project means letting untrusted code
install dependencies and execute. `sbx` gives that agent a real boundary: it runs
as your user, but the **bind layout is the security control**, so the host
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
  (binds, network, secrets, packages, app definitions, …); the trust gate binds
  approval to the file's content hash, on the direnv model (`sbx trust`).

## Documentation

The complete, task-oriented **user guide** is published at
[gigi206.github.io/ops-cli](https://gigi206.github.io/ops-cli/), and its sources live
in [`docs-site/docs/guide/`](docs-site/docs/guide/index.md). It is split into small,
cross-linked pages covering the concepts, the how-to walkthroughs, the full
`.sbx.toml` configuration reference, every command, apps and profiles,
networking/egress, declared operations, secrets, and plugins. Start there.

It is a Docusaurus site: `mise run docs` serves it locally with live reload,
`mise run docs-build` runs the checks the publish job runs (navigation, links,
anchors, and the provider recipes imported from `examples/`), and `mise run docs-serve`
serves the built site, which is what the search index needs.

For the design rationale and the limits, see
[Decisions and limits](docs-site/docs/guide/concepts/decisions.md): what `sbx` does not do,
and why it is one process rather than a daemon, bubblewrap rather than raw namespaces, and a
decrypting proxy by default. The threat analysis lives beside the model it belongs to, in
[Security model](docs-site/docs/guide/concepts/security-model.md).

## Build

The shipping artifact is a **static musl binary**. Some dependencies carry
C/asm, so the musl target is built with
[`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild) (a self-contained
musl cross-cc via zig), wired up through [mise](https://mise.jdx.dev/):

```sh
mise install        # the pinned toolchain (rust, zig, cargo-zigbuild, …)
mise run build      # cargo zigbuild --release --target x86_64-unknown-linux-musl
```

For a normal development build:

```sh
cargo build
cargo run -- doctor   # preflight: user namespaces, bwrap, …
```

The compiler is pinned by `rust-toolchain.toml` and the rest of the chain by
`mise.toml`, so a fresh clone may download the pinned toolchain on its first `cargo`
command. Linting denies warnings and every compiler release adds lints: without the
pin, unchanged code goes red from one week to the next.

## Usage

```sh
sbx doctor                       # check the sandbox prerequisites
sbx run -- <cmd> [args…]         # run a command in the sandbox
sbx run                          # an interactive shell in the sandbox (no command)
sbx app run <name>               # launch a named agent profile (its own isolated $HOME)
sbx config show [--details]      # the resolved configuration for the current project
sbx search <query>               # discover Nix tools to declare
sbx upgrade [target]             # roll a managed channel forward (nix, mise, flake, …)
sbx trust .sbx.toml              # vouch for a project config's security fields
sbx session ls|attach|stop       # the live session registry
sbx gc [--prune]                 # reclaim the project's Nix store
```

A project is configured by an optional `.sbx.toml`. Its two free fields, `env` and
`timezone`, apply from any project, and so does `[fs]`, which can only close a path off
inside the cage; the security fields (`binds`, `network`, `secret`, `packages`,
`[app.<name>]`, …) apply only once the file is **trusted** (`sbx trust`), and the trust
is re-armed whenever the file changes.

### App profiles

A `[app.<name>]` table, or a standalone profile file under
`<config>/sbx/apps/<name>.toml`, defines a named, reusable agent launcher with
its own isolated `$HOME`, package set, network allowlist, and host-side credential
injection. The [`examples/app/`](examples/app/) directory ships importable starter
profiles (`sbx app import <file>`); see [`examples/README.md`](examples/README.md).

## Development

```sh
mise run fmt     # cargo fmt --check, for sbx and for proc-shim/
mise run lint    # cargo clippy --all-targets -- -D warnings, for sbx and for proc-shim/
mise run rustdoc # cargo doc with -D warnings (a doc reference that resolves to nothing)
mise run test    # cargo test --no-fail-fast (the heavy sandbox e2e skip without userns/nix/network)
mise run ci      # all of the above
```

`proc-shim/` is named separately in `fmt` and `lint` because it is its own workspace
root: the in-cage shim must inherit none of sbx's dependency graph, and the cost of
that isolation is that no cargo invocation rooted at the repository reaches it
(`--all` spans a workspace's members, and the shim is not one).

A test whose prerequisites are absent returns early, and `cargo test` counts that as a
pass, so `mise run test` ends by naming how many of its green tests did nothing, and
why. It runs `--no-fail-fast` for the same reason a skip is reported: without it cargo
stops at the first target that fails and the later test binaries never run, so a red
run says nothing about how much is red. On a host that is supposed to have userns,
bwrap and nix, make it prove it:

```sh
SBX_REQUIRE_CAPABLE=1 mise run test   # a missing host capability fails instead of skipping
mise run test-cage                    # the same, scoped to the suites that carry a cage skip
```

## License

See [LICENSE](LICENSE).
