# Installation

`sbx` is a single binary. The shipping artifact is a **static musl binary** with no
runtime dependency on a system libc; a normal `cargo build` also works for
development.

See also: [`sbx doctor` and prerequisites](doctor.md) · [Quick start](quickstart.md).

## Runtime prerequisites

Before `sbx` can launch anything it needs:

- **Capability-bearing unprivileged user namespaces** — the security boundary
  everything rests on. Without them there is no boundary, so `sbx doctor`
  **hard-fails** rather than falling back to a weaker mechanism.
- **The bubblewrap engine** (`bwrap`) — the sandbox itself. A release can embed its
  own static `bwrap`; otherwise the host's is used.
- **The `nix` binary** — drives the user-owned store. A release can embed its own
  static `nix`; otherwise the host's is used.

Run [`sbx doctor`](doctor.md) to check all of these at once. On a restricted
Ubuntu 24.04+ host, user namespaces may exist but be stripped of capabilities;
`doctor` checks specifically for the capability-bearing case.

## Development build

For iterating on `sbx` itself:

```sh
cargo build
cargo run -- doctor      # preflight: user namespaces, bwrap, nix, …
```

## Release build (static musl)

Some dependencies carry C/asm, so the musl target is built with
[`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild) (a self-contained
musl cross-cc via zig), wired up through [mise](https://mise.jdx.dev/):

```sh
mise install        # zig + cargo-zigbuild
mise run build      # cargo zigbuild --release --target x86_64-unknown-linux-musl
```

The resulting binary is self-contained and can be copied to another x86_64 Linux
host.

### Self-contained engines (optional)

A release can embed its **own** static `nix` and `bwrap` so it does not depend on
host-installed engines. These are opt-in build features (`bundled-nix`,
`bundled-bwrap`); the default build uses host engines so CI stays lean. When built
this way, `sbx doctor` reports which engine it would use and why. See
[Provisioning](../concepts/provisioning.md) for how the engines are materialized and
verified.

## Verifying prerequisites

```sh
cargo build && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

The heavy sandbox end-to-end tests skip (rather than fail) when the host lacks user
namespaces, nix, or network — so the suite is green on a constrained CI runner.

## Development tasks

Common tasks are wired through mise:

```sh
mise run fmt     # cargo fmt --check
mise run lint    # cargo clippy --all-targets -- -D warnings
mise run test    # cargo test
mise run ci      # all of the above
```
