---
description: "Build or fetch the single static binary, or a dev build, and what the install script places where."
---

# Installation

`sbx` is a single binary. The shipping artifact is a **static musl binary** with no
runtime dependency on a system libc; a normal `cargo build` also works for
development.

See also: [`sbx doctor` and prerequisites](doctor) · [Quick start](quickstart).

## Runtime prerequisites

Before `sbx` can launch anything it needs:

- **Capability-bearing unprivileged user namespaces**: the security boundary
  everything rests on. Without them there is no boundary, so `sbx doctor`
  **hard-fails** rather than falling back to a weaker mechanism.
- **The bubblewrap engine** (`bwrap`): the sandbox itself. A release can embed its
  own static `bwrap`; otherwise the host's is used.
- **The `nix` binary**: drives the user-owned store. A release can embed its own
  static `nix`; otherwise the host's is used.

Run [`sbx doctor`](doctor) to check all of these at once. On a restricted
Ubuntu 24.04+ host, user namespaces may exist but be stripped of capabilities;
`doctor` checks specifically for the capability-bearing case.

## Running under WSL2

`sbx` runs inside a WSL2 distribution without adaptation. The shipping binary is
static, so the same artifact that runs on a native host runs here once it is copied
into the distribution's own filesystem. Copy it out of `/mnt/c` before running it:
the Windows drive is mounted through `drvfs`, which synthesises permission bits, and
the executable bit does not reliably survive there.

The WSL2 kernel has been observed to provide capability-bearing user namespaces, and it does not carry
the AppArmor restriction that an Ubuntu 24.04 host applies to them, so the boundary
`sbx` rests on is available with no sysctl to set (if that changes, [`sbx doctor`](doctor)
reports it before anything else runs). `bubblewrap` is not part of a
fresh distribution image and is installed from the distribution's own packages.
Install `nix` as the user that will run `sbx` rather than as `root`: run as root,
its single-user installer writes a configuration naming a build group it does not
create, and stops before it has a usable profile.

What differs from a native host is **resource limits**, which are hardening rather
than the boundary and therefore degrade instead of failing:

- A distribution running **systemd** (the default for recent Ubuntu images, set as
  `systemd=true` under `[boot]` in `/etc/wsl.conf`) has a user manager, and the cage
  is capped by a transient scope exactly as on a native host.
- A distribution running **without systemd** has no user session for a scope to be
  registered against, so the cage launches uncapped. This is the documented
  degradation and not a failure: `doctor` reports it, and the namespace, seccomp and
  egress layers are unaffected.

Graphical applications do reach the Windows desktop. WSLg publishes a Wayland socket
in the distribution, `sbx` binds it into the cage under the `wayland` GUI posture, and
a window opened by a caged application appears on the desktop with its own taskbar
entry, like any other window. An X11 application needs an X11 posture rather than the
Wayland one; asking for Wayland and running an X11 binary fails on the display, which
says nothing about the platform.

**WSLg belongs to one Windows session, and it is the session that started WSL first.**
That is the trap worth knowing, because nothing reports it: start the distribution
from a service, a remote shell or a scheduled task outside the desktop session and its
window server attaches there, so applications run with no error and their windows are
drawn where nobody can see them. `wsl --shutdown`, then a launch from the desktop
session, puts it back. The same holds for notifications, which Windows also delivers
per session.

Three further differences are worth knowing before they surprise you:

- **Where you launch from decides what is bound in.** A `wsl` shell opened from
  Windows starts in the Windows user profile under `/mnt/c`, and `sbx run` binds the
  project directory into the cage. Launching from there therefore hands the cage the
  Windows home directory, which is the opposite of what the security model is for.
  Keep projects in the distribution's own filesystem, where the bind is the project
  and nothing above it.
- **Refusals are raised as Windows toasts.** A distribution owns no
  `org.freedesktop.Notifications`, and the desktop these announcements are for is the
  Windows one, so under a WSL kernel `sbx` raises them there instead. It also keeps the
  stderr line: nothing in the toast call reports whether it was seen, because a session
  mismatch, Focus Assist, or a per-application notification setting each swallow one and
  return success. A duplicate line is the price of never announcing a refusal into
  silence. Should a distribution own that bus name after all, the ordinary desktop sink
  wins and neither of these applies.

  The toast carries **PowerShell's** name, and that is a choice rather than an oversight.
  A toast has to be raised under an application id Windows already knows; registering one
  for `sbx` means writing to the Windows registry from Linux, which is a heavier thing to
  do as a side effect of a notification than the wrong name on a banner is to read.

  A toast is drawn in the Windows session the distribution's interop belongs to, which is
  the session that started it. Start the distribution from a service or a remote shell and
  the toasts are drawn where nobody looks; `sbx` compares that session against the
  desktop's and says so once, after the first announcement, rather than leaving it to be
  discovered. `wsl --shutdown` and a launch from the desktop puts them back.
- **GPU acceleration needs the bridge libraries, and `sbx` binds them.** Where the
  Windows host has a GPU that WSL can share, the distribution gets an ordinary
  `renderD*` node and `gpu = true` grants it as it would on any Linux host. The driver
  behind that node is mesa's `d3d12`, which reaches the GPU through `libdxcore.so` and
  `libd3d12core.so`. Windows provides those under `/usr/lib/wsl/lib` rather than nixpkgs
  building them, so a hermetic cage holds the node and renders in software anyway. Under `gpu = true` that directory is bound read-only and put on the cage's
  loader path. Both halves are needed: bound and not on the path, the cage still
  answers `cannot open shared object file`, because a subdirectory of `/usr/lib` is not
  a default search path. A host without that directory is untouched.

- **The light/dark preference comes from Windows.** A distribution runs no desktop
  portal, so the bus name `sbx` reads that preference from owns nothing there. Under a
  WSL kernel it asks Windows instead, through its own registry, and seeds the cage with
  what the desktop is wearing. The two scales are opposites and `sbx` reconciles them,
  so nothing has to be set. What this does **not** do is follow a switch made after the
  launch: the relay that mirrors a live change subscribes to a bus signal, and Windows
  offers none to subscribe to across that boundary. A cage opens in the desktop's theme
  and keeps it for the session. On any other host nothing changes, and nothing is run:
  the branch is reached only by a WSL kernel.
- **No encapsulated storage volume.** A distribution's filesystem is an ordinary
  one, so the store is a plain directory rather than a compressed volume.
  `$SBX_DATA_DIR` can still point `sbx` at a volume that is mounted.

## Development build

For iterating on `sbx` itself:

```sh
cargo build
cargo run -- doctor      # preflight: user namespaces, bwrap, nix, …
```

The compiler is pinned by `rust-toolchain.toml`, so the first `cargo` command in a
fresh clone may download that exact toolchain before it builds anything. That is
deliberate rather than incidental: linting here denies warnings, and each compiler
release adds lints, so a floating compiler turns unchanged code red from one week to
the next. `mise install` provisions the same version, along with the pinned zig that
links the musl build.

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
[Provisioning](../concepts/provisioning) for how the engines are materialized and
verified.

## Shell completion

`sbx` ships its own completion script, for bash and zsh:

```sh
source <(sbx completion bash)     # this shell only
source <(sbx completion zsh)
```

To install it permanently, and for what does and does not complete, see
[`sbx completion`](../cli/completion).

## Verifying prerequisites

```sh
cargo build && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

The heavy sandbox end-to-end tests skip, rather than fail, when the host lacks user
namespaces, nix, or network, so a constrained runner reports skips instead of failures.
`mise run test-cage` turns those skips into failures, for a host that is supposed to be
able to sandbox.

## Development tasks

Common tasks are wired through mise:

```sh
mise run fmt             # cargo fmt --check, for sbx and for proc-shim/
mise run lint            # cargo clippy --all-targets -- -D warnings, for sbx and for proc-shim/
mise run rustdoc         # cargo doc with -D warnings (catches a doc reference that resolves to nothing)
mise run test            # cargo test --no-fail-fast (the whole suite; the sandbox e2e skip where the host cannot sandbox)
mise run coverage        # cargo-llvm-cov coverage report (pass --html for a browsable report)
mise run ci              # fmt + lint + rustdoc + test, as CI runs them
```

`fmt` and `lint` name `proc-shim/` separately because it is its own workspace root: the
in-cage exec shim must inherit none of sbx's dependency graph, and the cost of that
isolation is that no cargo invocation rooted at the repository reaches it, since `--all`
spans a workspace's members and the shim is not one.

The self-contained build has its own pair of tasks:

```sh
mise run build-bundled   # release musl binary WITH the embedded nix + bwrap engines (needs host nix)
mise run lint-bundled    # compile + clippy the bundled-* feature paths (needs host nix)
```

(The `static-nix` / `static-bwrap` steps those depend on are internal, hidden in `mise.toml`.)

## Building the documentation site

The user guide lives in
`docs-site/docs/guide/`
and is built with [Docusaurus](https://docusaurus.io/), configured in
`docusaurus.config.ts`.
Mermaid diagrams render in the browser, from `@docusaurus/theme-mermaid`.

```sh
mise run docs-install   # Node + the pinned npm packages, into docs-site/node_modules
mise run docs           # local preview at http://localhost:3000 (live reload)
mise run docs-check     # the navigation and imported-recipe checks, without a build
mise run docs-import    # regenerate secrets/providers/ from examples/secrets/
mise run docs-build     # strict build into docs-site/build/ (runs docs-check first)
mise run docs-serve     # build, then serve it; the only way to exercise search
```

The build is strict on purpose, and refuses to finish on any of four things:

- a **broken internal link or anchor**: a page or a heading that does not exist. A link
  to a file *outside* the guide directory (`README.md`, the build config, anything under
  `src/`) has to be a full GitHub URL rather than a relative path, since the site is
  built from `docs-site/docs/guide/` alone.
- a **page nothing routes to**: every page must be named in `sidebars.ts`, sit in a
  directory with an `index.md`, and be linked from both its section index and the guide
  index.
- a **stale imported recipe**: `docs/guide/secrets/providers/` is generated from
  `examples/secrets/*/README.md`. Edit the README, run `mise run docs-import`, and commit
  both.
- **markdown that MDX cannot parse**, most often a bare `<` in prose.

Each error names the page and what it could not resolve.

Search is [Pagefind](https://pagefind.app/), which indexes the built HTML in a
`postbuild` step. There is therefore **no search index under `mise run docs`**:
the field falls back to a disabled input, and `docs-serve` is what shows the real
thing.

A diagram is a fenced block labelled `mermaid`:

```mermaid
flowchart LR
    config["config"]
    trust["trust gate"]
    sandbox["SandboxSpec"]
    bwrap["bwrap argv"]
    config --> trust --> sandbox --> bwrap
```
