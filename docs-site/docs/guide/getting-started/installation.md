---
description: "Install the released static binary with one command, and what the install script places where, or build it yourself."
---

# Installation

`sbx` is a single binary. The shipping artifact is a **static musl binary** with no
runtime dependency on a system libc; a normal `cargo build` also works for
development.

See also: [`sbx doctor` and prerequisites](doctor) · [Quick start](quickstart).

## Install a released binary

```sh
curl -fsSL https://raw.githubusercontent.com/gigi206/ops-cli/HEAD/install.sh | sh
```

The script runs as you, never as root, and does this:

1. Picks the asset for the machine, `sbx-linux-x86_64` or `sbx-linux-aarch64`, and stops on
   any other system or architecture. On macOS it sets up a Linux guest instead, as
   [Running under Lima](#running-under-lima-macos) describes.
2. Looks up the newest **stable** release through the GitHub API. A pre-release is never
   chosen on its own.
3. Downloads the binary and the `.sha256` published beside it, and stops without installing
   anything when they do not match.
4. Places the binary at `~/.local/bin/sbx`, writing it beside its destination and renaming
   it over the old one, so an `sbx` already running keeps its file.
5. Says so when that directory is not on your `PATH`, with the line to add to your shell's
   startup file, and when another `sbx` comes first on it. No startup file is edited.
6. Runs [`sbx doctor`](doctor), which checks the host and unpacks the `nix` and `bwrap`
   engines the release carries into `~/.local/share/sbx/engine/` (about 40 MB). The store
   itself is created on the first launch. A problem `doctor` reports does not undo the
   install.

Each step can be steered by a variable, set on the `sh` side of the pipe: set before `curl`,
it would reach `curl` and not the script.

| Variable | Meaning |
|---|---|
| `SBX_VERSION` | the release tag to install; `latest` is the rolling pre-release built from the development branch (default: the newest stable release) |
| `SBX_INSTALL_DIR` | the absolute directory the binary goes in (default: `~/.local/bin`) |
| `SBX_REPO` | the GitHub repository to install from, `owner/name` (default: `gigi206/ops-cli`) |
| `SBX_DOWNLOAD_BASE` | where the assets are fetched from (default: that repository's releases) |
| `SBX_RELEASES_API` | where the newest stable release is looked up (default: that repository's API) |
| `SBX_SOURCE_BASE` | macOS only: where the Lima template and the wrapper are read from, as `<base>/<tag>/dist/macos/` (default: that repository's files at the release's tag) |
| `SBX_LIMA_PROJECTS` | macOS only: the subtree of your home the guest can see, relative to it (default: `Projects`) |

No stable release is published yet, so for now the default stops and names the way out,
which is the pre-release:

```sh
curl -fsSL https://raw.githubusercontent.com/gigi206/ops-cli/HEAD/install.sh | SBX_VERSION=latest sh
```

The checksum comes from the same release as the binary. It catches a download that was
corrupted or cut short, not a release that was tampered with: that one would carry a
matching checksum. The script is also written so that a download of it cut short runs
nothing, since everything it does is one function called on its last line.

### Keeping it up to date

Once installed, `sbx` replaces itself:

```sh
sbx upgrade self
```

It follows the release it was installed from, makes the same checksum check, and
replaces the binary the same way, writing beside it and renaming over it.
[`sbx upgrade self`](../cli/upgrade#upgrading-sbx-itself) gives the details. A binary
whose `sbx --version` shows no release in parentheses predates the release stamp, or was
built from source. It has nothing to follow, so the script is how to replace it, once.

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

A session's control sockets, which `sbx net`, `sbx proc`, `sbx task status` and the
logs commands talk to, need **Linux 5.5 or later**, which `doctor` does not check.
They answer only a caller in `sbx`'s own PID namespace, never a cage's, and an older
kernel cannot tell them which namespace a caller runs in, so there they refuse every
connection. A launch runs without it. See [the security model](../concepts/security-model).

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
- **Refusals and an app's own notifications are raised as Windows toasts.** A
  distribution owns no `org.freedesktop.Notifications`, and the desktop these announcements are for is the
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

  A caged app's own notifications take the same route under `dbus = true`, as toasts
  titled `sandboxed · <app>` so they cannot pass for a refusal (see
  [`dbus`](../configuration/dbus)), and land in the same session. The session check runs
  only once a refusal has been announced, so a launch that refuses nothing raises the
  app's toasts into that session without the note.
- **GPU acceleration needs the bridge libraries, and `sbx` binds them.** Where the
  Windows host has a GPU that WSL can share, the distribution gets an ordinary
  `renderD*` node and `gpu = true` grants it as it would on any Linux host. The driver
  behind that node is mesa's `d3d12`, which reaches the GPU through `libdxcore.so` and
  `libd3d12core.so`. Windows provides those under `/usr/lib/wsl/lib` rather than nixpkgs
  building them, so a hermetic cage holds the node and renders in software anyway. Under `gpu = true` that directory is bound read-only and put on the cage's
  loader path. Both halves are needed: bound and not on the path, the cage still
  answers `cannot open shared object file`, because a subdirectory of `/usr/lib` is not
  a default search path. A host without that directory is untouched.

- **The light/dark preference comes from Windows, and a later switch is followed.** A
  distribution runs no desktop portal, so the bus name `sbx` reads that preference from
  owns nothing there. Under a WSL kernel it asks Windows instead, through its own
  registry, and seeds the cage with what the desktop is wearing. The two scales are
  opposites and `sbx` reconciles them, so nothing has to be set. A switch made after the
  launch is mirrored as well: Windows raises a notification of its own when that registry
  value is written, so `sbx` waits on it through a single interop process that lives as
  long as the cage, rather than asking again on a timer. An app that reads the preference
  only at startup still opens in whatever it was given, so relaunching is what changes
  such an app. On any other host nothing changes, and nothing is run: the branch is
  reached only by a WSL kernel.
- **No encapsulated storage volume.** A distribution's filesystem is an ordinary
  one, so the store is a plain directory rather than a compressed volume.
  `$SBX_DATA_DIR` can still point `sbx` at a volume that is mounted.

## Running under Lima (macOS)

macOS is not a host `sbx` runs on. The boundary it rests on is a capability-bearing
unprivileged user namespace, macOS has no such thing, and `doctor` hard-fails rather
than falling back to something weaker. What macOS can be is the host a Linux guest runs
on, which is the same arrangement as WSL2 above: the binary that runs is an ordinary
Linux `sbx` in an ordinary Linux kernel, and the Mac is what sits at the end of the
bridges. Nothing in `sbx` is macOS-aware.

The guest comes from [Lima](https://lima-vm.io), which the install script does not
install. With Lima in place, the same command as on Linux sets up the rest:

```sh
brew install lima
curl -fsSL https://raw.githubusercontent.com/gigi206/ops-cli/HEAD/install.sh | SBX_VERSION=latest sh
```

On macOS the script downloads no binary. It reads the Lima template, the wrapper and the
Mac-side bridge this repository ships at the release's tag, creates a Lima instance named
`sbx` from the template for that release, starts it, installs the wrapper at
`~/.local/bin/sbx`, saying so when that directory is not on your `PATH`, and installs two
launchd agents, `org.sbx.lima.theme` and `org.sbx.lima.notify`, in
`~/Library/LaunchAgents`. macOS announces each new agent once with a "Background Items
Added" banner naming `sbx-bridge`, the program both agents run, and lists it under that name
in Login Items settings; each is removed with `launchctl bootout gui/$(id -u)/<label>` and the
deletion of its plist. Beside the bridge it compiles `sbx.app`, the application Notification
Center shows sbx's notes under, removed by deleting
`~/.local/share/sbx/lima/sbx.app`. The first start downloads an image
and provisions the guest, including its compositor and sound server, which takes a few
minutes. An instance named `sbx` that already exists is kept as it is: running the script
again only reinstalls the wrapper, and an instance keeps the template it was created
from, so a newer template reaches it only by `limactl delete sbx` and running the script
again. The
template and the wrapper carry no checksum; they come from the same origin as the script
itself.

`SBX_LIMA_PROJECTS` names the subtree of your home the guest can see, relative to it, and
defaults to `Projects`; the script creates it. The same setup by hand, from a checkout of
this repository:

```sh
mkdir -p ~/Projects ~/.local/state/sbx/lima/theme ~/.local/state/sbx/lima/notify
limactl create --name sbx --param projects=Projects dist/macos/sbx.yaml
limactl start sbx
sudo install -d -m 0755 /usr/local/bin
sudo install -m 0755 dist/macos/sbx /usr/local/bin/sbx
```

`/usr/local/bin` is on the default macOS `PATH` but is not created by macOS itself, and
the `install` macOS ships has no `-D` to create it, hence the line before the last.

Then `cd` into a project under that subtree and run `sbx` as you would anywhere:

```sh
cd ~/Projects/my-app
sbx run -- npm test
```

The global configuration is the guest's, under the guest's home, and a file of that name on
the Mac is read by nothing. It is written through the wrapper like any other command, from a
directory under the shared subtree:

```sh
cd ~/Projects/my-app
sbx config set -g gui wayland
sbx config set -g audio true
```

**The guest sees one subtree of your home, and that is a deliberate narrowing.** Lima's
own default mounts the whole of `~`. That is the opposite of what `sbx` is for: the
project is writable and nothing above it is in scope at all, so the template mounts one
subtree and asks you to name yours. The mount is writable, because a cage that cannot
write the project is not a sandbox to work in, and that is also what makes the narrowing
worth doing: apart from the two small directories the theme and notification channels
below use, this mount is the whole of the guest's reach into the Mac's disk.

Four things come from Lima rather than from `sbx`, and only the last takes a line of
configuration:

- **The path is the same on both sides.** A mount appears in the guest at the path it has
  on the Mac, so `/Users/you/Projects/my-app` is that path in the guest too, and nothing
  has to be translated.
- **The working directory is carried over.** The wrapper hands the guest the directory
  you were standing in, and `sbx run` builds the cage around it. A directory outside the
  mounted subtree is refused by name, including one whose path the guest also has on its
  own disk, such as `/tmp`: the cage is never built around the guest's directory of the
  same name.
- **Resource limits work.** Lima enables lingering for the guest user at boot, so there is
  a user manager for the transient scope to be registered against and the cage is capped
  as it is on a native Linux host.
- **A forwarded port reaches the Mac.** A cage has its own network namespace, so a server
  started in it listens on the cage's loopback, which nothing outside the cage reaches.
  Declare the port in [`forward`](../networking/forward), as on a native Linux host, and
  `sbx` binds it on the guest's loopback. Lima forwards the guest's loopback listeners to
  the Mac, so `localhost:<port>` in a Mac browser then reaches the server.

**The guest and the release drift apart, and a restart is what closes it.** The binary is
installed by provisioning, from the published release, verified against the checksum
published beside it. Lima re-runs provisioning on restart, so `limactl stop sbx && limactl
start sbx` converges the guest on the current build. A guest left running falls behind
instead, and the wrapper says so on stderr once it has been up long enough to matter. If
`limactl stop` does not return, `limactl stop --force sbx` ends the instance, and the next
`sbx` command starts the guest again.

Three smaller things follow from the command crossing an SSH connection rather than being
run locally. Exit codes come back: the wrapper exits with what the caged program exited
with, though a connection failure surfaces as 255, which a program is also free to return.
A terminal is allocated only when the wrapper's own standard output is one, so an
interactive tool behaves differently inside a pipeline here than it does natively. And the
command is run through a login shell in the guest, so the guest's own profile is read
before `sbx` starts.

Three differences from a native host are worth knowing before they surprise you:

- **The window shows the whole guest screen, not one window per application.** With
  `vmType: vz`, Lima opens a native macOS window and draws the guest's framebuffer in it,
  at a fixed 1920 by 1200. The template runs Weston on that display, under the socket name
  `wayland-sbx`, and the wrapper points a launch at it, so a `gui = "wayland"` posture binds
  the compositor socket of the *guest*, exactly as on Linux, and the caged application
  appears inside that window. This is not what WSLg does, which publishes each window onto
  the Windows desktop with its own taskbar entry. `sbx` writes no display code either way,
  and there is no VNC involved. Weston's keyboard layout is US. X11 is not offered here for the same reason it is not
  offered anywhere else in `sbx`: an X client can snoop and drive every other window on the
  same display.
- **Sound plays through the Mac, and there is no microphone yet.** `audio.device: vz` gives
  the guest a virtio-sound device played through the Mac's default output, and the template
  runs PipeWire with `pipewire-pulse` behind it, so the `audio = true` posture behaves as
  it does on any Linux host. The guest user reaches the sound card and the display through
  its primary group, which every session carries from the start. Lima 2.2.1 attaches the
  output stream alone, so the guest has no capture device and an app's microphone finds
  nothing.
- **The light/dark appearance follows the Mac's, live.** Under `dbus = true` a cage opens in
  the Mac's appearance and follows a later switch, Auto mode included. The guest cannot ask
  the Mac, so the `org.sbx.lima.theme` agent writes `dark` or `light` into a directory the
  guest mounts read-only, on every change to the global preferences and once a minute; `sbx`
  reads it at launch and every two seconds after, so a switch reaches a running app within
  about ten seconds.
- **Refusals and an app's own notifications are raised in Notification Center.** The guest
  runs no notification daemon, so `sbx` drops each note into a second directory, writable from
  the guest: its own refusals, and under `dbus = true` what a caged app raises, titled
  `sandboxed · <app>` so it cannot pass for a refusal (see [`dbus`](../configuration/dbus)). The
  `org.sbx.lima.notify` agent raises each note and removes it, under `sbx.app`, a small
  application the installer compiles on the Mac with the system's own tools so the note carries
  sbx's name and icon. macOS asks at the first note whether sbx may notify, and shows nothing
  until it is allowed. Without that application, because a tool it is built with was missing or
  it was deleted, the note is raised through `osascript` under Script Editor's icon. As under WSL
  the stderr line of a refusal is kept, since nothing tells the guest whether the note was seen.
  Refusals and app notifications are each held to 32 notes waiting for an agent that is not
  running and to 5 raised per run of the agent, so a busy app never crowds out a refusal. The
  agent reads only regular files from that directory, and only their first bytes, because the
  guest is the one writing there. Neither directory is ever given to a cage.
- **There is no GPU acceleration.** `vmType: vz` gives the guest a virtio-GPU device without
  3D acceleration. `gpu = true` grants its render node, and mesa renders in software
  (`llvmpipe`) behind it; the launch proceeds. The scope this template commits to is CLI plus GUI, and the two
  halves cannot currently be had together: the virtio-GPU route that does expose a GPU to a
  Linux guest on Apple Silicon opens no screen. CUDA is out of reach by any route on a Mac,
  because Apple Silicon carries no NVIDIA hardware.

**Where this is supported.** The template and the wrapper, the window, the sound and the
GPU behaviour above included, are verified on macOS x86_64 with Lima 2.2.1. Apple Silicon is
not verified: neither the `sbx-linux-aarch64` binary in the guest nor the window, sound and
GPU behaviour there. [`sbx doctor`](doctor) inside the guest is what decides whether
the boundary is there, and it is the first thing to run after `limactl start`. The
acceptance workflow in the repository runs these checks on a Mac: GitHub's hosted Intel
runner (`macos-26-intel`), the kind of hosted Mac that lets a job start a virtual machine.

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
host. That task builds x86_64 only. A published release carries two assets,
`sbx-linux-x86_64` and `sbx-linux-aarch64`, each built on a runner of its own
architecture; to build the other one here, name its target instead:

```sh
cargo zigbuild --release --target aarch64-unknown-linux-musl
```

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
`mise run test-cage` turns the skips for a missing host capability into failures, for a
host that is supposed to be able to sandbox. A skip for the network stays a skip there
too, including a binary cache that failed a download: no setting on the host makes a
remote dependable.

## Development tasks

Common tasks are wired through mise:

```sh
mise run fmt             # cargo fmt --check, for sbx and for proc-shim/
mise run lint            # cargo clippy --all-targets -- -D warnings, for sbx and for proc-shim/
mise run rustdoc         # cargo doc with -D warnings (catches a doc reference that resolves to nothing)
mise run test            # cargo test --no-fail-fast (the whole suite; the sandbox e2e skip where the host cannot sandbox)
mise run audit           # cargo audit against the RustSec advisory database, for both lockfiles
mise run coverage        # cargo-llvm-cov coverage report (pass --html for a browsable report)
mise run ci              # fmt + lint + rustdoc + audit + test, as CI runs them
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
