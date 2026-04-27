# ops — Containerized development environment

[![tests](https://github.com/gigi206/ops-cli/actions/workflows/tests.yml/badge.svg)](https://github.com/gigi206/ops-cli/actions/workflows/tests.yml)

Shell wrapper around **docker / podman / nerdctl** that provides a ready-to-use development container, with AI agents (Claude Code, Gemini, OpenCode, Codex), mise + Nix (via the mise-nix plugin), and standard tooling (git, semgrep, ripgrep, jq, ast-grep, gh).

The goal: a single entry point (`ops.sh`) to build, run, debug and update the environment, regardless of the underlying container runtime.

---

## Table of contents

**Getting started**
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)

**Reference**
- [Subcommands](#subcommands)
- [`run` flags](#run-flags)
- [Configuration (`ops.conf`) & environment variables](#configuration-opsconf--environment-variables)
- [Build-time tools (`EXTRA_MISE_TOOLS` / `OPS_BUILD_ARGS`)](#build-time-tools-extra_mise_tools--ops_build_args)
- [GUI apps (Chrome, Wayland)](#gui-apps-chrome-wayland)
- [Exit codes](#exit-codes)

**Configuration patterns**
- [Custom aliases](#custom-aliases)
- [Images (Arch / Debian)](#images-arch--debian)
- [Named images (profiles)](#named-images-profiles)
- [Runtime selection](#runtime-selection)

**Inside the container**
- [Nix tooling (mise-nix plugin)](#nix-tooling-mise-nix-plugin)
- [AI CLI agents](#ai-cli-agents)
- [Named volumes `ops-*`](#named-volumes-ops-)
- [Labels](#labels)

**Usage guides**
- [Typical flows](#typical-flows)

**Support**
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)

**Project**
- [Project structure](#project-structure)
- [Tests](#tests)
- [License & contributing](#license--contributing)

---

## Requirements

- Linux (tested on Debian/Ubuntu/Arch)
- `bash` 5+
- **One** container runtime among:
  - `docker` — installed via `apt install docker-ce` / `pacman -S docker` (or Docker Desktop)
  - `podman` — `apt install podman` / `pacman -S podman`
  - `nerdctl` — **auto-installable** through `ops.sh nerdctl install` (downloads nerdctl-full into `~/.local/share/ops/nerdctl/`)
- System tooling always used by `ops.sh`: `curl`, `tar`, `sha256sum`, `awk`, `sed`, `grep`, `realpath` (any `coreutils`-shipped build).
- `nerdctl`-specific extras (only needed when `OPS_RUNTIME=nerdctl`): `systemctl --user` (manages `containerd.service` / auto-start / `self-update`), `mktemp`, `uname` — all required by `nerdctl install`.

The script auto-detects the available runtime in this order: **docker > podman > nerdctl**.

---

## Installation

### Step 1 — clone / copy the files

Place at least these files in a directory (e.g. `~/Documents/ops-cli/`):

```
ops.sh              ← [required] the wrapper
Dockerfile          ← [required] default image (Arch-based)
scripts/            ← [required] helper wrappers (google-chrome, nix-wrapper,
                      nix-cli-wrapper). Both Dockerfiles COPY these into
                      /opt/ops/bin — the build FAILS with "COPY not found"
                      if the directory is missing.
mise/               ← [optional] local mise-nix plugin. Without it the image
                      still builds, but the `nix:pkg@ver` backend and the
                      `flake.nix` auto-activation feature are disabled.
```

### Step 2 — make it executable

```bash
chmod +x ops.sh
```

### Step 3 — (optional) shell aliases

In `~/.bashrc` or `~/.zshrc`:

```bash
# The wrapper itself
alias ops='~/Documents/ops-cli/ops.sh'

# One alias per AI agent — type `claude` instead of `ops run --claude`
alias claude='ops run --claude'
alias gemini='ops run --gemini'
alias opencode='ops run --opencode'
alias codex='ops run --codex'
```

Reload the shell (`exec $SHELL`), then:

```bash
claude                    # → ops run --claude → container with Claude Code
gemini -p "summarize"     # extra args flow through to the agent
claude --no-rm            # flags before the agent args still parse as ops flags
```

See [AI CLI agents → Shell shortcuts](#shell-shortcuts) for the full alias matrix (shell alias vs ops alias) and trade-offs.

### Step 4 — (optional) persistent config

```bash
mkdir -p ~/.config/ops
cat > ~/.config/ops/ops.conf <<'EOF'
# See the "Configuration" section for the full list
# OPS_RUNTIME=auto
# OPS_IMAGE=localhost/ops-dev
# GITHUB_TOKEN=ghp_xxxxxxxxxxxx   # classic PAT without scope, avoids GitHub rate-limits during Nix builds
EOF
```

### Step 5 — if you want nerdctl auto-installed

```bash
./ops.sh nerdctl install
```

Downloads nerdctl-full, verifies the SHA256, extracts it into `~/.local/share/ops/nerdctl/`, and sets up the user `containerd.service` (disabled at boot, started on demand).

---

## Quick start

```bash
./ops.sh                        # enter the dev container (auto-build if the image is missing)
./ops.sh run -- uname -a        # run `uname -a` inside the container
./ops.sh build                  # (re-)build the image
./ops.sh --claude               # launch Claude Code in the container
./ops.sh status                 # status: image, container, volumes, services
./ops.sh clean                  # purge dangling images + stopped containers + ops-* volumes
```

---

## Subcommands

| Command | Description |
|---|---|
| `run [OPTIONS] [-- CMD...]` | Start or join the dev container. **Default command.** The `--` marks the start of the container command (anything after is no longer parsed as an ops flag). |
| `version` (`--version`, `-V`) | Prints `ops <OPS_VERSION>`. Does not start the runtime, does not read containerd. |
| `build [FLAGS]` | Build (or rebuild) the image. After a successful build, compares the new image ID to the previous one and, if it changed, lists containers still running on the old ID with a `relaunch:` hint from the `ops.cmdline.user` label, then offers a `[y/N]` prompt to remove them. |
| `runtime ARGS...` | Proxy directly to the runtime binary (e.g. `ops.sh runtime ps -a`) |
| `status` \| `info` | Show the state: services, images (default + profiles + labelled), labelled volumes, containers (name, image, coloured state, cmd, ops cli, real cli, mounts) |
| `inspect KEY` | Detailed info for an `OPS_IMAGES` key, a container name, or a raw image reference |
| `config` | Dumps the effective config (all `OPS_*` scalars + arrays) with origin (env/config/default) |
| `doctor` | Validates config consistency: `OPS_IMAGES`/dockerfiles/`ops.dockerfile` labels, dangling entries, orphan containers (missing image) and mismatches (container on an image ≠ its profile's). Non-zero return code if warnings |
| `update [KEY]` | Builds (or rebuilds) an image — same post-build flow as `build` (diff image IDs, offer to recreate containers on the previous layer). The only difference: `update KEY` pre-resolves `KEY` against `OPS_IMAGES` **before** the build, while `build` uses the active `-i`/default image. Without a key, `update` behaves exactly like `build` on the default image. |
| `backup VOL > file.tar.gz` | Streams a volume as tar.gz to stdout (redirection required) |
| `restore VOL < file.tar.gz` | Restores a volume from a tar.gz on stdin (creates the volume with the `ops.volume=true` label if missing) |
| `logs\|log [NAME] [-s\|--strip] [FLAGS]` | Tails the logs of a container (NAME defaults to `$OPS_CONTAINER_NAME`, `--strip` drops ANSI codes from TUIs) |
| `clean [--dry-run]` | Purges dangling images (with the `ops.dockerfile` label shown if present), stopped labelled containers (`ops.container=true`), labelled volumes (`ops.volume=true`) |
| `nerdctl install` | Downloads nerdctl-full to `$OPS_NERDCTL_HOME`, verifies SHA256, sets up the rootless `containerd.service` (disabled at boot). Independent of `$OPS_RUNTIME`. |
| `nerdctl uninstall` | Stops/disables `containerd.service`, removes binaries + optionally the `~/.local/share/containerd` data directory (two-prompt interactive) |
| `nerdctl self-update` | Updates the nerdctl binary at `$OPS_NERDCTL_HOME/bin/nerdctl` to the latest GitHub release |
| `aliases` | Lists aliases defined in `ops.conf` |
| `images` | Lists named images (profiles) defined in `ops.conf` |
| `<alias>` | Invokes a user alias (see [Custom aliases](#custom-aliases)) |
| `help` | Shows the built-in help |

### Command output examples

Quick reference — how to invoke, and what each diagnostic subcommand produces. Colours/ANSI are stripped here for readability.

```bash
ops status                 # ops-labelled state, coloured
ops info                   # alias of `status`
ops config                 # all OPS_* with [env]/[config]/[default] origin
ops doctor                 # validate OPS_IMAGES coherence; exit 1 if any warning
ops inspect KEY            # KEY = OPS_IMAGES profile | container name | image ref
ops run --dry-run          # print the runtime command without executing
```

**`ops status`** — runtime, images, volumes, containers, with coloured state markers:

```
=== Services ===
config:             /home/you/.config/ops/ops.conf (loaded)
runtime:            docker (/usr/bin/docker)

=== Images ===
  ✓ localhost/ops-dev             (default)            523.4MiB  2026-04-20
  ✓ localhost/ops-ml              (ml)                 987.1MiB  2026-04-18
  ✗ localhost/ops-rust            (rust)                    ---  (not built)

=== Volumes ===
  ✓ ops-share-nix              /var/lib/.../volumes/ops-share-nix/_data  (used by: ops-dev)
  ✓ ops-share-mise             /var/lib/.../volumes/ops-share-mise/_data (used by: ops-dev)
    ops-claude                 /var/lib/.../volumes/ops-claude/_data     (unused)

=== Containers ===
  ops-dev              localhost/ops-dev  (Up 2 hours)
    cmd:      bash
    ops cli:  ./ops.sh run --claude
    real cli: /usr/bin/docker run -it --rm --name ops-dev ...
    bind    /home/you                                  → /home/you
    volume  ops-share-nix                              → /nix
    volume  ops-share-mise                             → /opt/mise/data
```

**`ops config`** — effective configuration with provenance tags (`[env]` / `[config]` / `[default]`):

```
=== Config file ===
  /home/you/.config/ops/ops.conf (loaded)

=== Scalars ===
  OPS_BUILDKITD_TIMEOUT            = 10                                       [default]
  OPS_CONTAINER_NAME               = ops-dev                                  [config]
  OPS_DOCKERFILE                   = /home/you/Documents/ops-cli/Dockerfile  [default]
  OPS_IMAGE                        = localhost/ops-dev                        [env]
  OPS_RUNTIME                      = docker                                   [config]
  OPS_USER_LANG                    = fr_FR.UTF-8                              [config]
  ...

=== Arrays ===

  OPS_IMAGES [config]
    ml                   = localhost/ops-ml
    rust                 = localhost/ops-rust

  OPS_ALIASES [config]
    dev                  = -i arch run --claude
```

**`ops doctor`** — validates the config before a build; returns non-zero if any warning:

```
=== Config ===
    ✓ config file: /home/you/.config/ops/ops.conf

=== OPS_IMAGES ===

  ml → localhost/ops-ml
    ✓ dockerfile: Dockerfile.ml
    ✓ image built: localhost/ops-ml
    ✓ label ops.dockerfile matches

  rust → localhost/ops-rust
    ⚠ dockerfile not found: Dockerfile.rust
    ⚠ image not built: localhost/ops-rust (run: ops.sh -i rust build)

=== Dangling config entries ===
    (none)

=== Containers (label=ops.container=true) ===
    ✓ container 'ml' matches OPS_IMAGES[ml]

=== Summary ===
  3 OK  2 warning(s)
```

**`ops inspect ml`** — resolves an `OPS_IMAGES` key (profile), a container name, or a raw image ref:

```
=== Image ===
  ref:        localhost/ops-ml
  ops key:    ml
  size:       987.1MiB
  created:    2026-04-18
  dockerfile: /home/you/Documents/ops-cli/Dockerfile.ml

=== Container ===
  name:       ml
  image:      localhost/ops-ml
  state:      Up 30 minutes
  cmd:        bash
  ops cli:    ./ops.sh -i ml --claude

=== Mounts ===
    bind    /home/you                                  → /home/you
    volume  ops-share-nix                              → /nix
```

**`ops run --dry-run`** — prints the exact runtime command without executing it:

```
/usr/bin/docker run -it --rm --name ops-dev --hostname ops-dev \
  --label ops.container=true --user 0:1000 --env HOME=/home/you \
  --env TERM=xterm-256color --env COLORTERM=truecolor \
  --workdir /home/you/project --volume /home/you/project:/home/you/project \
  --volume /home/you:/home/you --volume ops-share-nix:/nix \
  --volume ops-share-mise:/opt/mise/data \
  --label ops.cmdline.user=./ops.sh\ run\ --dry-run \
  --label 'ops.cmdline.real=/usr/bin/docker run ...' \
  localhost/ops-dev bash
```

---

## `run` flags

### Identity & image

| Flag | Description |
|---|---|
| `-i, --image NAME` | Image to use — **raw name OR `OPS_IMAGES` key** (see [Named images](#named-images-profiles)) |
| `-n, --name NAME` | Container name (default: `ops-dev`) — always wins over a profile |
| `-f, --dockerfile PATH` | Dockerfile path — always wins over a profile |
| `-u, --uid UID` | UID inside the container |
| `-g, --gid GID` | GID inside the container |
| `-l, --lang LOCALE` | Container locale (default: `$LANG`) |

### Mounts & env

| Flag | Description |
|---|---|
| `-v, --volume SRC:DST` | Extra volume (repeatable) |
| `-e, --env KEY=VAL` | Extra environment variable (repeatable) |
| `--env-file FILE` | Reads env vars from a file |
| `-p, --port HOST:CTN` | Publishes a port (repeatable) |
| `--no-mount-home` | Do not bind-mount host `$HOME` (default: mounted). When active, per-agent auto bind-mounts of `~/.claude`, `~/.gemini`, `~/.local/share/opencode`, `~/.codex` kick in **only if the host path exists** — giving an ephemeral `$HOME` while preserving agent credentials. Use `--no-<agent>-mount` to opt out of a specific agent. |
| `--no-mount-volume` | Do not mount the mise and nix volumes (shortcut for `--no-nix-volume --no-mise-volume`) |
| `--isolated-volumes` | Use per-container named volumes (`$OPS_CONTAINER_NAME-nix`, `$OPS_CONTAINER_NAME-mise`, and — when `--<agent>-volume` is also set — `$OPS_CONTAINER_NAME-claude` / `-gemini` / `-opencode` / `-codex`) instead of the shared `ops-share-*` / `ops-<agent>` defaults |

### `ops-*` volumes (selective opt-out)

| Flag | Effect |
|---|---|
| `--no-nix-volume` | Do not mount the nix volume on `/nix` |
| `--no-mise-volume` | Do not mount the mise volume on `/opt/mise/data` |
| `--no-claude-mount` | Do not bind-mount `~/.claude` (only meaningful with `--no-mount-home`) |
| `--no-gemini-mount` | Do not bind-mount `~/.gemini` (only meaningful with `--no-mount-home`) |
| `--no-opencode-mount` | Do not bind-mount `~/.local/share/opencode` (only meaningful with `--no-mount-home`) |
| `--no-codex-mount` | Do not bind-mount `~/.codex` (only meaningful with `--no-mount-home`) |
| `--claude-volume` / `--gemini-volume` / `--opencode-volume` / `--codex-volume` | Use a named volume (`ops-<agent>` by default, or `$OPS_CONTAINER_NAME-<agent>` with `--isolated-volumes`) for the agent config instead of a bind-mount — isolates the container's agent auth from the host's |

### Build

| Flag | Description |
|---|---|
| `-b, --build` | Triggers a build as part of `run` then exits — the container command (after `--`) is ignored. Use the top-level `build` subcommand for clarity. |
| `--no-cache` | Invalidates the cache — requires `--build`. Standalone `run --no-cache` is rejected with a clear error. |

### AI agents

See the [AI CLI agents](#ai-cli-agents) section below.

### Misc

| Flag | Description |
|---|---|
| `--no-rm` | Keeps the container after exit (default: ephemeral `--rm`) |
| `--dry-run` | Prints the runtime command without executing it |
| `--nix-cleanup` | Runs `nix-collect-garbage -d` in the container |
| `--update` | Updates mise and cleans up the nix store inside the container |
| `-H, --nerdctl-home PATH` | nerdctl install directory (nerdctl only; no effect when `OPS_RUNTIME` is docker/podman — warning emitted) |
| `--no-trust-workdir` | Do not forward `MISE_TRUSTED_CONFIG_PATHS=$PWD` (default: forwarded so `mise activate` doesn't prompt). Use when running in a repo whose `mise.toml` isn't trusted. Global opt-out: `OPS_TRUST_WORKDIR=0`. |
| `-h, --help` | Shows the `run` help (full flag list) and exits 0 |

---

## Configuration (`ops.conf`) & environment variables

### `ops.conf`

Sourced at startup: **`~/.config/ops/ops.conf`** (respects `$XDG_CONFIG_HOME`). The file is a regular bash script — you can put any shell logic there (e.g. loading secrets via `pass`, `gopass`, or a project `.env`).

Full example:

```bash
# ~/.config/ops/ops.conf

# Container runtime
OPS_RUNTIME=auto                          # auto | docker | podman | nerdctl

# Image & container
OPS_IMAGE=localhost/ops-dev               # image name
OPS_CONTAINER_NAME=ops-dev                # container name
OPS_DOCKERFILE=Dockerfile                 # Dockerfile path (relative or absolute)

# Additional volumes (space-separated)
OPS_VOLUMES="/data:/data /mnt/shared:/mnt/shared"

# Per-image --build-arg overrides (see "Build-time tools" section below).
# Keys must match OPS_IMAGES keys. Value is "KEY=VALUE" (or "K1=V1;K2=V2").
# Most common use: override EXTRA_MISE_TOOLS to add/remove tools baked
# into the image (google-chrome, ngrok, terraform, ...).
# declare -A OPS_BUILD_ARGS=(
#   [arch]="EXTRA_MISE_TOOLS=nix:google-chrome nix:ngrok"
#   [arch-min]="EXTRA_MISE_TOOLS="          # disable default google-chrome
#   [deb]="EXTRA_MISE_TOOLS=nix:chromium"
# )

# Container user (defaults = host user)
# OPS_USER_UID=1000
# OPS_USER_GID=1000
# OPS_USER_NAME=dev
# OPS_USER_LANG=fr_FR.UTF-8

# Nerdctl: binary location (for a custom install)
# OPS_NERDCTL_HOME=/opt/nerdctl

# Timeouts (seconds) — bump these on slow networks / VMs
# OPS_BUILDKITD_TIMEOUT=10               # default 10
# OPS_CONTAINERD_STARTUP_TIMEOUT=30      # default 30

# Tokens (propagated to both build and runtime; masked in ops.cmdline.real label)
# GITHUB_TOKEN: classic GitHub PAT, NO scope required (just authentication to lift the rate limit)
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxx
# ANTHROPIC_API_KEY=sk-ant-...
# OPENAI_API_KEY=sk-...
# GEMINI_API_KEY=...
```

### Build-time tools (`EXTRA_MISE_TOOLS` / `OPS_BUILD_ARGS`)

The image baseline (`mise use -g nix:git nix:semgrep github:cli/cli ...`) is always installed. On top of it, the Dockerfile accepts an `EXTRA_MISE_TOOLS` build-arg — a **whitespace-separated list of mise tool specs** — whose default is:

```dockerfile
ARG EXTRA_MISE_TOOLS="nix:google-chrome"
```

This default installs **Google Chrome** (~300 MB) so the [`chrome-devtools-mcp`](https://github.com/ChromeDevTools/chrome-devtools-mcp) server works out of the box. Google Chrome is one of the two browsers officially supported by the MCP (the other being Chrome for Testing).

> **Why not `chrome-for-testing`?** It is not packaged in nixpkgs at the moment — only `chromium`, `ungoogled-chromium` and `google-chrome` are. If `chrome-for-testing` lands upstream later, you can switch via `OPS_BUILD_ARGS`.

> **Why not `chromium`?** The MCP docs state "Other Chromium-based browsers may work, but this is not guaranteed." — so we pick an officially supported browser by default. If you prefer chromium (open-source, no unfree flag needed), override: `OPS_BUILD_ARGS[<key>]="EXTRA_MISE_TOOLS=nix:chromium"`.

> **Unfree flag** — `google-chrome` is unfree. The Dockerfile already sets both `NIXPKGS_ALLOW_UNFREE=1` (standard Nix var) and `MISE_NIX_ALLOW_UNFREE=true` (mise-nix plugin escape hatch, auto-forwarded to `NIXPKGS_ALLOW_UNFREE=1` when the plugin calls `nix build`). No extra setup needed.

**To opt out** (e.g. you never use Chrome/Puppeteer/Playwright in the container), explicitly set `EXTRA_MISE_TOOLS=""`:

```bash
# Ad-hoc, single build
./ops.sh build --build-arg EXTRA_MISE_TOOLS=""

# Permanent, per-profile (via ops.conf)
declare -A OPS_IMAGES=(
  [arch]="localhost/ops-dev"
  [arch-min]="localhost/ops-dev-min"   # no chrome, leaner image
)
declare -A OPS_BUILD_ARGS=(
  [arch-min]="EXTRA_MISE_TOOLS="
)
# ./ops.sh -i arch-min build       → no chrome
# ./ops.sh -i arch build           → google-chrome (default)
```

**To add more tools**, list them whitespace-separated:

```bash
declare -A OPS_BUILD_ARGS=(
  [arch]="EXTRA_MISE_TOOLS=nix:google-chrome nix:ngrok"
  [arch-full]="EXTRA_MISE_TOOLS=nix:chromium nix:terraform nix:ngrok"
)
```

**Semantics of `OPS_BUILD_ARGS`:**

- Associative array keyed by `OPS_IMAGES` key (same keys as `OPS_IMAGES` / `OPS_DOCKERFILES` / `OPS_CONTAINER_NAMES`).
- Value is one `KEY=VALUE` pair, or several separated by `;` (e.g. `"EXTRA_MISE_TOOLS=nix:chromium;NIX_CLEANUP=false"`).
- Applied **only** when `-i <key>` matches an `OPS_IMAGES` key. When `-i` points to a raw image ref, no per-profile args are injected.
- Propagated to `docker build` / `podman build` / `nerdctl build` via `--build-arg`.
- The default value in the Dockerfile (`nix:google-chrome`) applies **only when no override is set**. An empty override (`EXTRA_MISE_TOOLS=`) explicitly disables it.

**Applicable build-args** (declared in `Dockerfile` / `Dockerfile.debian`): `EXTRA_MISE_TOOLS`, `NIX_CLEANUP`, `MISE_INSTALL_SHA256`, `USER_UID`, `USER_GID`, `USER_NAME`, `USER_LANG`, `SOURCE_URL` (auto-forwarded from `$OPS_SOURCE_URL`).

### Precedence

For any given variable, the effective value is the **first** non-empty source in this order:

1. Environment (`KEY=val ops ...`) — highest priority
2. `ops.conf` (when using the `${KEY:-default}` idiom, env wins; plain `KEY=val` in `ops.conf` overwrites env)
3. Built-in default — lowest priority

Run `ops config` to see every variable tagged with its origin (`[env]` / `[config]` / `[default]`).

### `OPS_*` variables

| Variable | Default | Role |
|---|---|---|
| `OPS_RUNTIME` | `auto` | Container runtime (`auto`/`docker`/`podman`/`nerdctl`) |
| `OPS_IMAGE` | `localhost/ops-dev` | Image to use |
| `OPS_CONTAINER_NAME` | `ops-dev` | Container name |
| `OPS_DOCKERFILE` | `<script_dir>/Dockerfile` | Dockerfile path |
| `OPS_VOLUMES` | _(empty)_ | Extra volumes (space-separated `SRC:DST` pairs) |
| `OPS_NERDCTL_HOME` | `~/.local/share/ops/nerdctl` | nerdctl install directory |
| `OPS_BUILDKITD_TIMEOUT` | `10` | buildkitd startup timeout (s) — bump on slow machines |
| `OPS_CONTAINERD_STARTUP_TIMEOUT` | `30` | containerd startup timeout (s) |
| `OPS_USER_UID` | `$(id -u)` | UID in the container |
| `OPS_USER_GID` | `$(id -g)` | GID in the container |
| `OPS_USER_NAME` | `$(id -un)` | Username in the container |
| `OPS_USER_LANG` | `$LANG` or `en_US.UTF-8` | Container locale |
| `OPS_FORCE_TTY` | `0` | When `1`, bypasses the TTY guard on `backup`/`restore` (use with care — defeats the safety net against accidental `backup > /dev/tty`) |
| `OPS_TRUST_WORKDIR` | `1` | When `1`, forwards `MISE_TRUSTED_CONFIG_PATHS=$PWD` to the container so `mise activate` auto-trusts the workdir's `mise.toml` (no interactive "Trust them?" prompt). Set `0` — globally in `ops.conf` or inline `OPS_TRUST_WORKDIR=0 ops run` — when entering a repo whose `mise.toml` you don't fully trust: a hostile `mise.toml` can execute tasks, hooks, or `[env]` shell expansions on `mise activate`. Per-invocation opt-out: `ops run --no-trust-workdir`. |
| `OPS_SOURCE_URL` | `https://github.com/gigi206/ops-cli` | Forwarded as `--build-arg SOURCE_URL=…`; populates the `org.opencontainers.image.source` / `url` / `documentation` labels. Fork or vendor build: export `OPS_SOURCE_URL=""` to blank it, or set your own URL. |
| `OPS_DEV_PLUGIN_MOUNT` | `0` | When `1`, bind-mounts the repo's `mise/` directory read-only over the image-baked plugin path (`/opt/ops/mise-plugin/nix`) so contributors can iterate on the Lua plugin without rebuilding the image. |

### External variables (no prefix)

| Variable | Role |
|---|---|
| `GITHUB_TOKEN` | Passed to the build via **BuildKit secret** (`--secret id=github_token,env=GITHUB_TOKEN`), consumed transiently by the `mise use` step and **never baked into image layers**. Also auto-propagated at runtime. Lifts the GitHub API rate limit 60→5000 req/h. **Classic PAT, no scope required.** Masked in the `ops.cmdline.user` and `ops.cmdline.real` labels. |
| `ANTHROPIC_API_KEY` | Auto-propagated to the container when set on the host. Masked in both labels. |
| `OPENAI_API_KEY` | Auto-propagated to the container when set on the host. Masked in both labels. |
| `GEMINI_API_KEY` | Auto-propagated to the container when set on the host. Masked in both labels. |
| `LANG`, `HOME`, `TERM`, `COLORTERM` | POSIX standards, honored inside the container. |
| `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `XDG_RUNTIME_DIR` | XDG standards — affect `ops.conf` lookup, hash cache location, buildkit socket. |
| `MISE_NIX_ALLOW_UNTRACKED=1` | Read by the bundled mise-nix plugin **inside the container**. When set, the plugin uses Nix's `path:.` fetcher instead of `git+file:.` so `flake.nix` is read regardless of its git status. Use case: throwaway flakes you don't want to `git add -fN`. Set it via the workdir's `mise.local.toml` `[env]` block (mise exports it before invoking the plugin). Without this var, an untracked `flake.nix` triggers an actionable error pointing at `git -C <root> add -fN flake.nix flake.lock` as the strict-mode fix. |

### Internal (unit-test only)

| Variable | Role |
|---|---|
| `OPS_SOURCE_ONLY=1` | When set before `source ops.sh`, the script defines all helpers then returns without running the dispatcher — used by `tests/test_unit_helpers.bats` to unit-test `_human_bytes` / `_shell_quote`. Not for end users. |

---

## Exit codes

`ops.sh` follows POSIX conventions: `0` = success, non-zero = specific failure. The main codes surfaced by the wrapper:

| Code | Meaning | Typical trigger |
|---|---|---|
| `0` | Success | normal path |
| `1` | Generic error | unknown subcommand, missing required arg, runtime not found, `--no-cache` without `--build`, `OPS_NERDCTL_HOME` outside the safe whitelist, Dockerfile not found, invalid `OPS_RUNTIME`, user declined an install / uninstall prompt |
| `1` (from `doctor`) | At least one warning | missing Dockerfile for a profile, image not built, `ops.dockerfile` label mismatch, orphan container, dangling config entry |
| `$runtime_exit_code` | Pass-through | `ops.sh runtime CMD` and `ops build` / `ops run` propagate the underlying `docker` / `podman` / `nerdctl` exit code (container exit included) |
| `130` | Interrupted | user hit Ctrl-C; the `trap cleanup EXIT INT TERM` stops buildkitd and cleans temp dirs |

Scripting tip:

```bash
if ops doctor >/dev/null; then
    ops build            # only build if config is clean
else
    echo "Fix doctor warnings first" >&2
    exit 1
fi
```

---

## Custom aliases

`ops.conf` can define **shortcuts** for recurring invocations (image + volumes + agent + ports in a single keystroke). Two forms coexist.

### Form 1 — **string** aliases (simple, frozen)

```bash
# ~/.config/ops/ops.conf
declare -A OPS_ALIASES

OPS_ALIASES[ml]="run -i localhost/ml-dev -v /datasets:/data --claude"
OPS_ALIASES[web]="run -p 3000:3000 -p 5173:5173"
OPS_ALIASES[rust]="run -- cargo build --release"
OPS_ALIASES[update-all]="run --update"
```

Usage:
```bash
ops ml                       # → ops run -i localhost/ml-dev -v /datasets:/data --claude
ops ml --no-rm               # → extra args are appended automatically
ops web                      # → ops run -p 3000:3000 -p 5173:5173
```

- ✅ Trivial to write, evaluated once when `ops.conf` is loaded
- ❌ Split on whitespace → **no paths with spaces** (work around with form 2)
- ❌ No conditional logic or runtime expansion

### Form 2 — **function** aliases (bash scripts)

For anything that needs dynamic logic (env vars read at call time, conditionals, `$@` expansion, etc.):

```bash
# ~/.config/ops/ops.conf

# Simple: reads $CUDA at invocation time
ops_alias_gpu() {
    echo run -i ml-dev -e "CUDA_VISIBLE_DEVICES=${CUDA:-0}" --claude
}

# With conditional logic
ops_alias_dev() {
    local args=(run -v "$PWD:/workspace")
    # Different image depending on the git branch
    if git -C "$PWD" branch --show-current 2>/dev/null | grep -q '^main$'; then
        args=(-i localhost/ops-prod "${args[@]}")
    fi
    # Load a project-local .env if present
    [ -f .env ] && args+=(--env-file .env)
    echo "${args[@]}"
}

# Paths containing spaces
ops_alias_docs() {
    echo run -v "/mnt/my docs:/docs"
}

# Dynamic port list
ops_alias_ports() {
    local args=(run)
    for p in 3000 5173 8080 9090; do args+=(-p "$p:$p"); done
    echo "${args[@]}"
}
```

Usage:
```bash
ops gpu                      # CUDA=0
CUDA=1 ops gpu               # CUDA=1
ops dev                      # logic evaluated at call time
```

**The function must:**
1. Be called `ops_alias_<name>` (discovery pattern)
2. **Print** (via `echo`) the argv to pass to `ops`
3. Anything on stderr is just logging

### Reserved names

Aliases whose name matches a **built-in** subcommand are **ignored** so they don't shadow native commands. The reserved list mirrors `_OPS_RESERVED` in `ops.sh`:

```
run build runtime status info logs log clean
nerdctl alias aliases image images
doctor inspect config backup restore update
version --version -V
help -h --help
```

> Note: `install`, `uninstall`, and `self-update` live under the `nerdctl` namespace (`ops nerdctl install`) and are **not** reserved at the top level — an alias named `install` would therefore expand normally. The guard applies only to their parent `nerdctl`.

### Precedence

- If both a string alias **and** a function share a name → the **string wins**.
- If an alias has the same name as a built-in subcommand → the **built-in wins** (the alias is ignored).
- An alias **cannot recursively expand** into another alias (a single expansion pass, to avoid loops).

### Listing aliases

```bash
ops aliases
```

Shows string aliases with their expansion, and function aliases by name (the body is not executed here — check `ops.conf` for details).

### Full example

```bash
# ~/.config/ops/ops.conf

# Global defaults
OPS_IMAGE=localhost/ops-dev
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxx

# String aliases
declare -A OPS_ALIASES
OPS_ALIASES[ds]="run -i data-science-img -v /datasets:/data -e CUDA_VISIBLE_DEVICES=0 --claude"
OPS_ALIASES[clean-all]="clean"
OPS_ALIASES[quick]="run"

# Function aliases
ops_alias_project() {
    # Use the current directory as the container name
    echo run -n "proj-$(basename "$PWD")" -v "$PWD:/workspace"
}

ops_alias_benchmark() {
    # Pipeline: run a benchmark in an ephemeral container
    local script="${1:-benchmark.sh}"
    echo run -- bash -c "cd /workspace && ./$script"
}
```

Invocations:
```bash
ops ds                       # data-science env
ops project                  # container named after the PWD
ops benchmark custom.sh      # runs /workspace/custom.sh in the container
ops benchmark                # runs ./benchmark.sh (default)
```

---

## Images (Arch / Debian)

### Arch (default — `Dockerfile`)

- Base: `archlinux:base`
- ~500 MB final
- Advantages: rolling release, fast pacman
- Caveat: the `archlinux:base` image has `NoExtract` rules that exclude locales. The Dockerfile removes them and reinstalls `glibc` without `--needed` to restore the source files.

### Debian (optional — `Dockerfile.debian`)

An alternative base for environments where Arch's rolling-release model is undesirable (reproducible pinning, stable LTS base). **Same tooling stack** as the main `Dockerfile` — mise + Nix via the merged mise-nix plugin, same CLI agents, same `/opt/mise` and `/opt/nix-home` layout. Only the base OS (Debian testing vs Arch) and its package manager (apt vs pacman) differ.

Three equivalent ways to build and run it — pick the one that fits your workflow:

**Method 1 — one-shot `-f` flag**

```bash
ops -f Dockerfile.debian -i localhost/ops-deb build      # build into a named image
ops -f Dockerfile.debian -i localhost/ops-deb -n deb run # enter it
```

**Method 2 — `OPS_DOCKERFILE` env var**

```bash
OPS_DOCKERFILE=Dockerfile.debian OPS_IMAGE=localhost/ops-deb ops build
OPS_DOCKERFILE=Dockerfile.debian OPS_IMAGE=localhost/ops-deb ops
```

**Method 3 — named profile in `ops.conf`** (recommended for regular use)

```bash
# ~/.config/ops/ops.conf
declare -A OPS_IMAGES
OPS_IMAGES[deb]="localhost/ops-deb"
declare -A OPS_DOCKERFILES
OPS_DOCKERFILES[deb]="Dockerfile.debian"
declare -A OPS_CONTAINER_NAMES
OPS_CONTAINER_NAMES[deb]="ops-deb"       # optional; defaults to "deb"
```

Then:

```bash
ops -i deb build            # builds using Dockerfile.debian → localhost/ops-deb
ops -i deb                  # enter the ops-deb container
ops -i deb --claude         # Claude inside the Debian container
ops doctor                  # verify the deb profile is coherent
```

### Add your own variant

The same three methods apply to any custom Dockerfile you write.

**Method A — minimal profile (auto-detects `Dockerfile.<key>`)**

```bash
# 1. Drop Dockerfile.custom next to ops.sh
vim Dockerfile.custom

# 2. One line in ~/.config/ops/ops.conf
declare -A OPS_IMAGES
OPS_IMAGES[custom]="localhost/ops-custom"
# → OPS_DOCKERFILES[custom] omitted: ops auto-detects Dockerfile.custom in $SCRIPT_DIR

# 3. Build + use
ops -i custom build
ops -i custom
```

**Method B — full profile (explicit Dockerfile path)**

```bash
declare -A OPS_IMAGES
OPS_IMAGES[ml]="localhost/ops-ml"
declare -A OPS_DOCKERFILES
OPS_DOCKERFILES[ml]="/abs/path/to/Dockerfile.ml"   # any path, not just $SCRIPT_DIR
declare -A OPS_CONTAINER_NAMES
OPS_CONTAINER_NAMES[ml]="ml-dev"                   # otherwise defaults to the key "ml"
```

**Method C — one-shot (no profile)**

```bash
ops -f /path/to/Dockerfile.experimental -i localhost/ops-exp -n exp build
# → useful for throwaway experiments you don't want to register
```

**Parallel builds are safe**: each image has its own hash file (`~/.cache/ops/<image>.sha256sum`) and its own build lock — building `deb` and `ml` simultaneously works. The `--if-missing` guard prevents the TOCTOU where two processes race to build the same image.

---

## Named images (profiles)

You can declare an **image registry** with a short name in `ops.conf`. `-i NAME` then becomes smart: if `NAME` is declared, `ops` resolves **image + Dockerfile + container** in one go.

### Declaration

```bash
# ~/.config/ops/ops.conf

declare -A OPS_IMAGES           # REQUIRED to declare a profile
OPS_IMAGES[ml]="localhost/ops-ml"
OPS_IMAGES[go]="localhost/ops-go"
OPS_IMAGES[rust]="localhost/ops-rust"

declare -A OPS_DOCKERFILES      # optional
OPS_DOCKERFILES[ml]="Dockerfile.ml"
# If missing for a key → automatic fallback to $SCRIPT_DIR/Dockerfile.<key>
# If that file does not exist either → default Dockerfile

declare -A OPS_CONTAINER_NAMES  # optional
OPS_CONTAINER_NAMES[ml]="ml-dev"
# If missing for a key → uses the key itself ("go" becomes the container name)
```

### Usage

```bash
ops -i ml                       # enter the ml-dev container (ops-ml image + Dockerfile.ml)
ops -i ml build                 # (re)build the ml image via Dockerfile.ml
ops -i go                       # enter "go" (ops-go image, no OPS_CONTAINER_NAMES → key)
ops -i rust --claude            # rust + claude
ops -i alpine:latest            # raw image (not a declared profile) → OPS_IMAGE=alpine:latest
ops images                      # list declared profiles
```

### Override rule: `-n` and `-f` always win

Regardless of argument order, an explicit `-n` or `-f` overwrites the profile's value:

```bash
ops -i ml -n custom         # container "custom" (not "ml-dev")
ops -n custom -i ml         # same — reverse order yields the same result
ops -i ml -f alt.Dockerfile # build with alt.Dockerfile, not Dockerfile.ml
ops -f alt.Dockerfile -i ml # same
```

### Composition with aliases

Profiles and aliases are **independent** — you can combine them:

```bash
# ops.conf
declare -A OPS_IMAGES
OPS_IMAGES[ml]="localhost/ops-ml"

declare -A OPS_ALIASES
OPS_ALIASES[ml-claude]="-i ml run --claude"    # alias triggers the profile
```

Usage: `ops ml-claude` → expands to `-i ml run --claude` → profile `ml` is resolved and claude is launched.

### Listing

```bash
ops images     # or: ops image (singular)
```

Shows, for each declared profile:
- Key name
- Mapped image (`OPS_IMAGES[key]`)
- Effective Dockerfile (mapped, `Dockerfile.key`, or default)
- Effective container name (mapped or key)

### Full example

```bash
# ~/.config/ops/ops.conf

# Global defaults (applied when no profile/override is active)
OPS_IMAGE=localhost/ops-dev
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxx

# Named images
declare -A OPS_IMAGES
OPS_IMAGES[arch]="localhost/ops-dev"
OPS_IMAGES[ml]="localhost/ops-ml"
OPS_IMAGES[rust]="localhost/ops-rust"

declare -A OPS_DOCKERFILES
OPS_DOCKERFILES[ml]="Dockerfile.ml"
OPS_DOCKERFILES[rust]="Dockerfile.rust"
# arch uses the default Dockerfile

declare -A OPS_CONTAINER_NAMES
OPS_CONTAINER_NAMES[arch]="ops-dev"   # default
# ml, rust → derive from their key

# Aliases for frequent combinations
declare -A OPS_ALIASES
OPS_ALIASES[dev]="-i arch run --claude"
OPS_ALIASES[ml-gpu]="-i ml run -e CUDA_VISIBLE_DEVICES=0 --claude"
```

Invocations:

```bash
ops                        # default image/container (localhost/ops-dev / ops-dev)
ops -i ml build            # rebuild ops-ml from Dockerfile.ml
ops ml-gpu                 # alias → ml + claude + CUDA
ops -i rust -n rust-test run -- cargo --version
ops images                 # list profiles
ops aliases                # list aliases
```

---

## Runtime selection

Three possible values for `OPS_RUNTIME`:

### `auto` (default)

Detects in order: **docker > podman > nerdctl**. If none is available, falls back to `nerdctl` to trigger the auto-install prompt.

### `docker` / `podman`

Uses the binary from `$PATH`. If missing → clear error asking to install via the distro's package manager.

- For docker: supports both **rootless** (recommended) and **rootful**. The script detects via `docker info` and adapts `--user` (rootful = `$UID:$GID` so that files are owned by you; rootless = `0:$GID` because the UID mapping is inverted).
- For podman: rootless by default, no config required.

### `nerdctl`

Uses `$OPS_NERDCTL_HOME/bin/nerdctl` (default `~/.local/share/ops/nerdctl/bin/nerdctl`). If missing, prompts for auto-install. Automatically manages:
- The `containerd.service` systemd-user unit (started when needed, stopped on exit)
- The rootless `buildkitd` daemon (started only for builds, with trap-based cleanup)

### Force a specific runtime

```bash
OPS_RUNTIME=podman ./ops.sh status      # one-shot
echo "OPS_RUNTIME=podman" >> ~/.config/ops/ops.conf   # persistent
```

---

## Nix tooling (mise-nix plugin)

The image ships a merged `mise-nix` plugin that gives mise two complementary capabilities on top of Nix:

1. A **backend** to install individual packages by version: `nix:pkg@ver` entries in `mise.toml`.
2. An **env plugin** to auto-activate a project-local `flake.nix` dev shell when you enter the directory.

Both rely on single-user Nix (installed with `HOME=/opt/nix-home`, so the profile lives at `/opt/nix-home/.nix-profile` — outside user `$HOME`) and on packages available through `nixpkgs` via [nixhub.io](https://www.nixhub.io).

### Searching for packages

mise has no native `search` command for backend-provided tools (the vfox backend API does not define a search hook). To discover what is installable, use Nix directly or the nixhub web UI.

**Nix-native (recommended, works offline after first run)**

```bash
nix search nixpkgs hyperfine
nix search nixpkgs '^postgresql_[0-9]+$'   # regex
nix search nixpkgs python   # list all python variants
```

- The first invocation downloads and evaluates nixpkgs metadata (~10–30 s, one-off).
- Subsequent searches are served from `~/.cache/nix/eval-cache-v*` (<1 s).
- Output format: `legacyPackages.<system>.<attr> (<version>) — <description>`.

**Web UI — nixhub.io**

Open [nixhub.io/search?q=&lt;term&gt;](https://www.nixhub.io/) in a browser. Same source mise queries behind `mise ls-remote nix:…`, presented with each historical version and its pinned nixpkgs commit.

**Typical workflow**

```bash
nix search nixpkgs postgresql        # find the exact attr name
mise ls-remote nix:postgresql        # list installable versions via nixhub
mise use -g nix:postgresql@16.4      # install the chosen version
```

Why the split: `nix search` is the right tool for discovery (full catalog, fuzzy by description), `mise ls-remote nix:<pkg>` is the right tool for versioning (the actual list the plugin will resolve against).

### Installing individual packages

Declare them as regular mise tools, with the `nix:` prefix:

```toml
# mise.toml (or ~/.config/mise/config.toml for global scope)
[tools]
"nix:jq"       = "1.7.1"
"nix:ripgrep"  = "latest"
"nix:terraform" = "1.7.0"
```

Or from the command line:

```bash
mise use -g nix:hyperfine
mise install nix:nodejs@20.10.0
mise ls-remote nix:python           # list available versions from nixhub
```

The package itself is stored once in `/nix/store` (shared between all projects). mise records a symlink under `/opt/mise/data/installs/nix/<pkg>@<ver>/` and activates it via PATH when you `cd` into a project that declares it.

### Activating a `flake.nix` dev shell

For projects with a runtime + dependencies (Python + libs, Node + native builds, …), a flake is usually the right abstraction. The plugin's env side mirrors `nix develop`.

Minimal example:

```nix
# flake.nix (project root)
{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = { nixpkgs, ... }: let
    system = "x86_64-linux";
    pkgs   = import nixpkgs { inherit system; };
    python = pkgs.python312.withPackages (ps: with ps; [ requests numpy pandas ]);
  in {
    devShells.${system}.default = pkgs.mkShell {
      packages = [ python pkgs.nodejs_20 ];
    };
  };
}
```

Then enable mise activation:

```toml
# mise.toml (same project root)
[env]
_.nix = true

[settings]
env_cache = true
```

On `cd` into the directory, mise runs `nix print-dev-env` against `flake.nix` + `flake.lock` and exports the resulting `PATH`, `PYTHONPATH`, etc. No `venv`, no `pip` required — `python -c "import numpy"` just works.

Options you can pass through `_.nix`:

```toml
[env]
_.nix = { flake_attr = "default", flake_lock = "flake.lock", profile_dir = ".mise-nix" }
```

| Option | Default | Role |
|---|---|---|
| `flake_attr` | `default` | Which `devShells.<system>.<attr>` to load |
| `flake_lock` | `flake.lock` | Lock file that pins the flake inputs |
| `profile_dir` | `.mise-nix` | Per-project profile directory (GC root — prevents `nix store gc` from removing the shell) |

Limitation: `shellHook` declared in the flake is **not** executed (we only read the env, not run the shell). Put hook-like behavior in `ops.conf` aliases or `mise.toml` `[hooks]` instead.

### Choosing between `nix:pkg` and `flake.nix`

| You need… | Pick |
|---|---|
| A couple of standalone CLI tools (terraform, jq, kubectl…) | `nix:pkg@ver` entries |
| A language runtime **with its library dependencies** (Python + libs, Rust + toolchain + targets…) | `flake.nix` + `[env] _.nix = true` |
| Byte-for-byte reproducibility across machines / CI | `flake.nix` (flake.lock pins the nixpkgs commit) |
| Shell hooks, env vars, custom derivations, overlays | `flake.nix` |
| Zero Nix language to write | `nix:pkg@ver` |

The two are complementary — it is common to pin platform tools via `nix:` and runtime/deps via `flake.nix` in the same project:

```toml
# mise.toml
[tools]
"nix:terraform" = "1.7.0"
"nix:kubectl"   = "1.29.0"

[env]
_.nix = true      # Python + deps come from flake.nix
```

### Troubleshooting

- **`custom backends is experimental`**: the image sets `MISE_EXPERIMENTAL=true` so `nix:` works out of the box. If you see this locally, run `mise settings set experimental true` or export `MISE_EXPERIMENTAL=true`.
- **`Nix is not installed or not in PATH`** during a `mise use -g nix:…`: `/opt/nix-home/.nix-profile/bin` is missing from the non-interactive PATH. The image injects it via `ENV PATH`; if you hit this outside the image, source `/opt/nix-home/.nix-profile/etc/profile.d/nix.sh` or add it to `/etc/profile.d/`.
- **Slow first install**: the plugin queries nixhub to resolve `pkg@ver` → nixpkgs commit, then `nix build` downloads from `cache.nixos.org`. Subsequent installs reuse the store.

---

## AI CLI agents

Four pre-integrated AI agents, installed on demand via `mise` (Node.js + npm).

| Flag | npm package | Bind-mount variant (only useful with `--no-mount-home`) | Config paths exposed |
|---|---|---|---|
| `--claude` | `@anthropic-ai/claude-code` | `--claude-mount` | `~/.claude`, `~/.claude.json` |
| `--gemini` | `@google/gemini-cli` | `--gemini-mount` | `~/.gemini` |
| `--opencode` | `github:sst/opencode` | `--opencode-mount` | `~/.local/share/opencode`, `~/.config/opencode` |
| `--codex` | `@openai/codex` | `--codex-mount` | `~/.codex` |

`GITHUB_TOKEN`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and `GEMINI_API_KEY` are auto-propagated into the container when set on the host — no flag required. All four are masked in **both** the `ops.cmdline.user` and `ops.cmdline.real` labels (see [Labels → Security](#%E2%9A%A0-security-secret-exposure)), so inlining them via `-e KEY=VAL` on the ops command line does not leak them via `docker inspect`.

### `--foo` vs `--foo-mount`

- `--foo`: installs (if missing) and runs the agent. With the default `$HOME` bind-mount, your host config at `~/.foo` is already visible inside the container, so this is usually all you need.
- `--foo-mount`: explicitly bind-mounts the agent's config directory. Redundant with the default `$HOME` bind-mount — only useful when combined with `--no-mount-home` (ephemeral `$HOME` but keep the agent's auth).

### Examples

```bash
./ops.sh --claude                    # launches Claude with your credentials
./ops.sh --codex "help me debug"     # Codex with a direct prompt
./ops.sh --gemini -p "explain this"      # args passed to gemini after the break
```

### Manual install inside the container

Agents are **not** baked into the image by default — `--claude/--gemini/--opencode/--codex` trigger a `mise use -g` on the fly (persistent thanks to the `ops-share-mise` volume).

### Shell shortcuts

Two idiomatic ways to shorten `ops run --<agent>` into a single word. **Pick one per agent** — use both if you want different shortcuts (e.g. `cc` in shell, `ops claude-gpu` in ops.conf for a GPU variant).

#### Option A — shell aliases (in `~/.bashrc` / `~/.zshrc`)

```bash
alias claude='ops run --claude'
alias gemini='ops run --gemini'
alias opencode='ops run --opencode'
alias codex='ops run --codex'
```

Usage:

```bash
claude                        # bare invocation
claude --no-rm                # ops flags work (consumed before the agent)
claude -- --help              # args after -- flow to the agent CLI
gemini -p "summarize README"
```

**Pros**: shortest form (`claude` vs `ops claude`). No config file involved.
**Cons**: per-shell (bash/zsh/fish syntax differs), not portable to CI or remote hosts.

#### Option B — ops aliases (in `~/.config/ops/ops.conf`)

```bash
declare -A OPS_ALIASES
OPS_ALIASES[cc]="run --claude"
OPS_ALIASES[gg]="run --gemini"
OPS_ALIASES[oc]="run --opencode"
OPS_ALIASES[cx]="run --codex"
```

Usage:

```bash
ops cc                        # → ops run --claude
ops cc --no-rm                # extra args appended
ops gg -- -p "summarize"
```

**Pros**: portable (travels with `ops.conf`), composable with profiles (`OPS_ALIASES[claude-ml]="-i ml run --claude"`), inspectable via `ops aliases`.
**Cons**: slightly longer invocation (`ops cc` vs `cc`).

#### Option C — combined (both layers)

Shell alias that targets an ops alias — best of both:

```bash
# ~/.config/ops/ops.conf
OPS_ALIASES[claude]="run --claude"
# But `claude` is also an ops-reserved subcommand? No — `claude` is NOT in _OPS_RESERVED,
# so an alias named "claude" works fine.

# ~/.bashrc
alias claude='ops claude'       # typing "claude" → "ops claude" → "run --claude"
```

#### Variants with profiles

Combine shell alias + named image profile for context-aware agents:

```bash
# ops.conf
declare -A OPS_IMAGES
OPS_IMAGES[ml]="localhost/ops-ml"
declare -A OPS_ALIASES
OPS_ALIASES[claude-ml]="-i ml run --claude"   # ML image + Claude

# ~/.bashrc
alias claude-ml='ops claude-ml'
```

Now `claude-ml` drops you into an ML-ready container with Claude already launched.

---

## GUI apps (Chrome, Wayland)

`ops.sh` auto-forwards the **Wayland** socket when the host runs Wayland — GUI apps like Chrome (baked into the image via `nix:google-chrome`, see [Build-time tools](#build-time-tools-extra_mise_tools--ops_build_args)) can render on the host compositor without any extra setup.

### Prerequisites

- The host is running a Wayland session: `echo $XDG_SESSION_TYPE` must print `wayland`.
- `$WAYLAND_DISPLAY` is set and `$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY` is a live socket.

When all of that is true, `ops.sh run` automatically injects:
```
--volume $XDG_RUNTIME_DIR/$WAYLAND_DISPLAY:$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY
--env    WAYLAND_DISPLAY=$WAYLAND_DISPLAY
--env    XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR
```

No `xhost`, no X11 socket forwarding, no `.Xauthority` bind-mount — Wayland uses the socket permissions as the auth gate, and your container runs as the same UID as the host user (set via `--build-arg USER_UID=$(id -u)`), so the socket is readable out of the box.

### Launching Chrome via the default run

```bash
ops run google-chrome
```

That is literally all you need. The `/opt/ops/bin/google-chrome` wrapper (baked into the image and first in PATH — see the [wrapper section below](#google-chrome-wrapper--for-cli-use-and-chrome-launcher-based-tools)) injects the flags required for Chrome to start inside a rootless container, then execs the real binary. You only need to pass extra flags yourself when you want to override wrapper behaviour.

Flags the wrapper adds automatically:

| Flag | Why |
|---|---|
| `--no-sandbox` | Chrome's SUID sandbox cannot work in a rootless container where the binary lives in `/nix/store` (read-only, no setuid). The container is already the sandbox. Standard practice (Playwright, Puppeteer, Selenium CI images do the same). |
| `--disable-dev-shm-usage` | Avoids renderer crashes when `/dev/shm` in the container is small (64 MB default on Docker). |
| `--ozone-platform=wayland` (conditional) | Added only when `$WAYLAND_DISPLAY` is set in the container. Switches to the Wayland backend instead of X11/XWayland. |
| `--enable-features=UseOzonePlatform,WaylandWindowDecorations` (conditional) | Same condition — activates the Ozone path and adds client-side window decorations (titlebar, close button). |

If you need the raw binary without the wrapper (custom flags for testing, benchmarking a specific variant, …), invoke `/opt/mise/data/installs/nix-google-chrome/latest/bin/google-chrome` directly or use `mise exec nix:google-chrome --`.

### Permanent shortcut via `ops.conf`

Because the wrapper already adds the required flags, the alias only needs to invoke `google-chrome`. Add site-specific arguments (start URL, profile dir, proxy, …) as needed.

```bash
declare -A OPS_ALIASES=(
  [chrome]="run google-chrome"
)
```

Then:
```bash
ops chrome                     # opens Chrome with the wrapper defaults
ops chrome https://example.com # extra args are appended
```

### Opting out — `--no-wayland`

Disable the auto-forward when you don't want it (headless CI, remote SSH, you're configuring a custom display path):
```bash
ops run --no-wayland <cmd>
```

The Wayland mount + envs are skipped; nothing else changes. `ops.sh` never touches X11 (considered deprecated here) — if you really need X11, wire it manually:
```bash
ops run -v /tmp/.X11-unix:/tmp/.X11-unix \
        -v "$HOME/.Xauthority:/home/$(id -un)/.Xauthority:ro" \
        -e DISPLAY="$DISPLAY" \
        -e XAUTHORITY="/home/$(id -un)/.Xauthority" \
        <cmd>
```

### Expected non-blocking warnings

When Chrome starts in the container you'll see a handful of errors that are **cosmetic only**:
- `drmGetDevices2() has not found any devices` / `eglInitialize failed` — no GPU passthrough, Chrome falls back to software rendering. Slower but works.
- `Failed to connect to bus /run/dbus/system_bus_socket` — DBus system bus not mounted. Kills desktop notifications, UPower, KWallet — not rendering.
- `Failed to decrypt token for service AccountId-…` — consequence of the missing DBus (no keychain). Login-related state won't persist.

If you care about these, mount DBus too: `-v /run/dbus/system_bus_socket:/run/dbus/system_bus_socket`. The `/etc/machine-id contains 0 characters` warning is already handled by the Dockerfile (populated at build time).

### `google-chrome` wrapper — for CLI use and `chrome-launcher`-based tools

Both Dockerfiles ship a wrapper at **`/opt/ops/bin/google-chrome`** (from `scripts/google-chrome.sh`). The container PATH is **prefixed** with `/opt/ops/bin`, so the wrapper shadows the mise shim at `/opt/mise/data/shims/google-chrome`. Consequence: typing `google-chrome` anywhere inside the container (manually or via [`chrome-launcher`](https://www.npmjs.com/package/chrome-launcher), used by [`chrome-devtools-mcp`](https://github.com/ChromeDevTools/chrome-devtools-mcp), Puppeteer, Lighthouse) picks up this wrapper automatically.

The wrapper:
1. Verifies `google-chrome` is actually installed (i.e. you built with `EXTRA_MISE_TOOLS` containing `nix:google-chrome`). If not, it prints a short explanation and exits 127 instead of failing with an obscure error.
2. Adds `--no-sandbox --disable-dev-shm-usage` unconditionally (both are mandatory in a rootless Nix-backed container — see the Chrome section above).
3. Appends `--ozone-platform=wayland --enable-features=UseOzonePlatform,WaylandWindowDecorations` **only** when `$WAYLAND_DISPLAY` is set (works headless in CI, switches to Wayland in dev sessions).
4. Forwards any other arguments from the caller.
5. Execs the real binary via absolute path from the mise install tree (`/opt/mise/data/installs/nix-google-chrome/latest/bin/google-chrome`) — no PATH recursion, no redundant mise shim traversal. The mise-nix plugin does not install into the Nix user profile, so the mise install tree is the canonical location; the `latest` symlink tracks the active version.

Discoverability is ensured via three redundant hooks so every tool locates the wrapper regardless of how they look for Chrome:

| Hook | Who uses it |
|---|---|
| `/opt/ops/bin/google-chrome` + `/opt/ops/bin` first in PATH | Interactive shell, any tool honoring PATH |
| `ENV CHROME_PATH=/opt/ops/bin/google-chrome` | `chrome-launcher` (Lighthouse, some MCP servers) — highest priority |
| `ENV PUPPETEER_EXECUTABLE_PATH=/opt/ops/bin/google-chrome` | Any tool using `puppeteer-core` directly |
| `/usr/bin/google-chrome` symlink → wrapper | Tools with a stripped PATH, `which` fallbacks |
| `/opt/google/chrome/chrome` symlink → wrapper | `chrome-devtools-mcp` / `puppeteer-core` (hard-codes this path for the "stable" channel on Linux) |

Practical effects:

```bash
# Interactive: just type `google-chrome`, no flags required
google-chrome https://example.com

# MCP / Puppeteer / Lighthouse: no CHROME_PATH or --executablePath needed
```

Example chrome-devtools-mcp config (minimal — no flags, no path override):
```json
{
  "mcpServers": {
    "chrome-devtools": {
      "command": "npx",
      "args": ["chrome-devtools-mcp", "--headless", "--isolated"]
    }
  }
}
```
`chrome-launcher` resolves `google-chrome` from the PATH → hits the wrapper → correct flags applied automatically.

> If you ever need the raw binary (e.g. for testing), it's reachable at `/opt/mise/data/installs/nix-google-chrome/latest/bin/google-chrome` or via `mise exec nix:google-chrome -- …`.

---

## Named volumes `ops-*`

Created on demand, persistent between container launches. Tracked by the **label** `ops.volume=true` (automatically set by `ensure_volume`) — volumes that existed before this change do not carry the label and will only be re-labelled on their next creation.

| Volume | Mount point | Contents |
|---|---|---|
| `ops-share-nix` | `/nix` | Nix store (used by the mise-nix plugin). Shared between all ops containers by default. |
| `ops-share-mise` | `/opt/mise/data` | Tool versions managed by mise (includes the `nix` plugin). Shared by default. Path is outside `$HOME` so the volume coexists with the default `$HOME` bind-mount. |

Pass `--isolated-volumes` to swap these for per-container volumes: `$OPS_CONTAINER_NAME-nix` and `$OPS_CONTAINER_NAME-mise` (e.g. `ops-dev-nix`, `ops-dev-mise`). Useful when multiple containers need independent tool versions.

**Bind-mounts** (not named volumes) for the agents:

| Host source | Container destination | Mounted when |
|---|---|---|
| `~/.claude`, `~/.claude.json` | `$HOME_IN_CTN/.claude*` | `~/.claude` exists |
| `~/.gemini` | `$HOME_IN_CTN/.gemini` | exists |
| `~/.local/share/opencode`, `~/.config/opencode` | same | exist |
| `~/.codex` | `$HOME_IN_CTN/.codex` | exists |

List volumes:
```bash
./ops.sh status
# or
./ops.sh runtime volume ls
```

Remove all labelled volumes (⚠ loses the Nix cache ~1GB):
```bash
./ops.sh clean         # interactive removal
```

### Backup / restore

Streaming tar.gz through an ephemeral `alpine` container (auto-pulled, ~5 MB):

```bash
# Backup (stdout MUST be redirected)
./ops.sh backup ops-share-nix > ops-share-nix.tar.gz

# Restore (stdin MUST be redirected)
./ops.sh restore ops-share-nix < ops-share-nix.tar.gz

# Cross-host migration
./ops.sh backup ops-share-mise | ssh other-host './ops.sh restore ops-share-mise'
```

Guards: refuses to write binary to a terminal (stdout TTY) or read from a TTY (stdin TTY). Override via `OPS_FORCE_TTY=1`. The target volume is created automatically at restore time (with the `ops.volume=true` label).

---

## Labels

`ops.sh` automatically stamps **Docker labels** on the resources it creates. These labels power discovery (by `info`/`clean`/`doctor`) without relying on naming conventions.

| Resource | Label | Value | Set by |
|---|---|---|---|
| Image | `ops.dockerfile` | Absolute path of the Dockerfile used at build time | `build_image` |
| Image | `org.opencontainers.image.title` | Static: `ops-dev` (Arch) / `ops-dev-debian` | Dockerfile `LABEL` |
| Image | `org.opencontainers.image.description` | Static: one-liner describing the image stack | Dockerfile `LABEL` |
| Image | `org.opencontainers.image.licenses` | `Apache-2.0` | Dockerfile `LABEL` |
| Image | `org.opencontainers.image.authors` | `Ghislain LE MEUR` | Dockerfile `LABEL` |
| Image | `org.opencontainers.image.source` / `url` / `documentation` | `$OPS_SOURCE_URL` (defaults to upstream repo URL) | `build_image` |
| Container | `ops.container` | `true` | `cmd_run` |
| Container | `ops.cmdline.user` | The original `./ops.sh ...` invocation (shell-quoted) | `cmd_run` |
| Container | `ops.cmdline.real` | The effective `docker run ...` command (shell-quoted) | `cmd_run` |
| Volume | `ops.volume` | `true` | `ensure_volume` |

The OCI labels follow the [opencontainers image-spec annotations](https://github.com/opencontainers/image-spec/blob/main/annotations.md) so registry UIs (Docker Hub, GHCR, Podman Desktop), `docker image inspect`, and vulnerability scanners (trivy, grype, syft) display the right metadata out of the box when the image is published.

### Concrete effects

- **`info`**: shows labelled images even if not declared in `OPS_IMAGES` (with the Dockerfile basename as tag). Labelled containers are listed even when their image disappeared (marker `⚠ (image missing)`). `cmd:`, `ops cli:`, `real cli:` are extracted from these labels.
- **`doctor`**: checks that the `ops.dockerfile` label of a built image matches the Dockerfile declared in `OPS_DOCKERFILES[key]` / `Dockerfile.<key>`.
- **`clean`**: filters strictly on `ops.container=true` / `ops.volume=true` — containers/volumes created outside `ops.sh` are **preserved**.

### ⚠ Security: secret exposure

The `ops.cmdline.real` label contains **the full `docker run` command**, including every `--env KEY=VAL`. Secret-bearing variables are **masked** in the label as `KEY=***` before it is written. Two layers:

1. **Explicit list** — always masked:
   - `GITHUB_TOKEN`
   - `ANTHROPIC_API_KEY`
   - `OPENAI_API_KEY`
   - `GEMINI_API_KEY`
2. **Convention fallback** — any uppercase variable whose name ends in `_TOKEN`, `_SECRET`, `_KEY`, `_API_KEY`, `_APIKEY`, `_PASSWORD`, `_PASS`, or `_PWD` is **also masked**. Examples: `MY_DB_PASSWORD`, `SLACK_WEBHOOK_SECRET`, `STRIPE_API_KEY`. Non-secret names matching the suffix (e.g. a hypothetical `PUBLIC_KEY`) are a deliberate false-positive trade-off: masking too much is strictly safer than masking too little.

The same masking is applied to **both** `ops.cmdline.user` and `ops.cmdline.real`, so a user who types `ops -e GITHUB_TOKEN=xxx run` does not leak the token via either label. The container itself still receives the real values (via `--env` in the actual invocation, not via the label). If a secret variable happens to use a naming convention outside the list above, add it explicitly to `_mask_secrets` in `cmd_run`.

Layer-level exposure: `GITHUB_TOKEN` is passed to `docker build` via a **BuildKit secret** (`--mount=type=secret`), consumed in-process as `NIX_CONFIG` for the `mise use` step, and never written to disk. `/etc/nix/nix.conf` in the image contains only `experimental-features = nix-command flakes` and `build-users-group =` — no `access-tokens` line. The token does **not** appear in any image layer.

Inspect labels manually:
```bash
docker image inspect localhost/ops-dev --format '{{json .Config.Labels}}'
docker container inspect ops-dev --format '{{json .Config.Labels}}'
docker volume inspect ops-share-nix --format '{{json .Labels}}'
```

### Re-label existing resources

For images/volumes built before the labels were introduced:
```bash
# Image: rebuild (Docker reuses layers, just adds the label)
./ops.sh -i ml build

# Volume: volume create is idempotent on labels
docker volume create --label ops.volume=true ops-share-nix
```

Existing containers cannot be re-labelled at runtime — recreate them (`docker rm -f` then `./ops.sh ...`).

---

## Typical flows

### First use

```bash
chmod +x ops.sh
./ops.sh nerdctl install                # if nerdctl is required (skip if docker/podman is already there)
./ops.sh build                  # build the image (~5 min on first run)
./ops.sh                        # enter the container shell
```

### Daily usage

```bash
cd ~/my-project
ops                             # shell in the container, mapped onto $PWD
ops --claude                # or directly Claude Code with your session
ops run -- git status           # one-shot command
```

### Updating

```bash
ops --update                    # mise self-update / upgrade + nix cleanup in the container
ops nerdctl self-update         # update nerdctl to the latest release
```

### Modifying the Dockerfile

```bash
# Edit the Dockerfile...
ops build                       # rebuild the default image. If old containers run the previous layer,
                                # they're listed with a relaunch hint and a [y/N] removal prompt.
ops update ml                   # same flow but targets the `ml` profile from OPS_IMAGES.
ops                             # without --build: no rebuild is triggered, but a red warning
                                # "Dockerfile changed since last build" is emitted so you know.
```

### Migrate / back up a volume

```bash
ops backup ops-share-nix > nix-$(date +%F).tar.gz            # local snapshot
ops backup ops-share-mise | ssh other './ops.sh restore ops-share-mise'   # cross-host migration
```

### Cleanup

```bash
ops clean --dry-run             # see what would be removed
ops clean                       # interactive removal
```

### Debugging a build issue

```bash
OPS_DOCKERFILE=Dockerfile.ml ops build --no-cache   # force a full rebuild
ops runtime images              # raw image listing
ops logs ops-dev                # container logs (stripped of ANSI with `ops logs -s`)
```

### Preview the exact runtime command (`--dry-run`)

Useful when debugging flag interactions or writing a new alias:

```bash
ops run --claude --dry-run                   # see what --claude expands to
ops -i ml -n tmp run --isolated-volumes --dry-run   # inspect a profile + isolation
ops run --build --dry-run                    # print the `docker build …` cmdline
                                              # without starting the build or buildkitd
```

### Expose a dev server (port publish)

```bash
ops run -p 3000:3000 -p 5173:5173 -- npm run dev
# Or as an alias:
# OPS_ALIASES[web]="run -p 3000:3000 -p 5173:5173"
```

### Mount project data directories

One-shot via `-v`:

```bash
ops run -v /mnt/datasets:/data -v /mnt/models:/models
```

Persistent via `OPS_VOLUMES` in `ops.conf` (space-separated pairs):

```bash
# ~/.config/ops/ops.conf
OPS_VOLUMES="/mnt/datasets:/data /mnt/models:/models"
```

### Inject a project-local `.env`

```bash
# .env (in the project)
DATABASE_URL=postgres://localhost/dev
SENTRY_DSN=...

ops run --env-file .env -- npm run start
```

`--env-file` is repeatable (`--env-file base.env --env-file secrets.env`). Values override each other in the order passed.

### Different user inside the container

Rootful docker writes files as `root` by default — `ops.sh` auto-corrects via `--user $UID:$GID`. Override with explicit flags when needed (e.g. running a tool that expects UID 0):

```bash
ops run -u 0 -g 0 -- apt-get update       # tool needs root inside ctn
ops run -u 1001 -g 1001                   # a different user (must exist in the image)
```

Or rename the in-container user globally (useful when `$USER` on the host is exotic):

```bash
OPS_USER_NAME=dev ops run                 # container sees /home/dev regardless of host user
```

### Custom locale

```bash
ops -l fr_FR.UTF-8 build                  # locale compiled into the image
ops run -l de_DE.UTF-8 -- locale          # override just for this run
```

### Parallel experiments — isolated mise/nix per container

By default all ops containers share the same Nix store and mise tools (`ops-share-*`). To experiment without contaminating the shared cache:

```bash
ops -n sandbox --isolated-volumes run     # creates sandbox-nix / sandbox-mise
ops -n sandbox run --update               # Nix upgrade stays local to this container
```

Clean up when done:

```bash
ops runtime rm -f sandbox
ops runtime volume rm sandbox-nix sandbox-mise
```

### Hermetic agent auth — `--<agent>-volume`

Keep the container's Claude/Gemini session separate from the host's:

```bash
ops run --no-mount-home --claude-volume --claude
# Auth prompt appears on first use; stored in the `ops-claude` named volume.
# Next run reuses it without touching ~/.claude on the host.
```

Combine with `--isolated-volumes` for per-container isolation (`$OPS_CONTAINER_NAME-claude`).

### Custom nerdctl install path

```bash
# Install nerdctl into a project-local dir instead of ~/.local/share/ops/nerdctl
OPS_NERDCTL_HOME="$PWD/.nerdctl" ./ops.sh nerdctl install
OPS_NERDCTL_HOME="$PWD/.nerdctl" ./ops.sh run
# Or via the -H flag (one-shot)
./ops.sh -H "$PWD/.nerdctl" run
```

Safety: `nerdctl install` refuses paths outside `$HOME/.local/*`, `/opt/ops/*`, `/tmp/*`, `/var/tmp/*` to avoid an accidental `rm -rf /usr`.

### VSCode devcontainer attach

Keep a persistent container, then attach VSCode to it:

```bash
ops run --no-rm                          # keeps the container on exit
# In VSCode: Ctrl+Shift+P → "Dev Containers: Attach to Running Container" → ops-dev
```

For a reproducible setup, add a `.devcontainer/devcontainer.json` at the project root:

```json
{
  "name": "ops-dev",
  "image": "localhost/ops-dev",
  "remoteUser": "you",
  "workspaceFolder": "/workspace",
  "mounts": ["source=${localWorkspaceFolder},target=/workspace,type=bind"]
}
```

### Agent mount / volume matrix

The four agents (`claude`, `gemini`, `opencode`, `codex`) all share the same flag pattern. Illustrated with `claude`:

```bash
# 1. Default — $HOME bind-mount → ~/.claude on host visible in container
ops --claude

# 2. Explicit bind-mount, redundant unless $HOME is NOT mounted
ops run --no-mount-home --claude-mount --claude

# 3. Named volume (isolated from host) — survives container recreation
ops --claude-volume --claude                 # volume: ops-claude
ops -n test --isolated-volumes --claude-volume --claude    # volume: test-claude

# 4. Opt out entirely (no config visible inside)
ops run --no-mount-home --no-claude-mount --claude
```

Replace `claude` with `gemini` / `opencode` / `codex` for the other agents — the four sets are symmetric. The full 16-cell matrix, one example per cell:

```bash
# Named volume
ops --claude-volume --claude
ops --gemini-volume --gemini
ops --opencode-volume --opencode
ops --codex-volume --codex

# Explicit bind-mount (meaningful only with --no-mount-home)
ops run --no-mount-home --claude-mount --claude
ops run --no-mount-home --gemini-mount --gemini
ops run --no-mount-home --opencode-mount --opencode
ops run --no-mount-home --codex-mount --codex

# Opt out (only meaningful with --no-mount-home)
ops run --no-mount-home --no-claude-mount
ops run --no-mount-home --no-gemini-mount
ops run --no-mount-home --no-opencode-mount
ops run --no-mount-home --no-codex-mount
```

### Shrink the container's Nix store (`--nix-cleanup`)

After months of mise installs, `/nix/store` bloats. One-shot GC inside the container:

```bash
ops run --nix-cleanup           # runs `nix-collect-garbage -d` then exits
```

Combined with `--update` (mise + Nix):

```bash
ops run --update                # mise self-update + mise upgrade + nix GC
```

Or wipe the ops-share-nix volume completely (⚠ all tools re-install on next run):

```bash
ops runtime volume rm ops-share-nix
```

### Run without any shared tool volume (`--no-mount-volume`)

Fresh environment with no pre-installed mise/Nix (useful for reproducing a first-boot state):

```bash
ops run --no-mount-volume --dry-run     # inspect what's mounted (only $HOME + $PWD)
ops run --no-mount-volume                # actually run — mise/nix have to re-bootstrap

# Granular — keep mise but drop the nix store:
ops run --no-nix-volume
# Or the opposite — keep /nix but drop /opt/mise/data:
ops run --no-mise-volume
```

`--no-mount-volume` is shorthand for `--no-nix-volume --no-mise-volume` combined.

### Remove nerdctl (`nerdctl uninstall`)

Interactive — prompts separately for the binaries and the containerd data directory:

```bash
./ops.sh nerdctl uninstall
# Stopping and disabling containerd service...
# Remove binaries (/home/you/.local/share/ops/nerdctl)? [y/N]  y
# Remove containerd data (images, containers, snapshots) (...)? [y/N]  n
# Uninstall complete.
```

Both prompts default to **No** (bare Enter keeps the data). Type `y` explicitly to remove; answer `n` (or just press Enter) to the second prompt if you want to reinstall later without losing the image cache.

### Tune daemon-startup timeouts on slow machines

Under heavy I/O (VM on HDD, corporate laptop) the containerd/buildkitd start-up can race the default timeouts:

```bash
# One-shot
OPS_CONTAINERD_STARTUP_TIMEOUT=120 OPS_BUILDKITD_TIMEOUT=30 ops build

# Persistent
echo 'OPS_CONTAINERD_STARTUP_TIMEOUT=120' >> ~/.config/ops/ops.conf
echo 'OPS_BUILDKITD_TIMEOUT=30'           >> ~/.config/ops/ops.conf
```

Both accept seconds; defaults are 30 and 10 respectively.

### Pipe the backup / restore stream

```bash
ops backup ops-share-nix | ssh other-host './ops.sh restore ops-share-nix'
OPS_FORCE_TTY=1 ops backup ops-share-mise | xxd | head   # bypass the TTY guard
                                                          # (use sparingly — defeats the safety net)
```

---

## Troubleshooting

### Nix commands inside the container — HOME routing

`$HOME` inside the container is bind-mounted from the host (`/home/<you>` → `/home/<you>`). The Nix single-user installer on the host (if you have one) and the one on the container both read profile state from `$HOME/.local/state/nix/profiles/`. Running a Nix command inside the container would therefore **touch the host profile** by default, which is almost never what you want.

The image ships wrappers at `/opt/ops/bin/` that force `HOME=/opt/nix-home` so stateful commands target the **container** profile. Full matrix of the 12 `nix*` binaries:

| Binary | Wrapped? | Rationale |
|---|---|---|
| `nix` | ✅ *selective* | Modern multi-subcommand CLI. Wrapper forces `HOME=/opt/nix-home` only for `profile`, `channel`, `registry`, `upgrade-nix`. All other subcommands (`build`, `shell`, `develop`, `run`, `search`, `eval`, `flake`, `store`, …) pass through transparently to keep the shared host `~/.cache/nix/` build cache. |
| `nix-env` | ✅ | Installs/removes packages from the Nix user profile. |
| `nix-channel` | ✅ | Manages `$HOME/.nix-channels` + rebuilds the channels profile. |
| `nix-store` | ✅ | `--delete`, `--gc`, `--register-validity` modify the store + GC roots. |
| `nix-collect-garbage` | ✅ | `-d` deletes old profile generations (the bug that started this). |
| `nix-build` | ❌ | Pure build. Uses `$HOME/.cache/nix/` as eval cache — sharing with the host is a *feature* (faster evaluation across sessions). Creates `./result` in CWD, not `$HOME`. |
| `nix-shell` | ❌ | Cache-heavy, same rationale as `nix-build`. |
| `nix-instantiate` | ❌ | Pure evaluation, uses the shared eval cache. |
| `nix-prefetch-url` | ❌ | Downloads to the shared Nix cache. No profile impact. |
| `nix-hash` | ❌ | Stateless cryptographic hash. |
| `nix-copy-closure` | ❌ | Uses `$HOME/.ssh/` for SSH auth. Forcing `HOME=/opt/nix-home` would break key discovery. Wrap manually if you copy closures between container-ish peers. |
| `nix-daemon` | ❌ | Multi-user daemon mode — not applicable here (we run single-user). |

**Escape hatch** — pass `--host` anywhere in the arguments to explicitly target the host profile:

```bash
nix-collect-garbage --host -d          # clean the host profile's old generations
nix profile list --host                # list packages installed on the host profile
nix-env --host -iA nixpkgs.ripgrep     # install into the host profile
```

If an upgrade of Nix later introduces a new stateful binary or subcommand not on the list above, wrap it manually inside the container:

```bash
# For a new standalone binary:
sudo ln -s /opt/ops/bin/_nix-wrapper /opt/ops/bin/nix-new-thing

# For a new `nix` subcommand: prefix manually
HOME=/opt/nix-home nix new-subcommand ...
```

Or add it to `/opt/ops/bin/_nix-cli-wrapper.sh`'s subcommand list and rebuild the image.

### `Image not found, building...` but the build fails

```bash
ops build --no-cache            # force a clean rebuild
```

### The `ops-dev` container refuses to start

`ops run` already handles this: if `start` fails, it removes the container with `rm -f` and recreates it in the same invocation. You should only see this path if the image itself is broken. Force a clean slate with:

```bash
ops runtime rm -f ops-dev   # force-remove (normally unnecessary)
ops build --no-cache        # rebuild from scratch if the image is suspect
ops                         # recreate and enter
```

### Warning `$HOME ... is not owned by you` (Nix)

Expected behaviour under rootless: `/home/<user>` inside the image is created by `useradd` with UID 1000 (namespace), but we run as UID 0. Nix falls back to `/root` — **non-blocking** thanks to the `/etc/nix/nix.conf` baked into the image, which forces `build-users-group =`.

### Issues related to a missing `GITHUB_TOKEN`

Without a token, you run into a few kinds of errors depending on the stage:

**At build time** (mise-nix / nix step):
```
Error: ... unable to download 'https://api.github.com/repos/NixOS/nixpkgs/commits/nixpkgs-unstable': HTTP error 403
```
→ the mise-nix plugin queries nixhub / GitHub to resolve the nixpkgs pin, which is capped at 60 req/h without auth.

**At runtime with `ops run --update`**:
```
mise ERROR NetworkError: api request failed with status: 403 - for: "https://api.github.com/repos/jdx/mise/releases/latest"
mise WARN  GitHub rate limit exceeded. Resets at ...
```
→ mise hits GitHub for its own updates.

**During `ops nerdctl install` or `ops nerdctl self-update`**:
```
Failed to fetch version from GitHub (rate-limited or offline?).
```
→ ops itself queries the GitHub API for the latest nerdctl release.

**Fix — provide a token** (classic PAT with no scope, only to lift the rate limit 60→5000 req/h):

```bash
# Option 1: in ops.conf (persistent)
echo 'GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxx' >> ~/.config/ops/ops.conf

# Option 2: in your shell (current session)
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxx
```

Then rebuild so the token is available to the build-time `mise use` step (fetched from the BuildKit secret, consumed in-process — never written to `/etc/nix/nix.conf`):
```bash
ops build --no-cache    # force a full rebuild
```

**⚠ Build-time vs runtime**: the token is needed at two distinct moments. **At build time**, the mise-nix plugin queries the GitHub API to resolve nixpkgs pins; without a token, the build fails with HTTP 403 when the rate limit is hit. **At runtime**, mise and gh inside the container also query GitHub. `ops.sh` propagates `$GITHUB_TOKEN` to both (the build via a BuildKit secret, the runtime via `--env GITHUB_TOKEN`). If the build succeeded without a token (small Nix cache, fast resolve) but fails later at runtime, just make sure `$GITHUB_TOKEN` is exported before invoking `ops run` — no rebuild needed for that case.

**Generate a token**: https://github.com/settings/tokens/new → any name, **no scope required** → Generate. Because the token is never persisted in the image (BuildKit secret), it is not exposed by `docker image inspect`; still, good hygiene is to keep it in `~/.config/ops/ops.conf` and not in commits.

### `context deadline exceeded` on `cache.nixos.org`

buildkit network is too slow. The script already uses `--network host`. If it persists: a network issue on your side (IPv6, DNS, corporate proxy).

### `security.insecure entitlement is not allowed` (nerdctl build)

The flag is allowed by default inside `ensure_buildkitd` (see `ops.sh`). If the error still shows up, buildkitd must have been started differently — kill the existing process (`pkill -f buildkitd`) and relaunch via `ops build`, which spawns buildkitd with the right entitlements.

### After switching runtime, the image seems to be gone

Every runtime has its own storage:
- docker: `/var/lib/docker` (or `~/.local/share/docker` rootless)
- podman: `~/.local/share/containers`
- nerdctl: `~/.local/share/containerd`

Images are not shared. You must rebuild for the new runtime.

### Auto-detect picks the wrong runtime

```bash
echo "OPS_RUNTIME=nerdctl" >> ~/.config/ops/ops.conf   # pin a specific runtime
```

### Error `Warning: -H has no effect with OPS_RUNTIME=docker`

Expected: `-H/--nerdctl-home` only makes sense for nerdctl. Drop the flag when using docker/podman.

---

## FAQ

### Why a custom wrapper rather than `docker-compose` / `devcontainer`?

- Compose/devcontainer require a specific stack (docker daemon, VSCode, ...)
- ops also handles runtime install (rootless nerdctl auto), systemd services, buildkitd
- Native integration of AI agents with persisted sessions
- Runtime-agnostic: same interface whether you are on docker, podman, or nerdctl

### Where are the Dockerfile hashes stored?

`~/.cache/ops/<image>.sha256sum` (per image). Used to detect whether the Dockerfile changed since the last build.

### Does the script run rootless or rootful?

Auto-detects via `docker info` / `podman info`. nerdctl is always rootless in this setup.

- **Rootless**: `--user 0:$GID` (container UID 0 ↔ host you via the user namespace)
- **Rootful docker**: `--user $UID:$GID` (avoids files owned by root)

### Can I use a public image (no Dockerfile)?

Yes:
```bash
OPS_IMAGE=python:3.12 ops --no-rm
```

But `ops-*` volumes and the AI agents will not work because the image has neither mise, nor Nix, nor the mise-nix plugin installed. Prefer building your own Dockerfile on top of our `Dockerfile` (which inherits the whole setup).

### How do I test Dockerfile changes without breaking the current image?

Simplest — declare a test profile in `ops.conf`:

```bash
declare -A OPS_IMAGES
OPS_IMAGES[test]="localhost/ops-dev-test"
```

Then:
```bash
ops -i test build          # build into a separate image
ops -i test                # test it
# If all good, promote:
ops runtime tag localhost/ops-dev-test localhost/ops-dev
```

### Can the container be used from VSCode?

Yes, via "Dev Containers: Attach to Running Container" after `ops --no-rm`. Or, more cleanly, through a `devcontainer.json` pointing at the `localhost/ops-dev` image.

### How do I avoid retyping GITHUB_TOKEN on every build?

Put it into `~/.config/ops/ops.conf`:
```bash
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxx
```

The token is propagated **at build time** (via a BuildKit secret, consumed by the `mise use` step as `NIX_CONFIG`) **and at runtime** (env var for mise/gh).

ℹ The token is **not** baked into the image — the BuildKit `--mount=type=secret` path makes it available only to the RUN step that reads it, and nothing writes it to disk. It is also masked in the `ops.cmdline.user` and `ops.cmdline.real` labels (see [Labels → Security](#%E2%9A%A0-security-secret-exposure)). As long as the token is not exported in your shell history or committed to git, the image is safe to share.

---

## Project structure

Core files:

```
ops-cli/
├── ops.sh                       # the wrapper (entry point)
├── Dockerfile                   # default image (Arch)
├── Dockerfile.debian            # optional Debian-based variant
├── README.md                    # this file
├── CHANGELOG.md                 # Keep-a-Changelog history
├── LICENSE                      # Apache-2.0
├── .editorconfig                # indent rules (4 spaces, 2 for Lua/YAML/MD)
├── .shellcheckrc                # shellcheck CI/local-parity shim (shell=bash; all disables are inline)
├── .dockerignore                # excludes mise/.git and backups from the build context
├── .gitignore                   # hash cache + transient artefacts
├── mise.toml                    # dev toolchain (bats, shellcheck, luacheck, hadolint) + `mise run <task>` entry points
├── .github/
│   ├── CODEOWNERS               # default reviewers per path
│   ├── dependabot.yml           # weekly bumps for GH Actions + Docker bases
│   ├── pull_request_template.md # PR checklist (image-integration reminder)
│   └── workflows/tests.yml      # CI (shellcheck + hadolint + luacheck + bats + Docker build matrix + trivy)
├── mise/                        # local mise-nix plugin (copied into the image)
│   ├── NOTICE                   #   per-file license map (Apache-2.0 + MIT)
│   ├── LICENSE / LICENSE.MIT    #   upstream licenses (Apache + MIT sources)
│   ├── metadata.lua             #   PLUGIN descriptor (name=nix)
│   ├── types.lua                #   Lua type definitions (meta)
│   ├── hooks/                   #   mise plugin hooks (install, list, env, path)
│   └── lib/                     #   internal helpers (flake, shell, security, …)
├── scripts/                     # helper scripts copied into the image
│   ├── google-chrome.sh         #   google-chrome wrapper (adds --no-sandbox, routes to real binary)
│   ├── _nix-wrapper.sh          #   generic wrapper for stateful Nix legacy binaries (nix-env, nix-channel, nix-store, nix-collect-garbage)
│   └── _nix-cli-wrapper.sh      #   wrapper for the modern `nix` CLI — forces HOME only for profile/channel/registry/upgrade-nix subcommands
└── tests/                       # bats suite (see the Tests section for the list)
```

Runtime paths (per user):

```
~/.config/ops/ops.conf           # user config (optional, sourced at startup)
~/.cache/ops/                    # per-image Dockerfile hashes + build locks
~/.local/share/ops/nerdctl/      # nerdctl install (when managed via `ops nerdctl install`)
```

---

## Tests

[bats](https://github.com/bats-core/bats-core) suite using **runtime mocks** (fake `docker`/`podman`/`nerdctl`/`curl`/`tar`/`systemctl` on an isolated `PATH`) — no real daemon, build, or network call involved.

### Files

```
tests/
├── helpers.bash                   — runtime mocks + system tool stubs + setup helpers
├── test_dispatch.bats             — 17 tests: subcommands, runtime proxy, clean, version/--version/-V
├── test_runtime.bats              — 11 tests: auto-detection, rootless/rootful, invalid
├── test_dryrun.bats               — 42 tests: run flag parsing
├── test_flags.bats                — 26 tests: -u/-g/-l/-H/-e/-p/--env-file/no-*-volume/api-key masking/…
├── test_config.bats               —  5 tests: ops.conf loading + precedence
├── test_hash.bats                 —  5 tests: per-image hash + dockerfile_changed
├── test_container_state.bats      —  6 tests: running/stopped/logs/status
├── test_image_state.bats          —  5 tests: build trigger, volume warning
├── test_build_flags.bats          — 17 tests: --network host, --allow, build-args (incl. OCI VERSION/SOURCE_URL/REVISION forwarding)
├── test_install.bats              — 10 tests: full install/uninstall/self-update
├── test_aliases.bats              — 14 tests: string + function aliases, reserved names
├── test_images.bats               — 14 tests: OPS_IMAGES profiles, -n/-f override, smart -i
├── test_edge_cases.bats           — 29 tests: --nix-cleanup, --update, HOME_IN_CTN, etc.
├── test_labels.bats               —  8 tests: ops.dockerfile / ops.container / ops.cmdline.* / ops.volume labels
├── test_doctor.bats               —  9 tests: doctor, OPS_IMAGES/Dockerfiles validation, dangling entries, containers section
├── test_inspect.bats              —  7 tests: inspect key/container/image ref
├── test_cmd_config.bats           —  7 tests: config subcommand, origin tracking (env/config/default)
├── test_logs.bats                 —  9 tests: logs|log, [NAME] positional, --strip|-s, --tail N parsing
├── test_alias_global_flags.bats   —  7 tests: alias regression with -i/-n/-f prefix (cc bug)
├── test_clean_labels.bats         —  9 tests: clean filters by ops.container / ops.volume labels (incl. interactive y/n branches)
├── test_status_enhanced.bats      —  9 tests: info layout (Services at top, Volumes before Containers)
├── test_backup_restore.bats       — 10 tests: cmd_backup / cmd_restore, TTY guards, alpine tar, OPS_FORCE_TTY override
├── test_update.bats               —  4 tests: cmd_update, build + dispatch
├── test_update_flow.bats          —  4 tests: full cmd_update flow (image ID diff, container rm, (none))
├── test_status_visual.bats        —  7 tests: coloured Up/Exited states, ⚠ orphan, cmd:/ops cli:/real cli:
├── test_doctor_containers.bats    —  5 tests: doctor Containers — orphan, image mismatch, OK match
├── test_unit_helpers.bats         — 14 tests: direct unit tests for _human_bytes, _shell_quote (via OPS_SOURCE_ONLY)
├── test_label_masking.bats        —  8 tests: secret masking in BOTH ops.cmdline.user and ops.cmdline.real labels (GITHUB_TOKEN / ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY)
├── test_regressions.bats          — 14 tests: build arg leak fix (#18), --user-name remap (#24), PWD⊂HOME (#23), clean interactive (#20), rootless cache reset (#17), isolated agent volumes, install-path safety, start-fail re-dispatch (#19), and more
├── test_image_integration.bats    — 40 integration tests against the actually-built localhost/ops-dev image (Nix GC root, chrome hooks, mise config split, machine-id, unfree flags, OCI labels, …). Skips if Docker or the image is absent.
├── test_subcommand_help.bats      — 18 tests: per-subcommand --help output (doctor/inspect/config/clean/status/logs/backup/restore/update/aliases/images/runtime). Ensures `-h|--help` is intercepted before arg parsing and exits 0.
├── test_secret_symmetry.bats      —  8 tests: regression guard ensuring `_dry_run_print` (dry-run) and `_mask_secrets` (labels) agree on what is a secret (e.g. MY_DB_PASSWORD redacted everywhere; MONKEY treated as non-secret in both paths).
├── test_match_agent_flag.bats     —  8 tests: per-agent flag dispatcher `_match_agent_flag` — `--{claude,gemini,opencode,codex}-{mount,volume}` + `--no-X-mount` collapsed into one nameref-based handler.
└── test_volume_validation.bats    —  5 tests: `-v / --volume SRC:DST` arg-shape validation (rejects bare values that lack `:`).
```

### Running the image integration suite

The file `test_image_integration.bats` is the **only** one that touches a real image (everything else mocks). Run it after a local build:

```bash
./ops.sh build
bats tests/test_image_integration.bats
```

CI runs this job (`image-integration`) automatically on pushes to `main` and via manual `workflow_dispatch`. It is **not** triggered on pull requests — building the full Arch image with Nix takes ~15 min and we don't want to block every PR on that. If you want to run it on a PR branch, push to a branch named `main` in your fork or trigger it manually from the Actions tab.

### Coverage

| Area | Coverage |
|---|---|
| Subcommand dispatch (run/build/status/logs/clean/inspect/config/doctor/backup/restore/update) | **100%** |
| Per-subcommand `--help` / `-h` (doctor/inspect/config/clean/status/info/logs/log/backup/restore/update/aliases/alias/images/image/runtime) | **100%** |
| Runtime detection (auto/docker/podman/nerdctl/invalid) | **100%** |
| Config file loading + precedence (env > config) | **100%** |
| `config` subcommand (origin tracking env/config/default) | **100%** |
| `run` flags (all documented flags are tested) | **~95%** |
| Agents (claude/gemini/opencode/codex + -mount) | **100%** |
| `nerdctl install` / `nerdctl uninstall` / `nerdctl self-update` (happy path + errors + namespace dispatch) | **~95%** |
| Build args (docker/podman/nerdctl) | **~90%** |
| Labels (`ops.dockerfile` / `ops.container` / `ops.cmdline.*` / `ops.volume`) | **100%** |
| Aliases (string + function + global flag re-parse) | **100%** |
| Container lifecycle (running/stopped/volume warning/orphan) | **~90%** |
| Logs (positional NAME / `--strip` / `--tail` / `log` alias) | **100%** |
| Clean (label filter, dangling/stopped/volumes sections) | **100%** |
| Backup / restore (TTY guards, alpine tar, ensure_volume) | **100%** |
| Per-image hash + rebuild detection | **100%** |

**465 tests across 36 files.** The "coverage" column above is an eyeballed estimate based on which documented subcommands and flags are exercised; no coverage tool is run in CI (see `mise run coverage` for an opt-in local report, with caveats).

A pure-Lua unit-test harness lives under `tests/lua/` (run via `mise run test-lua` or `lua5.4 tests/lua/run.lua`). It exercises the plugin helpers that don't need mise's native modules — `shell.shquote`, `version.parse_version`, `flake.is_reference`, `plugin_matcher.matches`, `tempdir.with_temp_dir`, `security.is_safe_local_path`, `jetbrains.extract_plugin_info`. The harness stubs the native modules via `package.preload` so any vanilla `lua5.x` interpreter is enough; busted is not required.

### What remains uncovered

- **`ensure_buildkitd` / `stop_buildkitd`**: require a real `buildkitd` + `rootlesskit` process (too heavy to mock). The CI `runtime-build` job on nerdctl exercises the full `ensure_buildkitd` → `docker build` → `stop_buildkitd` sequence against `Dockerfile.cismoke` (alpine base — kept small to stay under the 5 min CI budget; the real Arch+Nix image is not rebuilt every CI run).
- **`flock` concurrency**: multi-process TOCTOU scenarios (the fix is covered by the `--if-missing` guard but not by a concurrent-process test)
- **`_print_mounts`**: tested indirectly through its consumers (`status`, `inspect`)

### Run the tests locally

Two equivalent ways — pick either.

**Option A — via `mise.toml` (recommended if you already use mise)**

A `mise.toml` at the repo root declares the dev toolchain: bats, shellcheck, hadolint (via the `aqua:` backend) plus ruby + bashcov (via the core `ruby` plugin + `gem:` backend, for `mise run coverage`). One-time setup:

```bash
mise trust            # authorize the repo's mise.toml
mise install          # fetches all the pinned tools (~2-3 min first time due to ruby compile)

# luacheck is NOT in mise.toml (not packaged in the aqua registry). Install
# it via your system package manager so `mise run lint` can lint mise/*.lua:
sudo apt install luacheck          # Debian/Ubuntu
# or: sudo pacman -S luacheck      # Arch
# or: brew install luacheck        # macOS
# Without it, `mise run lint` prints a warning and skips the Lua checks.
```

Then:

```bash
mise run lint         # shellcheck + bash -n + luacheck + hadolint
mise run test         # full mocked bats suite
mise run ci           # lint + test (mirrors the CI pipeline one-for-one)
mise run test-image   # integration suite (needs `./ops.sh build` first)
mise run coverage     # bashcov → coverage/index.html (see mise.toml for caveats)
mise run smoke        # cismoke Dockerfile build against the active runtime
```

**Option B — via the distro package manager**

```bash
# Debian/Ubuntu
sudo apt install bats shellcheck luacheck hadolint

# Arch
sudo pacman -S bats shellcheck luacheck hadolint

# From the project directory
bats tests/
```

### GitHub Actions CI

The `.github/workflows/tests.yml` workflow runs on every push/PR to `main`:

1. **bats** job: installs `bats` + `shellcheck` + `luacheck`, runs `shellcheck -S style ops.sh` (blocking), `bash -n ops.sh`, `luacheck mise/` (blocking — lints the whole plugin tree, with `types.lua` excluded because it only carries EmmyLua meta-annotations), and the full bats suite.
2. **hadolint** job: lints `Dockerfile` (and `Dockerfile.debian` if present).
3. **runtime build smoke** matrix job (docker / podman / nerdctl): builds a minimal `Dockerfile.cismoke` (alpine base) through `ops.sh build` on each runtime — exercises the full wrapper pipeline (flags, lock, hash, labels, `ensure_buildkitd` on nerdctl) without pulling the heavy Arch/Nix tree.

To reproduce the CI locally:
```bash
shellcheck -S style ops.sh && bash -n ops.sh
luacheck mise/ --globals PLUGIN RUNTIME --no-max-line-length --exclude-files mise/types.lua
bats tests/
hadolint Dockerfile
./ops.sh build          # smoke test against your local runtime
```

---

## License & contributing

- **License**: Apache License 2.0. See [`LICENSE`](LICENSE); the `mise/` subdir
  ships its own per-file license map (`mise/NOTICE`, `mise/LICENSE`,
  `mise/LICENSE.MIT`).
- **Contributing**: PRs are welcome. The CI pipeline is what gates merges —
  see [`.github/workflows/tests.yml`](.github/workflows/tests.yml) for the
  `shellcheck` / `hadolint` / `luacheck` / `bats` / `trivy` jobs you'll need
  to keep green. `mise run ci` reproduces the unit-test path locally.
