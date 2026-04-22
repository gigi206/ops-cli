# ops — Containerized development environment

![tests](../../actions/workflows/tests.yml/badge.svg)

Shell wrapper around **docker / podman / nerdctl** that provides a ready-to-use development container, with AI agents (Claude Code, Gemini, OpenCode, Codex), mise + Nix (via the mise-nix plugin), and standard tooling (git, semgrep, ripgrep, jq, ast-grep, gh, qlty).

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
- System tooling: `curl`, `tar`, `sha256sum`, `awk`, `sed`, `systemctl` (only required for `nerdctl install`), `realpath` (optional — used to resolve the absolute Dockerfile path for labels; falls back to the raw path if missing)

The script auto-detects the available runtime in this order: **docker > podman > nerdctl**.

---

## Installation

### Step 1 — clone / copy the files

Place at least these files in a directory (e.g. `~/Documents/msb/`):

```
ops.sh              ← the wrapper
Dockerfile          ← default image (Arch-based)
mise/               ← local mise-nix plugin, COPY'd into the image at build time
```

(Without `mise/`, the image still builds but the `nix:pkg@ver` backend + `flake.nix` auto-activation features are missing.)

### Step 2 — make it executable

```bash
chmod +x ops.sh
```

### Step 3 — (optional) shell aliases

In `~/.bashrc` or `~/.zshrc`:

```bash
# The wrapper itself
alias ops='~/Documents/msb/ops.sh'

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
| `build [FLAGS]` | Build (or rebuild) the image. After a successful build, compares the new image ID to the previous one and, if it changed, lists containers still running on the old ID with a `relaunch:` hint from the `ops.cmdline.user` label, then offers a `[y/N]` prompt to remove them. |
| `runtime ARGS...` | Proxy directly to the runtime binary (e.g. `ops.sh runtime ps -a`) |
| `status` \| `info` | Show the state: services, images (default + profiles + labelled), labelled volumes, containers (name, image, coloured state, cmd, ops cli, real cli, mounts) |
| `inspect KEY` | Detailed info for an `OPS_IMAGES` key, a container name, or a raw image reference |
| `config` | Dumps the effective config (all `OPS_*` scalars + arrays) with origin (env/config/default) |
| `doctor` | Validates config consistency: `OPS_IMAGES`/dockerfiles/`ops.dockerfile` labels, dangling entries, orphan containers (missing image) and mismatches (container on an image ≠ its profile's). Non-zero return code if warnings |
| `update [KEY]` | Alias of `build`. Accepts an optional profile key to target a specific image from `OPS_IMAGES` (e.g. `ops update ml`); without a key, behaves exactly like `build` on the default image. |
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
  OPS_DOCKERFILE                   = /home/you/Documents/msb/Dockerfile      [default]
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
  dockerfile: /home/you/Documents/msb/Dockerfile.ml

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
| `-H, --nerdctl-home PATH` | nerdctl install directory (nerdctl only) |

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

### External variables (no prefix)

| Variable | Role |
|---|---|
| `GITHUB_TOKEN` | Injected into `/etc/nix/nix.conf` at build time **and** auto-propagated at runtime. Lifts the GitHub API rate limit 60→5000 req/h. **Classic PAT, no scope required.** Masked in `ops.cmdline.real` label. |
| `ANTHROPIC_API_KEY` | Auto-propagated to the container when set on the host. Masked in label. |
| `OPENAI_API_KEY` | Auto-propagated to the container when set on the host. Masked in label. |
| `GEMINI_API_KEY` | Auto-propagated to the container when set on the host. Masked in label. |
| `LANG`, `HOME`, `TERM`, `COLORTERM` | POSIX standards, honored inside the container. |
| `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `XDG_RUNTIME_DIR` | XDG standards — affect `ops.conf` lookup, hash cache location, buildkit socket. |

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
install uninstall self-update
alias aliases image images
doctor inspect config backup restore update
help -h --help
```

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

`GITHUB_TOKEN`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and `GEMINI_API_KEY` are auto-propagated into the container when set on the host — no flag required. All four are masked in the `ops.cmdline.real` label (see [Labels → Security](#%E2%9A%A0-security-secret-exposure)).

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
| Container | `ops.container` | `true` | `cmd_run` |
| Container | `ops.cmdline.user` | The original `./ops.sh ...` invocation (shell-quoted) | `cmd_run` |
| Container | `ops.cmdline.real` | The effective `docker run ...` command (shell-quoted) | `cmd_run` |
| Volume | `ops.volume` | `true` | `ensure_volume` |

### Concrete effects

- **`info`**: shows labelled images even if not declared in `OPS_IMAGES` (with the Dockerfile basename as tag). Labelled containers are listed even when their image disappeared (marker `⚠ (image missing)`). `cmd:`, `ops cli:`, `real cli:` are extracted from these labels.
- **`doctor`**: checks that the `ops.dockerfile` label of a built image matches the Dockerfile declared in `OPS_DOCKERFILES[key]` / `Dockerfile.<key>`.
- **`clean`**: filters strictly on `ops.container=true` / `ops.volume=true` — containers/volumes created outside `ops.sh` are **preserved**.

### ⚠ Security: secret exposure

The `ops.cmdline.real` label contains **the full `docker run` command**, including every `--env KEY=VAL`. Known secret-bearing variables are **masked** in the label as `KEY=***` before it is written:

- `GITHUB_TOKEN`
- `ANTHROPIC_API_KEY`
- `OPENAI_API_KEY`
- `GEMINI_API_KEY`

The container itself still receives the real values (via `--env` in the actual invocation, not via the label). **Any other secret** passed through `-e MY_TOKEN=...` or `--env-file` is **not masked** — add its name to the masking regex in `cmd_run` if you need it covered.

Layer-level exposure remains: `GITHUB_TOKEN` is baked into the image's `/etc/nix/nix.conf` at build time and is visible in the image layers via `docker image inspect`. Do not push that image to a public registry.

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
ops                             # without --build: no rebuild is triggered, but a yellow warning
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
ops build --dry-run 2>/dev/null || true      # build path doesn't support --dry-run;
                                              # use `ops run --build --dry-run` for that
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
# Remove binaries (/home/you/.local/share/ops/nerdctl)? [Y/n]  Y
# Remove containerd data (images, containers, snapshots) (...)? [Y/n]  n
# Uninstall complete.
```

Answer `n` to the second prompt if you want to reinstall later without losing the image cache.

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

Then rebuild so the token is baked into the image's `/etc/nix/nix.conf`:
```bash
ops build --no-cache    # force a full rebuild
```

**⚠ Watch out for the hybrid case**: if the image was built **without** a token and you later provide a token at runtime, the image's `/etc/nix/nix.conf` still contains `access-tokens =` (empty). Nix will not automatically pick up the env token — a rebuild is required. mise/gh do read the env var directly and are therefore covered.

**Generate a token**: https://github.com/settings/tokens/new → any name, **no scope required** → Generate. The token is baked into the build layer → do not push that image to a public registry.

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

The token is propagated **at build time** (baked into `/etc/nix/nix.conf`) **and at runtime** (env var for mise/gh).

⚠ The token is visible in the **image layers** (`docker image inspect`), baked into `/etc/nix/nix.conf`. It is **not** exposed in the container's `ops.cmdline.real` label — `GITHUB_TOKEN=***` is masked there (see [Labels → Security](#%E2%9A%A0-security-secret-exposure)). Fine for local personal use — do not push the image to a registry.

---

## Project structure

Core files:

```
msb/
├── ops.sh                       # the wrapper (entry point)
├── Dockerfile                   # default image (Arch)
├── Dockerfile.debian            # optional Debian-based variant
├── README.md                    # this file
├── mise/                        # local mise-nix plugin (copied into the image)
├── tests/                       # bats suite (see the Tests section for the list)
└── .github/workflows/tests.yml  # CI (shellcheck + hadolint + bats + Docker build matrix)
```

Optional helpers (not required to run `ops.sh`):

```
├── setup.sh / setup-debian.sh / setup-nix.sh / setup-debian-deps.sh
├── mise-plugin/                 # upstream mise-nix sources (vendored for dev)
├── nerdctl/ / rootfs/           # local artefacts, not packaged
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
├── test_dispatch.bats             — 12 tests: subcommands, runtime proxy, clean
├── test_runtime.bats              —  8 tests: auto-detection, rootless/rootful, invalid
├── test_dryrun.bats               — 15 tests: run flag parsing
├── test_flags.bats                — 22 tests: -u/-g/-l/-H/-e/-p/--env-file/no-*-volume/api-key masking/…
├── test_config.bats               —  5 tests: ops.conf loading + precedence
├── test_hash.bats                 —  5 tests: per-image hash + dockerfile_changed
├── test_container_state.bats      —  6 tests: running/stopped/logs/status
├── test_image_state.bats          —  5 tests: build trigger, volume warning
├── test_build_flags.bats          —  7 tests: --network host, --allow, build-args
├── test_install.bats              — 10 tests: full install/uninstall/self-update
├── test_aliases.bats              — 14 tests: string + function aliases, reserved names
├── test_images.bats               — 14 tests: OPS_IMAGES profiles, -n/-f override, smart -i
├── test_edge_cases.bats           — 27 tests: --nix-cleanup, --update, HOME_IN_CTN, etc.
├── test_labels.bats               —  8 tests: ops.dockerfile / ops.container / ops.cmdline.* / ops.volume labels
├── test_doctor.bats               —  9 tests: doctor, OPS_IMAGES/Dockerfiles validation, dangling entries, containers section
├── test_inspect.bats              —  6 tests: inspect key/container/image ref
├── test_cmd_config.bats           —  7 tests: config subcommand, origin tracking (env/config/default)
├── test_logs.bats                 —  9 tests: logs|log, [NAME] positional, --strip|-s, --tail N parsing
├── test_alias_global_flags.bats   —  6 tests: alias regression with -i/-n/-f prefix (cc bug)
├── test_clean_labels.bats         —  7 tests: clean filters by ops.container / ops.volume labels
├── test_status_enhanced.bats      —  9 tests: info layout (Services at top, Volumes before Containers)
├── test_backup_restore.bats       — 10 tests: cmd_backup / cmd_restore, TTY guards, alpine tar, OPS_FORCE_TTY override
├── test_update.bats               —  4 tests: cmd_update, build + dispatch
├── test_update_flow.bats          —  4 tests: full cmd_update flow (image ID diff, container rm, (none))
├── test_status_visual.bats        —  7 tests: coloured Up/Exited states, ⚠ orphan, cmd:/ops cli:/real cli:
├── test_doctor_containers.bats    —  5 tests: doctor Containers — orphan, image mismatch, OK match
├── test_unit_helpers.bats         — 11 tests: direct unit tests for _human_bytes, _shell_quote (via OPS_SOURCE_ONLY)
├── test_label_masking.bats        —  7 tests: GITHUB_TOKEN / ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY masking in ops.cmdline.real label
└── test_regressions.bats          — 14 tests: build arg leak fix (#18), --user-name remap (#24), PWD⊂HOME (#23), clean interactive (#20), rootless cache reset (#17), isolated agent volumes, install-path safety, start-fail re-dispatch (#19), and more
```

### Coverage

| Area | Coverage |
|---|---|
| Subcommand dispatch (run/build/status/logs/clean/inspect/config/doctor/backup/restore/update) | **100%** |
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

**~98% overall coverage** — 273 tests across 29 files.

### What remains uncovered

- **`ensure_buildkitd` / `stop_buildkitd`**: require a real `buildkitd` + `rootlesskit` process (too heavy to mock). The CI `runtime-build` job on nerdctl exercises the full `ensure_buildkitd` → `docker build` → `stop_buildkitd` sequence against `Dockerfile.cismoke` (alpine base — kept small to stay under the 5 min CI budget; the real Arch+Nix image is not rebuilt every CI run).
- **`flock` concurrency**: multi-process TOCTOU scenarios (the fix is covered by the `--if-missing` guard but not by a concurrent-process test)
- **`_print_mounts`**: tested indirectly through its consumers (`status`, `inspect`)

### Run the tests locally

```bash
# Debian/Ubuntu
sudo apt install bats

# Arch
sudo pacman -S bats

# From the project directory
bats tests/
```

### GitHub Actions CI

The `.github/workflows/tests.yml` workflow runs on every push/PR to `main`:

1. **bats** job: installs `bats` + `shellcheck`, runs `shellcheck -S style ops.sh` (blocking), `bash -n ops.sh`, and the full bats suite.
2. **hadolint** job: lints `Dockerfile` (and `Dockerfile.debian` if present).
3. **runtime build smoke** matrix job (docker / podman / nerdctl): builds a minimal `Dockerfile.cismoke` (alpine base) through `ops.sh build` on each runtime — exercises the full wrapper pipeline (flags, lock, hash, labels, `ensure_buildkitd` on nerdctl) without pulling the heavy Arch/Nix tree.

To reproduce the CI locally:
```bash
shellcheck -S style ops.sh && bash -n ops.sh && bats tests/
hadolint Dockerfile
./ops.sh build          # smoke test against your local runtime
```

---

## License & contributing

Personal project. Use, adapt, fork freely.
