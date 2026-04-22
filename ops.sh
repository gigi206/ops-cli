#!/bin/bash
# shellcheck disable=SC2016
# Intentional single-quoted '$...' strings (cmd_run --nix-cleanup / --update):
# the inner $HOME etc. are expanded later by bash -c inside the container,
# not on the host. Applies file-wide because case-branch directives are invalid.

# `set -uo pipefail` but deliberately NOT `-e`: this script has many optional
# paths (image/container inspect, volume ls, etc.) where a non-zero return
# is an expected "not found" signal, not an error. We prefer explicit
# `|| true` / `[ $ret -eq 0 ] && ...` guards over a global exit-on-error.
# `-u` catches unset-variable typos; `pipefail` stops silent pipe failures.
set -uo pipefail

# Single source of truth for the ops.sh version. Update when cutting a new
# release; CHANGELOG.md should carry the matching entry.
OPS_VERSION="0.1.0"
readonly OPS_VERSION

# Snapshot OPS_* vars at entry so cmd_config can report each var's origin:
# - env:     present before config is sourced
# - config:  defined by sourcing ops.conf
# - default: assigned later by :- fallbacks in this script
declare -A _OPS_ORIGIN=()
for _v in $(compgen -v 2>/dev/null | grep '^OPS_' || true); do _OPS_ORIGIN[$_v]='env'; done
unset _v

_CONFIG_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/ops/ops.conf"
# shellcheck disable=SC1090
[ -f "$_CONFIG_FILE" ] && source "$_CONFIG_FILE"

for _v in $(compgen -v 2>/dev/null | grep '^OPS_' || true); do
    [ -z "${_OPS_ORIGIN[$_v]:-}" ] && _OPS_ORIGIN[$_v]='config'
done
unset _v

OPS_NERDCTL_HOME="${OPS_NERDCTL_HOME:-$HOME/.local/share/ops/nerdctl}"
export PATH="$OPS_NERDCTL_HOME/bin:$PATH"

OPS_RUNTIME="${OPS_RUNTIME:-auto}"
RUNTIME_BIN=""

# Resolves OPS_RUNTIME to a concrete runtime (docker/podman/nerdctl) and
# sets RUNTIME_BIN to the binary path. Auto order: docker > podman > nerdctl.
# If auto finds nothing, falls back to nerdctl so the auto-install prompt kicks in.
_resolve_runtime() {
    # Reset rootless cache: a change of RUNTIME_BIN invalidates it (e.g. when
    # -H switches OPS_RUNTIME from docker to nerdctl mid-run).
    _IS_ROOTLESS_CACHE=""
    case "$OPS_RUNTIME" in
        auto)
            for r in docker podman nerdctl; do
                case "$r" in
                    nerdctl) [ -x "$OPS_NERDCTL_HOME/bin/nerdctl" ] && { OPS_RUNTIME=$r; break; } ;;
                    *)       command -v "$r" >/dev/null 2>&1       && { OPS_RUNTIME=$r; break; } ;;
                esac
            done
            [ "$OPS_RUNTIME" = auto ] && OPS_RUNTIME=nerdctl
            ;;
        docker|podman|nerdctl) ;;
        *)
            echo "Invalid OPS_RUNTIME: $OPS_RUNTIME (valid: auto, docker, podman, nerdctl)" >&2
            exit 1
            ;;
    esac
    case "$OPS_RUNTIME" in
        nerdctl) RUNTIME_BIN="$OPS_NERDCTL_HOME/bin/nerdctl" ;;
        docker)  RUNTIME_BIN="$(command -v docker  || true)" ;;
        podman)  RUNTIME_BIN="$(command -v podman  || true)" ;;
    esac
}
_resolve_runtime

# Detects whether the current runtime is running rootless. Rootless containers
# map the host UID to container UID 0, so we want --user 0 to retain R/W on
# bind-mounted host files. In rootful docker there is no mapping, so we want
# --user $OPS_USER_UID instead (otherwise files created in $PWD land as root).
# Result is cached because `docker info` is a daemon round-trip (~50-100ms).
# _IS_ROOTLESS_CACHE is initialized in _resolve_runtime.
_is_rootless() {
    if [ -z "$_IS_ROOTLESS_CACHE" ]; then
        if [ ! -x "$RUNTIME_BIN" ]; then
            _IS_ROOTLESS_CACHE=yes
        else
            case "$OPS_RUNTIME" in
                docker)  "$RUNTIME_BIN" info --format '{{.SecurityOptions}}' 2>/dev/null \
                            | grep -q 'name=rootless' && _IS_ROOTLESS_CACHE=yes || _IS_ROOTLESS_CACHE=no ;;
                podman)  [ "$("$RUNTIME_BIN" info --format '{{.Host.Security.Rootless}}' 2>/dev/null)" = "true" ] \
                            && _IS_ROOTLESS_CACHE=yes || _IS_ROOTLESS_CACHE=no ;;
                nerdctl) _IS_ROOTLESS_CACHE=yes ;;
            esac
        fi
    fi
    [ "$_IS_ROOTLESS_CACHE" = yes ]
}

BUILDKITD_PID=""
TMP_INSTALL_DIR=""
OPS_BUILDKITD_TIMEOUT="${OPS_BUILDKITD_TIMEOUT:-10}"
OPS_CONTAINERD_STARTUP_TIMEOUT="${OPS_CONTAINERD_STARTUP_TIMEOUT:-30}"

ensure_buildkitd() {
    local sock="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/buildkit/buildkitd.sock"
    if ! "$OPS_NERDCTL_HOME/bin/buildctl" --addr "unix://$sock" debug workers &>/dev/null; then
        echo "Starting buildkitd..."
        "$OPS_NERDCTL_HOME/bin/rootlesskit" "$OPS_NERDCTL_HOME/bin/buildkitd" \
            --addr "unix://$sock" \
            --oci-worker=true \
            --oci-worker-rootless=true \
            --oci-worker-binary="$OPS_NERDCTL_HOME/bin/runc" \
            --containerd-worker=false \
            --allow-insecure-entitlement network.host \
            --allow-insecure-entitlement security.insecure \
            &>/tmp/buildkitd.log &
        BUILDKITD_PID=$!
        local i=0
        while ! "$OPS_NERDCTL_HOME/bin/buildctl" --addr "unix://$sock" debug workers &>/dev/null; do
            sleep 1; i=$((i+1)); [ $i -ge "$OPS_BUILDKITD_TIMEOUT" ] && { echo "buildkitd timeout (${OPS_BUILDKITD_TIMEOUT}s). See /tmp/buildkitd.log" >&2; exit 1; }
        done
    fi
}

stop_buildkitd() {
    if [ -n "${BUILDKITD_PID:-}" ]; then
        kill "$BUILDKITD_PID" 2>/dev/null || true
        local _i=0
        while kill -0 "$BUILDKITD_PID" 2>/dev/null && [ $_i -lt 10 ]; do
            sleep 0.2; _i=$((_i+1))
        done
        if kill -0 "$BUILDKITD_PID" 2>/dev/null; then
            kill -9 "$BUILDKITD_PID" 2>/dev/null || true
        fi
        wait "$BUILDKITD_PID" 2>/dev/null || true
        echo "buildkitd stopped."
        BUILDKITD_PID=""
    fi
}

cleanup() {
    stop_buildkitd
    [ -n "${TMP_INSTALL_DIR:-}" ] && rm -rf "$TMP_INSTALL_DIR"
    return 0
}
trap cleanup EXIT INT TERM

# Shell-quote args for human-readable display: leave simple tokens bare,
# single-quote anything with special chars. Safe to re-execute, but much
# nicer to read than printf %q (which backslash-escapes each metachar).
_shell_quote() {
    local s
    for s in "$@"; do
        if [ -z "$s" ]; then
            printf "'' "
        elif [[ "$s" =~ ^[A-Za-z0-9._/=@:,+-]+$ ]]; then
            printf '%s ' "$s"
        else
            printf "'%s' " "${s//\'/\'\\\'\'}"
        fi
    done
}

# Captured before any parsing so cmd_run can stamp it as a label on new containers.
OPS_ORIG_ARGV="$(_shell_quote "$0" "$@")"

OPS_IMAGE="${OPS_IMAGE:-localhost/ops-dev}"
OPS_CONTAINER_NAME="${OPS_CONTAINER_NAME:-ops-dev}"
OPS_USER_UID="${OPS_USER_UID:-$(id -u)}"
OPS_USER_GID="${OPS_USER_GID:-$(id -g)}"
OPS_USER_NAME="${OPS_USER_NAME:-$(id -un)}"
OPS_USER_LANG="${OPS_USER_LANG:-${LANG:-en_US.UTF-8}}"

# Container-side $HOME. Distinct from host's $HOME when OPS_USER_NAME differs
# from the invoking user (rare but breaks bind-mount dest paths otherwise).
HOME_IN_CTN="/home/$OPS_USER_NAME"

SCRIPT_DIR="$(dirname "$0")"
OPS_DOCKERFILE="${OPS_DOCKERFILE:-$SCRIPT_DIR/Dockerfile}"

# Hash file is derived from OPS_IMAGE so each image has its own cache.
# Lazy so changes to OPS_IMAGE via -i (global or in cmd_run) are picked up.
_hash_file() {
    echo "${XDG_CACHE_HOME:-$HOME/.cache}/ops/${OPS_IMAGE//\//_}.sha256sum"
}

current_hash() {
    if [ ! -f "$OPS_DOCKERFILE" ]; then
        echo "Error: Dockerfile not found: $OPS_DOCKERFILE" >&2
        return 1
    fi
    sha256sum "$OPS_DOCKERFILE" | cut -d' ' -f1
}

stored_hash() {
    local f; f=$(_hash_file)
    [ -f "$f" ] && cat "$f" || echo ""
}

save_hash() {
    local f h
    h=$(current_hash) || return 1
    f=$(_hash_file)
    mkdir -p "$(dirname "$f")"
    printf '%s\n' "$h" > "$f"
}

dockerfile_changed() {
    local f; f=$(_hash_file)
    [ -f "$f" ] && [ "$(current_hash)" != "$(cat "$f")" ]
}

build_image() {
    # First arg --if-missing: after acquiring the build lock, skip the build if
    # the image now exists (another process may have built it). Prevents the
    # classic TOCTOU between the caller's `images -q` check and the lock grab.
    local if_missing=0
    if [ "${1:-}" = "--if-missing" ]; then
        if_missing=1
        shift
    fi

    if [ ! -f "$OPS_DOCKERFILE" ]; then
        echo "Error: Dockerfile not found: $OPS_DOCKERFILE" >&2
        return 1
    fi

    local lock_file
    lock_file="$(_hash_file).lock"
    mkdir -p "$(dirname "$lock_file")"
    if command -v flock >/dev/null 2>&1; then
        exec 9>"$lock_file"
        if [ "$if_missing" = 1 ]; then
            if ! flock -w 300 9; then
                echo "Timed out waiting for build lock ($lock_file)" >&2
                return 1
            fi
            # Re-check under the lock: if another process built the image, we're done.
            if "$RUNTIME_BIN" images -q "$OPS_IMAGE" 2>/dev/null | grep -q .; then
                exec 9>&-
                return 0
            fi
        else
            if ! flock -n 9; then
                echo "Another build is in progress (lock: $lock_file)" >&2
                return 1
            fi
        fi
    fi

    # --network host is needed during image builds: Nix needs to reach
    # cache.nixos.org, and the default bridge network is too flaky for
    # a 150 MB download across 170+ narinfo fetches.
    local -a extra_build_flags=(--network host)
    if [ "$OPS_RUNTIME" = "nerdctl" ]; then
        ensure_buildkitd
        # --allow is a buildkit-specific entitlement grant (nerdctl 2.x also
        # asks for security.insecure when network.host is granted — the daemon
        # is configured to allow it in ensure_buildkitd).
        extra_build_flags+=(--allow network.host)
    fi

    local dockerfile_abs
    dockerfile_abs="$(realpath "$OPS_DOCKERFILE" 2>/dev/null || echo "$OPS_DOCKERFILE")"

    # GITHUB_TOKEN is passed via BuildKit secret (never baked into image
    # layers). --secret is a no-op for legacy builders without BuildKit; the
    # Dockerfile declares the mount as required=false so the build still
    # succeeds without a token (API rate limit falls back to 60 req/h).
    local -a secret_flags=()
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        secret_flags+=(--secret "id=github_token,env=GITHUB_TOKEN")
    fi
    "$RUNTIME_BIN" build -t "$OPS_IMAGE" \
        --file "$OPS_DOCKERFILE" \
        --label "ops.dockerfile=$dockerfile_abs" \
        --pull \
        "${extra_build_flags[@]}" \
        --build-arg USER_UID="$OPS_USER_UID" \
        --build-arg USER_GID="$OPS_USER_GID" \
        --build-arg USER_NAME="$OPS_USER_NAME" \
        --build-arg USER_LANG="$OPS_USER_LANG" \
        "${secret_flags[@]}" \
        "$@" "$SCRIPT_DIR"
    local ret=$?
    [ $ret -eq 0 ] && save_hash
    [ "$OPS_RUNTIME" = "nerdctl" ] && stop_buildkitd
    command -v flock >/dev/null 2>&1 && exec 9>&-
    return $ret
}

show_help() {
    cat <<EOF
Usage: $(basename "$0") [SUBCOMMAND] [OPTIONS] [ARGS...]

Subcommands:
  run [OPTIONS] [COMMAND...]  Start or join the dev container (default subcommand; -- stops flag parsing)
  build [FLAGS]  Build the image (shortcut for: run --build)
  runtime CMD    Proxy directly to the runtime binary (currently: $OPS_RUNTIME)
  status|info    Show image, container, volumes and services state
  logs|log [NAME] [-s|--strip] [FLAGS]  Tail container logs (--strip removes ANSI escapes)
  clean [--dry-run]  Prune dangling images, stopped ops containers, ops volumes
  doctor         Validate config: OPS_IMAGES refs, dockerfiles, image labels
  inspect KEY    Show detailed info for an OPS_IMAGES key, container, or image ref
  config         Dump effective OPS_* config (scalars + arrays) with origin
  backup VOL     Stream a volume as tar.gz to stdout  (redirect to a file)
  restore VOL    Restore a volume from a tar.gz on stdin  (redirect from a file)
  update KEY     Rebuild an image and offer to recreate containers on the old version
  nerdctl CMD    Manage the nerdctl install (see 'nerdctl --help'):
                   install        Download nerdctl-full to \$OPS_NERDCTL_HOME
                   uninstall      Stop containerd.service + remove binaries/data
                   self-update    Update nerdctl to the latest release
  alias|aliases  List user-defined aliases from the config file
  image|images   List declared images (OPS_IMAGES) from the config file
  <alias>        Invoke a user-defined alias (see 'aliases')
  help           Show this help
  version        Print the ops version (alias: --version / -V)

Config: $_CONFIG_FILE (sourced on startup, sets default env vars)
Runtime: $OPS_RUNTIME (set OPS_RUNTIME=auto|docker|podman|nerdctl; auto picks docker > podman > nerdctl)

Global flags (may appear before the subcommand, apply to all):
  -n, --name NAME           Container name           (default: $OPS_CONTAINER_NAME)
  -i, --image NAME          Image — raw ref or key of OPS_IMAGES (default: $OPS_IMAGE)
  -f, --dockerfile PATH     Dockerfile path          (default: $OPS_DOCKERFILE)
  -H, --nerdctl-home PATH   nerdctl directory        (default: ~/.local/share/ops/nerdctl)
  Example: $(basename "$0") -n web logs -f

$(basename "$0") run [OPTIONS] [COMMAND...]
  -i, --image NAME          Image to use             (default: $OPS_IMAGE)
  -n, --name NAME           Container name           (default: $OPS_CONTAINER_NAME)
  -u, --uid UID             UID inside container     (default: $(id -u))
  -g, --gid GID             GID inside container     (default: $(id -g))
  -l, --lang LOCALE         Container locale         (default: ${LANG:-en_US.UTF-8})
  -v, --volume SRC:DST      Extra volume             (repeatable)
  -e, --env KEY=VAL         Extra env var            (repeatable)
      --env-file FILE       Read env vars from file  (repeatable)
  -p, --port HOST:CTN       Publish port             (repeatable)
  -H, --nerdctl-home PATH   nerdctl directory        (default: ~/.local/share/ops/nerdctl)
      --no-rm               Keep container on exit   (default: removed)
      --dry-run             Print the runtime command instead of executing it
  -b, --build [ARGS]        Build the image
      --no-cache            Invalidate build cache
      --nix-cleanup         Run nix-collect-garbage -d inside the container
      --update              Update mise and nix store inside the container
      --no-mount-home       Do not bind-mount host \$HOME (default: mounted).
                            Agent volume bind-mounts (~/.claude, ~/.gemini,
                            ~/.local/share/opencode, ~/.codex) become active
                            when this flag is used.
      --no-mount-volume     Do not mount the mise and nix volumes
                            (equivalent to --no-nix-volume --no-mise-volume)
      --no-nix-volume       Do not mount the nix volume (/nix)
      --no-mise-volume      Do not mount the mise volume (/opt/mise/data)
      --isolated-volumes    Use per-container volumes (\$OPS_CONTAINER_NAME-nix,
                            \$OPS_CONTAINER_NAME-mise) instead of the shared
                            ops-share-nix / ops-share-mise defaults
      --no-claude-mount     Do not bind-mount ~/.claude (only meaningful with
                            --no-mount-home)
      --no-gemini-mount     Do not bind-mount ~/.gemini (only meaningful with
                            --no-mount-home)
      --no-opencode-mount   Do not bind-mount ~/.local/share/opencode (only
                            meaningful with --no-mount-home)
      --no-codex-mount      Do not bind-mount ~/.codex (only meaningful with
                            --no-mount-home)
      --claude              Run claude (install if missing)
      --claude-mount        Bind-mount ~/.claude + ~/.claude.json (only
                            meaningful with --no-mount-home)
      --claude-volume       Use named Docker volume ops-claude for
                            ~/.claude (isolated from host — works with or
                            without --no-mount-home)
      --gemini              Run gemini (install if missing)
      --gemini-mount        Bind-mount ~/.gemini (only meaningful with
                            --no-mount-home)
      --gemini-volume       Use named Docker volume ops-gemini for ~/.gemini
      --opencode            Run opencode (install github:sst/opencode if missing)
      --opencode-mount      Bind-mount ~/.local/share/opencode + ~/.config/opencode
                            (only meaningful with --no-mount-home)
      --opencode-volume     Use named Docker volume ops-opencode for
                            ~/.local/share/opencode
      --codex               Run codex (install @openai/codex if missing)
      --codex-mount         Bind-mount ~/.codex (only meaningful with
                            --no-mount-home)
      --codex-volume        Use named Docker volume ops-codex for ~/.codex
  -h, --help                Show this help

  Auto-propagated host env vars (when set): ANTHROPIC_API_KEY,
  OPENAI_API_KEY, GEMINI_API_KEY, GITHUB_TOKEN.

  Behavior:
    - Container running      → exec into it
    - Container stopped      → restart it
    - Container missing      → create it (auto-build if image absent)
    - No COMMAND             → start bash

$(basename "$0") runtime COMMAND [ARGS...]
  Proxy directly to the runtime binary (currently: $OPS_RUNTIME).
  Example: $(basename "$0") runtime ps -a
           $(basename "$0") runtime rm -f ops-dev
EOF
}

# Whitelist the destination of install/uninstall rm -rf operations.
# Refuses any path outside $HOME/.local, $HOME/.cache, /opt/ops, /tmp, or
# /var/tmp. Prevents an OPS_NERDCTL_HOME=/ or =/usr accident from
# destroying the host when install/uninstall blindly rm -rf the target.
# Usage: _assert_safe_install_path <path> <verb>    (verb = install|uninstall)
_assert_safe_install_path() {
    local path="$1" verb="${2:-operate on}"
    local abs home_abs
    abs="$(realpath -m "$path" 2>/dev/null || echo "$path")"
    home_abs="$(realpath -m "$HOME" 2>/dev/null || echo "$HOME")"
    case "$abs" in
        "$home_abs"/.local/*|"$home_abs"/.cache/*|/opt/ops/*|/tmp/*|/var/tmp/*) ;;
        *)
            echo "Refusing to $verb '$abs' — outside \$HOME/.local, \$HOME/.cache, /opt/ops, or /tmp." >&2
            echo "Set OPS_NERDCTL_HOME to a safe path (default: ~/.local/share/ops/nerdctl)." >&2
            return 1
            ;;
    esac
}

cmd_install() {
    local install_dir="$OPS_NERDCTL_HOME"

    local missing=() cmd
    for cmd in curl tar sha256sum systemctl uname mktemp awk; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo "Missing required commands: ${missing[*]}" >&2; exit 1
    fi

    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        *) echo "Unsupported architecture: $arch" >&2; exit 1 ;;
    esac

    echo "Fetching latest nerdctl release..."
    local version
    version="$(curl -fsSL https://api.github.com/repos/containerd/nerdctl/releases/latest | grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/')"
    if [ -z "$version" ]; then
        echo "Failed to fetch version from GitHub (rate-limited or offline?)." >&2; exit 1
    fi
    echo "Version: $version"

    local tarball="nerdctl-full-${version}-linux-${arch}.tar.gz"
    local base_url="https://github.com/containerd/nerdctl/releases/download/v${version}"
    TMP_INSTALL_DIR="$(mktemp -d)"

    echo "Downloading $tarball..."
    curl -fsSL "$base_url/$tarball" -o "$TMP_INSTALL_DIR/$tarball"

    echo "Verifying checksum..."
    curl -fsSL "$base_url/SHA256SUMS" -o "$TMP_INSTALL_DIR/SHA256SUMS"
    local expected_line
    expected_line=$(awk -v f="$tarball" '$2==f' "$TMP_INSTALL_DIR/SHA256SUMS")
    if [ -z "$expected_line" ]; then
        echo "Error: $tarball not listed in SHA256SUMS" >&2; exit 1
    fi
    if ! ( cd "$TMP_INSTALL_DIR" && echo "$expected_line" | sha256sum -c - ); then
        echo "Checksum verification failed for $tarball" >&2; exit 1
    fi

    # Safety: refuse to rm -rf anything that isn't clearly under $HOME/.local
    # or an explicit ops-owned path. Prevents an OPS_NERDCTL_HOME=/ or
    # =/usr accident from destroying the host.
    _assert_safe_install_path "$install_dir" install || exit 1

    if [ -d "$install_dir" ] && [ -n "$(ls -A "$install_dir" 2>/dev/null)" ]; then
        printf "Directory %s is not empty. Overwrite? [Y/n] " "$install_dir"
        read -r answer
        if [[ "$answer" =~ ^[nN]$ ]]; then
            echo "Aborted."; exit 1
        fi
        rm -rf "$install_dir"
    fi
    mkdir -p "$install_dir"

    echo "Installing into $install_dir..."
    if ! tar -xzf "$TMP_INSTALL_DIR/$tarball" -C "$install_dir"; then
        echo "Extraction failed." >&2; exit 1
    fi

    echo "Configuring rootless containerd service..."
    export PATH="/usr/bin:$install_dir/bin:$PATH"
    "$install_dir/bin/containerd-rootless-setuptool.sh" install
    systemctl --user disable containerd.service
    echo "Service installed and disabled at boot."
    echo "To start: systemctl --user start containerd.service"
}

cmd_uninstall() {
    local install_dir="$OPS_NERDCTL_HOME"
    local containerd_data="$HOME/.local/share/containerd"
    local unit_file="$HOME/.config/systemd/user/containerd.service"

    # Validate BEFORE touching anything: OPS_NERDCTL_HOME is user-controlled
    # (env / -H flag) and the removals below are rm -rf — refuse unsafe paths.
    _assert_safe_install_path "$install_dir" uninstall || exit 1

    echo "Stopping and disabling containerd service..."
    systemctl --user stop containerd.service 2>/dev/null || true
    systemctl --user disable containerd.service 2>/dev/null || true
    rm -f "$unit_file"
    systemctl --user daemon-reload

    printf "Remove binaries (%s)? [Y/n] " "$install_dir"
    read -r answer
    if [[ ! "$answer" =~ ^[nN]$ ]]; then
        rm -rf "$install_dir"
        echo "Binaries removed."
    fi

    printf "Remove containerd data (images, containers, snapshots) (%s)? [Y/n] " "$containerd_data"
    read -r answer
    if [[ ! "$answer" =~ ^[nN]$ ]]; then
        rm -rf "$containerd_data"
        echo "Data removed."
    fi

    echo "Uninstall complete."
}

cmd_runtime() {
    exec "$RUNTIME_BIN" "$@"
}

# Prints the mounts of a single container (indented).
_print_mounts() {
    local ctn="$1"
    local mounts
    mounts=$("$RUNTIME_BIN" container inspect "$ctn" \
        --format '{{range .Mounts}}{{.Type}}|{{if eq .Type "volume"}}{{.Name}}{{else}}{{.Source}}{{end}}|{{.Destination}}
{{end}}' 2>/dev/null || true)
    if [ -z "$(echo "$mounts" | tr -d '[:space:]')" ]; then
        echo "    (no mounts)"
        return
    fi
    while IFS='|' read -r m_type m_src m_dst; do
        [ -z "$m_type" ] && continue
        printf '    %-7s %-48s → %s\n' "$m_type" "$m_src" "$m_dst"
    done <<< "$mounts"
}

# Humanize a byte count to IEC units (KiB/MiB/GiB/...) with one decimal.
# Pure bash — no numfmt dependency. Uses *10 trick for the decimal digit.
_human_bytes() {
    local bytes="${1:-0}"
    local units=(B KiB MiB GiB TiB PiB)
    local i=0 div=1
    while [ "$bytes" -ge $((div * 1024)) ] && [ $i -lt 5 ]; do
        div=$((div * 1024)); i=$((i+1))
    done
    if [ $i -eq 0 ]; then
        echo "${bytes}B"
    else
        local tenths=$(( (bytes * 10) / div ))
        printf '%d.%d%s\n' "$((tenths / 10))" "$((tenths % 10))" "${units[$i]}"
    fi
}

cmd_status() {
    # --- Services (top: runtime + daemons) ---
    echo -e "\033[1;34m=== Services ===\033[0m"
    if [ -f "$_CONFIG_FILE" ]; then
        echo -e "config:             $_CONFIG_FILE \033[32m(loaded)\033[0m"
    else
        echo -e "config:             $_CONFIG_FILE \033[33m(missing)\033[0m"
    fi
    echo "runtime:            $OPS_RUNTIME ($RUNTIME_BIN)"
    if [ "$OPS_RUNTIME" = "nerdctl" ]; then
        if systemctl --user is-active containerd.service >/dev/null 2>&1; then
            echo "containerd.service: active"
        else
            echo "containerd.service: inactive"
        fi
        local sock="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/buildkit/buildkitd.sock"
        if "$OPS_NERDCTL_HOME/bin/buildctl" --addr "unix://$sock" debug workers >/dev/null 2>&1; then
            echo "buildkitd:          active"
        else
            echo "buildkitd:          inactive"
        fi
    fi
    echo ""

    # --- Compute the set of "ops" image refs (default + all OPS_IMAGES) ---
    local -a ops_image_refs=("$OPS_IMAGE")
    local -A ops_image_seen=(["$OPS_IMAGE"]=1)
    local -A ops_image_keys=()
    local k ref
    if declare -p OPS_IMAGES >/dev/null 2>&1; then
        for k in "${!OPS_IMAGES[@]}"; do
            ref="${OPS_IMAGES[$k]}"
            ops_image_keys[$ref]="$k"
            if [ -z "${ops_image_seen[$ref]:-}" ]; then
                ops_image_refs+=("$ref")
                ops_image_seen[$ref]=1
            fi
        done
    fi
    # Discover images labeled ops.dockerfile (built by ops.sh, not in OPS_IMAGES)
    while IFS= read -r ref; do
        [ -z "$ref" ] && continue
        ref="${ref%:latest}"
        if [ -z "${ops_image_seen[$ref]:-}" ]; then
            ops_image_refs+=("$ref")
            ops_image_seen[$ref]=1
        fi
    done < <("$RUNTIME_BIN" image ls --filter "label=ops.dockerfile" --format '{{.Repository}}:{{.Tag}}' 2>/dev/null || true)

    # --- Images (default + declared + labeled) ---
    echo -e "\033[1;34m=== Images ===\033[0m"
    local info size created human_size label tags df_label
    for ref in "${ops_image_refs[@]}"; do
        info=$("$RUNTIME_BIN" image inspect "$ref" --format '{{.Size}}|{{.Created}}|{{if .Config.Labels}}{{index .Config.Labels "ops.dockerfile"}}{{end}}' 2>/dev/null || true)
        tags=""
        [ "$ref" = "$OPS_IMAGE" ] && tags="default"
        if [ -n "${ops_image_keys[$ref]:-}" ]; then
            [ -n "$tags" ] && tags="$tags,${ops_image_keys[$ref]}" || tags="${ops_image_keys[$ref]}"
        fi
        if [ -n "$info" ]; then
            IFS='|' read -r size created df_label <<< "$info"
            created="${created%%T*}"
            [ -z "$tags" ] && [ -n "$df_label" ] && tags="$(basename "$df_label")"
            label="($tags)"
            human_size=$(_human_bytes "$size")
            printf '  \033[32m✓\033[0m %-30s %-20s %10s  %s\n' "$ref" "$label" "$human_size" "$created"
        else
            label="($tags)"
            printf '  \033[31m✗\033[0m %-30s %-20s %10s  \033[33m%s\033[0m\n' "$ref" "$label" "---" "(not built)"
        fi
    done

    # --- Collect ops containers (match by ops image OR by ops.container label) ---
    local -A ops_ctn_labeled=()
    while IFS= read -r name; do
        [ -n "$name" ] && ops_ctn_labeled[$name]=1
    done < <("$RUNTIME_BIN" ps -a --filter "label=ops.container=true" --format '{{.Names}}' 2>/dev/null || true)

    local ops_containers="" img state cmd match
    local -a ctn_lines=()
    while IFS='|' read -r name img state cmd; do
        [ -z "$name" ] && continue
        match=0
        for ref in "${ops_image_refs[@]}"; do
            [ "$img" = "$ref" ] && { match=1; break; }
        done
        [ "$match" = 0 ] && [ -n "${ops_ctn_labeled[$name]:-}" ] && match=1
        if [ "$match" = 1 ]; then
            ops_containers+="$name "
            ctn_lines+=("$name|$img|$state|$cmd")
        fi
    done < <("$RUNTIME_BIN" ps -a --no-trunc --format '{{.Names}}|{{.Image}}|{{.Status}}|{{.Command}}' 2>/dev/null || true)

    # --- Volumes (labeled ops.volume=true) ---
    echo -e "\n\033[1;34m=== Volumes ===\033[0m"
    local vol_names mp ctn users
    vol_names=$("$RUNTIME_BIN" volume ls --filter "label=ops.volume=true" --format '{{.Name}}' 2>/dev/null || true)
    if [ -z "$vol_names" ]; then
        echo "  (none)"
    else
        while IFS= read -r v; do
            [ -z "$v" ] && continue
            mp=$("$RUNTIME_BIN" volume inspect "$v" --format '{{.Mountpoint}}' 2>/dev/null || echo "?")
            users=""
            for ctn in $ops_containers; do
                if "$RUNTIME_BIN" container inspect "$ctn" \
                    --format '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}} {{end}}{{end}}' 2>/dev/null \
                    | tr ' ' '\n' | grep -qx "$v"; then
                    users+="$ctn, "
                fi
            done
            users="${users%, }"
            if [ -n "$users" ]; then
                printf '  \033[32m✓\033[0m %-24s %s  \033[32m(used by: %s)\033[0m\n' "$v" "$mp" "$users"
            else
                printf '    %-24s %s  \033[33m(unused)\033[0m\n' "$v" "$mp"
            fi
        done <<< "$vol_names"
    fi

    # --- Containers (displayed after volumes, using collected lines) ---
    echo -e "\n\033[1;34m=== Containers ===\033[0m"
    if [ ${#ctn_lines[@]} -eq 0 ]; then
        echo "  (no ops containers)"
    else
        local line first=1 cli_user cli_real state_color marker orphan_suffix
        for line in "${ctn_lines[@]}"; do
            [ "$first" = 0 ] && echo ""
            first=0
            IFS='|' read -r name img state cmd <<< "$line"
            case "$state" in
                Up*)                state_color='\033[32m' ;;  # green
                Exited*|Dead*)      state_color='\033[31m' ;;  # red
                Created*|Restart*)  state_color='\033[33m' ;;  # yellow
                Paused*)            state_color='\033[34m' ;;  # blue
                *)                  state_color='\033[2m'  ;;  # dim fallback
            esac
            # Orphan = container references an image that no longer exists
            if "$RUNTIME_BIN" image inspect "$img" >/dev/null 2>&1; then
                marker="  "
                orphan_suffix=""
            else
                marker='\033[33m⚠\033[0m '
                orphan_suffix=' \033[33m(image missing)\033[0m'
            fi
            printf "$marker"'\033[1;32m%-20s\033[0m \033[34m%s\033[0m  '"$state_color"'(%s)\033[0m'"$orphan_suffix"'\n' "$name" "$img" "$state"
            printf '    \033[2mcmd:\033[0m      %s\n' "$cmd"
            cli_user=$("$RUNTIME_BIN" container inspect "$name" --format '{{if .Config.Labels}}{{index .Config.Labels "ops.cmdline.user"}}{{end}}' 2>/dev/null || true)
            cli_real=$("$RUNTIME_BIN" container inspect "$name" --format '{{if .Config.Labels}}{{index .Config.Labels "ops.cmdline.real"}}{{end}}' 2>/dev/null || true)
            [ -n "$cli_user" ] && printf '    \033[2mops cli:\033[0m  %s\n' "$cli_user"
            [ -n "$cli_real" ] && printf '    \033[2mreal cli:\033[0m %s\n' "$cli_real"
            _print_mounts "$name"
        done
    fi

}

cmd_logs() {
    # First non-flag arg = container name override. Otherwise fall back to OPS_CONTAINER_NAME.
    local target="$OPS_CONTAINER_NAME"
    local -a passthrough=()
    local seen_target=0 strip=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --strip|-s)                 strip=1; shift ;;
            --tail|-n|--since|--until)  passthrough+=("$1" "$2"); shift 2 ;;
            -*)                         passthrough+=("$1"); shift ;;
            *)  if [ "$seen_target" = 0 ]; then
                    target="$1"; seen_target=1
                else
                    passthrough+=("$1")
                fi
                shift ;;
        esac
    done
    if ! "$RUNTIME_BIN" ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$target"; then
        echo "Container '$target' does not exist." >&2; exit 1
    fi
    if [ "$strip" = 1 ]; then
        # Strip CSI (\e[...) and OSC (\e]...\a) escapes emitted by TUI programs.
        # Cursor-forward (\e[nC) is replaced by a single space so word boundaries
        # survive — TUIs often use it in place of explicit spaces.
        "$RUNTIME_BIN" logs "${passthrough[@]}" "$target" 2>&1 \
            | sed -E $'s/\x1b\\[[0-9]+C/ /g; s/\x1b\\[[0-9;?]*[a-zA-Z]//g; s/\x1b\\][^\x07]*\x07//g'
    else
        exec "$RUNTIME_BIN" logs "${passthrough[@]}" "$target"
    fi
}

cmd_clean() {
    local dry=0
    [ "${1:-}" = "--dry-run" ] && { dry=1; shift; }

    echo -e "\033[1;34m=== Dangling images ===\033[0m"
    local img_id img_size df_label label_suffix count_img=0
    while IFS='|' read -r img_id img_size; do
        [ -z "$img_id" ] && continue
        df_label=$("$RUNTIME_BIN" image inspect "$img_id" --format '{{if .Config.Labels}}{{index .Config.Labels "ops.dockerfile"}}{{end}}' 2>/dev/null || true)
        if [ -n "$df_label" ]; then
            label_suffix=" \033[2m($(basename "$df_label"))\033[0m"
        else
            label_suffix=""
        fi
        printf '  \033[31m✗\033[0m  %-14s  %-10s%b\n' "${img_id:0:12}" "$img_size" "$label_suffix"
        count_img=$((count_img+1))
    done < <("$RUNTIME_BIN" image ls -f dangling=true --format '{{.ID}}|{{.Size}}' 2>/dev/null || true)
    [ "$count_img" = 0 ] && echo "  (none)"

    echo -e "\n\033[1;34m=== Stopped ops containers (label=ops.container=true) ===\033[0m"
    local ctn_id ctn_name count_ctn=0
    while IFS='|' read -r ctn_id ctn_name; do
        [ -z "$ctn_id" ] && continue
        printf '  \033[31m✗\033[0m  %-14s  %s\n' "${ctn_id:0:12}" "$ctn_name"
        count_ctn=$((count_ctn+1))
    done < <("$RUNTIME_BIN" ps -a -f status=exited -f label=ops.container=true --format '{{.ID}}|{{.Names}}' 2>/dev/null || true)
    [ "$count_ctn" = 0 ] && echo "  (none)"

    echo -e "\n\033[1;34m=== ops volumes (label=ops.volume=true) ===\033[0m"
    local vol_name vol_mp count_vol=0
    while IFS='|' read -r vol_name vol_mp; do
        [ -z "$vol_name" ] && continue
        printf '  \033[31m✗\033[0m  %-24s  \033[2m%s\033[0m\n' "$vol_name" "$vol_mp"
        count_vol=$((count_vol+1))
    done < <("$RUNTIME_BIN" volume ls --filter label=ops.volume=true --format '{{.Name}}|{{.Mountpoint}}' 2>/dev/null || true)
    [ "$count_vol" = 0 ] && echo "  (none)"

    echo -e "\n\033[1;34m=== Summary ===\033[0m"
    printf '  dangling images:  %d\n' "$count_img"
    printf '  stopped ops containers: %d\n' "$count_ctn"
    printf '  ops volumes:      %d\n' "$count_vol"

    if [ "$dry" = 1 ]; then
        echo -e "\n\033[33m(dry-run — nothing removed)\033[0m"
        return 0
    fi

    printf "\nPrune dangling images and stopped ops containers? [y/N] "
    read -r answer
    if [[ "$answer" =~ ^[yY]$ ]]; then
        "$RUNTIME_BIN" image prune -f >/dev/null 2>&1 || true
        "$RUNTIME_BIN" ps -a -f status=exited -f label=ops.container=true --format '{{.ID}}' 2>/dev/null \
            | xargs -r "$RUNTIME_BIN" rm >/dev/null 2>&1 || true
        echo "Pruned."
    fi

    printf "Remove ops volumes? This deletes cached data (nix store, mise tools, ...) [y/N] "
    read -r answer
    if [[ "$answer" =~ ^[yY]$ ]]; then
        "$RUNTIME_BIN" volume ls --filter label=ops.volume=true --format '{{.Name}}' 2>/dev/null \
            | xargs -r "$RUNTIME_BIN" volume rm >/dev/null 2>&1 || true
        echo "Volumes removed."
    fi
}

cmd_config() {
    echo -e "\033[1;34m=== Config file ===\033[0m"
    if [ -f "$_CONFIG_FILE" ]; then
        echo -e "  $_CONFIG_FILE \033[32m(loaded)\033[0m"
    else
        echo -e "  $_CONFIG_FILE \033[33m(missing)\033[0m"
    fi

    # Mark any OPS_* var currently set that wasn't env or config as default.
    local v
    for v in $(compgen -v 2>/dev/null | grep '^OPS_' || true); do
        [ -z "${_OPS_ORIGIN[$v]:-}" ] && _OPS_ORIGIN[$v]=default
    done

    echo -e "\n\033[1;34m=== Scalars ===\033[0m"
    local origin val color
    for v in $(compgen -v 2>/dev/null | grep '^OPS_' | sort); do
        # Skip arrays — they get their own section below
        if declare -p "$v" 2>/dev/null | grep -qE '^declare -[aA]'; then
            continue
        fi
        origin="${_OPS_ORIGIN[$v]:-?}"
        val="${!v}"
        case "$origin" in
            env)     color='\033[36m' ;;  # cyan
            config)  color='\033[32m' ;;  # green
            default) color='\033[2m'  ;;  # dim
            *)       color='\033[33m' ;;  # yellow
        esac
        printf '  %-32s = %-40s '"$color"'[%s]\033[0m\n' "$v" "$val" "$origin"
    done

    echo -e "\n\033[1;34m=== Arrays ===\033[0m"
    local any_array=0
    for v in OPS_IMAGES OPS_DOCKERFILES OPS_CONTAINER_NAMES OPS_ALIASES OPS_VOLUMES; do
        if declare -p "$v" >/dev/null 2>&1; then
            any_array=1
            origin="${_OPS_ORIGIN[$v]:-config}"
            case "$origin" in
                env)     color='\033[36m' ;;
                config)  color='\033[32m' ;;
                default) color='\033[2m'  ;;
                *)       color='\033[33m' ;;
            esac
            printf '\n  \033[1;36m%s\033[0m '"$color"'[%s]\033[0m\n' "$v" "$origin"
            if declare -p "$v" 2>/dev/null | grep -qE '^declare -[aA]'; then
                # Associative / indexed array — iterate
                local -n _ref="$v"
                local k
                for k in "${!_ref[@]}"; do
                    printf '    %-20s = %s\n' "$k" "${_ref[$k]}"
                done
                unset -n _ref
            else
                # scalar OPS_VOLUMES (space-separated string)
                printf '    %s\n' "${!v}"
            fi
        fi
    done
    [ "$any_array" = 0 ] && echo "  (none)"
    return 0
}

cmd_inspect() {
    local key="${1:-}"
    if [ -z "$key" ]; then
        echo "Usage: $(basename "$0") inspect <key|container|image-ref>" >&2
        exit 1
    fi

    local resolved_img="" resolved_ctn="" resolved_key=""

    if declare -p OPS_IMAGES >/dev/null 2>&1 && [ -n "${OPS_IMAGES[$key]:-}" ]; then
        resolved_key="$key"
        resolved_img="${OPS_IMAGES[$key]}"
        if declare -p OPS_CONTAINER_NAMES >/dev/null 2>&1 && [ -n "${OPS_CONTAINER_NAMES[$key]:-}" ]; then
            resolved_ctn="${OPS_CONTAINER_NAMES[$key]}"
        else
            resolved_ctn="$key"
        fi
    elif "$RUNTIME_BIN" container inspect "$key" >/dev/null 2>&1; then
        resolved_ctn="$key"
        resolved_img=$("$RUNTIME_BIN" container inspect "$key" --format '{{.Config.Image}}' 2>/dev/null)
    elif "$RUNTIME_BIN" image inspect "$key" >/dev/null 2>&1; then
        resolved_img="$key"
    else
        echo "Error: '$key' not found as OPS_IMAGES key, container, or image" >&2
        exit 1
    fi

    # --- Image section ---
    if [ -n "$resolved_img" ]; then
        echo -e "\033[1;34m=== Image ===\033[0m"
        printf '  ref:        %s\n' "$resolved_img"
        [ -n "$resolved_key" ] && printf '  ops key:    %s\n' "$resolved_key"
        local info size created df_label
        info=$("$RUNTIME_BIN" image inspect "$resolved_img" --format '{{.Size}}|{{.Created}}|{{if .Config.Labels}}{{index .Config.Labels "ops.dockerfile"}}{{end}}' 2>/dev/null || true)
        if [ -n "$info" ]; then
            IFS='|' read -r size created df_label <<< "$info"
            created="${created%%T*}"
            printf '  size:       %s\n' "$(_human_bytes "$size")"
            printf '  created:    %s\n' "$created"
            [ -n "$df_label" ] && printf '  dockerfile: %s\n' "$df_label"
        else
            echo -e "  \033[33m(image not built)\033[0m"
        fi
    fi

    # --- Container section (if the resolved container exists) ---
    if [ -n "$resolved_ctn" ] && "$RUNTIME_BIN" container inspect "$resolved_ctn" >/dev/null 2>&1; then
        echo -e "\n\033[1;34m=== Container ===\033[0m"
        local c_img c_state c_cmd c_cli_user c_cli_real state_color
        c_img=$("$RUNTIME_BIN" container inspect "$resolved_ctn" --format '{{.Config.Image}}' 2>/dev/null)
        c_state=$("$RUNTIME_BIN" ps -a --filter "name=^${resolved_ctn}$" --format '{{.Status}}' 2>/dev/null)
        c_cmd=$("$RUNTIME_BIN" ps -a --no-trunc --filter "name=^${resolved_ctn}$" --format '{{.Command}}' 2>/dev/null)
        case "$c_state" in
            Up*)                state_color='\033[32m' ;;
            Exited*|Dead*)      state_color='\033[31m' ;;
            Created*|Restart*)  state_color='\033[33m' ;;
            Paused*)            state_color='\033[34m' ;;
            *)                  state_color='\033[2m'  ;;
        esac
        printf '  name:       \033[1;32m%s\033[0m\n' "$resolved_ctn"
        printf '  image:      \033[34m%s\033[0m\n' "$c_img"
        printf '  state:      '"$state_color"'%s\033[0m\n' "$c_state"
        printf '  cmd:        %s\n' "$c_cmd"
        c_cli_user=$("$RUNTIME_BIN" container inspect "$resolved_ctn" --format '{{if .Config.Labels}}{{index .Config.Labels "ops.cmdline.user"}}{{end}}' 2>/dev/null || true)
        c_cli_real=$("$RUNTIME_BIN" container inspect "$resolved_ctn" --format '{{if .Config.Labels}}{{index .Config.Labels "ops.cmdline.real"}}{{end}}' 2>/dev/null || true)
        [ -n "$c_cli_user" ] && printf '  ops cli:    %s\n' "$c_cli_user"
        [ -n "$c_cli_real" ] && printf '  real cli:   %s\n' "$c_cli_real"
        echo -e "\n\033[1;34m=== Mounts ===\033[0m"
        _print_mounts "$resolved_ctn"
    elif [ -n "$resolved_ctn" ]; then
        echo -e "\n\033[1;34m=== Container ===\033[0m"
        printf '  name:       %s \033[2m(not created)\033[0m\n' "$resolved_ctn"
    fi
}

# Shared post-build cleanup: compares the new image ID to the one captured
# before the build, lists every container still running on the old ID with
# its `ops.cmdline.user` label as a relaunch hint, and offers a [y/N] prompt
# to remove them. Used by both `build` and `update` so the two subcommands
# share the same lifecycle semantics.
_post_build_prompt() {
    local old_id="$1"
    local new_id
    new_id=$("$RUNTIME_BIN" image inspect "$OPS_IMAGE" --format '{{.Id}}' 2>/dev/null || true)

    if [ -z "$old_id" ]; then
        echo -e "\n\033[32mImage built fresh — no old containers to recreate.\033[0m"
        return 0
    fi
    if [ "$old_id" = "$new_id" ]; then
        echo -e "\n\033[32mImage unchanged (cache hit) — nothing to do.\033[0m"
        return 0
    fi

    echo -e "\n\033[1;34m=== Containers on the previous image ===\033[0m"
    local ctn img_id cli_user found=0
    local -a to_remove=()
    while IFS='|' read -r ctn img_id; do
        [ -z "$ctn" ] && continue
        if [ "$img_id" = "$old_id" ]; then
            found=1
            cli_user=$("$RUNTIME_BIN" container inspect "$ctn" --format '{{if .Config.Labels}}{{index .Config.Labels "ops.cmdline.user"}}{{end}}' 2>/dev/null || true)
            printf '  \033[1;36m%s\033[0m\n' "$ctn"
            [ -n "$cli_user" ] && printf '    relaunch: \033[2m%s\033[0m\n' "$cli_user"
            to_remove+=("$ctn")
        fi
    done < <("$RUNTIME_BIN" ps -a --format '{{.Names}}|{{.ImageID}}' 2>/dev/null || true)

    if [ "$found" = 0 ]; then
        echo "  (none)"
        return 0
    fi

    printf "\nRemove these containers? They'll need to be relaunched manually (see 'relaunch:' hints). [y/N] "
    read -r answer
    if [[ "$answer" =~ ^[yY]$ ]]; then
        for ctn in "${to_remove[@]}"; do
            "$RUNTIME_BIN" rm -f "$ctn" >/dev/null && echo "  removed $ctn"
        done
    fi
}

cmd_update() {
    local key="${1:-}"
    if [ -n "$key" ]; then
        _resolve_image "$key"
    fi

    local old_id
    old_id=$("$RUNTIME_BIN" image inspect "$OPS_IMAGE" --format '{{.Id}}' 2>/dev/null || true)

    echo -e "\033[1;34m=== Building $OPS_IMAGE ===\033[0m"
    build_image || exit $?
    _post_build_prompt "$old_id"
}

cmd_backup() {
    local vol="${1:-}"
    if [ -z "$vol" ]; then
        echo "Usage: $(basename "$0") backup <volume-name> > backup.tar.gz" >&2
        exit 1
    fi
    if ! "$RUNTIME_BIN" volume inspect "$vol" >/dev/null 2>&1; then
        echo "Volume '$vol' not found." >&2; exit 1
    fi
    # Refuse to stream a binary payload to a TTY — almost certainly a mistake
    # (user forgot the `> file` redirect). Allow with OPS_FORCE_TTY=1 for kicks.
    if [ -t 1 ] && [ "${OPS_FORCE_TTY:-0}" != "1" ]; then
        echo "Refusing to write tar.gz to a terminal. Redirect stdout:" >&2
        echo "    $(basename "$0") backup $vol > backup-$vol.tar.gz" >&2
        echo "(set OPS_FORCE_TTY=1 to override)" >&2
        exit 1
    fi
    echo "Backing up volume '$vol' → stdout (tar.gz)..." >&2
    "$RUNTIME_BIN" run --rm -v "$vol:/data:ro" --user 0 alpine tar -czf - -C /data .
}

cmd_restore() {
    local vol="${1:-}"
    if [ -z "$vol" ]; then
        echo "Usage: $(basename "$0") restore <volume-name> < backup.tar.gz" >&2
        exit 1
    fi
    if [ -t 0 ]; then
        echo "Refusing to read tar.gz from a terminal. Redirect stdin:" >&2
        echo "    $(basename "$0") restore $vol < backup-$vol.tar.gz" >&2
        exit 1
    fi
    ensure_volume "$vol"
    echo "Restoring volume '$vol' ← stdin (tar.gz)..." >&2
    "$RUNTIME_BIN" run --rm -i -v "$vol:/data" --user 0 alpine tar -xzf - -C /data
}

cmd_doctor() {
    local ok=0 warn=0 k ref declared_df labeled_df declared_abs
    _doc_ok()   { printf '    \033[32m✓\033[0m %s\n' "$1"; ok=$((ok+1)); }
    _doc_warn() { printf '    \033[33m⚠\033[0m %s\n' "$1"; warn=$((warn+1)); }

    echo -e "\033[1;34m=== Config ===\033[0m"
    if [ -f "$_CONFIG_FILE" ]; then
        _doc_ok "config file: $_CONFIG_FILE"
    else
        _doc_warn "config file missing: $_CONFIG_FILE"
    fi

    echo -e "\n\033[1;34m=== OPS_IMAGES ===\033[0m"
    if declare -p OPS_IMAGES >/dev/null 2>&1 && [ ${#OPS_IMAGES[@]} -gt 0 ]; then
        for k in "${!OPS_IMAGES[@]}"; do
            ref="${OPS_IMAGES[$k]}"
            printf '\n  \033[1;36m%s\033[0m → %s\n' "$k" "$ref"
            if declare -p OPS_DOCKERFILES >/dev/null 2>&1 && [ -n "${OPS_DOCKERFILES[$k]:-}" ]; then
                declared_df="${OPS_DOCKERFILES[$k]}"
            elif [ -f "$SCRIPT_DIR/Dockerfile.$k" ]; then
                declared_df="$SCRIPT_DIR/Dockerfile.$k"
            else
                declared_df=""
            fi
            if [ -n "$declared_df" ] && [ -f "$declared_df" ]; then
                _doc_ok "dockerfile: $declared_df"
            elif [ -n "$declared_df" ]; then
                _doc_warn "dockerfile not found: $declared_df"
            else
                _doc_warn "no dockerfile resolved (set OPS_DOCKERFILES[$k] or create Dockerfile.$k)"
            fi
            if "$RUNTIME_BIN" image inspect "$ref" >/dev/null 2>&1; then
                _doc_ok "image built: $ref"
                labeled_df=$("$RUNTIME_BIN" image inspect "$ref" --format '{{if .Config.Labels}}{{index .Config.Labels "ops.dockerfile"}}{{end}}' 2>/dev/null || true)
                if [ -n "$declared_df" ] && [ -n "$labeled_df" ]; then
                    declared_abs="$(realpath "$declared_df" 2>/dev/null || echo "$declared_df")"
                    if [ "$declared_abs" = "$labeled_df" ]; then
                        _doc_ok "label ops.dockerfile matches"
                    else
                        _doc_warn "label mismatch: config=$declared_abs image=$labeled_df"
                    fi
                elif [ -z "$labeled_df" ]; then
                    _doc_warn "image has no ops.dockerfile label (rebuild to stamp it)"
                fi
            else
                _doc_warn "image not built: $ref (run: $(basename "$0") -i $k build)"
            fi
        done
    else
        echo "  (none defined)"
    fi

    echo -e "\n\033[1;34m=== Dangling config entries ===\033[0m"
    local dangling=0
    if declare -p OPS_DOCKERFILES >/dev/null 2>&1; then
        for k in "${!OPS_DOCKERFILES[@]}"; do
            if [ -z "${OPS_IMAGES[$k]:-}" ]; then
                _doc_warn "OPS_DOCKERFILES[$k] set but no OPS_IMAGES[$k]"
                dangling=1
            fi
        done
    fi
    if declare -p OPS_CONTAINER_NAMES >/dev/null 2>&1; then
        for k in "${!OPS_CONTAINER_NAMES[@]}"; do
            if [ -z "${OPS_IMAGES[$k]:-}" ]; then
                _doc_warn "OPS_CONTAINER_NAMES[$k] set but no OPS_IMAGES[$k]"
                dangling=1
            fi
        done
    fi
    [ "$dangling" = 0 ] && echo "    (none)"

    echo -e "\n\033[1;34m=== Containers (label=ops.container=true) ===\033[0m"
    local any_ctn=0 ctn ctn_img expected_img
    while IFS='|' read -r ctn ctn_img; do
        [ -z "$ctn" ] && continue
        any_ctn=1
        # Orphan: the image referenced by the container no longer exists
        if ! "$RUNTIME_BIN" image inspect "$ctn_img" >/dev/null 2>&1; then
            _doc_warn "container '$ctn': image '$ctn_img' no longer exists (orphan)"
            continue
        fi
        # Image mismatch: container name matches an OPS_IMAGES key but runs
        # a different image than the one declared for that key.
        if declare -p OPS_IMAGES >/dev/null 2>&1 && [ -n "${OPS_IMAGES[$ctn]:-}" ]; then
            expected_img="${OPS_IMAGES[$ctn]}"
            if [ "$ctn_img" != "$expected_img" ]; then
                _doc_warn "container '$ctn' runs '$ctn_img' but OPS_IMAGES[$ctn]=$expected_img"
            else
                _doc_ok "container '$ctn' matches OPS_IMAGES[$ctn]"
            fi
        fi
    done < <("$RUNTIME_BIN" ps -a --filter "label=ops.container=true" --format '{{.Names}}|{{.Image}}' 2>/dev/null || true)
    [ "$any_ctn" = 0 ] && echo "    (no ops-labeled containers)"

    echo -e "\n\033[1;34m=== Summary ===\033[0m"
    printf "  \033[32m%d OK\033[0m  \033[33m%d warning(s)\033[0m\n" "$ok" "$warn"
    unset -f _doc_ok _doc_warn
    [ "$warn" -gt 0 ] && return 1 || return 0
}

cmd_self_update() {
    # Always operates on $OPS_NERDCTL_HOME/bin/nerdctl, regardless of OPS_RUNTIME —
    # the `nerdctl` namespace makes the intent explicit.
    local nerdctl_bin="$OPS_NERDCTL_HOME/bin/nerdctl"
    if [ ! -x "$nerdctl_bin" ]; then
        echo "nerdctl not installed at $nerdctl_bin. Run: $(basename "$0") nerdctl install" >&2; exit 1
    fi

    local missing=() cmd
    for cmd in curl awk; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo "Missing required commands: ${missing[*]}" >&2; exit 1
    fi

    local current_version
    current_version=$("$nerdctl_bin" --version 2>/dev/null | awk '{print $3}')
    if [ -z "$current_version" ]; then
        echo "Failed to read installed nerdctl version." >&2; exit 1
    fi
    echo "Installed: $current_version"

    echo "Fetching latest release..."
    local latest_version
    latest_version=$(curl -fsSL https://api.github.com/repos/containerd/nerdctl/releases/latest | grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/')
    if [ -z "$latest_version" ]; then
        echo "Failed to fetch latest version from GitHub (rate-limited or offline?)." >&2; exit 1
    fi
    echo "Latest:    $latest_version"

    if [ "$current_version" = "$latest_version" ]; then
        echo "Already up to date."
        return 0
    fi

    printf "Update nerdctl from %s to %s? [Y/n] " "$current_version" "$latest_version"
    read -r answer
    if [[ "$answer" =~ ^[nN]$ ]]; then
        echo "Aborted."; return 0
    fi

    if systemctl --user is-active containerd.service >/dev/null 2>&1; then
        echo "Stopping containerd service..."
        systemctl --user stop containerd.service || true
    fi

    cmd_install
}

_agent_cmd() {
    local bin="$1" pkg="$2"
    case "$pkg" in
        npm:*) echo "mise which $bin >/dev/null 2>&1 || { mise use -g node@lts; mise use -g $pkg; }; exec $bin \"\$@\"" ;;
        *)     echo "mise which $bin >/dev/null 2>&1 || mise use -g $pkg; exec $bin \"\$@\"" ;;
    esac
}

ensure_volume() {
    "$RUNTIME_BIN" --log-level error volume create --label ops.volume=true "$1" >/dev/null 2>&1 || true
}

# Adds host paths to extra_volumes as bind mounts, only if they exist.
# When the path is under the host's $HOME, the destination is remapped to
# the container's $HOME_IN_CTN — this matters only if OPS_USER_NAME differs
# from the invoking user.
# Relies on dynamic scoping: caller must have a local `extra_volumes` array.
_mount_if_exists() {
    local p dest
    for p in "$@"; do
        if [ -e "$p" ]; then
            dest="$p"
            [[ "$p" == "$HOME"* ]] && dest="$HOME_IN_CTN${p#"$HOME"}"
            extra_volumes+=("$p:$dest")
        fi
    done
}

cmd_run() {
    local extra_volumes=()
    local extra_envs=()
    # Propagate GITHUB_TOKEN if set on host: mise/nix use it to lift
    # GitHub API rate limits (60→5000 req/h) at runtime — same reason we bake
    # it into /etc/nix/nix.conf at build time.
    [ -n "${GITHUB_TOKEN:-}" ]      && extra_envs+=(--env "GITHUB_TOKEN=$GITHUB_TOKEN")
    # Auto-propagate agent API keys so the CLI agents (claude/gemini/codex)
    # can authenticate without an explicit --xxx-mount flag. Silent no-op
    # when unset on the host.
    [ -n "${ANTHROPIC_API_KEY:-}" ] && extra_envs+=(--env "ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY")
    [ -n "${OPENAI_API_KEY:-}" ]    && extra_envs+=(--env "OPENAI_API_KEY=$OPENAI_API_KEY")
    [ -n "${GEMINI_API_KEY:-}" ]    && extra_envs+=(--env "GEMINI_API_KEY=$GEMINI_API_KEY")
    local extra_ports=()
    local build_extra_args=()
    local do_build=""
    local ephemeral=1
    local agent_cmd=""
    local dry_run=0
    # Defaults: bind-mount host $HOME into the container AND mount the
    # shared mise/nix volumes. Agent config directories (~/.claude, ~/.gemini,
    # ~/.local/share/opencode, ~/.codex) are reachable transitively via the
    # $HOME bind-mount — no explicit bind-mount or named volume needed.
    # Per-agent state (claude_agent/gemini_agent/...) controls the override:
    # --no-mount-home → explicit bind-mount, --$agent-volume → named volume.
    local mount_home=1
    local mount_volume=1
    local use_nix_volume=1
    local use_mise_volume=1
    # Per-agent tri-state: "auto" | "mount" | "volume" | "off".
    #   auto   — visible via $HOME bind-mount (mount_home=1), or auto
    #            bind-mount of ~/.${agent} if it exists (mount_home=0)
    #   mount  — explicit bind-mount from host (--${agent}-mount)
    #   volume — named Docker volume ops-${agent} (--${agent}-volume)
    #   off    — disabled (--no-${agent}-mount)
    local claude_agent="auto"
    local gemini_agent="auto"
    local opencode_agent="auto"
    local codex_agent="auto"
    # Shared by default (one nix store / mise data dir for all containers).
    # --isolated-volumes switches to per-container volumes
    # ($OPS_CONTAINER_NAME-nix, $OPS_CONTAINER_NAME-mise).
    local isolated_volumes=0

    while [ $# -gt 0 ]; do
        case "$1" in
            --no-mount-home)      mount_home=0;            shift ;;
            --no-mount-volume)    mount_volume=0;          shift ;;
            --no-nix-volume)      use_nix_volume=0;        shift ;;
            --no-mise-volume)     use_mise_volume=0;       shift ;;
            --no-claude-mount)    claude_agent="off";      shift ;;
            --no-gemini-mount)    gemini_agent="off";      shift ;;
            --no-opencode-mount)  opencode_agent="off";    shift ;;
            --no-codex-mount)     codex_agent="off";       shift ;;
            --claude-volume)      claude_agent="volume";   shift ;;
            --gemini-volume)      gemini_agent="volume";   shift ;;
            --opencode-volume)    opencode_agent="volume"; shift ;;
            --codex-volume)       codex_agent="volume";    shift ;;
            --isolated-volumes)   isolated_volumes=1;      shift ;;
            -i|--image)        _resolve_image "$2";                         shift 2 ;;
            -n|--name)         OPS_CONTAINER_NAME="$2"; _user_set_n=1;       shift 2 ;;
            -f|--dockerfile)   OPS_DOCKERFILE="$2"; _user_set_f=1;           shift 2 ;;
            -u|--uid)          OPS_USER_UID="$2";                           shift 2 ;;
            -g|--gid)          OPS_USER_GID="$2";                           shift 2 ;;
            -l|--lang)         OPS_USER_LANG="$2";                          shift 2 ;;
            -v|--volume)       extra_volumes+=("$2");                   shift 2 ;;
            -H|--nerdctl-home) OPS_NERDCTL_HOME="$(realpath "$2")";
                               export PATH="$OPS_NERDCTL_HOME/bin:$PATH";
                               _resolve_runtime;
                               [ "$OPS_RUNTIME" != "nerdctl" ] && echo "Warning: -H has no effect with OPS_RUNTIME=$OPS_RUNTIME" >&2
                               shift 2 ;;
            -b|--build)        do_build=1;                              shift ;;
            --no-cache)        build_extra_args+=(--no-cache);          shift ;;
            --no-rm)           ephemeral=0;                             shift ;;
            --nix-cleanup)     agent_cmd='HOME=/opt/nix-home /opt/nix-home/.nix-profile/bin/nix-collect-garbage -d'; shift ;;
            --update)          agent_cmd='
                echo -e "\033[1;34m==> mise self-update...\033[0m" && mise self-update --yes
                echo -e "\033[1;34m==> mise upgrade...\033[0m"     && mise upgrade --yes
                echo -e "\033[1;34m==> nix cleanup...\033[0m"      && HOME=/opt/nix-home /opt/nix-home/.nix-profile/bin/nix-collect-garbage -d
                echo -e "\033[1;32m==> done\033[0m"
            '; shift ;;
            --claude)          agent_cmd="$(_agent_cmd claude npm:@anthropic-ai/claude-code)"; shift ;;
            --claude-mount)    claude_agent="mount";   shift ;;
            --gemini)          agent_cmd="$(_agent_cmd gemini npm:@google/gemini-cli)"; shift ;;
            --gemini-mount)    gemini_agent="mount";   shift ;;
            --opencode)        agent_cmd="$(_agent_cmd opencode github:sst/opencode)"; shift ;;
            --opencode-mount)  opencode_agent="mount"; shift ;;
            --codex)           agent_cmd="$(_agent_cmd codex npm:@openai/codex)"; shift ;;
            --codex-mount)     codex_agent="mount";    shift ;;
            --dry-run)         dry_run=1; shift ;;
            --env-file)        extra_envs+=(--env-file "$2"); shift 2 ;;
            -e|--env)          extra_envs+=(--env "$2"); shift 2 ;;
            -p|--port)         extra_ports+=(--publish "$2"); shift 2 ;;
            -h|--help)         show_help; exit 0 ;;
            --)                shift; break ;;
            *)                 [[ "$1" == -* ]] && echo "Warning: unknown flag '$1' — passing as command" >&2
                               break ;;
        esac
    done

    [ -n "$agent_cmd" ] && set -- bash -c "$agent_cmd" _ "$@"

    # Compute --user AFTER flag parsing so -u/-g CLI overrides take effect.
    local user_arg
    if _is_rootless; then
        user_arg="0:$OPS_USER_GID"
    else
        user_arg="$OPS_USER_UID:$OPS_USER_GID"
    fi

    if [ ${#build_extra_args[@]} -gt 0 ] && [ -z "$do_build" ]; then
        echo "Error: --no-cache requires --build" >&2; exit 1
    fi

    if [ -n "$do_build" ]; then
        local old_id
        old_id=$("$RUNTIME_BIN" image inspect "$OPS_IMAGE" --format '{{.Id}}' 2>/dev/null || true)
        # Do NOT forward "$@" to build_image: anything after -- is the container
        # command, not a build flag, and would be appended after the context
        # path ("$@" "$SCRIPT_DIR"), breaking `docker build`.
        build_image "${build_extra_args[@]}"
        local ret=$?
        if [ $ret -eq 0 ]; then
            _post_build_prompt "$old_id"
        fi
        exit $ret
    fi

    if [ $# -eq 0 ]; then
        set -- bash
    fi

    if ! "$RUNTIME_BIN" images -q "$OPS_IMAGE" 2>/dev/null | grep -q .; then
        echo "Image $OPS_IMAGE not found, building..."
        # --if-missing: under the lock, skip if another process just built it.
        build_image --if-missing || exit $?
    elif dockerfile_changed; then
        echo -e "\033[31m⚠ Dockerfile changed since last build. Re-run with: $(basename "$0") build\033[0m"
    fi

    local exists running
    exists=$("$RUNTIME_BIN" ps -a --format '{{.Names}}' 2>/dev/null | grep -x "$OPS_CONTAINER_NAME" || true)
    running=$("$RUNTIME_BIN" ps --format '{{.Names}}' 2>/dev/null | grep -x "$OPS_CONTAINER_NAME" || true)

    if [ -z "$running" ] && [ -n "$exists" ]; then
        "$RUNTIME_BIN" start "$OPS_CONTAINER_NAME" >/dev/null 2>&1 || true
        running=$("$RUNTIME_BIN" ps --format '{{.Names}}' 2>/dev/null | grep -x "$OPS_CONTAINER_NAME" || true)
        if [ -z "$running" ]; then
            echo -e "\033[33mContainer '$OPS_CONTAINER_NAME' failed to start, removing and recreating...\033[0m"
            # -f tolerates a still-exiting container; || true guards against a
            # race where the container is already gone (daemon restart, etc.).
            "$RUNTIME_BIN" rm -f "$OPS_CONTAINER_NAME" >/dev/null 2>&1 || true
        fi
    fi

    if [ -n "$running" ]; then
        if [ ${#extra_volumes[@]} -gt 0 ]; then
            local mounted missing=()
            mounted=$("$RUNTIME_BIN" container inspect "$OPS_CONTAINER_NAME" --format '{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' 2>/dev/null)
            for v in "${extra_volumes[@]}"; do
                echo "$mounted" | grep -qF "$v" || missing+=("$v")
            done
            if [ ${#missing[@]} -gt 0 ]; then
                echo -e "\033[33m⚠ Container '$OPS_CONTAINER_NAME' is already running — the following volumes cannot be added:\033[0m" >&2
                for v in "${missing[@]}"; do echo -e "\033[33m    -v $v\033[0m" >&2; done
                echo -e "\033[33m  Tip: use -n <name> to create a separate container without removing this one.\033[0m" >&2
                printf "\033[33mRemove and recreate the container? \033[1m[Y/n]\033[0m " >&2
                read -r answer
                if [[ ! "$answer" =~ ^[nN]$ ]]; then
                    "$RUNTIME_BIN" rm -f "$OPS_CONTAINER_NAME" >/dev/null
                    running=""
                fi
            fi
        fi
        if [ -n "$running" ]; then
            if [ "$dry_run" = 1 ]; then
                printf '%q ' "$RUNTIME_BIN" exec -it --workdir "$PWD" --user "$user_arg" \
                    --env "HOME=$HOME_IN_CTN" \
                    --env "TERM=${TERM:-xterm-256color}" --env "COLORTERM=${COLORTERM:-truecolor}" \
                    "${extra_envs[@]}" "$OPS_CONTAINER_NAME" "$@"
                echo
                exit 0
            fi
            exec "$RUNTIME_BIN" exec -it --workdir "$PWD" --user "$user_arg" --env "HOME=$HOME_IN_CTN" --env "TERM=${TERM:-xterm-256color}" --env "COLORTERM=${COLORTERM:-truecolor}" "${extra_envs[@]}" "$OPS_CONTAINER_NAME" "$@"
        fi
    fi

    # Apply high-level flags.
    # mount_home=1 bind-mounts host $HOME into the container. Agent configs
    # become visible transitively via the bind-mount.
    if [ "$mount_home" = 1 ]; then
        extra_volumes+=("$HOME:$HOME_IN_CTN")
    fi
    # mount_volume=0 is a single-shot opt-out equivalent to
    # --no-nix-volume --no-mise-volume combined.
    if [ "$mount_volume" = 0 ]; then
        use_nix_volume=0
        use_mise_volume=0
    fi

    local nix_volume="ops-share-nix"
    local mise_volume="ops-share-mise"
    if [ "$isolated_volumes" = 1 ]; then
        nix_volume="${OPS_CONTAINER_NAME}-nix"
        mise_volume="${OPS_CONTAINER_NAME}-mise"
    fi
    [ "$use_nix_volume" = 1 ]    && { ensure_volume "$nix_volume";    extra_volumes+=("$nix_volume:/nix"); }
    [ "$use_mise_volume" = 1 ]   && { ensure_volume "$mise_volume";   extra_volumes+=("$mise_volume:/opt/mise/data"); }

    # Per-agent state machine (auto / mount / volume / off).
    # First path after primary_dest is the "primary" source dir — its
    # container-side mapping (primary_dest) is also where the named volume
    # is attached when "volume" state is selected.
    # Relies on dynamic scoping: inherits mount_home + extra_volumes from
    # cmd_run (same pattern as _mount_if_exists).
    _apply_agent_state() {
        local state="$1" agent="$2" primary_dest="$3"
        shift 3
        local paths=("$@")
        local agent_vol="ops-${agent}"
        # --isolated-volumes: agent configs are per-container too, matching the
        # mise/nix volume naming (${OPS_CONTAINER_NAME}-${agent}).
        [ "$isolated_volumes" = 1 ] && agent_vol="${OPS_CONTAINER_NAME}-${agent}"
        case "$state" in
            auto)
                # mount_home=1: agent config visible via $HOME bind-mount.
                # mount_home=0: auto bind-mount ~/.<agent> if it exists.
                [ "$mount_home" = 0 ] && _mount_if_exists "${paths[@]}"
                ;;
            mount)
                _mount_if_exists "${paths[@]}"
                [ "$mount_home" = 1 ] && \
                    echo "Warning: --${agent}-mount is redundant when \$HOME is bind-mounted (default). Pass --no-mount-home to make it meaningful." >&2
                ;;
            volume)
                ensure_volume "$agent_vol"
                extra_volumes+=("${agent_vol}:${primary_dest}")
                ;;
            off)
                ;;
        esac
    }
    _apply_agent_state "$claude_agent"   claude   "$HOME_IN_CTN/.claude"                   "$HOME/.claude" "$HOME/.claude.json"
    _apply_agent_state "$gemini_agent"   gemini   "$HOME_IN_CTN/.gemini"                   "$HOME/.gemini"
    _apply_agent_state "$opencode_agent" opencode "$HOME_IN_CTN/.local/share/opencode"     "$HOME/.local/share/opencode" "$HOME/.config/opencode"
    _apply_agent_state "$codex_agent"    codex    "$HOME_IN_CTN/.codex"                    "$HOME/.codex"

    # Build args incrementally so --rm can be conditionally included.
    # (Using ${ephemeral:+--rm} with ephemeral=0 still expands because '0' is
    # a non-empty string — bash :+ tests for non-empty, not truthy.)
    local args=(run -it)
    [ "$ephemeral" = 1 ] && args+=(--rm)
    args+=(
        --name "$OPS_CONTAINER_NAME"
        --hostname "$OPS_CONTAINER_NAME"
        --label "ops.container=true"
        # rootless: container UID 0 maps to the host user → R/W access to bind-mounted files
        # rootful:  container UID matches host UID directly → same effect, different mechanism
        --user "$user_arg"
        --env "HOME=$HOME_IN_CTN"
        --env "TERM=${TERM:-xterm-256color}" --env "COLORTERM=${COLORTERM:-truecolor}"
        --workdir "$PWD"
        --volume "$PWD:$PWD"
    )
    for v in "${extra_volumes[@]}"; do
        args+=(--volume "$v")
    done
    if [ -n "${OPS_VOLUMES:-}" ]; then
        # Split OPS_VOLUMES on whitespace without triggering glob expansion
        # (a volume name containing * or ? would otherwise be expanded
        # against the host filesystem).
        local -a volumes_env
        read -r -a volumes_env <<< "$OPS_VOLUMES"
        for v in "${volumes_env[@]}"; do
            args+=(--volume "$v")
        done
    fi
    args+=("${extra_envs[@]}")
    [ ${#extra_ports[@]} -gt 0 ] && args+=("${extra_ports[@]}")

    # Build real-CLI snapshot BEFORE injecting cmdline labels (avoids recursive embedding).
    # Mask sensitive env values (tokens / API keys) in the label so they are
    # not readable via `docker inspect` — the container itself still receives
    # the real values via the extra_envs already in args.
    local real_cli
    real_cli="$(_shell_quote "$RUNTIME_BIN" "${args[@]}" "$OPS_IMAGE" "$@")"
    local real_cli_masked
    real_cli_masked=$(printf '%s' "$real_cli" \
        | sed -E "s/(GITHUB_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY|GEMINI_API_KEY)=[^[:space:]'\"]+/\\1=***/g")
    args+=(--label "ops.cmdline.user=$OPS_ORIG_ARGV")
    args+=(--label "ops.cmdline.real=$real_cli_masked")

    if [ "$dry_run" = 1 ]; then
        printf '%q ' "$RUNTIME_BIN" "${args[@]}" "$OPS_IMAGE" "$@"
        echo
        exit 0
    fi

    "$RUNTIME_BIN" "${args[@]}" "$OPS_IMAGE" "$@" 2> >(grep -v "already exists" >&2)
    exit $?
}

cmd_images() {
    echo -e "\033[1;34m=== Declared images (OPS_IMAGES) ===\033[0m"
    if declare -p OPS_IMAGES >/dev/null 2>&1 && [ ${#OPS_IMAGES[@]} -gt 0 ]; then
        local key img df cn
        for key in "${!OPS_IMAGES[@]}"; do
            img="${OPS_IMAGES[$key]}"
            if declare -p OPS_DOCKERFILES >/dev/null 2>&1 && [ -n "${OPS_DOCKERFILES[$key]:-}" ]; then
                df="${OPS_DOCKERFILES[$key]}"
            elif [ -f "$SCRIPT_DIR/Dockerfile.$key" ]; then
                df="$SCRIPT_DIR/Dockerfile.$key"
            else
                df="(default: $OPS_DOCKERFILE)"
            fi
            if declare -p OPS_CONTAINER_NAMES >/dev/null 2>&1 && [ -n "${OPS_CONTAINER_NAMES[$key]:-}" ]; then
                cn="${OPS_CONTAINER_NAMES[$key]}"
            else
                cn="$key"
            fi
            printf '  \033[1;36m%-15s\033[0m %s\n' "$key" "$img"
            printf '  %-15s   dockerfile: %s\n' "" "$df"
            printf '  %-15s   container:  %s\n' "" "$cn"
            echo ""
        done
    else
        echo "  (none defined)"
    fi
    echo "Define in: $_CONFIG_FILE"
    echo "Use with: $(basename "$0") -i <name>"
}

# Resolves an image name: if it's a key in OPS_IMAGES, applies the bundle
# (image + dockerfile + container name), respecting _user_set_n / _user_set_f
# flags so explicit -n / -f overrides (regardless of argument order) always win.
# Otherwise, the name is used as a raw image reference.
_resolve_image() {
    local name="$1"
    if declare -p OPS_IMAGES >/dev/null 2>&1 && [ -n "${OPS_IMAGES[$name]:-}" ]; then
        OPS_IMAGE="${OPS_IMAGES[$name]}"
        if [ "${_user_set_f:-0}" = 0 ]; then
            if declare -p OPS_DOCKERFILES >/dev/null 2>&1 && [ -n "${OPS_DOCKERFILES[$name]:-}" ]; then
                OPS_DOCKERFILE="${OPS_DOCKERFILES[$name]}"
            elif [ -f "$SCRIPT_DIR/Dockerfile.$name" ]; then
                OPS_DOCKERFILE="$SCRIPT_DIR/Dockerfile.$name"
            fi
        fi
        if [ "${_user_set_n:-0}" = 0 ]; then
            if declare -p OPS_CONTAINER_NAMES >/dev/null 2>&1 && [ -n "${OPS_CONTAINER_NAMES[$name]:-}" ]; then
                OPS_CONTAINER_NAME="${OPS_CONTAINER_NAMES[$name]}"
            else
                OPS_CONTAINER_NAME="$name"
            fi
        fi
    else
        OPS_IMAGE="$name"
    fi
}

cmd_aliases() {
    echo -e "\033[1;34m=== String aliases (OPS_ALIASES) ===\033[0m"
    if declare -p OPS_ALIASES >/dev/null 2>&1; then
        local key
        for key in "${!OPS_ALIASES[@]}"; do
            printf '  %-20s %s\n' "$key" "${OPS_ALIASES[$key]}"
        done
    else
        echo "  (none defined)"
    fi
    echo ""
    echo -e "\033[1;34m=== Function aliases (ops_alias_*) ===\033[0m"
    local fn name any=0
    while IFS= read -r fn; do
        name="${fn#ops_alias_}"
        printf '  %s\n' "$name"
        any=1
    done < <(declare -F | awk '{print $3}' | grep '^ops_alias_' || true)
    [ "$any" = 0 ] && echo "  (none defined)"
    echo ""
    echo "Define aliases in: $_CONFIG_FILE"
}

# Dispatcher for the `nerdctl` namespace — groups the nerdctl-specific
# lifecycle commands (install / uninstall / self-update) under a single
# subcommand. Keeps `ops install` out of the flat namespace, which was
# ambiguous (install what? the runtime? a container?).
cmd_nerdctl() {
    local sub="${1:-}"
    case "$sub" in
        install)      shift; cmd_install "$@" ;;
        uninstall)    shift; cmd_uninstall "$@" ;;
        self-update)  shift; cmd_self_update "$@" ;;
        -h|--help|"")
            cat <<EOF
Usage: $(basename "$0") nerdctl <subcommand>

Manage the nerdctl binary under \$OPS_NERDCTL_HOME (default: ~/.local/share/ops/nerdctl).
Independent of \$OPS_RUNTIME — you can keep docker/podman as your active runtime
while maintaining a separate nerdctl install.

Subcommands:
  install       Download nerdctl-full, verify SHA256, extract to \$OPS_NERDCTL_HOME,
                set up the rootless containerd.service (disabled at boot)
  uninstall     Stop/disable containerd.service, remove binaries + optionally data
  self-update   Update nerdctl to the latest GitHub release
EOF
            ;;
        *)
            echo "Error: unknown nerdctl subcommand '$sub'" >&2
            echo "Run '$(basename "$0") nerdctl --help' for the list." >&2
            exit 1
            ;;
    esac
}

# Reserved subcommand names — aliases with these names are ignored so they
# can't shadow built-in commands.
_OPS_RESERVED=" nerdctl build runtime status info logs log clean run help -h --help alias aliases image images doctor inspect config backup restore update "

# Expand a user-defined alias ($1 = name). Echoes the expanded argv to stdout
# and returns 0 if the name matches a string or function alias; returns 1 if
# no alias is found or the name is reserved.
_expand_alias() {
    local name="${1:-}"
    [ -z "$name" ] && return 1
    case "$_OPS_RESERVED" in
        *" $name "*) return 1 ;;
    esac
    if declare -p OPS_ALIASES >/dev/null 2>&1 && [ -n "${OPS_ALIASES[$name]:-}" ]; then
        printf '%s' "${OPS_ALIASES[$name]}"
        return 0
    fi
    if declare -F "ops_alias_$name" >/dev/null 2>&1; then
        "ops_alias_$name"
        return 0
    fi
    return 1
}

# Track whether user explicitly set -n / -f so that _resolve_image (for
# OPS_IMAGES profiles) doesn't clobber them regardless of flag ordering.
_user_set_n=0
_user_set_f=0

# Parse the leading -n / -i / -f / -H global flags and leave the remaining
# args in the array _parsed_args. Called once on the main argv and a second
# time after alias expansion (aliases may prepend global flags like
# OPS_ALIASES[cc]="-i arch run --claude").
_parse_global_flags() {
    _parsed_args=()
    while [ $# -gt 0 ]; do
        case "${1:-}" in
            -n|--name)          OPS_CONTAINER_NAME="$2"; _user_set_n=1; shift 2 ;;
            -i|--image)         _resolve_image "$2";                    shift 2 ;;
            -f|--dockerfile)    OPS_DOCKERFILE="$2"; _user_set_f=1;     shift 2 ;;
            -H|--nerdctl-home)  OPS_NERDCTL_HOME="$(realpath "$2")"
                                export PATH="$OPS_NERDCTL_HOME/bin:$PATH"
                                _resolve_runtime
                                [ "$OPS_RUNTIME" != "nerdctl" ] && echo "Warning: -H has no effect with OPS_RUNTIME=$OPS_RUNTIME" >&2
                                shift 2 ;;
            *) break ;;
        esac
    done
    _parsed_args=("$@")
}

# Unit-test hook: when sourced with OPS_SOURCE_ONLY=1, expose all functions
# defined above but skip flag parsing + dispatch. Lets bats call helpers like
# _human_bytes / _shell_quote directly.
# shellcheck disable=SC2317  # false positive — early return, code below IS reachable
if [ "${OPS_SOURCE_ONLY:-0}" = 1 ]; then
    return 0 2>/dev/null || exit 0
fi

# Global flags (apply to any subcommand, must appear before it)
_parse_global_flags "$@"
set -- "${_parsed_args[@]}"

# Detects subcommands that don't need a running runtime — skip the containerd
# auto-start / nerdctl auto-install prompts for these. `config` is included
# because it only prints OPS_* variables (no runtime call); `doctor` and
# `inspect` are NOT skipped because they query the runtime (image/container
# inspect) and would be misleading without the daemon running.
_skip_runtime_startup() {
    case "${1:-}" in
        nerdctl|alias|aliases|image|images|help|-h|--help|config) return 0 ;;
        *) return 1 ;;
    esac
}

# The containerd service auto-start and nerdctl auto-install prompts only
# apply when OPS_RUNTIME=nerdctl. Docker/podman ship their own daemon (or
# daemonless in podman's case) and are installed via distro package managers.
if [ "$OPS_RUNTIME" = "nerdctl" ] && ! _skip_runtime_startup "${1:-}"; then
    if [ -x "$RUNTIME_BIN" ] && ! systemctl --user is-active containerd.service >/dev/null 2>&1; then
        echo "Starting containerd service..."
        systemctl --user start containerd.service
        _i=0
        while ! systemctl --user is-active containerd.service >/dev/null 2>&1 || [ ! -d "/run/user/$(id -u)/containerd-rootless" ]; do
            sleep 1; _i=$((_i+1))
            [ $_i -ge "$OPS_CONTAINERD_STARTUP_TIMEOUT" ] && { echo "Timeout after ${OPS_CONTAINERD_STARTUP_TIMEOUT}s: containerd is not responding. Check: systemctl --user status containerd" >&2; exit 1; }
        done
    fi

    if [ ! -x "$RUNTIME_BIN" ]; then
        echo "nerdctl not installed ($RUNTIME_BIN not found)."
        printf "Run 'nerdctl install' now? [Y/n] "
        read -r answer
        if [[ ! "$answer" =~ ^[nN]$ ]]; then
            cmd_install
        else
            exit 1
        fi
    fi
fi

if [ -z "$RUNTIME_BIN" ] || [ ! -x "$RUNTIME_BIN" ]; then
    if [ "$OPS_RUNTIME" != "nerdctl" ]; then
        echo "Runtime '$OPS_RUNTIME' not found in PATH. Install it via your distro package manager." >&2
        exit 1
    fi
fi

# Expand user-defined alias if $1 matches one (string in OPS_ALIASES or
# function named ops_alias_<name>). Reserved subcommand names are skipped.
# Single-pass — aliases don't recursively expand into other aliases.
if _alias_expansion=$(_expand_alias "${1:-}"); then
    shift
    # Re-parse global flags: the alias may have prepended -i / -n / -f / -H
    # (e.g., OPS_ALIASES[cc]="-i arch run --claude"). Without this pass
    # those flags land in the subcommand dispatcher as unknown args.
    # shellcheck disable=SC2086  # intentional word split: alias tokens come from OPS_ALIASES
    _parse_global_flags $_alias_expansion "$@"
    set -- "${_parsed_args[@]}"
fi

case "${1:-}" in
    nerdctl)        shift; cmd_nerdctl "$@" ;;
    doctor)         shift; cmd_doctor "$@" ;;
    inspect)        shift; cmd_inspect "$@" ;;
    config)         shift; cmd_config "$@" ;;
    backup)         shift; cmd_backup "$@" ;;
    restore)        shift; cmd_restore "$@" ;;
    update)         shift; cmd_update "$@" ;;
    build)          shift; cmd_run --build "$@" ;;
    runtime)        shift; cmd_runtime "$@" ;;
    status|info)    shift; cmd_status "$@" ;;
    logs|log)       shift; cmd_logs "$@" ;;
    clean)          shift; cmd_clean "$@" ;;
    run)            shift; cmd_run "$@" ;;
    alias|aliases)  shift; cmd_aliases "$@" ;;
    image|images)   shift; cmd_images "$@" ;;
    help|-h|--help) show_help; exit 0 ;;
    version|--version|-V) echo "ops $OPS_VERSION"; exit 0 ;;
    "")             cmd_run ;;
    *)
        echo "Error: unknown subcommand or alias: '$1'" >&2
        echo "" >&2
        echo "Try one of:" >&2
        echo "  $(basename "$0") help              # list all subcommands" >&2
        echo "  $(basename "$0") alias             # list user-defined aliases" >&2
        echo "  $(basename "$0") run -- $1 ${*:2}" >&2
        exit 1
        ;;
esac
