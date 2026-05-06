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

# Associative arrays (OPS_IMAGES, OPS_ALIASES, OPS_BUILD_ARGS, _OPS_ORIGIN) +
# extglob patterns require bash 4+; the documented minimum is bash 5 to match
# tested platforms. Fail fast with a clear message on old bash.
if [ -z "${BASH_VERSINFO[0]:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 5 ]; then
    echo "Error: bash 5+ required (found bash ${BASH_VERSION:-unknown})" >&2
    exit 1
fi

# Single source of truth for the ops.sh version. Update when cutting a new
# release; CHANGELOG.md should carry the matching entry. Dockerfile and
# Dockerfile.debian declare `ARG VERSION=<same>` as the fallback for direct
# `docker build .` invocations — keep the three in lockstep.
OPS_VERSION="1.12.0"
readonly OPS_VERSION

# Snapshot OPS_* vars at entry so cmd_config can report each var's origin:
# - env:     present before config is sourced
# - config:  defined by sourcing ops.conf
# - default: assigned later by :- fallbacks in this script
declare -A _OPS_ORIGIN=()
for _v in $(compgen -v 2>/dev/null | grep '^OPS_' || true); do _OPS_ORIGIN[$_v]='env'; done
unset _v

# Snapshot every UPPER_CASE env var BEFORE sourcing ops.conf so
# `config secret add NAME --from-env` reads the caller's intent rather
# than the value the config file reinjects via `export NAME=…`. Without
# this, the second `secret add` would silently re-write the OLD value
# back over the new one (the source step already restored $NAME from
# the previous secret line). The cost is a few-kB associative array per
# invocation; negligible vs the rest of ops startup.
declare -A _PRE_SOURCE_ENV=()
for _v in $(compgen -v 2>/dev/null | grep -E '^[A-Z_][A-Z0-9_]*$' || true); do
    # `${!_v:-}` is mandatory under `set -u`: indirect expansion on a
    # variable that has been listed by `compgen -v` but transitioned to
    # unset between the listing and the lookup (rare race, but observed
    # under bats with helpers that aggressively unset env vars during
    # setup) would otherwise trip "unbound variable" and abort startup.
    _PRE_SOURCE_ENV[$_v]="${!_v:-}"
done
unset _v

_CONFIG_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/ops/ops.conf"
# Defence-in-depth: `source` executes arbitrary code, so refuse to load the
# config when it's writable by someone other than the current user (covers the
# world- / group-writable footgun where a shared $HOME lets an attacker drop
# into the shell that sources ops.conf). Ownership check uses `stat` with GNU
# and BSD fallbacks so macOS users keep the guard too.
if [ -f "$_CONFIG_FILE" ]; then
    _cfg_owner=""
    _cfg_perms=""
    if _cfg_owner=$(stat -c '%u' "$_CONFIG_FILE" 2>/dev/null); then
        _cfg_perms=$(stat -c '%a' "$_CONFIG_FILE" 2>/dev/null)
    elif _cfg_owner=$(stat -f '%u' "$_CONFIG_FILE" 2>/dev/null); then
        _cfg_perms=$(stat -f '%Lp' "$_CONFIG_FILE" 2>/dev/null)
    fi
    if [ -n "$_cfg_owner" ] && [ "$_cfg_owner" != "$(id -u)" ]; then
        echo "Refusing to source $_CONFIG_FILE: owned by UID $_cfg_owner, expected $(id -u)." >&2
        exit 1
    fi
    # World-writable (other-write bit set) is the hard footgun — any user on
    # the box could inject code. Group-writable is tolerated because Linux
    # distros with a user-private-group umask (002 on Ubuntu/Debian variants)
    # legitimately produce 664 files for $HOME content.
    case "${_cfg_perms:-000}" in
        *[2367]) echo "Refusing to source $_CONFIG_FILE: world-writable (perms $_cfg_perms)." >&2; exit 1 ;;
    esac
    unset _cfg_owner _cfg_perms
    # shellcheck disable=SC1090
    source "$_CONFIG_FILE"
fi

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
        # Defense-in-depth fallback: a missing RUNTIME_BIN is already caught by
        # the `[ ! -x "$RUNTIME_BIN" ]` guard at end-of-script (which exits 1
        # before any code path that calls _is_rootless can run). This branch
        # would only fire in an impossible-by-construction state; kept for
        # safety but not reachable from the test harness.
        # :nocov:
        if [ ! -x "$RUNTIME_BIN" ]; then _IS_ROOTLESS_CACHE=yes
        # :nocov:
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

# Real-daemon interactions — ensure_buildkitd / stop_buildkitd drive the
# rootless buildkitd process via rootlesskit, `kill -0`, `wait`, and real
# PID polling. Replicating that inside a bats mock isn't useful (the mock
# PID would behave differently from a real rootlesskit child), so these
# functions are verified end-to-end by the `runtime-build` CI matrix job
# (.github/workflows/tests.yml) which runs against an actual nerdctl install
# and exercises: `ensure_buildkitd` → `docker build` → `stop_buildkitd`.
# :nocov:
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
# :nocov:

# :nocov:
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
# :nocov:

# :nocov:
# EXIT/INT/TERM trap handler. bashcov can observe `trap` being registered but
# not the handler body once bash is tearing the process down — the DEBUG
# trap is gone by then. The handler's logic (stop_buildkitd + rm tempdir) is
# trivial and indirectly exercised every time a bats test ends cleanly.
cleanup() {
    stop_buildkitd
    [ -n "${TMP_INSTALL_DIR:-}" ] && rm -rf "$TMP_INSTALL_DIR"
    return 0
}
trap cleanup EXIT INT TERM
# :nocov:

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

# OCI image metadata default. Forwarded to build_image as --build-arg
# SOURCE_URL, which populates the org.opencontainers.image.{source,url,
# documentation} labels. Defaults to the upstream repo so the labels are
# meaningful out of the box; override (or set empty) in ops.conf for a
# fork or a vendor build.
OPS_SOURCE_URL="${OPS_SOURCE_URL-https://github.com/gigi206/ops-cli}"

# Container-side $HOME. Distinct from host's $HOME when OPS_USER_NAME differs
# from the invoking user (rare but breaks bind-mount dest paths otherwise).
HOME_IN_CTN="/home/$OPS_USER_NAME"

# Resolve symlinks so `ops` can be symlinked into /usr/local/bin/ while keeping
# the companion files (Dockerfile, mise/, scripts/) next to the real ops.sh.
# Falls back to raw $0 when readlink -f is unavailable (e.g. macOS without coreutils).
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")" && pwd)"
OPS_DOCKERFILE="${OPS_DOCKERFILE:-$SCRIPT_DIR/Dockerfile}"

# Hash file is derived from OPS_IMAGE so each image has its own cache.
# Lazy so changes to OPS_IMAGE via -i (global or in cmd_run) are picked up.
_hash_file() {
    echo "${XDG_CACHE_HOME:-$HOME/.cache}/ops/${OPS_IMAGE//\//_}.sha256sum"
}

_hash_dir() {
    # Hash every regular file under $1, sorted for determinism. Prints
    # nothing (not even a header) if the directory is absent, so the outer
    # digest is stable across layouts that don't ship mise/ or scripts/.
    local dir="$1"
    [ -d "$dir" ] || return 0
    # -print0 + sort -z + xargs -0 handles whitespace in paths safely.
    # Path prefix is stripped so the digest is relocation-invariant (the
    # same mise/ tree under /tmp/foo vs /home/bar hashes the same).
    find "$dir" -type f -print0 \
        | sort -z \
        | ( cd "$dir" && xargs -0 -I{} sh -c 'f="{}"; f="${f#./}"; sha256sum "$f"' ) 2>/dev/null
}

# Produce a digest over every input that ends up baked into the image.
# Changing ANY of these should invalidate the per-image hash cache so that
# `dockerfile_changed` emits its "rebuild needed" warning:
#   - the selected Dockerfile
#   - the mise/ plugin tree (COPY'd into /opt/mise/data/plugins/nix/)
#   - the scripts/ helpers (COPY'd into /opt/ops/bin/)
#   - the effective OPS_BUILD_ARGS[<key>] when building via a profile
# A single `sha256sum` folds all of these into one hex string.
current_hash() {
    if [ ! -f "$OPS_DOCKERFILE" ]; then
        echo "Error: Dockerfile not found: $OPS_DOCKERFILE" >&2
        return 1
    fi
    {
        # `sha256sum < file` (not `sha256sum file`) so the path doesn't enter
        # the digest — keeps the hash relocation-invariant, matching the
        # contract _hash_dir already follows for the mise/ + scripts/ trees.
        sha256sum < "$OPS_DOCKERFILE"
        _hash_dir "$SCRIPT_DIR/mise"
        _hash_dir "$SCRIPT_DIR/scripts"
        # Per-profile build args: when `-i <key>` matches a declared OPS_IMAGES
        # key, OPS_BUILD_ARGS[<key>] applies. For unkeyed builds (no `-i`, or
        # `-i` pointing at a raw image ref), the fallback key is `default` —
        # so OPS_BUILD_ARGS[default] applies to unkeyed builds without the
        # user having to register a matching OPS_IMAGES[default] entry.
        # Same condition used by build_image when it translates OPS_BUILD_ARGS
        # into --build-arg.
        local _build_args_key="${_OPS_IMAGE_KEY:-default}"
        if declare -p OPS_BUILD_ARGS >/dev/null 2>&1 \
           && [ -n "${OPS_BUILD_ARGS[$_build_args_key]:-}" ]; then
            printf 'build-args: %s\n' "${OPS_BUILD_ARGS[$_build_args_key]}"
        fi
    } | sha256sum | cut -d' ' -f1
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
    # --dry-run prints the composed build command and exits 0 without acquiring
    # the lock or starting buildkitd (invoked via `ops run --build --dry-run`).
    local if_missing=0 dry_run_build=0
    while [ "${1:-}" = "--if-missing" ] || [ "${1:-}" = "--dry-run" ]; do
        case "$1" in
            --if-missing) if_missing=1 ;;
            --dry-run)    dry_run_build=1 ;;
        esac
        shift
    done

    if [ ! -f "$OPS_DOCKERFILE" ]; then
        echo "Error: Dockerfile not found: $OPS_DOCKERFILE" >&2
        return 1
    fi

    local lock_file
    lock_file="$(_hash_file).lock"
    mkdir -p "$(dirname "$lock_file")"
    if [ "$dry_run_build" = 0 ] && command -v flock >/dev/null 2>&1; then
        exec 9>"$lock_file"
        if [ "$if_missing" = 1 ]; then
            if ! flock -w 300 9; then
                echo "Timed out waiting for build lock ($lock_file)" >&2
                exec 9>&-
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
                exec 9>&-
                return 1
            fi
        fi
    fi

    # --network host is needed during image builds: Nix needs to reach
    # cache.nixos.org, and the default bridge network is too flaky for
    # a 150 MB download across 170+ narinfo fetches.
    local -a extra_build_flags=(--network host)
    if [ "$OPS_RUNTIME" = "nerdctl" ]; then
        # Skip buildkitd startup in dry-run — we only want to print the cmdline.
        [ "$dry_run_build" = 0 ] && ensure_buildkitd
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

    # Per-profile build args from OPS_BUILD_ARGS[<image-key>]. Value is a
    # string of `KEY=VALUE` pairs separated by `;` (a single pair is the
    # common case). Allows e.g. overriding EXTRA_MISE_TOOLS per image:
    #   declare -A OPS_BUILD_ARGS=(
    #     [default]="EXTRA_MISE_TOOLS=nix:google-chrome"
    #     [arch-chrome]="EXTRA_MISE_TOOLS=nix:google-chrome-for-testing"
    #     [arch-min]="EXTRA_MISE_TOOLS="
    #   )
    # The lookup key is `_OPS_IMAGE_KEY` (set by `_resolve_image()` when
    # `-i <key>` matches an OPS_IMAGES entry) with `default` as the fallback
    # for unkeyed builds. This means `OPS_BUILD_ARGS[default]` applies to
    # `ops build` (no `-i`), matching the natural reading of "default" — and
    # keying off `default` does NOT require declaring `OPS_IMAGES[default]`,
    # since the unkeyed build's image name comes from `OPS_IMAGE` (default
    # `localhost/ops-dev`) rather than from an OPS_IMAGES profile.
    local _build_args_key="${_OPS_IMAGE_KEY:-default}"
    local -a profile_build_args=()
    if declare -p OPS_BUILD_ARGS >/dev/null 2>&1 \
       && [ -n "${OPS_BUILD_ARGS[$_build_args_key]:-}" ]; then
        local _pair
        local -a _profile_pairs=()
        # IFS=';' splits into KEY=VALUE chunks; `read -ra` avoids globbing
        # and preserves internal whitespace within each value.
        IFS=';' read -ra _profile_pairs <<< "${OPS_BUILD_ARGS[$_build_args_key]}"
        for _pair in "${_profile_pairs[@]}"; do
            # Trim surrounding whitespace so `;  FOO=bar` works.
            _pair="${_pair#"${_pair%%[![:space:]]*}"}"
            _pair="${_pair%"${_pair##*[![:space:]]}"}"
            [ -n "$_pair" ] && profile_build_args+=(--build-arg "$_pair")
        done
    fi

    # OCI-metadata build args. SOURCE_URL populates the source/url/
    # documentation labels and lets `docker inspect` consumers walk back to
    # the project. OPS_SOURCE_URL defaults to the upstream repo; override
    # (or set empty) for a fork / vendor build.
    local -a oci_build_args=(
        --build-arg "SOURCE_URL=${OPS_SOURCE_URL:-}"
    )

    local -a build_cmd=(
        "$RUNTIME_BIN" build -t "$OPS_IMAGE"
        --file "$OPS_DOCKERFILE"
        --label "ops.dockerfile=$dockerfile_abs"
        --pull
        "${extra_build_flags[@]}"
        --build-arg USER_UID="$OPS_USER_UID"
        --build-arg USER_GID="$OPS_USER_GID"
        --build-arg USER_NAME="$OPS_USER_NAME"
        --build-arg USER_LANG="$OPS_USER_LANG"
        "${oci_build_args[@]}"
        "${profile_build_args[@]}"
        "${secret_flags[@]}"
        "$@" "$SCRIPT_DIR"
    )

    if [ "$dry_run_build" = 1 ]; then
        _dry_run_print "${build_cmd[@]}"
        echo
        return 0
    fi

    "${build_cmd[@]}"
    local ret=$?
    # Propagate save_hash failure so the next build/run doesn't silently skip
    # the "Dockerfile changed" warning because the cache file never landed.
    if [ $ret -eq 0 ]; then
        save_hash || ret=$?
    fi
    [ "$OPS_RUNTIME" = "nerdctl" ] && stop_buildkitd
    command -v flock >/dev/null 2>&1 && exec 9>&-
    return $ret
}

# Single source of truth for which environment-variable names hold a secret.
# Both `_is_secret_key` (dry-run path) and `_ops_secret_alt` (label-mask path)
# derive their match logic from this single list — keep them in lock-step
# (a previous version diverged: glob `*KEY` matched MONKEY but the regex
# `[A-Z][A-Z0-9_]*_KEY` did not, so the same value was redacted in dry-run
# but leaked in `ops.cmdline.*` labels).
#
# Suffixes are matched against `_<SUF>` (with the underscore separator) so
# real-world identifier patterns are caught (`GITHUB_TOKEN`, `MY_DB_PASSWORD`,
# `ANTHROPIC_API_KEY`) while non-secret look-alikes are not (`MONKEY`,
# `WHISKEY`). False positives on names that *do* end in `_KEY` / `_TOKEN`
# but aren't secrets (e.g. `PUBLIC_KEY`) are an accepted trade-off in
# favour of never leaking.
readonly _OPS_SECRET_SUFFIXES='TOKEN KEY SECRET PASSWORD PASSWD PASS PWD APIKEY API_KEY'

# True when $1 is the name of an env-var that should be redacted in any
# logged output. Bash-glob match against `*_<SUF>` (mirrors the regex used
# by `_ops_secret_alt`).
_is_secret_key() {
    local name="$1" suf
    for suf in $_OPS_SECRET_SUFFIXES; do
        case "$name" in
            *"_$suf") return 0 ;;
        esac
    done
    return 1
}

# Render an argv through `printf '%q '` while redacting secret values in
# `--env KEY=VALUE` / `-e KEY=VALUE` / `--build-arg KEY=VALUE` pairs whose
# KEY matches `_is_secret_key`. Used by every --dry-run path so a shared
# transcript doesn't leak GITHUB_TOKEN, ANTHROPIC_API_KEY, etc.
_dry_run_print() {
    local arg next key
    while [ $# -gt 0 ]; do
        arg="$1"
        case "$arg" in
            --env|-e|--build-arg)
                if [ $# -ge 2 ]; then
                    next="$2"
                    key="${next%%=*}"
                    # Redact only when the arg is `KEY=VAL` (contains `=`) and
                    # the key name matches the sensitive suffix list.
                    if [ "$key" != "$next" ] && _is_secret_key "$key"; then
                        # Placeholder uses plain letters so `printf '%q'`
                        # doesn't shell-escape it (`***` and `<redacted>`
                        # both get backslash-escaped, breaking grep-style
                        # assertions on the dry-run output).
                        printf '%q %q ' "$arg" "${key}=REDACTED"
                        shift 2
                        continue
                    fi
                    printf '%q %q ' "$arg" "$next"
                    shift 2
                    continue
                fi
                ;;
        esac
        printf '%q ' "$arg"
        shift
    done
}

# Build the sed alternation (`A|B|C`) for the secret name list. Used by
# _mask_secrets below so it derives from the same source as _is_secret_key.
# The two match exactly the same set of names (any uppercase identifier
# ending in `_TOKEN`, `_KEY`, `_SECRET`, `_PASSWORD`, `_PASSWD`, `_PASS`,
# `_PWD`, `_APIKEY`, or `_API_KEY`).
_ops_secret_alt() {
    local first=1 alt='' suf
    for suf in $_OPS_SECRET_SUFFIXES; do
        if [ "$first" = 1 ]; then alt="_${suf}"; first=0
        else                       alt="$alt|_${suf}"
        fi
    done
    printf '%s' "[A-Z][A-Z0-9_]*($alt)"
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
  clean [--dry-run] [--no-volumes|--volumes-only] [--include-shared]
                 Prune dangling images, stopped ops containers, ops volumes
                 (ops-share-* volumes are SKIPPED unless --include-shared)
  doctor         Validate config: OPS_IMAGES refs, dockerfiles, image labels
  inspect KEY    Show detailed info for an OPS_IMAGES key, container, or image ref
  config         Dump effective OPS_* config (scalars + arrays) with origin
  backup VOL     Stream a volume as tar.gz to stdout  (redirect to a file)
  restore VOL    Restore a volume from a tar.gz on stdin  (redirect from a file)
  update KEY     Rebuild an image and offer to recreate containers on the old version
  self-update [-c|--check] [-f|--force] [REF]
                 Update ops-cli itself in place (re-execs install.sh).
                 REF = tag/branch/SHA; default = latest stable tag.
                 --check previews current → target without touching anything.
                 --force bypasses the dirty-working-tree safety check.
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
  -r, --runtime NAME        Runtime override (auto/docker/podman/nerdctl)
                            — equivalent to OPS_RUNTIME=NAME for this invocation
                            (default: $OPS_RUNTIME)
  -H, --nerdctl-home PATH   nerdctl directory        (default: ~/.local/share/ops/nerdctl)
  Example: $(basename "$0") -n web logs -f

$(basename "$0") run [OPTIONS] [COMMAND...]
  -i, --image NAME          Image to use             (default: $OPS_IMAGE)
  -n, --name NAME           Container name           (default: $OPS_CONTAINER_NAME)
  -r, --runtime NAME        Runtime override         (default: $OPS_RUNTIME)
  -u, --uid|--user UID[:GID] UID (or UID:GID) inside container (default: $(id -u))
  -g, --gid GID             GID inside container     (default: $(id -g))
  -l, --lang LOCALE         Container locale         (default: ${LANG:-en_US.UTF-8})
  -v, --volume SRC:DST      Extra volume             (repeatable)
  -e, --env KEY=VAL         Extra env var            (repeatable)
      --env-file FILE       Read env vars from file  (repeatable)
  -p, --port HOST:CTN       Publish port             (repeatable)
  -H, --nerdctl-home PATH   nerdctl directory        (default: ~/.local/share/ops/nerdctl)
      --no-rm               Keep container on exit   (default: removed)
      --dry-run             Print the runtime command instead of executing it
      --group-add GID       Forward --group-add to the runtime    (repeatable)
      --cap-add CAP         Forward --cap-add to the runtime      (repeatable)
      --cap-drop CAP        Forward --cap-drop to the runtime     (repeatable)
      --security-opt OPT    Forward --security-opt to the runtime (repeatable)
      --device DEV          Forward --device to the runtime       (repeatable)
      --privileged          Forward --privileged to the runtime
                            (the six flags above are runtime-creation passthroughs;
                            forwarded verbatim to docker/podman/nerdctl run.
                            Used by the nested-container function aliases —
                            see docs/nested-containers.md.)
  -h, --help                Show this help and exit
  -b, --build               Build the image (honors --no-cache)
      --no-cache            Invalidate build cache (requires --build)
      --install             Run \`mise install\` (from the workdir's mise.toml)
                            before the real command. Stand-alone gives you
                            an interactive bash after install; combinable
                            with --claude / --gemini / --opencode /
                            --opencode-desktop / --codex and with an explicit
                            command after \`--\`.
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
      --no-trust-workdir    Do not auto-trust the workdir's mise.toml (default:
                            trusted via MISE_TRUSTED_CONFIG_PATHS=\$PWD so
                            mise activates without prompting). Use this flag
                            when running in a repo whose mise.toml you don't
                            fully trust; global opt-out via OPS_TRUST_WORKDIR=0.
      --no-wayland          Disable the auto Wayland socket forward (enabled
                            by default when \$WAYLAND_DISPLAY is set on the
                            host). X11 is not auto-forwarded (deprecated).
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
      --opencode            Run opencode (install npm:opencode-ai if missing)
      --opencode-desktop    Run opencode-desktop GUI (Electron AppImage from
                            sst/opencode releases, ~150 MB; uses
                            --appimage-extract-and-run, no FUSE needed).
                            Shares the ops-opencode state with --opencode;
                            needs Wayland on the host (auto-forwarded
                            unless --no-wayland) AND an image built with
                            OPS_DESKTOP_DEPS=true (gtk3 / nss / mesa /
                            alsa runtime libs — opt-in, see Dockerfile).
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

# Fetch the latest release tag for a GitHub repo via the REST API, stripping
# a leading `v` if present. Uses GITHUB_TOKEN (if set) to lift the 60 req/h
# anonymous cap to 5000 req/h without writing the token to disk. Prints the
# bare version on stdout; returns non-zero with an empty stdout if the call
# fails or the payload can't be parsed. Factored out of cmd_install and
# cmd_update to avoid drift between the two copies.
_fetch_github_latest_tag() {
    local repo="$1"
    local -a gh_auth=()
    [ -n "${GITHUB_TOKEN:-}" ] && gh_auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
    curl -fsSL --max-time 20 "${gh_auth[@]}" \
        "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null \
        | grep -m1 '"tag_name"' \
        | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\{0,1\}\([^"]*\)".*/\1/'
}

cmd_install() {
    local install_dir="$OPS_NERDCTL_HOME"

    # Safety check upfront -- before any network call. Previously this check
    # ran after the tarball + SHA256SUMS downloads, which meant a user who
    # typed `OPS_NERDCTL_HOME=/usr ops nerdctl install` by mistake waited a
    # full download only to be refused. Moving the guard here also lets
    # test_regressions.bats exercise the refusal path without needing a
    # curl mock.
    _assert_safe_install_path "$install_dir" install || exit 1

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
    version="$(_fetch_github_latest_tag "containerd/nerdctl")"
    if [ -z "$version" ]; then
        echo "Failed to fetch version from GitHub (rate-limited or offline?)." >&2; exit 1
    fi
    echo "Version: $version"

    local tarball="nerdctl-full-${version}-linux-${arch}.tar.gz"
    local base_url="https://github.com/containerd/nerdctl/releases/download/v${version}"
    TMP_INSTALL_DIR="$(mktemp -d)"

    echo "Downloading $tarball..."
    if ! curl -fsSL "$base_url/$tarball" -o "$TMP_INSTALL_DIR/$tarball"; then
        echo "Error: failed to download $tarball" >&2; exit 1
    fi

    echo "Verifying checksum..."
    if ! curl -fsSL "$base_url/SHA256SUMS" -o "$TMP_INSTALL_DIR/SHA256SUMS"; then
        echo "Error: failed to download SHA256SUMS" >&2; exit 1
    fi
    local expected_line
    expected_line=$(awk -v f="$tarball" '$2==f' "$TMP_INSTALL_DIR/SHA256SUMS")
    if [ -z "$expected_line" ]; then
        echo "Error: $tarball not listed in SHA256SUMS" >&2; exit 1
    fi
    if ! ( cd "$TMP_INSTALL_DIR" && echo "$expected_line" | sha256sum -c - ); then
        echo "Checksum verification failed for $tarball" >&2; exit 1
    fi

    if [ -d "$install_dir" ] && [ -n "$(ls -A "$install_dir" 2>/dev/null)" ]; then
        # Default is "no" on destructive prompts: a bare Enter must not nuke
        # an existing install. The test suite explicitly sends "Y" to accept.
        printf "Directory %s is not empty. Overwrite? [y/N] " "$install_dir"
        read -r answer
        if [[ ! "$answer" =~ ^[yY]$ ]]; then
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
    # containerd-rootless-setuptool.sh fails fast if any prereq is missing
    # (uidmap, slirp4netns, fuse-overlayfs, dbus-user-session, a working
    # `systemctl --user`). Surface that exit status — the previous swallow
    # left ops users with a half-installed rootless stack and a confusing
    # "Unit containerd.service not found" the next time `ops build` ran.
    if ! "$install_dir/bin/containerd-rootless-setuptool.sh" install; then
        echo "Error: rootless containerd setup failed (missing uidmap / slirp4netns / fuse-overlayfs / dbus-user-session, or systemctl --user is unavailable)." >&2
        exit 1
    fi
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

    # Destructive default = N: bare Enter keeps the binaries / data. A user who
    # really wants to wipe them types "y" explicitly.
    printf "Remove binaries (%s)? [y/N] " "$install_dir"
    read -r answer
    if [[ "$answer" =~ ^[yY]$ ]]; then
        rm -rf "$install_dir"
        echo "Binaries removed."
    fi

    printf "Remove containerd data (images, containers, snapshots) (%s)? [y/N] " "$containerd_data"
    read -r answer
    if [[ "$answer" =~ ^[yY]$ ]]; then
        rm -rf "$containerd_data"
        echo "Data removed."
    fi

    echo "Uninstall complete."
}

cmd_runtime() {
    # Special case: a bare `ops runtime --help` (no other args) shows ops-cli's
    # own help for the subcommand. As soon as another arg is present
    # (`ops runtime --help build`, `ops runtime ps --help`), we forward
    # everything to the runtime — matching the proxy contract.
    if [ $# -eq 1 ] && { [ "$1" = "-h" ] || [ "$1" = "--help" ]; }; then
        cat <<EOF
Usage: $(basename "$0") runtime <ARGS...>

Proxy to the underlying runtime binary ($OPS_RUNTIME → $RUNTIME_BIN). Every
argument is forwarded verbatim — 'ops runtime' does not parse or rewrite
anything. Use this for runtime-specific commands ops.sh does not wrap.

Examples:
  $(basename "$0") runtime ps -a
  $(basename "$0") runtime rm -f ops-dev
  $(basename "$0") runtime volume inspect ops-share-nix
  $(basename "$0") runtime tag localhost/ops-dev-test localhost/ops-dev

The exit code of the runtime is propagated. To see the runtime's own help,
add any non-flag token: 'ops runtime help', 'ops runtime ps --help', etc.
EOF
        return 0
    fi
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
    case "${1:-}" in
        -h|--help)
            cat <<EOF
Usage: $(basename "$0") status [info]

Show the ops state: services (runtime + optional containerd/buildkitd when
OPS_RUNTIME=nerdctl), images (default + OPS_IMAGES profiles + ops-labelled),
labelled volumes (ops.volume=true), containers (name, image, coloured state,
cmd, ops cli, real cli, mounts). 'info' is an alias of 'status'.

No flags.
EOF
            return 0
            ;;
    esac
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
    # Discover images labeled ops.dockerfile (built by ops.sh, not in OPS_IMAGES).
    # When an image lost its tag (rebuild → previous version dangling), the
    # runtime reports `<none>:<none>` for Repository:Tag — substitute the
    # short ID so the row stays identifiable + actionable (`rmi <id>`)
    # instead of showing an unparseable placeholder. The full ID is also
    # remembered in ops_image_inspect_keys so the subsequent image inspect
    # can target the dangling image directly (inspect on `<none>:<none>`
    # would always fail).
    local -A ops_image_inspect_keys=()
    local raw_id
    while IFS='|' read -r ref raw_id; do
        [ -z "$ref" ] && continue
        if [ "$ref" = "<none>:<none>" ]; then
            local short_id="${raw_id#sha256:}"
            short_id="${short_id:0:12}"
            [ -z "$short_id" ] && continue
            ref="<dangling>:${short_id}"
            ops_image_inspect_keys[$ref]="$raw_id"
        else
            ref="${ref%:latest}"
        fi
        if [ -z "${ops_image_seen[$ref]:-}" ]; then
            ops_image_refs+=("$ref")
            ops_image_seen[$ref]=1
        fi
    done < <("$RUNTIME_BIN" image ls --filter "label=ops.dockerfile" --format '{{.Repository}}:{{.Tag}}|{{.ID}}' 2>/dev/null || true)

    # --- Images (default + declared + labeled) ---
    echo -e "\033[1;34m=== Images ===\033[0m"
    local info size created human_size label tags df_label inspect_target
    for ref in "${ops_image_refs[@]}"; do
        inspect_target="${ops_image_inspect_keys[$ref]:-$ref}"
        info=$("$RUNTIME_BIN" image inspect "$inspect_target" --format '{{.Size}}|{{.Created}}|{{if .Config.Labels}}{{index .Config.Labels "ops.dockerfile"}}{{end}}' 2>/dev/null || true)
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
    case "${1:-}" in
        -h|--help)
            cat <<EOF
Usage: $(basename "$0") logs|log [NAME] [OPTIONS] [RUNTIME_FLAGS...]

Tail the logs of an ops container. Alias: 'log'.

Arguments:
  NAME                  Container to follow (default: \$OPS_CONTAINER_NAME = $OPS_CONTAINER_NAME)

Options:
  -s, --strip           Strip ANSI escape sequences from the output (useful for
                        TUI programs that use cursor-forward \\e[nC — replaced
                        with a single space so word boundaries survive).
  -h, --help            Show this help.

Runtime flags are passed through to the underlying '<runtime> logs ...':
  --tail N, -n N        Last N lines
  --since DURATION      e.g. 10m, 1h
  --until DURATION
  Any other flag prefixed with '-' is forwarded verbatim.

Example:
  $(basename "$0") log ops-dev -s --tail 200
EOF
            return 0
            ;;
    esac
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
    case "${1:-}" in
        -h|--help)
            cat <<EOF
Usage: $(basename "$0") clean [--dry-run] [--no-volumes|--volumes-only] [--include-shared]

Prune ops-tracked resources. Strictly filtered by labels — containers and
volumes created outside ops.sh are preserved:

  dangling images          (<none>:<none>, regardless of origin)
  stopped ops containers   (filter: label=ops.container=true, status=exited)
  ops volumes              (filter: label=ops.volume=true)

Two interactive prompts — one for dangling images + stopped containers,
one for volumes (separate because volume removal is destructive and not
always intended).

Volumes named 'ops-share-*' (ops-share-nix, ops-share-mise, …) are
SKIPPED by default — they're shared cross-container caches that often
represent hours of nix store / mise tool downloads. Pass --include-shared
to add them back to the volumes prompt.

Options:
  --dry-run             Show what would be removed, exit without prompting or deleting
  --no-volumes          Skip the volumes prompt entirely (keep all volumes)
  --volumes-only        Only act on volumes — skip the images+containers prompt
  --include-shared      Include ops-share-* volumes in the volumes prompt
                        (default: skip them to protect cached state)
  -h, --help            Show this help

Examples:
  $(basename "$0") clean                              # interactive, keeps ops-share-*
  $(basename "$0") clean --dry-run                    # preview only
  $(basename "$0") clean --no-volumes                 # only dangling images + stopped containers
  $(basename "$0") clean --include-shared             # also prompt to drop ops-share-nix etc
EOF
            return 0
            ;;
    esac

    local dry=0 no_vol=0 vol_only=0 include_shared=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --dry-run)        dry=1 ;;
            --no-volumes)     no_vol=1 ;;
            --volumes-only)   vol_only=1 ;;
            --include-shared) include_shared=1 ;;
            *) echo "Error: unknown option '$1' (see 'clean --help')" >&2; return 2 ;;
        esac
        shift
    done
    if [ "$no_vol" = 1 ] && [ "$vol_only" = 1 ]; then
        echo "Error: --no-volumes and --volumes-only are mutually exclusive" >&2
        return 2
    fi

    local count_img=0 count_ctn=0 count_vol=0 count_shared=0
    if [ "$vol_only" = 0 ]; then
        echo -e "\033[1;34m=== Dangling images ===\033[0m"
        local img_id img_size df_label label_suffix
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
        local ctn_id ctn_name
        while IFS='|' read -r ctn_id ctn_name; do
            [ -z "$ctn_id" ] && continue
            printf '  \033[31m✗\033[0m  %-14s  %s\n' "${ctn_id:0:12}" "$ctn_name"
            count_ctn=$((count_ctn+1))
        done < <("$RUNTIME_BIN" ps -a -f status=exited -f label=ops.container=true --format '{{.ID}}|{{.Names}}' 2>/dev/null || true)
        [ "$count_ctn" = 0 ] && echo "  (none)"
    fi

    # Volumes section: split into "to prune" and "shared (kept)" lists.
    # The shared list is always shown so the user sees what would be touched
    # if they pass --include-shared, but it's only added to the prune
    # candidates when that flag is set.
    local -a vol_to_prune=()
    local -a vol_shared=()
    if [ "$no_vol" = 0 ]; then
        echo -e "\n\033[1;34m=== ops volumes (label=ops.volume=true) ===\033[0m"
        local vol_name vol_mp
        while IFS='|' read -r vol_name vol_mp; do
            [ -z "$vol_name" ] && continue
            if [[ "$vol_name" == ops-share-* ]] && [ "$include_shared" = 0 ]; then
                vol_shared+=("$vol_name|$vol_mp")
            else
                vol_to_prune+=("$vol_name|$vol_mp")
            fi
        done < <("$RUNTIME_BIN" volume ls --filter label=ops.volume=true --format '{{.Name}}|{{.Mountpoint}}' 2>/dev/null || true)
        local entry
        for entry in "${vol_to_prune[@]}"; do
            vol_name="${entry%%|*}"
            vol_mp="${entry#*|}"
            printf '  \033[31m✗\033[0m  %-24s  \033[2m%s\033[0m\n' "$vol_name" "$vol_mp"
            count_vol=$((count_vol+1))
        done
        [ "$count_vol" = 0 ] && echo "  (none)"
        if [ ${#vol_shared[@]} -gt 0 ]; then
            echo -e "\n  \033[2m-- Skipped (shared cache; pass --include-shared to drop):\033[0m"
            for entry in "${vol_shared[@]}"; do
                vol_name="${entry%%|*}"
                vol_mp="${entry#*|}"
                printf '  \033[33m·\033[0m  %-24s  \033[2m%s\033[0m\n' "$vol_name" "$vol_mp"
                count_shared=$((count_shared+1))
            done
        fi
    fi

    echo -e "\n\033[1;34m=== Summary ===\033[0m"
    [ "$vol_only" = 0 ] && printf '  dangling images:        %d\n' "$count_img"
    [ "$vol_only" = 0 ] && printf '  stopped ops containers: %d\n' "$count_ctn"
    if [ "$no_vol" = 0 ]; then
        printf '  ops volumes (to prune): %d\n' "$count_vol"
        [ "$count_shared" -gt 0 ] && printf '  ops volumes (kept):     %d  \033[2m(use --include-shared)\033[0m\n' "$count_shared"
    fi

    if [ "$dry" = 1 ]; then
        echo -e "\n\033[33m(dry-run — nothing removed)\033[0m"
        return 0
    fi

    if [ "$vol_only" = 0 ] && [ $((count_img + count_ctn)) -gt 0 ]; then
        printf "\nPrune %d dangling image(s) and %d stopped ops container(s)? [y/N] " \
            "$count_img" "$count_ctn"
        read -r answer
        if [[ "$answer" =~ ^[yY]$ ]]; then
            "$RUNTIME_BIN" image prune -f >/dev/null 2>&1 || true
            # Avoid `xargs -r` (GNU-only): on BSD/macOS xargs without -r runs the
            # command once with no args and the runtime errors out. Read into an
            # array and skip the call when empty.
            local -a _exited_ids=()
            while IFS= read -r _id; do
                [ -n "$_id" ] && _exited_ids+=("$_id")
            done < <("$RUNTIME_BIN" ps -a -f status=exited -f label=ops.container=true --format '{{.ID}}' 2>/dev/null)
            if [ ${#_exited_ids[@]} -gt 0 ]; then
                "$RUNTIME_BIN" rm "${_exited_ids[@]}" >/dev/null 2>&1 || true
            fi
            echo "Pruned."
        fi
    fi

    if [ "$no_vol" = 0 ] && [ "$count_vol" -gt 0 ]; then
        printf "Remove %d ops volume(s)? This deletes cached data (nix store, mise tools, ...) [y/N] " \
            "$count_vol"
        read -r answer
        if [[ "$answer" =~ ^[yY]$ ]]; then
            local -a _vol_names=()
            local entry
            for entry in "${vol_to_prune[@]}"; do
                _vol_names+=("${entry%%|*}")
            done
            if [ ${#_vol_names[@]} -gt 0 ]; then
                "$RUNTIME_BIN" volume rm "${_vol_names[@]}" >/dev/null 2>&1 || true
            fi
            echo "Volumes removed."
        fi
    fi
}

# ===========================================================================
#  cmd_config helpers — managed edits to ~/.config/ops/ops.conf
# ===========================================================================
#
# Programmatic, idempotent edits to ops.conf for /ops-setup and other tooling
# that need to manage the config file without re-implementing the parser.
# Three contracts:
#   - Atomicity: every write goes through mktemp + mv on the same filesystem,
#     so concurrent readers never observe a half-written file.
#   - Idempotency: running the same `set/unset/alias add/remove` twice is a
#     no-op on the second invocation.
#   - Preservation: comments, blank lines, and key ordering are kept; only
#     the targeted line is modified. Falls back to append when absent.

# Bash array names — when used WITHOUT a bracketed index, the scalar
# set/unset path is refused because the argv shape doesn't match (the
# user almost certainly meant a per-entry update, not "replace the whole
# array as a string"). With a bracketed index (e.g. `OPS_ALIASES[k]`)
# the same key IS accepted because that's a single-entry update which
# fits the same value-replace logic as a scalar.
_OPS_CONFIG_ARRAY_KEYS=" OPS_IMAGES OPS_DOCKERFILES OPS_CONTAINER_NAMES OPS_BUILD_ARGS OPS_ALIASES OPS_AGENT_FLAGS "

# Validate a key for `config set/get/unset`. Two accepted shapes:
#   1. Scalar:  OPS_FOO        (matches ^OPS_[A-Z][A-Z0-9_]*$)
#   2. Bracketed entry: OPS_ARRAY[index]   (the index can be any
#      [a-zA-Z0-9_-]+ — covers profile names like `arch-min`, agent
#      names like `claude`, image keys like `arch_v2`, etc.).
#
# The bracketed form is needed for direct edits to `OPS_AGENT_FLAGS[<agent>]`,
# `OPS_IMAGES[<key>]`, etc. without going through dedicated subcommands —
# it lets `/ops-setup` and other automation drive the config file with
# one consistent verb instead of growing a per-array helper for every
# new associative array we ship.
_cfg_validate_scalar_key() {
    local key="${1:-}"
    if [ -z "$key" ]; then
        echo "Error: config set/get/unset requires a KEY (got empty)" >&2
        return 1
    fi
    # Scalar form, no brackets
    if [[ "$key" =~ ^OPS_[A-Z][A-Z0-9_]*$ ]]; then
        case "$_OPS_CONFIG_ARRAY_KEYS" in
            *" $key "*)
                echo "Error: '$key' is an array — use 'config set ${key}[<index>] <value>' (per-entry) or 'config alias' for OPS_ALIASES" >&2
                return 1
                ;;
        esac
        return 0
    fi
    # Bracketed form: OPS_BASE[index]
    if [[ "$key" =~ ^OPS_[A-Z][A-Z0-9_]*\[[a-zA-Z0-9_-]+\]$ ]]; then
        return 0
    fi
    echo "Error: invalid key '$key' (must match ^OPS_[A-Z][A-Z0-9_]*\$ or ^OPS_[A-Z][A-Z0-9_]*\\[[a-zA-Z0-9_-]+\\]\$)" >&2
    return 1
}

# Extract the base array name from a bracketed key (`OPS_ALIASES[cc]` →
# `OPS_ALIASES`). Returns empty + non-zero when the key is a plain scalar.
_cfg_array_base() {
    local key="$1"
    if [[ "$key" == *\[*\]* ]]; then
        printf '%s' "${key%%\[*}"
        return 0
    fi
    return 1
}

# Validate a value for `config set`. Refuses newlines (would break the
# line-based ops.conf parser).
_cfg_validate_value() {
    local val="${1-}"
    if [[ "$val" == *$'\n'* ]] || [[ "$val" == *$'\r'* ]]; then
        echo "Error: value contains a newline (not supported in ops.conf)" >&2
        return 1
    fi
    return 0
}

# Validate an alias name. Refuses reserved subcommand names and any non-
# identifier shape — both would be unreachable through `_expand_alias`.
_cfg_validate_alias_name() {
    local name="${1:-}"
    if [ -z "$name" ]; then
        echo "Error: alias name required" >&2
        return 1
    fi
    if ! [[ "$name" =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ ]]; then
        echo "Error: invalid alias name '$name' (must match ^[a-zA-Z][a-zA-Z0-9_-]*\$)" >&2
        return 1
    fi
    case "$_OPS_RESERVED" in
        *" $name "*)
            echo "Error: '$name' is a reserved subcommand name" >&2
            return 1
            ;;
    esac
    return 0
}

# Ensure $_CONFIG_FILE exists with safe perms. Creates parent directory and
# a minimal seed header on first call. Idempotent — existing file untouched
# (only its perms are tightened to 600).
_cfg_ensure_file() {
    local dir
    dir=$(dirname "$_CONFIG_FILE")
    [ -d "$dir" ] || mkdir -p "$dir"
    if [ ! -f "$_CONFIG_FILE" ]; then
        cat > "$_CONFIG_FILE" <<'EOF'
# ops configuration file — sourced by ops.sh at startup.
# Managed by `ops config set/unset/alias`. Manual edits are preserved.
# Reference: https://github.com/gigi206/ops-cli
EOF
    fi
    chmod 600 "$_CONFIG_FILE" 2>/dev/null || true
}

# Atomic in-place rewrite of $_CONFIG_FILE. Body is read from stdin and
# becomes the new file contents on success. mktemp + mv on the same
# filesystem guarantees readers see either the old or new file, never
# a torn half.
_cfg_atomic_replace() {
    _cfg_ensure_file
    local tmp
    tmp=$(mktemp "${_CONFIG_FILE}.XXXXXX") || {
        echo "Error: cannot create temp file next to $_CONFIG_FILE" >&2
        return 3
    }
    cat > "$tmp"
    chmod 600 "$tmp" 2>/dev/null || true
    mv "$tmp" "$_CONFIG_FILE"
}

# Quote a value for safe round-trip through `source` (double-quote with
# embedded \ and " escaped).
_cfg_shellquote() {
    local val="${1-}"
    val="${val//\\/\\\\}"
    val="${val//\"/\\\"}"
    printf '"%s"' "$val"
}

# Strip surrounding "..." from a literal value read out of ops.conf.
_cfg_unquote() {
    local val="${1-}"
    if [[ "$val" =~ ^\".*\"$ ]]; then
        val="${val#\"}"
        val="${val%\"}"
        val="${val//\\\"/\"}"
        val="${val//\\\\/\\}"
    fi
    printf '%s' "$val"
}

# Read the literal value of `KEY=...` from ops.conf. Strips surrounding
# double-quotes if present. Echoes nothing and returns 1 if absent.
#
# `grep -F` (fixed string) is used so bracketed keys like
# `OPS_ALIASES[cc]` work without escaping `[` (it would otherwise open a
# regex character class). The `target` we look for is `KEY=`, anchored
# manually below: a leading-whitespace tolerance is implemented in the
# scan rather than via regex, which keeps the implementation portable to
# any awk variant.
_cfg_read_scalar() {
    local key="$1"
    [ -f "$_CONFIG_FILE" ] || return 1
    local target="${key}="
    local line
    # awk pass: skip leading whitespace, then keep lines that begin with
    # `target` literally. tail -1 picks the last assignment if the user
    # has manual duplicates (last-one-wins per shell semantics).
    line=$(awk -v target="$target" '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (substr(line, 1, length(target)) == target) {
                print
            }
        }
    ' "$_CONFIG_FILE" | tail -1)
    [ -z "$line" ] && return 1
    # Strip leading whitespace on the captured line (if any) before
    # extracting the value, so `${line#*=}` lines up with the user's
    # actual data even when the line was indented.
    line="${line#"${line%%[![:space:]]*}"}"
    local val="${line#*=}"
    _cfg_unquote "$val"
}

# Idempotent set: replace existing `KEY=…` line if present, append
# `KEY="value"` to the end of the file otherwise. Always double-quotes so
# values with spaces/$ round-trip safely through `source`.
#
# When KEY is bracketed (e.g. `OPS_ALIASES[cc]`), bootstraps the
# corresponding `declare -A <BASE>` line at end-of-file when absent —
# bash needs the declaration before the indexed assignment, otherwise
# `OPS_ALIASES[cc]=…` is silently misparsed as a string-indexed access
# on what bash thinks is an indexed array.
_cfg_set_scalar() {
    local key="$1" val="$2"
    _cfg_ensure_file
    local quoted target base
    quoted=$(_cfg_shellquote "$val")
    target="${key}="
    base=$(_cfg_array_base "$key" || true)

    # Existing line check via awk (substr — POSIX-safe over bracket chars).
    local has_line
    has_line=$(awk -v target="$target" '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (substr(line, 1, length(target)) == target) { print "yes"; exit }
        }
    ' "$_CONFIG_FILE")

    if [ "$has_line" = "yes" ]; then
        local current
        if current=$(_cfg_read_scalar "$key"); then
            if [ "$current" = "$val" ]; then
                return 0
            fi
        fi
        awk -v target="$target" -v new="${key}=${quoted}" '
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (substr(line, 1, length(target)) == target) {
                    if (!done) { print new; done=1 }
                    next
                }
                print
            }
            END { if (!done) print new }
        ' "$_CONFIG_FILE" | _cfg_atomic_replace
        return 0
    fi

    # New entry. For bracketed keys, ensure `declare -A <base>` exists in
    # the file before the indexed assignment. Append both at end-of-file
    # (the source order in ops.conf still places declare before the
    # bracketed line because we add them in that order in the heredoc).
    if [ -n "$base" ] \
       && ! grep -qE "^[[:space:]]*declare[[:space:]]+-A[[:space:]]+${base}([[:space:]]|$)" "$_CONFIG_FILE"; then
        {
            printf '\n# Associative array (managed by `ops config`)\n'
            printf 'declare -A %s\n' "$base"
            printf '%s=%s\n' "$key" "$quoted"
        } >> "$_CONFIG_FILE"
    else
        printf '%s=%s\n' "$key" "$quoted" >> "$_CONFIG_FILE"
    fi
    return 0
}

# Remove every line whose left-hand side matches `KEY=`. Idempotent when
# absent. The match uses substr() so it handles bracketed keys without
# escaping the `[`.
_cfg_unset_scalar() {
    local key="$1"
    [ -f "$_CONFIG_FILE" ] || return 0
    local target="${key}="
    local has_line
    has_line=$(awk -v target="$target" '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (substr(line, 1, length(target)) == target) { print "yes"; exit }
        }
    ' "$_CONFIG_FILE")
    [ "$has_line" != "yes" ] && return 0
    awk -v target="$target" '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (substr(line, 1, length(target)) != target) {
                print
            }
        }
    ' "$_CONFIG_FILE" | _cfg_atomic_replace
}

# Add or update `OPS_ALIASES[name]="argv"`. Thin wrapper around the
# generalized scalar setter — the bracketed-key path of _cfg_set_scalar
# handles the `declare -A OPS_ALIASES` bootstrap, the substr-based line
# match, and idempotency. Kept as its own function so the cmd_config
# `alias add NAME ARGV` dispatcher can reuse it cleanly without the
# caller having to compose `OPS_ALIASES[<name>]` itself.
_cfg_alias_set() {
    local name="$1" argv="$2"
    _cfg_set_scalar "OPS_ALIASES[${name}]" "$argv"
}

# Remove `OPS_ALIASES[name]=…`. Thin wrapper around the generalized
# scalar unsetter; same substr-based match handles the bracketed key.
_cfg_alias_unset() {
    local name="$1"
    _cfg_unset_scalar "OPS_ALIASES[${name}]"
}

# Validate a secret key name. Stricter than _cfg_validate_scalar_key (which
# requires the OPS_ prefix): secrets cover both OPS_* knobs and
# auto-propagated host vars (GITHUB_TOKEN, ANTHROPIC_API_KEY, …) so any
# upper-case shell identifier is accepted.
_cfg_validate_secret_key() {
    local key="${1:-}"
    if [ -z "$key" ]; then
        echo "Error: secret key required" >&2
        return 1
    fi
    if ! [[ "$key" =~ ^[A-Z_][A-Z0-9_]*$ ]]; then
        echo "Error: invalid secret key '$key' (must match ^[A-Z_][A-Z0-9_]*\$)" >&2
        return 1
    fi
    return 0
}

# Read the literal value of `export KEY=...` from ops.conf. Used internally
# for idempotency checks; never echoed via the user-facing list command.
_cfg_read_secret() {
    local key="$1"
    [ -f "$_CONFIG_FILE" ] || return 1
    local line
    line=$(grep -E "^[[:space:]]*export[[:space:]]+${key}=" "$_CONFIG_FILE" | tail -1)
    [ -z "$line" ] && return 1
    local val="${line#*=}"
    _cfg_unquote "$val"
}

# Add or update `export KEY="value"` in ops.conf. Idempotent when the same
# value is already stored. chmod 600 is enforced after every mutation.
_cfg_secret_set() {
    local key="$1" val="$2"
    _cfg_ensure_file
    local quoted target
    quoted=$(_cfg_shellquote "$val")
    target="export ${key}="

    if grep -qE "^[[:space:]]*export[[:space:]]+${key}=" "$_CONFIG_FILE"; then
        local current
        if current=$(_cfg_read_secret "$key"); then
            if [ "$current" = "$val" ]; then
                chmod 600 "$_CONFIG_FILE" 2>/dev/null || true
                return 0
            fi
        fi
        awk -v target="$target" -v new="export ${key}=${quoted}" '
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (substr(line, 1, length(target)) == target) {
                    if (!done) { print new; done=1 }
                    next
                }
                print
            }
            END { if (!done) print new }
        ' "$_CONFIG_FILE" | _cfg_atomic_replace
    else
        printf 'export %s=%s\n' "$key" "$quoted" >> "$_CONFIG_FILE"
    fi
    chmod 600 "$_CONFIG_FILE" 2>/dev/null || true
}

# Remove every `export KEY=...` line. Idempotent when absent.
_cfg_secret_unset() {
    local key="$1"
    [ -f "$_CONFIG_FILE" ] || return 0
    local target="export ${key}="
    if ! grep -qF "$target" "$_CONFIG_FILE"; then
        return 0
    fi
    awk -v target="$target" '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (substr(line, 1, length(target)) != target) {
                print
            }
        }
    ' "$_CONFIG_FILE" | _cfg_atomic_replace
}

# List every `export KEY` line, names only — values must NEVER be emitted.
# Output is sorted + de-duplicated to keep the snapshot stable when
# secrets were re-set (which leaves the line in place but the order
# may shift if the user manually edited the file in between).
_cfg_secret_list() {
    [ -f "$_CONFIG_FILE" ] || return 0
    grep -oE '^[[:space:]]*export[[:space:]]+[A-Z_][A-Z0-9_]*' "$_CONFIG_FILE" \
        | awk '{print $NF}' \
        | sort -u
}

cmd_config() {
    case "${1:-}" in
        -h|--help)
            cat <<EOF
Usage: $(basename "$0") config [SUBCOMMAND]

Without a subcommand, dump the effective OPS_* configuration with origin
tagging:
  [env]     defined before ops.sh sourced the config file
  [config]  defined by \$_CONFIG_FILE
  [default] assigned by a :- fallback in ops.sh

Two sections in the dump:
  Scalars   — every OPS_* simple variable with its resolved value + origin
  Arrays    — OPS_IMAGES / OPS_DOCKERFILES / OPS_CONTAINER_NAMES /
              OPS_BUILD_ARGS / OPS_ALIASES / OPS_VOLUMES

Subcommands (managed edits to \$_CONFIG_FILE — atomic, idempotent,
preserve comments and ordering):
  set KEY VALUE              Set or replace OPS_KEY="VALUE". KEY accepts
                             both scalars (OPS_RUNTIME) and bracketed
                             entries (OPS_AGENT_FLAGS[claude],
                             OPS_IMAGES[debian]). Bracketed keys auto-
                             bootstrap 'declare -A <BASE>' when missing.
  get KEY                    Read KEY's literal value from ops.conf
                             (exit 1 if unset). KEY accepts the same
                             two shapes as 'set'.
  unset KEY                  Remove KEY from ops.conf. Bracketed form
                             removes only that entry; the surrounding
                             'declare -A' line is left untouched.
  alias add NAME 'argv...'   Shortcut for 'set OPS_ALIASES[NAME] argv...'
  alias remove NAME          Shortcut for 'unset OPS_ALIASES[NAME]'
  secret add NAME [--from-env|--from-stdin|--from-prompt]
                             Add 'export NAME="..."' (chmod 600 enforced)
  secret list                Print secret names (values are never shown)
  secret remove NAME         Remove the secret entry

Examples:
  ops config set OPS_RUNTIME docker
  ops config set OPS_DEFAULT_RUN_FLAGS "--no-rm --no-wayland"
  ops config set 'OPS_AGENT_FLAGS[claude]' "--claude-volume --install"
  ops config set 'OPS_IMAGES[debian]' "localhost/ops-dev-debian"
  ops config get OPS_RUNTIME
  ops config get 'OPS_AGENT_FLAGS[claude]'
  ops config unset 'OPS_AGENT_FLAGS[claude]'
  ops config alias add cc 'run --claude'
  ops config alias remove cc
  ops config secret add GITHUB_TOKEN --from-env
  ops config secret list
  ops config secret remove GITHUB_TOKEN

Edits create the file (chmod 600) and the parent directory if missing.
'config' (no subcommand) does not start the runtime — safe in scripts.
EOF
            return 0
            ;;
        set)
            shift
            local _set_key _set_val
            _set_key="${1:-}"
            _set_val="${2-}"
            if [ $# -lt 2 ]; then
                echo "Error: 'config set' requires KEY VALUE" >&2
                return 1
            fi
            _cfg_validate_scalar_key "$_set_key" || return 1
            _cfg_validate_value "$_set_val" || return 1
            _cfg_set_scalar "$_set_key" "$_set_val"
            return 0
            ;;
        get)
            shift
            local _get_key="${1:-}"
            _cfg_validate_scalar_key "$_get_key" || return 1
            local _get_val
            if _get_val=$(_cfg_read_scalar "$_get_key"); then
                printf '%s\n' "$_get_val"
                return 0
            fi
            echo "Error: $_get_key is not set in $_CONFIG_FILE" >&2
            return 1
            ;;
        unset)
            shift
            local _u_key="${1:-}"
            _cfg_validate_scalar_key "$_u_key" || return 1
            _cfg_unset_scalar "$_u_key"
            return 0
            ;;
        alias)
            shift
            local _a_action="${1:-}"
            case "$_a_action" in
                add)
                    shift
                    if [ $# -lt 2 ]; then
                        echo "Error: 'config alias add' requires NAME ARGV" >&2
                        return 1
                    fi
                    local _a_name="${1:-}" _a_argv="${2-}"
                    _cfg_validate_alias_name "$_a_name" || return 1
                    if [ -z "$_a_argv" ]; then
                        echo "Error: alias argv must be non-empty" >&2
                        return 1
                    fi
                    _cfg_alias_set "$_a_name" "$_a_argv"
                    return 0
                    ;;
                remove|rm)
                    shift
                    local _ar_name="${1:-}"
                    _cfg_validate_alias_name "$_ar_name" || return 1
                    _cfg_alias_unset "$_ar_name"
                    return 0
                    ;;
                ""|-h|--help)
                    cat <<EOF
Usage: $(basename "$0") config alias <add|remove> NAME ['argv...']

  add NAME 'argv...'  Add or replace OPS_ALIASES[NAME]="argv..."
  remove NAME         Remove OPS_ALIASES[NAME] (idempotent)

Reserved names (built-in subcommands) are rejected. Valid name shape:
  ^[a-zA-Z][a-zA-Z0-9_-]*\$
EOF
                    return 0
                    ;;
                *)
                    echo "Error: 'config alias' subcommand: 'add' or 'remove' (got '$_a_action')" >&2
                    return 1
                    ;;
            esac
            ;;
        secret)
            shift
            local _s_action="${1:-}"
            case "$_s_action" in
                add)
                    shift
                    local _s_name="${1:-}"
                    _cfg_validate_secret_key "$_s_name" || return 1
                    shift || true
                    # Source mode: env var, stdin, or interactive (default).
                    # Interactive uses `read -rs` which only works on a TTY;
                    # tests should rely on --from-env or --from-stdin.
                    local _s_source="prompt"
                    case "${1:-}" in
                        --from-env)    _s_source="env" ;;
                        --from-stdin)  _s_source="stdin" ;;
                        --from-prompt|"") _s_source="prompt" ;;
                        *)
                            echo "Error: unknown 'config secret add' option '$1'" >&2
                            return 1
                            ;;
                    esac
                    local _s_value=""
                    case "$_s_source" in
                        env)
                            # Read from the pre-source snapshot so we don't
                            # silently echo back the value ops.conf already
                            # carries (which would defeat `add` entirely
                            # when the user intends to ROTATE the secret).
                            if [ -n "${_PRE_SOURCE_ENV[$_s_name]+set}" ] && [ -n "${_PRE_SOURCE_ENV[$_s_name]}" ]; then
                                _s_value="${_PRE_SOURCE_ENV[$_s_name]}"
                            elif [ -n "${!_s_name:-}" ]; then
                                _s_value="${!_s_name}"
                            else
                                echo "Error: $_s_name is not set in the environment (run 'export $_s_name=...' first, or use --from-stdin)" >&2
                                return 1
                            fi
                            ;;
                        stdin)
                            IFS= read -r _s_value || true
                            ;;
                        prompt)
                            printf 'Enter value for %s (input hidden): ' "$_s_name" >&2
                            IFS= read -rs _s_value
                            printf '\n' >&2
                            ;;
                    esac
                    if [ -z "$_s_value" ]; then
                        echo "Error: empty secret value rejected" >&2
                        return 1
                    fi
                    _cfg_validate_value "$_s_value" || return 1
                    _cfg_secret_set "$_s_name" "$_s_value"
                    return 0
                    ;;
                remove|rm)
                    shift
                    local _sr_name="${1:-}"
                    _cfg_validate_secret_key "$_sr_name" || return 1
                    _cfg_secret_unset "$_sr_name"
                    return 0
                    ;;
                list|ls)
                    _cfg_secret_list
                    return 0
                    ;;
                ""|-h|--help)
                    cat <<EOF
Usage: $(basename "$0") config secret <add|list|remove> [NAME] [SOURCE]

  add NAME [--from-env|--from-stdin|--from-prompt]
        Add or replace 'export NAME="value"' in \$_CONFIG_FILE.
        Default source: interactive prompt with hidden input.
        --from-env reads \$NAME from the calling shell.
        --from-stdin reads one line from stdin (newline-terminated).

  list  Print every secret NAME in alphabetic order. Values are NEVER
        emitted — list is safe to pipe to logs or share publicly.

  remove NAME
        Remove 'export NAME=...' from the config file (idempotent).

The config file is chmod 600 after every mutation. Empty values are
rejected (use 'config unset' if you want to delete the entry).
EOF
                    return 0
                    ;;
                *)
                    echo "Error: 'config secret' subcommand: 'add', 'list', or 'remove' (got '$_s_action')" >&2
                    return 1
                    ;;
            esac
            ;;
    esac
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
    for v in OPS_IMAGES OPS_DOCKERFILES OPS_CONTAINER_NAMES OPS_BUILD_ARGS OPS_ALIASES OPS_VOLUMES; do
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
    case "${1:-}" in
        -h|--help)
            cat <<EOF
Usage: $(basename "$0") inspect <KEY>

Show detailed info for KEY. The argument is resolved in this order:
  1. OPS_IMAGES[KEY]       → treated as an image profile (ref + Dockerfile + container)
  2. Container named KEY   → existing ops container (label or name match)
  3. Raw image reference   → any image the runtime knows about

Output:
  Image section:     ref, ops-key (if profile), size, created, dockerfile label
  Container section: name, image, coloured state, cmd, ops cli, real cli
  Mounts section:    bind / volume → destination

Exits 1 if KEY resolves to none of the three.
EOF
            return 0
            ;;
    esac
    local key="${1:-}"
    if [ -z "$key" ]; then
        echo "Usage: $(basename "$0") inspect <key|container|image-ref>  (see --help for details)" >&2
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
    case "${1:-}" in
        -h|--help)
            cat <<EOF
Usage: $(basename "$0") update [KEY]

Rebuild an ops image and offer to recreate containers running on the
previous layer. Post-build flow is identical to 'build'; the only
difference is the KEY pre-resolution:

  $(basename "$0") update              → rebuilds the active/default image
  $(basename "$0") update <KEY>        → resolves OPS_IMAGES[<KEY>] first
                                          (image + Dockerfile + container),
                                          then builds

After a successful build, compares the new image ID to the previous one.
If they differ, lists every container still on the old ID with its
'ops.cmdline.user' label (relaunch hint), then offers a [y/N] prompt to
remove them. Relaunch is manual — containers on the old layer stay
around otherwise.

No flags. To force a no-cache rebuild, use 'ops run --build --no-cache'
(or the alias 'ops build --no-cache').
EOF
            return 0
            ;;
    esac
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
    case "${1:-}" in
        -h|--help)
            cat <<EOF
Usage: $(basename "$0") backup <VOLUME> > FILE.tar.gz

Stream a runtime volume as a gzip-compressed tar archive to stdout. An
ephemeral alpine container bind-mounts the volume read-only, pipes tar to
stdout, and exits.

The stdout redirect is REQUIRED — writing a binary tarball to a TTY is
almost always a mistake, so the command refuses when stdout is a terminal.
Override (rarely needed) with OPS_FORCE_TTY=1.

Examples:
  $(basename "$0") backup ops-share-nix > nix-\$(date +%F).tar.gz
  $(basename "$0") backup ops-share-mise | ssh other './ops.sh restore ops-share-mise'

Exits 1 if the volume doesn't exist or stdout is a TTY (and OPS_FORCE_TTY
isn't set).
EOF
            return 0
            ;;
    esac
    local vol="${1:-}"
    if [ -z "$vol" ]; then
        echo "Usage: $(basename "$0") backup <volume-name> > backup.tar.gz  (see --help)" >&2
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
    case "${1:-}" in
        -h|--help)
            cat <<EOF
Usage: $(basename "$0") restore <VOLUME> < FILE.tar.gz

Restore a gzip-compressed tar archive from stdin into a runtime volume. An
ephemeral alpine container mounts the volume read-write, pipes tar from
stdin, and exits. The target volume is created automatically (with the
ops.volume=true label) if it doesn't exist.

The stdin redirect is REQUIRED — an empty stdin on a TTY is almost always
a mistake, so the command refuses when stdin is a terminal.

Examples:
  $(basename "$0") restore ops-share-nix < nix-2026-04-23.tar.gz
  ssh other './ops.sh backup ops-share-mise' | $(basename "$0") restore ops-share-mise

Exits 1 on missing argument or TTY stdin.
EOF
            return 0
            ;;
    esac
    local vol="${1:-}"
    if [ -z "$vol" ]; then
        echo "Usage: $(basename "$0") restore <volume-name> < backup.tar.gz  (see --help)" >&2
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
    local fix=0
    while [ $# -gt 0 ]; do
        case "$1" in
            -h|--help)
                cat <<EOF
Usage: $(basename "$0") doctor [--fix]

Validate OPS_IMAGES ↔ Dockerfile ↔ image label ↔ container coherence.
Intended as a pre-build scripting hook (see Exit codes below):

  ops doctor >/dev/null && ops build   # only build if config is clean

Checks performed:
  Config     config file presence at \$_CONFIG_FILE
  OPS_IMAGES each key has a resolvable Dockerfile:
               OPS_DOCKERFILES[key], else \$SCRIPT_DIR/Dockerfile.<key>
             each key's image is built, and its ops.dockerfile label
             matches the Dockerfile declared for that key
  Dangling   OPS_DOCKERFILES[k] / OPS_CONTAINER_NAMES[k] without OPS_IMAGES[k]
  Containers labelled ops.container=true — orphans (image gone), image
             mismatches (container image != OPS_IMAGES[key])

Options:
  --fix      After the diagnostic, print the concrete commands you should
             run to address each warning. Suggestions only — nothing is
             executed automatically (auto-execution would risk destructive
             actions like 'rm' on the wrong container).

Exit codes:
  0    no warnings
  1    at least one warning

Doctor queries the runtime (image/container inspect) so it needs a
working runtime context (unlike 'config' which doesn't).
EOF
                return 0
                ;;
            --fix) fix=1; shift ;;
            *) echo "Error: unknown 'doctor' option '$1'" >&2; return 1 ;;
        esac
    done
    local ok=0 warn=0 k ref declared_df labeled_df declared_abs
    # Suggested fixes collected by _doc_warn's optional 2nd arg. Displayed
    # under "Suggested fixes" at the end of the diagnostic when --fix is
    # passed; ignored otherwise (so the legacy invocation stays terse).
    local -a _fix_suggestions=()
    _doc_ok()   { printf '    \033[32m✓\033[0m %s\n' "$1"; ok=$((ok+1)); }
    _doc_warn() {
        printf '    \033[33m⚠\033[0m %s\n' "$1"
        warn=$((warn+1))
        [ -n "${2:-}" ] && _fix_suggestions+=("$2")
    }

    echo -e "\033[1;34m=== Config ===\033[0m"
    if [ -f "$_CONFIG_FILE" ]; then
        _doc_ok "config file: $_CONFIG_FILE"
    else
        _doc_warn "config file missing: $_CONFIG_FILE" \
                  "$(basename "$0") config set OPS_RUNTIME auto"
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
                _doc_warn "image not built: $ref (run: $(basename "$0") -i $k build)" \
                          "$(basename "$0") -i $k build"
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
            _doc_warn "container '$ctn': image '$ctn_img' no longer exists (orphan)" \
                      "$(basename "$0") runtime rm -f $ctn"
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

    # `--fix` mode: surface the concrete commands the user can run to
    # resolve each warning. Auto-execution is intentionally NOT done — a
    # blanket `ops clean` or `runtime rm -f` triggered by --fix could nuke
    # working containers if the diagnostic mis-classified them. Suggesting
    # the commands keeps the user as the final authority.
    if [ "$fix" = 1 ] && [ ${#_fix_suggestions[@]} -gt 0 ]; then
        echo -e "\n\033[1;34m=== Suggested fixes ===\033[0m"
        local _f
        for _f in "${_fix_suggestions[@]}"; do
            printf '    \033[36m$\033[0m %s\n' "$_f"
        done
        echo -e "    \033[2m(suggestions only — review and run manually)\033[0m"
    fi

    unset -f _doc_ok _doc_warn
    [ "$warn" -gt 0 ] && return 1 || return 0
}

# Top-level `ops self-update` — updates ops-cli itself by re-execing
# install.sh in place. Distinct from `ops nerdctl self-update` (which
# targets the nerdctl binary) and from `ops update [KEY]` (which
# rebuilds an image).
#
# Implemented as a thin re-exec of install.sh so all the resolution
# logic (default ref = latest vX.Y.Z tag, idempotent fetch+checkout,
# in-place upgrade/downgrade, untracked files preserved) lives in one
# place. The caller's OPS_REPO_URL / OPS_BIN_DIR overrides apply
# automatically if exported.
#
# Heads-up: install.sh's update path runs `git checkout --force` on
# the working tree, which discards local edits to tracked files. Any
# uncommitted changes the user has in $SCRIPT_DIR will disappear. That
# is intentional (the install dir is treated as installer-managed) but
# worth flagging if a contributor runs self-update on their dev clone.
cmd_update_self() {
    local force=0
    local check=0
    # Hand-rolled flag parsing: --force / -f and --check / -c are accepted
    # before the optional REF positional. Anything else either matches REF
    # (single token) or trips the help block. We don't need getopt here.
    while [ $# -gt 0 ]; do
        case "$1" in
            -h|--help)
                cat <<EOF
Usage: $(basename "$0") self-update [--check] [--force] [REF]

Update the ops-cli installation in place. REF is anything understood by
git: a tag (e.g. v1.0.0), a branch (main), or a commit SHA. When REF is
omitted, the latest vX.Y.Z tag is auto-resolved from the configured
remote (fallback: main).

Re-execs install.sh under the hood, so the same OPS_REPO_URL /
OPS_BIN_DIR overrides apply if exported beforehand.

Options:
  -c, --check    Preview what an update would do (current vs target ref +
                 action label) without touching the filesystem. Composes
                 with REF to preview a specific tag/branch:
                   ops self-update --check        # latest tag
                   ops self-update --check main   # would switch to main
                 Skips the dirty-tree safety check (no harm in previewing
                 from a dirty clone).

  -f, --force    Bypass the dirty-working-tree safety check.
                 Without it, self-update refuses when \$SCRIPT_DIR has
                 uncommitted changes — those would be silently discarded
                 by install.sh's 'git checkout --force' (lesson learned
                 the hard way during dev). Use this when you really want
                 a forced reinstall, or when the lingering changes are
                 known to be disposable. Ignored when --check is set.

Warning: even without --force, install.sh discards local edits to
tracked files (it always checks out with --force). Untracked files are
always preserved.

Examples:
  $(basename "$0") self-update                  # latest stable tag
  $(basename "$0") self-update --check          # preview the latest tag
  $(basename "$0") self-update --check main     # preview switch to main
  $(basename "$0") self-update main             # track main
  $(basename "$0") self-update v1.0.0           # downgrade to v1.0.0
  $(basename "$0") self-update --force          # skip the dirty-tree check
EOF
                return 0
                ;;
            -c|--check) check=1; shift ;;
            -f|--force) force=1; shift ;;
            --) shift; break ;;
            -*) echo "self-update: unknown flag: $1" >&2; exit 1 ;;
            *) break ;;
        esac
    done
    local target_ref="${1:-}"

    if [ ! -d "$SCRIPT_DIR/.git" ]; then
        echo "self-update: $SCRIPT_DIR is not a git checkout (ops.sh installed manually?)" >&2
        echo "             Reinstall via:" >&2
        echo "               curl -fsSL https://raw.githubusercontent.com/gigi206/ops-cli/main/install.sh | sh" >&2
        exit 1
    fi
    if [ ! -x "$SCRIPT_DIR/install.sh" ]; then
        echo "self-update: $SCRIPT_DIR/install.sh is missing — your checkout predates the installer." >&2
        echo "             Update manually: git -C \"$SCRIPT_DIR\" pull" >&2
        exit 1
    fi

    # Dirty-working-tree safety. install.sh runs 'git checkout --force',
    # which silently discards staged + unstaged edits to tracked files.
    # Refuse if the user has any such edits, unless they pass --force.
    # We use 'git status --porcelain' over 'git diff --quiet' because
    # the former also catches staged-but-not-committed changes (which
    # 'git diff' alone misses without --cached). Untracked files are
    # NOT a concern — install.sh's checkout leaves them alone.
    # Skipped entirely under --check (no checkout = no risk).
    if [ "$check" -ne 1 ] && [ "$force" -ne 1 ]; then
        local _dirty
        _dirty=$(git -C "$SCRIPT_DIR" status --porcelain --untracked-files=no 2>/dev/null)
        if [ -n "$_dirty" ]; then
            echo "self-update: $SCRIPT_DIR has uncommitted changes — refusing." >&2
            echo "             Without --force, install.sh's 'git checkout --force'" >&2
            echo "             would discard them silently. Commit or stash first," >&2
            echo "             or pass --force to proceed anyway." >&2
            echo "             Files:" >&2
            printf '%s\n' "$_dirty" | sed 's/^/               /' >&2
            exit 1
        fi
    fi

    if [ "$check" -eq 1 ]; then
        OPS_CHECK=1 OPS_REF="$target_ref" OPS_INSTALL_DIR="$SCRIPT_DIR" exec sh "$SCRIPT_DIR/install.sh"
    fi

    OPS_REF="$target_ref" OPS_INSTALL_DIR="$SCRIPT_DIR" exec sh "$SCRIPT_DIR/install.sh"
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
    latest_version="$(_fetch_github_latest_tag "containerd/nerdctl")"
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

# Emits extra argv tokens to inject AFTER consuming `--<agent>` from the
# user's argv. Two sources, both optional:
#
#   1. OPS_ISOLATION_PRESET=volume|fully-isolated
#      → auto-add `--<agent>-volume` so the agent's credentials live in
#        the named Docker volume `ops-<agent>` instead of the host's
#        ~/.<agent>. Skipped when the user already pinned the per-agent
#        mode via --<agent>-mount / --<agent>-volume / --no-<agent>-mount
#        (which sets <agent>_agent ≠ "auto").
#
#   2. OPS_AGENT_FLAGS[<agent>]="--no-rm --install"
#      → user-defined flags appended to every `--<agent>` invocation.
#
# Output is whitespace-delimited (one token per word). The caller does
# `set -- $(_agent_run_extras claude) "$@"` so the new tokens land at
# the head of the remaining argv and are parsed by the next loop turn.
_agent_run_extras() {
    local agent="$1"
    case "${OPS_ISOLATION_PRESET:-host}" in
        volume|fully-isolated)
            local var="${agent}_agent"
            if [ "${!var:-auto}" = "auto" ]; then
                printf '%s\n' "--${agent}-volume"
            fi
            ;;
    esac
    if declare -p OPS_AGENT_FLAGS >/dev/null 2>&1 && [ -n "${OPS_AGENT_FLAGS[$agent]:-}" ]; then
        printf '%s\n' "${OPS_AGENT_FLAGS[$agent]}"
    fi
}

_agent_cmd() {
    local bin="$1" pkg="$2"
    # `command -v` (PATH lookup, ~0 ms) instead of `mise which` (~5–17 s
    # to boot the full mise toolset + plugin hooks) for the warm-path
    # check. Once `mise use -g` has populated the install dir, the
    # bashrc cache regen at the next container start adds it to PATH —
    # so `command -v $bin` resolves directly to the real binary, not
    # the mise shim, and we exec it without any mise re-bootstrap.
    #
    # Why this is safe now: opencode used to hang at cold launch when
    # we bypassed the mise shim, because the shim's mise-bootstrap
    # side effects were load-bearing (extracting the Bun watcher
    # binding). We worked around it by switching opencode from
    # `github:sst/opencode` (Bun single-binary) to `npm:opencode-ai`
    # (regular Node.js package), which doesn't depend on Bun's
    # virtual-filesystem extraction at all. claude / gemini / codex
    # are also npm:* packages and never had the issue.
    #
    # Cold-path UX:
    #   - `printf '==> Installing $bin …'` BEFORE the `command -v`
    #     check so it shows up immediately when the user lands on a
    #     fresh container — not after a 10 s silent mise-which delay.
    #     Done in the same `||` arm so it only fires when an install
    #     actually runs (warm path stays silent).
    #   - `clear` after install, before `exec`, so the agent's TUI
    #     starts in a clean terminal (mise's spinner / final `tools:`
    #     line / `gem sources` warning would otherwise remain in the
    #     scrollback above the TUI).
    #   - `clear 2>/dev/null || true` keeps the chain alive if
    #     terminfo is missing (rare but defensive).
    # `printf '%s\n'` instead of `echo` so the embedded `\033` ANSI
    # escape stays literal in the rendered command line (bash inside
    # the container re-evaluates it via the inner `printf`). echo
    # would also work but trips shellcheck SC2028.
    # `__ops_refresh_cache` (defined in /etc/ops-bashrc) regenerates the
    # bashrc shell-env cache after `mise use -g`. Without it, the next
    # `./ops.sh run --<agent>` sees the bumped `/opt/mise/data/config/
    # config.toml` mtime > cache mtime, runs `mise hook-env` for ~8 s,
    # and the user perceives a slow 2nd run before the cache stabilizes.
    case "$pkg" in
        npm:*) printf '%s\n' "command -v $bin >/dev/null 2>&1 || { printf '\\033[1;34m==> Installing %s (first run, this may take a minute)...\\033[0m\\n' $bin >&2; mise use -g node@lts; mise use -g $pkg; __ops_refresh_cache; clear 2>/dev/null || true; }; exec $bin \"\$@\"" ;;
        *)     printf '%s\n' "command -v $bin >/dev/null 2>&1 || { printf '\\033[1;34m==> Installing %s (first run, this may take a minute)...\\033[0m\\n' $bin >&2; mise use -g $pkg; __ops_refresh_cache; clear 2>/dev/null || true; }; exec $bin \"\$@\"" ;;
    esac
}

ensure_volume() {
    "$RUNTIME_BIN" --log-level error volume create --label ops.volume=true "$1" >/dev/null 2>&1 || true
}

# One-time (idempotent) migration: make sure the mise-nix plugin inside the
# named volume is served as a symlink pointing to the image-baked path
# /opt/ops/mise-plugin/nix (see Dockerfile section 5 for the rationale).
#
# Why: the volume mounted on /opt/mise/data masks the image layer at the
# same path. Before this refactor, the plugin was copied under
# /opt/mise/data/plugins/nix/ directly, so the first run populated the
# volume with the plugin contents AND every subsequent rebuild of the
# plugin was invisible -- the volume kept the stale copy forever.
# Now the image ships the plugin at /opt/ops/mise-plugin/nix/ (OUTSIDE
# the volume) and places a symlink at /opt/mise/data/plugins/nix -> that
# path. Fresh volumes inherit the symlink automatically. Pre-existing
# volumes carry a plain directory; this function detects that and
# replaces it with the symlink. Costs ~200 ms once per volume lifetime.
_ensure_mise_plugin_symlink() {
    local volume="$1"
    # Fast-path: we already migrated (or confirmed clean) this volume in
    # a previous ops.sh invocation. The marker is a per-host, per-volume
    # file under XDG_STATE_HOME. Skipping here saves ~1.5 s (the cost of
    # the throwaway alpine container below) on every subsequent `ops run`.
    # OPS_SKIP_PLUGIN_MIGRATION_CHECK=1 is an escape hatch for debugging.
    local state_dir="${XDG_STATE_HOME:-$HOME/.local/state}/ops"
    local marker="$state_dir/plugin-symlink.$volume"
    if [ -f "$marker" ] && [ "${OPS_SKIP_PLUGIN_MIGRATION_CHECK:-0}" != "1" ]; then
        return 0
    fi

    # Probe the current state of /plugins/nix inside the volume. Uses a
    # throwaway alpine container so we don't need the (heavy) ops-dev
    # image here.
    local kind
    kind=$("$RUNTIME_BIN" run --rm -v "$volume":/data alpine sh -c '
        if   [ -L /data/plugins/nix ]; then echo symlink
        elif [ -d /data/plugins/nix ]; then echo dir
        else                                echo absent
        fi' 2>/dev/null) || return 0  # runtime/image unavailable → skip, non-fatal
    case "$kind" in
        symlink)
            # Already migrated. Set the marker so next run short-circuits.
            { mkdir -p "$state_dir" && touch "$marker"; } 2>/dev/null || true
            ;;
        absent)
            # Volume is empty (freshly created, or just wiped with
            # `docker volume rm`). Leave it alone: writing anything here
            # would make Docker skip the auto-populate step at the first
            # mount of the ops-dev image, and the volume would end up
            # without config/, installs/, shims/, cache/ -- a broken
            # state. Docker itself copies the image's /opt/mise/data/
            # contents (symlink included) on the first real mount.
            # NOT touching the marker here -- we want to re-probe on the
            # next run (after Docker populates the volume) to confirm the
            # symlink landed and then memoize.
            ;;
        dir)
            # Pre-existing volume from before the symlink refactor: plugin
            # files were copied directly under /data/plugins/nix/ and now
            # mask the image's updated code. Replace the directory with
            # the symlink so rebuilds take effect.
            echo "Migrating $volume: legacy plugin directory → symlink (one-time)" >&2
            if "$RUNTIME_BIN" run --rm -v "$volume":/data alpine sh -c '
                rm -rf /data/plugins/nix && \
                mkdir -p /data/plugins && \
                ln -s /opt/ops/mise-plugin/nix /data/plugins/nix' >/dev/null 2>&1; then
                { mkdir -p "$state_dir" && touch "$marker"; } 2>/dev/null || true
            fi
            ;;
    esac
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

# Agent-flag dispatcher used by cmd_run's argv loop.
# Recognised flags (X ∈ {claude, gemini, opencode, codex}):
#   --no-X-mount  → ${X}_agent="off"
#   --X-mount     → ${X}_agent="mount"
#   --X-volume    → ${X}_agent="volume"
# Returns 0 + sets the matching local in the caller's scope (dynamic
# scoping makes ${X}_agent visible from here), 1 otherwise. Replaces 12
# repetitive case-branches in cmd_run with a single dispatch line.
_match_agent_flag() {
    local flag="$1" agent state
    case "$flag" in
        --no-claude-mount|--no-gemini-mount|--no-opencode-mount|--no-codex-mount)
            agent="${flag#--no-}"; agent="${agent%-mount}"; state="off" ;;
        --claude-mount|--gemini-mount|--opencode-mount|--codex-mount)
            agent="${flag#--}";    agent="${agent%-mount}"; state="mount" ;;
        --claude-volume|--gemini-volume|--opencode-volume|--codex-volume)
            agent="${flag#--}";    agent="${agent%-volume}"; state="volume" ;;
        *) return 1 ;;
    esac
    # nameref into the caller's locals (claude_agent / gemini_agent / …).
    local -n _agent_ref="${agent}_agent"
    _agent_ref="$state"
    return 0
}

# Multi-session lifecycle helpers (shepherd pattern).
#
# Background: prior to v1.11 each `ops run` was the PID 1 of a `--rm`
# container. Two parallel sessions therefore shared one PID 1, and quitting
# the first session removed the container — killing every other `docker
# exec` attached to it. The shepherd pattern fixes that by making PID 1
# a long-lived placeholder (`tail -f /dev/null` under tini) and turning
# every interactive session — including the very first one — into a
# `docker exec`. Quitting any single session no longer affects the
# others; the container is removed only when the LAST session exits
# (and only when the user did not pass `--no-rm`).
#
# Sessions register a per-host-PID marker file inside the container at
# /tmp/ops-sessions/. The host-side trap removes it on exit and, for
# ephemeral containers, calls `docker rm -f` once the directory is empty.
# A SIGKILL that bypasses the trap leaves the marker behind; the next
# session's entry sweep removes any marker whose host PID is no longer
# alive (kill -0), so the directory eventually drains.
_ops_register_session() {
    local name="$1" sid="$2"
    "$RUNTIME_BIN" exec "$name" sh -c \
        "mkdir -p /tmp/ops-sessions && touch /tmp/ops-sessions/$sid" \
        >/dev/null 2>&1 || true
}

_ops_sweep_orphan_sessions() {
    # Drop markers whose host PID is no longer alive (i.e. a previous
    # session was SIGKILL'd before its trap could clean up). The PID
    # check is host-side: the marker name encodes the host PID, the
    # container itself can't see the host process table.
    #
    # `[ -d /proc/$pid ]` is preferred over `kill -0`: kill -0 returns
    # EPERM (and exits non-zero) when the target PID belongs to a
    # different user (e.g. root-owned init or another user's session),
    # which would mis-classify a still-alive marker as orphaned. The
    # /proc check only requires the directory to exist — it succeeds
    # for any visible PID regardless of the caller's UID. ops-cli is
    # Linux-only so /proc is guaranteed.
    local name="$1" markers m pid
    markers=$("$RUNTIME_BIN" exec "$name" sh -c \
        'ls /tmp/ops-sessions 2>/dev/null' 2>/dev/null || true)
    for m in $markers; do
        case "$m" in
            ops-session-*) pid="${m#ops-session-}" ;;
            *) continue ;;
        esac
        if [ ! -d "/proc/$pid" ]; then
            "$RUNTIME_BIN" exec "$name" \
                rm -f "/tmp/ops-sessions/$m" >/dev/null 2>&1 || true
        fi
    done
}

_ops_cleanup_session() {
    # Run from a host-side EXIT trap: drop the session's marker, then —
    # for ephemeral containers — remove the container if the marker
    # directory is now empty (i.e. we were the last session).
    local name="$1" sid="$2" eph="$3" count
    "$RUNTIME_BIN" exec "$name" \
        rm -f "/tmp/ops-sessions/$sid" >/dev/null 2>&1 || true
    [ "$eph" = 1 ] || return 0
    count=$("$RUNTIME_BIN" exec "$name" sh -c \
        'ls /tmp/ops-sessions 2>/dev/null | wc -l' 2>/dev/null || echo 0)
    count=$(printf '%s' "$count" | tr -d '[:space:]')
    if [ "${count:-0}" = 0 ]; then
        "$RUNTIME_BIN" rm -f "$name" >/dev/null 2>&1 || true
    fi
}

cmd_run() {
    local extra_volumes=()
    local extra_envs=()
    # Runtime-passthrough flags collected from the user's argv. Used by
    # nested-container function aliases (see docs/nested-containers.md) and
    # by power users who need to set runtime-level options ops doesn't
    # natively model. Forwarded verbatim to `<runtime> run` BEFORE the image
    # ref so docker/podman/nerdctl parse them as flags, not as command argv.
    local extra_runtime_flags=()
    # Auto-propagate host secrets (GitHub PAT for rate-limited builds, agent
    # API keys for authenticated --claude/--gemini/--codex without an
    # explicit --xxx-mount flag). The list lives in _OPS_AUTO_PROPAGATED_ENVS
    # near _OPS_RESERVED — one source of truth, also consumed by `cmd_env`.
    # Silent no-op when the var is unset.
    local _ev
    for _ev in "${_OPS_AUTO_PROPAGATED_ENVS[@]}"; do
        [ -n "${!_ev:-}" ] && extra_envs+=(--env "${_ev}=${!_ev}")
    done
    unset _ev
    local extra_ports=()
    local build_extra_args=()
    local do_build=""
    local do_install=0
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
    # Auto-forward the host Wayland socket so GUI apps (Chrome, Electron-
    # based tools, etc.) can display on the host compositor. Silently no-op
    # when the host isn't running Wayland ($WAYLAND_DISPLAY unset or socket
    # missing). --no-wayland disables this. X11 is NOT auto-forwarded —
    # wire it manually via -v /tmp/.X11-unix and -e DISPLAY if you need it.
    local wayland_auto=1
    # Auto-forward the host D-Bus session bus for full-fat GUI agents
    # (currently only --opencode-desktop). Electron/Chromium reads the
    # `org.freedesktop.portal.Settings` interface over this bus to get
    # the user's color-scheme (light/dark) preference, and gsettings /
    # dconf clients connect here for GTK theme resolution. Without it
    # the GUI is stuck on the light theme regardless of the host setting,
    # plus the startup is polluted by `dconf-CRITICAL: unable to create
    # directory /run/user/<uid>/dconf` spam (because dconf can't reach
    # the bus). Off by default — flipped on by individual agent branches
    # in the parser below. Trade-off: forwarding the session bus exposes
    # the entire host session API to the container (notifications,
    # secret service, screen recording portal, …); it's worth it for the
    # GUI agents the user explicitly opted into via the dedicated flag,
    # not for plain `ops run` shells.
    local dbus_session_auto=0
    # trust_workdir=1 injects MISE_TRUSTED_CONFIG_PATHS=$PWD so mise activates
    # any mise.toml found in the bind-mounted workdir without prompting.
    # Defaults to OPS_TRUST_WORKDIR (1 unless the user exported 0 in
    # ops.conf). The CLI flag --no-trust-workdir is the per-invocation
    # opt-out; set OPS_TRUST_WORKDIR=0 to opt out globally.
    local trust_workdir="${OPS_TRUST_WORKDIR:-1}"
    # Scratch buffer for agent flag extras emitted by _agent_run_extras.
    # Reused across each --<agent> branch in the parsing loop below.
    local _extras=""

    # OPS_ISOLATION_PRESET (host|volume|isolated|fully-isolated): a coarse-
    # grained dial that maps to per-agent state + mount_home. Per-agent
    # auto-volume happens in _agent_run_extras when each --<agent> flag is
    # parsed; the global mount_home=0 toggle for {isolated, fully-isolated}
    # happens here so it's stable regardless of argv order.
    case "${OPS_ISOLATION_PRESET:-host}" in
        host|volume) ;;
        isolated|fully-isolated) mount_home=0 ;;
        *)
            echo "Error: invalid OPS_ISOLATION_PRESET '${OPS_ISOLATION_PRESET:-}' (valid: host, volume, isolated, fully-isolated)" >&2
            exit 1
            ;;
    esac

    # OPS_DEFAULT_RUN_FLAGS — global flags injected before the user's argv
    # so the user keeps the last word (their flags appear later in argv,
    # and the parser is "last write wins" for most state). Field-split is
    # intentional: ops.conf entries are token sequences, not single args.
    if [ -n "${OPS_DEFAULT_RUN_FLAGS:-}" ]; then
        # shellcheck disable=SC2086  # intentional word split: tokens from config
        set -- $OPS_DEFAULT_RUN_FLAGS "$@"
    fi

    while [ $# -gt 0 ]; do
        # Per-agent {mount,volume,off} flags share a single dispatcher
        # (12 case-branches collapsed into one). The helper sets
        # ${X}_agent via dynamic scoping; if it didn't match, fall through
        # to the case below.
        if _match_agent_flag "$1"; then shift; continue; fi
        case "$1" in
            --no-trust-workdir)   trust_workdir=0;         shift ;;
            --no-mount-home)      mount_home=0;            shift ;;
            --no-mount-volume)    mount_volume=0;          shift ;;
            --no-nix-volume)      use_nix_volume=0;        shift ;;
            --no-mise-volume)     use_mise_volume=0;       shift ;;
            --no-wayland)         wayland_auto=0;          shift ;;
            --isolated-volumes)   isolated_volumes=1;      shift ;;
            -i|--image)        _resolve_image "$2";                         shift 2 ;;
            -n|--name)         OPS_CONTAINER_NAME="$2"; _user_set_n=1;       shift 2 ;;
            -f|--dockerfile)   OPS_DOCKERFILE="$2"; _user_set_f=1;           shift 2 ;;
            -r|--runtime)      OPS_RUNTIME="$2"; export OPS_RUNTIME; _resolve_runtime; shift 2 ;;
            -u|--uid|--user)
                # Accept either `UID` (current short form) or `UID:GID`
                # (the docker / podman / nerdctl idiom — used by the
                # nested-container `containerd` alias which needs --user 0:0
                # to enter the container as root). When `:` is present,
                # split into UID and GID; otherwise leave GID untouched
                # (caller can set it via -g).
                if [[ "$2" == *:* ]]; then
                    OPS_USER_UID="${2%%:*}"
                    OPS_USER_GID="${2##*:}"
                else
                    OPS_USER_UID="$2"
                fi
                shift 2 ;;
            -g|--gid)          OPS_USER_GID="$2";                           shift 2 ;;
            # Runtime passthrough — explicit list of flags forwarded
            # verbatim to `<runtime> run`. We don't generic-passthrough
            # unknown `--flag` tokens because that would break the existing
            # contract where the first unknown flag terminates parsing
            # (the user's COMMAND must be reachable). Adding flags here
            # is the supported way to extend the surface — see
            # docs/nested-containers.md for the use case that motivated
            # this set (`--group-add` for rootful docker socket access,
            # `--cap-add` / `--security-opt` for the containerd recipe).
            --group-add)       extra_runtime_flags+=("--group-add" "$2");    shift 2 ;;
            --cap-add)         extra_runtime_flags+=("--cap-add" "$2");      shift 2 ;;
            --cap-drop)        extra_runtime_flags+=("--cap-drop" "$2");     shift 2 ;;
            --security-opt)    extra_runtime_flags+=("--security-opt" "$2"); shift 2 ;;
            --device)          extra_runtime_flags+=("--device" "$2");       shift 2 ;;
            --privileged)      extra_runtime_flags+=("--privileged");        shift ;;
            -l|--lang)         OPS_USER_LANG="$2";                          shift 2 ;;
            -v|--volume)       case "$2" in
                                   *:*) extra_volumes+=("$2") ;;
                                   *)   echo "Error: -v expects SRC:DST[:OPTS] (got '$2'). Volume names must be paired with a destination path." >&2; exit 1 ;;
                               esac
                               shift 2 ;;
            -H|--nerdctl-home) OPS_NERDCTL_HOME="$(realpath -m "$2")";
                               export PATH="$OPS_NERDCTL_HOME/bin:$PATH";
                               _resolve_runtime;
                               [ "$OPS_RUNTIME" != "nerdctl" ] && echo "Warning: -H has no effect with OPS_RUNTIME=$OPS_RUNTIME" >&2
                               shift 2 ;;
            -b|--build)        do_build=1;                              shift ;;
            --install)         do_install=1;                            shift ;;
            --no-cache)        build_extra_args+=(--no-cache);          shift ;;
            --no-rm)           ephemeral=0;                             shift ;;
            --nix-cleanup)     agent_cmd='HOME=/opt/nix-home /opt/ops/lib/nix-collect-garbage -d'; shift ;;
            --update)          agent_cmd='
                echo -e "\033[1;34m==> mise self-update...\033[0m" && mise self-update --yes
                echo -e "\033[1;34m==> mise upgrade...\033[0m"     && mise upgrade --yes
                echo -e "\033[1;34m==> nix cleanup...\033[0m"      && HOME=/opt/nix-home /opt/ops/lib/nix-collect-garbage -d
                echo -e "\033[1;32m==> done\033[0m"
            '; shift ;;
            --claude)
                agent_cmd="$(_agent_cmd claude npm:@anthropic-ai/claude-code)"
                shift
                _extras=$(_agent_run_extras claude)
                # shellcheck disable=SC2086  # intentional word split for tokens
                [ -n "$_extras" ] && set -- $_extras "$@"
                ;;
            --claude-mount)    claude_agent="mount";   shift ;;
            --gemini)
                agent_cmd="$(_agent_cmd gemini npm:@google/gemini-cli)"
                shift
                _extras=$(_agent_run_extras gemini)
                # shellcheck disable=SC2086
                [ -n "$_extras" ] && set -- $_extras "$@"
                ;;
            --gemini-mount)    gemini_agent="mount";   shift ;;
            --opencode)
                agent_cmd="$(_agent_cmd opencode npm:opencode-ai)"
                shift
                _extras=$(_agent_run_extras opencode)
                # shellcheck disable=SC2086
                [ -n "$_extras" ] && set -- $_extras "$@"
                ;;
            --opencode-desktop)
                # Electron GUI variant of opencode. We pull the prebuilt
                # AppImage that upstream publishes on every GitHub release
                # (sst/opencode), via mise's `github:` backend with an
                # asset_pattern filter — this avoids the 15-min Tauri Rust
                # rebuild that nixpkgs would otherwise force on every cold
                # cache (and which produces an outdated Tauri build anyway,
                # because upstream switched to Electron mid-1.x).
                #
                # Three things this branch deliberately does differently
                # from `_agent_cmd`, which is why we inline the bash-c
                # snippet instead of calling that helper:
                #
                # 1. The mise tool spec uses bracket options
                #    (`[asset_pattern=…]`) which are bash glob characters.
                #    We single-quote the spec inside the emitted command
                #    so `bash -c` doesn't try to expand them as a pattern
                #    against the cwd.
                #
                # 2. The shimmed binary keeps the `.AppImage` suffix
                #    (mise's `github:` backend uses the asset filename as
                #    the on-disk and shim name; we accepted it rather than
                #    fighting mise to rename it).
                #
                # 3. AppImages need libfuse2 to mount themselves at run
                #    time. The container ships without fuse, so we use
                #    `--appimage-extract-and-run`: AppImageKit unpacks the
                #    embedded squashfs into /tmp on each launch and execs
                #    the binary from there — no FUSE needed, no Dockerfile
                #    patch. Cost: ~1–2s extra at startup. The /tmp dirs
                #    accumulate (`appimage_extracted_<hash>`), but /tmp is
                #    a tmpfs that goes away with the container, so the
                #    leak is bounded by container lifetime.
                #
                # Image-level prerequisite: the Electron AppImage links
                # against ~21 system libs (libnspr4, libnss3, libgtk-3,
                # libgbm, libasound, libcups, plus the X11/at-spi/cairo/
                # pango set pulled transitively by gtk3). The headless
                # baseline does NOT ship them — opt in by rebuilding with
                # OPS_DESKTOP_DEPS=true (see Dockerfile §1b). Without it
                # the AppImage exits with `error while loading shared
                # libraries: libnspr4.so` and similar; we don't pre-flight
                # the check here because the user already gets a clear
                # ld.so error pointing at the missing lib.
                #
                # `--no-sandbox`: Chromium's setuid sandbox helper
                # (`chrome-sandbox` inside the AppImage) requires
                # `chown root:root + chmod 4755` to work, which the
                # unprivileged container user cannot grant — the helper
                # then FATALs with "The SUID sandbox helper binary was
                # found, but is not configured correctly. Rather than run
                # without sandboxing I'm aborting now". Passing
                # `--no-sandbox` to Electron is the canonical workaround
                # for Electron-in-container (Puppeteer / Playwright /
                # every Electron CI image does this). Trade-off accepted:
                # the container boundary is the security perimeter we
                # already trust, the Chromium internal sandbox is
                # redundant in that context. The flag goes BEFORE `"$@"`
                # so user-supplied trailing args still flow through.
                #
                # `--ozone-platform=wayland --enable-features=UseOzonePlatform`:
                # Electron's default Ozone backend on Linux is X11, even
                # when WAYLAND_DISPLAY is set. ops.sh forwards the Wayland
                # socket (see the auto-forward block ~150 lines down) but
                # does NOT forward an X11 display, so the bare AppImage
                # exits with `Missing X server or $DISPLAY / The platform
                # failed to initialize. Exiting.`. We initially tried
                # `--ozone-platform-hint=auto` (the cleanest choice on
                # paper) but Chromium kept loading the X11 backend on the
                # opencode-desktop v1.14.39 Electron build — observed
                # empirically: `[ERROR:ozone_platform_x11.cc:256] Missing
                # X server` despite both --ozone-platform-hint=auto AND
                # WAYLAND_DISPLAY/XDG_RUNTIME_DIR/socket bind-mount being
                # present in the dry-run. Switching to the explicit
                # `--ozone-platform=wayland` plus `--enable-features=
                # UseOzonePlatform` (the older, pre-hint incantation) is
                # what actually pins Chromium to the Wayland Ozone
                # backend on this version. Trade-off: a hypothetical X11
                # user would now need to override the flag manually
                # (`./ops.sh run --opencode-desktop -- --ozone-platform=x11`,
                # since trailing args after `--` flow through to the
                # binary). Acceptable — we prioritise the common case.
                #
                # Shared state with the terminal CLI: same _agent_run_extras
                # call as `--opencode` so `--opencode-mount` / -volume /
                # --no-opencode-mount continue to drive
                # ~/.local/share/opencode + ~/.config/opencode for both
                # frontends. Sessions stay coherent.
                agent_cmd="command -v opencode-desktop.AppImage >/dev/null 2>&1 || { printf '\\033[1;34m==> Installing %s (first run, ~150 MB download)...\\033[0m\\n' opencode-desktop >&2; mise use -g 'github:sst/opencode[asset_pattern=opencode-desktop-linux-x86_64.AppImage]'; __ops_refresh_cache; clear 2>/dev/null || true; }; exec opencode-desktop.AppImage --appimage-extract-and-run --no-sandbox --ozone-platform=wayland --enable-features=UseOzonePlatform \"\$@\""
                # Theme detection (light/dark) + dconf access need the
                # host's D-Bus session bus inside the container. Set the
                # flag here; the actual --volume + --env wiring happens
                # in the auto-forward block alongside the Wayland one
                # so the dry-run output is grouped logically.
                dbus_session_auto=1
                shift
                _extras=$(_agent_run_extras opencode)
                # shellcheck disable=SC2086
                [ -n "$_extras" ] && set -- $_extras "$@"
                ;;
            --opencode-mount)  opencode_agent="mount"; shift ;;
            --codex)
                agent_cmd="$(_agent_cmd codex npm:@openai/codex)"
                shift
                _extras=$(_agent_run_extras codex)
                # shellcheck disable=SC2086
                [ -n "$_extras" ] && set -- $_extras "$@"
                ;;
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

    # --install: run `mise install` (from the workdir's mise.toml) before the
    # real command. Three cases, depending on what else was asked:
    #   1. an agent_cmd is already set (e.g. --claude / --update)
    #        → chain: `mise install && (agent_cmd)`
    #   2. an explicit command was given after `--`
    #        → chain: `mise install && exec "$@"`
    #   3. no command at all (plain `ops run --install`)
    #        → chain: `mise install && exec bash`  (interactive shell after install)
    # The `set -- bash -c "$agent_cmd" _ "$@"` line below then hands it off to
    # the container in a single exec-friendly form.
    if [ "$do_install" = 1 ]; then
        if [ -n "$agent_cmd" ]; then
            agent_cmd="mise install --yes && { $agent_cmd; }"
        elif [ $# -gt 0 ]; then
            # shellcheck disable=SC2016  # "$@" is evaluated INSIDE the container's bash -c
            agent_cmd='mise install --yes && exec "$@"'
        else
            agent_cmd="mise install --yes && exec bash --rcfile /etc/ops-bashrc"
        fi
    fi

    # Prepend `source /etc/ops-bashrc` so `bash -c` wrappers (claude, gemini,
    # --update, --nix-cleanup, or a user-supplied `--` command with --install)
    # inherit PATH/PYTHONPATH/... from the workdir's mise.toml + flake.nix.
    # The rcfile is idempotent (guarded on $- and OPS_BASHRC_DONE).
    [ -n "$agent_cmd" ] && set -- bash -c "source /etc/ops-bashrc; $agent_cmd" _ "$@"

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
        local old_id=""
        [ "$dry_run" = 0 ] && old_id=$("$RUNTIME_BIN" image inspect "$OPS_IMAGE" --format '{{.Id}}' 2>/dev/null || true)
        # Do NOT forward "$@" to build_image: anything after -- is the container
        # command, not a build flag, and would be appended after the context
        # path ("$@" "$SCRIPT_DIR"), breaking `docker build`.
        local -a build_prefix=()
        [ "$dry_run" = 1 ] && build_prefix=(--dry-run)
        build_image "${build_prefix[@]}" "${build_extra_args[@]}"
        local ret=$?
        if [ $ret -eq 0 ] && [ "$dry_run" = 0 ]; then
            _post_build_prompt "$old_id"
        fi
        exit $ret
    fi

    if [ $# -eq 0 ]; then
        # --rcfile bakes mise activation + nix profile sourcing so interactive
        # shells work even when $HOME is bind-mounted from the host (which
        # shadows the image's $HOME/.bashrc).
        set -- bash --rcfile /etc/ops-bashrc
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
        # Runtime-creation flags (--group-add, --cap-add, --cap-drop,
        # --security-opt, --device, --privileged) cannot be applied to a
        # running container — they're only honored at create time. We
        # filter out values that are ALREADY applied to the running
        # container before prompting, so the common case of a user
        # alias re-injecting the same flag on every invocation
        # (e.g. `ops_alias_docker` echoing `--group-add 145`) doesn't
        # trigger a recreate prompt every time. Comparison is exact
        # against `inspect` output for the trivially-comparable subset:
        # --group-add (GIDs / names), --device (host path; ignores
        # container-side path and perms which would over-match anyway),
        # and --privileged (boolean). --cap-add / --cap-drop /
        # --security-opt skip filtering because docker normalizes them
        # differently from user input (NET_ADMIN ↔ cap_net_admin,
        # apparmor= prefix presence/absence) — strict equality there
        # would still over-prompt, so we keep the honest over-prompt
        # rather than risk a silent drop.
        local -a missing_runtime_flags=()
        if [ ${#extra_runtime_flags[@]} -gt 0 ]; then
            local _inspect_combined _existing_groupadd _existing_devices _existing_privileged
            _inspect_combined=$("$RUNTIME_BIN" container inspect "$OPS_CONTAINER_NAME" \
                --format '{{range .HostConfig.GroupAdd}}{{.}} {{end}}|{{range .HostConfig.Devices}}{{.PathOnHost}} {{end}}|{{.HostConfig.Privileged}}' \
                2>/dev/null)
            IFS='|' read -r _existing_groupadd _existing_devices _existing_privileged <<< "$_inspect_combined"
            local _rt_idx=0
            while [ "$_rt_idx" -lt "${#extra_runtime_flags[@]}" ]; do
                local _f="${extra_runtime_flags[$_rt_idx]}"
                case "$_f" in
                    --privileged)
                        if [ "$_existing_privileged" != "true" ]; then
                            missing_runtime_flags+=("--privileged")
                        fi
                        _rt_idx=$((_rt_idx + 1))
                        ;;
                    --group-add)
                        local _v="${extra_runtime_flags[$((_rt_idx + 1))]}"
                        if ! grep -qF -- "$_v " <<< "$_existing_groupadd "; then
                            missing_runtime_flags+=("--group-add" "$_v")
                        fi
                        _rt_idx=$((_rt_idx + 2))
                        ;;
                    --device)
                        local _v="${extra_runtime_flags[$((_rt_idx + 1))]}"
                        local _host_path="${_v%%:*}"
                        if ! grep -qF -- "$_host_path " <<< "$_existing_devices "; then
                            missing_runtime_flags+=("--device" "$_v")
                        fi
                        _rt_idx=$((_rt_idx + 2))
                        ;;
                    *)
                        missing_runtime_flags+=("$_f" "${extra_runtime_flags[$((_rt_idx + 1))]}")
                        _rt_idx=$((_rt_idx + 2))
                        ;;
                esac
            done
            unset _rt_idx _f _v _host_path _inspect_combined _existing_groupadd _existing_devices _existing_privileged
        fi
        if [ ${#missing_runtime_flags[@]} -gt 0 ]; then
            echo -e "\033[33m⚠ Container '$OPS_CONTAINER_NAME' is already running — runtime-creation flags cannot be applied to it:\033[0m" >&2
            local _rt_idx=0
            while [ "$_rt_idx" -lt "${#missing_runtime_flags[@]}" ]; do
                local _f="${missing_runtime_flags[$_rt_idx]}"
                if [ "$_f" = "--privileged" ]; then
                    echo -e "\033[33m    $_f\033[0m" >&2
                    _rt_idx=$((_rt_idx + 1))
                else
                    echo -e "\033[33m    $_f ${missing_runtime_flags[$((_rt_idx + 1))]}\033[0m" >&2
                    _rt_idx=$((_rt_idx + 2))
                fi
            done
            unset _rt_idx _f
            echo -e "\033[33m  Tip: use -n <name> to create a separate container without removing this one.\033[0m" >&2
            printf "\033[33mRemove and recreate the container? \033[1m[Y/n]\033[0m " >&2
            read -r answer
            if [[ ! "$answer" =~ ^[nN]$ ]]; then
                "$RUNTIME_BIN" rm -f "$OPS_CONTAINER_NAME" >/dev/null
                running=""
            fi
        fi
        if [ -n "$running" ] && [ ${#extra_volumes[@]} -gt 0 ]; then
            local mounted missing=()
            # Format emits `Source:Destination ` per mount (trailing space).
            # The trailing space in `grep -qF "$v_match "` anchors the
            # comparison to whole entries — without it, `/foo/bar:/bar`
            # would be matched as containing `/foo` and we'd wrongly
            # report the volume as already mounted. The runtime does NOT
            # echo back the third `:opt` segment of `-v src:dst:opt`, so
            # we strip a whitelisted set of known options below before
            # matching (whitelisting beats `${v%:*}` because a POSIX path
            # may legally contain a `:`).
            mounted=$("$RUNTIME_BIN" container inspect "$OPS_CONTAINER_NAME" --format '{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' 2>/dev/null)
            for v in "${extra_volumes[@]}"; do
                local v_match="$v"
                case "$v" in
                    *:ro|*:rw|*:z|*:Z|*:cached|*:delegated|*:consistent|*:U)
                        v_match="${v%:*}" ;;
                    *:ro,[a-zA-Z]*|*:rw,[a-zA-Z]*)
                        # Composite suffix like `:ro,Z` or `:rw,cached` —
                        # still ends after the trailing `,...`.
                        v_match="${v%:*}" ;;
                esac
                echo "$mounted" | grep -qF "$v_match " || missing+=("$v")
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
            # trust_workdir=1 injects MISE_TRUSTED_CONFIG_PATHS=$PWD so mise
            # auto-activates any mise.toml in the bind-mounted workdir.
            # Opt out with --no-trust-workdir or OPS_TRUST_WORKDIR=0 before
            # running ops on a repo you don't fully trust: a hostile
            # mise.toml can run tasks/hooks via `mise activate`.
            local -a trust_env=()
            [ "$trust_workdir" = 1 ] && trust_env=(--env "MISE_TRUSTED_CONFIG_PATHS=$PWD")
            if [ "$dry_run" = 1 ]; then
                _dry_run_print "$RUNTIME_BIN" exec -it --workdir "$PWD" --user "$user_arg" \
                    --env "HOME=$HOME_IN_CTN" \
                    --env "TERM=${TERM:-xterm-256color}" --env "COLORTERM=${COLORTERM:-truecolor}" \
                    "${trust_env[@]}" \
                    "${extra_envs[@]}" "$OPS_CONTAINER_NAME" "$@"
                echo
                exit 0
            fi
            # Detect whether the running container was created with the
            # shepherd pattern (ops ≥ 1.11). Pre-1.11 containers do not
            # carry the `ops.shepherd=1` label and have a real user-cmd
            # PID 1 — for those we keep the legacy `exec` (no marker
            # bookkeeping, no post-exit cleanup) so an in-flight upgrade
            # doesn't disturb already-running sessions.
            local _has_shepherd
            _has_shepherd=$("$RUNTIME_BIN" container inspect \
                --format '{{ index .Config.Labels "ops.shepherd" }}' \
                "$OPS_CONTAINER_NAME" 2>/dev/null || true)
            if [ "$_has_shepherd" = "1" ]; then
                local _sid="ops-session-$$"
                _ops_sweep_orphan_sessions "$OPS_CONTAINER_NAME"
                _ops_register_session "$OPS_CONTAINER_NAME" "$_sid"
                # shellcheck disable=SC2064  # expand $OPS_CONTAINER_NAME / $_sid / $ephemeral now
                # Chain the global `cleanup` trap (set near `ops.sh:219`) so we don't
    # silently disable its stop_buildkitd + TMP_INSTALL_DIR scrub.
    trap "_ops_cleanup_session '$OPS_CONTAINER_NAME' '$_sid' '$ephemeral'; cleanup" EXIT
                "$RUNTIME_BIN" exec -it --workdir "$PWD" --user "$user_arg" \
                    --env "HOME=$HOME_IN_CTN" \
                    --env "TERM=${TERM:-xterm-256color}" --env "COLORTERM=${COLORTERM:-truecolor}" \
                    "${trust_env[@]}" "${extra_envs[@]}" "$OPS_CONTAINER_NAME" "$@"
                exit $?
            fi
            exec "$RUNTIME_BIN" exec -it --workdir "$PWD" --user "$user_arg" --env "HOME=$HOME_IN_CTN" --env "TERM=${TERM:-xterm-256color}" --env "COLORTERM=${COLORTERM:-truecolor}" "${trust_env[@]}" "${extra_envs[@]}" "$OPS_CONTAINER_NAME" "$@"
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
    [ "$use_mise_volume" = 1 ]   && {
        ensure_volume "$mise_volume"
        # Replace any legacy plain-directory plugin in the volume with a
        # symlink pointing at the image-baked copy, so plugin updates
        # surface after a rebuild. No-op after the first call.
        _ensure_mise_plugin_symlink "$mise_volume"
        extra_volumes+=("$mise_volume:/opt/mise/data")
    }

    # OPS_DEV_PLUGIN_MOUNT=1: bind-mount the repo's mise/ directory directly
    # over the image-baked plugin so contributors can iterate on Lua code
    # without rebuilding the image. Read-only to keep plugin mutations
    # confined to the host working copy (git-trackable).
    if [ "${OPS_DEV_PLUGIN_MOUNT:-0}" = "1" ]; then
        extra_volumes+=("$SCRIPT_DIR/mise:/opt/ops/mise-plugin/nix:ro")
    fi

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

    # Build args for the shepherd PID 1 (the long-lived placeholder
    # process that keeps the container alive across multiple sessions).
    # Per-session settings — workdir, user, TERM/COLORTERM, mise trust —
    # move to `docker exec` because they vary per session.
    # `--init` injects tini as PID 1 (which then runs `tail -f /dev/null`
    # at PID 2) so that orphan children are reaped instead of accumulating
    # as zombies in `docker top` output.
    #
    # Why `tail -f /dev/null` and not `sleep infinity`: `sleep infinity`
    # is a GNU/BSD-modern extension and is NOT supported by BusyBox
    # `sleep` (Alpine, distroless, scratch+busybox images all reject
    # the literal `infinity` argument). Users may run ops against any
    # image declared in `OPS_IMAGES`, including Alpine-based ones, so
    # we pick the portable POSIX idiom — `tail -f` blocking on /dev/null
    # works on every libc/coreutils variant we ship to. The cost is one
    # extra fd plus a blocking poll(2), which is dwarfed by tini's own
    # supervision overhead.
    local args=(run -d --init)
    # `--rm` is included to avoid leaving an "exited" husk behind if the
    # shepherd is ever killed externally; the normal teardown path goes
    # through `docker rm -f` from _ops_cleanup_session, so `--rm` is
    # cosmetic during the session lifetime but matters for crash safety.
    [ "$ephemeral" = 1 ] && args+=(--rm)
    args+=(
        --name "$OPS_CONTAINER_NAME"
        --hostname "$OPS_CONTAINER_NAME"
        --label "ops.container=true"
        --label "ops.shepherd=1"
        # rootless: container UID 0 maps to the host user → R/W access to bind-mounted files
        # rootful:  container UID matches host UID directly → same effect, different mechanism
        --user "$user_arg"
        --env "HOME=$HOME_IN_CTN"
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
    # Auto-forward the Wayland socket when the host runs Wayland. Silent
    # no-op when any of the preconditions is missing; --no-wayland opts out.
    if [ "$wayland_auto" = 1 ] \
       && [ -n "${WAYLAND_DISPLAY:-}" ] \
       && [ -n "${XDG_RUNTIME_DIR:-}" ] \
       && [ -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" ]; then
        args+=(--volume "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY:$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY")
        args+=(--env "WAYLAND_DISPLAY=$WAYLAND_DISPLAY")
        args+=(--env "XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR")
    fi
    # Auto-forward the D-Bus session bus + desktop env vars when an
    # agent flag opted in (currently --opencode-desktop sets
    # dbus_session_auto=1; see the dedicated comment block at the top of
    # cmd_run for the security rationale). Strips the "unix:path=" prefix
    # that systemd-style addresses use so the bind-mount source/dest
    # stays a plain filesystem path. Silent no-op when the host isn't
    # exporting DBUS_SESSION_BUS_ADDRESS or the socket is missing.
    if [ "$dbus_session_auto" = 1 ] && [ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]; then
        local _dbus_socket="${DBUS_SESSION_BUS_ADDRESS#unix:path=}"
        if [ -S "$_dbus_socket" ]; then
            args+=(--volume "$_dbus_socket:$_dbus_socket")
            args+=(--env "DBUS_SESSION_BUS_ADDRESS=$DBUS_SESSION_BUS_ADDRESS")
        fi
        # XDG_CURRENT_DESKTOP / DESKTOP_SESSION are read by xdg-desktop-portal
        # to pick the correct portal backend (gnome / kde / hyprland / …);
        # without them the portal call may answer with stale defaults
        # ('default' instead of 'prefer-dark') even with the bus connected.
        [ -n "${XDG_CURRENT_DESKTOP:-}" ] && args+=(--env "XDG_CURRENT_DESKTOP=$XDG_CURRENT_DESKTOP")
        [ -n "${DESKTOP_SESSION:-}" ]     && args+=(--env "DESKTOP_SESSION=$DESKTOP_SESSION")
        # GTK theme + color-scheme forwarding. We CANNOT rely on the portal
        # call from inside the container on Ubuntu hosts: AppArmor (the
        # `unconfined` profile that ships with snapd-shipped portals
        # since 24.04) actively blocks D-Bus method_call from a sender
        # that cannot be peer-authenticated through the snap chain — the
        # error is `An AppArmor policy prevents this sender from sending
        # this message`, observed empirically on Ubuntu 25.04. We
        # therefore READ the value on the host via `dconf read` (the raw
        # GVariant store, which IS accurate even when `gsettings get`
        # returns the schema default — observed during this feature's
        # development: gsettings said 'default'/'Yaru' while the user's
        # shell was visibly dark and dconf correctly read 'prefer-dark').
        #
        # The theme NAME is deliberately NOT forwarded verbatim
        # (e.g. GTK_THEME=Yaru-dark would fail: the container ships only
        # Adwaita, the GTK default — Yaru theme assets are not in the
        # base image, so libgtk silently falls back to Adwaita-light).
        # Instead, we set GTK_THEME=Adwaita:dark when the host signals
        # `prefer-dark`. The `:dark` suffix is GTK 3+ syntax that pins
        # the dark variant of the named theme — Adwaita has both light
        # and dark variants bundled, so this ALWAYS resolves to a real
        # theme on the on-disk side, which lets libgtk set
        # `gtk-application-prefer-dark-theme` to true. Electron's
        # `nativeTheme.shouldUseDarkColors` reads that GtkSetting and
        # the result reaches the renderer's `prefers-color-scheme` CSS
        # media query — which is what the opencode-desktop UI keys off.
        # Visual result: not pixel-identical to the user's host theme,
        # but unambiguously dark vs light. The trade-off is documented
        # in the bind-mount table because it's a deliberate compromise
        # between purity (true Yaru) and reliability (always works).
        local _host_color_scheme=""
        if command -v dconf >/dev/null 2>&1; then
            _host_color_scheme="$(dconf read /org/gnome/desktop/interface/color-scheme 2>/dev/null | tr -d "'")"
        fi
        if [ "$_host_color_scheme" = "prefer-dark" ]; then
            args+=(--env "GTK_THEME=Adwaita:dark")
        fi
    fi
    args+=("${extra_envs[@]}")
    [ ${#extra_ports[@]} -gt 0 ] && args+=("${extra_ports[@]}")
    [ ${#extra_runtime_flags[@]} -gt 0 ] && args+=("${extra_runtime_flags[@]}")

    # Build real-CLI snapshot BEFORE injecting cmdline labels (avoids recursive embedding).
    # Mask sensitive env values (tokens / API keys) in BOTH labels so they are
    # not readable via `docker inspect` — the container itself still receives
    # the real values via the extra_envs already in args. The masking regex is
    # applied to:
    #   - real_cli: the effective `docker run ...` (built from args above)
    #   - OPS_ORIG_ARGV: the raw user invocation captured at script entry
    #     (a user who types `ops -e GITHUB_TOKEN=xxx run` would otherwise
    #     leak the token via ops.cmdline.user).
    _mask_secrets() {
        # Both _dry_run_print and the labels below derive their secret
        # detection from `_OPS_SECRET_SUFFIXES` (see top of file) — keep
        # the two paths symmetric so a value redacted in dry-run is also
        # redacted in `ops.cmdline.*` labels.
        #
        # Quote forms covered per pattern:
        #   KEY=bare_value         → stops at whitespace
        #   KEY='single quoted'    → consumes up to closing '
        #   KEY="double quoted"    → consumes up to closing "
        # Non-secret names matching the suffix (e.g. PUBLIC_KEY) are a
        # deliberate false-positive trade-off in favour of not leaking.
        local pat
        pat="$(_ops_secret_alt)"
        sed -E \
            -e "s/(${pat})='[^']*'/\\1='***'/g" \
            -e "s/(${pat})=\"[^\"]*\"/\\1=\"***\"/g" \
            -e "s/(${pat})=[^[:space:]'\"]+/\\1=***/g"
    }
    local real_cli real_cli_masked user_cli_masked
    real_cli="$(_shell_quote "$RUNTIME_BIN" "${args[@]}" "$OPS_IMAGE" tail -f /dev/null)"
    real_cli_masked=$(printf '%s' "$real_cli" | _mask_secrets)
    user_cli_masked=$(printf '%s' "$OPS_ORIG_ARGV" | _mask_secrets)
    unset -f _mask_secrets
    args+=(--label "ops.cmdline.user=$user_cli_masked")
    args+=(--label "ops.cmdline.real=$real_cli_masked")

    # Per-session attach args (workdir, user, TERM/COLORTERM, mise trust).
    # trust_workdir=1 (default) auto-trusts mise.toml in the bind-mounted
    # workdir — the usual "mise Trust them?" prompt is suppressed. Disable
    # with --no-trust-workdir / OPS_TRUST_WORKDIR=0 before running against
    # an untrusted repo.
    local -a trust_env=()
    [ "$trust_workdir" = 1 ] && trust_env=(--env "MISE_TRUSTED_CONFIG_PATHS=$PWD")

    if [ "$dry_run" = 1 ]; then
        # Two commands describe the new lifecycle: the detached shepherd
        # creation, then the interactive `exec` that attaches the user
        # session. Both must appear so users can reproduce the flow.
        _dry_run_print "$RUNTIME_BIN" "${args[@]}" "$OPS_IMAGE" tail -f /dev/null
        echo
        _dry_run_print "$RUNTIME_BIN" exec -it --workdir "$PWD" --user "$user_arg" \
            --env "HOME=$HOME_IN_CTN" \
            --env "TERM=${TERM:-xterm-256color}" --env "COLORTERM=${COLORTERM:-truecolor}" \
            "${trust_env[@]}" "${extra_envs[@]}" "$OPS_CONTAINER_NAME" "$@"
        echo
        exit 0
    fi

    # Create the shepherd in detached mode. Output the container ID into
    # /dev/null (we don't need it — we already know the name) and filter
    # the harmless "image already exists" warning that some runtimes emit
    # on first pull when the layer is shared with another image.
    if ! "$RUNTIME_BIN" "${args[@]}" "$OPS_IMAGE" tail -f /dev/null \
            > /dev/null 2> >(grep -v "already exists" >&2); then
        exit 1
    fi

    # First interactive session in the freshly-created shepherd. Mirrors
    # the join path above so a SIGKILL on this PID doesn't strand the
    # container: the next `ops run` sweeps the orphan marker.
    local _sid="ops-session-$$"
    _ops_register_session "$OPS_CONTAINER_NAME" "$_sid"
    # shellcheck disable=SC2064  # expand $OPS_CONTAINER_NAME / $_sid / $ephemeral now
    # Chain the global `cleanup` trap (set near `ops.sh:219`) so we don't
    # silently disable its stop_buildkitd + TMP_INSTALL_DIR scrub.
    trap "_ops_cleanup_session '$OPS_CONTAINER_NAME' '$_sid' '$ephemeral'; cleanup" EXIT
    "$RUNTIME_BIN" exec -it --workdir "$PWD" --user "$user_arg" \
        --env "HOME=$HOME_IN_CTN" \
        --env "TERM=${TERM:-xterm-256color}" --env "COLORTERM=${COLORTERM:-truecolor}" \
        "${trust_env[@]}" "${extra_envs[@]}" "$OPS_CONTAINER_NAME" "$@"
    exit $?
}

cmd_images() {
    case "${1:-}" in
        -h|--help)
            cat <<EOF
Usage: $(basename "$0") images|image

List every image profile declared in OPS_IMAGES (associative array in
\$_CONFIG_FILE). For each entry:

  key           the lookup name you pass to '-i <key>'
  image         OPS_IMAGES[key] (the image reference)
  dockerfile    OPS_DOCKERFILES[key], else \$SCRIPT_DIR/Dockerfile.<key>,
                else the default \$OPS_DOCKERFILE
  container     OPS_CONTAINER_NAMES[key], else the key itself

'image' (singular) is an alias. No flags.

Declare profiles in \$_CONFIG_FILE:
  declare -A OPS_IMAGES=([ml]="localhost/ops-ml" [rust]="localhost/ops-rust")
EOF
            return 0
            ;;
    esac
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
        _OPS_IMAGE_KEY="$name"
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
    case "${1:-}" in
        -h|--help)
            cat <<EOF
Usage: $(basename "$0") aliases|alias

List user-defined aliases from \$_CONFIG_FILE. Two forms are supported:

  String aliases (OPS_ALIASES associative array):
    declare -A OPS_ALIASES=(
      [ml]="run -i localhost/ml-dev -v /data:/data --claude"
      [web]="run -p 3000:3000 -p 5173:5173"
    )

  Function aliases (ops_alias_<name>, must echo the argv):
    ops_alias_dev() { echo run -i arch --claude; }

Reserved names are ignored: built-in subcommands cannot be shadowed
(run, build, runtime, status, info, logs, log, clean, nerdctl, doctor,
inspect, config, backup, restore, update, alias, aliases, image, images,
version, -V, --version, help, -h, --help).

'alias' (singular) is an alias of this command. No flags. Aliases are
expanded in a single pass — they cannot recursively expand into other
aliases.
EOF
            return 0
            ;;
    esac
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

# `ops env` — surface the env vars that ops auto-propagates into the
# container at run time. Intentionally name-only: values are never echoed
# (a TUI screenshot of `ops env` should be safe to share). Useful when
# debugging "why is ANTHROPIC_API_KEY not reaching claude in the
# container?" — checks both the live shell and the ops.conf snapshot
# (host vars set after `source` of ops.conf may differ from what the
# pre-source snapshot captured).
cmd_env() {
    case "${1:-}" in
        -h|--help)
            cat <<EOF
Usage: $(basename "$0") env

Dump the environment variables that ops propagates into the container at
run time. Auto-propagated vars (sourced from the calling shell or from
ops.conf via 'config secret add'):

EOF
            local _hv
            for _hv in "${_OPS_AUTO_PROPAGATED_ENVS[@]}"; do
                printf '  %-18s %s\n' "$_hv" "${_OPS_AUTO_PROPAGATED_DESC[$_hv]:-}"
            done
            cat <<EOF

Output: NAME [set|unset] (origin: shell|config|both). Values are NEVER
printed — \`ops env\` is safe to paste into a screenshot or log.
EOF
            return 0
            ;;
    esac
    echo -e "\033[1;34m=== Auto-propagated env vars ===\033[0m"
    local var live_set status origin color
    for var in "${_OPS_AUTO_PROPAGATED_ENVS[@]}"; do
        live_set=0
        [ -n "${!var:-}" ] && live_set=1
        if [ -n "${_PRE_SOURCE_ENV[$var]+set}" ] && [ -n "${_PRE_SOURCE_ENV[$var]}" ]; then
            # Distinguish shell-set (pre-source) from config-set: if the
            # pre-source snapshot already had it, the shell exported it
            # and ops.conf MAY have re-exported the same value — but the
            # source of truth is the shell.
            if [ "$live_set" = 1 ] && [ "${!var}" = "${_PRE_SOURCE_ENV[$var]}" ]; then
                origin="shell"
            else
                origin="both"
            fi
        elif [ "$live_set" = 1 ]; then
            # Set after ops.conf was sourced → must come from config.
            origin="config"
        else
            origin="-"
        fi
        if [ "$live_set" = 1 ]; then
            color='\033[32m'
            status='set'
        else
            color='\033[33m'
            status='unset'
        fi
        printf '  %-22s '"$color"'[%s]\033[0m  origin: %s\n' "$var" "$status" "$origin"
    done

    # Custom exports — anything in ops.conf via `export NAME=…` that is NOT
    # in the auto-propagated list. Users routinely add their own tokens
    # (e.g. MISTRAL_API_KEY, HUGGINGFACE_TOKEN) via `config secret add`,
    # and they need to know whether ops run forwards them. Spoiler: it
    # doesn't. The auto-propagation list is intentionally narrow (one
    # entry per officially-supported agent + GITHUB_TOKEN); adding a
    # custom one means either passing it ad-hoc with `-e KEY=VAL` /
    # `--env-file`, or contributing the name upstream so ops run picks
    # it up automatically.
    if [ -f "$_CONFIG_FILE" ]; then
        # Stream the sorted unique list of `export NAME` from ops.conf
        # into the loop directly via process substitution — avoids an
        # intermediate variable + word-splitting (SC2086 under shellcheck
        # `-S style` 0.9.0 in CI).
        local cv first=1 is_auto
        while IFS= read -r cv; do
            [ -z "$cv" ] && continue
            is_auto=0
            for var in "${_OPS_AUTO_PROPAGATED_ENVS[@]}"; do
                [ "$cv" = "$var" ] && { is_auto=1; break; }
            done
            [ "$is_auto" = 1 ] && continue
            if [ "$first" = 1 ]; then
                echo -e "\n\033[1;34m=== Custom config exports (NOT auto-propagated to container) ===\033[0m"
                first=0
            fi
            live_set=0
            [ -n "${!cv:-}" ] && live_set=1
            if [ "$live_set" = 1 ]; then
                color='\033[32m'
                status='set'
            else
                color='\033[33m'
                status='unset'
            fi
            printf '  %-22s '"$color"'[%s]\033[0m  origin: config\n' "$cv" "$status"
        done < <(grep -oE '^[[:space:]]*export[[:space:]]+[A-Z_][A-Z0-9_]*' "$_CONFIG_FILE" 2>/dev/null \
            | awk '{print $NF}' \
            | sort -u)
        if [ "$first" = 0 ]; then
            echo -e "\n  \033[2mThese are exported when ops.conf is sourced, but \`ops run\` does NOT\033[0m"
            echo -e "  \033[2mforward them to the container. Pass them with \`-e KEY=VAL\` or\033[0m"
            echo -e "  \033[2m\`--env-file FILE\` at run time, or open an upstream issue if you want\033[0m"
            echo -e "  \033[2manother var added to the auto-propagated list.\033[0m"
        fi
    fi
}

# `ops volume list` — listing of ops-labelled volumes (label ops.volume=true).
# Subcommand kept narrow on purpose: deeper plumbing belongs to
# `ops runtime volume …` (raw runtime proxy). The point of `ops volume`
# is to give users a curated view that matches ops semantics (per-agent
# volumes, ops-share-* defaults, isolated volumes).
cmd_volume() {
    local sub="${1:-}"
    case "$sub" in
        list|ls)
            shift
            local agents_only=0
            while [ $# -gt 0 ]; do
                case "$1" in
                    --agent|--agents) agents_only=1; shift ;;
                    -h|--help)
                        cat <<EOF
Usage: $(basename "$0") volume list [--agent]

List ops-managed Docker volumes (filter: label=ops.volume=true).

  --agent  Only show per-agent credential volumes (ops-claude,
           ops-gemini, ops-opencode, ops-codex).

Without --agent, all ops-* volumes are listed (including the shared
ops-share-nix / ops-share-mise defaults and any per-container volumes
created by --isolated-volumes).
EOF
                        return 0
                        ;;
                    *)
                        echo "Error: unknown 'volume list' option '$1'" >&2
                        return 1
                        ;;
                esac
            done
            local name
            while IFS= read -r name; do
                [ -z "$name" ] && continue
                if [ "$agents_only" = 1 ]; then
                    case "$name" in
                        ops-claude|ops-gemini|ops-opencode|ops-codex)
                            printf '%s\n' "$name"
                            ;;
                    esac
                else
                    printf '%s\n' "$name"
                fi
            done < <("$RUNTIME_BIN" volume ls --filter label=ops.volume=true --format '{{.Name}}' 2>/dev/null)
            return 0
            ;;
        ""|-h|--help)
            cat <<EOF
Usage: $(basename "$0") volume <subcommand>

Inspect ops-managed volumes (filter: label=ops.volume=true).

Subcommands:
  list [--agent]   List ops volumes (optionally restricted to per-agent
                   credential volumes: ops-claude, ops-gemini, …)

Raw operations (rm, inspect, etc.) are not exposed here yet — use
'ops runtime volume <cmd>' for the full runtime CLI.
EOF
            return 0
            ;;
        *)
            echo "Error: unknown volume subcommand '$sub' (try 'list')" >&2
            return 1
            ;;
    esac
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
_OPS_RESERVED=" nerdctl build runtime status info logs log clean run help -h --help alias aliases image images doctor inspect config backup restore update version --version -V env volume "

# Single source of truth for env vars that ops auto-propagates host →
# container at run time. cmd_run iterates this to emit `--env KEY=VAL`
# args, cmd_env reads it for the diagnostic, and `ops env --help` reads
# the parallel _OPS_AUTO_PROPAGATED_DESC for the prose enumeration.
# Adding a new auto-propagated secret is a two-line change (name + desc)
# at this single location — no drift between code and help text.
#
# Indexed array (not associative) because we need iteration order to
# match between the diagnostic output and the help block. Bash 4
# associative array iteration is implementation-defined.
_OPS_AUTO_PROPAGATED_ENVS=(GITHUB_TOKEN ANTHROPIC_API_KEY OPENAI_API_KEY GEMINI_API_KEY)
declare -A _OPS_AUTO_PROPAGATED_DESC=(
    [GITHUB_TOKEN]="Lifts GitHub API rate limit during builds"
    [ANTHROPIC_API_KEY]="Used by --claude"
    [OPENAI_API_KEY]="Used by --codex"
    [GEMINI_API_KEY]="Used by --gemini"
)

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

# Set by _resolve_image to the OPS_IMAGES key in use (empty when -i points
# to a raw image ref outside OPS_IMAGES). build_image reads it to look up
# per-profile --build-arg entries in OPS_BUILD_ARGS.
_OPS_IMAGE_KEY=""

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
            -r|--runtime)       OPS_RUNTIME="$2"; export OPS_RUNTIME
                                # Re-resolve so RUNTIME_BIN points at the
                                # newly-picked runtime; also resets the
                                # rootless cache (handled inside
                                # _resolve_runtime). Validation happens
                                # there too — invalid values exit 1.
                                _resolve_runtime
                                shift 2 ;;
            -H|--nerdctl-home)  OPS_NERDCTL_HOME="$(realpath -m "$2")"
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
        nerdctl|alias|aliases|image|images|help|-h|--help|config|version|--version|-V) return 0 ;;
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
        # Dedicated name so a future top-level refactor can't clash with the
        # `_i` local used inside ensure_buildkitd().
        _containerd_retry=0
        while ! systemctl --user is-active containerd.service >/dev/null 2>&1 || [ ! -d "/run/user/$(id -u)/containerd-rootless" ]; do
            sleep 1; _containerd_retry=$((_containerd_retry+1))
            [ $_containerd_retry -ge "$OPS_CONTAINERD_STARTUP_TIMEOUT" ] && { echo "Timeout after ${OPS_CONTAINERD_STARTUP_TIMEOUT}s: containerd is not responding. Check: systemctl --user status containerd" >&2; exit 1; }
        done
        unset _containerd_retry
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
    self-update)    shift; cmd_update_self "$@" ;;
    update)         shift; cmd_update "$@" ;;
    build)          shift; cmd_run --build "$@" ;;
    runtime)        shift; cmd_runtime "$@" ;;
    status|info)    shift; cmd_status "$@" ;;
    logs|log)       shift; cmd_logs "$@" ;;
    clean)          shift; cmd_clean "$@" ;;
    run)            shift; cmd_run "$@" ;;
    alias|aliases)  shift; cmd_aliases "$@" ;;
    image|images)   shift; cmd_images "$@" ;;
    env)            shift; cmd_env "$@" ;;
    volume|volumes) shift; cmd_volume "$@" ;;
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
