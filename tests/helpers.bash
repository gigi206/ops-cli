#!/usr/bin/env bash
# Shared helpers for bats tests.
#
# Isolation model: every test runs in its own subshell with a per-test
# $BATS_TEST_TMPDIR (bats-core ≥ 1.8), which is what setup_mocks() /
# setup_ops_env() / mock_runtime_rich() root all their state in. That means
# PATH tweaks, MOCK_STATE, XDG_CACHE_HOME and HOME overrides never leak
# between tests — a dedicated `teardown()` would be redundant.
#
# Assertion helpers below (assert_success, assert_output_contains, …) exist so
# new tests can emit precise diagnostics on failure without the boilerplate
# `[ "$status" -eq 0 ] || { echo …; false; }` dance.

# Resolve the absolute path to ops.sh from the tests directory.
ops_sh() {
    echo "$BATS_TEST_DIRNAME/../ops.sh"
}

# ---- assertion helpers -----------------------------------------------------
# All helpers assume `run` has just executed: $status and $output are set.
# On failure they print the captured output to stderr so bats surfaces it in
# the TAP log with full context (much easier to debug a CI failure than the
# bare `in test file …` single-line default).

assert_success() {
    if [ "${status:-0}" -ne 0 ]; then
        printf 'assert_success: expected status 0, got %s\noutput:\n%s\n' \
            "${status}" "${output-<unset>}" >&2
        return 1
    fi
}

assert_failure() {
    # Optional first arg = expected non-zero status.
    if [ "${status:-0}" -eq 0 ]; then
        printf 'assert_failure: expected non-zero status, got 0\noutput:\n%s\n' \
            "${output-<unset>}" >&2
        return 1
    fi
    if [ -n "${1:-}" ] && [ "${status}" -ne "$1" ]; then
        printf 'assert_failure: expected status %s, got %s\noutput:\n%s\n' \
            "$1" "${status}" "${output-<unset>}" >&2
        return 1
    fi
}

assert_output_contains() {
    if [[ "${output-}" != *"$1"* ]]; then
        printf 'assert_output_contains: %q not found\noutput:\n%s\n' \
            "$1" "${output-<unset>}" >&2
        return 1
    fi
}

refute_output_contains() {
    if [[ "${output-}" == *"$1"* ]]; then
        printf 'refute_output_contains: %q WAS present\noutput:\n%s\n' \
            "$1" "${output-<unset>}" >&2
        return 1
    fi
}

# Count occurrences of a literal pattern in $output (no regex). Useful for
# catching over-matching bugs where a label or flag leaks multiple times.
output_count() {
    grep -oF -- "$1" <<< "${output-}" | wc -l | tr -d '[:space:]'
}

# Make an isolated copy of ops.sh in $BATS_TEST_TMPDIR and print its path.
# Use this when a test needs to exercise the `Dockerfile.<key>` auto-detection
# path (ops.sh looks next to itself via SCRIPT_DIR) without dropping files
# into the real repo — `$BATS_TEST_TMPDIR` is cleaned up automatically by
# bats between tests, so no `trap EXIT` housekeeping is needed.
# Creating the Dockerfile fixture next to the copy is safe:
#   local ops_bin; ops_bin=$(isolated_ops)
#   echo "FROM scratch" > "$(dirname "$ops_bin")/Dockerfile.autodetect"
#   run env OPS_RUNTIME=docker "$ops_bin" build -i autodetect
isolated_ops() {
    local d="$BATS_TEST_TMPDIR/ops-bin"
    mkdir -p "$d"
    cp "$BATS_TEST_DIRNAME/../ops.sh" "$d/ops.sh"
    chmod +x "$d/ops.sh"
    printf '%s' "$d/ops.sh"
}

# Sets up a mock runtime binary (docker/podman/nerdctl) in a temp PATH dir
# so ops.sh calls can be traced without hitting a real daemon.
#
# Behavior of the mock is parameterized via env vars that tests can set
# BEFORE calling this (propagated via `env` in `run`):
#   MOCK_SEC_OPTIONS   → output of `info --format '{{.SecurityOptions}}'`
#                        (default: '[name=rootless]')
#   MOCK_ROOTLESS      → output of `info --format '{{.Host.Security.Rootless}}'`
#                        (default: 'true')
#   MOCK_IMAGE_EXISTS  → controls `images -q`: 1=emit id (exists), 0=empty
#                        (default: 1)
#   MOCK_RUNTIME_VERSION → `--version` output (default: "mock version 1.0.0")
#   MOCK_LOG           → path where the mock appends each call (one line per call)
setup_mocks() {
    export MOCK_DIR="$BATS_TEST_TMPDIR/mocks"
    export MOCK_LOG="$BATS_TEST_TMPDIR/mock.log"
    mkdir -p "$MOCK_DIR"
    : > "$MOCK_LOG"
    export PATH="$MOCK_DIR:$PATH"
}

# Create a mock binary named $1 in MOCK_DIR.
# Tunable via env vars:
#   MOCK_SEC_OPTIONS     docker info SecurityOptions output (default rootless)
#   MOCK_ROOTLESS        podman Host.Security.Rootless (default true)
#   MOCK_RUNTIME_VERSION --version output (default "mock version 1.0.0")
#   MOCK_IMAGE_EXISTS    images -q returns id (1) or empty (0); default 1
#   MOCK_CONTAINER_RUNNING  ps returns OPS_CONTAINER_NAME (1/0); default 0
#   MOCK_CONTAINER_EXISTS   ps -a returns OPS_CONTAINER_NAME (1/0); default 0
#   MOCK_DANGLING            image ls -f dangling=true emits a line (1/0); default 0
#   MOCK_CONTAINER_MOUNTS   comma-separated list reported by container inspect
#
# For richer scenarios (status/doctor/update with container+image state),
# use mock_runtime_rich instead — see its block below for the full env var
# matrix. The basic mock here is sufficient for ~85 % of the suite and
# deliberately stays small to keep the per-test setup overhead negligible.
mock_runtime() {
    local name="$1"
    cat > "$MOCK_DIR/$name" <<'MOCK_EOF'
#!/bin/bash
# Log every call (one line) for test assertions.
printf '%s\n' "$*" >> "${MOCK_LOG:-/dev/null}"

# Detect -a flag anywhere in args (for ps)
_has_all_flag=0
for _a in "$@"; do [ "$_a" = "-a" ] && _has_all_flag=1; done

case "$1" in
    info)
        shift
        while [ $# -gt 0 ]; do
            case "$1" in
                --format)
                    case "$2" in
                        '{{.SecurityOptions}}')           echo "${MOCK_SEC_OPTIONS-[name=rootless]}" ;;
                        '{{.Host.Security.Rootless}}')    echo "${MOCK_ROOTLESS:-true}" ;;
                    esac
                    shift 2
                    ;;
                *) shift ;;
            esac
        done
        ;;
    --version)
        echo "${MOCK_RUNTIME_VERSION:-mock version 1.0.0}"
        ;;
    build)
        # Lets tests exercise the `build_image || exit $?` failure path by
        # exporting MOCK_BUILD_FAIL=1 — the mock then exits non-zero to
        # simulate e.g. a Nix fetch error.
        [ "${MOCK_BUILD_FAIL:-0}" = "1" ] && exit 2
        ;;
    images)
        [ "${MOCK_IMAGE_EXISTS:-1}" = "1" ] && echo "sha256:deadbeefcafe"
        ;;
    ps)
        # ps -a → list all; ps → only running
        if [ "$_has_all_flag" = "1" ]; then
            [ "${MOCK_CONTAINER_EXISTS:-0}" = "1" ] && echo "${OPS_CONTAINER_NAME:-test-container}"
        else
            [ "${MOCK_CONTAINER_RUNNING:-0}" = "1" ] && echo "${OPS_CONTAINER_NAME:-test-container}"
        fi
        ;;
    container)
        case "$2" in
            inspect)
                # If container "exists" per mock, return something.
                if [ "${MOCK_CONTAINER_EXISTS:-0}" = "1" ] || [ "${MOCK_CONTAINER_RUNNING:-0}" = "1" ]; then
                    echo "${MOCK_CONTAINER_MOUNTS:-}"
                else
                    exit 1
                fi
                ;;
        esac
        ;;
    image)
        case "$2" in
            inspect) echo "sha256:deadbeefcafe" ;;
            ls)
                # -f dangling=true emits a dangling image if requested
                for _a in "$@"; do [ "$_a" = "dangling=true" ] && \
                    [ "${MOCK_DANGLING:-0}" = "1" ] && echo "sha256:dangling  <none>:<none>"; done
                ;;
        esac
        ;;
    volume)
        case "$2" in
            ls) ;;      # empty list
            create) ;;  # succeed silently
            rm) ;;      # ditto
        esac
        ;;
    start|exec|run|logs|rm|stop|kill|rmi)
        ;;  # silent success
    *) ;;
esac
exit 0
MOCK_EOF
    chmod +x "$MOCK_DIR/$name"
}

# Richer mock that simulates stateful image/container inspection used by
# cmd_status (visual rendering), cmd_doctor (container orphan/mismatch), and
# cmd_update (image-ID diff before/after a build). Writes $1 (the binary
# name) into $MOCK_DIR; reads its configuration from env vars set by the
# caller before `run`.
#
# Runtime knobs (all optional):
#   MOCK_SEC_OPTIONS       docker info SecurityOptions     (default [name=rootless])
#   MOCK_PS_LINE           one line for `ps -a --format 'Names|Image|Status|Command'`
#                          (used by cmd_status)
#   MOCK_PS_LABELED        one name for `ps -a --filter label=ops.container=true`
#                          (used by cmd_status / cmd_clean)
#   MOCK_PS_LABELED_FULL   one `Name|Image` line for the same filter with a
#                          --format '{{.Names}}|{{.Image}}' (used by cmd_doctor)
#   MOCK_CTNS_ON_OLD       comma-separated container names to report as running
#                          on MOCK_OLD_ID (used by cmd_update post-build prompt)
#   MOCK_IMG_MISSING       image ref whose `image inspect` must return 1 — use
#                          to simulate orphaned containers
#   MOCK_IMG_INSPECT_FAIL_ALL=1   make `image inspect` fail for EVERY ref —
#                          use to drive the "no such key/container/image"
#                          branch of cmd_inspect
#   MOCK_OLD_ID            `.Id` returned BEFORE any `build` call   (default sha256:oldid)
#   MOCK_NEW_ID            `.Id` returned AFTER a `build` call       (default sha256:newid)
#   MOCK_CLI_USER          container inspect value for ops.cmdline.user label
#   MOCK_CLI_REAL          container inspect value for ops.cmdline.real label
#
# Build state is tracked via a flag file so a mock call to `build` flips the
# subsequent `.Id` inspection from OLD to NEW within the same test.
mock_runtime_rich() {
    local name="${1:-docker}"
    export MOCK_STATE="$BATS_TEST_TMPDIR/mock-state"
    mkdir -p "$MOCK_STATE"
    cat > "$MOCK_DIR/$name" <<'MOCK_RICH_EOF'
#!/bin/bash
printf '%s\n' "$*" >> "${MOCK_LOG:-/dev/null}"
case "$1" in
    info)
        case "$*" in
            *'{{.SecurityOptions}}'*)         echo "${MOCK_SEC_OPTIONS-[name=rootless]}" ;;
            *'{{.Host.Security.Rootless}}'*)  echo "${MOCK_ROOTLESS:-true}" ;;
        esac
        ;;
    --version) echo "${MOCK_RUNTIME_VERSION:-mock version 1.0.0}" ;;
    build)
        # Flip the image-ID flag so `.Id` inspections return MOCK_NEW_ID
        # from now on (used by cmd_update's pre/post-build diff).
        touch "$MOCK_STATE/built"
        ;;
    images)
        [ "${MOCK_IMAGE_EXISTS:-1}" = "1" ] && echo "sha256:deadbeefcafe"
        ;;
    ps)
        # Three observed call shapes, detected by the --format or --filter tokens:
        #   1. filter label=ops.container=true --format '{{.Names}}'               → MOCK_PS_LABELED
        #   2. filter label=ops.container=true --format '{{.Names}}|{{.Image}}'    → MOCK_PS_LABELED_FULL
        #   3. no filter --format '{{.Names}}|{{.ImageID}}'                        → loop MOCK_CTNS_ON_OLD
        #   4. no filter --format '{{.Names}}|{{.Image}}|{{.Status}}|{{.Command}}' → MOCK_PS_LINE
        if [[ "$*" == *"label=ops.container=true"* ]]; then
            if [[ "$*" == *'{{.Image}}'* ]]; then
                [ -n "${MOCK_PS_LABELED_FULL:-}" ] && echo "$MOCK_PS_LABELED_FULL"
            else
                [ -n "${MOCK_PS_LABELED:-}" ] && echo "$MOCK_PS_LABELED"
            fi
            exit 0
        fi
        if [[ "$*" == *'{{.ImageID}}'* ]]; then
            if [ -n "${MOCK_CTNS_ON_OLD:-}" ]; then
                IFS=',' read -ra _names <<< "$MOCK_CTNS_ON_OLD"
                for _n in "${_names[@]}"; do
                    printf '%s|%s\n' "$_n" "${MOCK_OLD_ID:-sha256:oldid}"
                done
            fi
            exit 0
        fi
        [ -n "${MOCK_PS_LINE:-}" ] && echo "$MOCK_PS_LINE"
        ;;
    image)
        case "$2" in
            inspect)
                _ref="$3"
                # Simulate a missing image for orphan / doctor tests.
                if [ "$_ref" = "${MOCK_IMG_MISSING:-}" ]; then
                    exit 1
                fi
                # Simulate every image being missing (for cmd_inspect's
                # "not found" branch when the profile/container paths also miss).
                if [ "${MOCK_IMG_INSPECT_FAIL_ALL:-0}" = "1" ]; then
                    exit 1
                fi
                # Pick the response shape off the --format token.
                if [[ "$*" == *'.Id'* ]]; then
                    if [ -f "$MOCK_STATE/built" ]; then
                        echo "${MOCK_NEW_ID:-sha256:newid}"
                    else
                        echo "${MOCK_OLD_ID:-sha256:oldid}"
                    fi
                elif [[ "$*" == *'.Size'* ]]; then
                    echo "2000000000|2026-04-20T10:00:00Z|"
                else
                    echo "ok"
                fi
                ;;
            ls) ;;
        esac
        ;;
    container)
        case "$2" in
            inspect)
                # Simulate "container doesn't exist" when requested (used by
                # cmd_inspect's "not found" branch).
                if [ "${MOCK_CTN_INSPECT_FAIL_ALL:-0}" = "1" ]; then
                    exit 1
                fi
                case "$*" in
                    *ops.cmdline.user*) echo "${MOCK_CLI_USER:-}" ;;
                    *ops.cmdline.real*) echo "${MOCK_CLI_REAL:-}" ;;
                    *ops.dockerfile*)   echo "" ;;
                    *Mounts*)           echo "" ;;
                    *)                  echo "ok" ;;
                esac
                ;;
        esac
        ;;
    volume)
        case "$2" in
            ls|inspect|create|rm) ;;
        esac
        ;;
    start|exec|run|logs|rm|stop|kill|rmi) ;;
esac
exit 0
MOCK_RICH_EOF
    chmod +x "$MOCK_DIR/$name"
}

# Configure deterministic ops env for tests.
setup_ops_env() {
    export OPS_IMAGE="localhost/test-img"
    export OPS_CONTAINER_NAME="test-container"
    export OPS_USER_UID=1000
    export OPS_USER_GID=1000
    export OPS_USER_NAME=testuser
    export OPS_USER_LANG=en_US.UTF-8
    # Isolate HOME so cmd_uninstall / bind-mount defaults don't touch the
    # dev machine's real files.
    export HOME="$BATS_TEST_TMPDIR/home"
    mkdir -p "$HOME"
    # Isolate from user's real ~/.config/ops/ops.conf
    export XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/no-config"
    # Isolate hash cache too
    export XDG_CACHE_HOME="$BATS_TEST_TMPDIR/cache"
    # Disable GITHUB_TOKEN propagation noise
    unset GITHUB_TOKEN
}

# Writes a minimal Dockerfile next to ops.sh so current_hash() works,
# unless one already exists. Returns the path.
ensure_dockerfile() {
    local df="$BATS_TEST_TMPDIR/Dockerfile"
    printf 'FROM scratch\nCMD ["/bin/sh"]\n' > "$df"
    export OPS_DOCKERFILE="$df"
}

# Installs mocks for the system tools used by cmd_install / cmd_self_update.
# Behavior controlled by env vars:
#   MOCK_GH_VERSION    tag_name value returned by GitHub API (default v1.2.3)
#   MOCK_GH_FAIL       if 1, curl against api.github.com fails
#   MOCK_TAR_FAIL      if 1, tar -xzf fails
#   MOCK_SYSTEMCTL_LOG file where systemctl calls are logged
#   MOCK_UNAME_ARCH    uname -m output (default x86_64)
mock_install_tools() {
    local d="$MOCK_DIR"
    : "${MOCK_SYSTEMCTL_LOG:="$BATS_TEST_TMPDIR/systemctl.log"}"
    export MOCK_SYSTEMCTL_LOG
    : > "$MOCK_SYSTEMCTL_LOG"

    # State dir is persisted between invocations of mock curl so the second
    # curl call (SHA256SUMS) can find the tarball written by the first.
    export MOCK_STATE_DIR="$BATS_TEST_TMPDIR/.mock-state"
    mkdir -p "$MOCK_STATE_DIR"

    cat > "$d/curl" <<'EOF'
#!/bin/bash
url=""
outfile=""
while [ $# -gt 0 ]; do
    case "$1" in
        -fsSL|-fsS|-fs|-f|-s|-S|-L) shift ;;
        -o) outfile="$2"; shift 2 ;;
        -*) shift ;;
        http*) url="$1"; shift ;;
        *) shift ;;
    esac
done

if [ "${MOCK_GH_FAIL:-0}" = "1" ] && [[ "$url" == *api.github.com* ]]; then
    exit 22
fi

STATE="${MOCK_STATE_DIR:-/tmp}"
mkdir -p "$STATE"

emit() {
    # Send $1 either to stdout (no -o) or to $outfile.
    if [ -n "$outfile" ]; then
        printf '%s' "$1" > "$outfile"
    else
        printf '%s' "$1"
    fi
}

case "$url" in
    *api.github.com*)
        emit "$(printf '{ "tag_name": "%s" }\n' "${MOCK_GH_VERSION:-v1.2.3}")"
        ;;
    *SHA256SUMS*)
        tb=""
        [ -f "$STATE/tarball" ] && tb=$(cat "$STATE/tarball")
        if [ -n "$tb" ] && [ -f "$tb" ]; then
            hash=$(sha256sum "$tb" | cut -d' ' -f1)
            emit "$(printf '%s  %s\n' "$hash" "$(basename "$tb")")"
        else
            emit "$(printf 'deadbeef  unused.tar.gz\n')"
        fi
        ;;
    *.tar.gz)
        staging=$(mktemp -d)
        mkdir -p "$staging/bin"
        printf '#!/bin/bash\necho nerdctl %s\n' "${MOCK_GH_VERSION:-v1.2.3}" > "$staging/bin/nerdctl"
        chmod +x "$staging/bin/nerdctl"
        printf '#!/bin/bash\nexit 0\n' > "$staging/bin/containerd-rootless-setuptool.sh"
        chmod +x "$staging/bin/containerd-rootless-setuptool.sh"
        tar -czf "$outfile" -C "$staging" bin
        rm -rf "$staging"
        # Persist path for subsequent SHA256SUMS call
        printf '%s\n' "$outfile" > "$STATE/tarball"
        ;;
    *)
        [ -n "$outfile" ] && : > "$outfile"
        ;;
esac
exit 0
EOF
    chmod +x "$d/curl"

    cat > "$d/systemctl" <<'EOF'
#!/bin/bash
printf '%s\n' "$*" >> "${MOCK_SYSTEMCTL_LOG:-/dev/null}"
case "$*" in
    *is-active*) [ "${MOCK_CONTAINERD_ACTIVE:-0}" = "1" ] && exit 0 || exit 3 ;;
esac
exit 0
EOF
    chmod +x "$d/systemctl"

    cat > "$d/uname" <<'EOF'
#!/bin/bash
case "$1" in
    -m) echo "${MOCK_UNAME_ARCH:-x86_64}" ;;
    *) exec /usr/bin/uname "$@" ;;
esac
EOF
    chmod +x "$d/uname"

    # Shim tar to optionally fail on EXTRACT only (-x*). Create (-c*) still
    # works so the curl mock can generate the test tarball while an
    # "extraction fails" test exercises cmd_install's error path.
    cat > "$d/tar" <<'EOF'
#!/bin/bash
if [ "${MOCK_TAR_FAIL:-0}" = "1" ]; then
    for _a in "$@"; do
        case "$_a" in
            -x*|--extract*) echo "mock: tar extraction failed" >&2; exit 1 ;;
        esac
    done
fi
exec /usr/bin/tar "$@"
EOF
    chmod +x "$d/tar"
}

# Answer "Y\nY\n..." lines to stdin for up to N interactive prompts.
answer_yes() {
    local n="${1:-5}"
    yes "Y" | head -n "$n"
}
answer_no() {
    local n="${1:-5}"
    yes "n" | head -n "$n"
}

# Builds an isolated PATH for runtime-detection tests where docker/podman/nerdctl
# must be considered absent unless explicitly mocked. Returns the isolated path
# on stdout (use as: PATH="$(isolated_path):$MOCK_DIR"). The isolated dir contains
# only coreutils symlinks — no docker/podman/nerdctl — so `command -v docker` on a
# host that has real docker in /usr/bin will correctly fail for the test.
isolated_path() {
    local d="$BATS_TEST_TMPDIR/bin-subset"
    if [ ! -d "$d" ]; then
        mkdir -p "$d"
        local t src
        for t in grep sed awk id uname dirname basename cat mkdir rm rmdir \
                 realpath printf sha256sum curl tar systemctl mktemp sleep \
                 xargs cut tee head tail sort wc ls chmod ln touch tr true false \
                 flock kill wait env locale-gen; do
            src=$(command -v "$t" 2>/dev/null) || continue
            ln -s "$src" "$d/$t"
        done
    fi
    printf '%s' "$d"
}

# ---- image-integration helpers ---------------------------------------------
# Used by tests/test_image_integration.bats. They exec into a freshly-spawned
# container from localhost/ops-dev and skip if the image or runtime is absent
# (keeps the bats suite green in environments without Docker, e.g. minimal CI
# runners or dev machines that haven't built the image yet).

# Returns the configured runtime binary (docker/podman/nerdctl), or "" if none
# is available.
image_runtime_bin() {
    local rt
    for rt in docker podman nerdctl; do
        if command -v "$rt" >/dev/null 2>&1; then
            printf '%s' "$rt"
            return 0
        fi
    done
    return 1
}

# Skip the current test unless localhost/ops-dev exists on the local runtime.
# Usage: require_ops_image
require_ops_image() {
    local rt
    rt=$(image_runtime_bin) || { skip "no container runtime found (docker/podman/nerdctl)"; }
    export IMAGE_RUNTIME="$rt"
    "$rt" image inspect localhost/ops-dev >/dev/null 2>&1 \
        || skip "localhost/ops-dev not built — run './ops.sh build' first"
}

# Run a command in a disposable container from localhost/ops-dev. Stdout/exit
# code from the container become $output/$status (use via `run run_in_image`).
# All commands are evaluated via /bin/bash -c, so you can chain with &&, |, etc.
run_in_image() {
    "$IMAGE_RUNTIME" run --rm --entrypoint /bin/bash localhost/ops-dev -c "$*"
}
