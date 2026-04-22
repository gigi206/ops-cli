#!/usr/bin/env bash
# Shared helpers for bats tests.

# Resolve the absolute path to ops.sh from the tests directory.
ops_sh() {
    echo "$BATS_TEST_DIRNAME/../ops.sh"
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
