#!/usr/bin/env bats
# cmd_clean — flag matrix + keep-shared default. v1.7.0 introduced
# --no-volumes / --volumes-only / --include-shared and changed the default
# behaviour: volumes named `ops-share-*` are now SKIPPED unless the user
# opts in, because they hold cross-container caches (nix store, mise
# tools) that often represent hours of downloads.

load helpers

setup() {
    setup_ops_env
    ensure_dockerfile

    # Custom mock: standard mock_runtime doesn't return `volume ls` output;
    # we need it to emit a mix of ops-share-* and per-container volumes so
    # the new keep-shared filter has something to filter.
    export MOCK_DIR="$BATS_TEST_TMPDIR/mocks"
    export MOCK_LOG="$BATS_TEST_TMPDIR/mock.log"
    mkdir -p "$MOCK_DIR"
    : > "$MOCK_LOG"
    export PATH="$MOCK_DIR:$PATH"

    cat > "$MOCK_DIR/docker" <<'MOCK_EOF'
#!/bin/bash
printf '%s\n' "$*" >> "${MOCK_LOG:-/dev/null}"
case "$1" in
    info)
        for a in "$@"; do
            case "$a" in
                '{{.SecurityOptions}}')        echo '[name=rootless]' ;;
                '{{.Host.Security.Rootless}}') echo 'true' ;;
            esac
        done
        ;;
    --version) echo 'mock version 1.0.0' ;;
    image)
        case "$2" in
            ls)
                # Only respond to the dangling=true filter (used by clean).
                if [[ "$*" == *"dangling=true"* ]]; then
                    echo 'sha256:dead1|10MB'
                fi
                ;;
            inspect) echo '' ;;  # no ops.dockerfile label
            prune)   ;;
        esac
        ;;
    ps)
        # cmd_clean asks for `ps -a -f status=exited -f label=ops.container=true`
        if [[ "$*" == *"status=exited"* ]]; then
            echo 'ctn1id|ops-stopped-1'
        fi
        ;;
    volume)
        case "$2" in
            ls)
                # Mix of shared (ops-share-*) and isolated (per-container) volumes.
                echo 'ops-share-nix|/var/lib/docker/volumes/ops-share-nix/_data'
                echo 'ops-share-mise|/var/lib/docker/volumes/ops-share-mise/_data'
                echo 'test-container-nix|/var/lib/docker/volumes/test-container-nix/_data'
                ;;
            rm) ;;  # silent success
        esac
        ;;
    rm) ;;  # silent success for container rm
esac
exit 0
MOCK_EOF
    chmod +x "$MOCK_DIR/docker"
}

# ---- default behaviour: shared volumes are kept ------------------------------

@test "clean --dry-run keeps ops-share-* by default" {
    run env OPS_RUNTIME=docker "$(ops_sh)" clean --dry-run
    assert_success
    # Shared volumes appear under the "Skipped (shared cache; …)" section
    assert_output_contains 'ops-share-nix'
    assert_output_contains 'ops-share-mise'
    assert_output_contains 'Skipped (shared cache'
    # The non-shared one is in the prune list (not in the kept section)
    assert_output_contains 'test-container-nix'
}

@test "clean --dry-run summary shows the shared-vs-prune split" {
    run env OPS_RUNTIME=docker "$(ops_sh)" clean --dry-run
    assert_success
    assert_output_contains 'ops volumes (to prune): 1'
    assert_output_contains 'ops volumes (kept):     2'
    assert_output_contains 'use --include-shared'
}

# ---- --include-shared brings the shared volumes back -------------------------

@test "clean --dry-run --include-shared lists ops-share-* in the prune list" {
    run env OPS_RUNTIME=docker "$(ops_sh)" clean --dry-run --include-shared
    assert_success
    refute_output_contains 'Skipped (shared cache'
    assert_output_contains 'ops-share-nix'
    # All three volumes are now in the prune list (count = 3).
    assert_output_contains 'ops volumes (to prune): 3'
}

# ---- --no-volumes ------------------------------------------------------------

@test "clean --dry-run --no-volumes hides the volumes section entirely" {
    run env OPS_RUNTIME=docker "$(ops_sh)" clean --dry-run --no-volumes
    assert_success
    refute_output_contains '=== ops volumes'
    refute_output_contains 'ops-share-nix'
    # But images + containers sections are still shown.
    assert_output_contains '=== Dangling images'
    assert_output_contains '=== Stopped ops containers'
}

# ---- --volumes-only ----------------------------------------------------------

@test "clean --dry-run --volumes-only hides images+containers sections" {
    run env OPS_RUNTIME=docker "$(ops_sh)" clean --dry-run --volumes-only
    assert_success
    refute_output_contains '=== Dangling images'
    refute_output_contains '=== Stopped ops containers'
    assert_output_contains '=== ops volumes'
}

# ---- --images-only -----------------------------------------------------------

@test "clean --dry-run --images-only hides containers+volumes sections" {
    run env OPS_RUNTIME=docker "$(ops_sh)" clean --dry-run --images-only
    assert_success
    assert_output_contains '=== Dangling images'
    refute_output_contains '=== Stopped ops containers'
    refute_output_contains '=== ops volumes'
    # Summary line for containers is gone, image line stays.
    refute_output_contains 'stopped ops containers:'
    assert_output_contains 'dangling images:'
}

@test "clean --images-only prompt mentions images only" {
    run bash -c "echo 'n' | env OPS_RUNTIME=docker $(ops_sh) clean --images-only"
    assert_success
    assert_output_contains 'Prune 1 dangling image(s)?'
    refute_output_contains 'stopped ops container'
}

# ---- error: mutually exclusive flags -----------------------------------------

@test "clean --no-volumes and --volumes-only are mutually exclusive" {
    run env OPS_RUNTIME=docker "$(ops_sh)" clean --no-volumes --volumes-only
    assert_failure
    assert_output_contains 'mutually exclusive'
}

@test "clean --images-only and --volumes-only are mutually exclusive" {
    run env OPS_RUNTIME=docker "$(ops_sh)" clean --images-only --volumes-only
    assert_failure
    assert_output_contains 'mutually exclusive'
}

# ---- error: unknown flag -----------------------------------------------------

@test "clean rejects unknown flags" {
    run env OPS_RUNTIME=docker "$(ops_sh)" clean --bogus
    assert_failure
    assert_output_contains "unknown option"
}

# ---- prompt format -----------------------------------------------------------
#
# These tests verify the prompt count is in the warning string. They use
# `echo n` to answer No so the actual rm calls are skipped — we only care
# about the diagnostic text.

@test "clean prompt shows volume count and the cached-data warning" {
    run bash -c "echo 'n
n' | env OPS_RUNTIME=docker $(ops_sh) clean"
    assert_success
    assert_output_contains 'Remove 1 ops volume(s)?'
    assert_output_contains 'cached data (nix store, mise tools'
}

@test "clean prompt shows image+container counts" {
    run bash -c "echo 'n
n' | env OPS_RUNTIME=docker $(ops_sh) clean"
    assert_success
    assert_output_contains 'Prune 1 dangling image(s) and 1 stopped ops container(s)?'
}

# ---- help -------------------------------------------------------------------

@test "clean --help describes the new flags and the keep-shared default" {
    run env OPS_RUNTIME=docker "$(ops_sh)" clean --help
    assert_success
    assert_output_contains '--no-volumes'
    assert_output_contains '--volumes-only'
    assert_output_contains '--images-only'
    assert_output_contains '--include-shared'
    assert_output_contains 'ops-share-*'
    assert_output_contains 'SKIPPED by default'
}
