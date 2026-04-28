#!/usr/bin/env bats
# cmd_info / cmd_status — dangling-image rendering. When an image carries
# the `ops.dockerfile` label but has lost its tag (typical after a rebuild
# leaves the previous version untagged), the runtime reports it as
# `<none>:<none>`. Pre-fix, ops.sh tried to `image inspect <none>:<none>`,
# which fails, and rendered the row with a red cross + "(not built)" —
# misleading, since the image DOES exist. This file pins the corrected
# behaviour: the row appears as `<dangling>:<short-id>` with a green check
# and the actual size/date/label.

load helpers

setup() {
    setup_ops_env
    ensure_dockerfile

    # Custom mock: replaces setup_mocks + mock_runtime because the standard
    # mocks don't cover `image ls --filter label=ops.dockerfile` with a
    # `Repository:Tag|ID` format. Kept inline so the test stays self-
    # contained and doesn't require helpers.bash extensions for this one
    # narrow scenario.
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
                # Only the `--filter label=ops.dockerfile` lookup is exercised
                # by cmd_info — emit one dangling line so we hit the new code
                # path. Format echoed must match the new request shape:
                # '{{.Repository}}:{{.Tag}}|{{.ID}}'.
                if [[ "$*" == *"label=ops.dockerfile"* ]]; then
                    echo '<none>:<none>|sha256:abc123def4567890abcdef'
                fi
                ;;
            inspect)
                # Match by ID — cmd_info now passes the full sha256:… for
                # dangling refs, so accept exactly that.
                _ref="$3"
                if [[ "$_ref" == sha256:abc123def4567890* ]] \
                   || [ "$_ref" = "localhost/test-img" ]; then
                    # Size|Created|ops.dockerfile-label
                    echo '1500000000|2026-04-28T10:00:00Z|/path/to/Dockerfile.foo'
                else
                    exit 1
                fi
                ;;
        esac
        ;;
    images)
        # cmd_info checks image existence elsewhere via `images -q`.
        echo 'sha256:deadbeef'
        ;;
    ps)
        # No containers — we only care about Images section here.
        ;;
    container|volume) ;;
esac
exit 0
MOCK_EOF
    chmod +x "$MOCK_DIR/docker"
}

@test "info renders <dangling>:<short-id> for ops.dockerfile-labeled <none>:<none>" {
    run env OPS_RUNTIME=docker "$(ops_sh)" info
    assert_success
    assert_output_contains '<dangling>:abc123def456'
}

@test "info shows green check (not red cross) for the dangling image" {
    run env OPS_RUNTIME=docker "$(ops_sh)" info
    assert_success
    # Pull the dangling row out of the output, then verify it carries the
    # green ✓ marker — pre-fix, this row showed the red ✗ + "(not built)"
    # because the inspect-by-name on `<none>:<none>` always failed.
    local row
    row=$(printf '%s\n' "$output" | grep '<dangling>:')
    [ -n "$row" ]
    [[ "$row" == *'✓'* ]]
    [[ "$row" != *'(not built)'* ]]
}

@test "info dangling row carries the dockerfile label and human size" {
    run env OPS_RUNTIME=docker "$(ops_sh)" info
    assert_success
    # The basename of /path/to/Dockerfile.foo is `Dockerfile.foo` — used as
    # the `(label)` since no OPS_IMAGES key maps to this dangling ref.
    assert_output_contains 'Dockerfile.foo'
    # 1.5 GB → "1.4GiB" via _human_bytes (1500000000/1073741824 ≈ 1.4)
    assert_output_contains 'GiB'
}

@test "info does NOT show raw <none>:<none> for ops.dockerfile-labeled images" {
    run env OPS_RUNTIME=docker "$(ops_sh)" info
    assert_success
    refute_output_contains '<none>:<none>'
}
