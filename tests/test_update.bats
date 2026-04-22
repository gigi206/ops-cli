#!/usr/bin/env bats
# cmd_update — rebuild image and offer to recreate containers on old version

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
}

@test "update without argument builds default image" {
    run bash -c "echo n | env OPS_RUNTIME=docker '$(ops_sh)' update"
    [ "$status" -eq 0 ]
    grep -qE '^build .*-t localhost/test-img' "$MOCK_LOG"
}

@test "update triggers build for the resolved image" {
    run bash -c "echo n | env OPS_RUNTIME=docker '$(ops_sh)' update my-img"
    [ "$status" -eq 0 ]
    grep -qE '^build .*-t my-img' "$MOCK_LOG"
}

@test "update resolves OPS_IMAGES key" {
    export XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/config"
    mkdir -p "$XDG_CONFIG_HOME/ops"
    cat > "$XDG_CONFIG_HOME/ops/ops.conf" <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[foo]="localhost/foo"
EOF
    run bash -c "echo n | env OPS_RUNTIME=docker '$(ops_sh)' update foo"
    [ "$status" -eq 0 ]
    grep -qE '^build .*-t localhost/foo' "$MOCK_LOG"
}

@test "update shows build section header" {
    run bash -c "echo n | env OPS_RUNTIME=docker '$(ops_sh)' update my-img"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Building my-img"* ]]
}
