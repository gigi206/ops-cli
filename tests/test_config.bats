#!/usr/bin/env bats
# Config file loading (~/.config/ops/ops.conf via XDG_CONFIG_HOME)

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
    # Make XDG_CONFIG_HOME point somewhere we control
    export XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/config"
    mkdir -p "$XDG_CONFIG_HOME/ops"
}

@test "config file is sourced and its OPS_IMAGE used" {
    cat > "$XDG_CONFIG_HOME/ops/ops.conf" <<'EOF'
OPS_IMAGE=from-config/my-img
EOF
    # Don't set OPS_IMAGE via env so config wins
    run env -u OPS_IMAGE OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"from-config/my-img"* ]]
}

@test "env var overrides config file" {
    # Canonical pattern: use :- so env takes precedence when set.
    # Plain `OPS_IMAGE=...` in ops.conf would unconditionally overwrite env.
    cat > "$XDG_CONFIG_HOME/ops/ops.conf" <<'EOF'
OPS_IMAGE=${OPS_IMAGE:-from-config/my-img}
EOF
    run env OPS_IMAGE=from-env/other OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"from-env/other"* ]]
    [[ "$output" != *"from-config/my-img"* ]]
}

@test "missing config file is not an error" {
    rm -rf "$XDG_CONFIG_HOME/ops"
    run env OPS_RUNTIME=docker "$(ops_sh)" help
    [ "$status" -eq 0 ]
}

@test "config can set OPS_RUNTIME" {
    cat > "$XDG_CONFIG_HOME/ops/ops.conf" <<'EOF'
OPS_RUNTIME=podman
EOF
    mock_runtime podman
    run env -u OPS_RUNTIME "$(ops_sh)" help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Runtime: podman"* ]]
}

@test "config can set OPS_CONTAINER_NAME" {
    cat > "$XDG_CONFIG_HOME/ops/ops.conf" <<'EOF'
OPS_CONTAINER_NAME=from-config-ctn
EOF
    run env -u OPS_CONTAINER_NAME OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"from-config-ctn"* ]]
}
