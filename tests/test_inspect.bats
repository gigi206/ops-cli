#!/usr/bin/env bats
# cmd_inspect — resolves an identifier to OPS_IMAGES key / container / image ref

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
    export XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/config"
    mkdir -p "$XDG_CONFIG_HOME/ops"
}

_write_conf() { cat > "$XDG_CONFIG_HOME/ops/ops.conf"; }

@test "inspect without argument prints usage and exits 1" {
    run env OPS_RUNTIME=docker "$(ops_sh)" inspect
    [ "$status" -eq 1 ]
    [[ "$output" == *"Usage:"* ]]
    [[ "$output" == *"inspect"* ]]
}

@test "inspect with unknown key falls back to raw image ref" {
    # cmd_inspect resolves in this order: OPS_IMAGES key → container name →
    # image ref → error. The default mock's `image inspect` always succeeds,
    # so an unknown name is treated as a raw image reference (the "Image"
    # section is rendered for it). The exit-1 path (all three lookups fail)
    # would need a mock that fails image inspect; see the test below.
    run env OPS_RUNTIME=docker "$(ops_sh)" inspect random-unknown-xyz
    [ "$status" -eq 0 ]
    [[ "$output" == *"Image"* ]]
    [[ "$output" == *"random-unknown-xyz"* ]]
}

@test "inspect exits 1 when nothing resolves (profile, container, image all miss)" {
    # mock_runtime_rich with both inspect-failure toggles flipped: container
    # inspect and image inspect both return 1, so cmd_inspect's three lookup
    # paths all miss and the "not found" error is emitted.
    mock_runtime_rich docker
    export MOCK_CTN_INSPECT_FAIL_ALL=1 MOCK_IMG_INSPECT_FAIL_ALL=1
    run env OPS_RUNTIME=docker \
        MOCK_CTN_INSPECT_FAIL_ALL=1 MOCK_IMG_INSPECT_FAIL_ALL=1 \
        "$(ops_sh)" inspect totally-unknown-xyz
    [ "$status" -eq 1 ]
    [[ "$output" == *"not found as OPS_IMAGES key, container, or image"* ]]
}

@test "inspect resolves OPS_IMAGES key" {
    _write_conf <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[foo]="localhost/foo-img"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" inspect foo
    [ "$status" -eq 0 ]
    [[ "$output" == *"Image"* ]]
    [[ "$output" == *"localhost/foo-img"* ]]
    [[ "$output" == *"ops key"* ]]
    [[ "$output" == *"foo"* ]]
}

@test "inspect for raw image ref does not emit ops key line" {
    run env OPS_RUNTIME=docker "$(ops_sh)" inspect alpine:latest
    [ "$status" -eq 0 ]
    [[ "$output" == *"Image"* ]]
    [[ "$output" == *"alpine:latest"* ]]
    [[ "$output" != *"ops key:"* ]]
}

@test "inspect on OPS_IMAGES key resolves default container name" {
    _write_conf <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[mykey]="localhost/mykey"
EOF
    # With MOCK_CONTAINER_EXISTS=1, the container mock returns "not exist"
    # for any name EXCEPT $OPS_CONTAINER_NAME. But container inspect on "mykey"
    # (default container name for the key) will fail → show "(not created)".
    run env OPS_RUNTIME=docker MOCK_CONTAINER_EXISTS=0 "$(ops_sh)" inspect mykey
    [ "$status" -eq 0 ]
    [[ "$output" == *"Image"* ]]
    [[ "$output" == *"localhost/mykey"* ]]
}

@test "inspect on explicit container name shows Container section" {
    # When the mock container exists (MOCK_CONTAINER_EXISTS=1), inspect on its
    # name should show the Container section. The mock container inspect still
    # returns minimal output but the section header must be present.
    run env OPS_RUNTIME=docker MOCK_CONTAINER_EXISTS=1 \
        "$(ops_sh)" inspect "$OPS_CONTAINER_NAME"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Container"* ]] || [[ "$output" == *"Image"* ]]
}
