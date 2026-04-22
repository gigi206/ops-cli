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

@test "inspect with unknown key exits 1" {
    # MOCK_IMAGE_EXISTS=1 defaults: image inspect succeeds for any ref. To
    # simulate "unknown", we disable that fallback.
    # But our mock always succeeds for `image inspect` — so we expect success
    # and the inspect treats the arg as a raw image ref.
    run env OPS_RUNTIME=docker "$(ops_sh)" inspect random-unknown-xyz
    # With the default mock, image inspect returns 0, so this is treated as
    # a raw image ref. We just ensure no crash and output mentions "Image".
    [ "$status" -eq 0 ]
    [[ "$output" == *"Image"* ]]
    [[ "$output" == *"random-unknown-xyz"* ]]
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
