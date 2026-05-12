#!/usr/bin/env bats
# cmd_status (info) — new layout: Services first, Images, Volumes, Containers.
# Features tested: config file display, Images section header, Volumes section,
# Containers section header, (no ops containers) message, services-first order.

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
}

@test "status shows Services section first" {
    run env OPS_RUNTIME=docker "$(ops_sh)" status
    [ "$status" -eq 0 ]
    # Services header must appear before Images / Volumes / Containers
    services_line=$(echo "$output" | grep -n '=== Services ===' | head -1 | cut -d: -f1)
    images_line=$(echo "$output" | grep -n '=== Images ===' | head -1 | cut -d: -f1)
    [ -n "$services_line" ]
    [ -n "$images_line" ]
    [ "$services_line" -lt "$images_line" ]
}

@test "status shows config file with loaded/missing status" {
    run env OPS_RUNTIME=docker "$(ops_sh)" status
    [ "$status" -eq 0 ]
    # The "config:" label is always emitted; the value is followed by either
    # "(loaded, origin: …)" or "(missing, origin: …)" depending on whether
    # ops.conf exists. The "origin:" suffix arrived with -c / --config /
    # OPS_CONFIG support so the user can audit which level resolved the path.
    [[ "$output" == *"config:"* ]]
    [[ "$output" == *"(loaded, origin:"* ]] || [[ "$output" == *"(missing, origin:"* ]]
}

@test "status shows Images section" {
    run env OPS_RUNTIME=docker "$(ops_sh)" status
    [ "$status" -eq 0 ]
    [[ "$output" == *"=== Images ==="* ]]
}

@test "status marks default image" {
    run env OPS_RUNTIME=docker "$(ops_sh)" status
    [ "$status" -eq 0 ]
    # The default image row carries a "(default)" tag; look for the exact
    # combination rather than a bare "default" substring (too laxist).
    [[ "$output" == *"localhost/test-img"*"(default)"* ]]
}

@test "status shows Volumes section" {
    run env OPS_RUNTIME=docker "$(ops_sh)" status
    [ "$status" -eq 0 ]
    [[ "$output" == *"=== Volumes ==="* ]]
}

@test "status shows Containers section" {
    run env OPS_RUNTIME=docker "$(ops_sh)" status
    [ "$status" -eq 0 ]
    [[ "$output" == *"=== Containers ==="* ]]
}

@test "status Volumes section comes BEFORE Containers" {
    run env OPS_RUNTIME=docker "$(ops_sh)" status
    [ "$status" -eq 0 ]
    vol_line=$(echo "$output" | grep -n 'Volumes' | head -1 | cut -d: -f1)
    ctn_line=$(echo "$output" | grep -n 'Containers' | head -1 | cut -d: -f1)
    [ -n "$vol_line" ]
    [ -n "$ctn_line" ]
    [ "$vol_line" -lt "$ctn_line" ]
}

@test "status with no containers shows (no ops containers)" {
    run env OPS_RUNTIME=docker MOCK_CONTAINER_EXISTS=0 "$(ops_sh)" status
    [ "$status" -eq 0 ]
    [[ "$output" == *"no ops containers"* ]]
}

@test "status includes OPS_IMAGES entries in Images section" {
    export XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/config"
    mkdir -p "$XDG_CONFIG_HOME/ops"
    cat > "$XDG_CONFIG_HOME/ops/ops.conf" <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[deb]="localhost/deb-test"
OPS_IMAGES[arch]="localhost/arch-test"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" status
    [ "$status" -eq 0 ]
    [[ "$output" == *"localhost/deb-test"* ]]
    [[ "$output" == *"localhost/arch-test"* ]]
    [[ "$output" == *"deb"* ]]
    [[ "$output" == *"arch"* ]]
}
