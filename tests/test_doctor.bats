#!/usr/bin/env bats
# cmd_doctor — validates OPS_IMAGES ↔ Dockerfile ↔ image label coherence

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

@test "doctor runs with no config and reports missing" {
    # No config file at all
    rm -rf "$XDG_CONFIG_HOME/ops"
    run env OPS_RUNTIME=docker "$(ops_sh)" doctor
    # Exit code can be 0 or 1 depending on warnings
    [[ "$output" == *"Config"* ]]
    [[ "$output" == *"missing"* ]] || [[ "$output" == *"$XDG_CONFIG_HOME"* ]]
}

@test "doctor reports config file as loaded when present" {
    _write_conf <<'EOF'
# empty config
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" doctor
    [[ "$output" == *"config"* ]] || [[ "$output" == *"Config"* ]]
    [[ "$output" == *"loaded"* ]] || [[ "$output" == *"$XDG_CONFIG_HOME"* ]]
}

@test "doctor lists OPS_IMAGES keys with their refs" {
    _write_conf <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[foo]="localhost/foo-img"
OPS_IMAGES[bar]="localhost/bar-img"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" doctor
    [[ "$output" == *"foo"* ]]
    [[ "$output" == *"localhost/foo-img"* ]]
    [[ "$output" == *"bar"* ]]
    [[ "$output" == *"localhost/bar-img"* ]]
}

@test "doctor detects dangling OPS_DOCKERFILES entry" {
    _write_conf <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[real]="localhost/real"
declare -A OPS_DOCKERFILES
OPS_DOCKERFILES[ghost]="ghost.Dockerfile"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" doctor
    [[ "$output" == *"Dangling"* ]]
    [[ "$output" == *"ghost"* ]]
}

@test "doctor detects dangling OPS_CONTAINER_NAMES entry" {
    _write_conf <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[real]="localhost/real"
declare -A OPS_CONTAINER_NAMES
OPS_CONTAINER_NAMES[phantom]="phantom-ctn"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" doctor
    [[ "$output" == *"phantom"* ]]
}

@test "doctor shows '(none defined)' when OPS_IMAGES is absent" {
    _write_conf <<'EOF'
# no OPS_IMAGES
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" doctor
    [[ "$output" == *"none defined"* ]]
}

@test "doctor summary line reports OK and warning counts" {
    _write_conf <<'EOF'
# empty
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" doctor
    [[ "$output" == *"Summary"* ]]
    [[ "$output" == *"OK"* ]]
    [[ "$output" == *"warning"* ]]
}

@test "doctor has Containers section" {
    _write_conf <<'EOF'
# empty
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" doctor
    [[ "$output" == *"Containers"* ]]
    [[ "$output" == *"ops.container=true"* ]]
}

@test "doctor shows '(no ops-labeled containers)' when filter returns none" {
    _write_conf <<'EOF'
# empty
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" doctor
    [[ "$output" == *"no ops-labeled containers"* ]]
}
