#!/usr/bin/env bats
# OPS_IMAGES profiles: declarative image registry in ops.conf.
# Smart -i resolves named profiles to image + dockerfile + container_name.

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
    export XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/config"
    mkdir -p "$XDG_CONFIG_HOME/ops"
}

_write_conf() {
    cat > "$XDG_CONFIG_HOME/ops/ops.conf"
}

@test "-i <profile-name> resolves to mapped image" {
    _write_conf <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[ml]="localhost/ops-ml"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" run -i ml --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"localhost/ops-ml"* ]]
}

@test "-i <profile-name> derives container name from key when not mapped" {
    _write_conf <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[ml]="localhost/ops-ml"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" run -i ml --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"--name ml"* ]]
}

@test "-i <profile-name> uses OPS_CONTAINER_NAMES mapping when present" {
    _write_conf <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[ml]="localhost/ops-ml"
declare -A OPS_CONTAINER_NAMES
OPS_CONTAINER_NAMES[ml]="custom-ctn"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" run -i ml --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"--name custom-ctn"* ]]
}

@test "-n overrides profile container name (flag order 1)" {
    _write_conf <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[ml]="localhost/ops-ml"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" run -i ml -n explicit --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"--name explicit"* ]]
    [[ "$output" != *"--name ml"* ]]
}

@test "-n overrides profile container name (flag order 2: -n before -i)" {
    _write_conf <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[ml]="localhost/ops-ml"
declare -A OPS_CONTAINER_NAMES
OPS_CONTAINER_NAMES[ml]="from-profile"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" run -n explicit -i ml --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"--name explicit"* ]]
    [[ "$output" != *"from-profile"* ]]
}

@test "-f overrides profile dockerfile (flag order 1)" {
    _write_conf <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[ml]="localhost/ops-ml"
declare -A OPS_DOCKERFILES
OPS_DOCKERFILES[ml]="Dockerfile.ml"
EOF
    local custom="$BATS_TEST_TMPDIR/Custom.Dockerfile"
    echo "FROM scratch" > "$custom"
    run env OPS_RUNTIME=docker "$(ops_sh)" build -i ml -f "$custom"
    [ "$status" -eq 0 ]
    grep -qE "build .*--file $custom" "$MOCK_LOG"
    ! grep -qE 'Dockerfile\.ml' "$MOCK_LOG"
}

@test "-f overrides profile dockerfile (flag order 2: -f before -i)" {
    _write_conf <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[ml]="localhost/ops-ml"
declare -A OPS_DOCKERFILES
OPS_DOCKERFILES[ml]="Dockerfile.ml"
EOF
    local custom="$BATS_TEST_TMPDIR/Custom.Dockerfile"
    echo "FROM scratch" > "$custom"
    run env OPS_RUNTIME=docker "$(ops_sh)" build -f "$custom" -i ml
    [ "$status" -eq 0 ]
    grep -qE "build .*--file $custom" "$MOCK_LOG"
}

@test "-i <raw-image-name> falls through when not a declared profile" {
    _write_conf <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[ml]="localhost/ops-ml"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" run -i alpine:latest --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"alpine:latest"* ]]
    # Not-a-profile → container name stays at default (not "alpine:latest" as key)
    [[ "$output" == *"--name test-container"* ]]
}

@test "-i works globally before the subcommand" {
    _write_conf <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[ml]="localhost/ops-ml"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" -i ml run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"localhost/ops-ml"* ]]
}

@test "profile uses Dockerfile.<name> convention when OPS_DOCKERFILES absent" {
    local custom="$BATS_TEST_TMPDIR/Dockerfile.autodetect"
    echo "FROM scratch" > "$custom"
    # Put it next to ops.sh so SCRIPT_DIR lookup finds it
    cp "$custom" "$BATS_TEST_DIRNAME/../Dockerfile.autodetect"
    trap "rm -f '$BATS_TEST_DIRNAME/../Dockerfile.autodetect'" EXIT

    _write_conf <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[autodetect]="localhost/ops-auto"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" build -i autodetect
    [ "$status" -eq 0 ]
    grep -qE "build .*Dockerfile.autodetect" "$MOCK_LOG"
}

@test "images subcommand lists declared profiles" {
    _write_conf <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[ml]="localhost/ops-ml"
OPS_IMAGES[go]="localhost/ops-go"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" images
    [ "$status" -eq 0 ]
    [[ "$output" == *"ml"* ]]
    [[ "$output" == *"localhost/ops-ml"* ]]
    [[ "$output" == *"go"* ]]
    [[ "$output" == *"localhost/ops-go"* ]]
}

@test "image subcommand (singular) also works" {
    _write_conf <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[ml]="localhost/ops-ml"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" image
    [ "$status" -eq 0 ]
    [[ "$output" == *"ml"* ]]
}

@test "images subcommand with no profiles shows '(none defined)'" {
    rm -rf "$XDG_CONFIG_HOME/ops"
    run env OPS_RUNTIME=docker "$(ops_sh)" images
    [ "$status" -eq 0 ]
    [[ "$output" == *"(none defined)"* ]]
}

@test "profile resolution applies all three at once" {
    _write_conf <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[ml]="localhost/ops-ml"
declare -A OPS_CONTAINER_NAMES
OPS_CONTAINER_NAMES[ml]="ml-ctn"
EOF
    # A dockerfile next to ops.sh for Dockerfile.ml
    local df="$BATS_TEST_DIRNAME/../Dockerfile.ml"
    echo "FROM scratch" > "$df"
    trap "rm -f '$df'" EXIT

    run env OPS_RUNTIME=docker "$(ops_sh)" run -i ml --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"localhost/ops-ml"* ]]
    [[ "$output" == *"--name ml-ctn"* ]]
}
