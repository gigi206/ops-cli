#!/usr/bin/env bats
# cmd_config — dumps effective OPS_* config with origin (env/config/default)

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

@test "config subcommand shows Config file section" {
    run env OPS_RUNTIME=docker "$(ops_sh)" config
    [ "$status" -eq 0 ]
    [[ "$output" == *"Config file"* ]]
}

@test "config shows Scalars section with known OPS_* vars" {
    run env OPS_RUNTIME=docker "$(ops_sh)" config
    [ "$status" -eq 0 ]
    [[ "$output" == *"Scalars"* ]]
    [[ "$output" == *"OPS_IMAGE"* ]]
    [[ "$output" == *"OPS_RUNTIME"* ]]
}

@test "config marks env-sourced var as [env]" {
    # setup_ops_env exports OPS_IMAGE=localhost/test-img (from env before config)
    run env OPS_RUNTIME=docker "$(ops_sh)" config
    [ "$status" -eq 0 ]
    [[ "$output" == *"OPS_IMAGE"* ]]
    # Look for [env] marker (possibly wrapped in ANSI color codes — grep for '[env]')
    echo "$output" | grep -E 'OPS_IMAGE.*\[env\]' >/dev/null
}

@test "config marks config-sourced var as [config]" {
    _write_conf <<'EOF'
OPS_FROM_CONFIG_ONLY=hello
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" config
    [ "$status" -eq 0 ]
    echo "$output" | grep -E 'OPS_FROM_CONFIG_ONLY.*\[config\]' >/dev/null
}

@test "config shows Arrays section with OPS_IMAGES entries" {
    _write_conf <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[arch]="localhost/arch"
OPS_IMAGES[deb]="localhost/deb"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" config
    [ "$status" -eq 0 ]
    [[ "$output" == *"Arrays"* ]]
    [[ "$output" == *"OPS_IMAGES"* ]]
    [[ "$output" == *"arch"* ]]
    [[ "$output" == *"localhost/arch"* ]]
    [[ "$output" == *"deb"* ]]
}

@test "config shows Arrays section when OPS_ALIASES defined" {
    _write_conf <<'EOF'
declare -A OPS_ALIASES
OPS_ALIASES[alpha]="run -i a"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" config
    [ "$status" -eq 0 ]
    [[ "$output" == *"OPS_ALIASES"* ]]
    [[ "$output" == *"alpha"* ]]
}

# Regression guard: OPS_APP_FLAGS is a user-facing assoc array (set via
# `ops config set 'OPS_APP_FLAGS[<app>]' ...`) and must render in the
# `=== Arrays ===` section like its siblings. The display loop in
# cmd_config previously omitted it, so a config-set + config round-trip
# left users wondering whether the value had actually persisted.
@test "config shows Arrays section when OPS_APP_FLAGS defined" {
    _write_conf <<'EOF'
declare -A OPS_APP_FLAGS
OPS_APP_FLAGS[claude]="--claude-volume --install"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" config
    [ "$status" -eq 0 ]
    [[ "$output" == *"OPS_APP_FLAGS"* ]]
    [[ "$output" == *"claude"* ]]
    [[ "$output" == *"--claude-volume --install"* ]]
}

@test "config with no arrays still produces valid output" {
    _write_conf <<'EOF'
# no arrays
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" config
    [ "$status" -eq 0 ]
    [[ "$output" == *"Scalars"* ]]
    [[ "$output" == *"Arrays"* ]]
}
