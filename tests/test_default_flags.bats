#!/usr/bin/env bats
# OPS_DEFAULT_RUN_FLAGS / OPS_APP_FLAGS[<app>] / OPS_ISOLATION_PRESET
#
# These knobs let users wire ops-cli through ops.conf without having to
# rebuild every alias around per-invocation flags. The behaviour is
# verified through `--dry-run` so we observe the resolved docker invocation
# without booting a real container.

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
}

# ---- OPS_DEFAULT_RUN_FLAGS ---------------------------------------------------

@test "OPS_DEFAULT_RUN_FLAGS injects --no-rm globally" {
    # Without --no-rm the docker invocation includes --rm. With OPS_DEFAULT_RUN_FLAGS
    # set to --no-rm, --rm should disappear (the parser sets ephemeral=0).
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *" --rm "* ]] || [[ "$output" == *" --rm"$'\n'* ]] || [[ "$output" == *" --rm "* ]]

    run env OPS_RUNTIME=docker OPS_DEFAULT_RUN_FLAGS="--no-rm" "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" != *" --rm "* ]] && [[ "$output" != *" --rm"$'\n'* ]]
}

@test "OPS_DEFAULT_RUN_FLAGS supports multiple tokens" {
    run env OPS_RUNTIME=docker OPS_DEFAULT_RUN_FLAGS="--no-rm --no-wayland" "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" != *" --rm "* ]] && [[ "$output" != *" --rm"$'\n'* ]]
}

@test "OPS_DEFAULT_RUN_FLAGS empty string is a no-op" {
    run env OPS_RUNTIME=docker OPS_DEFAULT_RUN_FLAGS="" "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
}

# ---- OPS_APP_FLAGS[<app>] ------------------------------------------------

@test "OPS_APP_FLAGS[claude] adds --no-rm only when --app claude is given" {
    # Need a config file because OPS_APP_FLAGS is an associative array —
    # bash can't export assoc arrays via `env`.
    export XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/config"
    mkdir -p "$XDG_CONFIG_HOME/ops"
    cat > "$XDG_CONFIG_HOME/ops/ops.conf" <<'EOF'
declare -A OPS_APP_FLAGS
OPS_APP_FLAGS[claude]="--no-rm"
EOF
    chmod 600 "$XDG_CONFIG_HOME/ops/ops.conf"

    # Without --app claude → --rm stays
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"--rm"* ]]

    # With --app claude → --no-rm wins
    run env OPS_RUNTIME=docker "$(ops_sh)" run --app claude --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" != *" --rm "* ]] && [[ "$output" != *" --rm"$'\n'* ]]
}

@test "OPS_APP_FLAGS[gemini] uses ops-gemini volume when --gemini-volume is the extra" {
    export XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/config"
    mkdir -p "$XDG_CONFIG_HOME/ops"
    cat > "$XDG_CONFIG_HOME/ops/ops.conf" <<'EOF'
declare -A OPS_APP_FLAGS
OPS_APP_FLAGS[gemini]="--gemini-volume"
EOF
    chmod 600 "$XDG_CONFIG_HOME/ops/ops.conf"

    run env OPS_RUNTIME=docker "$(ops_sh)" run --app gemini --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ops-gemini"* ]]
}

@test "OPS_APP_FLAGS empty for an app is a no-op" {
    export XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/config"
    mkdir -p "$XDG_CONFIG_HOME/ops"
    cat > "$XDG_CONFIG_HOME/ops/ops.conf" <<'EOF'
declare -A OPS_APP_FLAGS
OPS_APP_FLAGS[claude]=""
EOF
    chmod 600 "$XDG_CONFIG_HOME/ops/ops.conf"

    run env OPS_RUNTIME=docker "$(ops_sh)" run --app claude --dry-run
    [ "$status" -eq 0 ]
}

# ---- OPS_ISOLATION_PRESET ----------------------------------------------------

@test "OPS_ISOLATION_PRESET=host is the default behavior (HOME mounted)" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"$HOME"* ]]
}

@test "OPS_ISOLATION_PRESET=isolated sets mount_home=0 (HOME bind-mount absent)" {
    run env OPS_RUNTIME=docker OPS_ISOLATION_PRESET=isolated "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    # The HOME bind-mount line `--volume $HOME:/home/...` must be absent.
    [[ "$output" != *"--volume $HOME:"* ]] && [[ "$output" != *" -v $HOME:"* ]]
}

@test "OPS_ISOLATION_PRESET=fully-isolated implies mount_home=0 + app volumes" {
    run env OPS_RUNTIME=docker OPS_ISOLATION_PRESET=fully-isolated "$(ops_sh)" run --app claude --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" != *"--volume $HOME:"* ]]
    [[ "$output" == *"ops-claude"* ]]
}

@test "OPS_ISOLATION_PRESET=volume keeps HOME mounted but auto-uses ops-claude volume" {
    run env OPS_RUNTIME=docker OPS_ISOLATION_PRESET=volume "$(ops_sh)" run --app claude --dry-run
    [ "$status" -eq 0 ]
    # HOME still mounted (not isolated, only volume preset for credentials)
    [[ "$output" == *"$HOME"* ]]
    [[ "$output" == *"ops-claude"* ]]
}

@test "OPS_ISOLATION_PRESET=volume defers to explicit --claude-mount" {
    # User pinned --claude-mount → preset must NOT override to volume.
    run env OPS_RUNTIME=docker OPS_ISOLATION_PRESET=volume "$(ops_sh)" run --no-mount-home --claude-mount --app claude --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" != *"ops-claude"* ]]
}

@test "OPS_ISOLATION_PRESET invalid value errors out" {
    run env OPS_RUNTIME=docker OPS_ISOLATION_PRESET=bogus "$(ops_sh)" run --dry-run
    [ "$status" -ne 0 ]
    [[ "$output" == *"invalid OPS_ISOLATION_PRESET"* ]]
}

# ---- composition: preset + per-app flags + default flags -------------------

@test "OPS_DEFAULT_RUN_FLAGS + OPS_ISOLATION_PRESET=fully-isolated stack cleanly" {
    run env OPS_RUNTIME=docker OPS_DEFAULT_RUN_FLAGS="--no-wayland" \
        OPS_ISOLATION_PRESET=fully-isolated "$(ops_sh)" run --app gemini --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ops-gemini"* ]]
    [[ "$output" != *"--volume $HOME:"* ]]
}

@test "user CLI flag wins over OPS_ISOLATION_PRESET=volume for the same app" {
    # User explicitly passes --opencode-volume → already volume; preset is a no-op.
    run env OPS_RUNTIME=docker OPS_ISOLATION_PRESET=volume "$(ops_sh)" run --opencode-volume --app opencode --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ops-opencode"* ]]
    # Single occurrence of the volume bind (preset must not duplicate it).
    [ "$(printf '%s' "$output" | grep -oE 'ops-opencode' | wc -l)" -le 2 ]
}
