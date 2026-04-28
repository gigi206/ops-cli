#!/usr/bin/env bats
# cmd_env — list of env vars ops auto-propagates to the container.
# Names only; values are NEVER echoed.

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
    export XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/config"
    mkdir -p "$XDG_CONFIG_HOME/ops"
}

@test "env lists the four auto-propagated vars" {
    run "$(ops_sh)" env
    assert_success
    assert_output_contains "GITHUB_TOKEN"
    assert_output_contains "ANTHROPIC_API_KEY"
    assert_output_contains "OPENAI_API_KEY"
    assert_output_contains "GEMINI_API_KEY"
}

@test "env shows [unset] when no vars are exported" {
    run env -u GITHUB_TOKEN -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u GEMINI_API_KEY \
        "$(ops_sh)" env
    assert_success
    assert_output_contains "[unset]"
    refute_output_contains "[set]"
}

@test "env shows [set] when host has the var, never the value" {
    run env GITHUB_TOKEN="ghp_supersecret_xyz" "$(ops_sh)" env
    assert_success
    assert_output_contains "GITHUB_TOKEN"
    assert_output_contains "[set]"
    refute_output_contains "ghp_supersecret_xyz"
}

@test "env reports origin: shell when host has the var" {
    run env GITHUB_TOKEN="x" "$(ops_sh)" env
    assert_success
    assert_output_contains "origin: shell"
}

@test "env reports origin: config when only ops.conf has the secret" {
    cat > "$XDG_CONFIG_HOME/ops/ops.conf" <<'EOF'
export GITHUB_TOKEN="from_config"
EOF
    chmod 600 "$XDG_CONFIG_HOME/ops/ops.conf"
    run env -u GITHUB_TOKEN "$(ops_sh)" env
    assert_success
    refute_output_contains "from_config"
    assert_output_contains "origin: config"
}

@test "env reports origin: both when shell and config have the var with different values" {
    cat > "$XDG_CONFIG_HOME/ops/ops.conf" <<'EOF'
export GITHUB_TOKEN="from_config"
EOF
    chmod 600 "$XDG_CONFIG_HOME/ops/ops.conf"
    run env GITHUB_TOKEN="from_shell" "$(ops_sh)" env
    assert_success
    refute_output_contains "from_config"
    refute_output_contains "from_shell"
    assert_output_contains "origin: both"
}

@test "env --help describes the safety contract" {
    run "$(ops_sh)" env --help
    assert_success
    assert_output_contains "Values are NEVER"
}
