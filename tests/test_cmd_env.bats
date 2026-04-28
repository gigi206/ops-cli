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

# ---- Custom exports section (v1.6.0+) ----------------------------------------

@test "env lists custom exports from ops.conf in a dedicated section" {
    cat > "$XDG_CONFIG_HOME/ops/ops.conf" <<'EOF'
export MISTRAL_API_KEY="from_config"
export HUGGINGFACE_TOKEN="also_from_config"
EOF
    chmod 600 "$XDG_CONFIG_HOME/ops/ops.conf"
    run "$(ops_sh)" env
    assert_success
    assert_output_contains "Custom config exports"
    assert_output_contains "MISTRAL_API_KEY"
    assert_output_contains "HUGGINGFACE_TOKEN"
    refute_output_contains "from_config"
    refute_output_contains "also_from_config"
}

@test "env custom-export section explains they are NOT auto-propagated" {
    cat > "$XDG_CONFIG_HOME/ops/ops.conf" <<'EOF'
export MISTRAL_API_KEY="x"
EOF
    chmod 600 "$XDG_CONFIG_HOME/ops/ops.conf"
    run "$(ops_sh)" env
    assert_success
    assert_output_contains "NOT auto-propagated"
    assert_output_contains "-e KEY=VAL"
}

@test "env does NOT show the custom section when no extra exports exist" {
    : > "$XDG_CONFIG_HOME/ops/ops.conf"
    chmod 600 "$XDG_CONFIG_HOME/ops/ops.conf"
    run "$(ops_sh)" env
    assert_success
    refute_output_contains "Custom config exports"
}

@test "env does NOT duplicate auto-propagated vars in the custom section" {
    # GITHUB_TOKEN is auto-propagated — it must NOT appear in the custom block.
    cat > "$XDG_CONFIG_HOME/ops/ops.conf" <<'EOF'
export GITHUB_TOKEN="from_config"
export MISTRAL_API_KEY="from_config"
EOF
    chmod 600 "$XDG_CONFIG_HOME/ops/ops.conf"
    run "$(ops_sh)" env
    assert_success
    assert_output_contains "Custom config exports"
    # GITHUB_TOKEN should appear in the auto-propagated section ONLY.
    assert_output_contains "Auto-propagated env vars"
    # Count occurrences of GITHUB_TOKEN — should be exactly 1 (just the
    # auto-propagated row).
    [ "$(printf '%s' "$output" | grep -c 'GITHUB_TOKEN')" = "1" ]
    # MISTRAL_API_KEY appears exactly once, in the custom section.
    [ "$(printf '%s' "$output" | grep -c 'MISTRAL_API_KEY')" = "1" ]
}

@test "env custom-export section shows [set] when the var is in live env" {
    cat > "$XDG_CONFIG_HOME/ops/ops.conf" <<'EOF'
export MISTRAL_API_KEY="from_config"
EOF
    chmod 600 "$XDG_CONFIG_HOME/ops/ops.conf"
    run "$(ops_sh)" env
    assert_success
    # Source-of-ops.conf re-exports MISTRAL_API_KEY → it's [set] in live env.
    assert_output_contains "MISTRAL_API_KEY"
    assert_output_contains "[set]"
}
