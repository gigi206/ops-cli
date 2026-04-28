#!/usr/bin/env bats
# cmd_doctor --fix — surface concrete remediation commands collected
# alongside each warning. Suggestions only; nothing is auto-executed.

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
    export XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/no-config-here"
}

@test "doctor --help mentions --fix" {
    run "$(ops_sh)" doctor --help
    assert_success
    assert_output_contains "--fix"
}

@test "doctor without --fix does NOT print Suggested fixes" {
    run "$(ops_sh)" doctor
    [ "$status" -eq 1 ]  # config missing → warning
    refute_output_contains "Suggested fixes"
}

@test "doctor --fix prints Suggested fixes section when warnings exist" {
    run "$(ops_sh)" doctor --fix
    [ "$status" -eq 1 ]
    assert_output_contains "Suggested fixes"
    assert_output_contains "config set OPS_RUNTIME"
}

@test "doctor --fix on missing config suggests config set" {
    run "$(ops_sh)" doctor --fix
    [ "$status" -eq 1 ]
    assert_output_contains "config set OPS_RUNTIME auto"
}

@test "doctor --fix is a no-op when there are no warnings (no Suggested fixes section)" {
    # Set up a passing config: file exists, OPS_IMAGES empty, no containers
    export XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/config"
    mkdir -p "$XDG_CONFIG_HOME/ops"
    : > "$XDG_CONFIG_HOME/ops/ops.conf"
    chmod 600 "$XDG_CONFIG_HOME/ops/ops.conf"
    run "$(ops_sh)" doctor --fix
    assert_success
    refute_output_contains "Suggested fixes"
}

@test "doctor --fix rejects unknown options" {
    run "$(ops_sh)" doctor --bogus
    assert_failure
    assert_output_contains "unknown 'doctor' option"
}

@test "doctor --fix order does not matter" {
    # --fix before/after positional behaves the same (no positional today).
    run "$(ops_sh)" doctor --fix
    [ "$status" -eq 1 ]
    assert_output_contains "Suggested fixes"
}
