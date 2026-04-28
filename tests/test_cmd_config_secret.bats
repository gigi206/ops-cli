#!/usr/bin/env bats
# cmd_config secret add/list/remove — manage `export KEY="..."` entries
# in ops.conf with chmod 600 enforced and values never echoed back.

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
    export XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/config"
    mkdir -p "$XDG_CONFIG_HOME/ops"
    export OPS_CONF="$XDG_CONFIG_HOME/ops/ops.conf"
}

# ---- secret add --from-env ---------------------------------------------------

@test "secret add --from-env writes export line and chmod 600" {
    run env GITHUB_TOKEN="ghp_abc123" "$(ops_sh)" config secret add GITHUB_TOKEN --from-env
    assert_success
    grep -q '^export GITHUB_TOKEN="ghp_abc123"$' "$OPS_CONF"
    local perms
    perms=$(stat -c '%a' "$OPS_CONF")
    [ "$perms" = "600" ]
}

@test "secret add --from-env errors when env var is missing" {
    run env -u GITHUB_TOKEN "$(ops_sh)" config secret add GITHUB_TOKEN --from-env
    assert_failure
    assert_output_contains "not set in the environment"
}

@test "secret add --from-env is idempotent — same value no-op" {
    env GITHUB_TOKEN="x" "$(ops_sh)" config secret add GITHUB_TOKEN --from-env
    local hash1
    hash1=$(sha256sum "$OPS_CONF" | cut -d' ' -f1)
    sleep 0.1
    run env GITHUB_TOKEN="x" "$(ops_sh)" config secret add GITHUB_TOKEN --from-env
    assert_success
    local hash2
    hash2=$(sha256sum "$OPS_CONF" | cut -d' ' -f1)
    [ "$hash1" = "$hash2" ]
}

@test "secret add --from-env replaces existing value" {
    env GITHUB_TOKEN="x" "$(ops_sh)" config secret add GITHUB_TOKEN --from-env
    run env GITHUB_TOKEN="y" "$(ops_sh)" config secret add GITHUB_TOKEN --from-env
    assert_success
    grep -q '^export GITHUB_TOKEN="y"$' "$OPS_CONF"
    [ "$(grep -c '^export GITHUB_TOKEN=' "$OPS_CONF")" = "1" ]
}

# ---- secret add --from-stdin -------------------------------------------------

@test "secret add --from-stdin reads one line from stdin" {
    run bash -c 'printf "%s\n" "ghp_xyz789" | "'"$(ops_sh)"'" config secret add GITHUB_TOKEN --from-stdin'
    assert_success
    grep -q '^export GITHUB_TOKEN="ghp_xyz789"$' "$OPS_CONF"
}

@test "secret add --from-stdin rejects empty input" {
    run bash -c 'printf "" | "'"$(ops_sh)"'" config secret add GITHUB_TOKEN --from-stdin'
    assert_failure
    assert_output_contains "empty"
}

# ---- secret add: validation --------------------------------------------------

@test "secret add rejects lowercase keys" {
    run env github_token=x "$(ops_sh)" config secret add github_token --from-env
    assert_failure
    assert_output_contains "invalid secret key"
}

@test "secret add rejects key starting with digit" {
    run "$(ops_sh)" config secret add 1KEY --from-env
    assert_failure
    assert_output_contains "invalid secret key"
}

@test "secret add rejects unknown source flag" {
    run env GITHUB_TOKEN=x "$(ops_sh)" config secret add GITHUB_TOKEN --from-pass
    assert_failure
    assert_output_contains "unknown"
}

# ---- secret list -------------------------------------------------------------

@test "secret list emits names only, never values" {
    env GITHUB_TOKEN="ghp_supersecret" "$(ops_sh)" config secret add GITHUB_TOKEN --from-env
    env ANTHROPIC_API_KEY="sk-very-secret" "$(ops_sh)" config secret add ANTHROPIC_API_KEY --from-env
    run "$(ops_sh)" config secret list
    assert_success
    assert_output_contains "GITHUB_TOKEN"
    assert_output_contains "ANTHROPIC_API_KEY"
    refute_output_contains "ghp_supersecret"
    refute_output_contains "sk-very-secret"
}

@test "secret list returns empty on a fresh config" {
    run "$(ops_sh)" config secret list
    assert_success
    [ -z "$output" ]
}

@test "secret list output is sorted + de-duplicated" {
    env BBB=2 "$(ops_sh)" config secret add BBB --from-env
    env AAA=1 "$(ops_sh)" config secret add AAA --from-env
    run "$(ops_sh)" config secret list
    assert_success
    [ "$(printf '%s' "$output" | head -1)" = "AAA" ]
    [ "$(printf '%s' "$output" | sed -n '2p')" = "BBB" ]
}

# ---- secret remove -----------------------------------------------------------

@test "secret remove deletes the export line" {
    env GITHUB_TOKEN=x "$(ops_sh)" config secret add GITHUB_TOKEN --from-env
    run "$(ops_sh)" config secret remove GITHUB_TOKEN
    assert_success
    ! grep -q '^export GITHUB_TOKEN=' "$OPS_CONF"
}

@test "secret remove is idempotent — second call no-op" {
    env GITHUB_TOKEN=x "$(ops_sh)" config secret add GITHUB_TOKEN --from-env
    "$(ops_sh)" config secret remove GITHUB_TOKEN
    run "$(ops_sh)" config secret remove GITHUB_TOKEN
    assert_success
}

@test "secret remove preserves other secrets and scalars" {
    env GITHUB_TOKEN=x "$(ops_sh)" config secret add GITHUB_TOKEN --from-env
    env ANTHROPIC_API_KEY=y "$(ops_sh)" config secret add ANTHROPIC_API_KEY --from-env
    "$(ops_sh)" config set OPS_RUNTIME docker
    run "$(ops_sh)" config secret remove GITHUB_TOKEN
    assert_success
    ! grep -q '^export GITHUB_TOKEN=' "$OPS_CONF"
    grep -q '^export ANTHROPIC_API_KEY=' "$OPS_CONF"
    grep -q '^OPS_RUNTIME=' "$OPS_CONF"
}

# ---- secret help / unknown action --------------------------------------------

@test "config secret without action shows usage" {
    run "$(ops_sh)" config secret
    assert_success
    assert_output_contains "config secret"
    assert_output_contains "add NAME"
    assert_output_contains "Values are NEVER"
}

@test "config secret with bogus action errors out" {
    run "$(ops_sh)" config secret frobnicate KEY
    assert_failure
    assert_output_contains "add"
    assert_output_contains "list"
    assert_output_contains "remove"
}

# ---- chmod 600 invariant -----------------------------------------------------

@test "chmod 600 is enforced even when ops.conf was world-readable before" {
    : > "$OPS_CONF"
    chmod 644 "$OPS_CONF"
    run env GITHUB_TOKEN=x "$(ops_sh)" config secret add GITHUB_TOKEN --from-env
    assert_success
    local perms
    perms=$(stat -c '%a' "$OPS_CONF")
    [ "$perms" = "600" ]
}

# ---- end-to-end: secrets survive the source guard ----------------------------

@test "ops.conf with secrets is sourced cleanly by subsequent ops invocations" {
    env GITHUB_TOKEN=foo "$(ops_sh)" config secret add GITHUB_TOKEN --from-env
    # Now invoke a no-op subcommand that triggers ops.conf loading. The
    # security guard refuses world-writable files (we leave it 600), so a
    # successful exit means the export line is valid bash.
    run env -u GITHUB_TOKEN "$(ops_sh)" config get OPS_NONEXISTENT
    [ "$status" -ne 0 ]
    refute_output_contains "Refusing to source"
    refute_output_contains "syntax error"
}
