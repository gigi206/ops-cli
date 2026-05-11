#!/usr/bin/env bats
# config set/get/unset on bracketed keys (OPS_APP_FLAGS[claude],
# OPS_IMAGES[debian], etc.). Verifies the same atomicity + idempotency
# contract the scalar form already has, plus the `declare -A` bootstrap
# that bash needs for indexed assignment to work at source time.

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

# ---- set: bracketed key bootstraps declare -A --------------------------------

@test "config set OPS_APP_FLAGS[claude] bootstraps declare -A on fresh file" {
    [ ! -f "$OPS_CONF" ]
    run "$(ops_sh)" config set 'OPS_APP_FLAGS[claude]' "--claude-volume --install"
    assert_success
    [ -f "$OPS_CONF" ]
    grep -qE '^[[:space:]]*declare[[:space:]]+-A[[:space:]]+OPS_APP_FLAGS' "$OPS_CONF"
    grep -qF 'OPS_APP_FLAGS[claude]="--claude-volume --install"' "$OPS_CONF"
}

@test "config set OPS_APP_FLAGS[claude] does NOT duplicate declare -A on second add" {
    "$(ops_sh)" config set 'OPS_APP_FLAGS[claude]' "--claude-volume"
    run "$(ops_sh)" config set 'OPS_APP_FLAGS[gemini]' "--gemini-volume"
    assert_success
    [ "$(grep -c 'declare -A OPS_APP_FLAGS' "$OPS_CONF")" = "1" ]
    grep -qF 'OPS_APP_FLAGS[claude]="--claude-volume"' "$OPS_CONF"
    grep -qF 'OPS_APP_FLAGS[gemini]="--gemini-volume"' "$OPS_CONF"
}

@test "config set bracketed is idempotent — same value no-op" {
    "$(ops_sh)" config set 'OPS_APP_FLAGS[claude]' "--claude-volume"
    local hash1
    hash1=$(sha256sum "$OPS_CONF" | cut -d' ' -f1)
    sleep 0.1
    run "$(ops_sh)" config set 'OPS_APP_FLAGS[claude]' "--claude-volume"
    assert_success
    local hash2
    hash2=$(sha256sum "$OPS_CONF" | cut -d' ' -f1)
    [ "$hash1" = "$hash2" ]
}

@test "config set bracketed updates an existing entry in place" {
    "$(ops_sh)" config set 'OPS_APP_FLAGS[claude]' "--claude-volume"
    run "$(ops_sh)" config set 'OPS_APP_FLAGS[claude]' "--claude-volume --install --no-rm"
    assert_success
    grep -qF 'OPS_APP_FLAGS[claude]="--claude-volume --install --no-rm"' "$OPS_CONF"
    [ "$(grep -c '^OPS_APP_FLAGS\[claude\]=' "$OPS_CONF")" = "1" ]
}

@test "config set works for OPS_IMAGES[debian] (different array name)" {
    run "$(ops_sh)" config set 'OPS_IMAGES[debian]' "localhost/ops-dev-debian"
    assert_success
    grep -qE '^[[:space:]]*declare[[:space:]]+-A[[:space:]]+OPS_IMAGES' "$OPS_CONF"
    grep -qF 'OPS_IMAGES[debian]="localhost/ops-dev-debian"' "$OPS_CONF"
}

@test "config set bracketed accepts hyphens in the index" {
    run "$(ops_sh)" config set 'OPS_IMAGES[arch-min]' "localhost/ops-dev-arch-min"
    assert_success
    grep -qF 'OPS_IMAGES[arch-min]="localhost/ops-dev-arch-min"' "$OPS_CONF"
}

@test "config set rejects bare array name (no bracket)" {
    run "$(ops_sh)" config set OPS_APP_FLAGS "anything"
    assert_failure
    assert_output_contains "is an array"
    assert_output_contains "config set OPS_APP_FLAGS"
}

@test "config set rejects empty index OPS_FOO[]" {
    run "$(ops_sh)" config set 'OPS_FOO[]' "x"
    assert_failure
    assert_output_contains "invalid key"
}

@test "config set rejects malformed bracket OPS_FOO[" {
    run "$(ops_sh)" config set 'OPS_FOO[' "x"
    assert_failure
    assert_output_contains "invalid key"
}

@test "config set rejects nested brackets OPS_FOO[a[b]]" {
    run "$(ops_sh)" config set 'OPS_FOO[a[b]]' "x"
    assert_failure
    assert_output_contains "invalid key"
}

# ---- get: bracketed key ------------------------------------------------------

@test "config get OPS_APP_FLAGS[claude] reads the value" {
    "$(ops_sh)" config set 'OPS_APP_FLAGS[claude]' "--claude-volume --install"
    run "$(ops_sh)" config get 'OPS_APP_FLAGS[claude]'
    assert_success
    [ "$output" = "--claude-volume --install" ]
}

@test "config get bracketed returns 1 + diagnostic when entry absent" {
    run "$(ops_sh)" config get 'OPS_APP_FLAGS[nonexistent]'
    assert_failure
    assert_output_contains "not set"
}

@test "config get bracketed reads the right entry when others coexist" {
    "$(ops_sh)" config set 'OPS_APP_FLAGS[claude]' "--claude-volume"
    "$(ops_sh)" config set 'OPS_APP_FLAGS[gemini]' "--gemini-volume"
    run "$(ops_sh)" config get 'OPS_APP_FLAGS[gemini]'
    assert_success
    [ "$output" = "--gemini-volume" ]
}

# ---- unset: bracketed key ----------------------------------------------------

@test "config unset OPS_APP_FLAGS[claude] removes only that entry" {
    "$(ops_sh)" config set 'OPS_APP_FLAGS[claude]' "--claude-volume"
    "$(ops_sh)" config set 'OPS_APP_FLAGS[gemini]' "--gemini-volume"
    run "$(ops_sh)" config unset 'OPS_APP_FLAGS[claude]'
    assert_success
    ! grep -qF 'OPS_APP_FLAGS[claude]=' "$OPS_CONF"
    grep -qF 'OPS_APP_FLAGS[gemini]="--gemini-volume"' "$OPS_CONF"
}

@test "config unset bracketed is idempotent" {
    "$(ops_sh)" config set 'OPS_APP_FLAGS[claude]' "--claude-volume"
    "$(ops_sh)" config unset 'OPS_APP_FLAGS[claude]'
    run "$(ops_sh)" config unset 'OPS_APP_FLAGS[claude]'
    assert_success
}

@test "config unset bracketed leaves declare -A intact when other entries remain" {
    "$(ops_sh)" config set 'OPS_APP_FLAGS[claude]' "--claude-volume"
    "$(ops_sh)" config set 'OPS_APP_FLAGS[gemini]' "--gemini-volume"
    "$(ops_sh)" config unset 'OPS_APP_FLAGS[claude]'
    grep -qE '^[[:space:]]*declare[[:space:]]+-A[[:space:]]+OPS_APP_FLAGS' "$OPS_CONF"
}

# ---- end-to-end: file is sourcable + values reach cmd_run --------------------

@test "ops.conf written with bracketed keys is sourcable cleanly" {
    "$(ops_sh)" config set 'OPS_APP_FLAGS[claude]' "--claude-volume --install"
    # Trigger a no-op subcommand that touches the source path. Failure
    # would manifest as "syntax error" or "Refusing to source".
    run "$(ops_sh)" config get 'OPS_APP_FLAGS[claude]'
    assert_success
    refute_output_contains "syntax error"
    refute_output_contains "Refusing to source"
}

@test "OPS_APP_FLAGS[claude] set via config set drives --app claude isolation at run time" {
    # Wire the per-app flag, then verify ops run --app claude --dry-run picks it up.
    "$(ops_sh)" config set 'OPS_APP_FLAGS[claude]' "--claude-volume"
    run env OPS_RUNTIME=docker "$(ops_sh)" run --app claude --dry-run
    assert_success
    [[ "$output" == *"ops-claude"* ]]
}

# ---- alias add still works (refactored backend) ------------------------------

@test "config alias add still works after refactor (regression guard)" {
    run "$(ops_sh)" config alias add cc 'run --app claude'
    assert_success
    grep -qE '^[[:space:]]*declare[[:space:]]+-A[[:space:]]+OPS_ALIASES' "$OPS_CONF"
    grep -qF 'OPS_ALIASES[cc]="run --app claude"' "$OPS_CONF"
}

@test "config alias add coexists with config set OPS_APP_FLAGS[…]" {
    "$(ops_sh)" config alias add cc 'run --app claude'
    "$(ops_sh)" config set 'OPS_APP_FLAGS[claude]' "--claude-volume"
    grep -qF 'OPS_ALIASES[cc]="run --app claude"' "$OPS_CONF"
    grep -qF 'OPS_APP_FLAGS[claude]="--claude-volume"' "$OPS_CONF"
    grep -qE '^[[:space:]]*declare[[:space:]]+-A[[:space:]]+OPS_ALIASES' "$OPS_CONF"
    grep -qE '^[[:space:]]*declare[[:space:]]+-A[[:space:]]+OPS_APP_FLAGS' "$OPS_CONF"
}
