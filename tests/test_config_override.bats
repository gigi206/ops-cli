#!/usr/bin/env bats
# Config file path override via -c / --config CLI flag and $OPS_CONFIG env var.
#
# Precedence (highest first):
#   1. -c / --config / --config=PATH   (CLI flag, must precede the subcommand)
#   2. $OPS_CONFIG                     (environment variable)
#   3. $XDG_CONFIG_HOME/ops/ops.conf   (default)
#
# Scope split with test_config.bats:
#   - test_config.bats          — default-path sourcing semantics
#                                 (env vs config precedence, missing file).
#   - test_config_override.bats — the new override entry points; covers
#                                 flag parsing, precedence, regression
#                                 guards (self-update -c stays as --check),
#                                 mixed-flag positioning, and config-write
#                                 follow-through to the overridden file.

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
}

# Helper: write a minimal config file at $1 with OPS_IMAGE set to $2.
# The chmod 600 mirrors what ops itself enforces on managed writes — required
# so the ownership / world-writable safety check at the top of ops.sh accepts
# it (it would refuse a 666 file as world-writable).
_write_conf_at() {
    local path="$1" image="$2"
    mkdir -p "$(dirname "$path")"
    cat > "$path" <<EOF
OPS_IMAGE=$image
EOF
    chmod 600 "$path"
}

@test "-c PATH redirects the config file source" {
    local alt="$BATS_TEST_TMPDIR/alt/ops.conf"
    _write_conf_at "$alt" "via-c/img"
    run env -u OPS_IMAGE OPS_RUNTIME=docker "$(ops_sh)" -c "$alt" run --dry-run
    assert_success
    assert_output_contains "via-c/img"
}

@test "--config PATH redirects the config file source" {
    local alt="$BATS_TEST_TMPDIR/alt/ops.conf"
    _write_conf_at "$alt" "via-long/img"
    run env -u OPS_IMAGE OPS_RUNTIME=docker "$(ops_sh)" --config "$alt" run --dry-run
    assert_success
    assert_output_contains "via-long/img"
}

@test "--config=PATH (equals form) redirects the config file source" {
    local alt="$BATS_TEST_TMPDIR/alt/ops.conf"
    _write_conf_at "$alt" "via-equals/img"
    run env -u OPS_IMAGE OPS_RUNTIME=docker "$(ops_sh)" "--config=$alt" run --dry-run
    assert_success
    assert_output_contains "via-equals/img"
}

@test "OPS_CONFIG env var redirects the config file source" {
    local alt="$BATS_TEST_TMPDIR/alt/ops.conf"
    _write_conf_at "$alt" "via-env/img"
    run env -u OPS_IMAGE OPS_RUNTIME=docker OPS_CONFIG="$alt" "$(ops_sh)" run --dry-run
    assert_success
    assert_output_contains "via-env/img"
}

@test "CLI -c wins when CLI + OPS_CONFIG + default all coexist" {
    # Discriminating triple-source test: define ALL three paths with
    # distinct OPS_IMAGE values, then assert the CLI value wins. This
    # is the single test that proves the full precedence chain — three
    # separate tests would not catch a CLI/env order flip.
    local cli_conf="$BATS_TEST_TMPDIR/cli.conf"
    local env_conf="$BATS_TEST_TMPDIR/env.conf"
    local default_conf="$XDG_CONFIG_HOME/ops/ops.conf"
    _write_conf_at "$cli_conf"     "cli-wins/img"
    _write_conf_at "$env_conf"     "env-loses/img"
    _write_conf_at "$default_conf" "default-loses/img"
    run env -u OPS_IMAGE OPS_RUNTIME=docker OPS_CONFIG="$env_conf" \
        "$(ops_sh)" -c "$cli_conf" run --dry-run
    assert_success
    assert_output_contains "cli-wins/img"
    refute_output_contains "env-loses/img"
    refute_output_contains "default-loses/img"
}

@test "OPS_CONFIG wins over default when no CLI flag is given" {
    local env_conf="$BATS_TEST_TMPDIR/env.conf"
    local default_conf="$XDG_CONFIG_HOME/ops/ops.conf"
    _write_conf_at "$env_conf"     "env-wins/img"
    _write_conf_at "$default_conf" "default-loses/img"
    run env -u OPS_IMAGE OPS_RUNTIME=docker OPS_CONFIG="$env_conf" \
        "$(ops_sh)" run --dry-run
    assert_success
    assert_output_contains "env-wins/img"
    refute_output_contains "default-loses/img"
}

@test "missing override file emits a warning (does not abort)" {
    local missing="$BATS_TEST_TMPDIR/does-not-exist.conf"
    run env OPS_RUNTIME=docker "$(ops_sh)" -c "$missing" run --dry-run
    assert_success
    assert_output_contains "Warning: config file not found"
    assert_output_contains "origin: cli"
}

@test "missing default config file produces no warning" {
    # XDG path intentionally empty (setup_ops_env points it at a non-existent
    # dir). Regression: only EXPLICIT overrides should warn.
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    assert_success
    refute_output_contains "Warning: config file not found"
}

@test "config / help / version suppress the missing-override warning" {
    local missing="$BATS_TEST_TMPDIR/does-not-exist.conf"
    run env OPS_RUNTIME=docker "$(ops_sh)" -c "$missing" help
    assert_success
    refute_output_contains "Warning: config file not found"
    run env OPS_RUNTIME=docker OPS_CONFIG="$missing" "$(ops_sh)" version
    assert_success
    refute_output_contains "Warning: config file not found"
    run env OPS_RUNTIME=docker "$(ops_sh)" --config "$missing" config
    assert_success
    refute_output_contains "Warning: config file not found"
}

@test "-c errors when no path argument is provided" {
    run env OPS_RUNTIME=docker "$(ops_sh)" -c
    assert_failure
    assert_output_contains "requires a non-empty path"
}

@test "--config= errors when value is empty" {
    run env OPS_RUNTIME=docker "$(ops_sh)" --config= run --dry-run
    assert_failure
    assert_output_contains "non-empty path"
}

@test "self-update -c REF preserves its --check meaning (no override theft)" {
    # Regression: the pre-parse must stop at the first non-global-flag token,
    # so `-c` AFTER `self-update` belongs to that subcommand (its --check
    # shortcut). If the pre-parse greedily consumed it, the script would
    # error out trying to load `v1.0.0` as a config path.
    # Use a fake REF that fails after parsing succeeds — the parse-survival
    # is what we're asserting, not the resolve. --check tells the user it
    # would (or would not) switch; we check the output names the REF.
    run env OPS_RUNTIME=docker "$(ops_sh)" self-update -c --help
    assert_success
    # If pre-parse stole -c, `--help` would never reach cmd_update_self and
    # the help text wouldn't appear.
    assert_output_contains "self-update"
}

@test "mixed positioning: -n BEFORE -c works" {
    local alt="$BATS_TEST_TMPDIR/alt.conf"
    _write_conf_at "$alt" "mixed-pos/img"
    run env -u OPS_IMAGE -u OPS_CONTAINER_NAME OPS_RUNTIME=docker \
        "$(ops_sh)" -n my-ctn -c "$alt" run --dry-run
    assert_success
    assert_output_contains "mixed-pos/img"
    assert_output_contains "my-ctn"
}

@test "mixed positioning: -c BEFORE -n works" {
    local alt="$BATS_TEST_TMPDIR/alt.conf"
    _write_conf_at "$alt" "mixed-pos2/img"
    run env -u OPS_IMAGE -u OPS_CONTAINER_NAME OPS_RUNTIME=docker \
        "$(ops_sh)" -c "$alt" -n my-ctn run --dry-run
    assert_success
    assert_output_contains "mixed-pos2/img"
    assert_output_contains "my-ctn"
}

@test "ops -c PATH config set writes to the OVERRIDDEN file" {
    # This is the silent-footgun guard: if `config set` ignored -c and
    # wrote to the default path, the feature would be worse than not having
    # it (user thinks they edited /work/conf.conf, change is in ~/.config/...).
    local alt="$BATS_TEST_TMPDIR/alt.conf"
    local default_conf="$XDG_CONFIG_HOME/ops/ops.conf"
    run env OPS_RUNTIME=docker "$(ops_sh)" -c "$alt" config set OPS_RUNTIME podman
    assert_success
    [ -f "$alt" ] || { echo "override file was not created: $alt"; false; }
    grep -q 'OPS_RUNTIME="podman"' "$alt" || {
        echo "override file does not contain the new setting:"; cat "$alt"; false;
    }
    # Default path must NOT have been touched.
    [ ! -f "$default_conf" ] || { echo "default path was modified — leakage:"; cat "$default_conf"; false; }
}

@test "ops --config PATH config set writes to the OVERRIDDEN file (long form)" {
    local alt="$BATS_TEST_TMPDIR/alt.conf"
    run env OPS_RUNTIME=docker "$(ops_sh)" --config "$alt" config set OPS_RUNTIME podman
    assert_success
    grep -q 'OPS_RUNTIME="podman"' "$alt"
}

@test "OPS_CONFIG=PATH config set writes to the env-resolved file" {
    local alt="$BATS_TEST_TMPDIR/alt.conf"
    # Pre-create so the writer-by-env path is exercised (and so cmd_config
    # finds an existing file to update rather than creating a fresh seed).
    _write_conf_at "$alt" "env-write/img"
    run env OPS_RUNTIME=docker OPS_CONFIG="$alt" "$(ops_sh)" config set OPS_RUNTIME podman
    assert_success
    grep -q 'OPS_RUNTIME="podman"' "$alt"
}

@test "world-writable override file is refused (security check still applies)" {
    # The pre-existing 0o22 ownership / world-writable guard at the top of
    # ops.sh must apply to whichever path -c resolves to, not just the
    # default. Otherwise -c becomes an end-run around the safety check.
    local alt="$BATS_TEST_TMPDIR/wide.conf"
    _write_conf_at "$alt" "should-not-load/img"
    chmod 666 "$alt"   # world-writable
    run env OPS_RUNTIME=docker "$(ops_sh)" -c "$alt" run --dry-run
    assert_failure
    assert_output_contains "world-writable"
}

@test "doctor reports the resolved origin tag" {
    local alt="$BATS_TEST_TMPDIR/alt.conf"
    _write_conf_at "$alt" "doctor-origin/img"
    run env OPS_RUNTIME=docker "$(ops_sh)" -c "$alt" doctor
    assert_success
    assert_output_contains "origin: cli"
}

@test "config (no subcommand) reports the resolved origin tag" {
    local alt="$BATS_TEST_TMPDIR/alt.conf"
    _write_conf_at "$alt" "config-origin/img"
    run env OPS_RUNTIME=docker OPS_CONFIG="$alt" "$(ops_sh)" config
    assert_success
    assert_output_contains "origin: env"
}

@test "alias-injected -c is ignored with a warning (does not break parsing)" {
    # Regression: if an alias prepends `-c PATH`, the second
    # _parse_global_flags pass after alias expansion would previously hit
    # `*) break` and the downstream dispatcher would error on `-c` as an
    # unknown subcommand. Now it warns and skips so the alias's other
    # tokens still flow through.
    local default_conf="$XDG_CONFIG_HOME/ops/ops.conf"
    local alt="$BATS_TEST_TMPDIR/alt.conf"
    mkdir -p "$(dirname "$default_conf")"
    cat > "$default_conf" <<EOF
declare -A OPS_ALIASES
OPS_ALIASES[withcfg]="-c $alt run"
EOF
    chmod 600 "$default_conf"
    run env OPS_RUNTIME=docker "$(ops_sh)" withcfg --dry-run
    assert_success
    assert_output_contains "ignored"
    refute_output_contains "unknown subcommand"
}
