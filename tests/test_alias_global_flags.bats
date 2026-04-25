#!/usr/bin/env bats
# Regression: alias expansion must re-parse global flags so that aliases
# starting with -i / -n / -f / -H resolve correctly.
# Prior bug: OPS_ALIASES[cc]="-i arch run --claude" would fail with
# "unknown subcommand or alias: '-i'" because the global flag loop already
# ran before expansion.
#
# Scope split with test_aliases.bats:
#   - test_aliases.bats         — baseline alias semantics (string/function,
#                                 reserved names, listing, single-pass expand).
#                                 All aliases there start with a subcommand
#                                 (e.g. "run -i ml-dev").
#   - test_alias_global_flags.bats (this file) — the narrow case of an alias
#                                 whose first token is a GLOBAL flag (-i/-n/-f/-H).
#                                 Kept separate because the code path (second
#                                 `_parse_global_flags` pass after expansion)
#                                 is distinct and would otherwise drown in
#                                 the broader alias test file.

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

@test "alias starting with -i is correctly expanded and -i consumed" {
    _write_conf <<'EOF'
declare -A OPS_ALIASES
OPS_ALIASES[cc]="-i ccimg run"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" cc --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ccimg"* ]]
    [[ "$output" != *"unknown subcommand"* ]]
}

@test "alias starting with -n expands and sets container name" {
    _write_conf <<'EOF'
declare -A OPS_ALIASES
OPS_ALIASES[mynamed]="-n custom-ctn run"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" mynamed --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"custom-ctn"* ]]
}

@test "alias with multiple global flags (-i then -n) expands both" {
    _write_conf <<'EOF'
declare -A OPS_ALIASES
OPS_ALIASES[combo]="-i comboimg -n comboctn run"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" combo --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"comboimg"* ]]
    [[ "$output" == *"comboctn"* ]]
}

@test "alias -i resolves OPS_IMAGES key via smart resolution" {
    _write_conf <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[arch]="localhost/ops-arch"
declare -A OPS_ALIASES
OPS_ALIASES[dev]="-i arch run"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" dev --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"localhost/ops-arch"* ]]
}

@test "alias with no global flag works unchanged" {
    _write_conf <<'EOF'
declare -A OPS_ALIASES
OPS_ALIASES[plain]="run"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" plain --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"localhost/test-img"* ]]
}

@test "-f before subcommand is consumed by _parse_global_flags" {
    # Regression: `-f PATH build` routes through _parse_global_flags (the
    # top-of-script pass that runs BEFORE subcommand dispatch), not through
    # cmd_run's own flag parser. Covers line 2157 in ops.sh. Without this
    # test, only `ops build -f PATH` (parsed by cmd_run) is exercised.
    local custom="$BATS_TEST_TMPDIR/Custom.Dockerfile"
    echo "FROM scratch" > "$custom"
    run env OPS_RUNTIME=docker "$(ops_sh)" -f "$custom" build
    [ "$status" -eq 0 ]
    grep -qE "build .*--file $custom" "$MOCK_LOG"
}

@test "alias expansion preserves global flags from CLI too" {
    # ops -n cli-ctn cc  — CLI -n cli-ctn applied first, then alias expands
    _write_conf <<'EOF'
declare -A OPS_ALIASES
OPS_ALIASES[cc]="-i ccimg run"
EOF
    # The alias -i ccimg expands, _user_set_n from CLI is preserved.
    run env OPS_RUNTIME=docker "$(ops_sh)" -n cli-ctn cc --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ccimg"* ]]
    [[ "$output" == *"cli-ctn"* ]]
}
