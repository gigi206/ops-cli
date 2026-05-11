#!/usr/bin/env bats
# User-defined aliases (string via OPS_ALIASES + function via ops_alias_*)

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
    # Prepare a real ops.conf so we can inject aliases per-test.
    export XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/config"
    mkdir -p "$XDG_CONFIG_HOME/ops"
}

# Helper: write content to ops.conf
_write_conf() {
    cat > "$XDG_CONFIG_HOME/ops/ops.conf"
}

@test "string alias expands to run command" {
    _write_conf <<'EOF'
declare -A OPS_ALIASES
OPS_ALIASES[ml]="run -i ml-dev -v /data:/data --app claude"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" ml --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ml-dev"* ]]
    [[ "$output" == *"/data:/data"* ]]
}

@test "string alias accepts additional runtime args" {
    _write_conf <<'EOF'
declare -A OPS_ALIASES
OPS_ALIASES[base]="run -i my-img"
EOF
    # ops base --no-rm --dry-run → run -i my-img --no-rm --dry-run
    run env OPS_RUNTIME=docker "$(ops_sh)" base --no-rm --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"my-img"* ]]
    [[ "$output" != *"--rm"* ]]
}

@test "function alias expands to run command" {
    _write_conf <<'EOF'
ops_alias_dev() {
    echo run -i dev-img --no-rm
}
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" dev --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"dev-img"* ]]
    [[ "$output" != *"--rm"* ]]
}

@test "function alias can read env vars at invocation" {
    _write_conf <<'EOF'
ops_alias_gpu() {
    echo run -e "GPU_ID=${GPU:-cpu}"
}
EOF
    run env OPS_RUNTIME=docker GPU=0 "$(ops_sh)" gpu --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"GPU_ID=0"* ]]
}

@test "function alias uses default when env var unset" {
    _write_conf <<'EOF'
ops_alias_gpu() {
    echo run -e "GPU_ID=${GPU:-cpu}"
}
EOF
    run env -u GPU OPS_RUNTIME=docker "$(ops_sh)" gpu --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"GPU_ID=cpu"* ]]
}

@test "aliases subcommand lists string aliases" {
    _write_conf <<'EOF'
declare -A OPS_ALIASES
OPS_ALIASES[ml]="run -i ml-dev"
OPS_ALIASES[web]="run -p 3000:3000"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" aliases
    [ "$status" -eq 0 ]
    [[ "$output" == *"ml"* ]]
    [[ "$output" == *"ml-dev"* ]]
    [[ "$output" == *"web"* ]]
    [[ "$output" == *"3000:3000"* ]]
}

@test "aliases subcommand lists function aliases" {
    _write_conf <<'EOF'
ops_alias_foo() { echo run; }
ops_alias_bar() { echo status; }
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" aliases
    [ "$status" -eq 0 ]
    [[ "$output" == *"foo"* ]]
    [[ "$output" == *"bar"* ]]
}

@test "aliases subcommand shows '(none defined)' with empty config" {
    # No config at all
    rm -rf "$XDG_CONFIG_HOME/ops"
    run env OPS_RUNTIME=docker "$(ops_sh)" aliases
    [ "$status" -eq 0 ]
    [[ "$output" == *"(none defined)"* ]]
}

@test "reserved name 'run' does not shadow built-in" {
    _write_conf <<'EOF'
declare -A OPS_ALIASES
OPS_ALIASES[run]="should-not-trigger"
EOF
    # ops run --dry-run → normal dispatch, default image
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"localhost/test-img"* ]]
    [[ "$output" != *"should-not-trigger"* ]]
}

@test "reserved name 'build' does not shadow built-in" {
    _write_conf <<'EOF'
declare -A OPS_ALIASES
OPS_ALIASES[build]="should-not-trigger"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" build
    [ "$status" -eq 0 ]
    grep -qE '^build .*-t localhost/test-img' "$MOCK_LOG"
}

@test "unknown alias name errors out with suggestions" {
    _write_conf <<'EOF'
declare -A OPS_ALIASES
OPS_ALIASES[real]="run -i x"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" unknowncmd
    [ "$status" -eq 1 ]
    [[ "$output" == *"unknown subcommand or alias"* ]]
    [[ "$output" == *"unknowncmd"* ]]
}

@test "alias expansion is single-pass (no recursion)" {
    _write_conf <<'EOF'
declare -A OPS_ALIASES
OPS_ALIASES[b]="run"
OPS_ALIASES[a]="b"
EOF
    # `ops a` → `ops b`. If 'b' got re-expanded, 'run' would dispatch.
    # With single-pass, 'b' is seen as an unknown subcommand → error.
    run env OPS_RUNTIME=docker "$(ops_sh)" a
    [ "$status" -eq 1 ]
    [[ "$output" == *"unknown subcommand or alias"* ]]
}

@test "function alias can emit multi-line output (only first line matters via echo joining)" {
    _write_conf <<'EOF'
ops_alias_multi() {
    local args=(run)
    args+=(-i multi-img)
    args+=(-v /a:/a)
    echo "${args[@]}"
}
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" multi --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"multi-img"* ]]
    [[ "$output" == *"/a:/a"* ]]
}

@test "string and function alias of same name: string wins" {
    _write_conf <<'EOF'
declare -A OPS_ALIASES
OPS_ALIASES[both]="run -i string-img"
ops_alias_both() { echo run -i function-img; }
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" both --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"string-img"* ]]
    [[ "$output" != *"function-img"* ]]
}
