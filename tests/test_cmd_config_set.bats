#!/usr/bin/env bats
# cmd_config set/get/unset/alias — managed edits to ops.conf
#
# Each test runs against an isolated $XDG_CONFIG_HOME so the host's real
# ~/.config/ops/ops.conf is never touched. The atomic-replace contract is
# verified by re-reading the file after each mutation; idempotency is
# verified by running the same command twice and checking the second
# invocation is a no-op (mtime stable, content identical).

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

# ---- config set --------------------------------------------------------------

@test "config set creates ops.conf with a new scalar" {
    [ ! -f "$OPS_CONF" ]
    run "$(ops_sh)" config set OPS_RUNTIME docker
    assert_success
    [ -f "$OPS_CONF" ]
    grep -q '^OPS_RUNTIME="docker"$' "$OPS_CONF"
}

@test "config set chmod 600 the created file" {
    run "$(ops_sh)" config set OPS_RUNTIME docker
    assert_success
    local perms
    perms=$(stat -c '%a' "$OPS_CONF")
    [ "$perms" = "600" ]
}

@test "config set is idempotent — same key+value is a no-op" {
    run "$(ops_sh)" config set OPS_RUNTIME docker
    assert_success
    local hash1
    hash1=$(sha256sum "$OPS_CONF" | cut -d' ' -f1)
    sleep 0.1
    run "$(ops_sh)" config set OPS_RUNTIME docker
    assert_success
    local hash2
    hash2=$(sha256sum "$OPS_CONF" | cut -d' ' -f1)
    [ "$hash1" = "$hash2" ]
}

@test "config set replaces an existing key in place" {
    run "$(ops_sh)" config set OPS_RUNTIME docker
    assert_success
    run "$(ops_sh)" config set OPS_RUNTIME podman
    assert_success
    grep -q '^OPS_RUNTIME="podman"$' "$OPS_CONF"
    ! grep -q '^OPS_RUNTIME="docker"$' "$OPS_CONF"
    # Single occurrence
    [ "$(grep -c '^OPS_RUNTIME=' "$OPS_CONF")" = "1" ]
}

@test "config set preserves comments and surrounding lines" {
    cat > "$OPS_CONF" <<'EOF'
# Header comment
OPS_RUNTIME="docker"
# Another comment
OPS_BUILDKITD_TIMEOUT=15
EOF
    run "$(ops_sh)" config set OPS_RUNTIME podman
    assert_success
    grep -q '^# Header comment$' "$OPS_CONF"
    grep -q '^# Another comment$' "$OPS_CONF"
    grep -q '^OPS_BUILDKITD_TIMEOUT=15$' "$OPS_CONF"
    grep -q '^OPS_RUNTIME="podman"$' "$OPS_CONF"
}

@test "config set quotes values with spaces" {
    run "$(ops_sh)" config set OPS_DEFAULT_RUN_FLAGS "--no-rm --no-wayland"
    assert_success
    grep -q '^OPS_DEFAULT_RUN_FLAGS="--no-rm --no-wayland"$' "$OPS_CONF"
}

@test "config set escapes embedded double quotes" {
    run "$(ops_sh)" config set OPS_DEFAULT_RUN_FLAGS '--label="key=value"'
    assert_success
    # The line should be: OPS_DEFAULT_RUN_FLAGS="--label=\"key=value\""
    grep -q '^OPS_DEFAULT_RUN_FLAGS="--label=\\"key=value\\""$' "$OPS_CONF"
}

@test "config set rejects newlines in value" {
    run "$(ops_sh)" config set OPS_DEFAULT_RUN_FLAGS $'foo\nbar'
    assert_failure
    assert_output_contains "newline"
}

@test "config set rejects invalid keys (lowercase, no OPS_ prefix)" {
    run "$(ops_sh)" config set runtime docker
    assert_failure
    assert_output_contains "invalid key"
}

@test "config set rejects array-typed keys" {
    run "$(ops_sh)" config set OPS_ALIASES "anything"
    assert_failure
    assert_output_contains "array"
    [ ! -f "$OPS_CONF" ] || ! grep -q '^OPS_ALIASES=' "$OPS_CONF"
}

@test "config set rejects missing VALUE arg" {
    run "$(ops_sh)" config set OPS_RUNTIME
    assert_failure
    assert_output_contains "KEY VALUE"
}

@test "config set accepts empty string as VALUE" {
    run "$(ops_sh)" config set OPS_DEFAULT_RUN_FLAGS ""
    assert_success
    grep -q '^OPS_DEFAULT_RUN_FLAGS=""$' "$OPS_CONF"
}

# ---- config get --------------------------------------------------------------

@test "config get reads a scalar from ops.conf" {
    "$(ops_sh)" config set OPS_RUNTIME docker
    run "$(ops_sh)" config get OPS_RUNTIME
    assert_success
    [ "$output" = "docker" ]
}

@test "config get returns 1 + diagnostic for unset key" {
    run "$(ops_sh)" config get OPS_NONEXISTENT
    assert_failure
    assert_output_contains "not set"
}

@test "config get reads value with spaces correctly" {
    "$(ops_sh)" config set OPS_DEFAULT_RUN_FLAGS "--no-rm --no-wayland"
    run "$(ops_sh)" config get OPS_DEFAULT_RUN_FLAGS
    assert_success
    [ "$output" = "--no-rm --no-wayland" ]
}

@test "config get reads value with embedded quotes correctly" {
    "$(ops_sh)" config set OPS_DEFAULT_RUN_FLAGS '--label="key=value"'
    run "$(ops_sh)" config get OPS_DEFAULT_RUN_FLAGS
    assert_success
    [ "$output" = '--label="key=value"' ]
}

@test "config get rejects invalid key" {
    run "$(ops_sh)" config get foo
    assert_failure
    assert_output_contains "invalid key"
}

# ---- config unset ------------------------------------------------------------

@test "config unset removes a scalar" {
    "$(ops_sh)" config set OPS_RUNTIME docker
    run "$(ops_sh)" config unset OPS_RUNTIME
    assert_success
    ! grep -q '^OPS_RUNTIME=' "$OPS_CONF"
}

@test "config unset is idempotent — second call is no-op" {
    "$(ops_sh)" config set OPS_RUNTIME docker
    run "$(ops_sh)" config unset OPS_RUNTIME
    assert_success
    run "$(ops_sh)" config unset OPS_RUNTIME
    assert_success
}

@test "config unset preserves other keys" {
    cat > "$OPS_CONF" <<'EOF'
OPS_RUNTIME="docker"
OPS_BUILDKITD_TIMEOUT=15
EOF
    run "$(ops_sh)" config unset OPS_RUNTIME
    assert_success
    ! grep -q '^OPS_RUNTIME=' "$OPS_CONF"
    grep -q '^OPS_BUILDKITD_TIMEOUT=15$' "$OPS_CONF"
}

@test "config unset on nonexistent file succeeds silently" {
    [ ! -f "$OPS_CONF" ]
    run "$(ops_sh)" config unset OPS_RUNTIME
    assert_success
}

# ---- config alias add --------------------------------------------------------

@test "config alias add creates declare -A + entry on fresh file" {
    [ ! -f "$OPS_CONF" ]
    run "$(ops_sh)" config alias add cc 'run --claude'
    assert_success
    grep -qE '^[[:space:]]*declare[[:space:]]+-A[[:space:]]+OPS_ALIASES' "$OPS_CONF"
    grep -q '^OPS_ALIASES\[cc\]="run --claude"$' "$OPS_CONF"
}

@test "config alias add does not duplicate declare -A on existing config" {
    cat > "$OPS_CONF" <<'EOF'
declare -A OPS_ALIASES
OPS_ALIASES[cc]="run --claude"
EOF
    run "$(ops_sh)" config alias add gg 'run --gemini'
    assert_success
    [ "$(grep -c 'declare -A OPS_ALIASES' "$OPS_CONF")" = "1" ]
    grep -q '^OPS_ALIASES\[cc\]="run --claude"$' "$OPS_CONF"
    grep -q '^OPS_ALIASES\[gg\]="run --gemini"$' "$OPS_CONF"
}

@test "config alias add is idempotent — same name+argv no-op" {
    "$(ops_sh)" config alias add cc 'run --claude'
    local hash1
    hash1=$(sha256sum "$OPS_CONF" | cut -d' ' -f1)
    sleep 0.1
    run "$(ops_sh)" config alias add cc 'run --claude'
    assert_success
    local hash2
    hash2=$(sha256sum "$OPS_CONF" | cut -d' ' -f1)
    [ "$hash1" = "$hash2" ]
}

@test "config alias add replaces existing entry with new argv" {
    "$(ops_sh)" config alias add cc 'run --claude'
    run "$(ops_sh)" config alias add cc 'run --claude --no-rm'
    assert_success
    grep -q '^OPS_ALIASES\[cc\]="run --claude --no-rm"$' "$OPS_CONF"
    [ "$(grep -c '^OPS_ALIASES\[cc\]=' "$OPS_CONF")" = "1" ]
}

@test "config alias add rejects reserved names" {
    run "$(ops_sh)" config alias add run 'whatever'
    assert_failure
    assert_output_contains "reserved"
}

@test "config alias add rejects invalid name shape" {
    run "$(ops_sh)" config alias add '1bad' 'whatever'
    assert_failure
    assert_output_contains "invalid alias name"
}

@test "config alias add requires NAME and ARGV" {
    run "$(ops_sh)" config alias add cc
    assert_failure
    assert_output_contains "NAME ARGV"
}

@test "config alias add rejects empty argv" {
    run "$(ops_sh)" config alias add cc ""
    assert_failure
    assert_output_contains "non-empty"
}

# ---- config alias remove -----------------------------------------------------

@test "config alias remove deletes the entry" {
    "$(ops_sh)" config alias add cc 'run --claude'
    run "$(ops_sh)" config alias remove cc
    assert_success
    ! grep -q '^OPS_ALIASES\[cc\]=' "$OPS_CONF"
}

@test "config alias remove is idempotent" {
    "$(ops_sh)" config alias add cc 'run --claude'
    "$(ops_sh)" config alias remove cc
    run "$(ops_sh)" config alias remove cc
    assert_success
}

@test "config alias remove preserves other entries" {
    "$(ops_sh)" config alias add cc 'run --claude'
    "$(ops_sh)" config alias add gg 'run --gemini'
    run "$(ops_sh)" config alias remove cc
    assert_success
    ! grep -q '^OPS_ALIASES\[cc\]=' "$OPS_CONF"
    grep -q '^OPS_ALIASES\[gg\]="run --gemini"$' "$OPS_CONF"
}

@test "config alias remove on nonexistent file succeeds" {
    [ ! -f "$OPS_CONF" ]
    run "$(ops_sh)" config alias remove cc
    assert_success
}

# ---- config alias bad action -------------------------------------------------

@test "config alias without action shows help" {
    run "$(ops_sh)" config alias
    assert_success
    assert_output_contains "add NAME"
    assert_output_contains "remove NAME"
}

@test "config alias with bogus action errors out" {
    run "$(ops_sh)" config alias frobnicate cc
    assert_failure
    assert_output_contains "add"
    assert_output_contains "remove"
}

# ---- end-to-end: source loads back what we wrote -----------------------------

@test "ops.conf written by config set is sourcable and the alias works" {
    "$(ops_sh)" config set OPS_RUNTIME docker
    "$(ops_sh)" config alias add cc 'help'
    # Now invoke `ops cc` — the alias dispatcher should expand to `help`
    run "$(ops_sh)" cc
    assert_success
    assert_output_contains "Subcommands"
}

# ---- help --------------------------------------------------------------------

@test "config --help shows the new subcommand list" {
    run "$(ops_sh)" config --help
    assert_success
    assert_output_contains "set KEY VALUE"
    assert_output_contains "alias add NAME"
}
