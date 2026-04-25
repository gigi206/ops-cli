#!/usr/bin/env bats
# Per-subcommand --help coverage. Each subcommand that previously silently
# mis-parsed "--help" as its first positional arg now intercepts `-h|--help`
# at the top of its cmd_* function and prints a dedicated usage block.
#
# The sub-help blocks deliberately include the subcommand name in their first
# "Usage:" line so we can assert on the right one being printed (vs. the
# top-level help that starts with just "Usage: ops.sh [SUBCOMMAND]").

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
}

@test "doctor --help prints its own usage, not the top-level one" {
    run env OPS_RUNTIME=docker "$(ops_sh)" doctor --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"*"doctor"* ]]
    [[ "$output" == *"OPS_IMAGES"* ]]
    # Should NOT contain the top-level subcommand list
    [[ "$output" != *"Global flags (may appear before the subcommand"* ]]
}

@test "doctor -h is equivalent to --help" {
    run env OPS_RUNTIME=docker "$(ops_sh)" doctor -h
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"*"doctor"* ]]
}

@test "inspect --help does NOT error on missing KEY" {
    # Before the fix, `inspect` without KEY errored with usage-to-stderr (exit 1).
    # With --help, it must return 0 and print the help block.
    run env OPS_RUNTIME=docker "$(ops_sh)" inspect --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"*"inspect"* ]]
    [[ "$output" == *"OPS_IMAGES[KEY]"* ]]
}

@test "config --help prints its own usage" {
    run env OPS_RUNTIME=docker "$(ops_sh)" config --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"*"config"* ]]
    [[ "$output" == *"[env]"* ]]
    [[ "$output" == *"[config]"* ]]
    [[ "$output" == *"[default]"* ]]
}

@test "clean --help prints its own usage" {
    run env OPS_RUNTIME=docker "$(ops_sh)" clean --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"*"clean"* ]]
    [[ "$output" == *"ops.container=true"* ]]
    [[ "$output" == *"ops.volume=true"* ]]
}

@test "status --help prints its own usage (and info alias)" {
    run env OPS_RUNTIME=docker "$(ops_sh)" status --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"*"status"* ]]
    [[ "$output" == *"'info' is an alias"* ]]
}

@test "info --help routes through cmd_status and prints the same help" {
    run env OPS_RUNTIME=docker "$(ops_sh)" info --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"*"status"* ]]
}

@test "logs --help prints its own usage" {
    run env OPS_RUNTIME=docker "$(ops_sh)" logs --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"*"logs"* ]]
    [[ "$output" == *"--strip"* ]]
    [[ "$output" == *"--tail"* ]]
}

@test "log --help (singular) routes through cmd_logs" {
    run env OPS_RUNTIME=docker "$(ops_sh)" log --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"*"logs"* ]]
}

@test "backup --help prints its own usage without needing a volume arg" {
    run env OPS_RUNTIME=docker "$(ops_sh)" backup --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"*"backup"* ]]
    [[ "$output" == *"tar.gz"* ]]
    [[ "$output" == *"OPS_FORCE_TTY"* ]]
}

@test "restore --help prints its own usage without needing a volume arg" {
    run env OPS_RUNTIME=docker "$(ops_sh)" restore --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"*"restore"* ]]
    [[ "$output" == *"ops.volume=true"* ]]
}

@test "update --help prints its own usage" {
    run env OPS_RUNTIME=docker "$(ops_sh)" update --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"*"update"* ]]
    [[ "$output" == *"OPS_IMAGES"* ]]
}

@test "aliases --help prints its own usage" {
    run env OPS_RUNTIME=docker "$(ops_sh)" aliases --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"*"aliases"* ]]
    [[ "$output" == *"ops_alias_"* ]]
}

@test "alias --help (singular) routes through cmd_aliases" {
    run env OPS_RUNTIME=docker "$(ops_sh)" alias --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"*"aliases"* ]]
}

@test "images --help prints its own usage" {
    run env OPS_RUNTIME=docker "$(ops_sh)" images --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"*"images"* ]]
    [[ "$output" == *"OPS_IMAGES"* ]]
}

@test "runtime --help (alone) prints ops-cli's runtime help, NOT the runtime's own help" {
    # When --help is the ONLY arg, show the proxy-subcommand doc. Any extra
    # arg (even other flags) must pass through to the runtime.
    run env OPS_RUNTIME=docker "$(ops_sh)" runtime --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Proxy to the underlying runtime"* ]]
    [[ "$output" == *"exit code"* ]]
}

@test "runtime ps --help forwards the --help to the runtime (proxy contract)" {
    # With a preceding non-flag token, --help is the runtime's flag, not ours.
    # The mock logs every call, so we can assert --help landed in its argv.
    run env OPS_RUNTIME=docker "$(ops_sh)" runtime ps --help
    [ "$status" -eq 0 ]
    grep -q '^ps --help$' "$MOCK_LOG"
}

@test "doctor/inspect/config/clean --help stay at exit code 0" {
    # Regression: each of these must exit 0 on --help (not 1). doctor has a
    # special case because its normal body can return 1 when warnings are
    # found — but --help is short-circuited before that logic runs.
    for cmd in doctor inspect config clean aliases images status logs; do
        run env OPS_RUNTIME=docker "$(ops_sh)" "$cmd" --help
        [ "$status" -eq 0 ] || { echo "cmd=$cmd status=$status"; return 1; }
    done
}
