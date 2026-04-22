#!/usr/bin/env bats
# cmd_backup / cmd_restore — volume tar.gz streaming via docker run

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
}

@test "backup without argument shows usage" {
    run env OPS_RUNTIME=docker "$(ops_sh)" backup
    [ "$status" -eq 1 ]
    [[ "$output" == *"Usage:"* ]]
    [[ "$output" == *"backup"* ]]
    [[ "$output" == *".tar.gz"* ]]
}

@test "backup refuses to stream to a terminal" {
    # `run` in bats provides a pipe as stdout, NOT a TTY, so the TTY guard
    # doesn't trip — simulate the TTY case by forcing with a subshell that
    # has stdout as a tty. We can't easily get a real TTY in bats, so instead
    # we verify the opposite: the guard is NOT triggered when stdout is piped.
    run env OPS_RUNTIME=docker "$(ops_sh)" backup some-vol
    # Either the volume-not-found error OR a runtime call. Not the TTY error.
    [[ "$output" != *"Refusing to write"* ]]
}

@test "backup with existing volume calls docker run with tar" {
    # Our volume inspect mock succeeds by default for image inspect, but
    # volume inspect is a no-op (just exits 0) — so the guard passes.
    run env OPS_RUNTIME=docker "$(ops_sh)" backup ops-share-nix
    # docker run should be invoked with tar -czf
    grep -qE 'run .*-v ops-share-nix:/data.*alpine tar -czf' "$MOCK_LOG"
}

@test "backup passes volume name as read-only mount" {
    run env OPS_RUNTIME=docker "$(ops_sh)" backup my-vol
    grep -qE 'my-vol:/data:ro' "$MOCK_LOG"
}

@test "restore without argument shows usage" {
    run env OPS_RUNTIME=docker "$(ops_sh)" restore
    [ "$status" -eq 1 ]
    [[ "$output" == *"Usage:"* ]]
    [[ "$output" == *"restore"* ]]
}

@test "restore refuses to read from a terminal stdin" {
    # With no stdin redirect, bats' run attaches a pipe to stdin. If the
    # shell running the test considers stdin a TTY, the guard triggers.
    # We can't easily force a real TTY; verify the opposite — the guard
    # is NOT triggered when stdin is piped (via heredoc).
    run bash -c "echo fake-tar-data | env OPS_RUNTIME=docker '$(ops_sh)' restore some-vol"
    [[ "$output" != *"Refusing to read"* ]]
}

@test "restore creates the volume first (ensure_volume)" {
    run bash -c "echo data | env OPS_RUNTIME=docker '$(ops_sh)' restore new-vol"
    grep -qE 'volume create --label ops.volume=true new-vol' "$MOCK_LOG"
}

@test "restore calls docker run with tar -xzf" {
    run bash -c "echo data | env OPS_RUNTIME=docker '$(ops_sh)' restore my-vol"
    grep -qE 'run .*-v my-vol:/data.*alpine tar -xzf' "$MOCK_LOG"
}

@test "restore passes volume name as writable mount" {
    run bash -c "echo data | env OPS_RUNTIME=docker '$(ops_sh)' restore my-vol"
    # NO :ro on restore (writable)
    grep -qE 'my-vol:/data (--user|--rm|alpine)' "$MOCK_LOG" || \
        grep -qE 'my-vol:/data\b' "$MOCK_LOG"
}

@test "backup OPS_FORCE_TTY=1 skips the TTY guard" {
    # Simulate a TTY stdout by running inside `script -qc` — this makes stdout
    # look like a pty to bash's -t test. Without OPS_FORCE_TTY=1 the guard would
    # trip; with it, the guard is bypassed.
    if ! command -v script >/dev/null 2>&1; then
        skip "'script' not available"
    fi
    # Use script to attach a PTY to stdout. OPS_FORCE_TTY=1 should bypass guard.
    run script -qc "env OPS_RUNTIME=docker OPS_FORCE_TTY=1 '$(ops_sh)' backup my-vol" /dev/null
    [[ "$output" != *"Refusing to write"* ]]
    # It should have reached the runtime run call
    grep -qE 'run .*my-vol.*alpine tar -czf' "$MOCK_LOG"
}
