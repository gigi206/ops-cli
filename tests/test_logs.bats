#!/usr/bin/env bats
# cmd_logs — positional container name, --strip, log alias, flag passthrough

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
}

@test "log (singular alias) dispatches to cmd_logs" {
    run env OPS_RUNTIME=docker MOCK_CONTAINER_EXISTS=1 \
        "$(ops_sh)" log -f
    [ "$status" -eq 0 ]
    grep -qE 'logs .*-f .*test-container' "$MOCK_LOG"
}

@test "logs with positional name overrides OPS_CONTAINER_NAME" {
    # Mock ps -a will return "test-container" (OPS_CONTAINER_NAME). To test
    # a different positional, we set OPS_CONTAINER_NAME to the desired name.
    # Actually cmd_logs checks `ps -a --format '{{.Names}}' | grep -qx "$target"`
    # so the positional name must appear in ps output. Our mock echoes
    # OPS_CONTAINER_NAME when MOCK_CONTAINER_EXISTS=1.
    # So: set OPS_CONTAINER_NAME to foo, then call logs foo.
    run env OPS_RUNTIME=docker OPS_CONTAINER_NAME=target-ctn MOCK_CONTAINER_EXISTS=1 \
        "$(ops_sh)" logs target-ctn -f
    [ "$status" -eq 0 ]
    grep -qE 'logs .*target-ctn' "$MOCK_LOG"
}

@test "logs --tail N with positional arg parses correctly" {
    # Regression for earlier bug where --tail 30 treated '30' as container name.
    run env OPS_RUNTIME=docker MOCK_CONTAINER_EXISTS=1 \
        "$(ops_sh)" logs --tail 30
    [ "$status" -eq 0 ]
    grep -qE 'logs --tail 30 .*test-container' "$MOCK_LOG"
}

@test "logs -n N with positional works too" {
    run env OPS_RUNTIME=docker MOCK_CONTAINER_EXISTS=1 \
        "$(ops_sh)" logs -n 50
    [ "$status" -eq 0 ]
    grep -qE 'logs -n 50 .*test-container' "$MOCK_LOG"
}

@test "logs --since ISO arg doesn't get treated as container name" {
    run env OPS_RUNTIME=docker MOCK_CONTAINER_EXISTS=1 \
        "$(ops_sh)" logs --since 2024-01-01
    [ "$status" -eq 0 ]
    grep -qE 'logs .*--since 2024-01-01' "$MOCK_LOG"
}

@test "logs --strip does NOT directly exec (pipes through sed)" {
    # With --strip, cmd_logs pipes through sed. We can't fully assert the
    # pipeline semantics with a simple mock, but we can verify exit code 0.
    run env OPS_RUNTIME=docker MOCK_CONTAINER_EXISTS=1 \
        "$(ops_sh)" logs --strip
    [ "$status" -eq 0 ]
    grep -qE 'logs .*test-container' "$MOCK_LOG"
}

@test "logs -s (short form of --strip) works" {
    run env OPS_RUNTIME=docker MOCK_CONTAINER_EXISTS=1 \
        "$(ops_sh)" logs -s
    [ "$status" -eq 0 ]
    grep -qE 'logs .*test-container' "$MOCK_LOG"
}

@test "logs missing container: positional arg errors out" {
    run env OPS_RUNTIME=docker MOCK_CONTAINER_EXISTS=0 \
        "$(ops_sh)" logs nonexistent
    [ "$status" -eq 1 ]
    [[ "$output" == *"does not exist"* ]]
    [[ "$output" == *"nonexistent"* ]]
}

@test "logs combines --strip and --tail without mis-parsing" {
    run env OPS_RUNTIME=docker MOCK_CONTAINER_EXISTS=1 \
        "$(ops_sh)" logs --strip --tail 10
    [ "$status" -eq 0 ]
    grep -qE 'logs --tail 10 .*test-container' "$MOCK_LOG"
}
