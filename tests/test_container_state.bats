#!/usr/bin/env bats
# Container lifecycle paths (running / stopped / rebuild)

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
}

@test "running container: --dry-run emits exec command" {
    # Container running → should print `docker exec -it ...` in dry-run,
    # not `docker run ...`
    run env OPS_RUNTIME=docker MOCK_CONTAINER_RUNNING=1 MOCK_CONTAINER_EXISTS=1 \
        "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"exec -it"* ]]
    [[ "$output" != *"run -it"* ]]
}

@test "stopped container: starts + exec (no --dry-run sanity)" {
    # Container exists but not running → ops.sh calls `start` then tries to
    # re-detect. Our mock doesn't update state, so after `start` the container
    # is still reported as not running → it gets removed. Then run path.
    # This exercises the `start` call at minimum.
    run env OPS_RUNTIME=docker MOCK_CONTAINER_EXISTS=1 MOCK_CONTAINER_RUNNING=0 \
        "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    grep -qE '^start ' "$MOCK_LOG"
}

@test "logs: existing container" {
    run env OPS_RUNTIME=docker MOCK_CONTAINER_EXISTS=1 \
        "$(ops_sh)" logs -f
    [ "$status" -eq 0 ]
    grep -qE 'logs .*-f .*test-container' "$MOCK_LOG"
}

@test "logs: missing container errors" {
    run env OPS_RUNTIME=docker MOCK_CONTAINER_EXISTS=0 MOCK_CONTAINER_RUNNING=0 \
        "$(ops_sh)" logs
    [ "$status" -eq 1 ]
    [[ "$output" == *"does not exist"* ]]
}

@test "status shows runtime info" {
    run env OPS_RUNTIME=docker "$(ops_sh)" status
    [ "$status" -eq 0 ]
    [[ "$output" == *"runtime:"* ]]
    [[ "$output" == *"docker"* ]]
}

@test "status skips containerd check for non-nerdctl" {
    run env OPS_RUNTIME=docker "$(ops_sh)" status
    [ "$status" -eq 0 ]
    [[ "$output" != *"containerd.service"* ]]
    [[ "$output" != *"buildkitd:"* ]]
}
