#!/usr/bin/env bats
# Runtime detection & validation

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
}

@test "auto resolves to docker when docker is first available" {
    mock_runtime docker
    mock_runtime podman
    run env OPS_RUNTIME=auto "$(ops_sh)" help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Runtime: docker"* ]]
}

@test "auto resolves to podman when docker is absent" {
    mock_runtime podman
    # Isolated PATH excludes host /usr/bin/docker while keeping coreutils.
    run env OPS_RUNTIME=auto PATH="$MOCK_DIR:$(isolated_path)" "$(ops_sh)" help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Runtime: podman"* ]]
}

@test "auto falls back to nerdctl when docker and podman absent" {
    # No runtime mocks, isolated PATH — command -v {docker,podman,nerdctl} all fail.
    run env OPS_RUNTIME=auto PATH="$MOCK_DIR:$(isolated_path)" \
        OPS_NERDCTL_HOME="$BATS_TEST_TMPDIR/noexist" "$(ops_sh)" help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Runtime: nerdctl"* ]]
}

@test "explicit docker runtime is honored" {
    mock_runtime docker
    mock_runtime podman
    run env OPS_RUNTIME=podman "$(ops_sh)" help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Runtime: podman"* ]]
}

@test "invalid OPS_RUNTIME is rejected" {
    run env OPS_RUNTIME=invalidrt "$(ops_sh)" help
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid OPS_RUNTIME: invalidrt"* ]]
}

@test "docker selected but missing yields clear error on action" {
    # No mock docker in PATH, but explicit docker runtime requested. Use an
    # isolated PATH (no MOCK_DIR either) so docker/podman/nerdctl are all absent.
    # `help` bypasses the runtime check via _skip_runtime_startup; use `status`
    # which does need a runtime.
    run env OPS_RUNTIME=docker PATH="$(isolated_path)" "$(ops_sh)" status
    [ "$status" -eq 1 ]
    [[ "$output" == *"Runtime 'docker' not found"* ]]
}

@test "rootful docker uses UID:GID (not 0:GID)" {
    mock_runtime docker
    # Empty SecurityOptions → _is_rootless returns false → --user $UID:$GID
    run env OPS_RUNTIME=docker MOCK_SEC_OPTIONS="" \
        "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"--user 1000:1000"* ]]
    [[ "$output" != *"--user 0:1000"* ]]
}

@test "rootless docker uses 0:GID" {
    mock_runtime docker
    # Default MOCK_SEC_OPTIONS="[name=rootless]" → _is_rootless true
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"--user 0:1000"* ]]
}
