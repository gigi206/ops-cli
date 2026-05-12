#!/usr/bin/env bats
# Runtime detection & validation

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
}

@test "auto resolves to podman when both docker and podman are available" {
    # Priority order is podman > docker > nerdctl — podman wins by default
    # because rootless podman avoids the host-root daemon surface of rootful
    # docker. Users who specifically want docker set OPS_RUNTIME=docker.
    mock_runtime docker
    mock_runtime podman
    run env OPS_RUNTIME=auto "$(ops_sh)" help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Runtime: podman"* ]]
}

@test "auto resolves to docker when podman is absent" {
    mock_runtime docker
    # Isolated PATH excludes host /usr/bin/podman while keeping coreutils.
    run env OPS_RUNTIME=auto PATH="$MOCK_DIR:$(isolated_path)" "$(ops_sh)" help
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

@test "rootless podman (Host.Security.Rootless=true) uses 0:GID" {
    # Exercises the podman branch of _is_rootless (line 87-88 in ops.sh).
    # The mock reads MOCK_ROOTLESS and echoes it for the
    # `info --format '{{.Host.Security.Rootless}}'` query.
    mock_runtime podman
    run env OPS_RUNTIME=podman MOCK_ROOTLESS=true "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"--user 0:1000"* ]]
}

@test "rootful podman (Host.Security.Rootless=false) uses UID:GID" {
    # Same branch as above, but the false-path → _is_rootless=no → UID:GID.
    mock_runtime podman
    run env OPS_RUNTIME=podman MOCK_ROOTLESS=false "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"--user 1000:1000"* ]]
}

@test "nerdctl is always treated as rootless" {
    # Line 89 in ops.sh — nerdctl hardcodes _IS_ROOTLESS_CACHE=yes because the
    # ops-installed nerdctl is always rootless (containerd-rootless-setuptool.sh).
    local nh="$BATS_TEST_TMPDIR/nh"
    mkdir -p "$nh/bin"
    cat > "$nh/bin/nerdctl" <<'EOF'
#!/bin/bash
printf '%s\n' "$*" >> "${MOCK_LOG:-/dev/null}"
case "$1" in
    info|--version) ;;
    images) echo "sha256:deadbeefcafe" ;;
    container) exit 1 ;;
esac
exit 0
EOF
    chmod +x "$nh/bin/nerdctl"
    run env OPS_RUNTIME=nerdctl OPS_NERDCTL_HOME="$nh" "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"--user 0:1000"* ]]
}
