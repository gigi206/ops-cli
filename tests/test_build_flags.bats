#!/usr/bin/env bats
# Runtime-specific build flags (--allow network.host for nerdctl, etc.)

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
}

@test "docker build includes --network host but not --allow" {
    mock_runtime docker
    run env OPS_RUNTIME=docker "$(ops_sh)" build
    [ "$status" -eq 0 ]
    grep -qE 'build .*--network host' "$MOCK_LOG"
    ! grep -qE 'build .*--allow' "$MOCK_LOG"
}

@test "podman build includes --network host but not --allow" {
    mock_runtime podman
    run env OPS_RUNTIME=podman "$(ops_sh)" build
    [ "$status" -eq 0 ]
    grep -qE 'build .*--network host' "$MOCK_LOG"
    ! grep -qE 'build .*--allow' "$MOCK_LOG"
}

@test "build passes USER_UID/GID/NAME/LANG build-args" {
    mock_runtime docker
    run env OPS_RUNTIME=docker OPS_USER_UID=1234 OPS_USER_GID=5678 \
        OPS_USER_NAME=customuser OPS_USER_LANG=it_IT.UTF-8 \
        "$(ops_sh)" build
    [ "$status" -eq 0 ]
    grep -qE 'build .*USER_UID=1234' "$MOCK_LOG"
    grep -qE 'build .*USER_GID=5678' "$MOCK_LOG"
    grep -qE 'build .*USER_NAME=customuser' "$MOCK_LOG"
    grep -qE 'build .*USER_LANG=it_IT.UTF-8' "$MOCK_LOG"
}

@test "build propagates GITHUB_TOKEN as a BuildKit secret (not build-arg)" {
    mock_runtime docker
    run env OPS_RUNTIME=docker GITHUB_TOKEN=ghp_mytoken "$(ops_sh)" build
    [ "$status" -eq 0 ]
    # The token must be passed via --secret so it never lands in image layers.
    grep -qE 'build .*--secret .*id=github_token,env=GITHUB_TOKEN' "$MOCK_LOG"
    # Defensive: assert the raw token value is NOT anywhere in the build cmd.
    ! grep -qF 'ghp_mytoken' "$MOCK_LOG"
}

@test "build omits --secret when GITHUB_TOKEN is unset" {
    mock_runtime docker
    unset GITHUB_TOKEN
    run env OPS_RUNTIME=docker "$(ops_sh)" build
    [ "$status" -eq 0 ]
    ! grep -qE 'build .*--secret' "$MOCK_LOG"
}

@test "build --no-cache is forwarded" {
    mock_runtime docker
    run env OPS_RUNTIME=docker "$(ops_sh)" build --no-cache
    [ "$status" -eq 0 ]
    grep -qE 'build .*--no-cache' "$MOCK_LOG"
}

@test "build uses OPS_DOCKERFILE via --file" {
    mock_runtime docker
    local custom="$BATS_TEST_TMPDIR/custom.Dockerfile"
    echo "FROM scratch" > "$custom"
    run env OPS_RUNTIME=docker OPS_DOCKERFILE="$custom" "$(ops_sh)" build
    [ "$status" -eq 0 ]
    grep -qE "build .*--file $custom" "$MOCK_LOG"
}

@test "build passes --pull" {
    mock_runtime docker
    run env OPS_RUNTIME=docker "$(ops_sh)" build
    [ "$status" -eq 0 ]
    grep -qE 'build .*--pull' "$MOCK_LOG"
}
