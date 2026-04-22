#!/usr/bin/env bats
# Per-image hash cache and dockerfile_changed detection

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
}

@test "build writes hash file named after the image" {
    # Force build via --build, mock runtime swallows it
    run env OPS_RUNTIME=docker "$(ops_sh)" build
    [ "$status" -eq 0 ]
    local expected="$XDG_CACHE_HOME/ops/localhost_test-img.sha256sum"
    [ -f "$expected" ]
}

@test "different image → different hash file" {
    run env OPS_RUNTIME=docker OPS_IMAGE=my/other "$(ops_sh)" build
    [ "$status" -eq 0 ]
    [ -f "$XDG_CACHE_HOME/ops/my_other.sha256sum" ]
    # Original should not exist
    [ ! -f "$XDG_CACHE_HOME/ops/localhost_test-img.sha256sum" ]
}

@test "no warning when hash file is fresh" {
    run env OPS_RUNTIME=docker "$(ops_sh)" build
    [ "$status" -eq 0 ]
    # Now `run` without --build should not warn about Dockerfile changed
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" != *"Dockerfile changed"* ]]
}

@test "warning when Dockerfile changes after build" {
    run env OPS_RUNTIME=docker "$(ops_sh)" build
    [ "$status" -eq 0 ]
    # Mutate Dockerfile
    echo "# mutation" >> "$OPS_DOCKERFILE"
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"Dockerfile changed"* ]]
}

@test "no warning when hash file absent (first run on existing image)" {
    # No hash file, mock says image exists (default MOCK_IMAGE_EXISTS=1)
    rm -rf "$XDG_CACHE_HOME"
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" != *"Dockerfile changed"* ]]
}
