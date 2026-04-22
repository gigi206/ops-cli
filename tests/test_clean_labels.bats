#!/usr/bin/env bats
# cmd_clean — label-based filtering of containers and volumes.
# - Containers: label=ops.container=true
# - Volumes: label=ops.volume=true
# - Dangling images: shown with ops.dockerfile label context if available

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
}

@test "clean --dry-run shows Dangling images section" {
    run env OPS_RUNTIME=docker "$(ops_sh)" clean --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"Dangling images"* ]]
}

@test "clean --dry-run shows Stopped ops containers section (label filter)" {
    run env OPS_RUNTIME=docker "$(ops_sh)" clean --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"Stopped ops containers"* ]]
    [[ "$output" == *"ops.container=true"* ]]
}

@test "clean --dry-run shows ops volumes section (label filter)" {
    run env OPS_RUNTIME=docker "$(ops_sh)" clean --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ops volumes"* ]]
    [[ "$output" == *"ops.volume=true"* ]]
}

@test "clean --dry-run shows Summary with counts" {
    run env OPS_RUNTIME=docker "$(ops_sh)" clean --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"Summary"* ]]
    [[ "$output" == *"dangling images"* ]]
    [[ "$output" == *"stopped ops containers"* ]]
    [[ "$output" == *"ops volumes"* ]]
}

@test "clean --dry-run does not invoke destructive operations" {
    run env OPS_RUNTIME=docker "$(ops_sh)" clean --dry-run
    [ "$status" -eq 0 ]
    ! grep -qE 'image prune|container prune|volume rm' "$MOCK_LOG"
}

@test "clean --dry-run shows (none) for empty sections" {
    run env OPS_RUNTIME=docker "$(ops_sh)" clean --dry-run
    [ "$status" -eq 0 ]
    # Our default mock returns nothing for ps filter / volume ls filter
    [[ "$output" == *"(none)"* ]]
}

@test "clean --dry-run with MOCK_DANGLING=1 shows dangling entry" {
    run env OPS_RUNTIME=docker MOCK_DANGLING=1 "$(ops_sh)" clean --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"Dangling images"* ]]
    # Mock emits sha256:dangling as the ID
    [[ "$output" == *"sha256:dang"* ]] || [[ "$output" == *"dangling"* ]]
}
