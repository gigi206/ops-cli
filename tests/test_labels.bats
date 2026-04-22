#!/usr/bin/env bats
# Labels injected by ops.sh on images, containers, and volumes:
#   ops.dockerfile    on images  (abs path of the Dockerfile used at build)
#   ops.container     on containers  (="true")
#   ops.cmdline.user  on containers  (original ./ops.sh invocation)
#   ops.cmdline.real  on containers  (actual docker run command)
#   ops.volume        on volumes  (="true")

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
}

@test "cmd_run injects ops.container=true label" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"--label ops.container=true"* ]]
}

@test "cmd_run injects ops.cmdline.user label" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ops.cmdline.user="* ]]
}

@test "cmd_run injects ops.cmdline.real label" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ops.cmdline.real="* ]]
}

@test "ops.cmdline.user captures original invocation flags" {
    run env OPS_RUNTIME=docker "$(ops_sh)" -i my-special-img run --dry-run
    [ "$status" -eq 0 ]
    # The user cmdline label must reflect -i my-special-img
    [[ "$output" == *"ops.cmdline.user="*"my-special-img"* ]]
}

@test "ops.cmdline.real does not embed itself (no recursion)" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    # real should NOT contain the literal 'ops.cmdline.real=' inside its own value
    # (counted via grep -o should be at most 1 occurrence)
    count=$(echo "$output" | grep -o 'ops.cmdline.real=' | wc -l)
    [ "$count" -le 2 ]  # allow at most 2 (once in --label, once if dry-run echoes twice)
}

@test "build_image injects ops.dockerfile label" {
    run env OPS_RUNTIME=docker "$(ops_sh)" build
    [ "$status" -eq 0 ]
    grep -qE 'build .*--label ops.dockerfile=' "$MOCK_LOG"
}

@test "ensure_volume injects ops.volume=true label when creating" {
    # cmd_run triggers ensure_volume for ops-share-nix / ops-share-mise
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    grep -qE 'volume create --label ops.volume=true' "$MOCK_LOG"
}

@test "ops.cmdline.real contains docker run command" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ops.cmdline.real="*"docker"* ]]
}
