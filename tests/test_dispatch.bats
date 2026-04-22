#!/usr/bin/env bats
# Subcommand dispatch & help output

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
}

@test "help subcommand prints usage" {
    run env OPS_RUNTIME=docker "$(ops_sh)" help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"* ]]
    [[ "$output" == *"Subcommands:"* ]]
    [[ "$output" == *"run [OPTIONS]"* ]]
}

@test "--help flag prints usage" {
    run env OPS_RUNTIME=docker "$(ops_sh)" --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"* ]]
}

@test "-h flag prints usage" {
    run env OPS_RUNTIME=docker "$(ops_sh)" -h
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"* ]]
}

@test "help lists all expected subcommands" {
    run env OPS_RUNTIME=docker "$(ops_sh)" help
    [ "$status" -eq 0 ]
    for sub in run build runtime status logs clean nerdctl; do
        [[ "$output" == *"$sub"* ]] || { echo "missing: $sub"; return 1; }
    done
}

@test "help reflects current OPS_RUNTIME" {
    run env OPS_RUNTIME=docker "$(ops_sh)" help
    [[ "$output" == *"Runtime: docker"* ]]
}

@test "flat 'install' is no longer a subcommand (nerdctl namespace now)" {
    run env OPS_RUNTIME=docker "$(ops_sh)" install
    [ "$status" -eq 1 ]
    [[ "$output" == *"unknown subcommand or alias"* ]]
}

@test "flat 'uninstall' is no longer a subcommand" {
    run env OPS_RUNTIME=docker "$(ops_sh)" uninstall
    [ "$status" -eq 1 ]
    [[ "$output" == *"unknown subcommand or alias"* ]]
}

@test "flat 'self-update' is no longer a subcommand" {
    run env OPS_RUNTIME=docker "$(ops_sh)" self-update
    [ "$status" -eq 1 ]
    [[ "$output" == *"unknown subcommand or alias"* ]]
}

@test "'nerdctl' with no subcommand prints its help" {
    run env OPS_RUNTIME=docker "$(ops_sh)" nerdctl
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"*"nerdctl"* ]]
    [[ "$output" == *"install"* ]]
    [[ "$output" == *"uninstall"* ]]
    [[ "$output" == *"self-update"* ]]
}

@test "'nerdctl <bad-sub>' errors with suggestion" {
    run env OPS_RUNTIME=docker "$(ops_sh)" nerdctl totallymadeup
    [ "$status" -eq 1 ]
    [[ "$output" == *"unknown nerdctl subcommand"* ]]
}

@test "runtime subcommand proxies to the runtime binary" {
    run env OPS_RUNTIME=docker "$(ops_sh)" runtime ps -a
    [ "$status" -eq 0 ]
    grep -q '^ps -a$' "$MOCK_LOG"
}

@test "clean --dry-run does not prompt or delete" {
    run env OPS_RUNTIME=docker "$(ops_sh)" clean --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"dry-run"* ]]
    # Should not call image/container prune in dry-run
    ! grep -q 'prune' "$MOCK_LOG"
}

@test "clean --dry-run lists dangling images when present" {
    run env OPS_RUNTIME=docker MOCK_DANGLING=1 "$(ops_sh)" clean --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"Dangling images"* ]]
    # New format truncates IDs to 12 chars: 'sha256:dangling  <none>:<none>' → 'sha256:dangl'
    [[ "$output" == *"sha256:dang"* ]]
}

@test "build subcommand triggers image build" {
    run env OPS_RUNTIME=docker "$(ops_sh)" build
    [ "$status" -eq 0 ]
    grep -qE '^build .*-t localhost/test-img' "$MOCK_LOG"
}
