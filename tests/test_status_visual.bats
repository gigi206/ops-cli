#!/usr/bin/env bats
# Visual/stateful aspects of cmd_status: container state coloring,
# orphan marker (⚠ image missing), cmd:/ops cli:/real cli: display.
#
# Uses the shared mock_runtime_rich from helpers.bash (see its docstring
# for the full env-var matrix).

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
}

@test "status: Up state is green" {
    mock_runtime_rich docker
    export MOCK_PS_LINE="mycontainer|localhost/test-img|Up 5 minutes|bash"
    export MOCK_PS_LABELED="mycontainer"
    run env OPS_RUNTIME=docker "$(ops_sh)" status
    [ "$status" -eq 0 ]
    # Green state color: \033[32m then (Up...
    [[ "$output" == *$'\033[32m(Up'* ]]
}

@test "status: Exited state is red" {
    mock_runtime_rich docker
    export MOCK_PS_LINE="mycontainer|localhost/test-img|Exited (0) 2 minutes ago|bash"
    export MOCK_PS_LABELED="mycontainer"
    run env OPS_RUNTIME=docker "$(ops_sh)" status
    [ "$status" -eq 0 ]
    # Red state color: \033[31m then (Exited...
    [[ "$output" == *$'\033[31m(Exited'* ]]
}

@test "status: orphan container shows ⚠ marker and (image missing)" {
    mock_runtime_rich docker
    export MOCK_PS_LINE="orphaned|localhost/gone-img|Up 1 hour|bash"
    export MOCK_PS_LABELED="orphaned"
    export MOCK_IMG_MISSING="localhost/gone-img"
    run env OPS_RUNTIME=docker "$(ops_sh)" status
    [ "$status" -eq 0 ]
    [[ "$output" == *"⚠"* ]]
    [[ "$output" == *"image missing"* ]]
}

@test "status: cmd: line displays container command" {
    mock_runtime_rich docker
    export MOCK_PS_LINE="mycontainer|localhost/test-img|Up 1 minute|\"my-custom-cmd\""
    export MOCK_PS_LABELED="mycontainer"
    run env OPS_RUNTIME=docker "$(ops_sh)" status
    [ "$status" -eq 0 ]
    [[ "$output" == *"cmd:"* ]]
    [[ "$output" == *"my-custom-cmd"* ]]
}

@test "status: ops cli: line appears when label is set" {
    mock_runtime_rich docker
    export MOCK_PS_LINE="mycontainer|localhost/test-img|Up|bash"
    export MOCK_PS_LABELED="mycontainer"
    export MOCK_CLI_USER="./ops.sh run --claude"
    run env OPS_RUNTIME=docker "$(ops_sh)" status
    [ "$status" -eq 0 ]
    [[ "$output" == *"ops cli:"* ]]
    [[ "$output" == *"./ops.sh run --claude"* ]]
}

@test "status: real cli: line appears when label is set" {
    mock_runtime_rich docker
    export MOCK_PS_LINE="mycontainer|localhost/test-img|Up|bash"
    export MOCK_PS_LABELED="mycontainer"
    export MOCK_CLI_REAL="/usr/bin/docker run --rm --name mycontainer localhost/test-img"
    run env OPS_RUNTIME=docker "$(ops_sh)" status
    [ "$status" -eq 0 ]
    [[ "$output" == *"real cli:"* ]]
    [[ "$output" == *"/usr/bin/docker run"* ]]
}

@test "status: container matched only via label (not via image) still appears" {
    # Container's image isn't in ops_image_refs, but label=ops.container=true matches
    mock_runtime_rich docker
    export MOCK_PS_LINE="labeled-only|some-random-image:latest|Up|bash"
    export MOCK_PS_LABELED="labeled-only"
    run env OPS_RUNTIME=docker "$(ops_sh)" status
    [ "$status" -eq 0 ]
    [[ "$output" == *"labeled-only"* ]]
}
