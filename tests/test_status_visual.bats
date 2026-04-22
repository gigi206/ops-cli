#!/usr/bin/env bats
# Visual/stateful aspects of cmd_status: container state coloring,
# orphan marker (⚠ image missing), cmd:/ops cli:/real cli: display.

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
}

# Custom docker mock for these tests: supports --format output for ps/inspect.
# Controlled via:
#   MOCK_PS_LINE         → single line emitted by `ps -a --format '...'`
#                          format: Names|Image|Status|Command
#   MOCK_PS_LABELED      → single line emitted by `ps -a --filter label=ops.container=true`
#                          (just the name, newline-terminated)
#   MOCK_CTN_LABELS      → stdin for `container inspect --format '...{{index .Config.Labels ...}}...'`
#   MOCK_IMG_MISSING     → if set, `image inspect $1` fails for this exact ref
_custom_docker_mock() {
    cat > "$MOCK_DIR/docker" <<'MOCK'
#!/bin/bash
printf '%s\n' "$*" >> "${MOCK_LOG:-/dev/null}"
case "$1" in
    info)
        case "$*" in
            *'{{.SecurityOptions}}'*) echo "${MOCK_SEC_OPTIONS-[name=rootless]}" ;;
        esac
        ;;
    ps)
        # Check for label filter (doctor / status secondary sweep)
        if [[ "$*" == *"label=ops.container=true"* ]]; then
            [ -n "${MOCK_PS_LABELED:-}" ] && echo "$MOCK_PS_LABELED"
            exit 0
        fi
        # Otherwise normal ps -a
        [ -n "${MOCK_PS_LINE:-}" ] && echo "$MOCK_PS_LINE"
        ;;
    image)
        case "$2" in
            inspect)
                # Ref is $3 (args before --format)
                ref="$3"
                if [ "$ref" = "${MOCK_IMG_MISSING:-}" ]; then
                    exit 1
                fi
                # --format output: label lookup returns empty, size 2GB, created recent
                if [[ "$*" == *Size* ]]; then
                    echo "2000000000|2026-04-20T10:00:00Z|"
                elif [[ "$*" == *.Id* ]]; then
                    echo "sha256:deadbeefcafe"
                else
                    echo "ok"
                fi
                ;;
            ls) ;;
        esac
        ;;
    container)
        case "$2" in
            inspect)
                # `container inspect NAME --format 'ops.cmdline.user...'`
                case "$*" in
                    *ops.cmdline.user*) echo "${MOCK_CLI_USER:-}" ;;
                    *ops.cmdline.real*) echo "${MOCK_CLI_REAL:-}" ;;
                    *ops.dockerfile*)   echo "" ;;
                    *Mounts*)           echo "" ;;
                    *)                  echo "ok" ;;
                esac
                ;;
        esac
        ;;
    volume)
        case "$2" in
            ls|inspect|create|rm) ;;
        esac
        ;;
    *) ;;
esac
exit 0
MOCK
    chmod +x "$MOCK_DIR/docker"
}

@test "status: Up state is green" {
    _custom_docker_mock
    export MOCK_PS_LINE="mycontainer|localhost/test-img|Up 5 minutes|bash"
    export MOCK_PS_LABELED="mycontainer"
    run env OPS_RUNTIME=docker "$(ops_sh)" status
    [ "$status" -eq 0 ]
    # Green state color: \033[32m then (Up...
    [[ "$output" == *$'\033[32m(Up'* ]]
}

@test "status: Exited state is red" {
    _custom_docker_mock
    export MOCK_PS_LINE="mycontainer|localhost/test-img|Exited (0) 2 minutes ago|bash"
    export MOCK_PS_LABELED="mycontainer"
    run env OPS_RUNTIME=docker "$(ops_sh)" status
    [ "$status" -eq 0 ]
    # Red state color: \033[31m then (Exited...
    [[ "$output" == *$'\033[31m(Exited'* ]]
}

@test "status: orphan container shows ⚠ marker and (image missing)" {
    _custom_docker_mock
    export MOCK_PS_LINE="orphaned|localhost/gone-img|Up 1 hour|bash"
    export MOCK_PS_LABELED="orphaned"
    export MOCK_IMG_MISSING="localhost/gone-img"
    run env OPS_RUNTIME=docker "$(ops_sh)" status
    [ "$status" -eq 0 ]
    [[ "$output" == *"⚠"* ]]
    [[ "$output" == *"image missing"* ]]
}

@test "status: cmd: line displays container command" {
    _custom_docker_mock
    export MOCK_PS_LINE="mycontainer|localhost/test-img|Up 1 minute|\"my-custom-cmd\""
    export MOCK_PS_LABELED="mycontainer"
    run env OPS_RUNTIME=docker "$(ops_sh)" status
    [ "$status" -eq 0 ]
    [[ "$output" == *"cmd:"* ]]
    [[ "$output" == *"my-custom-cmd"* ]]
}

@test "status: ops cli: line appears when label is set" {
    _custom_docker_mock
    export MOCK_PS_LINE="mycontainer|localhost/test-img|Up|bash"
    export MOCK_PS_LABELED="mycontainer"
    export MOCK_CLI_USER="./ops.sh run --claude"
    run env OPS_RUNTIME=docker "$(ops_sh)" status
    [ "$status" -eq 0 ]
    [[ "$output" == *"ops cli:"* ]]
    [[ "$output" == *"./ops.sh run --claude"* ]]
}

@test "status: real cli: line appears when label is set" {
    _custom_docker_mock
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
    _custom_docker_mock
    export MOCK_PS_LINE="labeled-only|some-random-image:latest|Up|bash"
    export MOCK_PS_LABELED="labeled-only"
    run env OPS_RUNTIME=docker "$(ops_sh)" status
    [ "$status" -eq 0 ]
    [[ "$output" == *"labeled-only"* ]]
}
