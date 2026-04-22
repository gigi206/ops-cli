#!/usr/bin/env bats
# --dry-run output of cmd_run

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
}

@test "plain run --dry-run outputs a docker run command" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    # Binary name appears in the first arg
    [[ "$output" == *"docker"* ]]
    [[ "$output" == *"run"* ]]
    [[ "$output" == *"localhost/test-img"* ]]
    [[ "$output" == *"test-container"* ]]
    # Default entrypoint is bash when no command is given
    [[ "$output" == *"bash"* ]]
}

@test "run --dry-run honors -i image override" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run -i my-custom-img --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"my-custom-img"* ]]
    # Ensure the default image is NOT present
    [[ "$output" != *"localhost/test-img"* ]]
}

@test "run --dry-run honors -n container name override" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run -n my-ctn --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"my-ctn"* ]]
}

@test "global flag ordering: -i before subcommand" {
    run env OPS_RUNTIME=docker "$(ops_sh)" -i global-img run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"global-img"* ]]
}

@test "run -e injects --env KEY=VAL" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run -e FOO=bar --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"--env"* ]]
    [[ "$output" == *"FOO=bar"* ]]
}

@test "run -p injects --publish HOST:CTN" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run -p 8080:80 --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"--publish"* ]]
    [[ "$output" == *"8080:80"* ]]
}

@test "run -v injects extra volume" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run -v /host/path:/ctn/path --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"/host/path:/ctn/path"* ]]
}

@test "run --claude builds agent command" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --claude --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"mise"* ]]
    [[ "$output" == *"claude"* ]]
    [[ "$output" == *"@anthropic-ai/claude-code"* ]]
}

@test "run --codex builds agent command" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --codex --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"codex"* ]]
    [[ "$output" == *"@openai/codex"* ]]
}

@test "run --gemini builds agent command" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --gemini --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"gemini"* ]]
    [[ "$output" == *"@google/gemini-cli"* ]]
}

@test "run --opencode builds agent command" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --opencode --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"opencode"* ]]
    [[ "$output" == *"sst/opencode"* ]]
}

@test "run --dry-run with explicit command includes it" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run -- echo hello
    [ "$status" -eq 0 ]
    [[ "$output" == *"echo"* ]]
    [[ "$output" == *"hello"* ]]
}

@test "run -- CMD passes args as container command" {
    # `run -- foo bar` → no ops flag parsing after --, command is exec'd.
    run env OPS_RUNTIME=docker "$(ops_sh)" run -- my-inner-cmd arg1
    [ "$status" -eq 0 ]
    grep -qE 'run .* my-inner-cmd arg1' "$MOCK_LOG"
}

@test "--no-cache without --build is rejected" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --no-cache
    [ "$status" -ne 0 ]
    [[ "$output" == *"--no-cache requires --build"* ]]
}

@test "unknown flag emits a warning" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --definitely-not-a-flag --dry-run
    # We expect both the "Warning: unknown flag" prefix AND the specific
    # offending flag name in the output -- asserting either/or would let a
    # regression (e.g. silent parsing) slip through.
    [[ "$output" == *"Warning: unknown flag"* ]]
    [[ "$output" == *"--definitely-not-a-flag"* ]]
}
