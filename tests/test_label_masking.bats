#!/usr/bin/env bats
# Secret-masking in the ops.cmdline.real label:
# - GITHUB_TOKEN / ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY
#   must appear as KEY=*** in the label, not in cleartext.
# - The container itself still receives the real value via --env (verified
#   by separate flag tests).

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
}

@test "GITHUB_TOKEN is masked in ops.cmdline.real label" {
    run env OPS_RUNTIME=docker GITHUB_TOKEN=ghp_supersecret123 \
        "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    # The --env part still shows the real value (container needs it)
    [[ "$output" == *"--env GITHUB_TOKEN=ghp_supersecret123"* ]]
    # But ops.cmdline.real label must mask it
    # printf %q escapes * as \* in the dry-run shell-quoted output
    [[ "$output" == *"GITHUB_TOKEN=\\*\\*\\*"* ]]
    # And must NOT contain the real token inside the label value
    # Extract substring starting at ops.cmdline.real and assert no secret
    label_part="${output#*ops.cmdline.real=}"
    [[ "$label_part" != *"ghp_supersecret123"* ]]
}

@test "ANTHROPIC_API_KEY is masked in ops.cmdline.real label" {
    run env OPS_RUNTIME=docker ANTHROPIC_API_KEY=sk-ant-secret \
        "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ANTHROPIC_API_KEY=\\*\\*\\*"* ]]
    label_part="${output#*ops.cmdline.real=}"
    [[ "$label_part" != *"sk-ant-secret"* ]]
}

@test "OPENAI_API_KEY is masked in ops.cmdline.real label" {
    run env OPS_RUNTIME=docker OPENAI_API_KEY=sk-oai-secret \
        "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"OPENAI_API_KEY=\\*\\*\\*"* ]]
    label_part="${output#*ops.cmdline.real=}"
    [[ "$label_part" != *"sk-oai-secret"* ]]
}

@test "GEMINI_API_KEY is masked in ops.cmdline.real label" {
    run env OPS_RUNTIME=docker GEMINI_API_KEY=g-secret-value \
        "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"GEMINI_API_KEY=\\*\\*\\*"* ]]
    label_part="${output#*ops.cmdline.real=}"
    [[ "$label_part" != *"g-secret-value"* ]]
}

@test "multiple secrets all masked at once" {
    run env OPS_RUNTIME=docker \
        GITHUB_TOKEN=ghp_a ANTHROPIC_API_KEY=sk-ant-b \
        OPENAI_API_KEY=sk-oai-c GEMINI_API_KEY=g-d \
        "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    # The ops.cmdline.real label must not leak any of the 4 secrets
    label_part="${output#*ops.cmdline.real=}"
    [[ "$label_part" != *"ghp_a"* ]]
    [[ "$label_part" != *"sk-ant-b"* ]]
    [[ "$label_part" != *"sk-oai-c"* ]]
    [[ "$label_part" != *"g-d"* ]]
    # But the container still receives them via --env (before the label)
    [[ "$output" == *"GITHUB_TOKEN=ghp_a"* ]]
    [[ "$output" == *"ANTHROPIC_API_KEY=sk-ant-b"* ]]
    [[ "$output" == *"OPENAI_API_KEY=sk-oai-c"* ]]
    [[ "$output" == *"GEMINI_API_KEY=g-d"* ]]
}

@test "ops.cmdline.user label is not masked (it's the user's raw invocation, no secrets)" {
    # User-typed invocation doesn't carry -e flags for tokens (they come from env).
    # Just verify the label is present and unaffected by the masking regex.
    run env OPS_RUNTIME=docker GITHUB_TOKEN=ghp_abc "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ops.cmdline.user="* ]]
}

@test "non-secret env vars are NOT masked" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run -e FOO=bar_value --dry-run
    [ "$status" -eq 0 ]
    # Both in --env and in the label, FOO=bar_value is preserved
    label_part="${output#*ops.cmdline.real=}"
    [[ "$label_part" == *"FOO=bar_value"* ]]
}
