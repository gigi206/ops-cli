#!/usr/bin/env bats
# Secret handling in --dry-run output. Two orthogonal guarantees:
#
# 1. Label masking (ops.cmdline.{user,real}) — GITHUB_TOKEN, ANTHROPIC_API_KEY,
#    OPENAI_API_KEY, GEMINI_API_KEY never appear in cleartext in either label,
#    even when the user inlined the secret on the command line.
# 2. --dry-run redaction (NEW) — the `--env KEY=VAL` position that carries the
#    secret to the container is also redacted in dry-run output so pasted
#    transcripts (bug reports, CI logs) don't leak credentials. The
#    container itself still receives the real value at run time (separate
#    flag tests pin that down).
#
# Assertion strategy: count literal secret occurrences in the dry-run output.
# With redaction in place the expected count is zero (never cleartext); the
# `--env KEY=REDACTED` placeholder is asserted separately.

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
}

# Count occurrences of a literal string in the test output.
_count() {
    local needle="$1" hay="$2"
    printf '%s' "$hay" | grep -oF "$needle" | wc -l
}

@test "GITHUB_TOKEN redacted in --dry-run and absent from labels" {
    run env OPS_RUNTIME=docker GITHUB_TOKEN=ghp_supersecret123 \
        "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    # No cleartext anywhere (labels masked + --env redacted).
    [ "$(_count ghp_supersecret123 "$output")" -eq 0 ]
    # The --env slot shows the redaction placeholder so the wiring is still
    # visible to the caller.
    [[ "$output" == *"GITHUB_TOKEN=REDACTED"* ]]
}

@test "ANTHROPIC_API_KEY redacted in --dry-run and absent from labels" {
    run env OPS_RUNTIME=docker ANTHROPIC_API_KEY=sk-ant-secret \
        "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [ "$(_count sk-ant-secret "$output")" -eq 0 ]
    [[ "$output" == *"ANTHROPIC_API_KEY=REDACTED"* ]]
}

@test "OPENAI_API_KEY redacted in --dry-run and absent from labels" {
    run env OPS_RUNTIME=docker OPENAI_API_KEY=sk-oai-secret \
        "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [ "$(_count sk-oai-secret "$output")" -eq 0 ]
    [[ "$output" == *"OPENAI_API_KEY=REDACTED"* ]]
}

@test "GEMINI_API_KEY redacted in --dry-run and absent from labels" {
    run env OPS_RUNTIME=docker GEMINI_API_KEY=g-secret-value \
        "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [ "$(_count g-secret-value "$output")" -eq 0 ]
    [[ "$output" == *"GEMINI_API_KEY=REDACTED"* ]]
}

@test "multiple secrets all redacted at once in --dry-run" {
    run env OPS_RUNTIME=docker \
        GITHUB_TOKEN=ghp_a1b2c3 ANTHROPIC_API_KEY=sk-ant-xyz \
        OPENAI_API_KEY=sk-oai-uvw GEMINI_API_KEY=g-def456 \
        "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    # Each secret: zero occurrences in cleartext.
    [ "$(_count ghp_a1b2c3   "$output")" -eq 0 ]
    [ "$(_count sk-ant-xyz   "$output")" -eq 0 ]
    [ "$(_count sk-oai-uvw   "$output")" -eq 0 ]
    [ "$(_count g-def456     "$output")" -eq 0 ]
    # Redaction placeholders visible for each forwarded --env slot.
    [[ "$output" == *"GITHUB_TOKEN=REDACTED"* ]]
    [[ "$output" == *"ANTHROPIC_API_KEY=REDACTED"* ]]
    [[ "$output" == *"OPENAI_API_KEY=REDACTED"* ]]
    [[ "$output" == *"GEMINI_API_KEY=REDACTED"* ]]
}

@test "user-typed -e GITHUB_TOKEN=... is redacted in --dry-run (no cleartext)" {
    # Regression guard: the raw user invocation (OPS_ORIG_ARGV) captures every
    # argv token, including `-e KEY=VAL`. The label masker scrubs the labels;
    # the --env printer scrubs the dry-run rendering. Cleartext must not show
    # up in either.
    # (setup_ops_env unsets GITHUB_TOKEN, so the auto-propagation path adds
    #  no additional --env for this key.)
    run env OPS_RUNTIME=docker "$(ops_sh)" \
        run -e GITHUB_TOKEN=ghp_inline_secret --dry-run
    [ "$status" -eq 0 ]
    [ "$(_count ghp_inline_secret "$output")" -eq 0 ]
    [[ "$output" == *"GITHUB_TOKEN=REDACTED"* ]]
}

@test "user-typed -e ANTHROPIC_API_KEY=... is redacted in --dry-run (no cleartext)" {
    run env OPS_RUNTIME=docker "$(ops_sh)" \
        run -e ANTHROPIC_API_KEY=sk-ant-inline --dry-run
    [ "$status" -eq 0 ]
    [ "$(_count sk-ant-inline "$output")" -eq 0 ]
    [[ "$output" == *"ANTHROPIC_API_KEY=REDACTED"* ]]
}

@test "non-secret env vars are NOT masked in --dry-run or in labels" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run -e FOO=bar_value --dry-run
    [ "$status" -eq 0 ]
    # FOO=bar_value appears at least twice: in the user argv (-e FOO=bar_value)
    # and in the effective --env FOO=bar_value. Both labels carry it unmasked.
    [ "$(_count FOO=bar_value "$output")" -ge 2 ]
    [[ "$output" == *"--env FOO=bar_value"* ]]
}
