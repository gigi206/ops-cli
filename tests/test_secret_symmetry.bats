#!/usr/bin/env bats
# Symmetry between the two redaction code paths: `_dry_run_print` (used to
# render the dry-run command line) and `_mask_secrets` (used to scrub the
# `ops.cmdline.{user,real}` labels). Both must agree on whether a given
# variable name holds a secret — a previous version diverged (the bash
# glob `*KEY` matched MONKEY, but the sed regex `[A-Z][A-Z0-9_]*_KEY`
# did not), so the same value was redacted in dry-run output but leaked
# through the labels.
#
# Strategy: run `ops run --dry-run` with various env-var names and check
# that for *each* name either both code paths redact the value, or
# neither does. We assert this by counting cleartext occurrences and
# matching the REDACTED placeholder.

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
}

_count() {
    local needle="$1" hay="$2"
    printf '%s' "$hay" | grep -oF "$needle" | wc -l
}

# ---- positive: convention names (IDENT_<SUF>) MUST be redacted ----------

@test "MY_DB_PASSWORD redacted in both --dry-run and labels" {
    run env OPS_RUNTIME=docker "$(ops_sh)" \
        run -e MY_DB_PASSWORD=very_secret_value --dry-run
    [ "$status" -eq 0 ]
    [ "$(_count very_secret_value "$output")" -eq 0 ]
    [[ "$output" == *"MY_DB_PASSWORD=REDACTED"* ]]
}

@test "SLACK_WEBHOOK_SECRET redacted in both --dry-run and labels" {
    run env OPS_RUNTIME=docker "$(ops_sh)" \
        run -e SLACK_WEBHOOK_SECRET=hush_hush_value --dry-run
    [ "$status" -eq 0 ]
    [ "$(_count hush_hush_value "$output")" -eq 0 ]
    [[ "$output" == *"SLACK_WEBHOOK_SECRET=REDACTED"* ]]
}

@test "STRIPE_API_KEY redacted in both --dry-run and labels" {
    run env OPS_RUNTIME=docker "$(ops_sh)" \
        run -e STRIPE_API_KEY=sk_live_redacted_value --dry-run
    [ "$status" -eq 0 ]
    [ "$(_count sk_live_redacted_value "$output")" -eq 0 ]
    [[ "$output" == *"STRIPE_API_KEY=REDACTED"* ]]
}

@test "DEPLOY_PWD redacted in both --dry-run and labels" {
    run env OPS_RUNTIME=docker "$(ops_sh)" \
        run -e DEPLOY_PWD=p4ssw0rd_unique --dry-run
    [ "$status" -eq 0 ]
    [ "$(_count p4ssw0rd_unique "$output")" -eq 0 ]
    [[ "$output" == *"DEPLOY_PWD=REDACTED"* ]]
}

@test "MY_APIKEY (single-word suffix) redacted in both --dry-run and labels" {
    run env OPS_RUNTIME=docker "$(ops_sh)" \
        run -e MY_APIKEY=abracadabra_unique --dry-run
    [ "$status" -eq 0 ]
    [ "$(_count abracadabra_unique "$output")" -eq 0 ]
    [[ "$output" == *"MY_APIKEY=REDACTED"* ]]
}

# ---- negative: look-alikes WITHOUT the underscore separator ------------
# These would have been false positives under the old `*KEY` glob in
# _is_secret_key; the new `*_KEY` form aligns with the regex used by
# _mask_secrets so neither path redacts them.

@test "MONKEY (no underscore before KEY) is NOT a secret in either path" {
    run env OPS_RUNTIME=docker "$(ops_sh)" \
        run -e MONKEY=banana_value --dry-run
    [ "$status" -eq 0 ]
    # Cleartext present (i.e. NOT redacted) in both labels + the --env slot.
    [[ "$output" == *"MONKEY=banana_value"* ]]
    [[ "$output" != *"MONKEY=REDACTED"* ]]
    [[ "$output" != *"MONKEY=***"* ]]
}

@test "WHISKEY (no underscore before KEY) is NOT a secret in either path" {
    run env OPS_RUNTIME=docker "$(ops_sh)" \
        run -e WHISKEY=irish_neat --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"WHISKEY=irish_neat"* ]]
    [[ "$output" != *"WHISKEY=REDACTED"* ]]
    [[ "$output" != *"WHISKEY=***"* ]]
}

# ---- positive control: a non-secret name with no suffix at all --------

@test "FOO=value (no secret suffix) is NOT redacted by either path" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run -e FOO=plain_value --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"FOO=plain_value"* ]]
    [[ "$output" != *"FOO=REDACTED"* ]]
    [[ "$output" != *"FOO=***"* ]]
}
