#!/usr/bin/env bats
# Per-agent flag dispatcher (`_match_agent_flag`): the helper that collapsed
# the 12 case-branches of `--{claude,gemini,opencode,codex}-{mount,volume}`
# / `--no-X-mount` into a single nameref-based dispatch. Tests assert the
# observable effect of each flag combination through the --dry-run path.
#
# We rely on visible side-effects in the dry-run rendering:
#   --no-X-mount → off    : NO ops-X named volume, NO bind-mount of ~/.X
#   --X-volume   → volume : `--volume ops-claude:/path/in/container`
#   --X-mount    → mount  : `--volume $HOME/.claude:/path/in/container`
# The default ("auto") is exercised by other test files; here we focus on
# the explicit overrides that the dispatcher resolves.

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
    mkdir -p "$HOME/.claude" "$HOME/.gemini" "$HOME/.codex" \
             "$HOME/.local/share/opencode"
}

# ---- claude --------------------------------------------------------------

@test "--claude-volume injects the ops-claude named volume" {
    run env OPS_RUNTIME=docker "$(ops_sh)" \
        run --no-mount-home --claude-volume --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ops-claude:"* ]]
}

@test "--claude-mount injects the host ~/.claude bind-mount" {
    run env OPS_RUNTIME=docker "$(ops_sh)" \
        run --no-mount-home --claude-mount --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"$HOME/.claude:"* ]]
    [[ "$output" != *"ops-claude:"* ]]
}

@test "--no-claude-mount disables both the bind-mount and the named volume" {
    run env OPS_RUNTIME=docker "$(ops_sh)" \
        run --no-mount-home --no-claude-mount --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" != *"ops-claude:"* ]]
    [[ "$output" != *"$HOME/.claude:"* ]]
}

# ---- gemini --------------------------------------------------------------

@test "--gemini-volume injects the ops-gemini named volume" {
    run env OPS_RUNTIME=docker "$(ops_sh)" \
        run --no-mount-home --gemini-volume --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ops-gemini:"* ]]
}

@test "--no-gemini-mount disables the gemini wiring" {
    run env OPS_RUNTIME=docker "$(ops_sh)" \
        run --no-mount-home --no-gemini-mount --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" != *"ops-gemini:"* ]]
    [[ "$output" != *"$HOME/.gemini:"* ]]
}

# ---- opencode ------------------------------------------------------------

@test "--opencode-volume injects the ops-opencode named volume" {
    run env OPS_RUNTIME=docker "$(ops_sh)" \
        run --no-mount-home --opencode-volume --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ops-opencode:"* ]]
}

# ---- codex --------------------------------------------------------------

@test "--codex-volume injects the ops-codex named volume" {
    run env OPS_RUNTIME=docker "$(ops_sh)" \
        run --no-mount-home --codex-volume --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ops-codex:"* ]]
}

# ---- multiple agents at once -------------------------------------------

@test "--claude-volume + --gemini-volume both injected" {
    run env OPS_RUNTIME=docker "$(ops_sh)" \
        run --no-mount-home --claude-volume --gemini-volume --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ops-claude:"* ]]
    [[ "$output" == *"ops-gemini:"* ]]
}
