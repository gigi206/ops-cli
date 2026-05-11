#!/usr/bin/env bats
# Per-app flag dispatcher (`_match_app_flag`): the helper that collapsed
# the 12 case-branches of `--{claude,gemini,opencode,codex}-{mount,volume}`
# / `--no-X-mount` into a single generic parser that consults `_OPS_APPS`.
# Tests assert the observable effect of each flag combination through the
# --dry-run path.
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

# ---- opencode-desktop (Electron GUI) ------------------------------------
# Design decision: --app opencode-desktop deliberately reuses the SAME
# state volume as --app opencode (~/.local/share/opencode + ~/.config/
# opencode) so sessions stay coherent between the terminal CLI and the
# desktop app. The dispatcher therefore must NOT mint a separate
# `ops-opencode-desktop` volume — if anyone splits the state in the
# future this test fires. The normalisation lives in `_match_app_flag`
# (opencode-desktop → opencode) so a single _app_state entry is set.
@test "--app opencode-desktop --opencode-volume reuses ops-opencode (no ops-opencode-desktop volume)" {
    run env OPS_RUNTIME=docker "$(ops_sh)" \
        run --no-mount-home --opencode-volume --app opencode-desktop --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ops-opencode:"* ]]
    [[ "$output" != *"ops-opencode-desktop:"* ]]
}

# Theme detection (light/dark) + dconf access in the Electron GUI need
# the host's D-Bus session bus inside the container. The flag flips
# `dbus_session_auto=1` in cmd_run, which the auto-forward block down
# below translates into a `--volume` of the bus socket and an `--env
# DBUS_SESSION_BUS_ADDRESS=…`. Without this, the GUI is stuck on the
# light theme and the startup is polluted with dconf-CRITICAL spam.
# We test under DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/test-bus with a
# real socket file so the `[ -S … ]` precondition passes; the assertion
# checks the resulting --env line in the dry-run.
@test "--app opencode-desktop forwards DBUS_SESSION_BUS_ADDRESS when a session bus exists" {
    socket="$BATS_TEST_TMPDIR/test-bus"
    # bats provides BATS_TEST_TMPDIR; fall back to mktemp for older bats.
    [ -z "$socket" ] && socket="$(mktemp -u)"
    # Create a real Unix socket so the `[ -S … ]` test passes.
    python3 -c "import socket as s; sock = s.socket(s.AF_UNIX); sock.bind('$socket')" 2>/dev/null \
        || perl -MIO::Socket::UNIX -e "IO::Socket::UNIX->new(Local => '$socket', Type => SOCK_STREAM, Listen => 1) or die" 2>/dev/null \
        || skip "no python3 / perl available to create a test socket"
    run env OPS_RUNTIME=docker \
        DBUS_SESSION_BUS_ADDRESS="unix:path=$socket" \
        XDG_CURRENT_DESKTOP="ubuntu:GNOME" \
        "$(ops_sh)" run --app opencode-desktop --dry-run
    rm -f "$socket"
    [ "$status" -eq 0 ]
    [[ "$output" == *"DBUS_SESSION_BUS_ADDRESS=unix:path=$socket"* ]]
    [[ "$output" == *"$socket:$socket"* ]]
    [[ "$output" == *"XDG_CURRENT_DESKTOP=ubuntu:GNOME"* ]]
}

# Negative side: plain `ops run` (no --app opencode-desktop) must NOT
# auto-mount the session bus. The bus exposes notifications, secrets,
# screen recording portal — surface we don't want in shells that
# didn't ask for the GUI flow.
@test "plain run does NOT forward DBUS_SESSION_BUS_ADDRESS" {
    socket="$BATS_TEST_TMPDIR/test-bus"
    [ -z "$socket" ] && socket="$(mktemp -u)"
    python3 -c "import socket as s; sock = s.socket(s.AF_UNIX); sock.bind('$socket')" 2>/dev/null \
        || perl -MIO::Socket::UNIX -e "IO::Socket::UNIX->new(Local => '$socket', Type => SOCK_STREAM, Listen => 1) or die" 2>/dev/null \
        || skip "no python3 / perl available to create a test socket"
    run env OPS_RUNTIME=docker \
        DBUS_SESSION_BUS_ADDRESS="unix:path=$socket" \
        "$(ops_sh)" run --dry-run
    rm -f "$socket"
    [ "$status" -eq 0 ]
    [[ "$output" != *"DBUS_SESSION_BUS_ADDRESS"* ]]
    [[ "$output" != *"$socket:$socket"* ]]
}

# ---- multiple apps at once -------------------------------------------

@test "--claude-volume + --gemini-volume both injected" {
    run env OPS_RUNTIME=docker "$(ops_sh)" \
        run --no-mount-home --claude-volume --gemini-volume --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ops-claude:"* ]]
    [[ "$output" == *"ops-gemini:"* ]]
}
