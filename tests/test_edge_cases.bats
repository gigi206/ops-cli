#!/usr/bin/env bats
# Miscellaneous edge cases + branches not covered by the main suites.

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
}

@test "default run disables named agent volumes (overlap with HOME bind-mount)" {
    mkdir -p "$HOME/.claude"
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    # mount_home=1 by default → agent bind-mounts of ~/.claude etc. are
    # skipped (redundant with the $HOME bind-mount)
    [[ "$output" != *"$HOME/.claude:"* ]]
}

# Agent-volume tests run with --no-mount-home so the agent bind-mount logic
# is actually exercised (otherwise the $HOME bind-mount would make those
# bind-mounts redundant and auto-disabled).

@test "--no-claude-mount skips ~/.claude mount" {
    mkdir -p "$HOME/.claude"
    echo '{}' > "$HOME/.claude.json"
    run env OPS_RUNTIME=docker "$(ops_sh)" run --no-mount-home --no-claude-mount --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" != *"/.claude"* ]]
}

@test "--no-gemini-mount skips ~/.gemini mount" {
    mkdir -p "$HOME/.gemini"
    run env OPS_RUNTIME=docker "$(ops_sh)" run --no-mount-home --no-gemini-mount --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" != *"/.gemini"* ]]
}

@test "--no-codex-mount skips ~/.codex mount" {
    mkdir -p "$HOME/.codex"
    run env OPS_RUNTIME=docker "$(ops_sh)" run --no-mount-home --no-codex-mount --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" != *"/.codex"* ]]
}

@test "--no-opencode-mount skips opencode mounts" {
    mkdir -p "$HOME/.local/share/opencode" "$HOME/.config/opencode"
    run env OPS_RUNTIME=docker "$(ops_sh)" run --no-mount-home --no-opencode-mount --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" != *"share/opencode"* ]]
}

@test "--claude-volume mounts named Docker volume ops-claude" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --claude-volume --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ops-claude:"* ]]
    [[ "$output" == *"/.claude"* ]]
}

@test "--gemini-volume mounts named Docker volume ops-gemini" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --gemini-volume --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ops-gemini:"* ]]
}

@test "--opencode-volume mounts named Docker volume ops-opencode" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --opencode-volume --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ops-opencode:"* ]]
}

@test "--codex-volume mounts named Docker volume ops-codex" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --codex-volume --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ops-codex:"* ]]
}

@test "auto-detected claude volume mounts only when ~/.claude exists (--no-mount-home)" {
    # No ~/.claude in isolated HOME → no mount
    run env OPS_RUNTIME=docker "$(ops_sh)" run --no-mount-home --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" != *"/.claude"* ]]
}

@test "claude volume mounts when ~/.claude directory exists (--no-mount-home)" {
    mkdir -p "$HOME/.claude"
    run env OPS_RUNTIME=docker "$(ops_sh)" run --no-mount-home --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"$HOME/.claude"* ]]
}

@test "OPS_USER_NAME different from \$USER changes HOME_IN_CTN" {
    run env OPS_RUNTIME=docker OPS_USER_NAME=different \
        "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"HOME=/home/different"* ]]
    # ops-share-mise now mounts at a fixed /opt/mise/data (outside $HOME), so it
    # does not vary with OPS_USER_NAME.
    [[ "$output" == *"ops-share-mise:/opt/mise/data"* ]]
}

@test "unknown non-flag arg becomes the command" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run mycustomcmd arg1 --dry-run
    [ "$status" -eq 0 ]
    # mycustomcmd breaks parsing, --dry-run is part of \$@ → real run would execute.
    # We can't easily assert dry-run path here, but verify mycustomcmd is in output.
    # Since dry-run is not recognized (past break), the command is actually executed
    # through the mock — check mock log instead.
    grep -qE 'mycustomcmd' "$MOCK_LOG"
}

@test "unknown subcommand shows error with suggestions" {
    run env OPS_RUNTIME=docker "$(ops_sh)" totallymadeup
    [ "$status" -eq 1 ]
    [[ "$output" == *"unknown subcommand or alias"* ]]
    [[ "$output" == *"totallymadeup"* ]]
    [[ "$output" == *"help"* ]]
    [[ "$output" == *"run -- "* ]]
}

@test "empty invocation (no args) still starts bash in container" {
    run env OPS_RUNTIME=docker "$(ops_sh)"
    [ "$status" -eq 0 ]
    # Shepherd lifecycle (≥1.11): `docker run` creates the container with
    # `tail -f /dev/null` as PID 1 — the bash session lives in the
    # subsequent `docker exec`, not in `run`.
    grep -qE '^run -d --init' "$MOCK_LOG"
    grep -qE '^exec -it .*bash' "$MOCK_LOG"
}

@test "OPS_VOLUMES empty is accepted without crashing" {
    run env OPS_RUNTIME=docker OPS_VOLUMES="" "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
}

@test "missing Dockerfile causes build to fail cleanly" {
    # build_image now refuses to run when OPS_DOCKERFILE doesn't exist, before
    # it can ever reach the runtime. The old assertion was a tautology
    # (`status != 0 OR build mock invoked`) — always true regardless. Tighten
    # to require BOTH a non-zero exit AND the specific error on stderr.
    run env OPS_RUNTIME=docker OPS_DOCKERFILE="/nonexistent/Dockerfile" \
        "$(ops_sh)" build
    [ "$status" -ne 0 ]
    [[ "$output" == *"Dockerfile not found"* ]]
    # And the runtime build call must NOT have been issued.
    ! grep -qE '^build ' "$MOCK_LOG"
}

@test "--dry-run with --claude-mount + --no-mount-home mounts .claude and injects key" {
    mkdir -p "$HOME/.claude"
    echo '{}' > "$HOME/.claude.json"
    run env OPS_RUNTIME=docker ANTHROPIC_API_KEY=sk-test \
        "$(ops_sh)" run --no-mount-home --claude-mount --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *".claude"* ]]
    # ANTHROPIC_API_KEY is auto-propagated as --env; the value is redacted in
    # --dry-run output (dry-run transcripts don't leak secrets), so we pin
    # the redaction placeholder rather than the cleartext key.
    [[ "$output" == *"ANTHROPIC_API_KEY=REDACTED"* ]]
    [[ "$output" != *"sk-test"* ]]
}

@test "dockerfile_changed requires hash file to exist (false positive guard)" {
    # Fresh cache, image exists per mock — no hash file → no warning
    rm -rf "$XDG_CACHE_HOME"
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" != *"Dockerfile changed"* ]]
}

@test "-H with nerdctl runtime updates OPS_NERDCTL_HOME" {
    # Pre-populate a fake nerdctl binary
    local nh="$BATS_TEST_TMPDIR/custom-nerdctl"
    mkdir -p "$nh/bin"
    cat > "$nh/bin/nerdctl" <<'EOF'
#!/bin/bash
printf '%s\n' "$*" >> "${MOCK_LOG:-/dev/null}"
case "$1" in
    info) ;;
    --version) echo "nerdctl version 1.0.0" ;;
    images) echo "sha256:deadbeefcafe" ;;
    container) exit 1 ;;
esac
exit 0
EOF
    chmod +x "$nh/bin/nerdctl"
    run env OPS_RUNTIME=nerdctl "$(ops_sh)" -H "$nh" help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Runtime: nerdctl"* ]]
}

@test "--nix-cleanup sets agent_cmd for nix GC" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --nix-cleanup --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"nix-collect-garbage"* ]]
}

@test "--update sets agent_cmd running mise + nix cleanup" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --update --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"mise self-update"* ]]
    [[ "$output" == *"mise upgrade"* ]]
    [[ "$output" == *"nix-collect-garbage"* ]]
}

@test "-h inside run triggers help and exits" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run -h
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"* ]]
}

@test "run with -- separator passes args as command verbatim" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run -- --some-flag-for-cmd value
    [ "$status" -eq 0 ]
    [[ "$output" == *"--some-flag-for-cmd"* ]]
    [[ "$output" == *"value"* ]]
}

@test "'nerdctl uninstall' is independent of OPS_RUNTIME (works on any runtime)" {
    # Namespace makes intent explicit; no guard on OPS_RUNTIME.
    # With OPS_NERDCTL_HOME pointing to an empty tmpdir, uninstall still runs
    # (systemctl stop fails silently, binaries already gone).
    export OPS_NERDCTL_HOME="$BATS_TEST_TMPDIR/empty-nerdctl"
    mkdir -p "$OPS_NERDCTL_HOME"
    mock_install_tools
    run bash -c "printf 'n\\nn\\n' | env OPS_RUNTIME=podman '$(ops_sh)' nerdctl uninstall"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Uninstall complete"* ]]
}

@test "'nerdctl self-update' fails if nerdctl binary is missing" {
    export OPS_NERDCTL_HOME="$BATS_TEST_TMPDIR/noexist"
    run env OPS_RUNTIME=podman "$(ops_sh)" nerdctl self-update
    [ "$status" -eq 1 ]
    [[ "$output" == *"nerdctl not installed"* ]]
}

@test "end-of-script auto-install prompt: declining exits 1" {
    # Exercises lines 2170-2177 in ops.sh: when OPS_RUNTIME=nerdctl AND the
    # binary at $OPS_NERDCTL_HOME/bin/nerdctl isn't executable AND the
    # subcommand isn't in _skip_runtime_startup (status isn't), ops.sh prompts
    # "Run 'nerdctl install' now? [Y/n]". Declining → exit 1.
    export OPS_NERDCTL_HOME="$BATS_TEST_TMPDIR/no-nerdctl"
    # Don't pre-create the binary, so RUNTIME_BIN → not executable.
    run bash -c "printf 'n\n' | env OPS_RUNTIME=nerdctl '$(ops_sh)' status"
    [ "$status" -eq 1 ]
    [[ "$output" == *"nerdctl not installed"* ]]
    # Should NOT proceed to cmd_status rendering (no Services header).
    [[ "$output" != *"=== Services ==="* ]]
}

@test "end-of-script auto-install prompt: accepting triggers cmd_install" {
    # Same scenario as above, but answer Y. cmd_install runs and fetches the
    # version from (mocked) GitHub. We stop short of asserting the full
    # install succeeded — the subsequent cmd_status would need more mocks —
    # we just check that cmd_install kicked in (visible via its "Fetching"
    # + "Downloading" messages).
    export OPS_NERDCTL_HOME="$BATS_TEST_TMPDIR/to-install-nerdctl"
    mock_install_tools
    # Feed 3 Y's to cover: auto-install prompt + any post-install prompts.
    run bash -c "printf 'Y\nY\nY\n' | env OPS_RUNTIME=nerdctl '$(ops_sh)' status"
    [[ "$output" == *"nerdctl not installed"* ]]
    [[ "$output" == *"Fetching latest nerdctl release"* ]]
}

@test "'nerdctl self-update' aborts cleanly if user declines" {
    export OPS_NERDCTL_HOME="$BATS_TEST_TMPDIR/nerdctl"
    mkdir -p "$OPS_NERDCTL_HOME/bin"
    cat > "$OPS_NERDCTL_HOME/bin/nerdctl" <<'EOF'
#!/bin/bash
[ "$1" = "--version" ] && echo "nerdctl version 1.0.0"
exit 0
EOF
    chmod +x "$OPS_NERDCTL_HOME/bin/nerdctl"
    mock_install_tools
    run bash -c "printf 'n\n' | env OPS_RUNTIME=nerdctl MOCK_GH_VERSION=v2.0.0 '$(ops_sh)' nerdctl self-update"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Aborted"* ]]
}
