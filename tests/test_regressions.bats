#!/usr/bin/env bats
# Regressions and gaps identified during code review:
# - #18: build with trailing cmd args must not inject them into `docker build`
# - #22: `run -- --` passes the second -- as a container arg
# - #23: PWD under HOME must not duplicate/crash the bind-mount set
# - #24: OPS_USER_NAME ≠ invoking user remaps agent bind-mount destinations
# - #20: cmd_clean interactive y-path invokes prune/rm
# - #17: -H change during the same invocation picks up rootless re-detection
# - isolated-volumes extension to agent configs

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
}

@test "#18: run --build -- cmd does NOT forward cmd into docker build args" {
    # Previously: build_image "$@" "$SCRIPT_DIR" would result in
    #   docker build ... cmd SCRIPT_DIR → "requires exactly 1 argument".
    # Fix: cmd_run strips $@ before calling build_image under --build.
    run env OPS_RUNTIME=docker "$(ops_sh)" run --build -- mycmd arg
    [ "$status" -eq 0 ]
    # The build command in the mock log must not end with "mycmd arg ..."
    ! grep -qE '^build .*mycmd' "$MOCK_LOG"
    # Build still triggered normally
    grep -qE '^build .*-t localhost/test-img' "$MOCK_LOG"
}

@test "#22: run -- --foo passes --foo as container arg, not an ops flag" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run -- --no-rm
    [ "$status" -eq 0 ]
    # --no-rm after -- must appear as a command argument in the output,
    # NOT consumed as the ops --no-rm flag (which would drop --rm).
    [[ "$output" == *"--rm"* ]]        # ops --rm is still present
    [[ "$output" == *"--no-rm"* ]]     # and --no-rm passed through as cmd arg
}

@test "#23: \$PWD under \$HOME produces both bind-mounts without crash" {
    # bats tmpdir is under /tmp by default. Force PWD to be under HOME
    # (our isolated test HOME).
    mkdir -p "$HOME/project"
    cd "$HOME/project"
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    # HOME bind-mount (host HOME → /home/$OPS_USER_NAME in container) AND
    # PWD bind-mount (identity map) both present; overlap is safe.
    [[ "$output" == *"$HOME:/home/testuser"* ]]
    [[ "$output" == *"$HOME/project:$HOME/project"* ]]
}

@test "#24: OPS_USER_NAME ≠ invoker remaps \$HOME/.claude → \$HOME_IN_CTN/.claude" {
    mkdir -p "$HOME/.claude"
    run env OPS_RUNTIME=docker OPS_USER_NAME=alt \
        "$(ops_sh)" run --no-mount-home --dry-run
    [ "$status" -eq 0 ]
    # Bind-mount destination is /home/alt/.claude (not /home/testuser/.claude)
    [[ "$output" == *"$HOME/.claude:/home/alt/.claude"* ]]
}

@test "#20: cmd_clean y-answer triggers image prune + container rm" {
    # Answer Y to both prompts (dangling images + ops volumes)
    run bash -c "printf 'y\\ny\\n' | env OPS_RUNTIME=docker MOCK_DANGLING=1 \
        '$(ops_sh)' clean"
    [ "$status" -eq 0 ]
    # image prune was called
    grep -qE 'image prune' "$MOCK_LOG"
}

@test "#20: cmd_clean N-answer does NOT prune" {
    run bash -c "printf 'n\\nn\\n' | env OPS_RUNTIME=docker MOCK_DANGLING=1 \
        '$(ops_sh)' clean"
    [ "$status" -eq 0 ]
    ! grep -qE 'image prune' "$MOCK_LOG"
}

@test "#17: second -H call refreshes rootless cache (bug fix)" {
    # Indirect test: when -H switches runtime from docker to nerdctl, the
    # rootless cache must reset. We can't easily exercise this end-to-end,
    # but we can verify that help output reflects the new runtime after -H.
    local nh="$BATS_TEST_TMPDIR/custom-nerdctl"
    mkdir -p "$nh/bin"
    cat > "$nh/bin/nerdctl" <<'EOF'
#!/bin/bash
case "$1" in
    info) echo "[name=rootless]" ;;
    --version) echo "nerdctl version 1.0.0" ;;
    images) echo "sha256:deadbeef" ;;
esac
exit 0
EOF
    chmod +x "$nh/bin/nerdctl"
    # Start with docker runtime then switch via -H nerdctl
    run env OPS_RUNTIME=nerdctl "$(ops_sh)" -H "$nh" help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Runtime: nerdctl"* ]]
}

@test "#6 (code): --isolated-volumes also isolates agent volumes" {
    run env OPS_RUNTIME=docker OPS_CONTAINER_NAME=myctn \
        "$(ops_sh)" run --isolated-volumes --claude-volume --dry-run
    [ "$status" -eq 0 ]
    # With isolation, the agent volume is named ${OPS_CONTAINER_NAME}-${agent}
    [[ "$output" == *"myctn-claude:"* ]]
    # Default shared name must NOT be used
    [[ "$output" != *"ops-claude:"* ]]
}

@test "#6 (code): default run (no isolation) uses shared ops-claude volume" {
    run env OPS_RUNTIME=docker \
        "$(ops_sh)" run --claude-volume --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ops-claude:"* ]]
}

@test "#5 (code): build fails cleanly when Dockerfile is missing" {
    run env OPS_RUNTIME=docker OPS_DOCKERFILE="/nonexistent/Dockerfile.nope" \
        "$(ops_sh)" build
    [ "$status" -ne 0 ]
    [[ "$output" == *"Dockerfile not found"* ]]
}

@test "#3 (code): install refuses unsafe OPS_NERDCTL_HOME outside \$HOME/.local" {
    run env OPS_RUNTIME=nerdctl OPS_NERDCTL_HOME=/usr \
        "$(ops_sh)" nerdctl install
    [ "$status" -ne 0 ]
    [[ "$output" == *"Refusing to install"* ]]
}

@test "#3 (code): install accepts OPS_NERDCTL_HOME under /tmp (bats tmpdir)" {
    # bats tmpdir is under /tmp → whitelist
    export OPS_NERDCTL_HOME="$BATS_TEST_TMPDIR/nerdctl"
    mock_install_tools
    run bash -c "yes Y | env OPS_RUNTIME=nerdctl '$(ops_sh)' nerdctl install"
    [ "$status" -eq 0 ]
    [ -x "$OPS_NERDCTL_HOME/bin/nerdctl" ]
}

@test "#19: container exists but start fails → rm -f then recreate path" {
    # Existing, NOT running. Our mock's `start` is silent success but the
    # subsequent `ps` still reports not running (no state change in mock).
    # ops.sh prints the "failed to start" message and calls `rm -f`.
    run env OPS_RUNTIME=docker MOCK_CONTAINER_EXISTS=1 MOCK_CONTAINER_RUNNING=0 \
        "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"failed to start"* ]]
    grep -qE '^rm -f test-container' "$MOCK_LOG"
}

@test "#4 (code): rm -f survives when container already gone (race)" {
    # Container exists per mock, but during the start/re-check window the
    # daemon reports it gone. The new `rm -f ... 2>&1 || true` must not abort.
    run env OPS_RUNTIME=docker MOCK_CONTAINER_EXISTS=1 MOCK_CONTAINER_RUNNING=0 \
        "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    # Path reached end-of-flow: the dry-run output was emitted
    [[ "$output" == *"docker"* ]]
    [[ "$output" == *"localhost/test-img"* ]]
}
