#!/usr/bin/env bats
# Additional flag parsing coverage for cmd_run

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
}

@test "run -u UID override applied in rootful mode" {
    # Rootful docker → --user uses OPS_USER_UID:OPS_USER_GID
    run env OPS_RUNTIME=docker MOCK_SEC_OPTIONS="" \
        "$(ops_sh)" run -u 2000 --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"--user 2000:1000"* ]]
}

@test "run -g GID override applied in rootless mode" {
    # Rootless: --user is "0:$GID" → -g should change the GID part
    run env OPS_RUNTIME=docker "$(ops_sh)" run -g 2500 --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"--user 0:2500"* ]]
}

@test "run -u and -g together in rootful mode" {
    run env OPS_RUNTIME=docker MOCK_SEC_OPTIONS="" \
        "$(ops_sh)" run -u 2000 -g 2500 --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"--user 2000:2500"* ]]
}

@test "run -l LOCALE sets the locale build-arg" {
    run env OPS_RUNTIME=docker "$(ops_sh)" build -l de_DE.UTF-8
    [ "$status" -eq 0 ]
    grep -qE 'build .*USER_LANG=de_DE.UTF-8' "$MOCK_LOG"
}

@test "run --env-file is forwarded" {
    local f="$BATS_TEST_TMPDIR/envs"
    printf 'KEY=value\n' > "$f"
    run env OPS_RUNTIME=docker "$(ops_sh)" run --env-file "$f" --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"--env-file"* ]]
    [[ "$output" == *"$f"* ]]
}

@test "OPS_VOLUMES env is parsed and appended" {
    run env OPS_RUNTIME=docker OPS_VOLUMES="/a:/b /c:/d" "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"/a:/b"* ]]
    [[ "$output" == *"/c:/d"* ]]
}

@test "run --no-rm omits --rm" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --no-rm --dry-run
    [ "$status" -eq 0 ]
    # The args should contain `run -it` but no `--rm`
    [[ "$output" == *"run -it"* ]]
    [[ "$output" != *"--rm"* ]]
}

@test "default run includes --rm (ephemeral)" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"--rm"* ]]
}

@test "default run bind-mounts host HOME" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"$HOME:$HOME"* ]] || [[ "$output" == *"$HOME:/home/"* ]]
}

@test "run --no-mount-home skips HOME bind-mount" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --no-mount-home --dry-run
    [ "$status" -eq 0 ]
    # no bare $HOME:$HOME bind-mount; the workdir /home/.../msb bind is still there
    [[ "$output" != *"$HOME:$HOME "* ]]
    [[ "$output" != *"$HOME:$HOME\\"* ]]
}

@test "run --no-mount-volume skips both mise and nix volumes" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --no-mount-volume --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" != *"-nix:/nix"* ]]
    [[ "$output" != *"-mise:/opt/mise/data"* ]]
}

@test "run --no-nix-volume skips nix volume" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --no-nix-volume --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" != *"-nix:/nix"* ]]
}

@test "run --no-mise-volume skips mise volume" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --no-mise-volume --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" != *"-mise:"* ]]
}

@test "default run uses ops-share-* volumes + HOME bind-mount" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ops-share-nix:/nix"* ]]
    [[ "$output" == *"ops-share-mise:/opt/mise/data"* ]]
    [[ "$output" == *"$HOME:$HOME"* ]] || [[ "$output" == *"$HOME:/home/"* ]]
}

@test "run --isolated-volumes uses per-container volumes" {
    run env OPS_RUNTIME=docker OPS_CONTAINER_NAME=my-ctn \
        "$(ops_sh)" run --isolated-volumes --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"my-ctn-nix:/nix"* ]]
    [[ "$output" == *"my-ctn-mise:/opt/mise/data"* ]]
    # ensure share defaults are NOT used
    [[ "$output" != *"ops-share-nix:"* ]]
    [[ "$output" != *"ops-share-mise:"* ]]
}

@test "-H flag emits warning when runtime != nerdctl" {
    run env OPS_RUNTIME=docker "$(ops_sh)" -H /tmp/fake help 2>&1
    [ "$status" -eq 0 ]
    [[ "$output" == *"-H has no effect"* ]]
}

@test "GITHUB_TOKEN is forwarded as --env" {
    run env OPS_RUNTIME=docker GITHUB_TOKEN=ghp_testtoken "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"GITHUB_TOKEN=ghp_testtoken"* ]]
}

@test "ANTHROPIC_API_KEY auto-propagated when set on host" {
    run env OPS_RUNTIME=docker ANTHROPIC_API_KEY=sk-ant-test "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"ANTHROPIC_API_KEY=sk-ant-test"* ]]
}

@test "OPENAI_API_KEY auto-propagated when set on host" {
    run env OPS_RUNTIME=docker OPENAI_API_KEY=sk-oai-test "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"OPENAI_API_KEY=sk-oai-test"* ]]
}

@test "GEMINI_API_KEY auto-propagated when set on host" {
    run env OPS_RUNTIME=docker GEMINI_API_KEY=g-test "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"GEMINI_API_KEY=g-test"* ]]
}

@test "--claude-mount bind-mounts ~/.claude (with --no-mount-home)" {
    mkdir -p "$HOME/.claude"
    echo '{}' > "$HOME/.claude.json"
    run env OPS_RUNTIME=docker "$(ops_sh)" run --no-mount-home --claude-mount --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"$HOME/.claude"* ]]
    [[ "$output" == *"$HOME/.claude.json"* ]]
}

@test "--claude-mount warns when combined with default HOME bind-mount" {
    mkdir -p "$HOME/.claude"
    run env OPS_RUNTIME=docker "$(ops_sh)" run --claude-mount --dry-run 2>&1
    [ "$status" -eq 0 ]
    [[ "$output" == *"Warning:"*"--claude-mount"*"redundant"* ]]
}
