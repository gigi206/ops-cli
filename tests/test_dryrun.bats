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

@test "run --dry-run auto-trusts workdir's mise.toml by default" {
    # trust_workdir=1 (default) forwards MISE_TRUSTED_CONFIG_PATHS=\$PWD so
    # mise activates the workdir's mise.toml without the interactive prompt.
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"MISE_TRUSTED_CONFIG_PATHS=$PWD"* ]]
}

@test "run --no-trust-workdir omits MISE_TRUSTED_CONFIG_PATHS" {
    # Per-invocation opt-out when the current mise.toml is untrusted.
    run env OPS_RUNTIME=docker "$(ops_sh)" run --no-trust-workdir --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" != *"MISE_TRUSTED_CONFIG_PATHS"* ]]
}

@test "OPS_TRUST_WORKDIR=0 opts out globally" {
    # Global opt-out path (typically set in ops.conf).
    run env OPS_RUNTIME=docker OPS_TRUST_WORKDIR=0 "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" != *"MISE_TRUSTED_CONFIG_PATHS"* ]]
}

# --dry-run renders the full command line through `printf '%q '`, which
# shell-escapes spaces ("mise install" → "mise\ install"), `&&`, etc.
# Strip the backslash-space escapes before asserting so tests match the
# semantic command rather than its quoted rendering.
_unquote() { printf '%s' "${1//\\ / }"; }

@test "run --install alone chains mise install before an interactive bash" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --install --dry-run
    [ "$status" -eq 0 ]
    norm="$(_unquote "$output")"
    [[ "$norm" == *"mise install --yes "*"exec bash"* ]]
}

@test "run --install combined with --claude chains before the agent command" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --install --claude --dry-run
    [ "$status" -eq 0 ]
    norm="$(_unquote "$output")"
    [[ "$norm" == *"mise install --yes "* ]]
    [[ "$norm" == *"claude"* ]]
}

@test "run --install -- CMD execs CMD after mise install" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --install --dry-run -- pytest -k smoke
    [ "$status" -eq 0 ]
    norm="$(_unquote "$output")"
    [[ "$norm" == *"mise install --yes "*"exec "* ]]
    [[ "$norm" == *"pytest"* ]]
    [[ "$norm" == *"smoke"* ]]
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
    [ "$status" -eq 0 ]
    # We expect both the "Warning: unknown flag" prefix AND the specific
    # offending flag name in the output -- asserting either/or would let a
    # regression (e.g. silent parsing) slip through.
    [[ "$output" == *"Warning: unknown flag"* ]]
    [[ "$output" == *"--definitely-not-a-flag"* ]]
}

@test "run without args launches bash with --rcfile /etc/ops-bashrc" {
    # mount_home=1 (default) bind-mounts the host's $HOME onto the container,
    # which shadows the image's $HOME/.bashrc. The interactive shell is
    # therefore started with --rcfile pointing at /etc/ops-bashrc, a file
    # baked into the image by the Dockerfile (outside $HOME so it survives
    # the bind-mount). Regression guard.
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    norm="$(_unquote "$output")"
    [[ "$norm" == *"bash --rcfile /etc/ops-bashrc"* ]]
}

@test "run --install alone execs bash with --rcfile /etc/ops-bashrc" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --install --dry-run
    [ "$status" -eq 0 ]
    norm="$(_unquote "$output")"
    [[ "$norm" == *"exec bash --rcfile /etc/ops-bashrc"* ]]
}

@test "run --claude wraps agent_cmd with source /etc/ops-bashrc" {
    # Agent wrappers (claude/gemini/opencode/codex/update/nix-cleanup) run via
    # `bash -c`, which is non-interactive and therefore ignores --rcfile. We
    # source /etc/ops-bashrc explicitly at the top of agent_cmd so the agent
    # inherits PATH / PYTHONPATH / ... from mise env (mise-nix plugin picks
    # up the workdir's flake.nix devShell when [env] _.nix = true is set).
    run env OPS_RUNTIME=docker "$(ops_sh)" run --claude --dry-run
    [ "$status" -eq 0 ]
    norm="$(_unquote "$output")"
    [[ "$norm" == *"source /etc/ops-bashrc"* ]]
    [[ "$norm" == *"claude"* ]]
}

@test "run --install -- CMD wraps with source /etc/ops-bashrc" {
    # --install without an agent flag but WITH a user command after `--`
    # still goes through the bash -c wrapper, so the same source prefix
    # applies and the user's CMD inherits the flake env.
    run env OPS_RUNTIME=docker "$(ops_sh)" run --install --dry-run -- pytest -k smoke
    [ "$status" -eq 0 ]
    norm="$(_unquote "$output")"
    [[ "$norm" == *"source /etc/ops-bashrc"* ]]
    [[ "$norm" == *"mise install --yes "* ]]
    [[ "$norm" == *"pytest"* ]]
}

@test "run -- CMD without agent_cmd bypasses the bash -c wrapper" {
    # Bare `run -- CMD` (no --install, no agent flag) forwards "$@" directly
    # to the container runtime. No bash -c wrapper is built, therefore no
    # /etc/ops-bashrc source prefix is injected — the Dockerfile's ENV PATH
    # already covers the baseline mise + nix shims, and flake activation is
    # opt-in through a mise.toml with [env] _.nix = true.
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run -- echo hello
    [ "$status" -eq 0 ]
    norm="$(_unquote "$output")"
    [[ "$norm" != *"source /etc/ops-bashrc"* ]]
    [[ "$norm" != *"bash -c"* ]]
    [[ "$norm" == *"echo"* ]]
    [[ "$norm" == *"hello"* ]]
}

@test "OPS_DEV_PLUGIN_MOUNT=1 bind-mounts the repo's mise/ over the baked plugin" {
    # Contributor escape hatch: iterate on the Lua plugin without rebuilding
    # the image. The bind-mount is read-only so plugin mutations live only
    # on the host working copy (git-trackable, no container drift).
    run env OPS_RUNTIME=docker OPS_DEV_PLUGIN_MOUNT=1 "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"/mise:/opt/ops/mise-plugin/nix:ro"* ]]
}

@test "default run does NOT bind-mount the repo's mise/ (prod-safe)" {
    # Without OPS_DEV_PLUGIN_MOUNT, the plugin comes from the image only.
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" != *"/opt/ops/mise-plugin/nix:ro"* ]]
}

@test "run --build --dry-run prints build cmdline and does NOT build" {
    # Regression: the README used to claim that `ops run --build --dry-run`
    # dry-ran the build, but the flag was only honored by cmd_run's container
    # path, not the build path. Now build_image short-circuits on --dry-run,
    # prints the composed docker build command, and exits 0 without touching
    # the runtime.
    run env OPS_RUNTIME=docker "$(ops_sh)" run --build --dry-run
    [ "$status" -eq 0 ]
    # The printed cmdline must include the docker build invocation with the
    # expected key flags...
    [[ "$output" == *"docker"* ]]
    [[ "$output" == *"build"* ]]
    [[ "$output" == *"-t"* ]]
    [[ "$output" == *"localhost/test-img"* ]]
    [[ "$output" == *"--file"* ]]
    [[ "$output" == *"--label"* ]]
    [[ "$output" == *"ops.dockerfile="* ]]
    # ...and the mock must NOT have recorded an actual `build ...` call.
    ! grep -qE '^build ' "$MOCK_LOG"
}
