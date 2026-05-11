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

# More aggressive: strip ALL `\X` escapes so assertions can match against
# the bare semantic command line. Used when the pattern includes shell
# metachars that printf '%q' escapes too (`|`, `;`, `{`, `}`, `<`, `>`,
# `&`, `(`, `)`, `*`, `?`). _unquote alone only strips `\ `.
_unescape() {
    # `bash -c 'printf %b'` interprets `\\;` etc. but we want a plain
    # textual strip — Python-style: drop any backslash that precedes a
    # non-alphanumeric char. Implemented with a sed character class so we
    # don't depend on bash's parameter expansion edge cases.
    printf '%s' "$1" | sed 's/\\\([^A-Za-z0-9]\)/\1/g'
}

@test "run --install alone chains mise install before an interactive bash" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --install --dry-run
    [ "$status" -eq 0 ]
    norm="$(_unquote "$output")"
    [[ "$norm" == *"mise install --yes "*"exec bash"* ]]
}

@test "run --install combined with --app claude chains before the app command" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --install --app claude --dry-run
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

@test "run --app claude builds app command" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --app claude --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"mise"* ]]
    [[ "$output" == *"claude"* ]]
    [[ "$output" == *"@anthropic-ai/claude-code"* ]]
}

@test "run --app codex builds app command" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --app codex --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"codex"* ]]
    [[ "$output" == *"@openai/codex"* ]]
}

@test "run --app gemini builds app command" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --app gemini --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"gemini"* ]]
    [[ "$output" == *"@google/gemini-cli"* ]]
}

@test "run --app opencode builds app command" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --app opencode --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"opencode"* ]]
    [[ "$output" == *"opencode-ai"* ]]
}

# Electron GUI variant: pulled as a prebuilt AppImage from upstream's
# GitHub releases via mise's `github:` backend with asset_pattern. The
# dry-run must show:
#   - the `github:sst/opencode[asset_pattern=…AppImage]` install token
#     (regression guard if anyone swaps to npm: / nix: / aqua: again),
#   - `--appimage-extract` (NOT `--appimage-extract-and-run`) — we cache
#     the squashfs-root under $HOME/.cache/opencode-desktop/ so the
#     extraction cost is paid once per upstream version, not per launch.
#     Switching back to extract-and-run would re-introduce ~1–2 s of
#     squashfs decompression on every `ops run`.
#   - `--no-sandbox` on the exec line (without it Chromium FATALs at
#     startup because chrome-sandbox can't be SUID-root in a non-
#     privileged container — see the comment block in cmd_run for the
#     full rationale; this assertion locks in the workaround so a
#     well-meaning revert ("we don't need --no-sandbox, do we?") fails
#     loudly here),
#   - `exec "$extracted/AppRun"` from the cache directory (NOT directly
#     `opencode-desktop.AppImage`) — we exec the AppRun bundled inside
#     the extracted squashfs-root, which gives instant startup on the
#     warm path.
@test "run --app opencode-desktop pulls Electron AppImage via github backend" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --app opencode-desktop --dry-run
    [ "$status" -eq 0 ]
    norm="$(_unescape "$output")"
    [[ "$norm" == *"github:sst/opencode[asset_pattern=opencode-desktop-linux-x86_64.AppImage]"* ]]
    [[ "$norm" == *"--appimage-extract"* ]]
    [[ "$norm" != *"--appimage-extract-and-run"* ]]
    [[ "$norm" == *"--no-sandbox"* ]]
    [[ "$norm" == *"--ozone-platform=wayland"* ]]
    [[ "$norm" == *"--enable-features=UseOzonePlatform"* ]]
    [[ "$norm" == *'APPDIR="$extracted" exec "$extracted/AppRun"'* ]]
}

@test "run --app opencode-desktop caches the extracted squashfs under \$HOME/.cache/opencode-desktop/" {
    # Regression guard: the cache path uses a sha256-truncated fingerprint
    # of the resolved AppImage path so that `mise upgrade` (which moves the
    # asset side-by-side under /opt/mise/data/installs/...) naturally
    # invalidates the cache without manual purge. Anything that drops the
    # fingerprint and falls back to a single static path would mean a stale
    # squashfs-root keeping the old version alive after an upgrade.
    run env OPS_RUNTIME=docker "$(ops_sh)" run --app opencode-desktop --dry-run
    [ "$status" -eq 0 ]
    norm="$(_unescape "$output")"
    [[ "$norm" == *'$HOME/.cache/opencode-desktop/$fp/squashfs-root'* ]]
    [[ "$norm" == *"sha256sum"* ]]
    [[ "$norm" == *"mise which opencode-desktop.AppImage"* ]]
}

# Regression guard: opencode used to be installed via the Bun
# single-binary `github:sst/opencode`, which hung the TUI at cold
# launch (see CHANGELOG / commit history). The fix was to switch to
# the regular npm package `npm:opencode-ai`. If anyone reverts that
# switch, this test fails loudly.
@test "run --app opencode uses npm:opencode-ai (NOT github:sst/opencode)" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --app opencode --dry-run
    [ "$status" -eq 0 ]
    norm="$(_unescape "$output")"
    [[ "$norm" == *"npm:opencode-ai"* ]]
    [[ "$norm" != *"github:sst/opencode"* ]]
}

# Regression guard: _app_cmd uses `command -v $bin` (PATH lookup, ~0 ms)
# for the warm-path resolution, NOT `mise which` (which boots the full
# mise toolset, ~5–17 s, and would re-trigger the nix plugin's MiseEnv
# hook on every app launch). Switching opencode from the Bun
# single-binary to `npm:opencode-ai` removed the constraint that forced
# us back to `mise which` previously. One @test per app so a regression
# on a single branch of _app_cmd's `case "$pkg" in npm:*) ... ;; *)
# ... ;; esac` surfaces clearly. `_unescape` strips the printf '%q'
# backslash-escapes so we match the semantic command line.
@test "run --app claude uses 'command -v claude' (not 'mise which')" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --app claude --dry-run
    [ "$status" -eq 0 ]
    norm="$(_unescape "$output")"
    [[ "$norm" == *"command -v claude"* ]]
    [[ "$norm" != *"mise which claude"* ]]
}

@test "run --app gemini uses 'command -v gemini' (not 'mise which')" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --app gemini --dry-run
    [ "$status" -eq 0 ]
    norm="$(_unescape "$output")"
    [[ "$norm" == *"command -v gemini"* ]]
    [[ "$norm" != *"mise which gemini"* ]]
}

@test "run --app opencode uses 'command -v opencode' (not 'mise which')" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --app opencode --dry-run
    [ "$status" -eq 0 ]
    norm="$(_unescape "$output")"
    [[ "$norm" == *"command -v opencode"* ]]
    [[ "$norm" != *"mise which opencode"* ]]
}

@test "run --app codex uses 'command -v codex' (not 'mise which')" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --app codex --dry-run
    [ "$status" -eq 0 ]
    norm="$(_unescape "$output")"
    [[ "$norm" == *"command -v codex"* ]]
    [[ "$norm" != *"mise which codex"* ]]
}

# The fast path skips the slow mise install. The fallback (`|| mise use
# -g …`) must still be present so a fresh container without the shim
# falls back to a real install. opencode now uses the npm package
# `opencode-ai` (was `github:sst/opencode`, the Bun single-binary
# variant — switched because the bundled Bun watcher binding fails to
# extract on cold container start, hanging the TUI).
@test "app commands keep 'mise use -g' fallback after 'command -v'" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --app opencode --dry-run
    [ "$status" -eq 0 ]
    norm="$(_unescape "$output")"
    [[ "$norm" == *"|| { printf "* ]]
    [[ "$norm" == *"mise use -g node@lts; mise use -g npm:opencode-ai"* ]]
}

# UX guard: cold-path install can take ~1 min (download + extract). To
# avoid the user staring at a silent terminal, _app_cmd emits an
# "==> Installing $bin …" notice on stderr BEFORE `mise use -g`. The
# stderr destination (>&2) keeps the app's stdout clean for piping.
@test "app cold-path install prints an 'Installing …' notice on stderr" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --app opencode --dry-run
    [ "$status" -eq 0 ]
    norm="$(_unescape "$output")"
    [[ "$norm" == *"Installing %s (first run, this may take a minute)"* ]]
    [[ "$norm" == *"' opencode >&2"* ]]
}

# UX guard: after `mise use -g` writes its install spinner / progress /
# "tools:" line to the TTY, we `clear` the screen before exec'ing the
# app. Without it, the app's TUI would start with mise's output
# still in the scrollback above it. `2>/dev/null || true` keeps the
# chain alive if `clear` is somehow missing (rare, defensive).
@test "app cold-path install runs 'clear' before exec" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --app opencode --dry-run
    [ "$status" -eq 0 ]
    norm="$(_unescape "$output")"
    [[ "$norm" == *"; clear 2>/dev/null || true; }"* ]]
}

# Perf guard: after `mise use -g` bumps /opt/mise/data/config/config.toml,
# the bashrc cache becomes stale. If we don't regen it inside this same
# run, the NEXT `./ops.sh run --<app>` will trigger `mise hook-env`
# (~8 s cold) before reaching the app. Calling __ops_refresh_cache
# (defined in /etc/ops-bashrc) here amortizes that cost into the
# already-slow cold install.
@test "app cold-path install regenerates the bashrc cache via __ops_refresh_cache" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --app opencode --dry-run
    [ "$status" -eq 0 ]
    norm="$(_unescape "$output")"
    [[ "$norm" == *"; __ops_refresh_cache; clear 2>/dev/null"* ]]
}

@test "app cold-path: claude (npm) also notices + clears" {
    # Same UX guard on the npm:* branch of the case.
    run env OPS_RUNTIME=docker "$(ops_sh)" run --app claude --dry-run
    [ "$status" -eq 0 ]
    norm="$(_unescape "$output")"
    [[ "$norm" == *"Installing %s (first run, this may take a minute)"* ]]
    [[ "$norm" == *"' claude >&2"* ]]
    [[ "$norm" == *"; clear 2>/dev/null || true; }"* ]]
}

# Coverage parity: gemini and codex must get the same UX (notif + clear
# + cache refresh) — otherwise a regression on _app_cmd's npm:*
# branch could silently break one app without the other tests
# catching it.
@test "app cold-path: gemini (npm) notices + clears + refreshes cache" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --app gemini --dry-run
    [ "$status" -eq 0 ]
    norm="$(_unescape "$output")"
    [[ "$norm" == *"Installing %s (first run, this may take a minute)"* ]]
    [[ "$norm" == *"' gemini >&2"* ]]
    [[ "$norm" == *"; __ops_refresh_cache; clear 2>/dev/null || true; }"* ]]
}

@test "app cold-path: codex (npm) notices + clears + refreshes cache" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --app codex --dry-run
    [ "$status" -eq 0 ]
    norm="$(_unescape "$output")"
    [[ "$norm" == *"Installing %s (first run, this may take a minute)"* ]]
    [[ "$norm" == *"' codex >&2"* ]]
    [[ "$norm" == *"; __ops_refresh_cache; clear 2>/dev/null || true; }"* ]]
}

# Notice + clear must NOT appear in the warm path (they live inside the
# `||` arm that only runs when `command -v` fails). Negative test
# ensures we don't accidentally emit the install banner on every launch.
@test "app warm path does NOT print Installing notice" {
    # The Installing string only appears INSIDE the install branch — the
    # outer command line still contains it (rendered by --dry-run), but
    # we can verify the install branch is gated behind `command -v … ||
    # {`. Concretely: the literal `command -v $bin >/dev/null 2>&1 ||`
    # precedes the `printf 'Installing'` call.
    run env OPS_RUNTIME=docker "$(ops_sh)" run --app opencode --dry-run
    [ "$status" -eq 0 ]
    norm="$(_unescape "$output")"
    [[ "$norm" == *"command -v opencode >/dev/null 2>&1 || { printf"* ]]
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

@test "run --app claude wraps app_cmd with source /etc/ops-bashrc" {
    # App wrappers (claude/gemini/opencode/codex/update/nix-cleanup) run via
    # `bash -c`, which is non-interactive and therefore ignores --rcfile. We
    # source /etc/ops-bashrc explicitly at the top of app_cmd so the app
    # inherits PATH / PYTHONPATH / ... from mise env (mise-nix plugin picks
    # up the workdir's flake.nix devShell when [env] _.nix = true is set).
    run env OPS_RUNTIME=docker "$(ops_sh)" run --app claude --dry-run
    [ "$status" -eq 0 ]
    norm="$(_unquote "$output")"
    [[ "$norm" == *"source /etc/ops-bashrc"* ]]
    [[ "$norm" == *"claude"* ]]
}

@test "run --install -- CMD wraps with source /etc/ops-bashrc" {
    # --install without an app flag but WITH a user command after `--`
    # still goes through the bash -c wrapper, so the same source prefix
    # applies and the user's CMD inherits the flake env.
    run env OPS_RUNTIME=docker "$(ops_sh)" run --install --dry-run -- pytest -k smoke
    [ "$status" -eq 0 ]
    norm="$(_unquote "$output")"
    [[ "$norm" == *"source /etc/ops-bashrc"* ]]
    [[ "$norm" == *"mise install --yes "* ]]
    [[ "$norm" == *"pytest"* ]]
}

@test "run -- CMD without app_cmd bypasses the bash -c wrapper" {
    # Bare `run -- CMD` (no --install, no app flag) forwards "$@" directly
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
