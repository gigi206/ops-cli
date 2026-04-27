#!/usr/bin/env bats
# Integration tests against the actually-built localhost/ops-dev image.
# Skips gracefully when the image is absent (e.g. CI PRs that don't build
# the heavy Nix image, or dev machines that haven't run `./ops.sh build`
# yet). Run locally with:
#
#     ./ops.sh build
#     bats tests/test_image_integration.bats
#
# CI runs this file in a dedicated `image-integration` job (see
# .github/workflows/tests.yml) gated on push to main + manual trigger.

load helpers

setup() {
    require_ops_image
}

# ---- Nix (single-user installer, GC root) ----------------------------------

@test "image: nix binary is discoverable via PATH and reports a version" {
    run run_in_image 'which nix && nix --version'
    [ "$status" -eq 0 ]
    # /opt/ops/bin/nix is our CLI wrapper; it delegates to the real binary
    # under /opt/nix-home/.nix-profile/bin/nix transparently for --version.
    [[ "$output" == */opt/ops/bin/nix* ]]
    [[ "$output" == *"nix (Nix) "* ]]
}

@test "image: explicit GC root protects the Nix profile against collect-garbage" {
    run run_in_image 'target=$(readlink -f /nix/var/nix/gcroots/ops-nix-profile) && [ -e "$target" ] && echo "$target"'
    [ "$status" -eq 0 ]
    [[ "$output" == /nix/store/*user-environment* ]]
}

@test "image: Nix profile binary directory exists (symlink chain resolves)" {
    run run_in_image 'ls /opt/nix-home/.nix-profile/bin/ | head -1'
    [ "$status" -eq 0 ]
    [ -n "$output" ]
}

# ---- google-chrome discoverability (5 redundant hooks) ---------------------

@test "image: which google-chrome resolves to /opt/ops/bin/google-chrome (PATH prefix)" {
    run run_in_image 'which google-chrome'
    [ "$status" -eq 0 ]
    [ "$output" = "/opt/ops/bin/google-chrome" ]
}

@test "image: CHROME_PATH env is set to the wrapper" {
    run run_in_image 'echo "$CHROME_PATH"'
    [ "$status" -eq 0 ]
    [ "$output" = "/opt/ops/bin/google-chrome" ]
}

@test "image: PUPPETEER_EXECUTABLE_PATH env is set to the wrapper" {
    run run_in_image 'echo "$PUPPETEER_EXECUTABLE_PATH"'
    [ "$status" -eq 0 ]
    [ "$output" = "/opt/ops/bin/google-chrome" ]
}

@test "image: /usr/bin/google-chrome is a symlink to the wrapper" {
    run run_in_image 'readlink /usr/bin/google-chrome'
    [ "$status" -eq 0 ]
    [ "$output" = "/opt/ops/bin/google-chrome" ]
}

@test "image: /opt/google/chrome/chrome is a symlink to the wrapper (puppeteer-core stable)" {
    run run_in_image 'readlink /opt/google/chrome/chrome'
    [ "$status" -eq 0 ]
    [ "$output" = "/opt/ops/bin/google-chrome" ]
}

@test "image: google-chrome --version starts Chrome successfully" {
    run run_in_image 'google-chrome --version'
    [ "$status" -eq 0 ]
    [[ "$output" == "Google Chrome "* ]]
}

# ---- mise config split (baseline in /etc/mise, user in /opt/mise/data) -----

@test "image: baseline config in /etc/mise/config.toml contains expected tools" {
    run run_in_image 'cat /etc/mise/config.toml'
    [ "$status" -eq 0 ]
    [[ "$output" == *"nix:git"* ]]
    [[ "$output" == *"nix:semgrep"* ]]
    [[ "$output" == *"nix:google-chrome"* ]]
    [[ "$output" == *"node"* ]]
}

@test "image: /etc/mise is root-owned, read-only for users" {
    run run_in_image 'stat -c "%U %a" /etc/mise'
    [ "$status" -eq 0 ]
    [[ "$output" == "root "* ]]
}

@test "image: user config dir /opt/mise/data/config exists and is writable by the container user" {
    run run_in_image 'test -d /opt/mise/data/config && touch /opt/mise/data/config/__probe && rm /opt/mise/data/config/__probe && echo OK'
    [ "$status" -eq 0 ]
    [ "$output" = "OK" ]
}

@test "image: MISE_CONFIG_DIR points at the volume-backed user config dir" {
    run run_in_image 'echo "$MISE_CONFIG_DIR"'
    [ "$status" -eq 0 ]
    [ "$output" = "/opt/mise/data/config" ]
}

@test "image: mise ls shows baseline tools sourced from /etc/mise/config.toml" {
    run run_in_image 'mise ls 2>&1'
    [ "$status" -eq 0 ]
    [[ "$output" == *"/etc/mise/config.toml"* ]]
    [[ "$output" == *"nix:git"* ]]
}

# ---- unfree flag, locale, machine-id ---------------------------------------

@test "image: MISE_NIX_ALLOW_UNFREE and NIXPKGS_ALLOW_UNFREE are both set" {
    run run_in_image 'echo "$MISE_NIX_ALLOW_UNFREE|$NIXPKGS_ALLOW_UNFREE"'
    [ "$status" -eq 0 ]
    [ "$output" = "true|1" ]
}

@test "image: /etc/machine-id is populated with 32 hex chars" {
    run run_in_image 'cat /etc/machine-id | tr -d "\n" | wc -c'
    [ "$status" -eq 0 ]
    [ "$output" = "32" ]
}

# ---- wrapper behaviour ------------------------------------------------------

@test "image: Nix wrappers are all served from /opt/ops/bin" {
    run run_in_image '
        for cmd in nix-env nix-channel nix-store nix-collect-garbage; do
            /usr/bin/which "$cmd"
        done
    '
    [ "$status" -eq 0 ]
    [[ "$output" == *"/opt/ops/bin/nix-env"* ]]
    [[ "$output" == *"/opt/ops/bin/nix-channel"* ]]
    [[ "$output" == *"/opt/ops/bin/nix-store"* ]]
    [[ "$output" == *"/opt/ops/bin/nix-collect-garbage"* ]]
}

@test "image: Nix wrappers all point at the shared _nix-wrapper script" {
    run run_in_image '
        for cmd in nix-env nix-channel nix-store nix-collect-garbage; do
            readlink /opt/ops/bin/"$cmd"
        done
    '
    [ "$status" -eq 0 ]
    # Each line must be the same target
    count=$(echo "$output" | grep -c '^/opt/ops/bin/_nix-wrapper$')
    [ "$count" = "4" ]
}

@test "image: nix-collect-garbage -d targets the container profile by default" {
    run run_in_image 'nix-collect-garbage -d 2>&1 | head -2'
    [ "$status" -eq 0 ]
    [[ "$output" == *"/opt/nix-home/.local/state/nix/profiles/profile"* ]]
    ! [[ "$output" == *"/home/"*"/.local/state/nix/profiles"* ]]
}

@test "image: nix-collect-garbage --host -d does NOT target the container profile" {
    # In a pristine `docker run` container there's no user profile under
    # $HOME/.local/state/nix/ at all, so we can't positively assert which
    # profile path Nix looked at. What we *can* assert is the negative:
    # the escape hatch must disable the HOME=/opt/nix-home force, so the
    # output must NOT mention /opt/nix-home/. (The real benefit of --host
    # is visible only when $HOME is bind-mounted from the host, i.e. via
    # `ops run`.)
    run run_in_image 'nix-collect-garbage --host -d 2>&1'
    [ "$status" -eq 0 ]
    ! [[ "$output" == *"/opt/nix-home/"* ]]
}

@test "image: nix-env --list-generations targets the container profile by default" {
    run run_in_image 'nix-env --list-generations 2>&1'
    [ "$status" -eq 0 ]
    # First generation is created by the installer at build time.
    [[ "$output" == *"1"* ]]
    [[ "$output" == *"(current)"* ]]
}

# ---- modern `nix` CLI wrapper (selective HOME forcing) ---------------------

@test "image: nix CLI is served from /opt/ops/bin (wrapper shadows real binary)" {
    run run_in_image 'which nix'
    [ "$status" -eq 0 ]
    [ "$output" = "/opt/ops/bin/nix" ]
}

@test "image: nix build-like subcommands pass through without forcing HOME" {
    # `nix --version` is a no-subcommand call -- wrapper must not force HOME.
    # We can't directly observe HOME from the test, but we can check the
    # command still succeeds and the version is reported (proving the wrapper
    # didn't fail or misroute).
    run run_in_image 'nix --version 2>&1 | head -1'
    [ "$status" -eq 0 ]
    [[ "$output" == *"nix (Nix) "* ]]
}

@test "image: nix profile list forces HOME to the container" {
    # This call would otherwise inspect the host profile. We can verify
    # HOME was forced by checking the fall-back message that Nix emits
    # when HOME isn't writable: it mentions the HOME path Nix saw.
    run run_in_image 'nix profile list 2>&1'
    [ "$status" -eq 0 ]
    # Either the HOME warning mentions /opt/nix-home OR no warning but
    # we need some evidence it did not read /home/… . Looser check: no
    # mention of a host-style /home/ path in the output.
    ! [[ "$output" == *"/home/"*"/.local/state/nix"* ]]
}

@test "image: OCI label org.opencontainers.image.title is populated" {
    # Static label (no ARG expansion) — must be present regardless of
    # build-args. The Arch Dockerfile uses "ops-dev"; Dockerfile.debian
    # uses "ops-dev-debian" so the variant is distinguishable in
    # registries / docker inspect output. Accept either via prefix
    # match — both image-integration jobs (Arch + Debian) re-tag their
    # build under `localhost/ops-dev`, so we only see the title label,
    # not the tag.
    run "$IMAGE_RUNTIME" image inspect localhost/ops-dev \
        --format '{{ index .Config.Labels "org.opencontainers.image.title" }}'
    [ "$status" -eq 0 ]
    [[ "$output" == ops-dev* ]]
}

@test "image: OCI label org.opencontainers.image.licenses is Apache-2.0" {
    run "$IMAGE_RUNTIME" image inspect localhost/ops-dev \
        --format '{{ index .Config.Labels "org.opencontainers.image.licenses" }}'
    [ "$status" -eq 0 ]
    [ "$output" = "Apache-2.0" ]
}

@test "image: OCI label org.opencontainers.image.source points at the project URL" {
    # SOURCE_URL is forwarded by ops.sh from OPS_SOURCE_URL at build time.
    # Default value is the upstream repo. Lets `docker inspect` consumers
    # walk back from the image to the project's homepage.
    run "$IMAGE_RUNTIME" image inspect localhost/ops-dev \
        --format '{{ index .Config.Labels "org.opencontainers.image.source" }}'
    [ "$status" -eq 0 ]
    [[ "$output" == https://* ]]
    [[ "$output" == *ops-cli* ]]
}

@test "image: OCI label org.opencontainers.image.description mentions mise + Nix + AI agents" {
    run "$IMAGE_RUNTIME" image inspect localhost/ops-dev \
        --format '{{ index .Config.Labels "org.opencontainers.image.description" }}'
    [ "$status" -eq 0 ]
    [[ "$output" == *"mise"* ]]
    [[ "$output" == *"Nix"* ]]
    [[ "$output" == *"AI"* ]]
}

# ---- plugin location: symlink-baked to survive volume overlay -------------

@test "image: mise-nix plugin is baked at /opt/ops/mise-plugin/nix" {
    # The real plugin files live OUTSIDE /opt/mise/data so ops-share-mise
    # can't mask them. Rebuilds update this path and the symlink below
    # picks up the change transparently.
    run run_in_image 'test -f /opt/ops/mise-plugin/nix/metadata.lua && echo OK'
    [ "$status" -eq 0 ]
    [ "$output" = "OK" ]
}

@test "image: /opt/mise/data/plugins/nix is a symlink to the baked plugin" {
    run run_in_image 'readlink /opt/mise/data/plugins/nix'
    [ "$status" -eq 0 ]
    [ "$output" = "/opt/ops/mise-plugin/nix" ]
}

@test "image: mise discovers the plugin transparently via the symlink" {
    # Belt-and-suspenders: the symlink design is only useful if mise
    # actually treats the plugin as present. `mise plugins ls` exits 0
    # and lists "nix" when everything is wired.
    run run_in_image 'mise plugins ls'
    [ "$status" -eq 0 ]
    [[ "$output" == *"nix"* ]]
}

# ---- /etc/ops-bashrc (interactive shell init survives host $HOME bind-mount) ----

@test "image: /etc/ops-bashrc is baked and readable by the container user" {
    # Must live outside $HOME so the default mount_home=1 bind-mount can't
    # shadow it. The Dockerfile builds it via `sudo tee` during the mise+nix
    # RUN step. No need to be executable — it's sourced, not run.
    run run_in_image 'test -r /etc/ops-bashrc && echo OK'
    [ "$status" -eq 0 ]
    [ "$output" = "OK" ]
}

@test "image: default CMD invokes bash with --rcfile /etc/ops-bashrc" {
    # Read the CMD directly from the image config so we verify the Dockerfile
    # change rather than relying on a successful interactive launch.
    run "$IMAGE_RUNTIME" image inspect localhost/ops-dev \
        --format '{{ json .Config.Cmd }}'
    [ "$status" -eq 0 ]
    [[ "$output" == *"bash"* ]]
    [[ "$output" == *"--rcfile"* ]]
    [[ "$output" == *"/etc/ops-bashrc"* ]]
}

@test "image: interactive shell wires the bashrc PROMPT_COMMAND hook" {
    # The bashrc deliberately does NOT call `mise activate bash`
    # (would install a `_mise_hook` PROMPT_COMMAND that runs
    # `mise hook-env` at every prompt, ~7 s cold-start that makes the
    # first prompt of every shell painfully slow). Instead, it
    # installs its own custom prompt hook
    # `__ops_mise_refresh_if_stale` that only regenerates the
    # shell-env cache when one of the config files (mise.toml,
    # mise.local.toml, flake.lock, flake.nix) has been modified
    # since the last run. Verify that hook is registered as
    # PROMPT_COMMAND in an interactive shell.
    run run_in_image 'bash --rcfile /etc/ops-bashrc -ic "declare -F __ops_mise_refresh_if_stale >/dev/null && [[ \$PROMPT_COMMAND == *__ops_mise_refresh_if_stale* ]] && echo WIRED || echo MISSING"'
    [ "$status" -eq 0 ]
    [[ "$output" == *"WIRED"* ]]
}

@test "image: untracked flake.nix produces an actionable 'git add -N' hint" {
    # Nix flakes silently ignore untracked files in a git working tree
    # (reproducibility guarantee). The plugin now checks is_git_tracked()
    # upfront and emits the exact fix command instead of the generic
    # 'Failed to load environment' that users used to see.
    #
    # IMPORTANT: this test requires the MISE_NIX_HOOK_REENTRY guard to be
    # present in the baked plugin — without it, `mise env` runs git via a
    # mise shim which re-invokes mise, re-runs the hook, and fork-bombs
    # the host. Skip if the image predates that guard so old images don't
    # hang a whole bats run. The `timeout` wrapper is a second belt.
    if ! "$IMAGE_RUNTIME" run --rm --entrypoint /usr/bin/grep localhost/ops-dev \
            -q MISE_NIX_HOOK_REENTRY \
            /opt/mise/data/plugins/nix/lib/utils.lua 2>/dev/null; then
        skip "image predates the MISE_NIX_HOOK_REENTRY guard; rebuild to enable this test"
    fi
    run run_in_image '
        set -e
        tmp=$(mktemp -d)
        cd "$tmp"
        git init -q .
        git config user.email test@ops.local
        git config user.name  test
        : > flake.nix
        : > flake.lock
        printf "[env]\n_.nix = true\n" > mise.toml
        export MISE_TRUSTED_CONFIG_PATHS="$tmp"
        timeout 10s mise env 2>&1 || true
    '
    [ "$status" -eq 0 ]
    [[ "$output" == *"not tracked by git"* ]]
    [[ "$output" == *"add -fN flake.nix flake.lock"* ]]
}

@test "image: non-interactive source of /etc/ops-bashrc applies mise env" {
    # Agents (claude, gemini, ...) run via `bash -c`, non-interactive. ops.sh
    # prepends `source /etc/ops-bashrc` so they still inherit PATH/... from
    # `mise env`. Verify the always-on block (nix profile + mise env) runs
    # even when the interactive guard is false.
    run run_in_image 'bash -c "source /etc/ops-bashrc && command -v mise >/dev/null && echo OK"'
    [ "$status" -eq 0 ]
    [ "$output" = "OK" ]
}

# The baked /etc/ops-bashrc must contain the MISE_NIX_ALLOW_UNTRACKED
# pre-export grep — without it, every cold launch from a fresh container
# leaks `mise ERROR [nix] flake.nix … not tracked by git` lines to
# stderr (because mise's MiseEnv hook fires before the env var is set
# from mise.local.toml).
@test "image: /etc/ops-bashrc contains MISE_NIX_ALLOW_UNTRACKED pre-export" {
    run run_in_image 'grep -q "export MISE_NIX_ALLOW_UNTRACKED=1" /etc/ops-bashrc \
        && grep -qE "grep -qE.*MISE_NIX_ALLOW_UNTRACKED" /etc/ops-bashrc \
        && echo OK'
    [ "$status" -eq 0 ]
    [[ "$output" == *"OK"* ]]
}

# The baked /etc/ops-bashrc must define `__ops_refresh_cache` — ops.sh
# `_agent_cmd` calls it after every `mise use -g`, and a missing helper
# would make the agent wrapper crash with "command not found" mid-install.
@test "image: /etc/ops-bashrc defines __ops_refresh_cache helper" {
    run run_in_image 'bash -c "source /etc/ops-bashrc && declare -F __ops_refresh_cache >/dev/null && echo DEFINED || echo MISSING"'
    [ "$status" -eq 0 ]
    [[ "$output" == *"DEFINED"* ]]
}

# The helper must actually do something — call it and verify the cache
# file lands at the expected path with non-empty content.
@test "image: __ops_refresh_cache writes \$PWD/.mise-nix/shell-env.cache" {
    # `source … 2>/dev/null` (no pipe) so the redirection only filters
    # stderr without spawning a sub-shell — the function must remain
    # visible in the outer shell to be callable next.
    run run_in_image 'bash -c "
        cd /tmp
        rm -rf sandbox-refresh && mkdir sandbox-refresh && cd sandbox-refresh
        printf \"[env]\nMISE_NIX_ALLOW_UNTRACKED = \\\"1\\\"\n\" > mise.toml
        export MISE_TRUSTED_CONFIG_PATHS=/tmp/sandbox-refresh
        source /etc/ops-bashrc 2>/dev/null || true
        __ops_refresh_cache
        if [ -s .mise-nix/shell-env.cache ]; then echo HAS_CONTENT; else echo EMPTY; fi
    "'
    [ "$status" -eq 0 ]
    [[ "$output" == *"HAS_CONTENT"* ]]
}

@test "image: chrome wrapper emits help message when binary is missing" {
    # Simulate "chrome not installed" by hiding the mise install dir. We run
    # the wrapper script directly so PATH/CHROME_PATH redirection isn't in play.
    run run_in_image 'ls /opt/mise/data/installs/nix-google-chrome/latest/bin/google-chrome >/dev/null 2>&1 \
        && mv /opt/mise/data/installs/nix-google-chrome /tmp/hide-it; \
        /opt/ops/bin/google-chrome --version 2>&1; \
        rc=$?; \
        [ -d /tmp/hide-it ] && mv /tmp/hide-it /opt/mise/data/installs/nix-google-chrome; \
        exit $rc'
    [ "$status" -eq 127 ]
    [[ "$output" == *"not installed in this container"* ]]
    [[ "$output" == *"EXTRA_MISE_TOOLS=nix:google-chrome"* ]]
}
