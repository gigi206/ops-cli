#!/usr/bin/env bats
# scripts/ops-bashrc — host-side tests of the bashrc preamble that:
#   1. Pre-exports MISE_NIX_ALLOW_UNTRACKED from mise.local.toml on EVERY
#      source (warm + cold paths) so subsequent `mise <cmd>` invocations
#      inherit the var instead of re-tripping the nix plugin's
#      "flake.nix not tracked" diagnostic.
#   2. Regenerates $PWD/.mise-nix/shell-env.cache only when needed.
#
# Why these tests live in bats and not in test_image_integration.bats:
# the integration suite needs a built ops-dev image and a working `mise`
# binary, gated behind --runtime-build matrix jobs. We want a fast unit
# guard that exercises the pure-bash logic directly. We sandbox the
# bashrc by:
#   - copying it under $BATS_TEST_TMPDIR
#   - patching the unconditional `source /opt/nix-home/.../nix.sh` away
#     (the path doesn't exist on the host, would abort the source)
#   - stubbing `mise hook-env` via a PATH-prepended fake that always
#     succeeds with empty output.
# That isolates the two responsibilities listed above, which is precisely
# what the regression we are guarding against touched.

load helpers

# Build a sandboxed copy of /etc/ops-bashrc + a fake $PWD with a
# mise.local.toml fixture. Echoes the path of the patched bashrc.
# Args:
#   $1 = contents of mise.local.toml (empty string → don't create the file)
#   $2 = "fresh"|"stale"|"absent" — controls $PWD/.mise-nix/shell-env.cache
_setup_bashrc_sandbox() {
    local local_toml_content="$1"
    local cache_state="$2"
    local sandbox="$BATS_TEST_TMPDIR/sandbox"
    local stub_path="$BATS_TEST_TMPDIR/stubs"
    mkdir -p "$sandbox" "$stub_path"

    # Optional mise.local.toml fixture in the sandbox $PWD.
    if [ -n "$local_toml_content" ]; then
        printf '%s' "$local_toml_content" > "$sandbox/mise.local.toml"
    fi

    # `mise` stub: hook-env returns nothing (we don't test mise's behaviour
    # here, only the bashrc's own logic). Other subcommands are no-ops too.
    cat > "$stub_path/mise" <<'MOCK_MISE'
#!/usr/bin/env bash
case "$1 $2" in
    "hook-env -s") ;;       # silent successful no-op → empty cache file
    *)             ;;       # any other call: no-op success
esac
exit 0
MOCK_MISE
    chmod +x "$stub_path/mise"

    # Patched copy of ops-bashrc:
    #   - drop the `source /opt/nix-home/.../nix.sh` line (path absent on host)
    local patched="$sandbox/ops-bashrc"
    sed -e 's|^source /opt/nix-home/.nix-profile/etc/profile.d/nix.sh|: # stubbed in test|' \
        "$BATS_TEST_DIRNAME/../scripts/ops-bashrc" > "$patched"

    # Cache state preparation (after patching so our cache file isn't reset).
    local cache_dir="$sandbox/.mise-nix"
    case "$cache_state" in
        absent) ;;  # nothing to do
        fresh)
            mkdir -p "$cache_dir"
            : > "$cache_dir/shell-env.cache"
            # Make all configs older than the cache: bashrc's `-nt` test
            # then returns false → __ops_needs_refresh stays 0.
            touch -d "1 hour ago" "$sandbox/mise.local.toml" 2>/dev/null || true
            ;;
        stale)
            mkdir -p "$cache_dir"
            : > "$cache_dir/shell-env.cache"
            touch -d "1 hour ago" "$cache_dir/shell-env.cache"
            # mise.local.toml is now newer than the cache.
            ;;
    esac

    printf '%s\n%s\n' "$sandbox" "$stub_path"
}

# Source the sandboxed bashrc in a clean subshell with the given $PWD,
# then echo the resulting MISE_NIX_ALLOW_UNTRACKED value (empty if unset).
_source_and_print_var() {
    local sandbox="$1"
    local stub_path="$2"
    # `bash -c` runs non-interactively, mirroring the app_cmd path.
    # We export a minimal PATH that prefers our stub `mise` over the
    # system one, plus the standard utilities the bashrc needs.
    PATH="$stub_path:/usr/bin:/bin" \
        bash -c "
            cd '$sandbox' || exit 1
            source './ops-bashrc'
            printf 'MISE_NIX_ALLOW_UNTRACKED=%s\n' \"\${MISE_NIX_ALLOW_UNTRACKED:-<unset>}\"
        "
}

# A mise.local.toml that opts into MISE_NIX_ALLOW_UNTRACKED.
_local_toml_with_flag='[env]
MISE_NIX_ALLOW_UNTRACKED = "1"
_.nix = true
'

# A mise.local.toml without the flag.
_local_toml_no_flag='[env]
_.nix = true
'

# ---- Cache absent (true cold start) ---------------------------------------

@test "ops-bashrc: cache absent + flag in mise.local.toml → MISE_NIX_ALLOW_UNTRACKED=1" {
    paths="$(_setup_bashrc_sandbox "$_local_toml_with_flag" absent)"
    sandbox="${paths%$'\n'*}"; stub_path="${paths#*$'\n'}"
    run _source_and_print_var "$sandbox" "$stub_path"
    [ "$status" -eq 0 ]
    [[ "$output" == *"MISE_NIX_ALLOW_UNTRACKED=1"* ]]
}

# ---- Cache fresh (warm path: this was the regression) --------------------

@test "ops-bashrc: cache fresh + flag in mise.local.toml → MISE_NIX_ALLOW_UNTRACKED=1 (warm path)" {
    # Regression guard: before this fix, the grep+export was wrapped in
    # `if __ops_needs_refresh=1`, so on a warm path the var was never
    # exported — letting `mise use -g` and friends re-emit the
    # "flake.nix not tracked" diagnostic.
    paths="$(_setup_bashrc_sandbox "$_local_toml_with_flag" fresh)"
    sandbox="${paths%$'\n'*}"; stub_path="${paths#*$'\n'}"
    run _source_and_print_var "$sandbox" "$stub_path"
    [ "$status" -eq 0 ]
    [[ "$output" == *"MISE_NIX_ALLOW_UNTRACKED=1"* ]]
}

# ---- Cache stale (config newer than cache) -------------------------------

@test "ops-bashrc: cache stale + flag in mise.local.toml → MISE_NIX_ALLOW_UNTRACKED=1" {
    paths="$(_setup_bashrc_sandbox "$_local_toml_with_flag" stale)"
    sandbox="${paths%$'\n'*}"; stub_path="${paths#*$'\n'}"
    run _source_and_print_var "$sandbox" "$stub_path"
    [ "$status" -eq 0 ]
    [[ "$output" == *"MISE_NIX_ALLOW_UNTRACKED=1"* ]]
}

# ---- Negative cases ------------------------------------------------------

@test "ops-bashrc: no mise.local.toml → MISE_NIX_ALLOW_UNTRACKED stays unset" {
    paths="$(_setup_bashrc_sandbox "" absent)"
    sandbox="${paths%$'\n'*}"; stub_path="${paths#*$'\n'}"
    run _source_and_print_var "$sandbox" "$stub_path"
    [ "$status" -eq 0 ]
    [[ "$output" == *"MISE_NIX_ALLOW_UNTRACKED=<unset>"* ]]
}

@test "ops-bashrc: mise.local.toml without flag → MISE_NIX_ALLOW_UNTRACKED stays unset" {
    paths="$(_setup_bashrc_sandbox "$_local_toml_no_flag" absent)"
    sandbox="${paths%$'\n'*}"; stub_path="${paths#*$'\n'}"
    run _source_and_print_var "$sandbox" "$stub_path"
    [ "$status" -eq 0 ]
    [[ "$output" == *"MISE_NIX_ALLOW_UNTRACKED=<unset>"* ]]
}

# ---- Cache-regen guard --------------------------------------------------

@test "ops-bashrc: cache absent → mise hook-env is invoked (cache regen)" {
    paths="$(_setup_bashrc_sandbox "$_local_toml_with_flag" absent)"
    sandbox="${paths%$'\n'*}"; stub_path="${paths#*$'\n'}"
    # Replace the stub `mise` with one that records its calls so we can
    # assert hook-env was triggered.
    cat > "$stub_path/mise" <<MOCK_MISE_CALLS
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$BATS_TEST_TMPDIR/mise.calls"
MOCK_MISE_CALLS
    chmod +x "$stub_path/mise"
    : > "$BATS_TEST_TMPDIR/mise.calls"

    PATH="$stub_path:/usr/bin:/bin" bash -c "cd '$sandbox' && source ./ops-bashrc"
    grep -q 'hook-env' "$BATS_TEST_TMPDIR/mise.calls"
}

@test "ops-bashrc: cache fresh → mise hook-env is NOT invoked (warm path is cheap)" {
    # Performance guard: warm path must skip the ~10 s mise hook-env call.
    paths="$(_setup_bashrc_sandbox "$_local_toml_with_flag" fresh)"
    sandbox="${paths%$'\n'*}"; stub_path="${paths#*$'\n'}"
    cat > "$stub_path/mise" <<MOCK_MISE_CALLS
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$BATS_TEST_TMPDIR/mise.calls"
MOCK_MISE_CALLS
    chmod +x "$stub_path/mise"
    : > "$BATS_TEST_TMPDIR/mise.calls"

    PATH="$stub_path:/usr/bin:/bin" bash -c "cd '$sandbox' && source ./ops-bashrc"
    ! grep -q 'hook-env' "$BATS_TEST_TMPDIR/mise.calls"
}

@test "ops-bashrc: cache stale → mise hook-env is invoked (regen)" {
    paths="$(_setup_bashrc_sandbox "$_local_toml_with_flag" stale)"
    sandbox="${paths%$'\n'*}"; stub_path="${paths#*$'\n'}"
    cat > "$stub_path/mise" <<MOCK_MISE_CALLS
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$BATS_TEST_TMPDIR/mise.calls"
MOCK_MISE_CALLS
    chmod +x "$stub_path/mise"
    : > "$BATS_TEST_TMPDIR/mise.calls"

    PATH="$stub_path:/usr/bin:/bin" bash -c "cd '$sandbox' && source ./ops-bashrc"
    grep -q 'hook-env' "$BATS_TEST_TMPDIR/mise.calls"
}

# ---- Pattern-matching tolerance -----------------------------------------

@test "ops-bashrc: mise.local.toml with no spaces around '=' still matches the grep" {
    # `MISE_NIX_ALLOW_UNTRACKED="1"` (no spaces) must trigger the export
    # too — the grep pattern uses [[:space:]]* on both sides.
    local toml='[env]
MISE_NIX_ALLOW_UNTRACKED="1"
'
    paths="$(_setup_bashrc_sandbox "$toml" absent)"
    sandbox="${paths%$'\n'*}"; stub_path="${paths#*$'\n'}"
    run _source_and_print_var "$sandbox" "$stub_path"
    [ "$status" -eq 0 ]
    [[ "$output" == *"MISE_NIX_ALLOW_UNTRACKED=1"* ]]
}

@test "ops-bashrc: commented-out flag in mise.local.toml does NOT export" {
    # The grep is anchored on `^[[:space:]]*MISE_NIX_…`, so a leading `#`
    # comment must be rejected. Otherwise users who deliberately comment
    # the line out (to opt back into the strict git-tracked check) would
    # see no effect.
    local toml='[env]
# MISE_NIX_ALLOW_UNTRACKED = "1"
'
    paths="$(_setup_bashrc_sandbox "$toml" absent)"
    sandbox="${paths%$'\n'*}"; stub_path="${paths#*$'\n'}"
    run _source_and_print_var "$sandbox" "$stub_path"
    [ "$status" -eq 0 ]
    [[ "$output" == *"MISE_NIX_ALLOW_UNTRACKED=<unset>"* ]]
}

# ---- __ops_refresh_cache helper ------------------------------------

# Called by ops.sh `_app_cmd` after `mise use -g` to refresh the
# shell-env cache so the next container run skips the ~8 s mise hook-env
# pass. Must be defined and must regenerate $PWD/.mise-nix/shell-env.cache
# from the output of `mise hook-env -s bash`.
@test "ops-bashrc: __ops_refresh_cache helper is defined after sourcing" {
    paths="$(_setup_bashrc_sandbox "$_local_toml_with_flag" absent)"
    sandbox="${paths%$'\n'*}"; stub_path="${paths#*$'\n'}"
    run env PATH="$stub_path:/usr/bin:/bin" bash -c "
        cd '$sandbox' || exit 1
        source './ops-bashrc'
        if declare -F __ops_refresh_cache >/dev/null; then echo DEFINED; else echo MISSING; fi
    "
    [ "$status" -eq 0 ]
    [[ "$output" == *"DEFINED"* ]]
}

@test "ops-bashrc: __ops_refresh_cache regenerates the cache file" {
    paths="$(_setup_bashrc_sandbox "$_local_toml_with_flag" fresh)"
    sandbox="${paths%$'\n'*}"; stub_path="${paths#*$'\n'}"
    # Stub mise hook-env to emit a sentinel string we can grep for.
    cat > "$stub_path/mise" <<'MISE_HOOK_STUB'
#!/usr/bin/env bash
case "$1 $2" in
    "hook-env -s") printf 'export __FROM_REFRESH=1\n' ;;
    *) ;;
esac
exit 0
MISE_HOOK_STUB
    chmod +x "$stub_path/mise"

    run env PATH="$stub_path:/usr/bin:/bin" bash -c "
        cd '$sandbox' || exit 1
        source './ops-bashrc'
        __ops_refresh_cache
        cat .mise-nix/shell-env.cache
    "
    [ "$status" -eq 0 ]
    [[ "$output" == *"export __FROM_REFRESH=1"* ]]
}

