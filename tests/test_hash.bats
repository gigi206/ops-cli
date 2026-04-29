#!/usr/bin/env bats
# Per-image hash cache and dockerfile_changed detection

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
}

@test "build writes hash file named after the image" {
    # Force build via --build, mock runtime swallows it
    run env OPS_RUNTIME=docker "$(ops_sh)" build
    [ "$status" -eq 0 ]
    local expected="$XDG_CACHE_HOME/ops/localhost_test-img.sha256sum"
    [ -f "$expected" ]
}

@test "different image → different hash file" {
    run env OPS_RUNTIME=docker OPS_IMAGE=my/other "$(ops_sh)" build
    [ "$status" -eq 0 ]
    [ -f "$XDG_CACHE_HOME/ops/my_other.sha256sum" ]
    # Original should not exist
    [ ! -f "$XDG_CACHE_HOME/ops/localhost_test-img.sha256sum" ]
}

@test "no warning when hash file is fresh" {
    run env OPS_RUNTIME=docker "$(ops_sh)" build
    [ "$status" -eq 0 ]
    # Now `run` without --build should not warn about Dockerfile changed
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" != *"Dockerfile changed"* ]]
}

@test "warning when Dockerfile changes after build" {
    run env OPS_RUNTIME=docker "$(ops_sh)" build
    [ "$status" -eq 0 ]
    # Mutate Dockerfile
    echo "# mutation" >> "$OPS_DOCKERFILE"
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"Dockerfile changed"* ]]
}

@test "no warning when hash file absent (first run on existing image)" {
    # No hash file, mock says image exists (default MOCK_IMAGE_EXISTS=1)
    rm -rf "$XDG_CACHE_HOME"
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" != *"Dockerfile changed"* ]]
}

# OPS_BUILD_ARGS cache invalidation. current_hash() folds OPS_BUILD_ARGS[<key>]
# (with `default` as the unkeyed-build fallback) into the digest, so any mutation
# must trigger the "Dockerfile changed" warning on the next non-build invocation.
# Mirrors the `OPS_BUILD_ARGS[default]: applies to unkeyed build` propagation
# test in test_build_flags.bats — without this guard, the cache could go stale
# silently when the user adds or edits OPS_BUILD_ARGS[default].

@test "warning when OPS_BUILD_ARGS[default] is added after build" {
    # Initial build with no config → hash captures empty build-args.
    local cfg="$BATS_TEST_TMPDIR/.config/ops/ops.conf"
    mkdir -p "$(dirname "$cfg")"
    run env OPS_RUNTIME=docker XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/.config" \
        "$(ops_sh)" build
    [ "$status" -eq 0 ]

    # User adds OPS_BUILD_ARGS[default] post-build — current_hash must now
    # differ from the stored hash, triggering the rebuild-needed warning.
    cat > "$cfg" <<'EOF'
declare -A OPS_BUILD_ARGS=( [default]="EXTRA_MISE_TOOLS=nix:google-chrome" )
EOF
    run env OPS_RUNTIME=docker XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/.config" \
        "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"Dockerfile changed"* ]]
}

@test "warning when OPS_BUILD_ARGS[default] is mutated after build" {
    # Build with config A.
    local cfg="$BATS_TEST_TMPDIR/.config/ops/ops.conf"
    mkdir -p "$(dirname "$cfg")"
    cat > "$cfg" <<'EOF'
declare -A OPS_BUILD_ARGS=( [default]="EXTRA_MISE_TOOLS=nix:terraform" )
EOF
    run env OPS_RUNTIME=docker XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/.config" \
        "$(ops_sh)" build
    [ "$status" -eq 0 ]

    # Mutate to config B — same shape, different value. current_hash must
    # detect the change (this is the regression guard for the current_hash()
    # mirror of the build_image() fix; without the mirror, the hash would
    # ignore OPS_BUILD_ARGS[default] and the cache would go stale).
    cat > "$cfg" <<'EOF'
declare -A OPS_BUILD_ARGS=( [default]="EXTRA_MISE_TOOLS=nix:ngrok" )
EOF
    run env OPS_RUNTIME=docker XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/.config" \
        "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"Dockerfile changed"* ]]
}
