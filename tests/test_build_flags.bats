#!/usr/bin/env bats
# Runtime-specific build flags (--allow network.host for nerdctl, etc.)

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
}

@test "docker build includes --network host but not --allow" {
    mock_runtime docker
    run env OPS_RUNTIME=docker "$(ops_sh)" build
    [ "$status" -eq 0 ]
    grep -qE 'build .*--network host' "$MOCK_LOG"
    ! grep -qE 'build .*--allow' "$MOCK_LOG"
}

@test "podman build includes --network host but not --allow" {
    mock_runtime podman
    run env OPS_RUNTIME=podman "$(ops_sh)" build
    [ "$status" -eq 0 ]
    grep -qE 'build .*--network host' "$MOCK_LOG"
    ! grep -qE 'build .*--allow' "$MOCK_LOG"
}

@test "build passes USER_UID/GID/NAME/LANG build-args" {
    mock_runtime docker
    run env OPS_RUNTIME=docker OPS_USER_UID=1234 OPS_USER_GID=5678 \
        OPS_USER_NAME=customuser OPS_USER_LANG=it_IT.UTF-8 \
        "$(ops_sh)" build
    [ "$status" -eq 0 ]
    grep -qE 'build .*USER_UID=1234' "$MOCK_LOG"
    grep -qE 'build .*USER_GID=5678' "$MOCK_LOG"
    grep -qE 'build .*USER_NAME=customuser' "$MOCK_LOG"
    grep -qE 'build .*USER_LANG=it_IT.UTF-8' "$MOCK_LOG"
}

@test "build propagates GITHUB_TOKEN as a BuildKit secret (not build-arg)" {
    mock_runtime docker
    run env OPS_RUNTIME=docker GITHUB_TOKEN=ghp_mytoken "$(ops_sh)" build
    [ "$status" -eq 0 ]
    # The token must be passed via --secret so it never lands in image layers.
    grep -qE 'build .*--secret .*id=github_token,env=GITHUB_TOKEN' "$MOCK_LOG"
    # Defensive: assert the raw token value is NOT anywhere in the build cmd.
    ! grep -qF 'ghp_mytoken' "$MOCK_LOG"
}

@test "build omits --secret when GITHUB_TOKEN is unset" {
    mock_runtime docker
    unset GITHUB_TOKEN
    run env OPS_RUNTIME=docker "$(ops_sh)" build
    [ "$status" -eq 0 ]
    ! grep -qE 'build .*--secret' "$MOCK_LOG"
}

@test "build passes SOURCE_URL build-arg (default applied)" {
    mock_runtime docker
    run env OPS_RUNTIME=docker "$(ops_sh)" build
    [ "$status" -eq 0 ]
    # SOURCE_URL defaults to an upstream repo URL so the OCI labels
    # (source / url / documentation) are populated out of the box. We
    # assert the shape (https:// + non-empty value) rather than the exact
    # URL so the test survives forks, renames, and local OPS_SOURCE_URL
    # overrides.
    grep -qE 'build .*--build-arg SOURCE_URL=https://[^ ]+' "$MOCK_LOG"
}

@test "build passes empty SOURCE_URL when OPS_SOURCE_URL is explicitly blanked" {
    # Fork / vendor build that doesn't want to inherit the upstream URL:
    # OPS_SOURCE_URL="" is honored thanks to \${VAR-default} (bare `-`),
    # which only applies the default when the var is unset, not when empty.
    mock_runtime docker
    run env OPS_RUNTIME=docker OPS_SOURCE_URL="" "$(ops_sh)" build
    [ "$status" -eq 0 ]
    # The forwarded value must NOT start with https:// (default was bypassed).
    ! grep -qE 'build .*--build-arg SOURCE_URL=https://' "$MOCK_LOG"
    grep -qE 'build .*--build-arg SOURCE_URL=' "$MOCK_LOG"
}

@test "build forwards OPS_SOURCE_URL from the environment" {
    # Vendor / fork build pointing the OCI labels at a different repo URL.
    mock_runtime docker
    run env OPS_RUNTIME=docker \
        OPS_SOURCE_URL=https://example.com/ops-cli \
        "$(ops_sh)" build
    [ "$status" -eq 0 ]
    grep -qE 'build .*--build-arg SOURCE_URL=https://example.com/ops-cli' "$MOCK_LOG"
}

@test "build does NOT forward VERSION/REVISION build-args" {
    # Both args were dropped: VERSION duplicated OPS_VERSION (already in
    # `ops --version`) and REVISION was empty in practice unless CI
    # stamped it. Regression guard so a future revival keeps an explicit
    # design discussion.
    mock_runtime docker
    run env OPS_RUNTIME=docker "$(ops_sh)" build
    [ "$status" -eq 0 ]
    ! grep -qE 'build .*--build-arg VERSION=' "$MOCK_LOG"
    ! grep -qE 'build .*--build-arg REVISION=' "$MOCK_LOG"
}

@test "build --no-cache is forwarded" {
    mock_runtime docker
    run env OPS_RUNTIME=docker "$(ops_sh)" build --no-cache
    [ "$status" -eq 0 ]
    grep -qE 'build .*--no-cache' "$MOCK_LOG"
}

@test "build uses OPS_DOCKERFILE via --file" {
    mock_runtime docker
    local custom="$BATS_TEST_TMPDIR/custom.Dockerfile"
    echo "FROM scratch" > "$custom"
    run env OPS_RUNTIME=docker OPS_DOCKERFILE="$custom" "$(ops_sh)" build
    [ "$status" -eq 0 ]
    grep -qE "build .*--file $custom" "$MOCK_LOG"
}

@test "build passes --pull" {
    mock_runtime docker
    run env OPS_RUNTIME=docker "$(ops_sh)" build
    [ "$status" -eq 0 ]
    grep -qE 'build .*--pull' "$MOCK_LOG"
}

# OPS_BUILD_ARGS: per-image --build-arg propagation from ops.conf.

@test "OPS_BUILD_ARGS: entry matching OPS_IMAGES key yields --build-arg" {
    mock_runtime docker
    local cfg="$BATS_TEST_TMPDIR/.config/ops/ops.conf"
    mkdir -p "$(dirname "$cfg")"
    cat > "$cfg" <<'EOF'
declare -A OPS_IMAGES=( [arch-chrome]="localhost/ops-chrome" )
declare -A OPS_BUILD_ARGS=( [arch-chrome]="EXTRA_MISE_TOOLS=nix:google-chrome-for-testing" )
EOF
    run env OPS_RUNTIME=docker XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/.config" \
        "$(ops_sh)" -i arch-chrome build
    [ "$status" -eq 0 ]
    grep -qE 'build .*--build-arg EXTRA_MISE_TOOLS=nix:google-chrome-for-testing' "$MOCK_LOG"
}

@test "OPS_BUILD_ARGS: no entry means no extra --build-arg injected" {
    mock_runtime docker
    local cfg="$BATS_TEST_TMPDIR/.config/ops/ops.conf"
    mkdir -p "$(dirname "$cfg")"
    cat > "$cfg" <<'EOF'
declare -A OPS_IMAGES=( [arch]="localhost/ops-dev" )
EOF
    run env OPS_RUNTIME=docker XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/.config" \
        "$(ops_sh)" -i arch build
    [ "$status" -eq 0 ]
    ! grep -qE 'build .*--build-arg EXTRA_MISE_TOOLS' "$MOCK_LOG"
}

@test "OPS_BUILD_ARGS: ';' separates multiple pairs" {
    mock_runtime docker
    local cfg="$BATS_TEST_TMPDIR/.config/ops/ops.conf"
    mkdir -p "$(dirname "$cfg")"
    cat > "$cfg" <<'EOF'
declare -A OPS_IMAGES=( [multi]="localhost/ops-multi" )
declare -A OPS_BUILD_ARGS=( [multi]="EXTRA_MISE_TOOLS=nix:chromium;NIX_CLEANUP=false" )
EOF
    run env OPS_RUNTIME=docker XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/.config" \
        "$(ops_sh)" -i multi build
    [ "$status" -eq 0 ]
    grep -qE 'build .*--build-arg EXTRA_MISE_TOOLS=nix:chromium' "$MOCK_LOG"
    grep -qE 'build .*--build-arg NIX_CLEANUP=false' "$MOCK_LOG"
}

@test "OPS_BUILD_ARGS: empty value explicitly disables the default tool" {
    mock_runtime docker
    local cfg="$BATS_TEST_TMPDIR/.config/ops/ops.conf"
    mkdir -p "$(dirname "$cfg")"
    cat > "$cfg" <<'EOF'
declare -A OPS_IMAGES=( [arch-min]="localhost/ops-min" )
declare -A OPS_BUILD_ARGS=( [arch-min]="EXTRA_MISE_TOOLS=" )
EOF
    run env OPS_RUNTIME=docker XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/.config" \
        "$(ops_sh)" -i arch-min build
    [ "$status" -eq 0 ]
    # The empty override DOES reach the build ("EXTRA_MISE_TOOLS=" present).
    grep -qE 'build .*--build-arg EXTRA_MISE_TOOLS=' "$MOCK_LOG"
    # And crucially, no default tool name leaks into --build-arg.
    ! grep -qE 'build .*--build-arg EXTRA_MISE_TOOLS=nix:' "$MOCK_LOG"
}

@test "OPS_BUILD_ARGS: ignored when -i points to a raw image ref (no key)" {
    mock_runtime docker
    local cfg="$BATS_TEST_TMPDIR/.config/ops/ops.conf"
    mkdir -p "$(dirname "$cfg")"
    cat > "$cfg" <<'EOF'
declare -A OPS_IMAGES=( [arch]="localhost/ops-dev" )
declare -A OPS_BUILD_ARGS=( [arch]="EXTRA_MISE_TOOLS=nix:chromium" )
EOF
    run env OPS_RUNTIME=docker XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/.config" \
        "$(ops_sh)" -i localhost/some-other build
    [ "$status" -eq 0 ]
    ! grep -qE 'build .*--build-arg EXTRA_MISE_TOOLS' "$MOCK_LOG"
}
