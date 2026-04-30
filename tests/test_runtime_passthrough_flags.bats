#!/usr/bin/env bats
# Runtime-passthrough flags: --group-add, --cap-add, --cap-drop,
# --security-opt, --device, --privileged, and --user UID:GID.
#
# Motivated by docs/nested-containers.md — the three function aliases for
# podman / docker rootful / containerd nested-container access need these
# flags forwarded verbatim to `<runtime> run`. Before this support landed,
# `ops run --group-add 999` triggered the "unknown flag — passing as
# command" warning and broke at exec time. These tests pin the verbatim
# forwarding to the runtime invocation.

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
}

# ---- single-flag forwarding --------------------------------------------------

@test "--group-add GID is forwarded verbatim to docker run" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run --group-add 145
    [ "$status" -eq 0 ]
    [[ "$output" == *"--group-add 145"* ]]
    # Must NOT trigger the "unknown flag" warning (regression guard).
    [[ "$output" != *"unknown flag"* ]]
}

@test "--cap-add SYS_ADMIN is forwarded verbatim" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run --cap-add SYS_ADMIN
    [ "$status" -eq 0 ]
    [[ "$output" == *"--cap-add SYS_ADMIN"* ]]
    [[ "$output" != *"unknown flag"* ]]
}

@test "--cap-drop NET_RAW is forwarded verbatim" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run --cap-drop NET_RAW
    [ "$status" -eq 0 ]
    [[ "$output" == *"--cap-drop NET_RAW"* ]]
}

@test "--security-opt apparmor=unconfined is forwarded verbatim" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run --security-opt apparmor=unconfined
    [ "$status" -eq 0 ]
    [[ "$output" == *"--security-opt apparmor=unconfined"* ]]
}

@test "--device /dev/kvm is forwarded verbatim" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run --device /dev/kvm
    [ "$status" -eq 0 ]
    [[ "$output" == *"--device /dev/kvm"* ]]
}

@test "--privileged is forwarded verbatim (boolean flag, no value)" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run --privileged
    [ "$status" -eq 0 ]
    [[ "$output" == *"--privileged"* ]]
}

# ---- repeatability -----------------------------------------------------------

@test "--cap-add can appear multiple times (containerd recipe)" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run \
        --cap-add SYS_ADMIN --cap-add NET_ADMIN
    [ "$status" -eq 0 ]
    [[ "$output" == *"--cap-add SYS_ADMIN"* ]]
    [[ "$output" == *"--cap-add NET_ADMIN"* ]]
}

@test "--group-add accepts numeric and named groups" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run \
        --group-add 999 --group-add docker
    [ "$status" -eq 0 ]
    [[ "$output" == *"--group-add 999"* ]]
    [[ "$output" == *"--group-add docker"* ]]
}

# ---- --user UID[:GID] form ---------------------------------------------------

# Note: setup_ops_env mocks docker info → rootless by default, which forces
# user_arg to "0:$OPS_USER_GID" (see _is_rootless override in ops.sh:3044).
# To verify the UID half of UID:GID parsing actually lands, we override
# MOCK_SEC_OPTIONS to a non-rootless value for these tests.

@test "--user 0:0 sets both UID and GID (rootful path)" {
    run env OPS_RUNTIME=docker MOCK_SEC_OPTIONS="" "$(ops_sh)" run --dry-run --user 0:0
    [ "$status" -eq 0 ]
    [[ "$output" == *"--user 0:0"* ]]
}

@test "--user 1000 (UID only) preserves default GID (rootful path)" {
    run env OPS_RUNTIME=docker MOCK_SEC_OPTIONS="" OPS_USER_GID=42 "$(ops_sh)" run --dry-run --user 1000
    [ "$status" -eq 0 ]
    [[ "$output" == *"--user 1000:42"* ]]
}

@test "-u UID:GID short form also splits (rootful path)" {
    run env OPS_RUNTIME=docker MOCK_SEC_OPTIONS="" "$(ops_sh)" run --dry-run -u 33:33
    [ "$status" -eq 0 ]
    [[ "$output" == *"--user 33:33"* ]]
}

@test "--uid UID:GID long form (legacy) also splits (rootful path)" {
    run env OPS_RUNTIME=docker MOCK_SEC_OPTIONS="" "$(ops_sh)" run --dry-run --uid 33:33
    [ "$status" -eq 0 ]
    [[ "$output" == *"--user 33:33"* ]]
}

@test "rootless override clobbers requested UID (existing safety contract)" {
    # The pre-existing _is_rootless override forces --user 0:GID to preserve
    # host-user file ownership when the runtime is rootless. This is NOT a
    # regression — verify the override still fires when user passes -u 1000.
    run env OPS_RUNTIME=docker MOCK_SEC_OPTIONS="[name=rootless]" \
        "$(ops_sh)" run --dry-run --user 1000:1000
    [ "$status" -eq 0 ]
    [[ "$output" == *"--user 0:1000"* ]]
    [[ "$output" != *"--user 1000:1000"* ]]
}

# ---- nested-containers function alias compose --------------------------------

@test "ops_alias_docker rootful body forwards --group-add cleanly" {
    # Reproduces the failure that motivated this fix:
    # `ops docker` → ops_alias_docker echoes `run -v /var/run/docker.sock:... --group-add 145`
    # → ops parses argv → before this fix, --group-add became the command and broke at exec.
    export XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/config"
    mkdir -p "$XDG_CONFIG_HOME/ops"
    cat > "$XDG_CONFIG_HOME/ops/ops.conf" <<'EOF'
ops_alias_docker() {
    local sock=/var/run/docker.sock
    echo run -v "$sock:$sock" --group-add 145
}
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" docker --dry-run
    [ "$status" -eq 0 ]
    # ops.sh normalizes -v → --volume in the resolved docker invocation.
    [[ "$output" == *"--volume /var/run/docker.sock:/var/run/docker.sock"* ]]
    [[ "$output" == *"--group-add 145"* ]]
    [[ "$output" != *"unknown flag"* ]]
}

# ---- combine with command ----------------------------------------------------

@test "passthrough flags compose with -- and an explicit command" {
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run \
        --cap-add SYS_ADMIN -- echo hello
    [ "$status" -eq 0 ]
    [[ "$output" == *"--cap-add SYS_ADMIN"* ]]
    [[ "$output" == *"echo hello"* ]]
}

# ---- OPS_DEFAULT_RUN_FLAGS interplay ----------------------------------------

@test "OPS_DEFAULT_RUN_FLAGS with --cap-add forwards correctly" {
    run env OPS_RUNTIME=docker OPS_DEFAULT_RUN_FLAGS="--cap-add SYS_ADMIN" \
        "$(ops_sh)" run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"--cap-add SYS_ADMIN"* ]]
}

# ---- regression: truly unknown flags still warn -----------------------------

@test "truly unknown flags still trigger the 'passing as command' warning" {
    # The fix added explicit support for an enumerated set; flags outside
    # that set must keep the existing break-and-warn behaviour so the user
    # sees their typo as a command, not a silent passthrough.
    run env OPS_RUNTIME=docker "$(ops_sh)" run --dry-run --totally-bogus-flag value
    # Don't assert exit status — the warning routes to stderr, the rest to
    # stdout; bats merges both into $output.
    [[ "$output" == *"unknown flag '--totally-bogus-flag'"* ]] || \
    [[ "$output" == *"unknown flag '--totally-bogus-flag' — passing as command"* ]]
}
