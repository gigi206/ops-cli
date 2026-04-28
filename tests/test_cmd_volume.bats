#!/usr/bin/env bats
# cmd_volume — listing of ops-managed Docker volumes.

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    # Custom mock that returns volume names from MOCK_VOLUME_LIST when
    # the runtime is invoked with `volume ls --filter label=ops.volume=true`.
    cat > "$MOCK_DIR/docker" <<'EOF'
#!/bin/bash
printf '%s\n' "$*" >> "${MOCK_LOG:-/dev/null}"
case "$1" in
    info|--version) echo "mock" ;;
    volume)
        if [ "$2" = "ls" ]; then
            # Honor --filter label=ops.volume=true contract by always emitting
            # what the test asked for (the filter logic itself lives in ops.sh).
            if [ -n "${MOCK_VOLUME_LIST:-}" ]; then
                printf '%s\n' "${MOCK_VOLUME_LIST//,/$'\n'}"
            fi
        fi
        ;;
esac
exit 0
EOF
    chmod +x "$MOCK_DIR/docker"
}

@test "volume list prints all ops-labelled volumes" {
    run env OPS_RUNTIME=docker MOCK_VOLUME_LIST="ops-share-nix,ops-share-mise,ops-claude" \
        "$(ops_sh)" volume list
    assert_success
    assert_output_contains "ops-share-nix"
    assert_output_contains "ops-share-mise"
    assert_output_contains "ops-claude"
}

@test "volume list --agent restricts to per-agent credential volumes" {
    run env OPS_RUNTIME=docker MOCK_VOLUME_LIST="ops-share-nix,ops-share-mise,ops-claude,ops-gemini,ops-codex" \
        "$(ops_sh)" volume list --agent
    assert_success
    assert_output_contains "ops-claude"
    assert_output_contains "ops-gemini"
    assert_output_contains "ops-codex"
    refute_output_contains "ops-share-nix"
    refute_output_contains "ops-share-mise"
}

@test "volume list --agents (alias) works the same way" {
    run env OPS_RUNTIME=docker MOCK_VOLUME_LIST="ops-claude,ops-share-nix" \
        "$(ops_sh)" volume list --agents
    assert_success
    assert_output_contains "ops-claude"
    refute_output_contains "ops-share-nix"
}

@test "volume list with empty runtime output prints nothing" {
    run env OPS_RUNTIME=docker MOCK_VOLUME_LIST="" "$(ops_sh)" volume list
    assert_success
    [ -z "$output" ]
}

@test "volume without subcommand shows usage" {
    run env OPS_RUNTIME=docker "$(ops_sh)" volume
    assert_success
    assert_output_contains "list"
    assert_output_contains "--agent"
}

@test "volume bogus subcommand errors" {
    run env OPS_RUNTIME=docker "$(ops_sh)" volume frobnicate
    assert_failure
    assert_output_contains "unknown volume subcommand"
}

@test "volume list --bogus errors out" {
    run env OPS_RUNTIME=docker MOCK_VOLUME_LIST="ops-claude" \
        "$(ops_sh)" volume list --bogus
    assert_failure
    assert_output_contains "unknown 'volume list' option"
}

@test "volumes (plural) is an alias for volume" {
    run env OPS_RUNTIME=docker MOCK_VOLUME_LIST="ops-claude" \
        "$(ops_sh)" volumes list
    assert_success
    assert_output_contains "ops-claude"
}
