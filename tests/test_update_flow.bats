#!/usr/bin/env bats
# cmd_update full flow: image-ID diff triggers container recreation prompt,
# same ID → silent no-op. Requires a stateful image-inspect mock.

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
}

# Stateful mock: image-inspect returns MOCK_OLD_ID before build, MOCK_NEW_ID after.
# Tracked via a flag file so the same binary returns different output.
_stateful_mock() {
    export MOCK_STATE="$BATS_TEST_TMPDIR/mock-state"
    mkdir -p "$MOCK_STATE"
    cat > "$MOCK_DIR/docker" <<'MOCK'
#!/bin/bash
printf '%s\n' "$*" >> "${MOCK_LOG:-/dev/null}"
case "$1" in
    info) echo "${MOCK_SEC_OPTIONS-[name=rootless]}" ;;
    build)
        # Mark that a build has happened
        touch "$MOCK_STATE/built"
        ;;
    image)
        case "$2" in
            inspect)
                if [[ "$*" == *'.Id'* ]]; then
                    if [ -f "$MOCK_STATE/built" ]; then
                        echo "${MOCK_NEW_ID:-sha256:newid}"
                    else
                        echo "${MOCK_OLD_ID:-sha256:oldid}"
                    fi
                else
                    echo "ok"
                fi
                ;;
            ls) ;;
        esac
        ;;
    ps)
        # Label filter returns nothing (we don't use it here)
        if [[ "$*" == *"label="* ]]; then exit 0; fi
        # ps -a --format '{{.Names}}|{{.ImageID}}' - list containers on old ID
        if [[ "$*" == *'.ImageID'* ]]; then
            # MOCK_CTNS_ON_OLD: "name1,name2" — both on old ID
            if [ -n "${MOCK_CTNS_ON_OLD:-}" ]; then
                IFS=',' read -ra names <<< "$MOCK_CTNS_ON_OLD"
                for n in "${names[@]}"; do
                    echo "$n|${MOCK_OLD_ID:-sha256:oldid}"
                done
            fi
            exit 0
        fi
        ;;
    container)
        case "$2" in
            inspect)
                case "$*" in
                    *ops.cmdline.user*) echo "./ops.sh run --claude" ;;
                    *) echo "" ;;
                esac
                ;;
        esac
        ;;
    volume) ;;
    rm)   ;;
esac
exit 0
MOCK
    chmod +x "$MOCK_DIR/docker"
}

@test "update: image unchanged (same ID) reports no-op" {
    _stateful_mock
    # Same ID before and after
    export MOCK_OLD_ID="sha256:sameid"
    export MOCK_NEW_ID="sha256:sameid"
    run env OPS_RUNTIME=docker "$(ops_sh)" update my-img
    [ "$status" -eq 0 ]
    [[ "$output" == *"unchanged"* ]] || [[ "$output" == *"cache hit"* ]]
}

@test "update: new image lists containers on old ID" {
    _stateful_mock
    export MOCK_OLD_ID="sha256:oldid"
    export MOCK_NEW_ID="sha256:newid"
    export MOCK_CTNS_ON_OLD="ctn-alpha,ctn-beta"
    run bash -c "echo n | env OPS_RUNTIME=docker MOCK_STATE='$MOCK_STATE' \
        MOCK_OLD_ID=sha256:oldid MOCK_NEW_ID=sha256:newid \
        MOCK_CTNS_ON_OLD=ctn-alpha,ctn-beta '$(ops_sh)' update my-img"
    [ "$status" -eq 0 ]
    [[ "$output" == *"ctn-alpha"* ]]
    [[ "$output" == *"ctn-beta"* ]]
    [[ "$output" == *"relaunch:"* ]]
}

@test "update: user answers Y → containers are removed" {
    _stateful_mock
    export MOCK_OLD_ID="sha256:oldid"
    export MOCK_NEW_ID="sha256:newid"
    export MOCK_CTNS_ON_OLD="oldctn"
    run bash -c "echo Y | env OPS_RUNTIME=docker MOCK_STATE='$MOCK_STATE' \
        MOCK_OLD_ID=sha256:oldid MOCK_NEW_ID=sha256:newid \
        MOCK_CTNS_ON_OLD=oldctn '$(ops_sh)' update my-img"
    [ "$status" -eq 0 ]
    # A 'docker rm -f oldctn' call should have been logged
    grep -qE 'rm -f oldctn' "$MOCK_LOG"
}

@test "update: no containers on old image says '(none)'" {
    _stateful_mock
    export MOCK_OLD_ID="sha256:oldid"
    export MOCK_NEW_ID="sha256:newid"
    # MOCK_CTNS_ON_OLD empty → no containers reported
    run env OPS_RUNTIME=docker "$(ops_sh)" update my-img
    [ "$status" -eq 0 ]
    [[ "$output" == *"(none)"* ]]
}
