#!/usr/bin/env bats
# cmd_update full flow: image-ID diff triggers container recreation prompt,
# same ID → silent no-op.
#
# Uses the shared mock_runtime_rich from helpers.bash for the stateful
# image-ID flip (MOCK_OLD_ID before a build, MOCK_NEW_ID after). See its
# docstring for the full env-var matrix.

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    # Default cmdline.user label for all tests in this file (cmd_update reads
    # it to emit the `relaunch:` hint).
    export MOCK_CLI_USER="./ops.sh run --claude"
}

@test "update: image unchanged (same ID) reports no-op" {
    mock_runtime_rich docker
    # Same ID before and after
    export MOCK_OLD_ID="sha256:sameid"
    export MOCK_NEW_ID="sha256:sameid"
    run env OPS_RUNTIME=docker "$(ops_sh)" update my-img
    [ "$status" -eq 0 ]
    [[ "$output" == *"unchanged"* ]] || [[ "$output" == *"cache hit"* ]]
}

@test "update: new image lists containers on old ID" {
    mock_runtime_rich docker
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
    mock_runtime_rich docker
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
    mock_runtime_rich docker
    export MOCK_OLD_ID="sha256:oldid"
    export MOCK_NEW_ID="sha256:newid"
    # MOCK_CTNS_ON_OLD empty → no containers reported
    run env OPS_RUNTIME=docker "$(ops_sh)" update my-img
    [ "$status" -eq 0 ]
    [[ "$output" == *"(none)"* ]]
}
