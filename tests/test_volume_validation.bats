#!/usr/bin/env bats
# Validation of `-v / --volume SRC:DST[:OPTS]` arg shape. The cmd_run argv
# loop now rejects bare values that lack a colon, since a runtime called
# with `-v vol_only` would either treat it as a named volume mount with no
# destination (silently broken) or refuse to start with a confusing error.

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
}

@test "-v <name> (no colon) is rejected with a clear error" {
    run env OPS_RUNTIME=docker "$(ops_sh)" \
        run -v vol_with_no_dest --dry-run
    [ "$status" -ne 0 ]
    [[ "$output" == *"-v expects SRC:DST"* ]]
    [[ "$output" == *"vol_with_no_dest"* ]]
}

@test "--volume <name> (no colon) is rejected with a clear error" {
    run env OPS_RUNTIME=docker "$(ops_sh)" \
        run --volume bare_name --dry-run
    [ "$status" -ne 0 ]
    [[ "$output" == *"-v expects SRC:DST"* ]]
}

@test "-v src:dst is accepted (sanity check)" {
    run env OPS_RUNTIME=docker "$(ops_sh)" \
        run -v /tmp/foo:/tmp/bar --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"/tmp/foo:/tmp/bar"* ]]
}

@test "-v src:dst:ro is accepted with the option suffix" {
    run env OPS_RUNTIME=docker "$(ops_sh)" \
        run -v /tmp/foo:/tmp/bar:ro --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"/tmp/foo:/tmp/bar:ro"* ]]
}

@test "named-volume:dst is accepted" {
    run env OPS_RUNTIME=docker "$(ops_sh)" \
        run -v my-named-vol:/data --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"my-named-vol:/data"* ]]
}
