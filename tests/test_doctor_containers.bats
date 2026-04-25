#!/usr/bin/env bats
# cmd_doctor container section — orphan detection + image mismatch
#
# Uses the shared mock_runtime_rich from helpers.bash
# (MOCK_PS_LABELED_FULL + MOCK_IMG_MISSING). See its docstring for details.

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    export XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/config"
    mkdir -p "$XDG_CONFIG_HOME/ops"
}

_write_conf() { cat > "$XDG_CONFIG_HOME/ops/ops.conf"; }

@test "doctor: Containers section header appears" {
    mock_runtime_rich docker
    _write_conf <<'EOF'
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" doctor
    [ "$status" -le 1 ]
    [[ "$output" == *"Containers (label=ops.container=true)"* ]]
}

@test "doctor: (no ops-labeled containers) when none" {
    mock_runtime_rich docker
    _write_conf <<'EOF'
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" doctor
    [ "$status" -le 1 ]
    [[ "$output" == *"no ops-labeled containers"* ]]
}

@test "doctor: orphan container (image missing) is flagged" {
    mock_runtime_rich docker
    export MOCK_PS_LABELED_FULL="orphaned|localhost/vanished-img"
    export MOCK_IMG_MISSING="localhost/vanished-img"
    _write_conf <<'EOF'
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" doctor
    [[ "$output" == *"orphaned"* ]]
    # cmd_doctor emits "no longer exists (orphan)" for this case; we assert
    # the full message rather than either substring.
    [[ "$output" == *"no longer exists"*"orphan"* ]]
    [ "$status" -ne 0 ]  # warning present → return 1
}

@test "doctor: image mismatch (container uses image ≠ OPS_IMAGES[name]) is flagged" {
    mock_runtime_rich docker
    # Container named 'mykey' exists, using 'actual-img', but OPS_IMAGES[mykey] says 'expected-img'
    export MOCK_PS_LABELED_FULL="mykey|localhost/actual-img"
    _write_conf <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[mykey]="localhost/expected-img"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" doctor
    [[ "$output" == *"mykey"* ]]
    # The mismatch warning names both the observed and expected images.
    [[ "$output" == *"localhost/actual-img"* ]]
    [[ "$output" == *"localhost/expected-img"* ]]
    [ "$status" -ne 0 ]
}

@test "doctor: matching container ↔ OPS_IMAGES[name] reports OK" {
    mock_runtime_rich docker
    export MOCK_PS_LABELED_FULL="mykey|localhost/expected-img"
    _write_conf <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[mykey]="localhost/expected-img"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" doctor
    # cmd_doctor emits "container 'mykey' matches OPS_IMAGES[mykey]" via _doc_ok
    [[ "$output" == *"container 'mykey' matches"* ]]
}
