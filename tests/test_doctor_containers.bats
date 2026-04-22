#!/usr/bin/env bats
# cmd_doctor container section — orphan detection + image mismatch

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    export XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/config"
    mkdir -p "$XDG_CONFIG_HOME/ops"
}

_write_conf() { cat > "$XDG_CONFIG_HOME/ops/ops.conf"; }

# Mock that simulates image inspect success/failure per ref
_custom_docker_mock() {
    cat > "$MOCK_DIR/docker" <<'MOCK'
#!/bin/bash
printf '%s\n' "$*" >> "${MOCK_LOG:-/dev/null}"
case "$1" in
    info) echo "${MOCK_SEC_OPTIONS-[name=rootless]}" ;;
    image)
        case "$2" in
            inspect)
                ref="$3"
                # Fail inspect on the ref listed in MOCK_IMG_MISSING
                if [ "$ref" = "${MOCK_IMG_MISSING:-}" ]; then
                    exit 1
                fi
                # --format output
                if [[ "$*" == *'.Id'* ]]; then echo "sha256:deadbeefcafe"
                elif [[ "$*" == *Size* ]]; then echo "2000000000|2026-04-20T10:00:00Z|"
                else echo "ok"; fi
                ;;
            ls) ;;
        esac
        ;;
    ps)
        if [[ "$*" == *"label=ops.container=true"* ]]; then
            [ -n "${MOCK_PS_LABELED_FULL:-}" ] && echo "$MOCK_PS_LABELED_FULL"
        fi
        ;;
    container) case "$2" in inspect) echo "" ;; esac ;;
    volume) ;;
esac
exit 0
MOCK
    chmod +x "$MOCK_DIR/docker"
}

@test "doctor: Containers section header appears" {
    _custom_docker_mock
    _write_conf <<'EOF'
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" doctor
    [[ "$output" == *"Containers (label=ops.container=true)"* ]]
}

@test "doctor: (no ops-labeled containers) when none" {
    _custom_docker_mock
    _write_conf <<'EOF'
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" doctor
    [[ "$output" == *"no ops-labeled containers"* ]]
}

@test "doctor: orphan container (image missing) is flagged" {
    _custom_docker_mock
    export MOCK_PS_LABELED_FULL="orphaned|localhost/vanished-img"
    export MOCK_IMG_MISSING="localhost/vanished-img"
    _write_conf <<'EOF'
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" doctor
    [[ "$output" == *"orphaned"* ]]
    [[ "$output" == *"no longer exists"* ]] || [[ "$output" == *"orphan"* ]]
    [ "$status" -ne 0 ]  # warning present → return 1
}

@test "doctor: image mismatch (container uses image ≠ OPS_IMAGES[name]) is flagged" {
    _custom_docker_mock
    # Container named 'mykey' exists, using 'actual-img', but OPS_IMAGES[mykey] says 'expected-img'
    export MOCK_PS_LABELED_FULL="mykey|localhost/actual-img"
    _write_conf <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[mykey]="localhost/expected-img"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" doctor
    [[ "$output" == *"mykey"* ]]
    [[ "$output" == *"mismatch"* ]] || [[ "$output" == *"OPS_IMAGES"* ]]
    [ "$status" -ne 0 ]
}

@test "doctor: matching container ↔ OPS_IMAGES[name] reports OK" {
    _custom_docker_mock
    export MOCK_PS_LABELED_FULL="mykey|localhost/expected-img"
    _write_conf <<'EOF'
declare -A OPS_IMAGES
OPS_IMAGES[mykey]="localhost/expected-img"
EOF
    run env OPS_RUNTIME=docker "$(ops_sh)" doctor
    [[ "$output" == *"matches"* ]] || [[ "$output" == *"OK"* ]]
}
