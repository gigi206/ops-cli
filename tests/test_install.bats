#!/usr/bin/env bats
# Install / uninstall / self-update happy & error paths.
# Uses mocked curl/tar/systemctl so no real network or daemon is touched.

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_install_tools
    # Install tests target nerdctl specifically; put OPS_NERDCTL_HOME in tmp.
    export OPS_NERDCTL_HOME="$BATS_TEST_TMPDIR/nerdctl"
}

@test "install happy path writes binary and reaches end message" {
    run bash -c "printf 'Y\nY\nY\n' | env OPS_RUNTIME=nerdctl '$(ops_sh)' nerdctl install"
    [ "$status" -eq 0 ]
    [ -x "$OPS_NERDCTL_HOME/bin/nerdctl" ]
    [[ "$output" == *"Service installed and disabled at boot"* ]]
}

@test "install fails when GitHub API returns nothing" {
    run env OPS_RUNTIME=nerdctl MOCK_GH_FAIL=1 "$(ops_sh)" nerdctl install
    [ "$status" -eq 1 ]
    [[ "$output" == *"Failed to fetch version"* ]]
}

@test "install fails on unsupported architecture" {
    run env OPS_RUNTIME=nerdctl MOCK_UNAME_ARCH=riscv64 "$(ops_sh)" nerdctl install
    [ "$status" -eq 1 ]
    [[ "$output" == *"Unsupported architecture"* ]]
}

@test "install declining overwrite aborts" {
    mkdir -p "$OPS_NERDCTL_HOME/bin"
    echo "dummy" > "$OPS_NERDCTL_HOME/bin/placeholder"
    run bash -c "printf 'n\n' | env OPS_RUNTIME=nerdctl '$(ops_sh)' nerdctl install"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Aborted"* ]]
}

@test "install fails when tar extraction fails" {
    run bash -c "printf 'Y\nY\nY\n' | env OPS_RUNTIME=nerdctl MOCK_TAR_FAIL=1 '$(ops_sh)' nerdctl install"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Extraction failed"* ]]
}

@test "uninstall happy path removes binary dir with user consent" {
    mkdir -p "$OPS_NERDCTL_HOME/bin"
    echo "fake-binary" > "$OPS_NERDCTL_HOME/bin/nerdctl"
    run bash -c "printf 'Y\nn\n' | env OPS_RUNTIME=nerdctl '$(ops_sh)' nerdctl uninstall"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Uninstall complete"* ]]
    [[ "$output" == *"Binaries removed"* ]]
    [ ! -d "$OPS_NERDCTL_HOME" ]
}

@test "uninstall declining both prompts keeps everything" {
    mkdir -p "$OPS_NERDCTL_HOME/bin"
    echo "fake-binary" > "$OPS_NERDCTL_HOME/bin/nerdctl"
    run bash -c "printf 'n\nn\n' | env OPS_RUNTIME=nerdctl '$(ops_sh)' nerdctl uninstall"
    [ "$status" -eq 0 ]
    [ -f "$OPS_NERDCTL_HOME/bin/nerdctl" ]
}

@test "self-update says already up to date when versions match" {
    # Pre-install fake nerdctl reporting version v1.2.3
    mkdir -p "$OPS_NERDCTL_HOME/bin"
    cat > "$OPS_NERDCTL_HOME/bin/nerdctl" <<'EOF'
#!/bin/bash
[ "$1" = "--version" ] && echo "nerdctl version 1.2.3"
exit 0
EOF
    chmod +x "$OPS_NERDCTL_HOME/bin/nerdctl"
    run env OPS_RUNTIME=nerdctl MOCK_GH_VERSION=v1.2.3 "$(ops_sh)" nerdctl self-update
    [ "$status" -eq 0 ]
    [[ "$output" == *"Already up to date"* ]]
}

@test "self-update proposes update when a newer version is available" {
    mkdir -p "$OPS_NERDCTL_HOME/bin"
    cat > "$OPS_NERDCTL_HOME/bin/nerdctl" <<'EOF'
#!/bin/bash
[ "$1" = "--version" ] && echo "nerdctl version 1.2.3"
exit 0
EOF
    chmod +x "$OPS_NERDCTL_HOME/bin/nerdctl"
    # Decline the prompt to keep the test scope small.
    run bash -c "printf 'n\n' | env OPS_RUNTIME=nerdctl MOCK_GH_VERSION=v1.5.0 '$(ops_sh)' nerdctl self-update"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Update nerdctl from 1.2.3 to 1.5.0"* ]]
    [[ "$output" == *"Aborted"* ]]
}

@test "self-update fails if nerdctl is not installed" {
    # No pre-installed binary at OPS_NERDCTL_HOME
    run env OPS_RUNTIME=nerdctl "$(ops_sh)" nerdctl self-update
    [ "$status" -eq 1 ]
    [[ "$output" == *"nerdctl not installed"* ]]
}
