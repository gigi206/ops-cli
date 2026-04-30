#!/usr/bin/env bats
# -r / --runtime flag — per-invocation runtime override.
#
# Symmetry pin: ops already exposes -n / -i / -f / -H as global flags that
# double an env var or config setting. -r / --runtime fills the gap for
# OPS_RUNTIME, which previously could only be set via the env var or
# `ops config set OPS_RUNTIME ...`. Use case: user has OPS_RUNTIME=docker
# pinned in ops.conf but wants to test podman ad-hoc → `ops -r podman run`.

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
}

# ---- global form: ops -r RUNTIME run ... ------------------------------------

@test "global -r docker overrides OPS_RUNTIME=podman from env" {
    mock_runtime docker
    # Env says podman, flag says docker → flag wins.
    run env OPS_RUNTIME=podman "$(ops_sh)" -r docker run --dry-run
    [ "$status" -eq 0 ]
    # The mock RUNTIME_BIN is the docker mock; its path appears in the dry-run
    # invocation. Verifying via the mock path is more precise than grepping for
    # the literal "docker" word (which can appear in many unrelated args).
    [[ "$output" == *"/mocks/docker run"* ]]
}

@test "global --runtime podman overrides OPS_RUNTIME=docker from env" {
    mock_runtime podman
    run env OPS_RUNTIME=docker "$(ops_sh)" --runtime podman run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"/mocks/podman run"* ]]
}

@test "global -r flag sets and exports OPS_RUNTIME for downstream resolution" {
    mock_runtime docker
    # No env, no config — pure flag-driven runtime selection.
    run env -u OPS_RUNTIME "$(ops_sh)" -r docker run --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"/mocks/docker run"* ]]
}

# ---- per-run form: ops run -r RUNTIME ... -----------------------------------

@test "per-run -r docker also overrides (symmetry with -n / -i / -f / -H)" {
    mock_runtime docker
    run env OPS_RUNTIME=podman "$(ops_sh)" run -r docker --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"/mocks/docker run"* ]]
}

@test "per-run --runtime podman also overrides" {
    mock_runtime podman
    run env OPS_RUNTIME=docker "$(ops_sh)" run --runtime podman --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"/mocks/podman run"* ]]
}

# ---- validation --------------------------------------------------------------

@test "-r unknown_runtime exits 1 (same path as OPS_RUNTIME=unknown)" {
    # _resolve_runtime exits 1 with "Invalid OPS_RUNTIME" — the flag must
    # route through the same validator (no silent acceptance).
    run "$(ops_sh)" -r totally_bogus_runtime run --dry-run
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid OPS_RUNTIME"* ]] || [[ "$output" == *"totally_bogus_runtime"* ]]
}

@test "-r auto resolves to first detected runtime" {
    mock_runtime docker
    run env -u OPS_RUNTIME "$(ops_sh)" -r auto run --dry-run
    [ "$status" -eq 0 ]
    # auto with docker available picks docker (per docker > podman > nerdctl
    # priority documented in ops.sh::_resolve_runtime).
    [[ "$output" == *"/mocks/docker run"* ]]
}
