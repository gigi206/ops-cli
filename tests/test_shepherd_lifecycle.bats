#!/usr/bin/env bats
# Multi-session lifecycle (shepherd pattern, ops ≥ 1.11).
#
# These tests exercise the host-side helpers directly against a real
# container runtime (docker / podman / nerdctl) using a minimal
# `tail -f /dev/null` shepherd. They skip when no runtime is available
# so the suite stays green on minimal CI runners.
#
# What's covered:
#   - Several sessions can register markers in the same shepherd.
#   - _ops_cleanup_session removes the container only when the LAST
#     marker is gone AND ephemeral=1.
#   - --no-rm equivalent (ephemeral=0): cleanup leaves the container
#     running for later re-attach.
#   - _ops_sweep_orphan_sessions drops markers whose host PID is dead
#     (simulating a SIGKILL'd session that bypassed its EXIT trap).
#
# The bug these tests guard against: pre-1.11 `ops run` used the user
# command (bash, opencode, …) as PID 1 of a `--rm` container; quitting
# the first session removed the container and killed every other
# attached `docker exec`. The shepherd inverts that — quitting any
# single session is now harmless, and the runtime sees a `docker rm`
# only on the LAST exit.

load helpers

setup() {
    # Need a real runtime; skip cleanly otherwise (mirrors the existing
    # require_ops_image gate used by test_image_integration.bats).
    if ! command -v docker >/dev/null 2>&1 \
       && ! command -v podman >/dev/null 2>&1 \
       && ! command -v nerdctl >/dev/null 2>&1; then
        skip "no container runtime found (docker/podman/nerdctl)"
    fi
    # Pick the first available runtime the same way image_runtime_bin does,
    # but we only need the binary itself (no image baked in this test —
    # alpine:latest is small and works on any runtime).
    for rt in docker podman nerdctl; do
        if command -v "$rt" >/dev/null 2>&1; then
            export RT="$rt"
            break
        fi
    done

    # Per-test container name (avoid collision with parallel test runs).
    export TEST_CTN="ops-shepherd-test-$$-$BATS_TEST_NUMBER"

    # Always tear down even on failure; the trap fires before bats moves on.
    teardown_ctn() { "$RT" rm -f "$TEST_CTN" >/dev/null 2>&1 || true; }
}

teardown() {
    "$RT" rm -f "$TEST_CTN" >/dev/null 2>&1 || true
}

# Spin up a shepherd container modelled on what cmd_run produces:
# detached, --init, tail -f /dev/null as PID 1. Uses alpine because it
# is small and ubiquitous; the test only cares about the lifecycle
# helpers, not the ops image contents.
#
# `tail -f /dev/null` (not `sleep infinity`) because BusyBox's `sleep`
# — what alpine ships — does not accept the `infinity` literal. The
# main code path in ops.sh (cmd_run) makes the same choice for the
# same reason; this test would silently fail to start on Alpine if we
# diverged. See the matching comment in `ops.sh:cmd_run` for the
# longer rationale.
_start_shepherd() {
    "$RT" run -d --init --rm --name "$TEST_CTN" \
        --label ops.container=true --label ops.shepherd=1 \
        alpine:latest tail -f /dev/null >/dev/null
}

# Source ops.sh as a library so we can call _ops_register_session and
# friends directly. RUNTIME_BIN must be set before calling them.
_call() {
    OPS_SOURCE_ONLY=1 OPS_RUNTIME="$RT" bash -c "
        source '$(ops_sh)'
        RUNTIME_BIN=\$(command -v $RT)
        $*
    "
}

@test "shepherd: container survives until the last session unregisters (ephemeral=1)" {
    _start_shepherd
    _call "_ops_register_session $TEST_CTN ops-session-111"
    _call "_ops_register_session $TEST_CTN ops-session-222"

    # Drop the first session: container must still be running.
    _call "_ops_cleanup_session $TEST_CTN ops-session-111 1"
    "$RT" inspect -f '{{.State.Running}}' "$TEST_CTN" | grep -q '^true$'

    # Drop the second (last) session: container must be removed.
    _call "_ops_cleanup_session $TEST_CTN ops-session-222 1"
    ! "$RT" inspect "$TEST_CTN" >/dev/null 2>&1
}

@test "shepherd: ephemeral=0 leaves the container alive after the last session" {
    _start_shepherd
    _call "_ops_register_session $TEST_CTN ops-session-aaa"
    _call "_ops_cleanup_session $TEST_CTN ops-session-aaa 0"

    # Container must still be running — equivalent to user passing --no-rm.
    "$RT" inspect -f '{{.State.Running}}' "$TEST_CTN" | grep -q '^true$'
}

@test "shepherd: killing the first attached docker exec leaves a sibling exec alive" {
    # End-to-end pin of the user-reported bug, modelled at the runtime
    # level: pre-1.11 `ops run` made the first user command PID 1 of a
    # `--rm` container, so quitting it tore the container down and
    # killed every other `docker exec`. Post-fix the shepherd is PID 1,
    # so the same scenario at the runtime level (start shepherd → two
    # `docker exec`s in parallel → kill the first) must leave the
    # container running and the second exec untouched.
    #
    # We model the scenario without going through `cmd_run` because
    # `cmd_run` issues `docker exec -it` which requires a TTY and bats
    # runs without one. The runtime-level reproduction is what the
    # original bug was about anyway: the question is whether the
    # container survives one of two parallel attached execs exiting,
    # and the answer depends entirely on the PID-1 lifecycle, which
    # the shepherd model is the fix to.
    _start_shepherd

    # Two backgrounded `docker exec` sessions, both running `sleep 60`
    # so they won't exit on their own during this test.
    "$RT" exec "$TEST_CTN" sh -c 'sleep 60' &
    local pid_a=$!
    "$RT" exec "$TEST_CTN" sh -c 'sleep 60' &
    local pid_b=$!
    sleep 1  # let both attach

    # Kill A — pre-1.11 (no shepherd) the container would have torn
    # itself down here because A would have been PID 1.
    kill "$pid_a" 2>/dev/null || true
    wait "$pid_a" 2>/dev/null || true
    sleep 1

    # Container still running, B's exec still alive.
    "$RT" inspect -f '{{.State.Running}}' "$TEST_CTN" | grep -q '^true$'
    kill -0 "$pid_b" 2>/dev/null

    kill "$pid_b" 2>/dev/null || true
    wait "$pid_b" 2>/dev/null || true
}

@test "shepherd: orphan sweep drops markers whose host PID is dead" {
    _start_shepherd

    # Spawn a short-lived process and capture its PID; once it exits the
    # marker `ops-session-<pid>` is orphaned (no EXIT trap fired).
    sh -c 'exit 0' &
    local dead_pid=$!
    wait "$dead_pid" 2>/dev/null || true
    _call "_ops_register_session $TEST_CTN ops-session-$dead_pid"

    # Also register a "live" marker — pid 1 always exists on the host.
    _call "_ops_register_session $TEST_CTN ops-session-1"

    _call "_ops_sweep_orphan_sessions $TEST_CTN"

    # Dead marker gone, live marker preserved.
    run "$RT" exec "$TEST_CTN" ls /tmp/ops-sessions
    [ "$status" -eq 0 ]
    [[ "$output" != *"ops-session-$dead_pid"* ]]
    [[ "$output" == *"ops-session-1"* ]]
}
