#!/usr/bin/env bats
# Direct unit tests for internal helpers: _human_bytes, _shell_quote.
# Uses OPS_SOURCE_ONLY=1 so sourcing ops.sh defines the functions but skips
# the global flag parsing + dispatch.

load helpers

setup() {
    setup_mocks
    setup_ops_env
    ensure_dockerfile
    mock_runtime docker
}

# Helper: source ops.sh in a subshell as library, then call the function under test.
_ops_eval() {
    OPS_SOURCE_ONLY=1 OPS_RUNTIME=docker bash -c "source '$(ops_sh)'; $*"
}

@test "_human_bytes: 0 bytes" {
    result=$(_ops_eval '_human_bytes 0')
    [ "$result" = "0B" ]
}

@test "_human_bytes: below 1 KiB stays in bytes" {
    result=$(_ops_eval '_human_bytes 512')
    [ "$result" = "512B" ]
}

@test "_human_bytes: 1024 → 1.0KiB" {
    result=$(_ops_eval '_human_bytes 1024')
    [ "$result" = "1.0KiB" ]
}

@test "_human_bytes: 1.5 MiB" {
    result=$(_ops_eval '_human_bytes 1572864')  # 1.5 * 1024 * 1024
    [ "$result" = "1.5MiB" ]
}

@test "_human_bytes: 2 GiB" {
    result=$(_ops_eval '_human_bytes 2147483648')
    [ "$result" = "2.0GiB" ]
}

@test "_human_bytes: empty input falls back to 0" {
    result=$(_ops_eval '_human_bytes ""')
    [ "$result" = "0B" ]
}

@test "_shell_quote: simple alnum tokens stay bare" {
    result=$(_ops_eval '_shell_quote hello world123')
    # Trailing space is intentional per _shell_quote design
    [[ "$result" == "hello world123 " ]]
}

@test "_shell_quote: tokens with spaces get single-quoted" {
    result=$(_ops_eval "_shell_quote 'hello world'")
    [[ "$result" == "'hello world' " ]]
}

@test "_shell_quote: single-quote inside a token is escaped" {
    result=$(_ops_eval "_shell_quote \"don't\"")
    # The quote gets escaped via '\'' idiom
    [[ "$result" == *"don"*"'"*"t"* ]]
}

@test "_shell_quote: empty token is rendered as ''" {
    result=$(_ops_eval "_shell_quote ''")
    [[ "$result" == "'' " ]]
}

@test "_shell_quote: preserves safe path characters" {
    result=$(_ops_eval '_shell_quote /path/to/file.tar.gz')
    [[ "$result" == "/path/to/file.tar.gz " ]]
}

@test "_hash_dir: nonexistent directory returns 0 silently (no output)" {
    # current_hash() calls _hash_dir for mise/ and scripts/, either of which
    # may be absent in minimal setups. The function must return 0 without
    # printing anything so the outer sha256sum pipeline stays deterministic.
    result=$(_ops_eval '_hash_dir /nonexistent/absolutely/missing; echo "rc=$?"')
    [[ "$result" == *"rc=0"* ]]
    # No sha256sum lines, no error messages — the function short-circuits
    # before find runs.
    [[ "$result" != *"sha256"* ]]
    [[ "$result" != *"No such file"* ]]
}

@test "stored_hash: empty when no cache file exists" {
    # stored_hash() in ops.sh: `[ -f "$f" ] && cat "$f" || echo ""` — the
    # empty-string fallback when the per-image cache file doesn't exist.
    # Fresh XDG_CACHE_HOME guarantees no cached file.
    local fresh="$BATS_TEST_TMPDIR/fresh-cache"
    rm -rf "$fresh"
    result=$(XDG_CACHE_HOME="$fresh" _ops_eval 'stored_hash')
    [ -z "$result" ]
}

@test "save_hash: returns 1 when current_hash fails (Dockerfile missing)" {
    # current_hash returns 1 when OPS_DOCKERFILE doesn't exist; save_hash
    # uses `h=$(current_hash) || return 1`, so the failure must propagate.
    # Guards the `h=$(current_hash) || return 1` short-circuit in save_hash.
    result=$(OPS_DOCKERFILE="/absolutely/nonexistent/Dockerfile" \
             _ops_eval 'save_hash 2>/dev/null; echo "rc=$?"')
    [[ "$result" == *"rc=1"* ]]
}
