#!/usr/bin/env bats
# install.sh — public curl|sh installer at the repo root.
#
# Tests exercise the script's logic without hitting the network by
# pointing OPS_REPO_URL at a local bare-repo fixture built fresh in
# $BATS_TEST_TMPDIR. This makes the suite:
#   - offline (no internet, no rate-limited GitHub API),
#   - deterministic (we control the tags / branches / commits),
#   - fast (well under a second per test).
#
# Distinct file from `tests/test_install.bats`, which targets the
# `ops.sh nerdctl install` subcommand (a different installer that
# downloads and sets up nerdctl, not ops-cli itself).

load helpers

# Path to the installer under test.
installer() {
    echo "$BATS_TEST_DIRNAME/../install.sh"
}

# Build a local bare repo with two tagged commits (v1.0.0, v1.1.0)
# plus a post-tag commit on `main` so OPS_REF=main produces a different
# HEAD than OPS_REF=v1.1.0. Echoes the absolute path of the bare repo.
make_fixture_remote() {
    local work="$BATS_TEST_TMPDIR/upstream-work"
    local bare="$BATS_TEST_TMPDIR/upstream.git"
    mkdir -p "$work"
    (
        cd "$work"
        git -c init.defaultBranch=main init -q
        git config user.email test@ops.local
        git config user.name  test
        : > ops.sh
        chmod +x ops.sh
        git add ops.sh
        git -c commit.gpgsign=false commit -q -m "v1.0.0"
        git tag v1.0.0
        echo "newer" >> ops.sh
        git add ops.sh
        git -c commit.gpgsign=false commit -q -m "v1.1.0"
        git tag v1.1.0
        echo "post-release" >> ops.sh
        git add ops.sh
        git -c commit.gpgsign=false commit -q -m "post-1.1.0"
    )
    git -C "$work" clone --bare --quiet . "$bare"
    printf '%s' "$bare"
}

# Run install.sh with a controlled env. $1 = OPS_REF (empty for default
# auto-resolution). REMOTE_URL caller can pre-set to reuse a fixture.
run_installer() {
    local ref="$1"
    local remote="${REMOTE_URL:-}"
    [ -z "$remote" ] && remote=$(make_fixture_remote)
    REMOTE_URL="$remote"
    run env \
        HOME="$BATS_TEST_TMPDIR/home" \
        OPS_REPO_URL="$remote" \
        OPS_REF="$ref" \
        OPS_INSTALL_DIR="$BATS_TEST_TMPDIR/install" \
        OPS_BIN_DIR="$BATS_TEST_TMPDIR/bin" \
        sh "$(installer)"
}

# ---- happy path ------------------------------------------------------------

@test "install.sh: fresh clone with default ref picks the latest vX.Y.Z tag" {
    # No OPS_REF set → installer runs `git ls-remote --tags`, picks
    # v1.1.0 (sort -V over v1.0.0 + v1.1.0).
    run_installer ""
    assert_success
    [ -d "$BATS_TEST_TMPDIR/install/.git" ]
    [ -L "$BATS_TEST_TMPDIR/bin/ops" ]
    head=$(git -C "$BATS_TEST_TMPDIR/install" describe --tags --always)
    [[ "$head" == "v1.1.0" ]]
}

@test "install.sh: fresh clone with explicit OPS_REF=v1.0.0 checks that tag out" {
    run_installer "v1.0.0"
    assert_success
    head=$(git -C "$BATS_TEST_TMPDIR/install" describe --tags --always)
    [[ "$head" == "v1.0.0" ]]
}

@test "install.sh: fresh clone with OPS_REF=main checks main out (post-tag commit)" {
    run_installer "main"
    assert_success
    head=$(git -C "$BATS_TEST_TMPDIR/install" describe --tags --always)
    # main has a post-tag commit so describe returns "v1.1.0-1-g<short>".
    [[ "$head" == v1.1.0-1-g* ]]
}

@test "install.sh: symlink \$OPS_BIN_DIR/ops points at the installed ops.sh" {
    run_installer "v1.1.0"
    assert_success
    target=$(readlink "$BATS_TEST_TMPDIR/bin/ops")
    [[ "$target" == "$BATS_TEST_TMPDIR/install/ops.sh" ]]
}

# ---- summary output formats -----------------------------------------------

# Three shapes the installer's final summary line can take:
#   - fresh clone:           ref:     <ref> (commit <sha>)
#   - update, version moved: ref:     <from> → <to> (commit <sha>)
#   - update, no-op:         ref:     <ref> (already up to date, commit <sha>)
# These three tests lock the formats so a future refactor of the
# summary block does not silently drop the from→to indication.

@test "install.sh: fresh clone summary shows just the ref + commit" {
    run_installer "v1.0.0"
    assert_success
    [[ "$output" == *"ref:     v1.0.0 (commit "* ]]
    [[ "$output" != *"→"* ]]
    [[ "$output" != *"already up to date"* ]]
}

@test "install.sh: update summary shows from → to when the ref moved" {
    run_installer "v1.0.0"
    assert_success
    run_installer "v1.1.0"
    assert_success
    # The "current: <ref>" annotation on the entry line, plus the
    # "<from> → <to>" arrow on the summary line, both appear.
    [[ "$output" == *"current: v1.0.0"* ]]
    [[ "$output" == *"ref:     v1.0.0 → v1.1.0 (commit "* ]]
}

@test "install.sh: re-run on the same ref reports 'already up to date'" {
    run_installer "v1.1.0"
    assert_success
    run_installer "v1.1.0"
    assert_success
    [[ "$output" == *"already up to date"* ]]
    [[ "$output" != *"→"* ]]
}

# ---- update path -----------------------------------------------------------

@test "install.sh: re-run with a different OPS_REF switches in-place (no re-clone)" {
    run_installer "v1.0.0"
    assert_success
    # Drop a sentinel file in the installed tree. install.sh's update
    # path must NOT `git clean -fd` (the comment in install.sh promises
    # this), so the sentinel must survive the second run. If the script
    # ever switches to a clone-from-scratch strategy, this file
    # disappears and the test fails — the regression we want to catch.
    echo "preserve-me" > "$BATS_TEST_TMPDIR/install/.installer-sentinel"
    run_installer "v1.1.0"
    assert_success
    [[ "$output" == *"updating ops-cli"* ]]
    head=$(git -C "$BATS_TEST_TMPDIR/install" describe --tags --always)
    [[ "$head" == "v1.1.0" ]]
    [ -f "$BATS_TEST_TMPDIR/install/.installer-sentinel" ]
}

@test "install.sh: switching from a tag to main works on a depth-1 clone" {
    # Regression guard: `--depth 1 --branch v1.0.0` does not fetch
    # main, so a naive `git checkout main` fails with "pathspec did
    # not match any file(s) known to git". install.sh must `git fetch
    # origin <ref>` first and check out FETCH_HEAD.
    run_installer "v1.0.0"
    assert_success
    run_installer "main"
    assert_success
    head=$(git -C "$BATS_TEST_TMPDIR/install" describe --tags --always)
    [[ "$head" == v1.1.0-1-g* ]]
}

@test "install.sh: update path realigns origin URL when OPS_REPO_URL changes" {
    # Install once from one URL, then re-run from a renamed copy of the
    # same fixture. The installer must `git remote set-url origin` so
    # subsequent fetches go to the new URL.
    run_installer "v1.0.0"
    assert_success
    cp -a "$BATS_TEST_TMPDIR/upstream.git" "$BATS_TEST_TMPDIR/upstream-renamed.git"
    REMOTE_URL="$BATS_TEST_TMPDIR/upstream-renamed.git" run_installer "v1.1.0"
    assert_success
    actual=$(git -C "$BATS_TEST_TMPDIR/install" remote get-url origin)
    [[ "$actual" == "$BATS_TEST_TMPDIR/upstream-renamed.git" ]]
}

# ---- symlink + PATH warning ------------------------------------------------

@test "install.sh: warns when OPS_BIN_DIR is not on \$PATH" {
    # The fixture HOME is empty so $OPS_BIN_DIR (under tmpdir) is not on
    # the inherited PATH. The case statement must trip and emit the
    # warning + the export PATH= snippet.
    run_installer "v1.1.0"
    assert_success
    [[ "$output" == *"is not on your \$PATH"* ]]
    [[ "$output" == *"export PATH="* ]]
}

@test "install.sh: stays silent on the PATH warning when BIN_DIR IS on PATH" {
    # Prepend OPS_BIN_DIR to $PATH so the case statement short-circuits
    # before the warning printf.
    bin_dir="$BATS_TEST_TMPDIR/bin"
    PATH="$bin_dir:$PATH" run_installer "v1.1.0"
    assert_success
    [[ "$output" != *"is not on your"* ]]
}

# ---- failure modes ---------------------------------------------------------

@test "install.sh: refuses to overwrite a non-git directory at OPS_INSTALL_DIR" {
    mkdir -p "$BATS_TEST_TMPDIR/install"
    echo "important" > "$BATS_TEST_TMPDIR/install/keepme"
    run_installer "v1.1.0"
    [ "$status" -ne 0 ]
    [[ "$output" == *"is not a git checkout"* ]]
    # The pre-existing file must be preserved (no destructive side
    # effects on the bail path).
    [ -f "$BATS_TEST_TMPDIR/install/keepme" ]
}

@test "install.sh: surfaces a clear error on an unknown ref" {
    run_installer "v999.999.999"
    [ "$status" -ne 0 ]
    # git's own error message is informative; we only check that
    # install.sh did not swallow it silently.
    [[ "$output" == *"v999.999.999"* ]]
}

# ---- uninstall mode (OPS_UNINSTALL=1) -------------------------------------

# Helper: install fresh from the fixture, then return paths in env vars
# the test can use. The uninstall flow needs an existing install to
# operate on, so we build one each time inside $BATS_TEST_TMPDIR.
prepare_install() {
    REMOTE_URL=$(make_fixture_remote)
    env \
        HOME="$BATS_TEST_TMPDIR/home" \
        OPS_REPO_URL="$REMOTE_URL" \
        OPS_REF="v1.1.0" \
        OPS_INSTALL_DIR="$BATS_TEST_TMPDIR/install" \
        OPS_BIN_DIR="$BATS_TEST_TMPDIR/bin" \
        sh "$(installer)" >/dev/null
    [ -d "$BATS_TEST_TMPDIR/install/.git" ] || return 1
    [ -L "$BATS_TEST_TMPDIR/bin/ops" ] || return 1
}

@test "install.sh: uninstall removes install dir + symlink (FORCE for non-TTY)" {
    prepare_install
    run env \
        HOME="$BATS_TEST_TMPDIR/home" \
        OPS_UNINSTALL=1 \
        OPS_UNINSTALL_FORCE=1 \
        OPS_INSTALL_DIR="$BATS_TEST_TMPDIR/install" \
        OPS_BIN_DIR="$BATS_TEST_TMPDIR/bin" \
        sh "$(installer)" </dev/null
    assert_success
    [[ "$output" == *"removed:"* ]]
    [ ! -e "$BATS_TEST_TMPDIR/install" ]
    [ ! -e "$BATS_TEST_TMPDIR/bin/ops" ]
}

@test "install.sh: uninstall refuses when OPS_INSTALL_DIR is not a git checkout" {
    # Critical safety gate — a misconfigured OPS_INSTALL_DIR pointing at
    # $HOME or anywhere else MUST NOT be wiped. The script must check
    # for both .git/ and ops.sh inside it.
    mkdir -p "$BATS_TEST_TMPDIR/random-dir"
    echo "important" > "$BATS_TEST_TMPDIR/random-dir/keepme"
    run env \
        OPS_UNINSTALL=1 \
        OPS_UNINSTALL_FORCE=1 \
        OPS_INSTALL_DIR="$BATS_TEST_TMPDIR/random-dir" \
        OPS_BIN_DIR="$BATS_TEST_TMPDIR/bin" \
        sh "$(installer)" </dev/null
    [ "$status" -ne 0 ]
    [[ "$output" == *"does not look like an ops-cli install"* ]]
    # Pre-existing file must still be there.
    [ -f "$BATS_TEST_TMPDIR/random-dir/keepme" ]
}

@test "install.sh: uninstall refuses a git checkout that lacks ops.sh" {
    # Git checkout exists, but no ops.sh — could be any random repo the
    # user pointed OPS_INSTALL_DIR at. Refuse.
    mkdir -p "$BATS_TEST_TMPDIR/wrong-repo"
    git -c init.defaultBranch=main init -q "$BATS_TEST_TMPDIR/wrong-repo"
    run env \
        OPS_UNINSTALL=1 \
        OPS_UNINSTALL_FORCE=1 \
        OPS_INSTALL_DIR="$BATS_TEST_TMPDIR/wrong-repo" \
        OPS_BIN_DIR="$BATS_TEST_TMPDIR/bin" \
        sh "$(installer)" </dev/null
    [ "$status" -ne 0 ]
    [[ "$output" == *"does not look like an ops-cli install"* ]]
    [ -d "$BATS_TEST_TMPDIR/wrong-repo/.git" ]
}

@test "install.sh: uninstall refuses non-TTY stdin without OPS_UNINSTALL_FORCE" {
    prepare_install
    run env \
        HOME="$BATS_TEST_TMPDIR/home" \
        OPS_UNINSTALL=1 \
        OPS_INSTALL_DIR="$BATS_TEST_TMPDIR/install" \
        OPS_BIN_DIR="$BATS_TEST_TMPDIR/bin" \
        sh "$(installer)" </dev/null
    [ "$status" -ne 0 ]
    [[ "$output" == *"stdin is not a TTY"* ]]
    [[ "$output" == *"OPS_UNINSTALL_FORCE=1"* ]]
    # Install should be untouched.
    [ -d "$BATS_TEST_TMPDIR/install/.git" ]
    [ -L "$BATS_TEST_TMPDIR/bin/ops" ]
}

@test "install.sh: uninstall does NOT remove a foreign \$BIN_DIR/ops symlink" {
    # Edge case: user has another `ops` symlink in BIN_DIR pointing
    # ELSEWHERE (e.g. a system-wide install). The uninstaller must NOT
    # clobber it just because the name matches.
    prepare_install
    # Replace the symlink with one pointing somewhere else.
    rm -f "$BATS_TEST_TMPDIR/bin/ops"
    ln -s "$BATS_TEST_TMPDIR/foreign-ops" "$BATS_TEST_TMPDIR/bin/ops"
    run env \
        HOME="$BATS_TEST_TMPDIR/home" \
        OPS_UNINSTALL=1 \
        OPS_UNINSTALL_FORCE=1 \
        OPS_INSTALL_DIR="$BATS_TEST_TMPDIR/install" \
        OPS_BIN_DIR="$BATS_TEST_TMPDIR/bin" \
        sh "$(installer)" </dev/null
    assert_success
    [[ "$output" == *"points elsewhere"* ]]
    # Install dir gone, foreign symlink kept.
    [ ! -e "$BATS_TEST_TMPDIR/install" ]
    [ -L "$BATS_TEST_TMPDIR/bin/ops" ]
}

@test "install.sh: uninstall preserves \$HOME/.config/ops/ops.conf" {
    prepare_install
    mkdir -p "$BATS_TEST_TMPDIR/home/.config/ops"
    echo "OPS_RUNTIME=docker" > "$BATS_TEST_TMPDIR/home/.config/ops/ops.conf"
    run env \
        HOME="$BATS_TEST_TMPDIR/home" \
        OPS_UNINSTALL=1 \
        OPS_UNINSTALL_FORCE=1 \
        OPS_INSTALL_DIR="$BATS_TEST_TMPDIR/install" \
        OPS_BIN_DIR="$BATS_TEST_TMPDIR/bin" \
        sh "$(installer)" </dev/null
    assert_success
    # Config file must still be there + mentioned in the "Preserved" list.
    [ -f "$BATS_TEST_TMPDIR/home/.config/ops/ops.conf" ]
    [[ "$output" == *"Preserved"* ]]
    [[ "$output" == *"ops.conf"* ]]
}

# ---- ops self-update (top-level wrapper around install.sh) ----------------

# Build a fake ops-cli checkout so we can exercise `ops self-update`
# without touching the real repo. Each test gets its own fresh
# checkout under $BATS_TEST_TMPDIR; the stub install.sh inside lets
# us assert what env vars `cmd_update_self` exports before re-exec.

@test "ops self-update --help prints its dedicated help block" {
    run env "$(ops_sh)" self-update --help
    assert_success
    [[ "$output" == *"self-update"* ]]
    [[ "$output" == *"REF"* ]]
    [[ "$output" == *"latest"* ]]
}

@test "ops self-update refuses when SCRIPT_DIR is not a git checkout" {
    # Copy ops.sh into a non-git directory. cmd_update_self must
    # refuse and surface the reinstall hint — never silently try to
    # repair a manually-copied install.
    local fake="$BATS_TEST_TMPDIR/non-git"
    mkdir -p "$fake"
    cp "$(ops_sh)" "$fake/ops.sh"
    chmod +x "$fake/ops.sh"
    run env "$fake/ops.sh" self-update
    [ "$status" -ne 0 ]
    [[ "$output" == *"not a git checkout"* ]]
    [[ "$output" == *"install.sh"* ]]
}

@test "ops self-update refuses when install.sh is missing from the checkout" {
    # Synthesize a git checkout that contains ops.sh but no
    # install.sh — mimics a clone made before the installer existed.
    local fake="$BATS_TEST_TMPDIR/git-no-installer"
    mkdir -p "$fake"
    git -c init.defaultBranch=main init -q "$fake"
    cp "$(ops_sh)" "$fake/ops.sh"
    chmod +x "$fake/ops.sh"
    run env "$fake/ops.sh" self-update
    [ "$status" -ne 0 ]
    [[ "$output" == *"install.sh"* ]]
    [[ "$output" == *"missing"* ]]
}

@test "ops self-update re-execs install.sh with OPS_REF and OPS_INSTALL_DIR" {
    # Stub install.sh that just echoes its env so we can assert what
    # cmd_update_self handed off. Exec semantics mean the stub's
    # output IS the test's stdout.
    local fake="$BATS_TEST_TMPDIR/git-with-stub"
    mkdir -p "$fake"
    git -c init.defaultBranch=main init -q "$fake"
    cp "$(ops_sh)" "$fake/ops.sh"
    chmod +x "$fake/ops.sh"
    cat > "$fake/install.sh" <<'STUB'
#!/usr/bin/env sh
echo "STUB_INSTALL_RAN"
echo "OPS_REF=${OPS_REF}"
echo "OPS_INSTALL_DIR=${OPS_INSTALL_DIR}"
STUB
    chmod +x "$fake/install.sh"
    run env "$fake/ops.sh" self-update v1.0.0
    assert_success
    [[ "$output" == *"STUB_INSTALL_RAN"* ]]
    [[ "$output" == *"OPS_REF=v1.0.0"* ]]
    [[ "$output" == *"OPS_INSTALL_DIR=$fake"* ]]
}

@test "ops self-update with no arg leaves OPS_REF empty (installer auto-resolves)" {
    local fake="$BATS_TEST_TMPDIR/git-with-stub-noarg"
    mkdir -p "$fake"
    git -c init.defaultBranch=main init -q "$fake"
    cp "$(ops_sh)" "$fake/ops.sh"
    chmod +x "$fake/ops.sh"
    cat > "$fake/install.sh" <<'STUB'
#!/usr/bin/env sh
echo "OPS_REF=[${OPS_REF}]"
STUB
    chmod +x "$fake/install.sh"
    run env "$fake/ops.sh" self-update
    assert_success
    # OPS_REF must be the empty string (not the literal `${OPS_REF:-}`
    # nor a default like "main") so install.sh's own auto-resolution
    # logic kicks in and picks the latest vX.Y.Z tag.
    [[ "$output" == *"OPS_REF=[]"* ]]
}

# Helper for the dirty-working-tree tests below: build a fake checkout
# whose ops.sh is the real one (so cmd_update_self runs), commit it,
# THEN modify a tracked file so the working tree is dirty.
make_dirty_checkout() {
    local dir="$1"
    mkdir -p "$dir"
    git -c init.defaultBranch=main init -q "$dir"
    git -C "$dir" config user.email test@ops.local
    git -C "$dir" config user.name  test
    cp "$(ops_sh)" "$dir/ops.sh"
    chmod +x "$dir/ops.sh"
    cat > "$dir/install.sh" <<'STUB'
#!/usr/bin/env sh
echo "STUB_INSTALL_RAN"
STUB
    chmod +x "$dir/install.sh"
    git -C "$dir" add ops.sh install.sh
    git -C "$dir" -c commit.gpgsign=false commit -q -m "init"
    # Now make the working tree dirty by editing the tracked file.
    echo "# local edit" >> "$dir/ops.sh"
}

@test "ops self-update refuses when working tree has uncommitted changes" {
    # Without --force, the safety net fires: install.sh's
    # `git checkout --force` would discard the local ops.sh edit.
    local fake="$BATS_TEST_TMPDIR/dirty-tree"
    make_dirty_checkout "$fake"
    run env "$fake/ops.sh" self-update
    [ "$status" -ne 0 ]
    [[ "$output" == *"uncommitted changes"* ]]
    [[ "$output" == *"--force"* ]]
    [[ "$output" == *"ops.sh"* ]]
    # The dirty file must still be there, untouched.
    grep -q "# local edit" "$fake/ops.sh"
}

@test "ops self-update --force bypasses the dirty-working-tree check" {
    local fake="$BATS_TEST_TMPDIR/dirty-tree-force"
    make_dirty_checkout "$fake"
    run env "$fake/ops.sh" self-update --force
    assert_success
    # The stub install.sh ran, meaning the safety net was bypassed.
    [[ "$output" == *"STUB_INSTALL_RAN"* ]]
}

@test "ops self-update -f is the short form of --force" {
    local fake="$BATS_TEST_TMPDIR/dirty-tree-short-f"
    make_dirty_checkout "$fake"
    run env "$fake/ops.sh" self-update -f
    assert_success
    [[ "$output" == *"STUB_INSTALL_RAN"* ]]
}

@test "ops self-update --force REF combines flag + ref correctly" {
    # Order matters: `--force` must precede REF in the argv parser.
    # The test verifies both are honoured: REF is propagated to the
    # stub install.sh AND the safety net is bypassed.
    local fake="$BATS_TEST_TMPDIR/dirty-tree-force-ref"
    make_dirty_checkout "$fake"
    cat > "$fake/install.sh" <<'STUB'
#!/usr/bin/env sh
echo "STUB_RAN_WITH_REF=${OPS_REF}"
STUB
    chmod +x "$fake/install.sh"
    run env "$fake/ops.sh" self-update --force v1.0.0
    assert_success
    [[ "$output" == *"STUB_RAN_WITH_REF=v1.0.0"* ]]
}

@test "ops self-update rejects unknown flags" {
    local fake="$BATS_TEST_TMPDIR/unknown-flag"
    mkdir -p "$fake"
    git -c init.defaultBranch=main init -q "$fake"
    cp "$(ops_sh)" "$fake/ops.sh"
    chmod +x "$fake/ops.sh"
    : > "$fake/install.sh"
    chmod +x "$fake/install.sh"
    run env "$fake/ops.sh" self-update --not-a-real-flag
    [ "$status" -ne 0 ]
    [[ "$output" == *"unknown flag"* ]]
}

# ---- back to install.sh test cases ----------------------------------------

@test "install.sh: wraps logic in main() called via 'main \"\$@\"' at end-of-file" {
    # Defensive curl|sh pattern: the entire body must be wrapped in
    # `main() { ... }` and invoked with `main "$@"` at the very end of
    # the file. POSIX requires the function body to be parsed before
    # invocation, so a truncated download (network hiccup mid-pipe to
    # `sh`) fails to parse `main` itself and never executes a partial
    # install. Without the wrap, we observed `sh: <line>: [tag: not
    # found` errors when dash streamed prefix lines while the rest of
    # the file was still in flight.
    local installer
    installer="$(installer)"
    # 1. main() function definition is present, with a body.
    grep -qE '^main\(\)[[:space:]]*\{' "$installer"
    # 2. Last non-blank, non-comment line is the invocation.
    last_real_line=$(grep -vE '^[[:space:]]*(#|$)' "$installer" | tail -n 1)
    [[ "$last_real_line" == 'main "$@"' ]]
}

@test "install.sh: parses cleanly when the body is truncated mid-fetch" {
    # Simulate a curl|sh truncation by piping only the prefix of the file
    # into sh. Without the main() wrap, dash would try to execute prefix
    # lines and abort partway through. With the wrap, parsing the
    # incomplete `main() {` block fails the parser BEFORE any logic
    # runs — no partial install. Either no output at all (preferred) or
    # only a parse error mentioning the unfinished function. We don't
    # assert which: the regression we care about is "no real install
    # logic executed". Look for lack of "ops-cli installed" /
    # "updating ops-cli" / "cloning ops-cli" markers.
    local installer
    installer="$(installer)"
    # Cut to ~halfway through the file (well into main()'s body).
    local size
    size=$(wc -c < "$installer")
    local half=$((size / 2))
    run sh -c "head -c $half '$installer' | sh"
    # The truncated body must NOT have triggered any real install
    # action. Any output containing those phrases means logic ran.
    [[ "$output" != *"ops-cli installed"* ]]
    [[ "$output" != *"updating ops-cli"* ]]
    [[ "$output" != *"cloning ops-cli"* ]]
}

@test "install.sh: bails early when git is missing from \$PATH" {
    # Build a tmpdir containing every standard utility install.sh needs
    # (sh, env, mkdir, printf, ln, awk, sed, grep, sort, tail, dirname,
    # chmod, cd) but explicitly NOT git. Symlink rather than copy so we
    # don't carry whole binaries around. install.sh's `command -v git`
    # check must trip and emit the "git is required" message.
    local stub="$BATS_TEST_TMPDIR/no-git-bin"
    mkdir -p "$stub"
    for util in sh env mkdir printf ln awk sed grep sort tail dirname chmod cd; do
        bin=$(command -v "$util" 2>/dev/null) || continue
        ln -sf "$bin" "$stub/$util"
    done
    run env -i \
        HOME="$BATS_TEST_TMPDIR/home" \
        PATH="$stub" \
        OPS_INSTALL_DIR="$BATS_TEST_TMPDIR/install" \
        OPS_BIN_DIR="$BATS_TEST_TMPDIR/bin" \
        "$stub/sh" "$(installer)"
    [ "$status" -ne 0 ]
    [[ "$output" == *"git is required"* ]]
}
