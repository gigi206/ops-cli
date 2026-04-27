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

# ---- back to install.sh test cases ----------------------------------------

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
