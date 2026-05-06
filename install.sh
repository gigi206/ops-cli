#!/usr/bin/env sh
# ops-cli installer.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/gigi206/ops-cli/main/install.sh | sh
#
# Override via env vars (pipe-friendly):
#   curl -fsSL .../install.sh | OPS_REF=v1.1.0 sh
#   curl -fsSL .../install.sh | OPS_REF=main sh
#   curl -fsSL .../install.sh | OPS_INSTALL_DIR=/opt/ops-cli OPS_BIN_DIR=/usr/local/bin sh
#
# Variables (all optional):
#   OPS_REF              tag (vX.Y.Z), branch, or commit SHA to check out.
#                        Default: the latest vX.Y.Z tag on the remote, or
#                        'main' if no tag exists / 'git ls-remote' is
#                        unavailable.
#   OPS_INSTALL_DIR      where the working tree lives. Default: ~/.local/share/ops-cli
#   OPS_BIN_DIR          where to drop the 'ops' symlink. Default: ~/.local/bin
#   OPS_REPO_URL         git remote (override for forks / mirrors).
#                        Default: https://github.com/gigi206/ops-cli.git
#   OPS_UNINSTALL=1      uninstall mode: remove the install dir + symlink.
#                        Preserves ~/.config/ops/ and Docker volumes.
#                        Prompts on TTY; in curl|sh use OPS_UNINSTALL_FORCE=1.
#   OPS_UNINSTALL_FORCE=1  skip the y/N prompt in uninstall mode (required
#                          when stdin is not a TTY, e.g. curl|sh).
#   OPS_CHECK=1          check mode: print 'current → target' summary and
#                        exit 0 without touching the filesystem. Compose with
#                        OPS_REF to preview a specific tag/branch.
#
# Idempotent. Re-running with a different OPS_REF upgrades/downgrades in
# place: the existing working tree is fetched + checked out, never wiped.
#
# Uninstall examples:
#   curl -fsSL .../install.sh | OPS_UNINSTALL=1 OPS_UNINSTALL_FORCE=1 sh
#   OPS_UNINSTALL=1 sh ~/.local/share/ops-cli/install.sh   # interactive prompt
#
# All logic is wrapped in 'main' and the script ends with 'main "$@"'. This
# is the standard curl|sh defensive pattern (rustup, oh-my-zsh, …): POSIX
# requires the entire function body to be parsed before invocation, so a
# truncated download — e.g. a network hiccup mid-pipe to 'sh' — fails to
# parse 'main' itself and never executes a partial install. Without the
# wrap, dash/sh streaming the script can run prefix lines while the rest
# is still in flight; we observed 'sh: <line>: [tag: not found' errors
# under exactly this scenario in dev.

main() {
    set -eu

    # ERR trap: when 'set -e' aborts on a failing command, the script
    # currently exits silently with no indication of WHICH command failed.
    # Users seeing only the partial output ("install.sh: updating …") and
    # then unrelated noise from their shell post-command hooks (mise
    # activate, direnv, starship) easily mistake the noise for the failure
    # itself. We trap EXIT and check $? so the last-command lineage is
    # visible. POSIX sh has no ERR trap, hence using EXIT + $? gating.
    _ops_install_step="initialising"
    _ops_install_done=0
    _ops_install_exit_handler() {
        _rc=$?
        if [ "$_ops_install_done" != "1" ] && [ "$_rc" -ne 0 ]; then
            printf '\ninstall.sh: aborted (exit %s) during step: %s\n' \
                "$_rc" "$_ops_install_step" >&2
            printf "install.sh: re-run with 'sh -x %s/install.sh' for verbose tracing.\n" \
                "${OPS_INSTALL_DIR:-$HOME/.local/share/ops-cli}" >&2
        fi
    }
    trap _ops_install_exit_handler EXIT

    REPO_URL="${OPS_REPO_URL:-https://github.com/gigi206/ops-cli.git}"
    INSTALL_DIR="${OPS_INSTALL_DIR:-$HOME/.local/share/ops-cli}"
    BIN_DIR="${OPS_BIN_DIR:-$HOME/.local/bin}"
    REF="${OPS_REF:-}"
    UNINSTALL="${OPS_UNINSTALL:-0}"
    UNINSTALL_FORCE="${OPS_UNINSTALL_FORCE:-0}"
    CHECK="${OPS_CHECK:-0}"

    # ---- uninstall mode ----------------------------------------------------
    #
    # Triggered by 'OPS_UNINSTALL=1'. Removes the working tree at
    # $OPS_INSTALL_DIR and the $OPS_BIN_DIR/ops symlink. Preserves
    # $HOME/.config/ops/ (user config) and Docker volumes — those are not
    # install artefacts; the user must clean them explicitly via
    # 'ops clean' BEFORE uninstall, or with 'docker volume rm' afterwards.
    #
    # Two safety gates so a misconfigured 'OPS_INSTALL_DIR=$HOME' does not
    # 'rm -rf' the user's home:
    #   1. INSTALL_DIR must be a git checkout ('.git/' present).
    #   2. INSTALL_DIR/ops.sh must exist (this is what makes the checkout
    #      look like ops-cli specifically, not just any random repo the
    #      user happened to point OPS_INSTALL_DIR at).
    #
    # A third gate handles the curl|sh non-interactive case: stdin won't
    # be a TTY, so 'read' cannot prompt — we require OPS_UNINSTALL_FORCE=1
    # to confirm in that scenario, otherwise we abort with a hint.
    if [ "$UNINSTALL" = "1" ]; then
        if [ ! -d "$INSTALL_DIR/.git" ] || [ ! -f "$INSTALL_DIR/ops.sh" ]; then
            printf "install.sh: %s does not look like an ops-cli install\n" "$INSTALL_DIR" >&2
            printf "            (missing .git/ or ops.sh). Refusing to remove.\n" >&2
            printf "            Set OPS_INSTALL_DIR if your install is elsewhere.\n" >&2
            exit 1
        fi

        if [ -t 0 ]; then
            printf "About to remove:\n"
            printf "  %s/\n" "$INSTALL_DIR"
            [ -L "$BIN_DIR/ops" ] && printf "  %s/ops (symlink)\n" "$BIN_DIR"
            printf "Continue? [y/N] "
            read -r _ans
            case "$_ans" in
                y|Y|yes|YES) ;;
                *) printf "Aborted.\n"; exit 0 ;;
            esac
        elif [ "$UNINSTALL_FORCE" != "1" ]; then
            printf "install.sh: stdin is not a TTY (running under curl|sh?).\n" >&2
            printf "            Set OPS_UNINSTALL_FORCE=1 to skip the confirmation:\n" >&2
            printf "              curl -fsSL .../install.sh | OPS_UNINSTALL=1 OPS_UNINSTALL_FORCE=1 sh\n" >&2
            exit 1
        fi

        # Only remove the symlink if it actually points at OUR ops.sh —
        # avoids clobbering an 'ops' from a different install (e.g. system
        # package, second checkout under a different OPS_INSTALL_DIR).
        if [ -L "$BIN_DIR/ops" ]; then
            _target=$(readlink "$BIN_DIR/ops")
            if [ "$_target" = "$INSTALL_DIR/ops.sh" ]; then
                rm -f "$BIN_DIR/ops"
                printf "removed: %s/ops\n" "$BIN_DIR"
            else
                printf "install.sh: %s/ops points elsewhere (%s) — leaving it alone.\n" \
                    "$BIN_DIR" "$_target" >&2
            fi
        fi

        rm -rf "$INSTALL_DIR"
        printf "removed: %s\n" "$INSTALL_DIR"

        # Tell the user what we deliberately did NOT touch so they can
        # follow up if they want a full purge. Pattern lifted from the
        # apt remove vs apt purge convention.
        printf "\n"
        printf "Preserved (remove manually if desired):\n"
        if [ -e "$HOME/.config/ops/ops.conf" ]; then
            printf "  %s\n" "$HOME/.config/ops/ops.conf"
        fi
        printf "  Docker volumes labelled ops.volume=true (mise / nix / agent state).\n"
        printf "  Run 'ops clean' BEFORE uninstall to clear them, or after via:\n"
        printf "    docker volume ls --filter label=ops.volume=true -q | xargs -r docker volume rm\n"

        exit 0
    fi

    # ---- prerequisites -----------------------------------------------------

    # 'git' is required: we install via clone+checkout (not tarball+curl) so
    # the user can 'git pull' later, and so OPS_REF can transparently
    # reference any branch/tag/SHA understood by git. Bail loudly if git is
    # missing.
    if ! command -v git >/dev/null 2>&1; then
        # Double-quoted printf format (with escaped '\$') keeps '$PATH'
        # literal in the message without tripping shellcheck SC2016 — the
        # warning is correct in general but this is precisely the case where
        # we WANT the dollar sign visible to the user.
        printf "install.sh: git is required but was not found in \$PATH.\n" >&2
        printf "            Install git first (e.g. 'sudo apt install git',\n" >&2
        printf "            'brew install git', or your distro equivalent).\n" >&2
        exit 1
    fi

    # ---- ref resolution ----------------------------------------------------

    # Pick the most recent semver-shaped tag (vX.Y.Z[-...]) when the caller
    # did not pin one. 'git ls-remote --tags --refs' skips '^{}' peel
    # entries (the refs that point to the underlying commit of an annotated
    # tag) so the result is one line per tag — no de-duplication needed.
    # 'sort -V' (version sort) handles 1.10.0 > 1.9.0 correctly; a plain
    # 'sort' would rank 1.10.0 below 1.2.0. If the network is unreachable
    # or the repo has no tags yet, fall through to 'main'.
    if [ -z "$REF" ]; then
        REF=$(git ls-remote --tags --refs "$REPO_URL" 2>/dev/null \
            | awk '{print $2}' \
            | sed 's,^refs/tags/,,' \
            | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+([.+-].*)?$' \
            | sort -V \
            | tail -n 1) || REF=""
        [ -z "$REF" ] && REF=main
    fi

    # ---- check mode --------------------------------------------------------

    # 'OPS_CHECK=1' (exposed as 'ops self-update --check') previews what an
    # update would do without touching the filesystem. We resolve the
    # current ref (if INSTALL_DIR exists as a git checkout) and the target
    # ref's commit SHA via 'git ls-remote $REPO_URL $REF', then print a
    # summary identical in shape to the post-install one — minus any
    # side-effect: no clone, no fetch, no checkout, no symlink. Exit 0
    # so check-mode composes cleanly in scripts ('if … --check; then').
    #
    # 'git ls-remote' resolves both annotated and lightweight tags, branch
    # names, and full or short commit SHAs server-side, so we don't need
    # a local checkout to look the target up. The command emits one line
    # per matching ref ('<sha>\t<refname>'); we take the first sha and
    # short it locally.
    if [ "$CHECK" = "1" ]; then
        _current="(not installed)"
        if [ -d "$INSTALL_DIR/.git" ]; then
            _current=$(git -C "$INSTALL_DIR" describe --tags --always --dirty 2>/dev/null || echo unknown)
        fi
        _target_sha=$(git ls-remote "$REPO_URL" "$REF" 2>/dev/null | awk 'NR==1 {print $1}')
        if [ -z "$_target_sha" ]; then
            # Could be a SHA passed directly that ls-remote does not echo
            # (it only matches refs, not raw SHAs). We pass it through
            # without shortening so the user sees what they asked for.
            _target_sha="$REF"
        fi
        _target_short=$(printf '%s' "$_target_sha" | cut -c1-7)

        # Decide the action label. Two signals are checked in order:
        #   1. The describe of HEAD ($_current, e.g. "v1.0.0") equals
        #      REF — strong "already at target" signal for tag inputs.
        #   2. The resolved $_target_sha matches the local HEAD SHA —
        #      catches branch / SHA inputs. (Tag inputs don't match this
        #      way: 'git ls-remote $REPO_URL v1.0.0' returns the tag-
        #      object SHA for annotated tags, not the underlying commit.)
        # Without a local fetch we can't be 100 % certain — the remote
        # ref might have moved while we slept — so this is a hint, not
        # a guarantee.
        _action="upgrade"
        [ ! -d "$INSTALL_DIR/.git" ] && _action="install (fresh clone)"
        if [ -d "$INSTALL_DIR/.git" ]; then
            _current_sha=$(git -C "$INSTALL_DIR" rev-parse HEAD 2>/dev/null || echo "")
            if [ "$_current" = "$REF" ]; then
                _action="no-op (already at target)"
            elif [ -n "$_current_sha" ] && [ "$_target_sha" = "$_current_sha" ]; then
                _action="no-op (already at target)"
            fi
        fi

        printf 'install.sh: check mode (no changes will be made)\n'
        printf '            tree:    %s\n' "$INSTALL_DIR"
        printf '            current: %s\n' "$_current"
        printf '            target:  %s (commit %s)\n' "$REF" "$_target_short"
        printf '            action:  %s\n' "$_action"
        exit 0
    fi

    # ---- install or update -------------------------------------------------

    # '_from' captures the pre-update HEAD (only set on the update path)
    # so the summary at the bottom can show "v1.0.0 → v1.2.0" instead of
    # just the destination ref. Empty on a fresh clone (no "from" makes
    # sense) and on the bail path (which exits before reaching the
    # summary anyway).
    _from=""

    if [ -d "$INSTALL_DIR/.git" ]; then
        # Update path: keep the existing tree, just fast-forward to the
        # requested ref. We do NOT 'git clean -fd' — the user may have an
        # 'ops.local.toml' or other untracked artefacts they want to keep.
        _ops_install_step="cd to install dir"
        cd "$INSTALL_DIR"
        _ops_install_step="describing current HEAD"
        _from=$(git describe --tags --always --dirty 2>/dev/null || echo unknown)
        printf 'install.sh: updating ops-cli in %s (ref: %s, current: %s)\n' \
            "$INSTALL_DIR" "$REF" "$_from"
        # Make sure the remote URL is what we expect — handles the case
        # where the user originally cloned from a fork and is now switching
        # to the canonical upstream (or vice-versa, by setting OPS_REPO_URL).
        _ops_install_step="setting remote URL to $REPO_URL"
        git remote set-url origin "$REPO_URL"
        # Fetch the requested ref by name, regardless of whether it is a
        # branch, a lightweight tag, or an annotated tag. Going through
        # FETCH_HEAD afterwards avoids two failure modes of 'git checkout
        # $REF' on a '--depth 1' clone:
        #   1. The original clone fetched only one ref (the tag we cloned),
        #      so 'main' does not exist locally as a tracking branch — a
        #      bare 'git checkout main' errors with "pathspec 'main' did
        #      not match any file(s) known to git".
        #   2. 'git fetch origin --tags' fetches tags but not arbitrary
        #      branches; switching from a tag to a branch needed the
        #      explicit '<remote> <ref>' form.
        # '--prune-tags' cleans up tags deleted upstream so a re-pushed
        # tag (rare) is not shadowed by the stale local entry. '--force'
        # accepts a server-side tag rewrite (force-pushed annotated tag)
        # silently — without it the fetch prints "[rejected] vX.Y.Z (would
        # clobber existing tag)" on stderr and, while exit code stays 0
        # locally, the LOCAL tag stays stale and would shadow the new
        # commit on a 'git checkout vX.Y.Z'. We deliberately consume that
        # rewrite when ops-cli's own release process amends a cut commit
        # to fix a CI bug (rare but happens; see git_amend pattern in
        # the project's CLAUDE.md).
        _ops_install_step="git fetch $REF (force, tags+prune)"
        git fetch --quiet --force --tags --prune --prune-tags origin "$REF"
        # '--force' discards any local edits to tracked files — the
        # working tree is treated as immutable / installer-managed.
        _ops_install_step="git checkout FETCH_HEAD"
        git checkout --quiet --force --detach FETCH_HEAD
    elif [ -e "$INSTALL_DIR" ]; then
        printf 'install.sh: %s exists but is not a git checkout. Refusing\n' "$INSTALL_DIR" >&2
        printf '            to overwrite. Move it aside or set\n' >&2
        printf '            OPS_INSTALL_DIR to a different path.\n' >&2
        exit 1
    else
        printf 'install.sh: cloning ops-cli into %s (ref: %s)\n' "$INSTALL_DIR" "$REF"
        _ops_install_step="creating parent dir of $INSTALL_DIR"
        mkdir -p "$(dirname "$INSTALL_DIR")"
        # '--depth 1 --branch $REF' works for both branch names and
        # lightweight tags. For an annotated tag, --branch + --depth 1 still
        # resolves the peel, so this branch is fine for any ref shape git
        # understands.
        _ops_install_step="git clone --depth 1 --branch $REF"
        git clone --quiet --depth 1 --branch "$REF" "$REPO_URL" "$INSTALL_DIR"
    fi

    _ops_install_step="chmod +x ops.sh"
    chmod +x "$INSTALL_DIR/ops.sh"

    # ---- symlink -----------------------------------------------------------

    _ops_install_step="creating $BIN_DIR"
    mkdir -p "$BIN_DIR"
    # 'ln -sf' overwrites an existing symlink/regular file at the target.
    # The previous installer run leaves a working symlink so the overwrite
    # is a no-op; if the user replaced it by hand, we prefer "always reflect
    # the current install" over preserving a stale value.
    _ops_install_step="symlinking $BIN_DIR/ops -> $INSTALL_DIR/ops.sh"
    ln -sf "$INSTALL_DIR/ops.sh" "$BIN_DIR/ops"

    # ---- summary -----------------------------------------------------------

    _to=$(git -C "$INSTALL_DIR" describe --tags --always 2>/dev/null || echo unknown)

    printf '\n'
    printf 'install.sh: ops-cli installed.\n'
    printf '            tree:    %s\n' "$INSTALL_DIR"
    printf '            binary:  %s -> %s/ops.sh\n' "$BIN_DIR/ops" "$INSTALL_DIR"
    # Three summary shapes:
    #   - fresh clone:           ref:     v1.2.0 (commit 050c147)
    #   - update, version moved: ref:     v1.0.0 → v1.2.0 (commit 050c147)
    #   - update, no-op:         ref:     v1.2.0 (already up to date, commit 050c147)
    # 'git describe --tags --always' returns the exact tag name when HEAD
    # is on a tag, otherwise <tag>-<count>-g<short-sha>; --always falls back
    # to the bare short SHA if no reachable tag exists at all (e.g. brand
    # new repo without releases).
    _short=$(git -C "$INSTALL_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)
    if [ -z "$_from" ]; then
        printf '            ref:     %s (commit %s)\n' "$_to" "$_short"
    elif [ "$_from" = "$_to" ]; then
        printf '            ref:     %s (already up to date, commit %s)\n' "$_to" "$_short"
    else
        printf '            ref:     %s → %s (commit %s)\n' "$_from" "$_to" "$_short"
    fi

    # Warn if BIN_DIR is not on PATH so the user does not silently fall back
    # to a different 'ops' (or none at all). 'case "$PATH" in *":$BIN_DIR:"*)'
    # catches BIN_DIR mid-PATH; the leading/trailing ':' ensures the test
    # matches the exact directory and not e.g. /usr/local/bin matching /usr.
    case ":$PATH:" in
        *":$BIN_DIR:"*) ;;
        *)
            printf '\n'
            # Double-quoted format with '\$PATH' so the literal '$PATH'
            # reaches the user. Single-quoted printf would do the same but
            # trips SC2016 on shellcheck 0.9.x (treated as a CI failure on
            # ubuntu-noble apt-installed shellcheck).
            printf "install.sh: warning — %s is not on your \$PATH.\n" "$BIN_DIR" >&2
            printf "            Add this to your shell rc file:\n" >&2
            printf "              export PATH=\"%s:\$PATH\"\n" "$BIN_DIR" >&2
            ;;
    esac

    # Final marker. _ops_install_done flips on so the EXIT trap above does
    # NOT print the "aborted at step: …" warning when the script exits 0.
    # The marker also gives users a clear visual end-of-output: any
    # subsequent error lines they see in their terminal (mise post-cmd
    # hooks, direnv reload, starship prompt errors, …) are coming from
    # their shell environment, NOT from install.sh. Pre-this-change,
    # users seeing "install.sh: …updating" followed by unrelated noise
    # often concluded "self-update is broken" when it had finished
    # successfully — see the troubleshooting note in the matching
    # CHANGELOG entry.
    _ops_install_done=1
    printf '\ninstall.sh: done.\n'
}

main "$@"
