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
#                        `main` if no tag exists / `git ls-remote` is
#                        unavailable.
#   OPS_INSTALL_DIR      where the working tree lives. Default: ~/.local/share/ops-cli
#   OPS_BIN_DIR          where to drop the `ops` symlink. Default: ~/.local/bin
#   OPS_REPO_URL         git remote (override for forks / mirrors).
#                        Default: https://github.com/gigi206/ops-cli.git
#   OPS_UNINSTALL=1      uninstall mode: remove the install dir + symlink.
#                        Preserves ~/.config/ops/ and Docker volumes.
#                        Prompts on TTY; in curl|sh use OPS_UNINSTALL_FORCE=1.
#   OPS_UNINSTALL_FORCE=1  skip the y/N prompt in uninstall mode (required
#                          when stdin is not a TTY, e.g. curl|sh).
#
# Idempotent. Re-running with a different OPS_REF upgrades/downgrades in
# place: the existing working tree is fetched + checked out, never wiped.
#
# Uninstall examples:
#   curl -fsSL .../install.sh | OPS_UNINSTALL=1 OPS_UNINSTALL_FORCE=1 sh
#   OPS_UNINSTALL=1 sh ~/.local/share/ops-cli/install.sh   # interactive prompt

set -eu

REPO_URL="${OPS_REPO_URL:-https://github.com/gigi206/ops-cli.git}"
INSTALL_DIR="${OPS_INSTALL_DIR:-$HOME/.local/share/ops-cli}"
BIN_DIR="${OPS_BIN_DIR:-$HOME/.local/bin}"
REF="${OPS_REF:-}"
UNINSTALL="${OPS_UNINSTALL:-0}"
UNINSTALL_FORCE="${OPS_UNINSTALL_FORCE:-0}"

# ---- uninstall mode --------------------------------------------------------
#
# Triggered by `OPS_UNINSTALL=1`. Removes the working tree at
# $OPS_INSTALL_DIR and the $OPS_BIN_DIR/ops symlink. Preserves
# $HOME/.config/ops/ (user config) and Docker volumes — those are not
# install artefacts; the user must clean them explicitly via
# `ops clean` BEFORE uninstall, or with `docker volume rm` afterwards.
#
# Two safety gates so a misconfigured `OPS_INSTALL_DIR=$HOME` does not
# `rm -rf` the user's home:
#   1. INSTALL_DIR must be a git checkout (`.git/` present).
#   2. INSTALL_DIR/ops.sh must exist (this is what makes the checkout
#      look like ops-cli specifically, not just any random repo the
#      user happened to point OPS_INSTALL_DIR at).
#
# A third gate handles the curl|sh non-interactive case: stdin won't
# be a TTY, so `read` cannot prompt — we require OPS_UNINSTALL_FORCE=1
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
    # avoids clobbering an `ops` from a different install (e.g. system
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
    printf "  Run \`ops clean\` BEFORE uninstall to clear them, or after via:\n"
    printf "    docker volume ls --filter label=ops.volume=true -q | xargs -r docker volume rm\n"

    exit 0
fi

# ---- prerequisites ---------------------------------------------------------

# `git` is required: we install via clone+checkout (not tarball+curl) so the
# user can `git pull` later, and so OPS_REF can transparently reference any
# branch/tag/SHA understood by git. Bail loudly if git is missing.
if ! command -v git >/dev/null 2>&1; then
    # Double-quoted printf format (with escaped `\$`) keeps `$PATH`
    # literal in the message without tripping shellcheck SC2016 — the
    # warning is correct in general but this is precisely the case where
    # we WANT the dollar sign visible to the user.
    printf "install.sh: git is required but was not found in \$PATH.\n" >&2
    printf "            Install git first (e.g. \`sudo apt install git\`,\n" >&2
    printf "            \`brew install git\`, or your distro equivalent).\n" >&2
    exit 1
fi

# ---- ref resolution --------------------------------------------------------

# Pick the most recent semver-shaped tag (vX.Y.Z[-...]) when the caller did
# not pin one. `git ls-remote --tags --refs` skips `^{}` peel entries (the
# refs that point to the underlying commit of an annotated tag) so the
# result is one line per tag — no de-duplication needed. `sort -V`
# (version sort) handles 1.10.0 > 1.9.0 correctly; a plain `sort` would
# rank 1.10.0 below 1.2.0. If the network is unreachable or the repo has
# no tags yet, fall through to `main`.
if [ -z "$REF" ]; then
    REF=$(git ls-remote --tags --refs "$REPO_URL" 2>/dev/null \
        | awk '{print $2}' \
        | sed 's,^refs/tags/,,' \
        | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+([.+-].*)?$' \
        | sort -V \
        | tail -n 1) || REF=""
    [ -z "$REF" ] && REF=main
fi

# ---- install or update ------------------------------------------------------

if [ -d "$INSTALL_DIR/.git" ]; then
    # Update path: keep the existing tree, just fast-forward to the
    # requested ref. We do NOT `git clean -fd` — the user may have an
    # `ops.local.toml` or other untracked artefacts they want to keep.
    printf 'install.sh: updating ops-cli in %s (ref: %s)\n' "$INSTALL_DIR" "$REF"
    cd "$INSTALL_DIR"
    # Make sure the remote URL is what we expect — handles the case where
    # the user originally cloned from a fork and is now switching to the
    # canonical upstream (or vice-versa, by setting OPS_REPO_URL).
    git remote set-url origin "$REPO_URL"
    # Fetch the requested ref by name, regardless of whether it is a
    # branch, a lightweight tag, or an annotated tag. Going through
    # FETCH_HEAD afterwards avoids two failure modes of `git checkout
    # $REF` on a `--depth 1` clone:
    #   1. The original clone fetched only one ref (the tag we cloned),
    #      so `main` does not exist locally as a tracking branch — a
    #      bare `git checkout main` errors with "pathspec 'main' did
    #      not match any file(s) known to git".
    #   2. `git fetch origin --tags` fetches tags but not arbitrary
    #      branches; switching from a tag to a branch needed the
    #      explicit `<remote> <ref>` form.
    # `--prune-tags` cleans up tags deleted upstream so a re-pushed
    # tag (rare) is not shadowed by the stale local entry.
    git fetch --quiet --tags --prune --prune-tags origin "$REF"
    # `--force` discards any local edits to tracked files — the
    # working tree is treated as immutable / installer-managed.
    git checkout --quiet --force --detach FETCH_HEAD
elif [ -e "$INSTALL_DIR" ]; then
    printf 'install.sh: %s exists but is not a git checkout. Refusing\n' "$INSTALL_DIR" >&2
    printf '            to overwrite. Move it aside or set\n' >&2
    printf '            OPS_INSTALL_DIR to a different path.\n' >&2
    exit 1
else
    printf 'install.sh: cloning ops-cli into %s (ref: %s)\n' "$INSTALL_DIR" "$REF"
    mkdir -p "$(dirname "$INSTALL_DIR")"
    # `--depth 1 --branch $REF` works for both branch names and lightweight
    # tags. For an annotated tag, --branch + --depth 1 still resolves the
    # peel, so this branch is fine for any ref shape git understands.
    git clone --quiet --depth 1 --branch "$REF" "$REPO_URL" "$INSTALL_DIR"
fi

chmod +x "$INSTALL_DIR/ops.sh"

# ---- symlink ---------------------------------------------------------------

mkdir -p "$BIN_DIR"
# `ln -sf` overwrites an existing symlink/regular file at the target. The
# previous installer run leaves a working symlink so the overwrite is a
# no-op; if the user replaced it by hand, we prefer "always reflect the
# current install" over preserving a stale value.
ln -sf "$INSTALL_DIR/ops.sh" "$BIN_DIR/ops"

# ---- summary ---------------------------------------------------------------

printf '\n'
printf 'install.sh: ops-cli installed.\n'
printf '            tree:    %s\n' "$INSTALL_DIR"
printf '            binary:  %s -> %s/ops.sh\n' "$BIN_DIR/ops" "$INSTALL_DIR"
printf '            ref:     %s (commit %s)\n' "$REF" \
    "$(git -C "$INSTALL_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"

# Warn if BIN_DIR is not on PATH so the user does not silently fall back
# to a different `ops` (or none at all). `case "$PATH" in *":$BIN_DIR:"*)`
# catches BIN_DIR mid-PATH; the leading/trailing `:` ensures the test
# matches the exact directory and not e.g. /usr/local/bin matching /usr.
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
        printf '\n'
        # Double-quoted format with `\$PATH` so the literal `$PATH`
        # reaches the user. Single-quoted printf would do the same but
        # trips SC2016 on shellcheck 0.9.x (treated as a CI failure on
        # ubuntu-noble apt-installed shellcheck).
        printf "install.sh: warning — %s is not on your \$PATH.\n" "$BIN_DIR" >&2
        printf "            Add this to your shell rc file:\n" >&2
        printf "              export PATH=\"%s:\$PATH\"\n" "$BIN_DIR" >&2
        ;;
esac
