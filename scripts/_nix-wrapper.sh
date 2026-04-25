#!/bin/bash
# ops-cli: generic wrapper for stateful Nix commands (`nix-env`,
# `nix-channel`, `nix-store`, `nix-collect-garbage`).
#
# Rationale: $HOME in the ops-dev container is bind-mounted from the
# host. Commands that read/write the Nix user profile (via $HOME) would
# silently touch the HOST profile instead of the container one at
# /opt/nix-home/.local/state/nix/profiles/. This wrapper forces
# HOME=/opt/nix-home so stateful operations act on the container
# profile.
#
# Each wrapped command gets a copy (or symlink) of this script under
# /opt/ops/bin/ named after the real binary. Because /opt/ops/bin is
# first in PATH (see Dockerfile), typing `nix-env`, `nix-channel`, etc.
# goes through this script. The real binary is reached via absolute
# path to avoid PATH recursion.
#
# Escape hatch: pass --host anywhere in the arguments to operate on the
# host profile instead (rarely what you want). We strip --host before
# delegating so the real binary doesn't choke on an unknown flag.
#
# NOT wrapped:
# - nix-build, nix-shell, nix-instantiate, nix-prefetch-url, and the
#   modern `nix` CLI. These use $HOME mostly for the eval/fetch cache
#   (~/.cache/nix/) which we deliberately keep bind-mounted from the
#   host for a fast shared cache.
# - When you need the modern CLI equivalents of nix-env
#   (`nix profile install/remove/upgrade`), prefix them manually:
#       HOME=/opt/nix-home nix profile install nixpkgs#ripgrep
#   or call the wrapper explicitly (see scripts/_nix-wrapper.sh).

set -eu

# Resolve which command was invoked (via $0's basename).
name=$(basename "$0")
real=/opt/nix-home/.nix-profile/bin/"$name"

if [ ! -x "$real" ]; then
    echo "$name: Nix binary not found at $real" >&2
    exit 127
fi

# Look for --host anywhere and strip it if present.
use_host=0
filtered_args=()
for arg in "$@"; do
    if [ "$arg" = "--host" ]; then
        use_host=1
    else
        filtered_args+=("$arg")
    fi
done

if [ "$use_host" = 1 ]; then
    exec "$real" "${filtered_args[@]}"
fi

# Force HOME to the container's Nix home unless already there.
# Use the filtered argv so a stray --host cannot reach the real binary even
# if the detection loop above is later extended.
case "${HOME:-}" in
    /opt/nix-home|/opt/nix-home/*) exec "$real" "${filtered_args[@]}" ;;
    *) exec env HOME=/opt/nix-home "$real" "${filtered_args[@]}" ;;
esac
