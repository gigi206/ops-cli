#!/bin/bash
# ops-cli: wrapper for the modern `nix` CLI.
#
# Unlike the legacy binaries (nix-env, nix-channel, nix-store,
# nix-collect-garbage) that are always stateful, `nix` is a multi-
# subcommand CLI where only SOME subcommands mutate the user profile
# (stored under $HOME by Nix). Blindly forcing HOME=/opt/nix-home
# for every `nix ...` would break the shared host-mounted eval/build
# cache (~/.cache/nix/) used by `nix build`, `nix shell`, `nix search`,
# etc. Here we selectively force HOME only for the subcommands that
# touch the profile or channels:
#
#   nix profile install|remove|upgrade|list|history|rollback|diff-closures
#   nix channel add|remove|update|list|rollback
#   nix registry add|remove|pin|list
#   nix upgrade-nix
#
# All other subcommands pass through transparently so the shared cache
# is preserved.
#
# Escape hatch: pass --host anywhere to force the host profile.
#
# This script lives at /opt/ops/bin/nix and shadows the real binary
# via PATH (/opt/ops/bin is first). The real binary is reached via
# absolute path to avoid recursion.

set -eu

REAL=/opt/nix-home/.nix-profile/bin/nix

if [ ! -x "$REAL" ]; then
    echo "nix: Nix binary not found at $REAL" >&2
    exit 127
fi

# Look for --host anywhere and strip it.
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
    exec "$REAL" "${filtered_args[@]}"
fi

# Detect the first positional (non-flag) argument after any global flags.
# `nix --extra-experimental-features … profile install …` should still
# trigger the stateful path. We scan the FILTERED list so `--host` does
# not get treated as the subcommand.
subcommand=""
for a in "${filtered_args[@]}"; do
    case "$a" in
        -*) continue ;;
        *) subcommand="$a"; break ;;
    esac
done

# Force HOME only for subcommands that mutate profile/channels/registry.
force_home=0
case "$subcommand" in
    profile|channel|registry|upgrade-nix) force_home=1 ;;
esac

if [ "$force_home" = 1 ]; then
    case "${HOME:-}" in
        /opt/nix-home|/opt/nix-home/*) exec "$REAL" "${filtered_args[@]}" ;;
        *) exec env HOME=/opt/nix-home "$REAL" "${filtered_args[@]}" ;;
    esac
else
    exec "$REAL" "${filtered_args[@]}"
fi
