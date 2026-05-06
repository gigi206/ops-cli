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
set -o pipefail

# Points at the image-baked static nix binary in /opt/ops/lib/, NOT the
# dynamic one in /nix/store. Rationale: /nix is a runtime volume mount
# that can mask the image's /nix/store contents when the volume was
# created against a different image — /opt/ops/lib/ is image-resident
# and never masked. See Dockerfile §3b.
#
# We point at the `nix` SYMLINK (which targets nix-static) so that after
# `exec`, the binary sees argv[0] = ".../nix" and its busybox-style
# dispatch keeps `--version` reporting "nix (Nix) X.Y.Z" rather than
# "nix-static (Nix) X.Y.Z" (which would surprise downstream tooling
# that greps the version output).
REAL=/opt/ops/lib/nix

if [ ! -x "$REAL" ]; then
    echo "nix: static binary missing at $REAL — rebuild the image" >&2
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
#
# Bug pre-fix: the previous one-line "first non-flag wins" loop treated
# the VALUE of multi-arg globals as the subcommand. `nix --option
# allow-import-from-derivation true profile install …` saw `true` first
# and decided NOT to force HOME — rendering the wrapper a no-op for any
# user who set a global option. Now we explicitly skip the values of:
#   --option K V                       (2 values)
#   --arg / --argstr name expr         (2 values)
#   --include / -I / --store / etc.    (1 value)
# Anything else starting with `-` is treated as a flag with no value;
# unknown future globals will at worst yield a benign "no force_home"
# decision (the real binary then handles the args correctly).
subcommand=""
i=0
n=${#filtered_args[@]}
while [ "$i" -lt "$n" ]; do
    a="${filtered_args[$i]}"
    case "$a" in
        # 2-value globals: --option K V, --arg name expr, --argstr name str.
        --option|--arg|--argstr)
            i=$((i + 3))
            ;;
        # 1-value globals (path, URL, integer, identifier).
        # Sources for the list (`nix --help` common-options + flake options):
        #   evaluation:    --inputs-from FLAKE
        #                  --override-flake REF FLAKE         (2 values — handled below)
        #                  --override-input REF FLAKE         (2 values — handled below)
        #                  --update-input REF                 (1 value)
        #                  --eval-store URL
        #   substituters:  --store URL, --substituters URLS,
        #                  --trusted-public-keys KEYS, --trusted-substituters URLS
        #   exec:          --max-jobs N (-j), --cores N, --system SYSTEM,
        #                  --builders SPEC
        #   misc:          --include PATH (-I), --log-format raw,
        #                  --add-root PATH, --profile PATH,
        #                  --extra-experimental-features FEATURES,
        #                  --experimental-features FEATURES,
        #                  --extra-substituters URLS, --extra-trusted-public-keys KEYS,
        #                  --extra-trusted-substituters URLS, --extra-sandbox-paths PATHS
        --include|-I|--store|--log-format|--max-jobs|-j|--cores|--builders|--system|\
        --substituters|--trusted-public-keys|--trusted-substituters|\
        --extra-substituters|--extra-trusted-public-keys|--extra-trusted-substituters|\
        --extra-sandbox-paths|\
        --add-root|--profile|\
        --extra-experimental-features|--experimental-features|\
        --inputs-from|--update-input|--eval-store)
            i=$((i + 2))
            ;;
        # 2-value flake-input overrides: name + ref/flake.
        --override-flake|--override-input)
            i=$((i + 3))
            ;;
        -*)
            # Bare flag with no value (or an unknown one). Worst case for
            # an unknown future global with a value: we'd treat its value
            # as the subcommand and pass through without forcing HOME —
            # benign degradation, the real binary still parses correctly.
            i=$((i + 1))
            ;;
        *)
            subcommand="$a"
            break
            ;;
    esac
done

# Force HOME only for subcommands that mutate profile/channels/registry.
# Whitelist the known mutating subcommands rather than relying on a
# negative match — a future `nix mutate-something-new` should default to
# pass-through rather than silently rewriting HOME.
#
# Whitelist last reviewed against `nix --help` from Nix 2.21. When a new
# stateful subcommand lands upstream (rare; current set has been stable
# since 2.5), append it here and bump the version note.
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
