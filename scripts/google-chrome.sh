#!/bin/bash
# ops-cli: google-chrome wrapper for rootless containers.
#
# Copied to /opt/ops/bin/google-chrome, which is prefixed to the image
# PATH so that typing `google-chrome` (or any `chrome-launcher`-based
# tool -- chrome-devtools-mcp, Puppeteer, Lighthouse) picks this up
# INSTEAD of the mise shim at /opt/mise/data/shims/google-chrome.
#
# The wrapper adds the flags required for Chrome to start inside a
# rootless Nix-backed container:
#   --no-sandbox            SUID sandbox can't work when the binary sits
#                           in read-only /nix/store with no setuid bit
#   --disable-dev-shm-usage avoids renderer crashes on small /dev/shm
# When a Wayland socket is available (auto-forwarded by `ops run`), it
# also switches Chrome to the Wayland backend so it renders on the host
# compositor.
#
# It calls the real binary from the mise install tree
# (/opt/mise/data/installs/nix-google-chrome/latest/bin/google-chrome)
# in absolute form. This avoids recursing through the PATH back into
# this wrapper and skips the mise shim (which would re-do version
# resolution we don't need). The `latest` symlink is maintained by
# mise and resolves to whatever version is currently active.
#
# The mise-nix plugin does NOT install packages into the Nix user
# profile (/opt/nix-home/.nix-profile/bin), so the profile path is not
# a reliable place to look. The mise install tree is.
#
# Useful only when `google-chrome` is actually installed (i.e.
# EXTRA_MISE_TOOLS contains `nix:google-chrome`). Otherwise the wrapper
# exits with a short explanation so the failure mode is obvious.

set -eu

CHROME_BIN=/opt/mise/data/installs/nix-google-chrome/latest/bin/google-chrome

if [ ! -x "$CHROME_BIN" ]; then
    cat >&2 <<'MSG'
google-chrome: not installed in this container.

To install it, rebuild the image with:
  ./ops.sh build --build-arg EXTRA_MISE_TOOLS=nix:google-chrome

Or declare it per-profile in ~/.config/ops/ops.conf:
  declare -A OPS_BUILD_ARGS=(
    [<image-key>]="EXTRA_MISE_TOOLS=nix:google-chrome"
  )

See the README section "Build-time tools" for details.
MSG
    exit 127
fi

args=(--no-sandbox --disable-dev-shm-usage)
if [ -n "${WAYLAND_DISPLAY:-}" ]; then
    args+=(--ozone-platform=wayland)
    # SC2054: the comma is intentional (Chrome feature-list syntax).
    args+=("--enable-features=UseOzonePlatform,WaylandWindowDecorations")
fi

exec "$CHROME_BIN" "${args[@]}" "$@"
