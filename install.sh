#!/bin/sh
# Install sbx: fetch the static binary published for this machine's architecture, check it
# against the SHA-256 published beside it, and place it in a directory of the user's own.
#
#   curl -fsSL https://raw.githubusercontent.com/gigi206/ops-cli/HEAD/install.sh | sh
#
# Environment, each optional:
#   SBX_REPO           the GitHub repository sbx is released from, `owner/name` (default:
#                      gigi206/ops-cli); the two addresses below are derived from it
#   SBX_VERSION        the release tag to install (default: the newest stable release, looked up
#                      when the script runs); `latest` is the rolling pre-release built from the
#                      development branch
#   SBX_INSTALL_DIR    the absolute directory the binary goes in (default: $HOME/.local/bin)
#   SBX_DOWNLOAD_BASE  where release assets are fetched from (default: the repository's GitHub
#                      releases)
#   SBX_RELEASES_API   where the newest stable release is looked up (default: the repository's
#                      GitHub API); both accept https, or file:// for a local copy
#
# A variable reaches the script when it is set on the `sh` side of the pipe:
#   curl -fsSL …/install.sh | SBX_VERSION=v2.0.0 sh
#
# Nothing runs as root and no shell startup file is edited: when the directory is not on PATH,
# the line to add is printed instead. The checksum comes from the same release as the binary, so
# it catches a download that was corrupted or cut short, not a release that was tampered with.
#
# The whole script is one function called on its last line, so a download cut short while it is
# piped into `sh` defines nothing and runs nothing.

set -eu

REPO=${SBX_REPO:-gigi206/ops-cli}
DEFAULT_BASE="https://github.com/$REPO/releases/download"
DEFAULT_API="https://api.github.com/repos/$REPO/releases"
DOCS="https://${REPO%%/*}.github.io/${REPO#*/}/docs/getting-started/installation/"

say() {
    printf 'sbx-install: %s\n' "$*" >&2
}

die() {
    say "$*"
    exit 1
}

# The architecture name the release assets carry for this machine.
release_arch() {
    kernel=$(uname -s)
    [ "$kernel" = Linux ] || die "sbx runs on Linux, not $kernel; on macOS it runs in a \
Linux VM, see $DOCS"
    machine=$(uname -m)
    case "$machine" in
        x86_64 | amd64) echo x86_64 ;;
        aarch64 | arm64) echo aarch64 ;;
        *) die "no release is published for $machine; build sbx from source, see $DOCS" ;;
    esac
}

# Fetch $1 into the file $2. Plain http is refused, and so is a redirect to anything but https.
# The caller says what failed, since only it knows what the file was for.
fetch() {
    curl -fsSL --proto '=https,file' --proto-redir '=https' -o "$2" "$1"
}

# The tag of the newest stable release, as the releases API names it. A pre-release is never
# the answer, the rolling `latest` build included: that one is installed only when asked for.
newest_release() {
    api=${SBX_RELEASES_API:-$DEFAULT_API}
    fetch "$api/latest" "$tmp/latest.json" || die "could not look up the newest release at \
$api/latest: none is published yet, or it could not be reached. Set SBX_VERSION to a release \
tag, or to latest for the rolling pre-release build"
    sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' "$tmp/latest.json" | head -n 1
}

# Refuse a tag that is not one: the value is spliced into a URL.
check_tag() {
    case "$1" in
        '' | *[!A-Za-z0-9._-]*) die "$2 is not a release tag: '$1'" ;;
    esac
}

main() {
    # Spliced into every default address, so it is held to the shape GitHub gives one.
    case "$REPO" in
        */*/* | /* | */ | *[!A-Za-z0-9._/-]*) die "SBX_REPO must be owner/name, not '$REPO'" ;;
        */*) ;;
        *) die "SBX_REPO must be owner/name, not '$REPO'" ;;
    esac
    command -v curl >/dev/null 2>&1 || die "curl is needed to download sbx"
    command -v sha256sum >/dev/null 2>&1 || die "sha256sum is needed to check the download"

    # Every input is judged before anything is fetched.
    [ -z "${SBX_VERSION:-}" ] || check_tag "$SBX_VERSION" "SBX_VERSION"
    dir=${SBX_INSTALL_DIR:-${HOME:?HOME is not set}/.local/bin}
    case "$dir" in
        /*) ;;
        *) die "SBX_INSTALL_DIR must be an absolute path, not '$dir'" ;;
    esac
    asset="sbx-linux-$(release_arch)"

    tmp=$(mktemp -d)
    partial=""
    trap 'rm -rf "$tmp"; [ -z "$partial" ] || rm -f "$partial"' EXIT
    trap 'exit 1' HUP INT TERM

    if [ -n "${SBX_VERSION:-}" ]; then
        version=$SBX_VERSION
    else
        version=$(newest_release)
        [ -n "$version" ] || die "the releases API named no tag for the newest release"
        check_tag "$version" "the newest release's tag"
    fi
    url="${SBX_DOWNLOAD_BASE:-$DEFAULT_BASE}/$version/$asset"

    say "downloading $asset ($version)"
    fetch "$url" "$tmp/sbx" || die "could not download $url"
    fetch "$url.sha256" "$tmp/sbx.sha256" || die "could not download $url.sha256"

    expected=$(cut -d ' ' -f 1 <"$tmp/sbx.sha256" | head -n 1)
    case "$expected" in
        *[!0-9a-f]*) die "the published checksum of $asset is not a SHA-256" ;;
    esac
    [ "${#expected}" -eq 64 ] || die "the published checksum of $asset is not a SHA-256"
    actual=$(sha256sum "$tmp/sbx" | cut -d ' ' -f 1)
    [ "$actual" = "$expected" ] || die "checksum mismatch for $asset: expected $expected, got \
$actual; nothing was installed"

    # Written beside its destination and renamed over it, so the directory never holds a partial
    # binary and a running sbx keeps the file it was started from.
    mkdir -p "$dir"
    partial="$dir/.sbx.install.$$"
    cp "$tmp/sbx" "$partial"
    chmod 0755 "$partial"
    mv -f "$partial" "$dir/sbx"
    partial=""
    say "installed $("$dir/sbx" --version) at $dir/sbx"

    case ":${PATH:-}:" in
        *":$dir:"*)
            found=$(command -v sbx || true)
            [ "$found" = "$dir/sbx" ] || say "another sbx comes first on PATH: $found"
            ;;
        *)
            say "$dir is not on PATH; add it in your shell's startup file:"
            say "  export PATH=\"$dir:\$PATH\""
            ;;
    esac

    say "checking what sbx needs from this host (sbx doctor):"
    "$dir/sbx" doctor </dev/null || say "sbx is installed, but doctor reported a problem above; \
see $DOCS"
}

main "$@"
