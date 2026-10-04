#!/bin/sh
# Install sbx: fetch the static binary published for this machine's architecture, check it
# against the SHA-256 published beside it, and place it in a directory of the user's own.
#
#   curl -fsSL https://raw.githubusercontent.com/gigi206/ops-cli/HEAD/install.sh | sh
#
# On macOS there is no binary to install: sbx runs in a Linux guest that Lima provides. The script
# creates that guest from the template published with the release, unless one named `sbx` exists
# already, and installs the wrapper that reaches it from a Mac shell. It also installs two launchd
# agents in ~/Library/LaunchAgents, `org.sbx.lima.theme` and `org.sbx.lima.notify`, which hand the
# Mac's light/dark preference to the guest and raise its refusals in Notification Center; each is
# removed with `launchctl bootout gui/$(id -u)/<label>` and the deletion of its plist. Lima itself
# is not installed here; the script stops and names the command when it is missing.
#
# Environment, each optional:
#   SBX_REPO           the GitHub repository sbx is released from, `owner/name` (default:
#                      gigi206/ops-cli); the addresses below are derived from it
#   SBX_VERSION        the release tag to install (default: the newest stable release, looked up
#                      when the script runs); `latest` is the rolling pre-release built from the
#                      development branch
#   SBX_INSTALL_DIR    the absolute directory the binary goes in (default: $HOME/.local/bin)
#   SBX_DOWNLOAD_BASE  where release assets are fetched from (default: the repository's GitHub
#                      releases)
#   SBX_RELEASES_API   where the newest stable release is looked up (default: the repository's
#                      GitHub API); both accept https, or file:// for a local copy
#   SBX_SOURCE_BASE    macOS only: where the Lima template and the wrapper are read from, as
#                      <base>/<tag>/dist/macos/ (default: the repository's raw files at the tag)
#   SBX_LIMA_PROJECTS  macOS only: the subtree of your home the guest can see, relative to it
#                      (default: Projects); every other part of the Mac stays out of the guest
#
# A variable reaches the script when it is set on the `sh` side of the pipe:
#   curl -fsSL …/install.sh | SBX_VERSION=v2.0.0 sh
#
# Nothing runs as root and no shell startup file is edited: when the directory is not on PATH,
# the line to add is printed instead. The checksum comes from the same release as the binary, so
# it catches a download that was corrupted or cut short, not a release that was tampered with.
# The macOS template and wrapper carry no checksum: they are read from the repository at the
# release's tag, the same origin this script is read from, and are trusted as far as it is.
#
# The whole script is one function called on its last line, so a download cut short while it is
# piped into `sh` defines nothing and runs nothing.

set -eu

REPO=${SBX_REPO:-gigi206/ops-cli}
DEFAULT_BASE="https://github.com/$REPO/releases/download"
DEFAULT_API="https://api.github.com/repos/$REPO/releases"
DEFAULT_SOURCE="https://raw.githubusercontent.com/$REPO"
DOCS="https://${REPO%%/*}.github.io/${REPO#*/}/docs/getting-started/installation/"

# The launchd agents installed on macOS, and the job each runs.
AGENT_THEME=org.sbx.lima.theme
AGENT_NOTIFY=org.sbx.lima.notify

# The Lima instance the wrapper reaches by default.
LIMA_INSTANCE=sbx

say() {
    printf 'sbx-install: %s\n' "$*" >&2
}

die() {
    say "$*"
    exit 1
}

# The architecture name the release assets carry for this machine.
release_arch() {
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

# The release tag to install: the one asked for, or the newest stable one.
resolve_version() {
    if [ -n "${SBX_VERSION:-}" ]; then
        version=$SBX_VERSION
    else
        version=$(newest_release)
        [ -n "$version" ] || die "the releases API named no tag for the newest release"
        check_tag "$version" "the newest release's tag"
    fi
}

# Place the file $1 at $dir/sbx, executable. Written beside its destination and renamed over it,
# so the directory never holds a partial file and a running sbx keeps the file it was started
# from.
place() {
    mkdir -p "$dir"
    partial="$dir/.sbx.install.$$"
    cp "$1" "$partial"
    chmod 0755 "$partial"
    mv -f "$partial" "$dir/sbx"
    partial=""
}

# Name the line to add when $dir is not on PATH, and another sbx that would shadow this one.
path_hint() {
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
}

# Run the preflight through what was just installed. Its standard input is closed, because the
# script's own is the pipe it is being read from.
run_doctor() {
    say "checking what sbx needs from this host (sbx doctor):"
    "$dir/sbx" doctor </dev/null || say "sbx is installed, but doctor reported a problem above; \
see $DOCS"
}

install_linux() {
    command -v sha256sum >/dev/null 2>&1 || die "sha256sum is needed to check the download"
    asset="sbx-linux-$(release_arch)"
    resolve_version
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

    place "$tmp/sbx"
    say "installed $("$dir/sbx" --version) at $dir/sbx"
    path_hint
    run_doctor
}

# The launchd agent `$1` running the bridge `$2` in mode `$3`, woken by the plist keys in `$4`.
#
# The bridge is the program itself, run through its own shebang, never an argument to `/bin/sh`:
# macOS lists a background item, and announces it when it is added, under the name of its
# executable, and `sh` would name nothing the user installed.
agent_plist() {
    cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$1</string>
  <key>ProgramArguments</key>
  <array><string>$2</string><string>$3</string></array>
$4
</dict>
</plist>
EOF
}

# Install the bridge from `$1` and the two agents that run it over the channels under `$2`, replacing
# any earlier copy. The theme agent runs at load, on every write to the global preferences, and
# once a minute, which also catches Auto mode changing the appearance at dusk; the notify agent runs
# whenever the queue holds a note.
install_agents() {
    share="${XDG_DATA_HOME:-$HOME/.local/share}/sbx/lima"
    mkdir -p "$share" "$HOME/Library/LaunchAgents"
    cp "$1" "$share/.sbx-bridge.$$"
    chmod 0755 "$share/.sbx-bridge.$$"
    mv -f "$share/.sbx-bridge.$$" "$share/sbx-bridge"
    if ! command -v launchctl >/dev/null 2>&1; then
        say "launchctl is not on PATH, so the theme and notification agents were not started"
        return 0
    fi
    domain="gui/$(id -u)"
    for agent in "$AGENT_THEME" "$AGENT_NOTIFY"; do
        case "$agent" in
            "$AGENT_THEME")
                mode=theme
                keys="  <key>RunAtLoad</key><true/>
  <key>StartInterval</key><integer>60</integer>
  <key>WatchPaths</key>
  <array><string>$HOME/Library/Preferences/.GlobalPreferences.plist</string></array>"
                ;;
            *)
                mode=notify
                keys="  <key>QueueDirectories</key>
  <array><string>$2/notify/queue</string></array>"
                ;;
        esac
        plist="$HOME/Library/LaunchAgents/$agent.plist"
        agent_plist "$agent" "$share/sbx-bridge" "$mode" "$keys" > "$plist"
        launchctl bootout "$domain/$agent" </dev/null >/dev/null 2>&1 || true
        launchctl bootstrap "$domain" "$plist" </dev/null \
            || say "launchd did not load $plist; the $mode channel stays off"
    done
    say "installed the launchd agents $AGENT_THEME and $AGENT_NOTIFY"
}

# macOS has no capability-bearing user namespaces, and `sbx doctor` refuses to emulate them, so
# sbx runs in a Linux guest and what is installed on the Mac is the wrapper that reaches it.
install_macos() {
    projects=${SBX_LIMA_PROJECTS:-Projects}
    # Spliced into the guest's mount, so it must name a directory under the home and nothing else.
    case "/$projects/" in
        *//* | */../* | */./* | *[!A-Za-z0-9._/-]*)
            die "SBX_LIMA_PROJECTS must be a directory relative to your home, not '$projects'" ;;
    esac
    command -v limactl >/dev/null 2>&1 || die "sbx runs on macOS inside a Linux guest that \
Lima provides, and limactl is not on PATH. Install Lima (brew install lima), then run this \
again; see $DOCS"
    resolve_version
    source="${SBX_SOURCE_BASE:-$DEFAULT_SOURCE}/$version/dist/macos"

    say "downloading the Lima template and the wrapper ($version)"
    fetch "$source/sbx.yaml" "$tmp/sbx.yaml" || die "could not download $source/sbx.yaml; \
the release $version may predate the macOS support"
    fetch "$source/sbx" "$tmp/sbx" || die "could not download $source/sbx"
    fetch "$source/sbx-bridge" "$tmp/sbx-bridge" || die "could not download $source/sbx-bridge"

    # The two channels the template mounts into the guest. Lima mounts a directory that exists, and
    # launchd watches one, so both are made before either is asked to.
    bridge_dir="$HOME/.local/state/sbx/lima"
    mkdir -p "$bridge_dir/theme" "$bridge_dir/notify/staging" "$bridge_dir/notify/queue"

    if limactl list --quiet </dev/null 2>/dev/null | grep -qx "$LIMA_INSTANCE"; then
        say "the Lima instance '$LIMA_INSTANCE' exists and is kept as it is, with the release \
and the projects directory it was created with; to recreate it, run limactl delete \
$LIMA_INSTANCE and this script again"
    else
        mkdir -p "$HOME/$projects"
        say "creating the Lima instance '$LIMA_INSTANCE', which sees ~/$projects and nothing \
else of the Mac; the first start downloads an image and provisions the guest, which takes \
a few minutes"
        limactl create --tty=false --name "$LIMA_INSTANCE" --param "projects=$projects" \
            --param "release=$version" "$tmp/sbx.yaml" </dev/null \
            || die "limactl could not create the instance '$LIMA_INSTANCE'"
        limactl start --tty=false "$LIMA_INSTANCE" </dev/null \
            || die "limactl could not start the instance '$LIMA_INSTANCE'; its logs are under \
~/.lima/$LIMA_INSTANCE"
    fi

    place "$tmp/sbx"
    say "installed the sbx wrapper at $dir/sbx; run sbx from a directory under ~/$projects"
    install_agents "$tmp/sbx-bridge" "$bridge_dir"
    path_hint
    # The wrapper refuses a directory the guest does not share, so the preflight is run from the
    # subtree. A guest kept from an earlier install may share another one, which only its creator
    # knows.
    if [ -d "$HOME/$projects" ]; then
        (cd "$HOME/$projects" && run_doctor)
    else
        say "run sbx doctor from a directory the guest shares to check it"
    fi
}

main() {
    # Spliced into every default address, so it is held to the shape GitHub gives one.
    case "$REPO" in
        */*/* | /* | */ | *[!A-Za-z0-9._/-]*) die "SBX_REPO must be owner/name, not '$REPO'" ;;
        */*) ;;
        *) die "SBX_REPO must be owner/name, not '$REPO'" ;;
    esac
    command -v curl >/dev/null 2>&1 || die "curl is needed to download sbx"

    # Every input is judged before anything is fetched.
    [ -z "${SBX_VERSION:-}" ] || check_tag "$SBX_VERSION" "SBX_VERSION"
    dir=${SBX_INSTALL_DIR:-${HOME:?HOME is not set}/.local/bin}
    case "$dir" in
        /*) ;;
        *) die "SBX_INSTALL_DIR must be an absolute path, not '$dir'" ;;
    esac
    kernel=$(uname -s)
    case "$kernel" in
        Linux | Darwin) ;;
        *) die "sbx runs on Linux, and on macOS inside a Linux guest, not on $kernel; see $DOCS" ;;
    esac

    tmp=$(mktemp -d)
    partial=""
    trap 'rm -rf "$tmp"; [ -z "$partial" ] || rm -f "$partial"' EXIT
    trap 'exit 1' HUP INT TERM

    case "$kernel" in
        Linux) install_linux ;;
        Darwin) install_macos ;;
    esac
}

main "$@"
