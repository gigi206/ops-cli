# syntax=docker/dockerfile:1.6
#
# ops-dev — Arch-based dev container image used by ops.sh.
# Ships: mise + Nix (packages via the merged mise-nix plugin, flake.nix env
# activation) + base dev tools (git, semgrep, gh, ripgrep, jq, ast-grep,
# node@lts). CLI agents (claude-code, gemini-cli, opencode, codex) are NOT
# baked — they are installed on demand by ops.sh when you pass --claude /
# --gemini / --opencode / --codex, and persist in the ops-share-mise volume.
# mise handles both Nix package installation (nix:pkg@ver) and flake.nix
# dev-shell activation; no other package manager is involved.
#
# Build args:
#   USER_UID=$(id -u) USER_GID=$(id -g) USER_NAME=$(id -un)   match host user to avoid
#                                                              file-ownership headaches
#                                                              on bind-mounted workspaces
#   USER_LANG=${LANG:-en_US.UTF-8}                             locale compiled at build time
#   NIX_CLEANUP=true|false                                     run `nix-collect-garbage -d`
#                                                              at the end of the tooling
#                                                              layer (default: true — shaves
#                                                              ~200 MB off the image)
#   EXTRA_MISE_TOOLS="nix:<pkg> ..."                           extra tools baked into the image
#                                                              on top of the baseline set.
#                                                              Default: nix:google-chrome
#                                                              (needed by chrome-devtools MCP,
#                                                              officially supported browser).
#                                                              Set to "" to skip — saves ~300 MB.
#                                                              Configure per profile via
#                                                              OPS_BUILD_ARGS in ops.conf.
#
# Build secret (passed only in-process, never baked into image layers):
#   --secret id=github_token,env=GITHUB_TOKEN                  classic PAT, no scope — lifts
#                                                              GitHub API rate limit during Nix
#                                                              resolution (60 → 5000 req/h).
#                                                              Read at build time from
#                                                              /run/secrets/github_token if set.
#
# Build (recommended, via ops.sh):
#   ./ops.sh build
# Or directly:
#   nerdctl build -t ops-dev \
#     --build-arg USER_UID=$(id -u) --build-arg USER_GID=$(id -g) \
#     --build-arg USER_NAME=$(id -un) \
#     --build-arg USER_LANG=${LANG:-en_US.UTF-8} \
#     .
#
# ─────────────────────────────────────────────────────────────────────────────
# KEEP IN SYNC WITH Dockerfile.debian
# ─────────────────────────────────────────────────────────────────────────────
# This Dockerfile and Dockerfile.debian share ~80 % of their structure
# (ENV, USER setup, Nix install, mise install + tools, bashrc, wrappers).
# Any change to the Arch image that touches one of those sections MUST be
# mirrored in Dockerfile.debian (and vice versa). The CI `image-integration`
# job only exercises the Arch image; silent drift between the two is the
# most common regression vector. Sections 2, 3, 4, 5, 6 are the
# high-overlap ones — look for matching numbered headers in the Debian file.

FROM archlinux:base

# Enable `pipefail` for every RUN so piped commands fail loudly instead of
# silently ignoring the producer's exit code (hadolint DL4006).
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Standard OCI labels — read by Docker Hub / GHCR / Podman Desktop / `image
# inspect`. `ops.dockerfile` (set at build time by ops.sh, not here) carries
# the wrapper-specific info; these annotations cover the registry-standard
# fields. Values with ${VAR} come from ARGs declared below FROM so BuildKit
# substitutes them at build time without affecting the image layers.
LABEL org.opencontainers.image.title="ops-dev" \
      org.opencontainers.image.description="Containerized development environment with mise + Nix + AI CLI agents (Claude Code, Gemini, OpenCode, Codex). Arch Linux base." \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.authors="Ghislain LE MEUR"

ARG USER_UID=1000
ARG USER_GID=1000
ARG USER_NAME=dev
ARG USER_LANG=en_US.UTF-8
ARG NIX_CLEANUP=true
# Nix and mise installers are fetched from their upstream "latest" endpoints
# (nixos.org/nix/install, mise.run). Each installer verifies its own binary
# payload internally; HTTPS + upstream mirror trust is the only hop we rely
# on at this layer. MISE_INSTALL_SHA256 remains an optional pin for the mise
# bootstrap shim — useful in locked-down CI setups that mirror a specific
# snapshot of the installer.
ARG MISE_INSTALL_SHA256=

# Extra tools installed on top of the baseline `mise use -g` set. Value is a
# whitespace-separated list of mise tool specs (e.g. "nix:chromium nix:ngrok").
# Default installs Google Chrome via nixhub so the chrome-devtools MCP server
# works out of the box (officially supported browser per the MCP docs). Pass
# --build-arg EXTRA_MISE_TOOLS="" to skip (saves ~300 MB), or set
# OPS_BUILD_ARGS[<image-key>]="EXTRA_MISE_TOOLS=..." in ops.conf to override
# per profile. `chrome-for-testing` is intentionally NOT used: it is not
# packaged in nixpkgs at the moment (only `chromium`, `ungoogled-chromium`
# and `google-chrome` are). `google-chrome` is unfree; the ENV block above
# already sets NIXPKGS_ALLOW_UNFREE=1 + MISE_NIX_ALLOW_UNFREE=true so the
# build goes through without extra flags.
ARG EXTRA_MISE_TOOLS="nix:google-chrome"

# OCI image metadata (https://github.com/opencontainers/image-spec/blob/main/annotations.md).
# Only SOURCE_URL is exposed: it lets `docker inspect` consumers walk back to
# the project's homepage. `version` was dropped because it duplicated
# OPS_VERSION (already returned by `ops --version`) and `revision` because it
# was empty unless CI explicitly stamped it. Override SOURCE_URL at build
# time with --build-arg for forks / vendor builds, or set OPS_SOURCE_URL=""
# to suppress the labels entirely.
ARG SOURCE_URL="https://github.com/gigi206/ops-cli"

# Second LABEL block: references the ARG above (required to be declared
# BEFORE any LABEL that expands ${VAR}). Empty ARG results in empty label
# values — acceptable per the OCI spec, and trivially filtered out by
# consumers.
LABEL org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.url="${SOURCE_URL}" \
      org.opencontainers.image.documentation="${SOURCE_URL}"

# -----------------------------------------------------------------------------
# 1. System packages + locales
# -----------------------------------------------------------------------------
# archlinux:base strips locale data via NoExtract rules in /etc/pacman.conf
# (usr/share/i18n/* and usr/share/locale/* — only en_* / C / POSIX kept).
# We drop those rules, then reinstall glibc WITHOUT --needed so all locale
# source files get re-extracted, allowing locale-gen to compile USER_LANG.
RUN sed -i '/^NoExtract/d' /etc/pacman.conf \
 && pacman -Syu --noconfirm --needed \
      bash-completion ca-certificates curl sudo which \
 && pacman -S --noconfirm glibc \
 && sed -i "/${USER_LANG}/s/^# *//" /etc/locale.gen \
 && locale-gen \
 && tr -d '-' < /proc/sys/kernel/random/uuid > /etc/machine-id \
 && pacman -Scc --noconfirm \
 && rm -rf /var/cache/pacman/pkg/*
# /etc/machine-id: Chrome (and anything DBus-based) expects a 32-char hex
# machine-id. archlinux:base ships an empty file, which triggers a startup
# warning ("contains 0 characters (32 were expected)"). We populate it at
# build time from /proc/sys/kernel/random/uuid (stripped of dashes → 32
# hex chars) so Chrome boots clean.

ENV LANG=${USER_LANG} \
    LC_ALL=${USER_LANG} \
    TERM=xterm-256color \
    MISE_EXPERIMENTAL=true \
    MISE_NIX_ALLOW_UNFREE=true \
    NIXPKGS_ALLOW_UNFREE=1 \
    MISE_INSTALL_PATH=/opt/mise/bin/mise \
    MISE_DATA_DIR=/opt/mise/data \
    MISE_CACHE_DIR=/opt/mise/cache \
    MISE_CONFIG_DIR=/opt/mise/data/config \
    MISE_STATE_DIR=/opt/mise/state
# MISE_CONFIG_DIR sits under MISE_DATA_DIR (and thus inside the
# ops-share-mise volume) so that `mise use -g` run inside the container
# writes to a persistent path: `ops run --claude`, `mise use -g X`, etc.
# survive a container recreation.
# The baseline toolchain baked at build time lives separately in
# /etc/mise/config.toml (system-wide, image layer, re-baked on each
# rebuild). Mise reads both locations and merges them additively.
# Two unfree escape hatches, belt + suspenders:
#   MISE_NIX_ALLOW_UNFREE=true   custom plugin var, forwarded as
#                                NIXPKGS_ALLOW_UNFREE=1 when the mise-nix
#                                plugin invokes `nix build`
#                                (see mise/lib/platform.lua:get_env_prefix).
#   NIXPKGS_ALLOW_UNFREE=1       standard Nix var; kicks in when anyone in
#                                the container runs `nix build` directly
#                                (e.g. interactive shell, hand-written scripts)
# Covers unfree nixpkgs packages like google-chrome, vscode, ngrok,
# terraform, oracle-jdk.
# Relocating mise + nix-profile out of $HOME (to /opt/mise and /opt/nix-home)
# means the ops-mise volume and the nix profile symlink survive a $HOME
# bind-mount (e.g. --with-home / --with-home-volumes).

# -----------------------------------------------------------------------------
# 2. Non-root user with matching UID/GID
# -----------------------------------------------------------------------------
RUN groupadd -g "${USER_GID}" "${USER_NAME}" \
 && useradd -m -l -u "${USER_UID}" -g "${USER_GID}" -s /bin/bash "${USER_NAME}" \
 && echo "${USER_NAME} ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/${USER_NAME}" \
 && chmod 440 "/etc/sudoers.d/${USER_NAME}" \
 && mkdir -m 0755 /nix /opt/mise /opt/nix-home \
 && chown "${USER_NAME}:${USER_NAME}" /nix /opt/mise /opt/nix-home
# useradd -l: skip writing lastlog/faillog entries for the UID. With a
# high-numbered UID these files are sparse on disk, but the `useradd` call
# still dirties a layer with ~4 KB per UID range. -l avoids that and silences
# hadolint DL3046.
# /nix is pre-created so the single-user Nix installer can write there as a
# non-root user. /opt/mise holds the mise binary + data (shims, installs,
# plugins) outside $HOME so an ops-mise volume on /opt/mise/data survives a
# --with-home bind-mount. /opt/nix-home is the HOME passed to the Nix
# installer so .nix-profile and the XDG state dir land outside user $HOME.

# Rootless nerdctl limitation: in rootless mode, host UID 1000 maps to container
# UID 0 (root in the namespace). This USER runs the process as UID 1000 inside
# the container, which corresponds to UID ~101000 on the host — unable to read
# or write bind-mounted files owned by host UID 1000 (e.g. ~/.claude, $PWD).
# Workaround: launch tools needing access to host files with --user 0
# (container root = host UID 1000) and --env HOME=/home/<user>.
USER ${USER_NAME}
WORKDIR /home/${USER_NAME}

# Pre-create XDG-style user dirs so bind-mounts don't create their parent
# dirs as root:root at runtime, breaking later writes (e.g. uv, opencode).
# mise-related dirs live under /opt/mise (see ENV above) so they are not
# pre-created here.
RUN mkdir -p "$HOME/.local/bin" \
             "$HOME/.local/share" \
             "$HOME/.local/state" \
             "$HOME/.cache" \
             "$HOME/.config"

# -----------------------------------------------------------------------------
# 3. Nix single-user (required by the mise-nix plugin; no daemon possible in
#    rootless mode)
# -----------------------------------------------------------------------------
# System-wide /etc/nix/nix.conf is read regardless of $HOME ownership, which
# matters in rootless: /home/$USER is UID 1000 in namespace but we run as UID 0,
# so Nix warns and falls back to /root — skipping the user's ~/.config/nix/nix.conf.
# Setting build-users-group empty here keeps nix in single-user mode even then.
#
# We run the installer with HOME=/opt/nix-home so the .nix-profile symlink,
# XDG state dir (.local/state/nix) and bash-profile hooks land under
# /opt/nix-home/* instead of user $HOME. /opt/nix-home is image-baked (not a
# volume), so its symlinks resolve to /nix/store paths served by ops-nix at
# runtime. Experimental features live in /etc/nix/nix.conf (system-wide), so
# we no longer need a user-level nix.conf.
# Installer is fetched from the floating /nix/install endpoint (always the
# latest stable release). Trust relies on HTTPS + the upstream mirror; the
# installer script itself verifies the binary payload it downloads.
# No GitHub token is written into /etc/nix/nix.conf: it would persist in the
# image layer. GITHUB_TOKEN is consumed only transiently by the RUN below
# that performs `mise use` (via --mount=type=secret), never baked in.
RUN HOME=/opt/nix-home curl -fsSL --retry 3 --max-time 120 \
      -o /tmp/nix-install.sh "https://nixos.org/nix/install" \
 && HOME=/opt/nix-home sh /tmp/nix-install.sh --no-daemon \
 && rm -f /tmp/nix-install.sh \
 && sudo mkdir -p /etc/nix \
 && printf 'experimental-features = nix-command flakes\nbuild-users-group =\n' \
      | sudo tee /etc/nix/nix.conf > /dev/null

# Expose nix + mise shims in PATH for every subsequent RUN and for the
# Lua hooks that mise spawns as sub-processes (which inherit the ENV PATH,
# not the transient PATH set by `source nix.sh`). Paths are rooted at /opt/*
# so they remain valid even when $HOME is bind-mounted from the host.
# /opt/ops/bin is prefixed first so ops-cli wrappers (google-chrome, ...)
# shadow the mise shims for tools that need container-specific flags.
ENV PATH=/opt/ops/bin:/opt/nix-home/.nix-profile/bin:/opt/mise/data/shims:/opt/mise/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# -----------------------------------------------------------------------------
# 4. mise (env-manager — single ~20 MB binary, installed at /opt/mise/bin)
# -----------------------------------------------------------------------------
# Installer reads MISE_INSTALL_PATH + MISE_*_DIR from ENV above to place the
# binary at /opt/mise/bin/mise and state/cache/data under /opt/mise/*.
RUN curl -fsSL --retry 3 --max-time 120 -o /tmp/mise-install.sh https://mise.run \
 && if [ -n "${MISE_INSTALL_SHA256}" ]; then \
      echo "${MISE_INSTALL_SHA256}  /tmp/mise-install.sh" | sha256sum -c -; \
    fi \
 && sh /tmp/mise-install.sh \
 && rm -f /tmp/mise-install.sh \
 && chmod 755 /opt/mise/bin/mise

# -----------------------------------------------------------------------------
# 5. mise tools (merged mise-nix plugin + GitHub/npm backends) + shell setup
# -----------------------------------------------------------------------------
# The local mise-nix plugin is copied into /opt/ops/mise-plugin/nix/ (OUTSIDE
# $MISE_DATA_DIR), then symlinked into /opt/mise/data/plugins/nix so mise
# auto-discovers it. Keeping the real files outside the data dir is what
# allows plugin updates to take effect after a rebuild: ops.sh mounts
# ops-share-mise:/opt/mise/data at runtime, which masks the image's own
# /opt/mise/data/plugins/ with the volume's (potentially stale) copy.
# The symlink in the volume points at the image-baked path, which *is*
# refreshed on every build, so the plugin never goes stale. ops.sh also
# runs a one-time migration that replaces a legacy plain-directory
# `plugins/nix/` in existing volumes with this symlink.
#
# Base dev tools are installed in one `mise use -g` pass (nix:* via the
# plugin, github:* via the built-in backend). node@lts is baked as the base
# for any npm: agent that ops.sh later installs on demand. bashrc is
# populated last, with mise activation followed by a fast
# command_not_found override (mise's default handler runs a network lookup
# per unknown command, which is slow).
COPY --chown=${USER_NAME}:${USER_NAME} mise/ /opt/ops/mise-plugin/nix/

RUN --mount=type=secret,id=github_token,required=false,uid=${USER_UID},mode=0400 \
    . /opt/nix-home/.nix-profile/etc/profile.d/nix.sh \
 && github_token="$(cat /run/secrets/github_token 2>/dev/null || true)" \
 && if [ -n "${github_token}" ]; then \
      export GITHUB_TOKEN="${github_token}"; \
      export NIX_CONFIG="access-tokens = github.com=${github_token}"; \
    fi \
 && unset github_token \
 && sudo mkdir -p /etc/mise \
 && sudo chown "${USER_NAME}:${USER_NAME}" /etc/mise \
 && mkdir -p /opt/mise/data/plugins \
 && ln -sfn /opt/ops/mise-plugin/nix /opt/mise/data/plugins/nix \
 && MISE_CONFIG_DIR=/etc/mise /opt/mise/bin/mise use -g \
      nix:git nix:semgrep \
      github:cli/cli github:BurntSushi/ripgrep \
      github:jqlang/jq github:ast-grep/ast-grep \
      node@lts \
 && if [ -n "${EXTRA_MISE_TOOLS}" ]; then \
      # shellcheck disable=SC2086  -- intentional word split on whitespace
      MISE_CONFIG_DIR=/etc/mise /opt/mise/bin/mise use -g ${EXTRA_MISE_TOOLS}; \
    fi \
 && sudo chown -R root:root /etc/mise \
 && sudo chmod -R a+rX /etc/mise \
 && mkdir -p /opt/mise/data/config \
 && mkdir -p /nix/var/nix/gcroots/mise \
 && for f in /opt/mise/data/installs/nix-*/*; do \
      [ -L "$f" ] || continue; \
      t=$(readlink -f "$f"); \
      case "$t" in \
        /nix/store/*) \
          ln -sfn "$t" "/nix/var/nix/gcroots/mise/$(basename "$(dirname "$f")")-$(basename "$f")"; \
          ;; \
      esac; \
    done \
 && _profile_store="$(readlink -f /opt/nix-home/.nix-profile)" \
 && if [ -n "$_profile_store" ] && [ -e "$_profile_store" ]; then \
      ln -sfn "$_profile_store" /nix/var/nix/gcroots/ops-nix-profile; \
    else \
      echo "ERROR: cannot resolve /opt/nix-home/.nix-profile to a store path" >&2; exit 1; \
    fi \
 && if [ "$NIX_CLEANUP" = "true" ]; then \
      HOME=/opt/nix-home /opt/nix-home/.nix-profile/bin/nix-collect-garbage -d; \
    fi

# Bake the interactive shell init OUTSIDE $HOME so it survives the host
# bind-mount of $HOME at runtime. ops.sh launches `bash --rcfile
# /etc/ops-bashrc` for interactive sessions and `source`s the same file at
# the top of `bash -c` agent wrappers, so claude / gemini / opencode / codex
# / --update / --install all see PATH / PYTHONPATH / ... from the workdir's
# flake.nix devShell.
COPY --chown=root:root --chmod=644 scripts/ops-bashrc /etc/ops-bashrc

# -----------------------------------------------------------------------------
# 6. google-chrome wrapper (shadows the mise shim via /opt/ops/bin)
# -----------------------------------------------------------------------------
# Copied as /opt/ops/bin/google-chrome. Because /opt/ops/bin is the first
# entry in PATH (see the ENV above), typing `google-chrome` or any
# chrome-launcher-based tool (chrome-devtools-mcp, Puppeteer, Lighthouse)
# picks up this wrapper rather than the mise shim. The wrapper adds the
# flags required in a rootless container (--no-sandbox,
# --disable-dev-shm-usage, Wayland ozone when available), then execs the
# real Nix-provided binary via absolute path to avoid PATH recursion.
#
# The wrapper is always present; it short-circuits with a clear message
# if google-chrome isn't actually installed (i.e. EXTRA_MISE_TOOLS did
# not include nix:google-chrome at build time).
COPY --chown=root:root --chmod=755 scripts/google-chrome.sh /opt/ops/bin/google-chrome
# Reach the wrapper from tools that don't inherit our /opt/ops/bin PATH
# prefix:
#   CHROME_PATH is consulted first by chrome-launcher (used by
#   chrome-devtools-mcp, Puppeteer, Lighthouse, ...).
#   /usr/bin/google-chrome is the fallback `which` lookup + the path
#   hard-coded by some tools on Linux.
ENV CHROME_PATH=/opt/ops/bin/google-chrome \
    PUPPETEER_EXECUTABLE_PATH=/opt/ops/bin/google-chrome
RUN sudo ln -sf /opt/ops/bin/google-chrome /usr/bin/google-chrome \
 && sudo mkdir -p /opt/google/chrome \
 && sudo ln -sf /opt/ops/bin/google-chrome /opt/google/chrome/chrome

# Nix wrappers — force HOME=/opt/nix-home for stateful commands so they
# act on the container profile, not the host one (which would otherwise
# be reached via the bind-mounted $HOME). Escape hatch: pass --host.
#
# Two scripts:
#   _nix-wrapper.sh     — always force HOME (legacy binaries are
#                         wholly stateful)
#   _nix-cli-wrapper.sh — inspect subcommand and force HOME only for
#                         `nix profile|channel|registry|upgrade-nix`.
#                         Other subcommands (`nix build/shell/search/...`)
#                         pass through so they can share the host-mounted
#                         ~/.cache/nix/ for a fast build cache.
#
# Not wrapped: nix-build, nix-shell, nix-instantiate, nix-prefetch-url
# (cache-heavy, sharing the host cache is a feature).
COPY --chown=root:root --chmod=755 scripts/_nix-wrapper.sh /opt/ops/bin/_nix-wrapper
COPY --chown=root:root --chmod=755 scripts/_nix-cli-wrapper.sh /opt/ops/bin/nix
RUN for cmd in nix-env nix-channel nix-store nix-collect-garbage; do \
        sudo ln -sf /opt/ops/bin/_nix-wrapper /opt/ops/bin/"$cmd"; \
    done
# The extra symlink at /opt/google/chrome/chrome matches the hard-coded
# path puppeteer-core expects for the Chrome "stable" channel on Linux.
# chrome-devtools-mcp uses puppeteer-core internally, so without that
# symlink it fails with `Could not find Google Chrome executable for
# channel 'stable' at: - /opt/google/chrome/chrome` even if CHROME_PATH,
# PATH, and /usr/bin/google-chrome are all correct. PUPPETEER_EXECUTABLE_PATH
# is consulted in addition, as a belt-and-suspenders for non-MCP puppeteer
# users inside the container.

# -----------------------------------------------------------------------------
# 7. Entrypoint (PATH is set right after the Nix install above)
# -----------------------------------------------------------------------------
# WORKDIR stays at /home/${USER_NAME} (set earlier). ops.sh overrides it per
# invocation via `--workdir $PWD` (bind-mounted from the host); direct
# `docker run` users land in $HOME, which is more useful than an empty
# /workspace that nothing creates anyway.

CMD ["bash", "--rcfile", "/etc/ops-bashrc"]
