# syntax=docker/dockerfile:1.6
#
# ops-dev — Arch-based dev container image used by ops.sh.
# Ships: mise + Nix (packages via the merged mise-nix plugin, flake.nix env
# activation) + base dev tools (git, gh, ripgrep, jq, ast-grep, node@lts).
# google-chrome is NOT in the baseline — opt-in via EXTRA_MISE_TOOLS (see
# the "Build-time tools" section in README for the chrome-devtools-mcp setup
# example). CLI apps (claude-code, gemini-cli, opencode, codex) are NOT
# baked — they are installed on demand by ops.sh when you pass --app claude /
# --app gemini / --app opencode / --app codex, and persist in the
# ops-share-mise volume.
# Add extra tools (terraform, ngrok, google-chrome, …) via:
#   ops config set 'OPS_BUILD_ARGS[default]' \
#     'EXTRA_MISE_TOOLS=nix:terraform nix:google-chrome'
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
#                                                              Default: empty — purely additive.
#                                                              Configure per profile via
#                                                              OPS_BUILD_ARGS in ops.conf, e.g.
#                                                              OPS_BUILD_ARGS[default]=
#                                                                "EXTRA_MISE_TOOLS=nix:terraform"
#   OPS_DESKTOP_DEPS=true|false                                Opt-in Electron GUI runtime libs
#                                                              (gtk3 / nss / nspr / mesa /
#                                                              alsa-lib / libcups). Required only
#                                                              for `--app opencode-desktop`.
#                                                              Default: false. Adds ~80–120 MB.
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
# KEEP IN SYNC WITH Dockerfile.debian — design doc: docs/dockerfile-design.md
# ─────────────────────────────────────────────────────────────────────────────
# Long-form rationale for every section below lives in docs/dockerfile-design.md.
# The two Dockerfiles share ~80 % of their structure; the design doc is the
# single source of truth for the *why*. The numbered headers here (1..7)
# match the section headers in that doc one-for-one.

FROM archlinux:base

# Enable `pipefail` for every RUN so piped commands fail loudly instead of
# silently ignoring the producer's exit code (hadolint DL4006).
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

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
# whitespace-separated list of mise tool specs (e.g. "nix:terraform nix:ngrok").
# Empty by default — the layer is purely additive. The image baseline ships
# git, gh, ripgrep, jq, ast-grep, node@lts; google-chrome is NOT baked (it's
# ~300 MB and only needed for chrome-devtools-mcp / Puppeteer / Lighthouse
# users). To opt in:
#   ops config set 'OPS_BUILD_ARGS[default]' 'EXTRA_MISE_TOOLS=nix:google-chrome'
#   ops update default
# OPS_BUILD_ARGS[default] applies to unkeyed builds without requiring an
# OPS_IMAGES[default] registration — the lookup falls through to `default`
# automatically. For per-profile setups (multiple images side-by-side), use
# OPS_BUILD_ARGS[<key>] paired with OPS_IMAGES[<key>]. See the
# "Build-time tools" section in README for the full recipe.
ARG EXTRA_MISE_TOOLS=""

# Opt-in runtime libs for the Electron GUI variant of opencode
# (`ops run --opencode-desktop`). The flag downloads upstream's prebuilt
# AppImage which embeds Chromium and pulls in a Linux-desktop-shaped set
# of system libs at runtime (libnspr4, libnss3, libgtk-3, libasound,
# libcups, libgbm + transitives). These are NOT in the headless baseline
# — same opt-in philosophy as EXTRA_MISE_TOOLS=nix:google-chrome above.
# Adds ~80–120 MB to the image when enabled. Off by default: zero impact
# on users who only use --claude / --gemini / --opencode (terminal TUIs).
# Enable per-profile via OPS_BUILD_ARGS:
#   ops config set 'OPS_BUILD_ARGS[default]' 'OPS_DESKTOP_DEPS=true'
#   ops update default
# The conditional install layer below is fully cacheable: a build with
# OPS_DESKTOP_DEPS=false (default) bakes a ~50-byte "skipped" marker; a
# build with OPS_DESKTOP_DEPS=true rebuilds only that layer onward.
ARG OPS_DESKTOP_DEPS=false

# -----------------------------------------------------------------------------
# 1. System packages + locales — see docs/dockerfile-design.md §1
# -----------------------------------------------------------------------------
RUN sed -i '/^NoExtract/d' /etc/pacman.conf \
 && pacman -Syu --noconfirm --needed \
      bash-completion ca-certificates curl sudo which \
 && pacman -S --noconfirm --overwrite '/usr/share/locale/*' --overwrite '/usr/share/i18n/*' glibc \
 && sed -i "/${USER_LANG}/s/^# *//" /etc/locale.gen \
 && locale-gen \
 && printf '%s\n' "$(tr -d '-' < /proc/sys/kernel/random/uuid)" > /etc/machine-id \
 && pacman -Scc --noconfirm

# 1b. (Opt-in) Electron / Chromium runtime libs for --opencode-desktop.
# `gtk3` is a meta dep that pulls pango / cairo / atk / at-spi2 / libxkbcommon
# / libxcomposite / libxdamage / libxfixes / libxrandr / libxext / libx11 /
# libxcb in transitive — covers ~15 of the 21 .so DT_NEEDED entries on the
# Electron AppImage. The remaining five (`nss` for libnss3 / libnssutil3 /
# libsmime3, `nspr` for libnspr4, `mesa` for libgbm.so.1, `alsa-lib` for
# libasound.so.2, `libcups` for libcups.so.2) are listed explicitly. Tested
# against the v1.14.39 AppImage published by sst/opencode (Electron + bundled
# Chromium); the set is stable across point releases — Electron's runtime
# requirements only churn between major Electron versions. Keep this list
# in sync with Dockerfile.debian §1b.
RUN if [ "$OPS_DESKTOP_DEPS" = "true" ]; then \
      pacman -Sy --noconfirm --needed \
        gtk3 nss nspr alsa-lib libcups mesa \
      && pacman -Scc --noconfirm; \
    else \
      echo "OPS_DESKTOP_DEPS=false — Electron GUI libs not installed (--opencode-desktop will fail)"; \
    fi

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
    MISE_STATE_DIR=/opt/mise/state \
    MISE_JOBS=2 \
    MISE_FETCH_REMOTE_VERSIONS_TIMEOUT=120s

# -----------------------------------------------------------------------------
# 2. Non-root user with matching UID/GID — see docs/dockerfile-design.md §2
# -----------------------------------------------------------------------------
RUN groupadd -g "${USER_GID}" "${USER_NAME}" \
 && useradd -m -l -u "${USER_UID}" -g "${USER_GID}" -s /bin/bash "${USER_NAME}" \
 && echo "${USER_NAME} ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/${USER_NAME}" \
 && chmod 440 "/etc/sudoers.d/${USER_NAME}" \
 && mkdir -m 0755 /nix /opt/mise /opt/nix-home /etc/mise \
 && chown "${USER_NAME}:${USER_NAME}" /nix /opt/mise /opt/nix-home /etc/mise

USER ${USER_NAME}
WORKDIR /home/${USER_NAME}

# Pre-create XDG-style user dirs so bind-mounts don't create their parents
# as root:root at runtime, breaking later writes (e.g. uv, opencode).
RUN mkdir -p "$HOME/.local/bin" \
             "$HOME/.local/share" \
             "$HOME/.local/state" \
             "$HOME/.cache" \
             "$HOME/.config"

# -----------------------------------------------------------------------------
# 3. Nix single-user — see docs/dockerfile-design.md §3
# -----------------------------------------------------------------------------
# Single-user (no daemon, rootless-friendly). HOME=/opt/nix-home so the
# .nix-profile symlink survives a runtime $HOME bind-mount. GITHUB_TOKEN
# is NOT baked here — see the secret-mount in §5 below.
RUN HOME=/opt/nix-home curl -fsSL --retry 3 --max-time 120 \
      -o /tmp/nix-install.sh "https://nixos.org/nix/install" \
 && HOME=/opt/nix-home sh /tmp/nix-install.sh --no-daemon \
 && rm -f /tmp/nix-install.sh \
 && sudo mkdir -p /etc/nix \
 && printf 'experimental-features = nix-command flakes\nbuild-users-group =\n' \
      | sudo tee /etc/nix/nix.conf > /dev/null

# 3b. nix-static — image-baked binary that lives OUTSIDE the runtime /nix
# volume mount point. Eliminates the entire class of bug where the user
# profile's /opt/nix-home/.nix-profile/bin/nix symlink points at a /nix/store/
# path that is masked at runtime by an out-of-sync ops-share-nix volume.
#
# Mechanism: the bootstrap nix above (dynamic, lives in /nix/store) is used
# ONLY at build time to download the prebuilt nixpkgs#pkgsStatic.nix from
# cache.nixos.org (~25s on warm cache). The resulting fully-static, musl-
# linked nix binary is copied to /opt/ops/lib/nix-static. nix dispatches on
# argv[0], so a single binary serves nix / nix-env / nix-store / nix-channel
# / nix-collect-garbage / nix-build / nix-instantiate / nix-shell via a
# symlink farm in /opt/ops/lib/.
#
# At runtime, /opt/ops/bin (which is first in PATH) holds the existing
# wrappers (_nix-cli-wrapper.sh and _nix-wrapper.sh) that delegate to
# /opt/ops/lib/<cmd> — both image-resident, both unmaskable by the /nix
# volume. The bootstrap nix in /nix/store is no longer referenced from any
# image path; if NIX_CLEANUP=true at the end of §5 it gets garbage-collected
# along with other build-only deps. Tools installed via mise:* below land at
# /nix/store/<hash>/... as before — they're content-addressable so they
# coexist transparently between rebuilds and across the volume.
# PATH ENV is defined further down (ENV PATH=...), so call the bootstrap
# nix by absolute path here. Sourcing nix.sh exports NIX_PROFILES etc.
# but not PATH (it assumes PATH already has /opt/nix-home/.nix-profile/bin).
RUN . /opt/nix-home/.nix-profile/etc/profile.d/nix.sh \
 && /opt/nix-home/.nix-profile/bin/nix build \
        --extra-experimental-features "nix-command flakes" \
        --no-link --print-out-paths \
        "nixpkgs#pkgsStatic.nix" > /tmp/nix-static-paths \
 && nix_static_path=$(tail -1 /tmp/nix-static-paths) \
 && sudo mkdir -p /opt/ops/lib \
 && sudo install -m 0755 -o root -g root \
      "$nix_static_path/bin/nix" /opt/ops/lib/nix-static \
 && for cmd in nix nix-env nix-store nix-channel nix-collect-garbage \
               nix-build nix-instantiate nix-shell nix-prefetch-url; do \
      sudo ln -sf nix-static /opt/ops/lib/"$cmd"; \
    done \
 && rm -f /tmp/nix-static-paths \
 && /opt/ops/lib/nix-static --version

# /opt/ops/bin first so ops-cli wrappers (google-chrome, nix CLI) shadow
# the mise shims; rooted under /opt/* so the PATH survives a $HOME bind-mount.
ENV PATH=/opt/ops/bin:/opt/nix-home/.nix-profile/bin:/opt/mise/data/shims:/opt/mise/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# -----------------------------------------------------------------------------
# 4. mise binary — see docs/dockerfile-design.md §4
# -----------------------------------------------------------------------------
RUN curl -fsSL --retry 3 --max-time 120 -o /tmp/mise-install.sh https://mise.run \
 && if [ -n "${MISE_INSTALL_SHA256}" ]; then \
      echo "${MISE_INSTALL_SHA256}  /tmp/mise-install.sh" | sha256sum -c -; \
    fi \
 && sh /tmp/mise-install.sh \
 && rm -f /tmp/mise-install.sh \
 && chmod 755 /opt/mise/bin/mise

# -----------------------------------------------------------------------------
# 5. mise tools + shell setup — see docs/dockerfile-design.md §5
# -----------------------------------------------------------------------------
# Plugin lives at /opt/ops/mise-plugin/nix/ (outside the volume mount point
# at /opt/mise/data) and is symlinked into the mise plugins dir below.
COPY --chown=${USER_NAME}:${USER_NAME} mise/ /opt/ops/mise-plugin/nix/

RUN --mount=type=secret,id=github_token,required=false,uid=${USER_UID},mode=0400 \
    . /opt/nix-home/.nix-profile/etc/profile.d/nix.sh \
 && github_token="$(cat /run/secrets/github_token 2>/dev/null || true)" \
 && if [ -n "${github_token}" ]; then \
      export GITHUB_TOKEN="${github_token}"; \
      export NIX_CONFIG="access-tokens = github.com=${github_token}"; \
    fi \
 && unset github_token \
 && mkdir -p /opt/mise/data/plugins \
 && ln -sfn /opt/ops/mise-plugin/nix /opt/mise/data/plugins/nix \
 && MISE_CONFIG_DIR=/etc/mise /opt/mise/bin/mise use -g \
      nix:git \
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
      HOME=/opt/nix-home /opt/ops/lib/nix-collect-garbage -d; \
    fi

# Interactive shell init outside $HOME so it survives the runtime $HOME
# bind-mount. See docs/dockerfile-design.md §5 ("Bashrc lives at /etc/ops-bashrc").
COPY --chown=root:root --chmod=644 scripts/ops-bashrc /etc/ops-bashrc

# -----------------------------------------------------------------------------
# 6. google-chrome wrapper + Nix wrappers — see docs/dockerfile-design.md §6
# -----------------------------------------------------------------------------
COPY --chown=root:root --chmod=755 scripts/google-chrome.sh /opt/ops/bin/google-chrome
ENV CHROME_PATH=/opt/ops/bin/google-chrome \
    PUPPETEER_EXECUTABLE_PATH=/opt/ops/bin/google-chrome
# Three discoverability hooks (chrome-launcher env, /usr/bin fallback,
# puppeteer-core hard-coded /opt/google/chrome/chrome). See §6.
RUN sudo ln -sf /opt/ops/bin/google-chrome /usr/bin/google-chrome \
 && sudo mkdir -p /opt/google/chrome \
 && sudo ln -sf /opt/ops/bin/google-chrome /opt/google/chrome/chrome

# Nix wrappers force HOME=/opt/nix-home for stateful commands so they target
# the container profile, not the host one. `--host` escape hatch.
COPY --chown=root:root --chmod=755 scripts/_nix-wrapper.sh /opt/ops/bin/_nix-wrapper
COPY --chown=root:root --chmod=755 scripts/_nix-cli-wrapper.sh /opt/ops/bin/nix
RUN for cmd in nix-env nix-channel nix-store nix-collect-garbage; do \
        sudo ln -sf /opt/ops/bin/_nix-wrapper /opt/ops/bin/"$cmd"; \
    done

# -----------------------------------------------------------------------------
# OCI image metadata — placed last to keep the build cache warm
# -----------------------------------------------------------------------------
# Every LABEL is its own cache layer, and changing a single LABEL value —
# even a purely textual edit to the description — invalidates the cache of
# every instruction that follows. Keeping the labels at the very end means
# doc-only releases (renames, wording fixes, source-URL changes for a fork)
# rebuild only the ~0-byte LABEL layer and reuse the costly mise/Nix install
# layers above. `ops.dockerfile` (set at build time by ops.sh, not here)
# carries the wrapper-specific info; these annotations cover the registry-
# standard fields. Override SOURCE_URL via `--build-arg` for forks / vendor
# builds, or set OPS_SOURCE_URL="" to suppress the source/url/documentation
# labels.
ARG SOURCE_URL="https://github.com/gigi206/ops-cli"
LABEL org.opencontainers.image.title="ops-dev" \
      org.opencontainers.image.description="Containerized development environment with mise + Nix + AI CLI apps (Claude Code, Gemini, OpenCode, Codex). Arch Linux base." \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.authors="Ghislain LE MEUR" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.url="${SOURCE_URL}" \
      org.opencontainers.image.documentation="${SOURCE_URL}"

# -----------------------------------------------------------------------------
# 7. Entrypoint
# -----------------------------------------------------------------------------
# WORKDIR stays at /home/${USER_NAME}. ops.sh overrides per-invocation via
# `--workdir $PWD` (bind-mounted from the host).
CMD ["bash", "--rcfile", "/etc/ops-bashrc"]
