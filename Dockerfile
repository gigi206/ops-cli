# syntax=docker/dockerfile:1.6
#
# ops-dev — Arch-based dev container image used by ops.sh.
# Ships: mise + Nix (packages via the merged mise-nix plugin, flake.nix env
# activation) + base dev tools (git, google-chrome, gh, ripgrep, jq,
# ast-grep, node@lts). CLI agents (claude-code, gemini-cli, opencode,
# codex) are NOT baked — they are installed on demand by ops.sh when you
# pass --claude / --gemini / --opencode / --codex, and persist in the
# ops-share-mise volume.
# Add extra tools (terraform, ngrok, …) via:
#   ops config set 'OPS_BUILD_ARGS[default]' \
#     'EXTRA_MISE_TOOLS=nix:terraform'
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
# whitespace-separated list of mise tool specs (e.g. "nix:terraform nix:ngrok").
# Empty by default — the layer is purely additive. The image baseline already
# ships google-chrome (so `chrome-devtools-mcp` works out of the box), git,
# gh, ripgrep, jq, ast-grep, node@lts; EXTRA_MISE_TOOLS is for everything
# else the user wants without patching the Dockerfile. Configure per profile
# via OPS_BUILD_ARGS[<image-key>]="EXTRA_MISE_TOOLS=..." in ops.conf.
ARG EXTRA_MISE_TOOLS=""

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
      nix:git nix:google-chrome \
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
 && shopt -s nullglob \
 && for f in /opt/mise/data/installs/nix-*/*; do \
      [ -L "$f" ] || continue; \
      t=$(readlink -f "$f"); \
      case "$t" in \
        /nix/store/*) \
          ln -sfn "$t" "/nix/var/nix/gcroots/mise/$(basename "$(dirname "$f")")-$(basename "$f")"; \
          ;; \
      esac; \
    done \
 && shopt -u nullglob \
 && _profile_store="$(readlink -f /opt/nix-home/.nix-profile)" \
 && if [ -n "$_profile_store" ] && [ -e "$_profile_store" ]; then \
      ln -sfn "$_profile_store" /nix/var/nix/gcroots/ops-nix-profile; \
    else \
      echo "ERROR: cannot resolve /opt/nix-home/.nix-profile to a store path" >&2; exit 1; \
    fi \
 && if [ "$NIX_CLEANUP" = "true" ]; then \
      HOME=/opt/nix-home /opt/nix-home/.nix-profile/bin/nix-collect-garbage -d; \
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
# 7. Entrypoint
# -----------------------------------------------------------------------------
# WORKDIR stays at /home/${USER_NAME}. ops.sh overrides per-invocation via
# `--workdir $PWD` (bind-mounted from the host).
CMD ["bash", "--rcfile", "/etc/ops-bashrc"]
