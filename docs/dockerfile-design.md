# Dockerfile design notes

Single source of explanatory text shared between `Dockerfile` (Arch base)
and `Dockerfile.debian` (Debian base). The two files mirror each other
section-for-section; before changing one, **read the matching section
here** so you don't drop a constraint that's not obvious from the line
alone.

The Dockerfiles themselves keep short, line-local comments. Anything
longer than ~3 lines lives here.

---

## §1. System packages and locales

### Why we re-extract glibc on Arch

`archlinux:base` ships `/etc/pacman.conf` with `NoExtract` rules that
strip every locale source under `usr/share/i18n/*` and `usr/share/locale/*`
except `en_*`, `C` and `POSIX`. A user who builds with `USER_LANG=fr_FR.UTF-8`
or `de_DE.UTF-8` would land in a container that can't compile their locale.

We drop those rules **and reinstall glibc with `--overwrite`**:

```dockerfile
pacman -S --noconfirm --overwrite '/usr/share/locale/*' --overwrite '/usr/share/i18n/*' glibc
```

`--needed` alone would skip the package as already installed. `-S` without
`--overwrite` would refuse the reinstall on file-conflict errors against
the previously-extracted glibc. Together, the two flags force a clean
re-extraction of just the locale source files.

After the re-extract, `locale-gen` compiles `USER_LANG` and the resulting
`.UTF-8` locale is usable. `pacman -Scc --noconfirm` clears the package
cache (no separate `rm -rf /var/cache/pacman/pkg/*` needed — `-Scc` covers
both the package cache and the database).

### Why we set `/etc/machine-id` at build time

Chrome (and any DBus-based app) expects a 32-char hex `/etc/machine-id`.
Both `archlinux:base` and `debian:testing-slim` ship an empty file, which
triggers the runtime warning:

```
/etc/machine-id contains 0 characters (32 were expected)
```

We populate the file at build time from `/proc/sys/kernel/random/uuid`,
strip the dashes (32 hex chars), and add a trailing newline (some systemd
versions reject a file without one):

```dockerfile
printf '%s\n' "$(tr -d '-' < /proc/sys/kernel/random/uuid)" > /etc/machine-id
```

The newline is what `printf '%s\n'` enforces; the previous `tr | >` form
left the file without one.

---

## §2. Non-root user

We pin the user UID/GID to the host invoker's via `USER_UID`/`USER_GID`
build-args. This avoids the file-ownership headache when a host directory
is bind-mounted: the user inside sees its own files as owned by the same
numeric UID/GID, so writes round-trip correctly.

`useradd -l` skips the `lastlog`/`faillog` extension that would otherwise
add ~4 KB per UID range to the image (sparse on disk, but still costs a
layer increment). Hadolint flags this as DL3046 if you forget `-l`.

`NOPASSWD: ALL` in the sudoers entry: this is a **dev** image. Tests, mise
hooks, and post-USER `RUN` lines all need to write to `/etc`, `/usr`, or
chmod the Nix profile. `gosu` doesn't fit the model (no runtime supervisor
to step down from root).

### `/nix`, `/opt/mise`, `/opt/nix-home` pre-creation

All three are `mkdir -m 0755` + `chown` to the build user **before** the
USER directive. Why up-front:

- **`/nix`** — the single-user Nix installer needs to write here as a
  non-root user. The default location (`/`) is owned by root.
- **`/opt/mise`** — holds the mise binary, shims, installs, plugins,
  state, cache, and config. Lives outside `$HOME` so the `ops-share-mise`
  volume on `/opt/mise/data` survives a `--with-home` bind-mount of the
  user's `$HOME`.
- **`/opt/nix-home`** — passed as `HOME` to the Nix installer so its
  `.nix-profile` symlink and XDG state dir land outside the user's `$HOME`,
  for the same reason.

### Rootless nerdctl UID-mapping caveat

In rootless mode, **host UID 1000 maps to container UID 0**. If `USER`
runs as UID 1000 inside the container, that's UID ~101000 on the host —
which can't read or write bind-mounted files owned by host UID 1000
(e.g. `~/.claude`, `$PWD`).

`ops.sh::cmd_run` works around this by launching the container with
`--user 0:$OPS_USER_GID` in rootless and `--user $OPS_USER_UID:$OPS_USER_GID`
in rootful. See `_is_rootless` in `ops.sh`.

---

## §3. Nix single-user installer

The image runs the **single-user** Nix installer, not the multi-user
daemon. Multi-user requires daemonized `nix-daemon` + a build-users group,
which doesn't work in a rootless container (no privilege to create a
group with sub-UIDs).

Three constraints shape this section:

1. **System-wide `/etc/nix/nix.conf`** — Nix reads this regardless of
   `$HOME` ownership. In rootless we run as UID 0 inside the namespace,
   so `~/.config/nix/nix.conf` (mapped from the host user's home) is
   skipped with a warning. Putting the experimental-features flag in
   `/etc/nix/nix.conf` works in both rootless and rootful.

2. **`build-users-group =`** (empty) — explicitly sets single-user mode
   even when Nix's heuristic would otherwise look for the group.

3. **`HOME=/opt/nix-home` during install** — the installer creates
   `.nix-profile` and the state dir under `$HOME`. We override that to
   `/opt/nix-home` so the symlinks survive a runtime bind-mount of the
   user's host `$HOME` over `/home/<user>`.

### No GitHub token in the image

`GITHUB_TOKEN` is consumed via BuildKit `--mount=type=secret`, never baked
into a layer. The `RUN` reads `/run/secrets/github_token` (file is gone
when the RUN ends) and exposes it through `NIX_CONFIG=access-tokens=…`
**only for the duration of that RUN**. The token is used to lift the
GitHub API rate limit (60 → 5000 req/h) when Nix resolves `github:` flake
references.

### Installer trust model

The Nix installer is fetched from `https://nixos.org/nix/install` (the
floating "latest" endpoint). We trust:
- HTTPS + the upstream mirror, and
- The installer's own internal SHA verification of the binary payload it
  fetches.

A user who wants byte-exact reproducibility can pin
`MISE_INSTALL_SHA256=<sha>` (build-arg, optional). There is no equivalent
`NIX_INSTALL_SHA256` arg by design — the Nix installer is the more stable
of the two, and adding a pin would commit us to refresh it on every
upstream release.

### `mise/data/installs/nix-*/*` GC roots

The `RUN` in §5 builds explicit GC roots under `/nix/var/nix/gcroots/mise/`
that point at the resolved store paths of every `nix:` tool installed
through the mise plugin. Without this, `nix-collect-garbage -d` (run at
the end of the same layer to shed ~200 MB) would prune the binaries
out from under the shims.

The auto-gcroot the Nix single-user installer creates
(`gcroots/auto/<hash>` → `profile-N-link` → store path) is a 2-level
indirect symlink that some Docker/BuildKit versions did not honor under
a custom `HOME=/opt/nix-home`. Result: the Nix profile (and `nix` itself)
vanishing from the image after build. The direct gcroots bypass that.

---

## §4. mise binary

mise is a single ~20 MB Go binary. We install it at `/opt/mise/bin/mise`
and read state/cache/data from `/opt/mise/*` (set via the ENV block in §1).

`MISE_INSTALL_SHA256` (build-arg, optional) lets locked-down CI mirrors
pin a specific bootstrap shim. Empty by default — same trust model as
the Nix installer.

---

## §5. mise tools and shell init

### Why the plugin lives outside the volume

The local `mise/` plugin is copied into `/opt/ops/mise-plugin/nix/`
(image-baked, **outside** `$MISE_DATA_DIR`). A symlink at
`/opt/mise/data/plugins/nix → /opt/ops/mise-plugin/nix` is created in
the same `RUN`.

Why: `ops.sh` mounts `ops-share-mise:/opt/mise/data` at runtime. The
volume **masks** the image's own `/opt/mise/data/plugins/` directory
with whatever was previously copied into the volume. Without the
out-of-volume layout, every plugin update after the first build was
invisible to existing users (Docker only populates a named volume from
the image layer on its first mount; subsequent mounts use the volume's
stale copy).

`ops.sh::_ensure_mise_plugin_symlink` runs once per invocation
(idempotent, ~200 ms cold) to migrate any pre-existing volume that still
carries a plain `plugins/nix/` directory, replacing it with the symlink.

### Why `/etc/mise/config.toml` for the baseline

mise reads `/etc/mise/config.toml` (system-wide) **and**
`/opt/mise/data/config/config.toml` (volume-backed) and merges them
additively. Splitting baseline (image-baked) from user-additions
(volume-backed) is what makes `mise use -g` survive a container
recreation:

- **Baseline** (`/etc/mise/config.toml`) — `mise use -g nix:git nix:semgrep
  github:cli/cli …` writes here at build time, gets re-baked on every
  rebuild.
- **User additions** (`/opt/mise/data/config/config.toml`) — `mise use -g
  X` from inside a running container writes here, persists in
  `ops-share-mise`.

Before this split, both paths wrote to `/opt/mise/data/config/config.toml`
inside the image layer; that path was wiped on every container recreation,
producing "orphan" entries in `mise ls` and breaking `claude` /
`terraform` / any manually-installed tool after a fresh `ops run`.

### `EXTRA_MISE_TOOLS` word-splitting

`EXTRA_MISE_TOOLS` is a whitespace-separated list (default
`"nix:google-chrome"`). We deliberately word-split it inside the `RUN`
(`shellcheck disable=SC2086`) so values like
`"nix:chromium nix:ngrok"` work. A user-controlled list **is** a minor
shell-injection surface, but the value comes from `OPS_BUILD_ARGS` /
`--build-arg` — same trust as the rest of the Dockerfile.

### Bashrc lives at `/etc/ops-bashrc`, not `~/.bashrc`

`ops.sh::cmd_run` bind-mounts the host's `$HOME` over `/home/<user>` by
default (`mount_home=1`). That mount **shadows** any `.bashrc` the image
baked into `/home/<user>/.bashrc` — the mise activation, Nix profile
sourcing, command_not_found handler, and PS1 are silently skipped, and
the mise-nix plugin's flake env hook (`[env] _.nix = true`) never makes
it into the runtime PATH.

We bake the init at `/etc/ops-bashrc` (outside `$HOME`, survives the
bind-mount) and:
- Interactive sessions: `ops run` calls `bash --rcfile /etc/ops-bashrc`.
- Non-interactive `bash -c` agent wrappers (`--claude`, `--gemini`,
  `--opencode`, `--codex`, `--update`, `--nix-cleanup`, `--install -- CMD`):
  `ops.sh` prepends `source /etc/ops-bashrc;` so the agent inherits the
  mise env (PATH / PYTHONPATH / …) from the workdir's `mise.toml` +
  `flake.nix`.

The rcfile guards on `$-` (interactive vs sourced) and chains to a
user-provided `$HOME/.bashrc` via `OPS_BASHRC_DONE` so host-side aliases
still load.

---

## §6. google-chrome wrapper and Nix wrappers

### `/opt/ops/bin` precedence

`ENV PATH=/opt/ops/bin:…` puts our wrappers first. The wrapper
`/opt/ops/bin/google-chrome` (from `scripts/google-chrome.sh`) shadows
the mise shim at `/opt/mise/data/shims/google-chrome`. Typing
`google-chrome` manually or via any chrome-launcher-based tool
(`chrome-devtools-mcp`, Puppeteer, Lighthouse) hits our wrapper first.

The wrapper:
- Adds the mandatory `--no-sandbox --disable-dev-shm-usage` for rootless
  containers.
- Adds Wayland ozone flags when `$WAYLAND_DISPLAY` is set.
- Execs the real binary via absolute path
  (`/opt/mise/data/installs/nix-google-chrome/latest/bin/google-chrome`)
  to avoid PATH recursion.
- Short-circuits with a clear error message if `google-chrome` is not
  installed (i.e. `EXTRA_MISE_TOOLS=""`).

### Three discoverability hooks for Chrome

Some tools refuse to use `$PATH` and look at hard-coded paths. We provide
three redundant entry points so they all converge on the wrapper:

1. `ENV CHROME_PATH=/opt/ops/bin/google-chrome` +
   `PUPPETEER_EXECUTABLE_PATH=/opt/ops/bin/google-chrome` — chrome-launcher
   reads these.
2. Symlink `/usr/bin/google-chrome → /opt/ops/bin/google-chrome` —
   fallback for `which`.
3. Symlink `/opt/google/chrome/chrome → /opt/ops/bin/google-chrome` —
   `chrome-devtools-mcp` uses `puppeteer-core`, which hard-codes this
   path for the Chrome "stable" channel on Linux. Without this symlink
   the MCP server fails with `Could not find Google Chrome executable for
   channel 'stable' at: - /opt/google/chrome/chrome`.

### Nix wrappers

`HOME` in the container is bind-mounted from the host. Stateful Nix
commands (`nix profile install`, `nix-env -i`, `nix-channel update`, …)
read/write `$HOME/.nix-profile` and `$HOME/.local/state/nix/profiles/`
— so without intervention they would touch the **host** profile, not
the container one at `/opt/nix-home/.local/state/nix/profiles/`.

Two wrappers force `HOME=/opt/nix-home` for the right subset of commands:

- **`scripts/_nix-wrapper.sh`** — serves `nix-env`, `nix-channel`,
  `nix-store`, `nix-collect-garbage`. These legacy CLIs are wholly
  stateful, so we always force `HOME`.
- **`scripts/_nix-cli-wrapper.sh`** — serves the modern `nix` CLI. Inspect
  the subcommand and force `HOME` only for the stateful ones (`profile`,
  `channel`, `registry`, `upgrade-nix`). Read-only subcommands (`build`,
  `shell`, `develop`, `run`, `search`, `eval`, `flake`, …) pass through
  transparently so they share the host-mounted `~/.cache/nix/` build
  cache for speed.

Both wrappers accept `--host` to explicitly target the host profile. Not
wrapped: `nix-build`, `nix-shell`, `nix-instantiate`, `nix-prefetch-url`
(stateless / cache-only).

---

## Drift watch

The CI `image-integration` job only builds the **Arch** image; the
Debian variant is checked by hadolint but not by an integration suite.
Common drift sources:

- A new `RUN` step added on Arch but forgotten on Debian (or vice versa).
- A new `ENV` variable on one side only.
- A new wrapper or symlink in §6.

Both Dockerfiles carry a `KEEP IN SYNC WITH` header pointing at this
file; please touch both (and add a short note here) when extending the
image.
