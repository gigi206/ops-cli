# Changelog

All notable changes to ops-cli are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `LICENSE` at repository root (Apache-2.0, © 2026 Ghislain LE MEUR).
- `OPS_VERSION` constant in `ops.sh`; `version` subcommand and `--version` / `-V` flags.
- `CONTRIBUTING.md`, `.editorconfig`, `.shellcheckrc`.
- SPDX license identifiers on every `mise/` Lua file; NOTICE enriched with a per-file license map.
- `--mount=type=secret` path for `GITHUB_TOKEN` (via `--secret id=github_token,env=GITHUB_TOKEN`).
- Optional SHA256 pinning of the Nix and mise installer scripts (`NIX_INSTALL_SHA256`, `MISE_INSTALL_SHA256`).
- `shell.shquote` helper in `mise/lib/shell.lua` for safe shell quoting.
- Global `permissions: contents: read` on the GitHub Actions workflow.
- `runtime-build` now depends on `hadolint` in addition to `bats`.

### Changed
- `cmd_uninstall` validates `OPS_NERDCTL_HOME` against the safe-paths whitelist before any `rm -rf`.
- `OPS_VOLUMES` is now parsed with `read -ra` (no glob expansion).
- Global-flag parsing factored into `_parse_global_flags` (removes the duplicated parse block).
- `mise/lib/tempdir.lua` now uses `mktemp -d` instead of `os.time()+math.random` (fixes TOCTOU + unseeded RNG).
- `mise/lib/security.lua` rejects any `..` path component after normalization and requires paths to resolve inside `cwd`.
- `flake ↔ security` require cycle broken: `security.validate_local_flake` now takes a pre-parsed descriptor.
- `vsix.from_flake` returns a usable `version` field instead of a full flake URL.
- `bats`: `test_dryrun.bats` unknown-flag assertion now requires both markers (was OR).

### Removed
- `ARG GITHUB_TOKEN` from both Dockerfiles; the token is no longer baked into `/etc/nix/nix.conf`.

## [0.1.0]

Initial tagged version.
