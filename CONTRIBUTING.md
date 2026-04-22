# Contributing to ops-cli

Thanks for taking the time to contribute.

## Scope

ops-cli is a single-file bash CLI (`ops.sh`) that wraps docker / podman /
nerdctl to run a Nix+mise containerized dev environment. The `mise/`
subdirectory is a derivative mise-nix plugin (see `mise/NOTICE`).

Changes that stay in scope:
- Bug fixes in `ops.sh` and the Dockerfiles.
- New subcommands / flags that fit the "single bash file" constraint.
- Improvements to the mise plugin (`mise/lib/`, `mise/hooks/`).
- Tests (`tests/*.bats`).

Out of scope:
- Rewriting `ops.sh` in another language.
- Adding heavy dependencies.

## Development

```bash
# Run the test suite (needs bats + shellcheck)
shellcheck -S style ops.sh
bash -n ops.sh
bats tests/
```

Keep `ops.sh` passing `shellcheck -S style` and `bats tests/` before opening
a PR. `hadolint Dockerfile` and `hadolint Dockerfile.debian` should also be
clean (the CI ignores `DL3008` and `DL3059`).

## Commits

- One logical change per commit.
- Imperative mood, under ~72 chars on the subject line.
- No trailers (no `Co-Authored-By`, no `Signed-off-by` unless you know you need one).

## Licensing of contributions

Contributions are accepted under the Apache License, Version 2.0 (same as
the project). Files imported from MIT-licensed sources must retain their
SPDX header and be documented in `mise/NOTICE`. When you modify an
upstream-sourced file, add a `-- Modifications: Copyright (c) YYYY Your Name`
line under the existing SPDX block and update `mise/NOTICE` accordingly.
