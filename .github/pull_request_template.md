<!--
Thank you for contributing to ops-cli. Please skim this template before
submitting. Every item that applies to your change should be ticked.
-->

## Summary

<!-- One or two sentences on the "why" of this PR. -->

## Change classification

- [ ] Bug fix
- [ ] New feature or subcommand / flag
- [ ] Refactor (no behaviour change)
- [ ] Docs / CHANGELOG only
- [ ] Tooling / CI
- [ ] Image / Dockerfile change
- [ ] **Breaking change** (describe the migration path in Notes below)

## Verification done locally

- [ ] `shellcheck -S style ops.sh scripts/*.sh` is clean
- [ ] `bash -n ops.sh` is clean
- [ ] `bats tests/` is green
- [ ] `hadolint Dockerfile` and `hadolint Dockerfile.debian` are acceptable
      (the project tolerates `DL3008`, `DL3059`, `DL3004`, `SC1091`, `SC2028`;
      anything new needs a justification in the PR description)

## Tests and documentation

- [ ] Added / updated bats tests that cover the change (or justified below
      why no test was added — e.g. pure docs, untestable image path)
- [ ] Updated `README.md` / `CHANGELOG.md` when user-visible behaviour moved

## Image integration coverage

The `image-integration` CI job exercises `tests/test_image_integration.bats`
against the real `localhost/ops-dev` Arch image. It is intentionally **not**
triggered by pull requests (the Nix build takes ~15 min per run), so these
tests do **not** gate your PR by default.

If your change touches any of the areas below, please either run the
integration suite locally (`./ops.sh build && bats tests/test_image_integration.bats`)
or trigger the workflow manually from the Actions tab once the PR is open:

- [ ] Dockerfile / Dockerfile.debian
- [ ] `mise/` plugin (Lua files, NOTICE, metadata)
- [ ] `scripts/` helpers (google-chrome wrapper, nix wrappers)
- [ ] Nix GC root, mise config split, machine-id handling
- [ ] `EXTRA_MISE_TOOLS` defaults / `OPS_BUILD_ARGS` plumbing

Otherwise tick the box below to acknowledge the coverage gap:

- [ ] This change does not touch image-level code; integration suite not
      needed.

## Notes for reviewers

<!-- Anything reviewers should know: follow-up tasks, trade-offs, links. -->
