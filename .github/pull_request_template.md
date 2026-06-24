<!--
Thank you for contributing to ops. Please skim this template before
submitting. Every item that applies to your change should be ticked.
-->

## Summary

<!-- One or two sentences on the "why" of this PR. -->

## Change classification

- [ ] Bug fix
- [ ] New feature or subcommand / flag
- [ ] Refactor (no behaviour change)
- [ ] Docs only
- [ ] Tooling / CI
- [ ] **Breaking change** (describe the migration path in Notes below)

## Verification done locally

- [ ] `cargo fmt --check` is clean
- [ ] `cargo clippy --all-targets -- -D warnings` is clean
- [ ] `cargo test` is green (the heavy sandbox e2e skip when userns/nix/network are absent)
- [ ] `mise exec -- cargo zigbuild --release --target x86_64-unknown-linux-musl`
      builds the static binary (for changes that could affect the shipping artifact)

## Tests and documentation

- [ ] Added / updated tests that cover the change (or justified below why none was added)
- [ ] Updated the docs under `docs/` or the README when user-visible behaviour moved

## Notes for reviewers

<!-- Anything reviewers should know: follow-up tasks, trade-offs, links. -->
