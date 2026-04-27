# ops-cli — repo conventions

## Cutting a release (when user says "bump version" / "cut a release")

### 1. Pick the bump level (semver)

| Bump | Trigger |
|---|---|
| **PATCH** (`X.Y.Z` → `X.Y.(Z+1)`) | Bug fixes only. No new flag, env var, file, or behaviour change. |
| **MINOR** (`X.Y.Z` → `X.(Y+1).0`) | New backwards-compatible functionality (new subcommand, new env var, new public file like `install.sh`). |
| **MAJOR** (`X.Y.Z` → `(X+1).0.0`) | Breaking change (removed/renamed flag, env var, subcommand; default change that breaks scripts). |

If the user states a version, trust it. If they ask, give the rationale and let them pick.

### 2. Bump version sources

Two sources, must stay in lockstep:

```bash
grep -n '^OPS_VERSION=' ops.sh
grep -n '^  version' mise/metadata.lua
```

`mise/metadata.lua` carries the **plugin** version (mise-nix, embedded under `mise/`). Bump it only when the plugin's behaviour changed in this release; otherwise leave it on whatever it currently is. When in doubt, ask the user.

The `1.0.0` strings in `tests/`, `tests/lua/test_version.lua`, and `tests/helpers.bash` are mock fixtures / regex anchors, **not** the project version — leave them alone unless the test author tells you otherwise.

### 3. Update `CHANGELOG.md`

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

1. Insert `## [X.Y.Z] - YYYY-MM-DD` immediately under `## [Unreleased]`. Keep `[Unreleased]` empty for the next cycle.
2. Subsections in order, dropping empties: `Security` → `Fixed` → `Performance` → `Added` → `Changed` → `Deprecated` → `Removed`.
3. **Style** is verbose, not terse. Each bullet starts with a bold one-line summary, then a paragraph explaining root cause, what was tried, what landed, and where the regression guard lives. See `[1.0.0]` / `[1.1.0]` / `[1.2.0]` for the canonical voice. No one-liners.
4. Reference exact file paths and test files in the prose, so `git blame CHANGELOG.md` points readers at code.

### 4. Sync README test counts

```bash
bash scripts/check-test-counts.sh --update
```

Skipping this fails CI's `Verify README test counts` step.

### 5. Lint + tests locally

```bash
shellcheck -S style ops.sh install.sh scripts/*.sh
bash -n ops.sh && sh -n install.sh
bats --tap tests/        # test_image_integration.bats may fail if ops-dev isn't built locally; CI rebuilds it
lua tests/lua/run.lua
```

### 6. Commit and tag

Pattern: `chore: cut vX.Y.Z`. Body: 3-6 highlight bullets ending with a pointer to the CHANGELOG section. **No `Co-Authored-By:` line** (per the user's global preference).

```bash
git add ops.sh CHANGELOG.md README.md   # whatever you actually touched
git commit -m "$(cat <<'EOF'
chore: cut vX.Y.Z

Bumps OPS_VERSION to X.Y.Z and adds the [X.Y.Z] CHANGELOG section.
Highlights from this release:

- ...
- ...

See CHANGELOG.md [X.Y.Z] for the full per-feature breakdown.
EOF
)"

git tag -a vX.Y.Z -m "vX.Y.Z — see CHANGELOG.md"
```

Cuts go directly on `main` — no release branch. Push branch then tag, fast-forward (no `--force` on a clean cut):

```bash
git push origin main
git push origin vX.Y.Z
```

### 7. Watch CI; amend in place if it fails

The convention here is **one clean cut commit per release**, not a `cut + fix CI` pair. If CI fails:

```bash
# fix the issue, then:
git add <files>
git commit --amend --no-edit
git tag -d vX.Y.Z && git tag -a vX.Y.Z -m "vX.Y.Z — see CHANGELOG.md"
git push origin main --force-with-lease
git push origin vX.Y.Z --force
```

Ask the user **once** before the first force-push of a session (force-pushing main is destructive on shared state); after that explicit OK, iterate freely until CI is green.

Poll CI without blocking the chat:

```bash
gh api repos/gigi206/ops-cli/actions/runs/<run-id> --jq '.status'
```

### 8. (Optional) Publish a GitHub Release

Tags are pushed to GitHub but the **Releases** page stays empty unless explicitly published. Historically we have **not** published GitHub Releases on this repo — only tags. If the user wants one, ask whether to attach assets or just generate notes from the tag.

---

## Repo-specific gotcha worth remembering

**Shellcheck on Ubuntu apt (`noble` / 24.04) is 0.9.0**, and that version treats `info`-level warnings as exit-1 under `-S style`. Newer shellchecks (0.10+ from linuxbrew, koalaman/shellcheck docker, etc.) do not. CI installs via `apt-get install shellcheck` so it gets 0.9.0; local dev usually gets a newer version. Symptom: `mise run lint` passes locally but CI fails on `Shellcheck ops.sh + helper scripts (style level)`. Common culprits:

- **SC2015** (`A && B || C is not if-then-else`) — refactor to `if [ … ]; then …; fi` rather than `# shellcheck disable`. The trade-off is two extra lines for clarity.
- **SC2016** (`expressions don't expand in single quotes`) — when the literal `$PATH` is intentional in a user-facing message, use `printf "…\$PATH\n"` (double quotes + escaped `$`) instead of single quotes.

Reproduce CI's exact behaviour locally with: `docker run --rm -v "$PWD":/work -w /work ubuntu:latest bash -c 'apt-get update -qq && apt-get install -y -qq shellcheck && shellcheck -S style ops.sh install.sh scripts/*.sh'`.
