# Store de-risk — record (2026-06-15)

> Empirical closure of the §7.4 store-mechanism checklist
> ([`bwrap-architecture.md`](bwrap-architecture.md) §7.4). The chosen design —
> a **single shared flat store**, read-only at consumption / read-write only
> during ops-mediated provisioning, with **trust-gated** provisioning — is
> de-risked here. These results are **host/kernel-specific**; re-run on the
> target host before trusting them (especially on a restricted Ubuntu 24.04+,
> where capability-bearing userns is off by default).

## Host

| | |
|---|---|
| OS / kernel | Ubuntu 26.04, `7.0.0-22-generic` x86_64 |
| nix | 2.34.5, daemonless invocation (`NIX_REMOTE=`) |
| `kernel.apparmor_restrict_unprivileged_userns` | `0` |
| `kernel.unprivileged_userns_clone` | `1` |
| `sandbox` (effective) | `true` |
| `auto-optimise-store` | `true` |
| `require-sigs` | `true` (`trusted-public-keys` = `cache.nixos.org-1:…`) |

All experiments use a throwaway **user-owned** store under `mktemp -d`, cleaned
up on exit. `NIX=/nix/var/nix/profiles/default/bin/nix`.

## Experiment 1 — build sandbox ON, outside the cap-dropped cage (load-bearing)

**Question.** Can ops-mediated provisioning run a from-source nix build with
`sandbox = true` daemonless, into a user-owned store, in **plain host context**
(caps available)? The spike showed `sandbox = false` is forced *inside* the
bwrap cage; provisioning runs *outside* it.

```bash
STORE=$(mktemp -d); trap 'chmod -R u+w "$STORE"; rm -rf "$STORE"' EXIT
export NIX_REMOTE=
EXPR='let p = (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem};
      in p.runCommand "ops-derisk" {} "echo from-source-ok > $out"'
# from-source (unique output, uncached) WITH the build sandbox ON:
$NIX --store "$STORE" build --impure --no-link --print-out-paths \
     --option sandbox true --expr "$EXPR"
```

**Result: ✓ `rc=0`.** `building '…ops-derisk.drv'…` runs and the unique output
path is produced.

**Isolation signature (proof the sandbox actually engaged).** A first attempt
with an under-declared raw `derivation { builder = "${bash}/bin/bash"; … }`
failed *inside* the build with `ENOENT` — the builder's `ld-linux` was not
mounted, because a `sandbox = true` build exposes only the derivation's
**declared closure**. The `runCommand` form (which carries its stdenv closure)
then succeeded. Had the sandbox been silently off, the raw derivation would have
*succeeded* via the host's real store. Failure-then-success is the signature that
the build sandbox was real.

## Experiment 2 — concurrent provision-rw vs a live consume-ro (+ auto-optimise)

**Question.** Is a provisioning write (rw) — including `auto-optimise-store`
hardlinking — safe while a sandbox holds the same store read-only and actively
execs a store binary?

```bash
STORE=$(mktemp -d); trap 'chmod -R u+w "$STORE"; rm -rf "$STORE"' EXIT
export NIX_REMOTE=
# populate WITHOUT auto-optimise, so `store optimise` has duplicates to hardlink:
CU=$($NIX --store "$STORE" build --no-link --print-out-paths \
      --option auto-optimise-store false 'nixpkgs#coreutils' | head -1)
BASH=$($NIX --store "$STORE" build --no-link --print-out-paths \
      --option auto-optimise-store false 'nixpkgs#bash' | grep -v -- '-man$' | head -1)

# live ro consumer: exec a store binary in a loop, assert output integrity
bwrap --ro-bind "$STORE/nix" /nix --proc /proc --dev /dev --tmpfs /tmp --unshare-all \
  "$BASH/bin/bash" -c '
    fail=0
    for ((i=0;i<150;i++)); do
      out="$('"$CU"'/bin/cat --version 2>&1)" || fail=1
      case "$out" in *coreutils*) ;; *) fail=1;; esac
      '"$CU"'/bin/sleep 0.1
    done
    [ $fail -eq 0 ] && echo CONSUMER_OK_NO_FAILURES || echo CONSUMER_HAD_FAILURES
  ' &
CONSUMER=$!

sleep 1                                            # let the consumer get going
$NIX --store "$STORE" build --no-link --option auto-optimise-store false 'nixpkgs#jq'  # rw provision
$NIX --store "$STORE" store optimise               # hardlink UNDER the live consumer
wait $CONSUMER
$NIX --store "$STORE" store verify --all           # integrity
```

**Result: ✓.** `store optimise` reported `920.9 KiB freed by hard-linking 863
files` *while the consumer ran*; consumer printed `CONSUMER_OK_NO_FAILURES`
(150/150 iterations, output integrity intact); `store verify --all` clean.
Unix semantics hold: hardlink-via-rename preserves the open inode, and new
execs pick up the identical hardlinked inode.

## Experiment 3 — gcroot handoff + GC (the store stays bounded & per-project cleanable)

**Question.** Does a gcroot keep a path alive across GC, does GC collect the
rest, and does a shared store dedup + stay cleanable when a project is removed?

```bash
STORE=$(mktemp -d); trap 'chmod -R u+w "$STORE"; rm -rf "$STORE"' EXIT
export NIX_REMOTE=; ROOTS="$STORE/roots"; mkdir -p "$ROOTS"

# project A: coreutils + jq ; project B: coreutils (shared) + ripgrep — all gcrooted
$NIX --store "$STORE" build --out-link "$ROOTS/A-coreutils" 'nixpkgs#coreutils'
$NIX --store "$STORE" build --out-link "$ROOTS/A-jq"        'nixpkgs#jq'
$NIX --store "$STORE" build --out-link "$ROOTS/B-coreutils" 'nixpkgs#coreutils'
$NIX --store "$STORE" build --out-link "$ROOTS/B-ripgrep"   'nixpkgs#ripgrep'
# (A and B resolve coreutils to the SAME store path — one physical copy)

# "remove project B": drop its gcroots, then GC
rm -f "$ROOTS/B-coreutils" "$ROOTS/B-ripgrep"
$NIX --store "$STORE" store gc
```

**Result: ✓.** coreutils path is **identical** for A and B (dedup: one copy).
Before GC: 388 MB / 1653 paths. After dropping B's roots + `store gc`:
`752 store paths deleted, 189.3 MiB freed` → 56 MB / 901 paths. **coreutils
survives** (still rooted by A), **jq survives** (A), **ripgrep is collected**
(was exclusive to B). The store is bounded by the union of currently-referenced
closures and is cleanable per project — the `session/` GC model (M5), with
standard nix policy (`--delete-older-than`, max generations, GC-on-removal) for
stale generations.

## Verdict

| Check | Verdict |
|---|---|
| 1. `sandbox = true` build, daemonless, outside the cage | ✓ proven (rc=0 + isolation signature) |
| 2. provision-rw concurrent with live consume-ro (+ auto-optimise) | ✓ safe (863 files hardlinked, 0 failures, verify clean) |
| 3. trusted vs untrusted provisioning | decided: trust-gate (Option 1), not an experiment |
| 4. gcroot handoff + GC | ✓ bounded, deduped, per-project cleanable |

Conclusion: the **shared flat store + trust-gated provisioning** design is
de-risked. See [`bwrap-architecture.md`](bwrap-architecture.md) §7.4 for the
decision and the M3 follow-ups (mise-nix bridge relocation, dry-run enforcement,
fixed-output-derivation boundary).
