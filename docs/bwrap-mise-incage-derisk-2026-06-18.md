# De-risk: the mise `nix:` backend plugin in the open cage (2026-06-18)

Before wiring `ops mise` passthrough, a throwaway live spike settled the one
load-bearing unknown: **does the bundled mise "nix" backend plugin register and
install a `nix:` tool *in-cage*, against the per-project relocated single-user
store, with the shared store left untouched?** It does — and the spike's real
value was the exact set of conditions that make it work.

## Verdict

`mise install nix:jq` inside the open cage (cage `/nix` = a per-project writable
store seeded from the shared one) succeeded: jq `1.8.1` resolved through nixhub,
built/substituted into the **project's own store**, ran (`jq-1.8.1`), and the
**shared store stayed byte-identical** (same teeth as the store-isolation smokes:
sorted store-path fingerprint, before == after). The plugin's `register_gc_root`
writes a hardcoded `/nix/var/nix/gcroots/mise` — which the architecture notes flag
as daemon-store-shaped — but in-cage `/nix` *is* the project store, so the gcroot
lands there correctly (and, as a bonus, roots the installed tool against an in-cage
`nix-collect-garbage`). No plugin patch was needed for the relocated layout.

## The conditions (the spike's payoff)

For the in-cage mise to self-equip a `nix:` tool, all of the following are needed —
each discovered by a failing spike iteration, not by reasoning:

1. **`MISE_EXPERIMENTAL=1`.** A `nix:` tool uses a mise *custom backend*, which mise
   gates behind this flag (`custom backends is experimental`).
2. **`NIX_CONFIG` with `extra-experimental-features = nix-command flakes`.** The
   plugin builds a flake reference (`nix build github:NixOS/nixpkgs/<commit>#<attr>`),
   which needs flakes + the new CLI enabled. `extra-` appends to nix's compiled
   defaults, so the existing offline base build still works.
3. **The plugin registered.** mise discovers backends under `$MISE_DATA_DIR/plugins/`;
   a `plugins/nix` symlink (what `mise plugins link` creates) is enough — ops can
   pre-create it without running mise.
4. **mise present in the cage**, on `PATH`.
5. **`command -v nix`, not `which nix`.** The plugin's `check_nix_available` probed
   with the `which` *binary*, which the hermetic cage does not carry (it is a separate
   package, not coreutils). nix was on `PATH` the whole time; the probe was wrong. The
   fork's `lib/platform.lua` now uses the POSIX builtin `command -v`.

## Latent gap (recorded, not solved here)

The plugin also shells out to `find` (findutils, not coreutils) — but only on the
`MiseEnv`/flake path, **not** the `nix:` *install* path exercised here. "The minimal
hermetic cage may not satisfy every external tool an agent's toolchain shells out to"
is the **curated-base-packages (M3.4)** concern, not a blocker for `ops mise`.

## Consequence to keep conscious

`ops mise install` (in-cage lua plugin → `nixhub.lua`) and `ops run`'s host-side
`nixhub.rs` → `tools.lock` are **two parallel resolution+realise paths for the same
`nix:` syntax that share no state**. A tool the agent self-installs via `ops mise` is
not pinned in `tools.lock`, not reproduced by a fresh `ops run`, and outside
`ops upgrade mise`'s reach. That is the correct open-cage semantics (the agent equips
its own cage), but it is a deliberate divergence, not an oversight.
