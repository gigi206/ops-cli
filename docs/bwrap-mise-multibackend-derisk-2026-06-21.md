# De-risk: auto-equipping a project's non-nix mise `[tools]` in-cage (2026-06-21)

Before wiring multi-backend support, a throwaway live spike settled the one
load-bearing unknown for the launch path: **does a non-`nix:` mise backend tool
(`aqua:`/`github:`/`npm:`/…), declared in a project's `mise.toml [tools]`,
auto-install in-cage and land on `PATH` through the existing shims mechanism —
on a plain `ops run`, with the shared store untouched?** It does, and the spike
fixed the exact conditions and the cost.

## Verdict

A project declaring `[tools] "aqua:BurntSushi/ripgrep" = "latest"` (anchored on a
`.ops.toml`), launched with an in-cage `mise install` of the explicit non-nix
token:

- **installs in-cage**: aqua downloaded ripgrep 15.1.0 (musl), verified the
  checksum, extracted, installed — into the per-(project/app) home under
  `$MISE_DATA_DIR/installs/…`, which is durable;
- **resolves through the shim**: `command -v rg` → `…/.local/share/mise/shims/rg`,
  and `rg --version` ran. The shim resolves because the **trusted** project config
  *sets* the version (`latest`), unlike an ad-hoc `mise install` with no config
  entry (which leaves a `No version set` shim — the 2b.5 caveat). This is the
  load-bearing result: a config-declared non-nix tool reaches `PATH` with no
  `mise use`/activation, on the non-interactive `ops run` path.

## The conditions (the spike's payoff)

1. **`MISE_TRUSTED_CONFIG_PATHS=<project dir>` in the cage.** Without it the
   in-cage mise does not trust the project `mise.toml`, so `mise install` (reading
   the config) installs nothing and the shim cannot resolve. ops must set this for
   the launch where it auto-equips. (The cage already carries `MISE_EXPERIMENTAL=1`
   + `MISE_YES=1`; those are necessary but not sufficient — config *trust* is the
   missing piece for reading the project's declared tools.)
2. **Install by explicit non-nix token** (`mise install "aqua:BurntSushi/ripgrep@latest"`),
   not a bare `mise install`. A bare install would also (re)install the config's
   `nix:` tools, which ops already provisions host-side and seeds — duplicated work
   and a deeper version of the host-vs-in-cage `nix:` divergence CLAUDE.md flags.
   Proven: the explicit aqua-only install left a sibling `nix:jq` untouched.
3. **The shims dir on `PATH`** (already wired in 2b.5). After install mise reshims;
   the new `rg` shim sits in the already-on-`PATH` shims dir, so it resolves within
   the same cage.

## Cost (measured, a real `ops run`)

- **Cold** (first launch, tool absent): ≈ 2.8 s total — download-bound (network).
- **Warm** (already installed): ≈ 1.15 s total; the warm `mise install` reports
  "all tools are installed" and **touches no network** — a `latest` spec does **not**
  re-resolve upstream once a version is installed. The marginal mise overhead is
  ~0.3 s on top of the bare cage.
- **Persisted-shim**: a warm `ops run -- rg` (no install step at all) already
  resolves `rg` through the persisted shim — so the install only does work on the
  first launch into a fresh per-(project/app) home; later launches are free even if
  the wrap re-runs the (idempotent, network-free) install.

The install-wrap is therefore gated on the project actually declaring non-nix
tools, so a project that declares none pays nothing.

## Posture — OPEN (user's call, 2026-06-21)

The spike enabled the install for an **untrusted** project (the trust env was set
inside the cage), and it worked — so the **open** posture (self-equip, like
`ops mise`, where the egress allowlist is the real control) is mechanically viable
and sidesteps any "trust the writable project config" window (untrusted ⇒ no
integrity expectation; trusted ⇒ self-harm). The user chose **open**: auto-equip
runs whether or not the project is trusted; the real gate is that
`network = "allowlist"` is configurable only from a trusted/global config, so an
untrusted project may *declare* `aqua:evil/x` but cannot *open* the egress to fetch
it.

## Composition with egress — PROVEN live (the advisor's discriminating case)

Under `network = "allowlist"` the install fetches through the in-cage forwarder, so
`socat` must be up first. The install-wrap wraps `cmd` **first**, then
`egress::wrap_command` wraps the result — socat nests outermost, the install runs
after it. Under `shared`/`none` there is no egress wrap, so the install-wrap stands
alone.

The load-bearing unknown an advisor flagged: a non-`nix:` tool downloads via mise's
**own reqwest** (not nix's libcurl), and mise's reqwest reads the certificate
**file**, not the CA-bundle env. So whether mise's reqwest trusts the proxy's
per-session **MITM** CA on a *direct* download was untested by the `nix:jq`
allowlist smoke (whose heavy fetch is nix's libcurl). A throwaway probe settled it:
a trusted `network = "allowlist"` (allow `cache.nixos.org` only; aqua's github fetch
rides the built-in nix-cache allow-set) ran `ops run -- rg --version` to
`ripgrep 15.1.0` — so mise's reqwest **does** trust the MITM CA on a direct download,
and the wrap composition is correct. This is now a committed e2e
(`the_cage_auto_equips_a_non_nix_tool_under_a_network_allowlist`), the more valuable
of the two (it is the posture the shipped profiles use).

`network = "none"` + a non-nix tool is an inherent conflict (install needs network):
the launch **skips** the install (it would only fail) and prints a loud, by-name
warning, not the host `nix:` hard-fail — an already-equipped tool still resolves
through its persisted shim.
