# `ops` (bwrap) — architecture skeleton

> Blueprint for the new `ops` (bubblewrap substrate + daemonless nix). Synthesizes
> the feasibility study ([`bwrap-spike-2026-06-14.md`](bwrap-spike-2026-06-14.md)) and the
> threat model + decisions
> ([`bwrap-threat-model-and-binds.md`](bwrap-threat-model-and-binds.md)) into
> Rust modules, CLI surface, and milestone ordering.

## 1. The pipeline (overview)

```
  config (global + project)
        │   ← trust gate (content hash, direnv model; untrusted ⇒ security fields ignored)
        ▼
  tool resolution  ── mise + nix (daemonless, sandbox=false, pinned nixpkgs)
        │
        ▼
  ┌──────────────────────────────────────────────┐
  │   SandboxSpec   (THE single audit point)       │   ← the policy engine (mode A/B) produces it
  └──────────────────────────────────────────────┘
        │
        ▼
  bwrap assembler  (binds + env + FHS + namespaces + network)  →  argv  (PURE function of the Spec)
        │
        ▼
  launch: exec bwrap, hand over the TTY
```

**Keystone: `SandboxSpec`.** A **declarative and pure** struct that describes
everything the sandbox exposes (binds, env, store, namespaces, holes, cmd). The
entire upstream **produces** it; the assembler **consumes** it. Security invariant:
**only the Spec constructor adds exposure; argv generation is a pure function of
the Spec.** ⇒ the security review has **a single surface** to audit.

## 2. Rust modules

| Module | Role | Reuses current code? |
|---|---|---|
| `cli/` | clap surface + dispatch | adapts `src/cli.rs` |
| `config/` | parse + global/project layering (symmetric schema), validation | **adapts** the existing layering machinery |
| `trust/` | trust gate: **hashing of security fields**, store of validated hashes, re-prompt on change (direnv); gating of security fields for an untrusted project | **extends** `src/trust.rs` |
| `store/` | provisions the **user-owned daemonless store** (relocated static nix) + manages the base/overlay layout, daemonless nix invocation (`NIX_REMOTE=`, `sandbox=false`). ⚠️ **PROVISIONAL mechanism — see §7.4** | new |
| `provision/` | resolves declared tools/packages → store paths via **mise+nix**; mise-nix bridge; **nixpkgs pinning** for untrusted | **adapts** the mise-nix bridge (lua) |
| `sandbox/` | **the core** — assembles the `SandboxSpec` then the bwrap argv | new |
| ↳ `sandbox/spec.rs` | the `SandboxSpec` struct + its invariants | new |
| ↳ `sandbox/policy.rs` | mode A/B × trust → which holes are open (the matrix from §5 of the threat model) | new |
| ↳ `sandbox/binds.rs` | zones 0/1/2; TOCTOU canonicalization; **synthetic** `/etc/passwd`+`group`; FHS userland (loader+libs) | new |
| ↳ `sandbox/env.rs` | env zone: `--clearenv` + allowlist + secret injection (trusted config only) | new |
| ↳ `sandbox/net.rs` | network policy (share/unshare; future allowlist hook) | new |
| ↳ `sandbox/argv.rs` | final construction of the bwrap argv (pure) | new |
| ↳ `sandbox/launch.rs` | exec bwrap + hand over the TTY (exec-replace model) | adapts `src/run/` |
| `session/` | **session registry** (no daemon → on-disk registry): list of active sandboxes, "2nd terminal in the same env", **GC** of per-project `$HOME`/overlays | new (replaces `status.rs`/`clean.rs`) |
| `app/` | app definitions (claude/gemini/…): which tool, **which secrets required** (declared trusted), which mode | **adapts** `src/app/` + `apps.toml` |
| `doctor/` | prerequisites (**userns**!), store health, nix version | **reorients** `src/doctor.rs` |
| `platform/ term/ util/ download/` | unchanged (download serves to fetch the static nix / assets) | keep |

**Disappearing**: `src/build.rs` (image build), `src/nerdctl.rs`, the OCI
runtime wrapping; `clean.rs` + `status.rs` → merged into the **`session/`** module
(GC of overlays/`$HOME` + session listing).

## 3. The central struct (sketch)

```rust
struct SandboxSpec {
    mode:       ActorMode,        // Interactive (A) | Agent (B, default)
    trust:      TrustTier,        // Untrusted (default) | Trusted
    workdir:    PathBuf,
    binds:      Vec<Bind>,        // { src, dest, Ro|Rw } — the only source of FS exposure
    store:      StoreLayout,      // { base_ro, per_project_overlay_upper }
    env:        EnvPolicy,        // { clearenv: true, allowlist, injected_secrets }
    fhs:        FhsUserland,      // { loader, lib_paths } — 100% nix userland
    net:        NetPolicy,        // Shared{blocks} | Isolated | Allowlist(future)
    namespaces: NsPolicy,         // pid: REQUIRED, user, ipc, uts, mount…
    holes:      Holes,            // { gui: None|Wayland|X11, ssh_agent, container_socket }
    cmd:        Vec<String>,
}
```

Invariants checked at construction: `namespaces.pid == true`; no bind outside the
project-root/store/synthetic for `Untrusted`; `env.clearenv == true`;
`holes.container_socket == false` if `mode == Agent`.

## 4. CLI surface

| Command | Effect | Mode |
|---|---|---|
| `ops shell` | interactive dev shell in the project sandbox | A |
| `ops run -- <cmd>` | runs a command in the sandbox | A |
| `ops app <name>` | launches a packaged app (claude/gemini/…); the mode is **declared by the app** | B (default) |
| `ops install <pkg>` | installs a tool in the project (in-sandbox, overlay) | — |
| `ops trust` / `ops untrust` | manages trust (content hash, re-validation) | — |
| `ops config …` | views/edits the layered config | — |
| `ops doctor` | checks prerequisites (**userns**), store health | — |
| `ops self-update` | updates the binary | — |

## 5. Milestone ordering (the DAG)

| M | Title | Content | Deliverable |
|---|---|---|---|
| **M0** | Prerequisites + store bootstrap | `ops doctor`: **userns absent → hard-fail with remediation, NEVER a silent fallback** (proot = no security boundary); provisions the daemonless store; **validate the EXACT design path: base ro + overlay upper + daemonless install + consistency of the nix SQLite db across the overlay** (≠ what the spike proved, which was a *flat* store) | productized spike **+ store de-risking (§7.4)** |
| **M1** | Minimal sandbox | `SandboxSpec` + `binds.rs` (zones 0/1/2) + FHS userland + `--clearenv` + `--unshare-pid` + same-uid + **`session/` (registry, 2nd terminal)**; `ops shell` isolates the host. Also: **`doctor`** — replace the userns *proxy* probe with a real bwrap smoke run through this argv builder (turns "looks like it'll work" into "verified") | usable shell, Mode A |
| **M2** | Config + trust | global/project layering; content-hash trust gate (direnv); gating of untrusted fields | `.ops.toml` drives the sandbox **safely** |
| **M3** | Tool provisioning | mise+nix bridge; declarative packages; in-sandbox install → per-project overlay; pinned nixpkgs | reproducible tools |
| **M4** | Apps + **Mode B** | app definitions; policy engine (A/B × trust → holes); least-privilege secret injection. ⚠️ **ships the flagship with the confidentiality hole OPEN until M6** (injected API key + open network = possible exfiltration, cf. §1 of the threat model). Option to validate: bring forward here the 2 near-free blocks (`169.254.169.254`+localhost) + opt-in egress allowlist (you said network last) | **`ops app claude` = the differentiator, confidentiality-open** |
| **M5** | Parity holes + GC | GUI (Wayland); container socket **Mode A only**; ssh-agent; **GC of per-project overlays/`$HOME`** (`session/`) | opt-in conveniences + housekeeping |
| **M6** | **Network policy / allowlist** | netns layer + filtering (nono/greywall); metadata/localhost blocks → allowlist | **closes the confidentiality hole — LAST** |
| **M7** | Hardening (later) | subuid tier; Landlock file ACL; cgroups/DoS limits | opt-in tiers |

Rationale: **M1** quickly delivers something usable; **M4** delivers the
differentiator; **M6** closes confidentiality last (decision made).

## 6. Cross-cutting invariants
- **`SandboxSpec` = single audit surface**; argv = pure function of the Spec.
- **Default-deny** everywhere (FS, env, network later).
- **`--unshare-pid` always** (same-uid is only safe with it).
- **Untrusted config never touches the security fields.**
- **In-sandbox installs only**; base store ro; per-project overlay (⚠️ provisional, cf. §7.4).

## 7. Design questions still open (to settle with the user)
1. **Config noun model.** [[noun-inheritance-model]] locks
   `image → container → app` — **obsolete** (no more image or container).
   Likely replacement: `profile`(userland/base tools) → `sandbox`(runtime:
   binds/env/net/mode) → `app`. To be redefined.
2. **CLI verb for agents.** `ops app <x>` with mode declared by the app
   (proposed) vs an explicit `ops agent <x>` that makes posture B visible.
3. **How ops embeds nix.** Static nix binary **embedded** in the ops asset,
   or **downloaded** at bootstrap (base closure from a binary cache /
   cachix)? Impacts the asset size and the first `ops doctor`.
4. **⚠️ Store mechanism — PROVISIONAL (the only point that could force a
   structural change).** The spike proved a **flat user-owned store** bound on `/nix`
   — **not** the "base ro + per-project overlay upper + daemonless install +
   consistency of the nix SQLite db across the overlay" design. This exact path is **not
   tested** → to be de-risked in **M0**. And an unresolved **trilemma**:

   | Mechanism | disk dedup | per-project isolation (anti-poison) | multi-session |
   |---|---|---|---|
   | shared flat store | ✓ | ✗ | ✓ (nix db locks) |
   | per-project flat store | ✗ (574 MB × N) | ✓ | ✓ |
   | **base+upper overlay (the design)** | ✓ | ✓ | **✗** |

   The overlay buys dedup+isolation but **breaks multi-session**: overlayfs does
   not support the same `upperdir` mounted by 2 concurrent mounts — yet 2 sessions
   of the same project **must** share the upper. The irony: the **proven flat**
   store handles concurrency on its own via the nix db locks. Lead (spike, not
   decision): **nix signature verification** already covers poisoning for
   **cache-substituted** paths (only **locally built** paths under
   `sandbox=false` are unsigned) → could **reopen the shared flat store option**.
