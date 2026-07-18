# Flake cross-project reuse — feasibility spike (2026-07-18)

Throwaway spike. Nothing installed; host `bwrap` + host/bundled `nix` only.

## The problem

A `flake:` package (and inline flake) builds **in-cage** (`nix build --out-link`),
its output landing in the launch's **per-project** store, with the out-link *symlink*
kept in the (possibly `home_scope = "global"`) home. For a global-home app launched
from a **new project**:

- the flake output is **not** in the new project's store (it is not in
  `collect_roots`, so `seed_project_store` never seeds it), and
- the warm out-link in the global home points at a `/nix/store/<hash>` **absent**
  from the new project's `/nix`,

so the `[ -e "$out/bin" ]` short-circuit fails → **rebuild** (~minutes; hard failure
if offline). `nix:` packages do **not** have this problem: they build host-side into
the **shared** store and are seeded per-project, so a fresh project re-seeds from the
shared store (offline-ok).

## The security wall (why the cheap fixes are unsafe)

Making the flake output cross-project reusable by **sharing the store** — or by
promoting/copying one project's in-cage build to a shared cache — is a **write-isolation
regression**:

- the flake build runs **in-cage with `sandbox = false`** (M4.1 seccomp reconciliation),
  so it is **not hermetic** — a same-uid Mode-B agent can overwrite a per-project store
  path in place (name/hash unchanged, content changed), and a later build using it as a
  dependency silently consumes poisoned content;
- promoting that output to a cross-project shared store lets project A's cage influence
  project B's launch — the exact contamination the per-project store exists to prevent.

Worse for the "dedicated host-orchestrated build cage into a **writable shared-store
bind**" idea: the flake **itself** is untrusted third-party code whose eval + build
scripts run under `sandbox = false`; pointed at a writable shared store it can write
**arbitrary** paths, poisoning what every project/app seeds from — strictly worse than
today's one-project blast radius. The "holes" (dbus/fonts/mesa) and `deb:` precedents do
**not** transfer: they build **trusted nixpkgs** attributes (`deb:` runs *no* build
script — `dontBuild`). Flake went in-cage precisely because arbitrary flake eval is
arbitrary code.

## The only safe direction, and the load-bearing unknown

Safety requires the build to run under **nix's own build sandbox** (`sandbox = true`,
hermetic per-build isolation) in a **dedicated build-only cage** with **no agent and no
`/project`** — then its output can be promoted to the shared store and seeded per-project
like `nix:`. Nix's build sandbox needs a **nested user namespace that maps root** (to set
up the build chroot + mounts) plus the mount/unshare syscalls M4.1's denylist blocks.

**Load-bearing question:** can that nested root-mapping userns exist inside a bwrap cage
at all, given sbx's **single-uid** (same-uid) cage model?

## Spike results (all run live on this host)

Host facts: `/etc/subuid` = `gigi:100000:65536` (+ subgid); `newuidmap`/`newgidmap`
present, setuid-root; `kernel.apparmor_restrict_unprivileged_userns = 0`; host nix
`sandbox = true` by default.

1. **Single-uid cage (sbx's model) → BLOCKED.** Inside a faithful sbx-like cage
   (`bwrap --unshare-user --uid 1000 --gid 1000 [--cap-drop ALL --new-session] …`),
   `unshare --user --map-root-user id` fails with
   `échec d'écriture /proc/self/uid_map: Opération non permise` (EPERM), with **and**
   without cap-drop. This confirms the M4.1 note live: the single-uid cage cannot nest a
   root-mapping userns, so **daemonless `nix build --option sandbox true` cannot
   initialise its build sandbox inside sbx's agent cage.**

2. **Multi-uid subuid userns → the nested root-map WORKS (kernel primitive only).** Under
   an outer userns that maps the **subuid range** (`unshare --user --map-auto
   --map-root-user …`), the nested root-mapping userns **succeeds**: the inner
   `unshare --user --map-root-user id` prints `uid=0(root)`.

   **Scope of this result, stated honestly:** it proves *one kernel primitive* — a subuid
   (`map-auto`) userns permits nested root-mapping — run **as the plain user, not inside a
   bwrap cage, and not involving nix at all**. It does **not** prove that daemonless
   `nix build --option sandbox true` initialises its sandbox and **completes a build**
   inside an sbx-constructed subuid cage (the build chroot, `pivot_root`, `/proc`, and the
   mounts are well beyond nesting a userns). Note also that **bwrap alone does single-uid
   self-mapping** — a subuid-mapped cage needs `newuidmap` orchestration *outside* bwrap
   (or a pre-made userns fd), i.e. different cage-construction tooling entirely.

(A direct daemonless `nix build --option sandbox true` into an empty user store failed —
but only because the throwaway test set `substitute = false` on an empty store, forcing a
from-source build of the whole gcc toolchain; that is a test-construction artifact, not a
sandbox-init failure. End-to-end feasibility is therefore **unproven**.)

## Verdict: kernel-feasible, end-to-end UNPROVEN — and it changes sbx's security/portability story

The safe design (build cage running nix's **own** `sandbox = true`) is **kernel-feasible**
but **end-to-end unproven**, and — the headline — it does not merely add a subsystem, it
**changes two of sbx's defining properties**:

1. **A second cage security model.** The multi-uid cage is essentially *how rootless nix
   already sandboxes* (newuidmap + subuid) — the mechanism is not exotic. The real cost is
   that it introduces a **second** cage model alongside sbx's deliberate **same-uid** one
   ("same-uid → the bind layout IS the security control"). Two models to reason about and
   keep secure.
2. **A new host prerequisite that dents portability.** It **hard-depends on `/etc/subuid` +
   the setuid `newuidmap` helper** — a prerequisite sbx's same-uid model *specifically
   avoids*, and one **absent on exactly the restricted/hardened hosts `doctor` already
   worries about**. So this partially regresses sbx's portability and its
   no-privileged-helper story.

Beyond those, the implementation is still large:

- a **multi-uid build-cage constructor** (newuidmap orchestration, outside bwrap's
  single-uid mapping);
- the build cage needs the flake's **fetch network** (its own egress allowlist/proxy,
  since it runs before/without the agent cage);
- a **security argument** that a `sandbox = true` build in a multi-uid cage produces output
  safe to promote to the shared store (needs advisor review — premature until greenlit);
- promotion of the built closure to the shared store + seeding per-project like `nix:`.

**Gate before any implementation:** an end-to-end spike proving a daemonless
`sandbox = true` build *completes* inside an sbx-constructed subuid cage (substituters on)
— run **only if the user greenlights** building this.

## Cost/benefit

All of the above buys the elimination of a **one-time, first-launch-per-new-directory**
rebuild of a global GUI app — already paid via network at first launch by the shipped
profiles, and hit by most users from only one or two directories. The existing
`home_scope = "project"` knob already aligns store and home for anyone wanting zero
cross-project surprise. Whether that trade is worth a multi-uid build-cage subsystem +
its new host prerequisite + its own security argument is a **product decision**, recorded
here for that call.
