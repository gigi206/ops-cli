# `ops` (bwrap) — threat model & bind layout

> Design document that **drives everything else** in the new `ops` (bubblewrap
> substrate + daemonless nix; feasibility validated in
> [`bwrap-spike-2026-06-14.md`](bwrap-spike-2026-06-14.md)). The layout of
> mounts, environment, and network follows directly from the threat model
> below.

## 0. The backbone: TWO actor modes

All the "hole by hole" decisions (network, GUI, nested containers,
ssh-agent) contradict each other as long as we reason about **one** fuzzy
actor. We separate them; this is the structuring axis:

| | **Mode A — interactive dev shell** | **Mode B — autonomous agent** |
|---|---|---|
| Who drives | The **user** | The **agent's actions** (LLM) |
| Trust | Semi-trusted (risk mostly to oneself) | **Untrusted** (prompt-injection, poisoned dependency) |
| GUI / ssh-agent / nested containers | Conveniences | **Escape / exfiltration channels** |

**ops's announced differentiator = Mode B.** → **Mode B is the default
posture; Mode A is an explicit opt-in.** Each "dangerous hole" default
falls out of this axis instead of being debated one by one.

## 1. Threat model

### Assets to protect
- **Secrets**: `~/.ssh`, `~/.aws`, `~/.config/gh`, `~/.gnupg`, `~/.netrc`,
  browser cookies, app tokens, **ssh-agent socket** (`$SSH_AUTH_SOCK`),
  and **environment variables** carrying secrets (`ANTHROPIC_API_KEY`,
  `GITHUB_TOKEN`, `AWS_*`…).
- **Host integrity**: writing outside the project (shell rc files → persistence,
  system, other projects).
- **Other projects** present on the machine.
- **Network position**: exfiltration; pivot to `169.254.169.254` (cloud
  metadata), `localhost` (dev databases/servers), LAN.
- **User identity**: acting on their behalf (signed git push, accounts).

### Adversaries
1. **Rogue / prompt-injected AI agent** (web page, README, booby-trapped dependency).
2. **Malicious dependency** (npm/pip postinstall, supply chain).
3. **Untrusted project** itself: its `.ops.toml`, its Makefiles/hooks/devshell
   are **attacker-controlled** the moment you `cd` into a cloned repo.

### Trust boundaries
1. Host ↔ sandbox (the bwrap boundary — the main one).
2. **Trusted** config (`~/.config/ops/ops.toml`, written by the user) ↔
   **untrusted** project config (`.ops.toml` of an arbitrary repo).
3. `ops` the launcher (trusted, runs on the host) ↔ everything inside the sandbox.

### Assumed attacker capabilities (inside the sandbox)
- **Arbitrary code execution under the host's uid** (the sandbox runs as
  `uid=1000`, proven). ⇒ **no uid barrier inside**: whatever is visible is
  compromised. **The bind layout IS the security control.**
- ⇒ **"read-only" protects integrity, NOT confidentiality.** A secret
  mounted read-only is still **readable**. So **a secret must be ABSENT, not read-only.**
- Reads all environment variables passed through.

### Out of scope (declared)
- Kernel 0day on namespaces/userns (bwrap == namespace security of the
  kernel; the kernel is in the TCB).
- Side channels (timing, Spectre).
- DoS / resource exhaustion (fork bomb, disk filling) — mitigated
  later (cgroups), not a v1 guarantee.
- The user deliberately sabotaging their own sandbox (but ops makes the safe
  path **the default** and the dangerous path **explicit and noisy**).

### ⚠️ Confidentiality limit to state up front
The flagship use case (claude-code) requires **both** its API key **and** the
network to `api.anthropic.com`. With an **open network by default**, a
prompt-injected agent can **exfiltrate any sandbox secret to
anywhere**. So: **as long as the network allowlist (the "nono/greywall
later" work) does not exist, there is NO confidentiality guarantee in v1.**
Blocking `169.254.169.254` + `localhost` is **necessary but far from
sufficient**. The honest v1 guarantee: *"no mutation of the host system state
/ other projects / secrets, and no exfiltration once the network allowlist
ships."*

## 2. The zones — file system (default-deny)

We start from **nothing** (no `--bind / /`). Only the explicit exists.

### Zone 0 — Hidden (deny by default)
Absent by construction: `~/.ssh`, `~/.aws`, `~/.config/gh`, `~/.gnupg`,
`~/.netrc`, browser profiles, `$SSH_AUTH_SOCK`, `/root`, the other projects,
the host's `$HOME`, most of `/etc`.

### Zone 1 — Shared read-only (integrity, non-secret)
| Mount | Source | Why |
|---|---|---|
| `/nix` (base) | **ops's trusted base store** (ro lower) | append-only, secret-free; ro = the agent cannot tamper with installed binaries |
| FHS loader | `nixpkgs#glibc.out` → `/lib64/ld-linux-…` | 100% nix userland (hermetic FHS, cf. spike) |
| `/etc/passwd`, `/etc/group` | **SYNTHETIC** (sandbox-user + nobody) | uid/gid resolution **without** leaking the host's accounts |
| `/etc/ssl/certs/ca-bundle.crt`, `…/ca-certificates.crt` | **ops's own `cacert`**, ro | TLS trust anchor, hermetic — the cage trusts ops's bundle, not the host's certs (under a network allowlist the egress proxy's per-session CA overrides it) |
| `/etc/resolv.conf` | host, ro (best-effort) | DNS (if network allowed) |
| `/dev` | minimal `--dev` (not the host `/dev`) | null/zero/urandom/tty only |

Never: `/etc/shadow`, the **host's** `/etc/passwd`.

### Zone 2 — Writable (the work surface)
| Mount | Source | Notes |
|---|---|---|
| project | host project dir, **rw** | bound at the **same absolute path** as on the host (tool compat); code is not a secret |
| sandbox `$HOME` | `…/ops/projects/<id>/home`, **rw** | **NOT** the host `$HOME`; tool caches, agent config |
| `/tmp` | fresh tmpfs | ephemeral, private |
| store (upper) | per-project overlay, **rw** | cf. §3 |
| a trusted `binds` entry with `mode = "rw"` | host path, **rw** | opt-in, **trusted-only** (an untrusted project gets no bind at all, so never a writable one); bound at its own absolute path, **after** the structural mounts in precedence so it can never make `/nix` or the identity files writable. A rw bind overlapping ops's own control plane (the data/engine, trust-marker, or config directory) is protected two ways: a bind **at or inside** one of those roots is **forced read-only** (the whole bind is control plane), while a broad bind that merely **contains** them (e.g. a whole-home rw bind) stays read-write with each control-plane path **pinned read-only in place** — its whole directory chain made mountpoints so in-cage code cannot rename a writable parent to substitute a forged engine binary or trust marker (the kernel refuses to rename/remove a mountpoint). Either way in-cage code cannot rewrite a host-executed engine binary or forge a trust marker for another project. A read-only `binds` entry (the default) exposes contents only; per the box above, read-only protects integrity, **not** confidentiality. |

## 3. The store model (corrected)

⚠️ **Stock nix is *input-addressed*, not content-addressed** (CA is
experimental). In single-user daemonless mode, the store dir **and**
`/nix/var/nix/db` are **owned by the user** → a same-uid agent of project A
can **trojanize** a store path or the db that project B (or the next
session) consumes. "CA bounds the poisoning" is **false** here.

**Retained model** (with the overlay already proven at the spike):

```
  trusted BASE store     →  --overlay-src  (ro lower, populated ONLY by ops on the host side)
  per-project upper (rw) →  --overlay      (the agent's installs land here, isolated)
  /nix in the sandbox    =  union of the two
```

The agent installs into **its upper**; the shared base stays trustworthy;
no project contaminates another.

## 4. The zones — environment (2nd layout, same rigor)

**Proven: bwrap does NOT clear the env by default** (`SPIKE_SECRET` leaked
through). ⇒ **default = `--clearenv` + explicit injection allowlist**, exactly
the same default-deny as the file system. `PATH`, `HOME`, `TERM`, `LANG`
rebuilt; secrets (`ANTHROPIC_API_KEY`…) **injected one by one**,
declared **only in trusted config**, never inherited en masse, never from
project config.

## 5. The deliberate holes (default per actor mode)

| Hole | Mode B (agent, default) | Mode A (interactive, opt-in) |
|---|---|---|
| **Network** | open in v1 **but** block `169.254.169.254` + `localhost`; **target goal = allowlist** (Landlock/netns) | same / broader |
| **GUI** | **off** by default; opt-in via `gui = "wayland"` (trusted/global only) — Wayland (per-client isolated on a well-behaved compositor), **never X11** (an X client keylogs/screenshots the other windows). **BUILT** — see §5a. | opt-in, Wayland preferred |
| **Nested containers (podman socket)** | **DROPPED** — the socket = **root-equivalent on the host** (launch a container with `/` bind-mounted). Not "gated": **absent**. A filtering proxy-broker is **future work**, not a v1 checkbox. | gated + confirmation |
| **ssh-agent** (`$SSH_AUTH_SOCK`) | **off** (hands over ALL your keys for their lifetime) | scoped opt-in |
| **Secret injection** | least-privilege, declared in **trusted** config only | same |
| **A tool's credential persistence** (e.g. claude-code's own creds) | a **dedicated, persistent, isolated** creds dir, mounted **for that tool alone** — never all of `~/.config` | same |

### 5a. The GUI / Wayland hole (BUILT — `gui = "wayland"`)

A security field `gui`, gated **exactly like `network`**: honored from the global config
(trusted by location) or a trusted project, dropped with a warning from an untrusted one — so
an agent run *on* untrusted code can never have that code open the user's compositor (the
flagship property, tested both ways). `"none"` (the default) exposes no display; `"wayland"`
opens the hole. There is **no `x11` value** — X is never offered.

The hole, when opened:

- **Mount** — a **read-only bind of the Wayland socket *file*** only (`$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY`,
  or `$WAYLAND_DISPLAY` verbatim when absolute). Never `$XDG_RUNTIME_DIR` itself — that directory
  also holds the dbus session bus, pulse, and the gpg/ssh agents, which a directory bind would
  hand to the cage. Read-only suffices because the cage runs **same-uid**, so `connect()` succeeds.
- **Env** — `WAYLAND_DISPLAY` and `XDG_RUNTIME_DIR`, fixed by ops; an untrusted `[env]` could only
  mispoint a client at a nonexistent socket (self-DoS), never redirect the bound socket.
- **Best-effort** — with no compositor socket found, ops warns and runs without the bind (the app
  fails on its own); *not* binding is the fail-closed direction for a display hole.
- **Fonts** — a fontless cage renders boxes, so the hole provisions a base font set (DejaVu)
  host-side into ops's store, **seeds it into the project store** (the cage reads it through `/nix`),
  and binds a generated, self-contained fontconfig configuration read-only at `/opt/ops/fonts.conf`,
  named to the cage's fontconfig via `FONTCONFIG_FILE`. A font package has no `bin/`, so it **cannot**
  ride the user-facing `[packages]` field (which selects a bin-bearing output) — the hole provisions
  it directly, like the base userland. Best-effort like the socket (a font fetch/stage failure warns
  and the app runs without fonts). `FONTCONFIG_FILE` is fixed by ops; an untrusted `[env]` override
  only re-points the agent's own in-cage fontconfig (self-sabotage, not an escape). The hole supplies
  the font *files* and the *configuration*; the fontconfig **library** is the app's own (a nix-packaged
  app carries it in its closure).
- **Not exposed** — `/dev/dri` (software GL renders fine), dbus, pipewire/pulse, X11/`DISPLAY`.
  Each is a separate, later, opt-in hole.

A Chromium/Electron app additionally needs `--no-sandbox` (its own namespace sandbox collides with
the cage's seccomp denylist; bwrap + seccomp + the netns *is* the boundary) plus
`--ozone-platform=wayland --disable-gpu --disable-dev-shm-usage` — these are **app argv** (a
profile's `cmd`), not hole state.

**Composition with `network = "allowlist"` (proven).** The real desktop-agent posture opens the
display hole *and* a filtered egress at once. They coexist with no special-casing: the display is a
local **Unix** socket (so it connects inside the empty netns the allowlist imposes — it needs no
network route), and its binds/env are disjoint from the egress machinery (the proxy socket + CA under
`/opt/ops`, the forwarder on cage loopback). A single-cage e2e holds the teeth together — `wayland-info`
enumerates the compositor **and** a non-allowlisted host is refused `403`, in the same launch — so the
two holes are proven to function together, not merely each alone.

**Real rendering (proven live).** The fonts are not merely *discoverable* (`fc-list`) — they
*rasterize*. A headless **Chromium** (the desktop-agent class engine) run in the cage renders a black
`Hello` on white to a screenshot: with `gui = "wayland"` the hole's DejaVu is present and the image
carries black glyph pixels (darkest pixel `0`, non-zero variance); with `gui = "none"` the cage has no
font and the *same* render is perfectly blank (darkest pixel `1`, zero variance). The only difference
between the two is the font hole, so the hole's fonts are what turn an empty page into rendered **Latin**
text — the spike's HarfBuzz `glyph_count: 0` failure, now closed. (Proven *text-vs-nothing*, not
*text-vs-boxes*: DejaVu covers Latin, so CJK/emoji would still box — broader script coverage is a
per-need extension. This is a heavy live proof — Chromium's closure makes a per-run committed test
impractical, like the in-cage flake build — so it is documented as proven-live, **not** a committed e2e.)

**Residuals (documented, not assumed away):**

- **Clipboard** — `wl_data_device` is advertised, so a *focused* GUI client can read/set the
  clipboard. Bounded to focus, but a real cross-app channel.
- **Compositor-dependent** — the isolation is the *compositor's*. On GNOME/Mutter ordinary clients
  get no screen-capture or input-injection protocol; on **wlroots** (sway/hyprland) they would get
  `wlr_screencopy` + virtual-keyboard/pointer. So "Wayland is isolated" is **host-compositor-dependent**;
  active compositor detection + a doctor warning is a later refinement.
- **A read-only `XDG_RUNTIME_DIR`** — bwrap auto-creates `/run/user/<uid>` on the read-only rootfs to
  host the socket bind, so the directory holds only the socket and is not writable. A client that
  *connects* (the Wayland case) is fine; a toolkit that wants to *write* `$XDG_RUNTIME_DIR/<app>` would
  fail. A writable per-app runtime directory is a later refinement, driven by a real app's need.

Feasibility, recipe, and the protocol enumeration: [`bwrap-gui-wayland-spike-2026-06-22.md`](bwrap-gui-wayland-spike-2026-06-22.md).

## 6. The trust gate (security-first) — DECIDED (option a)

**Decision (2026-06-14): the trust gate IS the validation.** Doing `ops trust`
means validating the content; a trusted project therefore has its config
honored **in full** — symmetric schema [[config-layering-symmetric]] **reaffirmed**,
the trust gate remains the **only** boundary.

- **Untrusted project** (default for any unblessed repo) — its `.ops.toml`
  **may**: choose which tools/packages to install **inside** the sandbox (from
  **the pinned nixpkgs only**), the workdir, the non-secret project env. It
  **may NOT**: add binds, expose a host path, broaden the network,
  enable GUI/container-socket/ssh-agent, run host-side hooks, inject
  secrets, change the userland, point to remote flakes/substituters.
  These fields are **ignored with a warning**.
- **Trusted project** (`ops trust`): config honored **in full**, on par
  with the global config.
- **Global config** (trusted, on the host): always honored.

> ✅ **Safeguard — content-bound trust (direnv model).** For "trust =
> validated content" to stay **true over time**: `ops trust` records a
> **hash** of the config's security fields. Any later change (e.g. after
> `git pull`) **re-triggers validation** before application — exactly like
> `direnv allow` re-arms when `.envrc` is edited. Without it, a trusted
> `.ops.toml` that gains `bind ~/.ssh` on the next pull would get it silently.

## 7. Supply chain (coupled to the "brokered install vs in-sandbox" fork)
- Arbitrary flake URL = **code execution** (a flake's eval can be
  impure). Restrict untrusted packages to **the pinned nixpkgs**, not URLs.
- Also block `substituters` / `extra-substituters` / `trusted-public-keys`
  from an untrusted config: **a malicious binary cache serves a trojan for
  everything**, worse than a flake.
- Coupling: if installs are **brokered on the host side**, a malicious URL =
  execution **on the host** (severe); if **in-sandbox**, it's **content** but
  feeds the store poisoning vector (§3). Both forks are decided
  together.

## 8. TOCTOU on bind sources
bwrap resolves bind **sources** in the **host** namespace, before the pivot.
If a bind path derives from a project-controlled input, a symlink
`./data → ~/.ssh` makes it bind the real `~/.ssh`. ⇒ **canonicalize + confine
bind sources to the project root.** (Symlinks **internal** to the project
are safe: they resolve **inside** the sandbox — this kills a common false
worry.)

## 9. Hard prerequisites (not preferences)
- **Unprivileged user namespaces** (otherwise: no product; cf. spike).
- **`--unshare-pid`**: the same-uid model is safe **only** thanks to the
  pidns + userns isolation. This is a **requirement**, not a default.
- **`--clearenv`** + allowlist (proven necessary).
- **same-uid** mapping by default (direct write of `uid_map`, no helper).
  The "subuid hardening" reintroduces the **setuid** helpers
  `newuidmap`/`newgidmap` → runs against the 100% unprivileged pitch; to be
  reserved for an opt-in hardening tier.

## 10. Decisions (settled 2026-06-14)
1. **Symmetric schema reaffirmed**: the trust gate is the validation; a trusted
   project = config honored in full, with **content-hash-bound trust**
   (re-validation on every change, direnv model). Cf. §6.
2. **Network: handled at the very end.** Open by default until then. ⇒ **the
   confidentiality limit (§1) holds until then, and that is accepted.** The two
   near-free blocks (`169.254.169.254`, `localhost`) can come early;
   the full allowlist (nono/greywall layer) is the **last** step.
3. **In-sandbox installs** (option a) + ro base store + per-project overlay +
   pinned nixpkgs for the untrusted. No attacker code runs on the host.
4. **same-uid by default**; `--unshare-pid` required; subuid = later opt-in
   hardening.
