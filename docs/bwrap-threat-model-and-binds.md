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
| **GUI** | **off**; if required, Wayland (better isolated) never X11 (an X client keylogs/screenshots the other windows) | opt-in, Wayland preferred |
| **Nested containers (podman socket)** | **DROPPED** — the socket = **root-equivalent on the host** (launch a container with `/` bind-mounted). Not "gated": **absent**. A filtering proxy-broker is **future work**, not a v1 checkbox. | gated + confirmation |
| **ssh-agent** (`$SSH_AUTH_SOCK`) | **off** (hands over ALL your keys for their lifetime) | scoped opt-in |
| **Secret injection** | least-privilege, declared in **trusted** config only | same |
| **A tool's credential persistence** (e.g. claude-code's own creds) | a **dedicated, persistent, isolated** creds dir, mounted **for that tool alone** — never all of `~/.config` | same |

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
