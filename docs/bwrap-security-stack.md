# `ops` (bwrap) — security stack

> Which kernel/userspace security building blocks `ops` adopts, why, and when.
> The [threat model](bwrap-threat-model-and-binds.md) says **what** we defend;
> this doc says **how**. Synthesized from the primitives used by serious
> *unprivileged* agent sandboxes — greywall, OpenAI Codex `linux-sandbox`,
> Anthropic `sandbox-runtime` (both source-verified), landrun, nsjail, Flatpak —
> plus the wider tool landscape (sources at the end).

## 1. The consensus the field converged on

Most serious unprivileged Linux agent sandboxes converge on the same shape, and
`ops` adopts it:

> **bubblewrap** (unprivileged user namespaces, **no setuid**) as the base —
> all namespaces + `no_new_privs` + drop-all-capabilities + a **default-deny**
> bind layout — then **seccomp** (a syscall denylist) and **Landlock** (a
> filesystem allowlist) layered on top as defense-in-depth, with the network
> funneled through a **filtering proxy**.

bwrap is the right base precisely because, on modern kernels, it runs
**non-setuid** via unprivileged userns — there is no privileged binary to
attack. That is the architectural reason to use it over Firejail (§7). (A few
agent sandboxes, e.g. Cursor, use Landlock + seccomp with **no** namespaces — but
pure-Landlock tools like landrun share the host network stack and cannot isolate
PIDs, so they are weak as a standalone jail. bwrap's namespaces are why it is the
base, not Landlock alone.)

## 2. Building blocks, primitive by primitive

| Primitive | Protects against | Unprivileged? | bwrap provides? | ops tier |
|---|---|---|---|---|
| user/pid/mount/ipc/uts/cgroup namespaces | host visibility, privilege, IPC/hostname leakage | yes (userns is the enabler) | **free** (`--unshare-*`) | M1 |
| `no_new_privs` | setuid re-privileging; also required for unprivileged seccomp | yes | **free** (`PR_SET_NO_NEW_PRIVS`) | M1 |
| drop all capabilities | ambient caps inside the userns | yes | **free** (`--cap-drop ALL`) | M1 |
| default-deny binds (tmpfs root + explicit allowlist) | host filesystem exposure | yes | bwrap, via our `binds.rs` | M1 |
| `--new-session` | terminal-input injection (`TIOCSTI`) at the source | yes | **free** | M1 |
| **seccomp-bpf denylist** | dangerous syscalls (§3) | yes (with `no_new_privs`) | bwrap takes `--seccomp FD`; **we compile it** | M4 |
| **Landlock (filesystem)** | file access outside the allowlist, *independent of mounts* | yes (by design) | **not** in bwrap; `rust-landlock` crate | M4 |
| Landlock (network, TCP) | outbound `connect()`/`bind()` per port | yes | not in bwrap; TCP-port-only (§4) | later (M6) |
| **cgroups v2 limits** (mem/pids/cpu) | fork bombs, memory exhaustion, runaway agents | partly — needs a *delegated* subtree | **not** free (§5) | later |
| network egress filtering | exfiltration, C2, registry spoofing | yes (userspace) | not in bwrap (§6) | M6 (last) |
| AppArmor/SELinux | MAC policy | **no — needs root** | — | not used (§7) |

## 3. The seccomp denylist (the consensus list + the gaps to close)

bwrap ships **no** default seccomp filter — it only accepts a compiled cBPF
program via `--seccomp FD`. We author one: **default-allow**, returning `EPERM`
(or `ENOSYS` for the new mount API) on a denylist. The cross-tool consensus
(Flatpak + greywall + Codex + Anthropic) is:

- **ptrace family**: `ptrace`, `process_vm_readv`, `process_vm_writev` — block memory inspection/patching of sibling processes.
- **mount / namespace family**: `mount`, `umount2`, `pivot_root`, `chroot`, `unshare`/`setns` (and `ENOSYS` for the new mount API `open_tree`/`move_mount`/`fsopen`/`fsconfig`/`fsmount`/`fspick`/`mount_setattr`).
- **module family**: `init_module`, `finit_module`, `delete_module`.
- **kexec/reboot**: `kexec_load`, `kexec_file_load`, `reboot`.
- **introspection/perf**: `bpf`, `perf_event_open`.
- **kernel keyring**: `keyctl`, `add_key`, `request_key`.
- **misc privileged**: `ioperm`, `iopl`, `swapon`, `swapoff`, `acct`, `syslog`, `sethostname`, `setdomainname`, `userfaultfd`, `personality`.
- **tty injection**: `ioctl(TIOCSTI)` and `ioctl(TIOCLINUX)`.

**Two gaps `ops` must close that greywall's list misses** (both verified in
Codex and Anthropic's filters):

- ⚠️ **`io_uring_setup` / `io_uring_enter` / `io_uring_register`** — io_uring can
  create sockets and do I/O *without* the corresponding syscalls, so it bypasses
  a syscall-level filter's view. Block it outright.
- ⚠️ **`socket(AF_UNIX)` / `socketpair` arg0 filtering** — when egress is forced
  through a proxy/UDS bridge, block creation of `AF_UNIX` sockets (a masked-eq
  filter on arg0) so the agent cannot bypass the bridge; allow only the proxy's
  socket family.

Carve-out: **do not block `recvfrom`** (breaks toolchains like cargo/clippy that
use socketpair-based subprocess plumbing). The filter is x86_64/aarch64 only
(other arches: deny by default or `unimplemented`).

⚠️ **Open-cage tension — this denylist will break in-cage `nix` builds unless
reconciled.** The cage carries a writable per-project store and `nix` itself, so a
Mode-B agent self-equips by running `nix build`/`mise install` *inside* the cage.
nix's own build sandbox creates **nested** namespaces and mounts — it needs exactly
the `unshare`/`clone(CLONE_NEWUSER|CLONE_NEWNS)`, `mount`, `pivot_root`, and the new
mount API this list denies, plus `seccomp()` itself (for nix's `filter-syscalls`).
With no syscall filter yet, those all succeed and in-cage builds work with nix's
*compiled defaults* (no ops config). Once this denylist lands it must either (a)
**allowlist** that set for the build-sandbox path, or (b) have ops force nix's
`sandbox = false` + `filter-syscalls = false` (via `NIX_CONFIG`, set by ops — note
`NIX_CONFIG` is on the untrusted-only env denylist, so a project cannot smuggle it).
Option (b) trades nix's *inner* isolation for the cage's *outer* filter; that is the
right tradeoff (the cage is the boundary), but it must be a **conscious** choice made
here, not rediscovered as a mystery "cannot set up build sandbox" failure. The open
cage *wants* the agent to manipulate namespaces; this denylist *wants* to block that
as an escape vector — they meet exactly on the in-cage builder.

**Implementation**: compile the filter with **`seccompiler`** (pure Rust, as
Codex does) — no libseccomp / kafel C dependency, which keeps the static-musl
binary self-contained. (nsjail's **kafel** policy language is a nicer authoring
model — human-readable allow/deny rules compiled to BPF — but it is C.)

A default-allow **denylist** is the pragmatic choice — an allowlist would break
the open-ended toolchains agents run — but it is **weaker than an allowlist**:
unknown/new syscalls pass. Accepted residual risk for Mode B.

## 4. Landlock — filesystem defense-in-depth (+ the bwrap-combo caveat)

Landlock is an unprivileged, **irrevocable, intersective** LSM: each ruleset can
only *narrow* access, is inherited across `execve`, and needs only
`no_new_privs` (no root). We apply a filesystem ruleset (via the
[`rust-landlock`](https://crates.io/crates/landlock) crate, `BestEffort` compat)
**after** bwrap sets up mounts and **before** `exec`, as a second layer that
survives bind-mount mistakes.

- **Kernels**: filesystem ABI v1 = Linux 5.13; network ABI v4 = Linux 6.7.
  Degrade gracefully (`BestEffort`): on 5.13–6.6 you get FS rules but no network
  rules.
- **Prior art for bwrap+Landlock**: Codex's legacy path ships them together;
  bwrap PR #519 / issue #713 propose it upstream (still unmerged). The caveat
  bwrap reviewers raised is real: **Landlock cannot see bind-mount boundaries**,
  so rules must target the *post-mount* paths.
- **Landlock network is TCP bind/connect *port-only*** (ABI4) — no UDP, no DNS,
  no per-host/CIDR, and not MPTCP-safe. A coarse kernel-enforced complement to
  the proxy, **never a replacement** for egress filtering.

## 5. cgroups v2 limits — the DoS layer the agent sandboxes skimp

None of greywall / Codex / Anthropic prominently does resource limiting, so this
is a **differentiator**, not catch-up. Wrap the sandbox in
`systemd-run --user --scope -p MemoryMax=… -p PidsMax=… -p CPUQuota=…` to stop
fork bombs and memory exhaustion by a runaway agent (nsjail does this natively;
bwrap only makes a cgroup *namespace*, with no controllers). ⚠️ It needs a
**delegated** cgroup subtree (systemd user-session delegation) — not root, but
not zero-setup; **degrade gracefully** if delegation is absent.

## 6. Borrowed techniques (specific, high-value)

- **nono — credential-injection proxy** (the highest-value borrow): the agent
  **never holds the API key**. Landlock/seccomp pins outbound `connect()` to a
  loopback proxy port; the proxy holds the key (zeroized, keyring-loaded),
  injects `Authorization: Bearer …` upstream over TLS, and does DNS-rebinding /
  link-local defense. Fully unprivileged, independent of general egress
  filtering — and it **relaxes the §1 confidentiality limit for the key itself**:
  even with an open network, the agent cannot exfiltrate a secret it never sees.
  (Other sandbox data still needs the egress allowlist.)
- **Anthropic `srt` — nested-namespace re-isolation** (`apply-seccomp`): inside
  the outer bwrap, a small static helper creates a *nested* user+pid+mount ns,
  sets `PR_SET_DUMPABLE=0` (un-`ptrace`-able), applies the seccomp filter, then
  execs — fail-closed. Closes the hole where the agent could `ptrace` or
  `/proc/<pid>/mem`-patch our own proxy/helper processes. ⚠️ **Not a naive
  borrow**: nesting a userns inside a **cap-dropped** bwrap fails (verified here —
  `uid_map: EPERM`, the same reason the spike forces `sandbox=false` for nix
  builds). It works only if the outer bwrap keeps capabilities until the helper
  has built the inner namespaces (the helper drops them last). Validate first.
- **Codex — `socket()` arg0 seccomp filter + TCP→UDS→TCP bridge**: the egress
  pattern for "no network namespace, everything funnels to a local proxy".
- **Flatpak — the portal pattern**: broker host access through a separate
  trusted process that policy-checks per request, instead of poking holes in the
  sandbox. This is the model for giving an agent controlled, audited host access
  (it aligns with our trust gate + least-privilege secret injection).
- **bubblejail — composable services → named profiles**: matches our per-app
  definitions (each app a named bundle of capabilities + its own `$HOME`).
- **gVisor — shrink the supervisor's own host syscalls**: apply a tight seccomp
  allowlist to `ops`'s own helper processes too, not just the agent.
- **Firecracker jailer — "set up the jail, then drop privileges"; minimal
  surface**: the sequencing principle for the argv builder.

## 7. What we deliberately do NOT use (conflicts with "fully unprivileged")

- ❌ **Firejail** as a base — **setuid-root**, long privesc CVE history
  (e.g. CVE-2022-31214). Cautionary tale; bwrap (non-setuid) is the correct base.
- ❌ **AppArmor / SELinux** policy loading — needs **root**.
- ❌ **microVMs** (gVisor KVM platform, Kata, Firecracker, libkrun/microsandbox,
  e2b) — need **`/dev/kvm`**. Their value to us is conceptual only (§6), not
  mechanical.
- ⚠️ **eBPF violation monitoring** (greywall's 5th layer) — needs **root/CAP_BPF**.
  Observability only, not enforcement → optional opt-in, never a hard dependency.
- ❌ **toolbx / distrobox** as a model — they pass through `$HOME` + the D-Bus
  session bus, so they are **not** a boundary (the explicit anti-pattern).

## 8. The named reference tools (greywall / nono)

- **greywall.io** (`GreyhavenHQ/greywall`, Go) — *source-verified*: bwrap in a
  `DefaultDenyRead` (tmpfs-root) layout + Landlock + a seccomp **27-syscall
  denylist** (blocks `TIOCSTI`; **misses `io_uring`** — see §3) + `tun2socks` →
  SOCKS5 proxy (`greyproxy`) + D-Bus isolation. eBPF monitor needs root. Its
  *enforcement* path is fully unprivileged and **top-tier for the class**.
- **nono.sh** (`always-further/nono`, Rust) — *source-verified*, and instructive
  as a **counter-example**: a deliberately **namespace-free** design —
  **Landlock** as the primary floor (FS + ABI-v4 TCP) + **seccomp-*notify*** that
  traps only `openat`/`openat2` (a supervisor injects the fd), **not** a syscall
  denylist + a **credential-injection proxy** for egress (§6). Fully unprivileged
  (no root, no namespaces). Its weakness is the flip side of skipping namespaces:
  **CVE-2026-47128** (fixed 0.55.0) — with no namespace and no AF_UNIX filtering,
  the agent reached the per-user systemd D-Bus socket and escaped via
  `systemd-run --user`. **The lesson for `ops`**: Landlock denies access to
  things that *exist*; a namespace makes them *not exist*. bwrap's
  `--unshare-pid`/`--unshare-net` + a private `/run` + an AF_UNIX seccomp block
  (§3) close exactly the escape class nono left open. Best of both worlds =
  nono's credential proxy **on top of** a bwrap namespace cage.

## 9. Adoption plan (mapped to milestones)

| When | Building blocks |
|---|---|
| **M0** (done) | `doctor` verifies a **capability-bearing** userns (catches the restricted-Ubuntu false-OK) |
| **M1** | bwrap base — the **free flags**: all namespaces, `no_new_privs`, `--cap-drop ALL`, `--new-session`, default-deny binds |
| **M4** | the **seccomp denylist** (incl. `io_uring` + `AF_UNIX`) + **Landlock-FS** (best-effort) — real work (compile cBPF via `seccompiler`, wire `rust-landlock`, get post-mount path rules right); bites hardest once Mode B agents run |
| **M5 / later** | cgroups v2 DoS limits; the nested-ns re-isolation (`apply-seccomp`) pattern — see the §6 caveat (needs caps retained through inner setup) |
| **M6** | network egress: `--unshare-net` + **pasta** uplink + filtering proxy (hostname allowlist) + **the credential-injection proxy** (§6) + optional Landlock-net TCP; the near-free `169.254.169.254` + `localhost` blocks can land earlier |
| **M7** | subuid hardening tier |
| **end / observability** | an **egress audit log + web consultation UI** (greywall-style): record every proxy decision — *allowed* as well as *denied*, each with its `X-Ops-Egress-Reason` category, the host/port/path, and the originating launch/session — and a small web view to review them. **Deferred to end-of-project**: it is observability, never on the enforcement path (a logging failure must not affect a verdict), and it must record **no secret** — echo only the host/port and category, never the injected credential or a request body. The egress proxy is the natural emission point: it already computes the verdict and the 6.2e category, which *is* the log taxonomy. |

## Sources

- bubblewrap: <https://github.com/containers/bubblewrap> · advisory GHSA-j2qp-rvxj-43vj
- greywall: <https://github.com/GreyhavenHQ/greywall> · <https://docs.greywall.io/greywall/platform-support>
- Codex `linux-sandbox`: <https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/src/> (`bwrap.rs`, `landlock.rs`)
- Anthropic `sandbox-runtime`: <https://github.com/anthropic-experimental/sandbox-runtime> (`vendor/seccomp-src/seccomp-unix-block.c`, `apply-seccomp.c`)
- Landlock: <https://docs.kernel.org/userspace-api/landlock.html> · `rust-landlock` <https://github.com/landlock-lsm/rust-landlock> · bwrap PR #519
- landrun: <https://github.com/Zouuup/landrun> · nsjail: <https://github.com/google/nsjail> (+ kafel) · Flatpak: <https://github.com/flatpak/flatpak/blob/main/common/flatpak-run.c>
- pasta/passt (egress uplink): <https://passt.top/>
- Firejail setuid caveat: CVE-2022-31214
