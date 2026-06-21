# M4.1 seccomp de-risk spike (throwaway) — 2026-06-21

> Goal: settle the seccomp **posture** (A vs B) by evidence before writing the
> production filter, and confirm the bwrap mechanism + the nix-build reconciliation
> the [security-stack](bwrap-security-stack.md) §3 flagged as load-bearing. Nothing
> installed; all under `target/spike-seccomp/` (gitignored). Filters compiled with
> `seccompiler` 0.5 (the crate the real filter will use).

## Environment

- bubblewrap **0.11.1** — supports both `--seccomp FD` (single) and
  `--add-seccomp-fd FD` (repeatable). Kernel 7.0.0 (Landlock ABI ≥ v4 available).
- Cage mirrored ops's hardening: `--unshare-{user,ipc,pid,uts,cgroup} --clearenv
  --die-with-parent --cap-drop ALL --new-session`, same-uid (uid 1000).
- The seccomp fd is handed to bwrap by opening the compiled cBPF file on fd 10
  (`exec 10< filter.bpf; bwrap … --seccomp 10`). Works first try.

## Postures compiled

- **core** (Posture B's filter) — the *conflict-free* denylist, default-allow →
  EPERM on: `ptrace`/`process_vm_{readv,writev}`, `init/finit/delete_module`,
  `kexec_load`/`kexec_file_load`/`reboot`, `bpf`, `perf_event_open`,
  `keyctl`/`add_key`/`request_key`, `io_uring_{setup,enter,register}`,
  `userfaultfd`, `ioperm`/`iopl`/`swapon`/`swapoff`/`acct`/`syslog`,
  `sethostname`/`setdomainname`/`personality`.
- **full** (Posture A's filter) — core **plus** the mount/ns family: `unshare`,
  `setns`, `mount`, `umount2`, `pivot_root`, `chroot`, and `clone` arg-filtered
  (deny only when arg0 carries `CLONE_NEWUSER` or `CLONE_NEWNS`).

## Findings

### 1. Mechanism — works, exact errno

Syscall prober (python `ctypes.syscall`) inside the cage:

| syscall | none (cap-drop only) | core (B) | full (A) |
|---|---|---|---|
| keyctl/bpf/add_key/perf/io_uring/userfaultfd/ptrace | reached | **EPERM** | **EPERM** |
| `unshare(CLONE_NEWUSER)` | **OK (0)** | OK (0) | **EPERM** |
| mount | reached (EFAULT, null args) | reached | **EPERM** |
| `socket(AF_UNIX)` | OK (fd) | **OK** | **OK** |

`--seccomp FD` returns the exact action (`EPERM`). **AF_UNIX survives both
filters** → the Model-B egress `socat` forwarder is unaffected. Carve-out holds.

### 2. The discriminating fact — cap-drop already neuters the nested userns

`--cap-drop ALL` + bwrap's single-uid userns let a process **create** a nested
userns (`unshare(CLONE_NEWUSER)` → 0) but **not weaponize** it:

- `unshare --user --map-root-user` → `write /proc/self/uid_map: EPERM` (the
  outer userns maps only the single sandbox uid, so the nested one cannot map
  root — confirmed live).
- This is the same reason the M5 `apply-seccomp` re-isolation helper would fail
  on a *range* map; a *single-self* map is the unprivileged-allowed case.

So blocking the mount/ns family (Posture A) is **kernel-attack-surface
reduction** (removing reachability of the userns→mount→overlayfs/pivot_root code
paths, a major real-world LPE class), **not** closing a concrete cap-drop escape.

### 3. The nix reconciliation — measured with REAL local builds

A faithful FLIP cage (a writable per-project store with nix+bash bound **rw** at
`/nix`, mirroring production), a real `nix build` of a trivial `storePath`-builder
derivation, offline (`substituters ""`):

| filter | nix `sandbox` | result |
|---|---|---|
| none | true | ✅ builds (inner sandbox **on**) |
| **core (B)** | true | ✅ builds (inner sandbox **on**) — core does not touch mount/ns |
| **full (A)** | true | ✅ builds **but inner sandbox silently OFF** |
| full (A) | true + `sandbox-fallback=false` | ❌ `error: this system does not support the kernel namespaces … required for sandboxing` |
| **full (A)** | false | ✅ builds (no denied syscall; writes rw `/nix`) |

**The surprise that retired the doc's "mystery cannot-set-up-sandbox failure"
fear:** nix's default **`sandbox-fallback = true`** catches the seccomp EPERM on
`unshare`/`clone(NEWNS)` and silently retries the build **without** the inner
sandbox — so under Posture A, in-cage builds **still succeed**, just degraded.
With `sandbox-fallback = false` it hard-fails with the exact §3 message.

## Decision inputs (A vs B)

The **conflict-free core ships in BOTH** — it is unambiguous kernel-surface
reduction (LPE/CVE-historied syscalls, no legitimate in-cage use, **no nix
conflict**). The contested delta is the **mount/ns family**:

- **Posture A** — block mount/ns; ops forces nix `sandbox = false` +
  `filter-syscalls = false` (explicit, not relying on the silent fallback).
  *Gain:* the userns→mount→overlayfs/pivot_root kernel code paths become
  **unreachable** in the cage (real reduction of the most common Linux LPE class).
  *Cost:* nix builds lose their **inner** sandbox, so a malicious *derivation*'s
  build script runs with the agent's cage access — but the agent already runs
  arbitrary code in-cage and the per-project store is the boundary, so within the
  accepted Mode-B threat model.
- **Posture B** — keep mount/ns allowed; nix keeps `sandbox = true` (inner build
  isolation intact). *Gain:* third-party build scripts stay contained in nix's
  own sandbox. *Cost:* the agent itself can reach the mount/ns kernel paths
  (no surface reduction there) — but cannot escalate (single-uid map, §2).

There is **no clean third option in M4.1**: seccomp is process-wide + inherited,
so one filter cannot allow `unshare` for nix yet deny it for the agent. The
selective path is the nested-ns re-isolation helper — deferred to M5, and itself
gated by the uid_map limit in §2.

## Production-filter validation (the advisor's blocking check)

The production design adds, over the spike's `full` filter, a **second filter**
(`match → ENOSYS`) for `clone3` + the new mount API, plus `ioctl(TIOCSTI/TIOCLINUX)`
rules. The highest-blast-radius element is `clone3 → ENOSYS`: if glibc did not fall
back to `clone`, **all process creation would break**. Re-tested live with both
production-shaped filters loaded (`--add-seccomp-fd` × 2):

- `clone3` → **errno 38 (ENOSYS)**, `unshare(NEWUSER)` → **errno 1 (EPERM)**,
  `keyctl` → **errno 1 (EPERM)** — the two-filter resolution is clean (disjoint
  sets; `ERRNO < ALLOW` so each syscall gets its own filter's action).
- **`os.fork()`, 8 threads, and `subprocess` all succeed** — glibc's clone3→clone
  fallback holds; process creation is intact.
- A real `nix build` with **`sandbox = false`** under both filters succeeds, its
  glibc-2.42 builder forking 50× — Posture A viable with the *full* production
  filter, not just the spike subset.

So `clone3 → ENOSYS` is safe. The reconciliation ships proven.

The **argument-filtered** rules (different BPF codegen — a 64-bit `MaskedEq` split
into two 32-bit compares) were verified to actually *fire*, not just be present:

- `clone(CLONE_NEWUSER|SIGCHLD)` → **errno 1 (EPERM)** — the independent userns
  escape path (the one Posture A exists to close) is shut; the EPERM action fires
  before any child is created.
- `ioctl(TIOCSTI)` → **errno 1**, while a benign `ioctl(TIOCGWINSZ)` → ENOTTY (25),
  i.e. the arg-filter is selective, not a blanket `ioctl` block.

Both are folded into the committed cage teeth test.

## Impl notes carried forward

- fd inheritance: the production path needs `memfd` + `lseek 0` + `pre_exec`/`dup2`
  across all three launch paths (`exec`, `run_supervised`, `supervise`/pty). The
  raw-fork pty path is the easiest (fds already hand-managed).
- io_uring/userfaultfd are blocked here with no observed breakage, but the real
  agent toolchain (node async runtimes, JITs) must be re-checked at impl — if one
  breaks, drop that single entry (the rest of the core is independent).
- Under Posture A, set `sandbox = false filter-syscalls = false` via the ops-set
  `NIX_CONFIG` (already on the untrusted-only denylist) — deterministic, no
  per-build fallback retry, no warning noise.
