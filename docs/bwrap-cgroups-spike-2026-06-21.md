# M4.2 cgroups v2 de-risk spike (throwaway) — 2026-06-21

> Goal: settle the cgroup **mechanism** (`systemd-run --user --scope` vs a
> directly-created cgroup) and the **limit profile** by measurement before writing
> the production code, and confirm the integration is non-invasive to the existing
> launch supervision (exit propagation, `ops shell` pty job control, the egress
> proxy-thread-outlives-cage model). Nothing installed; all probes host-side.

## Environment

- cgroup **v2** unified (`stat -fc %T /sys/fs/cgroup` → `cgroup2fs`).
- A live **systemd user session**: `XDG_RUNTIME_DIR=/run/user/1000`,
  `DBUS_SESSION_BUS_ADDRESS` present, `user@1000.service` active.
- **All three controllers delegated** to the user manager: `cgroup.controllers`
  inside `user@1000.service` (and at `app.slice`) = `cpu memory pids`, with
  `cgroup.subtree_control` already enabling them for children. (The competitor-
  comparison caveat "cpu often NOT delegated" did NOT hold here — but the
  production code must still degrade gracefully where it does not.)
- `systemd-run` on PATH.

## The mechanism decision — `systemd-run --user --scope`, measured non-invasive

The plan-of-record was `systemd-run --user --scope`; a direct-cgroup pivot was
considered (create our own leaf, move bwrap's pid into `cgroup.procs`) on the
theory that systemd-run would be process-invasive like the Model-P pasta wrapper.
**The deciding measurement retired that theory.**

In a **real pty** reproducing ops's `ops shell` path (`pty.fork()` makes the child
a session leader whose controlling terminal is the pts == `login_tty`; the child
then execs the candidate), comparing a bare `bash -i` against
`systemd-run --user --scope -- bash -i`:

| property | baseline `bash -i` | `systemd-run --scope -- bash -i` |
|---|---|---|
| job control (`$- == *m*`) | **ON** | **ON** |
| controlling tty | `/dev/pts/15` | `/dev/pts/16` |
| bash's parent | the session leader | the session leader (**not** `systemd-run`) |

`systemd-run --scope` **exec-chains** into the target (registers the transient
scope via D-Bus, moves itself in, then `execve`s the command), so **no
`systemd-run` process lingers** — the process-tree shape is identical to running
the command directly, and **pty job control is preserved**. So it behaves like a
plain **argv prefix** (the same shape as M4.1's `seccomp::argv_prefix`), wrapping
cleanly in all three launch paths without restructuring the supervision:

- **exit propagation:** `systemd-run --user --scope -- bash -c 'exit 7'` → host
  exit **7**.
- **limits land:** inside the scope, `memory.high`/`pids.max`/`cpu.max` reflect the
  `-p` properties (see below).
- **auto-clean:** every transient scope created during the spike was **gone**
  afterwards (async systemd GC; 0 leftover `run-*.scope` under `app.slice`) — no
  accumulation, unlike a hand-rolled cgroup which would leak an empty dir on the
  exec-replace path.

**Direct-cgroup was rejected as the primary.** A `mkdir` under
`app.slice` + writing `pids.max` *did* succeed unprivileged — but `app.slice` is
**systemd's territory**: the single-writer / delegation rule says you only manage
cgroups in a subtree systemd has explicitly `Delegate=yes`'d to you. Ad-hoc leaves
there work in an interactive scope today but can be GC'd by the user manager, and a
robust direct approach would *still* need systemd to delegate a subtree — so direct
does not escape systemd, it just does the **unsanctioned** version. systemd-run is
sanctioned, auto-cleaning, and (measured) non-invasive, so it wins. Direct stays a
fallback idea only if a future host has cgroup v2 + a writable delegated subtree
but no `systemd-run`.

## The limit profile — match each limit to the DoS, not to a round number

The real hazard is **values, not mechanism**: a too-tight `MemoryMax` **OOM-kills
legitimate nix builds** (linking rustc/LLVM blows past any tight ceiling), and
building toolchains is the open cage's entire purpose — a feature that kills
builds gets disabled, which is worse than no limit. Measured profile:

| limit | systemd property | default | rationale |
|---|---|---|---|
| **pids** | `TasksMax` | a generous cap (low-thousands) | **highest-value, safest.** Fork-bombs are the cheapest/most-damaging DoS and need millions of pids; a few-thousand cap stops them without touching `make -j`. |
| **memory** | `MemoryHigh` (throttle) | ~80% RAM, `MemoryMax` left `max` | host-protection via **reclaim/throttle** (build slows under pressure, survives), **not** a hard kill. Verified: `MemoryHigh=80%` → `memory.high≈52.6 GB` of 64 GB, `memory.max=max`. |
| **cpu** | `CPUQuota` | **none** | lowest priority — CPU saturation is self-resolving via the scheduler; capping mostly just slows legit builds. |

**Scope for M4.2: fixed structural defaults, no config field.** A future per-project
limits field would be a **free** field (not security-gated like `binds`/`network`):
loosening your own anti-DoS cap only self-harms, so it carries no trust risk.

## Graceful degradation — anti-DoS is hardening, not the boundary

Unlike the userns/seccomp/egress boundary (which **hard-fails** in `doctor`),
resource limits are best-effort: where there is no cgroup v2, no systemd user
session (`XDG_RUNTIME_DIR`/bus absent — headless/CI/cron), `systemd-run` missing,
or a controller not delegated, ops applies what it can and **warns**, never
hard-fails. `doctor` probes "can I create a limited scope here?" and surfaces it.

## Integration carried forward

- **argv prefix in all three paths** (`exec`, `run_supervised`, `supervise`/pty) —
  `systemd-run --user --scope -p … -- <bwrap> …`, mirroring `seccomp::argv_prefix`.
  No process-tree restructuring; the egress supervisor and pty job control are
  untouched (measured).
- The wrapper runs **host-side before bwrap creates the cage**, so the scope cgroup
  contains the whole cage; bwrap's `--unshare-cgroup` only virtualizes the *view*,
  the process stays in the scope and limits still apply.
- Property names: `MemoryHigh`, `TasksMax`, (`MemoryMax`/`CPUQuota` reserved) — all
  valid `--user --scope` properties; percentages resolve against physical RAM.
