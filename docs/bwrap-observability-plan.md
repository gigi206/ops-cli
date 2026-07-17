# In-cage observability & enforcement — design (proc + fs lenses)

Status: PROPOSED 2026-07-17 — awaiting user validation; the load-bearing spike (§1) is DONE and green.

## 0. Goal & framing

Close the one axis where we trail the observability-first sandboxes (Greywall): **seeing — and
optionally blocking — what an agent *does inside the cage***, in real time, in the terminal
(**no web dashboard** — deferred). The design principle that makes us *better*, not merely level:
**unprivileged-first, layered**. Greywall's filesystem observability *requires* CAP_BPF/root
(it shells `bpftrace`); our base layer needs **no privilege at all**, and eBPF is only an
*optional* richer layer for whoever chooses to grant it.

Three lenses, mirroring the existing `sbx net`:

| Lens | Command family | Status | Capture mechanism | Privilege |
|---|---|---|---|---|
| **network** | `sbx net logs/live/stats/rules/allow/deny` | **DONE** | host-side MITM proxy → `LogRing`/`FlowRegistry` | none |
| **process/exec** | `sbx proc` (new) | this plan | seccomp user-notif (enforce) + cgroup poll (observe) | none |
| **filesystem** | `sbx fs` (new) | this plan | inotify on writable mounts (writes) | none |
| *fs reads / full syscall trace* | (folded into the above) | **deferred (v3)** | eBPF, cgroup-scoped | CAP_BPF/root, opt-in |

The lenses are **orthogonal to the FS substrate**: they ride the hermetic cage today and would
ride an eventual host-passthrough ("greywall") mode identically. Host-passthrough is a **separate
later milestone** (the deliberately weaker, clearly-labelled convenience posture), not this plan.

> **Priority the user must weigh (open decision).** The user called *blocking* "primordial". This
> plan's increment order is cheap→risky: **v1 blocks nothing new** (observe-only); the strongest
> *new* hard control (**fs-write veto**) is the most deferred; and exec-blocking (v2) is a
> **guardrail, not a hard boundary** (§3). So the thing called primordial is the weakest and latest
> part. That may be the right *engineering* order, but it is the user's call: either accept
> observability-first, or pull hard fs-write enforcement earlier. This must be settled before build.

## 1. Load-bearing spike — DONE, all green (2026-07-17)

`net` already gives observe + enforce because the proxy sits in the data path. For `proc`/`fs` the
open question was: can we get an equivalent **park-and-decide** enforcement point **unprivileged**,
inside our bwrap cage? A throwaway C spike (`scratchpad/unotif/spike.c`) proved
`SECCOMP_RET_USER_NOTIF` does exactly this:

- **bwrap cannot install a notification filter** — it only loads plain cBPF via `--add-seccomp-fd`.
  So an **in-cage shim** (our `egress.rs::wrap_background` positional-exec idiom) installs a
  `SECCOMP_FILTER_FLAG_NEW_LISTENER` filter on `execve`/`execveat`, passes the listener fd **out**
  to the host supervisor via `SCM_RIGHTS` over a bind-mounted AF_UNIX socket (same shape as the
  egress UDS), then `exec`s the payload.
- The **host supervisor** `RECV`s each execve, reads the target path from `/proc/<pid>/mem`, and
  decides: **deny → `EPERM`** (the syscall never runs — TOCTOU-safe) or **allow → `CONTINUE`**.
  Proven live: `/bin/cat` denied (`Operation not permitted`, file never read), `/bin/echo` allowed.
- **Fail-closed confirmed**: when the listener fd closes, matched syscalls return **`ENOSYS`**, not
  fail-open. A supervisor crash *seals* the cage — consistent with ops's fail-closed ethos.
- **Cheap for exec**: ~tens of µs/syscall; 300 execve added ~0.02 s (~67 µs each, unoptimised
  supervisor). Negligible for exec (rare); confirms we must be **selective on the hot FS path**.
- The filter is **inherited across fork+exec** → the whole cage process tree is covered; the agent
  cannot spawn an unsurveilled child.

Two facts the spike surfaced for the production design:
- The supervisor must be an **ancestor** of the cage, or YAMA `ptrace_scope` blocks the
  `/proc/<pid>/mem` read. Our supervised launch path already is the parent — good.
- user-notif observes `execvp`'s **PATH-probe** attempts (one execve per candidate) → the observer
  must **dedupe** to the resolved exec.

## 2. The one architectural constraint — force supervision

Plain non-interactive `sbx run` **exec-replaces** (no ops parent survives — `launch.rs::exec`).
Every unprivileged host-side observer (the user-notif supervisor, cgroup poll, inotify) needs a
**live parent** for the cage's lifetime. So **enabling observation forces the supervised path**
(`run_supervised`, fork+wait) — a small, clean change. `sbx shell`/`sbx app` are already supervised;
the network-allowlist path already is too (the proxy thread). This is the single gating change.

**Shim fail-closed (Mode B correctness).** If the in-cage shim cannot install the filter or hand
the listener fd to the supervisor (supervisor not up, socket gone), the payload **must not run**
(or runs under a static deny) — **never unobserved/unfiltered**. "Observation enabled but silently
not enforcing" is the false-confidence trap; the shim returns non-zero and the launch fails closed,
exactly as the spike's `connect`/`send_fd` error paths do.

## 3. Honest limits (the enforcement is not uniform)

- **`deny` is a hard control; `allow`-via-`CONTINUE` is a strong guardrail, not a hard-allow.**
  `CONTINUE` re-runs the real syscall, so a hostile agent can race the path argument (documented
  seccomp-unotify TOCTOU). Refusal is safe (syscall never runs); *approving a specific path* is
  racy against a determined adversary. Hard FS confidentiality therefore still rests on what we
  already have — **absence** (the file isn't mounted), the **read-only store**, and (future)
  **Landlock** static rules — with user-notif adding *visibility + veto*, not a new hard boundary.
- **Enforceability differs by dimension.** `net` = hard (empty-netns chokepoint). `fs` open/write
  via user-notif *can* be a hard chokepoint (you can't touch a file without the syscall) but is on
  the **hot path** → selective, and v1 keeps fs **observe-only** (inotify). `exec` = a **guardrail**:
  it catches every spawn, but an agent can do the harmful thing *in-process* (its own interpreter)
  without `exec` — so exec-blocking is a useful guardrail, not a containment boundary.
- **FS *reads* are not in the unprivileged layer** — inotify sees writes, not reads; reads need
  eBPF or hot user-notif on `openat`. Deferred to the opt-in eBPF layer (v3).
- **The "see what it tried" surface is NOT a bolt-on lens** (it was pitched as a differentiator vs
  Greywall — recorded honestly here). Kernel action precedence is `ERRNO < USER_NOTIF`, so a syscall
  already `EPERM`'d by our cBPF denylist (`m4-seccomp`: ptrace/mount/unshare/…) will **never** fire
  a user-notif. Surfacing "the agent *tried* mount" means **moving** those syscalls out of the cBPF
  ERRNO denylist into the user-notif filter (supervisor returns the errno) — which makes their
  enforcement supervisor-dependent. That is a real rearchitecture, **deferred** and flagged, not a
  gap to discover later.
- **Exec `ask` parks *every* spawn** (and the spike showed `execvp` fires multiple execve per
  command via PATH-probing). A coding agent spawns constantly, so ask-per-spawn against an *empty*
  allowlist is unusable → exec-`ask` **presupposes a populated `[proc] allow`**, and **observe-mode
  feeds it** (the learning flow — observe a trusted run → auto-generate `allow` rules → then
  enforce; this is also the Greywall "learning mode" worth stealing).
- **inotify is pid-less and non-recursive.** It reports *what* changed, not *which process* did it
  (attribution needs fanotify + CAP_SYS_ADMIN), so `[sbx:fs]` cannot tie a write to a process the
  way `[sbx:exec]` can — a dent in the "conversation view" ambition. It also needs a watch per
  directory (manual recursion, a create-in-new-subdir race, `max_user_watches` limits on large
  trees). Neither blocks v1; both are accepted v1 limits.

## 4. Config surface (mirrors `[network]`, trusted-gated, disableable everywhere)

A security posture field, gated trusted/global-only like `network`/`gui` (an untrusted project can
neither loosen nor forge it), with the standard three faces + the one-shot override precedence
(config < `OPS_*` env < CLI):

```toml
[proc]                         # process/exec lens
mode  = "off"                  # off | observe | ask
allow = ["git", "rg", "/usr/bin/*"]   # ask-mode: auto-allow these (path/basename/glob)
deny  = ["curl", "ssh"]               # ask-mode: auto-deny these

[fs]                           # filesystem lens (v1 = writes, observe-only)
mode  = "off"                  # off | observe   (ask/enforce = later, hot-path)
```

CLI/env faces (via the existing one-shot override machinery): `--proc <off|observe|ask>` /
`OPS_PROC`, `--fs <off|observe>` / `OPS_FS`, and a convenience `--observe` (= `proc=observe` +
`fs=observe`). Disable per-run with `--proc off` etc., exactly like the rest. (Exact flag spelling
is a design point to settle at build time.)

## 5. Command surface (mirrors `sbx net`)

- `sbx proc live [<id>]` — current process tree in the cage (cgroup `sbx-<slug>-<pid>.scope` →
  `cgroup.procs` → `/proc/<pid>/cmdline`). Unprivileged, always-available snapshot; the `net live`
  analogue.
- `sbx proc logs [<id>] [-f] [--json]` — the exec event feed (spawns, with argv + verdict under
  `ask`). Same `--follow` client-poll idiom as `net logs`.
- `sbx proc allow|deny <rule> [--session]` — decide a parked exec / add a live rule, reusing the
  `net` ask/pending control-UDS verbs.
- `sbx fs logs [<id>] [-f] [--json]` — file create/modify/delete events on the writable mounts.
- Unified inline feed: with observation on, events stream to stderr during the run, prefixed
  `[sbx:net]` / `[sbx:exec]` / `[sbx:fs]` (the network events fold into the same timeline). The
  three async sources (proxy thread, user-notif supervisor, inotify) **share one ordering key** so
  the merged timeline is actually ordered — reuse `LogRing`'s `seq` + `at_epoch_ms` across all lenses.

Reused plumbing (from the codebase inventory): the host-side supervisor + control-UDS
(`control-<pid>.sock`, `egress.rs`), the `LogRing`/`FlowRegistry` event rings and their
`LOG`/`FLOWS` verbs (`control.rs`), the `ask`/pending/`REMEMBER` machinery, the deterministic
cgroup scope name (`naming::scope_unit`), and the `wrap_background` shim idiom. Net-new: the
user-notif shim + supervisor loop, the inotify + cgroup-poll observers, per-lens event rings +
control verbs, and forcing supervision when observation is on.

## 6. Increment breakdown (each ships green + advisor + user-validated, per project cadence)

1. **Plumbing + observe-only, zero risk** — force-supervision when observation is on; `[proc]`/`[fs]`
   `mode = observe`; cgroup-poll exec observer + inotify write observer; the `sbx proc live/logs`
   and `sbx fs logs` viewers + inline `[sbx:*]` feed. No user-notif yet. **Teeth:** an e2e where a
   control run with observation *off* shows nothing, and *on* shows the exec + write events.
2. **Exec enforcement (`ask`)** — the proven user-notif shim + supervisor; `[proc] mode = "ask"`
   with `allow`/`deny` rules; `sbx proc allow|deny` + parked-exec prompting via the control-UDS.
   **Teeth:** a denied binary returns EPERM in a real cage; fail-closed on supervisor exit.
3. **(opt-in, CAP_BPF) eBPF read/trace layer** — fs *reads* + full syscall trace, cgroup-scoped
   (finer than Greywall's `pid >= sandbox_pid`), best-effort, never required.

Deferred beyond this plan: host-passthrough ("greywall") FS substrate; cross-terminal push/subscribe
(today's `--follow` client-poll suffices for a human); a web dashboard.
