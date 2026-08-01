# What an `openat` lens would cost — measured

Everything `sbx` refuses through its own code — a host the egress policy denies, a binary `[proc]`
denies, a key the ssh-agent broker withholds, a task not declared, a field the trust gate drops —
is announced by [`[notify]`](guide/configuration/notify.md) at no runtime cost, because `sbx` is the
one saying no and already knows why.

The refusals it cannot announce are the ones the **kernel** renders: a path that is simply not bound
(`ENOENT`), a write under a read-only bind (`EROFS`), a `tmpfs` mask, a syscall the mandatory
denylist turns into `EPERM`. Nothing on the host observes them. Reaching them means putting a
supervisor in front of the syscall, and for files that means `openat` — the hottest syscall in the
cage.

This document is the measurement of what that would cost, and what it would actually buy. It does
not propose an implementation.

---

## The framing that comes before any number

A seccomp user-notification fires **before** the syscall runs. The supervisor answers either
`SECCOMP_USER_NOTIF_FLAG_CONTINUE` (let the kernel proceed) or an errno of its own. With `CONTINUE`
it **never learns the result**: no return value comes back to it.

So an `openat` lens cannot observe a block. It can only observe an *attempt* and **predict** the
block, by resolving the path against the mount layout `sbx` itself computed. That is a real
capability — `sbx` knows exactly which paths it bound and how — but it is a different product from
the other five notification sources, which report what happened. It is worth naming plainly before
weighing a cost, because it changes what a wrong answer means: a mispredicted toast tells the user
a file was blocked when it was not.

The alternative, `SECCOMP_IOCTL_NOTIF_ADDFD` — the supervisor opens the file itself and injects the
descriptor — does observe the true outcome, at the price of reimplementing `openat`'s semantics
(flags, `O_CREAT`, modes, symlink resolution, `O_PATH`, `openat2`'s resolve flags) in userspace.
That is a large, dangerous surface and is not considered further here.

---

## Method

`perf` tracepoints are unavailable on this host (`perf_event_paranoid=4`, no tracefs access), so
counts come from `strace -f -c` (exact; only timing is distorted) and timings from purpose-built
harnesses that install a real `SECCOMP_RET_USER_NOTIF` filter and serve it. Three ran, all on
x86-64, 16 cores, release `-O2`, each figure the spread of three runs:

- **`notif_openat`** — a child installs a `NEW_LISTENER` filter matching only `openat`, hands the
  listener out over `SCM_RIGHTS`, then times a tight `openat` loop while the parent serves. Gives
  the per-call round trip a caller actually pays.
- **`notif_ceiling`** — the same, with *W* workers sharing one inherited filter, measuring aggregate
  notifications served per second.
- **`notif_run`** — runs an arbitrary command under the filter, so the verdict rests on real
  workloads rather than on a microbenchmark multiplied out.

Two supporting harnesses (`ns_read`, `cold_pid`) isolate where the shipped exec supervisor's cost
comes from: one parks a child in a descendant user namespace and reads it, the other forks 400
children and reads each pid exactly once against the same count of reads on one pid.

The harnesses were throwaway and are not kept — this repo builds one Rust binary and nothing here
compiles C. Each is short enough to rebuild from the description above, and the two that decide
anything are the simplest: `cold_pid` needs only `fork`, `open("/proc/<pid>/mem")` and `pread`;
`notif_run` is the `NEW_LISTENER` + `SCM_RIGHTS` handoff the shipped
[`proc_enforce`](../src/sandbox/proc_enforce.rs) already implements, with `openat` in place of
`execve` and `CONTINUE` as the verdict.

---

## Finding 1 — the cost inherited from the exec supervisor does not apply

The [exec supervisor](guide/configuration/proc.md) measures **11.9 µs** to read a pathname from
`/proc/<pid>/mem`, and **17.0 µs** of total work per notification. Extrapolated to `openat` that
implies a cage-wide ceiling near 59 000 opens/s — low enough to kill the idea outright. It was worth
checking where that 11.9 µs actually goes, because a plain remote read of the same shape measures
about a tenth of it.

Two candidates. The first, that crossing into the cage's **user namespace** makes
`ptrace_may_access` expensive, is **refuted** — a child that calls `unshare(CLONE_NEWUSER)` is no
more expensive to read than a sibling:

| target | open+pread+close | cached fd | `process_vm_readv` |
|---|---|---|---|
| same namespace | 1.49–1.88 µs | 0.44–0.50 µs | 0.42–0.46 µs |
| descendant user namespace | 1.38–1.52 µs | 0.42–0.50 µs | 0.42–0.66 µs |

The second is the answer. An `execve` notification always names a **freshly created** process, so
every `open("/proc/<pid>/mem")` is a first touch — a new `proc` dentry and inode each time:

| which pid is read | open+pread+close |
|---|---|
| cold — a pid never read before | **11.96 / 12.67 / 13.47 µs** |
| warm — a pid already touched | 2.66 / 4.83 / 4.97 µs |
| warm, with the fd kept open | 0.42 / 1.47 / 1.48 µs |

The cold column reproduces the shipped supervisor's 11.9 µs almost exactly. **It is a per-new-process
cost, not a per-notification one** — and `openat` does not pay it: an `openat` lens reads long-lived
processes over and over, so a per-pid cached descriptor hits warm nearly every time.

This is also worth noting for the exec supervisor itself: the dominant term there is not intrinsic,
and `process_vm_readv` (one syscall, no descriptor) matches the cached-fd figure without needing a
cache at all.

## Finding 2 — the round trip, measured end to end

Summing the parts understates it: the calling task is **parked** for the whole exchange, so what it
pays is two context switches plus the supervisor's work.

| | µs per call | vs native |
|---|---|---|
| `openat`, no filter | 0.82–0.93 | — |
| notified, `CONTINUE` only | 4.37–4.61 | ~5× |
| notified, `CONTINUE` + pathname read | 4.99–5.82 | ~6× |
| notified, errno `EPERM` + pathname read | 4.65–4.75 | ~5× |

## Finding 3 — the cage-wide ceiling

A seccomp filter is inherited across `fork` and `exec`, and a second `NEW_LISTENER` returns `EBUSY`,
so **every process in the cage shares one listener served by one receive loop**. Per-notification
work is therefore a cage-wide throughput ceiling, not a per-caller cost: past it a parallel workload
does not slow proportionally, it serializes.

| workers | pathname read | notifications/s | supervisor time each |
|---|---|---|---|
| 1 | on | 191 777 | 5.21 µs (round-trip bound) |
| 2 | on | 340 023 | 2.94 µs |
| 4 | on | 577 255 | 1.73 µs |
| 8 | on | 541 036 | 1.85 µs |
| 16 | on | 526 667 | 1.90 µs |
| 4 | off | 693 162 | 1.44 µs |
| 16 | off | 824 253 | 1.21 µs |

**~530 000 notifications/s**, not 59 000 — an order of magnitude more headroom than the exec figure
implied, entirely because of Finding 1.

## Finding 4 — what it does to real workloads

The ceiling is not the answer on its own; demand is. Two workloads at opposite poles, each run under
`notif_run` with a per-pid cached descriptor and a `CONTINUE` verdict:

| workload | opens | rate | baseline | notified | cost |
|---|---|---|---|---|---|
| incremental `cargo build` of this repo | 2 497 | 1 340/s | 1.89 s | 1.85–1.87 s | **none measurable** |
| 20 parallel `rg` sweeps over 8 000 files | 161 732 | 270 000/s | 0.29 s | 0.60–0.63 s | **×2.1** |
| the same, without the pathname read | 161 724 | 341 000/s | 0.29 s | 0.47 s | ×1.6 |

A compile is invisible. A tree-wide search **doubles**. There is no single overhead figure for this
feature — it is entirely a function of how open-dense the workload is, and an agent's two commonest
activities sit at the two extremes.

## Finding 5 — coverage, and the one lever that would cut the cost

Breaking the same traces down along the axes that matter:

| | incremental build (2 503 calls) | `rg` sweep (8 084 calls) |
|---|---|---|
| syscall | `openat` 99.7%, `open` 0.3% | `openat` 100% |
| intent | read-only **98.6%**, write 1.4% | read-only **100%** |
| path form | absolute 94.9%, relative 5.1% | absolute 100% |
| already fails on the **host** | **11.7%** | 0.4% |

Three things follow.

**Coverage.** A filter on `openat` alone is bypassable — legacy `open` appears even in a modern
toolchain, and `openat2` is how new code asks for resolve flags. All three must match, or the lens
is worse than absent: it would claim a coverage it does not have.

**The cBPF lever, and its price.** cBPF cannot dereference a pathname, but it *can* test the flags
argument — the repo already does selector filtering of this kind on `clone` and `ioctl`. Notifying
only on write-intent opens would drop **~99%** of the traffic and make the cost disappear on every
workload measured. But a secret is read `O_RDONLY`. That pre-filter buys its speed by going blind to
confidentiality-by-absence, which is the case this sandbox is built around. It is a coverage/cost
fork for the user to decide, not a free win.

**A false-positive problem worth more than the cost.** 11.7% of a compile's opens **already fail on
the host** — `rustc` probing for optional files, the loader walking a search path. Roughly 290 of
them per incremental build. In a cage those same probes are unreachable paths, and a lens that
announced every unreachable path would fire hundreds of times per build about entirely normal
behaviour. This is the same lesson the exec supervisor already learned, where only a `deny` verdict
is announced and the `PATH`-walk `ENOENT` is not.

## Finding 6 — it would degrade `[proc] ask`

One listener, one loop, `EBUSY` on a second. `openat` notifications would share the receive loop
with `execve`, so at 270 000/s an interactive `[proc] ask` prompt queues behind them. Not fatal —
the loop never blocks on a park — but it is a real coupling between two features that are today
independent.

---

## Where this leaves it

The idea is **much healthier than the inherited numbers suggested**: the 59 000/s ceiling was an
artefact of a cost `openat` does not pay, and the true ceiling is ~530 000/s. It is not the
performance wall it looked like.

It is still **not a default-on lens**, for three reasons that are not about speed:

1. it predicts rather than observes, so it can be wrong in the direction that matters;
2. normal path-probing means most unreachable-path events are not refusals at all;
3. the cost is workload-shaped — invisible on a compile, ×2 on a search — so a default that is free
   for one user doubles another's day.

If it is built, the shape the measurements support is: match `open`/`openat`/`openat2`; always
`CONTINUE`; predict only the two classes `sbx` is **certain** of from the spec it already built —
no bind ancestor ⇒ `ENOENT`, write-open under a read-only bind ⇒ `EROFS`; keep one `/proc/<pid>/mem`
descriptor per pid (or use `process_vm_readv`); and route the result through the existing
[`[notify]`](guide/configuration/notify.md) coalescer, whose `once` and `repeat_after` already exist
to collapse exactly this kind of repetition.

There is also a **cheaper answer to the question this feature is really being asked**, which is "why
did that fail?". A launch-time summary of what the cage cannot see — derived from the same bind map,
at zero runtime cost and with no prediction — answers it for most cases without any of the above.
Worth offering before the supervisor, not after.
