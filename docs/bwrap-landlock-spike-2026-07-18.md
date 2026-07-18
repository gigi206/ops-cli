# Landlock FS write-scoping — feasibility spike (2026-07-18)

Throwaway spike (`scratchpad/landlock_spike.c`), run unprivileged on the dev host, to decide
whether a `[landlock]` FS write-scoping layer is worth building on top of the existing
bwrap + seccomp + cgroups stack — and, crucially, whether it can express the feature that
motivated it: **a read-only subdirectory (`.git/`, lockfiles) inside a read-write project tree.**

## Host support (verified)

- Kernel `7.0.0-27-generic`; `landlock` present in the active LSM list; `CONFIG_SECURITY_LANDLOCK=y`.
- Runtime **ABI = 8** (via `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`).
- Applied as **uid 1000** (non-root) with only `PR_SET_NO_NEW_PRIVS` — **unprivileged, confirmed**.

## What the spike proved

A ruleset handling only the **write-ish** rights (read rights deliberately UNHANDLED), granting
full write on one tree:

| Test | Result | Meaning |
|---|---|---|
| write inside the granted tree | **OK** | the granted tree is writable |
| write **outside** the granted tree | **EACCES** | **default-deny** on writes outside granted paths |
| read inside / read `/etc/hostname` | **OK** | reads are **unrestricted** (read rights not handled) — does not break loading libs / `/nix` / `/etc` |
| write `/dev/null` | **EACCES** | the writable set **must** include `/dev/null` (and `/dev/tty`, `/dev/full`, …) or tools break |
| `execve` a fresh `sh`, write granted tree | **OK** | ruleset is **inherited across `execve`** |
| `execve`, write outside | **EACCES** | inheritance holds both directions |

So Landlock cleanly delivers: **whitelist the writable trees; everything else is read-only**,
with reads untouched, unprivileged, inherited by children — the shim-delivery model `[proc]`
already uses fits (apply from inside the cage's mount ns, where the cage paths exist).

## The load-bearing finding — the original motivation does NOT hold

**A read-only subdirectory inside a read-write tree is NOT cleanly expressible**, because Landlock
resolves an access by the **UNION** of every matching ancestor rule's `allowed_access` — a child
rule can only *add* access, never remove it.

This was proven by a dedicated discriminating test (`scratchpad/landlock_semantics.c`), because the
first run's evidence did not establish it: handle **read+write**; grant read+write on `tree/`; add a
**non-empty read-only** rule on `tree/ro_sub/` (`READ_FILE|READ_DIR`, accepted); `restrict_self`;
then open an **existing** file `tree/ro_sub/existing.txt` for **write** (`O_WRONLY`, no `O_CREAT`, so
only `WRITE_FILE` is exercised — not `MAKE_REG`). Result: the write **succeeded (OK)**. Under
most-specific-wins semantics the subdir's read-only rule would have denied it (`EACCES`); the success
proves **union** — the parent's write grant reaches the subdir despite the read-only child rule.

(The first run's two data points did *not* prove this and were not relied on: `allowed_access = 0` on
the subdir is rejected with `ENOMSG` (errno 42), which only shows Landlock refuses an *empty* rule;
and "no rule on the subdir ⟹ it inherited the parent's write" is consistent with either semantics.)

To make `.git/` read-only inside a writable `project/`, the only Landlock-expressible route is to

To make `.git/` read-only inside a writable `project/`, the only Landlock-expressible route is to
**not** grant write on `project/` itself but to enumerate its writable children and grant each
except `.git` — fragile (a top-level dir created after launch has no write grant, so the agent
cannot create it) and not what was promised.

## Consequence for the increment

The marquee justification recorded earlier ("rw project but `.git/` ro, sub-mount granularity
bwrap can't express") **evaporated**. What a `[landlock]` layer would actually add over the
current stack is narrower:

1. **Defense-in-depth write-scoping** — a second fence that pins writes to an explicit whitelist
   (project tree, `/tmp`, home, per-project `/nix` store, the writable `/dev` nodes), so even a
   mis-bound bwrap mount or a future rw path is caught. But bwrap's mount layout already scopes
   writes, so the overlap is high; this is redundancy, not new reach — exactly what
   `docs/guide/concepts/enforcement.md` already says about Landlock ("mostly re-police paths that
   are not mounted at all").
2. **Per-operation FS rights** — genuinely novel vs bwrap's all-or-nothing ro/rw mounts: grant
   `WRITE_FILE`/`MAKE_REG` but deny `REMOVE_FILE`/`REMOVE_DIR` (no unlink/rmdir), `MAKE_SYM`
   (no symlink planting), `REFER` (no cross-dir move), `TRUNCATE`. e.g. "the agent may edit and
   create files in the project but may not delete them" — an anti-destruction guardrail neither
   bwrap nor seccomp can express. But a coding agent legitimately deletes/renames (refactors, git,
   build artifacts), so it would be opt-in and project-specific — marginal, like `[proc] ask`.

Neither is the "hard containment for in-process project corruption" the increment was pitched as:
the agent legitimately holds rw on the project tree (that is the point of the cage), and Landlock
cannot carve a protected subtree out of it. It restricts *where* writes land, not *what* the agent
does inside the tree it is meant to write.

## Recommendation

**Surface this to the user before building.** The spike changed the value proposition materially
(golden rule paid off). The realistic pitch is a trusted-only, best-effort-by-ABI, defense-in-depth
`[landlock]` layer offering (a) explicit writable-whitelist enforcement and (b) opt-in
per-operation hardening (no-delete / no-symlink / no-move) — not the ro-subdir carve-out. Given
`enforcement.md` already frames Landlock as largely redundant with confinement-by-absence, whether
that narrower value is worth an increment is the user's call — consistent with how thin-value
features have been deferred/dropped before (6.3c body-borne outbound; xdg-utils).
