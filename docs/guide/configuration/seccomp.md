# `[seccomp]`: relaxing the syscall denylist

Every cage runs behind a mandatory **seccomp denylist** that refuses a set of syscalls
with no legitimate in-cage use and a history of kernel privilege-escalation (the whole
`ptrace`/`bpf`/`perf_event_open`/`userfaultfd`/keyring set, plus the mount/namespace
family). `[seccomp] allow` lets a **trusted** config re-permit a specific denied syscall
so a tool that genuinely needs it can run.

```toml
[seccomp]
allow = ["ptrace", "perf_event_open", "clone:newns"]
```

`[seccomp]` is a **security field**: honored from the global config or a trusted
project, ignored from an untrusted one: because re-permitting a denied syscall reduces
the kernel-attack-surface control. An empty or absent `allow` leaves the full mandatory
denylist (identical to a cage with no `[seccomp]` config).

See also: [Enforcement stack](../concepts/enforcement.md) · [The trust gate](../concepts/trust.md) · [`[app.<name>]`](apps.md).

## When you need it

The denylist is mandatory by default, so these tools do **not** run in a cage until you
re-permit the syscall they need:

| Tool / need | Syscall | `allow` entry |
|---|---|---|
| `gdb`, `strace`, `ltrace` | `ptrace` | `"ptrace"` |
| `perf` | `perf_event_open` | `"perf_event_open"` |
| CRIU, some runtimes/JITs | `userfaultfd` | `"userfaultfd"` |
| an `io_uring` app | `io_uring_*` | `"io_uring_setup"`, `"io_uring_enter"`, `"io_uring_register"` |
| nested containers / `bwrap`-in-`bwrap` | `unshare`, `mount`, `clone(NEWNS)` | `"unshare"`, `"mount"`, `"clone:newns"` |

## The grammar

The grammar is **uniform**: a bare syscall name lifts the **whole** syscall; `clone`
and `ioctl`, the two *argument-filtered* entries in the denylist, additionally accept
a `:selector` that lifts only one sub-rule and leaves the rest denied.

| Token | Effect |
|---|---|
| `"ptrace"`, `"unshare"`, `"mount"`, `"perf_event_open"`, … | lift the whole syscall |
| `"clone"` | lift **all** of `clone` (both `CLONE_NEWUSER` and `CLONE_NEWNS`) |
| `"clone:newns"` | lift only `clone(CLONE_NEWNS)` (leaves `CLONE_NEWUSER` denied) |
| `"clone:newuser"` | lift only `clone(CLONE_NEWUSER)` |
| `"ioctl"` | lift **all** of the filtered `ioctl` requests (`TIOCSTI` and `TIOCLINUX`) |
| `"ioctl:tiocsti"` / `"ioctl:tioclinux"` | lift only that one request |

A rule is **a name, not `:selector`** for everything except `clone`/`ioctl` (the only
argument-filtered entries): a `:selector` on any other syscall is rejected.

### Comma lists

Each string may itself be a **comma-separated** list, so these are equivalent:

```toml
allow = ["ptrace", "unshare", "clone:newns"]
allow = ["ptrace,unshare,clone:newns"]
allow = ["ptrace, unshare", "clone:newns"]
```

### Unknown or malformed entries

An entry that names a syscall `sbx` does not deny, or a bad/superfluous `:selector`, is
**dropped with a warning** (fail-closed: it loosens nothing). It never fails the launch.

## Cautions

Some syscalls reopen a real escape surface, not just defense-in-depth. Lifting them is
allowed (you are the trusted operator), but `sbx` prints a **caution** naming what you
opened:

- **`clone`, `clone:newuser`, `clone3`** → reopens unprivileged **user-namespace
  creation**. (`clone3` cannot be argument-filtered: its flags live behind a struct
  pointer a cBPF filter cannot read: so lifting it reopens *unfiltered* namespace
  creation. Prefer `clone:newns` unless you truly need `clone3`.)
- **`ioctl`, `ioctl:tiocsti`, `ioctl:tioclinux`** → reopens **terminal input injection**
  (writing into the controlling terminal's input queue).
- **`umount2`** → reopens **tearing down a mount**. This is the one entry with a
  launch-side interdependency: if you also bind `sbx`'s control plane read-write, in-cage
  code could unmount a pin and defeat a control-plane protection. Lift it only when you
  understand that interaction.

Cautions are informational: the token is still applied.

## Why it stays surface-reduction, not a boundary

Blocking the mount/namespace family removes the
`userns → mount → overlayfs/pivot_root` kernel-LPE paths from the cage. Re-permitting
them reduces that *defense-in-depth*, but the boundary does not rest on it: `sbx` also
drops all capabilities and runs a single-uid user namespace, so a nested user namespace
is already neutered (`unshare(CLONE_NEWUSER)` succeeds but the `uid_map` write is
refused). Lifting a syscall is your informed, trusted-only choice.

Re-permitting the mount/namespace family does **not** re-enable nix's own build sandbox, `sbx` still runs in-cage `nix build` with `sandbox = false` (see
[Enforcement stack](../concepts/enforcement.md)).

## Per-app relaxation

An `[app.<name>.seccomp]` table (or a `[seccomp]` table in an imported profile) relaxes
the denylist **for that app's launches**, **unioned** onto the baseline and gated the
same way. An untrusted project's app `[seccomp]` is dropped: so a globally-declared
app's relaxation cannot be widened by an untrusted project (an agent runs *on* untrusted
code without that code widening the app's syscall surface).

```toml
[app.debugger.seccomp]
allow = ["ptrace"]
```

## Viewing the effective relaxation

```sh
sbx config show            # a `seccomp allow:` line only when a syscall is re-permitted
sbx config show --app dbg  # an app's effective relaxation, tagged inherited or set
```

The tokens render **canonically** (sorted, `:selector` form where narrow), derived from
the same tables the parser uses: so what `sbx config show` prints is exactly what the
cage enforces.

## Scope

`[seccomp]` is a config-file field (global, project, or an app overlay). It is
also a one-shot [override](overrides.md): `--seccomp <token[,token…]>` (repeatable) and
`SBX_SECCOMP` relax the denylist for a single launch, following the same `allow` grammar.
An override is **trusted by invocation**: the person running `sbx` outranks any config
layer, so it may declare exactly the relaxation a *trusted* config already can, even though
an untrusted project's `[seccomp]` is dropped (parity with the trusted config, not a new
axis). Note a relaxation re-permits a syscall whose only containment was the filter, widening
the in-cage kernel attack surface: so a stale `SBX_SECCOMP` is worth checking (its ambient
use prints a notice). A bad token is warned and skipped (less relaxation, fail-closed), never
fatal.
