# `[devices]`: exposing host device nodes

Every cage gets a **minimal, hostless `/dev`**: `null`, `zero`, `full`, `random`,
`urandom`, `tty`, `ptmx`/`pts`, `shm`, and the standard descriptor symlinks, and nothing
else. No real host device is present, so a tool that needs the GPU, a VPN tunnel, hardware
virtualization, or a userspace filesystem cannot reach one. `[devices] allow` lets a
**trusted** config bind a specific host device node into the cage.

```toml
[devices]
allow = ["/dev/dri", "/dev/net/tun"]
```

`[devices]` is a **security field**: honored from the global config or a trusted project,
ignored from an untrusted one: because a real device node widens the kernel attack
surface (a device-driver bug becomes reachable from inside the cage). An empty or absent
`allow` leaves the minimal `/dev` with no host devices.

See also: [Enforcement stack](../concepts/enforcement) · [The trust gate](../concepts/trust) · [`binds`](binds) · [`[app.<name>]`](apps).

## When you need it

| Tool / need | Device | `allow` entry |
|---|---|---|
| GPU compute / rendering (CUDA, VA-API, WebGPU) | `/dev/dri` | `"/dev/dri"` |
| a VPN / tunnel client (`wg`, `openvpn`) | `/dev/net/tun` | `"/dev/net/tun"` |
| hardware-accelerated VMs (QEMU/KVM) | `/dev/kvm` | `"/dev/kvm"` |
| a FUSE filesystem | `/dev/fuse` | `"/dev/fuse"` |
| sound | `/dev/snd` | `"/dev/snd"` |

## The grammar

Each `allow` entry is an **absolute path under `/dev/`**: either a single device node
(`/dev/kvm`) or a directory of them (`/dev/dri`, which holds `card*` and `renderD*`). The
device is bound at its own path **with device access**, over the minimal `/dev`.

- A path outside `/dev/`, the bare `/dev` (rebinding the whole tree is refused), a relative
  path, or one containing a `..` component is **dropped with a warning** (fail-closed: a bad
  path never widens exposure). It never fails the launch.
- The `/dev/` restriction is on the path **spelling**, not the resolved target: the source is
  not canonicalized (that would need the device to exist, breaking the portable-profile skip
  above). So a symlink under `/dev` pointing elsewhere (`/dev/foo -> /etc`) binds its target.
  Because `[devices]` is **trusted-only**, this is self-harm equivalent to writing
  `binds = [{ path = "/etc", mode = "rw" }]` directly, not a new capability, so keep your
  `allow` list to real device nodes.
- A device that does **not exist on this host** is **skipped at launch** (the bind is a
  `--dev-bind-try`), not fatal: so a portable profile that lists a GPU or `kvm` still
  launches on a host that lacks it. The tool simply does not see that device there.

## What a grant does and does not do

- It **binds the device node** into the cage. Whether a process may then *use* it is still
  governed by the device's own file permissions and the host uid the cage runs as
  (same-uid): exactly as on the host. `sbx` grants visibility, not new privilege.
- Some devices need more than the node. **`/dev/fuse`** additionally needs the `mount`
  syscall, which the mandatory [seccomp](seccomp) denylist refuses: so a FUSE tool
  needs `[seccomp] allow = ["mount"]` as well. **`/dev/net/tun`** is most useful under
  `network = "shared"` (an isolated/allowlist posture gives the cage an empty network
  namespace).

## Why it is trusted-only

A real device node is a kernel attack surface: device drivers are a classic
local-privilege-escalation vector, and a bound device makes that driver reachable from
in-cage code. That is a choice only a trusted operator makes: so an untrusted project's
`[devices]` is dropped, and a globally-declared grant survives an untrusted project
unchanged (an agent runs *on* untrusted code without that code exposing a host device).

## Per-app grant

An `[app.<name>.devices]` table (or a `[devices]` table in an imported profile) grants
devices **for that app's launches**, **unioned** onto the baseline and gated the same way.
An untrusted project's app `[devices]` is dropped: so a globally-declared app's device
grant cannot be widened by an untrusted project.

```toml
[app.render.devices]
allow = ["/dev/dri"]
```

## Viewing the effective grant

```sh
sbx config show               # a `devices:` line only when a device is granted
sbx config show --app render  # an app's effective grant, tagged inherited or set
```

The paths render sorted, the same set the cage binds.

## Scope

`[devices]` is a config-file field (global, project, or an app overlay). It is also a
one-shot [override](overrides): `--device <path>` (repeatable) and `SBX_DEVICE` grant a
host device for a single launch. An override is **trusted by invocation**: the person
running `sbx` outranks any config layer: so it may grant exactly the device a *trusted*
config already can, even though an untrusted project's `[devices]` is dropped (parity with
the trusted config). `--device` takes **one path per flag** (repeatable); it is not
comma-split, so `--device /dev/a,/dev/b` is a single, non-existent path (silently skipped),
not two grants. A malformed path is warned and skipped (no device, fail-closed), never
fatal. (Granting the *node* is not the same as being able to *use* it: see the note above;
in particular a device that needs a Linux capability, such as a VPN tun, is not made usable
by exposing it, in a config file or a one-shot flag.)
