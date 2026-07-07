# `[caps]` de-risk spike — capabilities in the single-uid cage (2026-07-07)

**Throwaway spike. No production code. Verdict: do not build `[caps]`.**

## Question

`[devices]` can now bind a host device node (a GPU, `/dev/net/tun`, `/dev/kvm`,
`/dev/fuse`) into the cage. Some of those devices need a Linux **capability** to be
*used* — the motivating case being a VPN: `/dev/net/tun` gives the tun node, but
configuring the tunnel interface (`ip link`, `TUNSETIFF`) needs `CAP_NET_ADMIN`.

Could a future `[caps] add = ["CAP_NET_ADMIN"]` re-grant a specific capability in
ops's cage — a non-setuid **unprivileged, single-uid** user namespace with
`no_new_privs` — *usably*, without regressing the hardening baseline?

## Method

Live `bwrap 0.11.1` experiments on the host (unprivileged userns unrestricted:
`kernel.apparmor_restrict_unprivileged_userns = 0`). Each cage mirrors ops's
hardening (`--unshare-{user,ipc,pid,uts,cgroup}`, `--clearenv`, `--die-with-parent`,
`--cap-drop ALL`) and reads `/proc/self/status` + `capsh` from inside, then attempts
a real privileged operation. Every "with cap" test has a "without cap" twin (teeth).
Scripts: `scratchpad/caps-spike/exp_*.sh`.

## Findings

### 1. `--cap-add` *does* inject the capability — even same-uid, and `no_new_privs` survives

Contrary to bwrap's `--help` ("Add cap CAP **when running as privileged user**"), in
the unprivileged single-uid userns:

| Config | CapEff | CapAmb | NoNewPrivs |
|---|---|---|---|
| ops baseline (`--cap-drop ALL`) | `0` | `0` | **1** |
| `--cap-drop ALL --cap-add CAP_NET_ADMIN` | `cap_net_admin` | `cap_net_admin` | **1** |
| no cap flags at all | `0` | `0` | **1** |

So bwrap propagates the added cap into the **ambient** set (it therefore survives the
non-root `execve` into the payload) and `no_new_privs` stays **1** — **no hardening
regression**. Also: bwrap already zeroes all caps by default; ops's explicit
`--cap-drop ALL` is belt-and-suspenders.

This part looked promising. It is a mirage — see (2).

### 2. The injected capability is **completely inert** in the cage

Every capability that motivates the feature is present in `CapEff` yet powerless:

| Capability | Operation | Netns | With cap | Without cap |
|---|---|---|---|---|
| `CAP_NET_ADMIN` | `ip link set lo up` | isolated (cage-owned) | **FAILED** EPERM | FAILED |
| `CAP_NET_ADMIN` | `ip link set lo up` | shared (host) | **FAILED** EPERM | FAILED |
| `CAP_NET_ADMIN` | `ip tuntap add` (`/dev/net/tun` bound) | either | **FAILED** EPERM | FAILED |
| `CAP_SYS_ADMIN` | `sethostname` | cage UTS ns | **FAILED** "must be root" | FAILED |
| `CAP_NET_RAW` | raw `SOCK_RAW` socket | shared **and** isolated | **FAILED** EPERM | FAILED |
| `CAP_NET_BIND_SERVICE` | `bind(:80)` | shared | **FAILED** EACCES | FAILED |

The cap in `CapEff` changes **nothing** — the "with cap" and "without cap" columns are
identical. Verified over both **same-uid** *and* **root-mapped** (`--uid 0`) cages, and
over both **cage-owned** and **host-owned** namespaces.

The contrast that isolates it: a plain `unshare --user --net --uts --map-root-user`
(root-mapped, full caps, and it *owns* the namespaces) runs `ip link set lo up` and
`sethostname` **OK**. The same operations under bwrap-with-`--cap-add` fail.

### 3. Root cause: the payload runs in a **descendant** user namespace of the one that owns the cage's namespaces

Capabilities are effective only over objects owned by the **current userns or its
descendants**, never an **ancestor**. bwrap runs the payload in a nested userns *inside*
the userns that owns the cage's net/uts/ipc namespaces. Proven with `ioctl(NS_GET_USERNS)`
from the host on the cage's netns:

```
payload  user ns inode : 4026534288
net ns  OWNER user ns  : 4026534194     # a different, ancestor userns
OWNER == payload userns ? False
```

So the payload's `CAP_NET_ADMIN` lives in a descendant userns (288) and is powerless
over the netns owned by the ancestor userns (194). This is structural to bwrap's design,
not a flag we can toggle.

And even if the payload *did* own the cage namespaces, a cap is still scoped to the
**cage** userns — so under `network = "shared"` the host netns (owned by the host/init
userns, an ancestor) would remain unreachable regardless. The VPN story is blocked twice
over.

## Verdict — do **not** build `[caps]`

A `[caps] add` field would be **security theater**: the granted capability shows up in
`capsh` / `/proc/self/status` but confers **no operational privilege** in the cage. It
would add a config surface, a trust-gating story, and docs for a knob that does nothing —
and worse, mislead a reader into thinking the cage is more capable (or more dangerous)
than it is. The honest thing is to not offer it.

- The tested caps (`CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_NET_RAW`,
  `CAP_NET_BIND_SERVICE`) are all inert. The general mechanism (2)+(3) — namespaced-object
  caps are gated by the owning userns, which is always an ancestor of the payload —
  applies to every namespaced capability, so no compelling case survives.
- FS-object caps (`CAP_DAC_OVERRIDE`, `CAP_CHOWN`, …) are likewise gated by the userns
  owning the inode's superblock; for host bind-mounts that is the init userns (an
  ancestor), so they are inert for host paths too. (Reasoned from the same mechanism;
  the network/admin caps above are the ones tested.)

## Consequence for the `[devices]` VPN note

`[devices]` remains correct as shipped: it binds the device **node**, and the guide
already says use is "governed by the device's own file permissions and the host uid" —
*not* by any capability grant. The doc's "`/dev/net/tun` is most useful under
`network = "shared"`" line should be read as "the node is reachable there", **not** "a
tunnel can be brought up in-cage". A real in-cage VPN / raw-networking capability is a
separate, larger design (a privileged out-of-cage helper that configures the tun and
hands the fd in, or userspace networking à la pasta/slirp) — explicitly **not** a
capability field. Left as a future consideration, not a gap.

## Artifacts

`scratchpad/caps-spike/`: `exp_base.sh` (cap injection + NNP), `exp_usability.sh`
(netns/tun), `exp_isolate.sh` (same-uid vs root-map), `exp_ownership.sh`
(UTS + net, root-cause), `exp_raw.sh` (NET_RAW / NET_BIND_SERVICE),
`exp_owner_check.sh` (`NS_GET_USERNS` proof). Throwaway — safe to delete.
