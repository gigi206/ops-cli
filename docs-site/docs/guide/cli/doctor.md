# `sbx doctor`

```
sbx doctor
```

Verify the runtime prerequisites before anything can run.

Checks the load-bearing requirements: capability-bearing unprivileged user namespaces
(the security boundary everything rests on), the bubblewrap engine, and the nix binary
that drives the user-owned store. A missing requirement is a **hard failure with a
remediation hint**: never a silent fallback to a weaker engine. Also reports
best-effort resource limiting, the store location and channel revision, and the
**storage posture**: whether the data directory lives in an encapsulated
[volume](storage), or, when it does not, whether one is worth adopting on this host
(the filesystem it sits on, and whether btrfs, loop devices and udisks2 are present).
That line is always informational, never a failure: a volume is opt-in. It does flag one
thing no volume would fix: a data directory on a **tmpfs**, where nothing survives a
reboot.

For the full explanation of each check, see
[`sbx doctor` and prerequisites](../getting-started/doctor).

## Examples

```sh
sbx doctor                     # the preflight, before anything else
sbx doctor && sbx run -- ./ci.sh   # gate a script on a usable host
```

`doctor` exits non-zero when a load-bearing requirement is missing, so the second
form is the way to make a CI job fail on the preflight rather than mid-launch. A
run through the [sample output](../getting-started/doctor#a-passing-host) shows what
each line asserts.

See also: [Installation](../getting-started/installation) · [Security model](../concepts/security-model) · [Enforcement stack](../concepts/enforcement).
