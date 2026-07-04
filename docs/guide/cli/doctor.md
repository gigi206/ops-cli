# `ops doctor`

```
ops doctor
```

Verify the runtime prerequisites before anything can run.

Checks the load-bearing requirements: capability-bearing unprivileged user namespaces
(the security boundary everything rests on), the bubblewrap engine, and the nix binary
that drives the user-owned store. A missing requirement is a **hard failure with a
remediation hint** — never a silent fallback to a weaker engine. Also reports
best-effort resource limiting and the store location and channel revision.

For the full explanation of each check, see
[`ops doctor` and prerequisites](../getting-started/doctor.md).

See also: [Installation](../getting-started/installation.md) · [Security model](../concepts/security-model.md) · [Enforcement stack](../concepts/enforcement.md).
