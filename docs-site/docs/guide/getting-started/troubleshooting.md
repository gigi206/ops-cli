---
description: "The symptoms you are most likely to meet first, each pointing at the page that owns the fix."
---

# Troubleshooting

A place to start when something is already broken. Each symptom below shows the **exact
output `sbx` prints** and the page that owns the fix. The messages are quoted verbatim from
the binary, so you can match what you see on screen.

If your symptom is not here, run `sbx doctor` first: it is the prerequisites preflight and
fails hard on anything load-bearing.

See also: [Prerequisites](doctor) · [Trust](../concepts/trust) · [Networking overview](../networking/) · [Configuration overview](../configuration/).

## `sbx doctor` reports `[FAIL]`

`doctor` exits non-zero and prints a remediation list:

```text
sbx: missing prerequisite(s) — sbx CANNOT run until these are resolved:
       • install bubblewrap (the sandbox engine)
       • enable capability-bearing unprivileged user namespaces (no security boundary without them; no fallback): `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`, or an AppArmor profile allowing unprivileged userns for sbx
```

This is **by design**: there is no silent fallback, because without a capability-bearing
user namespace there is no security boundary. Fix the listed item (usually bubblewrap or the
`kernel.apparmor_restrict_unprivileged_userns` sysctl) and re-run. See
[Prerequisites](doctor).

On a host that restricts unprivileged user namespaces, the `user namespaces` line of the same report
prints an AppArmor profile that lifts the restriction for `sbx` alone, the narrow alternative to the
sysctl. Save it as `/etc/apparmor.d/sbx` and load it with `sudo apparmor_parser -r
/etc/apparmor.d/sbx`. It lifts the failure even where the host's `bwrap` carries no profile of its
own. It is attached to the path `doctor` printed, so a binary that moves needs its path updated.

## A launch warns about its network namespace

A launch that would route proxy-blind clients, or that runs a graphical app, configures the network
namespace `bwrap` creates for the cage before the cage's command runs: it joins that namespace from
the host and adds the
[capture tap](../configuration/network#clients-that-ignore-the-proxy-variables) and the interface
that tells a graphical app it is online. Joining creates no namespace, so a host that restricts
unprivileged user namespaces (Ubuntu 24.04 and later do by default) does not prevent it: only `bwrap`
creates one. Where the join is refused, the launch prints:

```text
sbx: warning: the cage's network namespace could not be joined (bwrap runs privileged (setuid), so its sandbox is not this user's to join), so the cage runs in an empty network namespace of bwrap's own: a client that ignores the proxy variables will fail to connect rather than be routed; `sbx doctor` says what blocks it
```

The cage still runs, and it is still filtered: its network namespace is the empty one `bwrap`
creates, and its egress goes through the proxy as usual. What is missing is the tap and the
interface. The case above is a setuid `bwrap` on a host that also restricts unprivileged user
namespaces. Elsewhere `sbx` has a setuid `bwrap` run unprivileged, from a user namespace of its own
where the kernel ignores the setuid bit; here that namespace is refused, so `bwrap` runs
privileged and the namespace it creates belongs to the host, not to the invoking user. A `bwrap`
that is not setuid avoids it.
`sbx doctor` reports the same refusal under `capture`:

```text
  [warn] capture           sbx cannot configure the cage's network namespace, so a launch runs without capture
         · the cage's network namespace could not be joined (bwrap runs privileged (setuid), so its sandbox is not this user's to join)
         · a launch still filters its egress through the proxy, but a client that ignores the proxy environment variables fails to connect rather than being routed, and a graphical app may report itself offline
```

## The launch works, but the project's config is silently ignored

A brand-new project's `.sbx.toml` is **untrusted**, so its security-relevant fields are
ignored until you approve it:

```text
sbx: warning: .sbx.toml: ignoring `network` policy (untrusted — run `sbx trust`)
network: deny (allowlist — only listed and built-in hosts reach)
```

Nothing is broken: the sandbox dropped the project's own posture and fell back to the
built-in default, which filters and carries no rules, so only the
[self-equip set](../networking/modes#the-built-in-self-equip-set) reaches. This is why
your `allow` list appears to have no effect. Run `sbx trust` and the policy takes effect:

```text
sbx: trusted .sbx.toml
```

See [Trust](../concepts/trust) and [Networking overview](../networking/).

## A network request is denied inside the sandbox

Once a project is trusted with `mode = "deny"`, only listed hosts reach the network.
`sbx test net` shows the verdict:

```text
network: deny (allowlist — only listed and built-in hosts reach)
DENIED   https://api.example.com
  no allow rule matches (deny-by-default)
```

To allow it, add a rule to `[network] allow` (see [Networking rules](../networking/rules))
and re-run `sbx trust`. The built-in `cache.nixos.org` hosts are always allowed so
self-equipment works.

A `POST` to a host you only allow with `{GET}` is also denied: the method must match:

```text
DENIED   https://example.com
  no allow rule matches (deny-by-default)
```

## A secret is not injected

If a `from` reference points at a scheme `sbx` does not know, the launch fails with:

```text
unknown secret resolver scheme
```

Either the built-in scheme is mistyped (`env://`, `file://`, `sops://`) or a resolver
plugin that provides the scheme is not installed. See
[Resolvers](../secrets/resolvers) and [Plugins](../plugins/).

## A program will not run / exec is blocked

The `[proc]` policy is a security field and only applies to a trusted project. An untrusted
project's `proc` block is ignored, and, depending on posture, an exec that the policy would
deny is blocked. Diagnose with `sbx proc` and, if you meant to relax it, trust the project
and adjust `[proc]` (see [proc policy](../configuration/proc)).

## The sandbox launches but the GUI app shows no text / no window

A graphical app under `gui = "wayland"` needs fonts and (often) a GPU. A hermetic cage
carries neither `/etc/fonts` nor a font set, so text renders as boxes; without a GPU grant
the app falls back to software rendering or fails to start. See
[gui](../configuration/gui) and [gpu](../configuration/gpu).
