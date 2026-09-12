---
description: "Report whether an access would be allowed, and why, without launching anything."
---

# `sbx test`

```
sbx test net  [--app <name>] [-X|--method <verb>] <url|tcp://host:port>
sbx test fs   [--app <name>] <path>
sbx test proc [--app <name>] [--caller <path>]... <program>
```

A diagnostic surface that reports whether an access would be allowed, and why. No
launch, no nix, no network: it reports a verdict against the resolved policy.

Each kind answers by calling the **same** decision the enforcing path calls, rather than
re-deriving a verdict of its own. A tester carrying its own copy of the rule would eventually
disagree with what the cage does, and it would disagree silently.

For the same reason, each kind resolves its policy the way a launch resolves it: a named app's
overlay first, then the ambient `SBX_*` [one-shot override](../configuration/overrides), which
beats that overlay exactly as it does at launch. A verdict read while the shell carries an
override is therefore the verdict that launch would get. Override flags on the command line
belong to the launching verbs, so `sbx test` does not take them; export the variable instead if
you want to ask about a posture you have not written to the file.

See also: [`sbx net`](net) · [`sbx fs`](fs) · [`sbx proc`](proc) · [the `[fs]` table](../configuration/fs) · [Network modes](../networking/modes) · [Rule grammar](../networking/rules) · [Egress observability](../networking/observability).

## `sbx test net`

Reports **ALLOWED / DENIED / WOULD ASK** and the rule that decides it, against the
effective [egress policy](../networking/modes) a launch would serve. The built-in
self-equip allow-set is included, and a declared [credential injection](../secrets/injection)
is noted (by header and source, never the value, and not resolved). Reflects the
[trust gate](../concepts/trust): an untrusted project's policy is dropped.

| Option | Meaning |
|---|---|
| `<url>` | the URL (or a bare host, completed to `https`) to test |
| `tcp://host:port` | test a raw L4 splice instead: reports **SPLICED / NOT SPLICED** |
| `-a, --app <name>` | test against that app's effective policy (baseline + overlay) |
| `-X, --method <verb>` | the HTTP method to test (default `GET`); a `{GET}` rule only matches that verb (ignored for `tcp://`) |

## `sbx test fs`

Reports **DENIED / READ-ONLY / OPEN** against the [`[fs]`](../configuration/fs) masks a launch
mounts, and names the entry that decides. When a directory above the target is what closes it,
the covering path is named too, because the pattern alone does not say why that name is shut.

| Option | Meaning |
|---|---|
| `<path>` | the project path to ask about, absolute or relative to the project |
| `-a, --app <name>` | test against that app's effective policy (baseline + overlay) |

```sh
sbx test fs secrets/token               # is this closed?
sbx test fs certs/client.pem            # read-only, or open?
sbx test fs -a claude-code prod.key     # under that app's overlay
```

```
fs: 2 denied, 1 read-only
  DENIED  /home/you/project/secrets/token
  by `[fs] deny` entry `secrets/`, which closes `/home/you/project/secrets` above it
```

The path **need not exist**. A denied directory is an empty one inside the cage, so a file that
appears there later in the session is unreachable too, and that is the answer this reports: a name
nothing bears yet still reads as `DENIED`. Symlinks are followed, since a mask names a link's
target rather than the link.

The expansion's own warnings are printed here as well, which is half of what the verb is for: an
entry that matched nothing, a second hard link reaching a closed file, a path git tracks. A
refusal is fatal here for the same reason it is fatal to a launch, because a run without the masks
leaves open exactly the paths the policy closes.

### What it cannot tell you

Two things, and they are different in kind.

`[fs] scan` is the other half of the same table, and this verb cannot answer it: that lens decides
at **each open**, on what the file holds, so there is no verdict without the bytes and the launch
that reads them. Its presence is reported, never a result.

And unlike its siblings, this verb reports no [trust gate](../concepts/trust) on the masks,
because there is none. A project closing its own files off gains nothing it could turn on the
user, while dropping its masks would leave a file the project asked to close wide open, so `deny`
and `readonly` apply from an untrusted project too. The one gated key is `scan_max_kb`, which
raises how much of a file the content lens reads past.

## `sbx test proc`

Reports **ALLOWED / DENIED / PARKED** against the effective [`[proc]`](../configuration/proc)
exec policy a launch enforces, and names the mode that decides a program no rule matches.
Reflects the [trust gate](../concepts/trust) the same way: an untrusted project's `[proc]` is
dropped, so the tester reports the baseline rather than the policy the file asks for.

| Option | Meaning |
|---|---|
| `<program>` | the exec target to test, as the supervisor sees it: a basename (`curl`) or a full in-cage path (`/nix/store/…/bin/git`) |
| `-a, --app <name>` | test against that app's effective policy (baseline + overlay) |
| `--caller <path>` | one link of the chain leading to the exec, outermost first; repeatable |

```sh
sbx test proc curl                      # would this be blocked?
sbx test proc git -a claude-code        # under that app's policy
sbx test proc rm --caller /bin/sh       # under a [proc.callers] graph
```

```
proc: enforce (denylist — everything not denied runs)
  DENIED  curl
```

`--caller` matters only under a [caller graph](../configuration/proc), where what may run depends
on **who** runs it. Under one, a verdict asked without a caller answers a different question than
a real exec does, so the tester says as much rather than letting an unexpected `DENIED` be read as
the policy's answer.

### What it cannot tell you

The verdict is what the **rules** say about the program you named. It is not what a particular
`execve` would resolve to, because that part needs a live process: on a real exec the supervisor
resolves the target through the calling process's own `/proc` entry, follows a `#!` line and a
dynamic loader's argument to the programs they really run, and decides each of them; a target it
cannot read is decided by the mode's default.

So a script that passes here may still be refused in the cage for its interpreter, and the way to
see that is the feed: [`sbx proc logs`](proc#logs) on an observed session.

## Private and internal addresses

A permitted request meets one more check on the wire: the proxy resolves the host and
runs its [SSRF guard](../networking/architecture#the-ssrf-guard) on the address, which
admits a private or loopback one only when the deciding rule names **that exact host**.
`sbx test net` replays that guard, so a target it reports as allowed is one the proxy
would really connect to:

```
$ sbx test net https://127.0.0.1/
network: deny (allowlist — only listed and built-in hosts reach)
DENIED   https://127.0.0.1/
  the policy allows it (allow rule: re:.*), but the proxy refuses the address at connect time: a private or loopback address is reachable only when the deciding rule names that exact host
```

Naming the host exactly (`allow = ["192.168.1.10"]`, `allow = ["db.internal"]`) is the
deliberate act the guard admits, and the verdict is then a plain ALLOWED.

The guard needs an address, and this command resolves nothing (no network). So on an
**IP literal** the verdict is exact, while on a **name** under a rule that does not
name it exactly (a `re:` regex, a `*.domain`, an allow-by-default posture) it can only
state the condition:

```
  note: if this name resolves to a private or loopback address, the proxy refuses it at connect time (no rule names this exact host)
```

A link-local address (the cloud metadata one among them), a multicast, or the
unspecified address is refused however the policy is written, exact rule included.

## Examples

```sh
sbx test net https://api.github.com
sbx test net api.github.com --method POST
sbx test net --app claude-code https://api.anthropic.com/v1/messages
sbx test net tcp://db.internal:5432
sbx test net https://127.0.0.1/          # the address guard, replayed
```

`sbx test net` tests **one URL**; to list the effective rules, use
[`sbx net rules`](net).
