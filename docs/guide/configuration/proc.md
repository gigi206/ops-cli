# `[proc]` — process/exec observation and enforcement

```toml
[proc]
mode  = "off"            # off | observe | enforce | ask
allow = ["git", "rg"]    # exec targets that always run — only bites under `ask`
deny  = ["curl", "ssh"]  # exec targets that are blocked
```

The `[proc]` field governs the **process/exec lens**: what `sbx proc` sees, and — under `enforce`
or `ask` — what an in-cage agent is allowed to `execve`. It is the exec analogue of
[`network`](network.md): a **security field**, honored from the global config or a **trusted**
project and dropped (with a warning) from an untrusted one — an untrusted project may neither forge
nor loosen the enforcement of its own agent. It can be set on the baseline **or** per app
([`[app.<name>.proc]`](apps.md)); an app's policy replaces the baseline's for that app.

## Modes

| Mode | What it does |
|---|---|
| `off` (default) | no capture, no enforcement |
| `observe` | capture spawns via a cheap `/proc` poll (`sbx proc logs`), no blocking — the same feed as [`--observe`](../cli/run.md#observing-a-run-observe) |
| `enforce` | **block** a `deny` exec target before the syscall runs; everything else runs (a denylist) |
| `ask` | block `deny`, run `allow`, and **park** an unmatched target for a live [`sbx proc pending`](../cli/proc.md#pending) decision |

Under `enforce`/`ask` the lens uses a **seccomp user-notification** gate: every `execve`/`execveat`
traps to a host-side supervisor that decides it. A `deny` returns `EPERM` — the syscall **never
runs** (there is no time-of-check/time-of-use window on a refusal). Capture is then exact (no poll
gap), and `sbx proc logs` shows each spawn with its verdict.

## Rule grammar

Each `allow`/`deny` entry is a shell-style glob (`*` = any run, `?` = one character):

- a rule **without** `/` matches the exec target's **basename** — `curl` blocks `/usr/bin/curl`
  and any other `curl` on `PATH`;
- a rule **with** `/` matches the **full exec path** — `/usr/bin/*`, `/nix/store/*/bin/git`.

Matching is otherwise exact (`curl` never matches `curlish`), and **`deny` always wins** over
`allow` (an entry in both is denied).

## Posture — a denylist, by design

`enforce` is a **denylist**: everything runs except an explicit `deny`. A coding agent spawns
constantly (compilers, `git`, language servers), so a default-deny allowlist would brick it; the
denylist lets you block the specific things you don't want an agent reaching for — `ssh`, `curl`,
`sudo`, a package manager — while it works normally otherwise.

`ask` is stricter: an unmatched target parks. Because a coding agent spawns so much, `ask` is meant
to run against a **populated `allow` list** (the tools you trust it to use), with `deny` for the
ones to always refuse and the interactive prompt for the genuinely-new. A parked `execve` that is
not decided within the ask timeout is **auto-denied** (fail-closed), so a process tree never hangs
on a stalled decision.

## Honest scope

A `deny` is a **hard stop on `execve`**, even against a hostile agent — the two obvious ways around a
seccomp exec gate are both closed by the kernel: a foreign-ABI `execve` (the i386 compat call from a
64-bit process) is *killed* by the mandatory syscall denylist's architecture guard rather than
slipping through, and an agent cannot install its own notification filter to intercept its own
`execve`s (the kernel allows only one such listener, held here by the launcher). So `deny = "curl"`
genuinely stops `curl` from executing.

What exec enforcement is **not** is a full containment boundary — it is a **guardrail** on the exec
channel, for three honest reasons:

- an agent can do harm **in-process** (in its own interpreter) without `execve`ing anything at all;
- `allow`/approval re-runs the real syscall, which is **TOCTOU-racy** against an adversary that swaps
  the path argument after the check — so *refusing* a path is hard, but *approving* a specific one is
  a guardrail;
- the x32 ABI shares x86-64's architecture value with distinct syscall numbers — a narrow blind spot
  shared with the base denylist, and the base toolset is x86-64.

So the cage's real confidentiality/integrity boundaries stay what they always were — confinement by
absence (a secret that isn't mounted can't be read), the read-only store, and the
[network allowlist](network.md). `[proc]` adds **visibility and a hard veto on what the agent execs**
on top of them.

The `enforce`/`ask` feed (`sbx proc logs`) shows the resolved **exec path** the agent is running (the
thing policy matches on), not the full argv — a `curl https://…` appears as `…/bin/curl`.

## Watching and deciding

- [`sbx proc logs [<id>] [-f]`](../cli/proc.md#logs) — the exec feed, each line carrying its verdict
  (`allow`/`deny`/`ask`, or `observe` for a non-enforcing run).
- [`sbx proc pending`](../cli/proc.md#pending) — list, and `allow`/`deny`, the `execve`s an `ask`
  session has parked.

## Example

```toml
# A trusted project: let the agent build and use its toolchain, but never reach the network by
# shelling out, and prompt for anything unexpected.
[proc]
mode  = "ask"
allow = ["git", "rg", "cargo", "rustc", "node", "sh", "bash", "/nix/store/*"]
deny  = ["ssh", "scp", "sudo", "curl", "wget"]
```

See also: [`sbx proc`](../cli/proc.md) · [`network`](network.md) · [Enforcement stack](../concepts/enforcement.md).
