# `[notify]`: being told when something was blocked

```toml
notify = "always"        # off | once | always: the short form, one mode for everything

# or, per event:
[notify]
mode = "once"
[notify.events]
network = "always"       # every blocked request
proc    = "once"         # the first of each blocked program
task    = "off"          # never
```

See also: [`[network]`](network) · [`[proc]`](proc) · [Declared operations](../tasks/) ·
[Observability](../concepts/observability) · [One-shot overrides](overrides#--notify-how-loudly-one-launch-speaks).

A refusal is invisible by design. When the network policy turns a request down, the agent gets a
`403` it is under no obligation to mention; when the exec policy stops a program, the `execve`
simply fails. The boundary did its job and **you** heard nothing: which reads exactly like a
boundary that never bit, right up until you spend an afternoon debugging an agent that "just does
not work".

`[notify]` is what closes that gap: sbx tells you, on your desktop, what it refused and why.

## Where the notification goes

A desktop notification on your session bus (`org.freedesktop.Notifications`): the same daemon every
other application on your desktop uses. It is raised by **sbx itself**, host-side, not from inside
the cage: this is unrelated to [`dbus = true`](dbus), grants the sandbox nothing, and means an
in-cage agent can neither forge an "sbx blocked …" notification nor dismiss one that names it.

With no session bus to reach, over `ssh`, on a headless host, from `cron`, sbx says so once and
falls back to a line on stderr. A notification is always best-effort: a launch never fails because
one could not be delivered.

## Which sandbox it came from

Every notification names its session in the **summary**, after the headline:

```
sbx blocked a network request · kiro@ops-cli[48213]
```

- `kiro`, the app, when the launch is one (absent for a bare `sbx run`);
- `ops-cli`: the project's directory name;
- `48213`, the launching sbx **pid**, the same one [`sbx session ls`](../cli/session) lists and
  that [`sbx attach`](../cli/session) and [`sbx stop`](../cli/session) take.

It rides the summary rather than the body because with two or three sandboxes running at once,
"which one was that?" is the first question a toast has to answer, and the summary is the part read
first and never truncated. The pid is what makes it actionable: from the toast you can go straight to
`sbx attach <pid>` or `sbx net logs` for that session.

The project's **full path** is deliberately not there, no toast is wide enough, and lives in
`sbx session ls`.

## Modes

| Mode | What you get |
|---|---|
| `off` | nothing. The refusal still happens and is still recorded: `sbx net logs`, `sbx proc logs` |
| `once` | the **first** occurrence of each distinct problem, then silence for that one |
| `always` (default) | every occurrence, a repeat **revises** the notification already on screen rather than adding one |

`always` is the default because the cost of a repeat is not a second toast: it updates the first
one in place. So what you get over `once` is a problem that keeps saying it is still happening,
not a desktop to clear. Switch to `once` if you would rather each problem be stated exactly once
and never again.

### Spacing repeats out: `repeat_after`

Revising a toast is free, but an agent retrying for an hour keeps putting that toast back in front
of you, and *that* is the spam. A quiet period turns "every occurrence" into "at most once per
period, per problem":

```toml
[notify]
mode = "always"
repeat_after = "5m"      # this problem stays quiet for 5 minutes after being announced
```

Durations are `"90s"`, `"5m"`, `"2h"` (a bare number is seconds). The clock restarts from each
announcement, and it is **per problem**: one host being held back never delays another's first
notification. `once` ignores it (that mode never repeats at all) and says so with a warning, and a
malformed duration keeps whatever period was already in effect rather than falling back to
announcing everything.

### What `once` counts as "the same problem"

The identity is **the event, the subject, and the reason**. So:

- `api.example.com:443` refused two hundred times because nothing allows it → **one** notification;
- the same host later refused by an explicit `deny` rule → **a new** notification, because it is a
  different problem with a different fix;
- three different hosts refused → three notifications.

That memory lives in RAM for the session and is **never written to disk**. Start a new session and
you are told again, deliberately: a refusal you dismissed yesterday can mean something new today.

This is what makes `always` affordable as the default: an agent retrying a blocked host in a loop
leaves you **one** notification being revised, not two hundred to dismiss. Under `once`, that same
loop is announced a single time and then never mentioned again, even while it continues.

## Events

Each event is named after **the config section that governs the refusal**, so the name also tells
you where to go and change it.

| Event | Section | Fires when |
|---|---|---|
| `network` | [`[network]`](network) | a request is refused, by a `deny` rule, because nothing allowed the host, because the method is not permitted, or by a security guard (a credential on its way out, an SSRF target) |
| `proc` | [`[proc]`](proc) | a program is stopped before it runs |
| `ssh_agent` | [`[ssh_agent]`](ssh-agent) | a request for a key is refused |
| `task` | [`[task]`](task) | an invocation is refused |
| `trust` | [trust gate](../concepts/trust) | a security field is dropped because the config declaring it is not trusted |

An `events` **list** narrows which events speak at all: everything unnamed goes quiet:

```toml
[notify]
mode = "always"
events = ["network"]     # blocked requests only, everything else silent
```

An `events` **table** sets a mode per event and leaves the rest on the table's `mode`:

```toml
[notify]
mode = "once"
[notify.events]
network = "always"       # this one, every time
trust   = "off"          # never this one
```

A misspelled event name is **named in a warning**, not passed over: otherwise a typo would silently
mean "never told about this", which is the exact failure this field exists to prevent.

## What is *not* notified

- **A file the cage cannot reach.** The sandbox blocks files structurally: an unbound path simply
  does not exist inside the cage, a read-only bind refuses a write, and the kernel answers those
  *inside* the mount namespace. No call reaches sbx, so there is nothing to report. Same for a
  syscall the mandatory [seccomp](seccomp) filter refuses: the kernel returns the errno directly.
  What sbx can announce is what sbx itself decided.
- **A `mute`d request.** A [`mute`](network) (`dontaudit`) rule says "stop telling me about this
  one"; honouring that for the log while still raising a toast would defeat the point.
- **An `ask` you already answered.** Under the interactive posture you were asked about that exact
  request; a second, after-the-fact "it was denied" would be pure noise.

## When a fix is suggested

A notification for a host that **nothing allowed** carries the copy-paste command that allows it
(`sbx net allow <host>`, scoped to the app when the launch is an `sbx app`).

A refusal on a **security** ground never does: not for an explicit `deny` rule you wrote, and not
for a credential leak or an SSRF target. Telling you to allow a request that was stopped *because it
was carrying your token out of the cage* would be advice that opens the hole the guard just closed.

## Trust

`[notify]` is a **security field**: honored from the global config or a trusted project, dropped
(with a warning) from an untrusted one. A `.sbx.toml` able to silence these notifications could hide
precisely what the boundary exists to surface, and would do so from the side the boundary exists to
contain. Set it globally (trusted by its location) and it applies everywhere.

It can also be set per app ([`[app.<name>.notify]`](apps)); an app's policy replaces the
baseline's for that app. That matters because how much an app's refusals are worth hearing is a
property of the app: a browser profile refused on every third-party asset it loads is noise, while
the same refusal from a coding agent is the signal.

## One launch at a time

`--notify <off|once|always>` (or `SBX_NOTIFY`) sets one mode for every event, for a single launch,
beating both the config and an app's own policy: see [overrides](overrides):

```bash
sbx run --notify off -- ./nightly-batch      # read the refusals in the log instead
sbx app run agent --notify always            # watch this one closely
```

A mistyped mode is a hard error rather than a fall back to the baseline: the fallback could run the
launch quieter than you asked for.

The flag sets one mode for every event and nothing else, so a configured `repeat_after` survives it, `--notify always` over a config with `repeat_after = "5m"` announces every event, still no more
often than every five minutes. To change the period, or to refine a single event, use a `--config`
blob's `[notify]` table (and put the mode in that same blob, since the typed flag would replace it).

## Seeing the effective policy

```console
$ sbx config show
  notify: always (default)
```

When the events differ, each is listed with its own mode. `sbx config show --app <name>` shows the
app's effective policy and whether it is the app's own or inherited.

## Related

- [`[network]`](network): the egress policy, and `sbx net logs` for the full record
- [`[proc]`](proc): the exec policy, and `sbx proc logs`
- [trust](../concepts/trust): why an untrusted project cannot set this
