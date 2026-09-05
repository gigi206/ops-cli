---
description: "The park-and-confirm posture: a request waits while you decide, and the answer can be remembered."
---

# Ask mode

`ask` is the **park-and-confirm** [egress posture](modes#ask). It is the
discovery mode: run an agent and decide, in real time from another terminal, what it
may reach, allowing or denying each new destination as it comes up, and optionally
remembering the answer.

```toml
[network]
mode  = "ask"
allow = ["api.anthropic.com"]    # never asked: always allowed
deny  = ["telemetry.example.com"] # never asked: always denied
# everything else parks until you answer
```

Under `ask`, a request whose destination matches an `allow` rule auto-passes and one
matching a `deny` rule auto-fails: exactly as under `deny`/`allow` mode. Any
**undecided** request (matching neither list, and not a
[built-in self-equip host](modes#the-built-in-self-equip-set)) **parks**: it
blocks inside the cage while it waits for your live decision.

---

## The workflow

1. **A request parks.** The in-cage tool's connection blocks. By default a stderr
   **park notice** is printed announcing the parked destination and its id (silence
   it with `ask_notice = false`).

2. **List what is parked**: from any other terminal:

   ```bash
   sbx net pending
   ```

   This lists every request parked across every live `ask`-mode session, each with a
   `<pid>.<seq>` id (the PID is the one [`sbx session ls`](../housekeeping/sessions)
   shows). Identical retries of one URL collapse to a single `×N` line, so a tool
   that retries does not flood the list. Add `--json` for scripts, `-a <app>` to
   scope to one app's session(s).

3. **Answer it:**

   ```bash
   sbx net pending allow 12345.7     # let this destination proceed
   sbx net pending deny  12345.7     # refuse it (the cage gets a 403)
   ```

   The id addresses one live session's destination. Answering unblocks the parked
   request **and every identical retry of the same URL** at once. A denial reaches the
   cage as a `403` whose reason category is `asked-denied`, and that is the token
   [`sbx net logs`](observability) records for it: the same one stands for an explicit
   deny, an `ask_timeout` that ran out, and a park refused because the pending queue was
   full, since all three are the same answer to the caller.

4. **Optionally remember or persist the answer** (see below).

The tool sees the network appear (or a 403) the instant you answer.

---

## Watching live

To watch parked requests appear as an agent triggers them, without re-running
`sbx net pending`:

```bash
sbx net pending watch              # redraw every 2 seconds
sbx net pending watch -i 5         # every 5 seconds
sbx net pending watch -a claude    # one app's sessions
```

`watch` polls the same live control sockets and redraws the listing in place
(top-style, your scrollback is preserved), so a newly-parked request shows up on
the next refresh. Answer it from another shell with `sbx net pending allow|deny
<id>`; the watch picks up the change on the next tick. Ctrl-C quits. `watch` needs a
terminal, for a pipe or a script, use the one-shot listing with `--json`.

---

## Remembering vs persisting an answer

By default an answer decides just that one parked destination (and its identical
retries). Two flags make an answer stick further:

| Flag | Effect | Scope |
|---|---|---|
| *(none)* | decides this destination now | the parked request only |
| `--session` | also remembers the `host:port` for the **live session**, so it is not re-asked | until this session exits |
| `--save` | also **persists a rule** (an allow or deny) to config, so the host is pre-decided next launch | permanent |

```bash
sbx net pending allow 12345.7 --session          # don't ask again this session
sbx net pending allow 12345.7 --save             # write an allow rule (project config)
sbx net pending allow 12345.7 --save -g          # write it to the global config
sbx net pending deny  12345.7 --session          # remember as denied for the session
```

`--session` and `--save` combine. The unblock **sticks even if a save fails** (the
network decision is not held hostage to a config write). A `--save` to the project
config **re-trusts** it (a save must find the file absent or already trusted first);
the global config is trusted by location. A saved rule is scoped to a host; the id
addresses one live session's destination.

A saved rule goes through the same grammar as one you type at
[`sbx net allow`](rules): a destination no rule can be written for is refused, with
exit code 2 and nothing written, rather than saved as an entry the next launch would
drop. The request stays answered either way.

The persisted rules a session remembered from `--session` answers are visible with
[`sbx net rules --source session`](observability).

---

## Deciding a host *before* it parks (and outside `ask`)

`sbx net pending allow|deny <id> --session` reacts to a request that **already** parked.
To pre-decide a host you know is coming, without editing your config, load a rule into
the live session's overlay ahead of time:

```bash
sbx net allow api.example.com --session          # this project's live session(s)
sbx net allow api.example.com --session -a bot   # only app `bot`'s session(s)
sbx net deny  ads.example.com --session --all    # every reachable session, this run only
```

The proxy folds the overlay into its effective policy, so this works on **any** filtering
posture, not just `ask`. On an **allowlist** agent (the common case for a running
[`sbx app`](../cli/app)), `sbx net allow <host> --session` opens a host the allowlist
omits, and `sbx net deny <host> --session` cuts one it permits (deny wins), all without
relaunching. It writes no file and dies with the session. See
[`sbx net allow`/`deny`](../cli/net#sbx-net-allow-and-deny).

---

## Draining in bulk

`--all` answers every parked request at once instead of one id:

```bash
sbx net pending allow --all              # allow everything parked, every session
sbx net pending deny  --all              # deny everything parked
sbx net pending allow --all -a claude    # only one app's sessions
sbx net pending allow --all --session    # …and remember each for its session
```

`--all` is a **point-in-time** bulk answer: a request that parks *after* the drain
still waits. It reports per session, so a cross-agent grant is visible.

`--all` composes with `--save`, with a deliberate safety rule about scope:

- `--all --save` (default `--local`) drains only the **current project's** sessions
  and saves each host to the **project** config: never machine-wide, so one
  project's requests can never leak into another's config. A `--local` save
  pre-flights the trust gate before the (irreversible) drain.
- `--all --save --global` drains across sessions and saves to the global config.

---

## Tuning `ask` (table fields)

Both are inert outside `ask` mode:

```toml
[network]
mode         = "ask"
ask_timeout  = "90s"    # a parked request times out to a deny after this long
ask_notice   = false    # silence the inline stderr park alert
```

- **`ask_timeout`**, a duration (`"90s"`, `"5m"`, …) bounding how long a parked
  request waits before it times out to a **deny**. Absent means wait indefinitely
  until answered. Useful when an agent runs unattended and you do not want it wedged
  forever on an unanswered park.
- **`ask_notice`**, `true` by default. When a request parks, a notice is printed to
  the launch's stderr. Set `false` to silence that inline alert; the request still
  parks (answer it with `sbx net pending`): you have just chosen to watch via
  `sbx net pending watch` instead of inline notices.

Both are [trusted-only](modes#security-gated) and inherit across layers (a layer
that omits them leaves the inherited value unchanged).

---

## See also

- [Network modes](modes#ask): where `ask` sits among the five postures.
- [Rule grammar](rules): what `allow`/`deny` entries decide *before* a request
  reaches the park.
- [Egress observability](observability): `sbx net rules --source session` (the rules a
  session remembered), `sbx net logs` (watch every decision live).
- [`sbx net pending` CLI reference](../cli/net)
- [The trust gate](../concepts/trust): what `--save` re-trusts.
