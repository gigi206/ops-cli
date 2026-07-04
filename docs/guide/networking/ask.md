# Ask mode

`ask` is the **park-and-confirm** [egress posture](modes.md#ask). It is the
discovery mode: run an agent and decide, in real time from another terminal, what it
may reach — allowing or denying each new destination as it comes up, and optionally
remembering the answer.

```toml
[network]
mode  = "ask"
allow = ["api.anthropic.com"]    # never asked — always allowed
deny  = ["telemetry.example.com"] # never asked — always denied
# everything else parks until you answer
```

Under `ask`, a request whose destination matches an `allow` rule auto-passes and one
matching a `deny` rule auto-fails — exactly as under `deny`/`allow` mode. Any
**undecided** request (matching neither list, and not a
[built-in self-equip host](modes.md#the-built-in-self-equip-set)) **parks**: it
blocks inside the cage while it waits for your live decision.

---

## The workflow

1. **A request parks.** The in-cage tool's connection blocks. By default a stderr
   **park notice** is printed announcing the parked destination and its id (silence
   it with `ask_notice = false`).

2. **List what is parked** — from any other terminal:

   ```bash
   ops net pending
   ```

   This lists every request parked across every live `ask`-mode session, each with a
   `<pid>.<seq>` id (the PID is the one [`ops ls`](../housekeeping/sessions.md)
   shows). Identical retries of one URL collapse to a single `×N` line, so a tool
   that retries does not flood the list. Add `--json` for scripts, `-a <app>` to
   scope to one app's session(s).

3. **Answer it:**

   ```bash
   ops net pending allow 12345.7     # let this destination proceed
   ops net pending deny  12345.7     # refuse it (the cage gets a 403)
   ```

   The id addresses one live session's destination. Answering unblocks the parked
   request **and every identical retry of the same URL** at once.

4. **Optionally remember or persist the answer** (see below).

The tool sees the network appear (or a 403) the instant you answer.

---

## Watching live

To watch parked requests appear as an agent triggers them, without re-running
`ops net pending`:

```bash
ops net pending watch              # redraw every 2 seconds
ops net pending watch -i 5         # every 5 seconds
ops net pending watch -a claude    # one app's sessions
```

`watch` polls the same live control sockets and redraws the listing in place
(top-style — your scrollback is preserved), so a newly-parked request shows up on
the next refresh. Answer it from another shell with `ops net pending allow|deny
<id>`; the watch picks up the change on the next tick. Ctrl-C quits. `watch` needs a
terminal — for a pipe or a script, use the one-shot listing with `--json`.

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
ops net pending allow 12345.7 --session          # don't ask again this session
ops net pending allow 12345.7 --save             # write an allow rule (project config)
ops net pending allow 12345.7 --save -g          # write it to the global config
ops net pending deny  12345.7 --session          # remember as denied for the session
```

`--session` and `--save` combine. The unblock **sticks even if a save fails** (the
network decision is not held hostage to a config write). A `--save` to the project
config **re-trusts** it (a save must find the file absent or already trusted first);
the global config is trusted by location. A saved rule is scoped to a host; the id
addresses one live session's destination.

The persisted rules a session remembered from `--session` answers are visible with
[`ops net rules --source manual`](observability.md).

---

## Draining in bulk

`--all` answers every parked request at once instead of one id:

```bash
ops net pending allow --all              # allow everything parked, every session
ops net pending deny  --all              # deny everything parked
ops net pending allow --all -a claude    # only one app's sessions
ops net pending allow --all --session    # …and remember each for its session
```

`--all` is a **point-in-time** bulk answer: a request that parks *after* the drain
still waits. It reports per session, so a cross-agent grant is visible.

`--all` composes with `--save`, with a deliberate safety rule about scope:

- `--all --save` (default `--local`) drains only the **current project's** sessions
  and saves each host to the **project** config — never machine-wide, so one
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

- **`ask_timeout`** — a duration (`"90s"`, `"5m"`, …) bounding how long a parked
  request waits before it times out to a **deny**. Absent means wait indefinitely
  until answered. Useful when an agent runs unattended and you do not want it wedged
  forever on an unanswered park.
- **`ask_notice`** — `true` by default. When a request parks, a notice is printed to
  the launch's stderr. Set `false` to silence that inline alert; the request still
  parks (answer it with `ops net pending`) — you have just chosen to watch via
  `ops net pending watch` instead of inline notices.

Both are [trusted-only](modes.md#security-gated) and inherit across layers (a layer
that omits them leaves the inherited value unchanged).

---

## See also

- [Network modes](modes.md#ask) — where `ask` sits among the five postures.
- [Rule grammar](rules.md) — what `allow`/`deny` entries decide *before* a request
  reaches the park.
- [Observability](observability.md) — `ops net rules --source manual` (the rules a
  session remembered), `ops net logs` (watch every decision live).
- [`ops net pending` CLI reference](../cli/net.md)
- [The trust gate](../concepts/trust.md) — what `--save` re-trusts.
