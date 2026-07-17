# Inbound loopback forwarding — `forward`

A cage runs in an **empty network namespace** (Model B): its `127.0.0.1` is *its own*
loopback, not the host's. That is the security boundary — nothing the agent starts inside
the cage is reachable from the host by default, and that is the point. But two real cases
need the reverse:

- **An OAuth loopback callback.** A CLI (codex, others) authenticates by opening an
  `http://localhost:<port>/auth/callback?code=…` URL in your host browser. The provider
  redirects there, the CLI — listening on its own loopback — receives the code. Under the
  empty netns the host browser's `localhost:<port>` is the *host's* loopback, where nothing
  listens; the CLI is on the *cage's* loopback, unreachable.
- **A dev server started in the cage.** You run a tool that serves on `127.0.0.1:<port>`
  inside the cage and want to open it in your host browser.

`forward` declares a host loopback TCP port sbx forwards *into* the cage, so a host process
can reach a service the agent started there. It is the symmetrical reverse of the egress
forwarder — same `socat`-over-a-bound-socket plumbing, opposite direction.

## Declare it

```toml
[network]
mode = "deny"
allow = ["chatgpt.com"]

# Forward the host's localhost:1455 into the cage at the same port.
forward = [1455]
```

- **`forward = [port, …]`** — a list of TCP port numbers. Each is bound on the host's
  `127.0.0.1` — and, best-effort, on `[::1]` so a `localhost` callback the browser sends over
  IPv6 is caught too — loopback only, never an external interface, and bridged to the cage's own
  loopback at the *same* port. The host port equals the cage port — the OAuth redirect URL is
  baked into the tool, so the two must match. The in-cage bridge connects the service on
  `127.0.0.1:<port>`, so a cage service that binds only IPv6 loopback (`::1`) is not reached —
  bind `127.0.0.1` or all interfaces inside the cage.
- **Loopback only.** sbx never binds an external interface; the port is reachable only from
  the host itself. (Exposing it to the LAN/internet is a deliberately separate, unbuilt
  option.)
- **Trusted-only.** `forward` is a security field, gated exactly like `network`/`gui`:
  honored from the global `sbx.toml` (trusted by location), a trusted project, or a named
  app profile; dropped with a warning from an untrusted project. An untrusted project may
  not open a host port.
- **Per-app overlay unions.** A profile (or a global app) declaring `forward = [1455]` keeps
  those ports even under an untrusted project — the untrusted project can only *add* its own
  ports, never remove or override the trusted set.

## Behaviour

- **Under `network = "none"` or `"deny"`/`"allow"`/`"ask"`** (empty netns) the forwarder
  wires: sbx binds the host port, a per-launch dir is bound into the cage, and an in-cage
  `socat` bridges the Unix socket to the cage loopback. The browser connects to the host
  port; sbx pumps each connection through the socket into the cage.
- **Under `network = "shared"`** the cage shares the host netns, so a cage service on
  `127.0.0.1:<port>` is already on host loopback — the forwarder is a redundant no-op and
  sbx skips it with a note.
- **Collision = fail-closed.** A port already in use on the host (another login, a host
  service) aborts the launch with a clear message. sbx does not pick an ephemeral substitute
  — the tool's redirect URL is fixed, so a different port would silently break the callback.
  Two simultaneous `sbx app run codex` logins collide on 1455; the second fails (login is a
  one-shot, acceptable).
- **Orthogonal to egress.** Inbound is a new, declared *inbound* hole; the empty netns and the
  egress allowlist are unchanged. An OAuth flow needs **both**: `forward` for the callback,
  and the provider's host in `[network].allow` so the CLI can reach the authorize endpoint
  and exchange the code.

## One-shot override

`--forward <port[,port…]>` (repeatable) and `SBX_FORWARD` (a comma-list) add ports for one
launch, beating a trusted project config and an app's posture (an override is trusted by
invocation). It is a collection — it **unions** onto the config-declared ports, never
replaces them.

```
sbx app run codex --forward 1455
SBX_FORWARD=1455,8080 sbx run -- ./dev-server
```

## The first consumer: codex's ChatGPT login

`profiles/codex.toml` declares `forward = [1455]` and opens the OAuth runtime hosts in its
allowlist, so `sbx app run codex` → `codex login` completes end-to-end: codex opens the auth URL
in your browser, you authenticate, the provider redirects to `localhost:1455`, the forwarder
bridges it into the cage, codex receives the code, exchanges it (egress, allowlisted), and the
token persists in the app's isolated `$HOME`. Login is a one-time step; later launches reuse
the stored token under the same allowlist.

## See also

- [Egress rules](rules.md) and [modes](modes.md) — the outbound side `forward` is orthogonal to.
- [`sbx help run`](../cli/run.md) — the one-shot override flags.
- [Apps and profiles](../apps/profiles.md) — per-app `forward` overlay.