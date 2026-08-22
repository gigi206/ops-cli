---
sidebar_label: "Inbound forwarding"
description: "Reaching a port inside the cage from the host, under an empty network namespace."
---

# Inbound loopback forwarding: `forward`

A cage runs in an **empty network namespace** (Model B): its `127.0.0.1` is *its own*
loopback, not the host's. That is the security boundary: nothing the agent starts inside
the cage is reachable from the host by default, and that is the point. But two real cases
need the reverse:

- **An OAuth loopback callback.** A CLI (codex, others) authenticates by opening an
  `http://localhost:<port>/auth/callback?code=…` URL in your host browser. The provider
  redirects there, the CLI, listening on its own loopback, receives the code. Under the
  empty netns the host browser's `localhost:<port>` is the *host's* loopback, where nothing
  listens; the CLI is on the *cage's* loopback, unreachable.
- **A dev server started in the cage.** You run a tool that serves on `127.0.0.1:<port>`
  inside the cage and want to open it in your host browser.

`forward` declares a host loopback TCP port sbx forwards *into* the cage, so a host process
can reach a service the agent started there. It is the symmetrical reverse of the egress
forwarder, same `socat`-over-a-bound-socket plumbing, opposite direction.

## Declare it

```toml
# `forward` is a top-level key, declared before any table header. Written under
# `[network]` it is an unknown key and silently ignored.
forward = [1455]

[network]
mode = "deny"
allow = ["chatgpt.com"]
```

- **`forward = [port, …]`**: a list of entries, each a TCP port number. Each is bound on the
  host's `127.0.0.1`, and, best-effort, on `[::1]` so a `localhost` callback the browser sends
  over IPv6 is caught too, loopback only, never an external interface, and bridged to the cage's
  own loopback at the *same* port. The in-cage bridge connects the service on
  `127.0.0.1:<port>`, so a cage service that binds only IPv6 loopback (`::1`) is not reached: bind `127.0.0.1` or all interfaces inside the cage.
- **Loopback only.** sbx never binds an external interface; the port is reachable only from
  the host itself. (Exposing it to the LAN/internet is a deliberately separate, unbuilt
  option.)
- **Trusted-only.** `forward` is a security field, gated exactly like `network`/`gui`:
  honored from the global `sbx.toml` (trusted by location), a trusted project, or a named
  app profile; dropped with a warning from an untrusted project. An untrusted project may
  not open a host port.
- **Per-app overlay folds in by cage port.** A profile (or a global app) declaring
  `forward = [1455]` keeps that forward even under an untrusted project: the untrusted project
  can only *add* its own, never close one the trusted set opened. A layer that names a cage port
  already forwarded moves its host port rather than opening a second hole (see
  [Moving the host port](#moving-the-host-port)).

## Moving the host port

A forward has **two** ports: the one bound on your host, and the one the caged service listens
on. `forward = [9119]` makes them equal. They stop being equal the moment 9119 is taken on your
machine, and that is what the remap form is for:

```toml
# Reach the cage's :9119 from a free host port. The caged service is untouched, it still
# listens on 9119 inside the cage.
forward = ["9200:9119"]
```

- The form is `"<host>:<cage>"`, the same order as `docker -p`, written as a string. A bare
  integer stays the same-port form, and the two mix in one list: `forward = [1455, "9200:9119"]`.
- **The cage port identifies the forward.** It is what a layer is actually naming: *this service
  inside the cage should be reachable*. So a higher layer restating a cage port moves its host
  port instead of opening a second hole, which is what makes a remap resolve a collision rather
  than add to it. Nothing else changes: every cage port a lower layer published is still
  published, because a layer moves a forward and never closes one.
- **Do not remap an OAuth callback.** A tool that authenticates through a loopback redirect gets
  its URL from its provider, and the provider will still send your browser to the original port.
  Remapping such a forward breaks the login, silently. sbx cannot tell that port from a dev
  server's, so this one is yours to get right: `codex`'s `forward = [1455]` must stay 1455. The
  remap form is for the other case, a dev server or dashboard whose address only you decide.
- **One host port, one cage port.** Two forwards claiming the same host port fail the launch
  closed before anything is bound, naming both cage ports. Two entries naming the same *cage*
  port cannot both apply, so the last one wins, with a warning naming the host port it dropped.

## Behaviour

- **Under `network = "none"` or `"deny"`/`"allow"`/`"ask"`** (empty netns) the forwarder
  wires: sbx binds the host port, a per-launch dir is bound into the cage, and an in-cage
  `socat` bridges the Unix socket to the cage loopback. The browser connects to the host
  port; sbx pumps each connection through the socket into the cage.
- **Under `network = "shared"`** the cage shares the host netns, so a cage service on
  `127.0.0.1:<port>` is already on host loopback: the forwarder is a redundant no-op and
  sbx skips it with a note.
- **Collision = fail-closed.** A host port already in use (another login, a host service)
  aborts the launch with a message naming the port and the remap that would move it. sbx does
  not pick an ephemeral substitute: it cannot know what you published, and for an OAuth callback
  a different port would silently break the redirect. Moving off a taken host port is a thing to
  say, not to guess, which is what `"<host>:<cage>"` is for. Two simultaneous
  `sbx app run codex` logins collide on 1455; the second fails (login is a one-shot,
  acceptable, and remapping it is not the fix, since the redirect is fixed at 1455).
- **Orthogonal to egress.** Inbound is a new, declared *inbound* hole; the empty netns and the
  egress allowlist are unchanged. An OAuth flow needs **both**: `forward` for the callback,
  and the provider's host in `[network].allow` so the CLI can reach the authorize endpoint
  and exchange the code.

## One-shot override

`--forward <port|host:cage[,…]>` (repeatable) and `SBX_FORWARD` (a comma-list) set forwards for
one launch, beating a trusted project config and an app's posture (an override is trusted by
invocation). It folds onto the config-declared set **by cage port**: a cage port the config does
not forward is added, and one it does is *moved* to your host port.

That is the everyday use, and it needs no edit to the profile:

```
# The profile forwards 9119; 9119 is taken on this machine. Publish the same caged
# dashboard on 9200 instead, for this launch only.
sbx app run hermes-web --forward 9200:9119

sbx app run codex --forward 1455
SBX_FORWARD=1455,8080 sbx run -- ./dev-server
```

Unlike a config file, where a malformed entry warns and is skipped so one typo cannot void a
whole layer, a malformed flag value (`9200:nope`, `9200:9119:8787`) is a **hard error**: there
is nothing else in the flag to save, and a silently-dropped forward would leave the launch up
with the port you meant to publish answering nothing.

## The first consumer: codex's ChatGPT login

`examples/app/codex.toml` declares `forward = [1455]` and opens the OAuth runtime hosts in its
allowlist, so `sbx app run codex` → `codex login` completes end-to-end: codex opens the auth URL
in your browser, you authenticate, the provider redirects to `localhost:1455`, the forwarder
bridges it into the cage, codex receives the code, exchanges it (egress, allowlisted), and the
token persists in the app's isolated `$HOME`. Login is a one-time step; later launches reuse
the stored token under the same allowlist.

## See also

- [Egress rules](rules) and [modes](modes): the outbound side `forward` is orthogonal to.
- [`sbx help run`](../cli/run): the one-shot override flags.
- [Apps and profiles](../apps/profiles): per-app `forward` overlay.