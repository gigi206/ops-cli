# OAuth sessions: taking the token out of the cage

An agent that signs in for itself ends up holding an OAuth token in its
[isolated home](../apps/home), and that token is worth far more than one request:
a refresh token buys new access tokens for as long as the session lives. Nothing
declared it, so it is the application's, not `sbx`'s.

This page is about moving it out. The application keeps a **placeholder**, the
real token lives host-side in a resolver plugin's private state, and `sbx`
substitutes it on the wire. What an attacker finds inside the cage is a string
worth nothing.

:::note

This is opt-in and per application. Without it, an acquired token stays in the
cage, watched by the [tripwires](redaction#credentials-the-cage-obtained-for-itself)
but present. See [what the invariant covers](./#what-the-invariant-covers-and-what-it-does-not).

:::

## The one rule

**Exactly one thing may refresh a given account.**

Providers issue single-use refresh tokens and detect replay. If the application
still holds a working refresh token, it and the plugin will both eventually
exchange, the provider will see a token used twice, and it will **revoke the
whole session**. Recovery is an interactive re-login.

So the application must be dispossessed *before* its first run under the plugin,
not after.

## Setting it up

The example uses `codex` and the `openai://` plugin; the shape is the same for any
provider with a plugin.

### 1. Install the plugin

```sh
sbx plugins store update sbx-plugins
sbx plugins store install sbx-plugins openai-oauth
sbx plugins info openai        # the scheme, the grant, and where its state lives
```

A plugin that refreshes declares `state = true`, which is the only writable path
in its sandbox — it has to keep the rotated token. `sbx plugins info` names the
directory, so you can see exactly what a third-party plugin may keep.

### 2. Seed the session, once

The plugin cannot sign you in: a first login is an interactive browser or
device-code flow, and a resolver runs with no stdin and no terminal. Sign in with
the application as usual, then move its refresh token across.

```sh
AUTH=$(sbx app show codex | sed -n 's/^  home: *//p')/.codex/auth.json
STATE=<the directory `sbx plugins info openai` printed>

mkdir -p "$STATE" && chmod 700 "$STATE"
jq '{refresh_token: .tokens.refresh_token}' "$AUTH" > "$STATE/default.json"
chmod 600 "$STATE/default.json"
```

### 3. Dispossess the application

```sh
jq '.tokens.access_token  = "sbx-placeholder-not-a-real-credential"
  | .tokens.refresh_token = "sbx-placeholder-not-a-real-credential"' "$AUTH" > "$AUTH.new"
mv "$AUTH.new" "$AUTH"
```

What to replace, and what to leave alone, is per application — see
[the application's own habits](#the-applications-own-habits) below.

### 4. Declare the injection

In the app's profile:

```toml
[secret."chatgpt.com"]
header = "Authorization"
type   = "bearer"
from   = ["openai://default"]
```

### 5. Run it normally

```sh
sbx app run codex -- exec "…"
```

## What happens from then on

At each launch `sbx` invokes the plugin. An access token still inside its lifetime
is served from state, spending nothing. An expired one is exchanged, and whatever
comes back is **written before the value is handed over** — the token that bought
it is already spent, so losing the new one would cost a re-login.

If the API answers `401` mid-session, the proxy
[re-invokes the resolver](injection#when-the-upstream-refuses-the-credential) and
the next request carries a fresh token. The refused request itself is lost, so the
first call after a token goes stale does fail; every agent CLI observed here
retries and continues.

## The application's own habits

No two behave alike, and each difference decides what a placeholder may replace.
What has been observed:

| Application | What it does | What that means |
|---|---|---|
| `codex` | parses its `id_token` as a JWT at startup | leave `id_token` alone; it is an identity assertion, not an API credential |
| `claude-code` | checks the recorded expiry before sending, and **erases its auth state** when a refresh fails | leave `expiresAt` in the future, so it uses the token it has instead of trying to refresh it |
| `hermes` | keeps a second copy in a credential pool beside the active provider | replace both, or it restores itself from the copy |

The general lesson: replace **every** copy the application keeps, leave any field
it *parses* structurally valid, and leave any expiry in the future.

## Limits worth knowing before you start

**The application must be able to do without its refresh token.** Some obtain a
new one by a route of their own; `hermes` does, by a path this project has not
identified. For those, the setup does not hold.

**A WebSocket on the injected host is refused.** `sbx` will not inject into a host
that also carries a WebSocket, because a frame cannot be redacted — the handshake
gets a `403`. `codex` falls back to HTTPS on its own and keeps working; a feature
with no fallback, like voice dictation over `api.anthropic.com`, would be lost.

**Some applications keep their client secret to themselves.** A plugin can only
refresh if the credentials for the exchange are obtainable. Where an application
embeds them in its binary, no plugin can be written for it without reverse
engineering that breaks at the next release.

## Where each thing lives

| | Location |
|---|---|
| Refresh token | the plugin's state, host-side, owner-only, outside every sandbox |
| Access token | `sbx`'s memory and the plugin's state |
| Inside the cage | a placeholder, worth nothing to anyone |

## See also

- [Resolver plugins](plugins) — the manifest, the grant, and `state = true`
- [Injection](injection) — strip-and-replace, and the `401` re-resolution
- [Redaction](redaction) — what happens to a credential the cage obtained anyway
