# `github-copilot` — GitHub Copilot (individual API)

GitHub's OpenAI-compatible Copilot surface — **individual** subscriptions
(`api.individual.githubcopilot.com`). The mechanics, posture, and scoping are
in [the shared page](../README.md); this page only adds what is specific to
GitHub Copilot.

```toml
[secret."api.individual.githubcopilot.com/*"]
from   = "env://GITHUB_COPILOT_API_TOKEN"
header = "Authorization"
type   = "bearer"
```

Set the token in your shell, exactly as the `from` names it:

```sh
export GITHUB_COPILOT_API_TOKEN=…
```

## Specifics

- **Host:** `api.individual.githubcopilot.com` — the OpenAI-compatible layer
  for personal Copilot accounts (`/models`, `/chat/completions`, …).
  Enterprise tenants are `api.{tenant}.githubcopilot.com` — a dynamic host,
  **not** coverable by a `[secret]` block (same rule as Azure).
- **Variable:** `GITHUB_COPILOT_API_TOKEN` — the **Copilot session token**
  (`tid=…;exp=…;proxy-ep=…`), *not* a bare GitHub PAT. The token is minted by
  exchanging a GitHub token (PAT with `copilot` scope, or `ghu_…`) against
  `GET api.github.com/copilot_internal/v2/token`, host-side. It expires in
  **~30 minutes**, so this example is only livable behind a refresher (or a
  resolver plugin that re-mints it on each resolution — the exchange is
  invisible to the cage, an ideal `oc-oauth`-style target). A plain
  long-lived PAT in this slot gets `401`/`403` — the API does not accept it.
- **Mandatory companion headers:** the API refuses valid sessions without
  `Copilot-Integration-Id` (plus `User-Agent`, `Editor-…` version headers, and
  `Accept: text/event-stream` on streaming) — *403 « token not authorized*» .
  `[secret]` sets only `Authorization`; have the **client** send those (any
  OpenAI-compatible client with extra-headers support).
- **Trailing `/*` is load-bearing** (same rule as the opencode page): without
  it the block never matches beneath the base path.
- **Reference:** <https://docs.github.com/en/copilot/how-tos/copilot-sdk/auth/authenticate> ·
  <https://api.individual.githubcopilot.com/models>

## Verifying

```sh
sbx run -- curl -sS https://api.individual.githubcopilot.com/models
```

A `200` with the model listing means the session header arrived; a `401`/`403`
means the token in the slot is stale or has no session — re-mint it (or let the
plugin do it) and check the posture/allowlist (see the shared page).