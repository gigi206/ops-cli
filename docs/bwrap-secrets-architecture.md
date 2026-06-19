# ops secrets architecture (design)

> Status: **design draft**, captured from a long design discussion (2026-06-19).
> Informs the M6 network/secret work; the first brick (6.3a) is the foundation the
> rest extends. Read with [`bwrap-security-stack.md`](bwrap-security-stack.md) and
> [`bwrap-net-spike-findings.md`](bwrap-net-spike-findings.md). The competitor
> evidence behind it: a code-level read of Codex CLI, agent-vault (Infisical), nono,
> agent-sandbox, greywall, oauth2-proxy, Envoy, git-credential, aws-vault, and
> Anthropic's sandbox-runtime.

## 1. The invariant

> **ops never places a plaintext secret inside the cage.** The agent receives a
> *capability* (authenticate to an allowed host, sign a challenge, run a declared
> operation), never the secret's bytes.

This sits beside ops's other hard lines (capability-bearing userns → hard-fail, no
proot fallback; shared store immutable). It is what makes ops best-in-class on
confidentiality: the secret is absent *by construction*, not by a disableable
denylist (Codex) and not merely "present but deniable" (sandbox-runtime).

The distinction that carries everything:

- A **capability** is *scoped and ephemeral* — usable only while the cage runs, only
  toward hosts the egress allowlist permits.
- A **secret** is *permanent and portable* — exfiltrate it once, reuse it forever,
  anywhere.

Holding a capability ≠ holding the secret. ops blocks **extraction/portability**, not
**in-session use** (granting the use is the point). Therefore the irreducible lever is
**least privilege at the source**: a fine-scoped token, a read-only DB account — a
capability is only as dangerous as the secret's own permissions.

## 2. Two layers: resolver (source) × broker (sink)

A secret declaration composes two orthogonal, **host-side** halves:

- **Resolver (SOURCE)** — *where the value comes from*: `env`, `file`, **SOPS**,
  Vault, AWS Secrets Manager, 1Password, keyring… A host-side *fetch*. Mirrors nono's
  keystore-URI model (`env://`, `file://`, `op://`, `bw://`, `keyring://`).
- **Broker (SINK)** — *how the agent uses it without seeing it*: HTTP-header
  injection, ssh-agent, a protocol-aware DB proxy, mTLS client-cert.

Both run host-side and compose freely (any source × any broker). The resolver fetches
the plaintext into ops's host process; the broker consumes it host-side and exposes
only a capability to the cage; the plaintext is zeroized after use. **It never crosses
into the cage** — only ciphertext (if any) and capabilities ever do.

```
host side                                   │ cage (empty netns)
  resolver.fetch(ref)  ── plaintext ──▶ broker ── capability ──▶ agent's tool
   (sops -d, vault, …)   (in ops mem,      (header inject /        (curl, git, psql…)
                          zeroized)         ssh-agent / db proxy)
```

## 3. Plugin model

The secret-source space is open-ended, so **resolvers are pluggable**; the injectors
touch the security boundary, so **brokers stay first-party**.

| Layer | Pluggable? | Why |
|---|---|---|
| **Resolvers** (sops/vault/aws-sm/op/keyring…) | **plugins** | narrow, auditable contract: *host-side, return the plaintext for this reference* |
| **Brokers** (header-inject / ssh-agent / db-proxy / mtls) | **first-party** | they terminate TLS, inject into the wire, forward sockets — a bug is a boundary breach |

- **Plugins are typed** (`type = "resolver"` today; the type is an explicit,
  extensible discriminator so new plugin types can be added without breaking the
  registry — broker plugins, if ever, would be a separate heavily-gated type).
- A **default signed/curated ops store** ships built-in resolvers; **third-party
  stores are opt-in and an explicit trusted act** (the trust gate, like adding a nix
  substituter). Mirrors the embedded mise `nix:` plugin precedent (`build.rs`).
- A plugin runs **host-side, sandboxed, never in the cage**. A resolver plugin sees
  plaintext → it is in the TCB; the default store is signed, a third-party store is a
  risk the user accepts consciously. The resolver's *own* root credential (Vault
  token, age key, AWS creds) lives host-side, never in the cage.

## 4. The exposure tiers (a lattice)

Each secret declares its **maximum exposure tier**. The default and preferred path is
structural; everything below it is a conscious, labelled step down.

| Tier | Who controls the sink? | Guarantee | Headless? | Key residuals |
|---|---|---|---|---|
| **Broker** (HTTP-header / ssh-agent / DB-proxy / mTLS) | **ops** (the protocol binds the secret to its destination) | **structural** — agent never touches plaintext | yes | a *reflecting/cooperating allowed upstream* (irreducible) |
| **Template** (MCP) — `op.run("db-query", {sql})` | **ops** (fixed command), agent supplies **bounded data params** | structural, per-template vetted | yes | a too-general template; an escape hatch in the templated tool |
| **Command-MCP** — free command + `$SECRET` substitution, command allow/deny regex + TOFU approval | **agent** (chooses the program) | **procedural**, egress-bounded | only once trained | the *sudoers problem* (allowed binaries have exec escapes); exfil to an allowed writable host; trained "always-allow" re-opens headless auto-run |
| **Exposed** — arbitrary agent code holding the plaintext (e.g. a python script that spawns sub-commands) | **agent** (full interpreter) | none beyond the network boundary | n/a | only the egress allowlist + empty netns contain it |

The line through the table: **safe ⟺ ops controls the program/sink that touches the
plaintext; unsafe ⟺ the agent does.** "Who calls `exec()`" is irrelevant — a broker
that execs the *agent's* command still hands the agent the secret (the confused-deputy
/ SQL-injection logic). The command-regex and output-masking and volatile-FS are
*backstops*, never the boundary — masking is defeated by any encoding (the SOPS
research: none of 9 tools scrub responses; even pipelock's 6-pass normalization scans
only requests).

### 4.1 The method ladder — reach for the highest rung the protocol allows

There is no single "best" mechanism; there is a hierarchy, and the right choice is the
highest rung a given protocol/operation supports:

1. **Transparent broker / protocol proxy** *(best)* — the secret stays host-side, it is
   **command-agnostic** (any tool works unchanged), leak-safe, and needs **no agent
   cooperation**. First-party for HTTP/SSH/DB/mTLS, and extensible to new protocols via
   vetted **broker-plugins** wherever the protocol has a definable auth point (an HTTP
   header, the ssh-agent socket, a DB auth packet, a TLS client cert). This — not MCP —
   is the right way to widen coverage beyond HTTP/SSH.
2. **MCP, declared operation** — its killer property is that the operation **runs
   host-side** and only a *structured result* returns, so the secret **never enters the
   cage** (stronger than rungs 3–4). It is the agent-native, deliberate interface — so
   do **not** reinvent a bespoke socket/CLI RPC for it. This is the best **fallback**
   for an enumerable operation with **no proxyable handshake**, not the top of the
   ladder.
3. **command-MCP** (free command + allowlist + approval) — procedural, egress-bounded.
4. **Exposed** (arbitrary agent code) — only the network boundary contains it.

For the *free-command / arbitrary-code* cases (rungs 3–4) the **transport is moot**:
MCP, a CLI shim, or a socket are equivalent because the secret enters agent-controlled
code — what contains it is §5's fencing (egress mandatory + opt-in + per-secret
exposability), never the transport.

## 5. Escape-hatch rules (the lower two tiers)

Beyond HTTP/SSH, ops cannot transparently proxy everything, so the lower tiers are what
make ops **general** rather than "works only for brokered protocols". They are offered,
but fenced:

1. **Off by default** — the structural broker tier is the default; the command/exec
   tiers are an explicit opt-in **plugin** (the `sudo` / `--privileged` /
   `nix sandbox = false` pattern), documented with the risk incurred.
2. **Trusted-only to enable** — an untrusted project can never flip it; the network
   posture / cage-opening is never settable by an untrusted project.
3. **Egress allowlist MANDATORY** for any exposed/command tier — refuse to combine an
   exposed secret with `network = shared` (secret in agent code + open internet =
   instant exfil). For the exposed tier the command-allowlist is useless (the
   interpreter bypasses it), so **the egress allowlist + empty netns are the only net**
   — keep it mandatory and tight.
4. **Per-secret exposability flag** — a `broker-only` secret (e.g. a production DB
   password) is never usable by the command/exec tiers, even with the plugin enabled.
   The crown jewels stay structural; only a low-value token is exposable to the
   python tier.
5. **Loud runtime warning** — a launch that exposes a secret to agent-controlled code
   says so plainly ("secret X is exposed to agent code; only the egress allowlist
   contains it").

## 6. Schema sketch

A single typed `[[secret]]` table; transport (what can connect where) stays in
`[network]`, orthogonal and composable.

```toml
# broker tier — structural, secret never in the cage
[[secret]]
from   = "sops://secrets.enc.yaml#github.token"   # resolver (SOURCE)
kind   = "http-header"                             # broker (SINK), first-party
to     = "api.github.com/repos/*"                  # concrete host + optional path, via allowlist::Rule
header = "Authorization"
type   = "bearer"                                  # bearer | basic | raw

# ssh — key brokered by ssh-agent, transport via the tunnel lane
[[secret]]
kind = "ssh-agent"
to   = "git.example.com:22"

# transport (orthogonal to the secret)
[network]
mode   = "allowlist"
allow  = ["api.github.com/repos/*"]   # MITM-filtered lane (host+path+regex, content-aware)
tunnel = ["git.example.com:22"]       # blind TCP/SOCKS lane (host:port only), opt-in
```

`to` is classified with `allowlist::classify` and restricted to **concrete-host kinds**
(`Ip`/`Host`/`Url` host+path, exact or `/*`); `*.domain` and `re:` are rejected for an
injection target. Host-scoped by default, path on opt-in (git-credential's
`useHttpPath=false` model). One canonicalizer/matcher across allow / deny / inject.

### 6.1 6.3a schema locks (from the architecture review)

- **`http-header` injection requires `[network] mode = "allowlist"`.** Injection happens
  *inside the MITM proxy*, which only exists under the allowlist posture (`egress::start`
  is gated on `NetworkPolicy::Allowlist`). A `http-header` secret under `shared`/`none`/no
  network table must **warn loudly or fail-closed at config/launch — never a silent
  no-op** (the agent would otherwise send an unauthenticated request and not know why).
  Likewise, a `to` host absent from the `allow` list is denied *before* injection, so
  `ops config` surfaces it as a warning (a forgotten `allow` entry is not a silent "why
  is my auth missing").
- **Table name:** ship the kind-tagged **`[[secret]]`** (forward-compatible across all
  brokers), consciously chosen over the earlier `[[network.inject]]` working name — not
  drifted into.
- **`type = bearer | basic | raw` plus an optional `prefix`.** `bearer` =
  `Authorization: Bearer <secret>`; `basic` base64s a `user:pass`; `raw` = `<header>:
  <secret>` (no prefix). An optional `prefix` makes non-Bearer schemes expressible
  (`raw` + `prefix = "token "` → `Authorization: token <tok>`); `bearer` is just sugar
  for `raw` + `prefix = "Bearer "`.
- **Basic input format:** `from_env`/`from_file` holds the `user:pass` pair; ops
  base64-encodes it (the agent never pre-encodes).
- **`from_file`:** an absolute host path, read **host-side** at launch; it is **never
  bound into the cage** (only the resolved value reaches the broker, host-side).

## 7. Worked example — a SOPS token for an HTTPS API

1. **Declare** (trusted project): the `[[secret]]` above.
2. **Launch (host-side, before the cage):** ops calls the SOPS resolver plugin
   (host-side subprocess) → it uses the host-side age/KMS key to decrypt
   `secrets.enc.yaml` and returns `github.token`'s plaintext over a pipe. ops
   configures the MITM proxy: "for `api.github.com`, set `Authorization: Bearer
   <token>`". The token is in ops's host process — not the cage env, not a cage file.
3. **Agent runs:** `curl https://api.github.com/user` (no token anywhere) → in-cage
   socat → host MITM proxy → injects the header → forwards → relays the 200. The agent
   never saw the token; the `secrets.enc.yaml` it can read is useless ciphertext (no
   key in the cage).
4. **Teardown:** ops zeroizes the plaintext; proxy, CA, and socket are torn down.

The "consumption" is the HTTPS call the agent makes anyway; ops brokers it on the wire.
No MCP, no agent cooperation. MCP is only for the lower tiers (operations ops cannot
transparently proxy).

## 8. Honest residuals

- **Reflecting/cooperating allowed upstream** (all tiers): "the agent never sees the
  secret" over-claims if the injection-target host reflects request headers or the
  agent can write the secret into an allowed multi-tenant host (a gist, a paste). The
  real guarantee is "the agent cannot exfiltrate the secret to an *arbitrary* host"
  (concrete-host scope + empty netns + tight egress), not "can never observe it".
- **Command-regex is the sudoers problem** — most "normal" binaries are interpreters or
  have exec escapes (`git -c …`, `tar --to-command`, `find -exec`, `awk`, …), so the
  egress allowlist, not the command list, is the load-bearing barrier for that tier.
- **Capability is fully usable in-session** — scope the secret tightly at the source.

## 9. Positioning

The *primitives* are all standard (command allowlists ≈ sudoers; TOFU approval ≈ Claude
Code/Cursor; egress allowlist ≈ dev-container firewall / nono / greywall; broker-side
injection ≈ Codex / agent-vault). ops's lead is the **integration**: per-secret broker +
typed resolver plugins + a path/URL/regex MITM egress allowlist + a tier lattice under a
single "no plaintext in the cage" invariant. Claim the integration, not a magic
primitive.

## 10. Roadmap

Secret/broker bricks (each shipped + tested + advisor-reviewed + validated):

1. **6.3a** — `kind = "http-header"`, built-in `from_env` / `from_file` resolvers, the
   `[[secret]]` shape + the security deltas (strip-and-replace the header
   case-insensitively over all spellings; scope host+path via `allowlist::Rule`; match
   the verified CONNECT host + the same canonical `Request` the verdict used;
   fail-closed on a missing/empty source; per-request re-match; secret hygiene —
   never logged, redacted in `Debug`). **The foundation; proves the wire-injection
   consumption model end-to-end.**
2. **6.3b** — outbound secret redaction (block/refuse, a backstop).
3. **+** — a `sops://` resolver (proves the SOURCE layer is distinct from the BROKER,
   on the already-solid http-header broker).
4. **+** — one engine resolver (Vault or 1Password) → proves the generic resolver
   contract.
5. **+** — generalise into the **plugin store** once the resolver contract is
   battle-tested (default signed store + opt-in third-party).

Transport / broker bricks, in parallel:

6. **tunnel lane** (blind TCP / SOCKS, `host:port`, trusted-only) — the transport for
   SSH/DB/anything.
7. **ssh-agent forward** (sign-oracle, key never in the cage).
8. **DB protocol-aware proxy**, **mTLS client-cert injection**, **cloud signing
   proxy** — as needs arise.
9. **command-MCP / exec tier** — the opt-in, off-by-default, risk-documented escape
   hatch under §5's rules.
```
