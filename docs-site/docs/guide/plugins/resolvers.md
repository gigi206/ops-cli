---
description: "A new `scheme://` a secret's `from` routes to: the execution contract, and the resolvers published in the store."
---

# The resolver type

A **resolver** adds a `scheme://` that a secret's [`from`](../configuration/secret) can
route to. It is the first of the three plugin types and the one the rest of this section
is written about unless it says otherwise.

A plugin is a directory containing a `plugin.toml` manifest and an executable.
Run with a `scheme://locator` reference as its single argument, the executable
prints the secret's plaintext to stdout. `sbx` discovers installed plugins under
its owner-only data directory (`<data>/plugins/<name>/`) and builds a
`scheme → plugin` map the secret validator consults.

## The execution contract

The runner passes the **full reference** as the executable's single argument
(`argv[1]`, e.g. `vault://secret/data/ci#token`) and reads the outcome from the
exit status and the output streams:

| Outcome | Exit | stdout | Effect |
| --- | --- | --- | --- |
| resolved | `0` | the plaintext | the secret is used (one trailing line ending is stripped) |
| absent | `0` | empty | a clean fall-through to the next source in the `from` chain |
| failed | non-zero | ignored | a hard, fail-closed error: the launch aborts, and the next source is **not** tried |

`stdin` is closed, so a resolver can never prompt for anything: everything it
needs must come from its `[sandbox]` grant.

**A resolution is bounded.** A resolver runs on the launch's critical path, and again on
the refresh thread once the session is up, so a plugin that never answers would hold the
launch open for good. `sbx` gives it **ten minutes**, then kills it (the cage with it) and
fails the launch with an error naming the plugin. Ten minutes is the same line a broker
manifest may not cross with its own `host_deadline`: past it, whatever is on the other
side is wedged rather than thinking. A plugin that reaches a **broker** is given that
broker's own wait on top, because a gpg-agent stopping at a pinentry answers when you do,
and a bound tighter than the wait it is allowed to contain would kill a plugin doing
exactly what the manifests permit. A `sops` source is bounded the same way, by the same
clock.

**And an answer is bounded in size, not only in time**, because a plugin answering fast is
not slowed by a clock. `sbx` reads at most **256 KiB** from each stream, the same ceiling a
broker frame meets, and an answer over it is a hard error rather than a truncation: half a
secret is not a smaller secret. A plugin that floods **stderr** is not failed for it (that
stream is a diagnostic, and is cut to a single bounded line before anything reads it); its
flood simply stops at the ceiling.

A plugin runs in its own cage, built the same way an agent's is: its own user,
pid, ipc, uts and cgroup namespaces, every capability dropped, a cleared
environment, and no network unless the manifest asks for one. It carries the
same mandatory **syscall denylist** too, and for the same reason it exists at
all: this is the process running code you did not write, and it is also the
process a signer's credential is handed to. Nothing relaxes that denylist for a
plugin, since a plugin brings no config of its own.

The same reasoning puts it inside a **cgroup v2 scope** of its own, so a plugin that forks or
allocates without end is bounded exactly as a runaway in the sandbox would be. The ceilings are the
ones the **global** [`[limits]`](../configuration/limits) declares, not a project's: a plugin is
sbx's machinery rather than the project's, and it is started before a launch exists and outlives
each request inside one. Like everywhere else, the scope is best-effort and never the boundary. See
[the enforcement stack](../concepts/enforcement#which-cages-run-inside-a-scope).

**stderr is the diagnostic channel, and must never carry the value.** It is
folded into the error of a failed run, and relayed as an `sbx: warning:` line
when a run resolves *nothing*: so a plugin can explain a misspelled locator or
an empty field without turning a fall-through into a hard failure. A run that
returns a value stays silent, so a plugin that logs to stderr cannot echo a
plaintext back at you. What is relayed is first reduced to a single bounded line
with control characters removed, since a plugin's own text must not be able to
drive your terminal.

## The reference plugins

Ready-made resolvers are published in the signed
[sbx-plugins](https://github.com/sbx-labs/sbx-plugins) store, not carried in this
repository. A plugin is trusted by *location*, so none is installed by default:
it only counts once it sits in `<data>/plugins/<name>/`.

```sh
sbx plugins store install sbx-plugins pass    # then: from = "pass://github/token"
sbx plugins store install sbx-plugins vault   # then: from = "vault://secret/myapp#password"
```

| Plugin | Reference form | Resolves to | Sandbox grant |
|---|---|---|---|
| `pass` | `pass://<path>[#<field>]` | the **first line** of `~/.password-store/<path>.gpg` (the password by convention), or a named `key: value` field below it | `programs = ["pass"]`; `allow_paths` on the store and `~/.gnupg`; `brokers = ["gpg-agent"]` for the agent; **no network** |
| `vault` | `vault://<mount>/<path>[?version=<n>]#<field>` | one field of a HashiCorp Vault KV secret, optionally at a past version | `programs = ["vault"]`; `allow_env` for `VAULT_ADDR`/`VAULT_TOKEN`/`VAULT_NAMESPACE`; `allow_paths` on `~/.vault-token`; `network = true` |
| `openbao` | `openbao://<mount>/<path>[?version=<n>]#<field>` | the same, against an OpenBao server (`bao`) | `programs = ["bao"]`; the `BAO_*` equivalents; `network = true` |
| `infisical` | `infisical://<project>/<env>[/<folder>][?<opts>]#<secret>` | one secret of an Infisical project | `programs = ["infisical"]`; `allow_env` for the `INFISICAL_*` credentials; `network = true` |
| `bitwarden` | `bitwarden://<item>[#<field>]` | one field of an item in the Bitwarden vault the `bw` CLI keeps on disk: `password` by default, or `username`, `uri`, `totp`, `notes`, `field:<name>` | `programs = ["bw", "jq"]`; `allow_env` for `BW_SESSION`/`BW_PASSWORD`; `allow_paths` on the CLI's application directory; **no network** |
| `keepassxc` | `keepassxc://<database>/<entry>[#<attribute>]` | one attribute of an entry in a `.kdbx` on disk, unlocked by a key file or password file beside it | `programs = ["keepassxc-cli"]`; `allow_paths` on the vault directories; **no network** |
| `keepassxc-browser` | `keepassxc-browser://<url>[#<login>]` | a credential out of the database KeePassXC currently holds **unlocked**, over its browser-integration socket | `allow_paths` on that socket and the association; **no network** |

## The OAuth session holders

Three more are published, and they are a different kind of resolver. A vault
reader answers from something you already keep; these **hold the session
themselves**, so that an application which signed in for itself no longer has to.
Each mints a fresh access token from a refresh token that stays host-side, and
each is the only party allowed to refresh its account.

| Plugin | Reference form | Holds | Sandbox grant |
|---|---|---|---|
| `anthropic` | `anthropic://<account>` | a Claude.ai session, as `claude-code` obtains it | `programs = ["curl", "jq"]`; `network = true`; `state = true` |
| `openai` | `openai://<account>` | an OpenAI session, as `codex` obtains it | `programs = ["curl", "jq"]`; `network = true`; `state = true` |
| `nous` | `nous://<account>` | a Nous Portal session | `programs = ["curl", "jq"]`; `network = true`; `state = true` |

They are the only published plugins that declare `state = true`, because a
rotated refresh token that is not kept costs an interactive re-login. Setting one up takes two steps a
vault reader does not need: seeding the session once, and taking the application's
own copy away from it. Both are on [OAuth sessions](../secrets/oauth), which also carries the
per-application traps.

Each is also a worked example of [the manifest](manifest) and of the execution contract
above:
read its `plugin.toml`, its `resolve` script and its README when writing your own.
They show what the structural cage forces on a resolver (declaring the host tools
it runs, and restoring the host `HOME` a tool derives its paths from), and each
reports a reference it does not hold as a clean absent, so any of them is safe to
place ahead of another source in a `from` chain.

Two conventions are worth copying. A reference is read as a URI, so the container
is the authority, the item is the path, options are the query and the selector is
the fragment. And where a `#` could belong to either side, the split follows the
side the source constrains: `sops://` and `vault://` split at the **last** `#`
because a path may hold one, while `infisical://` splits at the **first**, since
an Infisical secret name may hold a `#` and the project, environment and folder
before it cannot.

## See also

- [The `plugin.toml` manifest](manifest): the fields a resolver's directory must declare.
- [`[plugin.<name>]`](configuring): what this machine supplies to it.
- [Managing plugins](managing): installing one, and what the registry does with it.
