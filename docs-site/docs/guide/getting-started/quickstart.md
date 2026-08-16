# Quick start

This walks through the first things you will do with `sbx`. It assumes you have a
binary on your `PATH` (see [Installation](installation)).

See also: [What sbx is](../concepts/overview) · [Configuration overview](../configuration/).

## Check the prerequisites

```sh
sbx doctor
```

This verifies the [runtime requirements](doctor): capability-bearing user
namespaces, the bubblewrap engine, and nix, and reports the store location and
channel revision. A missing requirement is a hard failure with a remediation hint,
never a silent fallback.

## Run a command in the sandbox

```sh
sbx run -- id
```

You should see a synthetic identity (`uid=1000(sandbox)`), not your host user. The
host home and the rest of the host filesystem are **absent** from the cage: the
[security model](../concepts/security-model) is confidentiality by absence. The
command's exit status is propagated.

The `--` separates `sbx`'s own flags from the command's, so `sbx run -- --version`
runs the literal `--version`.

## Open an interactive shell

```sh
sbx run
```

A real interactive shell with job control, inside the same sandbox. Useful for
exploring what a tool sees.

## Give the project a toolchain

Create an `.sbx.toml` in your project root:

```toml
[packages]
jq   = "nix:jq"
node = "nix:nodejs_20"
```

`packages` is a **security field**, so you must trust the file before it takes
effect:

```sh
sbx trust
sbx run -- jq --version
```

Use [`sbx search <query>`](../cli/search) to discover the attribute names, and
see [`packages`](../configuration/packages) for the `nix:` / `mise:` / `flake:`
backends.

## Launch an AI agent as an app

An **app** is a named, reusable launcher with its own isolated `$HOME`, package set,
network allowlist, and host-side credential injection. The repository ships
[importable starter profiles](../apps/catalog):

```sh
sbx bundle import examples/bundle/claude-code.toml
sbx app import    examples/app/claude-code.toml
sbx app run claude-code
```

A shipped profile is **not self-contained**, on purpose: the agent's package, the
environment it reads and the hosts it must reach live in a [bundle](../configuration/bundles),
which follows upstream, while the profile holds what you configure. So a starter profile
takes two imports. Either order works, and the app is inert until you launch it; what does
not work is skipping one. If you do, `sbx app import` names the file you still need, and
`sbx app run` starts an agent that is simply absent.

To do both in one gesture, `sbx app import examples/app/claude-code.toml --with-deps` follows
what the profile references and imports it from the files beside it. It writes into your
global config, so it is asked for rather than assumed. See
[the import reference](../cli/app#importing-what-it-references-in-one-gesture).

The agent runs in the cage with a persistent identity that never bleeds into your
project shell. See [the app framework](../apps/).

The profile authenticates through the tool's own interactive login by default. If you
would rather use an API key, the profile ships the declaration for it, commented out:

```toml
[secret."api.anthropic.com"]
from   = "env://ANTHROPIC_API_KEY"
header = "x-api-key"
type   = "raw"
```

Uncomment that block and the `ANTHROPIC_API_KEY` placeholder beside it in `[env]`, then
`export ANTHROPIC_API_KEY=…` **on the host**. The key still never enters the cage:
`from` names a *source*, not a value, so `sbx` reads it host-side and the egress proxy
swaps it onto the wire. What the agent holds in its environment is the placeholder; the
real key exists only in `sbx`'s host process. See [Injection](../secrets/injection).

## See what it is allowed to reach, and what it reached

The two commands that make the previous step's posture visible:

```sh
sbx net rules -a claude-code    # what the allowlist admits, before launching
sbx secret list -a claude-code  # which credentials it carries, by name and never by value
```

And, from a second terminal while the agent runs:

```sh
sbx net logs -f                 # every egress decision, as it is made
```

Everything outside that allowlist is refused, by construction rather than by policy:
the cage has an **empty network namespace**, so its only route out is the host proxy
that just decided. See [Network modes](../networking/modes) and
[Architecture](../networking/architecture).

## Inspect the resolved configuration

```sh
sbx config show
```

Prints the layered, trust-gated configuration a launch would use, with each value
tagged by where it came from: `(default)`, `(global)`, or `(project)`. Add
`--details` to expand app overlays, or `--json` for tooling. See
[`sbx config`](../cli/config).

## Where to go next

- Lock down what a tool can reach: [Network modes](../networking/modes).
- Understand the trust boundary: [The trust gate](../concepts/trust).
- Change one field for a single launch: [One-shot overrides](../configuration/overrides).
