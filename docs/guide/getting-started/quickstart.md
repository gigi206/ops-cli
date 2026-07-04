# Quick start

This walks through the first things you will do with `ops`. It assumes you have a
binary on your `PATH` (see [Installation](installation.md)).

See also: [What ops is](../concepts/overview.md) · [Configuration overview](../configuration/README.md).

## 1. Check the prerequisites

```sh
ops doctor
```

This verifies the [runtime requirements](doctor.md) — capability-bearing user
namespaces, the bubblewrap engine, and nix — and reports the store location and
channel revision. A missing requirement is a hard failure with a remediation hint,
never a silent fallback.

## 2. Run a command in the sandbox

```sh
ops run -- id
```

You should see a synthetic identity (`uid=1000(sandbox)`), not your host user. The
host home and the rest of the host filesystem are **absent** from the cage — the
[security model](../concepts/security-model.md) is confidentiality by absence. The
command's exit status is propagated.

The `--` separates `ops`'s own flags from the command's, so `ops run -- --version`
runs the literal `--version`.

## 3. Open an interactive shell

```sh
ops shell
```

A real interactive shell with job control, inside the same sandbox. Useful for
exploring what a tool sees.

## 4. Give the project a toolchain

Create an `.ops.toml` in your project root:

```toml
[packages]
jq   = "nix:jq"
node = "nix:nodejs_20"
```

`packages` is a **security field**, so you must trust the file before it takes
effect:

```sh
ops trust
ops run -- jq --version
```

Use [`ops search <query>`](../cli/search.md) to discover the attribute names, and
see [`packages`](../configuration/packages.md) for the `nix:` / `mise:` / `flake:`
backends.

## 5. Launch an AI agent as an app

An **app** is a named, reusable launcher with its own isolated `$HOME`, package set,
network allowlist, and host-side credential injection. The repository ships
[importable starter profiles](../apps/catalog.md):

```sh
ops app import profiles/claude-code.toml
ops app claude-code
```

The agent runs in the cage with a persistent identity that never bleeds into your
project shell. See [the app framework](../apps/README.md).

## 6. Inspect the resolved configuration

```sh
ops config show
```

Prints the layered, trust-gated configuration a launch would use, with each value
tagged by where it came from — `(default)`, `(global)`, or `(project)`. Add
`--details` to expand app overlays, or `--json` for tooling. See
[`ops config`](../cli/config.md).

## Where to go next

- Lock down what a tool can reach: [Network modes](../networking/modes.md).
- Understand the trust boundary: [The trust gate](../concepts/trust.md).
- Change one field for a single launch: [One-shot overrides](../configuration/overrides.md).
