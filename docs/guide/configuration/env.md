# `env` — environment variables

Extra environment variables for the sandbox.

```toml
[env]
RUST_LOG   = "info"
MY_SETTING = "value"
```

`env` is the one **free** field: it applies even from an **untrusted** project (minus
a reserved-key denylist, below). An untrusted project setting a variable can only
affect the process inside its own cage, so it is not gated.

See also: [The trust gate](../concepts/trust.md) · [Configuration overview](README.md) · [One-shot overrides](overrides.md).

## Precedence

Inside the cage, environment values are layered:

```
structural (set by sbx)  <  passthrough (TERM/LANG)  <  sbx-injected  <  config env
```

So a trusted config `env` value wins over `sbx`'s own structural defaults. (An
untrusted config's `env` has already lost its reserved keys — see below — so it
cannot override those.) An app's `[app.<name>.env]` overlays the baseline `env`, the
app winning on a key collision.

## The reserved-key denylist (untrusted only)

From an **untrusted** project, `env` keys that could subvert your later interactive
sessions are dropped. The denylist is the glibc `AT_SECURE` loader-control set plus a
few structural keys:

- Loader control: `LD_*` (e.g. `LD_PRELOAD`, `LD_LIBRARY_PATH`), `NIX_LD`,
  `NIX_LD_LIBRARY_PATH`, `GCONV_PATH`, `GLIBC_TUNABLES`, `LOCPATH`, `NLSPATH`,
  `RESOLV_HOST_CONF`, `HOSTALIASES`.
- Shell/exec hooks: `BASH_ENV`, `ENV`, `IFS`.
- Structural: `HOME`, `PATH`.
- The nix-config injection set (`NIX_CONFIG`, `NIX_USER_CONF_FILES`, `NIX_CONF_DIR`)
  and the proxy-control variables (`http_proxy`/`https_proxy`/`all_proxy`/`no_proxy`).

The denylist is **untrusted-only** by design: a *trusted* config overriding `PATH` or
`LD_PRELOAD` harms only itself, so the schema stays symmetric. The denylist's job is
to protect the *host* user's later Mode-A sessions from an untrusted project, not to
police the already-in-cage agent.

## Environment overrides for a single launch

To set a cage variable for one launch without editing the file, use the one-shot
override — `--env KEY=VALUE` (repeatable) or `SBX_ENV_<KEY>`:

```sh
sbx run --env RUST_LOG=debug -- cargo test
SBX_ENV_RUST_LOG=debug sbx run -- cargo test
```

See [One-shot overrides](overrides.md).

## What the cage inherits

The cage does **not** inherit your host environment. Only a small structural set
(`TERM`, `LANG`, the paths `sbx` sets, and whatever `env` declares) reaches it — part
of [confidentiality by absence](../concepts/security-model.md). So a variable a tool
needs must be declared in `env` (or injected as a [secret](secret.md) if it is a
credential — a credential should **not** go in `env`, which is visible in the cage).
