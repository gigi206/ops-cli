---
sidebar_label: "env"
description: "Extra environment variables for the cage, and the reserved keys no project may set."
---

# `env`: environment variables

Extra environment variables for the sandbox.

```toml
[env]
RUST_LOG   = "info"
MY_SETTING = "value"
```

`env` is a **free** field: it applies even from an **untrusted** project (minus
a reserved-key denylist, below). An untrusted project setting a variable can only
affect the process inside its own cage, so it is not gated. The other free field is
[`timezone`](timezone).

See also: [The trust gate](../concepts/trust) · [Configuration overview](../configuration/) · [One-shot overrides](overrides).

## Precedence

Inside the cage, environment values are layered:

```
structural (set by sbx)  <  passthrough (TERM/LANG)  <  sbx-injected  <  config env
```

So a trusted config `env` value wins over `sbx`'s own structural defaults. (An
untrusted config's `env` has already lost its reserved keys, see below, so it
cannot override those.) An app's `[app.<name>.env]` overlays the baseline `env`, the
app winning on a key collision.

## `TZ` also moves the clock's other half

Setting `TZ` here is not only a variable. A cage answers "what zone is this?" through `TZ` **and**
through the `/etc/localtime` link an FHS resolver reads, and the two disagreeing is a wrong answer
with no error, so sbx points the link at whatever `TZ` ends up naming. A `TZ` written here
therefore outranks the [`timezone`](timezone) field, and a name the zone database does not carry
warns and leaves the cage on `UTC`. The field is the clearer way to say it; this is what happens
when a config says it through `env` instead.

## The reserved-key denylist (untrusted only)

From an **untrusted** project, `env` keys that could subvert your later interactive
sessions are dropped. The denylist is the glibc `AT_SECURE` loader-control set plus a
few structural keys:

- Loader control: `LD_*` (e.g. `LD_PRELOAD`, `LD_LIBRARY_PATH`), `NIX_LD`,
  `NIX_LD_LIBRARY_PATH`, `GCONV_PATH`, `GLIBC_TUNABLES`, `LOCPATH`, `NLSPATH`,
  `RESOLV_HOST_CONF`, `HOSTALIASES`.
- Shell/exec hooks: `BASH_ENV`, `ENV`, `IFS`, and the interactive-prompt hooks
  `PROMPT_COMMAND` and `PS1` (bash evaluates `$(...)` in both before each prompt).
- Exported shell functions, whole: anything starting with `BASH_FUNC_`. Bash runs a
  `BASH_FUNC_<name>%%` definition when it starts, which is `BASH_ENV`'s hole without
  the file. A prefix rather than a name at a time, because the name half is the
  project's to spell.
- Interpreter pre-load hooks: `NODE_OPTIONS`, `PYTHONSTARTUP`, `PERL5OPT`, `RUBYOPT`.
  Each names a file its interpreter runs before the program, so setting one runs code
  in your later `sbx run` without needing a shell startup at all.
- A command a tool runs on your behalf: `GIT_SSH_COMMAND`, `GIT_SSH`,
  `GIT_EXTERNAL_DIFF`, `GIT_PAGER`, `GIT_EDITOR`, `LESSOPEN`, `LESSCLOSE`,
  `SSH_ASKPASS`, `SUDO_ASKPASS`. These carry an argv rather than a file to source, so
  the first `git fetch` or the first paged file runs whatever the value names.
- A search path an interpreter imports from: `PYTHONPATH`, `PYTHONHOME`, `NODE_PATH`,
  `PERL5LIB`, `RUBYLIB`, `CLASSPATH`, `LUA_PATH`, `LUA_CPATH`, `GEM_PATH`, `R_LIBS`,
  `JULIA_LOAD_PATH`, `PSModulePath`. Nothing is named and nothing is executed directly;
  a module the interpreter was going to import anyway is simply answered from a
  directory the value chose (a `sitecustomize.py` on `PYTHONPATH` runs before the
  program's first line).
- A runtime that loads a hook from its options: `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`,
  `DOTNET_STARTUP_HOOKS`, each honored before `main`.
- A shell startup file by another name, and the shell itself: `ZDOTDIR` (the directory
  zsh reads its startup files from), `KSH_ENV` (ksh's `ENV`), and `SHELL`.
- The directory half of OpenSSL's trust anchors: `SSL_CERT_DIR`. The file-valued names
  are covered by the CA-bundle set below.
- The two XDG base directories the in-cage portal resolves a URI scheme through:
  `XDG_DATA_HOME` and `XDG_CONFIG_HOME`. When `[open]` declares handlers, sbx freezes
  the route by binding the generated desktop entry and `mimeapps.list` read-only at the
  locations the XDG lookup prefers, and that only outranks everything else while these
  stay unset. Setting either points the lookup at a directory the project ships, whose
  `.desktop` would then answer a sign-in click you made. The rest of the `XDG_*` family
  stays free: they are data paths whose worst case is the cage sabotaging its own
  lookup.
- Structural: `HOME`, `PATH`.
- The nix-config injection set (`NIX_CONFIG`, `NIX_USER_CONF_FILES`, `NIX_CONF_DIR`).
- Proxy control, matched case-insensitively: `http_proxy`/`https_proxy`/`all_proxy`/
  `no_proxy` and their WebSocket siblings `ws_proxy`/`wss_proxy` (which sbx sets so a
  WS client routes through the proxy too).
- CA-bundle keys, matched case-insensitively: `NIX_SSL_CERT_FILE`, `SSL_CERT_FILE`,
  `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`,
  `PIP_CERT`, `npm_config_cafile` (a nonstandard tool reading a lowercase variant must
  not slip a swapped CA past the gate).
- GPU driver-load paths: `LIBGL_DRIVERS_PATH`, `GBM_BACKENDS_PATH`,
  `__EGL_VENDOR_LIBRARY_DIRS`, `__EGL_EXTERNAL_PLATFORM_CONFIG_DIRS`, `VK_DRIVER_FILES`,
  `VK_ADD_DRIVER_FILES`, `VK_ICD_FILENAMES`, `VK_LAYER_PATH`, `VK_ADD_LAYER_PATH`
  (mesa's libgbm/libEGL `dlopen` a `<driver>_dri.so` /
  gbm backend from these).
- Anything starting with `SBX_`. That prefix is sbx's own control namespace: it is what
  the [one-shot overrides](overrides) read from the environment (`SBX_NET`, `SBX_BIND`,
  `SBX_ENV_<KEY>` and the rest) and what sbx sets into a cage. It is reserved as a
  prefix rather than name by name so a control variable added later is covered the day
  it exists. A variable that merely contains the letters, like `MY_TOOL_SBX_UPDATE`,
  is an app's own and stays free.

The denylist is **untrusted-only** by design: a *trusted* config overriding `PATH` or
`LD_PRELOAD` harms only itself, so the schema stays symmetric. The denylist's job is
to protect the *host* user's later Mode-A sessions from an untrusted project, not to
police the already-in-cage agent.

## Environment overrides for a single launch

To set a cage variable for one launch without editing the file, use the one-shot
override: `--env KEY=VALUE` (repeatable) or `SBX_ENV_<KEY>`:

```sh
sbx run --env RUST_LOG=debug -- cargo test
SBX_ENV_RUST_LOG=debug sbx run -- cargo test
```

See [One-shot overrides](overrides).

## Examples

The four scopes a variable can come from, from the widest to the narrowest, each
beating the one before it:

```toml
# ~/.config/sbx/sbx.toml: every project on this machine
[env]
MISE_MINIMUM_RELEASE_AGE = "0"
```

```toml
# ./.sbx.toml: this project
[env]
RUST_LOG    = "info"
RUST_BACKTRACE = "1"
DATABASE_URL = "postgres://127.0.0.1:5432/demo"   # a tunnelled service, not a credential

# …and this one app inside it, which wins on a key collision
[app.my-agent.env]
RUST_LOG = "debug"
```

```sh
sbx run --env RUST_LOG=trace -- cargo test   # the final word, for one launch
```

Checking what a launch would actually carry, rather than reasoning about the layering:

```sh
sbx config show                    # each value tagged with where it came from
sbx config show --app my-agent     # …with that app's overlay folded in
sbx run -- env | sort              # what the cage really holds
```

Two things `env` is **not** for:

```toml
[env]
API_TOKEN = "sk-live-…"      # NO: readable by anything in the cage
```

```toml
# yes: the value stays on the host and is added to the request on the wire
[secret."api.example.com"]
from   = "env://API_TOKEN"
header = "Authorization"
type   = "bearer"
```

A host `export API_TOKEN=…` does not reach the cage on its own, which is why the
`env://` resolver reads it *host-side*: the variable is sbx's input, never the agent's.

## What the cage inherits

The cage does **not** inherit your host environment. Only a small structural set
(`TERM`, `LANG`, the paths `sbx` sets, and whatever `env` declares) reaches it: part
of [confidentiality by absence](../concepts/security-model). So a variable a tool
needs must be declared in `env` (or injected as a [secret](secret) if it is a
credential, a credential should **not** go in `env`, which is visible in the cage).
