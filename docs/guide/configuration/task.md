# `[task]` — declared operations

A **declared operation** is a fixed command sbx runs *on a caller's behalf*, in an ephemeral sibling
cage, with a credential the caller never holds. It is how an agent uses a database password or an API
token without the value ever entering its own cage.

```toml
[task.db-query]
description = "Read-only SQL against staging"
cmd     = ["psql", "-h", "db.staging.internal", "-c", "{sql}"]
params  = { sql = "^SELECT [A-Za-z0-9_,.*= ']{1,400}$" }
network = ["tcp://db.staging.internal:5432"]

[task.db-query.secret]
PGPASSWORD = "sops://secrets.enc.yaml#db.password"
```

> A task cage has **no network at all** unless `network` says otherwise, so the line above is not
> decoration — without it `psql` has nowhere to connect. A `tcp://` rule also gives the cage
> [somewhere to reach that host](#reaching-a-service-that-does-not-speak-http), so `-h
> db.staging.internal` works verbatim.

The agent then runs:

```sh
sbx task list
sbx task run db-query --param sql="SELECT id FROM users"
```

It never sees `PGPASSWORD`. sbx resolves it host-side, hands it to the command's environment in a
cage of its own, and returns the exit status and the output.

Trusted-only, like `[binds]`/`[seccomp]`/`[devices]`: an untrusted project may neither declare a task
nor loosen one. Declarable in the global config, a project's `.sbx.toml`, an app profile
(`[app.<name>.task.<task>]`) and a bundle (`[bundle.<name>.task.<task>]`).

## What makes it safe

**sbx fixes the program.** `cmd` is an argv list — never a shell string — and `cmd[0]` may carry no
placeholder. Nothing here ever reaches a shell, so `;`, `&&` and `||` are inert bytes inside an
argument; filtering them would be theater. What bounds the command is the fixed program, the
parameter bounds, and the absence of a shell.

**The command runs in its own cage, not the agent's.** In the agent's cage `/nix` is the per-project
store mounted read-write and a `mise` tool lives under a writable `$HOME`, so a same-uid agent could
overwrite the very binary a task is about to run. A task cage instead gets:

- the same hermetic FHS, `/etc` identity files and locales — so a task behaves like the project's own
  tooling;
- `/nix` **read-only from the shared store** (immutable, built host-side);
- the project **read-only**, a fresh tmpfs `$HOME`, its own pid namespace (so the agent cannot read
  the task's `/proc/<pid>/environ`), an empty network namespace, no stdin, no tty;
- **nothing else** — a `[binds]` path, a Wayland or D-Bus socket, a granted device, the session's
  egress socket: none of them are in a task cage.

**What crosses into the agent's cage is a client, not sbx.** Declaring a task binds the plane's
socket into the sandbox — an agent that cannot reach it cannot invoke an operation. What is bound
beside it is a small generated script that speaks the plane's protocol and refuses every other word,
so the sandbox never holds a program able to act on sbx's own state. See
[what the cage actually holds](../cli/task.md#what-the-cage-actually-holds).

**Every caller-supplied value is bounded.** A parameter must declare a `match` pattern or an `enum`,
and the pattern must match the **whole** value. This is load-bearing rather than cosmetic: a value
loose enough to embed a comparison (`… WHERE substr(:tok,1,1)='a'`) turns the exit status into an
oracle over the credential.

## Fields

| Field | Meaning |
|---|---|
| `description` | one line, listed to the caller — this is the operation's documentation |
| `cmd` | the argv list; `{param}` substitutes **inside** one element, never into extra elements |
| `params` | the caller-supplied values, each bounded (see below) |
| `env` | fixed environment for the command |
| `env_allow` | the variable **names** a caller may set for one invocation — names only, [values are not bounded](#caller-set-variables) |
| `stdout` / `stderr` | `"show"` (default) or `"hide"` |
| `timeout` | this task's wall-clock ceiling (`"20s"`), overriding `[task.defaults]` |
| `max_output` | this task's per-stream capture ceiling (`"64KiB"`), overriding `[task.defaults]` |
| `network` | the egress this task's cage gets, as allowlist entries (empty = no network) |
| `packages` | the `mise:` tools the command needs (see [below](#which-binaries-a-task-may-run)) |

### Parameters

```toml
# terse: the pattern itself
params = { sql = "^SELECT [a-z, ]+$" }

# table: a pattern or an enum, plus an optional default (which makes it optional)
[task.deploy.params]
env    = { enum = ["staging", "prod"] }
region = { match = "^[a-z]{2}-[a-z]+-[0-9]$", default = "eu-west-1" }
```

A parameter with no `default` is **required**: a missing value is an error, never an empty
substitution (`psql -c ""` is a different command than the one declared). An undeclared `{name}` in
`cmd`, and a declared parameter no `cmd` element uses, are both refused at validation.

### Caller-set variables

```toml
[task.build]
cmd       = ["make", "release"]
env_allow = ["MAKEFLAGS"]        # the caller may set MAKEFLAGS, and nothing else
```

`env_allow` and `params` look symmetric and are not. **`params` bounds values; `env_allow` bounds
only names.**

| | what the caller supplies | what the declaration constrains |
|---|---|---|
| `params` | a value for each declared name | the **value** — a `match` pattern or an `enum` is mandatory, and it must match the whole value |
| `env_allow` | `KEY=VALUE` for a listed name | the **name** only — the value is any string |

`env_allow` is empty by default, so out of the box a caller can set **nothing**. An unlisted name is
refused outright rather than dropped: a caller that believed a variable applied would otherwise be
reasoning about an invocation that never happened.

**Which names you may list is itself bounded.** Three kinds are refused when the config is
validated, so the declaration never loads rather than failing at invocation:

| Refused | Why |
|---|---|
| a variable that steers how a program **loads or connects** | `LD_*`, `NIX_LD*`, `PATH`, `HOME`, `IFS`, `ENV`, `BASH_ENV`, `SHELL`, `GCONV_PATH`, `GLIBC_TUNABLES`, `LOCPATH`, `NLSPATH`, `HOSTALIASES`, `RESOLV_HOST_CONF`, `PYTHONSTARTUP`, `PYTHONPATH`, `NODE_OPTIONS`, `PERL5OPT`, `RUBYOPT`, `GIT_SSH_COMMAND`, `SSH_ASKPASS`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `CURL_CA_BUNDLE`, `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` (case-insensitive) — the command and its trust anchors are sbx's choice, not a caller's |
| a name also declared in [`secret`](#credentials) | one name, one source — so a caller can never supply the credential the task exists to hold on its behalf |
| a name also fixed in `env` | the fixed value says "this is the declaration's", the allowlist says "this is the caller's"; sbx refuses rather than picks |

**What is left to your judgement** is the application's own variables — `MAKEFLAGS`, `PGOPTIONS`,
`AWS_PROFILE`. Their names pass, and their values are unconstrained, so what one is worth depends
entirely on what the program does with it. `PGOPTIONS` reshapes every query `psql` runs; that may be
exactly what you meant to expose, or a good deal more.

Two habits follow: list a variable only when the command's own handling of it is what you mean to
expose, and prefer a **parameter** when a value should be constrained — bounding values is what
parameters are for.

### Credentials

The key **is** the environment variable, so the name a substituted value is reported under is the
name the declaration already gives it:

```toml
[task.db-query.secret]
# terse: a resolver ref, or a bare key expanded through `[secret.defaults]`
PGPASSWORD = "sops://secrets.enc.yaml#db.password"

# table: adds an encoding and a description
[task.api-call.secret]
API_TOKEN = { from = "env://UPSTREAM_TOKEN", encode = "base64", description = "upstream API token" }
```

`encode` is `raw` (default), `base64`, `url`, or `json-string`. The set is closed on purpose: each
encoding registers the form it produces with the substituter, so a value can never reach the output
in a spelling sbx does not recognise.

Sources are the ones the rest of the product speaks — `env://`, `file://`, `sops://file#key`, and any
installed resolver plugin's scheme. They are resolved **per invocation**, never held for the session.

### Wire-injected credentials (the strongest form)

When the operation is an HTTP call, the credential need not enter the task cage at all — this task's
own proxy injects it on the wire, and the command runs knowing nothing:

```toml
[task.gh-issue]
cmd     = ["curl", "-sS", "https://api.github.com/repos/{repo}/issues"]
params  = { repo = "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$" }
network = ["api.github.com"]

[task.gh-issue.inject."api.github.com"]
from   = "sops://secrets.enc.yaml#github.token"
header = "Authorization"
type   = "bearer"
```

An `inject` entry requires `network` reaching that host — the injection happens in the task's proxy,
which only exists when the task has egress, so the pair is refused rather than silently doing
nothing.

**Each invocation gets its own proxy**, never the session's. That is a requirement, not tidiness:
with no per-process identity (the cage runs same-uid), a shared proxy could not tell a task's
connection from the agent's, so a task credential registered in the session's injection table would
be reachable by the agent simply requesting that host.

## Section defaults

```toml
[task.defaults]
timeout    = "30s"     # built-in default
max_output = "64KiB"   # built-in default, per stream
nonce      = false     # see below
```

Declared as a `[task.defaults]` sub-table rather than bare keys beside the entries, so a setting can
never be swallowed by whichever task table happens to precede it in the file. A task can therefore
not be named `defaults`.

## Output: what substitution does and does not promise

Every credential value found in a returned stream, in an error message sbx composes, or in a log line
is replaced by **`${NAME}`** — the credential's own name, so the output stays readable and says what
was withheld. It covers the plaintext *and* each registered encoding of it. Values shorter than 8
bytes are not substituted: such a needle would match benign text and leak the value through the
positions of its own placeholders.

Two things to keep in mind:

- **It is hygiene, not a boundary.** It catches the dominant accident — a credential echoed into an
  error message (`psql: … password=hunter2`) — and cannot catch a value the command itself
  transformed (hashed, encrypted, split).
- **`${NAME}` in the text is not proof.** The command can print that literal itself. The trustworthy
  signal is the substitution **count**, computed host-side and reported with the result (and in
  `sbx task logs`).

`nonce = true` makes each invocation's placeholders unforgeable: they read `${NAME@a91f3c}` where the
nonce is drawn per call and reported out of band, so the command could not have predicted it, and a
placeholder copied from an earlier result is detectably stale. Escaping the command's own `${…}` was
considered and rejected — it is imitable, and it would corrupt legitimate payloads (shell, CI YAML,
templates are full of `${…}`).

## Reaching a service that does not speak HTTP

A task's `network` is served by a proxy of the task's own, reached inside the cage as an HTTP
`CONNECT` proxy — which is all an `http_proxy`-aware tool (`curl`, `gh`, `git`) needs.

A database client does not speak that protocol, so a
[`tcp://host:port`](../networking/rules.md#raw-l4-splice-tcp) rule gets something else: **its own
loopback address inside the cage, and a listener on the port it names**, with the cage's `/etc/hosts`
resolving the host to that address. The declaration is then written exactly as it would be outside a
sandbox:

```toml
[task.db-query]
cmd     = ["psql", "-h", "db.staging.internal", "-p", "5432", "-U", "reader", "-d", "appdb", "-Atc", "{sql}"]
params  = { sql = "^SELECT [A-Za-z0-9_,.* ]{1,400}$" }
network = ["tcp://db.staging.internal:5432"]

[packages]
psql = "nix:postgresql"
```

The name in `cmd` is the name in `network` is the name the proxy matches its allowlist on. Nothing in
between is invented for you to look up.

**The fence is unchanged.** Only a declared destination gets a listener, so a port or a host the
policy never allowed has nothing to connect to — `-p 5433` on an allowed host is a refused
connection, and an undeclared host does not resolve at all (the cage's namespace has no DNS). The
request that leaves still carries the host name, so the proxy's verdict is made on what you wrote.

`tcp://localhost:<port>` works too, and means what you would expect: the cage's own loopback is a
different machine's, so the listener goes on the cage's `localhost` at that port and forwards to the
host's. `-h localhost -p 5432` reaches the service you meant.

**What gets no listener**, and is reported at launch rather than passed over: a rule naming no single
port (`tcp://host:*`, or a port range — sbx will not open a thousand listeners on a guess), a
non-loopback IP literal the cage's network namespace has no way to hold, and a host in the cage's own
`sbx-*` hostname space. Those rules still govern the proxy; what they lose is the convenience, and
the command has to tunnel itself.

## Which binaries a task may run

A task's program must come from a tree **no cage can write**, or "sbx fixes the program" is a
fiction. Most `[packages]` backends already satisfy that with nothing to declare here: `nix:`, a
remote `flake:`, `deb:`, `appimage:`, `tarball:` and `prebuilt:` all build **host-side into the
shared store**, which a task cage mounts read-only, so their binaries are on a task's path already.

Two are different:

- **`mise:`** installs *in-cage*, under a writable `$HOME` — so the pool the agent uses is
  agent-mutable and cannot back a task. Declare the tool in the task's own `packages` and sbx
  installs it into a pool of its own (below).
- an **inline `[flakes.<name>]`** flake builds in-cage to an out-link under the agent's `$HOME`,
  which a task cage does not have. Use a remote `flake:` reference, which builds host-side.

### What sbx does *not* bound: what the command spawns

sbx fixes the program a task runs. It does **not** police what that program goes on to spawn —
`allow` / `deny` keys on a task are refused rather than accepted into silence.

This is a deliberate limit, not an oversight, but it is a limit that may not stay. Deciding an
`execve` by path takes a seccomp user-notification supervisor and a shim bound inside the cage — and
this cage is the one holding a plaintext credential in the command's environment, so what gets bound
there matters more than anywhere else. The machinery [`[proc]`](proc.md) uses now binds a dedicated
binary that can do three things and nothing else, which is a far better thing to place next to a
credential than a general-purpose one. What is left to weigh is a supervisor per invocation against a
guardrail on a command a trusted declaration already chose.

What bounds a task today is its shape. The command is fixed by a trusted declaration, every
caller-supplied value is bounded by `params`, the cage has **no network** unless `network` declares
one (an empty netns, so a spawned child has nowhere to send anything), the project is read-only, and
the `$HOME` is a fresh tmpfs that dies with the invocation. And where the credential is an HTTP one,
[`inject`](#wire-injected-credentials-the-strongest-form) removes the question entirely: the plaintext never enters the cage, so
there is nothing for a spawned child to inherit.

### The task tool pool

```toml
[task.gh-issue]
cmd      = ["gh", "issue", "list", "--repo", "{repo}"]
params   = { repo = "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$" }
packages = ["mise:aqua:cli/gh"]
```

`packages` takes **`mise:` entries only** — every other backend is already covered above, and the
error message says so if you write one. `mise:nix:…` is refused too: mise's `nix:` backend builds
into the store the cage writes, which is the very problem the pool exists to solve; declare it as
`[packages] nix:…` instead.

What sbx does with it:

- installs the tools **host-side at launch**, in a cage of its own — the task cage's skeleton with
  the pool read-write and the host network (like every other host-side provisioning step, a cage's
  `network` allowlist governs the *agent*, not sbx's own setup);
- mounts the pool **read-only** into the task cage, at the same in-cage path the install used;
- puts the pool's **shims** directory at the front of that task's `PATH`, so the tool resolves by
  name. (Shims rather than install directories because the layout inside an install belongs to the
  backend, not to mise: an `aqua:` tarball extracts to a vendor-named subdirectory, an `npm:` tool
  to `bin/`, a `pipx:` one into a venv. The shim is mise's own answer to that, and it is what the
  agent's cage already uses.)

A version is honoured as declared: `mise:node@22` uses that version, a bare `mise:node` takes what
mise resolved for it. Changing the declared version re-pins the pool even when the old install is
still on disk, so what runs is always what the declaration says. A tool whose runtime is another tool
(an `npm:` CLI needs node) means declaring both — the pool holds what you ask for, nothing implicit.

`sbx upgrade mise` rolls the pool forward with everything else, under a `task pool` line. A pinned
`mise:node@22` stays where you pinned it; a bare `mise:node` moves to the current release.

Three things to know:

- **The pool is per project**, under its runtime tree, so `sbx projects rm` and the dead-tree sweep
  reclaim it with everything else. The cost is duplication: a heavy runtime is installed once per
  project a global app launches in.
- **It is filled best-effort.** A tool that will not install warns at launch and does not abort the
  session — one task's missing tool should not take the agent down with it. `sbx task list` then
  flags that task with `missing-tools=…`, and invoking it fails with a plain "not found".
- **The pool is shared by the config's tasks**, even though `packages` is declared per task: the
  field scopes what goes on a task's `PATH`, not what exists on disk. Every task is trusted config,
  so this is a scoping convenience, not a boundary.

## The quota, and the honest residual

Each session allows a bounded number of invocations (500). It is refused past that rather than
degraded, because an exit-status oracle over a credential gets cheaper the more calls it can make.
The quota, and the 512-invocation log ring behind [`sbx task logs`](../cli/task.md#logs), are **fixed
for now** — unlike the ceilings above, they are not `[task.defaults]` knobs.

The residual to know: the socket a caller reaches is bound into the cage, and same-uid gives **no
per-process identity**. Its authority is therefore the **cage's**, not the agent's — any process in
the cage, including a subprocess of whatever the agent spawned, can invoke a task. That is why what
bounds a task is its fixed program and its bounded parameters, not who is calling.

## See also

- [`sbx task`](../cli/task.md) — list, invoke, and read the invocation log.
- [`sbx secret list`](../cli/secret.md) — the credential inventory, by name.
- [`[secret]`](secret.md) — the wire-injection broker for the session itself.
- [Secrets](../secrets/README.md) — the resolvers, the redaction, and the invariant behind all of it.
