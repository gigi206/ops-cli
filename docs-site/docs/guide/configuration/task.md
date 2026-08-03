# `[task]`: declared operations

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
> decoration, without it `psql` has nowhere to connect. A `tcp://` rule also gives the cage
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

**sbx fixes the program.** `cmd` is an argv list, never a shell string, and `cmd[0]` may carry no
placeholder. Nothing here ever reaches a shell, so `;`, `&&` and `||` are inert bytes inside an
argument; filtering them would be theater. What bounds the command is the fixed program, the
parameter bounds, and the absence of a shell.

**The command runs in its own cage, not the agent's.** In the agent's cage `/nix` is the per-project
store mounted read-write and a `mise` tool lives under a writable `$HOME`, so a same-uid agent could
overwrite the very binary a task is about to run. A task cage instead gets:

- the same hermetic FHS, `/etc` identity files and locales: so a task behaves like the project's own
  tooling;
- `/nix` **read-only from the shared store** (immutable, built host-side);
- the project **read-only**, a fresh tmpfs `$HOME`, its own pid namespace (so the agent cannot read
  the task's `/proc/<pid>/environ`), an empty network namespace, no stdin, no tty;
- **nothing else**, a `[binds]` path, a Wayland or D-Bus socket, a granted device, the session's
  egress socket: none of them are in a task cage.

**What crosses into the agent's cage is a client, not sbx.** Declaring a task binds the plane's
socket into the sandbox, an agent that cannot reach it cannot invoke an operation. What is bound
beside it is a small generated script that speaks the plane's protocol and refuses every other word,
so the sandbox never holds a program able to act on sbx's own state. See
[what the cage actually holds](../cli/task#what-the-cage-actually-holds).

**Every caller-supplied value is bounded.** A parameter must declare a `match` pattern or an `enum`,
and the pattern must match the **whole** value. This is load-bearing rather than cosmetic: a value
loose enough to embed a comparison (`… WHERE substr(:tok,1,1)='a'`) turns the exit status into an
oracle over the credential. What sbx enforces is that a bound is *declared*: whether it excludes
anything is yours to write, and [a pattern matching everything](#a-pattern-that-matches-everything-possible-not-recommended)
is accepted with the consequences that come with it.

## Fields

| Field | Meaning |
|---|---|
| `description` | one line, listed to the caller: this is the operation's documentation |
| `cmd` | the argv list; `{param}` substitutes **inside** one element, never into extra elements |
| `params` | the caller-supplied values, each bounded (see below) |
| `env` | fixed environment for the command |
| `env_allow` | the variable **names** a caller may set for one invocation, names only, [values are not bounded](#caller-set-variables) |
| `stdout` / `stderr` | `"show"` (default) or `"hide"` |
| `timeout` | this task's wall-clock ceiling (`"20s"`), overriding `[task.defaults]` |
| `max_output` | this task's per-stream capture ceiling (`"64KiB"`), overriding `[task.defaults]` |
| `network` | the egress this task's cage gets, as allowlist entries (empty = no network) |
| `packages` | the `mise:` tools the command needs (see [below](#which-binaries-a-task-may-run)) |
| `spawn` | the programs the command may run beside itself, absent means no supervision (see [below](#what-the-command-may-run-spawn)) |
| `[exec.<program>]` | what one of those programs may run in turn (see [below](#what-each-program-may-run-in-turn-execprogram)) |
| `output` | give the invocation a writable directory whose contents outlive it (see [below](#producing-a-file-output)) |

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

### A pattern that matches everything (possible, not recommended)

`match` takes any regex that compiles, and nothing checks that it excludes anything. So a universal
pattern is accepted:

```toml
[task.shell]
cmd    = ["bash", "-c", "{script}"]
params = { script = "(?s).*" }      # accepts any value, newlines included
```

This is worth stating plainly rather than leaving as folklore, because it does something specific:
**it hands the command to the caller.** The declaration still fixes the *program*: `cmd[0]` is
`bash` and no caller can change it, but a program whose whole job is to run the string it is given
makes that distinction empty. One operation then replaces the fifteen you would otherwise declare,
which is the reason people reach for it.

What you give up is not a nuance. A declared task is safe because of **two** checks together: the
program is the declaration's, and every caller-supplied value is bounded. A universal pattern
satisfies the second on paper and voids it in fact, and the second is the one holding the credential:

- **The credential is disclosed.** A command the caller composes can read its own environment and
  re-encode the value in any spelling it likes. Substitution recognises the plaintext and the
  encodings a declaration registers; it cannot recognise a value the command reversed, spaced out or
  chunked, and a few shell builtins are enough. There is no configuration of this table that
  prevents it.
- **The substitution count stops meaning anything.** It is described [below](#output-what-substitution-does-and-does-not-promise)
  as the trustworthy signal, and it counts *substitutions*: so a value that leaves in an unrecognised
  spelling leaves with the count reading **zero**. Nothing was withheld, and nothing says so.
- **Nothing closes it; two things narrow it a lot.** See the shape below: what is left after them
  costs the caller an invocation per character instead of one call for the whole value.

So the honest description is **accident containment, not a boundary**: the credential never touches
the calling agent's own environment, its logs or its files unless that agent asks: and asking is
trivial. Against a mistake that is worth something. Against a program that is looking, it is worth
nothing.

#### If you do it anyway, the shape that costs least

```toml
[task.shell]
cmd     = ["bash", "-c", "{script}"]
params  = { script = "(?s).*" }
stdout  = "hide"                     # the widest channel — and the only one that
stderr  = "hide"                     # returns the whole value in a single call
network = ["api.example.com"]        # one host, not the project's posture
# `output` is deliberately absent (it defaults to off). A declared one is a directory
# the *calling* cage reads, so a value written there needs no encoding at all — it is
# the shortest path of the lot, shorter than the output streams this hides.

[task.shell.secret]
DEMO_API_KEY = "env://MY_TOKEN"      # something low-value, never the crown jewels
```

Those two lines, hidden streams, no output directory, are worth writing, and the difference is not
cosmetic. They remove every channel that carries the **whole credential in one call**. What remains is
narrow: the exit status is a byte per invocation, and the elapsed time is whatever a `sleep` encodes.
(The substitution count is not among them: hiding a stream withholds its count too, for exactly this
reason.) Each of those costs a separate invocation per character, each invocation is counted against
the session's call quota, and each one is recorded host-side where `sbx task logs` shows it. The
extraction goes from instant and silent to slow and loud: which is a real difference against a
mistake, or against something not really trying, and no difference at all against something that is.

It is also better than the alternative it usually replaces: putting the credential in the agent's own
cage, where it lives for the whole session, is inherited by every child process, and leaves through
whatever egress that session has rather than the one host above.

Where a credential must stay out of reach, neither of those is the answer: either bound the parameter
for real, or give the task no `secret` at all and declare an
[`inject`](#wire-injected-credentials-the-strongest-form) instead: the plaintext never enters the
cage, so a command the caller composed has nothing to read, whatever it is allowed to run.

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
| `params` | a value for each declared name | the **value**, a `match` pattern or an `enum` is mandatory, and it must match the whole value |
| `env_allow` | `KEY=VALUE` for a listed name | the **name** only: the value is any string |

`env_allow` is empty by default, so out of the box a caller can set **nothing**. An unlisted name is
refused outright rather than dropped: a caller that believed a variable applied would otherwise be
reasoning about an invocation that never happened.

**Which names you may list is itself bounded.** Three kinds are refused when the config is
validated, so the declaration never loads rather than failing at invocation:

| Refused | Why |
|---|---|
| a variable that steers how a program **loads or connects** | `LD_*`, `NIX_LD*`, `PATH`, `HOME`, `IFS`, `ENV`, `BASH_ENV`, `SHELL`, `GCONV_PATH`, `GLIBC_TUNABLES`, `LOCPATH`, `NLSPATH`, `HOSTALIASES`, `RESOLV_HOST_CONF`, `PYTHONSTARTUP`, `PYTHONPATH`, `NODE_OPTIONS`, `PERL5OPT`, `RUBYOPT`, `GIT_SSH_COMMAND`, `SSH_ASKPASS`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `CURL_CA_BUNDLE`, `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` (case-insensitive): the command and its trust anchors are sbx's choice, not a caller's |
| a name also declared in [`secret`](#credentials) | one name, one source, so a caller can never supply the credential the task exists to hold on its behalf |
| a name also fixed in `env` | the fixed value says "this is the declaration's", the allowlist says "this is the caller's"; sbx refuses rather than picks |

**What is left to your judgement** is the application's own variables: `MAKEFLAGS`, `PGOPTIONS`,
`AWS_PROFILE`. Their names pass, and their values are unconstrained, so what one is worth depends
entirely on what the program does with it. `PGOPTIONS` reshapes every query `psql` runs; that may be
exactly what you meant to expose, or a good deal more.

Two habits follow: list a variable only when the command's own handling of it is what you mean to
expose, and prefer a **parameter** when a value should be constrained: bounding values is what
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

Sources are the ones the rest of the product speaks: `env://`, `file://`, `sops://file#key`, and any
installed resolver plugin's scheme. They are resolved **per invocation**, never held for the session.

### Wire-injected credentials (the strongest form)

When the operation is an HTTP call, the credential need not enter the task cage at all: this task's
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

An `inject` entry requires `network` reaching that host: the injection happens in the task's proxy,
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

Every credential value found in a returned stream, in an error message sbx composes, in a log line, or
in the paths an exec refusal names is replaced by **`${NAME}`**: the credential's own name, so the
output stays readable and says what was withheld. It covers the plaintext *and* each registered
encoding of it. Values shorter than 8 bytes are not substituted: such a needle would match benign text
and leak the value through the positions of its own placeholders.

The refusal paths are on that list because they are text the **command** composed rather than text it
printed: a program name is chosen by whoever calls `execve`, so a command that built one out of its
credential would otherwise hand the caller that spelling untouched. What is promised is about the
spelling, not about who wrote the command.

Two things to keep in mind:

- **It is hygiene, not a boundary.** It catches the dominant accident: a credential echoed into an
  error message (`psql: … password=hunter2`): and cannot catch a value the command itself
  transformed (hashed, encrypted, split).
- **`${NAME}` in the text is not proof.** The command can print that literal itself. The trustworthy
  signal is the substitution **count**, computed host-side and reported with the result (and in
  `sbx task logs`). The count returned to the caller covers **the streams the caller received**; a
  withheld stream's substitutions are recorded only in the log, which never crosses into a cage.
  Otherwise a declaration that hides its output would still hand back a number the command chooses
  by printing the credential as many times as it likes: a channel out of a cage whose streams were
  hidden to close one. The log holds the total, so hiding a stream is not a blind spot for you.

`nonce = true` makes each invocation's placeholders unforgeable: they read `${NAME@a91f3c}` where the
nonce is drawn per call and reported out of band, so the command could not have predicted it, and a
placeholder copied from an earlier result is detectably stale. Escaping the command's own `${…}` was
considered and rejected, it is imitable, and it would corrupt legitimate payloads (shell, CI YAML,
templates are full of `${…}`).

## Reaching a service that does not speak HTTP

A task's `network` is served by a proxy of the task's own, reached inside the cage as an HTTP
`CONNECT` proxy, which is all an `http_proxy`-aware tool (`curl`, `gh`, `git`) needs.

A database client does not speak that protocol, so a
[`tcp://host:port`](../networking/rules#raw-l4-splice-tcp) rule gets something else: **its own
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
policy never allowed has nothing to connect to: `-p 5433` on an allowed host is a refused
connection, and an undeclared host does not resolve at all (the cage's namespace has no DNS). The
request that leaves still carries the host name, so the proxy's verdict is made on what you wrote.

`tcp://localhost:<port>` works too, and means what you would expect: the cage's own loopback is a
different machine's, so the listener goes on the cage's `localhost` at that port and forwards to the
host's. `-h localhost -p 5432` reaches the service you meant.

**What gets no listener**, and is reported at launch rather than passed over: a rule naming no single
port (`tcp://host:*`, or a port range: sbx will not open a thousand listeners on a guess), a
non-loopback IP literal the cage's network namespace has no way to hold, and a host in the cage's own
`sbx-*` hostname space. Those rules still govern the proxy; what they lose is the convenience, and
the command has to tunnel itself.

A **port below 1024** gets no listener either (binding one needs a capability the cage does not
have), but it is not left to the command: that covers ssh's port 22, and for it the task's cage gets
its own `/etc/ssh/ssh_config` with a `ProxyCommand` toward this task's proxy. So a declared
`ssh deploy@host …` on the default port works as written, routed through the task's own egress
policy: not the agent session's.

## Which binaries a task may run

A task's program must come from a tree **no cage can write**, or "sbx fixes the program" is a
fiction. Most `[packages]` backends already satisfy that with nothing to declare here: `nix:`, a
remote `flake:`, `deb:`, `appimage:`, `tarball:` and `prebuilt:` all build **host-side into the
shared store**, which a task cage mounts read-only, so their binaries are on a task's path already.

Two are different:

- **`mise:`** installs *in-cage*, under a writable `$HOME`: so the pool the agent uses is
  agent-mutable and cannot back a task. Declare the tool in the task's own `packages` and sbx
  installs it into a pool of its own (below).
- an **inline `[flakes.<name>]`** flake builds in-cage to an out-link under the agent's `$HOME`,
  which a task cage does not have. Use a remote `flake:` reference, which builds host-side.

### Producing a file: `output`

A task cage keeps nothing. `$HOME` and `/tmp` are fresh tmpfs that die with the invocation, the
project is read-only, and the store is read-only: so a command that produces a file has nowhere to
leave it, and the only way out is `stdout` (capped at `max_output`).

`output = true` gives the invocation **one** writable directory whose contents survive it:

```toml
[task.dump]
cmd     = ["pg_dump", "-h", "db.internal", "-f", "{out}/staging.sql", "appdb"]
secret  = { PGPASSWORD = "sops://db.yaml#pg" }
network = ["tcp://db.internal:5432"]
spawn   = []
output  = true
```

`{out}` substitutes to that directory, and `$SBX_TASK_OUT` names it for a command that takes its
destination from the environment instead. **`{out}` is not a parameter**, sbx fills it, because a
caller who could choose where a credential-bearing command writes would choose the project. A
parameter named `out` is refused for the same reason, and `{out}` without `output = true` is refused
at load rather than substituting from nothing.

**The path is predictable, so the caller does not have to be told it.** Each task gets *its own*
directory, readable from the session's cage at:

```
/opt/sbx/task-out/<task>/
```

The invocation reports it anyway, with the size, so "it produced something" is visible at the point
of use:

```console
$ sbx task run dump
sbx: the operation wrote 41231872 byte(s) to /opt/sbx/task-out/dump
```

**Read-only for the agent, writable for the task.** The inverse of the intuition, and deliberate: an
agent that could write there would plant the input a credential-bearing command later reads back
(`psql -f {out}/script.sql`), taking back control of what the privileged operation does.

**It is emptied when the invocation claims it.** A predictable path is only honest if what sits there
is *this* invocation's work; otherwise a caller reads the previous artifact and cannot tell. If you
want to keep an artifact, copy it out. For the same reason, a second invocation of the same task is
**refused** while the first still holds the directory: two would interleave in one place.

**It is a real directory, never a tmpfs.** A tmpfs is RAM: a 300 MiB dump would be 300 MiB of memory,
and the cage's own cgroup would kill it. The directory lives under the project's runtime tree, so
`sbx gc` and `sbx projects rm` reclaim it with everything else that belongs to the project.

**This channel is not redacted.** Secret substitution covers `stdout` and `stderr`; a *file* the
command writes is not scanned. What bounds the risk is the choice of command by a trusted
declaration, `pg_dump` does not write its environment into its dump, but that is a property of the
program, not a guarantee sbx makes.

### What the command may run: `spawn`

sbx fixes the program a task runs. `spawn` declares what that program may run **beside itself**:

```toml
[task.gh-issue]
cmd   = ["gh", "issue", "list", "--repo", "{repo}"]
spawn = ["git"]
```

What `git` may then run is [a section of its own](#what-each-program-may-run-in-turn-execprogram), naming it here would let the command run it directly instead.

**Why it matters where a credential is involved.** A child of the command inherits its environment,
so it inherits the credential. The output that comes back to the caller is redacted, but redaction
matches the credential's **exact bytes**: a child that encodes it first is not caught. Confining
what may run closes that.

**Leaving `spawn` out is not the same as `spawn = []`.** Absent means no exec supervision at all: the
command runs as it always has. Present, including empty, stands up a supervisor for that
invocation, after which **only the command, what it lists, and what a section below allows may
run**. `spawn = []` is therefore the strictest form: a command that must run nothing else.

**A name is resolved to the program, not to a filename.** Each entry is looked up on the cage's own
`PATH` and becomes the absolute path it will run as, in the read-only store. A rule matching a bare
name would admit any file so called, including one written into the invocation's own tmpfs; the
resolved path does not. Write an entry with a `/` and it is kept as you wrote it, globs included
(`/nix/store/*/bin/git`). A name that is nowhere in the cage refuses the launch rather than becoming
a rule that matches nothing.

**A refusal is reported, never silent.** The `execve` comes back as an error to a program that
decides for itself whether to mention it: and many say nothing at all, leaving an empty result and a
success code. So the invocation reports what it refused, by name:

```console
$ sbx task run db-query -p 'sql=…'
sbx: warning: the operation was not allowed to run:
  /bin/sh
sbx: note: this operation declares `spawn`; a program it needs must be listed there.
```

That is how a missing entry reads as a missing entry rather than as a command that mysteriously
returned nothing.

**It governs the whole tree, at any depth.** The filter is inherited across `fork` and `exec`, so a
program run by a program run by the command traps the same supervisor. What decides is then *who is
running*, which is what the next section is about.

**Listing an interpreter concedes most of the guard**, and sbx says so at load. `sh`, `python`, `awk`
and the like can take a credential apart and put it back together with builtins alone, and nothing
they do that way is an `execve` to decide. The same is true if `cmd` is itself a shell script.

### What each program may run in turn: `[exec.<program>]`

`spawn` says what the **command** may run. A section says what one of those programs may run once it
is running:

```toml
[task.release]
cmd   = ["make", "release"]
spawn = ["git"]

[task.release.exec.git]
spawn = ["ssh"]

[task.release.exec.ssh]
spawn = ["gpg"]
```

**This permits a chain without granting a shortcut**, which is the whole reason the form exists. To
let `make → git → ssh → gpg` happen with one flat list you would have to write
`spawn = ["git", "ssh", "gpg"]`, and then the command may run `gpg` **itself**, with the credential
in hand and nothing in between. Above, the command may run `git` and nothing else.

**A program with no section of its own may run nothing.** There is no inheritance down the chain:
inheritance would hand back the shortcut. So a program that needs to run something needs a section
naming it, and `spawn = ["git"]` alone means git runs on its own or not at all.

**A section addresses a program, wherever that program was reached from.** `[exec.ssh]` is *ssh*, not
"the ssh git ran", so an ssh reached some other way is governed by the same rule, and a program
reachable three ways is declared once. There is nothing deeper to address, and a deeper section
(`[exec.git.ssh]`) is refused rather than quietly ignored.

`exec` is a namespace rather than the program's own name at the top: `[task.release.env]` is already
the task's environment, and `env`, `network`, `output` and `secret` are all programs a command
plausibly runs.

**What is refused at load**, each by name, with the rest of the file left standing:

| Written | Why |
|---|---|
| a section with no `spawn` on the task | nothing enforces it: `spawn` is what stands the supervisor up |
| a section nothing can reach | it says what a program may run when no program may run that program |
| `[exec.git]` where the list says `/nix/store/…/bin/git` | reachability is by **spelling**: the cage's `PATH` is what resolves a name, and there is no cage yet at load. Write the section key the way the list writes it |
| a section for the command itself | what the command may run is `spawn`; two declarations would each be half of one |
| `[exec.git.ssh]` | a program is the whole address |
| `[exec.git] spawn = []` | that is what having no section already means |
| `[exec.git*]` | a caller is one executable, so two patterns matching it would both claim it |

A pattern may still appear in a `spawn` list, where the answer is only yes or no. It just cannot
*address* a node, the program it admits then has no section, and may run nothing.

**Several names, one binary.** A caller is addressed by the executable it **is**, and some programs
are one file behind many names: every coreutils tool is a symlink to `coreutils`, and `/bin/sh` is
`bash`. So `[exec.ls]` governs every coreutils program, and sbx says so when a name resolves to a
different binary. What bounds it is that only a program that is **allowed to run** can ever be a
caller, so the over-grant never reaches past what the declaration already admits. Two sections that
turn out to be the same executable are refused: nothing could tell them apart.

That refusal, and the one for a program that is nowhere in the cage, arrives **when the operation
is invoked**, not at load: which binary a name reaches is a fact about the cage, and there is no cage
until then. So a task can list cleanly and refuse on its first run, naming the program either way.

**A refusal names who reached and what for**, because under this model the target alone misleads: a
program can be declared and still refused, to whoever reached for it:

```console
sbx: warning: the operation was not allowed to run:
  /nix/store/…/bin/git  →  /nix/store/…/libexec/git-core/git-remote-https
sbx: note: this operation declares `spawn`; list the target there when the caller is the command
       itself, and under `[task.<name>.exec.<caller>]` otherwise.
```

Only what was **there** is reported. Looking up a program by name issues one `execve` per `PATH`
entry until one succeeds, so a program found in the fourth directory leaves three refusals of files
that never existed: those are what a cage with no policy at all would produce.

### When the command is a script

A `#!` line is read by the kernel **inside** the `execve` that named the script: there is no second
call, and nothing ever observes the script as a running program. Only the interpreter runs. So
`spawn` on a script task says what its **interpreter** may run, and sbx keys it that way: a node on
the file would govern a caller that never exists.

With the interpreter named by path, that is invisible and everything reads as expected:

```toml
[task.report]
cmd   = ["/srv/repo/report.sh"]   # #!/bin/sh
spawn = ["git"]                   # what the shell running it may run
```

`#!/usr/bin/env bash` has one more step, and it is a real one, Linux runs **`env`**, passing `bash`
as its argument, and it is `env` that goes on to run bash:

```toml
[task.report]
cmd   = ["/srv/repo/report.sh"]   # #!/usr/bin/env bash
spawn = ["bash"]                  # env runs bash

[task.report.exec.bash]
spawn = ["git"]                   # bash runs git
```

Leave the second line out and the refusal reads
`/nix/store/…/bin/coreutils  →  /nix/store/…/bin/bash`: `coreutils` because `env` is one of its
hundred names, as [above](#what-each-program-may-run-in-turn-execprogram). That caller is the
command's own entry point, so what it may run is `spawn`.

**What it is not.** It bounds what the command *runs*; it does not bound what the command *itself*
does with the values the caller supplies. Both come back to `params` being the caller's lever, which
is why the bounds there are the first line and this is the second.

The rest of what bounds a task is its shape. The command is fixed by a trusted declaration, every
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

`packages` takes **`mise:` entries only**: every other backend is already covered above, and the
error message says so if you write one. `mise:nix:…` is refused too: mise's `nix:` backend builds
into the store the cage writes, which is the very problem the pool exists to solve; declare it as
`[packages] nix:…` instead.

What sbx does with it:

- installs the tools **host-side at launch**, in a cage of its own: the task cage's skeleton with
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
(an `npm:` CLI needs node) means declaring both: the pool holds what you ask for, nothing implicit.

`sbx upgrade mise` rolls the pool forward with everything else, under a `task pool` line. A pinned
`mise:node@22` stays where you pinned it; a bare `mise:node` moves to the current release.

Three things to know:

- **The pool is per project**, under its runtime tree, so `sbx projects rm` and the dead-tree sweep
  reclaim it with everything else. The cost is duplication: a heavy runtime is installed once per
  project a global app launches in.
- **It is filled best-effort.** A tool that will not install warns at launch and does not abort the
  session, one task's missing tool should not take the agent down with it. `sbx task list` then
  flags that task with `missing-tools=…`, and invoking it fails with a plain "not found".
- **The pool is shared by the config's tasks**, even though `packages` is declared per task: the
  field scopes what goes on a task's `PATH`, not what exists on disk. Every task is trusted config,
  so this is a scoping convenience, not a boundary.

## The quota, and the honest residual

Each session allows a bounded number of invocations (500). It is refused past that rather than
degraded, because an exit-status oracle over a credential gets cheaper the more calls it can make.
The quota, and the 512-invocation log ring behind [`sbx task logs`](../cli/task#logs), are **fixed
for now**, unlike the ceilings above, they are not `[task.defaults]` knobs.

The residual to know: the socket a caller reaches is bound into the cage, and same-uid gives **no
per-process identity**. Its authority is therefore the **cage's**, not the agent's: any process in
the cage, including a subprocess of whatever the agent spawned, can invoke a task. That is why what
bounds a task is its fixed program and its bounded parameters, not who is calling.

## See also

- [`sbx task`](../cli/task): list, invoke, and read the invocation log.
- [`sbx secret list`](../cli/secret): the credential inventory, by name.
- [`[secret]`](secret): the wire-injection broker for the session itself.
- [Secrets](../secrets/): the resolvers, the redaction, and the invariant behind all of it.
