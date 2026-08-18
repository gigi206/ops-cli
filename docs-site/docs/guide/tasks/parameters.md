# Task parameters

Everything a caller supplies to a [declared operation](./) passes through one of two
fields: `params`, which bounds **values**, and `env_allow`, which bounds only **names**.

See also: [Declared operations](./) · [Credentials](credentials) · [Output](output) ·
[`sbx task run`](../cli/task#run).

## Bounding a value: `params`

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

## A pattern that matches everything (possible, not recommended)

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
- **The substitution count stops meaning anything.** It is described in [what a task returns](output)
  as the trustworthy signal, and it counts *substitutions*: so a value that leaves in an unrecognised
  spelling leaves with the count reading **zero**. Nothing was withheld, and nothing says so.
- **Nothing closes it; two things narrow it a lot.** See the shape below: what is left after them
  costs the caller an invocation per character instead of one call for the whole value.

So the honest description is **accident containment, not a boundary**: the credential never touches
the calling agent's own environment, its logs or its files unless that agent asks, and asking is
trivial. Against a mistake that is worth something. Against a program that is looking, it is worth
nothing.

### If you do it anyway, the shape that costs least

```toml
[task.shell]
cmd     = ["bash", "-c", "{script}"]
params  = { script = "(?s).*" }
stdout  = "hide"                     # the widest channel, and the only one that
stderr  = "hide"                     # returns the whole value in a single call
network = ["api.example.com"]        # one host, not the project's posture
# `output` is deliberately absent (it defaults to off). A declared one is a directory
# the *calling* cage reads, so a value written there needs no encoding at all: it is
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
[`inject`](credentials#wire-injected-credentials-the-strongest-form) instead: the plaintext never enters the
cage, so a command the caller composed has nothing to read, whatever it is allowed to run.

## Caller-set variables

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

One thing is refused on both sides whatever you declared: a value carrying a **NUL byte**. It cannot
be an argument or an environment entry, and a `match` pattern written with `.` would otherwise admit
one. The refusal names the field, and it happens before the invocation is admitted rather than when
the command fails to start.

`env_allow` is empty by default, so out of the box a caller can set **nothing**. An unlisted name is
refused outright rather than dropped: a caller that believed a variable applied would otherwise be
reasoning about an invocation that never happened.

**Which names you may list is itself bounded.** Three kinds are refused when the config is
validated, so the declaration never loads rather than failing at invocation:

| Refused | Why |
|---|---|
| a variable that steers how a program **loads or connects** | `LD_*`, `NIX_LD*`, `PATH`, `HOME`, `IFS`, `ENV`, `BASH_ENV`, `SHELL`, `GCONV_PATH`, `GLIBC_TUNABLES`, `LOCPATH`, `NLSPATH`, `HOSTALIASES`, `RESOLV_HOST_CONF`, `PYTHONSTARTUP`, `PYTHONPATH`, `NODE_OPTIONS`, `PERL5OPT`, `RUBYOPT`, `GIT_SSH_COMMAND`, `SSH_ASKPASS`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `CURL_CA_BUNDLE`, `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` (case-insensitive): the command and its trust anchors are sbx's choice, not a caller's |
| a name also declared in [`secret`](credentials) | one name, one source, so a caller can never supply the credential the task exists to hold on its behalf |
| a name also fixed in `env` | the fixed value says "this is the declaration's", the allowlist says "this is the caller's"; sbx refuses rather than picks |

**What is left to your judgement** is the application's own variables: `MAKEFLAGS`, `PGOPTIONS`,
`AWS_PROFILE`. Their names pass, and their values are unconstrained, so what one is worth depends
entirely on what the program does with it. `PGOPTIONS` reshapes every query `psql` runs; that may be
exactly what you meant to expose, or a good deal more.

Two habits follow: list a variable only when the command's own handling of it is what you mean to
expose, and prefer a **parameter** when a value should be constrained: bounding values is what
parameters are for.
