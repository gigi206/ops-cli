---
sidebar_label: "[service]"
description: "Running something alongside the command in the same cage, and waiting for it to be ready."
---

# `[service]`: what else runs in the cage

Some applications are not one process. An agent workbench wants a vector database beside it; a web
UI wants the daemon that ticks its scheduler. That second process belongs in the same cage as the
first: the same isolated home, the same egress allowlist, the same resource limits, and the same
lifetime.

`[service]` declares it:

```toml
[service.chroma]
cmd   = ["chroma", "run", "--host", "0.0.0.0", "--port", "8100", "--path", "~/chroma-data"]
ready = { tcp = 8100 }
```

Each service starts before the application's own command, in the order their names sort. They are
not started for `sbx doctor`, `sbx test`, or any other verb that does not run a cage.

`[service]` is a **security field**, honored from the global config or a trusted project and ignored
from an untrusted one. An entry runs a program of its choosing at every launch, before anything
else, which is the same grant `cmd` carries.

See also: [`[network]`](network) · [`forward`](../networking/forward) · [`[bundle.<name>]`](bundles) ·
[`[open]`](open) · [The trust gate](../concepts/trust)

## What it is, and what it is not

This is a declaration, not a supervisor. sbx starts the process, and that is the whole of it:

- **A service that exits stays dead.** Nothing restarts it, and the application is not told.
- **There is no ordering between services.** They all start before the command; none waits for
  another.
- **There is no stop.** A service ends when the cage does, because it is one more process in the
  cage's process namespace, and the cage takes its whole namespace with it.

Those are limits by choice. A cage's only init is bubblewrap's reaper, which collects orphans and
supervises nothing, and the systemd scope sbx puts around a cage carries resource limits from the
outside. Restart policies and dependency graphs need a real init inside the cage, which is a
different thing from what this field is for.

What you gain instead is that the process is **named**. The same daemon started by hand from a `cmd`
is invisible: `sbx config show` cannot list it, and a reader has to find it inside a shell script.

## The shape of an entry

The key is the service's name (`1-64` characters of letters, digits, `.`, `_` or `-`).
The value is either the argv to run, or a table adding when it runs:

| field         | meaning                                                                    |
|---------------|----------------------------------------------------------------------------|
| `cmd`         | the program and its arguments, as an argv (a bare string is a one-element argv) |
| `enable`      | an environment condition the service starts under                           |
| `ready`       | a port to wait for before the application starts                            |

An entry that is only a command can be written on one line, which is the common case:

```toml
[service]
gateway = ["hermes", "gateway", "run"]
```

The argv is never a shell line: each element is one argument, whatever it contains, and a `$VAR`
inside one stays the characters it was written as. The single exception is a **leading `~/`**, which
is expanded against the cage's home, because a service is declared where that home's path is not
knowable.

The name is also where the service's output goes: `~/.sbx-service-<name>.log` in the cage's isolated
home. A service shares its terminal with the application, and a chatty daemon would bury the
application's own output, so it is written to a file instead. The file is never rotated.

## `enable`: turning one off without editing anything

A service the profile starts by default should stay switchable for a single launch. `enable` is the
condition it starts under:

```toml
[service.gateway]
cmd    = ["hermes", "gateway", "run"]
enable = { env = "HERMES_WEBUI_SBX_GATEWAY", not = "0" }
```

```bash
# this launch runs the UI alone
sbx app run hermes-webui --env HERMES_WEBUI_SBX_GATEWAY=0
```

A condition names one variable and one value, compared with either `is` or `not` (exactly one of
them). An **unset variable compares as empty**, which is what decides the default: `not = "0"` starts
the service for someone who never sets anything, and `is = "1"` starts it only for someone who does.
The value is compared literally, spaces and all, and never expanded.

Either side takes a **list of values**, any of which matches, which is how a condition says "or":

```toml
enable = { env = "GATEWAY", not = ["0", "false", "no"] }
```

Off is written differently by different people, and asking which spelling a profile meant is not a
useful question.

The variable is the one the cage receives, so anything that sets the cage's environment answers it:
the profile's own [`[env]`](env), a one-shot `--env`, or a variable passed through from your shell.

This is a comparison, not an expression, and not a shell test. sbx builds the cage's environment
itself, so the condition is answered while the launch is being assembled: a service that fails it is
simply never started, and nothing about the condition reaches the cage. A condition sbx cannot read
is reported and dropped, and the service starts, so a mistake never silently withholds the process.

### Several conditions

A list is an **and**: every condition must hold.

```toml
[service.relay]
cmd    = ["relay", "serve"]
enable = [
    { env = "RELAY", not = "0" },
    { env = "MODE", is = "pair" },
]
```

If one member cannot be read, the whole condition is dropped rather than the one member: dropping a
single term of an `and` would quietly loosen what the profile asked for, and a service running under
half a condition is worse than one running under none. An `enable` that is `[]`, that names
no `env`, that carries both `is` and `not`, neither, or empty values, is dropped the same way:
the service then starts unconditionally.

A list of conditions is always an `and`, and there is no way to write an `or` **across different
variables**, nor to negate a list as a whole. That is where the field stops: a service that would
start under "A or B" has two independent switches, which is a shape worth questioning before it is a
shape worth expressing. Along with anything past equality (a file exists, a command succeeds), the
answer is not a richer field but the service's own command, where a real language says it in full
view:

```toml
[service.relay]
cmd = ["bash", "-c", "test -S ~/relay.sock || exec relay serve"]
```

## `ready`: not racing the service

Without `ready`, the application starts the moment the service has been launched, which is right
when it degrades gracefully without it. With `ready`, the launch waits for the port to accept a
connection on the cage's loopback:

```toml
ready = { tcp = 8100, timeout = "30s" }
```

`timeout` is optional and defaults to fifteen seconds. When it expires the launch **starts the
application anyway** and says which service it did not see come up. That direction is deliberate: a
gate that failed the launch would turn a slow auxiliary process into a broken application, and the
application is the thing you asked for. If it needs the service and the service is late, the
application's own error is the accurate one. The port is `1-65535` (`0` or out of range
drops the gate with a warning); a `timeout` of zero drops it too; a malformed gate keeps
its default with a warning.

The check is a TCP connection and nothing more. It says a socket is accepting, not that the service
behind it is ready to answer, and no richer probe is offered, because sbx cannot fail the launch on
the answer anyway.

## Where to declare it

A service can be declared at the baseline, on an application, or in a bundle. An application's entry
wins over a bundle's, and a bundle's over the baseline's, under the same name, exactly as
`packages` and `env` resolve.

A daemon a tool cannot work without belongs in that tool's [bundle](bundles), beside its packages
and its hosts: it is a property of the tool, and a hand-copy of it falls behind the tool just as a
hand-copied host list does. An application declaring the same name retunes it (a different port, a
readiness gate the bundle left off) without forking the bundle.

An entry sbx cannot honor is dropped with a warning naming the service, and the launch goes on: a
malformed service leaves an application without its auxiliary process, never an application that
will not start.

## Reaching a service from the host

A service listens inside the cage, on the cage's own loopback, which the host cannot reach. To open
a port to your own browser, add it to [`forward`](../networking/forward), the same way you would for a
server the application itself binds.
