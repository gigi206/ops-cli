---
sidebar_label: "Run an agent safely"
description: "Launch first, declare tools, shape the egress posture, keep credentials out of the cage, and vouch last."
---

# Run an agent on an untrusted project, safely

The goal: an AI agent works inside this project with the tools it needs, reaches only
what you approved, never holds your credentials, and everything it does is visible.
Nothing below requires trusting the project first; trusting is the last step, taken
when the evidence says so.

Prerequisites: `sbx` installed and `sbx doctor` clean
([installation](../getting-started/installation),
[doctor](../getting-started/doctor)).

## 1. Launch before trusting anything

A fresh project starts untrusted. That is not an error state: security-sensitive
fields of `.sbx.toml` are dropped until you vouch for the file, while ordinary ones
apply. Run the agent anyway:

```sh
sbx run -- claude          # foreground session
```

The cage still bounds the agent; what you are missing at this stage is exactly the
posture you have not written yet. See [the trust gate](../concepts/trust).

## 2. Give the project its tools

Declare what the agent needs in `.sbx.toml`; sbx installs it into the sandbox store,
not the host OS:

```toml
[packages]
jq       = "nix:jq"
ripgrep  = "nix:ripgrep"
node     = "mise:node"
```

```sh
sbx run -- jq --version    # proves the declaration resolved
```

Backends and pins: [`packages`](../configuration/packages). A shared mise toolchain is
declared under [`[tools]`](../configuration/tools).

## 3. Shape the network posture

Filtering modes route every egress through a host-side proxy that decides per
request. Start narrow and admit what the agent genuinely needs:

```sh
sbx net rules -a claude            # what the current policy admits
sbx net allow api.anthropic.com    # admit a host for this project
sbx run --net none -- ./offline.sh # any launch can override the posture
```

Unknown destinations either fail or park for a decision, depending on the mode;
[Network modes](../networking/modes) explains each, [Ask mode](../networking/ask)
shows the park-and-confirm flow (`sbx net pending`).

## 4. Keep credentials out of the cage

Declare secrets by name; the proxy injects them into matching requests at egress
time, so the token value never enters the filesystem or environment:

```toml
[secret.github]
resolver = "env://GITHUB_TOKEN"
hosts    = ["api.github.com"]
```

Two conditions matter: injection is **effective only under a filtering network
posture** (`deny` / `allow` / `ask`), because the proxy performs it, and the field is
**ignored from an untrusted project**. Details:
[Secrets](../secrets/), field reference: [`[secret]`](../configuration/secret).

## 5. Watch it run

Background agents are where observability pays:

```sh
sbx run --detach --observe -- claude   # prints the session id
sbx proc logs   <id> -f                # what it executed
sbx fs   logs   <id> -f                # what it wrote
sbx net  logs        -f                # where it went, request by request
sbx ssh-agent logs <id> -f             # what it asked your keys to sign
```

The four lenses and their limits are on [the observability page](../concepts/observability).

## 6. Vouch when the evidence says so

You have seen the config, the requests, the writes. When this project's file deserves
the same authority as its content:

```sh
sbx trust
```

From then on its security fields apply, and any later edit re-opens the gate by
design. Reference: [`sbx trust`](../cli/trust); threat analysis:
[Security model](../concepts/security-model).
