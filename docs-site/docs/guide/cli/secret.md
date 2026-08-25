---
description: "The credential inventory this configuration declares, by name and destination, never by value."
---

# `sbx secret`

```
sbx secret list [-a|--app <name>] [--sources]
```

The **credential inventory** this configuration declares: by name, and what each is for.
`sbx secrets` is an alias.

Values are never read and sources are never resolved: an inventory that had to decrypt a sops file to
print a name would be a way to make sbx decrypt on demand. What it prints is the *declaration*.

See also: [`[secret]`](../configuration/secret) · [`[task]`](../configuration/task) ·
[`sbx task secrets`](task#secrets) (the same inventory as an in-cage caller sees it) ·
[Secrets](../secrets/).

## `list`

```
sbx secret list [-a|--app <name>] [--sources]
```

| Flag | Meaning |
|---|---|
| `-a`, `--app <name>` | fold that app's overlay, so the inventory is what `sbx app run <name>` would carry |
| `--sources` | also show where each value would come from, by locator (a variable name, a file path) |

```
$ sbx secret list
gh_token    wire -> api.github.com (Authorization)  — read-only GitHub API token
PGPASSWORD  env of task `db-query` (raw)            — staging database password

$ sbx secret list --sources
gh_token    wire -> api.github.com (Authorization)  from sops secrets.enc.yaml#github.token  — read-only GitHub API token
PGPASSWORD  env of task `db-query` (raw)            from env DEMO_DB_PASSWORD                — staging database password
```

Two kinds appear:

- **wire**, a [`[secret."host"]`](../configuration/secret) credential, injected into a matching
  request by the egress proxy. The value never enters the cage at all.
- **env of task `<name>`**, a [`[task.<name>.secret]`](../tasks/credentials)
  credential, handed to that operation's command in its own cage. The parenthesis is the `encode`.
  A task's wire-injected credential shows as **wire of task `<name>`**, carrying the same columns
  as a launch-wide one: its destination, every header it sets, and under `--sources` the locator
  chain it would be read from.

Set `name` and `description` on a `[secret."host"]` entry to make this listing legible: a credential
with no name is listed under its destination host. The name is also what a substituted value is
reported as (`${NAME}`) in a task's output, so keep names non-sensitive.

## The declaration behind a listing

The two rows above come from these two declarations:

```toml
# a wire injection: the value never enters the cage
[secret."api.github.com"]
name        = "gh_token"
description = "read-only GitHub API token"
from        = "sops://secrets.enc.yaml#github.token"
header      = "Authorization"
type        = "bearer"

# a task credential: handed to that one command, in its own cage
[task.db-query.secret]
PGPASSWORD = { from = "env://DEMO_DB_PASSWORD", description = "staging database password" }
```

Which is why the listing is worth reading before a launch: it is the answer to
"what will this configuration hand out, and to whom", derived from the same
declarations the launch uses, without resolving a single value.

## Examples

```sh
sbx secret list                        # what this project declares
sbx secret ls                          # the alias
sbx secret list --sources              # …and where each value would come from
sbx secret list -a claude-code         # what `sbx app run claude-code` would carry
sbx secret list -a claude-code --sources
```

`--sources` prints locators, never values: a variable name, a file path plus its
key. It is the flag for "why is this credential empty" (the variable is unset on the
host) without ever making sbx decrypt anything.

An app's overlay can add credentials the project alone does not have, so `-a` and the
bare form legitimately differ. To see the same inventory as an in-cage caller sees it,
restricted to what a declared operation may use, see [`sbx task secrets`](task#secrets).
