# `sbx secret`

```
sbx secret list [-a|--app <name>] [--sources]
```

The **credential inventory** this configuration declares — by name, and what each is for.

Values are never read and sources are never resolved: an inventory that had to decrypt a sops file to
print a name would be a way to make sbx decrypt on demand. What it prints is the *declaration*.

See also: [`[secret]`](../configuration/secret.md) · [`[task]`](../configuration/task.md) ·
[`sbx task secrets`](task.md#secrets) (the same inventory as an in-cage caller sees it) ·
[Secrets](../secrets/README.md).

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

- **wire** — a [`[secret."host"]`](../configuration/secret.md) credential, injected into a matching
  request by the egress proxy. The value never enters the cage at all.
- **env of task `<name>`** — a [`[task.<name>.secret]`](../configuration/task.md#credentials)
  credential, handed to that operation's command in its own cage. The parenthesis is the `encode`.
  A task's wire-injected credential shows as **wire of task `<name>`**.

Set `name` and `description` on a `[secret."host"]` entry to make this listing legible — a credential
with no name is listed under its destination host. The name is also what a substituted value is
reported as (`${NAME}`) in a task's output, so keep names non-sensitive.
