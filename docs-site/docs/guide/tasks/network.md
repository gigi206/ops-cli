# Reaching a non-HTTP service

A [declared operation](./) gets no network at all unless `network` declares one. For an
HTTP tool that is enough; a database client needs one more thing.

See also: [Declared operations](./) · [Rule grammar](../networking/rules) ·
[Network modes](../networking/modes).

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

## Examples by protocol

Each of these is the whole declaration: the difference between them is only what the
`network` entry gets in the cage.

**HTTP, through the proxy.** An `http_proxy`-aware tool needs nothing else.

```toml
[task.gh-issue]
cmd      = ["gh", "issue", "list", "--repo", "{repo}"]
params   = { repo = "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$" }
packages = ["mise:aqua:cli/gh"]
network  = ["api.github.com"]
```

**A database wire, spliced raw.** A named port gets a listener and an `/etc/hosts`
entry, so the client is invoked exactly as it would be outside a sandbox.

```toml
[task.db-query]
cmd     = ["psql", "-h", "db.staging.internal", "-p", "5432", "-U", "reader", "-d", "appdb", "-Atc", "{sql}"]
params  = { sql = "^SELECT [A-Za-z0-9_,.* ]{1,400}$" }
network = ["tcp://db.staging.internal:5432"]
```

**A service on the host's own loopback.** The cage's `localhost` is not the host's, so
the rule is what bridges them.

```toml
[task.redis-info]
cmd     = ["redis-cli", "-h", "localhost", "-p", "6379", "info", "server"]
network = ["tcp://localhost:6379"]
```

**ssh on port 22.** Below 1024 there is no listener, and the cage instead gets an
`ssh_config` with a `ProxyCommand` toward this task's proxy.

```toml
[task.deploy]
cmd     = ["ssh", "deploy@build.internal", "/srv/deploy.sh", "{tag}"]
params  = { tag = "^v[0-9]+\\.[0-9]+\\.[0-9]+$" }
network = ["tcp://build.internal:22"]
```

**Several destinations, mixed layers.** An operation may need both an API and a wire
protocol; each entry is served the way its scheme implies.

```toml
[task.publish]
cmd     = ["/srv/repo/publish.sh", "{tag}"]
params  = { tag = "^v[0-9]+\\.[0-9]+\\.[0-9]+$" }
network = ["api.github.com", "tcp://registry.internal:5000"]
spawn   = ["curl"]
```

And the two shapes that are reported at launch rather than quietly working:

```toml
network = ["tcp://db.internal:*"]        # no single port: no listener
network = ["tcp://10.0.0.5:5432"]        # a non-loopback IP literal: no listener
```

Both still govern the proxy; what they lose is the convenience, so the command has to
tunnel itself.

Checking a declaration before invoking it:

```sh
sbx task show db-query        # its command, bounds, network, and where it was declared
sbx task run db-query -p 'sql=SELECT 1'
```

`sbx task show` is the surface for this: a task's `network` is its own, served by its
own proxy, so the session-level [`sbx net rules`](../cli/net) and
[`sbx test net`](../cli/test) describe the agent's egress rather than the operation's.
