# Restrict what a tool reaches on the network

The goal: a filtering posture where every request is decided against an explicit
rule set, the set starts from what the tool actually needs, and you can prove both
before and after a launch.

## 1. Pick the mode

`[network] mode` decides what happens to a request no rule claims:

| mode | unclaimed request |
|---|---|
| `none` / `shared` | no proxy at all: nothing to restrict here |
| `deny` | refused |
| `allow` | allowed, denylist only |
| `ask` | parked until you answer (`sbx net pending`) |

Postures and their trade-offs: [Network modes](../networking/modes).

## 2. Write the rules

Rules name hosts, wildcards, URLs, methods, ports; regexes are marked `re:`, raw
TCP is `tcp://host:port`:

```toml
[network]
mode = "deny"
allow = [
  "api.anthropic.com",
  "*.githubusercontent.com",
  "re:^stats\\.example\\.com$",
  "tcp://db.internal:5432",
]
```

The full grammar: [Rule grammar](../networking/rules). Sets reused across projects
belong in `[network.groups]`, referenced as `@name`:
[Egress groups](../networking/groups).

## 3. Learn the set from a live session instead of guessing

Launch with ask mode or net-learn, use the tool normally, then turn what it asked
for into rules:

```sh
sbx app run claude --net-learn
sbx net pending watch
sbx net pending allow 12345.7 --save   # writes the rule into the project config
```

The learn workflow end to end: [Ask mode](../networking/ask).

## 4. Prove it before launching

```sh
sbx test net https://api.anthropic.com/v1   # would this exact request pass, and why?
sbx net rules -a claude                     # the effective policy for one app
```

Reference: [`sbx test`](../cli/test), [`sbx net rules`](../cli/net).

## 5. Watch it during the run

```sh
sbx net logs -f      # every decision as it is made
sbx net stats        # per-host allow/deny counters, persisted
```

Noisy refusals can be muted without changing verdicts. All five surfaces:
[Egress observability](../networking/observability).
