# Exit codes

`sbx` follows conventional Unix exit-code semantics.

See also: [`sbx run`](../cli/run) · [One-shot overrides](../configuration/overrides) · [Command reference](../cli/).

## The conventions

| Code | Meaning |
|---|---|
| `0` | success |
| `1` | a runtime failure, an operation that ran but did not succeed (e.g. `sbx config get` on an unset key, a store/network operation that failed) |
| `2` | a **usage or fail-closed** error, a bad argument, a missing operand, or a rejected [one-shot override](../configuration/overrides) value |
| *other* | for a launch verb, the **launched command's** own exit status |

## Launch verbs propagate the command's status

[`sbx run`](../cli/run) and [`sbx app`](../cli/app)
propagate the status of the program they launched:

```sh
sbx run -- sh -c 'exit 7'   # sbx exits 7
sbx run -- true             # sbx exits 0
sbx run -- false            # sbx exits 1
```

So a non-zero exit from a launch verb is the tool's result, not an `sbx` error: unless
it is `2` from an argument/override problem `sbx` caught before launching.

## Fail-closed overrides exit 2

A [one-shot override](../configuration/overrides) with a **set-but-invalid** security
value (a `--net nonee` typo, a bad `[limits]` value, a bad `nixpkgs`) or a **structural**
error (a `--limit` with no `=`, a `--bind` with an empty path) is a **hard error, exit 2,
no launch**, because silently keeping the baseline could leave a wider posture than the
mistyped intent. See [One-shot overrides](../configuration/overrides#fail-closed-on-an-invalid-value).

## `sbx doctor` fails hard on a missing prerequisite

[`sbx doctor`](../cli/doctor) exits non-zero when a load-bearing requirement
(capability-bearing user namespaces, the engines) is absent: it never reports success on
a host where a launch could not be secured. See
[prerequisites](../getting-started/doctor).
