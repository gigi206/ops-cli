# `sbx shell`

```
sbx shell [override flags]
```

Open an interactive sandboxed shell in the current project, with job control and a
[synthetic identity](../concepts/security-model.md). The project's trusted config
drives the environment; the host home and the rest of the host filesystem are absent
(confidentiality by absence).

See also: [`sbx run`](run.md) · [`sbx app`](app.md) · [One-shot overrides](../configuration/overrides.md).

## Options

`sbx shell` accepts the same one-shot [override flags](../configuration/overrides.md)
as [`sbx run`](run.md) (`--config`, `--env`, `--net`, `--gui`, `--nixpkgs`, `--bind`,
`--limit`, `--package`), and their `SBX_*` environment equivalents. An override is the
final word for this launch.

## Behavior

- A real interactive shell with **job control** (a controlling terminal is present; no
  "no job control" warning), running inside the project sandbox.
- If a project's mise toolchain is [activated](../configuration/tools.md), `mise
  activate` runs in the shell so activated tools are on `PATH`.
- Like `sbx run`, this is a Mode-A launch — the human at the keyboard is the trust
  anchor.

## Examples

```sh
sbx shell
sbx shell --net deny --config '[network]
allow = ["api.github.com"]'
SBX_BIND=/opt/data:ro sbx shell
```
