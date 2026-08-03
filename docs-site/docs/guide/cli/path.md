# `sbx path`

```
sbx path [--json]
```

Prints where sbx keeps its state on this machine: the three `<xdg>/sbx` roots it
owns, the **data root** (per-project trees, app homes, the shared nix store, the
embedded engines), the **config root** (the profiles directory and its siblings),
and the **state root** (the trust markers).

Read-only and free: a path listing. No nix, no network, no sandbox.

`--json` prints the same view as JSON.

See also: [`sbx store`](store) · [`sbx projects`](projects) · [`sbx storage`](storage) · [Directory layout](../concepts/directory-layout).
