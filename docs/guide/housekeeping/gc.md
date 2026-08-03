# Garbage collection

`sbx` provisions a per-project nix store and, over time, leaves reclaimable residue, superseded closures and the builds of removed packages. `sbx gc` reclaims the nix
store; whole per-project runtime **trees** (for projects that no longer exist) are removed
by [`sbx projects rm`](../cli/projects.md).

See also: [`sbx gc`](../cli/gc.md) · [`sbx store`](../cli/store.md) · [`sbx projects`](../cli/projects.md) · [Provisioning](../concepts/provisioning.md) · [Directory layout](../concepts/directory-layout.md).

## Dry run by default

Reclamation is **irreversible**, so `sbx gc` is a **dry run by default**: it lists what
*would* be reclaimed and touches nothing. Pass `--prune` to actually reclaim:

```sh
sbx gc                    # dry run: what this project's store would reclaim
sbx gc --prune            # reclaim this project's store
```

Deduplication (`--optimise`) is the exception: it deletes nothing, so it applies
immediately. See [Deduplication](../cli/gc.md#deduplication).

## Scope

| Invocation | What it sweeps |
|---|---|
| `sbx gc` | the **current project's** store (dry run) |
| `sbx gc --prune` | the current project's store (reclaim) |
| `sbx gc --all` | also the **shared** store's orphaned closures, and the runtime files of launches that are gone (dry run) |
| `sbx gc --all --prune` | the above, collected under an exclusive lock |

### The build of a removed package

Delete a `nix:`/`flake:`/`deb:`/`appimage:`/`tarball:` entry from a project's (or an app's)
`[packages]` and the per-project sweep drops its data-directory out-link and reclaims its
per-project store copy (a full closure on a filesystem without reflink support), which was
otherwise held until the whole project tree was removed.

A `mise:` tool instead lives in the app home, reclaimed by
[`sbx app prune`](../cli/app.md); an inline `[flakes]` build is reclaimed once its name
leaves the config.

### Superseded builds

`sbx` roots every version it provisions into a project's store, and a newer build's root
never displaces the older one. So old base-channel revisions, rebuilt tools, rolled-forward
`flake:` builds (each [`sbx upgrade flake`](upgrade.md) re-points the name-keyed out-link,
leaving the old build) and rolled-forward GUI app builds (multiple
`chromium`/`electron`/desktop versions) pile up — and a plain sweep, seeing them all rooted,
frees nothing.

The sweep therefore reconciles those seed roots against what the project's **current**
out-links reference: it keeps the current version of each and collects the superseded ones.
It is conservative — if the base or mise out-links for the current revision are missing it
skips rather than risk dropping a live build, so an over-eager prune only ever costs a
re-provision on the next launch.

### The shared store (`--all`)

`--all` collects the closures no live project or locked channel revision still roots, under
an exclusive lock so a concurrent launch cannot race it.

A channel revision roots its **own package-set source** as well as the tools built from it:
resolving the channel materializes that source (a few hundred MiB), so collecting it would
only mean rewriting it on the next command that resolves the channel. It is reclaimed with
the rest of its revision once no project pins that channel any more.

### Per-launch runtime files (`--all`)

`--all` also sweeps the egress MITM CA and its proxy/control sockets, the inbound
forwarder's and in-cage portal's runtime directories, and the process-observation sockets.

A clean exit unlinks them, but a cage normally ends on a signal (Ctrl-C,
[`sbx session stop`](../cli/session.md), a detached session killed later) and the cleanup
does not run then. A leftover is identified by its launcher pid: gone, it is removed; still
live, it is never touched. Every launch already runs this sweep before adding its own files,
so `--all` matters for a data directory nothing launches from any more.

Per-session **egress statistics are never swept**: they outlive their session by design, as
the data [`sbx net stats`](../cli/net.md) aggregates (`sbx net stats --reset` is their purge).

### Whole project trees

Removing a whole per-project runtime tree is [`sbx projects rm`](../cli/projects.md); its
store closures are then reclaimed by `sbx gc --all --prune` — or in one step,
`sbx projects rm <id> --gc`.

## Examples

```sh
sbx gc                    # see what's reclaimable in this project
sbx gc --prune            # free this project's residue
sbx gc --all --prune      # + collect the shared store
```

Re-seeding heals what a sweep removes: a launch re-seeds the project store from the
shared store, so `gc` is safe to run: the cost is a re-fetch/re-seed on the next launch,
not lost work.
