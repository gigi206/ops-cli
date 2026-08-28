# Bugs, erreurs et anomalies — findings confirmés

Seize domaines fonctionnels ont été passés au crible pour la correction du code, hors
périmètre sécurité (traité séparément). Comme pour l'audit de sécurité, chaque défaut a été
soumis à un vérificateur chargé de le réfuter.

**Total : 74 défauts confirmés** (1 élevée, 20 moyenne, 53 faible).

## Table des matières

| # | Gravité | Emplacement | Défaut |
|---|---|---|---|
| [B1](#b1-an-explicitly-declared-misetoollatest-can-never-be-satisfied-so-the-pool-is-never-warm-and-the-task-gets-no-shims) | Élevée | `src/sandbox/taskpool.rs:107` | An explicitly declared `mise:<tool>@latest` can never be satisfied, so the pool is never warm and the task gets no shims |
| [B2](#b2-config-edit-trust-exits-0-after-failing-to-record-trust-unlike-every-other-trust-verb) | Moyenne | `src/cli/config.rs:3004` | `config edit --trust` exits 0 after failing to record trust, unlike every other `--trust` verb |
| [B3](#b3-plugins-info-tells-the-user-to-run-an-install-that-is-always-refused-so-a-programs-entry-added-after-install-can-never-be-built) | Moyenne | `src/cli/plugins.rs:2299` | `plugins info` tells the user to run an install that is always refused, so a `programs` entry added after install can never be built |
| [B4](#b4-sbx-session-logs-f-ignores-a-closed-stdout-and-keeps-polling-until-the-session-exits) | Moyenne | `src/cli/session.rs:714` | `sbx session logs -f` ignores a closed stdout and keeps polling until the session exits |
| [B5](#b5-two-tasks-naming-different-versions-of-one-tool-can-never-both-be-satisfied-the-pool-config-flips-every-launch-and-one-task-fails-with-command-not-found) | Moyenne | `src/sandbox/taskpool.rs:210` | Two tasks naming different versions of one tool can never both be satisfied; the pool config flips every launch and one task fails with "command not found" |
| [B6](#b6-a-readytcp-outside-u16-fails-the-untagged-rawservice-parse-and-drops-the-whole-config-layer) | Moyenne | `src/config/schema.rs:1159` | A `ready.tcp` outside u16 fails the untagged `RawService` parse and drops the whole config layer |
| [B7](#b7-rawtask-carries-no-unknown-key-bag-so-a-misspelled-spawn-silently-disables-exec-supervision) | Moyenne | `src/config/schema.rs:1418` | `RawTask` carries no unknown-key bag, so a misspelled `spawn` silently disables exec supervision |
| [B8](#b8-a-serviceopen-table-missing-its-cmd-or-an-enable-missing-env-drops-the-whole-config-layer) | Moyenne | `src/config/schema.rs:1053` | A `[service]`/`[open]` table missing its `cmd`, or an `enable` missing `env`, drops the whole config layer |
| [B9](#b9-a-match-bound-rejects-values-its-own-regex-accepts-because-find-is-leftmost-first-not-anchored) | Moyenne | `src/config/tasks.rs:669` | A `match` bound rejects values its own regex accepts, because `find` is leftmost-first, not anchored |
| [B10](#b10-a-higher-override-tiers-ssh-agent-confirm-is-silently-discarded-whenever-a-lower-tier-also-declares-ssh-agent) | Moyenne | `src/config/overrides.rs:648` | A higher override tier's `[ssh_agent] confirm` is silently discarded whenever a lower tier also declares `[ssh_agent]` |
| [B11](#b11-the-override-plane-folds-fs-scan-max-kb-with-min-while-the-layer-merge-it-cites-uses-max-so-the-environment-beats-the-command-line) | Moyenne | `src/config/overrides.rs:684` | The override plane folds `[fs] scan_max_kb` with `min` while the layer merge it cites uses `max`, so the environment beats the command line |
| [B12](#b12-space-entries-deletes-every-comment-inside-an-edited-array-and-collapses-it-to-one-line) | Moyenne | `src/config/manage.rs:578` | `space_entries` deletes every comment inside an edited array and collapses it to one line |
| [B13](#b13-longest-socket-suffix-omits-the-broker-plugin-socket-so-data-dir-max-does-not-bound-sun-path) | Moyenne | `src/store.rs:323` | LONGEST_SOCKET_SUFFIX omits the broker plugin socket, so DATA_DIR_MAX does not bound sun_path |
| [B14](#b14-sbx-task-run-tab-completes-app-names-instead-of-declared-operations) | Moyenne | `src/cli/completion.rs:697` | `sbx task run <TAB>` completes app names instead of declared operations |
| [B15](#b15-sbx-projects-tab-never-offers-list-or-rm-sbx-proc-pending-tab-never-offers-allowdeny) | Moyenne | `src/cli/completion.rs:797` | `sbx projects <TAB>` never offers `list` or `rm`; `sbx proc pending <TAB>` never offers `allow`/`deny` |
| [B16](#b16-app-runs-mashed-override-row-hides-the-flags-value-grammar-shifting-the-name-operand) | Moyenne | `src/help.rs:308` | `app run`'s mashed override row hides the flags' value grammar, shifting the `<name>` operand |
| [B17](#b17-prune-app-tools-builds-the-delete-path-from-the-sanitised-display-name-so-a-tool-whose-real-directory-name-is-not-sanitise-stable-is-reported-as-pruned-but-never-removed) | Moyenne | `src/sandbox/gc.rs:881` | `prune_app_tools` builds the delete path from the *sanitised* display name, so a tool whose real directory name is not sanitise-stable is reported as pruned but never removed |
| [B18](#b18-reap-dead-projectsreap-one-report-a-tree-as-reclaimed-even-when-force-remove-dir-all-failed-contradicting-the-rule-prune-rev-dirs-states-and-a-test-pins) | Moyenne | `src/sandbox/gc.rs:518` | `reap_dead_projects`/`reap_one` report a tree as reclaimed even when `force_remove_dir_all` failed, contradicting the rule `prune_rev_dirs` states and a test pins |
| [B19](#b19-sbx-upgrades-resolver-cage-omits-the-mise-nix-tools-the-prebuilt-bins-and-every-app-overlay-the-launch-cage-carries) | Moyenne | `src/sandbox/resolve.rs:84` | `sbx upgrade`'s resolver cage omits the mise `nix:` tools, the prebuilt bins and every app overlay the launch cage carries |
| [B20](#b20-a-removed-nix-mise-tools-gcroot-under-nix-tools-is-never-pruned-pinning-its-store-closure-forever) | Moyenne | `src/sandbox/nixhub.rs:256` | A removed `nix:` mise tool's gcroot under `nix-tools/` is never pruned, pinning its store closure forever |
| [B21](#b21-sbx-search-prints-a-packages-declaration-line-that-is-invalid-toml-for-any-dotted-nixhub-package-name) | Moyenne | `src/sandbox/search.rs:231` | `sbx search` prints a `[packages]` declaration line that is invalid TOML for any dotted nixhub package name |
| [B22](#b22-app-prefixed-key-rejects-a-dotted-app-name-on-the-strength-of-a-splitter-limitation-that-no-longer-exists) | Faible | `src/cli/config.rs:2355` | `app_prefixed_key` rejects a dotted app name on the strength of a splitter limitation that no longer exists |
| [B23](#b23-is-security-key-splits-on-every-dot-so-a-quoted-app-name-env-key-is-wrongly-reported-as-a-security-field) | Faible | `src/cli/config.rs:3103` | `is_security_key` splits on every dot, so a quoted app-name `env` key is wrongly reported as a security field |
| [B24](#b24-trust-is-accepted-and-silently-ignored-by-config-get-and-config-path) | Faible | `src/cli/config.rs:2386` | `--trust` is accepted and silently ignored by `config get` and `config path` |
| [B25](#b25-config-show-app-silently-drops-the-notify-repeat-window-that-config-show-prints) | Faible | `src/cli/config.rs:1872` | `config show --app` silently drops the notify repeat window that `config show` prints |
| [B26](#b26-sbx-net-pending-prints-a-session-header-for-every-reachable-session-including-ones-with-nothing-parked) | Faible | `src/cli/net.rs:617` | `sbx net pending` prints a session header for every reachable session, including ones with nothing parked |
| [B27](#b27-pending-allow-all-save-a-app-reports-no-pending-requests-for-this-project-without-naming-the-app-filter-that-emptied-the-drain) | Faible | `src/cli/net.rs:3359` | `pending allow --all --save -a <app>` reports "no pending requests for this project" without naming the `--app` filter that emptied the drain |
| [B28](#b28-comment-claims-a-session-rule-only-applies-to-ask-sessions-and-is-refused-with-err-not-ask-neither-is-true) | Faible | `src/cli/net.rs:3109` | Comment claims a `--session` rule only applies to `ask` sessions and is refused with `err not-ask`; neither is true |
| [B29](#b29-dispatch-comment-says-a-live-session-mute-is-not-yet-wired-it-is-wired-end-to-end) | Faible | `src/cli/net.rs:46` | Dispatch comment says "a live `--session` mute is not yet wired" — it is wired end to end |
| [B30](#b30-net-groups-export-out-writes-non-atomically-and-will-not-create-its-parent-directory-unlike-the-identical-bundle-export-out) | Faible | `src/cli/net.rs:2424` | `net groups export --out` writes non-atomically and will not create its parent directory, unlike the identical `bundle export --out` |
| [B31](#b31-render-statss-other-hosts-overflow-row-is-padded-to-the-host-column-width-and-misaligns-the-numeric-columns) | Faible | `src/cli/net.rs:1243` | `render_stats`'s "(other hosts)" overflow row is padded to the host column width and misaligns the numeric columns |
| [B32](#b32-task-show-invocation-id-answers-from-an-arbitrary-session-invocation-ids-are-per-session-not-globally-unique) | Faible | `src/cli/task.rs:1185` | `task show <invocation-id>` answers from an arbitrary session; invocation ids are per-session, not globally unique |
| [B33](#b33-plugins-store-install-and-plugins-store-update-silently-drop-every-argument-past-the-ones-they-read) | Faible | `src/cli/plugins.rs:1169` | `plugins store install` and `plugins store update` silently drop every argument past the ones they read |
| [B34](#b34-dispatch-docs-promise-a-built-inembedded-plugin-store-and-a-built-in-plugin-install-neither-exists) | Faible | `src/cli/plugins.rs:752` | Dispatch docs promise a built-in/embedded plugin store and a built-in plugin install; neither exists |
| [B35](#b35-task-runs-doc-comment-says-a-refusal-is-exit-2-it-is-125) | Faible | `src/cli/task.rs:623` | `task run`'s doc comment says a refusal is exit 2; it is 125 |
| [B36](#b36-a-store-listing-offers-a-brokersigner-entry-whose-name-is-already-taken-because-the-name-check-reads-directory-names-instead-of-manifest-names) | Faible | `src/cli/plugins.rs:360` | A store listing offers a broker/signer entry whose name is already taken, because the name check reads directory names instead of manifest names |
| [B37](#b37-plugins-info-reports-a-brokersigner-name-miss-as-an-unclaimed-resolver-scheme-and-offers-no-remediation) | Faible | `src/cli/plugins.rs:2146` | `plugins info` reports a broker/signer name miss as an unclaimed resolver scheme, and offers no remediation |
| [B38](#b38-sbx-store-reports-sizes-as-exact-when-the-reflink-probe-could-not-run-at-all) | Faible | `src/cli/store.rs:151` | `sbx store` reports sizes as "exact" when the reflink probe could not run at all |
| [B39](#b39-closing-notes-doc-and-store-moved-notes-doc-both-deny-that-mise-can-trigger-the-store-moved-note-which-it-does) | Faible | `src/cli/upgrade.rs:353` | `closing_note`'s doc and `store_moved_note`'s doc both deny that `mise` can trigger the store-moved note, which it does |
| [B40](#b40-app-scoped-targets-doc-says-both-for-three-targets-and-the-refusal-it-feeds-renders-provision-and-mise-and-nix) | Faible | `src/cli/upgrade.rs:39` | `APP_SCOPED_TARGETS` doc says "Both" for three targets, and the refusal it feeds renders "provision and mise and nix" |
| [B41](#b41-sbx-test-net-with-no-url-prints-the-parent-verbs-usage-line-and-swallows-an-unknown-flag-as-the-url) | Faible | `src/cli/test.rs:72` | `sbx test net` with no URL prints the parent verb's usage line, and swallows an unknown flag as the URL |
| [B42](#b42-sbx-search-silently-discards-every-flag-shaped-argument-instead-of-rejecting-it) | Faible | `src/cli/search.rs:13` | `sbx search` silently discards every flag-shaped argument instead of rejecting it |
| [B43](#b43-detachfalse-observefalse-dry-runfalse-turn-the-flag-on-flag-name-strips-the-value-for-pure-booleans) | Faible | `src/cli/mod.rs:435` | `--detach=false` / `--observe=false` / `--dry-run=false` turn the flag ON — `flag_name` strips the value for pure booleans |
| [B44](#b44-sbx-storage-migrate-leaves-the-whole-copy-in-the-volume-when-verification-fails-and-says-nothing-about-it) | Faible | `src/cli/storage.rs:458` | `sbx storage migrate` leaves the whole copy in the volume when verification fails, and says nothing about it |
| [B45](#b45-sbx-logs-f-a-feed-that-answers-with-rows-but-no-cursor-makes-the-loop-drop-those-rows-and-declare-the-session-ended) | Faible | `src/cli/logs.rs:708` | `sbx logs -f`: a feed that answers with rows but no cursor makes the loop drop those rows and declare the session ended |
| [B46](#b46-sbx-logs-feed-name-reports-session-n-is-recording-nothing-when-only-the-filtered-feed-is-absent) | Faible | `src/cli/logs.rs:621` | `sbx logs --feed <name>` reports "session N is recording nothing" when only the filtered feed is absent |
| [B47](#b47-sbx-session-stop-takes-as-a-session-id-the-comment-claims-it-ends-option-parsing) | Faible | `src/cli/session.rs:221` | `sbx session stop --` takes `--` as a session id; the comment claims it ends option parsing |
| [B48](#b48-sbx-app-rm-name-purge-reports-no-profile-and-no-home-for-a-profile-it-just-failed-to-delete) | Faible | `src/cli/app.rs:1224` | `sbx app rm <name> --purge` reports "no profile and no home" for a profile it just failed to delete |
| [B49](#b49-the-installs-stdout-tail-is-captured-and-then-discarded-so-a-mise-failure-reported-on-stdout-prints-no-output) | Faible | `src/sandbox/taskpool.rs:543` | The install's stdout tail is captured and then discarded, so a mise failure reported on stdout prints "no output" |
| [B50](#b50-a-project-brokername-table-with-no-allow-key-silently-clears-the-global-configs-broker-policy) | Faible | `src/config/mod.rs:2095` | A project `[broker.<name>]` table with no `allow` key silently clears the global config's broker policy |
| [B51](#b51-resolveds-field-docs-state-network-and-notify-defaults-the-code-does-not-implement) | Faible | `src/config/mod.rs:313` | `Resolved`'s field docs state network and notify defaults the code does not implement |
| [B52](#b52-apply-override-adds-credentials-to-secrets-but-leaves-declared-secrets-stale) | Faible | `src/config/mod.rs:1182` | `apply_override` adds credentials to `secrets` but leaves `declared_secrets` stale |
| [B53](#b53-bundleprovisions-doc-comment-opens-with-the-first-half-of-resolvedapps-sentence) | Faible | `src/config/mod.rs:503` | `BundleProvision`'s doc comment opens with the first half of `ResolvedApp`'s sentence |
| [B54](#b54-the-capture-max-kb-warning-fires-only-when-capture-is-absent-not-in-the-two-cases-its-own-message-names) | Faible | `src/config/validate.rs:701` | The `capture_max_kb` warning fires only when `capture` is absent, not in the two cases its own message names |
| [B55](#b55-validate-params-documents-declaration-order-but-a-btreemap-source-gives-alphabetical-order) | Faible | `src/config/tasks.rs:582` | `validate_params` documents declaration order but a `BTreeMap` source gives alphabetical order |
| [B56](#b56-doc-comment-line-duplicated-on-itself-in-validate-task-network) | Faible | `src/config/tasks.rs:927` | Doc comment line duplicated on itself in `validate_task_network` |
| [B57](#b57-add-egress-ruleadd-proc-rule-rewrite-the-file-on-alreadypresent-which-the-doc-says-is-never-written) | Faible | `src/config/manage.rs:886` | `add_egress_rule`/`add_proc_rule` rewrite the file on `AlreadyPresent`, which the doc says is never written |
| [B58](#b58-put-value-blames-the-leaf-key-when-it-is-a-parent-that-holds-a-scalar-giving-useless-remediation) | Faible | `src/config/manage.rs:622` | `put_value` blames the leaf key when it is a *parent* that holds a scalar, giving useless remediation |
| [B59](#b59-split-key-only-understands-quoted-key-segments-silently-mangling-quoted-ones-into-a-nonsense-table) | Faible | `src/config/manage.rs:1271` | `split_key` only understands `"`-quoted key segments, silently mangling `'`-quoted ones into a nonsense table |
| [B60](#b60-secrets-inherited-shadows-on-header-alone-while-upsert-secret-shadows-on-any-header-in-headers) | Faible | `src/config/view.rs:1879` | `secrets_inherited` shadows on `header` alone while `upsert_secret` shadows on any header in `headers()` |
| [B61](#b61-sbx-path-exits-0-and-reports-no-base-when-the-data-directory-could-not-be-resolved) | Faible | `src/main.rs:296` | `sbx path` exits 0 and reports "no base" when the data directory could not be resolved |
| [B62](#b62-an-untrusted-engine-override-is-reported-as-ignoring-and-then-as-not-found-neither-of-which-is-true) | Faible | `src/store.rs:678` | An untrusted engine override is reported as "ignoring" and then as "not found", neither of which is true |
| [B63](#b63-refresh-ref-documents-a-40-hex-pin-as-needing-no-nix-call-while-it-spawns-nix-and-queries-github) | Faible | `src/store.rs:1339` | `refresh_ref` documents a 40-hex pin as needing "no nix call" while it spawns nix and queries GitHub |
| [B64](#b64-the-bootstrap-local-save-refusal-prints-two-runs-of-14-literal-spaces-mid-sentence) | Faible | `src/main.rs:579` | The bootstrap `--local` save refusal prints two runs of 14 literal spaces mid-sentence |
| [B65](#b65-two-doc-comments-carry-a-duplicated-leading-fragment-glued-to-the-real-summary-line) | Faible | `src/main.rs:591` | Two doc comments carry a duplicated leading fragment glued to the real summary line |
| [B66](#b66-the-flag-menu-goes-dead-after-any-typed-flag-not-just-after-a-positional-value) | Faible | `src/cli/completion.rs:225` | The flag menu goes dead after any typed flag, not just after a positional value |
| [B67](#b67-the-emitted-bash-script-ignores-comp-wordbreaks-so-words-complete-nothing-there) | Faible | `src/cli/completion.rs:1028` | The emitted bash script ignores COMP_WORDBREAKS, so `:`/`=` words complete nothing there |
| [B68](#b68-sbx-app-prune-page-tells-the-user-to-run-sbx-stop-which-is-not-a-command) | Faible | `src/help.rs:2087` | `sbx app prune` page tells the user to run `sbx stop`, which is not a command |
| [B69](#b69-two-pages-say-sbx-app-name-launches-an-app-the-dispatcher-refuses-that-form) | Faible | `src/help.rs:1963` | Two pages say `sbx app <name>` launches an app; the dispatcher refuses that form |
| [B70](#b70-config-add-page-claims-config-rm-is-the-only-way-to-remove-a-rule-four-verbs-and-the-config-rm-page-say-otherwise) | Faible | `src/help.rs:1386` | `config add` page claims `config rm` is the only way to remove a rule; four verbs and the `config rm` page say otherwise |
| [B71](#b71-the-exec-observers-seen-set-is-never-pruned-so-a-reused-pid-silently-drops-its-exec-event-and-the-set-grows-without-bound) | Faible | `src/sandbox/observe_feed.rs:173` | The exec observer's `seen` set is never pruned, so a reused pid silently drops its exec event and the set grows without bound |
| [B72](#b72-sessiondescendants-has-no-visited-set-so-a-malformed-parent-graph-makes-sbx-session-stop-spin-forever-the-two-sibling-walkers-in-this-codebase-both-guard-against-exactly-that) | Faible | `src/session.rs:481` | `session::descendants` has no visited set, so a malformed parent graph makes `sbx session stop` spin forever -- the two sibling walkers in this codebase both guard against exactly that |
| [B73](#b73-treestates-doc-sends-users-to-sbx-gc-all-to-reclaim-a-dead-tree-which-that-command-explicitly-does-not-do) | Faible | `src/sandbox/gc.rs:933` | `TreeState`'s doc sends users to `sbx gc --all` to reclaim a dead tree, which that command explicitly does not do |
| [B74](#b74-flakepins-doc-says-the-revision-keys-the-out-link-the-module-header-fifteen-lines-above-says-nothing-is-keyed-by-it-and-the-code-agrees-with-the-header) | Faible | `src/sandbox/flake.rs:29` | `FlakePin`'s doc says the revision keys the out-link; the module header fifteen lines above says nothing is keyed by it, and the code agrees with the header |

## Détail

### B1 — An explicitly declared `mise:<tool>@latest` can never be satisfied, so the pool is never warm and the task gets no shims
| | |
|---|---|
| **Gravité** | Élevée |
| **Emplacement** | `src/sandbox/taskpool.rs:107` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | Concurrence, verrous, pools |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `version_dir` resolves an explicit `@version` by looking for a literal directory of that name: `Some(v) => tool.versions.iter().find(|d| d.as_str() == v).cloned()`. But `versions` comes from `inspect::mise_installed_in`, which keeps only real directories (`entry.file_type().map(|t| t.is_dir())` — `DirEntry::file_type` does not follow symlinks), and mise writes its `latest` alias as a *symlink* beside the concrete version. This repo's own test pins exactly that: `misses_aliases_are_symlinks_and_do_not_masquerade_as_versions` (taskpool.rs:714) asserts `installed[0].versions == vec!["15.2.0"]` after creating `latest`, `15` and `15.2` as symlinks.

So for the token `node@latest`, `split_version` yields `("node", Some("latest"))`, `version_dir` returns `None`, and `realized` at taskpool.rs:205-209 is `false` — even though the tool is installed and its shim works. Meanwhile the other half of the check passes: `mise use -g node@latest` records `node = "latest"` in the pool config, and `wanted_spec(Some("latest"))` is `"latest"` (taskpool.rs:180-182), so `pinned` is `true`. The two halves disagree, permanently.

The bare token `node` and the explicit `node@latest` are treated as the same request by `wanted_spec` ("A bare token asks for whatever mise resolves, which `mise use` writes as `latest`") but as different requests by `version_dir` — two code paths that should agree and do not.

**Scénario.** A project declares `[task.build] packages = ["mise:node@latest"]`. First launch: `bins_for` reports it missing, `ensure` runs the install cage, mise installs `installs/node/22.3.0` plus a `latest` symlink and records `node = "latest"`. `ensure` then recomputes and returns `PoolOutcome::Installed { still_missing: ["node@latest"] }`, so the user is told the tool did not install. Because `satisfied` stayed false, `out.bins` is empty, `TaskEngine::pool_bins` (task.rs:1320-1325) returns `None`, and the task cage runs with no `/opt/sbx/task-mise/shims` on `PATH` — the task fails with `node: command not found`. Every subsequent launch of that project repeats the whole install-cage run, because `ensure`'s short-circuit at taskpool.rs:261-264 never fires.

**Correction proposée.** Treat an explicit `latest` as the same request a bare token makes, so the two halves of the satisfaction rule agree:

```rust
fn version_dir(tool: &InstalledTool, wanted: Option<&str>) -> Option<String> {
    match wanted.filter(|v| *v != "latest") {
        Some(v) => tool.versions.iter().find(|d| d.as_str() == v).cloned(),
        None => { /* unchanged */ }
    }
}
```

That also makes the `if tool.versions.iter().any(|d| d == "latest")` branch at line 109 do useful work for both spellings instead of only for the rare case where mise materialises `latest` as a real directory.

**Rectification du vérificateur.** Two corrections, one narrowing and one widening. (a) The reporter says the user "is told the tool did not install" via `PoolOutcome::Installed { still_missing }`. That is wrong: the only caller, launch.rs:5151, is `if let Err(e) = engine.ensure_pool()` — the `Ok` value and its `still_missing` are discarded (they are read nowhere outside taskpool's own tests). When mise itself succeeds, `ensure`'s `!output.ok` warn at taskpool.rs:281-292 does not fire either, so the failure is silent at launch: the operator sees only a repeated `sbx: installing task tools: node@latest` line (taskpool.rs:278) each launch, plus `missing-tools=` from `sbx task list`. That makes the outcome worse, not better. (b) The defect is broader than `@latest`. Any non-exact version spec hits the same wall, because mise materialises partial-version aliases as symlinks too — which is exactly what the repo's own test creates (`for alias in ["latest", "15", "15.2"]`, taskpool.rs:719). That includes `mise:node@22`, the spelling the guide advertises at docs-site/docs/guide/tasks/execution.md:224 ("A version is honoured as declared: `mise:node@22` uses that version") and the fixture in config/tasks.rs:2044. The existing test `a_config_recording_another_version_is_not_satisfied` (taskpool.rs:897) misses it because its `realize` helper creates full versions (`22.3.0`, `24.4.1`) as real directories.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified end to end. taskpool.rs:107 is exactly `Some(v) => tool.versions.iter().find(|d| d.as_str() == v).cloned(),` — a literal directory-name match. inspect.rs:105-112 builds `versions` from `read_dir` filtered by `v.file_type().map(|t| t.is_dir())`, which is `DT_LNK` (false) for a symlink, and taskpool.rs:708-729 (`misses_aliases_are_symlinks_and_do_not_masquerade_as_versions`) pins that mise writes `latest`/`15`/`15.2` as symlinks, asserting `installed[0].versions == vec!["15.2.0"]`. So `version_dir(t, Some("latest"))` is `None` and `realized` (taskpool.rs:205-209) is false, while `wanted_spec(Some("latest")) == "latest"` (taskpool.rs:180-182) matches the `node = "latest"` that `mise use -g` writes, so `pinned` (taskpool.rs:210) is true. The two halves disagree permanently. Nothing upstream blocks the input: `validate_task_packages` (config/tasks.rs:531-570) rejects only non-`mise:` prefixes, `mise:nix:`, whitespace/control chars and `.`/`..` — `@latest` passes. `pool_bins` (task.rs:1318-1325) then returns `None`, so no shims reach the task's PATH, and `ensure`'s short-circuit (taskpool.rs:261-266, 275-277) never fires, so the install cage runs on every launch.

</details>

---

### B2 — `config edit --trust` exits 0 after failing to record trust, unlike every other `--trust` verb
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/cli/config.rs:3004` |
| **Catégorie** | `error-handling` |
| **Sous-système** | CLI — sbx config |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** In `config_edit`, the `--trust` tail treats a failed trust-record as advisory:

```rust
Some(dir) => match trust::trust(dir, &path) {
    Ok(()) => { ... println!("{}", render_trusted_whole_file(&path, &pal)); }
    Err(e) => diag::warn(&format!("could not trust {e}")),   // line 3004
},
None => diag::warn("no trust store available; cannot --trust"),  // line 3006
```

and then falls through to `ExitCode::SUCCESS` at line 3018. `report_write_trust` — the shared tail for `set`/`add`/`rm`/`unset` — handles the identical two failures at lines 3063-3069 and 3072-3075 with `diag::error` + a remediation `diag::hint` + `return ExitCode::FAILURE`, and its own comment at lines 3052-3056 says why: "A `--trust` that could not be recorded is a **failure**, not a warning. ... Reporting success there tells a script the security setting took effect when it did not, which is the one direction this must not be wrong in."

`config_edit` is subject to exactly that reasoning — the file has been saved, its security fields are on disk and inert until the marker exists — yet it reports success. This is the same class of drift `scope_is_gated`'s doc (lines 2441-2448) says it was extracted to prevent: "a second one is exactly how `edit` came to write a marker nothing reads and report a gate that does not exist." The `gated` computation was unified; the failure handling was not.

**Scénario.** Run `env -u HOME -u XDG_STATE_HOME sbx config edit --trust` in a project. `trust::default_store_dir()` returns `None`, so `store_dir` is `None`; `gated` is true (Local scope). The editor opens, the user writes a `.sbx.toml` carrying `[network] mode = "deny"` plus allow rules and `[fs] deny = [".env"]`, and saves. Line 3006 prints `sbx: warning: no trust store available; cannot --trust` and the function returns `ExitCode::SUCCESS`. A script written as `sbx config edit --trust && sbx run agent` therefore proceeds, and at launch the untrusted project config has its `[network]`, `[binds]`, `[fs]` and `[secret]` fields dropped — the cage runs with open egress. The identical environment with `sbx config set --trust network deny` prints `sbx: could not trust ...`, the hint `the field was written but does not apply until it is trusted`, and exits 1, so the `&&` short-circuits. The same divergence occurs on the `Err` arm (line 3004) whenever the store directory cannot be created (read-only `XDG_STATE_HOME`) or the file the editor was pointed at was never saved, so `trust_inner`'s `read_safe_bytes` returns `NotFound`.

**Correction proposée.** Make line 3004 and line 3006 behave as `report_write_trust` does: `diag::error` with the `sbx: ` prefix, a `diag::hint` naming `sbx trust <path>`, and `return ExitCode::FAILURE`. Better still, lift the whole `match store_dir { Some(dir) => trust::trust(...), None => ... }` tail into one helper shared by `config_edit` and `report_write_trust`, so the two cannot drift again — which is precisely the argument `scope_is_gated`'s doc already makes for `gated`.

**Rectification du vérificateur.** Mechanism confirmed; two corrections. (1) The `ExitCode::SUCCESS` fallthrough is src/cli/config.rs:3022, not 3018. (2) Severity is medium rather than high: reaching it needs an environment where the trust store cannot be resolved (no absolute HOME/XDG_STATE_HOME) or cannot be written, the user still gets a stderr warning, and nothing is falsely trusted — only the exit code lies. Note also that `config edit` cannot reuse `report_write_trust` verbatim, since `edit` intentionally blesses a previously-untrusted file (help.rs:1509-1511) while `admit_config_write` refuses that for `set`/`add`/`rm`/`unset`; the shareable part is just the Some/None/Err reporting tail.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Confirmed at the cited line. src/cli/config.rs:2997-3007 is the `else if trust_flag` arm of `config_edit`: `Some(dir) => match trust::trust(dir, &path) { Ok(()) => {...} Err(e) => diag::warn(&format!("could not trust {e}")) }` (line 3004) and `None => diag::warn("no trust store available; cannot --trust")` (line 3006); the function then falls through to `ExitCode::SUCCESS` (line 3022, not 3018 as cited). The shared tail for the key-writing verbs handles the identical pair at src/cli/config.rs:3064-3070 (`diag::error("sbx: could not trust {e}")` + hint + `return ExitCode::FAILURE`) and 3073-3076, under the comment at 3054-3058: "A `--trust` that could not be recorded is a **failure**, not a warning ... Reporting success there tells a script the security setting took effect when it did not, which is the one direction this must not be wrong in." Both arms are reachable for `edit`: `trust::default_store_dir()` (src/trust.rs:156-177) returns `None` when neither `XDG_STATE_HOME` nor `HOME` is an absolute path, and `config_edit` deliberately skips `admit_config_write` (comment at 2932-2934), so nothing upstream turns the None/Err case into a refusal. No comment, help page (src/help.rs:1481-1511) or test documents the warn-and-succeed choice; tests/config.rs:4430-4496 only pin the re-arm warning and the non-gated global note. Nothing prevents the traced path.

</details>

---

### B3 — `plugins info` tells the user to run an install that is always refused, so a `programs` entry added after install can never be built
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/cli/plugins.rs:2299` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | CLI — sbx plugins et sbx task |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `print_grant_programs` renders the terminal state of a declared program as `"{name} -> nix:{attr} configured but not built (run: sbx plugins install {dir_name})"` (lines 2297-2300). That remedy is wrong twice over. First, `plugins_install` (line 628) does `plugins::install(&layout, Path::new(source))` — the argument is a *source directory path* (`sbx plugins install <dir>`, help.rs:2878), not an installed plugin's name, so `sbx plugins install kp` looks for `./kp/plugin.toml`. Second, and fatally, even with the correct source path the install is refused: `install_inner` returns `Err` unconditionally when `dest.exists() && placement == Placement::Fresh` (src/plugins/mod.rs:1329-1346, pinned by `install_refuses_an_already_installed_name` at src/plugins/mod.rs:2927). `plugins_install` only reaches `provision_configured_programs` on the `Ok` arm (line 641), so provisioning is unreachable for an already-installed plugin. The doc at line 658-659 ("Re-running the install is therefore how a `programs` entry added *after* installing takes effect, which is what the launch-time refusal for a missing program tells the user to do") asserts a behaviour the code does not have — as do help.rs:2889 ("Run it again to pick up a `programs` entry added after installing"), src/plugins/programs.rs:22 and the launch-time error at src/sandbox/resolver.rs:727-732. `plugins_upgrade` does not call `provision_configured_programs` either, so a store upgrade that introduces a new declared program hits the same dead end.

**Scénario.** `sbx plugins install ~/src/kp` installs resolver `kp`. The user then adds `[plugin.kp] programs = { "keepassxc-cli" = "nix:keepassxc" }` to the config. `sbx plugins info kp` prints `programs: keepassxc-cli -> nix:keepassxc configured but not built (run: sbx plugins install kp)`. Running that: `sbx: cannot install plugin: kp is not a plugin (no plugin.toml)`, exit 1. Running the corrected form `sbx plugins install ~/src/kp`: `sbx: cannot install plugin: a plugin named `kp` is already installed from local directory /home/u/src/kp — to replace it, remove it first with `sbx plugins rm kp`, then install it again`, exit 1. The program is never built, and every launch that touches a `kp://` secret keeps failing with the same 're-run `sbx plugins install`' message.

**Correction proposée.** In `plugins_install`, treat 'already installed from the same source' as the re-provision case rather than a hard failure: match on that error (or add a `Placement::Reprovision` probe) and fall through to `provision_configured_programs(&layout, &name)` instead of returning FAILURE. At minimum, change the hint at line 2299 to the sequence that actually works — `run: sbx plugins rm {dir_name}, then sbx plugins install <its source dir>` — and correct the claims at line 658-659 (and help.rs:2889).

**Rectification du vérificateur.** Correct in mechanism, overstated in the title and severity. The program is not un-buildable: `install_inner`'s own refusal names the working sequence ("remove it first with `sbx plugins rm {name}`, then install it again", src/plugins/mod.rs:1336-1339), and `rm` + `install <source dir>` (or `rm` + `store install <store> <plugin>`) does reach `provision_configured_programs`. What is actually broken is the remediation text: `plugins info` prints a command whose argument form is wrong (an install name where a source directory is required), and three doc sites plus the launch-time error tell the user to "re-run the install" when a bare re-install is unconditionally refused. It is a wrong-remediation / doc-drift defect, not an unreachable capability.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Traced and confirmed. src/cli/plugins.rs:2298-2300 emits `(run: sbx plugins install {dir_name})`, and `dir_name` is the *installed directory* name (src/plugins/mod.rs:192-194 `dir_name_of` = `dir.file_name()`), while `plugins_install` treats its argument as a source path (`plugins::install(&layout, Path::new(source))`, src/cli/plugins.rs:628; synopsis `sbx plugins install <dir>`, src/help.rs:2878). `plugins::install` passes `Placement::Fresh` (src/plugins/mod.rs:1186-1192) and `install_inner` returns `Err` when `dest.exists() && placement == Placement::Fresh` (src/plugins/mod.rs:1328-1346), pinned by `install_refuses_an_already_installed_name` (src/plugins/mod.rs:2926-2950), which asserts the same-source case is also refused. `provision_configured_programs` is only reached on the `Ok` arms of `plugins_install` (src/cli/plugins.rs:641) and `plugins_store_install` (src/cli/plugins.rs:1198) — grep shows no other caller, so `plugins upgrade` (which uses `Placement::Replace`) never provisions. The claims at src/cli/plugins.rs:658-659, src/help.rs:2889 ("Run it again to pick up a `programs` entry added after installing"), src/plugins/programs.rs:21-23 and the launch-time error at src/sandbox/resolver.rs:726-731 therefore describe a behaviour the code does not have.

</details>

---

### B4 — `sbx session logs -f` ignores a closed stdout and keeps polling until the session exits
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/cli/session.rs:714` |
| **Catégorie** | `error-handling` |
| **Sous-système** | CLI — dispatcher, app, session, logs, storage |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `drain_log` writes the newly-appended bytes with `let _ = out.write_all(&buf); let _ = out.flush();` (session.rs:714-715) and returns `()`. `follow_log` (session.rs:684-693) therefore has no way to learn that stdout is gone and loops `session_is_live` / `drain_log` / `sleep(250ms)` until the *session* dies. Rust ignores SIGPIPE, so a closed downstream pipe surfaces only as the `Err` this line throws away. The streaming arm has the same hole: `stream_range` does `let _ = std::io::copy(...)` at session.rs:545 and then returns `ExitCode::SUCCESS`, after which `logs_cmd` still enters `follow_log`. This is a fourth copy of the follow loop that missed the discipline the sibling module states as its whole reason for existing: `src/cli/logs.rs`'s header says "a bare `println!` into a closed downstream pipe (`… | head`) panics; every write here goes through a locked, error-checked stdout and a failed write ends the view cleanly at exit 0 … Getting that wrong in one of three copies would be invisible until someone piped it", and both of its loops do `if wrote.is_err() { return ExitCode::SUCCESS; }` (logs.rs:190, logs.rs:732). `drain_log`'s own doc only excuses *read* failures ("a transient read failure skips one poll"); it says nothing about write failures.

**Scénario.** Detach an agent (`sbx app run claude --detach`, pid 4242), then run `sbx session logs 4242 --follow | head -20`. `head` prints 20 lines and exits, closing the pipe. Every subsequent `drain_log` write returns EPIPE, which is discarded, so sbx keeps opening the log, reading, failing to write and sleeping — forever. Because bash waits for every member of a pipeline, the user's shell never returns until the background agent finishes (possibly hours). The same happens for `sbx session logs 4242 -f --all | head`. By contrast `sbx logs 4242 -f | head` and `sbx fs logs 4242 -f | head` both exit immediately.

**Correction proposée.** Make `drain_log` return `std::io::Result<()>` (propagating the `write_all`/`flush` error, and advancing `*pos` only by the bytes actually written), and have `follow_log` return `ExitCode::SUCCESS` when a drain reports a write error — exactly the `if wrote.is_err() { return ExitCode::SUCCESS; }` shape used at src/cli/logs.rs:190 and 732. Do the same for the `std::io::copy` result in `stream_range` (session.rs:545) so a closed pipe short-circuits the follow that follows it.

**Rectification du vérificateur.** Mechanism is correct; severity overstated as high. Nothing is mis-printed and no data is lost (`*pos` still advances, so there is no duplication when writes fail) — the only symptom is that `sbx session logs <id> -f | head` leaves the shell blocked on the pipeline until the detached agent exits, and Ctrl-C clears it. That is a hang/robustness defect, not a correctness-of-output one, so medium.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified line-by-line. src/cli/session.rs:713-716 is exactly `let mut out = std::io::stdout(); let _ = out.write_all(&buf); let _ = out.flush(); *pos += buf.len() as u64;` — `drain_log` returns `()`, so `follow_log` (src/cli/session.rs:684-693: `loop { let live = session_is_live(..); drain_log(path, &mut pos); if !live { return } sleep(FOLLOW_POLL) }`) cannot observe EPIPE and spins at FOLLOW_POLL = 250ms (src/cli/session.rs:255) until the session dies. I looked for the obvious refutations and none hold: (a) `grep -rn 'SIGPIPE|SIG_DFL' src tests` returns only comments — nothing anywhere restores SIG_DFL, so the process is not killed by the signal; (b) `*pos` is advanced by `buf.len()` even when the write failed, so the next poll early-returns at src/cli/session.rs:703 and the loop is a silent 250ms spin, not a retry; (c) no test covers `follow_log`/`drain_log` (grep shows the only references are session.rs:644, 684, 687, 698) and no comment excuses write failures — `drain_log`'s doc (session.rs:695-697) only excuses *read* failures. The codebase states the opposite discipline for its sibling loops and acts on it: src/cli/logs.rs:190-193 `if wrote.is_err() { // A closed downstream pipe (`… | head`) ends the follow cleanly. return ExitCode::SUCCESS; }`, the same at logs.rs:147, 677, 732, and src/cli/net.rs:1561-1563 "Rust ignores SIGPIPE, so a write to a gone reader returns an error we must act on rather than spin forever". `stream_range`'s `let _ = std::io::copy(...)` at src/cli/session.rs:545 is real too and feeds straight into the same follow.

</details>

---

### B5 — Two tasks naming different versions of one tool can never both be satisfied; the pool config flips every launch and one task fails with "command not found"
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/sandbox/taskpool.rs:210` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | Concurrence, verrous, pools |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `bins_for` requires `recorded.get(locator).map(String::as_str) == Some(wanted_spec(wanted))` for *every* declared token. `recorded_specs` returns a `BTreeMap<String, String>` keyed by locator (taskpool.rs:148-172), so it holds **at most one** spec per tool — as does mise's `[tools]` table it is read from. Therefore when two tasks in one project declare `node@22` and `node@24`, at most one of the two tokens can ever have `pinned == true`, and the other is pushed onto `missing` forever, regardless of what is actually installed on disk.

That is not hypothetical for this codebase: `upgrade_argv`'s own test fixture is `["node@22", "aqua:cli/gh", "node@24"]` (taskpool.rs:846-860), with a doc line explaining that duplicates collapse because "two tasks sharing a tool roll it once".

Worse, `ensure` re-runs the install with only the currently-missing set (`mise use -g node@22`), which rewrites `[tools] node` to the *other* value — so the pin oscillates launch to launch and the guard that exists to detect drift can never converge. The comment at taskpool.rs:186-194 argues "failing *toward* re-running is cheap"; here re-running provably cannot fix the state.

**Scénario.** A project declares `[task.a] packages = ["mise:node@22"]` and `[task.b] packages = ["mise:node@24"]`. `declared_packages()` yields both. Launch 1: `missing` is both, the install cage runs `mise use -g node@22 node@24`, config ends up `node = "24"`. `bins_for` now reports `node@22` missing, so `sbx task invoke a` gets `pool_bins() == None` (no shims on PATH) and fails with `node: command not found`, while `b` works. Launch 2: `ensure` sees `missing = ["node@22"]`, runs a full install cage again, config flips to `node = "22"` — and now task `b` is the one that fails. The project never reaches `PoolOutcome::Warm`, so every single launch pays a bwrap+mise install-cage run before the agent starts.

**Correction proposée.** Detect the conflict instead of looping on it. In `bins_for` (or at config-resolve time in `TaskEngine::declared_packages`), group tokens by locator and refuse — or warn once and pick a single spec — when one locator carries two different `wanted_spec` values, e.g.:

```rust
let mut pinned_by: HashMap<&str, &str> = HashMap::new();
for token in tokens {
    let (locator, wanted) = split_version(token);
    if let Some(prev) = pinned_by.insert(locator, wanted_spec(wanted))
        && prev != wanted_spec(wanted) {
        // one pool, one global mise config: this can never be satisfied
    }
}
```

A declaration that cannot be realised should be reported once as a configuration error, not turned into an install cage that runs on every launch forever.

**Rectification du vérificateur.** Severity overstated and one part of the mechanism is speculative. The oscillation ("the pin flips launch to launch") assumes `mise use -g node@22` rewrites the whole `[tools] node` entry last-wins; mise also supports an array form (`node = ["22", "24"]`), which `recorded_specs`'s line-wise parse (taskpool.rs:167-171) would read as the literal value `["22", "24"]` and match against neither token. In that case there is no flip — both tokens stay missing and *both* tasks lose their shims, which is a different (and worse) shape than described. Also note the conflict is inherent, not just unhandled: one pool means one global mise config and one `shims/` directory, and mise cannot put two versions of one tool on one PATH either. The real defect is therefore the missing detection — sbx accepts an unsatisfiable declaration silently and converts it into an unbounded per-launch install-cage run — not that the two versions "should" both work. Finally, the reporter's own example (`node@22` / `node@24`) is confounded by the partial-version/symlink problem in the previous finding: with those tokens neither side is ever `realized`, so the conflict only produces the described one-wins/one-loses split for exact versions.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The mechanism checks out. `recorded_specs` returns `BTreeMap<String, String>` keyed by locator (taskpool.rs:151-175), so `recorded.get(locator)` yields at most one spec, and taskpool.rs:210 requires it to equal `wanted_spec(wanted)` for every declared token — so of `node@22.3.0` and `node@24.4.1`, at most one can ever be `pinned`. Nothing upstream groups by locator or objects: `declared_packages` (task.rs:515-523) dedupes only byte-identical tokens, `validate_task_packages` (config/tasks.rs:565-567) likewise, and `ensure` (taskpool.rs:270-297) re-runs the install cage with whatever `bins_for` still calls missing, with no convergence check. So the state is genuinely non-convergent: `bins_for(...).missing` is never empty, `ensure`'s short-circuits at taskpool.rs:264 and 276 never fire, and launch.rs:5151 pays a bwrap+mise install-cage run on every single launch while `pool_bins` (task.rs:1318-1325) returns `None` for the losing task. No comment or doc declares this limitation — docs-site/docs/guide/tasks/execution.md:243-245 says only that the pool is shared, not that one tool may carry one version.

</details>

---

### B6 — A `ready.tcp` outside u16 fails the untagged `RawService` parse and drops the whole config layer
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/config/schema.rs:1159` |
| **Catégorie** | `error-handling` |
| **Sous-système** | Configuration — modèle, schéma, types |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `RawServiceReady::tcp` is a `u16`, and `RawServiceReady` sits inside `RawServiceTable`, which is a variant of the **untagged** enum `RawService` (schema.rs:1036-1043). A value TOML accepts as an integer but serde cannot fit into a `u16` therefore fails both untagged variants, which fails `RawConfig`/`RawApp` as a whole, and `read_layer` (load.rs:615-623) turns that into `warnings.push("ignoring <path>: …")` and returns `None` — the entire layer is discarded. This is precisely the failure the rest of the schema is written to avoid: `RawForward::Port` is an `i64` and says so ("a value this layer refuses fails the untagged-enum parse and drops the *whole* config layer (env, packages, apps and all) … `forward = [70000]`, a port typed with one digit too many, took the config down with it", schema.rs:489-494), and `RawFs::scan_max_kb` (schema.rs:661-666) and `RawLimit::Number` (schema.rs:569-575) are signed for the same stated reason. The downstream validator already expects to do the range work — `service_ready` (validate.rs:963) refuses `tcp == 0` with a per-entry warning — but a `u16` guarantees it can never see the other end of the range.

**Scénario.** A project `.sbx.toml` containing `[env]\nKEEP = "yes"`, an `[fs] deny = [".env"]` mask, and `[service.gateway]\ncmd = ["hermes","gateway","run"]\nready = { tcp = 70000 }` fails `schema::parse` with "data did not match any variant of untagged enum RawService". The whole layer is dropped: the env var, the packages, every `[app.*]`, and the `[fs]` mask that was closing `.env` to the cage — all gone from one mistyped digit, where the same mistake in `forward = [70000]` is a named per-entry warning. The same typo in an `apps/<name>.toml` profile fails `parse_app` and takes the whole app with it.

**Correction proposée.** Hold the port as an `i64` like `RawForward::Port` (`pub(crate) tcp: i64`) and move the range check next to the existing `tcp == 0` check in `validate::service_ready`, warning `ignoring `ready` of `[service]` entry `<name>` — <n> is not a port in 1-65535` and dropping only the gate.

**Rectification du vérificateur.** Mechanism confirmed; severity overstated as high. Two corrections. (1) The cited validate line is 964, not 963 (off by one). (2) The authors were already aware of this field's fragility from the other direction: src/config/manage.rs:751-755 enumerates `RawServiceTable.cmd`, `RawServiceReady.tcp`, `RawOpenTable.cmd`, `RawInlineFlake.flake` by name as "required field with no `#[serde(default)]`" and makes `unset` validate the whole layer before committing (test at manage.rs:2421). So the gap is specifically the hand-edited path and the out-of-range value, not the field's existence; and the effect is a warning naming the file plus a silently reverted layer, the same cost the `forward` test treats as a bug worth fixing.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified. src/config/schema.rs:1159 is exactly `pub(crate) tcp: u16,` inside `RawServiceReady`, which is reached only through `RawServiceTable::ready` (schema.rs:1051-1050 region, field at 1050-1051) inside the untagged enum `RawService` (`#[serde(untagged)]` at schema.rs:1037, variants `Argv(RawCmd)` / `Detailed(RawServiceTable)` at 1039-1042). `RawCmd` is `Line(String) | Argv(Vec<String>)` (schema.rs:990-996), so a table never matches the first variant; `tcp = 70000` fails the second, so the untagged parse fails and `schema::parse` (schema.rs:2069) errors for the whole document. `read_layer` (src/config/load.rs:614-621) turns that into `warnings.push(format!("ignoring {}: {e}", path.display()))` and returns `None`, discarding the layer. The house rule the reporter cites is real and enforced elsewhere: schema.rs:489-494 states it verbatim, `RawForward::Port` is `i64` (schema.rs:499), `RawLimit::Number` is `i64` (schema.rs:576), `RawFs::scan_max_kb` is `Option<i64>` (schema.rs:666), and there is a dedicated regression test `a_forward_port_out_of_range_is_skipped_rather_than_dropping_the_layer` at src/config/tests.rs:2103-2117. The downstream gate can only ever see the low end: `if gate.tcp == 0` at src/config/validate.rs:964. No caller, invariant or earlier validation prevents an out-of-range integer from reaching serde. `service` is present on RawConfig (schema.rs:97), RawApp (457) and RawBundle (870), so app profiles are affected too.

</details>

---

### B7 — `RawTask` carries no unknown-key bag, so a misspelled `spawn` silently disables exec supervision
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/config/schema.rs:1418` |
| **Catégorie** | `inconsistency` |
| **Sous-système** | Configuration — modèle, schéma, types |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : moyenne) |

**Constat.** `RawTask` is the only significant table in the schema with no `#[serde(flatten)] rest: BTreeMap<String, RawIgnored>` — `RawConfig`, `RawApp`, `RawBundle`, `RawLimits`, `RawSeccomp`, `RawDevices`, `RawSshAgent`, `RawFs`, `RawRedact`, `RawPluginConfig`, `RawBrokerConfig`, `NetworkTable`, `ProcTable`, `NotifyTable` and even `RawTaskExecNode` (this table's own child, schema.rs:1563) all have one, each with a comment saying why silence is the worse half of the trade (`RawTaskExecNode`: "a node that means less than it says is the one failure this whole field exists to avoid"). `tasks.rs` reports unknown keys only for the exec node (tasks.rs:444); nothing walks a `[task.<name>]` table's own keys. The authors were aware of the silence and answered it per-key for two look-alikes only (`allow`/`deny`, schema.rs:1498-1505, "Present only so a task declaring them is refused rather than parsing into silence") — which leaves a misspelling of a *real* field unanswered, and `spawn` is the field where that costs a control: "Absent means no exec supervision at all" (schema.rs:1483-1489).

**Scénario.** A `[task.deploy]` block written `cmd = ["git", "push"]` / `spwan = ["ssh"]` parses cleanly, `spawn` resolves to `None`, and the task runs with **no exec supervisor at all** — the command may `execve` anything in the cage, with the task's credential in its environment — while the author believes they confined it to `git` plus `ssh`. Nothing is warned. The same typo one level down (`[task.deploy.exec.git] spwan = […]`) is refused by name.

**Correction proposée.** Add `#[serde(flatten)] pub(crate) rest: BTreeMap<String, RawIgnored>` to `RawTask` and report its keys in `tasks::apply_task_section`, in the same shape as the existing `node.rest` report at tasks.rs:444.

**Rectification du vérificateur.** Survives, but the reporter missed that the omission is documented, and overstated the uniqueness. (1) src/config/mod.rs:2933-2934 states the exclusion deliberately: "A `[task.<name>]`/`[app.<name>]` entry's own fields are not walked here — those carry a `cmd` whose absence already fails loudly." That rationale does not hold for the reported case: `RawTask::cmd` is `#[serde(default)] Vec<String>` (schema.rs:1425-1426), so a missing `cmd` is caught at src/config/tasks.rs:195, not at parse — and a misspelled `spawn` is caught nowhere. The app half of that sentence is also already answered by `warn_unknown_app_keys`, which is what makes tasks the odd one out. (2) `RawTask` is not the only table without a bag: `RawTaskDefaults` (schema.rs:1396) has none either.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified. `RawTask` begins at src/config/schema.rs:1418 and its derive at 1417 is `#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]` with no `deny_unknown_fields`; reading the full body (1418-1520) confirms there is no `#[serde(flatten)] rest`, while its own child `RawTaskExecNode` has one at schema.rs:1559-1560 and reports it at src/config/tasks.rs:444. The only global unknown-key walker, `warn_unknown_keys` (src/config/mod.rs:2935), reports `raw.rest`, `[limits]`, `[seccomp]`, `[devices]`, `[ssh_agent]`, `[redact]` and `[fs]` — and its doc at mod.rs:2933-2934 explicitly excludes task entries. Apps get their own walker (`warn_unknown_app_keys`, mod.rs:2982, called at mod.rs:3405 and 3568); tasks get none — grep finds no unknown-key report for `[task.<name>]` anywhere. The consequence is confirmed by the project's own test: src/config/tasks.rs:1262-1265, `assert_eq!(absent.spawn, None, "absent means no supervision at all")`. So `spwan = ["ssh"]` parses, is dropped, and the task runs unsupervised with nothing said.

</details>

---

### B8 — A `[service]`/`[open]` table missing its `cmd`, or an `enable` missing `env`, drops the whole config layer
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/config/schema.rs:1053` |
| **Catégorie** | `error-handling` |
| **Sous-système** | Configuration — modèle, schéma, types |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `RawServiceTable::cmd` (1053), `RawOpenTable::cmd` (1170) and `RawEnableCond::env` (1115) are required fields inside untagged enum variants (`RawService`, `RawOpen`, `RawEnable`). A table that omits one matches no variant, so the untagged parse fails and `read_layer` discards the entire config file — the same whole-layer cost `RawBindTable::path` was made `Option` to avoid: "Optional at the parse layer so a table missing its `path` — a typo, or the tell-tale of a wrongly-authored entry — is skipped with a per-entry warning downstream rather than failing the untagged-enum parse and dropping the *whole* config layer (env, packages, apps and all)" (schema.rs:530-535). The downstream validators are already written as if these arrive per entry and cannot: `validate_service` warns "it names no program to run" (validate.rs:833) and `service_enable` warns "a condition names no variable" (validate.rs:892) — branches only reachable via an explicitly empty `cmd = ""`/`env = ""`, never via the omitted key those messages read as describing.

**Scénario.** A global `sbx.toml` containing `[open.https]\nmode = "detach"` (the `cmd` line forgotten, or moved below the header) fails `schema::parse`; `read_global` warns once and returns `RawConfig::default()`, so every package, bind, network rule, secret and app in the global config is silently absent for that launch. Same for `[service.gateway]\nready = { tcp = 8100 }` with no `cmd`, and for `enable = { is = "1" }` with no `env`.

**Correction proposée.** Make the three fields optional at the parse layer (`cmd: Option<RawCmd>`, `env: Option<String>`) and let the existing downstream branches in `validate_service`/`validate_open`/`service_enable` drop the one entry with the warning they already carry.

**Rectification du vérificateur.** Survives, with two corrections to the reporter's framing. (1) The authors are not unaware of this shape — manage.rs:749-755 names these four fields explicitly and guards the `sbx config unset` write path (manage.rs:2417). The finding is therefore an unclosed gap on the hand-edited path, not an unnoticed one; the fix suggestion (make the fields optional) is still the one that matches `RawBindTable::path`. (2) The claim that the downstream branches are only reachable via an explicitly empty string is imprecise: src/config/validate.rs:833 tests `argv.is_empty() || argv[0].is_empty()`, so `cmd = []` reaches it too. Cited validate lines are off by one (the `enable` branch is 893, not 892; the service branch message is 835).

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified. src/config/schema.rs:1053 is `pub(crate) cmd: RawCmd,` in `RawServiceTable`, 1170 is `pub(crate) cmd: RawCmd,` in `RawOpenTable`, and 1115 is `pub(crate) env: String,` in `RawEnableCond` — all three required, no `#[serde(default)]`, all three inside untagged enums (`RawService` at 1037, `RawOpen` at 1018, `RawEnable` at 1087). `RawBindTable::path` is `Option` for precisely the stated reason (schema.rs:530-535). The decisive corroboration is the codebase's own words: src/config/manage.rs:749-755 says "several schema tables carry a required field with no `#[serde(default)]` (`RawServiceTable.cmd`, `RawServiceReady.tcp`, `RawOpenTable.cmd`, `RawInlineFlake.flake`), and `RawOpen`/`RawService` are `#[serde(untagged)]`, so a table left without its required field matches no variant at all", and the test at manage.rs:2417-2440 uses exactly the reporter's `[open.https]` example, commenting "the whole layer — the `network = \"deny\"` posture included — would stop parsing" and "the loader drops the WHOLE layer with only a warning, silently reverting every security field it carried". That guard covers only `sbx config unset`; nothing guards a hand-edited file, so the path from a forgotten `cmd` line to a dropped global layer is unobstructed.

</details>

---

### B9 — A `match` bound rejects values its own regex accepts, because `find` is leftmost-first, not anchored
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/config/tasks.rs:669` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | Configuration — couches, overrides, validation |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `check_value` claims to anchor an unanchored pattern by requiring the found match to span the whole value: "A pattern must match the **whole** value: an unanchored regex would accept anything containing a match, so the check anchors it here rather than trusting the author to have written `^…$`." But `Regex::find` returns the *leftmost-first* match, not the longest one at that position. The regex 1.13 docs state this with a worked example: `Regex::new("sam|samwise").find("samwise")` returns `"sam"`. So whenever an alternation's earlier branch is a prefix of a later one — or a lazy quantifier is used — `m.end() != value.len()` and the value is refused even though the pattern plainly matches it whole. The comment describes anchoring; the code implements "the preferred match happens to be full-span".

**Scénario.** Declare `[task.deploy.params] target = { match = "prod|prod-eu|staging" }`. Invoking the task with `target = "prod-eu"` is refused with `parameter \`target\` does not match its declared pattern` — leftmost-first picks `prod` (0..4) against a 7-byte value. Worse, add `default = "prod-eu"` to the same declaration: `validate_params` runs the same `check_value` on the default (tasks.rs:606), `validate_task` returns `Err`, and `apply_task_section` drops the entire task at config load with `ignoring task \`deploy\` — parameter \`target\` does not match its declared pattern`. A perfectly valid declaration silently disappears from the task list.

**Correction proposée.** Anchor the pattern once and match on the anchored form, in both places that compile it. In `compile_bound` build and validate the anchored source (`format!(r"(?s:\A(?:{pattern})\z)")`, so an author's own `^`/`$` still behave and an invalid pattern is still caught at declaration), and in `check_value` compile that same anchored source and use `re.is_match(value)` instead of inspecting `find`'s span.

**Rectification du vérificateur.** Survives, with two corrections. (1) The check on the default is at tasks.rs:598, not 606 — the reporter's in-prose cite is off by eight lines (the anchor cite, 669, is exact). (2) Severity is medium, not high: the defect is strictly fail-CLOSED. A full-span `find` result proves the pattern really does match the whole value, so no value is ever wrongly ACCEPTED; the only outcomes are a valid caller value refused at invocation, or a task with a `default` dropped at load — and the drop is not silent, it emits `ignoring task `<name>` — parameter `<p>` does not match its declared pattern` (tasks.rs:68). Note also a second, milder inconsistency the reporter did not mention: schema.rs:1611 documents the terse form as "the pattern the value must match, anchored by the author", which contradicts tasks.rs:649-651's claim that the check anchors it; the two comments disagree about who owns the anchoring, and the code implements neither cleanly.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Cite is exact. src/config/tasks.rs:669-671 is `match re.find(value) { Some(m) if m.start() == 0 && m.end() == value.len() => Ok(()), _ => Err(...) }`, under the doc at tasks.rs:649-651 that claims "the check anchors it here rather than trusting the author to have written `^…$`". The regex crate vendored in Cargo.lock is 1.13.1, and its own docs pin leftmost-first preference order with the exact worked example the reporter cites — ~/.cargo/registry/src/*/regex-1.13.1/src/lib.rs:726-732: `Regex::new(r"sam|samwise")` on "samwise" yields "sam". So for `match = "prod|prod-eu|staging"` and value "prod-eu", `find` returns 0..4, `m.end() != 7`, and check_value returns `parameter `target` does not match its declared pattern` even though the pattern matches the whole value. Nothing upstream anchors: compile_bound (tasks.rs:640-644) stores `pattern.to_string()` verbatim and only checks that it compiles, and no caller rewrites it (src/sandbox/task.rs:2217 passes the stored bound straight in). No test covers the case — `a_pattern_bound_must_match_the_whole_value` (tasks.rs:1203-1210) only uses the alternation-free `"SELECT"`. The docs promise whole-value matching (docs-site/docs/guide/tasks/parameters.md:114, "it must match the whole value"), so the behaviour contradicts the documented contract, and the load-time half is real too: a `default` goes through the same gate at tasks.rs:598, so validate_task returns Err and apply_task_section drops the whole task with `{source}: ignoring task `{name}` — …` (tasks.rs:68). Lazy quantifiers hit the same wall (`a.*?` never spans a 3-byte value).

</details>

---

### B10 — A higher override tier's `[ssh_agent] confirm` is silently discarded whenever a lower tier also declares `[ssh_agent]`
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/config/overrides.rs:648` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | Configuration — couches, overrides, validation |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `union_allow_opt` is generic over a table reached only through an `allow: &mut Vec<String>` accessor, and its `(Some(b), Some(h))` arm (overrides.rs:706-710) moves `h`'s `allow` into `b` and returns `b` — every other field of `h` is dropped. That is exact for `RawSeccomp` and `RawDevices`, which hold only `allow` plus the unknown-key bag (schema.rs:599-621), but `RawSshAgent` also carries `confirm: Option<bool>` (schema.rs:713). Its doc even says "the flag ORs across layers — a layer that asks for confirmation cannot have it turned off by another", and `apply_ssh_agent` reads it (mod.rs:3017) into `self.ssh_agent_confirm |= confirm`. The higher tier's value never reaches it. The function's own doc calls all three tables `{ allow: Vec<String> }`, which is what hid this. This is the fourth instance of the exact silent-field-drop that drove `overlay_into` and `union_fs_opt` to exhaustive destructuring; `union_allow_opt` is the one fold that still reads a single field by hand. The regression test at overrides.rs:2248 passes only one blob, so it takes the `(None, h)` arm and never exercises the drop.

**Scénario.** `sbx --config '[ssh_agent]\nallow = ["SHA256:aaa…"]' --config '[ssh_agent]\nallow = ["SHA256:bbb…"]\nconfirm = true' run …` — two CLI blobs, no environment needed. Tier 2 folds blob 1 then blob 2 through `overlay_into`, `union_allow_opt` returns blob 1's table with blob 2's key appended, and `confirm` is `None`. The launch grants both keys with no per-signature prompt, despite `confirm = true` on the command line. The inverse is equally wrong: `SBX_CONFIG` setting `confirm = true` beats a `--config` setting `confirm = false`, so the lower tier decides the field in both directions.

**Correction proposée.** Fold `confirm` at the call site where the type is known: `base.ssh_agent = union_ssh_agent_opt(base.ssh_agent, ssh_agent)` with a dedicated function that destructures `RawSshAgent` exhaustively and ORs `confirm` (`b.confirm = match (b.confirm, h.confirm) { (Some(true), _) | (_, Some(true)) => Some(true), (a, None) => a, (None, c) => c }`), keeping `union_allow_opt` for the two tables that really are `{ allow }`. Fix its doc at the same time.

**Rectification du vérificateur.** Survives, but the mechanism is half-overstated and the severity is medium rather than high. Only ONE of the reporter's two directions is a defect: a higher tier's `confirm = true` being lost when a lower tier also declares `[ssh_agent]` (blob 1 `allow`, blob 2 `confirm = true` → merged confirm is None → no per-signature prompt). The "inverse" they call "equally wrong" — `SBX_CONFIG` `confirm = true` beating a `--config` `confirm = false` — is precisely the documented OR rule (schema.rs:710-711, mod.rs:1156-1157: "an invoker may add the prompt, and the one place it must not be possible to remove it is the most convenient one to try"); tier precedence deliberately does not apply to this field. Medium because the fail-open outcome needs two override tiers to BOTH declare `[ssh_agent]` — a single blob takes the `(None, h)` arm and keeps `confirm`. One addition in the reporter's favour: the same arm also drops `h.rest`, the unknown-key bag that union_fs_opt's doc (overrides.rs:658) says must ride along; harmless only because warn_unknown_keys already fires per blob at overrides.rs:313/342.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every cite checks out. overrides.rs:648 is `base.ssh_agent = union_allow_opt(base.ssh_agent, ssh_agent, |s| &mut s.allow);`, and union_allow_opt's `(Some(mut b), Some(mut h))` arm at overrides.rs:706-710 moves only `allow` out of `h` and returns `b`, so `h.confirm` is dropped. RawSshAgent really does carry a third field: schema.rs:713 `pub(crate) confirm: Option<bool>`, whose doc at schema.rs:706-711 states "the flag ORs across layers — a layer that asks for confirmation cannot have it turned off by another". RawSeccomp (schema.rs:599-605) and RawDevices (schema.rs:615-621) are genuinely `{ allow, rest }`, so union_allow_opt's own doc at overrides.rs:694 ("Union two optional `{ allow: Vec<String> }` tables (`[seccomp]` / `[devices]` / `[ssh_agent]`)") mis-describes only the third. The dropped value is load-bearing: apply_ssh_agent reads `raw.confirm.unwrap_or(false)` (mod.rs:3017) and apply_override ORs it in at mod.rs:1158. The fold path is as described — collect_from folds repeated `--config` blobs with `t2 = overlay_into(t2, parsed)` (overrides.rs:343) and then the two sides with `overlay_into(env_side, cli_side)` (overrides.rs:377). The regression test really does pass a single blob (overrides.rs:2253-2258), so it takes the `(None, h)` arm and never exercises the drop.

</details>

---

### B11 — The override plane folds `[fs] scan_max_kb` with `min` while the layer merge it cites uses `max`, so the environment beats the command line
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/config/overrides.rs:684` |
| **Catégorie** | `inconsistency` |
| **Sous-système** | Configuration — couches, overrides, validation |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `union_fs_opt` folds `scan_max_kb` with `a.min(c)`, and its doc (overrides.rs:660-662) says it "folds by the rule its own layer merge uses ([`crate::config::fspolicy`]): the tighter ceiling wins, because a tier raising it would widen what a lower one had narrowed." `fspolicy::FsPolicy::union` does the opposite — `a.max(b)` (fspolicy.rs:108) — under a long comment (fspolicy.rs:93-107) that spells out why: `scan_max_kb` is how many bytes of a file the content lens reads, so a *larger* number closes more files and "taking the minimum therefore let a layer widen what another had narrowed". Its test `a_union_can_only_ever_widen_the_scan_window_never_shrink_it` (fspolicy.rs:412) pins that. The override side's own test (overrides.rs:2342) asserts `Some(64)` under the comment "the tighter ceiling wins, the rule the layer merge already applies", so a test encodes the inverted rule. Beyond the divergence, `min` breaks this module's stated precedence — "any CLI input beats any environment one" (overrides.rs:36) — for this one field.

**Scénario.** With `SBX_CONFIG='[fs]\nscan = ["AKIA[0-9A-Z]{16}"]\nscan_max_kb = 1'` left in the environment by a wrapper, run `sbx --config '[fs]\nscan_max_kb = 512' run …`. `union_fs_opt(Some(fs_env), Some(fs_cli))` yields `Some(1)`; `apply_override` then does `self.fs.union(over)` (mod.rs:1151), which maxes against the config layers — with none set, the launch scans one KiB per file. The invoker explicitly asked for 512 KiB on the command line and got the stale ambient 1 KiB, so every credential past the first line of a file passes.

**Correction proposée.** Change `Some(a.min(c))` to `Some(a.max(c))` at overrides.rs:684, correct the doc at overrides.rs:660-662 to state the widening rule and why, and update the assertion at overrides.rs:2342 to `Some(512)` with the reason `fspolicy.rs:93-107` gives.

**Rectification du vérificateur.** Survives; severity medium is right, and there is stronger corroboration than the reporter found. src/config/tests.rs:6581-6613 shows this is the leftover half of a completed fix: "The name this test used to carry — 'the tighter ceiling wins' — was the misreading itself, and it pinned the fold at `min`… the *larger* number is the tighter policy: it closes more files." The layer fold was deliberately flipped min→max and the override fold at overrides.rs:685 was not, which is why the stale comment and stale assertion survive verbatim in overrides.rs. Two small cite corrections: the `min` is on overrides.rs:685 (the `match` statement opens at 684), and `self.fs.union(over)` is mod.rs:1150, not 1151. One scope limit worth stating: both inputs here are invoker-supplied, so the untrusted-project threat fspolicy.rs:100-104 describes does not apply on this plane — the concrete harm is the narrower one the reporter names, an ambient SBX_CONFIG ceiling beating an explicit `--config` one, which also breaks the module's own precedence rule at overrides.rs:36.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The divergence is real and every cite lands. overrides.rs:684-687 folds `(Some(a), Some(c)) => Some(a.min(c))`, under a doc at overrides.rs:660-662 asserting it "folds by the rule its own layer merge uses ([`crate::config::fspolicy`]): the tighter ceiling wins". fspolicy::FsPolicy::union does the opposite at fspolicy.rs:108-109, `(Some(a), Some(b)) => Some(a.max(b))`, under a comment at fspolicy.rs:91-107 that states the direction explicitly ("The **larger** window wins… a bigger number closes *more* files… Taking the minimum therefore let a layer widen what another had narrowed") and is pinned by fspolicy.rs:412 `a_union_can_only_ever_widen_the_scan_window_never_shrink_it`. The semantics check out downstream: launch.rs:3929-3933 turns scan_max_kb into the OpenPolicy `ceiling`, i.e. bytes examined before an open is let through. The override side's test at overrides.rs:2340-2342 asserts `Some(64)` under "The tighter ceiling wins, the rule the layer merge already applies", so the inverted rule is pinned by a test whose comment is false. The attack path holds: the folded `Some(1)` reaches `self.fs.union(over)` and, with no config layer setting the field, maxes against None to yield 1 KiB.

</details>

---

### B12 — `space_entries` deletes every comment inside an edited array and collapses it to one line
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/config/manage.rs:578` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | Configuration — édition en place et rendu |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `space_entries` rewrites the decor **prefix** of *every* element of the array, not just the one just appended:

```rust
fn space_entries(list: &mut Array) {
    for (i, entry) in list.iter_mut().enumerate() {
        entry.decor_mut().set_prefix(if i == 0 { "" } else { " " });
    }
}
```

It is called unconditionally from `add` (lines 465 and 471) and from `remove` (line 494). In `toml_edit` an array element's decor prefix holds the whitespace **and the comments** that precede it (`src/parser/array.rs`: `EventKind::Comment` is routed through `State::whitespace`, which appends to `current_prefix` whenever `current_value` is `None` — i.e. after the preceding comma). `encode_array` then emits `elem`'s explicit prefix verbatim. Setting the prefix to `""`/`" "` therefore destroys the newlines *and* the comments of every entry in the list.

This directly contradicts the module doc at line 5 ("preserving comments and formatting (`toml_edit`)") and the header of `add` ("leaving the rest of the list (and the file's comments) alone", cli/config.rs:2661). It is also an inconsistency with the sibling rule writers: `push_outcome` (line 1249) uses `Array::push`, which decorates only the new element and leaves a hand-formatted list intact — so `sbx net allow` preserves a commented list while `sbx config add fs.deny` shreds it. No test covers a multi-line or commented array; `add_creates_the_list_appends_to_it_and_is_idempotent` (line 2040) only builds a list from scratch, which is the single case `space_entries` was written for. The repo's own `examples/net-groups/*.toml` ship exactly the shape that gets destroyed (`chromium-background = [ "clients2.google.com", # component updater ... ]`).

**Scénario.** Given `.sbx.toml`:

```toml
[fs]
deny = [
    ".env",             # local secrets
    "config/prod.key",  # never readable in the cage
]
```

run `sbx config add fs.deny id_rsa`. The command reports success and the file becomes:

```toml
[fs]
deny = [".env", "config/prod.key", "id_rsa",
]
```

Both comments — the documentation of *why* each path is masked — are gone, and the list is collapsed onto one line. `sbx config rm fs.deny .env` does the same damage. The user is never told anything was removed.

**Correction proposée.** Only decorate the entry that was just appended, and only when the array is already single-line. E.g. in `add`, replace `space_entries(list)` with a call that touches the pushed element alone (`if list.len() > 1 { last.decor_mut().set_prefix(" ") }`), and drop the call from `remove` entirely — removal never runs entries together. Detect the multi-line case (any existing element whose prefix contains `'\n'`) and leave the array untouched, letting `Array::push` supply the default decor as `push_outcome` already does.

**Rectification du vérificateur.** The mechanism is confirmed, but the reporter's sample output is slightly wrong and the severity is a notch high. A comment that follows the LAST element sits in the array's `trailing` decor (`State::close`), which `space_entries` never touches — so in their `fs.deny` example `# never readable in the cage` survives, now dangling after the newly appended `"id_rsa"`, while `# local secrets` (which lives in the prefix of the following element) is destroyed. In general: every comment after a non-final comma is lost, the final one survives but is re-anchored to the wrong entry, and the array collapses to one line. The proposed fix's premise is also slightly off — `Array::push` in toml_edit 0.25.13 (`src/array.rs:176`) does not apply formatting itself; the ` `/`` separators come from `DEFAULT_VALUE_DECOR`/`DEFAULT_LEADING_VALUE_DECOR` in `encode_array` when an element's decor is unset, which is why simply not calling `space_entries` on a freshly-pushed value already renders correctly. Impact is loss of user annotations in a config file, not a wrong security decision, so medium rather than high.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified end to end. `src/config/manage.rs:577-582` is `fn space_entries(list: &mut Array) { for (i, entry) in list.iter_mut().enumerate() { entry.decor_mut().set_prefix(if i == 0 { "" } else { " " }); } }` — it rewrites the prefix of EVERY element, and it is called unconditionally at lines 465, 471 (in `add`) and 494 (in `remove`). In toml_edit 0.25.13 the array parser routes `EventKind::Comment` through `State::whitespace` (`src/parser/array.rs:69`), which appends to `current_prefix` whenever `current_value` is `None` — i.e. everything between one comma and the next value, comments included, becomes that next element's decor prefix (`finish_value`: `decor.set_prefix(RawString::with_span(prefix…))`). `DocumentMut::despan` turns those spans into explicit strings, and `encode_array` (`src/encode.rs:130-138`) emits each element's explicit prefix verbatim. So `set_prefix(" ")` provably destroys the newline and any comment that preceded that entry. Nothing gates it: `add` returns early on an already-present entry and `remove` returns early on an absent one, so the damage happens exactly on a real edit. The behaviour contradicts three written promises: the module doc `src/config/manage.rs:5` ("preserving comments and formatting"), the `config add`/`rm` header `src/cli/config.rs:2660-2661` ("leaving the rest of the list (and the file's comments) alone"), and the guide `docs-site/docs/guide/cli/config.md:141` ("preserving its other keys, its comments and its formatting"). The only comment near the call (lines 462-464) justifies spacing an APPENDED entry, not rewriting existing ones, and the only test, `add_creates_the_list_appends_to_it_and_is_idempotent` (line 2040), builds the list from scratch. The repo ships the exact vulnerable shape in `examples/net-groups/chromium-background.toml` (a `[network.groups]` array with a trailing comment per host), and `rule_list_verb` does not divert `network.groups.<name>` to a dedicated verb, so `sbx config add network.groups.chromium-background <host>` goes through this path.

</details>

---

### B13 — LONGEST_SOCKET_SUFFIX omits the broker plugin socket, so DATA_DIR_MAX does not bound sun_path
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/store.rs:323` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | Point d'entrée, diagnostics, store, chemins |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `LONGEST_SOCKET_SUFFIX` (src/store.rs:323) is fixed at 33 bytes from a comment (src/store.rs:313-322) that claims "Every feature that binds an `AF_UNIX` socket under the data directory contributes one; the widest is what the cap must reserve for." It lists four families. The tree has at least ten, and the one it omits is the only *unbounded* one: `sandbox::broker::host_socket` (src/sandbox/broker.rs:1577) builds `<data>/broker/<pid>/<name>.sock` and `UnixListener::bind`s it at src/sandbox/broker.rs:1660. With a 7-digit pid that suffix is `21 + name.len()` bytes, so any broker whose `[broker.<name>]` key is 13 characters or longer exceeds 33. There is no length bound on the name: `plugins::validate_install_name` (src/plugins/mod.rs:1597) checks charset and leading dot only, and `config::is_valid_app_name`'s 64-byte cap does not apply to broker keys. The tests at src/store.rs:2321-2353 only compare a synthetic path against `LONGEST_SOCKET_SUFFIX` itself, so nothing holds the constant against a real socket path. (The list is also mislabelled: line 318 calls `/fs/control-<pid>.sock` "exec-enforcement control", but per DATA_ENTRIES in src/paths.rs `fs/` is filesystem observation and `proc/` is exec enforcement.)

**Scénario.** DATA_DIR_MAX is 107 − 33 = 74. Set `SBX_DATA_DIR` to a 74-byte absolute path — accepted by `check_data_dir_override`, which reports it fits "because sbx binds sockets under it". Declare `[broker.postgres-primary]` (16 chars) and launch with pid 1234567 (kernel.pid_max is 4194304 on a modern host). The bind path is 74 + len("/broker/1234567/")=16 + 16 + len(".sock")=5 = 111 > 107, so `UnixListener::bind` at src/sandbox/broker.rs:1660 fails with `InvalidInput: path must be shorter than SUN_LEN` and the launch reports a broker socket error — exactly the "fails at launch … with a message about a socket rather than about the directory" outcome `check_data_dir_override` exists to prevent, on a directory it explicitly approved.

**Correction proposée.** Either widen the sample so the constant reserves for the widest real bind — include `/broker/<pid>/<name>.sock` with the maximum permitted broker-name length — or, better, bound the broker name so the family is fixed-width (add a length cap to `plugins::validate_install_name` and to the `[broker.<name>]` key validation) and add the broker path to the enumerated list. Also correct the `fs/` label on src/store.rs:318, and add a test that measures the real socket-path builders against `LONGEST_SOCKET_SUFFIX` rather than restating the constant.

**Rectification du vérificateur.** Mechanism confirmed; one citation is two lines off — `host_socket` is src/sandbox/broker.rs:1575-1577, not 1577. Trigger needs both a data directory near the 74-byte cap and a broker key of ~13+ characters (16+ at a typical 4-digit pid), so it is an edge case, but it defeats an invariant the code states in its own comment and lands the user with the exact socket-shaped launch failure the guard was written to convert into a directory-shaped one.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Traced end to end and found nothing preventing it. src/store.rs:323 `const LONGEST_SOCKET_SUFFIX: usize = "/forward/fwd-1234567/p-65535.sock".len();` (33), src/store.rs:326 `DATA_DIR_MAX = SUN_PATH_MAX - LONGEST_SOCKET_SUFFIX` (74), enforced at store.rs:346 (`check_data_dir_override`) and store.rs:369 (`check_resolved_data_dir`). The enumeration at store.rs:313-322 ends with an explicit invariant — "A new feature whose host socket path is wider than this must widen the sample below, or a data directory the cap accepts would still overrun `sun_path` at that feature's first launch" — so the comment supports the finding rather than excusing it. The broker family violates it: `sockets_dir` = `<data>/broker/<pid>` (src/sandbox/broker.rs:1570-1572), `host_socket` appends `<name>.sock` (src/sandbox/broker.rs:1575-1577), and `UnixListener::bind(&host_uds)?` at src/sandbox/broker.rs:1660 uses `layout.data_dir()` (broker.rs:1658). Suffix = 21 + name.len() with a 7-digit pid, so a 13-char broker key already exceeds 33. No length bound exists on the key: `resolve_brokers` (src/config/mod.rs:4112-4200) validates `socket`, `secret` and unknown keys but never the name's length, and `plugins::validate_install_name` (src/plugins/mod.rs:1597-1612) checks emptiness, leading dot and charset only. The bind error is fatal and socket-shaped: src/sandbox/launch.rs:4379-4382 prints `sbx: cannot start the `<name>` broker: {e}` and returns `ExitCode::FAILURE` — precisely the outcome check_data_dir_override says it exists to prevent (store.rs:331-336). The tests at src/store.rs:2321-2353 only restate `LONGEST_SOCKET_SUFFIX` against a synthetic path; no test measures a real builder. The secondary mislabel is also confirmed: store.rs:318 calls `/fs/control-<pid>.sock` "exec-enforcement control", while src/paths.rs:142/148 assign `proc/` = "per-launch exec-enforcement sockets" and `fs/` = "per-launch filesystem-observation sockets".

</details>

---

### B14 — `sbx task run <TAB>` completes app names instead of declared operations
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/cli/completion.rs:697` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | Aide et complétion shell |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `kind_of_metavar` maps the metavariable name `name` to `ValueKind::Apps` for every page except the two it overrides (`plugins`, `projects`):

    "name" | "app" | "profile" | "sketch" => ValueKind::Apps,

But four pages use `<name>` for something that is not an app. `task run` documents its operand as `("<name>", "the operation to run, as `sbx task list` shows it")` (src/help.rs:940) while its sibling `task list` documents `("<operation>", …)` (src/help.rs:885), which maps to `ValueKind::Tasks` — two pages for the same vocabulary that do not agree. `bundle` (src/help.rs:2178) and `bundle export` (2202) use `<name>…` for a bundle name; `net groups` (2246) and `net groups export` (2265) use it for an egress-group name. All five complete the machine's app profiles.

The comment on the merge branch in `candidates` (src/cli/completion.rs:201-203) even asserts the opposite: "`sbx bundle <TAB>` offers export|import alongside the bundle names" — it offers app names.

The sweep `every_value_position_is_completed_or_declared_unenumerable` only checks that `kind_of_metavar` returns *something*, so nothing pins which registry, and the bash/zsh integration sweeps only assert that command names appear.

**Scénario.** With an imported app profile `demo-app` and a config declaring `[task.deploy]`: `sbx task run <TAB>` offers `demo-app` and never offers `deploy`. Accepting the completion yields `sbx task run demo-app`, which is refused as an unknown operation (exit 125). Same for `sbx bundle <TAB>` and `sbx net groups <TAB>`, which list app names for a bundle/group operand.

**Correction proposée.** Add page-context overrides in `kind_of_metavar` next to the existing `plugins`/`projects` ones — `["task", "run"]` → `ValueKind::Tasks`; `bundle`/`net groups` need a Bundles/Groups vocabulary (or `NOT_ENUMERABLE` until one exists). Cheapest partial fix for the task case: rename the `task run` option row's `<name>` to `<operation>` in src/help.rs:940 so it agrees with `task list`.

**Rectification du vérificateur.** Mechanism confirmed; two refinements. (1) The merge in `candidates` (src/cli/completion.rs:204-209) still adds the page's own subcommands, so `sbx bundle <TAB>` and `sbx net groups <TAB>` do offer `export`/`import` — only the value half is the wrong registry; `task run` has no subcommands, so there the whole menu is wrong. (2) The exit code in the attack is plausible but incidental: `sbx task run <app-name>` is refused by the control plane and rendered through `render_result`, which returns `REFUSED_EXIT` = 125 (src/cli/task.rs:32, :862). The defect itself is a wrong-vocabulary completion, not a wrong exit.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified line-by-line. src/cli/completion.rs:697 is exactly `"name" | "app" | "profile" | "sketch" => ValueKind::Apps,` and the only page-context overrides in `kind_of_metavar` are src/cli/completion.rs:681 (`path.first() == Some(&"plugins")`) and :691 (`path.first() == Some(&"projects")`) — neither covers `task`, `bundle` or `net groups`. `operand_slots(["task","run"])` sees only the bare row at src/help.rs:939-942 (`("<name>", "the operation to run, as `sbx task list` shows it")`) because every other row on that page starts with `-` and is skipped at src/cli/completion.rs:585, so the single slot is `Value("name")` -> `ValueKind::Apps`. The sibling row src/help.rs:886 (`("<operation>", ...)`) maps through src/cli/completion.rs:700 to `ValueKind::Tasks`, which really does enumerate `[task.<name>]` blocks (registry test at src/cli/completion.rs:1512-1516) — so the two pages for one vocabulary genuinely disagree. The same applies to src/help.rs:2178-2180 (`bundle`), :2202-2204 (`bundle export`), :2246-2248 (`net groups`), :2265-2267 (`net groups export`); there is no Bundles/Groups variant in the `ValueKind` enum (src/cli/completion.rs:260-288). Nothing makes this deliberate: the doc comment on `NOT_ENUMERABLE` at src/cli/completion.rs:1688-1690 states the governing rule — "A name that means something enumerable on one page and not on another is settled in `kind_of_metavar`, which sees the page" — so these are unclosed holes, and the sweep at :1724 only asks that *some* kind is returned. The merge comment at src/cli/completion.rs:201-202 does claim "`sbx bundle <TAB>` offers export|import alongside the bundle names".

</details>

---

### B15 — `sbx projects <TAB>` never offers `list` or `rm`; `sbx proc pending <TAB>` never offers `allow`/`deny`
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/cli/completion.rs:797` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | Aide et complétion shell |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** A verb documented as an option row rather than as a page is lost twice over.

(a) `operand_slots` accumulates bare literal rows into `pure`, but discards `pure` entirely once any row also names a metavariable: `if !saw_value_row && !pure.is_empty() { return vec![Operand::Literal(pure)] }` (line 616). On the `projects` page the rows are `("list", …)` (src/help.rs:1847) then `("rm <id>...", …)` (src/help.rs:1851), so `list` lands in `pure`, `rm <id>...` sets `saw_value_row`, and `pure` is thrown away.

(b) `cursor_value_kind` then skips the surviving literal slot outright:

    while let Some(Operand::Literal(_)) = slots.get(pos) { pos += 1; }

so `Literal(["rm"])` at position 0 is jumped over and the `<id>` behind it is what gets completed. `proc pending` has the same shape — `Literal(["allow","deny"])` followed by `Value("id")` (src/help.rs:484-500) — so its two answer verbs are unreachable too.

The merge branch's comment (line 202-203) claims "`sbx projects <TAB>` its commands alongside the tree ids"; only `show` appears, because `show` happens to have a page of its own. `every_command_path_in_the_table_completes` sweeps pages only, so neither case is caught.

**Scénario.** `sbx projects <TAB>` offers project tree ids and `show`, but not `list` or `rm` — both real verbs (src/cli/projects.rs:20-22). `sbx projects l<TAB>` completes nothing at all. Likewise `sbx proc pending a<TAB>` offers nothing, though `sbx proc pending allow <id>` is the documented way to release a parked exec (src/cli/proc.rs:468).

**Correction proposée.** Keep `pure` when a value row also exists (fold it into the leading literal slot), and offer the literal slot's words at `pos` instead of skipping it — e.g. return `ValueKind::Literal(words)` merged with the following value's candidates when `slots[pos]` is a `Literal` the cursor has not yet consumed.

**Rectification du vérificateur.** Survives, and the proc case is slightly worse than reported: bare `sbx proc pending` rejects *any* positional (`reject_extra`, src/cli/proc.rs:478), so position 0 completes parked-request ids that the command itself refuses, while the only two words it accepts there are the ones withheld. One overstatement: `sbx projects l<TAB>` completing "nothing at all" is machine-dependent — a tree id beginning with `l` would still be offered; the sound claim is that `list`/`rm` are never offered. Note also that the root cause is partly upstream of completion.rs: CLAUDE.md requires every subcommand to have a `Page`, and these four verbs are documented as option rows instead.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Both halves traced. (a) In `operand_slots`, the `("list", ...)` row at src/help.rs:1847-1850 has no metavariable, so it lands in `pure` (src/cli/completion.rs:603-605); the later `("rm <id>...", ...)` row at src/help.rs:1852-1858 sets `saw_value_row = true` (:608), so the guard at src/cli/completion.rs:616 (`if !saw_value_row && !pure.is_empty()`) is false and `pure` is dropped — the returned slots are exactly `[Literal(["rm"]), Value("id")]`. (b) src/cli/completion.rs:797 is verbatim `while let Some(Operand::Literal(_)) = slots.get(pos) {`, so with nothing typed `pos` walks past `Literal(["rm"])` to `Value("id")`, which src/cli/completion.rs:691-694 maps to `ValueKind::Projects`. `subcommands_of(["projects"])` can only supply `show`, the sole child page (src/help.rs:2049), so `sbx projects <TAB>` = tree ids + `show`; `list` and `rm` are real verbs (src/cli/projects.rs:20-22) and are unreachable. `proc pending` has the identical shape: the rows at src/help.rs:485-498 yield `[Literal(["allow","deny"]), Value("id"), ...]`, the literal is skipped, and `is_pending_page` (src/cli/completion.rs:715-719) turns the `<id>` into `PendingIds`; `allow`/`deny` (src/cli/proc.rs:467-469) are never offered. No test pins the current behaviour — `every_command_path_in_the_table_completes` (src/cli/completion.rs:1525) sweeps pages only.

</details>

---

### B16 — `app run`'s mashed override row hides the flags' value grammar, shifting the `<name>` operand
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/help.rs:308` |
| **Catégorie** | `inconsistency` |
| **Sous-système** | Aide et complétion shell |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** The `app run` page documents thirteen value-taking overrides in one prose row:

    ("--env / --net / --gui / --proc / --notify / --nixpkgs / --bind / --forward / --limit / --package / --seccomp / --device / --gpu / --audio / --dbus", "typed one-shot overrides …")

`flag_names` splits it correctly, so the flags complete — but `flag_tail` finds no `<value>` token after any of them (the next token is `/`), so `flag_takes_value` returns false for all of them on this page. `cursor_value_kind` then counts each flag's *value word* as a positional, which is exactly the failure the `PendingWord` doc comment (src/cli/completion.rs:735-738) says must not happen: "counted as an operand it would shift every slot after it, and the page would read as already past its own `<id>` the moment a flag was typed first." The `run` page gives each of these flags its own row with its metavariable, so the identical flag behaves differently on the two pages.

**Scénario.** `sbx app run --env FOO=bar <TAB>` (or `--net none`, `--bind /data`, `--limit tasks_max=4096`) offers nothing, because `FOO=bar` consumed the `<name>` slot — while `sbx app run --detach <TAB>` correctly lists the app profiles. In zsh, `sbx app run --net=<TAB>` also offers nothing, while `sbx run --net=<TAB>` offers none|shared|ask|allow|deny. The parser accepts all of these before the name (src/cli/app.rs:237, tested at src/cli/app.rs:2253-2270).

**Correction proposée.** Give the typed overrides their own rows on the `app run` page carrying their value grammar (`--net <posture>`, `--env KEY=VALUE`, `--bind <path[:ro|:rw]>`, …), as the `run` page already does, or point the page at `run`'s rows programmatically; alternatively teach `flag_tail` to fall back to the same-named row on the `run` page.

**Rectification du vérificateur.** Confirmed; one symptom the report missed makes it a wrong answer rather than only a missing one: because `--net` etc. take no value on this page, `sbx app run --net <TAB>` (cursor on the flag's own value word) answers with the app-profile list — the operand vocabulary offered where a posture belongs. The report's `--detach` contrast is correct: a genuinely valueless flag leaves `pos` at 0, so `sbx app run --detach <TAB>` still lists profiles.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The row is at src/help.rs:306-312, its flag string starting at :308 exactly as cited. `flag_names` splits on ',' and '/' (src/cli/completion.rs:984), so all fifteen flags do complete — but `flag_tail` (src/cli/completion.rs:944-970) matches `--net` at some token, finds `rest` empty, then scans `toks[i+1..]`: the next token is `/`, which does not start with `-` so it is not skipped, and the `(next.starts_with('<') || next.starts_with('['))` test at :963 returns `None`. Hence `flag_takes_value` (:899-903) is false for every one of them on this page, and in `cursor_value_kind` the following word falls through to the positional counter at :788-791, consuming the page's only slot (`Value("name")` from the row at src/help.rs:298-302). `slots.get(1)` is then `None`, `all_literal_words` returns `None` (:810), and the else branch's flag menu is gated off by :225 — zero candidates. The parser genuinely accepts those flags before the name (src/cli/app.rs:237 `take_override_flag`, exercised at src/cli/app.rs:2253-2270 with `--net none` ahead of `demo-app`). The zsh inline claim holds too: `flag_literals` is keyed `(["run"], "--net")` (src/cli/completion.rs:929), so `app run --net=<TAB>` gets nothing while `run --net=<TAB>` gets the posture cells. The value-position sweep cannot catch it: src/cli/completion.rs:1731-1733 `continue`s when `flag_tail` is `None`. The invariant broken is stated verbatim in the `PendingWord` doc comment and in the test comment at src/cli/completion.rs:1359-1363.

</details>

---

### B17 — `prune_app_tools` builds the delete path from the *sanitised* display name, so a tool whose real directory name is not sanitise-stable is reported as pruned but never removed
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/sandbox/gc.rs:881` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | Cycle de vie des sessions (gc, projects, attach) |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `prune_app_tools` enumerates tools with `super::inspect::mise_installed_in(&installs)` and then reconstructs the on-disk path as `installs.join(&tool.name)` (gc.rs:881). But `InstalledTool::name` is *not* the on-disk name: `mise_installed_in` builds it with `crate::sandbox::sanitize(&entry.file_name().to_string_lossy())` (src/sandbox/inspect.rs:103), which (a) replaces every `char::is_control()` with a space, (b) has already passed the name through `to_string_lossy` (invalid UTF-8 -> U+FFFD), and (c) truncates to 512 chars with a trailing ellipsis. `InstalledTool` keeps no raw name, so the round-trip is lossy by construction, and gc.rs:881 is the only place in the tree that joins that value back into a path.

This matters precisely because of the invariant the surrounding comments state. gc.rs:866-871 says "`home` is the cage's own `$HOME` (a plain writable `Mount::Bind`), so ... `installs` are ordinary directories untrusted in-cage code owns", and inspect.rs:98-102 says "the payload can `mkdir` whatever it likes under `installs/`, so a directory name is attacker-chosen text". The sanitiser exists to make those names safe *to print*; using its output as a *filesystem path* is the one thing it cannot support.

Three consequences chain from the one line: `tree_size(&dir)` returns 0 for the non-existent path; `force_remove_dir_all(&dir)` fails with ENOENT so `removed_any` stays false and the `prune_mise_config` cleanup at gc.rs:894-899 is skipped (the tool re-equips at the next launch); and `pruned.push(...)` at gc.rs:886 runs unconditionally, so the CLI prints `pruned N undeclared tool(s), freeing ...` (src/cli/app.rs:1963) for a tool still on disk. The two tests at gc.rs:1354 and gc.rs:1388 only ever use plain ASCII directory names, so nothing pins the round-trip.

**Scénario.** In a cage, `mkdir -p ~/.local/share/mise/installs/$'evil\ttool'/1.0` (a tab in the directory name -- or any non-UTF-8 byte, which is legal in a Linux filename). Host side: `sbx app prune <name> --yes`. `mise_installed_in` yields `name = "evil tool"` (tab -> space); the tool is undeclared so it is selected; `installs.join("evil tool")` does not exist; `tree_size` = 0 and `force_remove_dir_all` returns ENOENT, both discarded. sbx prints `evil tool  0 B` and then `pruned 1 undeclared tool(s), freeing 0 B.` -- while `installs/evil\ttool/` is still there, still listed by `sbx app show`, and still in `~/.config/mise/config.toml` (the config rewrite is gated on `removed_any`, which is false). Every subsequent `sbx app prune --yes` repeats the same false claim.

**Correction proposée.** Carry the raw name alongside the display name: add a `dir_name: std::ffi::OsString` (the unsanitised `entry.file_name()`) to `InstalledTool` in src/sandbox/inspect.rs and populate it in `mise_installed_in`, then use `installs.join(&tool.dir_name)` at gc.rs:881. Independently, make the report honest: only `pruned.push(...)` when `apply` is false or the removal actually succeeded, mirroring the rule `prune_rev_dirs` (gc.rs:1205-1213) already applies.

**Rectification du vérificateur.** The mechanism is right but the severity is overstated. The path half only fires for a directory name that is not sanitise-stable — a control byte, invalid UTF-8, or over 512 chars — which no mise install produces; it takes a deliberate in-cage `mkdir`, and this is explicitly not the security wave. What is unconditional, and the stronger half of the finding, is the reporting: `pruned.push` at gc.rs:886 runs whatever `force_remove_dir_all` returned, so *any* failed removal (EACCES on a subdirectory, a concurrent unlink racing `remove_file`) is still announced as `pruned N undeclared tool(s), freeing …`, and the `removed_any` gate then silently skips the config cleanup so the tool re-equips at the next launch. That is the exact failure the same module rejects in `prune_rev_dirs` (gc.rs:1200-1211) and pins with a test (gc.rs:2290), and it is the same doctrine `AppPurgeReport` follows with its `failed: Vec<(PathBuf, io::Error)>` field (gc.rs:1252-1256, "reported not swallowed").

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every citation verifies. gc.rs:881 is exactly `let dir = installs.join(&tool.name);`, gc.rs:884 `removed_any |= force_remove_dir_all(&dir).is_ok();`, gc.rs:886 the unconditional `pruned.push`, gc.rs:894-897 the `apply && removed_any` gate on `prune_mise_config`. inspect.rs:103 is exactly `let name = crate::sandbox::sanitize(&entry.file_name().to_string_lossy());` and `InstalledTool` (inspect.rs:11-25) carries only `name`/`token`/`versions` — no raw `OsString`, so the round-trip is lossy by construction. `sanitize` (observe_feed.rs:112-125, re-exported at mod.rs:153) does map `c.is_control()` to ' ' and truncate at 512 chars with '…', so a name containing a control byte or over 512 chars does not join back to an existing path. `force_remove_dir_all` (gc.rs:1040-1061) has no NotFound-is-ok shortcut: a missing root falls through to `read_dir(path)?`, which the doc comment at gc.rs:1044-1045 explicitly says ("a root that does not exist at all falls through too, so the error still comes from `read_dir`"), so `removed_any` stays false and the config rewrite is skipped. The CLI text at cli/app.rs:1963 is `pruned {count} undeclared tool(s), freeing {size}.` and the two tests at gc.rs:1354 and gc.rs:1388 use only `keep-me`/`drop-me`, so nothing pins the round-trip. No comment anywhere defends using the sanitised name as a path — the comments at gc.rs:866-872 and inspect.rs:96-102 argue the opposite (the names are payload-chosen and sanitised for *printing*).

</details>

---

### B18 — `reap_dead_projects`/`reap_one` report a tree as reclaimed even when `force_remove_dir_all` failed, contradicting the rule `prune_rev_dirs` states and a test pins
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/sandbox/gc.rs:518` |
| **Catégorie** | `error-handling` |
| **Sous-système** | Cycle de vie des sessions (gc, projects, attach) |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `reap_dead_projects` discards the removal result (`let _ = force_remove_dir_all(&dir);`, gc.rs:518 for a dead tree and gc.rs:530 for a `--markerless` one) and then unconditionally pushes the entry into `report.dead` / `report.reaped_unidentified`. `reap_one` does the same at gc.rs:614 before returning `ReapOneOutcome::Tree { dir, bytes }`. The callers in src/sandbox/projects.rs then print `reclaimed: <path> (<size>)` (projects.rs:62-66), `reclaimed N dead project tree(s), freed up to <total>` (projects.rs:70-74), `reclaimed (no marker, deadness unverified)` (projects.rs:97-101) and `removed: <dir>` (projects.rs:696-705) on the strength of a result nobody looked at.

This is the exact failure mode the same module documents and rejects a few hundred lines further down. `prune_rev_dirs` (gc.rs:1205-1213) carries a five-line comment -- "a failed removal reported as one makes `sbx gc` announce bytes that are still on the disk -- and hides the entry that keeps failing, since it is named as gone every time" -- and gates its `removed.push` on the removal succeeding; the test `a_prune_reports_the_roots_it_removed_and_not_the_ones_it_could_not` (gc.rs:2290) pins that behaviour for both loops of `prune_shared_gcroots`. The reap paths, which delete far more (whole multi-hundred-megabyte project trees) and are the ones that print a byte total, apply the opposite rule.

**Scénario.** A project tree contains one entry the recursive delete cannot get past -- e.g. `<data>/projects/<id>/home/mnt` is a mount point (`remove_dir` -> EBUSY), or a subdirectory is owned by another uid so the `let _ = set_permissions` at gc.rs:1051 is a no-op and `read_dir(path)?` at gc.rs:1052 returns EACCES. `sbx projects rm --dead --yes` prints `reclaimed: /home/u/gone-proj (2.4 GiB)` and `reclaimed 1 dead project tree(s), freed up to 2.4 GiB.` and exits 0. Nothing was freed; `df` is unchanged; the next run reports the same 2.4 GiB reclaimed again, forever, and never tells the user which entry is blocking it.

**Correction proposée.** Have `force_remove_dir_all`'s `io::Result` decide what goes into the report, as `prune_rev_dirs` does: in `reap_dead_projects`, `if prune && force_remove_dir_all(&dir).is_err() { continue; }` before the `dead.push`/`reaped_unidentified.push`; in `reap_one`, return a new `ReapOneOutcome::Failed(io::Error)` (or fold the error into `Tree`) so `projects_rm` can say which tree could not be removed and set `had_error`.

**Rectification du vérificateur.** Survives as stated. One correction to the proposed fix rather than the finding: `force_remove_dir_all` can fail *after* removing most of a tree (it propagates the first `?` inside the recursion, gc.rs:1052-1057), so `continue`-ing on error would hide a tree that is now partly gone and whose measured `bytes` are partly real. Threading the `io::Error` into the report — the shape `AppPurgeReport.failed` already uses — is the fix that stays honest in both directions.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Line numbers are exact. `grep -n 'let _ = force_remove_dir_all'` in gc.rs returns 518, 530, 614 — 518 inside the `Some(path) if project_is_gone(&path)` arm followed by an unconditional `dead.push(DeadTree { path, bytes })`, 530 inside the `None` arm followed by an unconditional `reaped_unidentified.push(...)`, 614 in `reap_one` followed by an unconditional `ReapOneOutcome::Tree { dir, bytes }`. The only two callers in the tree are projects.rs:44 and projects.rs:680; both print success on that basis — projects.rs prints `{ok}reclaimed{r}` per tree and `reclaimed {n} dead project tree(s), freed up to {size}.` whenever `prune` is set, `{ok}reclaimed{r} {warn}(no marker, deadness unverified){r}` for the markerless loop, and `{ok}removed{r}` in the `ReapOneOutcome::Tree` arm. The contrast is real and documented: `prune_rev_dirs` (gc.rs:1194-1214) carries the five-line comment the reporter quotes and gates `removed.push` on `force_remove_dir_all(&entry.path()).is_err()`, the sibling loop at gc.rs:1182-1185 says "Only what went, for the reason [`prune_rev_dirs`] gives", the test at gc.rs:2290 pins it, and `AppPurgeReport` (gc.rs:1250-1257) models failures explicitly. Nothing in the reap doc comments (gc.rs:462-478, gc.rs:586-590) claims the discard is deliberate.

</details>

---

### B19 — `sbx upgrade`'s resolver cage omits the mise `nix:` tools, the prebuilt bins and every app overlay the launch cage carries
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/sandbox/resolve.rs:84` |
| **Catégorie** | `inconsistency` |
| **Sous-système** | Provisionnement (nix, mise, flakes) |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `UpgradeCage::build` claims (lines 59-61) to assemble "the same hermetic base userland plus the project's `nix:` package bins a launch gives a resolve command, so a command runs identically at first launch and at upgrade", and line 82-83 repeats it ("The app's `nix:` bins ... resolves at upgrade time exactly as it does at launch"). It then builds `bins` from `userland.bin_paths` plus `packages::provision(nix, layout, project, &nixpkgs, &cfg.packages)` only. The launch-time cage is assembled at src/sandbox/launch.rs:3572-3581 from `userland.bin_paths` plus `bin_paths`, which at that point holds three families: `mise_tools(prep).bins` (the `nix:` tools declared in the project's mise file, launch.rs:3528-3532), `packages.bins`, and every direct prebuilt package's bin dir pushed by the `DIRECT_ORDER` loop (launch.rs:3547-3560). None of the first and third reach `UpgradeCage`. Worse, `cfg.packages` is the project baseline, while `prebuilt::declared` (prebuilt.rs:733-738) and `has_resolve_ref` (prebuilt.rs:766-770) both walk each app's *merged* package list — so an app-scoped `<backend>:resolve` package is rolled by `upgrade` using a cage that never saw that app's own `nix:` packages either. The two paths that the comment asserts are identical are three families apart.

**Scénario.** A project declares `"nix:yq-go" = "latest"` under `[tools]` in `.mise.toml`, and in `.sbx.toml` `app = "tarball:resolve"` with `[tarball.app] resolve = ["sh","-c","curl -sfL https://api.example.com/v | yq -r .url"]`. The first launch provisions `yq-go` host-side, puts its bin on the resolve cage's PATH, runs the command and pins the package. `sbx upgrade tarball` then builds `UpgradeCage` without that bin, the command dies with `yq: command not found`, `resolve_url` folds the stderr into `Upgrade::Failed`, and `sbx upgrade` exits non-zero reporting the package as un-rollable. It will never roll — the same failure repeats on every upgrade while the launch keeps working, so the package silently stays frozen at its first pin. The identical failure occurs for a resolve command that uses a `deb:`/`tarball:` package's binary, or for any resolver declared inside an app whose tool is declared in that app.

**Correction proposée.** Build the upgrade cage's `bins` the way the launch does: prepend `nixhub::provision(...)` bins for the project's mise `nix:` tools (from `cfg.mise`, trusted-only), append the direct prebuilt packages' bin dirs, and walk `cfg.apps` with `merge_app` so an app-scoped resolver sees its own app's packages — or, if that set genuinely cannot be reproduced here, correct the three comments so they stop asserting parity that does not exist.

**Rectification du vérificateur.** Mechanism is accurate; severity is medium rather than high. The divergence bites only a resolve command that reaches for a tool outside sbx's base userland and outside the baseline `[packages]` nix:/flake: layer, and it fails loudly (non-zero `sbx upgrade`, one `re-resolve failed` line per package) rather than silently: launches keep working off the existing pin. Also note the reporter's fix list is slightly off — the missing families are provisioned via `nixhub::provision` (mise `nix:` tools) and `prebuilt::provision` (direct bins), and rebuilding the direct layer at upgrade time is itself expensive, so correcting the three comments is the cheaper of the two remedies they offer.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified end to end. src/sandbox/resolve.rs:84 is exactly `if let Ok(p) = super::packages::provision(nix, layout, project, &nixpkgs, &cfg.packages) { bins.extend(p.bins); }` and that is the ONLY addition to `userland.bin_paths` (resolve.rs:81-86). `packages::provision` realises only `Backend::Nix` and `Backend::Flake` (src/sandbox/packages.rs:105-124; every prebuilt variant hits the explicit `continue` at packages.rs:137-147). The launch cage is strictly larger: `let mut bin_paths = tools.bins;` (launch.rs:3534, from `mise_tools(prep)` at launch.rs:3530 -> `nixhub::provision`, launch.rs:5365), then `bin_paths.extend(packages.bins)` (launch.rs:3535), then the `DIRECT_ORDER` loop pushes each prebuilt bin (launch.rs:3546-3552), and only then `let mut bins = prep.userland.bin_paths.clone(); bins.extend(bin_paths.iter().cloned());` (launch.rs:3573-3574). The parity claims are explicit and false for the upgrade path: resolve.rs:59-61 ("the same hermetic base userland plus the project's `nix:` package bins a launch gives a resolve command, so a command runs identically at first launch and at upgrade"), resolve.rs:82 ("The app's `nix:` bins ... exactly as it does at launch") and prebuilt.rs:640-642 ("a resolve command runs with every direct package's bin on `PATH`"). The app-overlay half also holds: `declared` materialises `merge_app` per app (prebuilt.rs:733-738) and `has_resolve_ref` does the same (prebuilt.rs:766-770), so an app-scoped resolver is rolled against a cage built from the baseline `cfg.packages` alone. Consequence chain confirmed: `resolve_url` failure -> `Upgrade::Failed` (prebuilt.rs:1067-1070), the prior pin is never removed (only successful resolutions `lock.insert`), and `upgrade_tarball_packages`/`upgrade_deb_packages` return false on any `Failed` (cli/upgrade.rs:1350-1353, 1180-1183), which feeds `ok &= ...` at cli/upgrade.rs:309. Nothing in the file argues the reduction is deliberate; the only deliberate narrowing commented there is the channel choice (resolve.rs:71-73).

</details>

---

### B20 — A removed `nix:` mise tool's gcroot under `nix-tools/` is never pruned, pinning its store closure forever
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/sandbox/nixhub.rs:256` |
| **Catégorie** | `resource-leak` |
| **Sous-système** | Provisionnement (nix, mise, flakes) |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `provision` roots each `nix:` mise tool at `<data>/gcroots/projects/<id>/nix-tools/<pkg>` via `store::provision` (line 289). That out-link is add-only: nothing ever removes it when the tool leaves the mise file. `upgrade_tools` prunes the *lock* entry (lines 434-443) and reports `ToolUpgrade::Pruned`, but leaves the out-link. On the gc side the family is read into the keep-set — `gc::project_keep_roots` explicitly names `projects/<id>/nix-tools` (gc.rs:191) — while `gc::prune_project_package_roots` (gc.rs:97) reads only the top level of `projects/<id>` and skips anything that is not a symlink, so the `nix-tools` directory is never descended into. This is exactly the leak class `prune_project_package_roots` was written to close for `[packages]` (see its docstring at gc.rs:80-89 and the launch-side prune at launch.rs:2175-2196), and the `nix:` mise-tool family is the one host-provisioned family that has a keep-set entry with no matching prune.

**Scénario.** A project's `.mise.toml` declares `"nix:nodejs" = "20"`. A launch provisions it and writes `gcroots/projects/<id>/nix-tools/nodejs -> /nix/store/<hash>-nodejs-20.x`. The user deletes that line and re-trusts. `sbx upgrade mise` prints `nix:nodejs (20): removed from the lock (no longer declared)`, but the out-link survives: it is still a live nix gcroot, so `nix-store --gc` can never collect the nodejs closure from the shared store, and because `project_keep_roots` reads the same out-link's target into the keep-set, `prune_superseded_roots` also keeps the project's private per-project copy. `sbx gc --prune` reports nothing reclaimable and frees nothing — a few hundred MB per removed toolchain, permanently, for a project that is still in use (whole-tree reaping only applies to a dead or explicitly named project).

**Correction proposée.** In `provision`, after building `declared.nix` on the trusted path, read `<data>/gcroots/projects/<id>/nix-tools/` and unlink any out-link whose `<pkg>` is not in the declared set (guarding, as elsewhere, on the entry being a symlink) — the same reconciliation `prune_project_package_roots` performs one level up. Doing it in `provision` rather than `upgrade_tools` covers the common case where the user removes a tool and never runs `sbx upgrade`.

**Rectification du vérificateur.** Correct as described; it is a housekeeping/disk leak, not a correctness bug — nothing misbehaves, `sbx gc --prune` just cannot reclaim the removed toolchain's closure or its per-project seed copy while the project tree lives. Worth adding that the same gap swallows a tool that was merely *renamed* in `.mise.toml` (old key's out-link survives beside the new one), and that `sbx projects rm`/the dead-tree reap still reclaim it, so the ceiling is one stale closure per removed tool per live project.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Confirmed. `nixhub::provision` builds the out-link directory at src/sandbox/nixhub.rs:256-261 (`gcroots/projects/<id>/nix-tools`) and roots each tool with `store::provision(nix, layout, &roots.join(&tool.pkg), ...)` at nixhub.rs:289-296; nothing in that function or anywhere else reconciles the directory against the declared set. `upgrade_tools` prunes only lock entries — the stale computation at nixhub.rs:442-450 and `outcomes.push(ToolUpgrade::Pruned { pkg, request })` at nixhub.rs:452 — leaving the out-link. On the gc side `project_keep_roots` deliberately descends into the family (`add_targets(data_gcroots.join("projects").join(id).join("nix-tools"));`, gc.rs:191), while `prune_project_package_roots` reads one directory level and skips every non-symlink (`if !entry.file_type().is_ok_and(|t| t.is_symlink()) { continue; }`, gc.rs:107-109), so the `nix-tools` directory entry is skipped and never descended. A repo-wide grep for `nix-tools` returns only nixhub.rs:261, gc.rs:151/158-160/191, gc.rs:1833 (a test), and inspect.rs:365-367/686 — no prune anywhere. The launch-side reconciliation (launch.rs:2181-2196) builds its `current` set from `packages::project_gcroot_names`, which covers only `[packages]` backends (packages.rs:260-284) and never mise tools. The leak class is exactly the one gc.rs:80-89 documents as needing closing.

</details>

---

### B21 — `sbx search` prints a `[packages]` declaration line that is invalid TOML for any dotted nixhub package name
| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/sandbox/search.rs:231` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | Provisionnement (nix, mise, flakes) |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** The exact-match report emits `  [packages]  {pkg} = "nix:{attr}"` with the package name as a **bare** TOML key, while the `[tools]` line one row above correctly quotes its key (`"nix:{pkg}"`). nixhub names are frequently attribute paths containing `.` — this very module acknowledges it in `NAME_COL`'s docstring ("one long attribute path (`python312Packages.…`)") and `is_valid_attr` is documented as "a dotted chain of attribute names (e.g. `python3Packages.requests`)". In TOML a bare dotted key is not a literal name: `python312Packages.numpy = "nix:…"` under `[packages]` declares the *table* `packages.python312Packages` with member `numpy`, not a package called `python312Packages.numpy`. `RawConfig::packages` is a `BTreeMap<String, String>` (src/config/schema.rs:34), so the layer fails to deserialize.

**Scénario.** `sbx search python312Packages.numpy` finds the exact hit and prints `  [packages]  python312Packages.numpy = "nix:python312Packages.numpy"`. The user pastes that line into `.sbx.toml`. `schema::parse` now fails with an `invalid type: map, expected a string` error, and `load::read_project` (src/config/load.rs:559-564) drops the **entire** project layer with a single `ignoring <path>: …` warning — the project loses its packages, apps, network allowlist and every other setting, not just the pasted line, and the sandbox launches on the global config alone. The `[tools]` suggestion printed immediately above works fine, which makes the failure read as an sbx bug rather than a quoting problem.

**Correction proposée.** Quote the key the way the `[tools]` line already does: `"  [packages]  \"{n}{pkg}{r}\" = \"{n}nix:{attr}{r}\"\n"`. A quoted key is valid for every name, dotted or not, so no conditional is needed.

**Rectification du vérificateur.** Accurate. Two small refinements: the pasted line is valid TOML syntax — the failure is at deserialization ("invalid type: map, expected a string"), not at the TOML parser; and the user does get a visible `sbx: ignoring <path>: …` warning, so the loss of the layer is noisy rather than silent, though the warning names the file and not the offending key.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Confirmed at the cited line. src/sandbox/search.rs:230-232 emits `"  [packages]  {n}{pkg}{r} = \"{n}nix:{attr}{r}\"\n"` — a bare key — while search.rs:227-229 emits `"  [tools]     \"{n}nix:{pkg}{r}\" = ..."` with the key quoted. `pkg` is nixhub's canonical name copied from the search hit (search.rs:95-105), and dotted names are both expected (NAME_COL's docstring, search.rs:33-35: "one long attribute path (`python312Packages.…`)"; MAX_MATCHES, search.rs:29-31: "every `emacsNNPackages.*` variant") and admitted by validation (`is_valid_pkg` allows '.', nixhub.rs:772-776; `is_valid_attr` allows '.', config/mod.rs:5468-5473). Under `[packages]`, `python312Packages.numpy = "nix:…"` is a dotted key that builds a sub-table, and `RawConfig::packages` is `BTreeMap<String, String>` (config/schema.rs:34), so serde fails with a type error and `read_project` discards the whole layer: `Err(e) => { warnings.push(format!("ignoring {}: {e}", path.display())); None }` at config/load.rs:562-565. The rendering test only exercises `jq` (search.rs:433-435), so nothing pins the bare-key form as intentional.

</details>

---

### B22 — `app_prefixed_key` rejects a dotted app name on the strength of a splitter limitation that no longer exists
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/config.rs:2355` |
| **Catégorie** | `inconsistency` |
| **Sous-système** | CLI — sbx config |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `app_prefixed_key` refuses any app name containing a `.`:

```rust
if name.contains('.') {
    return Err(format!(
        "an app name containing `.` (`{name}`) cannot be addressed with `--app`; \
         edit it directly with `sbx config edit`"
    ));
}
```

The justification is stated three times and is false in all three: line 2351 ("the segment splitter does not handle quoting"), line 2542 in `resolve_key_target`'s doc ("the dotted-key splitter does not handle a quoted segment"), and the test comments at lines 3219 and 3957 ("the naive key splitter"). `config::manage::split_key` (src/config/manage.rs:1258-1284) is quote-aware — it toggles on `"` and only splits on an unquoted `.`, and rejects an unbalanced quote — and `src/config/manage.rs:2277 a_quoted_key_segment_keeps_its_dots` pins `set`/`get`/`unset` round-tripping `secret."api.example.com".from`. `put_value`, `get` and `list_at` all route through that same splitter, so `app."my.app".network` would resolve correctly today. The guard is therefore an unnecessary restriction resting on a lying comment, and it makes `sbx config` disagree with the rest of the CLI about which app names exist.

**Scénario.** `config::is_valid_app_name` (src/config/mod.rs:3260-3268) permits `.`, and `split_one_rule` (src/main.rs:239-244) validates with exactly that function, so `sbx net allow -a my.app --local api.example.com` succeeds and writes `[app."my.app".network] allow = ["api.example.com"]` via `layer_parent`. `sbx config show --app my.app` then renders that app fine. But every key verb refuses it: `sbx config get -a my.app network.mode`, `sbx config set -a my.app cmd /bin/sh`, and `sbx config rm -a my.app network.allow api.example.com` all exit 2 with "an app name containing `.` (`my.app`) cannot be addressed with `--app`; edit it directly with `sbx config edit`". The user can create the app with one verb and inspect it with another, but cannot read or edit a single one of its keys — for a reason that stopped being true when quoting was added to `split_key`.

**Correction proposée.** Quote the segment when the name needs it: `let seg = if name.contains('.') { format!("\"{name}\"") } else { name.to_string() }; Ok(format!("app.{seg}.{key}"))` — quoting only when required keeps the existing `app.demo.network` spelling the test at line 3949 pins. (A name containing a `"` is already impossible: `is_valid_app_name` restricts the charset to `[A-Za-z0-9._-]`.) Then delete the false rationale at lines 2351-2353, 2542, 3219 and 3957.

**Rectification du vérificateur.** Survives only as a stale/false rationale (a lying comment repeated in five places), not as a functional hole — the reporter's impact claim is wrong. Because `resolve_key_target` passes `raw_key` through untouched when no `--app` is given (src/cli/config.rs:2562), the app IS fully addressable today with a quoted raw key: `sbx config get 'app."my.app".network.mode'`, `sbx config set 'app."my.app".cmd' /bin/sh` and `sbx config rm 'app."my.app".network.allow' api.example.com` all route through the quote-aware `split_key` and work. What is lost is only the `--app` sugar, and the refusal names a working alternative. The behaviour is also pinned by tests/config.rs:2745-2753 and src/cli/config.rs:3946-3962, so the fix is a comment correction plus (optionally) quoting in `app_prefixed_key` and updating those tests.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The factual core checks out at every cited line. src/config/manage.rs:1258-1284 `split_key` is quote-aware (toggles `quoted` on `"`, splits only on an unquoted `.`, rejects an unbalanced quote), it is the splitter used by all four key operations (manage.rs:335, 509, 604, 758), and manage.rs:2277-2307 `a_quoted_key_segment_keeps_its_dots` pins `set`/`get`/`unset` round-tripping `secret."api.example.com".from`. So the rationale stated at src/cli/config.rs:2351 ("the segment splitter does not handle quoting"), 2542 ("the dotted-key splitter does not handle a quoted segment"), 3219 and 3957 ("naive key splitter"), plus tests/config.rs:2748 ("under the naive key splitter"), is false as written. A dotted app name is genuinely creatable elsewhere: `config::is_valid_app_name` (src/config/mod.rs:3260-3268) allows `.`, main.rs:239-244 and 754-758 validate with exactly that, and `layer_parent` (manage.rs:1203-1228) inserts the raw name as one key, so `sbx net allow -a my.app --local …` writes `[app."my.app".network]`. I could not find anything that makes quoting the segment unsafe.

</details>

---

### B23 — `is_security_key` splits on every dot, so a quoted app-name `env` key is wrongly reported as a security field
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/config.rs:3103` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | CLI — sbx config |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** ```rust
fn is_security_key(key: &str) -> bool {
    let segs: Vec<&str> = key.split('.').collect();
    !matches!(segs.as_slice(), ["env", ..] | ["app", _, "env", ..])
}
```

This is a second, naive parser for the same dotted-key expression the write already parsed with the quote-aware `config::manage::split_key` (src/config/manage.rs:1258-1284). The two disagree exactly where a segment is quoted. For `app."my.app".env.FOO`, `split_key` yields `["app", "my.app", "env", "FOO"]` (and writes the value into `[app."my.app".env]`), while `key.split('.')` here yields `["app", "\"my", "app\"", "env", "FOO"]` — `segs[2]` is `app"`, not `env`, so neither arm of the `matches!` fires and the function returns `true`. The function's own doc (lines 3098-3101) states the intended rule: "The only field applied without trust ... is the free `env` table — both the baseline `env.*` and an app's `app.<name>.env.*`". A quoted `<name>` is still an app's `env` table; the code says otherwise.

**Scénario.** With an inline app named `my.app` (creatable via `sbx net allow -a my.app --local`, see finding 2), run `sbx config set 'app."my.app".env.FOO' bar --local` on a project `.sbx.toml` that is not trusted. The write succeeds and the value lands in `[app."my.app".env]`. `report_write_trust` then reaches line 3084 and prints `sbx: note: `app."my.app".env.FOO` is a security field; it applies only once ./.sbx.toml is trusted (`sbx trust`)`. That is wrong on both halves: `env` is free for an untrusted project (`resolve_app`, src/config/mod.rs:3270-3275: "`env` is free (denylisted for an untrusted project)"), and the variable is already in effect. The note sends the user to run `sbx trust` — blessing the entire file, every security field in it — to fix a problem that does not exist.

**Correction proposée.** Parse the key with the same splitter the write used rather than a second copy of the rules: expose `config::manage::split_key` to this module and match on its output (falling back to `true` — the conservative answer — if it errors), instead of `key.split('.')`.

**Rectification du vérificateur.** Correct, with two small fixes to the write-up. The note is emitted at src/cli/config.rs:3089-3092, not 3084. Impact is cosmetic-only: it is a `diag::note`, the write already succeeded and the exit code stays SUCCESS, so the sole consequence is a misleading suggestion to run `sbx trust`. Reachability is also narrower than described — it needs both an app whose name contains a `.` and a hand-quoted raw key, since `--app my.app` is refused by `app_prefixed_key`.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Confirmed. src/cli/config.rs:3102-3105 is `fn is_security_key(key: &str) -> bool { let segs: Vec<&str> = key.split('.').collect(); !matches!(segs.as_slice(), ["env", ..] | ["app", _, "env", ..]) }` — a second, non-quote-aware parser for the key the write already parsed with `split_key` (src/config/manage.rs:1258-1284). For `app."my.app".env.FOO` the naive split yields ["app", "\"my", "app\"", "env", "FOO"], so `segs[2]` is `app\"` and neither arm matches, returning true. The path is reachable without `--app` (which finding 2's guard blocks): `resolve_key_target` passes a raw key through unchanged (src/cli/config.rs:2562), `manage::set` writes it correctly via the quote-aware splitter, and `report_write_trust` then falls to `else if is_security_key(key)` at src/cli/config.rs:3089 and prints the note at 3090-3092 on an untrusted, gated file. That contradicts the function's own doc at 3098-3101 ("the free `env` table — both the baseline `env.*` and an app's `app.<name>.env.*`") and `resolve_app`'s (src/config/mod.rs:3270-3275, "`env` is free (denylisted for an untrusted project)"). No comment or test defends the naive split; the unit test at 3113-3118 only covers unquoted names.

</details>

---

### B24 — `--trust` is accepted and silently ignored by `config get` and `config path`
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/config.rs:2386` |
| **Catégorie** | `dead-code` |
| **Sous-système** | CLI — sbx config |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `split_scope` (src/main.rs:174) parses `--trust` for every management verb and rejects any *other* unknown flag with exit 2 (src/main.rs:175-177). `config_get` destructures the result as `ScopeArgs { positionals, scope, app, .. }` (lines 2382-2387) and `config_path_cmd` as `ScopeArgs { positionals, scope, scope_explicit, app, .. }` (lines 2797-2803) — the `..` swallows `trust` in both. Neither verb has any trust behaviour, and neither `sbx help config get` (src/help.rs:1278-1298) nor `sbx help config path` (src/help.rs:1462-1479) lists `--trust` among its options. So the flag is parsed, carried, and dropped.

This is inconsistent with the module's own stance on inapplicable flags: `reject_app` (line 2429) exists solely to refuse `--app` on `path` and `edit` rather than ignore it, and `set_show_source` (line 65) refuses a second conflicting source flag rather than take last-wins. `--trust` on a read-only verb gets neither treatment.

**Scénario.** `sbx config get -l --trust network` prints the value and exits 0, having silently discarded `--trust`. `sbx config path -g --trust` prints the global config path and exits 0 likewise. A user who typed `get` where they meant `set` — or who believes `--trust` on `path` will report or arm something — gets no signal at all, while the neighbouring typo `sbx config get -l --truts network` is correctly refused with `sbx: config get: unknown flag `--truts`` and exit 2.

**Correction proposée.** Add a `reject_trust(verb: &str, trust: bool) -> Option<ExitCode>` mirroring `reject_app`, and call it at the top of `config_get` and `config_path_cmd` (binding `trust` instead of letting `..` eat it), so an inapplicable `--trust` exits 2 with the verb's usage the way an inapplicable `--app` already does.

**Rectification du vérificateur.** Two corrections to the framing. (1) The scope is wider than the two verbs named: `--trust` rides the shared `split_scope`, so `sbx proc rules --trust` (src/cli/proc.rs:371) and the `net pending` paths (src/cli/net.rs:762, :793) also swallow it — `proc rules` even bothers to refuse `scope_explicit` at src/cli/proc.rs:386-393 while letting `--trust` through unremarked. The fix should be a shared reject, not two call sites. (2) One comment half-blesses the current state: src/cli/config.rs:45 says "Other flags belong to a specific subcommand (get/set/… take -c/--local/--trust)", which names `get` as taking `--trust`; that comment is itself out of step with the help page, the guide synopsis, and the fact that `config_get` has no trust behaviour, so it reads as a lying comment rather than a rationale. Impact is bounded: on a read-only verb an ignored `--trust` cannot cause a wrong write or a wrong value, so this is an inert-flag/UX anomaly, not a correctness bug — `low` is the right severity, not higher.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every citation is exact. src/main.rs:174 is `Some("--trust") => trust = true,` and 175-177 is `Some(flag) if flag.starts_with('-') && flag != "-" => { return Err(format!("unknown flag `{flag}`")); }`. src/cli/config.rs:2382-2387 destructures `ScopeArgs { positionals, scope, app, .. }` in `config_get` and 2797-2803 destructures `ScopeArgs { positionals, scope, scope_explicit, app, .. }` in `config_path_cmd` — `trust` is bound by neither, and neither function body mentions trust (the writing verbs bind it explicitly: 2597 `trust,`, 2677 `trust,`, 2747 `trust,`, 2893 `trust: trust_flag,`). `reject_app` is at 2429 and `set_show_source` at 65 as claimed. The dispatcher (src/cli/config.rs:32, :37) passes `&args[1..]` straight through with no pre-filter, so nothing upstream intercepts the flag. The help pages omit it (src/help.rs:1279 synopsis `sbx config get <key> [-l|--local|-g|--global|-c <file>] [-a|--app <name>]`; :1463 `sbx config path [-l|--local|-g|--global|-c <file>]`) and so does the guide (docs-site/docs/guide/cli/config.md:131 vs :132-135, which do carry `[--trust]`). No test in tests/ exercises `--trust` on `get` or `path`. The described sequence therefore reproduces exactly: `sbx config get -l --trust network` prints the value and exits 0.

</details>

---

### B25 — `config show --app` silently drops the notify repeat window that `config show` prints
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/config.rs:1872` |
| **Catégorie** | `inconsistency` |
| **Sous-système** | CLI — sbx config |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** The baseline renderer builds a suffix from `repeat_after` (lines 665-670):

```rust
let every = if n.repeat_after.is_empty() { String::new() }
            else { format!(" {dim}(a repeat waits {}){r}", n.repeat_after) };
```

and appends it to both the uniform and the per-event line. `render_app_detail`'s notify block (lines 1858-1882) reproduces the uniform/per-event logic verbatim but never reads `repeat_after` — `grep -n repeat_after src/cli/config.rs` returns only lines 666 and 669. The field is present on the app view: `AppDetailView.notify` is a full `NotifyView` (src/config/view.rs:627-633), and `build_app_detail` fills it through the same `notify_view` projection at src/config/view.rs:1635-1636, so the data is there and the renderer discards it.

The drift is the exact hazard the neighbouring `write_net_posture_head` doc (lines 926-938) says it was extracted to prevent: "Keeping the preamble in one place is what stops the two from drifting: they already had, on `ask timeout: none`, where this view explained the value and the app view printed it bare." Notify was never given the same treatment.

**Scénario.** Project config carries `[notify] repeat_after = "5m"` and an app `demo`. `sbx config show` prints `notify: once (a repeat waits 300s) (project)`. `sbx config show --app demo` prints `notify:  once (inherited)` — the quiet period is absent with no indication it exists, and it is not folded into the `at their default:` line either (`posture_shown` gates the whole notify block on `notify_origin`, which is not `Default` here, so the block *is* shown; only the suffix is missing). A user asking "why was I told about this refusal only once for this app" reads the per-app view, sees nothing about a repeat window, and concludes none is configured.

**Correction proposée.** Compute the same `every` suffix inside `render_app_detail`'s notify block and append it to both the `Some(mode)` and `None` lines — or, following the precedent of `write_net_posture_head`, lift the notify rendering into one helper that both `notify_section` and `render_app_detail` call, with the provenance tag passed in by the caller.

**Rectification du vérificateur.** The mechanism is right but the reporter's reproduction is a poor choice. `[notify] repeat_after = "5m"` with the default/uniform mode `once` trips the validator warning at src/config/validate.rs:407-416 ("`repeat_after` has no effect — it spaces out repeats, and no event is set to `always`"), so in that exact case the user is *not* left without a signal. A clean reproduction needs an event set to `always` — e.g. `[notify] mode = "always"` + `repeat_after = "5m"` — where `sbx config show` prints `notify: always (a repeat waits 300s) (project)` and `sbx config show --app demo` prints `notify:  always (inherited)` with the window gone. Two further notes: the JSON form is unaffected (`NotifyView` is `#[derive(Serialize)]` at src/config/view.rs:626 and is serialized whole), so this is a human-render-only inconsistency; and the suffix prints seconds, not the written value, because `notify_view` formats `format!("{}s", d.as_secs())` (src/config/view.rs:642-645) — which contradicts the field's own doc at src/config/view.rs:630 ("as it was written (`\"5m\"`)"). That contradiction is a separate defect from the one filed here.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified. `notify_section` builds the suffix at src/cli/config.rs:666-670 (`let every = if n.repeat_after.is_empty() { String::new() } else { format!(" {dim}(a repeat waits {}){r}", n.repeat_after) };`) and appends `{every}` on both branches (:675 and :682). `render_app_detail`'s notify block (guarded by `posture_shown` at :1859-1864) reproduces the same uniform/per-event logic at :1866-1880 and emits `"  {h}notify:{r}  {mode}{notify_tag}"` (:1874) and `"  {h}notify:{r}  {dim}per event{r}{notify_tag}"` (:1877) — no `every`. `grep -n repeat_after src/cli/config.rs` returns only 666 and 669, confirming the app renderer never reads it. The data is present: `AppDetailView.notify` is a full `NotifyView` (field at src/config/view.rs:883; struct at :627-633 with `repeat_after: String` at :632), filled by `build_app_detail` at src/config/view.rs:1635-1636 via the same `notify_view` projection (:635-647). The gating claim also holds: `posture_shown` folds only when `untouched(origin)`, i.e. `ProvenanceView::Default` (src/cli/config.rs:1713-1725), and `origin_or_inherited` (src/config/view.rs:1896-1908) returns `Inherited` when the baseline configured it — so the block prints, minus the suffix. The `write_net_posture_head` doc quoted by the reporter is real (src/cli/config.rs:929-938) and says exactly what they claim about drift. No test anywhere asserts the string "a repeat waits".

</details>

---

### B26 — `sbx net pending` prints a session header for every reachable session, including ones with nothing parked
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/net.rs:617` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | CLI — sbx net |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `render_pending`'s per-session loop writes the session header unconditionally:

```rust
for session in sessions {
    // A per-session header from the registry, ...
    write_session_header(&mut o, session.pid, context, pal);
    for group in group_pending(&session.rows) { ... }
}
```

There is no `if session.rows.is_empty() { continue; }` guard. Both sibling presenters have exactly that guard — `render_live` at line 406 (`if session.flows.is_empty() { continue; }`) and `render_logs` at line 1753 (`if events.is_empty() { continue; }`). `collect_pending` → `sandbox::control::list_all` (client.rs:39-47) pushes a `SessionPending` for *every* control socket whose `LIST` succeeded, with no emptiness filter, and the control server is stood up for every filtering posture, not just `ask` (`sandbox/egress.rs:865-894`), so non-ask sessions answer `LIST` with zero rows and still get a row here. The `total == 0` early return only suppresses the case where *no* session has anything.

**Scénario.** Two live sbx sessions: PID 4242 is an allowlist-posture agent (nothing ever parks), PID 4243 is an ask-posture agent with one parked request. `sbx net pending` prints:

```
pending egress requests:
  session 4242 [app:builder] /home/u/other-proj
  session 4243 [app:agent] /home/u/proj
    4243.1  api.example.com:443/v1/x  (waiting 12s)
```

The first header sits under "pending egress requests:" with nothing beneath it, so the user reads it as a session that has requests parked (the whole point of the header, per its own doc comment: "it is what tells the user which agent a flow, a parked request or a grant belongs to"). Every extra live session adds another phantom line, and with N idle sessions and one parked request the listing is mostly noise.

**Correction proposée.** Add the guard its two siblings already have, at the top of the loop body in `render_pending`:

```rust
for session in sessions {
    if session.rows.is_empty() {
        continue;
    }
    write_session_header(&mut o, session.pid, context, pal);
```

**Rectification du vérificateur.** Real, but purely cosmetic: the phantom header is noise in the listing (and in the `watch` redraw), no data is wrong, no exit code changes, and the ids/counts printed are still correct. Severity medium is overstated — low. Note also the case is broader than the reporter's framing: an *ask* session that simply has nothing parked right now produces the same empty header, so posture is not the trigger.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified end to end. src/cli/net.rs:615-617 writes the header unconditionally inside `for session in sessions {` with no emptiness guard, while the two siblings do guard: src/cli/net.rs:406 `if session.flows.is_empty() { continue; }` and src/cli/net.rs:1753 `if events.is_empty() { continue; }` — both cited line numbers are exact. Nothing upstream filters empty sessions: src/sandbox/control/client.rs:39-46 `list_all` pushes `SessionPending { pid, rows }` for every socket whose `query` succeeded, and src/cli/net.rs:88-101 `collect_pending` only applies the `--app` pid retain. The `total == 0` early return at src/cli/net.rs:585 only covers the all-empty case, so with one session holding a parked row and any other reachable session (an idle ask session, or a non-ask filtering session — the control socket is stood up for every posture, src/sandbox/egress.rs:846-893) the listing prints a bare `  session <pid> [label] <project>` line under `pending egress requests:` with nothing beneath it. No comment or test documents that as intentional; the render_pending doc (src/cli/net.rs:569-574) only describes grouping parked requests under a header, and the presenter test at src/cli/net.rs:3711-3760 never exercises an empty session.

</details>

---

### B27 — `pending allow --all --save -a <app>` reports "no pending requests for this project" without naming the `--app` filter that emptied the drain
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/net.rs:3359` |
| **Catégorie** | `ux-error-message` |
| **Sous-système** | CLI — sbx net |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** In `net_pending_drain_and_save`, the empty-drain message picks its scope word from `local` first and only falls through to the app:

```rust
let scope_note = if local {
    "for this project".to_string()
} else if let Some(name) = app {
    format!("for app `{name}`")
} else {
    "across any ask-mode session".to_string()
};
```

`local` is true for the *default* scope (`split_scope` defaults to `Scope::Local`), so the `else if` arm is unreachable for any invocation that does not pass `--global`. But the two filters compose — the drain predicate a few lines up is `app_pids.is_none_or(...) && project_pids.is_none_or(...)` — so an `--app` filter can be the sole reason nothing was answered while the message blames (and misdescribes) the project scope. Both sibling empty-result renderers deliberately do the opposite: `render_drain` (line 995) and `render_pending` (line 583) name the app precisely "so an empty result is not mistaken for 'nothing anywhere'", and the non-empty path of this very function calls `render_drain(past, session, app, ...)` with the app.

**Scénario.** In project `/home/u/proj`, two ask-mode sessions are running: `sbx app agent-a` (two requests parked) and `sbx app agent-b` (nothing parked). Run `sbx net pending allow --all --save -a agent-b`. `app_pids` excludes agent-a, so `total == 0` and the command prints `no pending requests for this project — nothing to answer or save` and exits 0. That statement is false — this project has two parked requests — and it names neither `agent-b` nor the fact that an app filter was applied, so the operator concludes the queue is empty and stops looking.

**Correction proposée.** Compose the two scopes into the note instead of letting `local` shadow the app, e.g.:

```rust
let scope_note = match (local, app) {
    (true, Some(name)) => format!("for app `{name}` in this project"),
    (true, None) => "for this project".to_string(),
    (false, Some(name)) => format!("for app `{name}`"),
    (false, None) => "across any ask-mode session".to_string(),
};
```

**Rectification du vérificateur.** Survives as a message-precision defect, not a medium one: exit 0 is correct here (nothing was answered, nothing was written), no request is lost or mis-answered, and the operator can see the truth with a plain `sbx net pending`. The mechanism is narrower than "local shadows the app" suggests — it only misleads in the default (local) scope combined with `-a`; with `--global -a name` the message already names the app.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The cited line is exact: src/cli/net.rs:3359 begins `let scope_note = if local {` with the `for this project` / `for app` / `across any ask-mode session` arms, consumed at src/cli/net.rs:3367. `local` is `matches!(scope, Scope::Local)` (src/cli/net.rs:3296) and `split_scope` defaults `scope = Scope::Local` (src/main.rs:139) while `-a/--app` sets a separate `app` field (src/main.rs:167-172), so `--all --save -a <name>` with no `--global` yields local=true, app=Some — the `else if let Some(name) = app` arm is reachable only under `--global`. The two filters genuinely compose: src/cli/net.rs:3343-3346 `app_pids.as_ref().is_none_or(...) && project_pids.as_ref().is_none_or(...)`, and the call path is live (src/cli/net.rs:777-782 routes `--all --save` here with `parsed.app.as_deref()`). So an app filter alone can empty the drain while the message blames the project scope, and the non-empty path immediately below does pass `app` to `render_drain` (src/cli/net.rs:3405), which names it (src/cli/net.rs:999-1006). No test pins the current wording — the string appears only at src/cli/net.rs:3367.

</details>

---

### B28 — Comment claims a `--session` rule only applies to `ask` sessions and is refused with `err not-ask`; neither is true
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/net.rs:3109` |
| **Catégorie** | `doc-drift` |
| **Sous-système** | CLI — sbx net |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `net_inject_session`'s doc comment ends:

```
/// `--all` widens to every reachable session. Only an `ask`-posture session consults the overlay, so a
/// filtering-posture session reports the load as skipped (`err not-ask`) rather than a silent no-op.
```

Both halves are false. (a) `sandbox/proxy/ctx.rs:785-808` (`effective_policy`) folds the manual overlay into the policy "in **every** filtering posture (allowlist, denylist, `ask`) and at every enforcement layer", and `sandbox/egress.rs:850-855` says the overlay "is wired into the proxy for **every** filtering posture (not only `ask`)". (b) The token `not-ask` appears nowhere else in the tree (`grep -rn "not-ask" src/` returns only this line); the server's `REMEMBER` handler (`sandbox/control/mod.rs:1199-1229`) replies `ok` for any classifiable rule regardless of posture, and `err bad-request` otherwise, which `send_remember` maps to `InjectOutcome::Refused` — which `render_inject` then reports as "an older sbx without --session rule support". The same file contradicts itself: `net_rules_manual`'s doc at line 2724 says "The proxy folds them into its effective policy, so they apply in any filtering posture, not only `ask`", and the `net allow` help page says the same.

**Scénario.** A maintainer debugging why `sbx net allow evil.test --session` had no visible effect on an allowlist-posture session reads this comment, concludes the load was correctly skipped as a non-ask session, and stops — when in fact the rule was loaded and is being enforced. Conversely, someone reading it may add a posture check that would break the documented, tested behaviour of `--session` on allowlist/denylist sessions.

**Correction proposée.** Replace the last sentence with the truth, e.g.: "The proxy folds the overlay into its effective policy in every filtering posture (allowlist, denylist, `ask`), so the rule takes effect immediately; a session whose control server predates `REMEMBER` refuses the load and is reported rather than silently skipped."

**Rectification du vérificateur.** Accurate as filed. One refinement: `err not-ask` is not merely undocumented drift from a removed protocol — no control-server reply string of that shape exists anywhere in the tree, so the sentence describes a wire response that never existed in this code, and the only reply a refusal can produce is `err bad-request` (an unclassifiable rule) or a connect error (a dead socket).

<details>
<summary>Preuve retenue par le vérificateur</summary>

Both halves confirmed. (a) src/cli/net.rs:3109-3110 reads "Only an `ask`-posture session consults the overlay, so a filtering-posture session reports the load as skipped (`err not-ask`) rather than a silent no-op." src/sandbox/proxy/ctx.rs:785-808 `effective_policy` folds the overlay into the policy "in **every** filtering posture (allowlist, denylist, `ask`) and at every enforcement layer", and src/sandbox/egress.rs:850-854 says the overlay "is wired into the proxy for **every** filtering posture (not only `ask`)". (b) `grep -rn not-ask src/ tests/` returns exactly one hit — src/cli/net.rs:3110, the comment itself. The server never emits it: the `REMEMBER` handler (src/sandbox/control/mod.rs:1199-1229) returns `"ok"` for any rule `classify` accepts, regardless of posture, and `"err bad-request"` otherwise; src/sandbox/control/client.rs:616-619 maps anything but `ok` to `InjectOutcome::Refused`, which render_inject reports as "an older sbx without --session rule support" (src/cli/net.rs:3244-3245). The file contradicts itself at src/cli/net.rs:2724-2726 ("they apply in any filtering posture, not only `ask`") and so does the user-facing help at src/help.rs:2331-2333 ("it takes effect immediately, on an allowlist or denylist session as well as `ask`").

</details>

---

### B29 — Dispatch comment says "a live `--session` mute is not yet wired" — it is wired end to end
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/net.rs:46` |
| **Catégorie** | `doc-drift` |
| **Sous-système** | CLI — sbx net |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** In `net_cmd`:

```rust
// `mute` adds a `dontaudit` log-suppression rule; `unmute` removes one. Both are
// config-level (the same scopes as allow/deny) — a live `--session` mute is not yet wired.
Some("mute") => net_add_rule(config::manage::EgressList::Mute, &args[1..]),
```

The full path exists and is implemented: `net_add_rule` routes `--session` to `net_inject_session`, which dispatches `EgressList::Mute => sandbox::control::inject_mute(...)` (line 3163); `inject_mute` sends `REMEMBER MUTE <rule>` (`control/client.rs:601`); the server routes it to the dedicated mute overlay (`control/mod.rs:1215-1224`, `Kind::Mute => manual.remember_mute(rule)`); `effective_policy` folds `manual.mute_snapshot()` into the policy's mute rules (`proxy/ctx.rs:805`); and `net_rules_manual` renders it back as `ManualKind::Mute => NetRuleKind::Mute` (line 2769). The help page for `net mute` documents `--session` and `--all` in full, including "A live mute is not un-loaded by `unmute`".

**Scénario.** A reader of `net_cmd` — the file's dispatch table and the first thing anyone reads — concludes `sbx net mute <rule> --session` is unimplemented and either doesn't offer it to a user asking how to quiet a noisy refusal on a running session, or "adds" it by writing a second implementation. Running the command actually works today: it loads the mute into the live overlay and quiets the log immediately.

**Correction proposée.** Drop the stale clause: `// `mute` adds a `dontaudit` log-suppression rule; `unmute` removes one from a config file. Both take the same scopes as allow/deny, and `mute --session` loads a live mute into the overlay (there is no session-scoped `unmute` — a live mute dies with the session).`

**Rectification du vérificateur.** Confirmed as filed. One citation slip in the supporting evidence, not the anchor: the manual-rule render is src/cli/net.rs:2778, not 2769. The anchor line 46 is exact.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified at src/cli/net.rs:45-46 (`// ... Both are // config-level (the same scopes as allow/deny) — a live `--session` mute is not yet wired.`), and the whole path exists: net_add_rule dispatches `--session` at src/cli/net.rs:3013 (`return net_inject_session(list, &rule, all, parsed.app.as_deref(), &cwd);`); net_inject_session at src/cli/net.rs:3164 does `EgressList::Mute => sandbox::control::inject_mute(&data_dir, pid, rule)`; src/sandbox/control/client.rs:601-603 sends `REMEMBER MUTE <rule>` via send_remember; src/sandbox/control/mod.rs:1215-1226 parses the `MUTE ` prefix and calls `manual.remember_mute(rule)`; src/sandbox/proxy/ctx.rs:805 folds it in (`mute.extend(ctx.manual.mute_snapshot());`) with the comment "a live `sbx net mute --session` — folds onto the config mutes"; and src/cli/net.rs:2778 renders it back as `ManualKind::Mute => NetRuleKind::Mute`. The help page contradicts the comment outright: src/help.rs:2439 synopsis is `sbx net mute <rule> [-l|--local|-g|--global] [-a|--app <name>] [--session [--all]]` and src/help.rs:2472-2476 documents "`--session` instead loads the mute into the **live overlay** ... it quiets the log immediately". Nothing in the tree gates or stubs the mute injection. The comment is stale on both clauses ("Both are config-level" and "not yet wired").

</details>

---

### B30 — `net groups export --out` writes non-atomically and will not create its parent directory, unlike the identical `bundle export --out`
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/net.rs:2424` |
| **Catégorie** | `inconsistency` |
| **Sous-système** | CLI — sbx net |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** The `--out` arm writes the fragment straight through:

```rust
Some(path) => match std::fs::write(path, &fragment) {
```

Its exact twin, `sbx bundle export --out` (`cli/bundle.rs:271-281`), routes through `config::manage::write_text(&path, &fragment, None)`, whose doc (`config/manage.rs:1330-1340`) states the reason verbatim: "A fragment written straight through leaves a truncated file at a destination whose whole purpose is to be imported back, which is the half-write this function exists to prevent for the config itself." `write_text` also does `create_dir_all(dir)` and writes to a pid-suffixed temp before `rename`. The two commands are otherwise presented as the same command in two namespaces — same synopsis shape, same `-o|--out`, same "the inverse of `import`" help wording, same portable-fragment purpose.

**Scénario.** `sbx net groups export --out ~/backup/2026-08/groups.toml` fails with `sbx: net groups export: cannot write /home/u/backup/2026-08/groups.toml: No such file or directory` when the directory does not yet exist, while `sbx bundle export --out ~/backup/2026-08/bundles.toml` in the same shell creates it and succeeds. Separately, a write interrupted part-way (full filesystem, ENOSPC) leaves a truncated `[network.groups]` fragment at the destination — the file whose entire purpose is to be fed back to `sbx net groups import`, which will then import a silently short group list.

**Correction proposée.** Use the shared writer the twin uses:

```rust
Some(path) => match config::manage::write_text(path, &fragment, None) {
```

(keeping the existing error arm, which already formats a `ManageError` fine via `{e}`).

**Rectification du vérificateur.** "Its exact twin" overstates the asymmetry: there are three export commands, and `sbx app export --out` (src/cli/app.rs:884, `if let Err(e) = std::fs::write(path, &bytes)`) behaves exactly like `net groups export`. So the split is two-vs-one with `bundle export` as the outlier, and which side is the defect is a judgment call — write_text's own doc frames `--out` as the same spelling as a shell redirect (src/config/manage.rs:1338-1340), and a shell redirect neither creates parent directories nor writes atomically. The defensible statement is that the three `--out` paths disagree and nothing declares why; the ENOSPC half-write half of the argument is the weaker half.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The code difference is real. src/cli/net.rs:2424 is `Some(path) => match std::fs::write(path, &fragment) {`, error-formatted at src/cli/net.rs:2432-2435 as `sbx: net groups export: cannot write {path}: {e}` — exactly the quoted failure text. src/cli/bundle.rs:275 uses `config::manage::write_text(&path, &fragment, None)`, and write_text (src/config/manage.rs:1341-1367) does `std::fs::create_dir_all(dir)` then writes a `.{name}.sbx-tmp.{pid}` and `rename`s it. write_text's doc at src/config/manage.rs:1330-1333 states the rationale the reporter quotes verbatim. No comment, test, or caller in net_groups_export (src/cli/net.rs:2351-2438) explains or prevents the straight-through write, and the docs (docs-site/docs/guide/networking/groups.md:120-123) claim nothing either way. Survives, but as a low-value inconsistency rather than a wrong answer: the command reports the failure accurately, and the destination is a user-named artifact, not sbx's own config.

</details>

---

### B31 — `render_stats`'s "(other hosts)" overflow row is padded to the host column width and misaligns the numeric columns
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/net.rs:1243` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | CLI — sbx net |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `host_w` is derived only from the real host rows (line 1219-1225: `rows.iter().map(|(host, _)| host.len()).max().unwrap_or(4).max(4)`), but the overflow row is printed with that same width using a 13-character literal:

```rust
let _ = writeln!(
    o,
    "  {dim}{:<host_w$}{r}  {:>6}  {:>6}  {:>7}",
    "(other hosts)", folded.allow, folded.deny, folded.blocked
);
```

Whenever the longest recorded host is shorter than `"(other hosts)".len() == 13`, the row overflows its column and pushes ALLOW/DENY/BLOCKED right by `13 - host_w` characters relative to the header and every other row. The existing test `render_stats_shows_the_folded_destinations_as_their_own_row` (line 5128) only asserts `contains("(other hosts)")` and `contains("44")`, so nothing pins the alignment.

**Scénario.** A project whose recorded destinations are short (`pypi.org`, `crates.io` — `host_w == 9`) and that exceeded the 256-host cap. `sbx net stats` prints:

```
  HOST       ALLOW    DENY  BLOCKED
  pypi.org      12       0        0
  (other hosts)       0      44        2
```

The fold row's `0 / 44 / 2` sit four columns right of the headers they belong to, so the counts read as if they were under DENY/BLOCKED/(nothing). The degenerate case in the code's own test — a tally with only overflow counts — gives `host_w == 4` and a nine-character shift.

**Correction proposée.** Include the literal in the width: `let host_w = rows.iter().map(|(h, _)| h.len()).max().unwrap_or(4).max(4);` becomes `... .max(if tally.overflow.total() > 0 { "(other hosts)".len() } else { 4 });` — or unconditionally `.max("(other hosts)".len())` when a fold row is possible.

**Rectification du vérificateur.** Confirmed as filed, including the arithmetic. Cosmetic only — the numbers themselves are correct and the JSON path (src/cli/net.rs:1168-1184) is unaffected, so this misleads a reader of the table and nothing else.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Confirmed. `host_w` is computed at src/cli/net.rs:1218-1223 from the real host rows only (`rows.iter().map(|(host, _)| host.len()).max().unwrap_or(4).max(4)`), and the fold row at src/cli/net.rs:1240-1245 reuses it with a 13-character literal: `"  {dim}{:<host_w$}{r}  {:>6}  {:>6}  {:>7}", "(other hosts)", folded.allow, folded.deny, folded.blocked`. Rust's `{:<width$}` pads but never truncates, so whenever the longest recorded host is under 13 characters the fold row runs `13 - host_w` columns wide and shifts ALLOW/DENY/BLOCKED right relative to the header and every host row. The header (src/cli/net.rs:1226-1230) and the host rows (1231-1237) both use the same unpadded `host_w`, so they stay aligned with each other and only the fold row breaks. Nothing prevents short hosts, and the only test covering this row, `render_stats_shows_the_folded_destinations_as_their_own_row` (src/cli/net.rs:5128), builds a tally whose sole host is `busy.test` (9 chars, so `host_w == 9`) and asserts only `folded.contains("44") && folded.contains("2")` (src/cli/net.rs:5149-5153) — it reproduces the misalignment and asserts nothing about it. The second half of that test, the overflow-only tally (src/cli/net.rs:5155-5166), gives `host_w == 4` and a 9-column shift.

</details>

---

### B32 — `task show <invocation-id>` answers from an arbitrary session; invocation ids are per-session, not globally unique
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/task.rs:1185` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | CLI — sbx plugins et sbx task |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** The comment at lines 1185-1187 states "An invocation id belongs to exactly one session; an operation name can be declared in several, and then `--session` is how a reader says which". That is false: ids come from `static TASK_INVOCATION: AtomicU64 = AtomicU64::new(1)` (src/sandbox/task.rs:90-96), a **per-process** counter, and the task plane runs inside each session's own process. Every session therefore hands out ids starting at 1. The loop at lines 1190-1196 takes the first plane that answers `Ok` — planes come from `session_pids`, which is sorted, so the lowest pid always wins — and pushes the rest onto `also`, which is then reported as "`{target}` is also **declared** in session(s) …" (line 1246), wording that only makes sense for an operation name. `read_info` resolves a numeric target against that session's own engine and log (src/sandbox/task_control.rs:1281-1288, 1108-1142), so a colliding id in a different session is a different invocation entirely. Note the inconsistency: `task_result` goes through `plane_for`, which refuses and demands `--session` when several sessions exist, while `task_show` guesses.

**Scénario.** Two sessions are live, pids 100 and 200. In session 200, `sbx task run --detach nightly-dump` prints `7`. `sbx task show 7` resolves planes [100, 200], session 100's log also holds invocation 7 (its seventh `unit-test` run), so session 100 answers first. The user is shown `operation unit-test`, that run's state, exit code and elapsed time — the wrong invocation — with a `session 100 — /path/to/other-project` line and a note claiming `7` is 'also declared' elsewhere.

**Correction proposée.** When `target` parses as a `u64` and more than one plane answers, refuse the way `resolve_task_session` does — name the sessions and require `--session` — rather than taking the first. Failing that, phrase the note for an id ("invocation `{target}` also exists in session(s) …") and correct the comment at line 1185.

**Rectification du vérificateur.** Mechanism verified; severity slightly overstated. `plane.announce()` (src/cli/task.rs:1206, printing `session <pid> — <project>`) runs before the fields, and the `also` note lists the other sessions, so the collision is visible rather than silent — and when the colliding ids belong to differently-named operations the `operation` row itself gives it away. The substantive defects are the false comment at src/cli/task.rs:1185-1187, the id/operation-blind note wording at line 1248, and the inconsistency with `plane_for`'s refusal; a genuinely misleading read needs the same operation name declared in both sessions.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Confirmed. `static TASK_INVOCATION: AtomicU64 = AtomicU64::new(1)` (src/sandbox/task.rs:90) is a process-global counter drawn by `next_invocation()` (src/sandbox/task.rs:95-96), whose only production caller is the per-session plane at src/sandbox/task_control.rs:933 — so every session numbers from 1 and ids collide across sessions, contradicting the comment at src/cli/task.rs:1185-1187 ("An invocation id belongs to exactly one session"). `task_show` fans out over `planes_for` (src/cli/task.rs:1181) whose pids come from `session_pids`, sorted at src/sandbox/task_control.rs:1490, and the loop at src/cli/task.rs:1190-1196 keeps the first `Ok` and pushes the rest onto `also`. The plane resolves a numeric target against its own engine and log (src/sandbox/task_control.rs:1276-1284 -> `finished_fields` -> `log.entry(id)` at 1281-1288), so a colliding id is a different invocation. The divergence from `task result`/`task stop`, which go through `plane_for` -> `resolve_task_session` and refuse ambiguity with "name one with `--session`" (src/cli/task.rs:228-236, 262-275), is real, and the note's wording "is also declared in session(s)" (src/cli/task.rs:1248) only fits an operation name.

</details>

---

### B33 — `plugins store install` and `plugins store update` silently drop every argument past the ones they read
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/plugins.rs:1169` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | CLI — sbx plugins et sbx task |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `plugins_store_install` reads only `args.first()` and `args.get(1)` (lines 1169-1172) and `plugins_store_update` reads only `args.first()` (line 1111); neither validates the tail. Every sibling verb in this file refuses extras: `plugins list`, `plugins info`, `plugins install`, `plugins verify` (lines 26-49), `plugins store info` and `plugins store rm` (lines 771-784) all route through `crate::cli::reject_extra`, and `store list`/`store add`/`store publish`/`store verify`/`store rekey` each reject an unrecognised token explicitly. As a result the two placement verbs accept a mistyped or extra operand, act on a subset of what was asked, and exit 0. `store update` additionally treats an unknown option as a store name, so `--all` produces `cannot update store '--all'` at exit 1 instead of a usage error at exit 2.

**Scénario.** `sbx plugins store install mine kp vault` installs only `kp`, prints the single success confirmation and exits 0 — the user believes `vault` was installed too and only discovers otherwise at the next launch. Likewise `sbx plugins store install mine kp --dry-run` performs a real install while silently discarding the flag, and `sbx plugins store update mine other-store` refreshes only `mine`.

**Correction proposée.** Guard both dispatch arms the way `store info`/`store rm` are guarded: `crate::cli::reject_extra(&["plugins","store","install"], args.get(2..).unwrap_or(&[]))` before `plugins_store_install`, and `reject_extra(&["plugins","store","update"], args.get(1..).unwrap_or(&[]))` before `plugins_store_update` (also catching the `-`-prefixed token case there).

**Rectification du vérificateur.** Real and correctly located, but medium overstates it. The consequence is a usage-validation inconsistency, not a wrong result: `store install mine kp vault` prints exactly one `render_plugin_installed` confirmation naming `kp` (src/cli/plugins.rs:1188-1197), so the output does not claim `vault` was installed — the user has to infer the omission rather than being told a falsehood. The `--dry-run` example in the report is a flag `store install` never had, so it is a mistyped-token case like any other.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Confirmed by reading both arms. `plugins_store_install` binds only `args.first()` and `args.get(1)` (src/cli/plugins.rs:1169-1172) and never inspects `args.get(2..)`; `plugins_store_update` binds only `args.first()` (src/cli/plugins.rs:1111-1118) and ignores the tail. The dispatch at src/cli/plugins.rs:765 and 764 passes `&args[1..]` straight through with no guard, while the siblings two arms below do guard: `store info` (768-774) and `store rm` (775-781) call `crate::cli::reject_extra(..., args.get(2..))`, and `plugins list`/`info`/`install`/`verify` do the same at lines 26-49. `store list`, `store add`, `store publish`, `store verify` and `store rekey` each reject an unrecognised token explicitly (src/cli/plugins.rs:1507-1513, 819-826, 1292-1299, 1357-1364). `reject_extra` exits 2 with `sbx: <path> takes no argument '<tok>'` (src/cli/mod.rs:39-54). The `--all` case also checks out: the token is accepted as a store name, `stores::update` -> `read_configured` fails (src/plugins/stores.rs:918-923), producing `sbx: cannot update store '--all': …` at exit 1 instead of a usage error at exit 2. No comment anywhere in either function claims the tolerance is deliberate, and no test pins it.

</details>

---

### B34 — Dispatch docs promise a built-in/embedded plugin store and a built-in plugin install; neither exists
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/plugins.rs:752` |
| **Catégorie** | `doc-drift` |
| **Sous-système** | CLI — sbx plugins et sbx task |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** Line 752-753 documents `plugins store` as "`list` shows the built-in (embedded) store and every configured remote store". `plugins_store_list` only ever iterates `stores::list(layout)`, which reads directory entries under `layout.stores_dir()` (src/plugins/stores.rs:668-680) — the configured remote stores and nothing else — and prints the single heading `configured plugin stores`. There is no embedded store anywhere in the tree (`grep -rn 'embedded' src/plugins/` finds nothing). The module header at line 2 has the matching stale claim, "`install`/`rm` (place a local or built-in plugin)": `plugins_install` only takes a source directory, and `origin::Origin` has exactly three variants — `Local`, `Store`, `Unknown` — with no built-in among them. The same header also omits `upgrade`, `verify`, `store verify` and `store rekey`, all of which the dispatch handles. The vestigial `what`/`install_cmd` parameters of `print_source_footer`, which has exactly one caller passing `"this store"`, are the residue of the removed second source.

**Scénario.** A maintainer (or a user reading the rendered docs) follows line 752 and runs `sbx plugins store list` on a machine with no store configured, expecting the built-in catalogue. The output is `configured plugin stores: (none)` plus the `store add` hint, exit 0 — the promised built-in listing never appears, and there is no command that produces one.

**Correction proposée.** Delete the 'built-in (embedded) store' clause from line 752 and 'or built-in' from line 2, and add the missing verbs (`upgrade`, `verify`, `store verify`, `store rekey`) to the module header. If the parameterisation is no longer earning its keep, collapse `print_source_footer`'s `what`/`install_cmd` to the single store case.

**Rectification du vérificateur.** The code facts hold, but the failure scenario is wrong: every cited claim lives in internal `//!`/`///` comments, not in user-facing output. The `plugins store list` help page (src/help.rs:2953-2972) correctly says "Every configured store" with no mention of a built-in one, so no user following the rendered CLI docs is misled — the audience for the stale text is maintainers reading `mise run rustdoc` output. Worth adding to the same cleanup: the `plugins_cmd` doc at src/cli/plugins.rs:22-24 is stale in the same direction ("A read-only diagnostic for now; installation and the signed plugin store are later increments, so the dispatch only knows the inspection verbs") when the dispatch already handles `install`, `rm`, `upgrade` and the whole `store` tree.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Confirmed as doc drift. src/cli/plugins.rs:752-753 says `list` shows "the built-in (embedded) store and every configured remote store", but `plugins_store_list` (src/cli/plugins.rs:1650-1685) only reads `stores::list(layout)` and prints `configured plugin stores`/`configured plugin stores: (none)`; there is no embedded catalogue anywhere (`grep -rn 'embedded' src/` hits only the mise plugin, the notify logos and the audio sitecustomize; no `include_str!`/`include_bytes!` of a catalogue). The module header at src/cli/plugins.rs:2 still says "`install`/`rm` (place a local or built-in plugin)" while `origin::Origin` has exactly `Local`/`Store`/`Unknown` (src/plugins/origin.rs:31-47), and line 3 omits `upgrade`, `verify`, `store verify` and `store rekey`, all dispatched at lines 45-51 and 766-767. `print_source_footer`'s `what`/`install_cmd` (src/cli/plugins.rs:1606-1620) do have exactly one caller, passing "this store" (lines 1731-1738).

</details>

---

### B35 — `task run`'s doc comment says a refusal is exit 2; it is 125
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/task.rs:623` |
| **Catégorie** | `doc-drift` |
| **Sous-système** | CLI — sbx plugins et sbx task |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** Line 622-624 documents `task_run` as "a *refusal* (an unknown task, a value outside its bound) is exit 2, distinguishable from the command having run and failed". Every refusal path returns `REFUSED_EXIT` = 125 instead: `render_result` (line 753), `run_as_json` (line 1045) and `run_detached` (lines 741, 862). The constant's own doc at lines 28-32 explains why 2 was rejected — "that is a plausible exit code for the wrapped command itself, and a caller must be able to tell 'sbx refused to run it' from 'it ran and exited 2'" — and help.rs:966 documents 125 to users. Only this one comment still says 2, which is the value the design deliberately does not use.

**Scénario.** A maintainer writing a wrapper reads line 623 and branches on `if [ $? -eq 2 ]` to detect a refusal. `sbx task run no-such-op` returns 125, the branch never fires, and a refused invocation is handled as if the wrapped command had run and exited 125.

**Correction proposée.** Change 'is exit 2' to 'is exit 125' at line 623 (or point at `REFUSED_EXIT`), matching lines 28-32 and help.rs:966.

**Rectification du vérificateur.** Accurate as reported, though its practical reach is smaller than the attack suggests: the wrong number lives only in a private `fn task_run` rustdoc comment, not in any user-facing output — `sbx help task run` (help.rs:966) and the `REFUSED_EXIT` constant both say 125 — so only a maintainer reading the source, not a user reading `--help`, can be misled.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified verbatim. src/cli/task.rs:622-624 reads "a *refusal* (an unknown task, a value outside its bound) is exit 2, distinguishable from the command having run and failed", while src/cli/task.rs:32 defines `const REFUSED_EXIT: u8 = 125;` and every refusal path returns it: line 741 (`--detach --json`), line 753 (`--detach` prose), line 862 in `render_result` — whose own comment at 857-859 says "Not 2: that is a plausible exit code for the wrapped command itself, and a caller must be able to tell 'sbx refused to run it' from 'it ran and exited 2'" — and line 1045 in `run_as_json`. help.rs:966 documents "is exit **125**" to users. No path returns 2 for a plane refusal (exit 2 is reserved for argument/usage errors, e.g. task.rs lines 663, 674, 682). The doc comment states the exact value the design explicitly rejected, in the wording of the category it rejected it for.

</details>

---

### B36 — A store listing offers a broker/signer entry whose name is already taken, because the name check reads directory names instead of manifest names
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/plugins.rs:360` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | CLI — sbx plugins et sbx task |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : moyenne) |

**Constat.** `InstalledIndex::marker` returns early for a scheme-less entry at lines 360-364, with the comment "A broker claims no scheme … its namespace is its name, which the `by_name` check above already answered." `by_name` is keyed by *directory* name (built from `read_dir` at lines 246-273, documented at lines 82-85 as 'the name an install would take'), but an install actually keys on the **manifest's** `name` — `install_inner` computes `let name = probe.name()` and refuses when `installed.broker(&name)`/`signer(&name)` resolves to a plugin whose directory differs from `dest` (src/plugins/mod.rs:1379-1401). For plugins sbx placed the two coincide, but the codebase explicitly supports hand-placed trees where they do not (see `About::dir_name`, lines 2187-2190: 'It may differ from the manifest's `name` for a hand-placed tree'). Resolvers are covered by the independent `by_scheme` index; scheme-less kinds have no such backstop, so the collision is invisible to the listing — exactly the failure the `InstalledIndex` doc at lines 78-81 says it exists to prevent.

**Scénario.** A user hand-places a broker at `<data>/plugins/vault-dev/` whose `plugin.toml` declares `name = "vault-broker"`. Store `mine` lists a broker named `vault-broker`. `sbx plugins store list` renders `vault-broker (broker)` with no marker — an entry the listing says is installable. `sbx plugins store install mine vault-broker` then fails: `the plugin name `vault-broker` is already taken by the installed plugin from an unknown source — remove it first with `sbx plugins rm vault-dev``.

**Correction proposée.** Index the scheme-less namespace by manifest name as well: in `InstalledIndex::scan`, record `registry.brokers()`/`signers()` under `p.name` in a `by_plugin_name` map, and in `marker` consult it before the scheme-less early return, emitting the same `[name taken by …]` marker the `by_name` branch produces. Then correct the comment at line 360-361.

**Rectification du vérificateur.** The mechanism is right but the description slightly misstates which check is directory-keyed: the install's *first* refusal (`dest.exists()`, mod.rs:1326-1346) is directory-keyed on both sides, so `by_name` is correct for it — the uncovered one is only the second, name-namespace check at mod.rs:1388-1404. Reachability requires a hand-placed tree, since an sbx-performed install always names the directory after the manifest `name` (mod.rs:1315/1327), so dir and manifest name can never diverge for anything sbx placed. Impact is confined to a missing advisory marker in `plugins store list`: the install itself still fails closed with a correct, remediating message. The concrete defect worth fixing is the inaccurate comment at plugins.rs:360-361 plus the missing manifest-name index.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Traced end to end and nothing prevents it. `InstalledIndex::by_name` is built from `read_dir` over `<data>/plugins` at src/cli/plugins.rs:263-289 and keyed by the *directory* name (comment at 222-224: "a hand-placed plugin may declare a manifest `name` that differs from its directory"); `by_scheme` (lines 226-229) is keyed by the manifest's `scheme`, so resolvers keep a manifest-side backstop. `marker` (line 313) looks up `by_name.get(name)` with the catalogue's entry name, and for a scheme-less entry (a broker/signer entry renders as `name (broker)` — line 1581-1584 passes `e.scheme = None`) returns `String::new()` at lines 362-364, guarded by the comment at 360-361 claiming "its namespace is its name, which the `by_name` check above already answered". The install path checks two different things: `dest = plugins_dir.join(&name)` where `name = probe.name()` (src/plugins/mod.rs:1315, 1327) — directory-keyed, correctly mirrored by `by_name` — and then a *second*, manifest-name-keyed refusal at src/plugins/mod.rs:1388-1404 (`installed.broker(&name)`/`signer(&name)`, whose maps are keyed by `plugin.name` per src/plugins/mod.rs:514-524, then `dir != dest`). Nothing in `load_one` requires the directory name to equal the manifest `name` (src/plugins/mod.rs:811-812 defaults `name` to the directory name only when absent), and `ResolverPlugin::dir_name`'s doc at 187-190 states the two may differ for a hand-placed tree. So a hand-placed broker at `plugins/vault-dev` declaring `name = "vault-broker"` leaves the catalogue entry `vault-broker` unmarked while `plugins store install` refuses it at mod.rs:1399-1403 — exactly what the `InstalledIndex` doc at plugins.rs:78-85 says the index exists to prevent.

</details>

---

### B37 — `plugins info` reports a broker/signer name miss as an unclaimed resolver scheme, and offers no remediation
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/plugins.rs:2146` |
| **Catégorie** | `ux-error-message` |
| **Sous-système** | CLI — sbx plugins et sbx task |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `plugins_info` accepts three namespaces — a built-in scheme, a broker or signer *name* (lines 2110-2116), and a resolver scheme (line 2118) — as the help page's own synopsis says (`sbx plugins info <scheme|name>`, help.rs:2856-2861). The terminal miss at lines 2145-2147 names only one of them: `"sbx: no installed resolver plugin claims the scheme '{scheme}'"`. A user who mistypes a broker or signer name is told about resolver schemes, which is not the namespace they were using, and the message carries no hint (unlike the conflict branches just above it, which print the full conflict, or `task show`'s miss, which points at `task ls`).

**Scénario.** A signer plugin is installed as `aws-sigv4`. `sbx plugins info aws-sigv4x` prints `sbx: no installed resolver plugin claims the scheme 'aws-sigv4x'` and exits 1. The user, who never asked about a scheme, concludes their signer is not installed as a resolver problem and has no pointer to `sbx plugins list`.

**Correction proposée.** Phrase the miss over all three namespaces — e.g. `sbx: nothing installed answers '{scheme}' (no resolver claims it as a scheme, and no broker or signer is named that)` — and add `diag::hint("       `sbx plugins list` shows every installed plugin.")`, matching the remediation style used elsewhere in this file.

**Rectification du vérificateur.** The message is not factually false — no resolver does claim that token — so this is a message-scope and remediation gap rather than a wrong statement: it names one of the three namespaces the function itself accepts, and unlike its sibling branches it prints no hint. Worth adding: the drift is broader than the one string — the function's own doc comment at src/cli/plugins.rs:2085-2087 still describes the verb as `sbx plugins info <scheme>` and "an unknown scheme is a non-zero 'no such plugin'", predating the broker/signer lookups at 2112-2117, so a fix should correct that comment alongside the message.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Confirmed at the cited lines. `plugins_info` accepts three namespaces: a built-in scheme (src/cli/plugins.rs:2096-2099), a broker or signer *name* (lines 2112-2117, `registry.broker(scheme)` / `registry.signer(scheme)`, whose maps are keyed by manifest `name` per src/plugins/mod.rs:514-524), and a resolver scheme (line 2118). help.rs:2857 documents the synopsis as `sbx plugins info <scheme|name>` and its details say "a broker and a signer claim none, so each is named by its own name". The terminal miss at lines 2145-2147 emits only `"sbx: no installed resolver plugin claims the scheme '{scheme}'"` with no `diag::hint` following it, while the two conflict branches immediately above (2124-2141) print the full conflict, and comparable misses elsewhere do carry remediation (task.rs:1199-1202 points a `task show` miss at `sbx task status`/`task ls`). The only test locking this wording, tests/config.rs:1875-1877, exercises `plugins info nope` in a fixture holding a resolver only, so it does not sanction the narrow phrasing for a broker/signer name miss.

</details>

---

### B38 — `sbx store` reports sizes as "exact" when the reflink probe could not run at all
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/store.rs:151` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | CLI — verbes restants |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `build` sets `shares_storage: sandbox::supports_reflink(data_dir)`, and `supports_reflink` (src/sandbox/projectstore.rs:434) is `reflink_verdict(dir) == Some(true)` — it collapses `None` ("the probe could not be carried out") into `false` ("this filesystem definitely does not share storage"). `reflink_verdict` returns `None` whenever `fs::write` of the probe file fails: an unwritable data directory, or a full filesystem. `render` then prints the unqualified claim at line 279: "sizes count allocated blocks and a hardlinked file once; on this filesystem they are exact." The sibling probe guards against exactly this collapse and says so — `storage::Preflight` keeps `shares_blocks: Option<bool>` with the comment "A probe that could not be carried out stays `None`: an unwritable directory says nothing about its filesystem, and this decision must not read it as an answer" (src/storage.rs:1478-1481). So `sbx doctor` and `sbx store` reach opposite conclusions from the same unknown. The surrounding comment at src/cli/store.rs:149-150 ("the honesty of the sizes is decided by what this filesystem actually does") and the render comment at 262-268 ("the honest thing is to state the bound, not invent a number") both describe behaviour the code does not have. Separately, the module doc at src/cli/store.rs:8 calls the command "Read-only and cheap: a filesystem walk" — `supports_reflink` creates and removes two `.reflink-probe-*` files inside the user's data directory, which is not read-only and leaves litter in the listing if the process is killed mid-probe.

**Scénario.** Point `SBX_DATA_DIR` at a btrfs directory owned by another user (or run `sbx store` when that filesystem is out of space). `fs::write` of `.reflink-probe-src-*` fails, `reflink_verdict` returns `None`, `supports_reflink` yields `false`, and the report closes with "on this filesystem they are exact" for a copy-on-write, compressing filesystem where every printed size is in fact a large over-estimate — the precise opposite of the truth, delivered as a certainty.

**Correction proposée.** Make `shares_storage` an `Option<bool>` fed by `sandbox::reflink_verdict` (already `pub(crate)`), and give `render` a third closing sentence for `None` ("this filesystem's block sharing could not be probed, so the sizes may be an upper bound"). Also amend the module doc so the probe write is declared rather than denied.

**Rectification du vérificateur.** Real, but the impact is one advisory sentence and one JSON bool in an informational report, not a decision input — medium overstates it. The doctor comparison is also imprecise: `storage::Preflight` only probes at all for an unrecognized filesystem (`matches!(host_fs, Some(FsKind::Other(_)))`, src/storage.rs:1482-1484), so on the reporter's btrfs example doctor answers from the name table and never consults the probe; the two commands do not "reach opposite conclusions from the same unknown", they use different evidence. The "Read-only and cheap" module-doc nit (src/cli/store.rs:8) is fair — the probe does create and remove two files — but the files are removed before returning.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified end to end. src/cli/store.rs:151 is `shares_storage: sandbox::supports_reflink(data_dir)`; src/sandbox/projectstore.rs:434-435 is `reflink_verdict(dir) == Some(true)`, and its own doc at :430-433 says the collapse "counts as no, which is what a caller about to copy needs" and explicitly redirects: "A caller that must tell the two apart wants [`reflink_verdict`]" — `sbx store` is a reporter, not a copier, so it is the caller that must tell them apart and it picked the wrong function. src/sandbox/projectstore.rs:443-449 returns `None` when `fs::write` of the probe file fails, and the unit test at projectstore.rs:700-702 pins exactly that (`reflink_verdict(&closed) == None` while `!supports_reflink(&closed)`). src/cli/store.rs:269-280 then prints the unqualified "on this filesystem they are exact" for the false branch. Nothing on the path prevents it: `store_cmd` (src/cli/store.rs:77-117) creates nothing and only resolves `store::Layout::from_env()`, so a readable-but-unwritable `SBX_DATA_DIR` (or an out-of-space filesystem — the very condition that makes a user run `sbx store`) yields the wrong sentence, plus `"shares_storage": false` in `--json`. The reachability is narrow, though: `render` returns early at src/cli/store.rs:222-225 when the listing is empty, so the dir must be readable and non-empty while being unwritable.

</details>

---

### B39 — `closing_note`'s doc and `store_moved_note`'s doc both deny that `mise` can trigger the store-moved note, which it does
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/upgrade.rs:353` |
| **Catégorie** | `doc-drift` |
| **Sous-système** | CLI — verbes restants |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** The doc on `closing_note` states: "The scope is enforced twice over: only [`upgrade_nix_channel`] and [`upgrade_flake_packages`] return a [`Roll`] at all, so no other channel can set `moved_store_paths`" (lines 353-355). Three functions return `Roll`: `upgrade_nix_channel` (869), `upgrade_mise_tools` (963) and `upgrade_flake_packages` (1063), and `upgrade_cmd` ORs all three into `moved_store_paths` at lines 259, **273**, and 288. The match arm at line 370 is `"nix" | "flake" | "mise" if moved_store_paths`, and the comment immediately above it (365-369) correctly explains *why* mise is included. So the function's own header contradicts its body eight lines later. The same falsehood is repeated on the thing it routes to: `store_moved_note`'s doc at line 763 says "Only `nix` and `flake` reach this" and then explicitly excludes mise — "`mise` already rolls per-home inside a cage, so none of them moves the paths a home points into" — which is the reverse of the arm that dispatches to it. These are the two comments a maintainer reads before touching the store-invalidation logic, and both assert a safety invariant ("no other channel can set this") that the compiler does not enforce and the code does not honour.

**Scénario.** A maintainer adds a `Roll`-returning channel and relies on the stated invariant ("only these two return a Roll") to skip auditing `closing_note`, or reads `store_moved_note`'s header and concludes a `sbx upgrade mise` run can never print the store-moved warning. Today, `sbx upgrade mise` in a project whose `nix:` tools roll forward prints exactly that note — reachable, and contradicting the documentation of the function that prints it.

**Correction proposée.** Rewrite line 353-355 to name all three `Roll`-returning channels and drop the "no other channel can set `moved_store_paths`" claim, and rewrite line 763 (and the mise clause in 766-768) to match the arm at line 370: `nix`, `flake` and `mise` (via the project's `nix:` tools) reach it; `deb`/`appimage`/`tarball`/`binary` do not.

**Rectification du vérificateur.** Documentation drift only — no runtime behaviour is wrong, the arm at :370 is the intended one — so low rather than medium. There is a third instance the finding missed: src/cli/upgrade.rs:253-254, "Tracked across the two channels that build through nix", above a variable three channels write.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Both quoted comments are stale and the code contradicts them. Three functions return `Roll`: `upgrade_nix_channel` (src/cli/upgrade.rs:862-869), `upgrade_mise_tools` (:957-963) and `upgrade_flake_packages` (:1057-1063), and `upgrade_cmd` ORs all three into `moved_store_paths` at :259, :273 and :288 — so the claim at :353-355 ("only [`upgrade_nix_channel`] and [`upgrade_flake_packages`] return a [`Roll`] at all, so no other channel can set `moved_store_paths`") is false on both halves. The dispatch arm eight lines below at :370 is `"nix" | "flake" | "mise" if moved_store_paths => ClosingNote::StoreMoved`, routed to `store_moved_hint`/`store_moved_note` at :319-321 and :765. `store_moved_note`'s own header at :763-768 ("Only `nix` and `flake` reach this … `mise` already rolls per-home inside a cage, so none of them moves the paths a home points into") is the reverse of the arm that calls it. The path is reachable: `sbx upgrade mise` with no `--app` takes the `only.is_none()` branch at :266-273, and the block comment there (:268-272) states outright that the project's `nix:` tools "resolve to store paths the cage binds, so rolling one repoints exactly what a home can hold" — i.e. the body knows what both headers deny.

</details>

---

### B40 — `APP_SCOPED_TARGETS` doc says "Both" for three targets, and the refusal it feeds renders "provision and mise and nix"
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/upgrade.rs:39` |
| **Catégorie** | `doc-drift` |
| **Sous-système** | CLI — verbes restants |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `APP_SCOPED_TARGETS` is `&["provision", "mise", "nix"]` (line 43), but its doc (lines 39-42) reads "Both are the in-cage rolls, the ones whose unit of work is already one app's own cage; every other target rewrites a project-wide lock host-side and has no per-app unit to select." Two independent errors: it says "Both" of a three-element list, and its stated criterion is wrong for `nix` — `nix` is *not* an in-cage roll, it is a host-side lock rewrite (`upgrade_nix_channel`, line 862), and it is app-scoped for an entirely different reason, which src/help.rs:1639-1643 states correctly ("an app resolves the base channel against a lock of its own"). The user-facing refusal built from the same constant inherits the drift: line 151-156 formats `APP_SCOPED_TARGETS.join(" and ")` into "sbx: upgrade: --app narrows provision and mise and nix only — `<what>` rewrites a project-wide lock host-side, which has no per-app unit to select." That sentence is both ungrammatical and self-refuting, since it has just listed `nix` — a project-wide host-side lock rewrite — as a target `--app` does narrow. The doc comment at line 471-472 (`Advance::PerApp` … "the same two targets `APP_SCOPED_TARGETS` lets `--app` narrow") carries the same stale count.

**Scénario.** `sbx upgrade flake --app demo-app` prints: "sbx: upgrade: --app narrows provision and mise and nix only — `flake` rewrites a project-wide lock host-side, which has no per-app unit to select." A user who reads the clause literally concludes `nix` is not a project-wide lock rewrite, or that the tool has a display bug; a maintainer reading the constant's doc concludes `nix` was added by mistake and removes it, silently breaking `sbx upgrade nix --app <name>` (guarded only by the hand-written assertion at line 1638).

**Correction proposée.** Rewrite the doc on line 39-42 to cover all three and give `nix` its own reason (per-app lock target), matching src/help.rs:1639-1643. Build the message with an Oxford-comma join ("provision, mise and nix") and reword the second clause so it does not claim host-side lock rewrites are never app-scoped — e.g. "`<what>` has no per-app unit to select."

**Rectification du vérificateur.** Severity low is right, but two parts of the argument are overstated. The "maintainer removes `nix` and silently breaks it" scenario cannot be silent: src/cli/upgrade.rs:1637-1646 asserts `parse_upgrade_args(["nix", "--app", "demo-app"])` succeeds and its comment says it is "spelled out rather than derived from `APP_SCOPED_TARGETS`, so removing `nix` from that list fails here instead of quietly … leaving the suite green". And the refusal is not self-refuting: its second clause describes `<what>` — the target the user typed — which is an accurate description of `flake`/`deb`/`appimage`/`tarball`/`binary` (the defaulted `all` is the only loose fit). The genuine defects are the stale "Both"/"two" counts at :39-42 and :471-472 and the `join(" and ")` grammar at :155.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Confirmed at the cited lines. src/cli/upgrade.rs:39-42 opens "The targets `--app <name>` narrows. Both are the in-cage rolls…" over a three-element constant at :43 (`&["provision", "mise", "nix"]`), and the stated criterion is wrong for `nix`: `upgrade_nix_channel` (:862-915) is a host-side lock refresh, and src/help.rs:1639-1643 gives the correct and different reason ("and to `nix`, because an app resolves the base channel against a lock of its own"). The user-facing refusal at :151-156 does render `APP_SCOPED_TARGETS.join(" and ")` as "provision and mise and nix". The stale count is repeated at :471-472 (`Advance::PerApp` … "the same two targets `APP_SCOPED_TARGETS` lets `--app` narrow"), where the enum variant genuinely covers two but the constant it cross-references covers three.

</details>

---

### B41 — `sbx test net` with no URL prints the parent verb's usage line, and swallows an unknown flag as the URL
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/test.rs:72` |
| **Catégorie** | `ux-error-message` |
| **Sous-système** | CLI — verbes restants |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** When the positional target is missing, `net_test` reports `help::synopsis("test")` (line 72), which is `synopsis_of(&["test"])` = "sbx test <subcommand> <target>" (src/help.rs:3158, src/help.rs:368) — the *parent* command's grammar. The page for the verb the user actually ran exists and reads "sbx test net [--app <name>] [-X|--method <verb>] <url|tcp://host:port>" (src/help.rs:2111), and the same function reaches for the child page correctly everywhere else via the "sbx: test net: …" prefix. The user is therefore told to supply a `<subcommand>` they already supplied, and is shown neither `--app`, `-X`, nor the `tcp://` form. Compounding it, the positional arm at line 61 is `Some(s) if target.is_none() => target = Some(s)` — placed after the flag arms but with no `starts_with('-')` guard — so any unrecognised flag is consumed as the URL and the *next* argument is what gets blamed.

**Scénario.** `sbx test net -X POST -a claude` (URL forgotten) prints "sbx: usage: sbx test <subcommand> <target>", which names none of the flags just used and implies the subcommand was the mistake. `sbx test net --app=claude https://api.anthropic.com` — the `=` form that `sbx upgrade` accepts (src/cli/upgrade.rs:122) but this verb does not — consumes `--app=claude` as the target and fails with "sbx: test net: unexpected argument `https://api.anthropic.com`", blaming the one argument that was correct.

**Correction proposée.** Use `help::synopsis_of(&["test", "net"])` (or `eprint!("{}", help::page_usage(&["test", "net"]).unwrap_or_default())`, as `proc_ls` and `logs::run` do) at line 72, and add a `Some(s) if s.starts_with('-')` arm before line 61 that rejects the token as an unknown flag.

**Rectification du vérificateur.** Two corrections. (1) The line is src/cli/test.rs:73, not 72. (2) The 'swallows an unknown flag as the URL' half is milder than implied: a lone flag becomes the target, is completed to `https://--json`, and is then rejected by `parse_url_target` because `is_valid_hostname` forbids a label starting with '-' (src/allowlist/grammar.rs:459-460, 571), so `sbx test net --json` exits 2 with "sbx: URL `https://--json` has an invalid host `--json`" — a confusing message naming a URL the user never typed, not a silent zero-exit verdict. The genuinely wrong outcomes are therefore (a) the parent-grammar usage line, which names `<subcommand>` the user already supplied and shows none of `--app`, `-X` or the `tcp://` form, and (b) the misattributed blame when a flag is followed by the real URL. Fix as proposed: `help::synopsis_of(&["test", "net"])` at line 73 and a `Some(s) if s.starts_with('-')` arm before line 61.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified. src/cli/test.rs:73 reads `diag::error(&format!("sbx: usage: {}", help::synopsis("test")));` — the reporter cited 72 (the `let Some(target) = target else {` head at line 72), one line off, not enough to discredit. `synopsis("test")` = `synopsis_of(&["test"])` (src/help.rs:3158-3160) resolves to the PARENT page at src/help.rs:367-368, synopsis "sbx test <subcommand> <target>"; the child page exists at src/help.rs:2110-2111 with "sbx test net [--app <name>] [-X|--method <verb>] <url|tcp://host:port>". `net_test` is reached only from `test_cmd` (src/cli/test.rs:18) after the literal "net", so this message always concerns `test net` — and every other error in the function is prefixed "sbx: test net: …". The house convention is overwhelmingly the child path: 40+ call sites use `help::synopsis_of(&[parent, child])` (src/cli/proc.rs:701, src/cli/net.rs:161/242/326, src/cli/config.rs:78, src/cli/app.rs:193, src/cli/session.rs:169, …), and the shared grammar helper `parse_one_name` (src/cli/mod.rs:88-133) both rejects `-`-prefixed tokens with a hint and prints `synopsis_of(path)` for the exact path. No comment or test defends the parent synopsis here; grep across the tree finds the string "sbx test <subcommand> <target>" only at src/help.rs:368 and its use at src/cli/test.rs:73, so nothing pins the current text. The missing `-` guard at src/cli/test.rs:61 (`Some(s) if target.is_none() => target = Some(s)`, placed after the --app/-X arms) is verified: `sbx test net --app=claude https://api.anthropic.com` binds target="--app=claude" then hits the arm at line 62-65 and prints "sbx: test net: unexpected argument `https://api.anthropic.com`", blaming the correct token — and the `--app=` spelling really is accepted by `sbx upgrade` (src/cli/upgrade.rs:118-127) and by nothing else in this family. `--help`/`-h` never reaches here (intercepted centrally at src/main.rs:71-78), so no false claim there. tests/argv.rs sweeps `test net` only for a surplus SECOND positional (tests/argv.rs:150) and never for a flag, so the gap is untested rather than sanctioned.

</details>

---

### B42 — `sbx search` silently discards every flag-shaped argument instead of rejecting it
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/search.rs:13` |
| **Catégorie** | `inconsistency` |
| **Sous-système** | CLI — verbes restants |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** The query is picked as `args.iter().filter_map(to_str).find(|a| !a.starts_with('-'))` (lines 13-16). There is no flag table and no rejection path: any `-`-prefixed token is dropped without a word, and any non-UTF-8 argument is dropped by `filter_map` without the "argument is not valid UTF-8" diagnostic every sibling emits. The help page declares `options: &[]` (src/help.rs:354), so *every* flag here is a typo by construction — yet this is the only verb in scope that does not refuse one. `gc` (src/cli/gc.rs:19), `store` (src/cli/store.rs:85), `projects` (src/cli/projects.rs:47), `bundle` (src/cli/bundle.rs:38) and `proc`/`test` all exit 2 on an unknown argument. The comment at lines 10-12 documents ignoring further *words* (a deliberate nixhub single-token decision) but says nothing about ignoring flags, so the silence is not a recorded decision.

**Scénario.** `sbx search --json ripgrep` performs a normal human-formatted search and exits 0, with no indication that `--json` was discarded — a script that pipes the output to `jq` gets a parse error with no diagnostic to explain it. `sbx search --limit 5 ripgrep` searches for "5" (the first non-flag token after `--limit` is silently dropped as a flag), returning results for an unrelated query at exit 0.

**Correction proposée.** Parse the arguments with a loop like `gc`'s: accept exactly one non-flag positional, and return `ExitCode::from(2)` with `sbx: usage: {help::synopsis("search")}` for any `-`-prefixed token, plus the "argument is not valid UTF-8" arm for a `None` from `to_str`.

**Rectification du vérificateur.** Three corrections to the write-up. (1) The comment at src/cli/search.rs:10-12 does say "the first non-flag argument", so flag-skipping is at least acknowledged in the wording — it is only the silent ACCEPTANCE that is undocumented, not the skipping. (2) The parenthetical in the second attack is muddled: in `sbx search --limit 5 ripgrep` the token "5" is not dropped, it becomes the query (only `--limit` is dropped) — the stated outcome (searching for an unrelated query at exit 0) is nonetheless correct. (3) `--help`/`-h` is unaffected: it is intercepted centrally at src/main.rs:71-78 via `help::maybe_help` before dispatch, so only non-help flags are swallowed. The non-UTF-8 sub-claim is real but harmless in practice (a lone non-UTF-8 argument yields the usage error at exit 2 rather than the sibling verbs' "argument is not valid UTF-8" diagnostic).

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified. src/cli/search.rs:13-16 is exactly `args.iter().filter_map(|a| a.to_str()).find(|a| !a.starts_with('-'))`, with no flag table and no rejection arm anywhere in the 44-line file; the only error paths are the missing-query usage (line 18), the data-dir failure (line 22) and the nix-not-found failure (line 28). The help page declares `options: &[]` (src/help.rs:354, page at 350-365), so no flag is legitimate here. Dispatch is bare — `"search" => search::run(rest)` (src/cli/mod.rs:472) with no pre-parse — and `split_scope`'s unknown-flag refusal (src/main.rs:175-177) is only used by the net/proc rule fronts, so nothing upstream catches a stray flag. The sibling comparisons are all accurate: src/cli/gc.rs:19-21, src/cli/store.rs:85-89, src/cli/projects.rs:47-50 and src/cli/bundle.rs:40-44 each exit 2 on an unknown argument, and the shared helper `parse_one_name` (src/cli/mod.rs:101-107) does the same with a hint. The codebase states the principle itself in tests/argv.rs:3-6: "An unknown flag that is rejected costs one retry; one that is silently dropped answers a different question than the one asked, with a zero exit and output that looks right" — `search` is simply absent from READ_ONLY_VERBS (tests/argv.rs:59-82), an omission, not a documented exemption, and no test anywhere exercises `sbx search` with a flag. `sbx search --limit 5 ripgrep` really does search for "5" and exit 0.

</details>

---

### B43 — `--detach=false` / `--observe=false` / `--dry-run=false` turn the flag ON — `flag_name` strips the value for pure booleans
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/mod.rs:435` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | CLI — dispatcher, app, session, logs, storage |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** Both launch parsers dispatch on `flag_name(raw)`, which is documented (src/main.rs:346-350) as "stripping a `=value` suffix — so `--config` and `--config=x` both dispatch on `--config`". That is right for the value-taking flags, but the pure booleans are matched through the same helper and then set unconditionally: `sbx run`'s loop matches `"--detach" => { detach = true; ... }` (src/cli/mod.rs:435-438) and `"--observe" => { observe = true; ... }` (mod.rs:439-442), and `parse_app_launch` does the same at src/cli/app.rs:198 (`--detach`), 202 (`--observe`), 222 (`--dry-run`), 226 (`--global`/`-g`) and 231 (`--local`/`-l`). The `=value` is discarded and the flag is switched on regardless of what it said. Nothing in the surrounding comments contemplates an `=` form for these; only `--net-learn` reads its own suffix (app.rs:208-218). The CLI itself teaches the `=false` idiom — `--gpu[=true|false]`, `--audio[=true|false]`, `--dbus[=true|false]` are documented optional-value booleans (src/help.rs:167-178) handled by `take_flag_bool` — so a user or script that spells every flag `--name=value` lands here. This is precisely the failure `parse_app_launch`'s own doc says it exists to prevent: "a typo cannot silently launch a different posture (a mistyped `--detach` running attached …)".

**Scénario.** `sbx run --detach=false npm test` — the user explicitly asks not to detach, and sbx launches the session detached: the terminal returns immediately, the command's output goes to `<data>/logs/<pid>.log`, and its exit status is not propagated. Symmetrically `sbx app run demo-app --observe=false` turns the `[sbx:exec]` feed on, and `sbx app run demo-app --net-learn --dry-run=false` writes the learned egress rules to the profile when the user asked for a preview.

**Correction proposée.** Match these booleans on the raw token rather than on `flag_name(raw)` (or, in each arm, reject a token carrying an `=`): e.g. keep `match flag_name(&raw)` for the value flags but add a guard `raw.contains('=')` on the `--detach`/`--observe`/`--dry-run`/`--global`/`--local` arms that reports `sbx: --detach takes no value` and exits 2 — or route them through `take_flag_bool` so `=true`/`=false` mean what they say.

**Rectification du vérificateur.** Real but lower-impact than claimed. `--detach=false` is not a form the CLI documents: src/help.rs:102/106 spells the flag as a bare `--detach`, and only the optional-value booleans carry the `[=true|false]` grammar (src/help.rs:169-178, handled by `take_flag_bool` at src/main.rs:358-366). So the trigger is a user extrapolating from `--gpu=false`, not a documented spelling being mishandled — a strictness/anomaly bug rather than a likely field failure. Note the same swallowing applies to any `=` suffix on these arms, including `--help=x` and `--global=x`.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every citation checks out. src/main.rs:348-350 `fn flag_name(raw: &str) -> &str { raw.split_once('=').map(|(f, _)| f).unwrap_or(raw) }`. src/cli/mod.rs:434-442 dispatches `match crate::flag_name(raw)` with `"--detach" => { detach = true; cmd.remove(0); }` and `"--observe" => { observe = true; cmd.remove(0); }`; src/cli/app.rs:197-235 does the same for `--detach` (198), `--observe` (202), `--dry-run` (222), `--global`/`-g` (226), `--local`/`-l` (231). I traced `sbx run --detach=false npm test`: `flag_name` yields `--detach`, the arm sets `detach = true`, `cmd.remove(0)` discards the whole token, and src/cli/mod.rs:460 calls `crate::sandbox::run(cmd, detach=true, ...)`. Nothing downstream re-reads the token. `--net-learn` is the only arm that reads its own `=` suffix (app.rs:208-218), so this is not a general convention being applied. No comment or test contemplates the `=` form for the pure booleans, and the silent acceptance contradicts the strictness the same function advertises (app.rs:240-246 rejects any other unknown `-`-leading token with `unknown flag {raw}`).

</details>

---

### B44 — `sbx storage migrate` leaves the whole copy in the volume when verification fails, and says nothing about it
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/storage.rs:458` |
| **Catégorie** | `error-handling` |
| **Sous-système** | CLI — dispatcher, app, session, logs, storage |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `migrate` has two failure exits after the copy starts. The copy-*failure* path (storage.rs:440-454) sweeps: `let swept = volume_was_empty && clear_tree(&mount_point).is_ok();` and the message ends "and the volume was cleared, so this can simply be re-run". The copy-*verification* path immediately below (storage.rs:458-466) does not: on `copied != before` it returns `fail(...)` with the census diff and "{dir} is untouched and still in use", leaving the entire copied tree sitting in the mounted volume, running no sweep and never mentioning the volume's new contents. `volume_was_empty`, computed at storage.rs:439, is simply unused on this branch. The mismatch is an anticipated outcome — the comment at storage.rs:456-457 says "A count that drifted means something was not carried across — most consequentially the hardlinks a store deduplicates into" — so this is not a can't-happen path.

**Scénario.** Run `sbx storage migrate` on a data directory whose store carries hardlinks that `copy_tree` does not reproduce. The copy runs to completion, `copied != before`, and sbx reports "the copy does not match the original, so nothing was switched over … is untouched and still in use" and exits 1 — but the volume now holds a full `store/`, `projects/` and `apps/`. The user fixes the cause and re-runs `sbx storage migrate`, which now trips the guard at storage.rs:393-398 — "<mount> already holds store, projects, apps — refusing to migrate into it (--force overrides)" — a second, unrelated-looking error the first message gave no warning of, and whose only documented escape (`--force`) makes the next copy interleave with the stale one.

**Correction proposée.** Apply the same sweep on the verification-failure branch: `let swept = volume_was_empty && clear_tree(&mount_point).is_ok();` and extend the message the way the copy-failure branch does ("the volume was cleared, so this can simply be re-run"), or — when the volume was not empty to begin with and cannot be swept — say explicitly that the partial copy is still in the volume and that a re-run needs `--force`.

**Rectification du vérificateur.** The defect is real but the reporter's trigger is wrong, and reachability is much narrower than implied. Hardlinks that cannot be reproduced do NOT reach this branch: `std::fs::hard_link` at src/storage.rs:869 (and `symlink` at 852) return `Err`, which takes the copy-*failure* arm that already sweeps. `copied != before` requires the two tallies to disagree, and `census` (src/storage.rs:782-814) and `copy_tree` (827-889) count dirs/files/inodes/bytes/symlinks/special by identical rules, so the branch is defensive — it needs the source tree to change under the copy, which the live-session guard at storage.rs:377-382 already narrows. One correction in the reporter's favour: `--force` does not merely "interleave" on the re-run — `copy_tree` will hit EEXIST on the stale copy's symlinks/hardlinks (src/storage.rs:852, 869) and fail, and that failure will not sweep either because `volume_is_empty` is now false, so the user is genuinely stuck without manually clearing the volume.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The asymmetry is exactly as described. src/cli/storage.rs:439 `let volume_was_empty = volume_is_empty(&mount_point);`; the copy-failure arm at storage.rs:443-452 sweeps with `let swept = volume_was_empty && clear_tree(&mount_point).is_ok();` and appends "and the volume was cleared, so this can simply be re-run"; the verification arm at storage.rs:458-466 returns `fail(...)` with "{dir} is untouched and still in use" and no sweep, no mention of the volume. Nothing unmounts on the way out — `fail` is only `diag::error` + `ExitCode::FAILURE` (storage.rs:135-138) and `ensure_mounted` (src/storage.rs:253-264) leaves the volume up — so the copied `store/`, `projects/`, `apps/` stay in place and the re-run trips `occupied_subtrees` at storage.rs:393-400. No comment defends the asymmetry; the mismatch is explicitly anticipated (storage.rs:456-457).

</details>

---

### B45 — `sbx logs -f`: a feed that answers with rows but no cursor makes the loop drop those rows and declare the session ended
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/logs.rs:708` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | CLI — dispatcher, app, session, logs, storage |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : moyenne) |

**Constat.** The merged follow loop collects each feed's new rows into `batch` and updates `feed.cursor = head` (logs.rs:694-707), then checks `if feeds.iter().all(|f| f.cursor.is_none())` and returns *before* `batch` is sorted and written (logs.rs:708-715). A feed can set its cursor to `None` on a **successful** read: `read_task_rows` deliberately returns `head = None` when `head == 0 && !rows.is_empty()` (logs.rs:378-382), the "older plane that cannot say what is new" case. When that is the last feed with a cursor, the rows it just handed back are silently discarded and the view prints "(session ended)" for a session that is still running. The first-read path handles this correctly — it keeps the rows and lists the feed under `unfollowable` (logs.rs:598-608), with a comment explaining that reading a missing cursor as a missing feed "threw those rows away and told the reader the session was recording nothing while holding its record in hand". The follow loop reintroduces exactly that.

**Scénario.** Follow a session whose control plane predates the append cursor (launched by an earlier sbx) and whose task log was empty at the first read: `sbx logs <pid> -f --feed task`. The first read returns no entries and `head=0`, so `head` becomes `Some(0)` and the feed is treated as followable. When the agent's first declared operation finishes, the next poll returns one entry with `head=0`, `read_task_rows` maps that to `None`, every cursor is now `None`, and sbx prints "(session ended)" and exits 0 — without ever printing the invocation it had just read, and while the session is still alive.

**Correction proposée.** Move the all-cursors-`None` check below the batch write, or write `batch` before returning: sort and emit `batch` (and the eviction note) first, then test `feeds.iter().all(|f| f.cursor.is_none())` and return. Distinguish the two ways a cursor becomes `None` if the "(session ended)" wording should not fire for a feed that merely stopped being followable.

**Rectification du vérificateur.** Survives, but two corrections. (1) The line citation for the head→None mapping is wrong: it is src/cli/logs.rs:391-394, not 378-382 (378-386 is the `token`/`subject` match on `e.refused`). (2) Reachability is legacy-only, which the reporter states but under-weights: the current plane always writes `head=` (src/sandbox/task_control.rs:1331) and `TaskLog::since` returns `inner.appended` (task_control.rs:502), which is ≥1 whenever any entry exists (incremented at 456), so a modern session can never produce head=0-with-rows; and no non-task feed can return `None` on a successful read, so the drop needs the task feed to be the last one holding a cursor. A simpler variant of the same root shows up first: with `--feed task` on such a plane and a *non-empty* first read, the feed is marked `unfollowable` (cursor `None`) and the very first poll 400 ms later prints "(session ended)" for a session that is still running — no rows lost, but the same wrong claim.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The load-bearing citation is right: src/cli/logs.rs:694-707 extends `batch` and sets `feed.cursor = head`, then 708-715 `if feeds.iter().all(|f| f.cursor.is_none()) { ... writeln!("(session {} ended)") ... return ExitCode::SUCCESS; }` fires before `batch.sort_by_key` (716) and the write block (717-734), so a batch collected in that round is discarded. A successful read can set the cursor to `None` — `read_task_rows` maps `head == 0 && !rows.is_empty()` to `None`. Tracing `sbx logs <pid> -f --feed task` against a plane that omits `head=`: first read returns no entries so `head` stays `Some(0)` and the feed is polled; a later poll returns a row with head still 0, the mapping yields `None`, every cursor is `None`, and the row is dropped while sbx prints "(session ended)" for a live session. The follow loop's own comment (logs.rs:686-689) explains only why a cursor may go `None`, not the ordering, and the first-read path deliberately does the opposite (logs.rs:601-620: it keeps the rows and lists the feed under `unfollowable`, with the comment "Reading the missing cursor as a missing feed threw those rows away and told the reader the session was recording nothing while holding its record in hand"). No test covers the follow loop (the only test in the module is `feeds_and_names_agree`, logs.rs:746-753).

</details>

---

### B46 — `sbx logs --feed <name>` reports "session N is recording nothing" when only the filtered feed is absent
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/logs.rs:621` |
| **Catégorie** | `ux-error-message` |
| **Sous-système** | CLI — dispatcher, app, session, logs, storage |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `--feed` narrows the list in place at logs.rs:592 (`feeds.retain(...)`), and the all-absent check that follows compares against the *narrowed* list: `if absent.len() == feeds.len()` (logs.rs:621) then `diag::error("sbx: logs: session {} is recording nothing.")` and exit 2. With a filter in play that sentence is false — it states a property of the whole session while only the selected subset was consulted. The message the code intends is defended in its own comment above ("'Recording nothing' is about feeds that did not **answer** …"), but the `--feed` interaction was not folded into the wording, and the hint loop underneath prints only the filtered feed's reason, so the reader is given a total verdict backed by a partial reading.

**Scénario.** Launch a session with a filtering `[network] mode` but without `--observe`, so `net` records and `fs` does not. `sbx logs 4242` shows the egress rows. `sbx logs 4242 --feed fs` prints "sbx: logs: session 4242 is recording nothing." plus one hint about `fs`, and exits 2 — telling the operator the session records nothing while the very next command shows its egress log.

**Correction proposée.** Word the refusal against what was asked for when `only.is_some()`: e.g. "none of the feeds you selected (fs) is recording for session 4242" plus the per-feed reasons, keeping the existing sentence for the unfiltered case. The `known` list is already available at logs.rs:588 to point at the feeds that were not asked about.

**Rectification du vérificateur.** Mechanism confirmed, with two corrections. (1) `known` is built at src/cli/logs.rs:586 (used at 588), not 588 — and it is the static seven-name list from `feeds_for`, which is what makes the case trivially reachable rather than a rare state. (2) The exit code itself is defensible — the operator asked for a feed that is not recording, so refusing is reasonable; the defect is purely the sentence, which asserts a whole-session property after consulting only the selected subset. Impact is a misleading message, not a wrong action.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Line numbers check out: `feeds.retain(|f| names.contains(&f.name.to_string()))` at src/cli/logs.rs:592 narrows the list, and the all-absent test at src/cli/logs.rs:621 is `if absent.len() == feeds.len()`, printing "sbx: logs: session {} is recording nothing." (src/cli/logs.rs:623) and returning ExitCode::from(2). Nothing prevents the narrowed case: `feeds_for` (src/cli/logs.rs:414-466) returns a fixed vec of all seven feeds regardless of what the session actually stood up, so the `known` check at src/cli/logs.rs:586-590 accepts `--feed fs` for every session; the fs socket then fails to connect for a session launched without `--observe` (absent text at logs.rs:440), while `net` is live for a filtering `[network] mode` (logs.rs:433). absent = feeds = [fs] and the totalizing sentence fires. The comment at src/cli/logs.rs:617-620 defends only the cursor-vs-answer distinction, and the tests cover the two cases separately (tests/logs.rs:596 narrowing with a live feed, tests/logs.rs:637-655 the unfiltered empty session) — none covers a filter that selects only an absent feed, so nothing documents this wording as deliberate.

</details>

---

### B47 — `sbx session stop --` takes `--` as a session id; the comment claims it ends option parsing
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/session.rs:221` |
| **Catégorie** | `doc-drift` |
| **Sous-système** | CLI — dispatcher, app, session, logs, storage |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** The unknown-flag guard is written `Some(flag) if flag.starts_with('-') && flag != "--" =>` (session.rs:222) and the comment directly above it (session.rs:220-221) explains the exemption as "`--` still ends the options for an id that genuinely starts with a dash." No such behaviour exists: there is no `only_positional` state in this loop (compare `split_scope` in src/main.rs:150, which does implement `--`), so a literal `--` falls straight through to `Some(id) => ids.push(id.to_string())` at session.rs:229 and becomes a target, while every token after it is still parsed as a flag. The premise is also unreachable — ids are PIDs, which never start with a dash — so the exemption is dead weight that only manufactures a bogus target.

**Scénario.** `sbx session stop -- 1234`. `ids` becomes `["--", "1234"]`. `sandbox::stop` (src/sandbox/launch.rs:2963-2971) stops 1234 correctly but reports "sbx session stop: no live session '--' — run `sbx session ls` to list them." and sets `any_missing`, so the command exits 2 even though the session the user named was stopped cleanly. A script checking the exit status concludes the stop failed.

**Correction proposée.** Either implement the terminator the comment describes (on `--`, set a `rest_are_ids` flag and push every later token as an id without flag parsing), or drop the `&& flag != "--"` exemption so a bare `--` is refused by the unknown-option arm, and delete the sentence that promises the behaviour.

**Rectification du vérificateur.** Survives as described. Worth noting the substantive half is the exit code, not the doc drift: a script running `sbx session stop -- <pid>` gets a clean stop plus exit 2 and a phantom target named '--'. The doc-drift half is real too (the comment promises a terminator the loop does not implement), and its stated premise is indeed vacuous since ids are PIDs.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified verbatim: the comment at src/cli/session.rs:220-221 reads "`--` still ends the options for an id that genuinely starts with a dash", the guard at src/cli/session.rs:222 is `Some(flag) if flag.starts_with('-') && flag != "--" =>`, and there is no `only_positional`-style state anywhere in the loop (src/cli/session.rs:199-236), so `--` falls through to `Some(id) => ids.push(id.to_string())` at src/cli/session.rs:229 and later tokens are still flag-parsed. Contrast src/main.rs:150 (`Some("--") => only_positional = true` inside `split_scope`), which is the behaviour the comment describes. The token reaches the loop unmodified: src/cli/mod.rs:412 hands `rest` to `session::session_cmd`, which slices it to `stop_cmd` at src/cli/session.rs:31 — no `--` stripping on that path (the only other `--` handling, src/cli/mod.rs:444, is inside the `run` arm). Consequence traced: `sandbox::stop` (src/sandbox/launch.rs:2963-2971) finds no session whose pid.to_string() equals "--", prints "sbx session stop: no live session '--'", sets any_missing, and returns `stop_exit_code(any_unstopped, any_missing)` = 2 even though the real pid was stopped. No test in tests/stop.rs exercises `--`.

</details>

---

### B48 — `sbx app rm <name> --purge` reports "no profile and no home" for a profile it just failed to delete
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/app.rs:1224` |
| **Catégorie** | `ux-error-message` |
| **Sous-système** | CLI — dispatcher, app, session, logs, storage |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `app_rm_purge_one` keeps `profile_failed` and `profile_removed` as separate flags precisely so an undeletable profile is not confused with an absent one — the long comment at app.rs:1172-1177 spells that out. But the no-op check at app.rs:1224 tests only `!profile_removed && report.found_nothing()`, so the `profile_failed` case falls into it and prints "sbx: nothing to purge for '{name}' (no profile and no home)" one line after "sbx: cannot remove {path}: {e}". The two messages contradict each other, and the second is the one that reads as the verdict. It also returns `acted: false`, which is what makes the batch in `app_rm_purge` skip its closing note (app.rs:1113-1121).

**Scénario.** Make the profiles directory non-writable (`chmod a-w ~/.config/sbx/apps`) and run `sbx app rm demo-app --purge` for an app with an imported profile and no home yet. Output: "sbx: cannot remove /home/u/.config/sbx/apps/demo-app.toml: Permission denied" followed by "sbx: nothing to purge for 'demo-app' (no profile and no home)" — the second sentence denies the existence of the file the first sentence just named.

**Correction proposée.** Guard the no-op arm with the flag the function already tracks: `if !profile_removed && !profile_failed && report.found_nothing()`. A `profile_failed` name should fall through to the summary path so it reports "purged with errors" (which `clean` at app.rs:1246 already computes from `profile_failed`), or get its own message naming the profile that survived.

**Rectification du vérificateur.** Survives, but two parts of the reporter's mechanism need correcting. (1) The comment at src/cli/app.rs:1172-1177 does not claim the no-op check distinguishes the two states — it says the collapsed flag "fed the 'nothing found' check and the summary's wording" and describes fixing the exit code/summary, so the no-op check was left as-is rather than contradicted. (2) The exit code is NOT wrong: `acted: false` also carries `ok: false`, so `app_rm_purge` sets had_error and `!purged_any` returns ExitCode::FAILURE (src/cli/app.rs:1077-1085). Skipping the closing gc note is also defensible, since nothing was actually reclaimed. The whole defect is the contradictory sentence.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Confirmed at the cited line: src/cli/app.rs:1224 is `if !profile_removed && report.found_nothing() {` followed by "sbx: nothing to purge for '{name}' (no profile and no home)" at src/cli/app.rs:1226, while the non-NotFound arm above (src/cli/app.rs:1213-1217) prints "sbx: cannot remove {}: {e}", sets `profile_failed = true` and yields `profile_removed = false`. `profile_failed` is consulted only at src/cli/app.rs:1246 (`let clean = report.failed.is_empty() && !profile_failed;`), which the early return at 1228-1231 never reaches. Reachability holds: `config::profile_path` (src/config/load.rs:658-660) only joins a path and never checks existence, so an existing profile in a non-writable directory yields Err(PermissionDenied), and with no homes on disk `report.found_nothing()` (src/sandbox/gc.rs:642-644) is true — the two contradictory sentences print back to back. No caller pre-validates that the profile exists (app_rm at src/cli/app.rs:912-952 only validates the name charset).

</details>

---

### B49 — The install's stdout tail is captured and then discarded, so a mise failure reported on stdout prints "no output"
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/taskpool.rs:543` |
| **Catégorie** | `error-handling` |
| **Sous-système** | Concurrence, verrous, pools |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `run`'s doc at taskpool.rs:502-505 states: "**Both** of mise's streams are piped and forwarded to sbx's own stderr as they arrive ... The tail of each is kept for the message when the install fails: mise's diagnostics are the only way to tell a registry outage from a typo'd token."

The code keeps only one. `out_reader` runs `tee_to_stderr` over the child's stdout and returns its `DIAGNOSTIC_TAIL` buffer — and line 543 throws that buffer away with `let _ = out_reader.join();`. `InstallRun` has a single `stderr: Vec<u8>` field (taskpool.rs:491-494), so there is nowhere for the stdout tail to go. The comment on line 542 explains why the *join* happens (ordering) and silently drops the returned bytes, which is the half the doc above promised to keep.

Both consumers of `InstallRun` render only that one stream: `ensure` at taskpool.rs:284-292 and `sbx upgrade` at launch.rs:1754-1761, which both fall back to the literal string "no output" when it is empty.

**Scénario.** A pool install fails for a reason mise reports on stdout (a backend that prints its resolution failure there, or a wrapped `npm`/`pip` whose diagnostic goes to stdout) while stderr carries only progress that ends empty after `trim()`. `ensure` then emits `the task tool pool did not install aqua:cli/gh — no output`, and `sbx upgrade` emits `mise upgrade failed: no output` — with the actual explanation having been read into `kept`, held in memory, and dropped one line later. The operator is left with exactly the "registry outage vs. typo'd token" ambiguity the doc says this machinery exists to resolve.

**Correction proposée.** Keep both tails, as documented. Add `stdout: Vec<u8>` to `InstallRun`, bind the join result (`let stdout = out_reader.join().unwrap_or_default();`), and have `ensure`/`launch.rs:1754` fall back to the stdout tail when the stderr tail is empty. Alternatively concatenate the two into the single `stderr` field before returning — either way, stop discarding the buffer the thread was spawned to fill.

**Rectification du vérificateur.** Severity overstated: the harm is a worse failure *message*, not lost diagnostics. Both streams are tee'd live to sbx's own stderr as they arrive (taskpool.rs:571), so mise's stdout output is already on the operator's terminal — the "registry outage vs. typo'd token" ambiguity the reporter describes is only in the one-line summary, with the full text scrolled just above it. Note also that `InstallRun`'s own doc at taskpool.rs:490 is honest ("its stderr for the message when it did not"); only the `run` doc at 504-505 overclaims, so the cleanest fix may be to correct that sentence rather than to add a field.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Confirmed as a documentation/code mismatch. taskpool.rs:504-505 states "The tail of each is kept for the message when the install fails: mise's diagnostics are the only way to tell a registry outage from a typo'd token." `out_reader` is spawned over `tee_to_stderr` at taskpool.rs:523, which returns the kept tail (taskpool.rs:563-580), and taskpool.rs:543 is `let _ = out_reader.join();` — the buffer is dropped. `InstallRun` has only `stderr: Vec<u8>` (taskpool.rs:491-494), so there is nowhere for it to go, and both consumers render that one stream with a "no output" fallback: taskpool.rs:282-292 and launch.rs:1753-1760 (`.lines().last().unwrap_or("no output")`). The comment on taskpool.rs:542 explains the join's ordering purpose only and does not address the discard, so the module-level promise at 504-505 is unfulfilled.

</details>

---

### B50 — A project `[broker.<name>]` table with no `allow` key silently clears the global config's broker policy
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/config/mod.rs:2095` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | Configuration — modèle, schéma, types |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : moyenne) |

**Constat.** `bound.allow = table.allow;` overwrites the globally-declared policy with the project table's `allow` unconditionally. `RawBrokerConfig::allow` is `#[serde(default)] Vec<String>` (schema.rs:786-787), so "the project said nothing about the policy" and "the project set an empty policy" are the same value here, and both wipe the global list. The surrounding code proves the case is reachable: the loop immediately above warns that a project's `socket` and `secret` are ignored (mod.rs:2067-2084), i.e. it expects project tables that exist for reasons other than setting `allow`. `broker_origin.insert(name, Provenance::Project)` then attributes the now-empty policy to the project, so `sbx config` blames the layer that never wrote it. The field's own doc frames `allow` as a narrowing or widening of what the global config exposed (schema.rs:780-787), not as a reset.

**Scénario.** Global `sbx.toml`: `[broker.gpg] socket = "$XDG_RUNTIME_DIR/gnupg/S.gpg-agent"` / `allow = ["sign"]`. A trusted project writes `[broker.gpg] socket = "/tmp/mine.sock"` trying to repoint the socket. sbx warns that the socket is ignored — and then sets `allow = []`. The gpg broker starts, every signing request is refused by an empty policy, and no warning connects that outcome to the project table. `sbx config` shows the empty `allow` with `Provenance::Project`.

**Correction proposée.** Only override when the project actually declared entries — `if !table.allow.is_empty() { bound.allow = table.allow; broker_origin.insert(name, Provenance::Project); }` — or make the field `allow: Option<Vec<String>>` in `RawBrokerConfig` so "unset" and "empty" are distinguishable, and warn when a project table sets nothing sbx reads.

**Rectification du vérificateur.** Mechanism confirmed at the cited line, but the stated consequence is asserted, not established. sbx does not interpret these entries: schema.rs:780-782 says "sbx does not interpret these: what an entry means belongs to the protocol the plugin speaks", and the list is passed verbatim in the handshake (`src/sandbox/broker.rs:191`, `let allow = serde_json::Value::from(self.allow.to_vec());`). So "every signing request is refused" is plugin-defined behaviour, not something sbx guarantees — the defect is that an unset project `allow` is indistinguishable from an empty one, silently replaces the global policy, and is then attributed to `Provenance::Project` (surfaced by `sbx config` via src/cli/config.rs:912). Real but low: it needs a project table containing only fields sbx already warns it is dropping.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified. src/config/mod.rs:2095 is exactly `bound.allow = table.allow;`, followed at 2096 by `broker_origin.insert(name, Provenance::Project);`, with no guard on whether the project actually wrote an `allow`. `RawBrokerConfig::allow` is `#[serde(default, skip_serializing_if = "Vec::is_empty")] pub(crate) allow: Vec<String>` (schema.rs:786-787), so absent and empty are the same `Vec::new()`. The loop above it (mod.rs:2069-2091) warns that a project's `socket` and `secret` are ignored and reports the table's unknown keys, proving project tables that carry no readable field are an anticipated case — so a project writing only `socket`, only `secret`, or a misspelled `alow` reaches line 2095 with an empty vector and wipes the global policy. The only test covering this path (mod.rs:5690-5718) exercises a project that *does* set `allow = ["list"]`; nothing covers the absent case.

</details>

---

### B51 — `Resolved`'s field docs state network and notify defaults the code does not implement
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/config/mod.rs:313` |
| **Catégorie** | `doc-drift` |
| **Sous-système** | Configuration — modèle, schéma, types |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** Three comments assert built-in defaults that contradict the code. (a) mod.rs:313-315 — "The resolved network posture: the default (`Shared`) unless the global config or a trusted project asked for `\"none\"`" — but the default is `NetworkPolicy::default()` = `Allowlist(EgressPolicy::default())`, the deny-by-default filtering posture, as `types.rs:230-255` states at length ("The default is the filtering allowlist, so a cage nobody configured reaches only the built-in self-equip set"), and the layer code falls back to exactly that at mod.rs:1815. The same stale claim is repeated in a schema test comment, schema.rs:2634-2635 ("the loader treats that as the default (shared)"). (b) mod.rs:340-341 — "the default (`once` for every event)" — and mod.rs:1842-1843 — "`parent` is the built-in default (every event `once`)" — but `NotifyPolicy::default()` is `uniform(NotifyMode::default())` and `NotifyMode`'s `#[default]` is `Always` (notify.rs:126-137), which is also what `RawConfig::notify` documents (schema.rs:159-160: "`\"always\"` (the default: every occurrence…)").

**Scénario.** A reader auditing the flagship posture reads `Resolved::network`'s doc and concludes that a machine with no `[network]` line anywhere hands the cage the host's network unfiltered, and that only `network = \"none\"` changes that. Both halves are false — the cage gets a deny-by-default allowlist, and `deny`/`allow`/`ask`/`shared` are all honored — so the comment misdescribes the single most security-relevant default in the crate, and the notify pair misstates whether a repeat is announced once or every time.

**Correction proposée.** Rewrite mod.rs:313-315 to name `NetworkPolicy::default()` (deny-by-default filtering allowlist) and to say the posture comes from the global config or a trusted project; change `once` to `always` at mod.rs:340 and mod.rs:1843; fix the stale test comment at schema.rs:2634-2635.

**Rectification du vérificateur.** Accurate as written, with one scoping nuance: sub-claim (c), src/config/schema.rs:2634-2635, sits inside the `#[cfg(test)]` module that opens at schema.rs:2160, so it is a stale comment in test code rather than in shipped documentation — the load-bearing half of the finding is (a) mod.rs:313 and (b) mod.rs:340 / mod.rs:1843, which are production doc comments on `Resolved`'s fields and in `resolve`'s global layer. Impact is documentation-only; no runtime behavior is wrong, and `network_origin`/`notify_origin` still report `Provenance::Default` correctly.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every cited line reads as claimed and every claim is contradicted by the code. src/config/mod.rs:313 — "/// The resolved network posture: the default (`Shared`) unless the global config" — but src/config/types.rs:248-255 is `impl Default for NetworkPolicy { fn default() -> Self { Self::Allowlist(crate::allowlist::EgressPolicy::default()) } }`, whose own doc says "Deny-by-default with no rules of its own: every host the cage reaches has to be named". The layer code agrees with types.rs and not with the field doc: src/config/mod.rs:1801-1802 comments "The parent of the global layer is sbx's built-in default (the `deny` allowlist)" and mod.rs:1815 is `None => NetworkPolicy::default()`. The field doc's second half ("unless … asked for `\"none\"`") is also wrong: `validate_network` accepts the table form with `mode` = deny/allow/ask as well. Notify: src/config/mod.rs:340 says "the default (`once` for every event)" and mod.rs:1843 says "default (every event `once`)", but src/notify.rs:181-184 is `NotifyPolicy::default() -> NotifyPolicy::uniform(NotifyMode::default())` and src/notify.rs:132-137 marks `Always` `#[default]` ("Every occurrence — the default"). The stale test comment is confirmed too, at src/config/schema.rs:2634-2635 ("the loader treats that as the default // (shared)"). Nothing in the surrounding prose reframes these as deliberate; they are three independent statements of a default the code does not have.

</details>

---

### B52 — `apply_override` adds credentials to `secrets` but leaves `declared_secrets` stale
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/config/mod.rs:1182` |
| **Catégorie** | `inconsistency` |
| **Sous-système** | Configuration — modèle, schéma, types |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : moyenne) |

**Constat.** `Resolved` keeps a pair: `secrets` (posture-cleared, effective) and `declared_secrets` ("The baseline credentials *before* the posture clear — what an app overlay inherits", mod.rs:467-473), snapshotted together at mod.rs:2489. `apply_override` folds an override's `[secret]` section into `self.secrets` (mod.rs:1182-1189) and re-runs `enforce_secret_posture`, but never touches `self.declared_secrets`, so after an override the two disagree. Nothing on the launch path notices — `merge_app` runs *before* `apply_override` — but `view.rs:1767` re-derives an app's effective credential set from `baseline.declared_secrets` *after* `apply_ambient_override` has run (view.rs:1578), so the display path reads the stale half.

**Scénario.** With `SBX_CONFIG='[secret."api.example.com"]\nfrom = "env://TOKEN"\nheader = "Authorization"\ntype = "bearer"'` exported, `sbx config show --app agent` builds `eff_secrets` from `declared_secrets` (which the override never reached) and reports that the app injects no credential for api.example.com — while `sbx app run agent` with the same environment injects it. The view under-reports exactly the field it exists to make visible.

**Correction proposée.** In `apply_override`, apply the override's section to both sets (or re-snapshot `self.declared_secrets = self.secrets.clone()` after `apply_secret_section` and before `enforce_secret_posture`), so the pair's invariant survives the final layer.

**Rectification du vérificateur.** Mechanism and line numbers are correct; two refinements. (1) The blast radius is display-only and under-reports rather than over-reports — `secrets_inherited` at view.rs:1874 is computed from the same stale `declared_secrets`, so both the credential list and the inherited count are low, but no launch injects anything it should not. (2) The reporter's suggested fix of re-snapshotting `self.declared_secrets = self.secrets.clone()` inside `apply_override` should be taken with care: `merge_app` restores that snapshot wholesale (mod.rs:782, documented at mod.rs:1352-1353 and asserted by `an_app_inherits_a_baseline_credentials_plugin_host_config` in src/config/tests.rs), so any future path that ran `merge_app` after `apply_override` would then inherit override credentials as baseline. Fixing the view to derive `eff_secrets` the way `merge_app` does — or applying the override section to both vectors — is the narrower change.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Traced end to end and nothing prevents it. `apply_override` folds the override's `[secret]` section into `self.secrets` at src/config/mod.rs:1182 (`apply_secret_section(&mut self.secrets, …)`) and re-runs `enforce_secret_posture(&self.network, &mut self.secrets, …)` at mod.rs:1191; `declared_secrets` is never written there. Grepping every reference confirms it: `declared_secrets` is written only at src/config/mod.rs:2489 (`let declared_secrets = secrets.clone();`, the pre-posture snapshot in `resolve`) and read at mod.rs:782, view.rs:1767 and view.rs:1874 — `apply_override` touches neither. The two paths then diverge exactly as reported. Launch: src/sandbox/launch.rs:876 `prep.cfg.merge_app(app);` then launch.rs:879 `apply_launch_override(&mut prep.cfg, ov)`, with the comment at launch.rs:877-878 stating the override is applied "*after* the app overlay" — so `merge_app`'s `self.secrets = self.declared_secrets.clone()` (mod.rs:782) runs first and the override's credential survives into the injected set. Display: `build_app_detail` calls `apply_ambient_override(&mut resolved)` at src/config/view.rs:1578, which reaches `resolved.apply_override(ov)` at view.rs:1008, and only afterwards does `app_detail_view` build `let mut eff_secrets = baseline.declared_secrets.clone();` at view.rs:1767 — reading the half the override never reached. The view explicitly claims to mirror the launch (view.rs:1763-1766: "Reproduce that check so the count — and the note — match what `sbx app <name>` would actually inject"), so this is a broken stated invariant, not a difference of expectation. The override path does carry `[secret]`: `RawConfig`'s `secret` is destructured in `apply_override` (mod.rs:871), merged by the collector at src/config/overrides.rs:635 (`if secret.is_some() { base.secret = secret; }`), and exercised with literally this shape in overrides.rs:1231/1666.

</details>

---

### B53 — `BundleProvision`'s doc comment opens with the first half of `ResolvedApp`'s sentence
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/config/mod.rs:503` |
| **Catégorie** | `doc-drift` |
| **Sous-système** | Configuration — modèle, schéma, types |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `BundleProvision` was inserted into the middle of `ResolvedApp`'s doc comment. Its first line is `/// An app's resolved overlay over the sandbox baseline: the command to run plus the extra` (mod.rs:503), which describes `ResolvedApp` and not a provision step, immediately followed by the real sentence "One bundle's install step, as the fold hands it to a launch…". The remainder of the orphaned sentence is then the opening line of `ResolvedApp`'s own doc, which begins mid-clause: `/// environment, binds, packages, network posture, and credentials it declares — each` (mod.rs:519).

**Scénario.** `cargo doc` renders `BundleProvision` with a summary line claiming it is an app's resolved overlay over the sandbox baseline, and renders `ResolvedApp` with a summary beginning "environment, binds, packages, network posture, and credentials it declares" — two wrong type summaries from one editing accident, in a crate whose doc comments are the primary specification.

**Correction proposée.** Move the dangling first line back onto `ResolvedApp` so its doc reads "An app's resolved overlay over the sandbox baseline: the command to run plus the extra environment, binds, packages, network posture, and credentials it declares — each …", and leave `BundleProvision`'s doc starting at "One bundle's install step".

**Rectification du vérificateur.** Confirmed as described; nothing to correct. Cosmetic/documentation only — it compiles, and `mise run rustdoc`'s broken-intra-doc-link denial does not catch a misplaced prose line, so only a reader notices. Note that view.rs carries a related editing accident worth folding into the same cleanup: src/config/view.rs:1012 concatenates two copies of a doc opener on one line (`/// Assemble the view restricted to one configuration `source`/// Assemble the view restricted to one configuration `source` — …`).

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified verbatim and the line numbers are exact. `grep -n` gives src/config/mod.rs:503 `/// An app's resolved overlay over the sandbox baseline: the command to run plus the extra`, immediately followed by mod.rs:504 `/// One bundle's install step, as the fold hands it to a launch: the step itself and the bundle`, with `pub(crate) struct BundleProvision {` at mod.rs:512 — so line 503 is unambiguously part of `BundleProvision`'s doc block and describes a different type. The orphaned remainder is likewise where the reporter says: mod.rs:519 `/// environment, binds, packages, network posture, and credentials it declares — each`, opening the doc block that ends at `pub(crate) struct ResolvedApp {` on mod.rs:524, so `ResolvedApp`'s summary line begins mid-clause. The two halves join into one grammatical sentence, which is the tell that a struct was pasted into the middle of an existing doc comment. No comment or test frames this as deliberate, and rustdoc takes the first line of each block as that item's summary, so both types render with the wrong one-liner.

</details>

---

### B54 — The `capture_max_kb` warning fires only when `capture` is absent, not in the two cases its own message names
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/config/validate.rs:701` |
| **Catégorie** | `ux-error-message` |
| **Sous-système** | Configuration — couches, overrides, validation |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** The guard is `} else if table.capture_max_kb.is_some()`, reached only when `table.capture` is `None`, but its message says `capture_max_kb` is only meaningful with `capture = "bodies"`. With `capture = "off"` or `capture = "headers"` the `if` branch is taken instead and `with_capture(level, table.capture_max_kb)` is called with a ceiling that level ignores — no warning at all. So the condition and the message describe different sets, and two of the three cases the message is about pass in silence. Same shape as the `ask_timeout`/`ask_notice` checks twenty lines up, which correctly key off the *effective* value rather than absence.

**Scénario.** Write `[network]\nmode = "deny"\ncapture = "headers"\ncapture_max_kb = 256`. No warning is emitted and the body ceiling is inert, so an author who set both believes bodies are being captured up to 256 KiB and finds `sbx net logs --with-body` empty with nothing in the config output to explain it. The identical mistake with `capture` omitted entirely is warned.

**Correction proposée.** Move the check so it keys off the parsed level: after `CaptureLevel::parse` succeeds, warn when `table.capture_max_kb.is_some()` and the level is not `Bodies`; keep the existing `else if` arm for the absent-`capture` case. One message, one condition that matches it.

**Rectification du vérificateur.** Mechanism confirmed, impact slightly overstated. The message text is not itself false (in the branch it guards, the value really is ignored); the defect is that the guard's condition covers a strictly narrower set than the message describes, so two of three non-bodies cases pass silently. The attack's claim of "nothing in the config output to explain it" is not quite right: src/config/view.rs:1386-1390 renders `capture_max_kb: a.capture_level().captures_bodies().then(|| a.capture_body_kb())`, so `sbx config show` omits the field when the effective level is not `bodies` — a weak signal, but a signal. This is a warning-coverage gap, not a wrong effective policy: the resolved capture behaviour is correct in every case.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified. src/config/validate.rs:694-704 reads `if let Some(raw) = &table.capture { match CaptureLevel::parse(raw) { Some(level) => policy = policy.with_capture(level, table.capture_max_kb), ... } } else if table.capture_max_kb.is_some() { warnings.push(... "`capture_max_kb` is only meaningful with `capture = \"bodies\"` — ignored") }`. The guard at line 701 is reachable only when `capture` is absent, so `capture = "off"`/`"headers"` plus `capture_max_kb` takes the `if` arm and warns nothing, while the ceiling is provably inert: src/sandbox/control/capture.rs:130-138 `CaptureCaps::new` sets `body: if level.captures_bodies() { ... } else { 0 }`, and src/sandbox/egress.rs:810-816 only builds a CaptureRing at all when `capture_level.captures()`. Nothing prevents it: no comment in the block justifies keying off absence, and the neighbouring check at src/config/validate.rs:667-680 explicitly does the opposite ("key off `action`, not the raw `mode` string") for ask_timeout/ask_notice. No test pins the silence either — src/config/tests.rs:1806-1819 only exercises `headers` with `kb = None` and `bodies` with `Some(64)`. The only other mention of the field, src/config/validate.rs:498, is the `none`/`shared` inert-key listing, which does not cover a filtering posture.

</details>

---

### B55 — `validate_params` documents declaration order but a `BTreeMap` source gives alphabetical order
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/config/tasks.rs:582` |
| **Catégorie** | `doc-drift` |
| **Sous-système** | Configuration — couches, overrides, validation |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** The doc reads "Validate the parameter declarations, keeping declaration order", but `raw` is a `BTreeMap<String, RawTaskParam>` (schema.rs:1433), which discards authoring order at parse time and iterates sorted by key. The resulting `Vec<TaskParam>` is therefore alphabetical, and nothing downstream can recover what the author wrote. The order is user-visible: `task_control.rs:773` builds the caller-facing parameter list from it and `contract.rs:126` walks it to emit the task's schema, so an agent reading a task's contract sees the parameters re-sorted.

**Scénario.** Declare `[task.report.params]` with `since`, then `until`, then `format`. `sbx` lists the operation's parameters as `format, since, until`. The doc promises the authored order; a maintainer relying on it (say, to render a positional usage line or to keep a contract byte-stable against the file) gets the wrong answer and has no way to fix it inside this function.

**Correction proposée.** Either drop the claim — "Validate the parameter declarations. Order follows the section's key order (a `BTreeMap`), not the file" — or, if the order is meant to be authored order, change `RawTask::params` to an order-preserving map (e.g. `IndexMap`, or a `Vec<(String, RawTaskParam)>` with a duplicate-key check) so the promise holds end to end.

**Rectification du vérificateur.** Real but purely a doc inaccuracy with no functional consequence, and the reporter's rationale is partly backwards. Parameters are addressed by name (`{name}` interpolation, and the `LIST`/contract listings are informational), so no behaviour depends on order; and because a BTreeMap is deterministic, the emitted contract IS byte-stable — just stable in key order rather than file order, which defeats the "byte-stable against the file" argument the reporter offers. The same claim also appears at src/config/types.rs:738 ("The declared parameters, in declaration order."), so a doc fix must touch both sites.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified. src/config/tasks.rs:582 reads `/// Validate the parameter declarations, keeping declaration order. Each must carry exactly one bound` and src/config/tasks.rs:584 is `fn validate_params(raw: BTreeMap<String, RawTaskParam>) -> Result<Vec<TaskParam>, String>`, iterated with `for (name, param) in raw` at line 585. The source type is confirmed at src/config/schema.rs:1433: `pub(crate) params: BTreeMap<String, RawTaskParam>`, so serde discards authoring order at parse time and iteration is key-sorted. The cited downstream uses check out: src/sandbox/task_control.rs:774 `let params: Vec<&str> = task.params.iter().map(|p| p.name.as_str()).collect();` inside the `LIST` handler, and src/sandbox/contract.rs:126 `for param in &task.params {` inside `operations_section`. Nothing recovers file order, and the codebase uses "declaration order" elsewhere (src/sandbox/packages.rs:38, src/config/mod.rs:272) for genuinely order-preserving `Vec` sources, so the phrase does mean authored order here.

</details>

---

### B56 — Doc comment line duplicated on itself in `validate_task_network`
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/config/tasks.rs:927` |
| **Catégorie** | `doc-drift` |
| **Sous-système** | Configuration — couches, overrides, validation |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** Line 927 is a single physical line containing its own text twice: `/// Classify the task's egress entries. The same grammar as `[network] allow`, so a task's rules read/// Classify the task's egress entries. The same grammar as `[network] allow`, so a task's rules read`, followed by line 928 `/// like any other egress rule.` A copy-paste artifact — the sentence renders once, mangled, in rustdoc and in any editor hover, and the line is 200 characters wide in a file that otherwise wraps at 100.

**Scénario.** Run `cargo doc` (or hover `validate_task_network`): the summary line reads "Classify the task's egress entries. The same grammar as `[network] allow`, so a task's rules read/// Classify the task's egress entries. …", with the stray `///` inline. The crate's own docs-coverage tooling (`src/docs_coverage.rs`) parses doc lines, so a duplicated one is also noise there.

**Correction proposée.** Delete the duplicated half so line 927 reads once: `/// Classify the task's egress entries. The same grammar as `[network] allow`, so a task's rules read`.

**Rectification du vérificateur.** Cosmetic only, and one supporting claim is wrong: src/docs_coverage.rs does not parse Rust doc comments — it walks the guide's `.md` pages (see its `guide_pages`/code-fence handling around lines 28-107), so a duplicated `///` line is invisible to it. Nor does it fail any gate: there is no rustfmt.toml in the tree (defaults leave comments untouched, so `cargo fmt --check` passes) and an over-long doc line raises no rustdoc warning, so `mise run rustdoc` stays green. The whole impact is a mangled summary line in rustdoc output and editor hover.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified byte-for-byte. `awk 'NR==927 {print length($0)}' src/config/tasks.rs` returns 202, and the line is `/// Classify the task's egress entries. The same grammar as `[network] allow`, so a task's rules read/// Classify the task's egress entries. The same grammar as `[network] allow`, so a task's rules read`, continued by line 928 `/// like any other egress rule.` and line 929 `fn validate_task_network(raw: &[String]) -> Result<Vec<Rule>, String> {`. This is production code — the only `#[cfg(test)]` in the file starts at line 1046 — and the function is live (called at src/config/tasks.rs:212). No surrounding comment or convention explains it; every other line in the file wraps at 100.

</details>

---

### B57 — `add_egress_rule`/`add_proc_rule` rewrite the file on `AlreadyPresent`, which the doc says is never written
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/config/manage.rs:886` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | Configuration — édition en place et rendu |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** Both rule adders end with an unconditional write:

```rust
let text = write_doc(path, &doc)?;   // line 886 (egress), line 976 (proc)
Ok(Written { outcome, text })
```

but `Written`'s own doc at lines 161-163 states: "`AlreadyPresent` carries text too, and the same text the decision was made on: **nothing was written**, so what is attested to is the document as read". `persist_egress_rule` (src/main.rs:848) prints "…is already present in {target} — no change" on that outcome. The inverse operation gets this right — `remove_rule_from` guards with `if !removed { return Ok(RemoveOutcome::NotPresent); }` at line 1119, and its doc says "writes atomically only when it actually removed something" — so the asymmetry looks like an oversight rather than a decision.

The consequences are (a) a documented no-op that can fail hard, (b) unlink/create/rename churn (new inode, new mtime) on a file the CLI says it did not change, and (c) a lost update: the document was read before the decision, so any edit that landed between `read_or_empty` and `write_doc` is silently reverted — on a project tree that, per the comment at lines 155-159, is bound read-write into the cage.

**Scénario.** Put `.sbx.toml` (containing `[network]\nmode = "deny"\nallow = ["github.com"]`) in a directory the user can read but not write — a read-only checkout, or a global `sbx.toml` reached via `-c` in a root-owned config dir. Run `sbx net allow github.com`. Expected (and what the code decided): `AlreadyPresent` → "allow github.com is already present … — no change", exit 0. Actual: `write_doc` fails, `add_egress_rule` returns `ManageError::Write`, `persist_egress_rule` maps it to `(2, "cannot write …: Permission denied")`, and the command errors out on an operation that changed nothing.

**Correction proposée.** Mirror `remove_rule_from`: skip the write when the outcome is `AlreadyPresent`, returning the document text as read. `let text = if matches!(outcome, AddOutcome::AlreadyPresent) { doc.to_string() } else { write_doc(path, &doc)? };` — this also keeps the attestation contract the `Written` doc describes.

**Rectification du vérificateur.** Real, but the mechanism is smaller than described and half the attack is impossible. (1) `open_rule_write` (`src/main.rs:746-753`) rejects `Scope::File` outright — "`sbx net allow` does not take `-c <file>`" — so the "global sbx.toml reached via `-c`" scenario cannot happen; only a `--local` project file in a non-writable directory or a `--global` config in a non-writable config dir reaches the write. (2) The exit code is 2, not because `ManageError::Write` deserves it, but because `src/main.rs:822` blanket-maps every `ManageError` with `.map_err(|e| (2, e.to_string()))` — which itself contradicts `persist_egress_rule`'s own doc at `src/main.rs:798` ("an operational failure (no trust store, an unwritable path, a re-trust failure) is code `1`"). That doc/code mismatch is the sharper half of this finding. (3) The "lost update" is not a new hazard: the read→write window is the same one the `Added` path already has, and `trust_written` is documented (main.rs:824-832) as making it fail-safe. So the substance is a lying doc comment plus needless write churn and a hard failure on a read-only target, not silent data loss.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The cited lines are correct: `src/config/manage.rs:886` and `:976` are both `let text = write_doc(path, &doc)?;` reached unconditionally after the `match` that produced `outcome`, and `write_doc` (line 1324) is unconditional — `write_text` creates a temp file and renames over the target every time (lines 1358-1366), with no compare-to-original short-circuit (contrast `commit` at line 427, which does have one: `if doc.to_string() == before { return Ok(SetOutcome::Unchanged); }`). The `Written` doc at `src/config/manage.rs:160-162` states plainly: "`AlreadyPresent` carries text too, and the same text the decision was made on: nothing was written, so what is attested to is the document as read". The inverse operation does guard — `remove_rule_from` at line 1119 is `if !removed { return Ok(RemoveOutcome::NotPresent); }`, and its doc at line 1055 says "writes atomically only when it actually removed something" — so the asymmetry is real and undefended by any comment. `persist_egress_rule` (`src/main.rs:848`) prints "…is already present in {target} — no change" while the inode and mtime have in fact changed.

</details>

---

### B58 — `put_value` blames the leaf key when it is a *parent* that holds a scalar, giving useless remediation
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/config/manage.rs:622` |
| **Catégorie** | `ux-error-message` |
| **Sous-système** | Configuration — édition en place et rendu |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** When descending to the leaf, `put_value` maps a non-table parent to an error named after the leaf:

```rust
table = table
    .get_mut(seg)
    .and_then(Item::as_table_like_mut)
    .ok_or_else(|| ManageError::NotScalar(key.to_string()))?;   // line 622
```

`list_at` handles the identical situation correctly one screen earlier (line 528): `.ok_or_else(|| ManageError::ParentNotTable(seg.to_string(), key.to_string()))`. That variant exists precisely for this case and its message names the obstacle and the fix ("give {parent} its table form first … or use the verb that promotes it"). The test `a_parent_holding_a_single_value_is_named_as_the_obstacle` (line 2103) pins it for `remove` and its comment spells out the rule this path breaks: *"Naming the leaf would send the user to fix the wrong key."* No test covers `set` on a scalar parent.

The message `set` actually produces is also factually false on two counts: the named key does not exist at all, and it is a boolean, not "an array or table".

**Scénario.** `sbx config set network deny` writes the bare-string posture `network = "deny"`. Then run `sbx config set network.stats false` — the exact command `scalar_value`'s own doc comment (line 653) names as the reason the natural-type guess exists. Output: `sbx: config: network.stats is not a single value (it is an array or table) — edit it with 'sbx config edit'`. Nothing named `network.stats` is in the file, it is not an array or a table, and the message does not mention the actual obstacle (`network` is a string, not a table). On the same file `sbx config rm network.allow x` correctly answers "network holds a single value, so network.allow cannot be reached".

**Correction proposée.** Use the existing variant: `.ok_or_else(|| ManageError::ParentNotTable(seg.to_string(), key.to_string()))?` at line 622, matching `list_at`. Reserve `NotScalar` for the leaf-shape arms at lines 681-686.

**Rectification du vérificateur.** Survives as described mechanically, but it is a message-quality defect only, not medium severity: the write is correctly refused, nothing is lost, and the suggested remedy (`sbx config edit`) does in fact resolve it — it just does not say what is in the way. Two citation corrections: `put_value`'s leaf-shape arms are at lines 642-647, not 681-686, and `scalar_value` itself begins at line 655 (its doc block at 651).

<details>
<summary>Preuve retenue par le vérificateur</summary>

The cited line is exact: `src/config/manage.rs:622` is `.ok_or_else(|| ManageError::NotScalar(key.to_string()))?;`, inside `put_value`'s parent-descent loop, and `key` there is the full dotted key, not the segment. `list_at` handles the identical condition at line 528 with `.ok_or_else(|| ManageError::ParentNotTable(seg.to_string(), key.to_string()))?`, and its comment (lines 524-527) states the rule: "saying 'the list is a single value' about the *leaf* would point at the wrong key entirely". The test `a_parent_holding_a_single_value_is_named_as_the_obstacle` (line 2103) pins that for `remove` only; I found no test and no comment defending `put_value`'s choice. The scenario is reachable and real: `network.stats` is a documented boolean field (`docs-site/docs/guide/cli/config.md`, `src/help.rs`), and `scalar_value`'s own doc (lines 651-654) names `sbx config set network.stats false` as its reason to exist. On a file holding `network = "deny"`, `set network.stats false` descends, finds `network` is a `Value::String`, and emits via `ManageError::NotScalar`'s Display (lines 183-186) `sbx: config: network.stats is not a single value (it is an array or table) — edit it with \`sbx config edit\``. Nothing named `network.stats` exists in the file and the obstacle is a string, so the message is false on both counts and names the wrong key to fix.

</details>

---

### B59 — `split_key` only understands `"`-quoted key segments, silently mangling `'`-quoted ones into a nonsense table
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/config/manage.rs:1271` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | Configuration — édition en place et rendu |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : moyenne) |

**Constat.** The dotted-key splitter tracks only the basic-string quote:

```rust
for c in key.chars() {
    match c {
        '"' => quoted = !quoted,
        '.' if !quoted => segments.push(std::mem::take(&mut current)),
        c => current.push(c),
    }
}
```

TOML has two quoted-key forms — basic (`"…"`) and literal (`'…'`) — and `split_key` handles one. A literal-quoted segment is split on its interior dots and the quote characters are carried into the segment text, so `secret.'api.example.com'.from` becomes the segments `secret`, `'api`, `example`, `com'`, `from`. `put_value` then creates a nested table chain and `toml_edit` re-quotes each key, producing `[secret."'api".example."com'"]`.

This is the exact failure the module already fixed for `"` — the test `a_quoted_key_segment_keeps_its_dots` (line 2277) says so verbatim: "splitting on all of them walked straight through the quotes and built `secret.'\"api'.example.'com\"'`, a nonsense table the schema happened to accept, so the write was **reported as a success**. A silent wrong write on a credential is the worst shape a bug can take here." The `'` form takes the same route and reaches the same end: `RawHostSecret` has no required fields and no `deny_unknown_fields`, so `schema::parse` accepts the garbage, `validate_layer` returns `Ok(())`, and the write commits.

**Scénario.** `sbx config set "secret.'api.example.com'.from" env://TOKEN` (outer double quotes so the shell preserves the single quotes). The command prints a success line. The file gains `[secret."'api".example."com'"]` with `from = "env://TOKEN"`. `sbx config get "secret.'api.example.com'.from"` reads it back through the same broken split, so it looks correct. At launch the credential is never injected — the destination host `api.example.com` has no declaration at all, and the bogus host `'api` is dropped as a secret naming neither `key` nor `from`.

**Correction proposée.** Track both quote characters, remembering which one opened the segment so the other is treated as ordinary text, and strip only the opening/closing pair: keep an `Option<char>` instead of a `bool`, toggle on `'"' | '\''` when it matches the open quote (or opens one), and leave the unbalanced-quote rejection at line 1277 as-is.

**Rectification du vérificateur.** Mechanism confirmed; severity overstated. Two mitigations the reporter omits. (1) The documented spelling is the double-quoted one — docs-site/docs/guide/cli/config.md:243-247 shows `sbx config set 'secret."api.example.com".from' …` — so the mangled form is an undocumented alternative, not the everyday path the `"` bug was. (2) The wrongness is not silent past the write: at resolve time `apply_secret_section` (src/config/secrets.rs:26-31) drops the bogus host via `validate_host_secret` -> `resolve_host_sources` (secrets.rs:253-266, the `(None, None)` arm) and pushes `"...: ignoring secret for `'api` — set `key` or `from`..."`, which `sbx config show` prints (src/cli/config.rs:200). So the defect is: `sbx config set` reports success for a key spelling it cannot address, leaving the intended credential undeclared, with a later warning naming the mangled host. Real and worth the proposed `Option<char>` fix, but low rather than medium.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The citation is exact. src/config/manage.rs:1268-1274 is `let mut quoted = false;` with the arms `'"' => quoted = !quoted,` (line 1271), `'.' if !quoted => …push`, and `c => current.push(c)` — so an apostrophe falls into the catch-all and is pushed into the segment text while its interior dots still split: `secret.'api.example.com'.from` yields `secret`, `'api`, `example`, `com'`, `from`. Nothing upstream stops it: src/cli/config.rs:2626 calls `config::manage::set` with the raw positional, and `resolve_key_target` (cli/config.rs:2548-2586) validates only an `--app` name, never the key shape. `set` (manage.rs:390-415) gates only on `validate_layer` (manage.rs:685-700) = `schema::parse` (schema.rs:2069-2072) plus forward/[fs] checks. `RawHostSecret` (schema.rs:1264-1298) is all-`Option` with no `deny_unknown_fields` (policy stated at schema.rs:721 and 764) and `RawHostSecrets` is `#[serde(untagged)]` (schema.rs:1251-1257), so `{"'api": {example: {"com'": {from = …}}}}` deserializes as `One(RawHostSecret{..None})` and the write commits with a success line. The module's own test comment at manage.rs:2278-2281 records that this exact shape parsed and 'was reported as a success' for the `"` spelling that was fixed; the fix comment (manage.rs:1262-1265) and the unbalanced-quote guard (1276-1279) discuss only `"`, so no comment or test makes the `'` case deliberate.

</details>

---

### B60 — `secrets_inherited` shadows on `header` alone while `upsert_secret` shadows on any header in `headers()`
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/config/view.rs:1879` |
| **Catégorie** | `inconsistency` |
| **Sous-système** | Configuration — édition en place et rendu |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : moyenne) |

**Constat.** `app_detail_view` counts the baseline credentials an app inherits with:

```rust
.filter(|b| {
    !app.secrets
        .iter()
        .any(|a| a.to == b.to && a.header.eq_ignore_ascii_case(&b.header))
})
```

The comment above it (lines 1738-1741) claims this mirrors the launch: "`merge_app` dedups env/packages/binds and folds secrets through the same `(to, header)` upsert, so the inherited counts mirror that." It does not. `upsert_secret` (src/config/secrets.rs:63-75) shadows when `s.to == secret.to` **and the two share any header from `HeaderSecret::headers()`** — and for a *signed* declaration `headers()` expands to the signer plugin's whole `sets_headers` list, while the `header` field is only "the first header the plugin's manifest declares" (src/config/types.rs:317-320). Comparing the single `header` field therefore misses a shadow whenever the app's signed credential writes the baseline's header at a position other than first.

The existing guard test `the_detail_views_effective_scalars_agree_with_merge_app` (view.rs:2364) uses `signer: None` throughout, so this path is unpinned.

**Scénario.** Baseline `[secret."api.example.com"]` with `header = "Authorization"`. App `[app.demo.secret."api.example.com"]` uses `sign = "<plugin>"` whose manifest declares `sets_headers = ["X-Amz-Date", "Authorization"]`, so its `header` field is `"X-Amz-Date"`. `merge_app` finds the shared `Authorization` and shadows, injecting **one** credential. `sbx config show --app demo` reports `secrets: 1` own + `secrets_inherited: 1` = **two** credentials, claiming a baseline credential is injected that the launch actually replaces.

**Correction proposée.** Compare through `headers()` the way `upsert_secret` does: `!app.secrets.iter().any(|a| a.to == b.to && a.headers().iter().any(|ah| b.headers().iter().any(|bh| ah.eq_ignore_ascii_case(bh))))`, and extend the `merge_app`-agreement test with a signed secret so the two stay pinned together.

**Rectification du vérificateur.** Confirmed as reported. One citation slip: the guard test `the_detail_views_effective_scalars_agree_with_merge_app` is at view.rs:2389, not 2364 (2364 falls in the preceding test's prose/helper region) — the load-bearing line 1879 is exact. Impact is display-only: `sbx config show --app <name>` over-counts injected credentials; the launch is unaffected because merge_app never consults this filter. Note the same expression already calls `s.headers().join(", ")` for the SecretView header at view.rs:1864, so the correct accessor is in hand fifteen lines earlier; the proposed headers()-based comparison is the minimal fix.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every cited line is accurate and the asymmetry is real. src/config/view.rs:1879 is verbatim `.any(|a| a.to == b.to && a.header.eq_ignore_ascii_case(&b.header))`, under the comment at view.rs:1747-1750 promising 'merge_app … folds secrets through the same `(to, header)` upsert, so the inherited counts mirror that'. The merge does not use `header`: src/config/mod.rs:779-782 re-derives `self.secrets` from `declared_secrets` and folds each app secret through `upsert_secret`, which at src/config/secrets.rs:63-71 computes `writes = secret.headers()` and shadows on ANY shared header — its doc at secrets.rs:49-54 says so explicitly ('The comparison is over **every** header each declaration writes, not the one it is named by'). `headers()` (src/config/types.rs:335-345) returns a signer's whole `sets_headers`, while `header` is only `plugin.signer.sets_headers[0]` (src/config/secrets.rs:164) and the comment at secrets.rs:157-162 states the distinction: the first header is 'the declaration's *label*, not what `upsert_secret` dedups on' (the field doc repeats it at types.rs:317-320). Multi-entry `sets_headers` is legal — src/plugins/signer.rs:215-238 rejects only an empty list and forbidden names. So with a baseline `Authorization` secret and an app secret signed by a plugin declaring `["X-Amz-Date", "Authorization"]`, merge_app shadows to one credential while the detail view reports 1 own + 1 inherited = 2. The guard test leaves this unpinned: it builds its credential via `a_header_secret()` with `signer: None` (view.rs:2586) and asserts the sum only in the all-dropped case (`merged.secrets.len() == 0`, view.rs:2574-2584).

</details>

---

### B61 — `sbx path` exits 0 and reports "no base" when the data directory could not be resolved
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/main.rs:296` |
| **Catégorie** | `error-handling` |
| **Sous-système** | Point d'entrée, diagnostics, store, chemins |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `path_cmd` calls `store::Layout::from_env()` (src/main.rs:296) and passes the `Option` straight to `paths::view(layout.as_ref())`, treating `None` as "there is no XDG base". But `Layout::from_env` returns `None` for three distinct reasons (src/store.rs:88-119): no `$HOME`/XDG base, a volume pointer whose volume could not be mounted (`follow_volume` → `Some(Err(why))`, after printing `sbx: refusing to continue rather than use an empty data directory`), and a resolved data directory that fails `check_resolved_data_dir`. Only the first is the case the render and the JSON model describe. `paths.rs:243` states of `BaseView::root`: "`None` only when no `$HOME`/XDG base resolves", and `paths.rs:288` repeats it for `view`: "`layout` is `None` only when the data directory cannot be resolved (no `$HOME`)". Both are false. Worse, `path_cmd` returns `ExitCode::SUCCESS` in both the `--json` and text branches after `from_env` has literally printed "refusing to continue".

**Scénario.** A user adopts a storage volume (`~/.local/share/sbx/storage.toml` exists), then connects over SSH, where udisks' polkit rule demands administrator authentication so `storage::up` cannot mount unattended. `sbx path` prints two `sbx: …` lines to stderr ("sbx's data is in a volume that could not be mounted: …" / "refusing to continue rather than use an empty data directory"), then prints `data:    (no base — $SBX_DATA_DIR, else $XDG_DATA_HOME/sbx (else ~/.local/share/sbx))` with every data entry omitted, and exits 0. The remedy the line names ($HOME/XDG) is the wrong one — $HOME is fine, the volume is simply unmounted. The documented script example in docs-site/docs/guide/cli/path.md, `sbx path --json | jq -r '.bases[0].root'`, prints `null` with a zero exit status, so a caller cd-ing into that path silently gets nothing. The same happens when `check_resolved_data_dir` refuses an overlong derived `$HOME` — precisely the situation `sbx path` is the command you run to diagnose.

**Correction proposée.** Distinguish the three cases. Either give `Layout::from_env` a `Result` variant (or add a `Layout::resolution_error()`) that `path_cmd` can render as the data base's status instead of "(no base)", or at minimum, in `path_cmd`, return a non-zero exit (`ExitCode::FAILURE`) when `store::Layout::from_env()` is `None` while `Layout::default_data_dir()` is `Some` — i.e. a base *did* resolve and something downstream refused it — and correct the two `only when no $HOME/XDG base resolves` claims at src/paths.rs:243 and src/paths.rs:288.

**Rectification du vérificateur.** What survives is doc drift plus one self-contradictory line, not a functional defect. Real: src/paths.rs:243 and src/paths.rs:288 both assert `None` happens "only when no $HOME/XDG base resolves", which src/store.rs:96-121 contradicts; and `sbx path` prints "sbx: refusing to continue rather than use an empty data directory" (store.rs:105-107) and then continues and exits 0. Not established: that the exit code is wrong — store.rs:57-59 explicitly designs the inventory command to report an unresolved base rather than fail — nor that the user gets no remedy, since the volume and length refusals each print their own named diagnostic first. Fix the two paths.rs sentences; the exit-code change is a judgement call, not a bug.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Line numbers check out: src/main.rs:296 `let layout = store::Layout::from_env();` → 297 `paths::view(layout.as_ref())`, and both branches return `ExitCode::SUCCESS` (main.rs:302, 312). `Layout::from_env` really does collapse three distinct outcomes into `None` (src/store.rs:82-85 relative/overlong `$SBX_DATA_DIR`, 96-108 `follow_volume` → `Some(Err(why))` after printing "sbx: refusing to continue rather than use an empty data directory", 116-121 `check_resolved_data_dir`). The two doc claims are verbatim false: src/paths.rs:243 "`None` only when no `$HOME`/XDG base resolves" and src/paths.rs:288 "`layout` is `None` only when the data directory cannot be resolved (no `$HOME`)". BUT the reporter overstates the behavioural half. `Layout::from_env`'s own doc (src/store.rs:57-59) deliberately assigns this behaviour to this command: "Every command that needs the data directory then stops; the one that merely inventories on-disk locations reports the base as unresolved rather than inventing one." And the user is not left guessing about the cause: the volume path prints two named diagnostics (store.rs:101-107) and the overlong path prints a message that names its own remedy ("Set SBX_DATA_DIR to a shorter path, or adopt a storage volume", store.rs:370-374). The `(no base — …)` text at src/paths.rs:568-571 is the base's `env_hint` (a contract description), not a remediation claim, so "the remedy the line names is the wrong one" is not accurate. No test pins the exit code (tests/path.rs only asserts success on the happy paths, lines 80 and 188).

</details>

---

### B62 — An untrusted engine override is reported as "ignoring" and then as "not found", neither of which is true
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/store.rs:678` |
| **Catégorie** | `ux-error-message` |
| **Sous-système** | Point d'entrée, diagnostics, store, chemins |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `engine_probe` prints `sbx: ignoring untrusted engine binary <path>: <why>` (src/store.rs:678) for every untrusted candidate. For the *override* tier that word is wrong: `pick_engine_bin` refuses outright — `EngineProbe::Untrusted => return None` at src/store.rs:710 — and `pick_bwrap` does the same. Its own doc says so (src/store.rs:694-696: "one that is **present but untrusted** is refused outright (`None`)"), so nothing is "ignored" in favour of anything. The caller then compounds it: `prepare_engines` maps the `None` to `missing("nix (the store engine)")` → `sbx: nix (the store engine) not found — the sandbox cannot run` (src/sandbox/launch.rs:3166-3168, 6165-6169). The binary was found; it was refused. Neither line names the actual remedy.

**Scénario.** A user points sbx at a locally built engine that happens to sit in a world-writable directory: `SBX_NIX_BIN=/srv/shared/nix sbx run make`. stderr reads:
  sbx: ignoring untrusted engine binary /srv/shared/nix: world-writable
  sbx: nix (the store engine) not found — the sandbox cannot run. See `sbx doctor`.
The first line says the override is being skipped (implying a fallback engine ran); the second says the engine does not exist. In fact the override was found, refused for its mode, and no fallback was consulted. Nothing tells the user to `chmod go-w` the file or unset the variable, and `sbx doctor` re-runs the same resolution and prints the same pair. The identical shape occurs for `SBX_BWRAP_BIN`, where the second line reads "bubblewrap (the sandbox engine) not found".

**Correction proposée.** Have `pick_engine_bin`/`pick_bwrap` distinguish refusal from absence — e.g. return `Result<Option<PathBuf>, String>` carrying the refusal reason, or let `engine_probe` take the tier so it can word the message. On the override tier say "refusing SBX_NIX_BIN=<path>: <why> — sbx will not silently substitute another engine; fix the file's permissions or unset the variable", and let the caller surface that instead of `missing("… not found")`.

**Rectification du vérificateur.** Real but smaller than "medium": this is message wording, not a wrong decision — the refusal itself is correct and deliberate. The reporter also understates what the user does see: `engine_probe` prints the offending path and the exact reason ("world-writable") immediately before the misleading line, so the information needed to fix it is on screen, just not assembled. The sharpest concrete harm is `sbx doctor`'s remediation list (src/cli/doctor.rs:121) telling a user whose nix is present to install nix.

<details>
<summary>Preuve retenue par le vérificateur</summary>

All four citations verified. src/store.rs:678-681 prints `sbx: ignoring untrusted engine binary {path}: {why}` unconditionally from `engine_probe`, for every tier. src/store.rs:710 is `EngineProbe::Untrusted => return None` in `pick_engine_bin` (and store.rs:908 the same in `pick_bwrap`), and the function's own doc at store.rs:694-696 says the override "is **present but untrusted** is refused outright (`None`), since it is a deliberate choice and silently substituting another engine would be worse" — so "ignoring" contradicts the documented semantics on that tier. The override does reach this path: `resolve_engine_bin` (store.rs:542-559) reads `ENGINE_OVERRIDE_ENV` and passes it as `override_nix` with `engine_probe` as the probe. The caller then re-labels the refusal as absence: src/sandbox/launch.rs:3166-3168 `let Some(nix) = crate::store::resolve_nix(...) else { return Err(missing("nix (the store engine)")) }`, and `missing` at src/sandbox/launch.rs:6165-6169 prints "… not found — the sandbox cannot run. See `sbx doctor`." `sbx doctor` compounds it rather than resolving it: src/cli/doctor.rs:113-123 prints "nix               not found" and pushes the remediation "install nix (the store engine sbx drives daemonlessly)", which is the wrong advice for a binary that exists but is world-writable. Nothing in the tree words the override refusal correctly.

</details>

---

### B63 — `refresh_ref` documents a 40-hex pin as needing "no nix call" while it spawns nix and queries GitHub
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/store.rs:1339` |
| **Catégorie** | `doc-drift` |
| **Sous-système** | Point d'entrée, diagnostics, store, chemins |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** `refresh_ref`'s doc (src/store.rs:1339) says "A 40-hex source resolves to itself with no nix call, so refreshing a fixed pin is a well-defined no-op", and `resolve_source_rev`'s doc (src/store.rs:1354) says a 40-hex source "already *is* the revision (an exact pin, needing no nix)". Fifteen lines below that second claim, src/store.rs:1369 calls `witness_revision(nix, layout, &rev, fresh)`, which goes through `reachability` → `crate::sandbox::nixhub::fetch_url_json(nix, layout, …)` — a nix `fetchurl`+`readFile` build against `https://api.github.com/repos/NixOS/nixpkgs/compare/master...<rev>` (src/sandbox/nixhub.rs:611-620). So a pinned refresh spawns nix, makes an HTTPS request, and may print a multi-sentence warning. The regression test named `refresh_of_a_revision_pin_is_a_noop_without_nix` (src/store.rs:2988) passes `BOGUS_NIX` and succeeds only because `witness_revision` swallows every failure into `Reachability::Unknown` — it does not establish the claim its name makes.

**Scénario.** A project pins `nixpkgs = "<40-hex>"`. On an air-gapped host the user runs `sbx upgrade nix`, expecting the documented offline no-op. sbx forks nix twice (the compare request, then the `master...master` control request), waits out both fetch timeouts, and only then reports the same revision as previous and new. On a rate-limited network the control request can also come back 403, and `verdict(None, true)` then classifies the pin as `Reachability::Absent`, emitting the "is being pinned under `NixOS/nixpkgs`, whose `master` history does not contain it" warning about a revision that is perfectly legitimate — a warning re-running does not clear.

**Correction proposée.** Correct both doc claims to say a 40-hex source needs no *channel resolution*, but is witnessed against the repository (a nix-driven HTTPS request that degrades silently offline); and rename the test to what it actually pins (`refresh_of_a_revision_pin_reports_itself_even_when_the_witness_cannot_run`). If the offline no-op is the intended contract, skip the witness when `resolve_source_rev` is reached from `refresh_ref` with a source that already equals the locked revision.

**Rectification du vérificateur.** Narrow it to one sentence and one test name. Genuinely stale: src/store.rs:1339's "with no nix call" describes refresh_ref's own behaviour and is false — an upgrade of a 40-hex pin forks nix once (twice when offline) and attempts api.github.com. Not a finding: src/store.rs:1354, whose "needing no nix" is about channel resolution and is qualified three lines later at 1356-1358, which states outright that an upgrade re-asks the witness. Also drop the rate-limit claim — a 403 on the control request yields Unknown and no warning (store.rs:1542), not Absent.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The core claim holds for refresh_ref. src/store.rs:1339 reads "/// 40-hex source resolves to itself with no nix call, so refreshing a fixed pin is a" (continued at 1340 "well-defined no-op"), and `refresh_ref` (store.rs:1341-1351) calls `resolve_source_rev(nix, layout, source, true)`, which for a 40-hex source calls `witness_revision(nix, layout, &rev, fresh)` at src/store.rs:1369 before returning. `witness_revision` (store.rs:1552) → `reachability` (store.rs:1504-1523) → `crate::sandbox::nixhub::fetch_url_json` (src/sandbox/nixhub.rs:610-619), a nix `fetchurl`+`readFile` build against `https://api.github.com/repos/NixOS/nixpkgs/compare/master...<rev>` (reachability_url, store.rs:1483-1485), plus a second control fetch when the first fails. So nix is spawned and HTTPS is attempted on a path documented as needing neither. Two of the reporter's supporting claims are wrong, though. First, `resolve_source_rev`'s doc is not misleading in context: the sentence at store.rs:1354 ("needing no nix") is scoped to resolution, and the very next paragraph, store.rs:1356-1358, discloses the witness explicitly — "`fresh` is passed to the witness the pinned form goes through … an upgrade re-asks". Second, the rate-limit scenario is backwards: if the control request also 403s, `endpoint_answers` is false and `verdict(None, false)` returns `Reachability::Unknown` (src/store.rs:1542), which is silent — the spurious "does not contain it" warning needs the control request to *succeed* while the compare fails, which is the design's intended Absent signal (store.rs:1541). The test at src/store.rs:2988 does pass BOGUS_NIX and survives only because the witness swallows failures, so its name overstates what it pins.

</details>

---

### B64 — The bootstrap `--local` save refusal prints two runs of 14 literal spaces mid-sentence
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/main.rs:579` |
| **Catégorie** | `ux-error-message` |
| **Sous-système** | Point d'entrée, diagnostics, store, chemins |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** The format string in `local_save_refusal` (src/main.rs:579) carries two 14-space runs inside the message text — at offsets 96 and 194 of the literal, between "…a `--local` save would write" and "also trusts…", and between "…you have not reviewed." and "Create the config…". They are literal string content, not source indentation: the `\` line continuation at the end of line 579 correctly elides the *leading* whitespace of line 580, but these two runs sit mid-line. The shape is a reflow that joined wrapped lines without collapsing their indentation. No test pins the text — the only assertions (src/main.rs:1084-1092) check for the substrings "mise.toml" and "have not reviewed".

**Scénario.** In a project with a `mise.toml` and no `.sbx.toml`, run `sbx net allow example.com --local` (or `sbx net pending --save --local`). The refusal reaching stderr reads: "this project has no .sbx.toml yet, and trusting the one a `--local` save would               also trusts mise.toml beside it — content sbx did not write and you have not reviewed.               Create the config …" — a gap wide enough to read as a column break in a paragraph that is otherwise the single most important explanation sbx gives about trust bootstrapping.

**Correction proposée.** Collapse each 14-space run to a single space in the format string at src/main.rs:579, or re-break the literal across source lines with `\` continuations so every continuation's indentation is elided.

**Rectification du vérificateur.** Substance holds; two details in the write-up are slightly off. (a) The offsets 96 and 194 are into the SOURCE LINE, not into the literal — the literal opens at column 12, so within the literal the runs sit at 84 and 182. (b) The "attack" transcription of the emitted text drops the word "write" and shows 15 spaces; the message actually reads "...a `--local` save would write<14 spaces>also trusts mise.toml beside it — ...". Neither slip affects the defect: two literal 14-space runs are printed mid-sentence, unmodified, by `sbx net allow <host> --local` (and the `net pending --save --local` path at src/cli/net.rs:3316) in a project with a mise file and no .sbx.toml. Cosmetic only — no logic is wrong, the refusal itself is correct — so "low" is the right severity.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Confirmed at the cited line. src/main.rs:579 is the format string, and a scan of that line finds space runs of exactly 14 at offsets 96 ("...`--local` save would write<14 spaces>also trusts {names}...") and 194 ("...you have not reviewed.<14 spaces>Create the config..."), alongside the expected 12-space source indent at offset 0. They are literal string content: the trailing `\` on line 579 elides only the leading whitespace of line 580, not runs sitting mid-line. I traced both callers to output. src/main.rs:644 (inside `precheck_local_save`, src/main.rs:626) and src/main.rs:773 (inside `open_rule_write`) return `Err((code, msg))`, consumed at src/cli/net.rs:3316 as `diag::error(&format!("sbx: {msg}"))`. `diag::error` (src/diag.rs:46) calls `highlight` (src/diag.rs:78-80), which is `crate::style::paint_spans(msg, pal.name, "", pal)`. paint_spans (src/style.rs:94-123) returns `text.to_owned()` verbatim on a plain palette (src/style.rs:98-100) and otherwise only wraps backtick spans in color — it never collapses or reflows whitespace, and src/diag.rs:87 `plain_lines_are_verbatim_including_backticks` asserts the plain path is byte-identical. No wrap/reflow helper exists on this path (src/style.rs has none; the crate-wide `fn wrap*` hits are all sandbox command wrappers). The only assertions on this text, src/main.rs:1093-1104, check the substrings "mise.toml", "have not reviewed" and the absence of "is not trusted", so nothing pins the spacing. The two gaps reach stderr as written.

</details>

---

### B65 — Two doc comments carry a duplicated leading fragment glued to the real summary line
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/main.rs:591` |
| **Catégorie** | `doc-drift` |
| **Sous-système** | Point d'entrée, diagnostics, store, chemins |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** src/main.rs:591 reads `/// The write-side trust gate for a save that blesses what it writes:/// The write-side trust gate for a save that blesses what it writes: an existing-but-untrusted (or` — the summary sentence appears twice on one line, with an inline `///` marker in the middle of the rendered text. src/storage.rs:464 has the same corruption: `/// Report where the volume stands, without changing anything./// Report where the volume stands, without changing anything.` In both cases rustdoc renders the doubled sentence and the stray `///` verbatim as the item's summary — the first line of the tooltip and of the generated page. The crate's own doc-coverage tests do not catch it: `a_paragraph_break_inside_a_doc_comment_is_written_as_one` (src/docs_coverage.rs:1158) checks paragraph separators, and there is no maximum-doc-line-width check, so a 190-character `///` line passes. (The same pattern exists at src/cli/mod.rs:265, src/config/tasks.rs:927 and src/config/view.rs:1013, outside this scope — it looks like one bad bulk edit.)

**Scénario.** Run `cargo doc --document-private-items` (or hover `local_save_permitted` / `storage::state` in an editor). The summary shown is "The write-side trust gate for a save that blesses what it writes:/// The write-side trust gate for a save that blesses what it writes: an existing-but-untrusted (or changed) config must not be silently blessed…" — the crate's most load-bearing trust invariant introduced by a doubled clause and a literal `///`.

**Correction proposée.** Delete the duplicated fragment and the inline `///` on src/main.rs:591 and src/storage.rs:464 (and the three sibling sites outside this scope). Consider adding a doc-coverage assertion that no `///` line exceeds `DOC_WRAP` by a wide margin, or that no `///` body contains the sequence `///`, so a repeat of this edit fails the suite.

**Rectification du vérificateur.** Real but purely cosmetic, and the audience is narrower than the write-up implies: `local_save_permitted` is private and `storage::state` is `pub(crate)`, so neither appears in default `cargo doc` output — the corruption is visible only under `--document-private-items` or on editor hover, which the description does concede. Nothing executes differently and no guard is weakened. The proposed "no `///` inside a `///` body" assertion would need an exemption for legitimate prose that quotes the marker in backticks — e.g. src/docs_coverage.rs:1146 ("so a bare `///` has") — which is why the crate-wide grep for doubled `///` returns 12 hits where only 5 are corruption.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Confirmed at both cited lines, and both are production items, not test code. src/main.rs:591 reads `/// The write-side trust gate for a save that blesses what it writes:/// The write-side trust gate for a save that blesses what it writes: an existing-but-untrusted (or` and documents `local_save_permitted`; src/storage.rs:464 reads `/// Report where the volume stands, without changing anything./// Report where the volume stands, without changing anything.` and documents `pub(crate) fn state` (src/storage.rs:465). The doubled fragment and the inline `///` are plain markdown text with no surrounding backticks or fence, so rustdoc renders them verbatim in the item summary. The reporter's account of why the guard misses it checks out: `DOC_WRAP = 96` is at src/docs_coverage.rs:1102 and `a_paragraph_break_inside_a_doc_comment_is_written_as_one` at src/docs_coverage.rs:1158, and its filter at src/docs_coverage.rs:1192 skips any line where `lines[i].chars().count() >= DOC_WRAP` — so the ~190-char main.rs line is treated as an ordinary wrapped line and passes. src/storage.rs:464 is additionally exempt because the following line is not a `/// ` body, so the `let (Some(cur), Some(next))` guard at src/docs_coverage.rs:1177 continues. No width or self-`///` check exists anywhere in src/docs_coverage.rs, and a duplicated sentence raises no rustdoc warning, so `mise run rustdoc` stays green. The three sibling sites named as out of scope are real and identical in shape: src/cli/mod.rs:265, src/config/tasks.rs:927, src/config/view.rs:1013.

</details>

---

### B66 — The flag menu goes dead after any typed flag, not just after a positional value
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/completion.rs:225` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | Aide et complétion shell |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** In the fallback branch of `candidates`, the command's own options are offered only when

    if tail_at == before.len() { names.extend(flag_menu(&path)); }

`tail_at` is the index just past the last *command* word, so this is true only when nothing at all has been typed after the command path. The comment above it states a different rule — "Bare on a command path (`sbx run <TAB>`, `sbx net logs <TAB>`), the menu is the command's own options; past a typed **value** it belongs to the launched command" — i.e. the gate is meant to fire on a positional value, not on a flag. Pages with no operand slots (`run`, `gc`, `doctor`, `net logs`, `net rules`, `net live`, `proc rules`, `logs`, `config edit`, `session ls`, …) therefore answer an empty cursor word with zero candidates as soon as one flag is present, and the emitted bash script deliberately drops `-o default`, so the prompt is dead rather than falling back to files.

**Scénario.** `sbx net logs <TAB>` offers all eleven documented flags; `sbx net logs -f <TAB>` offers nothing. `sbx gc <TAB>` offers `--all --prune --optimise --optimize --help`; `sbx gc --prune <TAB>` offers nothing. Typing `-` first still works, so the breakage is silent and looks like completion having simply stopped.

**Correction proposée.** Replace the gate with the condition the comment describes: offer the flag menu unless a non-flag word (that is not some flag's consumed value) has been typed after the command path — the information `cursor_value_kind` already computes while walking `before[tail_at..]`.

**Rectification du vérificateur.** Survives, but the page list overstates it. `logs` is not affected — it has an `<id>` operand row (src/help.rs:665-667), so `cursor_value_kind` returns `Some(Sessions)` and its menu keeps answering after `-f`. `doctor` (src/help.rs:65) and `session ls` (src/help.rs:1153) declare `options: &[]`, so the only candidate lost there is the synthesized `--help`. The real cases are the flag-only pages listed above. Worth adding that the same gate also empties the menu after a flag's *value* (`sbx net rules -a myapp <TAB>`), where the value word is correctly consumed as the flag's — so even a fully-understood line goes quiet.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The gate at src/cli/completion.rs:225 is `if tail_at == before.len() {`, and `tail_at` is set only while walking command words (:178), so it equals `before.len()` only when nothing whatsoever follows the command path — flags included. The comment directly above (:222-224) states a different rule ("past a typed **value** it belongs to the launched command"). For a page whose rows are all flags, `operand_slots` returns empty, `cursor_value_kind` reaches :802 with `slots.get(0) == None`, `all_literal_words` gives `None`, and the else branch is the only candidate source — so one typed flag empties it. Verified against flag-only pages: `gc` (src/help.rs:1661-1680), `net logs` (src/help.rs:2650-...), `net rules` (src/help.rs:2136-2157), `net live` (src/help.rs:2800-2817), `config edit` (src/help.rs:1481-1489). The `-o default` omission is real (src/cli/completion.rs:1017-1019), so the prompt is dead rather than falling back to files, and `cur` starting with `-` still reaches the flag branch at :186, which is why typing `-` first hides the breakage. No test pins the current behaviour: `a_positional_value_does_not_deepen_the_path` (src/cli/completion.rs:1233-1249) covers a typed *value*, not a typed flag.

</details>

---

### B67 — The emitted bash script ignores COMP_WORDBREAKS, so `:`/`=` words complete nothing there
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/completion.rs:1028` |
| **Catégorie** | `inconsistency` |
| **Sous-système** | Aide et complétion shell |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : moyenne) |

**Constat.** The bash function forwards `COMP_WORDS` verbatim:

    typed=("${COMP_WORDS[@]:1:COMP_CWORD-1}")
    typed+=("${COMP_WORDS[COMP_CWORD]-}")

Bash splits the line on `$COMP_WORDBREAKS`, whose default includes `:` and `=`, so `--net=allow` arrives as three words (`--net`, `=`, `allow`) and `api.example.com:443` as three (`api.example.com`, `:`, `443`). zsh's `${(@)words[2,CURRENT]}` splits on neither. Two consequences: the inline-value branch in `candidates` (`if let Some((flag, want)) = cur.split_once('=')`, line 189) is unreachable from bash — it only ever runs under zsh; and the stray `:`/`=` word is counted as a positional by `cursor_value_kind`, pushing the cursor past the page's operand slots. The unit tests build word lists by hand and the integration drives set `COMP_WORDS` themselves (tests/completion.rs:203-212, 450-455), so real bash word-splitting is never exercised.

**Scénario.** In bash, `sbx run --net=<TAB>` and `sbx run --net=al<TAB>` offer nothing, while the same input in zsh offers none|shared|ask|allow|deny. `sbx net unallow api.example.com:<TAB>` offers nothing even though `api.example.com:443` is in the config's allow list and is offered for the bare cursor.

**Correction proposée.** In the emitted bash function, reassemble the word under the cursor across word-break characters before sending it (the standard `_get_comp_words_by_ref -n :=` / `__ltrim_colon_completions` treatment), or strip `:` and `=` from `COMP_WORDBREAKS` in the script's preamble and trim the shared prefix off `COMPREPLY` entries.

**Rectification du vérificateur.** The bash half is right; the zsh comparison is overstated. For `sbx run --net=<TAB>` zsh does NOT offer none|shared|ask|allow|deny either: the emitted zsh function (src/cli/completion.rs:1057-1086) never does `compset -P '*='`, so PREFIX stays `--net=` while the oracle returns bare cells (`value_candidates` returns the literals unprefixed), and compadd discards every one of them. So the inline-`=` branch at src/cli/completion.rs:190 is unreachable from bash and unusable from zsh — dead in practice in both shells, which is the sharper statement. The genuine bash-only divergence is the colon case (`sbx net unallow api.example.com:<TAB>` / `re:<TAB>`), which zsh completes and bash does not. Failure mode is silence, not a corrupted insertion, since the Rust side prefix-filters.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Cited line is exact: src/cli/completion.rs:1028 is `typed=("${COMP_WORDS[@]:1:COMP_CWORD-1}")`, followed at :1031 by `typed+=("${COMP_WORDS[COMP_CWORD]-}")`. Nothing in the repo touches COMP_WORDBREAKS (`grep -rn COMP_WORDBREAKS` over src/, tests/ and docs-site/ returns nothing), and the zsh twin at :1062 uses `${(@)words[2,CURRENT]}`, which does not split on `:`/`=`. I traced the colon case end to end: `sbx net unallow api.example.com:<TAB>` reaches candidates() with cur=":", so value_candidates(Rules{Allow}, ":") applies `out.retain(|(name,_)| name.starts_with(prefix))` (src/cli/completion.rs:~712) and rejects `api.example.com:443`; one keystroke later (`…com:44`) the stray ":" sits in `before` and is counted as a positional by cursor_value_kind (src/cli/completion.rs:786-790), pushing pos past net unallow's single `<rule>` slot so the function returns None and the menu is empty. Under zsh the same input completes, since PREFIX is `api.example.com:` and the candidate starts with it. Nothing defends bash: the drives set COMP_WORDS by hand (tests/completion.rs:202-212 and 450-455) so real word-splitting is never exercised, and no test anywhere uses a `flag=value` word (`grep -rn '"--[a-z-]*="'` over src/cli/completion.rs and tests/completion.rs returns nothing). The docs promise the opposite behaviour (docs-site/docs/guide/cli/completion.md: "A removal verb completes what it can remove"), and the ZSH doc comment at :1048-1051 shows colons in candidates were reasoned about for zsh only.

</details>

---

### B68 — `sbx app prune` page tells the user to run `sbx stop`, which is not a command
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/help.rs:2087` |
| **Catégorie** | `ux-error-message` |
| **Sous-système** | Aide et complétion shell |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** The `app prune` page's remediation reads: "`--yes` is refused while a session of that app is running … Stop it with `sbx stop` and retry." There is no top-level `stop` verb — `dispatch` (src/cli/mod.rs:382-490) has no `"stop"` arm, so it falls into the catch-all and prints `sbx: unknown command 'stop'` with exit 2. Every other page names the real verb (`sbx session stop`, e.g. src/help.rs:1854 and 1888). This page is the single source of truth for that remediation, so the wrong name is what the user is handed at the exact moment the command failed.

**Scénario.** `sbx app prune demo-app --yes` while a `demo-app` session is live prints the refusal and the hint; following the hint gives `sbx: unknown command 'stop'` (exit 2). The correct command is `sbx session stop <pid>`.

**Correction proposée.** Change `sbx stop` to `sbx session stop` at src/help.rs:2087.

**Rectification du vérificateur.** Stronger than reported, and the fix location is wrong. The page is NOT the source of that hint — the runtime message is a separate hard-coded copy at src/cli/app.rs:1926: `"       stop it with `sbx stop`, or re-run without `--yes` to see what would go"`. Both sites must change; patching src/help.rs:2087 alone leaves the user still reading `sbx stop` at the moment the command fails. (The reporter's secondary citations are also off by a line or two: the correct-spelling examples are at src/help.rs:1856 and 1889, not 1854/1888.) A fourth instance of the same shorthand sits in an internal doc comment at src/notify.rs:303 ("`sbx attach`/`sbx stop`"), where neither verb exists top-level.

<details>
<summary>Preuve retenue par le vérificateur</summary>

src/help.rs:2087 reads verbatim "under a command in flight. Stop it with `sbx stop` and retry. The preview deletes". `dispatch` in src/cli/mod.rs:382-490 has no "stop" arm — the nearest is `"session" | "sessions" => session::session_cmd(rest)` (src/cli/mod.rs:411) — so `sbx stop` falls to the catch-all at src/cli/mod.rs:483-487 and prints `sbx: unknown command 'stop'` with `ExitCode::from(2)`. The real verb is `sbx session stop <id>...`, whose page documents `<id>...` as "the PIDs `sbx session ls` shows" (src/help.rs:1224-1229). The refusal itself is reachable: src/cli/app.rs:1911-1928 gates on `if apply` plus a non-empty `session_pids_for_app`.

</details>

---

### B69 — Two pages say `sbx app <name>` launches an app; the dispatcher refuses that form
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/help.rs:1963` |
| **Catégorie** | `doc-drift` |
| **Sous-système** | Aide et complétion shell |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** The `app import` page states "the profile stays inert until `sbx app <name>` launches it" (line 1963) and the `net rules` page states "`--app <name>` shows what `sbx app <name>` would launch with" (line 2166). Both contradict the `app` page itself, which is explicit that this spelling does not exist: "Launching always goes through `run`, so an app name is never a subcommand — an app may be named `run`, `show`, etc. and is still launched as `sbx app run <name>`" (lines 262-264). `app_cmd` (src/cli/app.rs:29-50) matches only `run|upgrade|import|export|rm|list|ls|show|prune` and sends anything else — including a valid app name — to the error arm.

**Scénario.** A user reads `sbx app import ./demo-app.toml`'s own output/page and runs `sbx app demo-app`: it prints `sbx: app needs a subcommand — to launch an app, use `sbx app run <name>`.` plus the usage page and exits 2. The remaining four references in the same table all use the correct `sbx app run <name>` spelling.

**Correction proposée.** Replace `sbx app <name>` with `sbx app run <name>` at src/help.rs:1963 and src/help.rs:2166.

**Rectification du vérificateur.** Correct but cosmetic-leaning, and there is a third site: the rustdoc comment at src/help.rs:3388 uses the same wrong spelling ("`sbx app <name> -- --help` passes `--help` through"), and src/notify.rs:307 uses `sbx app <name>` as loose shorthand for "the app this launch runs". So the spelling reads as a house shorthand that leaked into two user-facing pages; the user-visible cost is bounded because the error the dispatcher prints names the right verb.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Both citations are exact. src/help.rs:1963: "profile stays inert until `sbx app <name>` launches it." src/help.rs:2166: "<name>` shows what `sbx app <name>` would launch with". The `app` page contradicts them at src/help.rs:261-264: "Launching always goes through `run`, so an app name is never a subcommand — an app may be named `run`, `show`, etc. and is still launched as `sbx app run <name>`." `app_cmd` (src/cli/app.rs:28-50) matches only run|upgrade|import|export|rm|list|ls|show|prune; any other first token, including a valid app name, hits the `_` arm at src/cli/app.rs:43-49, which prints "sbx: app needs a subcommand — to launch an app, use `sbx app run <name>`." plus the usage page and returns ExitCode::from(2). The doc comment above it (src/cli/app.rs:25-27) states the invariant deliberately, so this is drift in the prose, not an undocumented dispatcher quirk.

</details>

---

### B70 — `config add` page claims `config rm` is the only way to remove a rule; four verbs and the `config rm` page say otherwise
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/help.rs:1386` |
| **Catégorie** | `doc-drift` |
| **Sous-système** | Aide et complétion shell |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** The `config add` page ends its redirect paragraph with: "Removal is not redirected — `sbx config rm` is in fact the only way to take an `allow`/`deny` rule back out." The same table carries pages for `net unallow`, `net undeny`, `net unmute`, `proc unallow` and `proc undeny`, each summarised as "remove an allow rule from a config file (the inverse of …)" (src/help.rs:2342, 2406, 2479, 543, 611) and each dispatched (src/cli/net.rs:42-48, src/cli/proc.rs:38-40). The `config rm` page states the truth directly — "`sbx net unallow|undeny|unmute` and `sbx proc unallow|undeny` do the same removal in the vocabulary the rule was written in; this is the lower-level route to it" (src/help.rs:1427-1429) — so the two pages of one table flatly disagree.

**Scénario.** A user who has just been redirected away from `sbx config add network.allow api.example.com` reads that paragraph and concludes the symmetric `sbx net unallow` does not exist, dropping to the raw dotted-key form — which additionally leaves `allow = []` behind where `net unallow` would have dropped the emptied list (the difference the `net unallow` page documents at line 2364).

**Correction proposée.** Reword src/help.rs:1386 to match the `config rm` page: removal is *not* redirected, and both routes exist — `sbx net unallow|undeny|unmute` / `sbx proc unallow|undeny` in the rule's own vocabulary, `sbx config rm` as the lower-level route.

**Rectification du vérificateur.** Confirmed stale prose, with history to prove it is not deliberate: the sentence landed in commit 4df15a2 (2026-08-05), and the removal verbs it denies were added the next day in e4df665 (2026-08-06, "feat(net): undo an egress rule with the verb that wrote it"), which updated the `config rm` page but not the `config add` page. Only the second clause is wrong — "Removal is not redirected" is accurate (`config rm` does work on `[network]`/`[proc]` lists, per src/help.rs:1426-1428); the "only way" claim is the drift.

<details>
<summary>Preuve retenue par le vérificateur</summary>

src/help.rs:1385-1386 reads "…so it is refused with the verb to use. Removal is not redirected — `sbx config rm` is in fact the only way to take an `allow`/`deny` rule back out." That is false: the same table carries pages at src/help.rs:2342 (net unallow), 2406 (net undeny), 2479 (net unmute), 543 (proc unallow), 611 (proc undeny), and all five are dispatched — src/cli/net.rs:42-48 (`Some("unallow") => net_remove_rule(EgressList::Allow, …)` etc.) and src/cli/proc.rs:38-40. The `config rm` page states the opposite at src/help.rs:1428-1431, and the net dispatcher's own comment (src/cli/net.rs:37-39) says "Each rule list is added to and taken back out with one vocabulary, so undoing a rule never means dropping to the schema key it was written under" — the exact inverse of the claim. The behavioural difference the reporter cites is real and documented at src/help.rs:2364 ("An emptied list is dropped rather than left as `allow = []`").

</details>

---

### B71 — The exec observer's `seen` set is never pruned, so a reused pid silently drops its exec event and the set grows without bound
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/observe_feed.rs:173` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | Cycle de vie des sessions (gc, projects, attach) |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : moyenne) |

**Constat.** `run_loop` dedupes by `seen.insert(pid)` against a `BTreeSet<u32>` (observe_feed.rs:173) that lives for the whole supervised session and is never cleaned of pids that have exited. `ExecRing::push` does no dedup of its own (src/sandbox/proc_control.rs:156), so this set is the only gate on the feed.

The dedup key is a bare host pid, which the kernel recycles. Once the host has wrapped its pid space, every cage process that lands on a previously-seen pid is dropped: `seen.insert(pid)` returns false and the `&&` chain short-circuits before `ring.push` and before the inline `[sbx:exec]` echo. The feed does not degrade loudly -- it goes progressively blind, and `sbx proc logs` shows nothing for commands that really ran. The rest of the codebase keys liveness on `(pid, start_ticks)` for exactly this reason (src/session.rs:11-16: "a bare pid is ambiguous because the kernel reuses pids"), and the module header here lists its limits honestly ("the exec poll only sees a process that outlives a tick, so very short-lived commands are missed", observe_feed.rs:20-22) without mentioning this one -- so the comment understates what the lens misses. Secondarily, the set is an unbounded leak for the supervisor's lifetime, capped only by `kernel.pid_max` (4194304 on a systemd host).

**Scénario.** Run a long agent session with `--observe` on a host with `kernel.pid_max = 32768` (the kernel default). A single large build inside the cage burns through the pid space in minutes. After the wrap, the agent runs `rg TODO`, which the kernel gives a pid that some earlier `sh` already used: `seen.insert(pid)` is false, so no `ExecEvent` is pushed and no `[sbx:exec] rg TODO` line is written. `sbx proc logs` reports the session as having run nothing new, with no warning that events are being dropped.

**Correction proposée.** Key the dedup on the incarnation, not the pid: keep `seen: BTreeSet<(u32, u64)>` using the start-time ticks already available via `crate::session::read_start_ticks` (or add a `start_ticks` field to `ProcInfo`, which `read_proc_table` parses `/proc/<pid>/stat` for anyway). That both fixes the drop and bounds the set -- pruning `seen` each tick to the pids still in `table` keeps it at the size of the live cage.

**Rectification du vérificateur.** Real but materially overstated. (a) The effect is not "progressively blind": after a pid wrap a new process is dropped only if its pid is *already in* `seen`, so the loss rate is |seen| / pid_max, i.e. a fraction of events, not a silence. (b) The "unbounded leak" is bounded by the number of distinct cage-descendant pids that outlived a tick in one session, not by `kernel.pid_max` — the set cannot hold 4M entries unless the cage actually spawned that many observed processes. (c) The blast radius is a best-effort display lens: the module header (observe_feed.rs:19-22) already says this poll misses short-lived commands and points at the seccomp user-notification path as the precise capture, and `Observation`'s doc says explicitly "observation is not a security boundary here". The finding is worth fixing as an inconsistency with `session.rs`'s stated (pid, start_ticks) rule, not as a medium-severity data-loss bug. Line cite for `ExecRing::push` is 157, not 156.

<details>
<summary>Preuve retenue par le vérificateur</summary>

observe_feed.rs:173 is exactly `let mut seen: BTreeSet<u32> = BTreeSet::new();` declared inside `run_loop`, with `if seen.insert(pid)` at line 177 short-circuiting the `&&` chain before `ring.push` and the inline echo; the set is never pruned and `run_loop` lives for the whole supervised session (spawned at observe_feed.rs:144, stopped only by `ExecObserver::drop`). `ExecRing::push` (proc_control.rs:157, doc at 155-156) delegates straight to `lens::Ring` and adds no dedup, so the `seen` set is the only gate. The rest of the tree does key on the incarnation: session.rs:11-16 states "a bare pid is ambiguous because the kernel reuses pids" and `descendants` returns `(pid, start_ticks)` pairs for exactly that reason. No comment in the module claims the pid-only key is deliberate.

</details>

---

### B72 — `session::descendants` has no visited set, so a malformed parent graph makes `sbx session stop` spin forever -- the two sibling walkers in this codebase both guard against exactly that
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/session.rs:481` |
| **Catégorie** | `logic-bug` |
| **Sous-système** | Cycle de vie des sessions (gc, projects, attach) |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : moyenne) |

**Constat.** `descendants` (src/session.rs:458-494) builds a `parent -> children` map from one `/proc` pass and then walks it with `let mut stack = vec![root]` (line 481) / `stack.pop()` (line 482) and no `visited` set and no `pid != ppid` filter. Any cycle in the map re-pushes its members forever: `out` and `stack` grow without bound until the process is OOM-killed, and `Session::stop` never reaches `stop_pinned`, so the cage is never signalled.

The codebase treats this graph as untrustworthy everywhere else it walks it, and says why. `crate::observe::build_tree` (src/observe.rs:36-38) keeps a `visited` set because "a malformed parent graph (a self-parent or a cycle from a `/proc` read race) [must] terminate rather than recurse forever", and `observe_feed::descendant_pids` (src/sandbox/observe_feed.rs:48-59) is described as "Pure and cycle-safe", skips `pid == info.ppid`, seeds `seen` with the root, and has a dedicated test `descendant_pids_is_cycle_safe` (observe_feed.rs:400). `session::descendants` reads the same `/proc` in the same way and has neither guard -- two code paths that should agree and do not.

**Scénario.** `/proc` reads are sequential and non-atomic, so a pid wrap during the scan produces the cycle the sibling modules defend against: pid 50's `stat` is read while its parent is 100, recording `50 -> 100`; process 100 then exits, pid 100 is recycled as a fork of pid 50's replacement, and the later read of `/proc/100/stat` records `100 -> 50`. `sbx session stop <pid>` (or `sbx stop`) then enters `descendants`, alternates 50/100 forever, allocates until the OOM killer fires, and the session it was asked to stop is left running with its SIGTERM never sent.

**Correction proposée.** Mirror `observe_feed::descendant_pids`: skip self-parents when building the map (`if pid != ppid`), seed a `BTreeSet<u32> visited` with `root`, and only push a kid when `visited.insert(kid)` succeeds.

**Rectification du vérificateur.** Survives as an inconsistency, but two corrections to the mechanism. First, a self-parent cannot actually appear in `/proc`: the kernel reparents an orphan onto a reaper whose pid differs from the child's, so `ppid == pid` is unreachable and the missing filter is defence-in-depth only. The sole realistic trigger is a >=2-cycle produced by pid reuse during the non-atomic `read_dir("/proc")` + per-pid `read_to_string` scan (session.rs:460-476), which needs the recycled pid to land on exactly the other member of the pair — much rarer than the finding implies, and it must also be reachable from `root`. Second, the other `descendants` call site, session.rs:1208, is inside `#[cfg(test)]`, so `Session::stop` is the only production exposure. The consequence when it does fire is as described: `out`/`stack` grow until the allocator or the OOM killer intervenes and the cage is never signalled.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Line numbers are exact: `fn descendants(root: u32) -> Vec<(u32, u64)>` at session.rs:458, `let mut stack = vec![root];` at 481, `while let Some(parent) = stack.pop()` at 482, and the unconditional `out.push((kid, start))` / `stack.push(kid)` at 488-489 — no `visited` set and no `pid != ppid` filter when the map is built (session.rs:475-476). The inconsistency with the siblings is real and self-documented: `observe::build_tree` (observe.rs:37-46) skips self-parents when building `kids` and threads a `visited` set through `node`, with the comment "a `visited` set makes a malformed parent graph (a self-parent or a cycle from a `/proc` read race) terminate rather than recurse forever"; `observe_feed::descendant_pids` (observe_feed.rs:48-70) does the same and is documented as "Pure and cycle-safe". The production caller is `Session::stop` at session.rs:241, `union_cage_members(descendants(self.pid), scope_members(self.pid))`, evaluated *before* `stop_pinned` — so a non-terminating walk means the SIGTERM is never sent, with the pidfd at that point still open. There is no timeout or bound around the call.

</details>

---

### B73 — `TreeState`'s doc sends users to `sbx gc --all` to reclaim a dead tree, which that command explicitly does not do
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/gc.rs:933` |
| **Catégorie** | `doc-drift` |
| **Sous-système** | Cycle de vie des sessions (gc, projects, attach) |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** The `TreeState` doc comment reads "`Dead` (the marker points at a gone path -- reclaimable by `sbx gc --all`)" (gc.rs:933-934). `sbx gc --all` does not reap project trees. Its implementation (`launch::gc`, src/sandbox/launch.rs:1814-1830) calls only `session_housekeeping`, `runtime_housekeeping` and `shared_store_gc`, and carries an inline comment saying so in as many words: "Reaping whole per-project runtime *trees* is `sbx projects rm`; `--all` here is purely the nix-store side" (launch.rs:1815-1817). `gc::reap_dead_projects` has exactly one production caller -- `projects::reap_dead_trees` (src/sandbox/projects.rs:44) -- reached only from `sbx projects rm --dead/--markerless`. The user-facing help agrees with the code (src/help.rs:1838), so gc.rs:933 is the outlier.

A second stale reference sits in the same file: `is_safe_tree_id`'s doc calls itself "the anti-traversal guard for `sbx gc --id`" (gc.rs:573-574, echoed by the test comment at gc.rs:2044). There is no `sbx gc --id` flag anywhere in the CLI; the real sinks are `sbx projects rm <id>` (projects.rs:663), `sbx projects show <id>` (projects.rs:277) and `purge_app_homes` (gc.rs:672).

**Scénario.** A user runs `sbx path`, sees a tree tagged `dead` (the label comes from `TreeState::label`, gc.rs:948), reads this doc, and runs `sbx gc --all --prune`. The command succeeds, reports on the shared store, and leaves the dead tree -- and its full size -- exactly where it was. Nothing in the output says the tree was skipped, and there is no hint pointing at `sbx projects rm --dead --yes`, which is the command that actually reclaims it.

**Correction proposée.** Change gc.rs:933-934 to name `sbx projects rm --dead --yes`, and gc.rs:573-574 (plus the test comment at gc.rs:2044) to name `sbx projects rm <id>` / `sbx projects show <id>` / `sbx app rm <name> --purge` as the sinks this guard protects.

**Rectification du vérificateur.** Real, but developer-facing rather than user-facing. `TreeState` is `pub(crate)`, so gc.rs:933-934 and gc.rs:573-574 are internal rustdoc, and every user-visible surface already names the right command: src/help.rs:1837-1839 says "Nothing is reclaimed here — that is `sbx gc --all --prune` for store closures, `sbx projects rm <id>` for a runtime tree", and the `sbx projects` listing footer at src/sandbox/projects.rs:605 says "sweep dead trees with `sbx projects rm --dead --yes`". The reporter's scenario of a user reading this doc and running `sbx gc --all --prune` therefore overstates it; the concrete harm is a maintainer trusting a comment the code contradicts. Two citation corrections: the launch.rs comment is at 1820-1822, not 1815-1817 (the function itself begins at 1814), and `TreeState::label` also feeds `sbx projects list` (projects.rs:179) and `sbx projects show` (projects.rs:418), which the doc's "for `sbx path`'s per-project annotation" omits.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Both halves check out at the cited lines. src/sandbox/gc.rs:933-934 reads "`Dead` (the marker points at a gone path — reclaimable by `sbx gc --all`)". `sbx gc --all` cannot reclaim a tree: `launch::gc` (src/sandbox/launch.rs:1814) calls only `sweep_current`, `session_housekeeping`, `runtime_housekeeping` and `shared_store_gc`, and its own inline comment at launch.rs:1820-1822 says "Reaping whole per-project runtime *trees* is `sbx projects rm`; `--all` here is purely the nix-store side". I checked the two passes that could plausibly touch a tree: `runtime_housekeeping` (launch.rs:1888) only folds egress counters and calls `sweep_runtime_dirs`, which per gc.rs:1279-1287 sweeps the per-launch RUNTIME_DIRS entries keyed by a dead launcher pid, not `projects/<id>`; `shared_store_gc` (launch.rs:1936) drops gc roots "of reaped projects" — already-reaped ones — so a Dead-but-unreaped tree still roots its closures. `reap_dead_projects` (gc.rs:481) has exactly one production caller, src/sandbox/projects.rs:44, reached only from `sbx projects rm --dead/--markerless`. The second half is also confirmed: `sbx gc` parses only `--prune`, `--all`, `--optimise/--optimize` (src/cli/gc.rs:33-38) and its help synopsis is "sbx gc [--all] [--prune] [--optimise]" (src/help.rs:1662), so the `sbx gc --id` named at gc.rs:573-574 and echoed at gc.rs:2044 does not exist; the real callers of `is_safe_tree_id` are projects.rs:277, projects.rs:663, gc.rs:602 (`reap_one`) and gc.rs:672 (`purge_app_homes`). I also confirmed the doc's premise that `sbx path` renders the label (src/paths.rs:487-492 calls `classify_tree` and stores `class.state.label()`).

</details>

---

### B74 — `FlakePin`'s doc says the revision keys the out-link; the module header fifteen lines above says nothing is keyed by it, and the code agrees with the header
| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/flake.rs:29` |
| **Catégorie** | `doc-drift` |
| **Sous-système** | Provisionnement (nix, mise, flakes) |
| **Statut** | confirmé par réfutation adversariale (confiance de l'analyste : haute) |

**Constat.** Line 29 documents `FlakePin` as "the immutable revision (40-hex, **which keys the out-link**) and the immutable build reference". The module header at lines 13-16 states the opposite and gives the reasoning: "The revision is recorded and displayed, not used as a path: nothing here is keyed by it. Only an **inline** flake has a content-keyed out-link (`binds::flake_out_link_hash`), because it builds in the cage and has no revision to name." The code sides with the header: `packages::provision` reads only `pin.locked_ref` and roots the build at `gcroots.join(&p.name)` (src/sandbox/packages.rs:119-127), a bare package name; the in-cage path is `binds::flake_out_link(name)`, also name-only (src/sandbox/binds.rs:1055); and `pin.rev` reaches only `pinned_revs`, which feeds `sbx config`'s display. The revision keys nothing at all.

**Scénario.** Not a runtime failure — a maintainer reading `FlakePin` believes a revision change re-points the out-link on its own, and so implements a roll (or a gc keep-set, or an out-link migration) on the assumption that two revisions of one `flake:` package occupy distinct out-links. They do not: both write `gcroots/projects/<id>/<name>`, and what actually forces the rebuild is `provision_flake`'s `<gcroot>.expr` stamp keyed on the *target string* (src/store.rs:1876-1935). Reasoning from the field doc rather than the header yields a change that silently serves the old build.

**Correction proposée.** Reword line 29 to match the header and the code, e.g. "the immutable revision (40-hex, recorded and displayed only — the build target is `locked_ref`) and the immutable build reference the launch builds".

**Rectification du vérificateur.** Two small corrections to the write-up: the module header is at lines 14-16, not 13-16, and the in-cage name-only out-link helper is `binds::flake_out_link` at src/sandbox/binds.rs:1055 (the reporter's 1055 is right, but it is the function definition line, and its rev-keyed sibling `flake_out_link_hash` is at 1071). Impact is documentation-only — no runtime behaviour is wrong today; the proposed rewording of line 29 to name `locked_ref` as the build target is the correct fix.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified verbatim. src/sandbox/flake.rs:29 reads "/// A locked flake package: the immutable revision (40-hex, which keys the out-link) and the", while the module header at src/sandbox/flake.rs:14-16 reads "The revision is recorded and displayed, not used as a path: nothing here is keyed by it. Only an **inline** flake has a content-keyed out-link (`binds::flake_out_link_hash`) …". The code sides with the header: the only consumer of the build reference is src/sandbox/packages.rs:123 `.map(|pin| pin.locked_ref.clone())`, whose gcroot is `gcroots.join(&p.name)` (packages.rs:125) — a bare package name; the in-cage out-link is `flake_out_link(name)` at src/sandbox/binds.rs:1055, also name-only, and the only rev-keyed path in the module is `flake_out_link_hash` at binds.rs:1071, which the header itself scopes to inline flakes. `pin.rev` reaches only `pinned_revs` (flake.rs:110, `.map(|(declared, pin)| (declared, pin.rev))`, consumed by `sbx config` at src/config/view.rs:1062 and 1586), the lock line (flake.rs:132) and the `FlakeUpgrade` display outcomes (flake.rs:301-316). Nothing keys an out-link on it; what forces a rebuild is `provision_flake`'s `<gcroot>.expr` stamp over the target string (src/store.rs:1876-1925). A field doc contradicting its own module header, in a codebase whose comments are the contract, is a real defect.

</details>

---

