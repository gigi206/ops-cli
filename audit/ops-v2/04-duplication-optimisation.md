# Duplication et optimisation

Sept balayages transverses : quatre sur la duplication (verbes CLI, modules sandbox, proxy,
config/plugins/store), deux sur la performance (chemin de données par octet, chemin de
lancement) et un sur le tri des remontées `clippy` en jeu strict. Comme pour les autres vagues,
chaque relevé a été soumis à un vérificateur chargé de le réfuter — avec ici une consigne
supplémentaire : une duplication n'est retenue que si les deux sites sont cités côte à côte,
et un coût de performance que si la fréquence d'appel est établie.

**Total : 44 relevés confirmés** sur 55 avancés — 11 réfutés, soit 20 %.

## Table des matières

| # | Gravité | Emplacement | Constat |
|---|---|---|---|
| [D1](#d1-resolve-the-data-directory-or-fail-is-written-28-times-in-srccli-in-five-different-wordings) | Moyenne | `src/cli/plugins.rs:622` | "Resolve the data directory or fail" is written 28 times in src/cli, in five different wordings |
| [D2](#d2-keep-replaced-bundleskeep-replaced-groups-and-their-renderers-are-the-same-functions-with-one-noun-swapped) | Moyenne | `src/cli/bundle.rs:307` | `keep_replaced_bundles`/`keep_replaced_groups` and their renderers are the same functions with one noun swapped |
| [D3](#d3-the-stdenvcurrent-dir-refusal-is-inlined-15-times-though-config-cwd-already-exists-and-10-sites-use-it) | Moyenne | `src/cli/net.rs:1118` | The `std::env::current_dir()` refusal is inlined 15 times though `config_cwd()` already exists and 10 sites use it |
| [D4](#d4-configrs-test-module-builds-the-full-configview-literal-seven-times-instead-of-using-its-own-sample-config-view) | Moyenne | `src/cli/config.rs:4184` | config.rs test module builds the full `ConfigView` literal seven times instead of using its own `sample_config_view()` |
| [D5](#d5-the-layout-session-registry-resolve-target-preamble-is-copied-into-six-session-reading-verbs) | Moyenne | `src/cli/proc.rs:623` | The layout → session-registry → resolve-target preamble is copied into six session-reading verbs |
| [D6](#d6-sbx-app-show-and-sbx-app-prune-share-a-25-line-preamble-that-has-already-diverged) | Moyenne | `src/cli/app.rs:1384` | `sbx app show` and `sbx app prune` share a 25-line preamble that has already diverged |
| [D7](#d7-session-rule-injection-composes-its-pid-filters-with-23-identical-lines-in-netrs-and-procrs) | Moyenne | `src/cli/net.rs:3126` | `--session` rule injection composes its pid filters with 23 identical lines in net.rs and proc.rs |
| [D8](#d8-netrs-and-procrs-repeat-the-rule-write-result-report-four-times-and-three-refusal-strings-twice-each) | Moyenne | `src/cli/net.rs:3034` | net.rs and proc.rs repeat the rule-write result report four times and three refusal strings twice each |
| [D9](#d9-the-dotted-key-toml-edit-descent-is-written-out-four-times-in-configmanagers-and-the-copies-have-already-diverged-into-a-wrong-error) | Moyenne | `src/config/manage.rs:607` | The dotted-key `toml_edit` descent is written out four times in config/manage.rs, and the copies have already diverged into a wrong error |
| [D10](#d10-pluginsstores-repeats-the-whole-stage-clone-verify-write-bookkeeping-sequence-in-add-rekey-and-update) | Moyenne | `src/plugins/stores.rs:117` | plugins::stores repeats the whole stage → clone → verify → write-bookkeeping sequence in add, rekey and update |
| [D11](#d11-write-file-write-owner-only-write-private-key-and-three-copies-of-unique-across-the-plugins-module) | Moyenne | `src/plugins/stores.rs:1218` | `write_file` / `write_owner_only` / `write_private_key` and three copies of `unique()` across the plugins module |
| [D12](#d12-apply-tools-fans-the-four-resolve-backends-out-by-hand-eight-near-identical-call-blocks) | Moyenne | `src/config/mod.rs:4398` | apply_tools fans the four `:resolve` backends out by hand, eight near-identical call blocks |
| [D13](#d13-handle-https-forward-is-a-300-line-verbatim-clone-of-serve-tunneled-requests-back-half-and-it-has-already-diverged-on-the-ws-pseudo-verb) | Moyenne | `src/sandbox/proxy/forward.rs:158` | handle_https_forward is a 300-line verbatim clone of serve_tunneled_request's back half, and it has already diverged on the WS pseudo-verb |
| [D14](#d14-the-declined-websocket-upgrade-branch-hand-rolls-relay-response-head-and-has-lost-both-the-connection-rewrite-and-the-reflection-masking) | Moyenne | `src/sandbox/proxy/websocket.rs:854` | The declined-WebSocket-upgrade branch hand-rolls relay_response_head and has lost both the Connection rewrite and the reflection masking |
| [D15](#d15-the-pty-openforkraw-moderelay-block-is-written-twice-in-launchrs) | Moyenne | `src/sandbox/launch.rs:5801` | The pty open/fork/raw-mode/relay block is written twice in launch.rs |
| [D16](#d16-temp-file-then-rename-is-written-eight-times-and-the-cleanup-behaviour-has-already-diverged-three-ways) | Moyenne | `src/sandbox/binds.rs:1476` | temp-file-then-rename is written eight times, and the cleanup behaviour has already diverged three ways |
| [D17](#d17-the-github-release-asset-pipeline-is-duplicated-between-debrs-and-appimagers-and-has-already-diverged-once) | Moyenne | `src/sandbox/deb.rs:680` | The `github:` release-asset pipeline is duplicated between deb.rs and appimage.rs, and has already diverged once |
| [D18](#d18-content-keyed-staging-plus-unique-and-content-hash-is-written-three-times) | Moyenne | `src/sandbox/fonts.rs:136` | Content-keyed staging (plus `unique()` and `content_hash()`) is written three times |
| [D19](#d19-the-seccomp-argv-to-netns-holder-to-cgroup-wrap-chain-is-spelled-out-four-times-in-launchrs) | Moyenne | `src/sandbox/launch.rs:5602` | The seccomp-argv to netns-holder to cgroup-wrap chain is spelled out four times in launch.rs |
| [D20](#d20-frametee-copies-every-websocket-payload-piece-into-a-fresh-vec-including-the-server-cage-direction-where-frames-are-never-masked) | Moyenne | `src/sandbox/proxy/websocket.rs:583` | FrameTee copies every WebSocket payload piece into a fresh Vec, including the server->cage direction where frames are never masked |
| [D21](#d21-relay-body-redacting-copies-every-h2-data-frame-into-a-vec-even-when-the-frame-holds-no-needle) | Moyenne | `src/sandbox/proxy/h2mitm.rs:823` | relay_body_redacting copies every h2 DATA frame into a Vec even when the frame holds no needle |
| [D22](#d22-gctree-usage-has-no-subtree-aware-form-so-sbx-projects-show-and-sbx-app-show-walk-the-same-nix-store-twice) | Moyenne | `src/sandbox/gc.rs:1143` | gc::tree_usage has no subtree-aware form, so `sbx projects show` and `sbx app show` walk the same nix store twice |
| [D23](#d23-the-bind-canonicalise-control-plane-dedup-nest-warn-pipeline-is-written-twice-in-configloadrs) | Moyenne | `src/config/load.rs:144` | The bind canonicalise / control-plane / dedup / nest-warn pipeline is written twice in config/load.rs |
| [D24](#d24-upstreampoolcheckout-holds-the-single-pool-mutex-across-up-to-12-socket-syscalls-per-request) | Faible | `src/sandbox/proxy/pool.rs:110` | UpstreamPool::checkout holds the single pool mutex across up to 12 socket syscalls per request |
| [D25](#d25-parse-log-args-re-implements-interval-seconds-which-the-same-file-already-imports) | Faible | `src/cli/net.rs:1309` | `parse_log_args` re-implements `interval_seconds`, which the same file already imports |
| [D26](#d26-seven-json-output-blocks-four-different-wordings-for-cannot-serialize) | Faible | `src/cli/config.rs:186` | Seven `--json` output blocks, four different wordings for "cannot serialize" |
| [D27](#d27-three-independent-lowercase-hex-encoders-and-two-hand-rolled-digest-vs-recorded-hash-comparisons) | Faible | `src/trust.rs:36` | Three independent lowercase-hex encoders, and two hand-rolled digest-vs-recorded-hash comparisons |
| [D28](#d28-the-secretview-projection-is-written-out-three-times-in-configviewrs) | Faible | `src/config/view.rs:1100` | The `SecretView` projection is written out three times in config/view.rs |
| [D29](#d29-three-hand-rolled-toml-basic-string-emitters-only-one-of-which-refuses-control-characters) | Faible | `src/plugins/catalogue.rs:387` | Three hand-rolled TOML basic-string emitters, only one of which refuses control characters |
| [D30](#d30-the-reflection-masking-predicate-is-written-out-three-times-once-per-plane) | Faible | `src/sandbox/proxy/tunnel.rs:784` | The reflection-masking predicate is written out three times, once per plane |
| [D31](#d31-the-connection-bound-auth-scheme-list-ntlm-negotiate-is-implemented-twice-once-per-protocol) | Faible | `src/sandbox/proxy/wire.rs:574` | The connection-bound-auth scheme list (NTLM / Negotiate) is implemented twice, once per protocol |
| [D32](#d32-header-name-eq-heap-allocates-two-vecu8-per-header-comparison-on-the-injection-hot-path) | Faible | `src/sandbox/proxy/wire.rs:20` | header_name_eq heap-allocates two Vec<u8> per header comparison on the injection hot path |
| [D33](#d33-the-upstream-unreachable-refusal-is-written-out-three-times-once-per-transport) | Faible | `src/sandbox/proxy/mod.rs:813` | The upstream-unreachable refusal is written out three times, once per transport |
| [D34](#d34-the-capture-tee-and-box-wrapper-is-copied-at-four-response-relay-sites) | Faible | `src/sandbox/proxy/tunnel.rs:871` | The capture tee-and-box wrapper is copied at four response-relay sites |
| [D35](#d35-forwardrs-hand-rolls-the-connection-cap-that-conncaprs-exists-to-be-the-one-copy-of) | Faible | `src/sandbox/forward.rs:239` | forward.rs hand-rolls the connection cap that conncap.rs exists to be the one copy of |
| [D36](#d36-egress-statsrs-contains-two-copies-of-the-same-0600-atomic-writer) | Faible | `src/sandbox/egress_stats.rs:307` | egress_stats.rs contains two copies of the same 0600 atomic writer |
| [D37](#d37-two-sites-take-a-poisoned-lock-inline-instead-of-through-locksrs-which-says-that-decision-is-made-once) | Faible | `src/sandbox/sshagent.rs:290` | Two sites take a poisoned lock inline instead of through locks.rs, which says that decision is made once |
| [D38](#d38-header-name-eq-heap-allocates-two-vecu8-per-header-name-comparison-on-every-planes-per-request-strip-loop) | Faible | `src/sandbox/proxy/wire.rs:20` | header_name_eq heap-allocates two Vec<u8> per header-name comparison, on every plane's per-request strip loop |
| [D39](#d39-framedbody-allocates-and-frees-a-fresh-vec-per-chunk-size-line-and-per-chunk-closing-crlf-two-mallocs-per-chunk-of-every-chunkedsse-response) | Faible | `src/sandbox/proxy/wire.rs:746` | FramedBody allocates and frees a fresh Vec per chunk-size line AND per chunk-closing CRLF — two mallocs per chunk of every chunked/SSE response |
| [D40](#d40-each-http11-response-head-is-parsed-into-owned-strings-two-or-three-times-per-response) | Faible | `src/sandbox/proxy/wire.rs:503` | Each HTTP/1.1 response head is parsed into owned Strings two or three times per response |
| [D41](#d41-find-head-end-scans-the-entire-captured-response-buffer-byte-at-a-time-for-nn-even-after-the-crlf-pair-is-found-with-memchr-already-a-dependency) | Faible | `src/sandbox/proxy/capture.rs:430` | find_head_end scans the entire captured response buffer byte-at-a-time for "\n\n" even after the CRLF pair is found, with memchr already a dependency |
| [D42](#d42-redact-named-rebuilds-the-whole-output-buffer-once-per-needle-even-when-the-needle-does-not-occur) | Faible | `src/sandbox/redact.rs:88` | redact_named rebuilds the whole output buffer once per needle even when the needle does not occur |
| [D43](#d43-every-launch-reads-and-parses-every-egress-rollup-file-to-discover-there-is-nothing-to-fold) | Faible | `src/sandbox/launch.rs:3504` | Every launch reads and parses every egress rollup file to discover there is nothing to fold |
| [D44](#d44-sbx-path-re-implements-the-current-project-id-and-live-session-id-helpers-sbx-projects-already-owns) | Faible | `src/paths.rs:365` | `sbx path` re-implements the current-project-id and live-session-id helpers `sbx projects` already owns |

## Détail

### D1 — "Resolve the data directory or fail" is written 28 times in src/cli, in five different wordings

| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/cli/plugins.rs:622` |
| **Autres sites** | src/cli/task.rs:176 (the existing helper), src/cli/plugins.rs:391,842,1100,1179,1218,1306,1385,1481,1787,1898,2016,2100; src/cli/proc.rs:481,538,623,732; src/cli/logs.rs:93,564; src/cli/session.rs:70,512; src/cli/app.rs:1053,1394,1876; src/cli/store.rs:96; src/cli/search.rs:21; src/cli/upgrade.rs:183 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — verbes CLI |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** The same six-line gesture appears 28 times, with five separate texts for one failure. task.rs:176 already extracted it: `fn layout_or_fail() -> Result<store::Layout, ExitCode> { store::Layout::from_env().ok_or_else(|| { diag::error("sbx: cannot resolve the data directory (no $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)."); ExitCode::FAILURE }) }`. proc.rs:481-487 copies that text verbatim: `let Some(layout) = store::Layout::from_env() else { diag::error("sbx: cannot resolve the data directory (no $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME).",); return ExitCode::FAILURE; };` — as do logs.rs:93, logs.rs:564, proc.rs:538/623/732, session.rs:70/512, search.rs:21, upgrade.rs:183 (11 sites). plugins.rs:622-627 says something else for the same condition: `let Some(layout) = store::Layout::from_env() else { diag::error("sbx: cannot locate the data directory (set $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)",); return ExitCode::FAILURE; };` — repeated at 13 sites in that file (391 and 2100 through `load_plugin_registry()`). app.rs:1053-1058 has a third: `"sbx: cannot locate sbx's data directory (set $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)"`. app.rs:1394-1397 and app.rs:1876-1879 have a fourth, verb-tagged and with no remedy at all: `diag::error("sbx: app show: cannot locate sbx's data directory.");`. store.rs:96-99 has a fifth: `diag::error("sbx store: cannot locate sbx's data directory.");`.

**Coût.** The drift has already happened: one condition, five messages, two of which (app.rs:1395, app.rs:1877, store.rs:97) do not tell the user which variables to set. Every future change to that remedy sentence is 28 edits, and the odds of catching all five variants with one grep are low — `grep 'cannot resolve the data directory'` finds 11 of the 28. Each copy is also 6 lines of noise at the head of a handler.

**Correction proposée.** Move `layout_or_fail` from src/cli/task.rs:176-183 to src/main.rs, beside `config_cwd` (main.rs:266) and `resolve_session_target` (main.rs:86) — the crate root is already the documented home for cross-family CLI plumbing (see the module doc at src/cli/config.rs:5-8). Make it `pub(crate)`, give it a doc comment, and keep the `cannot resolve …` wording (the majority, and the only one that names the variables). Replace all 27 inline blocks with `let layout = layout_or_fail()?;` in `-> Result<_, ExitCode>` helpers or `let layout = match layout_or_fail() { Ok(l) => l, Err(c) => return c };` in `-> ExitCode` handlers. For plugins.rs:391 and 2100 the value is `load_plugin_registry()`; give that function the same treatment (`fn load_plugin_registry() -> Result<(store::Layout, PluginRegistry, Vec<String>), ExitCode>` calling `layout_or_fail()?`). Two guard consequences to carry: delete the `("cli/task.rs", "layout_or_fail")` entry from `UNDOCUMENTED_MODULE_ITEMS` in src/docs_coverage.rs:884 (the moved function is documented), and re-check any integration test asserting the `cannot locate` phrasing.

**Rectification du vérificateur.** Three corrections. (1) The count is 27 inline blocks plus the one existing helper — 28 occurrences, but only 27 sites to rewrite. (2) The fix is not behaviour-neutral: adopting the majority wording rewrites four user-visible messages (app.rs:1055, app.rs:1395, app.rs:1877, store.rs:97) and drops the verb tags "app show:", "app prune:" and "sbx store:". Nothing asserts them, so it is safe, but it should be called out as a message change rather than a pure refactor — or the helper should take an optional verb tag if those tags are wanted (which would make it worse; recommend dropping them). (3) The condition is restated in still more wordings outside src/cli — src/sandbox/projects.rs:268,556,654 and src/main.rs:478 (`egress_data_dir`) — so a `layout_or_fail` at the crate root should be reachable by those too, or the report's "five messages" understates the drift. Severity downgraded to medium: no correctness or security impact, and the only user-facing defect is two messages missing the remedy sentence.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every site checked. `let Some(layout) = store::Layout::from_env() else {` appears at exactly the 27 cited src/cli sites (plugins.rs:622,842,1100,1179,1218,1306,1385,1481,1787,1898,2016,2100 and 391 via `load_plugin_registry`; proc.rs:481,538,623,732; logs.rs:93,564; session.rs:70,512; app.rs:1053,1394,1876; store.rs:96; search.rs:21; upgrade.rs:183), plus the extracted helper at src/cli/task.rs:176-183, whose body is quoted correctly. The five wordings are real and land at message lines +2 from each guard: "cannot resolve the data directory (no …)" at proc.rs:483/540/625/734, search.rs:23, upgrade.rs:185, session.rs:72/514, task.rs:179, logs.rs:95/566; "cannot locate the data directory (set …)" at all 13 plugins.rs sites; "cannot locate sbx's data directory (set …)" at app.rs:1055; verb-tagged, remedy-free at app.rs:1395 and app.rs:1877; "sbx store: cannot locate sbx's data directory." at store.rs:97. plugins.rs:389-396 confirms `load_plugin_registry() -> Option<…>` with the else-arm at 391-396 and again at 2100-2105. The fix is sound: main.rs already declares `mod store`, `mod diag` (main.rs:17-40) and already hosts the sibling cross-family helpers `resolve_session_target` (main.rs:86, same `Result<_, ExitCode>` shape) and `config_cwd` (main.rs:266); src/cli/config.rs:5-8 documents the crate root as the home for exactly this. src/docs_coverage.rs:884 does contain `("cli/task.rs", "layout_or_fail")`, and the guard's own doc (docs_coverage.rs:850-855) says it "fails just as loudly on an entry that no longer applies", so deleting that entry is mandatory, not optional. No test, no docs-site page and no other src file asserts any of the five strings (greps over tests/, src/, docs-site/docs return only the definition sites).

</details>

---

### D2 — `keep_replaced_bundles`/`keep_replaced_groups` and their renderers are the same functions with one noun swapped

| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/cli/bundle.rs:307` |
| **Autres sites** | src/cli/net.rs:2456-2497 (keep_replaced_groups), src/cli/bundle.rs:354-385 (render_replaced_bundle), src/cli/net.rs:2502-2533 (render_replaced_group) |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — verbes CLI |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** `diff` of bundle.rs:354-385 against net.rs:2502-2533 is four hunks: the fn name, and the noun "bundle" vs "egress group" in two format strings. 26 of 32 lines are byte-identical, including `const NAMED: usize = 3;`, the `dropped.is_empty()` early return, the `.take(NAMED).map(|l| format!("`{l}`"))` join, the `saturating_sub(NAMED)` " (and {rest} more)" tail, and the `if dropped.len() == 1 { "1 line".to_string() } else { format!("{} lines", dropped.len()) }` pluralization. The `keep_replaced_*` pair is the same story: `diff` of bundle.rs:307-348 against net.rs:2456-2497 is seven hunks — the signature, `config::bundles()` vs `config::net_groups()`, the `one(...)` exporter closure, the `.bundle.replaced` vs `.group.replaced` suffix, the noun in one error, and the renderer call. The `if !force { return Ok(Vec::new()); }` guard, the `config_path.parent()` guard, the `declared.get(name)` "added, not replaced" skip, the `before == after` skip, and the `crate::cli::keep_replaced_file(&kept, before.as_bytes()).map_err(...)` call are identical. net.rs:2454 already names the duplication in prose: "The bundle importer does the same thing for the same reason — see `cli::bundle::keep_replaced_bundles`." The two callers (bundle.rs:393-483 `bundle_import`, net.rs:2541-2643 `net_groups_import`) then repeat a third copy of the same 20-line shape: cwd → `config::manage::scope_path(&Scope::Global, &cwd)` → `keep_replaced_*` → import → `for note in &replaced { diag::warn(note); }` → the identical added/overwritten summary (bundle.rs:447-457 vs net.rs:2595-2605, byte-identical).

**Coût.** ~150 lines of twinned code. The halves this operation already shares (`keep_replaced_file`, `settings_dropped_by`) live in cli/mod.rs, so the split is arbitrary: any change to the overwrite warning's shape — the NAMED cap, the pluralization, the "differed only in layout" case — is two edits in two files, and the wording is user-visible so a missed one is a visible inconsistency. The line-wrap already differs between the two copies of the same sentence.

**Correction proposée.** In src/cli/mod.rs, beside `keep_replaced_file` (mod.rs:234) and `settings_dropped_by` (mod.rs:273): add `pub(crate) fn render_replaced_fragment(noun: &str, name: &str, dropped: &[String], kept: &Path) -> String` — the body of bundle.rs:354-385 with `"replaced {noun} `{name}`, …"`. Add `pub(crate) fn keep_replaced_fragments<T>(config_path: &Path, incoming: &BTreeMap<String, T>, declared: &BTreeMap<String, T>, force: bool, noun: &str, suffix: &str, export_one: impl Fn(&str, &T) -> Result<String, String>) -> Result<Vec<String>, String>` — the body of bundle.rs:307-348, calling `render_replaced_fragment`. Delete bundle.rs:307-385 and net.rs:2456-2533; each caller keeps only its own `config::bundles()` / `config::net_groups()` lookup, its `"bundle"`/`"egress group"` noun, its `"bundle"`/`"group"` suffix, and its exporter closure (`export_bundles` returns `Result`, `export_net_groups` returns `String` — wrap the latter in `Ok`). Move the two existing renderer tests (bundle.rs:601-616, net.rs:3536-3548) to mod.rs and parameterize them by noun. Also hoist the added/overwritten summary (bundle.rs:447-457, net.rs:2595-2605) as `pub(crate) fn import_summary(added: &[String], overwritten: &[String]) -> String`. Nothing here is an intra-doc link target, so rustdoc is unaffected; the net.rs:2454 prose reference to `cli::bundle::keep_replaced_bundles` must be rewritten to point at the shared helper.

**Rectification du vérificateur.** Three corrections. (1) The proposed `noun` parameter is not enough: the error path says "cannot keep the bundle/group being replaced" while the warning says "replaced bundle/egress group" — two different tokens ('group' vs 'egress group'). The proposed signature happens to carry both (`noun` for the render, `suffix` for the file name), so the error must be built from `suffix`, not `noun`, or one of the two messages changes wording. (2) Line-range nits: the import summary block is bundle.rs:448-459 vs net.rs:2596-2607 (verified `let mut parts = Vec::new();` at bundle.rs:448 and net.rs:2596), not 447-457/2595-2605; the two renderer tests are bundle.rs:599-620 and net.rs:3533-3551 — the cited numbers are the `render_replaced_*` calls inside them. (3) The `import_summary` hoist is the weakest part of the fix: it is ~12 lines over two different outcome types, and the `println!` around it differs ("imported {} bundle(s)" vs "imported {} egress group(s)"), so it saves little; the `keep_replaced_fragments` + `render_replaced_fragment` extraction is where the ~150 lines actually collapse.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Line ranges confirmed by grep -n: bundle.rs:307 `fn keep_replaced_bundles(`, bundle.rs:354 `fn render_replaced_bundle(...)`, bundle.rs:393 `fn bundle_import(...)`; net.rs:2456 `fn keep_replaced_groups(`, net.rs:2502 `fn render_replaced_group(...)`, net.rs:2541 `fn net_groups_import(...)`. Reading both bodies confirms the described sameness: identical `if !force { return Ok(Vec::new()); }`, `config_path.parent()` guard, `declared.get(name)` "added, not replaced" skip, `before == after` skip, `crate::cli::keep_replaced_file(&kept, before.as_bytes()).map_err(…)`, and identical renderers down to `const NAMED: usize = 3;`, the `.take(NAMED).map(|l| format!("`{l}`"))` join, `saturating_sub(NAMED)`, the " (and {rest} more)" tail and the 1-line/N-lines pluralization; only the noun differs in the two format strings, and the line-wrap of the same sentence does differ between the copies. The shared halves really do already live in src/cli/mod.rs (`keep_replaced_file` at mod.rs:234, `settings_dropped_by` at mod.rs:273), so the extraction moves code toward an existing seam rather than opening one — bundle.rs and net.rs are both children of `cli`, the `config::bundles()`/`config::net_groups()` lookups stay at the call sites, and nothing security-critical is touched (this is import-time backup bookkeeping). net.rs:2454 does carry the prose "The bundle importer does the same thing for the same reason — see `cli::bundle::keep_replaced_bundles`", and it is a plain code span, not a bracketed intra-doc link, so the rustdoc claim is correct; the only in-code references to the four symbols are the call sites (bundle.rs:434, net.rs:2578-ish) and the two tests.

</details>

---

### D3 — The `std::env::current_dir()` refusal is inlined 15 times though `config_cwd()` already exists and 10 sites use it

| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/cli/net.rs:1118` |
| **Autres sites** | src/cli/net.rs:2171,2564,3006,3027,3079,3308; src/cli/proc.rs:73,163; src/cli/config.rs:161; src/cli/test.rs:77; src/cli/bundle.rs:417; src/cli/app.rs:634,860; src/cli/upgrade.rs:215 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — verbes CLI |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** src/main.rs:266-272 is the shared helper: `fn config_cwd() -> Result<PathBuf, ExitCode> { std::env::current_dir().map_err(|e| { eprintln!("sbx: cannot read the current directory: {e}"); ExitCode::FAILURE }) }`. Ten sites already use it — app.rs:104, app.rs:1390, app.rs:1872, config.rs:2397/2611/2690/2758/2816/2909, upgrade.rs:679 — e.g. upgrade.rs:679-682: `let cwd = match crate::config_cwd() { Ok(c) => c, Err(code) => return code, };`. Twelve other sites inline the identical six lines instead; net.rs:1118-1124 is representative: `let cwd = match std::env::current_dir() { Ok(d) => d, Err(e) => { diag::error(&format!("sbx: cannot read the current directory: {e}")); return ExitCode::FAILURE; } };` — byte-for-byte the same at net.rs:2171, net.rs:2564, net.rs:3006, net.rs:3027, net.rs:3079, proc.rs:73, proc.rs:163, config.rs:161, test.rs:77, bundle.rs:417, app.rs:860 (net.rs:3308 differs only in binding `Ok(c)`). Two more use the `map_err`/`match` variants of the same thing: app.rs:634-637 (`std::env::current_dir().map_err(|e| { diag::error(...); ExitCode::FAILURE })?`) and upgrade.rs:215-220. The message text is identical everywhere; only the emitter differs (`diag::error` at the call sites, a bare `eprintln!` in the helper — which on a non-tty produces the same bytes, since diag::error only lifts backtick spans when stderr is a terminal).

**Coût.** Twelve six-line blocks that a single call replaces, all returning the same `ExitCode::FAILURE`. The helper's existence and its ten users prove the intent; the twelve stragglers mean the message now lives in 13 places and a change to it (or to the exit code) is 13 edits. It also means the crate has two spellings of one diagnostic emitter for the same line.

**Correction proposée.** Replace each of the 12 inline blocks with `let cwd = match config_cwd() { Ok(c) => c, Err(code) => return code, };` (net.rs, proc.rs, config.rs, test.rs, bundle.rs, app.rs) — net.rs, proc.rs, test.rs and bundle.rs must add `config_cwd` to their `use crate::{…}` list (net.rs:21-25, proc.rs:16-17); config.rs and app.rs already import it (config.rs:19, app.rs:16). app.rs:634-637 becomes `let cwd = config_cwd()?;` since it is already in a `Result<_, ExitCode>` function. upgrade.rs:215-220's arm becomes `None => config_cwd()?`-shaped. While there, change `config_cwd`'s `eprintln!` at main.rs:268 to `diag::error(&format!(...))` so the whole crate emits this line through the one chokepoint diag.rs documents; captured (plain-stream) output is unchanged.

**Rectification du vérificateur.** Three corrections. (1) upgrade.rs:215 sits inside `pub(crate) fn upgrade_cmd(args: Vec<OsString>) -> ExitCode` (src/cli/upgrade.rs:171), so the suggested `None => config_cwd()?` does not compile; it must be `None => match config_cwd() { Ok(d) => d, Err(code) => return code }`. Only app.rs:634 can use `?`. (2) The import line cites are off: net.rs's `use crate::{…}` list is lines 20-25, proc.rs's is 14-18 (proc.rs:13 is the separate `use crate::{config, diag, …}` line). (3) The report's impact paragraph says "twelve six-line blocks" while the title and site list say fifteen — fifteen is right (12 byte-identical `match` blocks, net.rs:3308's `Ok(c)` variant, app.rs:634's `map_err`, upgrade.rs:215's nested arm). Also worth stating explicitly so nobody over-applies the sweep: net.rs:899, proc.rs:399, plugins.rs:691,2272,2444,2554,2610, secret.rs:74 and completion.rs:530 use `current_dir()` with a fallback or a different failure shape and must be left alone. Severity downgraded to medium — pure noise removal, no correctness or security effect.

<details>
<summary>Preuve retenue par le vérificateur</summary>

main.rs:266-271 is the helper, quoted correctly (`eprintln!("sbx: cannot read the current directory: {e}")`, `ExitCode::FAILURE`). The ten existing users are exactly app.rs:104,1390,1872, config.rs:2397,2611,2690,2758,2816,2909 and upgrade.rs:679 (`crate::config_cwd()`), verified by grep. The fifteen inline sites are all present and all emit the identical message via `diag::error`: net.rs:1118,2171,2564,3006,3027,3079 and 3308 (which binds `Ok(c)`), proc.rs:73,163, config.rs:161, test.rs:77, bundle.rs:417, app.rs:860 — plus the two variants app.rs:634-637 (`map_err`, inside `fn write_deps(...) -> Result<(), ExitCode>`, so `config_cwd()?` really does fit) and upgrade.rs:215-220. The behaviour argument checks out: src/diag.rs:41-51 documents `error` as adding no prefix — "converting a plain `eprintln!` here changes no byte of a captured stream, only lifts the spans when stderr is a terminal" — and this message contains no backticks, so even on a tty the swap is byte-identical. `config_cwd` is private at the crate root but visible to descendant modules, which upgrade.rs:679 already proves. No test or docs-site page asserts the string.

</details>

---

### D4 — config.rs test module builds the full `ConfigView` literal seven times instead of using its own `sample_config_view()`

| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/cli/config.rs:4184` |
| **Autres sites** | src/cli/config.rs:3240 (sample_config_view), 4327, 4493, 4584, 4719, 4854; plus AppView literals at 3819, 4065, 4120, 4262, 4386, 4466, 4643, 4778, 4913 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — verbes CLI |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** config.rs:3238-3389 defines `fn sample_config_view() -> config::view::ConfigView` — a 150-line literal, described in its own doc as "Built by hand so the render tests need no I/O". Six other tests then build the same struct from scratch: config.rs:4184-4298 (115 lines), 4327-4421 (95), 4493-4558 (66), 4584-4684 (101), 4719-4819 (101), 4854-4969 (116). All seven open with the same fifteen lines verbatim — `timezone: "UTC".to_string(), timezone_origin: Default::default(), open: vec![], service: vec![], plugins: vec![], fs_deny: Vec::new(), tasks: Vec::new(), fs_origin: Default::default(), fs_readonly: Vec::new(), fs_scan: Vec::new(), fs_scan_max_kb: None, notify: Default::default(), notify_origin: Default::default(), ssh_agent_confirm: false, cwd: "/proj".into(),` — and six of them share a further contiguous ~25-line inert tail verbatim (config.rs:4229-4256 vs 4353-4380 vs 4519-4546 vs 4610-4637 vs 4745-4772 vs 4880-4907: `engine: ChannelView { source: "nixos-unstable".into(), origin: "default".into(), locked_rev: None, }, network: NetworkView::Shared, network_origin: ProvenanceView::Default, egress_stats: true, redact_min_len: crate::sandbox::redact::MIN_LEN_DEFAULT, … gpu_origin: ProvenanceView::Default, allow_insecure_http_origin: ProvenanceView::Default, audio_origin: ProvenanceView::Default, dbus_origin: ProvenanceView::Default, forward: vec![], forward_origin: ProvenanceView::Default, seccomp: vec![], seccomp_origin: ProvenanceView::Default, devices: vec![], devices_origin: ProvenanceView::Default, ssh_agent: vec![], brokers: Vec::new(), …`). The nested `AppView` literal repeats the same way — nine sites, with config.rs:4262-4291 and 4386-4415 differing only in the `packages`/`network` field. Meanwhile the *other* tests in the file already use the fixture: config.rs:3354, 3374, 3477, 3496, 3603, 3655, 3692, 3771, 3989, 4044, 4147 all say `let mut view = sample_config_view();` and then mutate the one field under test.

**Coût.** Adding one field to `config::view::ConfigView` — which the CLAUDE.md docs-coverage guard makes a routine event, since every config field a launch accepts must be named in the guide — is seven compile errors in this one file plus nine more for `AppView`, each fixed by pasting the same inert default. ~600 lines of test file are that paste. The two idioms coexisting in one module (`sample_config_view()` + mutate vs. a fresh 100-line literal) also means a reader cannot tell which fields a test actually cares about.

**Correction proposée.** Split the fixture in two inside the same `mod tests`: `fn blank_config_view() -> ConfigView` holding only the inert defaults (the 15-line head and the ~25-line tail that all seven share), and redefine `sample_config_view()` (config.rs:3238) as `ConfigView { env: vec![EnvVar{…}], binds: vec![BindView{…}], packages: vec![PackageView{…}], mise: Some(MiseView{…}), base: ChannelView{…}, network: NetworkView::Allowlist{…}, ..blank_config_view() }`. Rewrite each of the six inline literals as `ConfigView { <only the fields that test names>, ..blank_config_view() }`. Do the same for `AppView`: add `fn blank_app_view(name: &str) -> AppView` and reduce the nine literals (3819, 4065, 4120, 4262, 4386, 4466, 4643, 4778, 4913) to `AppView { packages: …, network: …, ..blank_app_view("demo-app") }`. Struct-update syntax is exhaustive-safe, so a new `ConfigView` field still fails to compile in exactly one place — `blank_config_view` — which is the point.

**Rectification du vérificateur.** Two corrections. (1) The AppView list is wrong by one: config.rs:3819 is an `AppDetailView` literal, not an `AppView` — it is the only `AppDetailView { … }` in the file, so it has no twin and no `blank_app_view` to share. The real AppView sites are eight: 4065, 4120, 4262, 4386, 4466, 4643, 4778, 4913, and two of those (4120, 4466) are already closures parameterized by the varying fields, so `blank_app_view` shrinks their bodies rather than removing a literal. (2) The impact paragraph misattributes the pressure: the docs-coverage guard is about config fields *a launch accepts* being named in the guide, not about `config::view::ConfigView`, so adding a view field is not "a routine event" because of that guard — the honest argument is just the 7+8 mechanical compile errors and the ~600 lines. Severity downgraded to medium: this is test-only churn with no user-facing or security impact, though the fan-out and the two coexisting idioms are real.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified mechanically, not by eye. `fn sample_config_view()` is at config.rs:3238 with the quoted doc "Built by hand so the render tests need no I/O" (3235-3237), and its literal opens at 3240. The six other `let view = ConfigView {` literals are at exactly 4184, 4327, 4493, 4584, 4719, 4854, ending at 4298, 4421, 4558 (checked) as claimed. The 15-line inert head is byte-identical across all seven: md5 of lines 3241-3255, 4185-4199, 4328-4342, 4494-4508, 4585-4599, 4720-4734, 4855-4869 all hash to 36e63e7f27b3b621ab2d3c96e56e47e1. The ~28-line inert tail is byte-identical across the six inline literals: md5 of 4229-4256, 4353-4380, 4519-4546, 4610-4637, 4745-4772, 4880-4907 all hash to ca063e1cb614acce1efc7fc37d10b65f. `diff` of the two AppView literals (4262-4296 vs 4386-4420) is exactly two hunks, `packages` and `network`, as claimed. The eleven `let mut view = sample_config_view();` users at 3354, 3374, 3477, 3496, 3603, 3655, 3692, 3771, 3989, 4044, 4147 are all present, so the fixture-plus-mutate idiom is the module's established one and no comment anywhere in the file argues for exhaustive literals on purpose. The fix is sound: `ConfigView`/`AppView` are crate-internal named-field structs, so `..blank_config_view()` compiles and still funnels a new field into one compile error; the tail the six share carries `network: NetworkView::Shared` while `sample_config_view` sets `NetworkView::Allowlist`, which is exactly the override the proposal already puts in `sample_config_view`.

</details>

---

### D5 — The layout → session-registry → resolve-target preamble is copied into six session-reading verbs

| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/cli/proc.rs:623` |
| **Autres sites** | src/cli/proc.rs:732-748, src/cli/logs.rs:93-109, src/cli/logs.rs:564-580, src/cli/proc.rs:481-495, src/cli/session.rs:70-82 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — verbes CLI |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** proc.rs:623-640 and logs.rs:564-580 are the same 17 lines apart from the id expression and the verb tag. proc.rs:623-640: `let Some(layout) = store::Layout::from_env() else { diag::error("sbx: cannot resolve the data directory (no $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME).",); return ExitCode::FAILURE; }; let sessions = match session::Registry::at(layout.data_dir()).list() { Ok(s) => s, Err(e) => { diag::error(&format!("sbx: cannot read the session registry: {e}")); return ExitCode::FAILURE; } }; let target = match resolve_session_target(&sessions, id, "proc") { Ok(t) => t, Err(code) => return code, };`. logs.rs:564-580 is identical except `resolve_session_target(&sessions, id, "logs")`. proc.rs:732-748 differs only in `parsed.id.as_deref()`. The first two-thirds (layout + registry, 13 lines) appear again at proc.rs:481-495 and session.rs:70-82 with no `resolve_session_target` following. The `cannot read the session registry: {e}` line alone is at logs.rs:102, logs.rs:573, proc.rs:298, proc.rs:426, proc.rs:490, proc.rs:632, proc.rs:741, session.rs:79.

**Coût.** Six handlers open with 13–17 lines of identical plumbing before doing anything specific to the verb; a seventh variant already exists at app.rs:1067 with a different registry-read message (`cannot read the session registry ({e}); not purging …`). Any change to how a session registry read fails — say, distinguishing a missing data dir from an unreadable one — is eight edits across four files.

**Correction proposée.** Add to src/main.rs, beside `resolve_session_target` (main.rs:86): `pub(crate) fn live_sessions(layout: &store::Layout) -> Result<Vec<session::Session>, ExitCode>` wrapping the `Registry::at(layout.data_dir()).list()` match. Combined with promoting `layout_or_fail()` (finding 1), each preamble collapses to three lines: `let layout = layout_or_fail()?; let sessions = live_sessions(&layout)?; let target = resolve_session_target(&sessions, id, "proc")?;` in `Result`-returning helpers, or the `match … return code` form in `-> ExitCode` handlers. Keep `resolve_session_target` separate rather than folding all three into one call: it borrows from `sessions`, and every caller needs the owned `Vec` and the `layout` to live on (proc.rs:634 uses `layout.data_dir()` again, logs.rs:110 calls `(view.socket)(layout.data_dir(), target.pid)`).

**Rectification du vérificateur.** Two details are wrong. (1) The cited range src/cli/proc.rs:481-495 is really 481-493 — 494-495 are `let pal = style::Palette::for_stream(..)` and the palette destructure, unrelated to the preamble. (2) "proc.rs:634 uses `layout.data_dir()` again" is false: 634 is a closing brace, and `proc_ls` never touches `layout` after the registry read (grep -n 'layout.data_dir()' src/cli/proc.rs gives only 487, 498, 544, 629, 738). The "layout must outlive the helper" argument holds only for logs.rs:110/582, proc.rs:498/544 and session.rs:518 — it is still a valid reason to keep the helper from consuming the layout, just not for the function cited. Also, the proposed signature `live_sessions(&store::Layout)` cannot serve proc.rs:295 and proc.rs:423, which read the registry at the `egress_data_dir()` path rather than a `Layout`; take `&Path` instead and the helper covers all eight message sites but one. app.rs:1062-1072 must stay bespoke: it fails closed for a batch and names the apps it refuses to purge.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every site checks out. The full 3-step preamble is at src/cli/proc.rs:623-640 (`let Some(layout)` 623, registry `diag::error` 632, `resolve_session_target(&sessions, id, "proc")` 637-640), src/cli/proc.rs:732-748 (`parsed.id.as_deref()` at 745), src/cli/logs.rs:93-110 (verb is `view.session_verb` at 106, then `(view.socket)(layout.data_dir(), target.pid)` at 110), src/cli/logs.rs:564-580 (`"logs"` at 577). The layout+registry half alone is at src/cli/proc.rs:481-493 and src/cli/session.rs:70-82. `grep -n "cannot read the session registry"` returns exactly the eight sites claimed: logs.rs:102, logs.rs:573, proc.rs:298, proc.rs:426, proc.rs:490, proc.rs:632, proc.rs:741, session.rs:79, plus the divergent app.rs:1067. All eight use `Registry::at(..).list()` with a byte-identical Err arm; no comment anywhere justifies the repetition, and main.rs already hosts the sibling helpers (`resolve_session_target` main.rs:86, `session_pids_for_app` main.rs:504, `pending_session_context` main.rs:488), so a `live_sessions` helper there creates no cycle and opens no seam — the registry read is a plain data read, not a policy decision.

</details>

---

### D6 — `sbx app show` and `sbx app prune` share a 25-line preamble that has already diverged

| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/cli/app.rs:1384` |
| **Autres sites** | src/cli/app.rs:1866-1891 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — verbes CLI |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** app.rs:1384-1412 and app.rs:1866-1891 are the same sequence: `one_name(...)` → `config_cwd()` → `Layout::from_env()` → `config::load(&cwd)` → `resolved.apps.get(name)` → `sandbox::inspect::app_home_dirs(layout.data_dir(), name)` → the `app.is_none() && homes.is_empty()` refusal that lists the declared apps. app.rs:1394-1416: `let Some(layout) = store::Layout::from_env() else { diag::error("sbx: app show: cannot locate sbx's data directory."); return ExitCode::FAILURE; }; let resolved = config::load(&cwd); let app = resolved.apps.get(name); let homes = sandbox::inspect::app_home_dirs(layout.data_dir(), name); if app.is_none() && homes.is_empty() { diag::error(&format!("sbx: app show: no app named {name:?}")); let declared: Vec<String> = resolved.apps.keys().cloned().collect(); if declared.is_empty() { diag::error("sbx: no apps are declared for this directory"); } else { diag::error(&format!("sbx: declared apps: {}", declared.join(", "))); } return ExitCode::FAILURE; }`. app.rs:1876-1891 is the same block with `app prune` substituted — except the empty-set branch is gone: `if app.is_none() && homes.is_empty() { diag::error(&format!("sbx: app prune: no app named {name:?}")); let declared: Vec<String> = resolved.apps.keys().cloned().collect(); if !declared.is_empty() { diag::error(&format!("sbx: declared apps: {}", declared.join(", "))); } return ExitCode::FAILURE; }`.

**Coût.** The divergence is already visible to users: `sbx app show bogus` in a directory with no declared apps prints "sbx: no apps are declared for this directory", while `sbx app prune bogus` in the same directory prints nothing after the refusal and leaves the user with no idea whether the name or the directory is wrong. Neither block names the data-directory variables in its `cannot locate` line (see finding 1).

**Correction proposée.** Add a private helper to src/cli/app.rs, above `app_show`: `struct AppTarget { resolved: config::Resolved, layout: store::Layout, homes: Vec<sandbox::inspect::AppHome> }` and `fn open_app(verb: &str, name: &str) -> Result<AppTarget, ExitCode>` holding lines 1390-1412 with `verb` substituted for `"app show"` and the `declared.is_empty()` branch kept (the more informative of the two). Both `config::load` and `app_home_dirs` return owned values, so there is no lifetime obstacle; the caller re-derives the borrow with `let app = t.resolved.apps.get(name);`. `app_show` becomes `let (name, json) = one_name(...)?; let t = open_app("app show", name)?;`, `app_prune` the same with `"app prune"` and its `-y/--yes` switch. Once finding 1 lands, `open_app` calls `layout_or_fail()?` and the two bespoke `cannot locate sbx's data directory.` strings disappear.

**Rectification du vérificateur.** Line ranges are slightly loose: the app_show block ends at 1413 (`}`), not 1412, and the quoted code is 1394-1413, not 1394-1416 — 1415 is already `build_app_show(..)`. Two things the finding does not say: adopting app_show's `declared.is_empty()` branch changes `sbx app prune`'s stderr output (an added line), which is an improvement but a user-visible behaviour change; nothing in tests/ asserts prune's refusal (tests/app.rs:427-442 covers only `app show nope`), so no test breaks. And a third copy of the declared-apps listing exists at src/cli/config.rs:209-222 (`config show --app`) — it builds the list from `config::view::build(cwd)` rather than `resolved.apps`, so it cannot join the same helper; leave it.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Both blocks are exactly as described. src/cli/app.rs:1384-1413: `one_name(args, &["app","show"], &["--json"], ..)` 1385-1389, `config_cwd()` 1390-1393, `Layout::from_env()` with `"sbx: app show: cannot locate sbx's data directory."` 1394-1397, `config::load(&cwd)` 1399, `resolved.apps.get(name)` 1400, `app_home_dirs(layout.data_dir(), name)` 1401, refusal 1404-1413 with the `declared.is_empty()` branch at 1407-1411. src/cli/app.rs:1866-1891 is the same sequence with `&["-y","--yes"]` (1868) and `"sbx: app prune: ..."` (1877), and its refusal at 1884-1891 has only `if !declared.is_empty()` (1887) — the empty-set sentence is genuinely absent, with no comment explaining the difference. The fix is mechanically sound: `config::load` returns an owned `Resolved` (src/config/load.rs:40) and `app_home_dirs` an owned `Vec<AppHome>` (src/sandbox/inspect.rs:160), so an `AppTarget` struct has no lifetime obstacle and the caller re-borrows with `resolved.apps.get(name)`.

</details>

---

### D7 — `--session` rule injection composes its pid filters with 23 identical lines in net.rs and proc.rs

| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/cli/net.rs:3126` |
| **Autres sites** | src/cli/proc.rs:271-293; the `egress_data_dir()` block alone at net.rs:167,275,490,828,935,1458,2731,3298 and proc.rs:392 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — verbes CLI |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** net.rs:3126-3149 and proc.rs:271-293 are byte-identical apart from one extra comment line in net.rs. net.rs:3126-3149: `let data_dir = match egress_data_dir() { Ok(d) => d, Err(e) => { diag::error(&format!("sbx: {e}")); return ExitCode::FAILURE; } }; let project_pids = if all { None } else { let canonical = match sandbox::project_identity(cwd) { Ok((_, c)) => c, Err(e) => { diag::error(&format!("sbx: cannot resolve the current project directory: {e}")); return ExitCode::FAILURE; } }; Some(session_pids_for_project(&data_dir, &canonical)) }; let app_pids = app.map(|name| session_pids_for_app(&data_dir, name));`. proc.rs:271-293 is the same text (its comment at 278 omits net.rs's second line 3134). Both then filter with the identical pair of guards — net.rs:3155-3160 `if app_pids.as_ref().is_some_and(|p| !p.contains(&pid)) { continue; } if project_pids.as_ref().is_some_and(|p| !p.contains(&pid)) { continue; }` and proc.rs:305-310, again identical. The `egress_data_dir()` half of that block, on its own, is copied at nine more sites (net.rs:167, 275, 490, 828, 935, 1458, 2731, 3298; proc.rs:392) with the same `diag::error(&format!("sbx: {e}")); return ExitCode::FAILURE;` arm.

**Coût.** Eleven copies of the data-dir arm and two copies of the whole scope-filter block. The scoping rule this block encodes is security-relevant — it decides which running sandboxes receive an injected allow/deny rule — so two independent copies of `--all` widening machine-wide is exactly the code that must not drift. `session_pids_for_project` and `session_pids_for_app` are already shared in main.rs; only the composition is not.

**Correction proposée.** Add to src/main.rs beside `session_pids_for_app` (main.rs:504) and `egress_data_dir` (main.rs:474): `pub(crate) fn egress_dir_or_fail() -> Result<PathBuf, ExitCode>` wrapping the nine-times-copied `match egress_data_dir()` arm, and `pub(crate) fn session_scope_pids(data_dir: &Path, all: bool, app: Option<&str>, cwd: &Path) -> Result<(Option<HashSet<u32>>, Option<HashSet<u32>>), ExitCode>` holding net.rs:3133-3149, plus `pub(crate) fn in_scope(pid: u32, project_pids: &Option<HashSet<u32>>, app_pids: &Option<HashSet<u32>>) -> bool` for the two-guard filter. Delete net.rs:3126-3149 / proc.rs:271-293 and the two guard pairs; everything after — the per-list `inject_rule`/`inject_mute`/`inject_proc_rule` dispatch and the two different result renderers (net.rs's `render_inject` at 3193, proc.rs's inline loaded/inert report at 320-355) — stays exactly where it is, since those genuinely differ.

**Rectification du vérificateur.** Three corrections. (1) proc.rs's guard pair is at 306-311, not 305-310 (305 is `let pid = s.pid;`). (2) There are twelve `egress_data_dir()` call sites, not eleven: the sweep missed src/cli/net.rs:1134, which has the identical Err arm but `Ok(d) => d.join("egress")` — it can still use `egress_dir_or_fail()` followed by a `.join`. (3) Important caveat the finding omits: a third, deliberately different project-pid composition lives at src/cli/proc.rs:399-417. Its comment at 403-406 documents why it is not the same code (it refuses instead of widening, and adds a `--all` hint at 413). It must not be folded into `session_scope_pids`, or that hint and the refusal shape are lost. Likewise net.rs:3315-3335 (the `--local` drain) is a different composition. The proposal covers only the two identical sites, which is correct — just do not let the helper grow to swallow the third.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified byte-for-byte. src/cli/net.rs:3126-3149 and src/cli/proc.rs:271-293 are the same code; the only textual difference is net.rs:3134 ("A session must pass every active filter to receive the rule."), which proc.rs omits. Both compose `egress_data_dir()` (3126/271), `project_pids = if all { None } else { .. project_identity(cwd) .. session_pids_for_project }` (3135-3148 / 279-292) and `app_pids = app.map(|name| session_pids_for_app(..))` (3149/293). The two-guard filter is likewise identical: net.rs:3155-3160 and proc.rs:306-311. `session_pids_for_project`/`session_pids_for_app` are already shared out of main.rs:504/531, so only the composition is unshared, and folding it there opens no seam. The nine extra `egress_data_dir()` arms cited (net.rs:167,275,490,828,935,1458,2731,3298; proc.rs:392) all carry the identical `diag::error(&format!("sbx: {e}")); return ExitCode::FAILURE;`.

</details>

---

### D8 — net.rs and proc.rs repeat the rule-write result report four times and three refusal strings twice each

| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/cli/net.rs:3034` |
| **Autres sites** | src/cli/net.rs:3086-3101, src/cli/proc.rs:103-118, src/cli/proc.rs:170-185; the refusal strings at net.rs:2992/3019/3071 and proc.rs:86/97/151 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — verbes CLI |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** Four copies of the same 15-line report. net.rs:3034-3049: `match persist_egress_rule(list, &rule, &parsed.scope, parsed.app.as_deref(), &cwd) { Ok(message) => { println!("{}", style::prose(&message, &style::Palette::for_stream(std::io::stdout().is_terminal()))); ExitCode::SUCCESS } Err((code, message)) => { diag::error(&format!("sbx: {message}")); ExitCode::from(code) } }`. proc.rs:103-118 is the same with `persist_proc_rule`; net.rs:3086-3101 with `persist_egress_removal`; proc.rs:170-185 with `persist_proc_removal`. Three user-visible refusal strings are also written twice each, verbatim: net.rs:2992-2994 and proc.rs:86-88 both say `"sbx: --session loads a live rule and writes no file, so --local/--global/-c do not apply — use -a <app> or --all to scope the session(s)"`; net.rs:3019-3022 and proc.rs:97-100 both say `"sbx: --all only applies with --session (it widens a live rule to every session); a config write targets one file — drop --all"`; net.rs:3071 and proc.rs:151 both say `"sbx: {family} {verb}: --session/--all do not apply — this removes a rule from a config file"` with only the family word differing. On top of that, `persist_egress_removal` (net.rs:3470-3523) and `persist_proc_removal` (proc.rs:193-247) are themselves the same 55-line function modulo `manage::remove_egress_rule` vs `manage::remove_proc_rule` and the family string.

**Coût.** Three security-adjacent refusal sentences and one result-reporting shape maintained in two files. The `--session`/`--all` semantics they explain are identical by design, so a clarification to either sentence is two edits with nothing linking them. The `Err((code, message))` arm is the sole place a persist exit code reaches the process, and it is written four times.

**Correction proposée.** These pieces are enum-independent, so they can be shared without touching the seam net.rs:3457 and proc.rs:121 deliberately keep (`removal_words`, correctly left per-module since the two match over unrelated enums). In src/main.rs beside `persist_egress_rule` (main.rs:800) and `persist_proc_rule` (main.rs:872): add `pub(crate) fn report_rule_write(result: Result<String, (u8, String)>) -> ExitCode` holding the four-times-copied match, and three `pub(crate) const` strings — `SESSION_IGNORES_FILE_SCOPE`, `ALL_NEEDS_SESSION`, and a `pub(crate) fn removal_takes_no_session_flags(family: &str, verb: &str) -> String`. Replace net.rs:3034-3049, net.rs:3086-3101, proc.rs:103-118, proc.rs:170-185 with `report_rule_write(persist_…(…))`, and the six refusal sites with the shared constants. Separately, `persist_egress_removal`/`persist_proc_removal` collapse the same way `persist_egress_rule`/`persist_proc_rule` should: one `fn persist_removal(family: &str, verb: &str, noun: &str, scope, app, base, remove: impl FnOnce(&Path, Option<&str>) -> Result<RemoveOutcome, E>) -> Result<String, (u8, String)>` in main.rs — a closure, not a trait, which is the objection the comment at proc.rs:125-127 raises.

**Rectification du vérificateur.** Small corrections: the report block is 16 lines, not 15; persist_egress_removal runs to net.rs:3524 and persist_proc_removal to proc.rs:248 (each one past the cited end). Two scope notes. Only four of the six `persist_*_rule` call sites can take `report_rule_write` — net.rs:902-914 warns and returns FAILURE, net.rs:3394-3400 counts into a batch renderer; the finding gets this right by naming only four. And the closing aside is overstated: `persist_egress_rule` and `persist_proc_rule` are not a pure copy — they differ in a user-visible string ("set network mode `{mode}`" main.rs:854 vs "set proc mode `{mode}`" main.rs:916) and in the long fail-safe rationale at main.rs:828-833 that has no proc counterpart, so collapsing them needs a noun parameter and a merged comment. The removal pair really is identical and is the one worth merging.

<details>
<summary>Preuve retenue par le vérificateur</summary>

All sites confirmed. The report match is at src/cli/net.rs:3034-3049 (persist_egress_rule), src/cli/net.rs:3086-3101 (persist_egress_removal), src/cli/proc.rs:103-118 (persist_proc_rule), src/cli/proc.rs:170-185 (persist_proc_removal) — identical `Ok(message) => println!(style::prose(..))` / `Err((code, message)) => { diag::error(&format!("sbx: {message}")); ExitCode::from(code) }`. The refusal strings match verbatim: net.rs:2992-2993 vs proc.rs:86-87; net.rs:3019-3020 vs proc.rs:97-98 (differing only in continuation indentation, which the `\` escape strips); net.rs:3071 vs proc.rs:151 differ only in the `net`/`proc` word. `persist_egress_removal` (net.rs:3470-3524) and `persist_proc_removal` (proc.rs:193-248) are the same function apart from the family word, the enum and `manage::remove_egress_rule` vs `manage::remove_proc_rule` — and both of those return the same `Result<RemoveOutcome, ManageError>` (src/config/manage.rs:1025 and 1041), so the closure form needs no generic error parameter. The one documented deliberate separation here is `removal_words` (net.rs:3455-3456, proc.rs:125-126: "deliberately a separate function: the two match over unrelated enums"), and the fix explicitly leaves it alone. There is no "keep net and proc apart" seam to violate: both already call the shared `open_rule_write` (main.rs:737, used at net.rs:3487 and via `crate::open_rule_write` at proc.rs:210), and the add-path twins already live side by side in main.rs:800/872 with a doc comment (main.rs:870-871) saying the admission is shared on purpose.

</details>

---

### D9 — The dotted-key `toml_edit` descent is written out four times in config/manage.rs, and the copies have already diverged into a wrong error

| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/config/manage.rs:607` |
| **Autres sites** | src/config/manage.rs:512, src/config/manage.rs:338, src/config/manage.rs:761 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — config, plugins, store, trust |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** Four functions walk a split dotted key through nested `TableLike`s, in two variants.

Parent-creating variant — `list_at`, src/config/manage.rs:512-529:
```rust
    let mut table: &mut dyn TableLike = doc.as_table_mut();
    for seg in parents.iter().map(String::as_str) {
        if !table.contains_key(seg) {
            let mut created = Table::new();
            created.set_implicit(true);
            table.insert(seg, Item::Table(created));
        }
        table = table
            .get_mut(seg)
            .and_then(Item::as_table_like_mut)
            .ok_or_else(|| ManageError::ParentNotTable(seg.to_string(), key.to_string()))?;
    }
```
`put_value`, src/config/manage.rs:607-623 — the same twelve lines, one closure different:
```rust
    let mut table: &mut dyn TableLike = doc.as_table_mut();
    for seg in parents.iter().map(String::as_str) {
        if !table.contains_key(seg) {
            let mut created = Table::new();
            created.set_implicit(true);
            table.insert(seg, Item::Table(created));
        }
        table = table
            .get_mut(seg)
            .and_then(Item::as_table_like_mut)
            .ok_or_else(|| ManageError::NotScalar(key.to_string()))?;
    }
```
Read-only variant — `get`, src/config/manage.rs:338-345:
```rust
    let mut table: &dyn TableLike = doc.as_table();
    for seg in parents.iter().map(String::as_str) {
        match table.get(seg).and_then(Item::as_table_like) {
            Some(t) => table = t,
            None => return Ok(None),
        }
    }
```
and `unset`, src/config/manage.rs:761-767, identical modulo `_mut` and `return Ok(false)`.

The divergence is not cosmetic. `ManageError::ParentNotTable`'s own doc (src/config/manage.rs:54-57) says `network = "deny"` under `network.allow` "is the case worth a distinct message", and the test `a_parent_holding_a_single_value_is_named_as_the_obstacle` (src/config/manage.rs:2103-2114) pins it for the `rm` path. The `set` path went through the copy that never got the variant: on a config holding `network = "deny"`, `sbx config set network.mode allow` reports `NotScalar` — rendered (src/config/manage.rs:183-186) as "network.mode is not a single value (it is an array or table) — edit it with `sbx config edit`" — about a key that does not exist and is not a table, instead of "network holds a single value, so network.mode cannot be reached".

**Coût.** One user-facing message is already wrong and actively misdirecting (it names the leaf, which is exactly what the `ParentNotTable` doc says "would point at the wrong key entirely"), and it is untested because the test was written against the other copy. Every future change to how `sbx config` descends a dotted key — a new inline-table case, a new refusal — has to be made in up to four places, and the two read-only copies will silently keep the old behaviour.

**Correction proposée.** Add two private helpers next to `split_key` in src/config/manage.rs:
```rust
/// Descend to the table holding `key`'s leaf, creating missing parents as implicit tables.
fn parent_table_mut<'d>(
    doc: &'d mut DocumentMut,
    parents: &[String],
    key: &str,
) -> Result<&'d mut dyn TableLike, ManageError>
```
with the `list_at` body verbatim (keeping `ManageError::ParentNotTable`, the more precise variant), and
```rust
/// Descend to the table holding `key`'s leaf without creating anything; `None` when any
/// parent is absent or is not a table.
fn existing_parent_mut<'d>(doc: &'d mut DocumentMut, parents: &[String]) -> Option<&'d mut dyn TableLike>
```
(plus a `&dyn`/`get` twin for `get`). `list_at` and `put_value` then call the first; `unset` and `get` call the second and map `None` to their own `Ok(false)`/`Ok(None)`. Adopting `ParentNotTable` in `put_value` is a deliberate behaviour fix, so add a `set`-path sibling of the existing test at src/config/manage.rs:2103.

**Rectification du vérificateur.** Three corrections. (1) It is three helpers, not two: Rust cannot be generic over mutability, so `get` needs a `&dyn TableLike` twin of the read-only descent — the claim concedes this in a parenthesis but the fix section reads as two. (2) The two parent-creating copies are not comment-identical: `list_at`:514-517 and 525-527 carry the `add network.groups.infra` and ParentNotTable worked examples, `put_value`:609-613 carries the `set task.build.description` one; the merged helper doc must keep both examples or the reason the parents are implicit is lost. (3) Adopting `ParentNotTable` in `put_value` also requires rewording its doc at src/config/manage.rs:54-56, which is phrased list-only ("A key on the way to *the list*"), and its Display at 196-200 suggests `sbx net allow`, which is off-target for a `config set` failure. Severity is medium, not high: it is a misleading CLI error message on an edge case, with no security or data-loss consequence.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every cite checks out. `get` src/config/manage.rs:338-345 (`&dyn TableLike`, `return Ok(None)`), `list_at` 512-529 (creates implicit parents, `.ok_or_else(|| ManageError::ParentNotTable(seg.to_string(), key.to_string()))?` at 528), `put_value` 607-623 (same creation block, `.ok_or_else(|| ManageError::NotScalar(key.to_string()))?` at 622), `unset` 761-767 (`_mut`, `return Ok(false)`). The divergence is real and reachable: `set` (src/config/manage.rs:390-415) calls `put_value` for every key with no earlier parent check, so on a layer holding `network = "deny"`, `set network.mode allow` hits line 622 and yields `NotScalar("network.mode")`, rendered at 183-186 as "network.mode is not a single value (it is an array or table)" — a key that is neither. That contradicts `NotScalar`'s own doc at line 46 ("resolves onto or through a non-scalar") and `ParentNotTable`'s doc at 54-56 ("`network = \"deny\"` under `network.allow` is the case worth a distinct message"), and `list_at`'s inline comment at 525-527 states the exact rule the `set` copy breaks ("saying 'the list is a single value' about the *leaf* would point at the wrong key entirely"). The test `a_parent_holding_a_single_value_is_named_as_the_obstacle` is at src/config/manage.rs:2102-2114 and exercises `remove`, i.e. the `list_at` copy only. Nothing outside the module matches on these variants (only `GroupCollision` at src/cli/net.rs:2629 and `ImportOutcome` at src/cli/app.rs:666), so switching `put_value` to `ParentNotTable` changes one message and no control flow — no test asserts the current string (the only assertions on these variants are src/config/manage.rs:1865-1866, 1936-1938, 2111, none of which touch a scalar parent).

</details>

---

### D10 — plugins::stores repeats the whole stage → clone → verify → write-bookkeeping sequence in add, rekey and update

| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/plugins/stores.rs:117` |
| **Autres sites** | src/plugins/stores.rs:842, src/plugins/stores.rs:925, src/plugins/stores.rs:280 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — config, plugins, store, trust |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** Three verbs (and, for the first half, a fourth) carry the same fetch pipeline inline.

Staging prologue — `add_inner`, src/plugins/stores.rs:117-131:
```rust
    ensure_owner_only(layout.data_dir())?;
    let stage = Stage(layout.data_dir().join(format!(
        ".store-stage-{}-{}",
        std::process::id(),
        unique()
    )));
    let _ = std::fs::remove_dir_all(&stage.0);
    ensure_owner_only(&stage.0)?;

    let checkout = stage.0.join(CHECKOUT);
    clone(git, url, &checkout)?;
```
`rekey`, src/plugins/stores.rs:842-851 — identical, `&cfg.url` instead of `url`. `update`, src/plugins/stores.rs:925-935 — identical again. `shipped_pubkey`, src/plugins/stores.rs:280-289 — identical but for the `".store-probe-…"` prefix.

Bookkeeping epilogue — `add_inner`, src/plugins/stores.rs:152-161:
```rust
    let _ = std::fs::remove_dir_all(checkout.join(".git"));

    write_file(
        &stage.0.join(STORE_TOML),
        store_toml(url, &pubkey, tofu).as_bytes(),
    )?;
    write_file(
        &stage.0.join(CATALOGUE_LOCK),
        format!("{}\n", catalogue.rev).as_bytes(),
    )?;
```
`rekey`, src/plugins/stores.rs:880-888 and `update`, src/plugins/stores.rs:973-981 — the same nine lines, differing only in which `(url, pubkey, tofu)` triple `store_toml` is handed. The catalogue read is a third repeat: `let catalogue_bytes = read_file(&checkout.join(CATALOGUE))?; let signature = read_signature(&checkout.join(CATALOGUE_SIG))?;` appears at 144-145, 865-866 and 939-940, each followed by a `verified_catalogue(...)` call.

**Coût.** Each of these lines is a security or crash-safety invariant — the data dir must be owner-only *before* anything is staged, the stage must be owner-only, `.git` must be dropped before the tree enters the trusted cache, `store.toml` must be written before the swap. A fourth fetch verb, or a fix to one of these invariants, has to be replicated across three functions in a 2,500-line file, and there is nothing that fails if one copy is missed. The `.store-probe-` copy in `shipped_pubkey` shows the drift starting: it is the same prologue under a different name.

**Correction proposée.** Extract two helpers in src/plugins/stores.rs, beside `Stage` (line ~1240):
```rust
/// A private, owner-only staging tree under the data dir, with `url` freshly cloned into
/// its `checkout/`. The guard removes the tree on every exit path.
fn staged_clone(layout: &crate::store::Layout, prefix: &str, url: &str, git: &Path)
    -> Result<(Stage, PathBuf), String>
```
holding lines 117-131 verbatim with `prefix` in place of the literal `".store-stage"` (`shipped_pubkey` passes `".store-probe"`), and
```rust
/// Drop the git metadata and write the cache's two bookkeeping files into the stage —
/// the trust anchor (`store.toml`) and the rollback floor (`catalogue.lock`).
fn seal_stage(stage: &Stage, checkout: &Path, url: &str, pubkey: &[u8; 32], tofu: bool, rev: u64)
    -> Result<(), String>
```
holding lines 152-161. `add_inner`/`rekey`/`update` keep everything that is genuinely theirs — which key to verify against (`TrustChoice` match), the rollback-floor comparison, the `rekey` "already pinned" refusal, `update`'s key-rotation diagnostic, and the two different placements (`rename` vs `swap_into_place`). The `Stage` drop guard already makes the early-return paths safe, so returning the `Stage` by value is enough.

**Rectification du vérificateur.** Two corrections. (1) "The `.store-probe-` copy in `shipped_pubkey` shows the drift starting" is wrong — the distinct prefix is load-bearing and pinned by tests on both sides: the in-module leak check scans for `.store-stage-` (src/plugins/stores.rs:2521-2527) and tests/plugins.rs:248 asserts no `.store-probe-` residue after a refused add. A shared prefix would make one of those tests blind, so `prefix` must stay a parameter (as the fix proposes) and this is not drift. (2) Severity high is overstated: all three copies are currently correct and consistent, nothing is broken today, and the risk is only future divergence — medium. Minor: `checkout` is derivable from `stage.0.join(CHECKOUT)`, so `seal_stage` needs five parameters, not six.

<details>
<summary>Preuve retenue par le vérificateur</summary>

All eight cites are exact. Prologue: `add_inner` src/plugins/stores.rs:117-131, `rekey` 842-851, `update` 925-935, `shipped_pubkey` 280-289 — identical statement for statement (`ensure_owner_only(layout.data_dir())`, `Stage(...join(format!("<prefix>-{}-{}", process::id(), unique())))`, `remove_dir_all`, `ensure_owner_only(&stage.0)`, `stage.0.join(CHECKOUT)`, `clone(...)`), differing only in the prefix literal and `url` vs `&cfg.url`. Epilogue: 152-161, 880-888, 973-981 — the `remove_dir_all(checkout.join(".git"))` plus the two `write_file`s, differing only in which `(url, pubkey, tofu)` triple `store_toml` receives (`update` passes `cfg.pubkey`/`cfg.tofu`, deliberately never a freshly read key). Catalogue read pairs at 144-145, 865-866, 939-940 as stated. The extraction is sound: `Stage` is a plain Drop guard (src/plugins/stores.rs:1242-1248), so returning it by value keeps every early-return path clean, and the divergent parts the claim leaves in place really are the divergent parts — the `TrustChoice` match (136-139 / 853-856), `rekey`'s already-pinned refusal (857-861), `update`'s key-rotation diagnostic (946-962), the rollback floor (872-878 / 967-972), and `rename` (164) vs `swap_into_place` (889 / 985). No comment anywhere claims the repetition is deliberate; the module doc at src/plugins/stores.rs:11-16 states the clone-stage-swap sequence as one module-wide invariant, which argues for a single helper rather than against it.

</details>

---

### D11 — `write_file` / `write_owner_only` / `write_private_key` and three copies of `unique()` across the plugins module

| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/plugins/stores.rs:1218` |
| **Autres sites** | src/plugins/origin.rs:258, src/plugins/stores.rs:575, src/plugins/mod.rs:1721, src/plugins/stores.rs:1233, src/plugins/origin.rs:274 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — config, plugins, store, trust |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** `plugins::stores::write_file` (src/plugins/stores.rs:1217-1229) and `plugins::origin::write_owner_only` (src/plugins/origin.rs:257-269) are byte-identical, doc comment included:
```rust
/// Write a file owner-readable/writable only, creating it fresh.
fn write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    f.write_all(bytes)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}
```
`plugins::stores::write_private_key` (src/plugins/stores.rs:575-586) is the same body again with two different error strings ("cannot create the signing key `{}`").

`unique()` is defined three times with the same body and its own private `static SEQ`:
```rust
fn unique() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    SEQ.fetch_add(1, Ordering::Relaxed)
}
```
at src/plugins/mod.rs:1721-1725, src/plugins/stores.rs:1233-1237 and src/plugins/origin.rs:274-278.

**Coût.** Six functions in one module tree that must all keep writing at 0o600 with `create_new` (the `create_new` is load-bearing — it is what stops a pre-planted symlink in a directory the cage can reach). A hardening change (adding `O_NOFOLLOW`, or an `fsync` before the rename that follows every one of these writes) has to be applied in three bodies that a grep for one of them will not find, because the names differ. The three `unique()` counters are harmless today only because each is combined with a different filename prefix.

**Correction proposée.** Hoist both into `src/plugins/mod.rs` as `pub(super)` items beside the existing `ensure_owner_only` (src/plugins/mod.rs:1706):
- `pub(super) fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), String>` — the shared body. `stores::write_file` and `origin::write_owner_only` are deleted and their ~8 call sites (src/plugins/stores.rs:154, 158, 257, 881, 885, 974, 978; src/plugins/origin.rs:180) become `super::write_owner_only(...)`. `stores::write_private_key` keeps its wrapper but delegates: `super::write_owner_only(path, bytes).map_err(|e| format!("signing key `{}`: {e}", path.display()))`, or keeps its own strings by taking a `what: &str` parameter on the shared helper.
- Keep the single `unique()` already in `src/plugins/mod.rs:1721`, make it `pub(super)`, and delete the copies in `stores.rs` and `origin.rs` (their call sites are already unqualified `unique()`, so only a `use super::unique;` is needed).
Neither symbol is referenced from a doc link, so nothing in the rustdoc graph moves.

**Rectification du vérificateur.** Three small corrections. (1) The `write_owner_only` call site in origin.rs is at :181, not :180 (:180 is the `remove_file` of the temp). (2) `unique()` in src/plugins/mod.rs:1721 is currently a bare `fn`, not `pub(super)` — the fix must add the visibility, which the claim states, but note the `mod.rs` copy's doc comment mentions "install and trash" staging while the other two mention store staging and origin temp records, so the hoisted doc needs a rewrite to cover all three rather than a copy of one. (3) `write_private_key`'s `create_new` is documented (stores.rs:573-574) as an anti-clobber race guard on a key that is *not* staged-and-renamed, a different rationale from the other two sites' anti-symlink staging — the shared body still serves it identically, so keeping the thin wrapper with its own strings (rather than a `what: &str` flag parameter) is the right half of the proposed fix. Nothing asserts those two strings: grep for `cannot create the signing key` finds only the definitions at stores.rs:583/585, so the wrapper is free to keep or reword them.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every site checks out. src/plugins/stores.rs:1217-1229 (`/// Write a file owner-readable/writable only, creating it fresh.` + `fn write_file` at :1218) and src/plugins/origin.rs:257-269 (same doc line at :257, `fn write_owner_only` at :258) are byte-identical including the doc comment, the `create_new(true).mode(0o600)` and both error strings. src/plugins/stores.rs:575-586 is the same body with `cannot create/write the signing key `{}`` at :583 and :585. The three `unique()` bodies are identical at src/plugins/mod.rs:1721-1725, src/plugins/stores.rs:1233-1237, src/plugins/origin.rs:274-278, each with its own private `static SEQ`. Call sites confirmed: stores.rs:154, 158, 257, 881, 885, 974, 978 and origin.rs:181. No comment anywhere marks the duplication as deliberate — and the codebase argues the opposite: `ensure_owner_only`'s doc at src/plugins/mod.rs:1697-1705 says in as many words that the plugins tree "states it once and every module in it calls this one" because "a copy per module would mean a hardening change here protecting some of those trees and not others". The write helper is the same rule, un-hoisted. The hardening premise also holds: stores.rs:154/158 and 881/885 write into a `Stage` dir that is then `rename`d (stores.rs:164, 889), and origin.rs:179-183 writes a `.tmp-` file it renames at :182. Hoisting to `super::write_owner_only`/`super::unique` beside the already-`pub(super)` `ensure_owner_only` creates no cycle (both are child modules of `plugins`) and neither symbol appears in any intra-doc link (`grep '\[`to_hex`\]'`-style search finds none for these), so rustdoc is unaffected.

</details>

---

### D12 — apply_tools fans the four `:resolve` backends out by hand, eight near-identical call blocks

| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/config/mod.rs:4398` |
| **Autres sites** | src/config/mod.rs:4410, src/config/mod.rs:4422, src/config/mod.rs:4434, src/config/mod.rs:4448, src/config/mod.rs:4457, src/config/mod.rs:4458, src/config/mod.rs:4467 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — config, plugins, store, trust |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** `apply_resolvers` and `apply_prebuilt_libs` are already correctly parameterized (`sentinel`, `label`, `make_backend: fn(Vec<String>) -> Backend`), but `apply_tools` still spells each backend out four times over, in four places.

src/config/mod.rs:4369-4378 — the sentinel collection and the retain:
```rust
    let tarball_names = collect_sentinel(&packages, TARBALL_RESOLVE_SENTINEL);
    let deb_names = collect_sentinel(&packages, DEB_RESOLVE_SENTINEL);
    let appimage_names = collect_sentinel(&packages, APPIMAGE_RESOLVE_SENTINEL);
    let binary_names = collect_sentinel(&packages, BINARY_RESOLVE_SENTINEL);
    packages.retain(|_, v| {
        v.as_str() != TARBALL_RESOLVE_SENTINEL
            && v.as_str() != DEB_RESOLVE_SENTINEL
            && v.as_str() != APPIMAGE_RESOLVE_SENTINEL
            && v.as_str() != BINARY_RESOLVE_SENTINEL
    });
```
src/config/mod.rs:4398-4445 — four eleven-line calls that differ in three tokens:
```rust
    apply_resolvers(out, warnings, source, tarball.clone(), &tarball_names, state,
        protect_trusted, TARBALL_RESOLVE_SENTINEL, "tarball",
        |command| Backend::TarballResolve { command });
    apply_resolvers(out, warnings, source, deb.clone(), &deb_names, state,
        protect_trusted, DEB_RESOLVE_SENTINEL, "deb",
        |command| Backend::DebResolve { command });
    // … appimage, binary
```
src/config/mod.rs:4448-4475 — four more:
```rust
    apply_prebuilt_libs(out, warnings, source, &tarball, "tarball", protect_trusted, state);
    apply_prebuilt_libs(out, warnings, source, &deb, "deb", protect_trusted, state);
    // … appimage, binary
```
And `apply_tools` itself takes the four maps as four separate parameters (src/config/mod.rs:4349-4353), which is a share of why it needs `#[allow(clippy::too_many_arguments)]` at src/config/mod.rs:4342; the four callers at src/config/mod.rs:1767-1770, 2160-2163, 3419-3422 and 3629-3632 each spell them out again.

**Coût.** Adding a fifth prebuilt backend — the module's own docs describe `deb`, `appimage` and `binary` each as "the exact analogue of tarball", so this list demonstrably grows — costs edits at eight places inside `apply_tools` plus four call sites plus three schema structs. Missing the `retain` entry alone makes the sentinel reach `apply_packages`, which rejects the bare prefix and warns on a package the user declared correctly. The four `.clone()`s (needed only because `apply_prebuilt_libs` borrows the map after `apply_resolvers` consumes it) also disappear with the fix.

**Correction proposée.** Inside `apply_tools`, replace lines 4369-4378 and 4398-4475 with a single local table and two loops:
```rust
    let backends: [(BTreeMap<String, RawResolve>, &str, &str, fn(Vec<String>) -> Backend); 4] = [
        (tarball,  TARBALL_RESOLVE_SENTINEL,  "tarball",  |command| Backend::TarballResolve { command }),
        (deb,      DEB_RESOLVE_SENTINEL,      "deb",      |command| Backend::DebResolve { command }),
        (appimage, APPIMAGE_RESOLVE_SENTINEL, "appimage", |command| Backend::AppImageResolve { command }),
        (binary,   BINARY_RESOLVE_SENTINEL,   "binary",   |command| Backend::BinaryResolve { command }),
    ];
    let names: Vec<BTreeSet<String>> =
        backends.iter().map(|(_, s, _, _)| collect_sentinel(&packages, s)).collect();
    packages.retain(|_, v| !backends.iter().any(|(_, s, _, _)| v.as_str() == *s));
```
then one loop calling `apply_resolvers` and, after `apply_packages`/`apply_flakes` have run, a second loop calling `apply_prebuilt_libs` — the two must stay separate loops, since the comment at src/config/mod.rs:4444-4446 records that `libs` decorates packages that must already be in `out`. `apply_resolvers` takes `tables` by value and `apply_prebuilt_libs` by reference, so keep the map alive across both loops (index `backends` in the second loop rather than consuming it in the first, or have `apply_resolvers` return the map). Leave `apply_resolvers` and `apply_prebuilt_libs` themselves untouched — they are already the right seam.

**Rectification du vérificateur.** Two errors in the write-up. (1) "The four `.clone()`s ... also disappear with the fix" is false, and contradicts the claim's own instruction to leave `apply_resolvers` untouched. `apply_resolvers` takes `tables: BTreeMap<String, RawResolve>` by value and consumes it (`for (name, raw) in tables`, src/config/mod.rs:4581, :4593), while `apply_prebuilt_libs` takes `&BTreeMap` (:4492) and must run afterwards — so the first loop must still hand over a clone (or `apply_resolvers` must be changed to return the map, which the claim forbids). Expect the loop version to keep four clones, just written once instead of four times. (2) The ordering comment is at src/config/mod.rs:4446-4447, not 4444-4446 (:4444-4445 are the tail of the `binary` `apply_resolvers` call). Also note the fix does not shrink `apply_tools`'s parameter list or the four call sites, so `#[allow(clippy::too_many_arguments)]` at :4342 stays; the win is the eight in-body blocks collapsing to a table plus two loops, not the signature.

<details>
<summary>Preuve retenue par le vérificateur</summary>

All line numbers are exact. src/config/mod.rs:4369-4372 are the four `collect_sentinel` calls and :4373-4378 the four-clause `retain`; :4398-4445 are the four eleven-line `apply_resolvers` calls differing only in the map, the sentinel const, the label and the `Backend` constructor; :4448-4475 are the four `apply_prebuilt_libs` calls (the `deb` one collapsed to one line at :4457 by rustfmt). `apply_tools`'s four map parameters are at :4350-4353 under the `#[allow(clippy::too_many_arguments)]` at :4342, and the four callers spell them out at :1767-1770, :2160-2163, :3419-3422 and :3629-3632 — all verified. `apply_resolvers` (src/config/mod.rs:4577-4588) is already parameterized on `sentinel`, `label` and `make_backend: fn(Vec<String>) -> Backend`, so the non-capturing closures coerce cleanly into a table; `apply_prebuilt_libs` (:4488-4496) is parameterized on `label`. The ordering constraint the claim flags is real and correctly respected by the two-loop shape: `apply_prebuilt_libs` resolves each `libs` table against a package already in `out` (:4501-4507) and warns when `slot.backend.label() != label` (:4507), so it must run after all four `apply_resolvers` calls. No comment marks the fan-out as deliberate.

</details>

---

### D13 — handle_https_forward is a 300-line verbatim clone of serve_tunneled_request's back half, and it has already diverged on the WS pseudo-verb

| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/sandbox/proxy/forward.rs:158` |
| **Autres sites** | src/sandbox/proxy/tunnel.rs:307 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — proxy (HTTP/1.1, HTTP/2, WebSocket) |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** From the injection match to the end of the response relay, forward.rs:158-607 and tunnel.rs:307-908 are the same code. A normalized diff (comments stripped, `connect_host`->`host`, `imethod`->`method`, `itarget`->`path`, `respond_refusal_tls(&mut br` -> `write_refusal(&mut client`, `br.get_mut()`->`client`, `inner`->`head`) makes 309 of ~385 lines identical; the only real deltas are the `!ws_upgrade` guards, the WebSocket branch, and the `ClientLeg`/`Turn` tail.

Sample pairs, verbatim from the files:

tunnel.rs:354-358 and forward.rs:192-195 (the pool-hold heuristic):
  tunnel:  `let hold_for_reuse = ctx.pool.is_some()` / `&& !ws_upgrade` / `&& digest_wanted.is_none()` / `&& !chunked` / `&& (1..=POOL_HOLD_MAX).contains(&body_len);`
  forward: `let hold_for_reuse = ctx.pool.is_some()` / `&& digest_wanted.is_none()` / `&& !chunked` / `&& (1..=POOL_HOLD_MAX).contains(&body_len);`

tunnel.rs:491 and forward.rs:315 (replayability, character for character):
  both: `let replayable = chunked || body_len == 0 || held.is_some();`

tunnel.rs:605 and forward.rs:368 (the forwarded-bytes construction, followed by ~60 identical lines each):
  both: `let forwarded: Option<Vec<u8>> = if !replayable {`

The drift is at the WS pseudo-verb. tunnel.rs:139-143 REBINDS the method itself:
  `let ws_upgrade = is_websocket_upgrade(&inner);`
  `let imethod = if ws_upgrade { "WS".to_string() } else { imethod };`
so every later `ctx.outcome` / `push_log` / `outcome_l7` on that plane names `WS` — e.g. tunnel.rs:283 `Some(&imethod)` into `resolve_checked`, tunnel.rs:530 `Some(&imethod)` into the allow `outcome_l7`.

forward.rs:90-91 instead introduces a SECOND binding and leaves `method` alone:
  `let ws_upgrade = is_websocket_upgrade(head);`
  `let verb = if ws_upgrade { "WS" } else { method };`
`verb` is then used at only two of the ~10 downstream sites (forward.rs:95 `decide_https`, forward.rs:117 the `ws-injection-refused` outcome). forward.rs:134 passes `Some(method)` to `resolve_checked`, and forward.rs:340 passes `Some(method)` to the allow `outcome_l7`.

**Coût.** Concrete, already-shipped divergence: an absolute-form WebSocket handshake that a `{WS}` rule allows is recorded in `sbx net logs` and `sbx net stats` as method `GET` on the forward plane and as `WS` on the tunnel plane, for the identical request under the identical policy — while forward.rs's own module doc (forward.rs:22-24) claims parity "down to deciding a WebSocket handshake under the `WS` pseudo-verb rather than its literal `GET`". The same split hits an SSRF-blocked upgrade (forward.rs:134 vs tunnel.rs:283). Beyond that, every future fix to the request/response pipeline — the pool-hold heuristic, the `Expect: 100-continue` ordering, the retry-on-dead-parked-connection loop, the body-budget release point — has to be made twice and verified twice; mod.rs's own module doc says this is the failure mode it exists to avoid ("every divergence between the planes that has turned into a bug was a decision written out twice").

**Correction proposée.** Extract the shared span into a new `src/sandbox/proxy/exchange.rs`, generic over the client leg. (a) Add `struct TunnelLeg(BufReader<StreamOwned<ServerConnection, UnixStream>>)` and `struct ForwardLeg(BufReader<UnixStream>)` there, each `impl Read + BufRead` by delegation and `impl Write` via `self.0.get_mut()` — that is the only reason the two bodies cannot already share a type. (b) Move tunnel.rs:307-580 / forward.rs:158-366 into `pub(super) fn prepare<C: BufRead + Write>(...) -> io::Result<Option<Prepared>>` where `Prepared { injected, injected_ids, held, budget, keep_alive, pool_key, replayable, upstream, from_pool, allow_seq, flow, capture }`; every refusal inside writes through `write_refusal` on the `&mut C` and returns `Ok(None)`. (c) Move tunnel.rs:605-908 / forward.rs:368-607 into `pub(super) fn forward_and_relay<C: BufRead + Write>(..., client_leg: ClientLeg) -> io::Result<Reuse>` returning `Reuse { persistent, position_known }`. (d) tunnel.rs keeps its SNI check, origin-form check, the `imethod`->`"WS"` rebinding, the `if ws_upgrade { relay_upgrade(...) }` branch (which consumes `Prepared`'s `upstream`/`capture`/`flow`), the `Turn` mapping and `finish_tls`. forward.rs keeps `admit_absolute_form`, `decide_https`, the `ws-injection-refused` refusal and the origin-form `Head` construction, and DROPS `verb` in favour of rebinding `method` the way tunnel.rs does — which is the divergence fix. (e) mod.rs's "Where things live" list (mod.rs:17-25) gains `exchange`. Honest cost: a ~600-line move through security-sensitive sequencing, and it must not dissolve the seam that keeps the WebSocket relay and the `Turn` lifetime in tunnel.rs — the two-function split above is what preserves it. Existing coverage is good (forward.rs:604-708 drives `handle_https_forward` over a socket pair with an unchanged signature, and tests.rs exercises both planes end to end), so the refactor is verifiable rather than speculative.

**Rectification du vérificateur.** Facts hold; severity and one step of the fix do not.

(1) Severity is medium, not high. The divergence is confined to the verb *label* written into `sbx net logs`/`sbx net stats`. The verdict itself (decide_https, forward.rs:95), the ws-injection refusal (forward.rs:113-129) and the parking posture are all in genuine parity - no security property differs. forward.rs:40-45 already says this plane "cannot switch protocols" and that "an upgrade the policy permits does not complete here", so logging the literal GET is arguably defensible; what is not defensible is that forward.rs:118 logs `WS` for the injection refusal while forward.rs:138 and :340 log `GET` for the SSRF refusal and the allow, inside the same function.

(2) Fix step (d) is a BUG as written. "forward.rs ... DROPS `verb` in favour of rebinding `method` the way tunnel.rs does" would corrupt the wire: forward.rs:364-367 builds the forwarded request line as `format!("{method} {path} {version}")`, so a rebound `method` sends `WS /socket HTTP/1.1` upstream. tunnel.rs can rebind safely only because it never rebuilds a request line - it reserializes `&inner` verbatim. `method` is also handed to `relay_response_head` as `request_method` (mod.rs:1454), feeding `response_framing`. The correct fix is the inverse: KEEP `verb` and use it at forward.rs:138, :340 and in `refuse_upstream`, never in `origin.request_line`. That is a ~4-line change, entirely independent of the extraction, and it is where the value of this finding actually sits.

(3) The extraction is in tension with mod.rs:20-24, which makes per-plane *sequencing* the deliberate content of these modules ("each is one plane's *sequencing* of decisions that all live here. That is deliberate ... only the order and the answering belong to a plane"). Moving ~600 lines of that ordering into a shared generic is defensible only because tunnel.rs keeps its gates, its WS rebinding, its upgrade branch and its `Turn` lifetime - but that module doc must be amended to say so, not merely gain an `exchange` bullet.

(4) Mechanical corrections: tunnel's leg is `Box<ClientTls>` (tunnel.rs:26, :40, :54) while `relay_upgrade` takes an unboxed `BufReader<StreamOwned<..>>` by value (websocket.rs:824), so `TunnelLeg` must wrap or deref the Box. `respond_refusal_tls` (tunnel.rs:960-967) is `write_refusal` + `Ok(Turn::Close)`, so a shared refusal returning `Ok(None)` does preserve the type-level property its doc at tunnel.rs:955-959 describes. The test-coverage citation is off: the tests are forward.rs:611-714, with `handle_https_forward` driven at :638, not 604-708.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every cited site checks out. src/sandbox/proxy/forward.rs:158 and src/sandbox/proxy/tunnel.rs:307 are both `let injected_ids = matching_injection_ids(...)`. The pool-hold heuristic is at forward.rs:192-195 (no `!ws_upgrade`) vs tunnel.rs:354-358 (with it). `let replayable = chunked || body_len == 0 || held.is_some();` is character-for-character at forward.rs:315 and tunnel.rs:491. `let forwarded: Option<Vec<u8>> = if !replayable {` is at forward.rs:368 and tunnel.rs:605. I reproduced the normalized diff: stripping comments and applying the reporter's renames, 295 of forward.rs:158-607's 348 code lines are identical to tunnel.rs:307-908, with only 53 forward-only and 82 tunnel-only lines. The real deltas are exactly the ones named: refusal writer (`write_refusal(&mut client` vs `respond_refusal_tls(&mut br`), the two `!ws_upgrade` guards (hold_for_reuse at tunnel.rs:355, keep_alive just below), body reads through a temp `BufReader::new(&client)` vs the persistent `br`, the `if ws_upgrade { relay_upgrade }` branch, the origin-form `Head` construction (forward.rs:364-367), `ClientLeg::Close` vs `MayReuse`, and the `Turn` tail (tunnel.rs:906-913). The WS divergence is real and internally inconsistent within forward.rs itself: `verb` exists at forward.rs:90 and is used at only :95, :103 and :118, while `Some(method)` goes to `resolve_checked` (forward.rs:138, inside the call opened at :133) and to the allow `outcome_l7` (forward.rs:340); tunnel.rs:139-143 rebinds `imethod` itself, so tunnel.rs:286 and tunnel.rs:530 both carry `WS`. The tunnel's allow `outcome_l7` at tunnel.rs:520-534 runs BEFORE the `if ws_upgrade` early return, so an allowed absolute-form upgrade really is logged `GET` on one plane and `WS` on the other. mod.rs:22-24 does say "every divergence between the planes that has turned into a bug was a decision written out twice".

</details>

---

### D14 — The declined-WebSocket-upgrade branch hand-rolls relay_response_head and has lost both the Connection rewrite and the reflection masking

| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/sandbox/proxy/websocket.rs:854` |
| **Autres sites** | src/sandbox/proxy/mod.rs:1485 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — proxy (HTTP/1.1, HTTP/2, WebSocket) |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** When the upstream answers a WebSocket handshake with anything other than `101`, websocket.rs:845-873 relays that response by re-implementing, inline, what `relay_response_head` (mod.rs:1446-1506) does for every other response — and two of that function's steps are missing.

websocket.rs:854-870 (the copy):
  `br.get_mut().write_all(&resp_head)?;`
  `down.fetch_add(resp_head.len() as u64, Ordering::Relaxed);`
  `if let Some(c) = capture { c.push_response(&resp_head); }`
  `let framing = response_framing(&resp_head, "GET");`
  `let counted = CountingReader::new(FramedBody::new(up_br, framing), down.clone());`
  `let mut body: Box<dyn Read + '_> = match capture { Some(c) => Box::new(CaptureReader::new(counted, c.response_sink())), None => Box::new(counted) };`
  `pump_to_eof(&mut body, br.get_mut())?;`

mod.rs:1485-1494 (the shared original):
  `let mut wire = match client_leg {`
  `    _ if !final_head => head.clone(),`
  `    ClientLeg::MayReuse { idle } if persistent => offer_reuse_in_head(&head, idle),`
  `    ClientLeg::Close | ClientLeg::MayReuse { .. } => force_close_in_head(&head),`
  `};`
  `if !redactions.is_empty() { redact_in_place(&mut wire, redactions); }`
  `client.write_all(&wire)?;`
  `down.fetch_add(wire.len() as u64, Ordering::Relaxed);`

The upgrade branch writes `resp_head` raw — no `force_close_in_head`, no `redact_in_place` — and then closes the leg unconditionally at websocket.rs:871 (`finish_tls(br.get_mut());`).

**Coût.** Two live gaps on the declined-upgrade path. (1) The cage is handed the UPSTREAM's `Connection: keep-alive` / `Keep-Alive: timeout=N` on a TLS leg sbx closes one line later — exactly the failure `ClientLeg`'s doc (mod.rs:1524-1531) was written to fix on the other planes ("an upstream that answers `keep-alive` anyway would have told the cage it could send a second request into a connection sbx is about to close"); a non-idempotent request pipelined into it is simply lost. (2) No reflected-secret masking, and this is reachable: the upgrade is refused only when `matching_injection_ids` (mod.rs:1215-1229, PATH-scoped via `allowlist::rule_matches`) is non-empty, while `masks_reflection` keys on `names_exact_host` (ssrf.rs:267-278, HOST-only) — so an injection scoped `api.test/v1/*` plus a handshake to `api.test/socket` passes the ws-injection refusal at tunnel.rs:259 and then relays a declined response head and body unmasked, where the ordinary request path on the same host would mask both.

**Correction proposée.** Split the tail of `relay_response_head` into `pub(super) fn relay_final_head<W: Write>(head: &[u8], client: &mut W, down: &AtomicU64, capture: Option<&CaptureGuard>, redactions: &[SecretNeedle], client_leg: ClientLeg) -> io::Result<()>` in mod.rs, holding exactly mod.rs:1485-1494 plus the `c.push_response(&head)` at mod.rs:1500-1502; `relay_response_head` calls it, and websocket.rs:854-860 is replaced by one call with `ClientLeg::Close`. `relay_upgrade` cannot call `relay_response_head` itself (that function treats any 1xx, `101` included, as an interim head to relay and loop past — mod.rs:1466-1467), which is why the tail rather than the whole function is what moves. To close gap (2), thread the `masks_reflection` needle slice from tunnel.rs:784-788 into `relay_upgrade`'s signature (it already takes 9 arguments and carries `#[allow(clippy::too_many_arguments)]`) and pass it as `redactions`.

**Rectification du vérificateur.** Real on both gaps, but overstated as high, and the fix is incomplete in three places.

Severity: gap (1) is a genuine protocol-level lie, but its blast radius is one lost pipelined request on a leg that still closes cleanly with `close_notify` (websocket.rs:871). Gap (2) needs a four-way coincidence - a path-scoped injection rule on the host, a separate `{WS}` allow for a different path on that same host, the upstream declining the handshake, and the declined response actually echoing a configured secret. Both are worth fixing; neither is high.

Fix corrections:
- `relay_final_head(head, client, down, capture, redactions, client_leg)` as signed cannot compute `persistent`, which mod.rs:1476-1480 derives from `framing` and `response_keeps_alive`. It needs `persistent: bool` passed in (trivially `false` for the `ClientLeg::Close` call from websocket.rs) or must also take `framing`.
- Threading the needles into `relay_upgrade` cannot reuse tunnel.rs:784-788 in place: that binding is computed AFTER the `if ws_upgrade { return Turn::closing(relay_upgrade(...)) }` early return, so it must be hoisted above the branch or recomputed. It is a pure function of `creds` + `connect_host`, so either is safe.
- Incomplete: the accepted-upgrade path has the identical masking hole. websocket.rs:879 writes the `101` head raw with no redaction either. If the reflection gap is worth closing on the declined branch it is worth closing on the `101` head too (the frames past it are correctly out of scope - websocket.rs:884-886).

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified line by line. src/sandbox/proxy/websocket.rs:845-873 is the non-101 branch and :854-870 is exactly the quoted inline relay: `br.get_mut().write_all(&resp_head)?;` at :854, `down.fetch_add` at :855, `c.push_response(&resp_head)` at :859, `response_framing(&resp_head, "GET")` at :863, `CountingReader::new(FramedBody::new(up_br, framing), down.clone())` at :865, the `Box<dyn Read>` capture tee at :866-869, `pump_to_eof(&mut body, br.get_mut())?` at :870, `finish_tls(br.get_mut());` at :871. The shared original is at mod.rs:1485-1494 exactly as quoted (`let mut wire = match client_leg {` at 1485, `force_close_in_head` at 1488, `redact_in_place` at 1491, `client.write_all(&wire)?` at 1493), with `c.push_response(&head)` at mod.rs:1500. Neither `force_close_in_head` nor `redact_in_place` appears anywhere in the websocket.rs branch. Gap (1) is real and is precisely the failure ClientLeg's doc describes at mod.rs:1524-1530 ("an upstream that answers `keep-alive` anyway would have told the cage it could send a second request into a connection sbx is about to close") - the leg is closed one line later at websocket.rs:871, and `Turn::closing` (tunnel.rs:34-36) maps the return to `Turn::Close`. Gap (2) is also real and the reachability argument holds: `matching_injection_ids` (mod.rs:1215-1228) filters on `allowlist::rule_matches(&inj.rule, host, port, target)` - path-scoped - while `names_exact_host` (ssrf.rs:267-278) matches `RuleKind::Url { host: rh, .. } => *rh == h`, host-only, so an `api.test/v1/*` injection makes `masks_reflection` true at tunnel.rs:784-788 for every path on that host yet leaves `matching_injection_ids` empty for `/socket`, so the ws-injection refusal at tunnel.rs:259 does not fire and the declined response is relayed unmasked. The claim that `relay_response_head` cannot be called wholesale is correct: mod.rs:1464-1465 classifies any 100..200 status, 101 included, as `interim` and loops past it.

</details>

---

### D15 — The pty open/fork/raw-mode/relay block is written twice in launch.rs

| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/sandbox/launch.rs:5801` |
| **Autres sites** | src/sandbox/launch.rs:2760 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — modules sandbox |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** `supervise` (launch.rs:5801-5877) and `supervise_attach` (launch.rs:2760-2826) carry the same ~66-line block. supervise:5801-5824 — `// Carry the real terminal's window size onto the pty so the inner shell / // wraps correctly from the start.` then `let mut ws: libc::winsize = unsafe { std::mem::zeroed() }; let winp = if unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) } == 0 { &ws as *const libc::winsize } else { std::ptr::null() };` then `libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null(), winp)`. supervise_attach:2760-2778 — `// Carry the real terminal's window size onto the pty so the inner shell wraps correctly from / // the start (as `supervise` does).` then the identical `ws`/`winp`/`openpty` lines. Both then repeat the CLOEXEC step verbatim (`let flags = libc::fcntl(master, libc::F_GETFD); libc::fcntl(master, libc::F_SETFD, flags | libc::FD_CLOEXEC);` at 5829-5831 and 2783-2785), the same fork-failure cleanup (`if child < 0 { let e = io::Error::last_os_error(); unsafe { libc::close(master); libc::close(slave); } return Err(e); }` at 5835-5842 and 2789-2798), and the same parent tail: `unsafe { libc::close(slave) }; let _raw = RawMode::enable(0)?; let winch = WinchRelay::install().ok(); if winch.is_some() { copy_winsize(0, master); } let winch_fd = winch.as_ref().map_or(-1, WinchRelay::read_fd); let status = pump(master, child, winch_fd, gui); drop(winch); unsafe { libc::close(master) }; status` (5859-5877) against the byte-identical tail at 2812-2826 with `false` in place of `gui`. supervise_attach's own comment at 2812 says "identical to `supervise`'s tail". Only two things actually differ: what the child does after the fork (`login_tty(slave)` + `execv` vs `attach::enter_and_exec(..., TtyMode::Pty(slave), ...)`), and the `gui` flag handed to `pump`.

**Coût.** Every change to sbx's terminal handling has to be made twice, and the pty master is the fd the cage must never see — the CLOEXEC step and the child's `close(master)` are security-relevant lines living in two places. The reasoning supervise carries at 5861-5865 about installing the WinchRelay after the fork is absent from supervise_attach, which is exactly how the two drift.

**Correction proposée.** Move the shared block into src/sandbox/pty.rs, which already owns `pump`, `copy_winsize`, `WinchRelay` (pty.rs:246), `RawMode` (pty.rs:329) and `exit_code`: add `pub(crate) unsafe fn fork_with_pty(gui: bool, child: impl FnOnce(libc::c_int) -> !) -> io::Result<i32>` doing the winsize probe, `openpty`, CLOEXEC on the master, `fork`, `child(slave)` in the child (documenting the async-signal-safe-only contract and that the closure must close the master itself), then the existing parent tail. `supervise` keeps its `seccomp_argv`/`cgroup::wrap`/`cstring` prelude and passes a closure doing `close(master)` + `login_tty(slave)` + `execv`; `supervise_attach` keeps its filter/argv/envp prelude and its `drop(cage)` after the call, and passes a closure doing `close(master)` + `attach::enter_and_exec`. pty.rs's module header gains a line for the new entry point.

**Rectification du vérificateur.** Three corrections. (1) The reasoning about installing the WinchRelay after the fork is at launch.rs:5863-5867, not 5861-5865; supervise's block spans 5801-5877 (77 lines) and supervise_attach's 2760-2826 (67), not "~66" each. (2) There is a third difference the description omits: supervise_attach drops the cage handle in the parent at launch.rs:2816, between `close(slave)` and `RawMode::enable`, and the comment at 2813-2814 explains why (the child holds its own copies across the fork; CageHandle owns a pidfd, attach.rs:59-63). The proposed "keeps its `drop(cage)` after the call" would hold that pidfd open for the whole session. It is recoverable — `fork_with_pty` can `drop(child_closure)` in the parent right after the fork, which the borrow checker accepts because the child branch diverges — but the fix as written changes fd lifetime and should say so. (3) Severity: this is one duplicated pair inside a single file whose two halves already cross-reference each other, and no drift has actually occurred yet (unlike claim 3's pair, where the tree records two regressions). Medium, not high.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every cited site checks out. src/sandbox/launch.rs:5801-5877 (supervise) and 2760-2826 (supervise_attach) carry the same sequence: the winsize probe (5801-5808 / 2760-2767), the identical `libc::openpty` call (5814-5825 / 2770-2781), the byte-identical CLOEXEC step (5830-5833 / 2783-2786), the identical fork-failure cleanup (5837-5845 / 2791-2799), and a parent tail that is line-for-line the same apart from `gui` vs `false` in the `pump` call (5861-5877 / 2815-2826). supervise_attach's own comment at launch.rs:2814 says "identical to `supervise`'s tail". The target module is real and its doc header ("Pure file-descriptor and terminal machinery — no launch or config state", src/sandbox/pty.rs:1-3) accommodates the new entry point, and it already owns pump (pty.rs:44), exit_code (157), WinchRelay (246), copy_winsize (320) and RawMode (329). The `FnOnce(c_int) -> !` closure contract is satisfiable: attach::enter_and_exec is declared `-> !` (src/sandbox/attach.rs:285-291) and libc::_exit is `!`, so both child branches diverge. No comment anywhere claims the restatement is deliberate, and no security seam is dissolved — the launch-specific argv/cage material stays in launch.rs.

</details>

---

### D16 — temp-file-then-rename is written eight times, and the cleanup behaviour has already diverged three ways

| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/sandbox/binds.rs:1476` |
| **Autres sites** | src/sandbox/flake.rs:116, src/sandbox/nixhub.rs:531, src/sandbox/prebuilt.rs:269, src/sandbox/notify_sink.rs:354, src/sandbox/audio.rs:261, src/sandbox/fonts.rs:136, src/sandbox/egress_stats.rs:307 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — modules sandbox |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** binds.rs:1476-1484 is the only named primitive: `fn write_atomic(path, bytes) { let tmp = dir.join(format!(".{name}.tmp.{}", std::process::id())); std::fs::write(&tmp, bytes)?; std::fs::rename(&tmp, path).inspect_err(|_| { let _ = std::fs::remove_file(&tmp); }) }` — no cleanup on a write error, cleanup on a rename error. flake.rs:134-138: `let tmp = path.with_extension(format!("tmp.{}", std::process::id())); if let Err(e) = std::fs::write(&tmp, body) { let _ = std::fs::remove_file(&tmp); return Err(e); } std::fs::rename(&tmp, &path)` — the opposite: cleanup on write, none on rename. nixhub.rs:547-552 is that same block verbatim, under a word-for-word identical docstring ("Write the lock atomically (temp + rename), creating the owner-only parent — so a concurrent launch reading it sees the old or the new file, never a torn one."). prebuilt.rs:294-302: `let tmp = path.with_extension(format!("tmp-{}", std::process::id())); std::fs::write(&tmp, body)?; match std::fs::rename(&tmp, &path) { Ok(()) => Ok(()), Err(e) => { let _ = std::fs::remove_file(&tmp); Err(e) } }` — a third combination, and a third temp-name spelling (`tmp-` rather than `tmp.`). notify_sink.rs:363-368: `let tmp = path.with_extension(format!("png.{}", std::process::id())); std::fs::write(&tmp, bytes).ok()?; if std::fs::rename(&tmp, path).is_err() { let _ = std::fs::remove_file(&tmp); return None; }` — the `.ok()?` on line 364 leaks the temp on a write failure. audio.rs:267-278 and fonts.rs:145-161 clean up on both. Three of them also repeat the parent step as the identical eight-line `if let Some(parent) = path.parent() { use std::fs::DirBuilder; use std::os::unix::fs::DirBuilderExt; DirBuilder::new().recursive(true).mode(0o700).create(parent)?; }` (flake.rs:122-129, nixhub.rs:532-539, prebuilt.rs:276-283).

**Coût.** Four different answers to "what happens to the temp file when this fails" for one rule, in the code that writes every per-project pin lock (flake, nixhub, deb/appimage/tarball/binary), the cage's synthetic /etc/passwd and egress contract, and the desktop mark. notify_sink.rs:364 already leaks a `.png.<pid>` orphan on ENOSPC. A future hardening of the shape — an fsync before the rename, say — has to be made in eight places to be made at all.

**Correction proposée.** New module `src/sandbox/atomicfile.rs`, registered in src/sandbox/mod.rs beside `cagedir`/`conncap` with a header comment in the same style, holding `pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()>` — parent created 0700, unique temp sibling, remove the temp on either failure (the strictest of the four current behaviours) — and `pub(crate) fn write_atomic_if_changed(path: &Path, bytes: &[u8]) -> io::Result<bool>` for the read-compare skip that audio.rs:264 and notify_sink.rs:356 both open with. Delete binds::write_atomic and update the intra-doc link at binds.rs:1431 (``[`write_atomic`]``) to ``[`super::atomicfile::write_atomic`]``, or `mise run rustdoc` fails the build. Replace the bodies of flake::write_pins, nixhub::LockFile::write, prebuilt::write_pins, notify_sink::write_mark and audio::stage_atomically with a call. What stays in each caller: its own body serialisation (the tab-separated lock lines) and its own docstring about why the file is written at all.

**Rectification du vérificateur.** Four corrections. (1) "A third combination" for prebuilt and "four different answers" are wrong: prebuilt.rs:296-303 (`write(...)?` then remove-on-rename-error) is behaviourally identical to binds.rs:1485-1488, and notify_sink.rs:364-368 is the same combination again. There are three distinct behaviours, not four — which is what the title says; the description contradicts it. (2) The intra-doc link is at binds.rs:1436, not 1431. (3) egress_stats.rs:307 does not belong in the site list: `flush` writes through `OpenOptions ... .mode(0o600)` with a per-instance `tmp_seq` counter rather than pid (egress_stats.rs:314-326), and the fix does not propose changing it — drop it from also_at. (4) The unified helper MUST keep binds' dot-prefixed temp name (`.{name}.tmp.{pid}`), not flake's `with_extension("tmp.{pid}")`: binds.rs:1539-1542 argues that the router directory bound at OPEN_ROUTER_DIR leads the cage's PATH and that write_atomic's temp sibling "is the one other name that appears here" — a non-hidden `xdg-open.tmp.<pid>` in that directory would weaken a documented property. Two further behaviour deltas the fix should acknowledge: audio.rs:262 uses plain `create_dir_all` (umask mode) where the helper would create 0700, and binds' callers already create their own 0700 dirs.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The sites are real. binds.rs:1476-1489 (`write_atomic`, fn at 1481) writes with `?` then `rename(...).inspect_err(remove_file)`. flake.rs:134-139 and nixhub.rs:547-552 are the opposite pairing, under a word-for-word identical docstring (flake.rs:114-115 vs nixhub.rs:529-530). prebuilt.rs:295-303, notify_sink.rs:363-368, audio.rs:267-278 and fonts.rs:144-161 are the other four. The eight-line 0700-parent block is repeated verbatim at flake.rs:122-129, nixhub.rs:532-539 and prebuilt.rs:276-283. notify_sink.rs:364's `std::fs::write(&tmp, bytes).ok()?` does return without removing the temp, so the leak is real; egress_stats.rs:327-329 documents the strict shape ("On ANY failure — open, write (e.g. ENOSPC), or rename — remove the temp"), which is evidence for consolidation, not against it. No dependency cycle: a leaf `atomicfile` module under src/sandbox/mod.rs (which does list `cagedir` at :14 and `conncap` at :16) is imported by binds/flake/nixhub/prebuilt/notify_sink/audio/fonts and imports none of them. None of the deleted symbols appear in docs_coverage's UNDOCUMENTED_MODULE_ITEMS, and nothing enumerates the lock directories by temp name (the only `.tmp.` skip-by-name readers are egress.rs:2242 and egress_stats.rs:517/593/637, which are not touched).

</details>

---

### D17 — The `github:` release-asset pipeline is duplicated between deb.rs and appimage.rs, and has already diverged once

| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/sandbox/deb.rs:680` |
| **Autres sites** | src/sandbox/appimage.rs:152 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — modules sandbox |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** deb.rs:680-699: `fn github_asset_url(json, system, owner, repo) -> io::Result<String> { let url = prebuilt::select_release_asset(json, system, ".deb").ok_or_else(|| io::Error::other(format!("no linux {} `.deb` asset in the latest release of {owner}/{repo}", prebuilt::arch_label(system))))?; if !crate::config::is_valid_deb_url(&url, false) { return Err(io::Error::other(format!("the latest release of {owner}/{repo} selected an asset URL that is not a valid `https://` `.deb` URL: {url}"))); } Ok(url) }`. appimage.rs:152-171 is that same function with `".appimage"`, `` `.AppImage` `` and `is_valid_appimage_url`. The callers are duplicated too: deb.rs:131-133 `let api = format!("https://api.github.com/repos/{owner}/{repo}/releases/latest"); let json = super::nixhub::fetch_url_json(nix, layout, &api, fresh)?; github_asset_url(&json, system, &owner, &repo)?` against appimage.rs:132-134, byte-identical. So is the locator split: deb.rs:66-73 `if let Some(path) = locator.strip_prefix("github:") && let Some((owner, repo)) = path.split_once('/') { return DebSource::Github { owner: owner.to_string(), repo: repo.to_string() }; }` against appimage.rs:68-75, identical modulo the enum name. And the tests are twins: deb.rs:997 and appimage.rs:332 are both `fn a_github_release_asset_is_held_to_tls_whatever_the_launch_allows`. `prebuilt::Kind` already carries the only two things that differ — `artefact()` (deb.rs:769 `"`.deb`"`, appimage.rs:243 `"`.AppImage`"`) and `url_validator()` (deb.rs:773, appimage.rs:247).

**Coût.** This exact pair has already drifted twice and the tree records both. prebuilt.rs:487-489: "this ranking was fixed once for `deb:` and the `appimage:` copy did not receive the fix, so an AppImage repo publishing a same-arch feature variant selected the variant." appimage.rs:327-330: "this backend passed the launch's flag through instead, so the same asset was refused for one backend and accepted for the other." The selector was lifted into prebuilt after the first incident; the wrapper around it was not, so the second happened in the layer that was left behind.

**Correction proposée.** Add to src/sandbox/prebuilt.rs beside `select_release_asset`: `pub(crate) fn github_locator(locator: &str) -> Option<(&str, &str)>` (the `strip_prefix("github:")` + `split_once('/')` split) and `pub(crate) fn github_release_asset(nix: &Path, layout: &Layout, kind: &dyn Kind, ext: &str, owner: &str, repo: &str, system: &str, fresh: bool) -> io::Result<String>` doing the `api.github.com/repos/{owner}/{repo}/releases/latest` fetch via `nixhub::fetch_url_json`, then `select_release_asset(&json, system, ext)`, then `kind.url_validator()(&url, false)`, with `kind.artefact()` in both messages. Carry deb.rs:676-683's docstring about why `allow_insecure_http` deliberately does not reach here onto it, since that argument is the shared one. Delete both `github_asset_url` functions and both `api = format!` lines; deb::parse_source and appimage::parse_source keep their enums but build the `Github` arm from `prebuilt::github_locator`. Fold the two twin tests into one in prebuilt.rs looping over `[(&Deb as &dyn Kind, ".deb"), (&AppImage, ".appimage")]`. deb.rs's `apt:` arm, `resolve_apt_deb_url` and their tests stay put — that is genuinely this backend's own.

**Rectification du vérificateur.** Two refinements to the fix, not to the evidence. (1) The two tests are not twins in prose and folding them into one loop in prebuilt.rs loses content the tree deliberately carries: deb.rs:998-1000 and 1019-1020 argue the `apt:` contrast ("the seventh path the plaintext switch could have reached"), and appimage.rs:327-330 records this backend's own regression. Keep two thin per-backend tests calling the shared helper, or carry both comment blocks onto the folded one — otherwise the fix trades a duplication for a lost regression narrative, which is the same failure mode the claim is complaining about. (2) `ext` in the proposed signature is redundant: it is `format!(".{}", kind.name())` for both backends (prebuilt.rs:530, deb.rs:765-767, appimage.rs:239-241), so passing both `kind` and `ext` invites exactly the mismatch the consolidation is meant to prevent.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified end to end. deb.rs:680-699 and appimage.rs:152-171 are the same function modulo `".deb"`/`".appimage"`, the artefact spelling and `is_valid_deb_url`/`is_valid_appimage_url`. The callers match: deb.rs:131-133 against appimage.rs:132-134, byte-identical. The locator split matches: deb.rs:66-73 against appimage.rs:68-75, identical apart from the enum name (deb's extra `apt:` arm sits above at 61-65 and is untouched). Both tests exist under the same name, deb.rs:997 and appimage.rs:332. The two drift records are real and quoted correctly: prebuilt.rs:484-487 ("this ranking was fixed once for `deb:` and the `appimage:` copy did not receive the fix") and appimage.rs:327-330 ("this backend passed the launch's flag through instead"). `Kind::artefact` and `Kind::url_validator` do carry the two differing values (deb.rs:769-775, appimage.rs:243-249), and Kind::url_validator's own docstring (prebuilt.rs:540-544) explains the bool the shared helper would pass as `false`. A grep for `strip_prefix("github:")` confirms only these two backends plus config/mod.rs:4950 have the form, so the scope is exactly right, and prebuilt already owns Kind so passing `&dyn Kind` into it creates no cycle.

</details>

---

### D18 — Content-keyed staging (plus `unique()` and `content_hash()`) is written three times

| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/sandbox/fonts.rs:136` |
| **Autres sites** | src/sandbox/miseplugin.rs:37, src/sandbox/flake_inline.rs:22 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — modules sandbox |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** Three `stage` functions with the same body. fonts.rs:144-161: `let file = base.join(format!("{}.conf", content_hash(contents))); if file.is_file() { return Ok(file); } let tmp = base.join(format!(".tmp-{}-{}", std::process::id(), unique())); if let Err(e) = std::fs::write(&tmp, contents) { let _ = std::fs::remove_file(&tmp); return Err(e); } match std::fs::rename(&tmp, &file) { Ok(()) => Ok(file), Err(_) if file.is_file() => { let _ = std::fs::remove_file(&tmp); Ok(file) } Err(e) => { let _ = std::fs::remove_file(&tmp); Err(e) } }`. flake_inline.rs:26-51: `let dir = base.join(&hash); if dir.join("flake.nix").is_file() { return Ok((dir, hash)); } let tmp = base.join(format!(".tmp-{}-{}", std::process::id(), unique())); ... match std::fs::rename(&tmp, &dir) { Ok(()) => Ok((dir, hash)), Err(_) if dir.join("flake.nix").is_file() => { let _ = std::fs::remove_dir_all(&tmp); Ok((dir, hash)) } Err(e) => { let _ = std::fs::remove_dir_all(&tmp); Err(e) } }`. miseplugin.rs:41-63 is the same again with `dir.join("metadata.lua")` as the sentinel. Even the lost-race comment is copied — flake_inline.rs:42-43 `// Lost the race (another launch staged the identical flake first) or it already existed: / // discard the redundant temp and use the winner.` against fonts.rs:155-156 and miseplugin.rs:56-57. Below each sits a byte-identical helper: `fn unique() -> u64 { use std::sync::atomic::{AtomicU64, Ordering}; static SEQ: AtomicU64 = AtomicU64::new(0); SEQ.fetch_add(1, Ordering::Relaxed) }` at flake_inline.rs:70-74, fonts.rs:179-183 and miseplugin.rs:151-155 under near-identical docstrings; and `content_hash`, whose sha256-to-8-byte-hex tail (`let mut s = String::with_capacity(16); for b in &digest[..8] { s.push_str(&format!("{b:02x}")); } s`) is repeated at flake_inline.rs:61-65, fonts.rs:170-174 and miseplugin.rs:141-145.

**Coût.** Nine near-identical functions across three files for one rule, and each file's docstring already admits the copy — fonts.rs:137 "Content-keyed and atomic, like the staged mise plugin", flake_inline.rs:17 "Content-keyed and atomic like the staged fontconfig/mise plugin". All three stage material that is then bound into the cage, so a hardening of the shape has to be applied three times to be applied at all.

**Correction proposée.** Put them in the same new `src/sandbox/atomicfile.rs`: `pub(crate) fn short_hash(bytes: &[u8]) -> String` (sha256, first 8 bytes as hex), `pub(crate) fn unique() -> u64`, and `pub(crate) fn stage_keyed(base: &Path, name: &str, sentinel: Option<&str>, assemble: impl FnOnce(&Path) -> io::Result<()>) -> io::Result<PathBuf>` — creates `base`, returns early when `base/name` (or `base/name/<sentinel>`) exists, assembles into `base/.tmp-<pid>-<unique>`, renames, and on a rename error re-checks the sentinel before discarding the temp, removing it with `remove_dir_all` falling back to `remove_file` (the shape projectstore.rs:470-473's `discard` already uses). fonts::stage becomes `stage_keyed(&base, &format!("{}.conf", short_hash(contents.as_bytes())), None, |tmp| std::fs::write(tmp, contents))`; flake_inline::stage passes `Some("flake.nix")` and returns the hash alongside; miseplugin::stage passes `Some("metadata.lua")` and its existing `write_tree`. Delete all three `unique()` and the hex tail of all three `content_hash()`. miseplugin keeps its own domain digest — the length-prefixed walk over `PLUGIN_FILES` at miseplugin.rs:134-139 — and calls `short_hash` only for the formatting.

**Rectification du vérificateur.** The evidence is right in substance but several citations are wrong and the count is inflated. (1) fonts.rs:137 does not carry "Content-keyed and atomic, like the staged mise plugin" — that is fonts.rs:131; line 137 is `let base = data_dir.join("fontconfig")`. (2) The quoted fonts body starts at fonts.rs:139, not 144. (3) The lost-race comments are at fonts.rs:151-152 and miseplugin.rs:54-55, not 155-156 and 56-57 — and they are not "copied": each is reworded for its domain ("wrote the identical file" / "staged the identical flake first" / "placed the identical tree"). (4) "Nine near-identical functions" overstates: 3 stage functions that genuinely differ (a single file with no sentinel vs a directory with a sentinel, and fonts removes with `remove_file` where the other two use `remove_dir_all`), 3 identical `unique()`, and only 2 of the 3 `content_hash` bodies alike. (5) One behaviour delta the fix should state: miseplugin.rs:39-46 checks the sentinel BEFORE `create_dir_all(&base)`, so a warm launch never creates the base directory; the unified `stage_keyed` creates it first, as fonts.rs:138 and flake_inline.rs:24 already do.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The three stage functions are real and structurally the same: fonts.rs:136-162, flake_inline.rs:22-53, miseplugin.rs:37-65, each with the same `.tmp-<pid>-<unique()>` sibling, the same rename, and the same re-check-the-sentinel-on-rename-error arm. The three `unique()` bodies are byte-identical (flake_inline.rs:70-74, fonts.rs:179-183, miseplugin.rs:151-155). The hex tail of `content_hash` is repeated at flake_inline.rs:61-65, fonts.rs:170-174 and miseplugin.rs:141-145, and miseplugin's domain digest is the length-prefixed walk at miseplugin.rs:134-139 exactly as described. `projectstore.rs:470-473`'s `discard` is the remove_dir_all-then-remove_file shape the fix wants to reuse. The existing tests that assert no temp survives filter on the `.tmp-` prefix (fonts.rs:234, miseplugin.rs:221), which the proposed helper preserves, and no security seam is involved — all three stage material bound read-only into the cage, so one hardening point is strictly better.

</details>

---

### D19 — The seccomp-argv to netns-holder to cgroup-wrap chain is spelled out four times in launch.rs

| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/sandbox/launch.rs:5602` |
| **Autres sites** | src/sandbox/launch.rs:5632, src/sandbox/launch.rs:5754, src/sandbox/launch.rs:5786 |
| **Catégorie** | `abstraction-missing` |
| **Balayage** | Duplication — modules sandbox |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** Every path that turns a `SandboxSpec` into a runnable command repeats the same three steps. run_status (5602-5615): `let (argv, _seccomp) = match seccomp_argv(spec) {...}; // For a graphical isolated cage, route the launch through the netns holder so the namespace / // carries a `dummy0` interface (see `super::netns`); a no-op `(bwrap, argv)` otherwise. let (holder_prog, holder_argv) = super::netns::holder_wrap(bwrap, argv, spec.netns_dummy.as_ref()); let (prog, args) = super::cgroup::wrap(&holder_prog, holder_argv, limits, &spec.cage_slug);`. run_captured (5632-5640) repeats it including those two comment lines verbatim. exec (5754-5764) repeats it including those two comment lines verbatim a third time. supervise (5786-5792) repeats it with the comment paraphrased: `// Route a graphical isolated cage through the netns holder (dummy interface; see `super::netns`); / // a no-op passthrough otherwise.`. Only the error handling differs across the four — `eprintln!` + `return 1`, `return (1, format!(...))`, `return e`, and `?`.

**Coût.** The middle step is the load-bearing one: omit `holder_wrap` and a graphical isolated cage gets a namespace with no `dummy0`. Today it is a line a new launch path has to remember to copy. task.rs:1154-1155 and taskpool.rs:512-513 already do the two outer steps without it — correct only because a task cage never sets `netns_dummy`, which nothing in the code states.

**Correction proposée.** Add `fn cage_command(bwrap: &Path, spec: &SandboxSpec, limits: &super::cgroup::Limits) -> io::Result<(PathBuf, Vec<OsString>, Vec<File>)>` to launch.rs immediately after `seccomp_argv` (launch.rs:5723), returning the wrapped program, its argv, and the seccomp/env descriptors the caller must keep alive until the exec. Rewrite the four sites as `let (prog, args, _keep_open) = match cage_command(bwrap, spec, limits) { ... }`, each keeping its own error rendering. The `_keep_open` lifetime comment at launch.rs:5757-5758 moves onto the new function's docstring, which is where that invariant belongs. task.rs::exec and taskpool::run can then adopt it too: `holder_wrap` is a documented byte-for-byte passthrough when `netns_dummy` is `None` (netns.rs:396-402 tests exactly that), so nothing changes for them and the rule stops being per-caller knowledge.

**Rectification du vérificateur.** Three corrections. (1) The lifetime comment is at launch.rs:5758-5759, not 5757-5758, and it names `_seccomp` (exec's binding); `_keep_open` is supervise's name at 5786, and supervise carries its own lifetime paragraph at 5783-5785 — both would have to fold into the new docstring, not just one. (2) "nothing in the code states" the task-cage rule is overstated: spec.rs:210-213 already says "The launch path sets it only for a graphical (`gui = \"wayland\"`) cage under an isolated netns". (3) The tail of the fix is wrong for taskpool: taskpool.rs:513 wraps with the caller-supplied `slug` (parameter at 258/345, used at 282/353), while install_spec pins the spec's own slug to "task-pool" (taskpool.rs:433). A helper that reads `spec.cage_slug` would rename the install cage's systemd scope from `sbx-<session-slug>-<pid>.scope` to `sbx-task-pool-<pid>.scope` — an observable change, and a collision hazard between concurrent sessions. taskpool::run must keep its own two lines (or the helper needs an explicit slug parameter). task.rs:1155 uses `spec.cage_slug()` and can adopt it; for that the helper must be `pub(super)`, not private.

<details>
<summary>Preuve retenue par le vérificateur</summary>

All four sites verified. launch.rs:5602 (run_status, fn at 5601), 5632 (run_captured, fn at 5631), 5754 (exec, fn at 5745), 5786 (supervise, `let (bwrap_argv, _keep_open) = seccomp_argv(spec)?;`). The `holder_wrap` calls are at 5614/5639/5763/5790 and the `cgroup::wrap` calls follow each. The two-line comment is byte-identical at 5612-5613, 5637-5638, 5761-5762 and paraphrased at 5788-5789. Error handling is the only divergence, exactly as described. seccomp_argv is at launch.rs:5723; holder_wrap (netns.rs:46-61) and cgroup::wrap (cgroup.rs:338-344) both return `(PathBuf, Vec<OsString>)` and are infallible, so a helper returning `io::Result<(PathBuf, Vec<OsString>, Vec<File>)>` is exactly right and each caller keeps its own rendering. The netns.rs:396-401 passthrough test exists as claimed, and task specs really are built fresh via `SandboxSpec::new` (task.rs:1130-1136, spec.rs:206 `netns_dummy: None`), so task.rs:1154-1155 and taskpool.rs:512-513 are safe today by accident of construction. No comment anywhere marks the repetition as deliberate, and the extraction creates no cycle and opens no seam — argv::compose stays the pure Spec->argv keystone underneath.

</details>

---

### D20 — FrameTee copies every WebSocket payload piece into a fresh Vec, including the server->cage direction where frames are never masked

| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/sandbox/proxy/websocket.rs:583` |
| **Catégorie** | `allocation` |
| **Balayage** | Optimisation — chemin de données par octet |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** websocket.rs:581-588, inside the per-read framing walk:

            let take = self.payload_left.min((chunk.len() - at) as u64) as usize;
            if self.keeps || (self.control && self.scan.is_some()) {
                let mut piece = chunk[at..at + take].to_vec();
                if let Some(key) = self.mask {
                    for (n, byte) in piece.iter_mut().enumerate() {
                        *byte ^= key[(self.mask_at as usize + n) % 4];
                    }
                }

`piece` is then only read: `self.control_payload.extend_from_slice(&piece[..fits])` (websocket.rs:598), `self.pending.extend_from_slice(&piece)` (websocket.rs:614), or `self.consume(&piece)` (websocket.rs:616). The `to_vec()` exists solely so the unmask loop has somewhere to write — but RFC 6455 masks only client-to-server frames, so on the upstream->cage direction `self.mask` is always `None` and the allocation plus full memcpy is pure waste.

**Coût.** One malloc + free + a full copy of the payload slice per frame-piece, on both directions of every established WebSocket, whenever the launch has a capture sink or any configured secret (`FrameTee::new` returns `None` only when it has neither — websocket.rs:466). A 16 KiB read (websocket.rs:1119) carrying many small frames costs one allocation per frame; a large binary frame costs a full 16 KiB copy per read. The cage->upstream direction genuinely needs a mutable buffer; the upstream->cage direction — the one that carries a streaming agent response — needs none at all.

**Correction proposée.** Add a `piece: Vec<u8>` scratch field to `FrameTee` (websocket.rs:31-75, initialized `Vec::new()` at websocket.rs:469-485) and replace the block with a borrow for the unmasked case and a reused buffer for the masked one:

            let raw = &chunk[at..at + take];
            let mut scratch = std::mem::take(&mut self.piece);      // keeps its capacity
            let piece: &[u8] = match self.mask {
                None => raw,
                Some(key) => {
                    scratch.clear();
                    scratch.extend_from_slice(raw);
                    for (n, byte) in scratch.iter_mut().enumerate() {
                        *byte ^= key[(self.mask_at as usize + n) % 4];
                    }
                    &scratch
                }
            };

then use `piece` at the three existing sites and `self.piece = scratch;` before the `mask_at`/`payload_left` update at websocket.rs:622. `self.consume(&piece)` needs the `&mut self` borrow, so hoist the consume/pending/control decision to operate on a local `&[u8]` — `mem::take` is what frees `self` for that. Unmasked direction: zero allocations and zero copies; masked direction: one allocation for the tunnel's whole life.

**Rectification du vérificateur.** Survives, and this is the one of the four with a per-byte (not per-message) win — a full memcpy of every scanned/captured payload byte in both directions. Two corrections. (1) "the server->cage direction where frames are never masked" is the RFC 6455 rule, not an invariant this code enforces: `self.mask` comes straight from the frame header via `scan_frame_header` (websocket.rs:552, decoded at websocket.rs:750-ish), so a non-compliant upstream that sets the MASK bit would still take the masked path. The proposed `match self.mask` handles both, so the fix is right — but do not write a comment asserting the upstream never masks. (2) The fix as written leaks the scratch capacity on the `self.done = true; break;` at websocket.rs:611-612, which is reached before the proposed `self.piece = scratch;` at websocket.rs:622. Harmless (the tee is finished at that point) but the restore should sit at the end of the `if self.keeps || ..` block rather than after it, or the break should restore first.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Cited lines are exact. src/sandbox/proxy/websocket.rs:581-588 is verbatim the quoted block (`let take = ..` at 581, `let mut piece = chunk[at..at + take].to_vec();` at 583, the unmask loop at 584-588). `piece` is thereafter read-only at all three consumers: websocket.rs:598 `self.control_payload.extend_from_slice(&piece[..fits])`, websocket.rs:614 `self.pending.extend_from_slice(&piece)`, websocket.rs:616 `filled |= self.consume(&piece)` — plus the `.len()` reads at 597 and 605, which work unchanged on a slice. Nothing mutates `piece` after the unmask, so the `to_vec` exists only to give that loop a writable target. `FrameTee::new` returns `None` only when both consumers are absent (websocket.rs:465-468), the struct spans websocket.rs:31-75 and its initializer websocket.rs:469-485, and the relay buffer is `[0u8; 16 * 1024]` at websocket.rs:1119, pushed whole into `tee.push(chunk)` via `follow` at websocket.rs:1010. The `mem::take` dance is needed and sufficient: `self.consume(piece)` wants `&mut self`, and after the take the slice borrows either `chunk` (a parameter) or the local `scratch`, neither of which borrows `self`. No security property moves: the unmask still never writes through to the shared read buffer, and the scan/capture see the same bytes.

</details>

---

### D21 — relay_body_redacting copies every h2 DATA frame into a Vec even when the frame holds no needle

| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/sandbox/proxy/h2mitm.rs:823` |
| **Autres sites** | src/sandbox/proxy/h2mitm.rs:883 |
| **Catégorie** | `allocation` |
| **Balayage** | Optimisation — chemin de données par octet |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** h2mitm.rs:817-825, per DATA frame of an injection-target response:

        if let Some(cap) = &cap {
            cap.push(&chunk);
        }
        let mut buf = chunk.to_vec();
        redact_in_place(&mut buf, needles);
        let sent = send_masked(&mut dst, buf).await?;

`chunk` is a `Bytes`; the non-redacting twin `relay_body` (h2mitm.rs:728) hands the same `Bytes` straight to `send_granted`, which splits it with zero copy (`let piece = chunk.split_to(take);`, h2mitm.rs:700). So the `to_vec()` here is the entire extra cost of the masking path, and it is paid whether or not the frame contains a secret — which is the overwhelmingly common case, since the whole point of the backstop is that reflection is rare.

Same shape at h2mitm.rs:881-888, per response header and trailer value:

    fn redact_header_map(headers: &mut http::HeaderMap, needles: &[SecretNeedle]) {
        for value in headers.values_mut() {
            let mut bytes = value.as_bytes().to_vec();
            redact_in_place(&mut bytes, needles);
            if let Ok(v) = http::HeaderValue::from_bytes(&bytes) { *value = v; }

**Coût.** One malloc + full memcpy per DATA frame (h2 frames are typically 16 KiB) for every response from a credential-injected host on the HTTP/2 plane — which is exactly the traffic sbx is built to carry. A 10 MB gRPC/streaming response is ~640 allocations and 10 MB of copying that the identical unmasked path does not pay. `redact_header_map` adds one allocation per header value per such response, again almost always for a value with no match.

**Correction proposée.** Scan first, allocate only on a hit — the scan is the prebuilt `memmem::Finder` in `SecretNeedle::find_in` (inject.rs:468-473), so it costs a fraction of the copy it replaces:

        let sent = if needles.iter().any(|n| n.find_in(&chunk, 0).is_some()) {
            let mut buf = chunk.to_vec();
            redact_in_place(&mut buf, needles);
            send_masked(&mut dst, buf).await?
        } else {
            send_granted(&mut dst, chunk).await? == len
        };

(`send_masked` already returns `Ok(true)` for an empty frame; the `len == 0` case must keep taking the `send_granted` arm's `== len` comparison, which it does.) Apply the same guard in `redact_header_map`: `if needles.iter().any(|n| n.find_in(value.as_bytes(), 0).is_some())` before the `to_vec()`. Equal-length masking is unaffected, so the framing invariant the doc comment states is untouched.

**Rectification du vérificateur.** Two corrections to the reasoning, neither fatal. (1) "The scan costs a fraction of the copy it replaces" understates what is already paid: `redact_in_place` (src/sandbox/proxy/mod.rs:1659-1673) already runs the same N finder passes over the buffer today, so the guard does not replace a copy with a scan — it removes the malloc+memcpy and leaves the scan count unchanged on the no-match path (and adds one redundant partial pass on the rare match path). The saving is therefore the allocation and the 16 KiB memcpy, order 1-2 us per frame, a few percent of the TLS work on the same bytes — real and worth taking in a per-frame relay loop, but not a throughput cliff. (2) In `redact_header_map` the guard also skips the `HeaderValue::from_bytes` rebuild, which incidentally stops resetting each value's `is_sensitive` flag; on upstream response headers that flag is false anyway, so this is not observable, but it is a difference from today's unconditional rebuild rather than a pure no-op.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Sites are exact. /home/user/ops-cli/src/sandbox/proxy/h2mitm.rs:815-830 is the DATA loop, with 823-825 `let mut buf = chunk.to_vec(); redact_in_place(&mut buf, needles); let sent = send_masked(&mut dst, buf).await?;`. The unmasked twin at h2mitm.rs:722-734 hands the `Bytes` straight to `send_granted` (line 728), which consumes it zero-copy via `chunk.split_to(take)` (h2mitm.rs:700), so the `to_vec()` really is the whole extra cost of the masking arm. h2mitm.rs:881-888 is `redact_header_map` as quoted. The arm is selected only when `masks_reflection` (h2mitm.rs:580-587, 615-619) — an injection-target host — which is precisely the traffic this proxy exists to carry, so it is genuinely hot. I checked the proposed guard for behaviour and framing: `SecretNeedle::find_in` (src/sandbox/proxy/inject.rs:467-473) uses the same prebuilt finder `redact_in_place` uses (src/sandbox/proxy/mod.rs:1659-1673), so `any(..) == false` implies `redact_in_place` would have changed nothing; masking stays equal-length so the framing invariant documented at h2mitm.rs:805-808 is untouched; and the empty-frame case is safe — `find_in` declines (empty haystack, non-empty needle), the else arm calls `send_granted` whose `while !chunk.is_empty()` loop is skipped and returns `Ok(0)`, so `0 == len` keeps the loop going exactly as `send_masked`'s early `Ok(true)` did (h2mitm.rs:847-853, 686-704).

</details>

---

### D22 — gc::tree_usage has no subtree-aware form, so `sbx projects show` and `sbx app show` walk the same nix store twice

| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/sandbox/gc.rs:1143` |
| **Autres sites** | src/sandbox/projects.rs:296-298, src/cli/app.rs:1539-1540 |
| **Catégorie** | `redundant-io` |
| **Balayage** | Optimisation — lancement et entretien |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** gc.rs offers only a whole-tree walker:

  src/sandbox/gc.rs:1093  pub(crate) fn tree_usage(path: &Path) -> TreeUsage { ... accumulate_usage(path, &mut seen, &mut usage); ... }
  src/sandbox/gc.rs:1143  pub(crate) fn tree_size(path: &Path) -> u64 { tree_usage(path).bytes }

Both callers that want a breakdown therefore call it once for the root and again for children *inside* that root:

  src/sandbox/projects.rs:296  let total_bytes = super::gc::tree_size(&dir);
  src/sandbox/projects.rs:297  let store_bytes = super::gc::tree_size(&dir.join("store"));
  src/sandbox/projects.rs:298  let home_bytes  = super::gc::tree_size(&dir.join("home"));

  src/cli/app.rs:1538  let app_dir = h.dir.parent().unwrap_or(&h.dir);
  src/cli/app.rs:1539  let bytes = sandbox::tree_size(app_dir);
  src/cli/app.rs:1540  let tools_bytes = sandbox::tree_size(&h.dir.join(".local/share/mise"));

`dir` contains `store` and `home`; `app_dir` contains `home/.local/share/mise` (inspect.rs:148-149 documents `AppHome::dir` as "the home directory itself (`.../home`), the parent of the mise data dir"). Each nested call re-walks a tree the first call already visited, and the per-call hardlink `seen` set (gc.rs:1102) is thrown away between calls so nothing is shared.

**Coût.** `<data>/projects/<id>/store` is a seeded nix store (the base userland closure plus every provisioned tool) and `home` holds mise installs — together commonly 10^4 to 10^5 inodes. The three calls visit ~2x the minimum: one extra `lstat` per file plus one extra `getdents64` batch per directory in `store` and `home`. On a 100k-inode project tree that is ~100k avoidable `lstat` syscalls per `sbx projects show`, and the same doubling of the mise data dir per home per `sbx app show`.

**Correction proposée.** Add beside tree_usage in gc.rs: `pub(crate) fn tree_usage_parts(root: &Path, parts: &[&str]) -> (TreeUsage, Vec<TreeUsage>)`. It lstats `root` itself, then for each `parts[i]` walks `root.join(parts[i])` into its own TreeUsage, then walks `root`'s remaining children skipping the named ones — all sharing one `seen: HashSet<(dev, ino)>` so the hardlink semantics tree_usage documents are unchanged. Keep `tree_usage`/`tree_size` (nine other callers want the whole tree). Then: projects.rs:296-298 becomes `let (total, parts) = super::gc::tree_usage_parts(&dir, &["store", "home"]);` with total_bytes/store_bytes/home_bytes read off it (`other_bytes` at 299-301 keeps its saturating_sub); app.rs:1539-1540 becomes `let (whole, parts) = sandbox::tree_usage_parts(app_dir, &["home/.local/share/mise"]);` — guard the `parent()` fallback at 1538, since when `app_dir == h.dir` the relative path is `.local/share/mise`. Export `tree_usage_parts` from src/sandbox/mod.rs:139 next to `tree_size, tree_usage`.

**Rectification du vérificateur.** Real, but overstated on two counts. (1) Severity: `sbx projects show` and `sbx app show` are one-shot human-invoked report commands, not a hot path — neither runs per request, and each already does several other tree reads beside these (inspect::gcroot_names, nix_tools_locked, mise_installed, nixpkgs_pin at projects.rs:305-315). The doubling is user-perceptible on a large seeded store but it is latency on an inspection verb, not 'high'. (2) The fix is more than a wrapper: `home/.local/share/mise` is four levels below `app_dir`, not a top-level child, so `accumulate_usage` (gc.rs:1097-1139) itself has to gain a skip parameter and compare each recursed child against the excluded paths — the claim's 'walks root's remaining children skipping the named ones' glosses over that. Also note the numbers change slightly (for the better): today `other_bytes` is `total - store - home` with three independent hardlink sets and a saturating floor, whereas a shared `seen` makes the remainder exact. Harmless under the gc.rs:1084-1087 invariant, but it is a behaviour delta and the existing test at gc.rs:1415-1435 only pins the per-call semantics, so the new helper needs its own test.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every site checks out. src/sandbox/gc.rs:1093 is the only walker (`pub(crate) fn tree_usage(path: &Path) -> TreeUsage`), its `seen` set is created per call at gc.rs:1102 and dropped at return, and src/sandbox/gc.rs:1143-1144 is `tree_size` delegating to it. src/sandbox/projects.rs:296-298 are exactly the three `tree_size` calls on `dir`, `dir.join("store")` and `dir.join("home")`, with the `saturating_sub` at 299-301. src/cli/app.rs:1538-1540 are `let app_dir = h.dir.parent().unwrap_or(&h.dir);` / `tree_size(app_dir)` / `tree_size(&h.dir.join(".local/share/mise"))`, and src/sandbox/inspect.rs:148-149 does document `AppHome::dir` as "The home directory itself (`.../home`), the parent of the mise data dir", so the second path is nested in the first. src/sandbox/mod.rs:139-141 exports `tree_size, tree_usage` where the new helper would go, and grep confirms no subtree-aware variant exists anywhere (the other callers at gc.rs:516/528/612/688/781/803/882, projects.rs:175 and cli/store.rs:128 all want a whole tree). Sharing one `seen` across the parts is consistent with the documented invariant at gc.rs:1084-1087 ("sbx's trees never share inodes with one another").

</details>

---

### D23 — The bind canonicalise / control-plane / dedup / nest-warn pipeline is written twice in config/load.rs

| | |
|---|---|
| **Gravité** | Moyenne |
| **Emplacement** | `src/config/load.rs:144` |
| **Autres sites** | src/config/load.rs:238-266 |
| **Catégorie** | `duplication` |
| **Balayage** | Optimisation — lancement et entretien |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** `load_scoped` inlines the pipeline for the baseline binds:

  src/config/load.rs:144  let mut canon_binds: Vec<Bind> = Vec::with_capacity(declared.len());
  src/config/load.rs:146  for bind in declared {
  src/config/load.rs:147      let Some(canon) = canonicalize_one(&bind.path, &mut resolved.warnings) else { continue; };
  src/config/load.rs:154      let writable = control_plane_mode(canon.as_path(), bind.writable, &sbx_roots, &mut resolved.warnings);
  src/config/load.rs:160      if let Some(layer) = raw_layer.get(&bind.path) { canon_layer.insert(canon.clone(), *layer); }
  src/config/load.rs:166      if let Some(existing) = canon_binds.iter_mut().find(|b| b.path == canon) { existing.writable = writable; }
  src/config/load.rs:169      else { canon_binds.push(Bind { path: canon, writable }); }
  src/config/load.rs:183  for bind in &canon_binds { if let Some(w) = crate::sandbox::structural_nesting_warning(&bind.path, bind.writable, project.as_deref()) { resolved.warnings.push(w); } }

and `canonicalize_binds`, called just below for each app, is the same algorithm again:

  src/config/load.rs:244  let mut out: Vec<Bind> = Vec::with_capacity(binds.len());
  src/config/load.rs:245  for bind in binds {
  src/config/load.rs:246      let Some(canon) = canonicalize_one(&bind.path, warnings) else { continue; };
  src/config/load.rs:249      let writable = control_plane_mode(canon.as_path(), bind.writable, roots, warnings);
  src/config/load.rs:250      if let Some(existing) = out.iter_mut().find(|b| b.path == canon) { existing.writable = writable; }
  src/config/load.rs:253      else { out.push(Bind { path: canon, writable }); }
  src/config/load.rs:259  for bind in &out { if let Some(w) = crate::sandbox::structural_nesting_warning(&bind.path, bind.writable, project) { warnings.push(w); } }

The only difference is the `bind_layer` re-keying at lines 160-162 — three lines the app path does not need.

**Coût.** Two copies of a security-relevant fold: control-plane read-only forcing, last-declaration-wins dedup, structural-nesting warning. A change to how a bind overlapping sbx's control plane is treated must land in both, and the app overlay silently keeps the old rule if only one is edited — exactly the divergence canonicalize_binds's own doc promises will not happen ("The same treatment the baseline binds get, so an app overlay advertises exactly what its launch would mount").

**Correction proposée.** Give `canonicalize_binds` (load.rs:238) one extra parameter and delete the inline copy: `layer: Option<(&BTreeMap<PathBuf, Provenance>, &mut BTreeMap<PathBuf, Provenance>)>`. Inside the loop, after `control_plane_mode`, add `if let Some((raw, canon_map)) = layer.as_mut() { if let Some(l) = raw.get(&bind.path) { canon_map.insert(canon.clone(), *l); } }`. In `load_scoped`, move `let project = cwd.canonicalize().ok();` (currently load.rs:181) up to just after `let sbx_roots = sbx_control_plane_roots();` (load.rs:141), then replace lines 144-190 with one call passing `Some((&raw_layer, &mut canon_layer))`; the per-app loop passes `None`. No symbol moves, so no rustdoc intra-doc link and no docs_coverage entry changes.

**Rectification du vérificateur.** Two mechanical corrections. (1) There is a third caller the fix does not mention: src/config/mod.rs:1005 calls `canonicalize_binds(resolved_binds, &roots, None, &mut self.warnings)` for `--bind` overrides (and does its own `bind_layer` insert at 1006-1007), so it must also gain the new argument. Its presence actually strengthens the claim — the shared helper is already the norm and load_scoped's inline copy is the outlier. (2) Do not use the proposed parameter type. `Option<(&BTreeMap<PathBuf, Provenance>, &mut BTreeMap<PathBuf, Provenance>)>` sits right at clippy's default `type_complexity` threshold of 250; there is no clippy.toml in the repo to raise it, and the lint is demonstrably live (`#[allow(clippy::type_complexity)]` is already needed at src/config/tests.rs:10589 and :10693), so under `-D warnings` this is a coin flip. Pass two plain parameters instead — `raw_layer: Option<&BTreeMap<PathBuf, Provenance>>` and `canon_layer: Option<&mut BTreeMap<PathBuf, Provenance>>` — which scores far below the threshold and reads better at the three call sites.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every line number is exact. src/config/load.rs:144-146 (`canon_binds` alloc, `canon_layer`, `for bind in declared`), 147 canonicalize_one, 154-159 control_plane_mode, 160-162 the bind_layer re-key, 166-173 the last-wins dedup, 181 `let project = cwd.canonicalize().ok();`, 182-190 the structural_nesting_warning loop. And canonicalize_binds at 238-267 is the same fold: 244 alloc, 245 loop, 246 canonicalize_one, 249 control_plane_mode, 250-257 dedup, 259-265 nesting warnings. The only delta is the three-line layer re-key, exactly as claimed. This is not the codebase's deliberate-restatement pattern: the doc at load.rs:232-237 asserts the two must be identical ('The same treatment the baseline binds get, so an app overlay advertises exactly what its launch would mount'), which is the argument for folding them, not against. The move of line 181 is safe — the outer `project` binding is consumed at load.rs:121, so shadowing it at ~142 is unambiguous, and nothing between 142 and 181 reads it.

</details>

---

### D24 — UpstreamPool::checkout holds the single pool mutex across up to 12 socket syscalls per request

| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/proxy/pool.rs:110` |
| **Autres sites** | src/sandbox/proxy/pool.rs:161 (sweep, called under the same guard), src/sandbox/proxy/mod.rs:798 (the per-request call site) |
| **Catégorie** | `lock-scope` |
| **Balayage** | Tri des signaux clippy stricts |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** pool.rs:109-119 does every probe inside the guard:

    pub(super) fn checkout(&self, key: &PoolKey) -> Option<UpstreamTls> {
        let mut idle = self.idle.lock().ok()?;          // 110
        Self::sweep(&mut idle, self.max_idle);          // 111
        let slot = idle.get_mut(key)?;                  // 112
        while let Some(parked) = slot.pop() {           // 113
            if still_live(&parked.stream.sock) {        // 114
                return Some(parked.stream);            // 115

`still_live` (pool.rs:184-195) is three syscalls per candidate:

    if sock.set_nonblocking(true).is_err() { return false; }
    let live = matches!(sock.peek(&mut one), Err(e) if e.kind() == io::ErrorKind::WouldBlock);
    sock.set_nonblocking(false).is_ok() && live

and the loop probes up to `MAX_PER_KEY = 4` (pool.rs:47) candidates. `sweep` (pool.rs:161-168) additionally `retain`s over every key and drops each expired `Parked`, and dropping one closes its TCP socket — a `close(2)` apiece, also under the guard. The sibling `park` (pool.rs:132-153) is careful to run its own probe (`is_quiet`) *before* taking the lock at 138; `checkout` is the one that does not.

**Coût.** `self.idle` is one Mutex shared by every proxy connection thread of a launch. `checkout` runs once per proxied request that can reuse a connection (proxy/mod.rs:797-799 in `acquire_upstream`) and `park` takes the same lock at the end of every relayed response (forward.rs:606, tunnel.rs:898), so on a keep-alive-heavy workload every request serialises behind up to twelve `fcntl`/`recv` syscalls plus one `close` per expired entry. It is microseconds, not a correctness bug — but it is the only one of the 19 significant-Drop hits where the guard actually spans syscalls, which is what that lint was asked to find.

**Correction proposée.** Keep the pool contents identical and move only the syscalls out: replace the `while let` at 113-118 with a loop of short lock scopes — `loop { let parked = { let mut idle = self.idle.lock().ok()?; Self::sweep(&mut idle, self.max_idle); idle.get_mut(key)?.pop()? }; if still_live(&parked.stream.sock) { return Some(parked.stream); } }` — so the guard is dropped before `still_live` runs and before the dead `parked` is dropped/closed. `sweep` stays inside (it is a map walk, and the drops it performs are the price of the sweep), or hoist it to the first iteration only. No signature, doc-link or docs-coverage surface changes.

**Rectification du vérificateur.** Correct in substance, imprecise in three places. (1) Line citations drift onto doc comments: `MAX_PER_KEY = 4` is pool.rs:48 (47 is its doc line), `sweep`'s body is 162-168 (156-161 is its doc), `park` takes the lock at 139 not 138 (136 is the pre-lock `is_quiet` probe), and `still_live` ends at 193 not 195. (2) The cost is overstated by the worst case: the loop returns on the first live candidate, so the typical checkout is one probe — three syscalls (`set_nonblocking` is ioctl(FIONBIO) on Linux, not fcntl) — and twelve only when four consecutive parked entries are dead. (3) The fix as literally written re-runs `Self::sweep` on every loop turn, i.e. up to four full walks of a <=64-entry map under the guard, with the expiry closes it performs still inside the lock on the first turn; the sweep should be hoisted to run once before the first pop, with later turns doing only lock/pop. With that adjustment the change is sound: no signature, no doc-link, no docs-coverage surface, and no observable behaviour change.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every cited site checks out. src/sandbox/proxy/pool.rs:109-119 is verbatim as quoted: the guard is taken at 110, `Self::sweep` at 111, `idle.get_mut(key)?` at 112, and the `while let Some(parked) = slot.pop()` / `still_live(&parked.stream.sock)` probe at 113-117 all run inside that guard, so a candidate that fails the probe is also dropped (closed) under it. `still_live` is src/sandbox/proxy/pool.rs:184-193 and is three socket calls per candidate (set_nonblocking true / peek / set_nonblocking false). `sweep` (body at 162-168) retains over every key and drops each expired `Parked`, i.e. a close(2) apiece, also under the guard. The contrast with `park` is real: `park` runs `is_quiet` at 136 and only then locks at 139. Call sites confirmed: `pool.checkout(key)` at src/sandbox/proxy/mod.rs:798 inside `acquire_upstream` (declared at 790), reached per request from src/sandbox/proxy/forward.rs:320 and src/sandbox/proxy/tunnel.rs:496; `pool.park(...)` at src/sandbox/proxy/forward.rs:606 and src/sandbox/proxy/tunnel.rs:898. The path is live in the default posture: the pool is built at src/sandbox/proxy/ctx.rs:217 and src/config/tests.rs:1450 asserts "reuse is the default posture". Clippy does flag exactly this site (clippy-signal.txt:102, `pool.rs:110:17`), and I spot-checked three of the other 18 significant-Drop hits (src/sandbox/locks.rs:70 is a test fixture, src/sandbox/proxy/capture.rs:90 and src/sandbox/lens.rs:149/164 are pure in-memory Vec/VecDeque work), consistent with the claim that this is the only one whose guard spans syscalls. Nothing in the module doc (pool.rs:1-33) or the checkout doc (103-108) requires the probe to happen under the lock, and popping under the guard still gives each thread exclusive ownership of the candidate it probes, so the proposed short-scope loop is behaviour-preserving and touches no doc or completion surface.

</details>

---

### D25 — `parse_log_args` re-implements `interval_seconds`, which the same file already imports

| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/net.rs:1309` |
| **Autres sites** | src/main.rs:251-263 (the helper), src/cli/net.rs:22 (already imported), src/cli/net.rs:234, src/cli/net.rs:320, src/cli/proc.rs:693 (the three correct call sites) |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — verbes CLI |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** main.rs:251-263 is the shared helper, with a doc comment that states the reason: "Shared for the three refusals it carries rather than for its length — a message the user reads, written out once per call site, is a message that drifts between them." Three parsers call it — net.rs:234 and net.rs:320 (`Some("-i") | Some("--interval") => interval_secs = interval_seconds(it.next())?,`) and proc.rs:693. net.rs:1309-1321, in the same file that imports it at line 22, inlines the whole body instead: `Some("-i") | Some("--interval") => { let val = it.next().ok_or("`--interval` needs a value in seconds")?; let secs: u64 = val.to_str().and_then(|s| s.parse().ok()).ok_or_else(|| { format!("invalid interval `{}` — expected a whole number of seconds", val.to_string_lossy()) })?; if secs == 0 { return Err("interval must be at least 1 second".into()); } v.interval_secs = secs; }` — all three messages identical to main.rs:252, 254-257 and 259. Nearby, `parse_watch_args` (net.rs:228-250) and `parse_live_args` (net.rs:313-333) are themselves near-identical: same `-i/--interval` arm, same `-a/--app` arm (`let name = it.next().ok_or("`--app` needs an app name")?; app = Some(name.to_string_lossy().into_owned());` — repeated a third time at net.rs:1322-1325), differing only in the default interval (2 vs 1), a `--json` arm, and the synopsis path.

**Coût.** The one thing the shared helper exists to prevent — three user-facing interval messages drifting — is 13 lines from happening, in the file that already imports the helper. The fix is a one-line substitution with zero behavioural change.

**Correction proposée.** Replace net.rs:1309-1321 with `Some("-i") | Some("--interval") => v.interval_secs = interval_seconds(it.next())?,` — the three error strings and the zero check are byte-identical to main.rs:251-263, so the existing tests at net.rs:4286-4291 still pass unchanged. Optionally also lift the thrice-copied `--app` arm into `fn app_name(next: Option<&OsString>) -> Result<String, String>` next to `interval_seconds` in main.rs and use it at net.rs:236-239, 322-325, 1322-1325.

**Rectification du vérificateur.** Two corrections, neither material to the primary fix. (1) Line-number nit inside the helper: the zero guard is main.rs:259-261 (the message string is on 260), not 259. (2) The optional half of the fix — lifting `--app` into a shared `app_name` — is weaker than presented, because the `--app` sites come in two incompatible shapes. The Result-shaped ones (net.rs:236-239, 322-325, 1323-1326, plus a fourth already at main.rs:169-172) could share one helper; but net.rs:154-156, 1097-1099 and 2130 are inside `ExitCode`-returning parsers that call `diag::error` and `return ExitCode::from(2)` directly, and two of them carry a different prefix ("sbx: net stats: `--app` needs an app name"). A single helper cannot serve both shapes without the flag argument that makes it worse, so scope that half to the four Result-shaped call sites or drop it. The one-line substitution at net.rs:1309-1321 stands on its own.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every cite is exact. src/main.rs:248-263 is the helper, and its doc comment at 248-250 reads verbatim "Shared for the three refusals it carries rather than for its length — a message the user reads, written out once per call site, is a message that drifts between them." src/cli/net.rs:22 imports `interval_seconds` from the crate root; net.rs:234 and net.rs:320 are `Some("-i") | Some("--interval") => interval_secs = interval_seconds(it.next())?,` and src/cli/proc.rs:693 is the same line (imported at proc.rs:16). net.rs:1309-1321, inside `parse_log_args` (declared net.rs:1291), inlines the body: the message at 1310 ("`--interval` needs a value in seconds"), the `format!("invalid interval `{}` — expected a whole number of seconds", ...)` at 1312-1315, and the zero guard at 1317-1319 — byte-identical to main.rs:252, 254-257 and 260. `parse_log_args` returns `Result<LogView, String>` and `interval_seconds` returns `Result<u64, String>`, so `v.interval_secs = interval_seconds(it.next())?` compiles and is behaviour-identical; the tests at net.rs:4290-4297 (`-i 0` errors, `-i soon` errors containing "soon", bare `-i` errors, default 1s) all still hold. No comment anywhere justifies the inline copy as deliberate. The adjacent parsers are as described: parse_watch_args at net.rs:228-250 and parse_live_args at net.rs:313-333 differ only in default interval (2 vs 1), the `--json` arm, and the synopsis path.

</details>

---

### D26 — Seven `--json` output blocks, four different wordings for "cannot serialize"

| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/cli/config.rs:186` |
| **Autres sites** | src/cli/config.rs:225, src/cli/app.rs:1417, src/cli/store.rs:104, src/cli/task.rs:737, src/cli/task.rs:1037, src/cli/storage.rs:788 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — verbes CLI |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** Every `--json` verb ends in the same `to_string_pretty` → print-or-fail block, and no two agree on the failure text. config.rs:186-192: `match serde_json::to_string_pretty(&view) { Ok(doc) => println!("{doc}"), Err(e) => { diag::error(&format!("sbx: cannot serialize the configuration: {e}")); return ExitCode::FAILURE; } }`. config.rs:225-231 is the same block with `"sbx: cannot serialize the app configuration: {e}"`. app.rs:1417-1426: `return match serde_json::to_string_pretty(&view) { Ok(doc) => { println!("{doc}"); ExitCode::SUCCESS } Err(e) => { diag::error(&format!("sbx: app show: cannot serialize: {e}")); ExitCode::FAILURE } };`. store.rs:104-113 is the same shape with `"sbx store: failed to serialize: {e}"`. task.rs:1037-1043 uses `"sbx: task run: failed to serialize: {e}"`, task.rs:737-746 repeats that string, and storage.rs:788-791 routes it through its own `fail(e)` helper instead: `match serde_json::to_string_pretty(&view) { Ok(s) => println!("{s}"), Err(e) => return fail(e), }`.

**Coût.** One condition, four wordings (`cannot serialize` / `cannot serialize the configuration` / `failed to serialize` / storage's `fail`), and two prefix conventions (`sbx:` vs `sbx store:`). Every new `--json` verb copies whichever neighbour it was written next to, so the set grows. The block is 8-10 lines each in seven handlers.

**Correction proposée.** Add to src/cli/mod.rs, beside the other cross-family CLI helpers: `pub(crate) fn print_json<T: serde::Serialize>(verb: &str, view: &T) -> Result<(), ExitCode> { match serde_json::to_string_pretty(view) { Ok(doc) => { println!("{doc}"); Ok(()) } Err(e) => { diag::error(&format!("sbx: {verb}: cannot serialize: {e}")); Err(ExitCode::FAILURE) } } }`. Use it at config.rs:186 (`"config"`), config.rs:225 (`"config show --app"`), app.rs:1417 (`"app show"`), store.rs:104 (`"store"`) and storage.rs:788 (`"storage status"`), each becoming `if let Err(c) = crate::cli::print_json(verb, &view) { return c; }` followed by the verb's own success code. Leave the two task.rs sites' *exit codes* alone — task.rs:737-744 and task.rs:1040-1046 map `result.error` to `REFUSED_EXIT` and `result.exit` respectively, which is genuine per-verb logic; only the serialize-failure arm moves into the helper. Settling on one prefix is the point: pick `sbx: {verb}: cannot serialize`, and check integration tests for the four superseded strings.

**Rectification du vérificateur.** Overstated on impact, sound on mechanics. The serialize-failure arm is close to unreachable for these views — `serde_json::to_string_pretty` on plain derived structs of strings, integers and bools fails only on a non-string map key, a non-finite float, or a custom Serialize that errors — so the four wordings are inconsistency in dead branches, not user-visible drift. The value here is ~40 lines of boilerplate and one convention, not a bug. Two caveats to the fix as written. (a) storage.rs:790 currently goes through `fail`, whose prefix is "sbx storage:"; routing it to the helper's "sbx: storage status:" makes that one line the odd one out among storage.rs's other 41 `fail` call sites. Either accept that, or leave storage.rs alone and take the other four. (b) The sweep's remit stopped at src/cli, but the same block appears three more times outside it — src/sandbox/projects.rs:433-441 ("sbx projects show: failed to serialize"), projects.rs:562-570 ("sbx projects: failed to serialize") and src/main.rs:299-307, which uses a bare `eprintln!` rather than `diag::error`. A helper placed in src/cli/mod.rs cannot serve the sandbox ones cleanly; if the goal is one wording, put it at the crate root instead.

<details>
<summary>Preuve retenue par le vérificateur</summary>

All seven cites are exact, and `grep -n to_string_pretty src/cli/*.rs` returns exactly those seven and no others, so the enumeration is complete for the sweep's remit. config.rs:186-192 with "sbx: cannot serialize the configuration: {e}" at 189; config.rs:225-231 with "sbx: cannot serialize the app configuration: {e}" at 228; app.rs:1417-1426 with "sbx: app show: cannot serialize: {e}" at 1423; store.rs:104-113 with "sbx store: failed to serialize: {e}" at 110; task.rs:737-749 with "sbx: task run: failed to serialize: {e}" at 746; task.rs:1037-1043 with the same string at 1040; storage.rs:788-791 routing through `fail(e)`, which is storage.rs:135-138 and prints "sbx storage: {msg}". The per-verb exit-code logic the fix says to leave alone is real and correctly located: task.rs:740-743 maps `result.error` to REFUSED_EXIT/SUCCESS, task.rs:1044-1046 to REFUSED_EXIT/`result.exit.clamp(0,255)`. Nothing asserts these strings — grep over tests/ and docs/ finds no occurrence — so consolidating the wording breaks no test. src/cli/mod.rs already hosts exactly this class of cross-family helper (`reject_extra` at mod.rs:38, `OneName` at mod.rs:61), and every affected module already imports `diag`, so the extraction creates no cycle and opens no seam. The prefix choice the fix proposes is the one diag.rs's own unit test treats as canonical ("sbx: store: unknown argument `--bogus`", diag.rs:123-128), and store.rs is already self-inconsistent about it ("sbx: store:" at 86 and 91 vs "sbx store:" at 97 and 110), as is storage.rs ("sbx: storage:" at 86 vs `fail`'s "sbx storage:").

</details>

---

### D27 — Three independent lowercase-hex encoders, and two hand-rolled digest-vs-recorded-hash comparisons

| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/trust.rs:36` |
| **Autres sites** | src/plugins/catalogue.rs:329, src/store.rs:2013, src/plugins/catalogue.rs:277, src/plugins/mod.rs:1548 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — config, plugins, store, trust |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** Three modules each carry their own byte-to-lowercase-hex loop, and the strings they produce are compared against records the others write.

`trust::hash_bytes`, src/trust.rs:36-43:
```rust
pub(crate) fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest { let _ = write!(out, "{b:02x}"); }
    out
}
```
`plugins::catalogue::to_hex`, src/plugins/catalogue.rs:329-336:
```rust
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes { let _ = write!(out, "{b:02x}"); }
    out
}
```
`store::expr_digest`, src/store.rs:2013-2018:
```rust
fn expr_digest(expr: &str) -> String {
    Sha256::digest(expr.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}
```
The "hash a tree, hex it, compare to a recorded string" step is likewise written twice. `catalogue::verify_entry`, src/plugins/catalogue.rs:277-278:
```rust
    let got = to_hex(&dir_digest(root)?);
    if got == entry.sha256 {
```
`plugins::integrity`, src/plugins/mod.rs:1546-1549:
```rust
    match catalogue::dir_digest(&layout.plugins_dir().join(dir_name)) {
        Err(why) => Integrity::Unreadable(why),
        Ok(digest) if catalogue::to_hex(&digest) == recorded => Integrity::Intact,
```
(`catalogue::validate_sha256`, src/plugins/catalogue.rs:312-324, exists precisely to assert the encoding these must agree on — but it guards only the catalogue's field, not the other two producers.)

**Coût.** `to_hex`'s output is what the origin record holds and what `install`/`upgrade` re-derive; `hash_bytes`' output is what a trust marker holds; `expr_digest`'s is what an `.expr` stamp holds. Nothing in the code ties the three encodings together, so a change to any one (uppercase, a `0x` prefix, a truncation) silently invalidates every stored record of that kind rather than failing to compile. Three copies also means three places a `format!` allocation per byte lives on.

**Correction proposée.** Move `to_hex` and its inverse `decode_hex` (src/plugins/catalogue.rs:405) into a new `src/hex.rs` declared in `src/main.rs` beside `mod help;`, with `pub(crate) fn to_hex(bytes: &[u8]) -> String` and `pub(crate) fn decode_hex(s: &str) -> Result<Vec<u8>, String>` carrying their existing bodies and doc comments. Then: `trust::hash_bytes` becomes `crate::hex::to_hex(&Sha256::digest(bytes))`; `store::expr_digest` becomes `crate::hex::to_hex(&Sha256::digest(expr.as_bytes()))`; the ~14 `crate::plugins::catalogue::to_hex`/`decode_hex` references in `src/plugins/stores.rs` (lines 246-247, 417-418, 480, 486, 958-959, 1115, 1176, 1212) and `src/plugins/mod.rs:1548` are re-pointed. Carry the intra-doc links with the symbols, per CLAUDE.md: `src/plugins/catalogue.rs:311` and `:328` say ``[`to_hex`]`` and ``[`decode_hex`]`` and must become ``[`crate::hex::to_hex`]``/``[`crate::hex::decode_hex`]`` or `mise run rustdoc` fails. Optionally add `pub(crate) fn digest_hex_of_dir(root: &Path) -> Result<String, String>` in `catalogue` so `verify_entry` and `integrity` share the hash-then-hex step.

**Rectification du vérificateur.** The finding is real but the risk story is invented and the migration list is materially incomplete; it is a tidiness item, not a medium. (1) "The strings they produce are compared against records the others write" is false, and the claim's own impact paragraph contradicts it: each encoder feeds only records its own subsystem writes (trust marker / `.expr` stamp / catalogue+origin digest). They are three self-consistent domains that never meet, so there is no cross-drift hazard — unifying them actually widens the blast radius of a future change rather than narrowing it. (2) "Three places a `format!` allocation per byte lives on" is wrong for two of the three: trust.rs:38-41 and catalogue.rs:331-334 both `write!` into a `String::with_capacity(n*2)`, no per-byte allocation. Only store.rs:2015-2017's `.map(|b| format!("{b:02x}")).collect()` allocates per byte, and `expr_digest` runs once per provisioning build, not per byte or per request. (3) The count is short and the fix's re-point list is short. There is a fourth pair — `session::to_hex`/`from_hex` at src/session.rs:756-764 and :768+, a table-based encoder, used at src/session.rs:658 — which the claim does not mention. And `catalogue::to_hex` is referenced far outside the claimed ~15 sites: src/sandbox/broker.rs:43,119,248; src/sandbox/deb.rs:256,262,263,275,277; src/sandbox/openpgp/mod.rs:31; src/cli/plugins.rs:885,1000,1074,1236,1417,1422,1436,1437; plus test modules in stores.rs (1253, 1347, 1357, 1379, 1582, 2121-2122, 2339, 2343). Following the fix as written breaks the build. The cheap correct form is to put the bodies in `src/hex.rs` and leave `pub(crate) use crate::hex::{to_hex, decode_hex};` in `catalogue`, which also keeps the two intra-doc links resolving with no rustdoc edit at all.

<details>
<summary>Preuve retenue par le vérificateur</summary>

The three bodies exist verbatim at the cited lines: `trust::hash_bytes` src/trust.rs:36-43, `catalogue::to_hex` src/plugins/catalogue.rs:329-336, `store::expr_digest` src/store.rs:2013-2018 (spelled over four lines, semantics as quoted). The two digest-vs-recorded comparisons are at src/plugins/catalogue.rs:277-278 and src/plugins/mod.rs:1546-1549, and `validate_sha256` is at :312-324 with its doc at :311 referencing ``[`to_hex`]``. The intra-doc links the fix must carry are real and are exactly the two named: catalogue.rs:311 ``[`to_hex`]`` and catalogue.rs:328 ``[`decode_hex`]`` (grep across src/ finds no others). A shared `src/hex.rs` under `mod help;` in src/main.rs:25 introduces no cycle — trust.rs and store.rs would stop needing nothing new, and neither currently depends on `plugins`. So the duplication is real and unifiable.

</details>

---

### D28 — The `SecretView` projection is written out three times in config/view.rs

| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/config/view.rs:1100` |
| **Autres sites** | src/config/view.rs:1543, src/config/view.rs:1862 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — config, plugins, store, trust |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** The same four-field mapping from `HeaderSecret` to `SecretView` appears three times.

Baseline view, src/config/view.rs:1097-1106:
```rust
    let secrets = resolved
        .secrets
        .iter()
        .map(|s| SecretView {
            header: s.headers().join(", "),
            to: s.to.to_string(),
            shape: s.shape_label(),
            sources: s.describe_sources(),
        })
        .collect();
```
App roster, src/config/view.rs:1541-1549:
```rust
            app.secrets
                .iter()
                .map(|s| SecretView {
                    header: s.headers().join(", "),
                    to: s.to.to_string(),
                    shape: s.shape_label(),
                    sources: s.describe_sources(),
                })
                .collect()
```
App detail view, src/config/view.rs:1860-1868 — the same nine lines again. All three iterate a `Vec<HeaderSecret>` (src/config/mod.rs:466 and :611).

**Coût.** `SecretView` is the surface `sbx config` prints credentials through, where the whole point is that it shows a locator and never a value. A fifth field, or a change to how `header` is joined, must be made in three places; a miss shows one of the three views differently from the other two, and the app-detail and app-roster views are exactly the pair a user compares.

**Correction proposée.** Add one helper in src/config/view.rs beside `app_limits_view` (line 1558):
```rust
/// Project a resolved secret list for display: locator, destination header and shape,
/// never a value.
fn secret_views(secrets: &[super::HeaderSecret]) -> Vec<SecretView> {
    secrets.iter().map(|s| SecretView {
        header: s.headers().join(", "),
        to: s.to.to_string(),
        shape: s.shape_label(),
        sources: s.describe_sources(),
    }).collect()
}
```
The three sites become `secret_views(&resolved.secrets)`, `if injects { secret_views(&app.secrets) } else { Vec::new() }`, and `if secrets_dropped { Vec::new() } else { secret_views(&app.secrets) }` — the two conditionals stay exactly as they are, since which list is shown is the part that genuinely differs.

**Rectification du vérificateur.** One line-number slip in the fix: `app_limits_view` is defined at src/config/view.rs:1559, not 1558 (:1557-1558 are its two doc-comment lines). Nothing else to correct — the helper is a pure extraction with no rustdoc or docs-coverage exposure, since `SecretView` itself (src/config/view.rs:701) is unchanged and a private `fn secret_views` adds no CLI verb, config field or profile.

<details>
<summary>Preuve retenue par le vérificateur</summary>

All three sites verified and identical field-for-field. Baseline: src/config/view.rs:1097-1106 (`let secrets = resolved.secrets` … `.map(|s| SecretView {` at :1100). App roster: :1540-1552, with `app.secrets` at :1541 and `.map(|s| SecretView {` at :1543, inside `secrets: if injects { … } else { Vec::new() }`. App detail: :1857-1869, with `.map(|s| SecretView {` at :1862, inside `secrets: if secrets_dropped { Vec::new() } else { … }`. `grep -n 'SecretView {'` returns exactly 1100, 1543, 1862 plus the struct at :701 and a test literal at :2169. Both sources are `Vec<HeaderSecret>` (src/config/mod.rs:466 and :611), and `headers()`/`shape_label()`/`describe_sources()` are inherent methods on `HeaderSecret` (src/config/types.rs:335, :350, :359). The helper's `super::HeaderSecret` path resolves because src/config/mod.rs:29 is `pub(crate) use types::*;`, and view.rs already reaches sibling types that way (e.g. `super::GuiPolicy` at :1529-1532). The two conditionals genuinely differ and the proposed fix correctly leaves them in place.

</details>

---

### D29 — Three hand-rolled TOML basic-string emitters, only one of which refuses control characters

| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/plugins/catalogue.rs:387` |
| **Autres sites** | src/plugins/origin.rs:253, src/plugins/stores.rs:1209, src/storage.rs:196 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — config, plugins, store, trust |
| **Statut** | confirmé par vérification contradictoire (confiance : moyenne) |

**Constat.** Four places in scope compose TOML by hand, with three different answers to the same escaping question.

`catalogue::toml_quoted`, src/plugins/catalogue.rs:387-399 — the complete one:
```rust
fn toml_quoted(s: &str) -> Result<String, String> {
    if let Some(bad) = s.chars().find(|c| c.is_control()) {
        return Err(format!("value `{}` contains a control character (U+{:04X}) and cannot be serialized", s.escape_default(), bad as u32));
    }
    Ok(format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
}
```
`origin::escape`, src/plugins/origin.rs:253-255 — the same two replaces, no control-character check:
```rust
fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
```
`stores::store_toml`, src/plugins/stores.rs:1209 — the same expression inlined:
```rust
    let url = url.replace('\\', "\\\\").replace('"', "\\\"");
```
and `storage::write_pointer`, src/storage.rs:206-212, which does no escaping at all and relies on `pointer_can_name` having refused anything that would need it.

**Coût.** `origin::escape`'s own doc claims "control characters are already excluded by the callers' own validation", but the `path` field it escapes is the canonicalized source directory of `sbx plugins install ./dir` (src/plugins/mod.rs:1181-1184), which is not validated anywhere — a path containing a newline writes an unparseable `.origins/<name>.toml`, which `origin::parse` (src/plugins/origin.rs:200-203) then swallows as `Origin::Unknown`. The provenance is lost silently rather than refused. The two other emitters are guarded, but by three different mechanisms in three files.

**Correction proposée.** Reuse the strictest one. Move `toml_quoted` from src/plugins/catalogue.rs:387 into `src/plugins/mod.rs` as `pub(super) fn toml_quoted(s: &str) -> Result<String, String>` (its doc comment travels with it; `catalogue.rs` has no intra-doc link to it, so nothing else moves). `catalogue::serialize` (src/plugins/catalogue.rs:352-366) calls it as `super::toml_quoted`. `origin::to_toml` (src/plugins/origin.rs:124-147) already returns `Option<String>`; have it drop a field whose value `toml_quoted` refuses rather than writing an unparseable record — that keeps the read-side `clean` filter (src/plugins/origin.rs:205) as a defence and makes the write side agree with it. `stores::store_toml` uses it for the URL, keeping `validate_url` (src/plugins/stores.rs:1189-1198) as the earlier, better-messaged gate. Leave `storage::write_pointer` alone: its comment at src/storage.rs:204-205 explains that `pointer_can_name` is what makes escaping unnecessary there, and that is a different, deliberate contract.

**Rectification du vérificateur.** Real, but overstated in the write-up and understated in one place.

1. The doc quote is truncated. src/plugins/origin.rs:251-252 continues "; a local path is the one free-form field, and a control byte in it is dropped on read." The comment already knows the path is unvalidated — it is not claiming otherwise. The actual defect is narrower and sharper than "the doc is wrong": drop-on-read only works for a control character TOML tolerates inside a basic string (tab). A newline makes the record unparseable, so `parse` fails at src/plugins/origin.rs:204-206 before the `clean` filter at src/plugins/origin.rs:210 ever runs, and the *whole* record is lost.

2. That loses more than provenance. The same record carries the install digest, so an unparseable record also turns `integrity` (src/plugins/mod.rs:1542-1550) from Intact/Modified into `Unrecorded`. Still not a security regression — the doc at src/plugins/mod.rs:1521-1525 states integrity is drift detection, never consulted on the launch path — but it is a second silent degradation the report does not mention.

3. Two cost items the fix omits. `store_toml` is infallible today (returns `String`); routing it through `toml_quoted` makes it `Result<String, String>` and touches its four call sites at src/plugins/stores.rs:156, 257, 883 and 976. And sharing the escaper couples the *signature-covered* catalogue byte format (src/plugins/catalogue.rs:340-347 calls these "the bytes a signature is taken over") to two unsigned writers; if that coupling is unwanted, the minimal fix is to give `origin::escape` its own control-char refusal — `validate_free_text` at src/plugins/catalogue.rs:374 is the same shape — and leave the three emitters separate.

4. Small citation slips: the function is `serialize_catalogue` at src/plugins/catalogue.rs:348, not `serialize`; `parse` is at src/plugins/origin.rs:203 (the swallow is 204-206), not 200-203; the storage comment is at src/storage.rs:205-206 and the write at 207-216, not 204-205/206-212. And `pub(super)` is the wrong keyword for the moved helper — a private `fn` in src/plugins/mod.rs is already reachable from the child modules as `super::toml_quoted`.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every cited site is where the reporter says it is. src/plugins/catalogue.rs:387-399 is `fn toml_quoted` with exactly the quoted body (control-char refusal + the two replaces); src/plugins/origin.rs:253-255 is `fn escape` with only the two replaces; src/plugins/stores.rs:1209 is the inlined `let url = url.replace('\\', "\\\\").replace('"', "\\\"");` inside `store_toml` (declared at src/plugins/stores.rs:1206); src/storage.rs:196 is `write_pointer`, which interpolates `image.display()` unescaped. The four answers really are different: refuse-and-escape, escape-only, escape-only-behind-`validate_url` (src/plugins/stores.rs:1193-1198), and no-escape-behind-`pointer_can_name` (src/storage.rs:148-172). The reachability chain holds: `install` at src/plugins/mod.rs:1181-1184 canonicalizes the argv source directory into `Origin::Local{path}` with no character validation, `record` (src/plugins/origin.rs:170) writes it through `escape`, and `parse` (src/plugins/origin.rs:203-206) maps a `toml::from_str` failure to `Origin::Unknown`. A shared helper can serve all three without a flag: catalogue propagates the error, origin drops the field, stores can never trip it because `validate_url` already refused. No dependency cycle — `catalogue`, `origin` and `stores` are all children of `src/plugins/mod.rs`.

</details>

---

### D30 — The reflection-masking predicate is written out three times, once per plane

| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/proxy/tunnel.rs:784` |
| **Autres sites** | src/sandbox/proxy/forward.rs:520, src/sandbox/proxy/h2mitm.rs:580 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — proxy (HTTP/1.1, HTTP/2, WebSocket) |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** The rule that decides whether a response is scanned for a reflected credential is spelled identically at all three sites.

tunnel.rs:784-788:
  `let masks_reflection = !creds.needles.is_empty()`
  `    && creds`
  `        .injections`
  `        .iter()`
  `        .any(|inj| names_exact_host(connect_host, Some(&inj.rule)));`

forward.rs:520-524:
  `let masks_reflection = !creds.needles.is_empty()`
  `    && creds`
  `        .injections`
  `        .iter()`
  `        .any(|inj| names_exact_host(&host, Some(&inj.rule)));`

h2mitm.rs:580-584:
  `let masks_reflection = !creds.needles.is_empty()`
  `    && creds`
  `        .injections`
  `        .iter()`
  `        .any(|inj| super::names_exact_host(host, Some(&inj.rule)));`

cleartext.rs:258-267 then explains in prose why it is `false` there, and websocket.rs's declined-upgrade branch never asks the question at all (see the separate finding).

**Coût.** This is the switch that decides whether an injected credential reflected by an upstream is masked before it re-enters the cage. Widening it — say to cover a `Subdomain` rule, which `names_exact_host` currently answers `false` for (ssrf.rs:276) — means finding and editing three call sites in three files; missing one silently leaves that plane unmasked, and the one most likely to be missed is h2mitm.rs, which spells it with a `super::` prefix and so does not match a naive grep for the other two.

**Correction proposée.** Add to the existing `impl CredentialSet` block in inject.rs (inject.rs:502-518, which already holds `wants_body_digest`): `pub(crate) fn masks_reflection_for(&self, host: &str) -> bool { !self.needles.is_empty() && self.injections.iter().any(|inj| crate::sandbox::proxy::names_exact_host(host, Some(&inj.rule))) }`. Replace the three blocks with `let masks_reflection = creds.masks_reflection_for(host);`. The doc comment explaining the reflection threat lives once, on the method; tunnel.rs:770-783, forward.rs:515-519 and h2mitm.rs:573-579 shrink to a one-line pointer at it.

**Rectification du vérificateur.** Sound and cheap, but medium overstates it and the impact argument is wrong.

The stated hazard - "the one most likely to be missed is h2mitm.rs, which spells it with a `super::` prefix and so does not match a naive grep for the other two" - does not hold. All three bindings are named `masks_reflection`, and `grep -rn masks_reflection src/` returns exactly those three plus the cleartext prose. Nobody widening this switch would miss the h2 site.

What remains is a genuine but small cleanup: 15 lines collapsing to 3 call sites plus one method, zero behaviour change, and one home for the threat comment currently triplicated at tunnel.rs:777-783, forward.rs:516-519 and h2mitm.rs:574-579. Two things must survive the move: the `!self.needles.is_empty()` short-circuit is load-bearing for cost (it is what keeps the scan off every allowed response), and cleartext.rs:260-267's prose must stay put - it explains an absence the helper does not represent, and replacing it with "a one-line pointer at the method" would lose the reasoning that a cleartext host can never be an injection target.

<details>
<summary>Preuve retenue par le vérificateur</summary>

All three sites verified verbatim: src/sandbox/proxy/tunnel.rs:784-788, src/sandbox/proxy/forward.rs:520-524, src/sandbox/proxy/h2mitm.rs:580-584 - identical expressions differing only in how the host is spelled (`connect_host` / `&host` / `host`) and the `super::` prefix on the h2 site. cleartext.rs:260-267 does explain in prose why it is absent there ("a cleartext host is never one"), and websocket.rs's declined branch never computes it. The proposed home is real and exact: `impl CredentialSet` is at inject.rs:502-518 and already holds `wants_body_digest` (inject.rs:509-517), so the new method sits beside its sibling. `names_exact_host` is re-exported `pub(crate)` at mod.rs:210, so `crate::sandbox::proxy::names_exact_host` resolves from inject.rs and creates no cycle (both are submodules of `sandbox::proxy`). No comment anywhere claims the restatement is deliberate; h2mitm.rs:577 says "parity with the HTTP/1.1 `masks_reflection`", which asks them to stay in sync rather than acting as a drift barrier.

</details>

---

### D31 — The connection-bound-auth scheme list (NTLM / Negotiate) is implemented twice, once per protocol

| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/proxy/wire.rs:574` |
| **Autres sites** | src/sandbox/proxy/h2mitm.rs:1019 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — proxy (HTTP/1.1, HTTP/2, WebSocket) |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** Both pools refuse to share a connection whose response bound an identity to it, and both decide that with their own copy of the same predicate.

wire.rs:574-582, inside `response_keeps_alive`:
  `let connection_bound_auth = parsed`
  `    .headers`
  `    .iter()`
  `    .filter(|(k, _)| k.eq_ignore_ascii_case("www-authenticate"))`
  `    .flat_map(|(_, v)| v.split(','))`
  `    .any(|challenge| {`
  `        let scheme = challenge.split_whitespace().next().unwrap_or("");`
  `        scheme.eq_ignore_ascii_case("ntlm") || scheme.eq_ignore_ascii_case("negotiate")`
  `    });`

h2mitm.rs:1019-1029, `binds_identity_to_the_connection`:
  `headers`
  `    .get_all("www-authenticate")`
  `    .iter()`
  `    .filter_map(|v| v.to_str().ok())`
  `    .flat_map(|v| v.split(','))`
  `    .any(|challenge| {`
  `        let scheme = challenge.split_whitespace().next().unwrap_or("");`
  `        scheme.eq_ignore_ascii_case("ntlm") || scheme.eq_ignore_ascii_case("negotiate")`
  `    })`

Only the header-container type differs; the comma splitting, the first-token extraction and the scheme list are byte-identical. h2mitm.rs:1013-1015's own doc admits the pairing ("The HTTP/1.1 pool refuses to park such a connection for the same reason this one stops sharing it").

**Coût.** The scheme list is the security-relevant part: adding a third connection-bound scheme (Kerberos, or a vendor challenge) means editing two files, and forgetting the h2 one leaves an HTTP/2 upstream connection carrying an authenticated identity shared across every later stream on the same tunnel — the exact hazard both comments describe. Two copies also means two test sites (wire.rs:1092-1102 and h2mitm.rs:2363-2378) that can pass independently.

**Correction proposée.** Add to wire.rs beside `response_keeps_alive`: `pub(super) fn names_connection_bound_scheme<'a>(challenges: impl Iterator<Item = &'a str>) -> bool { challenges.flat_map(|v| v.split(',')).any(|c| { let s = c.split_whitespace().next().unwrap_or(""); s.eq_ignore_ascii_case("ntlm") || s.eq_ignore_ascii_case("negotiate") }) }`. wire.rs:574-582 becomes `names_connection_bound_scheme(parsed.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("www-authenticate")).map(|(_, v)| v.as_str()))`; h2mitm.rs:1019-1029 becomes `super::wire::names_connection_bound_scheme(headers.get_all("www-authenticate").iter().filter_map(|v| v.to_str().ok()))`. Keep `binds_identity_to_the_connection` as the named wrapper so h2mitm.rs:1012-1018's doc and the call at h2mitm.rs:561 are unchanged, and its ``[`response_keeps_alive`]`` intra-doc link stays resolvable.

**Rectification du vérificateur.** Real but small, and the fix rationale contains one factual error: h2mitm.rs:1012-1018 contains no ``[`response_keeps_alive`]`` intra-doc link (it names "The HTTP/1.1 pool" in prose), so there is no link to keep resolvable — nothing in rustdoc is at stake. Both sides are independently tested (wire.rs:1092-1097 NTLM/Negotiate rows; h2mitm.rs:2361-2378 `a_connection_the_upstream_binds_an_identity_to_stops_being_shared`), and the h2 doc cross-references the HTTP/1.1 twin, so the drift risk is mitigated, not unguarded — medium is too high; low. One extra cost the report omits: wire.rs's module doc (wire.rs:1-5) scopes the file to "HTTP/1.1 wire parsing … helpers the CONNECT/MITM and cleartext paths share", so hosting a predicate the HTTP/2 plane calls needs that sentence updated to stay honest under CLAUDE.md's doc rule.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every cited site checks out. src/sandbox/proxy/wire.rs:574-582 is the `connection_bound_auth` closure inside `response_keeps_alive` (fn at wire.rs:558, doc wire.rs:545-557), and its last two lines are `let scheme = challenge.split_whitespace().next().unwrap_or(""); scheme.eq_ignore_ascii_case("ntlm") || scheme.eq_ignore_ascii_case("negotiate")`. src/sandbox/proxy/h2mitm.rs:1019-1030 is `binds_identity_to_the_connection`, doc at h2mitm.rs:1012-1018, called once at h2mitm.rs:562. The two bodies differ only in the header container (`Vec<(String,String)>` from wire.rs:55 vs `http::HeaderMap`); the comma split, the first-token extraction and the two-scheme list are identical. The h2 doc (h2mitm.rs:1013-1015) pairs the two rather than declaring a deliberate restatement, and h2mitm.rs:793-795 shows this codebase marks deliberate divergence explicitly when it means it, so the "restated on purpose" exemption does not apply. The extraction is feasible: mod.rs:196 declares `mod wire;` and mod.rs:214 does `use wire::*;`, so a new `pub(super) fn` in wire.rs is reachable from h2mitm as `super::…` exactly like `header_name_eq` (mod.rs:218, imported at h2mitm.rs:24-27); no cycle, no seam opened, and an iterator-of-&str signature serves both containers without a flag argument.

</details>

---

### D32 — header_name_eq heap-allocates two Vec<u8> per header comparison on the injection hot path

| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/proxy/wire.rs:20` |
| **Autres sites** | src/sandbox/proxy/mod.rs:1352, src/sandbox/proxy/h2mitm.rs:479, src/sandbox/proxy/websocket.rs:792, src/sandbox/proxy/inject.rs:697 |
| **Catégorie** | `allocation` |
| **Balayage** | Duplication — proxy (HTTP/1.1, HTTP/2, WebSocket) |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** wire.rs:20-32:
  `pub(crate) fn header_name_eq(a: &str, b: &str) -> bool {`
  `    let norm = |s: &str| -> Vec<u8> {`
  `        s.bytes().map(|c| { if c == b'_' { b'-' } else { c.to_ascii_lowercase() } }).collect()`
  `    };`
  `    norm(a) == norm(b)`
  `}`

Every call builds and drops two heap buffers to answer a boolean.

**Coût.** On any request to a credential-injected host the function runs once per (client header x injected name) in `reserialize_request` (mod.rs:1352), plus once per (OBSERVED_AUTH_HEADERS x injected name) in `Credentials::observe_head` (inject.rs:695-698, with the 5-entry list at inject.rs:728-734) — on the order of 25-50 calls, so 50-100 allocations, per forwarded request. The h2 plane pays it per stream (h2mitm.rs:479) and again per request trailer (h2mitm.rs:781). Not a per-byte cost, but it is on the per-request path of the proxy that fronts every agent call, and it buys nothing.

**Correction proposée.** Rewrite in place, same semantics, no allocation: `pub(crate) fn header_name_eq(a: &str, b: &str) -> bool { let fold = |c: u8| if c == b'_' { b'-' } else { c.to_ascii_lowercase() }; a.len() == b.len() && a.bytes().zip(b.bytes()).all(|(x, y)| fold(x) == fold(y)) }`. Header names are ASCII by the parser's own contract, so byte-length equality is exact. The doc comment (wire.rs:17-19) and the pinning test `header_name_eq_is_case_and_underscore_insensitive` (wire.rs:1487-1492) are unchanged.

**Rectification du vérificateur.** Two corrections, neither fatal. The fix's stated justification ("header names are ASCII by the parser's own contract") is unnecessary and slightly wrong — `parse_head` (wire.rs:49) requires UTF-8, not ASCII — but the rewrite is exact anyway because the normalization maps one byte to one byte, so equal normalized vectors imply equal byte lengths. And the volume estimate is high: injections are typically a single header per host (`pairs_for`, inject.rs:229-237, builds one entry per matching id), so a realistic forwarded request costs ~20-30 calls / 40-60 allocations, and a request to a host with no injection costs zero (`.any()` over an empty slice never calls it). Low severity is the right label: this is a free, mechanical win, not a measurable one.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified at every site. src/sandbox/proxy/wire.rs:20-33 is `pub(crate) fn header_name_eq`, whose `norm` closure (wire.rs:21-31) `.collect()`s a `Vec<u8>` per side and compares them at wire.rs:32 — two heap buffers per boolean. Callers verified: mod.rs:1352 (`injections.iter().any(|(name, _)| header_name_eq(k, name))`, once per client header), websocket.rs:792, h2mitm.rs:479 (per stream) and h2mitm.rs:781 (per request trailer), and inject.rs:697 inside `observe_head` (fn at inject.rs:688) over the 5-entry `OBSERVED_AUTH_HEADERS` at inject.rs:728-734. `observe_head` is genuinely per request on all four planes: tunnel.rs:474, forward.rs:307, h2mitm.rs:416, cleartext.rs:159. The proposed rewrite is exactly equivalent, not merely close: the fold is byte-for-byte length-preserving, so `a.len() == b.len()` plus a zipped byte comparison decides the same predicate the two normalized vectors do. Nothing observable changes, no security property is touched (the `_`→`-` fold and case-insensitivity are preserved, which is what wire.rs:17-19 and the pin at wire.rs:1486-1493 require), and the boundary test that follows at wire.rs:1495-1500 is unaffected.

</details>

---

### D33 — The upstream-unreachable refusal is written out three times, once per transport

| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/proxy/mod.rs:813` |
| **Autres sites** | src/sandbox/proxy/cleartext.rs:174, src/sandbox/proxy/splice.rs:127 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — proxy (HTTP/1.1, HTTP/2, WebSocket) |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** The same log line plus refusal, with the same reason token and the same sentence, at three sites.

mod.rs:819-826 (inside `refuse_upstream`):
  `UpstreamError::Unreachable => (`
  `    "upstream-unreachable",`
  `    format!("`{host}:{port}` is allowed but could not be reached"),`
  `),`
  ... then `ctx.push_log(..., LogVerdict::Error, reason)` and `write_refusal(w, "502 Bad Gateway", reason, &detail)`

cleartext.rs:175-187:
  `ctx.push_log(Proto::Http, &host, port, Some(method), Some(&path), LogVerdict::Error, "upstream-unreachable");`
  `return write_refusal(&mut client, "502 Bad Gateway", "upstream-unreachable", &format!("`{host}:{port}` is allowed but could not be reached"));`

splice.rs:128-140:
  `ctx.push_log(Proto::Tcp, connect_host, port, None, None, LogVerdict::Error, "upstream-unreachable");`
  `return write_refusal(&mut client, "502 Bad Gateway", "upstream-unreachable", &format!("`{connect_host}:{port}` is allowed but could not be reached"));`

The only real variables are the `Proto` and whether a method/path exists.

**Coût.** Three copies of a documented reason token and its exact sentence (both pinned by mod.rs:107). A wording change or an added detail has to land three times, and the cleartext/splice copies do not go through `refuse_upstream`, so a reader auditing that function does not see them.

**Correction proposée.** Add beside `refuse_upstream` in mod.rs: `fn refuse_unreachable<W: Write>(w: &mut W, ctx: &ProxyCtx, proto: crate::sandbox::control::Proto, host: &str, port: u16, method: Option<&str>, path: Option<&str>) -> io::Result<()>` holding the push_log + write_refusal + sentence. `refuse_upstream`'s `Unreachable` arm calls it with `Proto::Https`; cleartext.rs:174-188 calls it with `Proto::Http, Some(method), Some(&path)`; splice.rs:127-141 with `Proto::Tcp, None, None`. `refuse_upstream` keeps its `CertRejected` arm, which has no cleartext or splice analogue (neither validates a certificate).

**Rectification du vérificateur.** Three citation corrections: the Unreachable arm is mod.rs:819-822, not 819-826 (823-828 is the `CertRejected` arm); cleartext's push_log starts at 173, not 175; splice's at 126, not 128. Also, mod.rs:107 pins only the reason token and a different description ("the host is allowed but the TCP connection failed"), not the format-string sentence — nothing anywhere pins that sentence, which strengthens rather than weakens the drift argument. Finally the coverage is 3 of 4 token sites: the HTTP/2 plane emits `"upstream-unreachable"` at h2mitm.rs:982 and refuses through its own `refuse_upstream` (h2mitm.rs:1044-1063), which writes the token with no detail sentence at all, so it cannot use the proposed helper and would remain a fourth place the token is spelled.

<details>
<summary>Preuve retenue par le vérificateur</summary>

All three sites exist and are byte-identical in reason token and sentence. mod.rs:809-840 is `refuse_upstream`; its `Unreachable` arm is mod.rs:819-822 (`"upstream-unreachable"` at 820, the sentence at 821), followed by the shared `ctx.push_log(Proto::Https, …)` at mod.rs:830-838 and `write_refusal(w, "502 Bad Gateway", reason, &detail)` at mod.rs:839. cleartext.rs:173-181 is the same push_log with `Proto::Http, Some(method), Some(&path)`, and cleartext.rs:182-187 the same `write_refusal` with the same sentence at cleartext.rs:186. splice.rs:126-134 / 135-140 repeat it with `Proto::Tcp, None, None` and the sentence at splice.rs:139. `grep` over the whole crate finds the sentence at exactly those three lines and nowhere else — no test pins it, so drift between the three would go unnoticed. The extraction is sound: `write_refusal` is already generic over `W: Write` (mod.rs:1726-1731) and `push_log` already takes `Option<&str>` method/path (ctx.rs:507-516), both planes already reach mod.rs items through `use super::*` (cleartext.rs:7, splice.rs:7), and neither module doc claims the refusal wording is deliberately restated. No seam is dissolved — the helper carries a string and a log line, not policy.

</details>

---

### D34 — The capture tee-and-box wrapper is copied at four response-relay sites

| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/proxy/tunnel.rs:871` |
| **Autres sites** | src/sandbox/proxy/forward.rs:585, src/sandbox/proxy/cleartext.rs:291, src/sandbox/proxy/websocket.rs:866 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — proxy (HTTP/1.1, HTTP/2, WebSocket) |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** The same four lines wrap the response stream in a capture tee at every plane that relays an HTTP/1.1 response.

tunnel.rs:871-874, forward.rs:585-588 and cleartext.rs:291-294 are character-identical:
  `let mut response: Box<dyn Read + '_> = match &capture {`
  `    Some(c) => Box::new(CaptureReader::new(response, c.response_sink())),`
  `    None => Box::new(response),`
  `};`

websocket.rs:866-869 is the same with two renamed bindings:
  `let mut body: Box<dyn Read + '_> = match capture {`
  `    Some(c) => Box::new(CaptureReader::new(counted, c.response_sink())),`
  `    None => Box::new(counted),`
  `};`

The request-side twin is also tripled: `copy_exact(&mut CaptureReader::new(<client>, c.request_body_sink()), &mut upstream, body_len)?` with a `None` arm, at tunnel.rs:754-761, forward.rs:495-502 and cleartext.rs:245-252.

**Coût.** Low on its own, but it is the seam where a plane can silently stop capturing: the `Some`/`None` arms must stay in step, and the h2 plane already needed an extra `.filter(|c| c.keeps_body())` (h2mitm.rs:611-614) that these four sites do not have. Anyone adding a condition to "should this stream be teed" has four places to find, in four files.

**Correction proposée.** Add to capture.rs: `pub(super) fn tee_response<'a, R: Read + 'a>(r: R, capture: Option<&'a CaptureGuard>) -> Box<dyn Read + 'a> { match capture { Some(c) => Box::new(CaptureReader::new(r, c.response_sink())), None => Box::new(r) } }` and `pub(super) fn tee_request_body<'a, R: Read + 'a>(r: R, capture: Option<&'a CaptureGuard>) -> Box<dyn Read + 'a>` using `request_body_sink()`. The four response sites become `let mut response = tee_response(response, capture.as_ref());` (websocket.rs passes `capture` directly, already an `Option<&CaptureGuard>`), and the three `copy_exact` matches become `copy_exact(&mut tee_request_body(&mut client, capture.as_ref()), &mut upstream, body_len)?` with no branch at all.

**Rectification du vérificateur.** Survives, but three corrections. (1) The impact paragraph is wrong about the h2 `keeps_body()` filter. h2mitm.rs:611-614 is not a guard the four sites are missing — h2mitm.rs:607-610 documents why it is HTTP/2-only ("an HTTP/2 head is its own frame, so unlike a byte stream there is nothing to read past, and not one body byte is ever buffered"), and capture.rs:190-193 plus capture.rs:355-360 show the byte-stream planes deliberately tee head and body into one sink (`CapBuf::new(caps.head + caps.body)`, capture.rs:221) and apply `keeps_body` at filing time via `split_response(self.response.take(), self.keeps_body.then(|| ...))`. Adding `.filter(|c| c.keeps_body())` at the four sites would drop the response *head* under the headers-only level — a bug, not a missing condition. Drop that sentence; the duplication argument stands on its own. (2) Not character-identical: cleartext.rs:291-294 is at 4-space indent (function body) where tunnel.rs:871-874 and forward.rs:585-588 sit inside an extra block; and the request-side reader in tunnel.rs:756 is `&mut br` (the client BufReader), not `&mut client` as the fix text writes, so the helper must be called with the plane's own reader. (3) Two mechanical additions to the fix: the helpers must be added to mod.rs:199 (`use capture::{CaptureGuard, CaptureReader};`) or the submodules' `use super::*;` (tunnel.rs:8, forward.rs:7, cleartext.rs:7) will not see them; and for the request side prefer an enum wrapper (`enum MaybeTee<R> { Tee(CaptureReader<R>), Plain(R) }` with one `Read` impl) over `Box<dyn Read>`, since `copy_exact` (wire.rs:342) is generic and the current `None` arm has no allocation and no dyn dispatch at all — the same wrapper also removes the `Box` from the four response sites.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every cited site checks out. Response tee: src/sandbox/proxy/tunnel.rs:871-874 (`let mut response: Box<dyn Read + '_> = match &capture { Some(c) => Box::new(CaptureReader::new(response, c.response_sink())), None => Box::new(response), };`), src/sandbox/proxy/forward.rs:585-588 (identical text), src/sandbox/proxy/cleartext.rs:291-294 (identical text, 4-space indent instead of 8), src/sandbox/proxy/websocket.rs:866-869 (same shape, `body`/`counted` bindings, `match capture` because the parameter at websocket.rs:830 is already `Option<&CaptureGuard>`). Request tee: tunnel.rs:754-761, forward.rs:495-502, cleartext.rs:245-252 are the same `match &capture { Some(c) => copy_exact(&mut CaptureReader::new(<reader>, c.request_body_sink()), &mut upstream, body_len)?, None => copy_exact(<reader>, &mut upstream, body_len)? }`. grep confirms these are the only 4 `Box<dyn Read` and the only 7 `CaptureReader::new` call sites outside capture.rs itself. The extraction is sound: `CaptureReader` is generic (`pub(super) struct CaptureReader<R>`, capture.rs:147-161) and holds only an `Arc<CapBuf>`, so a helper in capture.rs needs no knowledge of any plane — no cycle, no seam opened. The three HTTP/1.1 planes hold `Option<CaptureGuard>` (tunnel.rs:549, forward.rs:349, cleartext.rs:217) so `.as_ref()` yields the `Option<&CaptureGuard>` the helper wants, and websocket passes its parameter directly, exactly as the fix states. Both consumers downstream of the box (`pump_to_eof` mod.rs:1562, `pump_redacting` mod.rs:1603) are generic over `R: Read`, so nothing constrains the wrapper's type. No comment anywhere marks these as deliberately restated; the module doc argues the opposite — mod.rs:22-24 ("every divergence between the planes that has turned into a bug was a decision written out twice, so a decision belongs in one place") and mod.rs:1860-1864 ("Written once for both inspected planes on purpose. The per-plane copy is precisely the mistake [`wire::inspect_framing`] exists to have fixed"). The head half of this exact tee is already unified: all three planes pass `capture.as_ref()` into the shared `relay_head` (tunnel.rs:811, forward.rs:539, cleartext.rs:277); the body tee is the leftover.

</details>

---

### D35 — forward.rs hand-rolls the connection cap that conncap.rs exists to be the one copy of

| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/forward.rs:239` |
| **Autres sites** | src/sandbox/conncap.rs:43 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — modules sandbox |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** forward.rs:239-271 re-implements `ConnCap` inline: `let live = Arc::new(AtomicUsize::new(0)); ... if live.load(Ordering::Relaxed) >= MAX_CONCURRENT_CONNS { // Refuse beyond the cap: dropping the stream closes it (fail-closed). continue; } live.fetch_add(1, Ordering::Relaxed); let live = live.clone(); ... std::thread::spawn(move || { struct Dec<'a>(&'a AtomicUsize); impl Drop for Dec<'_> { fn drop(&mut self) { self.0.fetch_sub(1, Ordering::Relaxed); } } let _dec = Dec(&live); let _ = bridge(stream, &sock); });`. conncap.rs:67-73 is the same thing, once: `pub(super) fn take(&self) -> Option<ConnSlot> { if self.live.fetch_add(1, Ordering::SeqCst) >= self.max { self.live.fetch_sub(1, Ordering::SeqCst); return None; } Some(ConnSlot(Arc::clone(&self.live))) }`, with `impl Drop for ConnSlot` at 83-87. conncap.rs:7-13 says it exists "because the loops that need it wrote it four times and no copy had both halves… Two released it from a `Drop` guard and *checked* the ceiling before taking it". forward.rs is a fifth copy of precisely that half. The other four were converted — broker.rs:1672/1683, sshagent.rs:716/725, task_control.rs:663/677 and task_control.rs:694/709 all read `let cap = super::conncap::ConnCap::new(MAX_CONCURRENT_CONNS); … let Some(slot) = cap.take() else { continue };` — while forward.rs contains no reference to `conncap` at all.

**Coût.** Being honest about the race: it is not reachable here, since there is one accept thread per listener and only handler exits decrement, so this is a maintenance finding rather than a live bug. But it is the one accept loop a future change to `ConnCap` will not reach, and the ceiling is not what the docstring says: `MAX_CONCURRENT_CONNS = 512` (forward.rs:65) is per listener, and `spawn_accept` is called once for v4 (forward.rs:190) and again for v6 (forward.rs:196), each with its own `live`, so N declared forwards admit up to 1024*N bridge threads while forward.rs:236-237 states only "A `MAX_CONCURRENT_CONNS` cap refuses beyond (fail-closed)".

**Correction proposée.** In forward.rs take `let cap = super::conncap::ConnCap::new(MAX_CONCURRENT_CONNS);` and pass a clone into `spawn_accept`/`accept_loop` so both listeners of one forward share it — `ConnCap` derives `Clone` for exactly this, and task_control.rs:663/694 deliberately does the opposite and says so in a comment, so forward.rs should state which it wants. Replace lines 255-259 with `let Some(slot) = cap.take() else { continue };`, delete `struct Dec` at 263-268 and `let _dec = Dec(&live);` at 269, and open the spawned closure with `let _slot = slot;` — the line broker.rs:1694 and sshagent.rs:739 already carry. `live` and the `AtomicUsize` import then drop out of forward.rs:54 and 239. The accept-error arm at 244-250 stays as it is and should not become `conncap::accept_backoff`: this listener is non-blocking and its `Err` is the ordinary no-pending-connection case, not the transient-error case — worth one comment line saying so, since it is the only accept loop where that distinction holds.

**Rectification du vérificateur.** Two things are wrong in the write-up. (1) The impact claims the ceiling "is not what the docstring says" — but forward.rs:63-64 already documents it as "A cap on live host→cage pump threads **per listener**, matching [`super::proxy::serve`]'s shape". Only accept_loop's own doc at 236-237 omits the qualifier; the 1024-per-forward arithmetic is the documented design, not an undocumented surprise. (2) Consequently the fix's central move — one shared `ConnCap` cloned into both listeners — is a behaviour change that contradicts forward.rs:63 and the proxy shape it deliberately matches. The pure refactor is `let cap = super::conncap::ConnCap::new(MAX_CONCURRENT_CONNS);` at forward.rs:239, inside `accept_loop`, exactly where `live` is created today, leaving the per-listener ceiling intact. Also downgrade to low: the reporter concedes the burst race is unreachable (one accept thread per listener; only handler exits decrement), so this is consistency-with-conncap only, not the half-a-copy defect the conncap header was written about. The accept-arm analysis is correct and worth keeping — spawn_accept sets non-blocking at forward.rs:227, so `Err` is ordinarily `WouldBlock` and `accept_backoff` would log-and-sleep on every idle poll.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every line checked out. forward.rs:239 `let live = Arc::new(AtomicUsize::new(0));`, the check-then-take at 255-259, `struct Dec` at 263-268, `let _dec = Dec(&live);` at 269, closure end 271; MAX_CONCURRENT_CONNS at forward.rs:65; the atomic import at forward.rs:54 (`AtomicBool`/`Ordering` stay, only `AtomicUsize` drops, as claimed); spawn_accept called for v4 at 190 and v6 at 196. conncap.rs:43 is the `ConnCap` doc line, `#[derive(Clone)]` at 44, `take` at 67-73, `impl Drop for ConnSlot` at 83-87, and the module header's "wrote it four times / checked the ceiling before taking it" passage is at 7-13. The four converted sites are exactly at broker.rs:1672/1683/1694, sshagent.rs:716/725/739, task_control.rs:663/677 and 694/709, with task_control.rs:705-708 giving the deliberate reason for two separate caps. `grep -rn conncap src/sandbox/forward.rs` returns nothing. ConnCap is pub(in crate::sandbox) via mod.rs:16, so `super::conncap::ConnCap` resolves from forward.rs. Swapping check-then-add for `take()` is behaviour-identical here (one taker), so the refactor is pure.

</details>

---

### D36 — egress_stats.rs contains two copies of the same 0600 atomic writer

| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/egress_stats.rs:307` |
| **Autres sites** | src/sandbox/egress_stats.rs:561 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — modules sandbox |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** `Stats::flush` (307-334) and `write_rollup` (561-578) hold the same closure. flush:317-333: `let write = || -> io::Result<()> { use std::os::unix::fs::OpenOptionsExt; let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?; f.write_all(body.as_bytes()) }; let result = write().and_then(|()| std::fs::rename(&tmp, &self.path)); if result.is_err() { let _ = std::fs::remove_file(&tmp); } result`. write_rollup:562-577: `use std::os::unix::fs::OpenOptionsExt; let body = serialize(project, app, tally); let tmp = target.with_extension(format!("tmp.{}", std::process::id())); let write = || -> io::Result<()> { let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?; f.write_all(body.as_bytes()) }; let result = write().and_then(|()| std::fs::rename(&tmp, target)); if result.is_err() { let _ = std::fs::remove_file(&tmp); } result`. The only difference is where the temp suffix comes from — `self.tmp_seq.fetch_add(1, Ordering::Relaxed)` for the per-session flush, `std::process::id()` for the fold.

**Coût.** Small, but this pair decides the on-disk mode of the egress counters, and the `.tmp.` spelling is load-bearing in a third place: `session_files` (egress_stats.rs:580) and `reset` both skip these intermediates by name, so one writer changing its temp name would make its orphans read back as session files.

**Correction proposée.** One private `fn write_stats_file(target: &Path, tmp_suffix: &str, body: &str) -> io::Result<()>` in egress_stats.rs holding the `OpenOptions … .mode(0o600)` open, the write, the rename and the remove-on-failure, with the `.tmp.` prefix built inside it so the name `session_files` filters on is spelled once. `flush` calls it with the sequence number, `write_rollup` with the pid; both keep their own `serialize(...)` call and their own docstrings.

**Rectification du vérificateur.** Line slop and one omission. `write_rollup` runs to 579 (the quoted body ends at 578, not 577), and `session_files` is at egress_stats.rs:583 with its doc at 581-582 — not 580. The `.tmp.` filter is load-bearing in three places, not two: `fold` at 517, `session_files` at 593, and `reset` at 637. One design constraint the fix must respect: the two sites rely on `Path::with_extension` behaving differently on their targets — flush's `stats-<pid>` has no extension so it gains `.tmp.<seq>`, while write_rollup's `stats-rollup.<hex>` (ROLLUP_PREFIX at 455, name built at 485-493) has its hex *replaced*, yielding `stats-rollup.tmp.<pid>`. So the helper must keep calling `with_extension(format!("tmp.{suffix}"))` verbatim; "building the `.tmp.` prefix inside it" any other way silently changes the rollup temp's name.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Both blocks are where the reporter says. `Stats::flush` is at egress_stats.rs:307-334 with the closure at 317-333; `write_rollup` is at egress_stats.rs:561 with the body at 562-578. The OpenOptions chain (`write/create/truncate/mode(0o600)`), the `write().and_then(rename)`, and the remove-on-failure are character-for-character the same; the only divergences are the temp suffix (`self.tmp_seq.fetch_add` at 314 vs `std::process::id()` at 564), the rename target, and flush's `recordable` early return at 310-312, all of which stay at the call site under the proposed split. Nothing marks the repetition as deliberate. The extraction is local to one file, creates no cycle, and touches no security property beyond keeping 0600 spelled once.

</details>

---

### D37 — Two sites take a poisoned lock inline instead of through locks.rs, which says that decision is made once

| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/sshagent.rs:290` |
| **Autres sites** | src/sandbox/resolver.rs:603 |
| **Catégorie** | `duplication` |
| **Balayage** | Duplication — modules sandbox |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** locks.rs:8-9 states the rule — "Which half a lock belongs to is decided once, here, rather than re-decided at each site that takes one" — and locks.rs:43-45 is the helper: `pub(crate) fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> { m.lock().unwrap_or_else(|e| e.into_inner()) }`. Seven modules use it (egress_stats.rs:37, lens.rs:60, notify_relay.rs:36, task.rs:44, task_control.rs:76, launch.rs:705). Two do not. sshagent.rs:288-290: `// A poisoned gate means another prompt's thread panicked; take the lock anyway rather than / // turning one panic into a broker that can never confirm again. let _held = self.gate.lock().unwrap_or_else(|e| e.into_inner());`. resolver.rs:602-603: `// A poisoned lock is not a reason to lose a warning: recover the set and speak anyway. let mut said = said.lock().unwrap_or_else(|e| e.into_inner());`. Both re-decide, in their own words, the decision locks.rs says it holds.

**Coût.** locks.rs names its exceptions explicitly — proxy/pool.rs, proxy/dns.rs and `ProcOverlay` in proc_enforce.rs, at locks.rs:20-31 — so that the set of locks not going through it is enumerable. These two sit outside that register, so the module header is no longer a complete account of who recovers and why, which is the only thing that makes the header worth having.

**Correction proposée.** sshagent.rs:290 becomes `let _held = crate::sandbox::locks::locked(&self.gate);` and resolver.rs:603 becomes `let mut said = crate::sandbox::locks::locked(said);`, each keeping its existing one-line comment as the local justification. Both fall squarely under the "recovers" half of locks.rs's rule (a serialising gate whose guard holds `()`, and a `BTreeSet<String>` of already-said warnings), so no new argument is owed at locks.rs and its exception list does not need to grow.

**Rectification du vérificateur.** The justification is wrong for one of the two sites, and the supporting list is wrong. sshagent's `gate` is `std::sync::Mutex<()>` (declared sshagent.rs:238, built at 245) — it guards no record at all, so it is not the "recovers" half locks.rs:11-18 describes ("a lens ring, a tally, an invocation log, a registry the run consults"). It is the ProcOverlay shape, and locks.rs:30-31 explicitly says such a lock "owes that argument in full at its own definition; it does not inherit one from here", while locks.rs:26 counts exactly "One site". So the claim's "no new argument is owed at locks.rs and its exception list does not need to grow" is false: converting sshagent.rs:290 means locks.rs:26 must stop saying "One site" and name the gate as the second. resolver.rs:603 does fit cleanly — a `BTreeSet` whose mutation is the single `insert` at 604, matching locks.rs:16-18 word for word. Separately, the users list is inaccurate: launch.rs:705 is `super::locks::read_locked`, not `locked`, and the list omits proc_enforce.rs:130 and proxy/capture.rs:30; the seven files importing `locked` are egress_stats.rs:37, notify_relay.rs:36, lens.rs:60, task_control.rs:76, proc_enforce.rs:130, proxy/capture.rs:30 and task.rs:44.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified precisely. locks.rs:8-9 carries the "decided once, here, rather than re-decided at each site" sentence; `locked` is at locks.rs:43-45; the exception register is at locks.rs:20-31. sshagent.rs:288-290 and resolver.rs:602-603 are exactly the two quoted inline recoveries, and an exhaustive `grep -rn 'into_inner()' src/` confirms they are the only two in the sandbox tree (the third, testutil.rs:23, is a test-only env lock outside the sweep). Both conversions compile: `locked` is `pub(crate)`, `self.gate` is a `Mutex<()>` and `said` is a `&Mutex<BTreeSet<String>>` from `OnceLock::get_or_init`. proc_enforce.rs:130 imports `locked` while being a named exception, so the "use the helper, keep your local argument" pattern the fix proposes already has precedent in-tree.

</details>

---

### D38 — header_name_eq heap-allocates two Vec<u8> per header-name comparison, on every plane's per-request strip loop

| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/proxy/wire.rs:20` |
| **Autres sites** | src/sandbox/proxy/mod.rs:1352, src/sandbox/proxy/h2mitm.rs:479, src/sandbox/proxy/h2mitm.rs:781, src/sandbox/proxy/websocket.rs:792, src/plugins/signer.rs:234, src/plugins/signer.rs:289 |
| **Catégorie** | `allocation` |
| **Balayage** | Optimisation — chemin de données par octet |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** wire.rs:20-33 normalizes BOTH names into fresh heap buffers just to compare them:

    pub(crate) fn header_name_eq(a: &str, b: &str) -> bool {
        let norm = |s: &str| -> Vec<u8> {
            s.bytes()
                .map(|c| { if c == b'_' { b'-' } else { c.to_ascii_lowercase() } })
                .collect()
        };
        norm(a) == norm(b)
    }

`.collect()` on a `Bytes` iterator is `ExactSizeIterator`, so each `norm` is one guaranteed `malloc` + `free`; two per call, and the result is discarded immediately.

It is called from inside a per-header loop on every serializer. mod.rs:1352 (`reserialize_request`, the HTTP/1.1 tunneled + absolute-form + cleartext planes):

        for (k, v) in &head.headers {
            ...
            if injections.iter().any(|(name, _)| header_name_eq(k, name)) {
                continue;
            }

websocket.rs:792 (`reserialize_upgrade`) is the identical line:

        if injections.iter().any(|(name, _)| header_name_eq(k, name)) {
            continue;
        }

h2mitm.rs:479 (request head rebuild, per HPACK header):

        if forbidden_request_header(n) || injected.iter().any(|(h, _)| header_name_eq(h, n)) {
            continue;
        }

and h2mitm.rs:781 (`strip_request_trailers`, per trailer):

        if !forbidden_request_header(n) && !injected.iter().any(|h| header_name_eq(h, n)) {

**Coût.** Runs (client headers x injections) times per forwarded request on four code paths. A typical agent request carries ~12-15 headers with 1 injection, so ~13 calls = 26 malloc/free pairs per request, purely to answer a case-insensitive compare; with 3 path-scoped injections it is ~80. The crate deliberately runs on the system allocator (see the Cargo.toml comment), so this is real per-request heap traffic on the single hottest loop in the proxy. Zero of it is needed: the normalization is length-preserving and byte-local.

**Correction proposée.** Rewrite the body in place, keeping the signature, doc comment and every call site unchanged:

    pub(crate) fn header_name_eq(a: &str, b: &str) -> bool {
        let fold = |c: u8| if c == b'_' { b'-' } else { c.to_ascii_lowercase() };
        a.len() == b.len() && a.bytes().zip(b.bytes()).all(|(x, y)| fold(x) == fold(y))
    }

Exactly equivalent (the old `norm` maps byte-for-byte, so equal normalized vectors implies equal lengths). No new symbols, no doc-link churn, and `wire::header_name_eq_is_case_and_underscore_insensitive` (wire.rs:1487) plus tests.rs:7058 pin the behaviour unchanged.

**Rectification du vérificateur.** Fix is correct and zero-risk, but the impact is overstated on three counts. (1) It is not "the single hottest loop in the proxy": it runs per header per request, never per byte. (2) `injections.iter().any(..)` short-circuits on an empty slice, so requests to hosts with no credential injection make ZERO calls — src/sandbox/proxy/cleartext.rs:236 passes `&[]` unconditionally, and forward.rs:382/426/431/483 pass the host-scoped `injected` set, empty for non-target hosts. The cost only exists for injection-target hosts. (3) src/plugins/signer.rs:234 and :289 are manifest-validation paths (`validate` / `check_header_list`), run once at plugin load, not per request — listing them under a per-request claim is misleading. Net win is ~26 small malloc/free pairs on a request that already paid for a TLS handshake and several syscalls: worth taking because the diff is three lines and provably equivalent, not because it is measurable.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every cited site checks out. src/sandbox/proxy/wire.rs:20-33 is verbatim the quoted body (`let norm = |s: &str| -> Vec<u8> { s.bytes().map(...).collect() }; norm(a) == norm(b)`). Call sites confirmed: src/sandbox/proxy/mod.rs:1352 inside the `for (k, v) in &head.headers` loop of `reserialize_request` (fn at mod.rs:1330); src/sandbox/proxy/websocket.rs:792 inside the same loop in `reserialize_upgrade` (fn at websocket.rs:777); src/sandbox/proxy/h2mitm.rs:479 inside `for (name, value) in parts.headers.iter()`; src/sandbox/proxy/h2mitm.rs:781 inside `strip_request_trailers`'s `for (name, value) in trailers`. The proposed replacement is exactly equivalent: `norm` is a byte-for-byte `map`, so normalized length equals input length and equal normalized vectors implies `a.len() == b.len()`. No secret material is compared here (only header names, per src/plugins/signer.rs:225-234 and src/sandbox/proxy/inject.rs:697), so the early-exit introduces no timing concern. Cargo.toml:67-78 does document the deliberate absence of a `#[global_allocator]`. Behaviour is pinned by src/sandbox/proxy/wire.rs:1487-1492 and src/sandbox/proxy/tests.rs:7058-7062, both of which the rewrite leaves passing.

</details>

---

### D39 — FramedBody allocates and frees a fresh Vec per chunk-size line AND per chunk-closing CRLF — two mallocs per chunk of every chunked/SSE response

| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/proxy/wire.rs:746` |
| **Autres sites** | src/sandbox/proxy/wire.rs:805, src/sandbox/proxy/wire.rs:828, src/sandbox/proxy/wire.rs:841 |
| **Catégorie** | `allocation` |
| **Balayage** | Optimisation — chemin de données par octet |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** `framing_line` starts from an empty Vec every time (wire.rs:746-756):

    fn framing_line(&mut self) -> (Vec<u8>, bool) {
        let mut line = Vec::new();
        let complete = match (&mut self.inner)
            .take(CHUNK_LINE_MAX + 1)
            .read_until(b'\n', &mut line)
        { Ok(0) | Err(_) => false, Ok(_) => line.len() as u64 <= CHUNK_LINE_MAX && line.ends_with(b"\n") };
        (line, complete)
    }

and the state machine installs it over `self.pending`, dropping (freeing) the buffer that was just cleared at wire.rs:768:

        BodyState::ChunkSize => {
            let (line, complete) = self.framing_line();
            ...
            self.pending = line;                         // wire.rs:805 — frees the cleared old Vec
        }
        BodyState::ChunkCrlf => {
            ...
            self.pending = crlf[..n].to_vec();           // wire.rs:828 — a 2-byte heap allocation
        }
        BodyState::ChunkTrailers => {
            let (line, complete) = self.framing_line();
            ...
            self.pending = line;                         // wire.rs:841
        }

The drain path at wire.rs:767-769 already does `self.pending.clear(); self.at = 0;`, retaining capacity — which is then thrown away by the very next assignment.

**Coût.** One full ChunkSize -> ChunkData -> ChunkCrlf cycle runs per chunk of every `Transfer-Encoding: chunked` response, and costs 2 mallocs + 2 frees. This is exactly the streaming-agent path this proxy exists to carry: an SSE completion frames one chunk per event, so a several-minute stream at 30 events/s is ~10k allocation pairs for framing bytes that never exceed a few dozen bytes; a 100 MB chunked download with 8 KiB chunks is ~25k pairs. FramedBody is on all three inspected planes (tunnel.rs:868, forward.rs:582, websocket.rs:865).

**Correction proposée.** Read into `self.pending` instead of into a new Vec, using the take-and-return dance to satisfy the borrow checker. Change `framing_line` to `fn framing_line(&mut self) -> bool` (returning only `complete`):

    fn framing_line(&mut self) -> bool {
        let mut line = std::mem::take(&mut self.pending);   // keeps the grown capacity
        line.clear();
        let complete = match (&mut self.inner).take(CHUNK_LINE_MAX + 1).read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => false,
            Ok(_) => line.len() as u64 <= CHUNK_LINE_MAX && line.ends_with(b"\n"),
        };
        self.pending = line;
        self.at = 0;
        complete
    }

Then at wire.rs:796-806 and 830-842 read the line back off `self.pending` (`parse_chunk_size(&self.pending)`, `strip_eol(&self.pending).is_empty()`) — disjoint-field borrows against `self.state = ...` are fine under NLL — and drop the `self.pending = line;` lines. At wire.rs:828 replace `self.pending = crlf[..n].to_vec();` with `self.pending.clear(); self.pending.extend_from_slice(&crlf[..n]);`. Reaching the state machine already guarantees `pending` is drained (the `self.at < self.pending.len()` branch at wire.rs:763 returns first), so nothing unread is discarded. After the first chunk the relay is allocation-free per chunk.

**Rectification du vérificateur.** Facts and fix are right; the severity is not. This is per-chunk, not per-byte: two ~8-byte allocations per chunk. The quoted 30-event/s SSE stream costs 60 malloc/free pairs per second — single-digit microseconds per second of streaming, invisible next to the TLS record work and the write syscall on the same path. Two caveats the report omits. (a) ChunkTrailers (wire.rs:841) runs once per body plus one per trailer line, not per chunk, so the per-chunk count is 2 (ChunkSize + ChunkCrlf), as the title says but the also_at list blurs. (b) With the fix `self.pending` retains its grown capacity for the FramedBody's life, bounded by CHUNK_LINE_MAX + 1 = 8 KiB + 1 (wire.rs:362); in practice a chunk-size line is a handful of bytes, and a line that ever approaches the bound degrades the state to ToEof/Done and ends the framing, so the retention is not a real memory cost — but it should be stated, since the buffer's doc comment at wire.rs:706-708 explicitly reasons about that bound. Weigh the micro-win against turning a small, obviously-correct framing state machine into one whose correctness depends on an unstated "pending is drained here" invariant.

<details>
<summary>Preuve retenue par le vérificateur</summary>

All four cited lines are exact. src/sandbox/proxy/wire.rs:746 `fn framing_line(&mut self) -> (Vec<u8>, bool)` opens with `let mut line = Vec::new();` (747); wire.rs:805 `self.pending = line;` in `BodyState::ChunkSize`; wire.rs:828 `self.pending = crlf[..n].to_vec();` in `BodyState::ChunkCrlf`; wire.rs:841 `self.pending = line;` in `BodyState::ChunkTrailers`. The drain path at wire.rs:763-771 does `self.pending.clear(); self.at = 0;` and returns, so the retained capacity is indeed discarded by the next assignment. The fix's stated precondition holds: the only route into the state machine is past `if self.at < self.pending.len()` (wire.rs:763), which always returns, and the clear at 768 pairs with `self.at = 0`, so on entry `pending` is empty and `at` is 0 — nothing unread is dropped by `mem::take` + `clear`. The `clear()` before `read_until` is load-bearing and the fix includes it: the bound check at wire.rs:753 (`line.len() as u64 <= CHUNK_LINE_MAX`) is a length test on the buffer, so a non-cleared reuse would corrupt it. Disjoint-field borrows (`parse_chunk_size(&self.pending)` then `self.state = ..`) are fine under NLL. FramedBody is instantiated on all the relaying planes: tunnel.rs:868, forward.rs:582, websocket.rs:865, cleartext.rs:290.

</details>

---

### D40 — Each HTTP/1.1 response head is parsed into owned Strings two or three times per response

| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/proxy/wire.rs:503` |
| **Autres sites** | src/sandbox/proxy/wire.rs:558, src/sandbox/proxy/mod.rs:1470, src/sandbox/proxy/mod.rs:1476, src/sandbox/proxy/tunnel.rs:895, src/sandbox/proxy/forward.rs:603 |
| **Catégorie** | `redundant-io` |
| **Balayage** | Optimisation — chemin de données par octet |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** `parse_head` (wire.rs:48-81) builds an owned `Head`: one String for the status line plus `k.trim().to_string()` and `v.trim().to_string()` per header (wire.rs:74). Both response readers call it on the same bytes:

    pub(super) fn response_framing(head: &[u8], request_method: &str) -> BodyFraming {   // wire.rs:503
        ...
        let Ok(parsed) = parse_head(head) else { return BodyFraming::ToEof; };            // wire.rs:511

    pub(super) fn response_keeps_alive(head: &[u8]) -> bool {                             // wire.rs:558
        let Ok(parsed) = parse_head(head) else { return false; };                         // wire.rs:559

and `relay_response_head` calls both, back to back, on one buffer (mod.rs:1469-1476):

        let framing = if final_head { response_framing(&head, request_method) } else { BodyFraming::ToEof };
        let persistent = final_head
            && matches!(client_leg, ClientLeg::MayReuse { .. })
            && response_keeps_alive(&head)

Then, after the body relay, both pooled planes ask the SAME question about the SAME bytes a third time. tunnel.rs:894-896:

        if position_known
            && response_keeps_alive(&resp_head)
            && let (Some(pool), Some(key)) = (ctx.pool.as_ref(), pool_key)

forward.rs:601-604:

        if ended_as_framed
            && no_residual
            && response_keeps_alive(&resp_head)
            && let (Some(pool), Some(key)) = (ctx.pool.as_ref(), pool_key)

**Coût.** Once per relayed HTTP/1.1 response, on both the tunneled and absolute-form planes. A 15-header response head costs ~31 String allocations plus the Vec growth per parse; three parses is ~110 allocations and three full copies of the head text where 36 and one would do. On a pooled connection serving many small API calls this is the dominant per-response heap cost outside the body relay.

**Correction proposée.** Parse once and pass the parsed head down. In wire.rs add `pub(super) fn response_framing_of(parsed: Option<&Head>, head: &[u8], request_method: &str) -> BodyFraming` and `pub(super) fn response_keeps_alive_of(parsed: Option<&Head>) -> bool` holding the current bodies (with `None` meaning "the head would not parse", i.e. `ToEof` / `false`), and keep `response_framing` / `response_keeps_alive` as one-line wrappers `..._of(parse_head(head).ok().as_ref(), ..)` so websocket.rs:863, bench.rs:363 and every wire.rs/tests.rs caller and every existing ``[`response_framing`]`` / ``[`response_keeps_alive`]`` intra-doc link stay valid. In `relay_response_head` (mod.rs:1450) do `let parsed = parse_head(&head).ok();` once and feed both. Add `upstream_keeps_alive: bool` to `RelayedHead` (mod.rs:1508), set from that same parse, and have tunnel.rs:895 and forward.rs:603 destructure and read the field instead of calling `response_keeps_alive(&resp_head)`. Note `response_framing`'s early `BodyFraming::Empty` return (wire.rs:505-510) must stay ahead of the parse, so make the parse lazy at the call site or keep it in `relay_response_head` where the status is already known.

**Rectification du vérificateur.** The count is overstated. Three parses only happen on the tunneled plane and only when the client leg is `ClientLeg::MayReuse` — mod.rs:1475-1476 short-circuits `response_keeps_alive` behind `matches!(client_leg, ClientLeg::MayReuse { .. })`, and forward.rs:544 passes `ClientLeg::Close` unconditionally, so the absolute-form plane parses twice, not three times. cleartext.rs:282 also passes `ClientLeg::Close` and never asks about keep-alive at all, so it parses once. Additionally `response_framing` returns `BodyFraming::Empty` at wire.rs:509 before any parse for HEAD/204/304/1xx, so those responses parse fewer times still. Cost is one head parse (~35 small allocations) avoided per response — real, but calling it "the dominant per-response heap cost" is unsupported. Weigh that against the fix's cost: two new `pub(super)` entry points whose signature (`parsed: Option<&Head>` *plus* the raw `head` bytes, because `parse_status_code` at wire.rs:504 must run before the parse) is uglier than what it replaces, plus a new `RelayedHead` field that must now be computed unconditionally where today it is short-circuited away on `ClientLeg::Close`. The `upstream_keeps_alive` field alone (dropping the `_of` wrappers, keeping `response_framing`/`response_keeps_alive` untouched) captures most of the win for a fraction of the churn.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every cited line is exact. `parse_head` at src/sandbox/proxy/wire.rs:46 allocates `request_line.to_string()` (wire.rs:52) plus `k.trim().to_string()`/`v.trim().to_string()` per header (wire.rs:74). `response_framing` is wire.rs:503 with `let Ok(parsed) = parse_head(head)` at wire.rs:511; `response_keeps_alive` is wire.rs:558 with its `parse_head` at wire.rs:559. `relay_response_head` (mod.rs:1446) calls both back to back on the same buffer at mod.rs:1470 and mod.rs:1476. The post-body third question is real: tunnel.rs:894-896 `if position_known && response_keeps_alive(&resp_head) && let (Some(pool), Some(key)) = ..` and forward.rs:601-604, both reading `resp_head` destructured straight out of `RelayedHead` (tunnel.rs:802-807, forward.rs:531-535), i.e. byte-identical to the buffer `relay_response_head` already parsed. The fix is behaviour-preserving: the value is a pure function of those same bytes at the same point in the exchange, and `RelayedHead.head` is documented (mod.rs:1511-1513) as the upstream's head exactly as it arrived, so a field derived from it does not blur the ClientLeg seam (which is about not relaying the upstream's answer to the client — `persistent` stays separate). Adding a field is safe: all three destructures (tunnel.rs:806, forward.rs:534, cleartext.rs:272) already use `..`.

</details>

---

### D41 — find_head_end scans the entire captured response buffer byte-at-a-time for "\n\n" even after the CRLF pair is found, with memchr already a dependency

| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/proxy/capture.rs:430` |
| **Catégorie** | `algorithmic` |
| **Balayage** | Optimisation — chemin de données par octet |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** capture.rs:430-442:

    fn find_head_end(bytes: &[u8]) -> Option<(usize, usize)> {
        let crlf = bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|i| (i, 4));
        let lf = bytes.windows(2).position(|w| w == b"\n\n").map(|i| (i, 2));
        match (crlf, lf) {
            (Some(c), Some(l)) => Some(if c.0 <= l.0 { c } else { l }),
            ...

The two searches are independent and both run to completion. `position()` on the CRLF search stops at the first hit (~200 bytes into a normal head), but the `\n\n` search finds nothing in a well-formed head, so it walks the WHOLE buffer with a two-byte slice compare per offset. `bytes` here is the response sink, sized `caps.head + caps.body` = 32 KiB + `body_kb` KiB (capture.rs:222, control/capture.rs:132-137), i.e. 40 KiB at the default `CAPTURE_BODY_KB_DEFAULT = 8` and up to 1056 KiB at `CAPTURE_BODY_KB_MAX = 1024`. `memchr` is already in Cargo.toml (line 65) and already used for the needle finders (inject.rs:358).

**Coût.** Once per captured exchange, when `[capture]` is on. A full 40 KiB (default) to 1 MiB (max) byte-at-a-time scan whose answer is known after the first few hundred bytes. On a busy agent session with capture enabled that is tens of megabytes of pointless scanning per minute, entirely in the filing path.

**Correction proposée.** Bound the LF search by the CRLF hit and use the SIMD searcher:

    fn find_head_end(bytes: &[u8]) -> Option<(usize, usize)> {
        let crlf = memchr::memmem::find(bytes, b"\r\n\r\n").map(|i| (i, 4));
        // Only an LF pair strictly before the CRLF pair can win the `c.0 <= l.0` tie-break, so the
        // second search need not look past it (+1 so a pair straddling that offset is still seen).
        let upto = crlf.map_or(bytes.len(), |(i, _)| (i + 1).min(bytes.len()));
        memchr::memmem::find(&bytes[..upto], b"\n\n")
            .map(|i| (i, 2))
            .or(crlf)
    }

Identical result: the original prefers `crlf` on a tie and otherwise takes the smaller offset, which is what `or(crlf)` over a strictly-earlier LF hit gives. The tests at capture.rs:445+ that exercise `split_response` cover both separators unchanged.

**Rectification du vérificateur.** Correct finding, inflated impact. Capture is opt-in and off by default (`CaptureLevel::Off` is `#[default]`, src/sandbox/control/capture.rs:43-46), so this costs nothing unless `[capture]` is set; under `headers` the sink is 32 KiB, under `bodies` 40 KiB by default. It runs once per exchange in `file()`, not per read, and the scan terminates early on the traffic sbx mostly carries: an SSE response body separates events with `\n\n`, so the LF search hits a few hundred bytes into the body rather than walking to the end. "Tens of megabytes of pointless scanning per minute" would need ~250 captured exchanges/second; the honest figure is a ~40 KiB scan (~10-15 us) per captured exchange on a non-SSE response, and up to 1 MiB only for an operator who raised `body_kb`. The fix is still worth taking — it is six lines, behaviour-identical, and uses a dependency already in the tree — but it is a tidy-up, not a throughput fix.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every cited site checks out. /home/user/ops-cli/src/sandbox/proxy/capture.rs:430-442 is exactly the quoted function (431-434 the `windows(4).position(|w| w == b"\r\n\r\n")`, 435 the unbounded `windows(2).position(|w| w == b"\n\n")`, 436-441 the tie-break). The two searches are independent and the LF one is unbounded, so on a well-formed CRLF head with no `\n\n` in the captured prefix it walks the whole buffer. Buffer sizing is as described: capture.rs:222 `response: Arc::new(CapBuf::new(caps.head + caps.body))`, src/sandbox/control/capture.rs:131-138 `head: CAPTURE_HEAD_MAX` (=32*1024 at capture.rs:99) plus `(body_kb.min(CAPTURE_BODY_KB_MAX)) * 1024`, with CAPTURE_BODY_KB_DEFAULT=8 (capture.rs:89) and CAPTURE_BODY_KB_MAX=1024 (capture.rs:95). memchr is a real dependency (Cargo.toml:65) already used at src/sandbox/proxy/inject.rs:358/392, and find_head_end is the only production head-end scanner in the file, so no existing helper is being ignored. I checked the proposed bound by hand and it is result-identical: an LF pair can only beat the CRLF hit when strictly earlier (the original prefers `crlf` on a tie via `c.0 <= l.0`), the `+1` keeps a pair straddling the offset visible, and with `crlf == None` the slice is the whole buffer so the (None, Some) and (None, None) arms are unchanged. The caller is src/sandbox/proxy/capture.rs:349-360 (`file()`, idempotent behind `filed.swap`), i.e. once per exchange — real, but not per byte.

</details>

---

### D42 — redact_named rebuilds the whole output buffer once per needle even when the needle does not occur

| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/redact.rs:88` |
| **Catégorie** | `allocation` |
| **Balayage** | Optimisation — chemin de données par octet |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** redact.rs:88-105:

    let mut out = buf.to_vec();
    let mut count = 0;
    for needle in order {
        let len = needle.as_bytes().len();
        let replacement = placeholder.render(needle.name()).into_bytes();
        let mut next = Vec::with_capacity(out.len());
        let mut i = 0;
        while let Some(at) = needle.find_in(&out, i) {
            next.extend_from_slice(&out[i..at]);
            next.extend_from_slice(&replacement);
            i = at + len;
            count += 1;
        }
        next.extend_from_slice(&out[i..]);
        out = next;
    }

With N needles the buffer is allocated and copied N+1 times regardless of whether anything matched: on the (usual) no-match iteration, `find_in` returns `None` immediately, and the loop still allocates `next` at full size, copies the whole of `out` into it, and frees the old `out`. `placeholder.render(..)` (redact.rs:54-59) also allocates a String per needle whether or not it is used.

**Coût.** Called once per completed task on the task's whole stdout and stderr (task.rs:883-884), plus per error message and per notification (task.rs:875, 959-960, notify_sink.rs:590-591, signer_control.rs:148, launch.rs:711). A task producing 8 MB of stdout under a launch with 5 needles copies 48 MB where 8 MB would do, and the common case is that none of the five occurs at all.

**Correction proposée.** Guard the rebuild on a match and move the placeholder render inside it:

    for needle in order {
        let Some(first) = needle.find_in(&out, 0) else { continue };
        let len = needle.as_bytes().len();
        let replacement = placeholder.render(needle.name()).into_bytes();
        let mut next = Vec::with_capacity(out.len());
        let mut i = 0;
        let mut at = Some(first);
        while let Some(hit) = at { ... at = needle.find_in(&out, i); }
        ...
    }

(or, minimally, `if needle.find_in(&out, 0).is_none() { continue; }` before the `replacement`/`next` lines, accepting one redundant search on the matching path). The `while let` walk, the longest-first ordering and the non-overlapping semantics are untouched, and the empty-needle termination property still comes from `find_in` declining it (inject.rs:469), so `an_empty_needle_is_declined_rather_than_matching_everywhere` (redact.rs:189) still holds — `continue` is reached for it instead of an empty rebuild.

**Rectification du vérificateur.** Impact numbers are wrong by two orders of magnitude. The streams are not unbounded: `task.max_output` caps captured output per stream (src/config/types.rs:755-757), the built-in default is 64 KiB (src/config/tasks.rs:124), and `redact_named` runs on that capped buffer plus a scan margin (src/sandbox/task.rs:863-870, 883-892). So the default cost is ~64 KiB copied N+1 times per stream, once per task invocation — next to a process spawn and a sandbox setup, invisible. The 8 MB example is only reachable if an operator sets `max_output = "8MiB"` (`parse_output_cap`, src/config/tasks.rs:1005-1030, imposes no ceiling). Also note the fix sketch's `while let Some(hit) = at { ... }` restructure is muddled as written; the "minimal" variant the claim itself offers — `if needle.find_in(&out, 0).is_none() { continue; }` placed before the `replacement`/`next` lines, at the cost of one redundant search on the matching path — is the correct and reviewable form, and it also moves the per-needle `Placeholder::render` allocation onto the matching path only.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Verified line for line. /home/user/ops-cli/src/sandbox/redact.rs:88-105 is exactly as quoted: `out = buf.to_vec()` at 88, then per needle a `placeholder.render(..).into_bytes()` at 92 and a `Vec::with_capacity(out.len())` at 93 that is filled and swapped in at 103-104, unconditionally — a no-match needle still allocates, copies the whole buffer and frees the old one, and `Placeholder::render` (redact.rs:52-59) allocates a String either way. Callers are as cited: src/sandbox/task.rs:883-884 (`redact_named` over `raw.stdout`/`raw.stderr`), task.rs:875, task.rs:959-960, src/sandbox/notify_sink.rs:590-591, src/sandbox/signer_control.rs:148, src/sandbox/launch.rs:711. The `continue` guard is behaviour-preserving: `find_in` (src/sandbox/proxy/inject.rs:467-473) is the only search used, so a needle it declines contributes nothing to `out` or `count` today either; the longest-first sort at redact.rs:85-86 and the non-overlapping walk are untouched; and the empty needle still reaches `continue` instead of an empty rebuild, so `an_empty_needle_is_declined_rather_than_matching_everywhere` (redact.rs:188-197) still passes.

</details>

---

### D43 — Every launch reads and parses every egress rollup file to discover there is nothing to fold

| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/sandbox/launch.rs:3504` |
| **Autres sites** | src/sandbox/gc.rs:1298, src/sandbox/egress_stats.rs:508-540 |
| **Catégorie** | `redundant-io` |
| **Balayage** | Optimisation — lancement et entretien |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** `build` runs the counter fold on every launch:

  src/sandbox/launch.rs:3503  super::gc::sweep_runtime_dirs(prep.layout.data_dir(), true);
  src/sandbox/launch.rs:3504  super::gc::fold_egress_counters(prep.layout.data_dir(), true);

gc.rs:1298 forwards straight to `egress_stats::compact`, whose first pass reads and parses the *contents* of every candidate before it can group anything:

  src/sandbox/egress_stats.rs:517  if !name.starts_with("stats-") || name.contains(".tmp.") || !is_finished(&name) { continue; }
  src/sandbox/egress_stats.rs:520  let Ok(contents) = std::fs::read_to_string(entry.path()) else { continue; };
  src/sandbox/egress_stats.rs:523  let Some(session) = parse(&contents) else { continue; };

The already-folded rollups match that filter: `ROLLUP_PREFIX` is `"stats-rollup."` (egress_stats.rs:455), so it starts with `stats-`, and `is_finished` returns true for it unconditionally (egress_stats.rs:467-470). Each launch therefore reads and line-parses one rollup per (project, app) pair the user has ever launched, only to hit the no-op guard afterwards:

  src/sandbox/egress_stats.rs:538  if sources.len() == 1 && sources[0] == target { continue; }

**Coût.** Steady-state cost is P file reads + P line-parses per launch, where P is the number of distinct (project, app) pairs ever run and grows monotonically — it is never bounded down. Each rollup carries one tab-separated row per destination host (`parse`, egress_stats.rs:375-410), so a heavy allowlist makes each read hundreds of lines. For 30 projects that is 30 opens/reads/closes plus thousands of parsed lines on the critical path of every `sbx run`, in the overwhelmingly common case where nothing is foldable.

**Correction proposée.** Restructure `compact` (egress_stats.rs:508-557) into two passes so it reads only what can matter. Pass one iterates the directory entries by NAME only and collects the finished non-rollup files (`name.starts_with("stats-") && !name.starts_with(ROLLUP_PREFIX) && !name.contains(".tmp.") && is_finished(&name)`); if that list is empty, return `Vec::new()` before any `read_to_string`. Pass two reads and parses exactly those files, builds `groups` as today, and then for each group key reads the single `egress_dir.join(rollup_name(&project, app.as_deref()))` target (when it exists) and merges it into the tally before `write_rollup`. Behaviour is identical: today's `sources.len() == 1 && sources[0] == target` case is simply never reached, because no session file put that group in the map. The `folded` return and the dry-run branch at 542-544 are unchanged.

**Rectification du vérificateur.** Correct, but the impact is inflated. These are a handful of few-hundred-byte files read with `read_to_string` and split on newlines, on a code path that in the same function forks nix to provision packages, seeds a per-project store and spawns bwrap — 30 opens and a few thousand `str::split('\t')` calls is microseconds against that, not a meaningful contribution to launch latency. The honest framing is tidiness plus an unbounded-per-launch pattern, not a latency defect. One behaviour delta the fix should acknowledge: today a rollup whose parsed `project=`/`app=` no longer hashes to its own filename gets re-homed into the correct target and deleted; under the name-only first pass it is never read, so it would linger. That is only reachable if `rollup_name` (egress_stats.rs:485-494) ever changes its hash input, but it is a self-healing property the current shape has and the restructure gives up.

<details>
<summary>Preuve retenue par le vérificateur</summary>

All sites verified. src/sandbox/launch.rs:3503-3504 are the two housekeeping calls in `build`, src/sandbox/gc.rs:1298-1300 forwards `fold_egress_counters` straight to `egress_stats::compact`, and `compact` at src/sandbox/egress_stats.rs:508 filters by name at 517, then reads at 520 and parses at 523 before grouping. The filter really does admit rollups: `ROLLUP_PREFIX` is `"stats-rollup."` (egress_stats.rs:455) so it satisfies `starts_with("stats-")`, and `is_finished` returns true for it unconditionally (egress_stats.rs:467-470). The no-op guard is at egress_stats.rs:538, after the read. `parse` (egress_stats.rs:375-415) is a per-line scan of the whole file. The proposed two-pass restructure is behaviour-preserving and survives the existing tests unchanged: folding_finished_sessions_preserves_every_counter (691-723) has no pre-existing rollup, a_running_sessions_file_is_never_folded (726-748) is unaffected by a name-only first pass, and folding_twice_leaves_one_file_and_no_churn (752-767) hits the new early return and still gets an empty result.

</details>

---

### D44 — `sbx path` re-implements the current-project-id and live-session-id helpers `sbx projects` already owns

| | |
|---|---|
| **Gravité** | Faible |
| **Emplacement** | `src/paths.rs:365` |
| **Autres sites** | src/sandbox/projects.rs:153-157, src/paths.rs:377-384, src/sandbox/launch.rs:1853-1880 |
| **Catégorie** | `duplication` |
| **Balayage** | Optimisation — lancement et entretien |
| **Statut** | confirmé par vérification contradictoire (confiance : haute) |

**Constat.** Two byte-identical helpers, differing only in the module path to `project_id`:

  src/paths.rs:365       fn current_project_id() -> Option<String> {
  src/paths.rs:366           let cwd = std::env::current_dir().ok()?;
  src/paths.rs:367           let canonical = cwd.canonicalize().ok()?;
  src/paths.rs:368           Some(sandbox::project_id(&canonical))
  src/paths.rs:369       }

  src/sandbox/projects.rs:153  fn current_tree_id() -> Option<String> {
  src/sandbox/projects.rs:154      let cwd = std::env::current_dir().ok()?;
  src/sandbox/projects.rs:155      let canonical = cwd.canonicalize().ok()?;
  src/sandbox/projects.rs:156      Some(super::binds::project_id(&canonical))
  src/sandbox/projects.rs:157  }

And the live-set derivation is written twice as well:

  src/paths.rs:377  fn live_project_ids(data_dir: &Path) -> BTreeSet<String> {
  src/paths.rs:378      let Ok((live, _)) = session::Registry::at(data_dir).housekeep() else { return BTreeSet::new(); };
  src/paths.rs:381      live.iter().map(|s| sandbox::project_id(&s.project)).collect()

  src/sandbox/launch.rs:1856  match session::Registry::at(layout.data_dir()).housekeep() {
  src/sandbox/launch.rs:1872      live.iter().map(|s| binds::project_id(&s.project)).collect()

launch.rs's `session_housekeeping` differs only by emitting a `diag::note` when it pruned and a `diag::error` on failure; projects.rs:164 already calls it. Both pairs feed the same downstream consumer — `classify_tree(&path, live_ids)` at paths.rs:487 and projects.rs:174.

**Coût.** Three call sites must agree on how a project id is derived from a cwd and on what counts as a live session. A change to `project_id`'s input (normalising a trailing component, reading the cwd through `$PWD`) has to land in two places or `sbx path` starts marking the wrong tree `*` while `sbx projects` marks the right one. The duplicated `live_project_ids` also silently drops the pruned-record notice every other reclaiming caller emits.

**Correction proposée.** Move the cwd->id derivation next to its siblings in src/sandbox/binds.rs (beside `project_id` at 1369 and `project_identity` at 1391) as `pub(crate) fn current_project_id() -> Option<String>`; re-export it from src/sandbox/mod.rs:127 alongside `project_id, project_identity`; delete both bodies (paths.rs:365-369, projects.rs:153-157) and call it. For the live set, delete `paths::live_project_ids` (377-384) and call `crate::sandbox::launch::session_housekeeping(layout)` from `view` — it already takes a `&Layout`, which `view` has at paths.rs:295 — widening it from `pub(super)` to `pub(crate)`. Its doc at launch.rs:1850-1852 lists its callers; add `sbx path` there.

**Rectification du vérificateur.** Real but overstated, and the fix is only half right.

(a) The id helper: agreed it is duplicated, but binds.rs is the wrong home. `grep -n 'current_dir()' src/sandbox/binds.rs` returns nothing — every binds.rs entry point takes an explicit `cwd: &Path` (`home_src` 1363, `project_runtime_id` 1387, `project_identity` 1396, `build_spec` 1492) precisely so the launch path passes `prep.cwd` rather than ambient state. Dropping an ambient-cwd reader beside `project_identity` is an attractive nuisance in the one module that must not read the environment. Make it `pub(super) fn current_tree_id()` in src/sandbox/projects.rs (where it already lives) and call it from paths.rs, or leave it: this is a 4-line best-effort helper, and `std::env::current_dir()` is already open-coded ~20 times across src/cli/ (app.rs:634, config.rs:161, net.rs:1118, plugins.rs:691, proc.rs:73, …), so unifying two of them buys little.

(b) The live-set helper: the fix is not the drop-in it claims. `view` (src/paths.rs:290) takes `Option<&Layout>`, not `&Layout`, and — more importantly — the `live_project_ids` call is not in `view` at all, it is at src/paths.rs:316 inside `view_with_roots`, documented at 300-304 as the test seam that deliberately takes bare `Option<PathBuf>` roots so unit tests need no `Layout`. Hoisting the call into `view` changes that signature and all seven test call sites (708, 744, 837, 853, 869, 938, 1017). And `session_housekeeping`'s failure arm hardcodes its own verb: src/sandbox/launch.rs:1877-1879 emits `"sbx gc: cannot read the session registry ..."`, so `sbx path` would start attributing an error to `sbx gc`. That message must be parameterised (or reworded) before any second caller is added. The "silently drops the pruned-record notice" framing is also unfair: src/paths.rs:377-381 explicitly reasons about the pruning side effect and its read-only stance, so the absence of the note is a considered position, not an oversight.

<details>
<summary>Preuve retenue par le vérificateur</summary>

Every citation checks out. src/paths.rs:365-369 `fn current_project_id()` and src/sandbox/projects.rs:153-157 `fn current_tree_id()` are byte-identical apart from `sandbox::project_id` (the re-export at src/sandbox/mod.rs:127) vs `super::binds::project_id`. src/paths.rs:377-384 `live_project_ids` and the `Ok((live, pruned))` arm of `session_housekeeping` at src/sandbox/launch.rs:1854-1875 both end in `live.iter().map(|s| project_id(&s.project)).collect()`; consumers agree too (src/paths.rs:487 vs src/sandbox/projects.rs:174, both `classify_tree(dir, live_ids)`). No comment anywhere marks either restatement as deliberate, and paths.rs already depends on `crate::sandbox` (src/paths.rs:22), so there is no layering objection. The duplication is genuine; only the proposed remedy needs correcting.

</details>

---

