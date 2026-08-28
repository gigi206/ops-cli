# Plan de refactoring — arbitrage des propositions

Douze analystes ont chacun proposé un découpage pour un module surdimensionné, sans se
consulter. Un dernier analyste, l'architecte, a reçu les douze propositions avec pour mandat de
les **arbitrer** : rejeter celles qui dissoudraient une couture délibérée, trouver les conflits
entre elles, les ordonner en une séquence exécutable où chaque étape laisse l'arbre vert, et
dire lesquels des modules doivent rester intacts. Il lui était demandé de vérifier les
propositions contre le code réel et de rejeter celles dont la structure citée ne correspondait
pas au fichier.

## Évaluation d'ensemble

Better factored than the line counts suggest; the proposals collectively overstate the problem by roughly half.

WHAT IS GENUINELY WELL DONE. The seams that matter are already cut and documented in prose, not folklore: Spec->argv is isolated; src/sandbox/projects.rs is kept out of launch on a stated criterion ("shares no state with the launch pipeline") precise enough to reuse as a test for other candidates; allowlist/grammar.rs says outright "the matching itself lives in [super]"; config/overrides.rs:45-48 names the boundary it refuses to cross; config/manage.rs rules_in explains why it is paired with remove_rule_from rather than filed with the readers. The guard suite is strong and doing real work: two non-recursive source scanners over src/cli (cli/mod.rs:966, help.rs:3727) that catch a dispatcher written to a new idiom; a docs-coverage list whose staleness half fails as loudly as its missing half (docs_coverage.rs:1082-1092); a fixture sweep asserting its own preconditions (testutil.rs:604-607). Several of the largest functions are correctly large -- build, run_admitted, cage_mounts, serve_tunneled_request, resolve, resolve_app are linear assemblies whose ordering is the security property, and six of the twelve engineers said so unprompted and declined to carve them.

WHAT IS NOT, in descending cost.

(1) About 40% of the "oversized module" problem is inline test modules, and the crate already has the fix in three places (proxy/mod.rs:2059, config/mod.rs:5841, openpgp/mod.rs:438), with docs_coverage.rs:995-997 skipping tests.rs / *_tests.rs whole. launch 2,708 lines of tests, proc_enforce 2,809, task+task_control 4,116, binds 2,968, allowlist 2,348 -- roughly 15,000 lines that can leave the production files at zero semantic cost. That nobody has done this is the largest single gap.

(2) A repeating documentation defect the guard was written for and is currently absorbing instead of catching. I verified four instances of the same failure -- a /// block severed from its item by a later insertion, so it renders on the wrong item and the intended one goes undocumented: config/mod.rs:503 (ResolvedApp's opening sentence swallowed into BundleProvision's doc), binds.rs:1460-1473 (build_spec's block sitting above write_atomic), allowlist/mod.rs:829-836 (EgressPolicy's paragraph rendering as Http2Host's; EgressPolicy at 955 has no doc at all), proxy/websocket.rs:965-979 (relay_websocket's doc AND its #[allow(clippy::too_many_arguments)] both landing on TunnelObservers, a struct). Three of the four are grandfathered in UNDOCUMENTED_MODULE_ITEMS (905, 857, 935) rather than fixed. The list's own doc says it can only shrink; it is not shrinking.

(3) Where duplication is real, it is in the two HTTP/1.1 proxy planes, and the proxy proposal's evidence is the best analysis in the set: three defects named in the codebase's own comments (forward.rs:83-89, h2mitm.rs:552-556, websocket.rs:786-789) each traced to a decision written out N times that drifted at one copy. That is a diagnosis worth acting on -- but not as part of a decomposition pass, for reasons in the ordering.

Sizes after step 2 alone, with no production code touched: launch 6,172; proc_enforce 2,940; task 2,320; binds 1,717; allowlist 1,741; task_control 1,741. Only launch is then still clearly oversized, and only it, proc_enforce, config/mod.rs and the two cli families genuinely warrant a directory.

## Conflits entre propositions

A. cli-config is wrong where cli-net is right, and only one of them looked. VERIFIED: both cli/mod.rs:966 (dispatch_heads) and help.rs:3727 (dispatched_alias_pairs) walk src/cli with a NON-recursive read_dir filtered to extension == "rs". cli-config proposes src/cli/config/mod.rs. config_cmd uses the scanned idiom verbatim (config.rs:30, `match args.first().and_then(|a| a.to_str()) {`) and ["config"] has child pages, so the assertion at cli/mod.rs:1113-1119 fails with "`sbx config` has subcommand pages but the scan found no dispatcher for it". cli-config asserts the opposite ("the split cannot fail it") because it checked docs_coverage and stopped. cli-net found the constraint and proposes the fix: keep src/cli/net.rs as the module root plus a src/cli/net/ directory. Resolution: cli-config adopts cli-net's shape; net lands first so the shape is precedent rather than argument. Verified safe for help-completion: completion_cmd does NOT use the idiom and ["completion"] has no child pages, so src/cli/completion/mod.rs is legal.

B. The same two proposals leave a latent hole neither fully owns. After net/ and completion/ exist, both scanners are structurally blind to two subtrees, and help.rs:3679 DISPATCHERS keys on bare filenames ("mod.rs"), which would collide across directories if the walk were made recursive. help-completion flagged the blindness; cli-net created it. Fix once, in the net step: make the walk recursive and key DISPATCHERS on the path relative to src/cli. Harmless today (I re-ran the scan: all 15 dispatcher pairs live in top-level files) and required before the third cli directory.

C. Three proposals each claim the test-module extraction as their own step one, and the ORDER between it and the production split is load-bearing in a way only two noticed. binds, task and allowlist all propose `#[cfg(test)] mod tests;`. allowlist states the dependency correctly: a child module sees its parent's private items, so tests extracted BEFORE a production split need no pub(super); tests extracted AFTER become siblings of the new modules and force widenings on every fixture they touch. Resolution: one cross-cutting extraction pass (step 2) covering all six files, landing before any production split, and each later step's pub(super) list is computed against sibling-tests.

D. Two proposals edit src/testutil.rs and only one sees the guard. launch promotes a test helper `resolved` there; test-suite consolidates 21 `struct TmpDir` declarations into 2. VERIFIED: testutil.rs:604-607 asserts `declaring >= 20` counting files containing the literal `struct TmpDir`, and there are exactly 21 today. The consolidation makes its own precondition fail. test-suite is right that the property survives (it becomes trivially true) and that the needle must be re-based, not the number lowered. Both edits land in step 3 so the guard is re-based once.

E. Nine docs_coverage keys are in flight across the plan and a partial rename fails the guard TWICE. Every entry is (src-relative path, item), so a file becoming a directory invalidates the key, and docs_coverage.rs:1082-1092 fails on a stale entry as well as on an undocumented item. Verified in-flight: 8 entries at proc_enforce.rs:920-927, 1 at task_control.rs:937, plus cli/completion.rs:861, config/view.rs:891, allowlist/mod.rs:857, storage.rs:940, binds.rs:905, proxy/websocket.rs:935. Three of those (905, 857, 935) should be DELETED in step 1 rather than re-keyed, because the underlying doc defect is fixable; completion.rs:861 likewise (write the missing /// on completion_cmd).

F. proxy-shape's exchange.rs collides with its own risk note. It proposes lifting ~200 lines shared by tunnel.rs and forward.rs, then concedes the move relocates about ten fail-closed refusal exits, in a directory whose own doc (mod.rs:1968-1983) calls the push_log/outcome split "the part most likely to drift under copying". Those two statements do not sit together in a decomposition pass. Resolution in the ordering: take the three small pieces, leave prepare_credentials to a dedicated change.

G. config-mod is a prerequisite for two later steps and none of the three says so. config-mod moves is_valid_app_name, is_valid_deb_url, is_valid_attr and six siblings behind pub(crate) use re-exports; cli-config's edit.rs and help-completion's values.rs both reach crate::config::* paths that only survive if those re-export lists are complete. Sequencing config/mod.rs before nothing that depends on it is not possible here (net and config come first for the shape), so the constraint is stated instead: the re-export lists are the contract, and the compiler enumerates every miss.

## Séquence proposée

| Étape | Effort | Périmètre |
|---|---|---|
| 1 | faible | config/mod.rs, binds.rs, allowlist/mod.rs, proxy/websocket.rs, cli/completion.rs, docs_coverage.rs |
| 2 | moyen | sandbox/launch.rs, sandbox/proc_enforce.rs, sandbox/task.rs, sandbox/task_control.rs, sandbox/binds.rs, allowlist/mod.rs |
| 3 | important | tests/common/, src/testutil.rs, tests/run.rs, tests/config.rs, tests/net.rs, tests/app.rs, tests/plugins.rs |
| 4 | important | src/sandbox/launch.rs -> src/sandbox/launch/ |
| 5 | important | src/sandbox/proc_enforce.rs -> src/sandbox/proc_enforce/ |
| 6 | moyen | src/cli/net.rs + src/cli/net/, src/cli/mod.rs, src/help.rs |
| 7 | moyen | src/cli/config.rs + src/cli/config/ |
| 8 | moyen | src/config/mod.rs |
| 9 | faible | src/sandbox/binds.rs -> src/sandbox/binds/ |
| 10 | faible | src/help.rs -> src/help/ |
| 11 | moyen | src/sandbox/proxy/websocket.rs, tunnel.rs, forward.rs, h2mitm.rs |
| 12 | moyen | src/store.rs -> src/store/ |

### Étape 1 — config/mod.rs, binds.rs, allowlist/mod.rs, proxy/websocket.rs, cli/completion.rs, docs_coverage.rs

**Effort : faible**

**Action.** Repair the four severed doc blocks and shrink the grandfather list. Rejoin config/mod.rs:503 to 519-522 and leave BundleProvision's own doc at 504-510. Move binds.rs:1460-1473 down below write_atomic's closing brace to sit above build_spec at 1492, taking the // grouping comment with it. Cut allowlist/mod.rs:829-836 out of Http2Host's block and place it above EgressPolicy at 955. Move proxy/websocket.rs:965-979 and its #[allow(clippy::too_many_arguments)] down onto relay_websocket at 1041 (7 params, under clippy's threshold of 8, so drop the allow). Write the missing /// on completion_cmd (cli/completion.rs:48). Then DELETE four UNDOCUMENTED_MODULE_ITEMS entries: binds.rs:905, allowlist/mod.rs:857, websocket.rs:935, completion.rs:861.

**Pourquoi à ce rang.** Four proposals found this independently and each treated it as a footnote to its own split; it is the one finding common to all of them. It must precede every move: an item carried into a new file with its doc attached to the wrong neighbour carries the bug forward and hides it behind a re-keyed grandfather entry, and the staleness assertion at docs_coverage.rs:1082-1092 will force those keys to be touched anyway. Doing it as a standalone commit also proves the guard is live before nine keys go in flight.

---

### Étape 2 — sandbox/launch.rs, sandbox/proc_enforce.rs, sandbox/task.rs, sandbox/task_control.rs, sandbox/binds.rs, allowlist/mod.rs

**Effort : moyen**

**Action.** Extract every inline #[cfg(test)] module to a sibling file using the idiom already at proxy/mod.rs:2059, config/mod.rs:5841 and openpgp/mod.rs:438. Six files, plus two smoke modules: launch tests 6172-8880; proc_enforce open_path_tests 2941-3133 and tests 3134-5750; task tests 2996-4436 and mod smoke 2423-2994 (rename to smoke_tests.rs, which both hits the docs_coverage skip and clears the collision with the production sandbox::smoke re-exported at sandbox/mod.rs:178); task_control tests 1742-3844; binds tests and mod smoke (rename likewise, rewriting its three super::super:: prefixes to crate::sandbox::); allowlist tests. Declare each as a bare `#[cfg(test)] mod tests;` with NO outer /// (mise.toml:96-98 records that a doc comment on a mod declaration merges with the child's header and moves link resolution into the declaring module's scope). Re-key docs_coverage 920-927 and 937 only for files that become directories in later steps -- not here.

**Pourquoi à ce rang.** About 15,000 lines for zero production edits, zero visibility changes and zero doc-link changes: a tests.rs is still a child of its parent, so it keeps reaching every private item, and docs_coverage.rs:995-997 skips the file whole. This is the largest measurable improvement in the plan and the cheapest. Critically it must come BEFORE the production splits, not after: as the allowlist proposal correctly argues, tests extracted first stay descendants and need nothing, while tests extracted after a split become siblings of the new modules and force pub(super) on every fixture they touch. Every later step's visibility list in this plan is computed against sibling-tests.

---

### Étape 3 — tests/common/, src/testutil.rs, tests/run.rs, tests/config.rs, tests/net.rs, tests/app.rs, tests/plugins.rs

**Effort : important**

**Action.** Fill the empty tests/common/ (already #[macro_use]-ed by 16 suites and already carrying #![allow(dead_code)] for this case) with fixture.rs, cage.rs and session.rs. Collapse 21 struct TmpDir declarations to 2, 11 copies of force_remove to 1, five near-identical Fixture structs to one Project, and nine hand-rolled /proc/<pid>/stat field-22 parsers to one. Add probe_or_skip! and need_cache! macros for the 65-fold and 46-fold hand-written gate blocks in tests/run.rs, and adopt them at tests/run.rs:7495-7602 and 7616-7746 -- the two audio e2es that provision nix: packages with no reachability gate and go red rather than skip on a capable but offline host. Re-base testutil.rs:604-607 to count files that REACH a fixture tree rather than files declaring struct TmpDir, keeping the rule that any declarer must contain fixture_root() and rewriting the doc block at 493-516 to say what it now guards. Move the misfiled clusters: tests/config.rs:1714-2193 (plugin surface) to tests/plugins.rs, collapsing git_available/git_in against git_run; tests/run.rs:8561-8813 (sbx app rm, no skip macro, never launches) to tests/app.rs.

**Pourquoi à ce rang.** This is the only step in the plan that changes what is tested rather than where it lives -- the two ungated audio e2es are a real hole that exists precisely because the probe is retyped instead of called. It is also the only step whose guard interaction is subtractive, so it wants its own review. Doing it before the production splits keeps the integration suites stable while src/ moves underneath them, and settles the testutil.rs guard once instead of twice (see conflict D).

---

### Étape 4 — src/sandbox/launch.rs -> src/sandbox/launch/

**Effort : important**

**Action.** git mv to launch/mod.rs, then land the children one commit each in the proposal's own order (startup, session, detach, equip, roll, reclaim, cage, build), so each is independently reviewable. build moves WHOLE into build.rs -- all 1,728 lines, uncarved. Keep Prepared, the prepare* chain, the launch-mode decision, run/app/run_mise and the three provisioning primitives (prebuilt_ctx, mise_tools, seed_project_store) in mod.rs, where every child sees them for free. Re-export so that sandbox/mod.rs:141-145 and the nine external call sites (projects.rs:164/293/657/729, task.rs:1154/1221, taskpool.rs:512, resolver.rs:221, spec.rs:221) are untouched -- note session_housekeeping/shared_store_gc/seccomp_argv/status_code are pub(super) today meaning 'visible in sandbox' and must become pub(in crate::sandbox), not pub(super). Repoint the source-scanning test at 6415-6474 to iterate (mod.rs, detach.rs), and the include_str! in the wrap-nesting test to build.rs. Run mise run rustdoc after every child.

**Pourquoi à ce rang.** Largest file, best-argued proposal, and verified accurate -- I checked its cited ranges (Prepared@50, run@88, build@3477, attach@2609) and all nine cross-module call sites. It earns first place among the production splits because it applies the project's OWN stated criterion rather than a new one: sandbox/mod.rs:114-117 keeps projects out of launch because it 'shares no state with the launch pipeline', and attach/stop/gc/the two upgrade rolls meet that test exactly. It also goes first because its residue (build.rs at ~2,700 lines, the security-review surface as a file you open rather than a range you scroll to) is the honest floor, and establishing that a 2,700-line file can be the right answer sets the standard for the seven steps after it.

---

### Étape 5 — src/sandbox/proc_enforce.rs -> src/sandbox/proc_enforce/

**Effort : important**

**Action.** Split on the two-lens seam: open_lens.rs, open_serve.rs, cagepath.rs, target.rs, notify.rs, pending.rs, overlay.rs, report.rs, with the supervisor state machine (supervise/accept_handoff/recv_loop/handle_notif/close_supervision) and the exec decision staying whole in mod.rs. Land the three pure leaves first (notify, target, cagepath), then open_lens+open_serve together since the handle_open extraction is what makes both clean, then pending/overlay/report. Delete the dead section banner at line 192. Rewrite the three super::sanitize sites (1888, 2609, 2628) to crate::sandbox::sanitize. Re-key all eight docs_coverage entries at 920-927 in the same commit as the directory conversion.

**Pourquoi à ce rang.** The seam is exact rather than hopeful, and I verified the load-bearing claim: Deciding has seven fields and the entire open branch of handle_notif touches two of them, so the open half lifts behind one call with no back-reference to Deciding at all. It comes after launch because both convert a file to a directory and both re-key docs_coverage, and doing them back to back keeps the nine keys in one reviewer's head. Its self-rejection of an exec_decide.rs -- 126 lines needing a child->parent use super::Deciding, the one place layering would stop being one-way -- is the right instinct and should be honoured.

---

### Étape 6 — src/cli/net.rs + src/cli/net/, src/cli/mod.rs, src/help.rs

**Effort : moyen**

**Action.** Keep src/cli/net.rs as the module root (Rust-2018 style: net.rs beside a net/ directory, NOT net/mod.rs) holding net_cmd, net_pending, net_groups and write_session_header{,_line}; add children pending.rs, logs.rs, rules.rs, groups.rs, stats.rs, live.rs. net_cmd must stay at column 0 and keep the scanned match idiom or help.rs:3699 body_lines panics. Twelve entry points widen to pub(super); one cross-module rustdoc fix at net.rs:1365 (collect_pending -> super::pending::collect_pending). In the same commit, close the latent hole: make both walks recursive (cli/mod.rs:970, help.rs:3729) and key help.rs:3679 DISPATCHERS on the path relative to src/cli rather than a bare filename. Separately, collapse the interval parser at net.rs:1309-1321 onto crate::interval_seconds, which the file already imports and uses correctly twice.

**Pourquoi à ce rang.** This step exists as much to establish the shape as to split the file. It is the only proposal that found the two non-recursive scanners, and the shape it derives (module root stays a top-level .rs) is what makes step 7 legal at all. Doing the recursive-walk fix here, while the constraint is in view and while exactly one cli directory exists, is far cheaper than discovering it when a third one lands and the bare-filename DISPATCHERS keys start colliding.

---

### Étape 7 — src/cli/config.rs + src/cli/config/

**Effort : moyen**

**Action.** Take the cli-config proposal's CONTENT with cli-net's SHAPE: keep src/cli/config.rs as the module root holding config_cmd, config_show, config_show_app and config_usage (hoisted from the edit half); add children format.rs, render.rs, app_detail.rs, edit.rs. Do NOT create src/cli/config/mod.rs. Before splitting, do the fixture cleanup the proposal identifies: six tests re-inline the whole 110-line ConfigView literal that sample_config_view() already provides (4184, 4327, 4493, 4584, 4719, 4854), differing in about eight fields; rewriting them as mutate-the-fixture removes ~600 lines and takes render.rs from ~2,760 to ~2,160. Replace the four open-coded usage blocks in config_show (76-80, 105-110, 135-140, 152-157) with config_usage. Re-declare use crate::config; in render.rs and app_detail.rs or the two [config::view] links break under -D rustdoc::warnings.

**Pourquoi à ce rang.** It is the same shape as step 6 and directly downstream of it -- the proposal as submitted does not build, and the fix is the precedent step 6 just set. The fixture cleanup goes first within this step because it shrinks the piece that stays largest, and because doing it after the move means rewriting six tests across a new file boundary instead of within one. Explicitly NOT unified with net's write side: scope_is_gated and admit_config_write differ from open_rule_write on Scope::File and on when local_save_permitted is consulted, and both differences are argued in place (config.rs:2452-2470, main.rs:590-612).

---

### Étape 8 — src/config/mod.rs

**Effort : moyen**

**Action.** Take three of the seven proposed modules and defer the rest: apps.rs (AppHomeScope, ResolvedApp, resolve_apps, resolve_app and the four app-layer readers), tools.rs (the contiguous 4250-5014 declared-tool pipeline plus the charset validators and warn_mise_nix_packages), gate.rs (Gate, refuse_untrusted, untrusted_reason, TRUST_DROP_MARKER, is_trust_drop, dropped_binds_warning). Resolved::merge_app stays beside Resolved; fn resolve stays 954 lines and whole. Each is an independent, separately reviewable commit. The re-export lists are the contract -- pub(crate) use for the eight locator validators reached from sandbox/{deb,tarball,binary,appimage,prebuilt,nixhub}.rs and store.rs:1668, for is_valid_app_name (8 external sites), and for is_trust_drop/untrusted_reason -- plus private use lines so validate.rs, tests.rs, overrides.rs and view.rs keep resolving through use super::* and explicit super:: paths.

**Pourquoi à ce rang.** These three are independent of each other and of everything above, so they are the natural place to slow down if appetite runs out; they are also the three with the best ratio of clarity to diff. gate.rs is the standout: TRUST_DROP_MARKER's own doc says 'there is more than one producer: untrusted_reason phrases it one way and dropped_binds_warning another', yet those three items sit 430 lines apart. Deferring override_apply/plugin_config/broker/netgroups costs nothing -- the proposal is right that fn resolve stays 954 lines under every variant, so the file goes to ~2,450 not ~1,200, and the last four modules do not change that.

---

### Étape 9 — src/sandbox/binds.rs -> src/sandbox/binds/

**Effort : faible**

**Action.** After step 2 has already taken the tests out, add three small production children: runtime.rs (ProjectRuntime, Runtime, project_runtime, home_src, project_id, project_runtime_id, project_identity, canonicalize_project -- zero super::/crate:: references in the moved range), synthetic.rs (SHELL_RC_CONTENTS, the four *_contents producers, Identity, current_identity, materialize_etc, write_atomic), nesting.rs (Nesting, structural_nesting_conflict, structural_nesting_warning). cage_mounts stays whole and the in-cage destination constants stay beside it; STRUCTURAL_DESTS stays in mod.rs where the lockstep test at 1845 holds it against the mount list. hosts_contents is pub(super) today (= visible in sandbox, called from task.rs:1057) and must become pub(crate) for the re-export to be legal. Re-verify the proposal's line numbers before moving: its ranges drift 5-70 lines against the current tree.

**Pourquoi à ce rang.** Small and cheap after step 1 has already fixed the build_spec doc block that this split would otherwise force. Placed late deliberately: the honest gain is ~370 production lines for three files, and the tests extraction in step 2 already took binds from 4,685 to 1,717, which is no longer a problem file. Skip this step entirely without regret if the queue is long -- but do NOT take the tempting fourth module (a binds/toolchain.rs), because MISE_PROJECT_INCAGE and CAGE_CA_BUNDLE are cage destinations bound by cage_mounts and listed in STRUCTURAL_DESTS, and moving them separates a structural destination from the mount plan declaring it.

---

### Étape 10 — src/help.rs -> src/help/

**Effort : faible**

**Action.** Convert to help/mod.rs (safe -- the scanners walk src/cli, not src/help) with pages.rs (the 3,035-line PAGES catalogue, verbatim, gaining pub(super)), render.rs (item, paint_synopsis, paint_inline_code, top_level, render), and tests.rs. mod.rs keeps Page and Opt with all five fields PRIVATE -- a child module sees its parent's private fields, so all 104 struct literals compile untouched -- plus ALIASES, the query layer and the entry points. One intra-doc link to fix: help.rs:3092, where ALIASES's doc says 'Aliases stay out of [PAGES]', which mod.rs's own use pages::PAGES; restores. Do NOT shard PAGES by namespace.

**Pourquoi à ce rang.** The engine a reader needs starts at line 3127, after 81% of the file, and the whole split needs exactly one visibility change and one link fix. It sits here rather than earlier because it is the least urgent structural change in the plan -- nothing is broken, and 3,035 lines of flat data is a catalogue you grep, not a file you read. The namespace shard is rejected outright: it introduces the one failure mode this design does not have (a page group nobody aggregates), for a benefit the flat const already provides.

---

### Étape 11 — src/sandbox/proxy/websocket.rs, tunnel.rs, forward.rs, h2mitm.rs

**Effort : moyen**

**Action.** Two independent pieces. (a) Split websocket.rs's frame decoder into wsframe.rs -- FrameTee, LeakScan, Inflater, Inflated, Deflate, negotiated_deflate, HeaderScan, scan_frame_header and the three caps -- verified to have zero references outside websocket.rs, taking that file from 2,083 to ~740. (b) Take ONLY the three small deduplications the proxy proposal identifies and NOT prepare_credentials: masks_reflection (the identical three-line predicate at tunnel.rs:784, forward.rs:520, h2mitm.rs:580), note_final_status (the set_status + 401-refresh pair at tunnel.rs:848, forward.rs:566, h2mitm.rs:546 -- the exact decision h2mitm.rs:552-556 records as having drifted), and refuse_ws_into_injected_host (23 self-contained lines, tunnel.rs:253-276 == forward.rs:108-130).

**Pourquoi à ce rang.** The proxy directory is the best-factored code in the crate and needs no reorganisation; what it needs is for three specific copied decisions to stop being copies, and its own comments name the bugs each copy produced. These three are small, individually testable, and each removes a documented drift class. prepare_credentials is deliberately excluded -- it relocates roughly ten fail-closed refusal exits on the security path, in a module whose own doc (mod.rs:1968-1983) calls the push_log/outcome split 'the part most likely to drift under copying'. That is a change that deserves its own design review and its own week, not a slot in a decomposition plan.

---

### Étape 12 — src/store.rs -> src/store/

**Effort : moyen**

**Action.** Four children along the existing acyclic layering (layout <- engine, channel, provisioning; engine <- provisioning): layout.rs (Layout, the data-dir guards, ensure, physical_path), engine.rs (nix/nix-store/bwrap/git/proc-shim resolution and host_exec_verdict), channel.rs (Origin, LockTarget, the lock readers and the GitHub reachability witness), provisioning.rs (nix_command and the four provision entry points). The file MUST be named provisioning.rs, not provision.rs: store::provision is a function, [provision] appears seven times in these docs, and mise.toml:96-97 records that this crate has already been bitten by a module/function name collision under -D rustdoc warnings. Two link fixes only (1841, 2024). Separately move projectstore's reflink probe to storage, which removes the storage->sandbox edge.

**Pourquoi à ce rang.** Last because it is the least pressing and the most self-contained -- 2,090 lines of production code that nothing else in the plan touches. It earns a slot because the split is unusually cheap (every symbol crossing a proposed boundary is already pub(crate), so ZERO visibility widenings) and because the channel cluster is a genuine state machine a reader currently has to find between the bwrap AppArmor logic and the nix-build argv assembly. Do NOT merge store.rs and storage.rs to break their cycle: the two directions are asymmetric, and isolating resolve_mkfs into storage/mkfs.rs turns a diffuse cycle into one named file, which is worth more than a 3,600-line merged module.

---

## Ce qu'il ne faut pas découper

LEAVE ALONE, and the reasons differ. This section is where I disagree most with the submissions.

THE BIG FUNCTIONS THEIR OWN AUTHORS CORRECTLY REFUSED TO CARVE. Endorsed, and worth restating so nobody relitigates them.
- launch.rs build (3477-5204, 1,728 lines): one linear assembly whose ~40 locals converge on three consumers at the end (extra_cage_env, binds::build_spec, the LaunchGuard literal). Extracting the GUI-hole or provisioning blocks moves 8-10 values across a signature and splits the one surface sandbox/mod.rs:4-7 asks a security review to audit in one place. It moves whole into build.rs at ~2,700 lines and that is the correct answer.
- proxy/tunnel.rs serve_tunneled_request (53-927): 875 lines whose entire value is that one reader follows one request from head to close. The numbered step comments are the structure. Carving it into step_5/step_7 helpers destroys exactly what it is for.
- proc_enforce's supervisor (743-1030): one machine, one invariant (the single listener never blocks). Stays whole in mod.rs with the lifecycle that documents it.
- config/mod.rs fn resolve (1647-2593, 954 lines) and resolve_app (3277-3935, 666): a linear pass over ~60 accumulator locals. Every alternative is worse -- a ResolveState god-struct, or twenty &mut parameters threaded through sub-functions. It stays 954 lines under every proposal on the table and the config proposal is right to say so out loud.
- binds cage_mounts (368-707) and its in-cage destination constants: order IS the invariant (the OPT_DIR tmpfs is emitted before the config binds precisely so it shadows nothing), and the router's three-link mountpoint chain must stay visible on one screen with the constants declaring it.
- task run_admitted (685-950) and build_spec (990-1146): the ORDER is the security property -- the proc shim wraps innermost, redaction happens before anything is returned or logged.
- The proxy's two servers serve_cage and serve_host: the module header is one sustained argument about why these exist as a pair. Separating them separates the two halves of that argument.

MODULES THAT SHOULD NOT BE SPLIT AT ALL.
- src/sandbox/projectstore.rs (670 production lines). One subject, and it carries the crate's most load-bearing prose -- why the shared store stays byte-identical, why atomic rename per store path suffices, why no lock of sbx's own is needed. Splitting scatters that argument where nobody reads it.
- src/sandbox/fsmask.rs (622 production). One pipeline whose every stage shares Expanded/Masked/Decoys. There is no cut that does not bisect a data structure. The only self-contained piece is a 70-line git-index parser, which is not worth a file.
- src/sandbox/fhs.rs (400 production). A straight-line sequence of realise() calls where the comments are the content and the ordering carries meaning.
- src/sandbox/taskpool.rs, task_shim.rs. One subject each; task_shim is a format! template plus a nine-line writer, and separating a generated script's text from the function that writes it is pure loss.
- src/allowlist/grammar.rs. Already the parse seam, and says so in its header.
- src/sandbox/proxy/wire.rs and ctx.rs. wire is correctly named and cohesive; ctx's builders and its observation chokepoints must stay in one file because the chokepoints are the single funnel every plane records through and they need to see all the fields.
- tests/net.rs (2,816 lines, 66 tests, zero skip macros). The only suite in scope that already reads as a designed fixture. It adopts the shared Project in step 3 and stops.

SPLITS I AM REJECTING OUTRIGHT.
- allowlist beyond tests.rs. Step 2 takes it from 4,089 to 1,741 -- smaller than proxy/mod.rs, which nobody proposes splitting. The four production modules would put impl Rule in two files and impl RuleKind in two, fragmenting impl Ports and impl Methods for a render cluster of ~100 lines. The proposal half-concedes this about render.rs; the same logic finishes the argument for the other three. Take the tests, keep the module.
- src/sandbox/proxy/tests/ and src/config/tests/ subdivision. proxy/tests.rs is 10,357 lines of genuinely well-ordered tests behind one real 540-line harness, and cargo test --bin sbx sandbox::proxy::tests::<filter> already targets it. The only thing wrong with it is its size, which is not a defect. config/tests.rs is the better case (its clusters are non-contiguous, so any cut is a re-sequencing) but its sharpest hazard is a deliberate shadowing shim at tests.rs:60-77 whose mis-import would silently compile 46 call sites against the wrong function -- the one failure mode in this whole plan the compiler cannot catch. Neither is worth that risk before everything above is done.
- tests/run.rs split into run_desktop/run_egress/run_tools. Deferred, not rejected. The finer granularity is real and CI already runs per-suite, but it adds three test binaries and two hardcoded suite lists (mise.toml:123, cage.yml:287, held character-identical by a guard) for zero coverage change. Step 3 captures the part that actually matters -- the fixture consolidation and the two ungated audio e2es.
- Merging store.rs with storage.rs; merging config's two trust gates (scope_is_gated vs open_rule_write); merging store::host_exec_verdict with config::safety::verdict; folding config/override_apply into overrides.rs. All four would dissolve a seam the code argues for in place.
- proxy's prepare_credentials extraction, per conflict F -- worth doing, not worth doing here.
- Sharding help.rs's PAGES by namespace, and factoring binds' two prebuilt walks behind a run_command: bool (which would put 'gc must never run the resolve command or touch the network' behind a boolean argument).

ONE THING NOBODY PROPOSED THAT IS WORTH MORE THAN HALF THIS LIST. The UNDOCUMENTED_MODULE_ITEMS list at docs_coverage.rs:856-943 is absorbing a recurring defect rather than catching it -- four verified instances of the same severed-doc-block failure, three of them grandfathered. The guard's own doc says the list can only shrink. Step 1 removes four entries; a follow-up should audit the remaining ~80 for the same pattern, because every one of them is either a real doc that needs writing or a block that has silently drifted onto the wrong item.
