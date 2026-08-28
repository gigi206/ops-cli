# Annexe — réfutations et requalifications

La réfutation adversariale a écarté une part substantielle des défauts avancés par les
analystes. Ce taux est une mesure utile de la fiabilité du reste du rapport.

| Vague | Avancés | Réfutés | Retenus | Taux |
|---|---|---|---|---|
| Sécurité | 73 | 21 | 52 | 29 % |
| Correction | 105 | 14 | 91 | 13 % |
| Duplication et optimisation | 55 | 11 | 44 | 20 % |
| **Sous-total** | **233** | **46** | **187** | **20 %** |

Vingt-neuf des relevés retenus ci-dessus (12 en sécurité, 17 en correction) avaient franchi
leur vague sans que leur vérificateur ait pu s'exécuter. Ils ont été repassés séparément :

| Lot | Jugés | Réfutés | Retenus | Taux |
|---|---|---|---|---|
| Rattrapage de vérification | 29 | 4 | 25 | 14 % |

Après ce rattrapage et le retrait d'un doublon (`src/sandbox/egress_stats.rs:380`, relevé par
deux vagues), le rapport retient **182 relevés distincts** : 138 défauts et 44 constats de
duplication ou d'optimisation. Le taux de réfutation d'ensemble s'établit à **21 %**
(50 écartés sur 233 avancés).

Le détail nominatif n'est conservé que pour le lot de rattrapage, dont les verdicts ont été
collectés séparément. Pour les trois autres vagues, les défauts réfutés ont été écartés au fil
de l'eau et seul le décompte subsiste.

## Défauts réfutés — lot de rattrapage (4)

### `src/sandbox/tarball.rs:161` — `tarball:` hoist treats a lone top-level SYMLINK as "a directory", copying its target's tree from outside the extraction root into $out

**Avancé comme.** Moyenne. The generated `installPhase` hoists an archive whose root holds a single directory:

```sh
root=extracted
only=$(find extracted -mindepth 1 -maxdepth 1)          # :160
if [ "$(printf '%s\n' "$only" | wc -l)" -eq 1 ] && [ -d "$only" ]; then   # :161
  root=$only                                              # :162
fi
cp -r "$root"/. "$out"                                     # :164
```

The comment…

**Réfutation.** The shell observation is right and the line is right (src/sandbox/tarball.rs:161 is `if [ "$(printf '%s\n' "$only" | wc -l)" -eq 1 ] && [ -d "$only" ]; then`, and `-d` follows symlinks), but every consequence the finding builds on it fails.

(1) The escape hatch the attack leans on is explicitly closed. The tarball derivation is built by `build_pinned`, which calls `store::provision_expr` (src/sandbox/prebuilt.rs:807), and `provision_expr` forces the nix build sandbox on the command line rather than inheriting a setting: `.args(["--option", "sandbox", "true"])` (src/store.rs:1977; the same forcing appears at src/store.rs:1693 and 1906). So "if the nix build sandbox is ever not in force, the reachable set widens ... to the host root" is not a residual — sbx sets it per invocation.

(2) With sandbox=true, nix's Linux builder chroot exposes only the derivation's *input closure* under the store dir, not the store directory itself — that is the whole reason a sandboxed build fails on an undeclared dependency. The headline "the whole store is bind-mounted ... sbx's entire shared store is copied into a new store path" is therefore false; `ln -s /nix/store` would copy back the gzip/gnutar/makeWrapper/autoPatchelfHook/buildInputs/`src` closure that the build already materialised.

(3) The residual that does remain (a symlink to `/proc`, or to an input path) is a build-time disk/CPU DoS in a build that then fails at `launcher_wrap`'s refusal — and it is strictly weaker than a capability the same actor already holds: whoever chose the archive bytes controls `unpackPhase`'s `tar -xz --no-same-permissions --no-same-owner -f $src -C extracted` (src/sandbox/tarball.rs:145-147), i.e. an ordinary decompression bomb unpacked onto the same volume, with no symlink needed.

(4) The "content that never came from the pinned archive" angle gains an archive-controlling attacker nothing — they can place arbitrary bytes in the archive directly; the symlink only lets them copy content that is already in their own build's inputs.

(5) The vector is further narrowed by trust: `prebuilt::withheld` (src/sandbox/prebuilt.rs:747-759) filters on `p.state != crate::trust::TrustState::Trusted`, so a prebuilt package declared by an untrusted project directory is never provisioned at all; the URL must come from the global config or a project the user trusted.

Minor: the proposed "case (e)" already exists in `the_install_phase_hoists_a_lone_top_level_directory_and_leaves_every_other_root_alone` (the FHS-tree case), so the fix note misreads the test it wants to extend. What survives is a comment/code hygiene mismatch (`-d` admits a symlink-to-directory where the comment says "it is a directory"), not a security finding.

---

### `src/sandbox/attach.rs:368` — attach's capability argument is false: `setns` into a user namespace grants CAP_FULL_SET permitted/effective, not an empty permitted set

**Avancé comme.** Faible. The module header asserts "With an empty permitted set and `no_new_privs`, no bounded capability can ever become effective, so a full bounding set (which `setns` leaves in place) is inert and grants nothing the agent lacks" (src/sandbox/attach.rs:21-24), and `confine_and_exec` repeats it to justify treating the bounding-set drop as optional: "Defense in depth: already inert under `no_new_privs` wi…

**Réfutation.** The kernel fact is right (`userns_install` → `set_cred_user_ns` sets permitted/effective/bset to CAP_FULL_SET), but it refutes the finding rather than supporting it, and every line cited is otherwise as described. (1) The bounding drop is not skippable in the case that matters: `PR_CAPBSET_DROP` is gated on `ns_capable(current_user_ns(), CAP_SETPCAP)`, and after the `setns` at src/sandbox/attach.rs:299 the effective set in the cage's user namespace is exactly full, so the loop at :371-375 always succeeds — the discarded return can only be an error in the complementary case where the mask skipped `CLONE_NEWUSER` (`namespaces_to_join`/`join_mask`, attach.rs:105-139, joins a namespace "only if" it differs from ours), and in *that* case the process kept its ordinary unprivileged host credentials and the comment's "empty permitted set" argument holds verbatim. The two branches cover each other; the comment states the second as if it were the first. (2) The exploit needs a file-capability binary inside the cage, and the agent cannot produce one: bubblewrap is invoked with `--unshare-user` (src/sandbox/argv.rs:106) so its `drop_privs` leaves the payload with an empty permitted and bounding set plus `PR_SET_NO_NEW_PRIVS`, i.e. no CAP_SETFCAP to write a `security.capability` xattr, and it cannot mint a namespace to get one — `unshare` and `setns` are unconditional EPERM and `clone` is argument-filtered on `CLONE_NEWUSER`/`CLONE_NEWNS` (src/sandbox/seccomp.rs:164-169, :238-246). bwrap's binds are `MS_NOSUID` besides, so `mnt_may_suid()` discards file caps before `execve` ever reads them. With no file caps, `P'(permitted) = (P(inh) & F(inh)) | (F(permitted) & P(bounding)) | P'(ambient)` is zero whatever the bounding set holds. (3) The intermediate `waitpid` process (attach.rs:309-325) does hold full caps in the cage's user namespace, but it is unreachable: `setns(CLONE_NEWPID)` moves only future children, so it stays in the host pid namespace where no caged process can see or signal it, `ptrace` is denied (seccomp.rs:133), and between the `setns` and the `_exit` it executes nothing but `fork`/`waitpid`/`_exit` — no path resolution, no exec, no attacker-supplied input. The finding itself concedes this half is latent ("reachable today only from the host pid namespace"). Finally, the attach path is host-initiated by the trusted operator and "the caged agent cannot trigger it" (attach.rs:33-37), so there is no attacker-controlled entry point to the stated consequence.

---

### `src/sandbox/egress_stats.rs:549` — A rollup written but whose source cannot be unlinked double-counts, and every later fold re-adds it

**Avancé comme.** Faible. `compact` commits the merged rollup first and only then unlinks the sources:

```rust
if write_rollup(&target, &project, app.as_deref(), &tally).is_err() {
    continue; // keep the sources: losing counters is worse than keeping files
}
for path in gone {
    if std::fs::remove_file(&path).is_ok() {
        folded.push(path);
    }
}
```

The write half is treated as all-or-nothing and correctly s…

**Réfutation.** The quoted lines are real (egress_stats.rs:546-553, with `for path in gone` at :549) and the compounding arithmetic would follow *if* a source ever survived its unlink after the rollup was committed. That premise is what fails. The attack rests on "`write_rollup` writes to a rollup that already exists and is therefore only opened for write (no directory entry created), so it succeeds" — the function does the opposite: `write_rollup` (egress_stats.rs:559-575) is documented "temp + rename" and opens `target.with_extension(format!("tmp.{}", std::process::id()))` with `.create(true)` in the *same* directory, then `std::fs::rename(&tmp, target)`. A read-only egress directory, a `ro` mount, or an immutable directory therefore fails at the tmp `open`, `write_rollup` returns `Err`, and control takes the `continue` at :547 that keeps the sources — no rollup, no double count. Conversely, once that create+rename has succeeded the directory is writable and non-sticky (it is the launcher's own `layout.data_dir()/egress`, created `DirBuilder…mode(0o700)` at egress.rs:741-742, files written `.mode(0o600)`), so `remove_file` on a file the same uid owns cannot return EPERM/EROFS. What is left is a root-set per-file immutable attribute (not reachable from the cage, and not "ordinary input") or ENOENT from a concurrent fold — and ENOENT means the file is gone, i.e. no double count. Nothing here is a security boundary either: these are `sbx net stats` counters, and the function's own doc states "Best-effort throughout" for exactly this class of failure.

---

### `src/sandbox/control/mod.rs:689` — The egress control plane's record locks propagate poisoning, against the rule `sandbox::locks` states for exactly that kind of lock

**Avancé comme.** Moyenne. src/sandbox/locks.rs is an entire module whose job is to decide, once, which locks recover from poisoning: "**A lock recovers when what it guards is kept for a reader** — a lens ring, a tally, an invocation log, a registry the run consults… `sbx proc logs`, `sbx task status`, `sbx net stats` and the answer to a parked `execve` all read through one of these, and one panic in an unrelated handler wo…

**Réfutation.** The bookkeeping is right — all 19 cited line numbers in control/mod.rs are `.lock()/.read()/.write().unwrap()`, control/capture.rs:408/458/485 too, and a tree-wide grep confirms these are the only non-test sites (every other hit — notify_sink.rs:758+, sshagent_control.rs:345+, h2mitm.rs:1725+, ctx.rs:941+, inject.rs:1124, launch.rs:7815 — sits after the file's `#[cfg(test)]`). What is missing is the trigger: poisoning needs an unwind *while a guard is held*, and none of these critical sections can unwind. `PendingState::park` (119-140) holds the lock only for a `BTreeMap` insert and deliberately calls `on_enqueue(seq)` after the guard's block closes; `list`/`answer_like`/`answer_all` are map scans, clones and `mem::take`. `ManualRules` (257-297) does `contains`/`push`/`clone`, and its `snapshot` doc states the lock is "cloned out so the read lock is not held across the fold". `LogRing::push` (689) holds it over `super::sanitize` — a panic-free char map (observe_feed.rs:112-125) — and `VecDeque` push/pop; `set_status`, `expect_capture`, `capture_settled`, `capture_grew`, `secret_seen` (742-829) only `iter_mut().rev().find()` and assign; `snapshot`'s one arithmetic hazard is already `a.saturating_add(1)` at :874, the very line the finding quotes as evidence. `FlowRegistry` (999, 1024) is map insert/clone, and `FlowGuard::drop` (966-975) already takes it as `if let Ok(mut g) = registry.inner.lock()`. capture.rs:408 indexes only with a `position()`-derived index and saturates its byte accounting for the stated reason ("an underflow here would panic the control plane"). That enumeration is exactly the argument the tree accepts for identically shaped locks — task_control.rs:397-405, "The lock cannot be poisoned, and that is a property to keep… no indexing, no slicing, no arithmetic that can overflow, no `unwrap` on anything fallible, and nothing that calls out" — so the cited category is guarded by construction rather than by recovery. The one concrete example offered (`LOG after=u64::MAX`) was debug-build-only and is fixed. The `PendingState` claim also inverts: a panicking proxy connection thread drops that connection with no verdict, which refuses the request — `ask` does not "stop denying". What survives is a style/uniformity nit (route these through `sandbox::locks` so the invariant is not re-argued per site), not a medium defect.

---

## Défauts retenus mais requalifiés (10)

Le vérificateur a confirmé le mécanisme tout en corrigeant la gravité annoncée.

| Emplacement | Annoncé | Retenu | Motif |
|---|---|---|---|
| `src/sandbox/prebuilt.rs:859` | Moyenne | Faible | The lost update is real; the security framing overstates it. (a) It needs two *cold* provisions of the same project overlapping in the mint window — a warm launch never mints (`pinned_or_mint` returns on a hit, src/sandb… |
| `src/sandbox/egress.rs:124` | Moyenne | Faible | The consequence is substantially overstated, so I am lowering it to low. Under the default `mode = "deny"` posture the task detour grants the agent nothing: `--net-learn` is documented to write an allow rule for every pl… |
| `src/sandbox/attach.rs:179` | Élevée | Moyenne | The mechanism is confirmed; the severity and one detail are overstated. (a) This is not a confinement break and gives the caged agent nothing: the attached shell still gets the baseline seccomp denylist, `no_new_privs` a… |
| `src/sandbox/forward.rs:189` | Élevée | Moyenne | Severity is overstated at high; the mechanism is right but the blast radius is narrower than described. The leak cannot outlive the process — a plain `sbx run`/`sbx app` returns `ExitCode::FAILURE` and exits, and the ker… |
| `src/sandbox/forward.rs:156` | Moyenne | Faible | Mechanism confirmed; likelihood and severity are overstated. (a) The window is much narrower than "within an hour of ordinary activity": every `build()` sweeps dead-pid `fwd-*` dirs (launch.rs:3503) and so does `sbx gc -… |
| `src/sandbox/contract.rs:91` | Moyenne | Faible | Real but overstated on two points. First, the `Deny` arm's sentence is *literally true* as written — it is a claim about hosts NOT listed, not a claim that listed hosts are reachable; the false implication actually comes… |
| `src/sandbox/proxy/mod.rs:283` | Moyenne | Faible | Three overstatements. (1) Not silent: with the default hook the panic prints `thread '<unnamed>' panicked at src/sandbox/proxy/mod.rs:283: failed to spawn thread: …` to the supervisor's stderr, which is where `crate::dia… |
| `src/sandbox/proxy/mod.rs:84` | Moyenne | Faible | Mechanism and line numbers are all correct; only the severity is high. This is documentation-only: no refusal behaves differently, no policy is weakened, and both omitted tokens are already tested at their emit sites (pr… |
| `src/sandbox/task_control.rs:399` | Moyenne | Faible | Verified as stated, but it is documentation only — no runtime behaviour is wrong today (all five takes already recover, which is the intended behaviour per locks.rs). The harm is a stale normative rule a future method co… |
| `src/cli/test.rs:427` | Moyenne | Faible | Mechanism confirmed, consequence overstated. (a) The line numbers for `render_ip_literal_refusal` are 439 (fn) / 449 (the quoted sentence), not "line 449" for the function. (b) No allowlist gate is bypassed: the forward … |

