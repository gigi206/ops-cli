# Audit architecture `sbx` — ce qu'il faut remettre en cause

Vérifié sur le code : pas de `clap` (`Cargo.toml/lock: 0 match`), `src/main.rs:1712l`, `src/help/pages.rs:3149l`, `src/sandbox/proxy/: ~37k lignes` dont `h2mitm.rs:3895l`, `tunnel.rs:979l`, `wire.rs:1841l`, `src/config/: ~35k lignes`, bin-only sans `lib.rs`.

## 1. CLI 100% manuel + `help.rs` source de vérité — le plus fragile

**Choix :** `main.rs:48-82` + `cli/mod.rs:569-643` (`match name` géant), chaque famille réimplémente sa boucle `to_str`/`-`/`--`. `help.rs:48-54` + `pages.rs:31-` (~90 pages) est la source unique dont dérivent `--help`, `synopsis_of`, erreurs et `completion.rs:2297l`.

**Pourquoi c'est défendable :** contrôle `OsString`/non-UTF8 (`main.rs:49`, `cli/mod.rs:114` vs `178`), `--flag=value` en bytes, booléens optionnels qui ne mangent pas l'arg suivant (`take_flag_bool:466`), messages `sbx: <verbe>` uniformes, zéro dépendance.

**Problème :** ~90 parsers à maintenir, seam help↔parser assumé (`help.rs:19-23`). La grammaire des opérandes est *parsée depuis du texte* (`completion.rs:643-747` `operand_slots/metavar_of/is_literal` + stop-list), `flag_takes_value` doit rester d'accord avec `take_override_flag` à la main. `split_session_flags:207` filtre par égalité aveugle. `main.rs` est devenu un fourre-tout (scope, overrides, `persist_egress_rule:1077`, `format_log_time:704` avec `unsafe localtime_r`, sessions).

**Mieux :** ne pas jeter la table, mais l'inverser : schéma typé `Opt{name,kind,value}` qui *rend* le help ET nourrit parsers + completion, au lieu de parser du prose. Générer un `clap::Command` **depuis** cette table (comme la completion le fait déjà) garderait messages maison + `OsString` fins tout en donnant `--help` auto, conflits `--all/--session`, `clap_complete`. A minima : extraire `cli/_shared.rs` (scope/override/rule_write) et réduire `main.rs` à `args→help→dispatch`.

## 2. Proxy egress MITM maison — le plus coûteux

**Choix :** netns vide + `socat` in-cage (`sandbox/egress.rs:205-289`) → socket Unix → proxy host sync qui fait CONNECT + MITM par-SNI (`proxy/ca.rs:36`, `rcgen` éphémère RAM-only), décision par requête, `ask` parqué, injection secrets host-side + tripwires, SSRF post-résolution, pool partitionné par credentials (`pool.rs`), `wire.rs` parser HTTP/1.1 main + `h2mitm.rs:3895l` gRPC.

**Pourquoi c'est défendable :** aucun existant (`tinyproxy/haproxy/envoy/squid/mitmproxy`) ne fait le combiné verdict/requête + `ask` humain + injection + SSRF exact-host-sauf-builtin + `tcp://` splice + WS (`WS` pseudo-verbe) + h2 + log/flows/capture/notif unifiés. Bien fait : CA jamais sur host, `SNI==CONNECT==Host` triple-check, `NTLM` jamais poolé, refus stables `X-Sbx-Egress-Reason`.

**Problème :** tu portes un parseur HTTP/TLS + re-sérialisation + de-chunk + `FramedBody` + keep-alive/pool + smuggling (`OBS-fold`, `CL` strict, split sur `SP` seul — bugs déjà trouvés et commentés). Dette permanente : fuzzing continu de `parse_head/inspect_framing/authority_bound_to/leaf_for`, WS post-`101` aveugle (pipe verbatim), oracle `outbound-secret`, bug `Keep-Alive timeout=120 vs close 30s` documenté.

**Mieux :** si l'équipe assume fuzz + veille : garder. Sinon déléguer le transport (`hyper/h2` + `rustls`, déjà deps) et ne garder que verdict/injection, ou `envoy` + ICAP externe pour le verdict. Ne pas remplacer par `mitmproxy` Python (runtime, pas de deny-by-construction, pas d'intégration ask/SSRF).

## 3. Double runtime + thread-par-connexion

**Choix :** monde std-threads sync partout (H1 linéaire, timeouts socket simples) ; `async-io` + `zbus(async-io)` confinés (`block_on` dédié, `Cargo.toml:31-40`) pour D-Bus ; `tokio current-thread` **par connexion h2** (`h2mitm.rs:53-66`), `FuturesUnordered` sans `spawn` (pas de `Arc<ProxyCtx>`).

**Problème :** 2 runtimes à debugger ; 1 runtime + 1 thread OS par tunnel h2 ; tout appel bloquant (signer IPC sous mutex, DNS non-caché) stalle les 256 streams siblings (documenté, assumé) ; `held_bodies` hors cgroup cage ; threads détachés `stop+poke`, vie=process ; `park` ask tient 1 thread/req (cap 256, ghosts documentés).

**Mieux :** à charge agent (dizaines, pas milliers de conns) c'est le bon compromis — ne pas passer en tout-`tokio` (réécriture H1 sync + `rustls` sync). Seule vraie alternative à arbitrer : **drop-h2** (forcer H1, tuer `h2mitm.rs`) si gRPC marginal vs coût mental. Sinon garder + monitorer `connection-cap/splice-cap` via `sbx net live`.

## 4. `bwrap` + `nix` daemonless + engines embarqués via `build.rs`

**Choix :** `SandboxSpec:spec.rs:116` + `to_argv()` pure comme seul point d'audit, env via memfd (`argv.rs:63`), seccomp non-oubliable (`compose()`), `NIX_REMOTE="" --store data/store` (`provisioning.rs:24`), `/nix` hermétique + `cacert`, 1 channel partagé base+tools. Release embarque `nix 2.34.7` + `bwrap 0.11.2` statiques musl (`build.rs:48-71`, `Cargo.toml:13-28` off par défaut, hash vérifié build + marker run).

**Problème :** `sandbox=false` in-cage assumé (pas de double confinement build), `as_root --uid 0` pour `distro run` élargit le `0` in-cage. Binaire +dizaines Mo, double pin rev+sha à bumper ensemble, x86_64 musl only, AppArmor Ubuntu 24.04+ (`/usr/bin/bwrap` profilé par path) annule le bénéfice bundled. Build shim imbriqué à chaque `cargo build`.

**Mieux :** garder le daemonless (repro, user-owned, offline) — c'est le cœur. Revoir seulement le packaging : alternative `nix bundle/staticelle` ou dep système + `doctor` strict (déjà le mode dev/CI), `cosign/minisign` pour releases au lieu de sha pinnée vérifiée qu'au build.

## 5. Seccomp denylist custom en cBPF

**Choix :** `seccomp.rs` : default-allow + 2 filtres `seccompiler` EPERM/ENOSYS (`clone3→clone` fallback), `ioctl` comparé en `Dword` (bypass `0x1_...5412` fermé), `x32` refusé, garde-ABI même si tout lifté, `[seccomp] allow` fin trusted-only.

**Verdict :** justifié par les 2 règles à args + `x32` + tests d'enforcement live. Alternative profil Flatpak amont = moins fin, plus de suivi amont. Garder, mais budgéter **veille kernel à vie** (`io_uring` couvert, `futex2/map_shadow_stack` à venir).

## 6. Store layout + sockets `AF_UNIX` + registry fichier

**Choix :** `store/layout.rs:40-106` (`SBX_DATA_DIR > XDG > HOME`, relatif refusé, `0700`, `from_env_without_mounting` pour completion), gardes `SUN_PATH_MAX=107` (`361-447`), `session.rs:167` records `<pid>-<start_ticks>` `0600` tmp+rename (anti half-read, anti pid-reuse via `/proc` champ 22, `kill(pid,0)` + start_ticks).

**Problème structurel :** `DATA_DIR_MAX ~70o` : `$HOME` long casse tout sauf volume `/run`. Registry `O(n)` (`readdir+kill+stat` par `ls`, poll 4Hz `logs --follow`), pas d'index/requête, `OnceLock` volume irréversible, Linux-only `/proc`.

**Mieux :** la seule remise en cause qui vaut le coût : **sockets sous `XDG_RUNTIME_DIR` (court, tmpfs) + blobs sous data long**, ou abstract sockets (plus de path, mais plus de perms fs). `sqlite WAL + inotify` ne se justifie qu'à 100+ sessions — le fichier `ls/cat/rm` + crash-safe rename est volontaire, garder.

## 7. Plugins + trust + catalogue maison

**Choix :** `plugins/` (~8k lignes) : `plugin.toml` trusted-by-location, cage bwrap par plugin, grants `network/state/allow_paths/mask/brokers`, conflits "2 claimants = les deux off", digest `relpath\0exec\0sha` trié, catalogue Ed25519 `ring` + `rev` anti-replay, `trust.rs:115` framing `tag\0len\bytes` couvrant `.sbx.toml` + mise (superset direnv), symlink leaf jamais résolu, TOCTOU `trust_written` sans relecture.

**Problème :** réinvention complète catalogue/sign/publish/provenance vs `WASI/extism` + `warg`/OCI, pas de transparency (`rekor`), pas d'expiry/rotation (`rekey` manuel), TOFU first-fetch MITMable, witness GitHub rate-limit 60/h warn-only.

**Mieux :** threat model (broker ne peut octroyer plus que le hole) + offline-verifiable sont bons, garder le runtime. Migrer seulement la **distribution** vers `sigstore-rs/rekor` pour stores publics + `minisign` releases, garder Ed25519 offline pour stores privés.

## 8. Divers : config, tasks, `mise`

* **Config layered** (`load.rs/gate.rs/overrides.rs/manage.rs`) : fail-safe (untrusted→drop+warn, override malformé→exit 2, `toml_edit` + `Written.text` anti-TOCTOU) excellent, mais garantie layering par relecture (`gate.rs:10-16` l'avoue) là où overrides ont l'exhaustivité compilateur (destructuration `RawConfig`). Extraire `sbx-core` en **lib** (aujourd'hui `[[bin]]` seul → tout `pub(crate)`, `main.rs` non importable, `proc-shim` duplique fmt/clippy).
* **Task sibling-cage** (`task.rs:1-28`, 4 cages : session/tâche/pool-install/plugin, 2 proxies, 2 sockets) : seule vraie isolation same-uid (`/nix`+`$HOME` RW agent → re-cage RO + `TASK_OUT` dir pas tmpfs). Complexe mais nécessaire. Juste revisiter `MAX_DETACHED=4/MAX_LIVE=8` et pool par-projet (duplique runtimes) sur workload réel.
* **Storage btrfs+udisks** (`storage.rs`) : 1 inode hôte + compression partagée, mais desktop-only (serveur/CI/WSL incertain). Alternative `GC agressif + nix-store --optimise` sans volume à considérer hors desktop.
* **`mise.toml` vs `just/xtask`** : `mise run ci == CI` bien, mais pin dupliqué 4× + pas de `nix develop` hermétique. Mineur.

### Priorité si tu dois n'en rouvrir que 3

1. **CLI/help/completion** (dette active, fragilité croissante avec chaque verbe).
2. **Sockets `DATA_DIR_MAX`** (limite structurelle qui mord les vrais `$HOME`).
3. **Fuzzing proxy + décision h2** (seule dette sécu qui peut devenir CVE).
