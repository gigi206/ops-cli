# Audit profond `sbx` — spark-1.3

- Date : 2026-09-08
- Périmètre : `/home/gigi/Documents/ops-cli`, binaire `sbx` (bubblewrap + nix daemonless)
- Volume : `src/` 253 633 lignes (237 fichiers `.rs`), `tests/` 28 140 lignes (27 fichiers), `build.rs` 261 lignes, total Rust 282 034 lignes
- Méthode : 5 audits parallèles (correctness, sécurité sandbox, concurrence/ressources, CLI/config/docs, I/O FS) avec `rg` + lecture intégrale + vérification ciblée des cas critiques. Aucune modification de code.

## 🔴 Critique / Haute

### 1. `src/storage.rs:801` + `:854` — symlinks jamais détectés
```rust
let meta = entry.metadata()?; // suit les liens
if meta.is_symlink() { // toujours faux, il faut symlink_metadata() / file_type()
```
- `census()` compte un symlink comme fichier/dossier suivi, boucle possible sur lien vers ancêtre, décision de validation fausse.
- `copy_tree()` déréférence au lieu de recréer le lien (`fs::copy` suit) : store ~2x, dedup `.links` perdue, lien absolu `/nix/store/...` copié comme contenu, lien vers `/etc/shadow` exfiltré dans le volume.

### 2. `src/sandbox/mise.rs:217-231` — `stage_files()` casse sur sous-dossier
```rust
let src = stage_dir.join(name); // name="mise/config.toml"
let tmp = stage_dir.join(format!("{name}.{pid}.tmp")); // slash inclus
```
Seul `stage_dir` est créé, jamais le parent. Projet avec `mise/config.toml` → `ENOENT` → launch avorté. En plus : `truncate(true)` sans `create_new` / `O_NOFOLLOW` suit un symlink pré-créé, pas de `fsync`.

### 3. `src/config/mod.rs:3531` — `tcp://[IPv6]:port` non dé-bracketté
```rust
fn parse_tcp_endpoint(endpoint: &str) {
    let (host, port) = endpoint.rsplit_once(':')...;
    Ok(BrokerTarget::Tcp { host: host.to_string(), .. }) // "[::1]" gardé verbatim
}
```
`TcpStream::connect((host, port))` n'accepte pas les crochets → `tcp://[::1]:5432` échoue toujours alors que l'exemple existe en `src/cli/completion.rs:2021`. `Display` re-ajoute `tcp://{host}:{port}`, masquant le bug au round-trip.

### 4. `src/config/load.rs:597-608` + `src/storage.rs:103-104,429-448` — fail-open en cascade
- `read_project` / `read_layer` : `NotFound → None`, tout autre `Err → warning + None`, couche entière droppée. `EMFILE` / `ENOSPC` / `EINTR` sur config globale `network deny` → launch en egress ouvert avec un simple warning.
- `read_pointer().ok()?` confond `EACCES` / `EMFILE` avec absence → provisionne des gigas dans `~/.local/share` au lieu du volume.
- `loop_for()` : `let Ok(entries) = ... else return Ok(None)`, `flatten()`, `let Ok(target) = ... else continue` → backing illisible transitoire → 2e `loop-setup` sur même image → deux vues inscriptibles du même btrfs (corruption documentée `storage.rs:416-420`).

### 5. Sécurité sandbox
- `src/sandbox/cagedir.rs:33` : `ensure_under` fait `symlink_metadata` puis `create` — TOCTOU résiduel assumé dans le commentaire. Cage live peut swapper entre check et use. Le cas sans race est fermé, le cas avec race reste ouvert (nécessiterait I/O à base de FD).
- `src/sandbox/launch/build.rs:98` : `canonicalize(project).unwrap_or_else(|_| project.to_path_buf())` — si `canonicalize` échoue (boucle symlink), fallback non résolu vs `sbx_control_plane_roots()` résolus → `pin_sources` ne pinne rien → cage RW non-pinnée.
- `src/sandbox/prebuilt.rs:444,229` : `prefetch_hash()` sans contrainte protocole (downgrade `https → http` invisible, TOFU sur octets MITM) + `bounded_unpack` en `tar -x` sans garde symlink/absolu ni limite nombre de membres (1M fichiers vides → remplissage 8 Gio).
- `src/sandbox/egress.rs:1478,1433-1445` : `sops_path = project_root.join(file)` sans normalisation + `try_exists` → `Command::new(sops)` TOCTOU → `sops://../../other/secrets.enc.yaml` sort du projet.
- `src/store/engine.rs:307` : `host_exec_verdict` ne refuse que `0o002` (world-writable), tolère group-writable + `stat-then-execve` assumé → substitution entre check et `execve` host-side.

### 6. Concurrence — hangs / leaks
- `src/sandbox/notify_sink.rs:870`, `notify_relay.rs:551`, `theme_relay.rs:268` : `Drop { h.join() }` sans borne sur D-Bus bloquant / socket cage remplie → `drop` pend, superviseur ne termine jamais.
- `src/sandbox/broker.rs:1749` : boucle `accept` détachée sans arrêt ni join, `Drop` ne fait que `remove_file` → thread + listener survivent au teardown.
- `src/sandbox/control/mod.rs:172` : `park()` avec `None => rx.recv().unwrap_or(Deny)` + cap 256 → 256 threads parqués à vie si `ask_timeout=None`, épuisement `max_connections`.
- `src/sandbox/resolver.rs:425` : lecteurs `drain()` détachés jamais joints + `child.wait()` avant `rx.recv_timeout` → helper héritant du pipe (`sh → sleep`) bloque le thread à vie, 2 threads + 2 FD par résolution tuée.
- `src/sandbox/proxy/websocket.rs:705` (`poll(-1)`), `splice.rs:173` (`set_timeout(None)` + join coopératif), `launch/cage.rs:188` (join lecteurs sans borne après `kill+wait`) : tunnels / splices idle = threads + FD à vie.

## 🟠 Majeur

- `src/sandbox/launch/build.rs:954` : `kb.saturating_mul(1024)` sature à `u64::MAX` au lieu d'échouer → `scan_max_kb=i64::MAX` → scan non borné au lieu du défaut 1 MiB.
- `src/config/validate.rs:852` : `parse_duration(raw).unwrap_or_else(|| { warnings.push(...indefinitely); None })` où `None` = attente infinie → coquille `ask_timeout="90x"` gare les requêtes `ask` pour toujours.
- `src/sandbox/proxy/ctx.rs:63`, `ssrf.rs:369`, `wsframe.rs:919` : `expect()` en chemin production sur entrées built-in / slice IP / octets réseau. Sûrs aujourd'hui par invariant externe, paniquent à la première dérive.
- Écritures non-atomiques / non-durables : `storage.rs:207` `write_pointer`, `store/channel.rs:570` `write_lock` (tmp pid-only → 2 writers même pid se marchent dessus), `store/provisioning.rs:536` `write_expr_stamp` (erreurs avalées, retour `()`), `session.rs:572` `register` (tmp fixe sans pid), `trust.rs:435` marqueur trust, `sandbox/task.rs:1071` `hosts` / `sshcfg` en écriture directe. Pas de `fsync` fichier ni dossier (contre-exemple : `sandbox/atomicfile.rs:94,106`).
- `src/storage.rs:1244` : `up()` ne vérifie `noexec` que si `mount_of() == Some` — si `None` (race / parse), point `udisks` retourné comme sain.
- `src/storage.rs:306,316,444` : `trim_end_matches('.')` ronge tous les points finaux légitimes ; `trim_end_matches(" (deleted)")` ampute un backing-file légitimement nommé `foo (deleted)` → 2e loop sur mêmes octets.
- Sécu moyenne : `egress.rs:999` CA `0600` seulement à la création (`truncate` garde `0644` résiduel), `:812` sockets pid-clé sans unlink CA, `proxy/ca.rs:116` mint feuille TLS avant check policy (flood SNI = burn CPU), `egress.rs:866` refresh secrets non propagé aux needles notifier (fuite en notification), `catrust.rs:85` purge NSS `delete-then-add` concurrente.

## 🟡 CLI / Help / Config — parité rompue

Règle `AGENTS.md` : toute commande = `Page` dans `src/help.rs`.

- `src/cli/proc.rs:367` : `proc pending allow/deny` parsés, une seule `Page ["proc","pending"]` (`pages.rs:529`) — `sbx help proc pending allow` échoue, `--help` montre le parent. Même défaut : `storage init/status/...` (`cli/storage.rs:73`, une seule Page `["storage"]`), `projects list/rm` (`cli/projects.rs:20`, Pages `["projects"]` + `show` seulement, `help projects` ne liste pas `list/rm`).
- `src/cli/net/rules.rs:47,58` vs `:55` : `--source manual` accepté mais message d'erreur dit `(config, builtin, session)` + completion `completion.rs:1093` sans `manual` → filtre qui marche, indiscoverable, erreur mensongère.
- `src/cli/projects.rs:99` : hint `Run sbx projects to list them` alors que nu `sbx projects` → `page_usage` exit 2, ne liste rien. Attendu `sbx projects list`.
- `src/cli/search.rs:32` : mots surnuméraires ignorés en silence (`["ripgrep","fast"] → Ok("ripgrep")`) vs synopsis `sbx search <query>` — `sbx search foo bar` répond `foo`.
- Bizareries : synopsis `gc` omet `--optimize` (`pages.rs:1730` vs parser `cli/gc.rs:18`), `secret list` dit `unexpected argument "--foo"` vs `unknown argument \`x\`` ailleurs, `store` vs `reject_extra` deux vocabulaires de refus, `upgrade --app= / --project=` parsés jamais documentés, `session logs` synopsis que formes courtes, `bundle export` / `net groups export` = verbe jamais le bundle nommé `export`, `net allow/deny` détails citent `-c` absent des Options.

## Priorités suggérées

1. `metadata()` → `symlink_metadata()` dans `census` / `copy_tree` + test avec symlink.
2. `stage_files` : créer parents, `create_new` + `O_NOFOLLOW`, tmp sans slash.
3. `parse_tcp_endpoint` : strip `[...]` + test `tcp://[::1]:5432`.
4. `load()` : distinguer erreur transitoire (fail-closed) de `NotFound`, ou `deny` par défaut avec erreur dure.
5. `Drop` avec `join()` borné (`recv_timeout`) sur les 3 relais + `Broker::drop` qui arrête l'`accept`.
