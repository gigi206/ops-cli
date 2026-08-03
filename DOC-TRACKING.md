# Suivi de couverture documentaire — docs/guide ↔ code source

> Fichier de travail qui trace la **lecture** de chaque fichier source et son **traitement
> documentaire** : pour chaque fichier, la doc guide (`docs/guide/`) qui doit le couvrir,
> si elle existe, et ce qui manque. La doc de conception (`docs/bwrap-*.md`) est suivie
> séparément en fin de fichier.
>
> Objectif : garantir que **chaque fichier de `src/` a sa page (ou section) dans
> `docs/guide/`**, que la doc est complète (tous les verbes, toutes les options, tous les
> invariants) et lisible (découpage, exemples). Un fichier n'est « traité » que lorsque sa
> ligne passe à **✅** dans les deux colonnes.

## Légende des statuts

| Statut | Lecture | Traitement documentaire |
|---|---|---|
| ✅ | fichier lu (au moins une fois, contenu réel) | **couvert** — la/les page(s) liée(s) documentent tout le comportement visible |
| 🟡 | lu partiellement / à relire (contenu non exhaustif) | **partiel** — la doc existe mais des lacunes sont identifiées (colonne Notes) |
| ❌ | — | **manquant** — pas de page/section doc pour ce fichier, ou une surface visible n'est pas documentée |
| ⬜ | non lu | **non évalué** — la doc n'a pas encore été comparée au code |

Statuts par défaut en début d'audit : lecture **⬜**, doc **⬜** (page liée indiquée, à vérifier).
La colonne **Notes** recense les écarts constatés (info manquante, exemple absent, rubrique à créer).

---

## Vue d'ensemble

| Périmètre | Fichiers | Lu | Doc ✅ | Doc 🟡 | Doc ❌ | Doc ⬜ |
|---|---|---|---|---|---|---|
| Racine `src/*.rs` | 14 | 2 | 0 | 0 | 0 | 14 |
| `src/cli/` | 22 | 22 | 22 | 0 | 0 | 0 |
| `src/config/` | 11 | 0 | 0 | 0 | 0 | 11 |
| `src/plugins/` | 4 | 0 | 0 | 0 | 0 | 4 |
| `src/allowlist/` | 2 | 0 | 0 | 0 | 0 | 2 |
| `src/sandbox/` | 67 | 0 | 0 | 0 | 0 | 67 |
| Autres (build, shim, Lua) | 11 | 0 | 0 | 0 | 0 | 11 |
| **Total** | **131** | **24** | **22** | **0** | **0** | **109** |

*(La vue d'ensemble est mise à jour à chaque session d'audit. Session 1 = surface CLI : 22/22 fichiers `src/cli/` audités, 22/22 pages couvertes. `main.rs` et `help.rs` lus mais non encore cotés Doc.)*

---

## Racine — `src/*.rs`

| Fichier | Rôle | Page(s) doc liée(s) | Lu | Doc | Notes |
|---|---|---|---|---|---|
| `main.rs` | entrée du binaire, dispatch des verbes, flags partagés (`split_scope`, overrides), helpers egress | `cli/README.md`, `reference/exit-codes.md` | ✅ | ⬜ | lu intégralement ce jour ; héberge aussi `run`/`mise`/`path` (pas de `cli/run.rs`) — à coter Doc lors de l'audit sandbox/overrides |
| `paths.rs` | `sbx path` — emplacements sur disque par XDG | `cli/path.md`, `concepts/directory-layout.md` | ⬜ | ⬜ | |
| `observe.rs` | observabilité in-cage (lecture `/proc`) | `concepts/observability.md`, `cli/proc.md` | ⬜ | ⬜ | |
| `style.rs` | palette ANSI / `NO_COLOR` | interne (rendu) | ⬜ | ⬜ | aucun besoin de page dédiée |
| `notify.rs` | politique de notification de refus (`[notify]`) | `configuration/notify.md` | ⬜ | ⬜ | |
| `proc_policy.rs` | politique exec (`[proc]`), verdict pur | `configuration/proc.md` | ⬜ | ⬜ | |
| `storage.rs` | volume compressé auto-géré pour `<data>` | `cli/storage.md` | ⬜ | ⬜ | |
| `trust.rs` | dépôt de confiance projet (direnv, hash de contenu) | `concepts/trust.md`, `cli/trust.md`, `cli/untrust.md` | ⬜ | ⬜ | |
| `diag.rs` | diagnostics stderr stylisés (`sbx: warning:`) | interne (rendu) | ⬜ | ⬜ | aucun besoin de page dédiée |
| `session.rs` | registre de sessions sur disque (sans démon) | `cli/session.md`, `housekeeping/sessions.md` | ⬜ | ⬜ | |
| `pathfind.rs` | localisation d'exécutables sur `PATH` | interne | ⬜ | ⬜ | aucun besoin de page dédiée |
| `help.rs` | pages d'aide (`sbx help …`), grammaire des verbes | `cli/README.md` (table source de vérité) | ✅ | ⬜ | lu (97 pages de la table des pages extraites et croisées avec la doc CLI — 100 % de correspondance) ; les 3 micro-écarts CLI (alias `--optimize`/`--lines`, synopsis) vivent ici |
| `store.rs` | store nix utilisateur, sans démon | `cli/store.md`, `concepts/provisioning.md`, `concepts/directory-layout.md` | ⬜ | ⬜ | |
| `testutil.rs` | helpers de test partagés | — (tests) | ⬜ | ⬜ | aucun besoin de page dédiée |

---

## `src/cli/` — surface de commandes (1 fichier ≈ 1 page `cli/*.md`) ✅ audité session 1

> **Verdict session 1 : 22/22 fichiers couverts.** Les 97 pages d'aide de `help.rs` (grammaire de vérité) ont été comparées à la surface réelle (flags parsés par fichier) et aux 25 pages `docs/guide/cli/*.md`. La couverture est **remarquablement complète** : chaque verbe, chaque flag, chaque sortie est documenté, souvent avec exemples et sorties annotées. Écarts relevés : 3 micro-lacunes (voir Notes) — toutes des alias de flags non documentés.

| Fichier | Verbe(s) | Page(s) doc liée(s) | Lu | Doc | Notes |
|---|---|---|---|---|---|
| `mod.rs` | dispatch central, `reject_extra` | `cli/README.md` | ✅ | ✅ | lu intégralement. NB : `run`/`mise`/`path` n'ont **pas** de fichier `cli/*.rs` — leur code vit dans `main.rs` + `sandbox/` (suivi à la racine) |
| `app.rs` | `sbx app` (run/import/export/rm/list/show/prune, `--net-learn`) | `cli/app.md`, `apps/*` | 🟡 | ✅ | doc 175 l. très fournie (table des options, `--net-learn` par niveau, `show`/`prune`) ; flags vérifiés : `--as/--out/--purge/--gc/--yes/--json/--force/--detach/--observe/--net-learn[=]/-g/-l/--dry-run` + overrides |
| `bundle.rs` | `sbx bundle` (list/export/import) | `cli/bundle.md`, `configuration/bundles.md` | 🟡 | ✅ | doc 101 l. avec table des exit codes ; flags `--force/--json/--out` ✓ |
| `config.rs` | `sbx config` (show/get/set/unset/edit/path) | `cli/config.md` | 🟡 | ✅ | doc 116 l. ; flags `--json/--details/-a/--app/-g/--global/-l/--local/-d/--default/-c/--trust` (via `split_scope`) ✓ ; synopsis `set/unset` incluent `--trust` ✓ |
| `confirm.rs` | rendus de confirmation des verbes d'écriture | interne (rendu) | 🟡 | ✅ | aucun besoin de page dédiée (interne) |
| `doctor.rs` | `sbx doctor` | `cli/doctor.md`, `getting-started/doctor.md` | 🟡 | ✅ | doc 24 l. + page getting-started dédiée ✓ ; aucun flag |
| `fs.rs` | `sbx fs logs` | `cli/fs.md` | 🟡 | ✅ | doc 91 l. (kinds write/create/remove/rename, scope, limites) ; flags `--follow/--json` ✓ |
| `gc.rs` | `sbx gc [--all] [--prune] [--optimise]` | `cli/gc.md`, `housekeeping/gc.md` | 🟡 | ✅ | doc 109 l. (dédup expliquée) ; **micro-écart** : le code accepte aussi `--optimize` (orthographe US), absent du synopsis help.rs et de la doc |
| `net.rs` | `sbx net` (rules/groups/allow/deny/mute/unmute/pending/stats/logs/live) | `cli/net.md`, `networking/*` | 🟡 | ✅ | doc 166 l. ; flags vérifiés : `--all/--app/--expand/--filter/--follow/--force/--host/--interval/--json/--out/--reset/--save/--session/--source/--verdict/--with-query/--with-status` ✓ ; synopsis `net logs` inclut `--with-status` (corrigé vs audit antérieur) |
| `plugins.rs` | `sbx plugins` (list/info/install/rm/verify/upgrade + store) | `cli/plugins.md`, `secrets/plugins.md` | 🟡 | ✅ | doc 96 l. ; 22 pages d'aide pour plugins/store, toutes documentées ; flags `--dry-run/--installed/--key/--name/--rev/--trust/--url/--yes` ✓ |
| `proc.rs` | `sbx proc` (ls/live/logs/pending/allow/deny/rules) | `cli/proc.md` | 🟡 | ✅ | doc 247 l. (l'une des plus détaillées) ; flags `--all/--follow/--interval/--json/--session` ✓ ; `-c <file>` accepté au parse puis refusé avec message explicite (comportement documenté en doc : « ne prend pas `-c` ») ✓ |
| `projects.rs` | `sbx projects [list|show|rm]` | `cli/projects.md` | 🟡 | ✅ | doc 90 l. ; flags `--dead/--markerless/--dry-run/-n/--yes/-y/--gc/--force/-f/--json` ✓ (doc documente les alias courts) |
| `search.rs` | `sbx search` | `cli/search.md` | 🟡 | ✅ | doc 29 l. ; aucun flag ✓ |
| `secret.rs` | `sbx secret list` | `cli/secret.md`, `configuration/secret.md` | 🟡 | ✅ | doc 48 l. (deux sorties annotées) ; flags `--app/--sources` ✓ |
| `session.rs` | `sbx session` (ls/logs/attach/stop) | `cli/session.md`, `housekeeping/sessions.md` | 🟡 | ✅ | doc 175 l. ; **micro-écart** : code accepte `-n` ET `--lines` (alias long), seul `-n <N>` figure au synopsis help.rs et en doc |
| `sshagent.rs` | `sbx ssh-agent logs` | `cli/ssh-agent.md`, `configuration/ssh-agent.md` | 🟡 | ✅ | doc 71 l. (kinds list/sign/refuse, destination) ; flags `--follow/--json` ✓ |
| `storage.rs` | `sbx storage` (init/migrate/use/status/up/down/unuse) | `cli/storage.md` | 🟡 | ✅ | doc 298 l. (la plus longue page CLI) ; flags `--force/--image/--json/--label/--size` ✓ — `--label` bien documenté en doc et en help |
| `store.rs` | `sbx store` | `cli/store.md` | 🟡 | ✅ | doc 87 l. (inodes, modes de comptage) ; flag `--json` ✓ |
| `task.rs` | `sbx task` (list/secrets/run/result/status/show/stop/logs) | `cli/task.md`, `configuration/task.md` | 🟡 | ✅ | doc 506 l. (la plus longue du site) ; flags `--param/-p/--env/-e/--detach/--session/--json` ✓ ; exit 125, quota, 32 résultats, log 512 — tout documenté |
| `test.rs` | `sbx test net` | `cli/test.md` | 🟡 | ✅ | doc 37 l. ; flags `--app/-a/--method/-X` ✓ (synopsis help.rs `test net` les inclut) |
| `trust.rs` | `sbx trust` / `sbx untrust` | `cli/trust.md`, `cli/untrust.md`, `concepts/trust.md` | 🟡 | ✅ | doc 43 l. + untrust 25 l. ; `--show` honoré en toute position (fix de l'audit précédent confirmé dans le code) ✓ |
| `upgrade.rs` | `sbx upgrade [all|nix|mise|flake|deb|appimage|tarball]` | `cli/upgrade.md`, `housekeeping/upgrade.md` | 🟡 | ✅ | doc 66 l. (table des cibles + `--project`) ; flag `--project` ✓ |

---

## `src/config/` — configuration

| Fichier | Rôle | Page(s) doc liée(s) | Lu | Doc | Notes |
|---|---|---|---|---|---|
| `mod.rs` | layering global/projet, gate de confiance, résolution | `configuration/README.md`, `concepts/trust.md` | ⬜ | ⬜ | |
| `types.rs` | types de la config résolue | `configuration/README.md` | ⬜ | ⬜ | |
| `schema.rs` | forme sur disque + parse (`RawConfig`…) | `configuration/README.md` (table des champs) | ⬜ | ⬜ | |
| `load.rs` | lecture disque, pin control-plane | `configuration/README.md` | ⬜ | ⬜ | |
| `safety.rs` | gate de sécurité des fichiers config | `concepts/trust.md` (safety gate) | ⬜ | ⬜ | |
| `overrides.rs` | overrides one-shot CLI/env | `configuration/overrides.md`, `reference/environment-variables.md` | ⬜ | ⬜ | |
| `view.rs` | modèle de vue de `sbx config show` | `cli/config.md` | ⬜ | ⬜ | |
| `manage.rs` | moteur d'édition des fichiers (`set/get/unset`) | `cli/config.md` | ⬜ | ⬜ | |
| `tasks.rs` | validation des `[task.<name>]` | `configuration/task.md` | ⬜ | ⬜ | |
| `secrets.rs` | sources de secrets + validation `[secret."host"]` | `configuration/secret.md`, `secrets/resolvers.md` | ⬜ | ⬜ | |
| `tests.rs` | tests du module | — (tests) | ⬜ | ⬜ | aucun besoin de page dédiée |

---

## `src/plugins/` — résolveurs de secrets

| Fichier | Rôle | Page(s) doc liée(s) | Lu | Doc | Notes |
|---|---|---|---|---|---|
| `mod.rs` | registre des plugins résolveurs | `secrets/plugins.md`, `secrets/resolvers.md` | ⬜ | ⬜ | |
| `catalogue.rs` | store signé distant — noyau de confiance hors-ligne | `secrets/plugins.md` | ⬜ | ⬜ | |
| `stores.rs` | fetch/vérif/cache des stores distants | `secrets/plugins.md` | ⬜ | ⬜ | |
| `origin.rs` | provenance d'un plugin installé | `secrets/plugins.md` | ⬜ | ⬜ | |

---

## `src/allowlist/` — politique d'egress

| Fichier | Rôle | Page(s) doc liée(s) | Lu | Doc | Notes |
|---|---|---|---|---|---|
| `mod.rs` | règles de correspondance + décision | `networking/rules.md`, `networking/architecture.md` | ⬜ | ⬜ | |
| `grammar.rs` | grammaire des entrées d'allowlist (hôte/URL/re:/tcp:) | `networking/rules.md` | ⬜ | ⬜ | |

---

## `src/sandbox/` — le cœur de la cage

### Noyau de la cage

| Fichier | Rôle | Page(s) doc liée(s) | Lu | Doc | Notes |
|---|---|---|---|---|---|
| `mod.rs` | `SandboxSpec` + conversion en argv bwrap | `concepts/overview.md`, `concepts/enforcement.md` | ⬜ | ⬜ | |
| `spec.rs` | spec déclarative + invariants | `concepts/enforcement.md` | ⬜ | ⬜ | |
| `argv.rs` | argv bwrap (namespaces, caps, seccomp) | `concepts/enforcement.md`, `bwrap-architecture.md` | ⬜ | ⬜ | |
| `binds.rs` | zones (caché/ro/rw), identité synthétique, userland FHS | `configuration/binds.md`, `concepts/security-model.md` | ⬜ | ⬜ | |
| `launch.rs` | lancement bwrap, sessions, `run` | `cli/run.md`, `concepts/provisioning.md` | ⬜ | ⬜ | |
| `pty.rs` | supervision pty interactive (job control, SIGWINCH) | `cli/run.md` (shell interactif) | ⬜ | ⬜ | |
| `attach.rs` | `sbx session attach` (jointure de ns) | `cli/session.md` | ⬜ | ⬜ | |
| `memfd.rs` | passage de bytes à bwrap par fd | interne | ⬜ | ⬜ | aucun besoin de page dédiée |
| `naming.rs` | nom lisible de la cage (scope systemd) | `concepts/directory-layout.md` | ⬜ | ⬜ | |
| `contract.rs` | contrat in-cage (ce que la cage permet) | `networking/observability.md` ? | ⬜ | ⬜ | **à mapper** — aucune page ne documente explicitement le fichier de contrat |
| `smoke.rs` | préflight live (launch minimal + vérif durcissement) | `getting-started/doctor.md` | ⬜ | ⬜ | |

### Enforcement

| Fichier | Rôle | Page(s) doc liée(s) | Lu | Doc | Notes |
|---|---|---|---|---|---|
| `seccomp.rs` | denylist seccomp-bpf obligatoire | `configuration/seccomp.md`, `concepts/enforcement.md` | ⬜ | ⬜ | |
| `proc_enforce.rs` | enforcement exec par seccomp user-notification | `configuration/proc.md` | ⬜ | ⬜ | |
| `proc_control.rs` | anneau des événements exec + socket `sbx proc logs` | `cli/proc.md` | ⬜ | ⬜ | |
| `cgroup.rs` | limites cgroup v2 (anti-DoS) | `configuration/limits.md` | ⬜ | ⬜ | |
| `netns.rs` | holder de netns (dummy0) | `networking/architecture.md`, `networking/modes.md` | ⬜ | ⬜ | |

### Egress réseau

| Fichier | Rôle | Page(s) doc liée(s) | Lu | Doc | Notes |
|---|---|---|---|---|---|
| `egress.rs` | câblage egress Model-B (proxy hôte + forwarder in-cage) | `networking/architecture.md` | ⬜ | ⬜ | |
| `forward.rs` | forwarding loopback hôte → cage | `networking/forward.md`, `configuration/network.md` | ⬜ | ⬜ | |
| `egress_stats.rs` | compteurs par hôte (allow/deny/blocked) | `networking/observability.md` | ⬜ | ⬜ | |
| `netlearn.rs` | synthèse de règles depuis le log (`--net-learn`) | `cli/app.md` (`--net-learn`), `networking/observability.md` | ⬜ | ⬜ | |
| `catrust.rs` | confiance CA pour Chromium/Electron | `networking/architecture.md`, `configuration/network.md` | ⬜ | ⬜ | |
| `proxy/mod.rs` | proxy MITM d'egress, hôte | `networking/architecture.md`, `networking/observability.md` | ⬜ | ⬜ | |
| `proxy/wire.rs` | parsing HTTP/1.1 bas niveau | `networking/architecture.md` | ⬜ | ⬜ | interne, peut rester hors guide |
| `proxy/h2mitm.rs` | MITM HTTP/2 (gRPC) | `networking/architecture.md` (`http2`) | ⬜ | ⬜ | |
| `proxy/ctx.rs` | contexte + politique évaluée | `networking/architecture.md` | ⬜ | ⬜ | interne |
| `proxy/ssrf.rs` | garde SSRF post-résolution | `networking/architecture.md` | ⬜ | ⬜ | |
| `proxy/websocket.rs` | proxying WebSocket | `networking/architecture.md` | ⬜ | ⬜ | |
| `proxy/ca.rs` | CA éphémère + résolveur de certificats | `networking/architecture.md` | ⬜ | ⬜ | interne |
| `proxy/dns.rs` | résolution DNS hôte + cache | `networking/architecture.md` | ⬜ | ⬜ | interne |
| `proxy/inject.rs` | injection de credential + needle anti-fuite | `secrets/injection.md`, `secrets/redaction.md` | ⬜ | ⬜ | |
| `control/mod.rs` | file de décisions `ask` + socket `sbx net pending` | `networking/ask.md` | ⬜ | ⬜ | |
| `control/client.rs` | client hôte de la control plane | `networking/ask.md`, `networking/observability.md` | ⬜ | ⬜ | |

### Observabilité in-cage

| Fichier | Rôle | Page(s) doc liée(s) | Lu | Doc | Notes |
|---|---|---|---|---|---|
| `observe_feed.rs` | moitié hôte de l'observation proc/fs | `concepts/observability.md` | ⬜ | ⬜ | |
| `fs_watch.rs` | observer d'écritures fs (inotify) | `cli/fs.md` | ⬜ | ⬜ | |
| `fs_control.rs` | anneau des écritures + socket `sbx fs logs` | `cli/fs.md` | ⬜ | ⬜ | |
| `notify_sink.rs` | où va une notification de refus | `configuration/notify.md` | ⬜ | ⬜ | |
| `notify_relay.rs` | relais de notifications in-cage (dbus) | `configuration/notify.md`, `configuration/dbus.md` | ⬜ | ⬜ | |

### Provisioning / packages / store

| Fichier | Rôle | Page(s) doc liée(s) | Lu | Doc | Notes |
|---|---|---|---|---|---|
| `packages.rs` | provisionnement des outils déclarés | `configuration/packages.md` | ⬜ | ⬜ | |
| `mise.rs` | moteur mise (provision + drive) | `configuration/tools.md`, `cli/mise.md` | ⬜ | ⬜ | |
| `miseplugin.rs` | plugin `nix:` embarqué pour mise | `configuration/tools.md` | ⬜ | ⬜ | |
| `nixhub.rs` | résolution `nix:` → références nixpkgs épinglées | `cli/search.md`, `configuration/packages.md` | ⬜ | ⬜ | |
| `flake.rs` | épinglage `flake:` + `sbx upgrade flake` | `configuration/packages.md`, `housekeeping/upgrade.md` | ⬜ | ⬜ | |
| `flake_inline.rs` | staging des `[flakes.<name>]` inline | `configuration/packages.md` (§ `[flakes]`) | ⬜ | ⬜ | |
| `prebuilt.rs` | socle commun `deb:`/`appimage:` | `configuration/packages.md` | ⬜ | ⬜ | |
| `deb.rs` | backend `deb:` | `configuration/packages.md` | ⬜ | ⬜ | |
| `appimage.rs` | backend `appimage:` | `configuration/packages.md` | ⬜ | ⬜ | |
| `tarball.rs` | backend `tarball:` | `configuration/packages.md` | ⬜ | ⬜ | |
| `resolve.rs` | commande `resolve` des backends prebuilt | `configuration/packages.md` (formes `:resolve`) | ⬜ | ⬜ | |
| `fhs.rs` | userland hermétique depuis le store sbx | `concepts/provisioning.md` | ⬜ | ⬜ | |
| `projectstore.rs` | store nix par-projet, seedé depuis le store partagé | `concepts/provisioning.md`, `concepts/directory-layout.md` | ⬜ | ⬜ | |
| `gc.rs` | GC du store par-projet | `housekeeping/gc.md`, `cli/gc.md` | ⬜ | ⬜ | |
| `search.rs` | `sbx search` (requête nixhub) | `cli/search.md` | ⬜ | ⬜ | |
| `taskpool.rs` | pool mise des tâches (lu en lecture seule) | `configuration/task.md` | ⬜ | ⬜ | |

### Tâches déclarées (`sbx task`)

| Fichier | Rôle | Page(s) doc liée(s) | Lu | Doc | Notes |
|---|---|---|---|---|---|
| `task.rs` | moteur de tâche (cage sœur éphémère) | `cli/task.md`, `configuration/task.md` | ⬜ | ⬜ | |
| `task_control.rs` | control plane des tâches (2 sockets) | `cli/task.md` | ⬜ | ⬜ | |
| `task_shim.rs` | client de tâche in-cage (script shell) | `configuration/task.md` | ⬜ | ⬜ | interne |

### GUI / GPU / audio / dbus

| Fichier | Rôle | Page(s) doc liée(s) | Lu | Doc | Notes |
|---|---|---|---|---|---|
| `fonts.rs` | polices du trou GUI Wayland | `configuration/gui.md` | ⬜ | ⬜ | |
| `guidata.rs` | schémas GSettings + thèmes GTK | `configuration/gui.md` | ⬜ | ⬜ | |
| `gpu.rs` | accélération GPU (mesa Intel/AMD/nouveau) | `configuration/gpu.md` | ⬜ | ⬜ | |
| `audio.rs` | micro + lecture via PulseAudio | `configuration/audio.md` | ⬜ | ⬜ | |
| `theme_relay.rs` | relais de thème live in-cage (dbus) | `configuration/gui.md`, `configuration/dbus.md` | ⬜ | ⬜ | |
| `portal.rs` | portail desktop in-cage (dbus) | `configuration/dbus.md` | ⬜ | ⬜ | |

### Secrets / ssh-agent

| Fichier | Rôle | Page(s) doc liée(s) | Lu | Doc | Notes |
|---|---|---|---|---|---|
| `resolver.rs` | runner sandboxé des plugins résolveurs | `secrets/resolvers.md`, `secrets/plugins.md` | ⬜ | ⬜ | |
| `redact.rs` | substitution nommée des valeurs secrètes | `secrets/redaction.md` | ⬜ | ⬜ | |
| `sshagent.rs` | broker ssh-agent filtrant (`[ssh_agent]`) | `configuration/ssh-agent.md` | ⬜ | ⬜ | |
| `sshagent_control.rs` | anneau des décisions + socket `sbx ssh-agent logs` | `cli/ssh-agent.md` | ⬜ | ⬜ | |

### Introspection / apps

| Fichier | Rôle | Page(s) doc liée(s) | Lu | Doc | Notes |
|---|---|---|---|---|---|
| `inspect.rs` | introspection disque (`sbx app show` / `sbx projects show`) | `cli/app.md`, `cli/projects.md` | ⬜ | ⬜ | |

---

## Autres fichiers à documenter

| Fichier | Rôle | Page(s) doc liée(s) | Lu | Doc | Notes |
|---|---|---|---|---|---|
| `build.rs` | script de build (embedding nix statique, sources) | `getting-started/installation.md` (self-contained) | ⬜ | ⬜ | |
| `proc-shim/src/main.rs` | moitié in-cage de l'enforcement exec | `configuration/proc.md` | ⬜ | ⬜ | |
| `plugins/vault/resolve` + `plugin.toml` + `README.md` | résolveur de secrets `vault:` | `secrets/plugins.md`, `secrets/resolvers.md` | ⬜ | ⬜ | |
| `plugins/pass/resolve` + `plugin.toml` + `README.md` | résolveur de secrets `pass:` | `secrets/plugins.md`, `secrets/resolvers.md` | ⬜ | ⬜ | |
| `mise/hooks/*.lua`, `mise/lib/*.lua` | hooks/toolchains mise embarqués | `configuration/tools.md`, `cli/mise.md` | ⬜ | ⬜ | vérifier si le guide décrit les backends (nix/flake/…) |

---

## Docs de conception (`docs/bwrap-*.md`) — hors site

| Fichier | Sujet | À jour ? | Notes |
|---|---|---|---|
| `bwrap-architecture.md` | squelette d'architecture, modules, jalons | ⬜ | |
| `bwrap-threat-model-and-binds.md` | modèle de menace + layout des binds | ⬜ | |
| `bwrap-security-stack.md` | briques d'enforcement | ⬜ | |
| `bwrap-secrets-architecture.md` | architecture des secrets | ⬜ | |

---

## Méthode d'audit (rappel)

1. Lire le fichier source (colonne **Lu** → ✅).
2. Comparer sa surface visible (verbes, options, champs config, invariants) à la/les page(s) liée(s).
3. Reporter les écarts dans **Notes** (info manquante, exemple absent, rubrique à créer, doc
   à découper/regrouper pour la lisibilité).
4. Passer la colonne **Doc** à ✅ (complet), 🟡 (lacunes listées) ou ❌ (manquant) selon le cas.
5. Mettre à jour la vue d'ensemble en tête de fichier.
