# Ce que le rapport `n8w5jx` vaut dans `ops-v2`

Le rapport ci-joint a été écrit contre `ops-v2` à `d717a05`, puis corrigé sur sa propre branche.
Cette branche n'a jamais été fusionnée. Ce document dit, pour chaque constat, ce qu'il en est dans
l'arbre **ici**, et surtout **comment on le sait** — parce que les deux ne se déduisent pas l'un de
l'autre.

Règle de lecture, la même que celle du registre voisin : **la colonne fait foi, la synthèse ne fait
pas foi.** Un chiffre de tête se recopie et survit au fait qu'il compte ; une ligne qui nomme sa
preuve ne le peut pas.

## Légende de provenance

| Provenance | Ce que ça garantit |
| --- | --- |
| **mesuré** | La ligne a été rouverte dans cet arbre et le prédicat du constat évalué sur le code présent. C'est le seul niveau qui autorise à dire « fermé ». |
| **non re-sondé** | Le constat a été rapproché d'un message de commit ou d'un correctif voisin, sans que la ligne soit rouverte ici. Une hypothèse, pas un verdict. |
| **jamais ouvert** | Personne n'a lu le constat depuis qu'il a été écrit. |

## HIGH (8) — les huit sont mesurés, les huit sont fermés

Chacun a été rouvert dans cet arbre : le prédicat du constat a été évalué sur le code présent, et le
commit qui l'a fermé est nommé.

| Constat | Statut | Fermé par | Ce qui a été mesuré |
| --- | --- | --- | --- |
| `binds.rs:1589` — les parents `[open]` créés par un `create_dir_all` qui suit les liens, puis bind-montés | fermé | `0ca9f8a` | `binds.rs:1238-1242` passe `APPLICATIONS_REL` et `MIMEAPPS_REL` par `cagedir::ensure_under` ancré sur `rt.home_src`. |
| `trust.rs:211` — la confiance transférable par un `.sbx.toml` symlink | fermé | `25691e1` | Le motif est écrit à `trust.rs:235-236` et le test `a_symlinked_config_does_not_inherit_the_trust_of_the_file_it_points_at` existe. |
| `config/mod.rs:132` — `BASH_FUNC_*` et les pré-chargements d'interpréteur absents de la denylist `[env]` | fermé | `2b6f01a` | `is_reserved_env_key` porte le préfixe et les quatre noms. |
| `fsmask.rs:311` — un masque `[fs] deny` que la cage rend irrésoluble s'évapore | fermé | `2b6f01a` | `resolve_list` sépare `NotFound` du reste et le second refuse le lancement. |
| `cli/config.rs:3058` — `config set` ré-atteste le fichier relu, pas les octets écrits | fermé | `8a4584d` | `trust::trust(` compte zéro dans `cli/config.rs`, `cli/net.rs` et `cli/proc.rs` ; les trois attestations passent par `trust_written` dans `main.rs`. |
| `cli/net.rs:3507` — même TOCTOU sur le retrait de règle | fermé | `2b6f01a` | Même mesure ; `RemoveOutcome::Removed` porte le texte composé. |
| `websocket.rs:1060` — les trames pipelinées derrière la poignée de main partent avant le scan | fermé | `1bbbe6e` | `seed_outbound_pending` (`websocket.rs:344`) appelle `follow` avant le `write_all`, et l'ordre est nommé comme la propriété. |
| `attach.rs:360` — le bras stdio hérité ne quitte pas la session de `sbx` | fermé | `2b6f01a` | `TtyMode::Inherit` appelle `setsid()` et sort en `126` s'il échoue. |

Quatre de ces fermetures sont antérieures au versement et viennent de l'arbre lui-même ; quatre ont
été écrites en re-dérivant ce rapport.

## MEDIUM (33)

Les trente-trois ont été rouverts à la ligne, puis traités un par un. **Les trente-trois sont
fermés**, par un correctif pour la plupart, par une mesure qui renverse l'énoncé pour trois, et par
un arbitrage écrit au site pour un. Deux cellules se sont trompées dans les deux sens, et les deux
sur une lecture plutôt que sur une mesure : `proc_enforce.rs:1266` était donné corrigé et ne l'était
pas ; `gc.rs:103` était donné ouvert sur un fait juste — `gc.rs` ne réconcilie pas — dont la
conséquence énoncée ne suit pas, la réconciliation vivant un module plus loin.

Chaque correctif porte un test **vu rouge sans lui**, et la colonne de droite dit ce que cette
mesure a donné plutôt que ce que le correctif prétend faire. Deux constats se sont révélés plus
larges que leur énoncé une fois mesurés (`proc_enforce.rs:1740`, `tarball.rs:126`), et un s'est
révélé plus grave (`h2mitm.rs:864` : la requête n'était pas refusée du tout).

Trois sont fermés **sans changement de comportement**, et la colonne dit pourquoi plutôt que de le
sous-entendre : `store.rs:1174` (l'app est l'unité partout ailleurs — mais la mesure a trouvé un
couplage non gardé, et la garde est écrite), `h2mitm.rs:558` (la mesure sépare le cas qui mord des
deux qui ne mordent pas ; les déclencheurs sont écrits) et `proc_enforce.rs:1266` (les deux remèdes
possibles sont nommés avec leur coût, et l'un des deux est invérifiable sur cet hôte).

| Constat | Statut | Provenance |
| --- | --- | --- |
| `websocket.rs:596` — une trame de contrôle de plus de 125 octets relayée sans scan | fermé par `1bbbe6e` | **mesuré** — `wsframe.rs:802` refuse `payload_len > CONTROL_MAX` sur un opcode de contrôle. |
| `config/fspolicy.rs:108` — un projet non approuvé rétrécit la fenêtre `[fs] scan` | fermé par `2b6f01a` | **mesuré** — remède différent de celui proposé : le pli sert aussi l'override autoritaire de l'appelant, donc `scan_max_kb` est gaté aux deux sites qu'une couche non approuvée atteint plutôt que rendu participant au `max`. |
| `config/mod.rs:3867` — un projet non approuvé fournit le `cmd` d'un profil approuvé | fermé par `2b6f01a` | **mesuré** — la porte interroge la provenance de l'app, non le champ. |
| `deb.rs:598` — la chaîne apt signée s'arrête à l'index | fermé par `2b6f01a` | **mesuré** — le `SHA256:` de la strophe gagnante est remis à nix, et un index attesté sans condensat est refusé. |
| `store.rs:404` — un `$HOME` relatif résout le répertoire de données contre le cwd | fermé par `2b6f01a` | **mesuré** — le refus est aussi *classé* comme refus, `sbx path` ne le lisant plus comme une absence. |
| `allowlist/mod.rs:587` — la canonicalisation ne retire ni `;params` ni `#fragment` | fermé par `2b6f01a` | **mesuré** — les deux coupes sont après décodage, le compromis est écrit au site. |
| `overrides.rs:685` — `union_fs_opt` plie `scan_max_kb` avec `min` | fermé par `34a9431` | **mesuré** — le pli est `max`. La note de session portait ce constat comme ouvert jusqu'à ce que le `pull` montre le contraire. |
| `gc.rs:103` — les out-links des outils mise `nix:` ne sont jamais élagués | **fermé** par `7e07e39` | **mesuré, et la cellule précédente lisait le bon fait pour la mauvaise conclusion** — `gc.rs` ne réconcilie effectivement pas, mais la conséquence énoncée (la clôture n'est jamais récupérable) ne suit pas : `nixhub::prune_tool_roots` retire à chaque lancement tout out-link qu'aucun outil déclaré ne réclame, avant le retour sur déclaration vide, deux tests le tiennent, et `gc.rs` n'a qu'à garder les vivants. Ce qui reste est un cran plus haut et écrit au site : `mise_tools` retourne avant d'appeler `provision` quand le projet n'a plus de fichier mise du tout. |
| `proc_enforce.rs:1266` — un `openat2` portant un bit `resolve` récupère la fenêtre d'échange | **fermé documentairement** par `950eb02` | **mesuré, arbitrage rendu et écrit** — le prédicat tient, et il est plus net que l'énoncé : *tout* `resolve` non nul prend la branche, donc la cage choisit la fenêtre en posant un bit qui ne lui coûte rien. Le verdict n'est pas touché. Les deux alternatives sont nommées au site avec leur coût — refuser punit la défense que la branche protège, servir demande de reprendre la sonde en `openat2` `RESOLVE_IN_ROOT` sur le chemin d'application, invérifiable sur un hôte sans cage — et le déclencheur est écrit. |
| `h2mitm.rs:864` — `:method` jamais scanné sur le plan h2 | **fermé** par `f1f584d` | **mesuré, puis corrigé** — `head_carries_secret` bâtit son tampon depuis la méthode, le schéma, l'autorité puis les en-têtes. Calibré : sans le correctif la requête portant le secret dans `:method` **n'est pas refusée du tout** — elle atteint le connect amont et rend `502`, quand le témoin en en-tête rend `403`. |
| `websocket.rs:645` — un rembourrage compressible pousse un secret au-delà du plafond de scan | **fermé** par `6f9d89a` | **mesuré, puis corrigé** — L'inflateur passe chaque octet au scan **dans l'ordre du flux**. Deux moitiés calibrées séparément : jeter la queue, ou décider le reste par la position de l'entrée. |
| `openuri.rs:17` — la route OpenURI gelée est re-pointable par un `[env]` non approuvé | **fermé** par `f1f584d` | **mesuré, puis corrigé** — Les deux clés sont dans `is_reserved_env_key`, le commentaire contradictoire de `portal.rs` nomme l'exception, et la liste du guide — en retard de six entrées — est à jour. |
| `plugins/mod.rs:1583` — `plugins rm` laisse le répertoire d'état privé du plugin | **fermé** par `f1f584d` | **mesuré, puis corrigé** — `forget_state` efface `<data>/plugin-state/<name>` par renommage puis suppression, et le chemin a désormais **une** définition partagée par le créateur et le suppresseur. |
| `proxy/mod.rs:761` — `connect(2)` non borné sur les chemins amont synchrones | **fermé** par `f05e397` | **mesuré, puis corrigé** — `ssrf::dial_bounded` sur les trois plans synchrones. Mesuré : **133 s** d'attente sans la borne, pour une échéance de 200 ms. |
| `proc_enforce.rs:800` — le `recvmsg` du passage de descripteur bloque sur une socket atteignable depuis la cage | **fermé** par `c50494b` | **mesuré, puis corrigé** — `HANDOFF_SILENCE` borne un pair muet, traité comme un handoff refusé. Mesuré : sans la borne la boucle est encore parquée quand le test la tue. |
| `launch.rs:3489` — les avertissements de configuration sont imprimés sans filtrage | **fermé** par `f1f584d, 5228b73` | **mesuré, puis corrigé** — `diag::warn_config` filtre les neuf boucles **et** les dix-sept sites en ligne qui interpolent une valeur de config, lus un par un. Le log détaché est filtré aussi, avec un test qui le mesure. |
| `grammar.rs:548` — un `*` ailleurs qu'en fin de chemin est silencieusement littéral | **fermé** par `f69972d` | **mesuré, puis corrigé** — Refusé à l'analyse, en nommant les deux formes qui marchent ; le guide le documente. |
| `secrets.rs:70` — `upsert_secret` ne remplace que la première déclaration en collision | **fermé** par `292fad3` | **mesuré, puis corrigé** — sans le correctif l'ensemble garde `["Authorization", "Signature"]` **et** `["Signature"]`, et `Signature` part deux fois. Le remède du rapport (comparer sur le recouvrement de règle) a été écarté : le même rapport arbitre cette question dans l'autre sens un constat plus loin. La portée reste l'égalité des cibles ; seul change le NOMBRE de déclarations qu'une seule peut supplanter. |
| `tarball.rs:126` — le `fetchurl` généré omet `name` | **fermé** par `f69972d` | **mesuré, puis corrigé** — Les quatre gabarits nomment leur téléchargement, et une garde les compte. |
| `proc_enforce.rs:1740` — `libc::SYS_open` sans la garde `cfg` | **fermé** par `f69972d` | **mesuré, puis corrigé** — Les trois sites de production et trois assertions de test sont gardés. Vérifié dans le libc épinglé plutôt que par ajout de cible. |
| `h2mitm.rs:558` — rafraîchissement et DNS bloquants sur le runtime partagé du tunnel | **fermé par la mesure, limite écrite** par `90a2d4b` | **mesuré** — la structure est bien celle-là, et mesurer les trois appels en sépare un des deux autres. La résolution passe par `caching_resolver` (60 s par défaut) et tous les flux d'un CONNECT partagent une autorité : elle bloque une fois par hôte et par fenêtre, par requête seulement sous `dns_cache_ttl = 0`. Le rafraîchissement ne court que sur un `401`, borné par son propre écart minimal. Reste le signer, par requête — et son mutex sérialise la signature sur n'importe quel fil, donc déplacer ne rendrait que les flux étrangers. `spawn_blocking` veut `Send + 'static`, l'emprunt que ce plan est fait pour éviter : les deux déclencheurs sont écrits à côté de la décision. |
| `store.rs:1174` — le verrou de canal d'une app est clé par le seul nom | **fermé par la mesure, limite et garde écrites** par `144c357` | **mesuré** — le prédicat tient, la gravité non, et c'est la surface autour qui tranche : `purge_app_homes` retire `<data>/apps/<name>/` **et** chaque `<data>/projects/*/apps/<name>/` pour un seul nom, et un roulement nomme une app, pas une app dans un projet. L'app est l'unité partout ; `home_scope` porte le home inscriptible, pas l'app. La trouvaille est ailleurs : `live_base_revisions` ne descend que d'un niveau, donc un verrou re-clé sous un projet lui serait invisible — une révision que l'ensemble à conserver rate est collectée sous un home vivant. Mesuré : déplacer le verrou d'un répertoire laisse le test voisin **vert**. `every_lock_target_writes_where_the_keep_set_reads` prend chaque chemin du constructeur qui l'écrit. |
| `store.rs:1724` — un out-link de gcroot repointé sans invalider le témoin `.expr` voisin | **fermé** par `1a6c9cf` | **mesuré, puis corrigé** — le partage est réel et non théorique : `packages.rs` enracine **chaque** entrée à `<gcroots>/<nom>`, quel que soit le backend déclaré, donc `nix:` repointe l'out-link que `flake:` a estampillé. Le témoin porte désormais le chemin de store à côté du condensat et la réutilisation exige les deux — ce qui répond de toute la prétention du court-circuit et tient contre n'importe quel écrivain, pas contre les deux connus. Calibré : sans la vérification du chemin, un out-link repointé sous un condensat inchangé est réutilisé. Un témoin d'avant reconstruit une fois : le seul sens d'échec possible. |
| `allowlist/mod.rs:1516` — un `deny` ne peut pas refuser un WebSocket sur le plan cleartext | fermé | **mesuré** — `explain_clear` interroge `matches_deny` (`allowlist/mod.rs:1562`), et sa doc (`:1545`) énonce la règle. |
| `h2mitm.rs:153` — un tunnel h2 sans flux épingle un thread pour toujours | fermé | **mesuré** — La borne existe (`h2mitm.rs:186-233`) : `ctx.idle` court en parallèle d'`accept()`. La doc (`:163-176`) nomme le `503 connection-cap` que le constat décrivait. |
| `gc.rs:881` — `prune_app_tools` rejoint le nom filtré pour l'affichage | fermé | **mesuré** — `installs.join(&tool.dir_name)` (`gc.rs:945`), avec la raison écrite : le filtrage n'est pas réversible. |
| `gc.rs:518` — un arbre de projet rapporté récupéré alors que la suppression a échoué | fermé | **mesuré** — `ReapReport` porte un champ `failed` et la branche d'échec y verse au lieu de pousser dans `dead`. |
| `cli/app.rs:198` — `--detach=false` allume `detach` | fermé | **mesuré** — `refuse_flag_value(&raw, APP_LAUNCH_VALUELESS_FLAGS, …)` court avant le `match flag_name`, et `--detach` est dans la liste (`app.rs:156`). |
| `inspect.rs:129` — `backend_token` suit un lien ou une FIFO | fermé | **mesuré** — `read_cage_metadata` ouvre en `O_NOFOLLOW | O_NONBLOCK`, vérifie le type **sur le descripteur** et plafonne à `CAGE_METADATA_CAP`. |
| `inspect.rs:347` — `flake_built_in` rend un texte de lien non filtré | fermé | **mesuré** — `sanitize` est appliqué au détail lu par `read_link` (`inspect.rs:413`). |
| `overrides.rs:648` — `union_allow_opt` perd le `confirm` de `[ssh_agent]` | fermé | **mesuré** — `union_ssh_agent_opt` est dédié, destructure exhaustivement, et sa doc raconte exactement la perte que le constat décrit. |
| `cli/upgrade.rs:43` — `nix` app-scopable mais classé projet | fermé | **mesuré** — `APP_SCOPED_TARGETS` contient `"nix"` (`upgrade.rs:46`), avec la raison écrite. |
| `fs_watch.rs:192` — la surveillance inotify suit un lien posé par la cage | fermé | **mesuré** — `WATCH_MASK` porte `IN_DONT_FOLLOW`, le type d'entrée est lu sans suivre, et la doc (`:248-253`) dit que les deux mécanismes tiennent ensemble. |

**Mesuré depuis (2026-09-01) : la moitié DOCUMENTAIRE du constat est confirmée, la moitié
EXPLOITABLE ne l'est pas.** `fs.md` affirmait deux choses fausses — « **Every** open a cage makes is
answered this way » et « **One** gap is left, and it is **not one a cage can arrange** ». Le déclin
sur `resolve` est un second trou, et c'en est un que la cage arrange en choisissant la forme de son
appel système, sans privilège ni course. La page le nomme désormais, avec le fait qu'il n'est pas
annoncé là où le repli noyau l'est. Ce correctif ne change aucune sémantique : il rend la page vraie
sur une décision volontaire.

Ce qui reste **non mesuré** est la course elle-même : que la fenêtre entre le jugement et le
`CONTINUE` soit gagnable par un thread frère. Le mécanisme, lui, est épinglé par un test qui existe
et qui l'affirme comme correct — `a_restricted_openat2_is_left_to_the_kernel_to_walk`. La produire
demanderait une sonde compilée appelant `openat2` en brut depuis la cage, le harnais e2e n'y lançant
qu'un script shell. Tant qu'elle ne l'est pas, choisir (a) ou (b) serait renverser une décision
délibérée et testée sur la foi d'une lecture — exactement ce que cette même colonne refuse de faire
pour `argv.rs:147`.

**`proc_enforce.rs:1266` était porté « fermé » et ne l'est pas.** C'était la seule cellule MEDIUM
tenue pour fermée sans mesure, sur la foi de la prose du rapport, qui décrivait un remède. La ligne
rouverte dit l'inverse : `open_serve.rs:63` décline la remise pour **tout** `resolve` non nul et
répond `CONTINUE`, ce qui est exactement la seconde marche que `fs.md` déclare supprimée. Le
commentaire du site a bien changé — l'arbitrage est désormais écrit au long, ce que le rapport
reprochait de ne pas être — mais écrire un arbitrage n'est pas le rendre dans l'autre sens.

Et le voisin immédiat montre que le remède proposé est praticable : la branche `O_NOFOLLOW`, vingt
lignes plus bas, **décide** au lieu de décliner — elle re-teste le dernier composant et répond
l'errno que le noyau aurait rendu. Son commentaire renvoie même à la règle du contrôle `resolve`
au-dessus. Une règle écrite, appliquée à une moitié : c'est la forme de défaut la plus productive de
cet audit.

**Arbitrage rendu le 2026-09-02, et écrit au site (`950eb02`).** La comparaison avec le voisin ne
tient pas jusqu'au bout, et c'est ce qui décide : la branche `O_NOFOLLOW` peut *décider* parce que
`lstat` répond exactement à sa question — le dernier composant est-il un lien. La question d'un mot
`resolve` est un parcours entier sous contraintes que seul le noyau applique, et rien d'autre
qu'`openat2` n'y répond ; servir demanderait donc de reprendre la sonde en `openat2` ancré par
`RESOLVE_IN_ROOT` sur un dirfd de `/proc/<pid>/root` — ce qui absorberait au passage ce que
`vouched_probe` vérifie à la main, et reste une réécriture de la sonde **sur le chemin
d'application**, invérifiable sur un hôte qui ne lance pas de cage. C'est le motif que le rapport
lui-même a accepté pour `observe_feed`.

Ce que la mesure a ajouté, et qui manquait : la fenêtre n'est pas résiduelle, elle est **choisie par
l'appelant**. N'importe quel bit `resolve` prend la branche, donc un programme de la cage qui pose
`RESOLVE_NO_MAGICLINKS` — sans rien y perdre — renvoie *tous* ses opens au `CONTINUE`. Le refus,
lui, refuse toujours. Les deux alternatives sont nommées au site avec leur coût, et le déclencheur
avec elles : un lancement qui a besoin que ses `openat2` soient servis, mesuré là où une cage tourne.

**`gc.rs:103` : le fait était juste, la conclusion non.** `gc.rs` ne réconcilie pas `nix-tools/`, et
il n'a pas à le faire. `2b6f01a` avait déjà corrigé le site qui le fait — `nixhub::provision`, dont
la réconciliation était appelée sous le retour anticipé d'une déclaration vide, donc retirer le
*dernier* outil la sautait — et la cellule a lu ce correctif comme voisin plutôt que comme le
constat. L'objection du rapport (réconcilier contre l'ensemble de `gc.rs` supprimerait tout root
vivant au premier `sbx gc --prune`) reste juste, et c'est exactement pourquoi la réconciliation
appartient à la déclaration : seule elle sait ce qui est vivant, et le nommage de l'out-link a une
définition unique que les deux lecteurs partagent.

Ce qui a été refermé, c'est la lecture : la doc de `project_keep_roots` dit désormais où vit la
réconciliation, parce qu'un lecteur qui la cherche dans le `gc` conclut ce que le constat a conclu.
Et **un résidu réel a été trouvé un cran plus haut**, de la même forme un retour plus loin :
`mise_tools` rend la main avant d'appeler `provision` quand le projet n'a plus de fichier mise du
tout, donc retirer le dernier *outil* réconcilie, mais retirer le dernier *fichier* ne réconcilie
pas. Non hissé, et la raison est écrite avec son déclencheur : élaguer suppose un projet approuvé, et
le verdict de confiance mise vit sur la `MiseConfig` absente là.

## LOW (51) — les cinquante-et-un sont mesurés

Les 28 constats en prose ont été rouverts un par un, puis les 23 du tableau. Le compte, par seau
plutôt que par un chiffre unique : **49 fermés + 1 réfuté + 1 ouvert = 51**.

Le réfuté est `plugins/stores.rs:775` : sa prémisse ne tient pas dans cet arbre, ce qui n'est pas la
même chose qu'un défaut corrigé. L'ouvert est `argv.rs:147`, et délibérément — sa course n'a été
reproduite par personne, et ses trois remèdes changent la durée de vie d'un lancement détaché.

Deux ont mesuré **plus large** que leur énoncé (`plugins/catalogue.rs:291`, `sandbox/launch.rs:3944`)
et un **plus étroit** (`cli/completion.rs:766` nommait `sbx run --gpu`, le défaut vaut aussi pour
`--audio` et `--dbus`, et coûtait en plus une position d'opérande).

### Fermés (25 en prose, 3 au tableau)

| Constat | Fermé par | Ce qui a été mesuré |
| --- | --- | --- |
| `proxy/ssrf.rs:60` — `embedded_v4` ignore `::a.b.c.d` | `2b6f01a` | Le remède évident (`to_ipv4`) ouvrait la boucle locale ; les deux adresses concernées sont écartées. |
| `allowlist/mod.rs:475` — `matches_mute` lit son jeu de méthodes du côté *allow* | `2b6f01a` | `admits_deny`. |
| `proxy/mod.rs:990` — `keeps_alive` découpe avec `split_whitespace` | `2b6f01a` | Un seul lecteur du jeton de version. |
| `proxy/wire.rs:445` — `parse_chunk_size` accepte une taille signée ou espacée | `2b6f01a` | `1*HEXDIG` exigé. |
| `prebuilt.rs:859` — `provision_pinned` réécrit le verrou depuis un instantané d'avant le mint | l'arbre | L'écriture est additive (`prebuilt.rs:939-943`), relue après le mint, et la raison est écrite au site. |
| `cgroup.rs:372` — `cage_scope_dirs` parcourt la tranche de tous les utilisateurs | l'arbre | `user_slice_root(uid)` rend `/sys/fs/cgroup/user.slice/user-<uid>.slice`. |
| `config/overrides.rs:272` — `env::vars()` panique sur une variable non-UTF-8 | l'arbre | `overrides.rs:280` lit en `vars_os()`. |
| `store.rs:323` — `LONGEST_SOCKET_SUFFIX` sous-estime le plus large chemin de socket | l'arbre | `BROKER_NAME_MAX` (`store/layout.rs:380`) est dérivé du budget. C'est le remède de l'autre audit ; les deux branches en proposaient un différent, celui-ci a été retenu. |
| `allowlist/mod.rs:1093` — `capture_max_kb` perdu sans un mot quand une couche redéclare `capture` | — | **Fermé par argument au site, pas par mesure** : `allowlist/mod.rs:1126` soutient que `capture_body_kb` chevauche `capture`, donc nommer l'un nomme l'autre. L'argument n'a pas été vérifié contre le comportement observable. |
| `config/tools.rs:654` — le suffixe `.deb` est apparié avec la casse | ce dépôt | **Mesuré** : `select_release_asset` minuscule le nom d'un asset avant de l'apparier, donc une release publiant `.DEB` était sélectionnée puis refusée en bloc. Le frère `is_valid_appimage_url` minuscule déjà, en disant pourquoi. |
| `config/load.rs:969` — `DESCRIBED` liste `"uses"` | ce dépôt | **Mesuré** : la clé sérialisée est `use`. La phrase de doc qui promettait un garde contre ce cas est devenue vraie : un profil déclarant les dix-huit clés est asserté sans ligne fourre-tout. |
| `proxy/mod.rs:483` — le garde d'IP littérale au CONNECT teste l'hôte brut | ce dépôt | **Mesuré, et plus grave que le constat** : sans le correctif, `CONNECT 127.0.0.1.:443` reçoit `200 Connection established` — le refus ne part pas du tout. Ce qui arrête ensuite la requête est le verdict de politique, rendu sur `connect_host` ; aucun contournement de politique n'est démontré, mais le garde ne tient pas son contrat. |
| `seccomp.rs:1287` — le commentaire annonce `EFAULT` | ce dépôt | Prose seule : l'assertion trois lignes plus bas lit `EINVAL`, et la raison est désormais écrite — `clone3` refuse une taille sous sa première version avant de déréférencer le pointeur. |
| `binds/tests.rs:295` — l'assertion « identifiant dégénéré » | ce dépôt | **Mesuré** : le sentinelle est calculé, non écrit. En mutant `machine_id_contents` pour qu'il ne hache plus rien, le test vire au rouge sur une valeur de 32 caractères — un de moins que le littéral qu'il portait. |
| `config/safety.rs:86` — la lecture d'une config n'est pas bornée | ce dépôt | **Mesuré** : `read_to_end` sans plafond sur un fichier que le dépôt cloné fournit. Plafond à 1 Mio, trois ordres de grandeur au-dessus du plus gros profil livré (~21 Kio) ; un fichier exactement au plafond est toujours chargé, pour que le refus ne puisse pas être satisfait en refusant tout. |
| `proxy/wire.rs:397` — la section de trailers n'est bornée ni en lignes ni par une échéance | ce dépôt | **Mesuré, et la moitié restante est écrite** : le nombre de lignes est plafonné, ce qui met fin à la boucle infinie. L'échéance, non : aucun des deux appelants de production ne passe un lecteur `Deadlined`, donc tout le corps chunked — données comprises — est borné en taille et pas en temps. Le goutte-à-goutte lent est une propriété du chemin de corps entier, pas de ce constat. |
| `proc_enforce/notify.rs:274` — `recv_fd_raw` ignore `cmsg_len` | ce dépôt | **Mesuré** : sans le correctif, un message à deux descripteurs rend `Ok(6)` et fuit le second. Le refus lit désormais TOUS les descripteurs et les ferme AVANT de rendre l'erreur — un refus qui rend la main sans fermer fuit exactement ce qu'il refuse. `MSG_CTRUNC` est refusé, et la limite du nettoyage est écrite : ce que le noyau a jeté n'est nommé par aucun cmsg. |
| `control/capture.rs:494` — l'élagage de l'historique d'aiguilles part de la tête | ce dépôt | **Mesuré** : sans le correctif, le rafraîchissement 255 dépose la clé statique EN CLAIR dans l'anneau. Le tri sépare retirées et vivantes ; le plafond cède avant qu'une valeur vivante ne tombe, parce que dépasser un plafond de coût est un coût et jeter une aiguille vivante est une divulgation. |
| `proxy/h2mitm.rs:206` — le refus de plafond de flux n'est enregistré nulle part | ce dépôt | Le journal est poussé avant la réponse, en `Blocked` — la documentation de `LogVerdict` y range le plafond de splice, dont c'est le jumeau h2. **Sans test de comportement** : le garde est un filet contre un client qui viole ses propres SETTINGS, et le client `h2` les respecte, donc l'atteindre demanderait un écrivain de trames brut. La raison est écrite au site. |
| `allowlist/grammar.rs` — une chaîne de requête dans un chemin de règle élargit la règle | ce dépôt | **Refusée à l'analyse**, comme le refus d'hôte joker une ligne plus haut, plutôt que de se mettre à apparier les requêtes. Sans le correctif la règle garde `path: "/exec?cmd=ls"` et n'apparie que `/exec`. |
| `allowlist/mod.rs:426` — une règle `re:` ancrée sur `http://` ne peut jamais apparier | ce dépôt | **Refusée à l'analyse** : l'URL testée est toujours rebâtie en `https://`. Un motif qui contient un schéma sans y être ancré est laissé tranquille. |
| `sandbox/argv.rs:49` — `compose` réécrit tout élément d'argv égal au marqueur | ce dépôt | **Mesuré** : sans le correctif, `sbx run -- printf '%s\n' @sbx-env-args` reçoit `"3"` — le numéro du descripteur. La substitution vise désormais la position que `to_argv` a écrite, après son `--args`. |
| `sandbox/argv.rs:82` — un NUL dans un *nom* est rapporté comme « the value of » | ce dépôt | **Mesuré** : l'ancien message disait « the value of `PO ISON` » — il se trompait de moitié ET recrachait les octets qu'il refuse. Le nom est décrit, jamais cité ; la valeur est trouvée en nommant sa clé. |
| `sandbox/binds.rs:1189` — le routeur d'URL n'est exécutable qu'après le renommage | ce dépôt | Le mode monte sur le fichier temporaire, donc le renommage est la seule chose qui paraisse au chemin final. **Le constat surestime** : la fenêtre montre un routeur NON exécutable, donc c'est une correction de justesse contre un lancement concurrent du même home, pas une élévation. |
| `sandbox/cgroup.rs:110` — `is_valid_memory_value` accepte ce que systemd refuse | ce dépôt | **Mesuré** : `99E` passait. La borne est 2^64 strict, pas `u64::MAX as f64` — cette conversion arrondit VERS LE HAUT et aurait laissé passer la plus grande valeur qu'un `u64` ne tient pas. |
| `config/secrets.rs:191` — le nom par défaut d'un secret échappe à `validate_secret_name` | ce dépôt | **Mesuré** : `classify` accepte un octet de contrôle, un saut de ligne, un ESC et un `}` dans le chemin d'une cible ; le nom par défaut était la clé brute, rendue en `${name}`. Il vient désormais de l'hôte classifié, dont les labels sont lettres, chiffres et tirets. |
| `proxy/ssrf.rs:299` — une seule adresse d'un hôte multi-domicilié est essayée | ce dépôt | **Mesuré** : sans le correctif, `502 upstream-unreachable` pour un hôte dont la seconde adresse répond. `checked_address` rend désormais **toutes** les adresses permises — le garde passe sur chacune, donc parcourir ne peut pas atteindre une adresse qu'il a refusée — et les six chemins de dial les essaient dans l'ordre (`first_reachable`, ou une boucle awaitée sur le plan h2). |
| `observe_feed.rs:44` — le filtre du flux d'exec s'appuie sur `comm` | ce dépôt | **Prose seule, et c'est le remède que le rapport approuve** : la limite honnête est écrite au site — `prctl(PR_SET_NAME)` laisse un processus se nommer `bwrap`, c'est un trou d'OBSERVATION et non d'application (le chemin `enforce` lit l'exécutable par la vue du superviseur), et le fermer demande une identité que le lancement possède. Le code reste tel quel, pour la raison que le rapport donne. |

### Ouvert et mesuré (1 en prose)

| Constat | Ce qui est mesuré |
| --- | --- |
| `sandbox/argv.rs:147` — `--die-with-parent` est inconditionnel, y compris détaché | La branche `exec`-replace de `detached_child` survit à la décomposition (`launch/detach.rs:157`), donc le chemin existe toujours. **Verdict PLAUSIBLE conservé, et laissé ouvert délibérément** : la course n'a été reproduite ni par le rapport ni ici, et les trois remèdes proposés changent chacun la durée de vie d'un lancement détaché sans qu'on puisse observer le correctif fonctionner sur cette machine. Le fermer sur la foi d'une lecture serait un changement de sémantique sans mesure. |

### Mesurés le 2026-09-02 (2 en prose, les 23 du tableau)

Deux des fichiers cités n'existent plus sous ce nom (`launch.rs`, `proc_enforce.rs`, repliés en
répertoires par la décomposition) ; chaque constat a été re-localisé avant d'être jugé, parce qu'une
conclusion de portée ne se transporte pas à travers un déplacement.

Les vingt-trois lignes du tableau sont reprises ici **en entier**, y compris les quatre dont la
liste « Fermés » ci-dessus porte déjà le verdict sous d'autres coordonnées (`observe_feed.rs:44`
pour `:179`, `h2mitm.rs:206` pour `:160`, `ssrf.rs:299` pour `:248`, et `store.rs:323` sous son
propre nom) : un lecteur du tableau doit pouvoir le parcourir sans reconstituer un appariement de
numéros de ligne.

**L'arithmétique, puisque ces quatre paraissent deux fois.** 28 lignes « Fermés » (25 en prose,
3 du tableau) + 1 « Ouvert » + 25 ici (2 en prose, les 23 du tableau) = 54 lignes pour **51
constats** : trois du tableau sont comptés dans les deux listes. Par seau : **49 fermés, 1 réfuté
(`plugins/stores.rs:775`), 1 ouvert (`argv.rs:147`)**.

| Constat | Statut | Ce qui a été mesuré |
| --- | --- | --- |
| `attach.rs:95` — pidfd ouvert après la découverte | fermé par `attach.rs` | **Mesuré, et la doc était fausse** : un pidfd ne pin qu'à partir de son ouverture, et la phrase promettait de couvrir la découverte aussi. Le prédicat discriminant — la cage de cette session porte-t-elle le projet — est re-posé sur le pid épinglé, donc un pid recyclé en un processus étranger est refusé au lieu d'être rejoint. La fenêtre restante exige que le recyclé satisfasse le prédicat, c'est-à-dire soit un autre processus de la MÊME cage : pas un mauvais endroit où s'attacher. |
| `proc_enforce:1302` — la re-sonde `O_NOFOLLOW` répond `ELOOP` pour des errnos du superviseur | fermé par argument au site | **Mesuré** : le bras `Err(_)` répond bien `ELOOP` quel que soit l'errno, et la raison est écrite — le chemin ne résout plus depuis ici, ce qui est la course et non un lien ; des deux réponses, `ELOOP` est celle qui ne peut pas servir un inode que cet appel n'a pas établi. Rendre l'errno vrai divulguerait l'état du superviseur. |
| `cli/completion.rs:766` — un drapeau à valeur optionnelle modélisé comme consommant le mot suivant | fermé par `bff6ff2` | **Mesuré, puis corrigé** : `take_override_flag` donne à `--gpu`/`--audio`/`--dbus` un chemin dédié pour ne **pas** consommer l'argument suivant, et le dit. La complétion les comptait consommateurs : elle offrait `true`/`false` en mot suivant — que le parseur lit comme la commande — et marquait consommé un opérande réel tapé là, décalant les positions derrière. `tail_is_fused` est la définition unique que les deux lecteurs partagent. |
| `cli/logs.rs:708` — `--follow` teste la fin avant d'écrire le lot qu'il vient de lire | fermé par l'arbre | **Mesuré** : la boucle écrit les lignes du tour **avant** d'agir sur sa fin, avec la raison au site — un flux peut perdre son curseur sur une lecture *réussie* qui a rendu des lignes. |
| `cli/mod.rs:479` — le bras `logs` ne peut jamais atteindre son `maybe_help` | fermé par `8871f2c` | **Mesuré, puis retiré** : `main` intercepte le drapeau d'aide pour toute commande connue sauf `run` et `mise`, qui le disent. Vérifié **sur le binaire** plutôt que sur la lecture : `sbx logs --help` et l'alias `sbx log -h` rendent la page. |
| `cli/proc.rs:405` — le commentaire prétendait que `proc pending` refuse un projet irrésolu | fermé par le rapport | Prose corrigée à la source ; la portée projet est refusée avec sa raison (une surface CLI nouvelle, ni minimale ni locale). |
| `cli/upgrade.rs:548` — `plan_app_upgrade` parcourt les deux couches non fusionnées | fermé par `237c197` | **Mesuré, puis corrigé** : sans le correctif, un nom que l'app redéclare compte **deux** paquets retenus là où la cage en équipe un, et le backend de la ligne de base nomme un canal que la déclaration de l'app a remplacé. Fusionné par nom, l'app en dernier — la précédence du lancement. |
| `help.rs:308` — la page `app run` replie les drapeaux d'override en une ligne sans grammaire | fermé par l'arbre | **Mesuré** : la page porte chaque drapeau sur sa propre ligne avec sa valeur. Le résidu de complétion qu'elle décrivait est celui de `completion.rs:766`, corrigé ci-dessus. |
| `paths.rs:48` — `DATA_ENTRIES` omet `flake-inline/` | fermé par `4474f10` | **Mesuré, puis corrigé** : la garde qui existe pour cela demande « sous quoi un lancement **bind** », et la racine de staging est écrite puis liée — possédée par toute lecture de la revendication et par aucune de la garde. Calibré : sans l'entrée, la garde échoue désormais. |
| `plugins/catalogue.rs:291` — le `path` d'une entrée échappe à la garde de caractères de contrôle | fermé par `6511d2e` | **Mesuré, et plus large que l'énoncé** : `scheme`, `sha256` et le **nom d'entrée** échappaient aussi, et leur route vers un terminal est celle que la garde n'avait pas vue — le REFUS de forme, qui cite la valeur qu'il refuse. Une valeur qui échoue à sa forme est justement celle qu'un attaquant envoie. Calibré sur `scheme`. |
| `plugins/mod.rs:537` — le conflit de nom inter-types est raté si un type a déjà un conflit | fermé par `5e86410` | **Mesuré, puis corrigé** : `claim` retire de son index une clé devenue ambiguë, donc le balayage ne la trouvait plus pour la comparer à l'autre type. Calibré : deux brokers et un signer nommés `gpg-agent` laissaient `sign = "gpg-agent"` résoudre. |
| `plugins/stores.rs:1218` — deux écrivains « propriétaire seul » byte-identiques, plus trois copies d'`unique()` | fermé par l'arbre | **Mesuré** : `write_owner_only` a une définition unique (`plugins/mod.rs:1796`) et cinq appelants ; `unique()` de même. |
| `plugins/stores.rs:36` — la doc de `REPO_PUBKEY` énumère ses lecteurs et se trompe | fermé par `3784607` | **Mesuré** : quatre lecteurs de production, et `update` — dont la doc disait qu'il ne lit jamais le fichier — en est un. `rekey --trust` et `shipped_pubkey` n'y étaient pas ; `publish` l'écrit. Une garde compte désormais les sites, parce que rien d'autre ne remarque le cinquième. |
| `plugins/stores.rs:775` — le pin de contenu vérifié sur le checkout, jamais sur l'arbre installé | **réfuté par la mesure** | `verify_entry` court sur `plugin_dir`, et `plugin_dir` **est** la `source` remise à `install_from_store`/`replace_from_store`. Il n'y a pas de second arbre qui contourne le pin. |
| `sandbox/control/mod.rs:1120` — une commande qui remplit `CMD_MAX` sans saut de ligne est dispatchée | fermé par `2346997` | **Mesuré, puis corrigé** : la moitié *réponse* du même échange applique déjà la règle, pour la raison miroir (un hôte partiel que `--save` persisterait). Calibré : sans elle, un `REMEMBER ALLOW` tronqué répond `ok` et **entre dans l'overlay**. Le troisième lecteur n'a pas besoin du contrôle — son bras par défaut est déjà le sens fermé. |
| `sandbox/launch.rs:3944` — des diagnostics contournent le point de passage `diag::` | fermé par `7dc8528` | **Mesuré avant de décider de la portée** : quarante `eprintln!("sbx…")` bruts, dont trente-six rendent le même octet dans les deux voies. **Quatre** portent un identifiant et le perdent. La garde tient la règle là où elle mord ; sa fenêtre va jusqu'au `);` de l'appel, et c'est elle qui a trouvé le quatrième — un grep ligne à ligne en voit trois. |
| `sandbox/notify_relay.rs:210` — les chaînes `Notify` de la cage relayées sans borne de longueur | fermé par `572b5b2` | **Mesuré** : aucun plafond sur `summary`, `body` ni les libellés d'action, relayés dans un processus hôte qui les rend. L'en-tête du module énumérait trois choses retenues à la cage ; la longueur en est une quatrième, et elle y est écrite — usurper un toast et déplacer celui du bureau ne sont pas la même chose. |
| `sandbox/notify_relay.rs:373` — les signaux hôte ré-émis dans la cage sans filtre | fermé par l'arbre | **Mesuré** : `OwnedIds::owns`/`closing` filtrent par id, et un test affirme les deux sens (le clic de la cage traverse, celui d'une autre application non). |
| `sandbox/observe_feed.rs:179` — le filtre du flux d'exec s'appuie sur `comm` | fermé par l'arbre | Prose seule, et c'est le remède que le rapport approuve : trou d'observation et non d'application, limite écrite au site. |
| `sandbox/proxy/h2mitm.rs:160` — le refus de plafond de flux n'est enregistré nulle part | fermé par ce dépôt | Le journal est poussé avant la réponse, en `Blocked`. |
| `sandbox/proxy/ssrf.rs:248` — une seule adresse d'un hôte multi-domicilié est essayée | fermé par ce dépôt | `checked_address` rend **toutes** les adresses permises ; les six chemins de dial les essaient dans l'ordre. |
| `sandbox/proxy/websocket.rs:845` — un `1xx` intermédiaire avant le `101` pris pour la réponse finale | fermé par `6e777bd` | **Mesuré, puis corrigé** : calibré, la cage reçoit `HTTP/1.1 103 Early Hints … Connection: close` et le tunnel se ferme, sur une mise à niveau que l'amont allait accepter — sbx ayant au passage réécrit le `Connection` de la tête intermédiaire. Le plan requête lit au-delà des têtes intermédiaires depuis toujours. Le harnais e2e lisait une seule tête lui aussi et **se bloquait** avant de pouvoir échouer. |
| `sandbox/proxy/websocket.rs:863` — une mise à niveau refusée cadrée comme si la requête était toujours `GET` | fermé par `6e777bd` | **Mesuré** : `is_websocket_upgrade` demandait les deux en-têtes et pas la méthode, donc un `HEAD` les portant arrivait ici, et le littéral `"GET"` du cadrage était une hypothèse. RFC 6455 exige `GET` : la méthode fait désormais partie de la question, et le littéral est devenu un fait. Une tentative non-`GET` est une requête ordinaire, que le chemin normal ne peut pas faire monter en grade. |
| `sandbox/sshagent.rs:481` — le bras « requête vide » ne peut pas partir du chemin socket | fermé par `e0a2674` | **Mesuré** : `read_message` refuse une trame de longueur nulle avant que `respond` en voie une ; seul un test peut la produire. La branche reste — `respond` prend une tranche, pas une trame — et le dit désormais au site. |
| `src/store.rs:323` — `LONGEST_SOCKET_SUFFIX` sous-estime le plus large chemin de socket | fermé par ce dépôt | `BROKER_NAME_MAX` est dérivé du budget ; le seul chemin dont la largeur est choisie par la configuration est mesuré au `bind`. |

## Duplication (10 familles) — neuf fermées, une partielle, aucune ouverte

Le rapport les classe par *ce qui casse si une copie est corrigée et pas les autres*. La
décomposition de neuf modules (`6f2a58d`) en a replié quatre au passage, sans les viser.

| Famille | Statut | Ce qui a été mesuré |
| --- | --- | --- |
| `proxy/forward.rs` / `proxy/tunnel.rs` — la queue de réponse du proxy | **fermée** | `relay_response_body` porte le lecteur compté, le tee et **le branchement `masks_reflection`** — la décision de sécurité — en une seule définition. Un garde de source compte `pump_redacting(`/`pump_to_eof(` à zéro dans les deux plans, pour que la scission ne se rouvre pas. 362 tests proxy inchangés : le refactor ne change rien d'observable. |
| `binary.rs` · `tarball.rs` · `appimage.rs` · `deb.rs` — les accesseurs de verrou | **partielle, et le constat surestime** | **Mesuré** : sur les douze délégations, **huit sont `#[cfg(test)]`** (`pins` et `write_pins` dans les quatre) et quatre seulement sont de production (`pinned_hashes`). Aucune ne porte de décision — chacune passe le même appel partagé avec un type marqueur différent — donc le critère du rapport lui-même (« ce qui casse si une copie est corrigée et pas les autres ») ne mord pas ici, et déplacer des méthodes `#[cfg(test)]` dans un trait de production coûterait plus qu'il ne rend. **En revanche l'addendum du constat était juste et est fait** : `binary::resolve_source` et `tarball::resolve_source` avaient des corps identiques et passent par `prebuilt::resolve_direct_url`. |
| `broker.rs` / `signer.rs` — le lancement d'un plugin en cage | **fermée** | `resolver::spawn_caged_plugin` porte la paire de sockets, les délais, **l'ordre clone-avant-spawn** et la remise de stdio. L'ordre était l'enjeu : un `?` après le spawn laisse vivre un bwrap que rien ne tue, et l'explication était recopiée mot pour mot des deux côtés — un ordre rétabli correctement d'un seul côté se répare en silence. |
| `help.rs:2310` et `:2378` — le texte de l'option `<rule>` | **fermée** | Deux constantes, `EGRESS_RULE_ARG` et `EGRESS_SESSION_OPT`. **La divergence soupçonnée n'en était pas une, et il a fallu la mesurer** : les deux variantes « enforcing session(s) » sont les jumelles `proc`, et elles diffèrent l'une de l'autre d'une seule phrase — la mise en garde propre à `proc allow`. Légitime, donc laissées séparées. `net mute` garde aussi son texte court : il renvoie à la grammaire au lieu de la redire. |
| `launch.rs` — deux séquences `openpty` + `fork` | **fermé** | Un seul site subsiste, `pty.rs:393`. |
| `layout_or_fail` réécrit à la main | **partiellement fermé** | De treize sites à six, et **aucun dans `src/cli/`** — les onze que le constat nommait là sont partis. Restent `notify_sink.rs:335`, `prebuilt.rs:298`, `flake.rs:103`, `launch/mod.rs:819`, `launch/session.rs:78` et `:340`. |
| `cli/net.rs` / `cli/proc.rs` — le préambule de filtres pid | **fermé** | `egress_data_dir` a une définition unique (`main.rs:568`). |
| `cli/config.rs` — six copies d'un littéral `ConfigView` | **fermé** | `blank_config_view` et `sample_config_view` (`cli/config/render.rs:1202`, `:1271`). |
| `plugins/stores.rs:1218` — deux écrivains « propriétaire seul », plus trois copies d'`unique()` | **fermée** | `unique()` a une définition unique, et les deux écrivains aussi : `write_owner_only` (`plugins/mod.rs:1796`) sert cinq sites, dont `write_private_key`, qui l'enveloppe seulement pour nommer la clé de signature dans l'échec. |
| `cli/logs.rs` / `cli/proc.rs` — le préambule de cible de session | **fermée** | `resolve_session_target` a une définition unique (`main.rs:86`), appelée deux fois depuis `logs.rs` et deux fois depuis `proc.rs`. |

## Ce que ce document ne dit pas

- Il ne rejuge aucun constat. Un `fermé` dit que le prédicat du constat ne tient plus dans cet
  arbre, pas que le constat était juste quand il a été écrit. Et un `ouvert` dit que le prédicat
  tient, pas que le remède proposé est le bon.
- Il ne reste **aucun** constat « non re-sondé ». Les 8 HIGH, les 33 MEDIUM, les 51 LOW et les 10
  familles de duplication ont tous été rouverts dans cet arbre. Un seul reste ouvert, et
  délibérément : `argv.rs:147`.
- Un `fermé` n'est pas toujours un correctif. Cinq constats sont fermés **sans changement de
  comportement**, parce que la mesure a montré que le remède serait un changement d'unité, une
  réécriture invérifiable ici, ou une réponse à une question que l'arbre tranche déjà autrement :
  `store.rs:1174`, `h2mitm.rs:558`, `proc_enforce.rs:1266`, `sshagent.rs:481` et
  `proc_enforce:1302`. Chacun porte au site la limite **et** son déclencheur.
- Les 17 constats que le rapport dit avoir réfutés lui-même, et les pistes qu'il dit avoir écartées,
  sont dans le rapport et n'ont pas été rejugés.
