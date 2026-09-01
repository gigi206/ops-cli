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

Huit constats ont été rouverts à la ligne : sept sont fermés, un est ouvert. Un neuvième est tenu
pour fermé sans avoir été re-sondé. Les vingt-quatre autres n'ont pas été regardés ici, et la
colonne le dit plutôt que de le taire.

| Constat | Statut | Provenance |
| --- | --- | --- |
| `websocket.rs:596` — une trame de contrôle de plus de 125 octets relayée sans scan | fermé par `1bbbe6e` | **mesuré** — `wsframe.rs:802` refuse `payload_len > CONTROL_MAX` sur un opcode de contrôle. |
| `config/fspolicy.rs:108` — un projet non approuvé rétrécit la fenêtre `[fs] scan` | fermé par `2b6f01a` | **mesuré** — remède différent de celui proposé : le pli sert aussi l'override autoritaire de l'appelant, donc `scan_max_kb` est gaté aux deux sites qu'une couche non approuvée atteint plutôt que rendu participant au `max`. |
| `config/mod.rs:3867` — un projet non approuvé fournit le `cmd` d'un profil approuvé | fermé par `2b6f01a` | **mesuré** — la porte interroge la provenance de l'app, non le champ. |
| `deb.rs:598` — la chaîne apt signée s'arrête à l'index | fermé par `2b6f01a` | **mesuré** — le `SHA256:` de la strophe gagnante est remis à nix, et un index attesté sans condensat est refusé. |
| `store.rs:404` — un `$HOME` relatif résout le répertoire de données contre le cwd | fermé par `2b6f01a` | **mesuré** — le refus est aussi *classé* comme refus, `sbx path` ne le lisant plus comme une absence. |
| `allowlist/mod.rs:587` — la canonicalisation ne retire ni `;params` ni `#fragment` | fermé par `2b6f01a` | **mesuré** — les deux coupes sont après décodage, le compromis est écrit au site. |
| `overrides.rs:685` — `union_fs_opt` plie `scan_max_kb` avec `min` | fermé par `34a9431` | **mesuré** — le pli est `max`. La note de session portait ce constat comme ouvert jusqu'à ce que le `pull` montre le contraire. |
| `gc.rs:103` — les out-links des outils mise `nix:` ne sont jamais élagués | **ouvert** | **mesuré** — `gc.rs` nomme `projects/<id>/nix-tools` comme cible à *conserver* (`gc.rs:191`) ; rien ne le réconcilie. Voir ci-dessous. |
| `proc_enforce.rs:1266` — un `openat2` portant un bit `resolve` récupère la fenêtre d'échange | fermé | **non re-sondé** — le rapport lui-même décrit le remède livré (partage des bits qui ne changent pas quel fichier la marche atteint) ; la ligne n'a pas été rouverte ici. |
| Les 24 autres | inconnu | **non re-sondé** |

**`gc.rs:103` n'est pas fermé par le correctif de `provision`.** `2b6f01a` a corrigé un *autre* site :
dans `nixhub::provision`, la réconciliation des gcroots contre la déclaration mise était appelée
sous le retour anticipé d'une déclaration vide, donc retirer le *dernier* outil — la seule forme qui
laisse un root pour de bon — la sautait. L'objection du rapport à la réconciliation vise `gc.rs`, où
l'ensemble courant ne contient rien pour un outil équipé par mise ; elle est juste là-bas et
n'atteint pas ce site-ci. Le constat `gc.rs:103` reste donc ouvert, avec la raison que le rapport
lui-même lui donne : réconcilier contre cet ensemble supprimerait tous les roots vivants au premier
`sbx gc --prune`, et le mode d'échec d'un décalage est la suppression, pas la rétention.

## LOW (51) — quatre fermés, le reste presque intact

Le rapport annonce 51 constats LOW : 29 en prose, le reste en tableau. Quatre ont été repris, parce
qu'ils touchaient un chemin qu'un autre correctif ouvrait déjà :

| Constat | Statut | Provenance |
| --- | --- | --- |
| `allowlist/mod.rs:475` — `matches_mute` lit son jeu de méthodes par la question du côté *allow* | fermé par `2b6f01a` | **mesuré** — un `mute` d'hôte nu ne silençait pas le refus le plus bruyant. |
| `proxy/wire.rs:445` — `parse_chunk_size` accepte une taille signée ou entourée de blancs | fermé par `2b6f01a` | **mesuré** — la grammaire exige `1*HEXDIG` ; l'espace insécable était accepté. |
| `proxy/ssrf.rs:60` — `embedded_v4` ignore la forme `::a.b.c.d` | fermé par `2b6f01a` | **mesuré** — le remède évident (`to_ipv4` au lieu de `to_ipv4_mapped`) ouvrait la boucle locale dans la même édition ; les deux adresses concernées sont écartées et un test échoue sous l'échange. |
| `proxy/mod.rs:990` — `Head::keeps_alive` lit le jeton de version avec `split_whitespace` | fermé par `2b6f01a` | **mesuré** — trois plans lisaient le jeton ainsi, un seul le lit maintenant. |

Les autres n'ont pas été regardés. Deux méritent d'être nommés parce que le rapport les laisse
explicitement sans code, et que la raison vaut d'être relue avant d'y toucher :

- `observe_feed.rs:179` — le filtre du flux d'exec s'appuie sur `comm`, que le processus observé
  choisit lui-même. **Mesuré ouvert ici** : `is_plumbing` (`observe_feed.rs:44`) apparie `comm`. Le
  rapport écarte le correctif parce que le fermer demande une identité que possède le *lancement*,
  pas le processus observé. La limite honnête que la branche avait écrite au site n'est pas dans cet
  arbre.
- `store.rs:323` — `LONGEST_SOCKET_SUFFIX` sous-estime le plus large chemin de socket. Le rapport
  refuse de rétrécir le plafond (ce serait un verrouillage pour une installation existante) et
  décrit un autre remède. **Non re-sondé ici.**

## Duplication (10 familles) — jamais ouvertes

Aucune n'a été traitée. Le rapport les classe par *ce qui casse si une copie est corrigée et pas les
autres*, et la première de la liste est la seule qui porte une décision de sécurité : la queue de
réponse du proxy, écrite deux fois entre `proxy/forward.rs` et `proxy/tunnel.rs`, `masks_reflection`
compris.

## Ce que ce document ne dit pas

- Il ne rejuge aucun constat. Un `fermé` dit que le prédicat du constat ne tient plus dans cet
  arbre, pas que le constat était juste quand il a été écrit.
- Les constats marqués « non re-sondé » ou « jamais ouvert » — vingt-quatre MEDIUM, la quasi-totalité
  des LOW, les dix familles de duplication — ne sont **pas** des constats réfutés. Ce sont des
  constats dont personne n'a mesuré l'état ici.
- Les 17 constats que le rapport dit avoir réfutés lui-même, et les pistes qu'il dit avoir écartées,
  sont dans le rapport et n'ont pas été rejugés.
