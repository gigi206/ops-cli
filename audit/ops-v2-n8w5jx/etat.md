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

## LOW (51) — le tiers ouvert et mesuré

Les 28 constats en prose ont été rouverts un par un dans cet arbre. Sur les 23 du tableau qui les
suit, trois l'ont été ; les vingt autres portent « non re-sondé » et rien d'autre.

### Fermés (24 en prose, 2 au tableau)

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

### Ouverts et mesurés (2 en prose, 1 au tableau)

Trois constats restent, chacun pour une raison écrite : un refactor à travers cinq chemins d'appel,
une course que personne n'a reproduite, et une lacune que le rapport lui-même laisse ouverte.

| Constat | Ce qui est mesuré |
| --- | --- |
| `proxy/ssrf.rs:299` — une seule adresse d'un hôte multi-domicilié est essayée | `ips.into_iter().find(..)` rend **une** adresse. Le chemin est plus long que le constat ne le dit : l'adresse voyage jusqu'au pool amont (`acquire_upstream`, `ready_upstream`, `open_upstream`) et jusqu'à deux `TcpStream::connect` directs. La parcourir demande de rendre une liste et de la faire essayer par cinq chemins d'appel aux transports différents, plus une décision sur ce que le pool indexe. C'est un incrément à part, pas une ligne à changer. |
| `sandbox/argv.rs:147` — `--die-with-parent` est inconditionnel, y compris détaché | La branche `exec`-replace de `detached_child` survit à la décomposition (`launch/detach.rs:157`), donc le chemin existe toujours. **Verdict PLAUSIBLE conservé, et laissé ouvert délibérément** : la course n'a été reproduite ni par le rapport ni ici, et les trois remèdes proposés changent chacun la durée de vie d'un lancement détaché sans qu'on puisse observer le correctif fonctionner sur cette machine. |
| `observe_feed.rs:44` — le filtre du flux d'exec s'appuie sur `comm` | `is_plumbing` apparie `comm`, que le processus observé choisit. Le rapport écarte lui-même le correctif de code — le fermer demande une identité que possède le *lancement*, pas le processus observé — mais **la limite honnête qu'il avait écrite au site n'est pas dans cet arbre**. L'écrire ne coûte rien et c'est le remède que le rapport approuve. |

### Non re-sondés (2 en prose, 20 au tableau)

`attach.rs:95` (pidfd ouvert après la découverte, PLAUSIBLE) et `proc_enforce:1302` (la re-sonde
`O_NOFOLLOW` répond `ELOOP` pour des errnos qui décrivent le superviseur) n'ont pas été rouverts. Les
vingt lignes de tableau restantes non plus. Plusieurs citent des fichiers que la décomposition a
déplacés (`launch.rs`, `store.rs`, `proc_enforce.rs`), et une conclusion de portée ne se transporte
pas à travers un déplacement : elle se re-mesure.

## Duplication (10 familles) — quatre fermées par la décomposition

Le rapport les classe par *ce qui casse si une copie est corrigée et pas les autres*. La
décomposition de neuf modules (`6f2a58d`) en a replié quatre au passage, sans les viser.

| Famille | Statut | Ce qui a été mesuré |
| --- | --- | --- |
| `proxy/forward.rs` / `proxy/tunnel.rs` — la queue de réponse du proxy | **ouvert** | Les deux sites calculent `masks_reflection_for` et composent leur `head_masking` séparément (`forward.rs:523`, `tunnel.rs:783`). C'est la seule famille qui porte une décision de sécurité. |
| `binary.rs` · `tarball.rs` · `appimage.rs` · `deb.rs` — les accesseurs de verrou | **ouvert** | Les quatre définissent encore `pins`, `pinned_hashes` et `write_pins` ; le trait `prebuilt::Kind` qu'ils implémentent déjà est l'endroit de ces méthodes. |
| `broker.rs` / `signer.rs` — le lancement d'un plugin en cage | **ouvert** | Deux `CagePlan` + `compose_cage` (`broker.rs:1034`, `signer.rs:476`), avec la même invariante de cycle de vie commentée des deux côtés. |
| `help.rs:2310` et `:2378` — le texte de l'option `<rule>` | **ouvert, et pire que dit** | Le texte de ~700 caractères apparaît exactement deux fois dans `help/pages.rs`. Un **second** texte long y est aussi dupliqué, et il a **déjà divergé** : deux quasi-variantes coexistent, l'une disant « running session(s) », l'autre « running enforcing session(s) ». C'est la panne que le constat annonçait, arrivée avant le correctif. |
| `launch.rs` — deux séquences `openpty` + `fork` | **fermé** | Un seul site subsiste, `pty.rs:393`. |
| `layout_or_fail` réécrit à la main | **partiellement fermé** | De treize sites à six, et **aucun dans `src/cli/`** — les onze que le constat nommait là sont partis. Restent `notify_sink.rs:335`, `prebuilt.rs:298`, `flake.rs:103`, `launch/mod.rs:819`, `launch/session.rs:78` et `:340`. |
| `cli/net.rs` / `cli/proc.rs` — le préambule de filtres pid | **fermé** | `egress_data_dir` a une définition unique (`main.rs:568`). |
| `cli/config.rs` — six copies d'un littéral `ConfigView` | **fermé** | `blank_config_view` et `sample_config_view` (`cli/config/render.rs:1202`, `:1271`). |
| `plugins/stores.rs:1218` — deux écrivains « propriétaire seul », plus trois copies d'`unique()` | **partiellement fermé** | `unique()` a une définition unique (`plugins/mod.rs:1746`). Les deux écrivains n'ont pas été re-sondés. |
| `cli/logs.rs` / `cli/proc.rs` — le préambule de cible de session | **non re-sondé** | — |

## Ce que ce document ne dit pas

- Il ne rejuge aucun constat. Un `fermé` dit que le prédicat du constat ne tient plus dans cet
  arbre, pas que le constat était juste quand il a été écrit. Et un `ouvert` dit que le prédicat
  tient, pas que le remède proposé est le bon.
- Les constats marqués « non re-sondé » — vingt-quatre MEDIUM, vingt-deux LOW, deux familles de
  duplication — ne sont **pas** des constats réfutés. Ce sont des constats dont personne n'a mesuré
  l'état ici.
- Les 17 constats que le rapport dit avoir réfutés lui-même, et les pistes qu'il dit avoir écartées,
  sont dans le rapport et n'ont pas été rejugés.
