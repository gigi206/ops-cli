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

Les trente-trois ont été rouverts à la ligne. **Dix-sept sont fermés, seize sont ouverts.** Le
neuvième, tenu pour fermé sur la foi du rapport, ne l'était pas : la mesure l'a rouvert.

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
| `proc_enforce.rs:1266` — un `openat2` portant un bit `resolve` récupère la fenêtre d'échange | **ouvert** | **mesuré, et la cellule précédente était fausse** — `open_serve.rs:63` décline toujours pour tout `resolve` non nul (`Some(0) => {}, _ => return false`) et répond `CONTINUE`. Le remède que la cellule disait livré ne l'est pas. Voir ci-dessous. |
| `h2mitm.rs:864` — `:method` jamais scanné sur le plan h2 | **ouvert** | **mesuré** — `head_carries_secret` (`h2mitm.rs:999`) bâtit son tampon de `:path` plus les en-têtes ordinaires. En HTTP/2 les pseudo-en-têtes ne sont pas dans `headers()` : ni la méthode, ni `:authority`, ni `:scheme` n'entrent dans le scan. Sa propre doc nomme le tampon qu'elle construit. |
| `websocket.rs:645` — un rembourrage compressible pousse un secret au-delà du plafond de scan | **ouvert** | **mesuré** — Le code a migré vers `wsframe.rs`. `Inflater::drain` (`wsframe.rs:305`) inflate et **jette** tout ce qui dépasse `SCAN_MESSAGE_CAP`, et `plaintext_cap` (`:689`) plafonne le scan à 256 Kio. Rien ne fait passer le rebut par `LeakScan`. |
| `openuri.rs:17` — la route OpenURI gelée est re-pointable par un `[env]` non approuvé | **ouvert** | **mesuré** — `is_reserved_env_key` (`config/mod.rs:163`) ne nomme ni `XDG_DATA_HOME` ni `XDG_CONFIG_HOME`. La cage part bien de `--clearenv` et ne laisse passer que `TERM`/`LANG`/`LC_ALL` (`build.rs:2253`) — donc la phrase « unset in the cage » est vraie du **passthrough** et fausse de `[env]`, qui est justement la moitié que le constat vise. |
| `plugins/mod.rs:1583` — `plugins rm` laisse le répertoire d'état privé du plugin | **ouvert** | **mesuré** — `remove` appelle `origin::forget` et `programs::forget` ; il n'existe pas de troisième. `<data>/plugin-state/<name>` (`resolver.rs:57`) n'est effacé nulle part, et le prochain plugin du même nom le reçoit monté en écriture. |
| `proxy/mod.rs:761` — `connect(2)` non borné sur les chemins amont synchrones | **ouvert** | **mesuré** — Trois sites sans échéance : `mod.rs:814`, `cleartext.rs:169`, `splice.rs:118`. Le plan h2, lui, enveloppe le sien dans `tokio::time::timeout` (`h2mitm.rs:1124`) — l'asymétrie est mesurable. |
| `proc_enforce.rs:800` — le `recvmsg` du passage de descripteur bloque sur une socket atteignable depuis la cage | **ouvert** | **mesuré** — le *listener* est non bloquant (`mod.rs:344`) et poll-é par tranches de 250 ms, mais Linux ne propage pas `O_NONBLOCK` au flux accepté, et `recv_fd_raw` (`notify.rs:290`) appelle `recvmsg` sans `MSG_DONTWAIT`. Aucun `set_read_timeout` dans tout `proc_enforce/` : un pair muet fige `accept_handoff`, qui ne relit plus `stop`. |
| `launch.rs:3489` — les avertissements de configuration sont imprimés sans filtrage | **ouvert** | **mesuré** — `diag::warn` (`diag.rs:13`) ne fait qu'un `eprintln!`. Les deux sites d'impression, `build.rs:299` et `reclaim.rs:376`, passent la chaîne telle quelle, alors que `mise_token_display` filtre la table voisine. |
| `grammar.rs:548` — un `*` ailleurs qu'en fin de chemin est silencieusement littéral | **ouvert** | **mesuré** — `parse_path_rule` refuse désormais le `?` (correctif de cette session) mais rien d'autre : `grammar.rs:581` ne lit que `path.ends_with("/*")`, et un `*` médian reste un segment littéral sans un mot. |
| `secrets.rs:70` — `upsert_secret` ne remplace que la première déclaration en collision | **ouvert** | **mesuré** — `find_map` rend la première. `HeaderSecret::headers()` (`types.rs:335`) peut rendre **plusieurs** en-têtes pour un signer, donc deux entrées peuvent se recouvrir partiellement et coexister ; la suivante n'en remplace qu'une. |
| `tarball.rs:126` — le `fetchurl` généré omet `name` | **ouvert** | **mesuré** — Trois gabarits sur quatre : `tarball.rs:124`, `deb.rs:719`, `appimage.rs:158`. Seul `binary.rs:124` passe `name = "@NAME@-download"`, et il dit pourquoi. |
| `proc_enforce.rs:1740` — `libc::SYS_open` sans la garde `cfg` | **ouvert, et plus large que le constat** | **mesuré** — Le rapport nommait un site et disait les deux autres gardés. Ici c'est l'inverse : `open_args` (`target.rs:220`) porte `#[cfg(target_arch = "x86_64")]`, et `open_flags` (`:79`), `open_mode` (`:107`) et `open_resolve` (`:142`) ne le portent pas. La décomposition a multiplié les sites. |
| `h2mitm.rs:558` — rafraîchissement et DNS bloquants sur le runtime partagé du tunnel | **ouvert** | **mesuré** — `resolve_checked` (`h2mitm.rs:351`) et `injection_values` (`:458`, soit `inject::pairs_for`, fonction **synchrone** qui peut lancer un plugin signer) sont appelés sans `await` dans le `serve` asynchrone. |
| `store.rs:1174` — le verrou de canal d'une app est clé par le seul nom | **ouvert** | **mesuré** — `app_lock_path` (`channel.rs:235`) rend `<data>/apps/<name>/nixpkgs.lock`, sans identifiant de projet. `project_lock_path` existe à côté (`:246`) mais sert le pin de projet, pas le canal d'app. |
| `store.rs:1724` — un out-link de gcroot repointé sans invalider le témoin `.expr` voisin | **ouvert** | **mesuré** — `provision` (`provisioning.rs:74`), `provision_unfree` (`:113`) et `provision_licensed` (`:181`) écrivent l'out-link et ne touchent jamais `expr_stamp_path`. Seuls `provision_flake` et `provision_expr` en écrivent un, et aucun writer n'en efface. |
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

### Non re-sondés (2 en prose, 20 au tableau)

`attach.rs:95` (pidfd ouvert après la découverte, PLAUSIBLE) et `proc_enforce:1302` (la re-sonde
`O_NOFOLLOW` répond `ELOOP` pour des errnos qui décrivent le superviseur) n'ont pas été rouverts. Les
vingt lignes de tableau restantes non plus. Plusieurs citent des fichiers que la décomposition a
déplacés (`launch.rs`, `store.rs`, `proc_enforce.rs`), et une conclusion de portée ne se transporte
pas à travers un déplacement : elle se re-mesure.

## Duplication (10 familles) — huit fermées, deux partielles, aucune ouverte

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
| `plugins/stores.rs:1218` — deux écrivains « propriétaire seul », plus trois copies d'`unique()` | **partiellement fermé** | `unique()` a une définition unique (`plugins/mod.rs:1746`). Les deux écrivains n'ont pas été re-sondés. |
| `cli/logs.rs` / `cli/proc.rs` — le préambule de cible de session | **non re-sondé** | — |

## Ce que ce document ne dit pas

- Il ne rejuge aucun constat. Un `fermé` dit que le prédicat du constat ne tient plus dans cet
  arbre, pas que le constat était juste quand il a été écrit. Et un `ouvert` dit que le prédicat
  tient, pas que le remède proposé est le bon.
- Les constats marqués « non re-sondé » — vingt-deux LOW et deux familles de duplication — ne sont
  **pas** des constats réfutés. Ce sont des constats dont personne n'a mesuré l'état ici. Le tier
  MEDIUM n'en porte plus : les trente-trois sont mesurés.
- Un `ouvert` mesuré ici n'est pas un correctif. Quinze constats MEDIUM tiennent toujours, et aucun
  n'a encore été corrigé sur cette branche.
- Les 17 constats que le rapport dit avoir réfutés lui-même, et les pistes qu'il dit avoir écartées,
  sont dans le rapport et n'ont pas été rejugés.
