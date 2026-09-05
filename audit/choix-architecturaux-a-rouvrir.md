# Quels choix d'architecture de `sbx` méritent d'être rouverts

Analyse conduite le 2026-09-05 sur `ops-v2` à `3711aeb`, arbre par ailleurs propre. La question
posée est « quel choix ferait mieux autrement », donc chaque constat porte une mesure, une
alternative nommée, et ce que l'alternative casserait ici. Les axes sortent des chiffres : rien
n'est retenu sur la seule impression de complexité.

Volumétrie de référence : 240 148 lignes de Rust dans `src/`, 27 267 en `tests/`, 1 207 commits
dont 391 `fix(` et 309 `feat(`.

## Méthode

Trois mesures servent de boussole, parce qu'elles répondent à trois questions différentes.

**Où l'architecture fuit** : la densité de correctifs, comptée en fichiers touchés par un commit
`fix(` sur toute l'histoire, normalisée par les lignes hors tests du répertoire.

| répertoire | fix·touches | lignes hors tests | fix / kLoC |
| --- | --- | --- | --- |
| `src/sandbox/proxy/` | 150 | 20 488 | **7,32** |
| `src/sandbox/*.rs` (racine) | 365 | 61 973 | 5,89 |
| `src/config/` | 133 | 27 533 | 4,83 |
| `src/sandbox/launch/` | 30 | 7 060 | 4,25 |
| `src/sandbox/distro/` | 8 | 2 122 | 3,77 |
| `src/allowlist/` | 9 | 2 516 | 3,58 |
| `src/cli/` | 101 | 32 628 | 3,10 |
| `src/sandbox/control/` | 9 | 4 974 | 1,81 |
| `src/plugins/` | 17 | 9 852 | 1,73 |
| `src/sandbox/proc_enforce/` | 4 | 3 316 | 1,21 |

Deux répertoires récents (`src/store/`, `src/help/`) sortent artificiellement bas : leurs
correctifs sont comptés sur les fichiers plats dont ils sont issus (`src/store.rs` 9, `src/help.rs`
15), ce qui les ramène vers 2,2 et 4,4.

**Ce que coûte le mono-crate**, sur arbre chaud, après `touch src/help/pages.rs` :

    cargo check      1,51 s
    cargo build      2,77 s
    cargo test --no-run   5,83 s

**Le coût d'ajout d'un champ**, lu sur les commits qui en ajoutent un : `feat(net) forward` touche
8 fichiers de `src/` et 4 pages de guide ; `feat(config)` sur une source de paquet en touche 10 et 1.

## 1. Trois constructeurs de cage pour un seul keystone

**Le choix.** `src/sandbox/mod.rs:1-7` énonce l'invariant central : le `SandboxSpec` est la seule
description de ce qu'une cage expose, `to_argv` n'ajoute aucune exposition, « a security review has
a single surface to audit ». `src/sandbox/argv.rs:63` (`compose`) est le point réel : il ajoute les
deux filtres seccomp et le descripteur d'environnement, ce qui rend le durcissement non oubliable
pour tout ce qui passe par lui.

**La mesure.** Trois sites émettent `--unshare-user` hors des tests inline, pas un —
`src/sandbox/argv.rs:161` (le keystone), `src/sandbox/mise.rs:293` (`bwrap_argv`) et
`src/storage.rs:1054` (la cage `mkfs`). Les deux derniers rejouent à la main les six
`--unshare-*`, le `--clearenv`, le `--die-with-parent`, le `--cap-drop ALL` et le préfixe seccomp.
Le code avoue le prix aux deux endroits : `src/storage.rs:1057` — « this argv is assembled by hand
rather than through the `SandboxSpec` keystone, **and had the namespaces and the capabilities
without it** » : cette cage a été livrée sans filtre et complétée après.
`src/sandbox/mise.rs:322` demande explicitement de tenir la parité à la main — « keep it in step
with `to_argv`'s baseline ».

**Ce qui est déjà fait, et qu'il faut créditer.** `src/sandbox/argv.rs:920-1030` porte une garde
d'exhaustivité : elle balaie les sources, retient tout fichier qui nomme `to_argv(`/`argv_prefix(`
ou qui lance un `Command::new(...bwrap...)`, le classe dans l'une de six catégories déclarées
(assemblé à la main dans un scope, assemblé à la main sans scope, lancé par la commande partagée,
lancé sur la liste composée, simple lecteur, définition), vérifie que chacun appelle ce que sa
catégorie lui impose, puis asserte que la population **découverte** égale la population
**déclarée**. Un nouveau site qui ne se déclare pas fait échouer le test. La dérive par ajout est
donc fermée, et mieux que par une revue.

**Ce que cette garde ne couvre pas.** Elle est syntaxique : elle vérifie qu'un site *appelle*
`argv_prefix(`, jamais que le socle qu'il émet vaut celui du keystone. Et il n'existe **aucune
définition partagée de ce socle** — `grep` sur une constante de durcissement dans `src/` ne rend
rien. Chaque copie est gardée par son propre test, avec sa propre liste littérale : celle de
`src/sandbox/argv.rs:366` énumère sept drapeaux, celle de `src/sandbox/mise.rs:542` six, celle de
`src/storage.rs:2299` six autres, et les trois listes ne se recouvrent pas.

La divergence est déjà là. En comparant les drapeaux réellement émis par les trois constructeurs,
un seul manque aux copies : `--new-session`, présent dans le keystone et dans aucune des deux.
Il faut être exact sur ce que cela vaut — le keystone ne l'émet pas inconditionnellement non plus,
il le lit sur le Spec (`src/sandbox/argv.rs:225`) et l'omet pour le chemin à pty privé, qui établit
sa propre session. Les deux cages construites à la main sont non interactives, c'est-à-dire
exactement le cas où le keystone l'émettrait ; ni l'une ni l'autre ne dit pourquoi elle s'en passe,
et aucune recherche de `new-session` ou `setsid` dans ces deux fichiers ne rend quoi que ce soit.

**Ce que cet écart coûte — mesuré, après une première réponse trop rapide.** L'analyse a d'abord
conclu que le vecteur était couvert ailleurs : le filtre seccomp obligatoire refuse
`ioctl(TIOCSTI)` et `ioctl(TIOCLINUX)` (`src/sandbox/seccomp.rs:83-85`), et les deux cages
appliquent ce filtre. C'était incomplet, et la mesure le dit.

Trois bras, sous un pty fabriqué pour la circonstance, chacun lisant le champ 7 de
`/proc/self/stat` puis tentant d'ouvrir et d'écrire `/dev/tty` :

| bras | `tty_nr` | ouvrir `/dev/tty` | écrire dessus |
| --- | --- | --- | --- |
| témoin, sans cage | 34842 | oui | oui |
| cage aux drapeaux de `mise` / `storage` | **34842** | **oui** | **oui** |
| même cage + `--new-session` | 0 | non | non |

La cage sans `--new-session` conserve **le terminal de contrôle du lanceur**, le même que le témoin :
elle peut l'ouvrir, y lire ce que l'utilisateur tape, et y écrire — le texte émis par la sonde s'est
affiché sur le terminal. Rien de tout cela ne passe par un `ioctl`, donc le filtre seccomp ne
l'atteint pas : il ferme l'injection dans la file d'entrée, pas l'accès au terminal.

Cela compte parce que la cage `mise` exécute du code téléchargé — plugins et paquets — et que le
terminal en question est celui où l'utilisateur a lancé sbx, où il tapera peut-être un secret plus
tard. L'écart n'est donc pas bénin, et l'issue de l'item n'est pas une exemption : c'est un
alignement.

Reste, au-delà de ce drapeau, ce qui l'a rendu possible : un socle dont la parité est maintenue à
la main, sans définition partagée ni test qui les compare. Ce n'est pas non plus une variation
assumée — `bwrap_argv` n'a qu'un appelant de production (`src/sandbox/mise.rs:133`).

**Ce que la raison invoquée vaut.** `mise.rs:322` justifie le contournement par « mise runs before
a `SandboxSpec` exists ». C'est un ordre d'initialisation, pas une impossibilité : `SandboxSpec` est
une structure de données pure (`src/sandbox/spec.rs`), et rien dans `compose` n'exige un lancement.
Ce qui bloque réellement est que `SandboxSpec::new` est taillé pour la cage d'agent et exige des
champs qu'un utilitaire n'a pas.

**Alternative.** Deux niveaux, du moins cher au plus complet. Une constante partagée décrivant le
socle, émise par les trois et asservie par un test unique, ferait apparaître toute divergence
future — et celle d'aujourd'hui. Un constructeur `SandboxSpec::helper(binds, cmd)` produisant ce
socle rendrait la parité structurelle plutôt que gardée.

**Ce que ça casse.** `mise.rs` compose ensuite avec `cgroup::wrap` et `netns::wrap`, qui prennent un
`(programme, argv)` : le helper doit rendre la même paire, donc `compose` doit être utilisable hors
du chemin de lancement. Coût réel mais borné ; les deux appelants sont connus, et la garde
d'exhaustivité existante servirait de filet pendant la bascule.

**Verdict : rouvrir, sur la parité du socle et non sur la découverte des sites.** Celle-ci est
déjà tenue par une garde qui fait son travail. Ce qui reste ouvert est qu'aucun mécanisme ne
compare ce que les trois cages émettent, et un écart y est déjà mesurable.

## 2. La configuration a quatre représentations parallèles du même modèle

**Le choix.** Un étage par usage : `RawConfig` et ses 56 types `Raw*` (`src/config/schema.rs`) pour
ce que TOML accepte, les types résolus (`src/config/mod.rs`, `apps.rs`, `types.rs`) pour ce qu'un
lancement voit, les `*View` (`src/config/view.rs`, 33 types) pour ce qu'un utilisateur inspecte, et
le rendu (`src/cli/config/render.rs`). Chaque étage est écrit à la main.

**La mesure.** 140 `struct`/`enum` dans `src/config/` seul. Un champ unique, `forward`, est déclaré
neuf fois : `schema.rs:288` et `:997` (deux `Option<Vec<RawForward>>`), `mod.rs:582`,
`apps.rs:121`, `view.rs:123`, `:833` et `:916`, plus `overrides.rs:141` et `:184` où il change de
type (`Vec<String>`). Trois de ces neuf sont les branches de la vue à provenance — défaut, hérité,
effectif — donc une couche voulue et non une redéclaration ; il reste six déclarations du même
champ pour trois étages. Le fan-out mesuré sur les commits est de 7 à 10 fichiers de `src/` par champ. La
densité de correctifs suit : 4,83 / kLoC, deuxième du dépôt derrière le proxy.

**Alternative.** Une seule définition par champ, les étages devenant des projections : soit un type
paramétré par l'étage (`Config<Raw>` / `Config<Resolved>` avec un trait à types associés), soit une
macro déclarative qui émet le `Raw`, la fusion, la vue et l'entrée de rendu depuis une déclaration
unique. Les deux existent en Rust ; la macro est la moins intrusive ici.

**Ce que ça casse.** Trois choses de valeur, qu'il faudrait explicitement préserver. La
destructuration exhaustive de `RawConfig` dans `overrides.rs`, qui donne aujourd'hui l'exhaustivité
au compilateur — une macro doit la conserver ou le filet tombe. La documentation par champ, dense et
souvent le seul endroit où une règle est écrite. Et `src/docs_coverage.rs`, qui lit les champs pour
garantir que chacun est nommé dans le guide : il devrait apprendre à lire la macro.

**Verdict : rouvrir, mais par incrément.** Pas de réécriture globale. Un `[network]` ou un `[fs]`
converti seul mesure ce que la macro coûte en lisibilité avant d'engager les 140 types.

## 3. Le plan de contrôle est un motif recopié, pas un type

**Le choix.** Chaque sous-système expose son propre plan de contrôle : un socket Unix, un protocole
texte d'une commande par ligne, un serveur, un client. Ils sont onze —
`src/sandbox/control/mod.rs` (egress `ask`), `task_control.rs`, `proc_control.rs`, `fs_control.rs`,
`sshagent_control.rs`, `signer_control.rs`, `forward.rs`, `lens.rs`, `resolver.rs`, `broker.rs`,
`egress.rs` — pour environ 18 sites de `bind`/`connect`.

**La mesure — et c'est le code qui la fournit.** `src/sandbox/conncap.rs:14` écrit noir sur blanc ce
que le motif a coûté : « The ceiling exists as a type because the loops that need it wrote it four
times **and no copy had both halves**. » Deux copies prenaient le jeton sans le rendre en cas de
panique, deux le testaient avant de le prendre. La facette a été extraite après quatre divergences,
et sept fichiers l'utilisent aujourd'hui.

Les autres facettes n'ont pas été extraites. La plus visible est l'invariant « une valeur ne doit
pas forger une structure de protocole », auquel **trois remèdes de production différents**
répondent : `src/sandbox/observe_feed.rs` mappe les caractères de contrôle en espaces,
`src/sandbox/proc_control.rs:79` (`head_token`) remplace l'espace et le `=` par `_`, et
`src/sandbox/egress_stats.rs:234` refuse la valeur si elle porte `\n` ou `\r`. Trois politiques —
transformer, remplacer, refuser — pour une même famille de problème.

Que ce soit une divergence et non trois choix indépendants, le code le dit lui-même :
`src/sandbox/proc_control.rs:72` explique que `observe_feed::sanitize` **ne ferme pas** le cas
qu'il traite, « it maps control characters to **spaces**, so it turns a newline into exactly the
separator that breaks the head ». Le remède d'un plan est inadéquat pour le plan voisin, et il a
fallu s'en apercevoir sur place.

Les tests qui gardent cet invariant divergent de la même manière : `src/notify.rs:849` et
`src/sandbox/resolver.rs:2821` n'assurent que `\n`, `src/cli/plugins.rs:2725` assure `\n` et `\r`.

**Alternative.** Le dépôt sait déjà faire autrement : `src/plugins/broker.rs:72` et `src/trust.rs:104`
utilisent un cadrage à longueur préfixée, précisément parce qu'une concaténation nue est ambiguë.
Un type `ControlPlane` portant le nommage du socket, la limite `SUN_PATH`, le plafond de
connexions, la règle d'échec, l'encodage d'un champ et la détection de session morte rendrait
l'invariant non oubliable au lieu de le rappeler.

**Ce que ça casse.** Les protocoles sont lisibles au `socat` et deux d'entre eux sont documentés
comme tels ; passer au binaire perdrait cela. Le compromis raisonnable est de garder le texte et de
n'extraire que l'**encodage d'un champ** — un type dont la construction refuse ou échappe le
séparateur — sans toucher aux verbes.

**Verdict : rouvrir la facette d'encodage, garder les plans séparés.** Un plan par sous-système est
défendable ; trois politiques de production pour une seule règle, dont le code note lui-même que
l'une ne convient pas là où l'autre sert, ne le sont pas.

## 4. Le proxy MITM maison est le vrai point chaud

**Le choix.** Un proxy synchrone maison qui termine TLS par SNI, décide par requête, injecte les
secrets côté hôte et relaie HTTP/1.1, HTTP/2, WebSocket et TCP brut : `src/sandbox/proxy/`,
20 488 lignes hors tests, plus 10 988 lignes de tests dans le seul `proxy/tests.rs`.

**La mesure.** 7,32 correctifs par kLoC, soit 2,4 fois le CLI et 4 fois les plugins. Sur les vingt
derniers commits du dépôt, neuf portent le scope `proxy`, `websocket`, `h2` ou `cleartext`. Ce n'est
pas la taille qui distingue ce module — `src/cli/` est plus gros — c'est le taux.

**Ce que ça dit, et ne dit pas.** Un taux élevé sur un analyseur de protocole exposé à des serveurs
tiers est attendu : chaque correctif est un cas de cadrage réel rencontré. Ce n'est pas un signe
que le choix était mauvais ; c'est la mesure de ce qu'il engage. La question n'est donc pas de
remplacer le proxy — aucun produit sur étagère ne combine le verdict par requête, l'attente humaine
et l'injection — mais de savoir si la **surface de parsing** doit rester maison.

**L'alternative évidente, et pourquoi elle ne tient pas.** Déléguer le transport HTTP/1.1 à
`hyper`, comme `h2` l'est déjà côté HTTP/2. Deux faits mesurés l'écartent, et aucun n'est une
préférence.

Le premier est la **fidélité du relais**. `src/sandbox/proxy/wire.rs:60` stocke les en-têtes en
`Vec<(String, String)>` : un vecteur ordonné, portant la casse du wire. `reserialize_request`
réémet « each name and value **verbatim** », et `wire.rs:93` dit pourquoi cette re-sérialisation
existe — « the upstream sees what sbx parsed, never what the client framed », ce qui est ce qui
ferme le desync de smuggling. Le `HeaderMap` de `http`/`hyper` ne peut pas porter cette propriété :
il normalise les noms en minuscules et n'a pas d'ordre inter-noms. Passer par lui réécrirait la
signature d'en-têtes de **toutes** les requêtes des agents vers leurs API. Le dépôt a d'ailleurs
identifié la différence sans la formuler ainsi : `src/sandbox/proxy/h2mitm.rs:619` note qu'« an
HTTP/2 name is lowercase already ». C'est exactement pourquoi `h2` a pu être adopté sans rien
perdre, et pourquoi le même geste en HTTP/1.1 ne serait pas neutre.

Le second est le **modèle d'exécution**. `hyper` n'a pas d'API synchrone : l'adopter ferait basculer
en tokio le plan majoritaire, soit une réécriture du chemin principal pour bénéficier d'un
analyseur.

**L'alternative qui tient : `httparse`, le parseur que `hyper` utilise lui-même.** Il est
synchrone, sans allocation et sans runtime, donc il n'impose aucune bascule. Et il conserve la
propriété qui écarte `hyper` : sa structure est `Header { name: &'a str, value: &'a [u8] }`, des
tranches empruntées au tampon d'origine, rendues dans un tableau. La documentation n'énonce pas la
préservation de la casse et de l'ordre ; c'est le type qui l'impose — un nom emprunté au tampon ne
peut pas avoir été normalisé, une normalisation demandant une allocation que ce crate ne fait pas,
et un tableau porte l'ordre de lecture. Inférence, donc, mais du genre qu'un test de trois lignes
confirmerait avant d'engager quoi que ce soit.

Ce qui rend le candidat sérieux est la liste de sa `ParserConfig`, qui recoupe nommément les
laxismes que ce dépôt a dû fermer un par un : `allow_multiple_spaces_in_request_line_delimiters`
est le correctif « split a request line the way the peer splits it, on SP » ;
`allow_spaces_after_header_name_in_responses` et `ignore_invalid_headers_in_requests` sont la
famille de « refuse a request header a lenient upstream would read as two ». Ces réglages sont, chez
`httparse`, des interrupteurs documentés et éprouvés par tout l'écosystème Rust ; ici ce sont des
décisions écrites à la main.

**Le périmètre du gain, mesuré.** Onze commits `fix` touchent `wire.rs`. Trois tombent dans ce que
`httparse` couvrirait — la ligne de requête, l'en-tête lu comme deux, le fold. Les autres portent
sur le `Content-Length`, le budget de tête, les en-têtes interdits : du cadrage et de la politique,
qu'aucun analyseur de tête ne prend en charge. Le chunked, le keep-alive, le pool, WebSocket et h2
restent maison quoi qu'il arrive. `httparse` durcit la porte d'entrée ; il ne solde pas la dette.

**Ce que ça casse, et qu'il faut décider avant — l'obs-fold, où l'affaire se complique.**
`parse_head` **déplie** un fold : la continuation rejoint la valeur au-dessus, séparée par une
espace (`wire.rs:66-76`), et le commentaire dit pourquoi — deux lecteurs du même message ne doivent
pas diverger, sous peine du desync que tout ce plan existe pour empêcher. `httparse` ne propose pas
cela. Son seul levier, `allow_obsolete_multiline_headers_in_responses`, ne vaut **que pour les
réponses** : côté requête il n'existe aucune option, donc le fold est refusé. Et lorsqu'il est
activé côté réponse, la continuation est jointe **CRLF compris** — la documentation le montre sur
`b"hello\r\n there"` et recommande au lecteur de remplacer lui-même les sauts de ligne par des
espaces.

Ce que cela donne ici est plus qu'un détail : une valeur portant un CRLF, réémise ensuite verbatim
par `reserialize_request`, réintroduirait dans la requête sortante exactement l'octet de framing que
ce plan refuse par ailleurs. Adopter `httparse` sur les réponses obligerait donc à refaire le
dépliage juste après lui. La conclusion est nuancée, et il faut la dire ainsi : sur le fold,
`httparse` apporte un refus propre côté requête et **rien d'utilisable** côté réponse. Des trois
classes créditées plus haut, deux tiennent pleinement ; celle-là, à moitié.

Second point d'intégration : `httparse` rend des tranches empruntées, là où le code actuel possède
des `String` — il faut soit copier à la frontière, soit propager une durée de vie dans `Head`.

**Le fait qui pèse le plus lourd, et qui n'était dans aucun des deux plateaux.** Il n'existe
**aucun fuzzing dans ce dépôt** : ni cible sous un répertoire `fuzz`, ni `cargo-fuzz`, ni
`arbitrary`, ni `proptest`, aucune mention dans `Cargo.toml`, `mise.toml` ou les workflows. Le
module le plus corrigé du projet (7,32 / kLoC), qui analyse des octets choisis par des serveurs
tiers, est couvert par des tests d'exemples et par rien d'autre. Cela déplace l'arbitrage : la
question n'est pas seulement quel analyseur écrit la tête, c'est que la surface entière — tête,
cadrage, chunked, WebSocket — n'est éprouvée par aucune génération d'entrées.

**Reporté par le mainteneur, sans date : pas de fuzzing pour le moment.** Le constat reste écrit
parce qu'il est mesuré et qu'il ne se périme pas ; ce qui suit en tient compte, et `httparse`
devient de ce fait le geste le plus utile disponible plutôt que le second.

**Verdict : garder le modèle, remplacer l'analyseur de tête.** `hyper` est
écarté sur deux motifs techniques et non par déférence envers une décision passée. `httparse` est
la meilleure option disponible pour la tête : il conserve le modèle synchrone, conserve la fidélité
verbatim, et convertit en réglages documentés deux classes de bugs pleines et une troisième à
moitié — étant entendu que son intérêt tient en grande partie à ce qu'il est éprouvé là où
`parse_head` ne l'est pas du tout. Le cadrage (`inspect_framing`, `response_framing`) reste maison dans tous les scénarios : sans
génération d'entrées, il continue de reposer sur des tests d'exemples, et c'est la part de la
surface qu'aucune bibliothèque ne viendra couvrir.

## 5. Le mono-crate ne coûte rien en temps, mais le graphe est cyclique

**Le choix.** Un seul `[[bin]]`, pas de `lib.rs`, 240 kLoC, tout en `pub(crate)`.

**La mesure, qui contredit l'argument habituel.** Le cycle d'itération est de 1,51 s en `check`,
2,77 s en `build`, 5,83 s pour compiler la totalité des tests. Découper en workspace « pour la
vitesse de compilation » n'a donc aucun objet ici : il n'y a rien à gagner.

**Ce que la mesure trouve à la place.** Les gros modules sont mutuellement dépendants — un
workspace serait aujourd'hui impossible, pas seulement inutile :

| sens | occurrences | sens inverse |
| --- | --- | --- |
| `sandbox` → `config` | 294 | 36 |
| `sandbox` → `store` | 118 | 3 |
| `sandbox` → `allowlist` | 92 | 6 |
| `sandbox` → `plugins` | 76 | 8 |

Or les retours sont ténus et de même nature : `config/` n'emprunte à `sandbox/` que des **types de
domaine** — `cgroup::Limits`, `control::CaptureLevel`, `seccomp::SeccompPolicy`,
`redact::MIN_LEN_DEFAULT`, `distro::reference` — et les trois backends de paquet ; les huit emprunts
de `allowlist/` sont un seul type, `control::CaptureLevel`. Ce ne sont pas des dépendances de
comportement, ce sont des types qui appartiennent au domaine et se trouvent déclarés dans le
sous-système qui les consomme.

**Alternative.** Un module `domain` (ou `types`) portant ces types rend la direction des
dépendances lisible — mais il faut être exact sur ce qu'il ferme, et c'est moins que ce que la
symétrie du tableau laisse croire. Le détail des emprunts inverses :

| cycle | ce que le retour contient | déplacer les types le ferme ? |
| --- | --- | --- |
| `allowlist` ↔ `sandbox` | un seul type, `control::CaptureLevel`, 8 fois | **oui** |
| `config` ↔ `sandbox` | des types (`Limits`, `CaptureLevel`, `SeccompPolicy`, `MIN_LEN_DEFAULT`) **et** des comportements (`effective_lock_target`, les modules `fsmask`, `resolver`, les trois backends) | partiellement |
| `store` ↔ `sandbox` | `nixhub::fetch_url_json` ×2, `effective_lock_target` — zéro type | non |
| `plugins` ↔ `sandbox` | `resolver::locate_program`, `header_name_eq`, `sshagent::AUTH_SOCK_ENV` | non |
| `trust` ↔ `config` | `config::safety::read_safe_bytes` | non |

Un seul cycle se ferme par un déplacement de déclarations ; un deuxième se réduit. Les trois autres
sont des emprunts de **comportement**, et ne se ferment qu'en déplaçant la fonction ou en
l'inversant derrière un trait — un travail d'une autre nature.

**Ce que ça casse.** Presque rien, mais chaque type déplacé emporte sa documentation, et
`mise run rustdoc` refuse un lien intra-doc cassé : le déplacement doit porter les références.

**Verdict : ne pas découper en crates. Casser ce qui est cassable, sans en promettre plus.** Le
découpage répond à un problème inexistant ; le déplacement des types est bon marché, ferme un
cycle, en réduit un second, et laisse les trois autres à un travail qui ne se justifie que si le
découpage devient un jour un objectif.

## 6. Le CLI écrit à la main : ne pas y toucher

**Le choix.** Aucun `clap` — vérifié, zéro occurrence dans `Cargo.toml` et `Cargo.lock`. Chaque
famille de verbes analyse ses propres arguments, et `src/help/pages.rs` est la source unique dont
dérivent `--help`, les synopsis d'erreur et la complétion.

**La mesure, contre-intuitive.** C'est la cible la plus évidente d'un audit — 32 628 lignes, une
centaine de parseurs, une réimplémentation de ce qu'une bibliothèque offre. C'est aussi l'un des
répertoires les plus **calmes** du dépôt : 3,10 correctifs par kLoC, sous `config/` (4,83), sous la
racine de `sandbox/` (5,89), très loin du proxy (7,32). La table de `help`, comptée avec le fichier
plat dont elle est issue, ressort à 4,40 — au-dessus des parseurs, ce qui est cohérent avec une
table de prose qui suit chaque verbe ajouté ; ce sont les parseurs, la partie qu'une bibliothèque
remplacerait, qui sont calmes.

**Interprétation.** Un module volumineux mais stable n'est pas une dette : c'est un coût
d'écriture déjà payé, qui ne se represente pas. Le remplacer par `clap` engagerait une réécriture
de la totalité de la surface CLI pour retirer un module qui ne casse pas — et ferait perdre le
traitement `OsString` de bout en bout que `src/main.rs:49` établit délibérément pour les arguments
non UTF-8 d'un `sbx run`.

**Une réserve, sur un mécanisme que la densité de correctifs ne peut pas voir.** Les parseurs sont
sains ; la façon dont la **complétion** dérive la grammaire ne l'est pas au même titre.
`src/cli/completion.rs:643` (`operand_slots`) découpe à l'espace les lignes de prose des pages de
help, et `src/cli/completion.rs:732` (`is_literal`) tranche ce qui est un opérande au moyen d'une
**stop-list de mots anglais** — « a », « an », « the », « of », « via », « e.g. ». Autrement dit, la
grammaire de la ligne de commande est obtenue par analyse lexicale de la documentation : reformuler
une phrase d'une page peut déplacer ce que la complétion propose.

Le même couplage a une seconde face, et celle-ci a déjà cassé. `flag_takes_value`
(`src/cli/completion.rs:1038`) décide si un drapeau consomme le mot suivant en lisant la mise en
forme de la ligne d'aide (`tail_is_fused` teste si la valeur commence par `[`), tandis que le
parseur en décide dans `take_override_flag` (`src/main.rs:482`). Deux définitions, deux fichiers,
un accord tenu à la main — et le commentaire du premier raconte l'issue : compter ce cas ici « made
the completion disagree with the parser **twice over** ».

Ce n'est pas un argument pour `clap` : une bibliothèque d'analyse d'arguments ne résout ce problème
qu'en emportant tout le reste. C'en est un pour la table typée — que la ligne d'aide soit *rendue*
depuis une déclaration d'options, au lieu que la déclaration soit *devinée* depuis la ligne d'aide.
La complétion et le parseur liraient alors la même donnée, et la prose redeviendrait de la prose.

**Verdict : garder les parseurs, retourner le sens de la dérivation.** Le seul autre geste qui se
défende est d'alléger `src/main.rs`
(1 712 lignes, 23 correctifs, 13,4 / kLoC) en le ramenant à `args → help → dispatch` : ce fichier
héberge aujourd'hui de la logique de session et de règles egress qui n'a rien à faire au point
d'entrée. C'est du rangement, pas une remise en cause.

## 7. La suite de tests n'a pas de palier

**Le choix.** 3 137 `#[test]` dans `src/` et 489 dans `tests/`, dont beaucoup lancent un vrai
moteur : 190 sites `skip_incapable!` (l'hôte ne peut pas), 47 `skip_unreachable!` (le réseau ne
peut pas), 9 `#[ignore]` seulement. `src/testskip.rs` explique pourquoi les sauts sont comptés
plutôt qu'invisibles, et `mise.toml` offre deux tâches : `test` (honnête sur ce qui a sauté) et
`test-cage` (`SBX_REQUIRE_CAPABLE=1`, où un saut devient un échec).

**La mesure.** Compiler la totalité coûte 5,83 s. Sa durée d'exécution n'a pas été mesurée ici :
`CLAUDE.md` réserve la suite complète au mainteneur, et cette analyse s'y est tenue. Ce que la
structure établit sans la lancer, c'est où le temps se trouve — 190 sites qui exigent un moteur
réel — et qu'il n'existe aucun palier déclaré entre « une cible filtrée » et « tout ».

**Alternative.** Un troisième palier déclaré, `mise run test-fast`, réunissant les tests purs — la
résolution de config, le rendu, les analyseurs, `to_argv` qui est justement une fonction pure — et
excluant tout ce qui lance `bwrap` ou `nix`. La séparation existe déjà dans les faits, portée par
les macros de saut ; elle n'est simplement pas exposée comme une cible.

**Ce que ça casse.** Rien, à condition que le palier rapide ne devienne pas la porte : le dépôt a
déjà écrit qu'un vert n'est pas une preuve d'exécution, et un palier rapide qui remplacerait
`test-cage` avant un push rendrait ce piège systématique.

**Verdict : rouvrir, coût faible.** C'est la seule proposition de la liste qui n'a pas de
contrepartie.

## 8. Deux runtimes et un thread par connexion

**Le choix.** Le monde par défaut est synchrone, sur threads système : 82 `thread::spawn`, 46
`Mutex`. Deux runtimes asynchrones sont confinés : `async-io` pour D-Bus, et un tokio mono-thread
**par connexion HTTP/2** (12 `new_current_thread`, 29 `block_on`).

**L'échelle, telle que le code la déclare.** Elle n'est pas à deviner, chaque plan porte son
plafond : 512 connexions simultanées pour le transfert de ports (`src/sandbox/forward.rs:72`), 256
requêtes parquées en posture `ask` (`src/sandbox/proxy/mod.rs:377`), 64 pour l'agent SSH, 32 pour
les tâches et pour les brokers. Un thread par connexion à ces plafonds est un ordre de grandeur que
Linux traite sans effort ; c'est trois ordres de grandeur sous le seuil où un modèle par événements
commence à payer.

**Ce qui plaiderait pour tokio, et qui n'a pas été mesuré.** L'argument classique est le coût
mémoire des piles. Aucun `stack_size` n'est fixé en production : les threads prennent la valeur par
défaut de la libc, et le binaire livré est musl statique. Ni cette valeur ni l'empreinte réelle
n'ont été mesurées ici, et c'est la seule chose qui pourrait rouvrir la question : un plan `forward`
réellement tenu à 512 connexions simultanées est le cas à instrumenter. Rien d'autre dans ce que la mesure a produit ne plaide pour un basculement.

**Le vrai prix, qui est ailleurs.** Ce n'est pas le nombre de threads, c'est que deux modèles
coexistent. `Cargo.toml:31-40` l'assume : tout appel bloquant à l'intérieur d'une connexion h2
arrête les flux frères de cette connexion, puisqu'ils partagent un runtime mono-thread. C'est un
piège de maintenance réel, mais il est confiné à une branche et documenté à l'endroit où il mord.

**Verdict : garder, et pour une raison qui tient toute seule.** L'unification vers tokio n'aurait
eu qu'un moteur — l'adoption de `hyper` — et le constat 4 l'écarte sur deux motifs techniques
mesurés. Sans ce moteur, la bascule serait une réécriture du plan majoritaire sans bénéfice
identifié, à une échelle où le modèle actuel est confortable.

## Ce qui est à rouvrir, par ordre

1. **La parité du socle de durcissement** (§1) — trois cages l'émettent, aucune définition ne le
   porte, et l'écart sur `--new-session` est déjà là sans que rien ne le signale.
2. **Le sens de la dérivation CLI** (§6) — la complétion devine la grammaire en analysant la prose
   du help, stop-list de mots anglais comprise, et le désaccord avec le parseur s'est déjà produit
   deux fois. Retourner la dérivation, sans toucher aux parseurs.
3. **L'analyseur de tête HTTP/1.1** (§4) — `httparse` conserve le modèle synchrone et la fidélité
   verbatim, et convertit en réglages documentés deux classes de bugs pleines et une troisième à
   moitié.
4. **Le palier de tests rapide** (§7) — bénéfice immédiat, aucune contrepartie.
5. **La configuration à quatre étages** (§2) — le plus gros gain de coût de changement, à engager
   sur une seule table pour mesurer avant de généraliser.

Reporté par le mainteneur, sans date, le constat restant écrit : **le fuzzing** (§4). Le proxy est le
module le plus corrigé du dépôt et aucune génération d'entrées ne le couvre ; sans elle, le
cadrage — la moitié que nulle bibliothèque ne reprend — reste éprouvé par des exemples seuls.

Trois cibles sont à écarter sur un motif mesuré et non sur une décision antérieure. Les parseurs
d'arguments écrits à la main (§6) sont parmi les modules les plus calmes du dépôt — c'est la
dérivation depuis la prose qui pose problème, pas eux. Le découpage en crates (§5) répond à un coût
de compilation qui n'existe pas. Et `hyper` (§4) perdrait la fidélité de relais que `wire.rs`
construit délibérément, tout en imposant un runtime au plan majoritaire — ce qui retire du même
coup son seul moteur au basculement vers tokio (§8).
