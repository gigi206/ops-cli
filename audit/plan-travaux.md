# Plan de travaux — suites de l'audit d'architecture

Découle de [`choix-architecturaux-a-rouvrir.md`](choix-architecturaux-a-rouvrir.md), qui porte les
mesures. Ce document ne les répète pas : il dit quoi faire, dans quel ordre, et à quoi chaque geste
se prouve. Un constat vieillit lentement, un plan vite ; les deux sont séparés pour cette raison.

Chaque item porte sa **preuve** — le test ou la mesure qui le ferme — et les **gardes** du dépôt
qu'il déclenche. Les trois portes courtes (`mise run fmt`, `mise run lint`, `mise run rustdoc`) sont
dues à chaque item et ne sont pas répétées ; la suite complète reste à la main du mainteneur.

**Où en est ce plan : il est terminé.** Trois items livrés (`5b632da`, `179925a`, `84b8f7f`), un
défaut corrigé qu'il ne contenait pas (`75dd077`), deux items clos par leur propre mesure.

| item | issue |
| --- | --- |
| 0 — `--new-session` sur les cages construites à la main | livré `5b632da`, plus un second écart trouvé en l'écrivant |
| 1 — dérivation CLI | réduit par sa mesure à un test de parité, livré `84b8f7f` |
| 2 — palier de tests rapide | clos : prémisse mesurée fausse, aucune sélection honnête n'existe |
| 3 — table de configuration convertie | clos : les étages portent des sémantiques, pas des copies |
| 4 — `httparse` | abandonné sur trois mesures |
| 4′ — espace avant le deux-points | trouvé en mesurant l'item 4, corrigé `75dd077` |
| 5 — définition unique du socle | livré `179925a` |

Deux items sur six sont sortis de leur mesure autrement qu'ils y étaient entrés, et le seul défaut
exploitable de la série n'était dans aucune version de ce plan : il est venu de la vérification
d'une prémisse, pas de son exécution.

## 0. `--new-session` sur les deux cages construites à la main — LIVRÉ (`5b632da`)

**Ce que la mesure a montré, et pourquoi cet item a changé de nature.** Il était prévu comme un test
de parité laissant ouverte la question « oubli ou exemption ». La mesure a tranché : c'est un oubli,
et il a une conséquence. Trois bras sous un pty, chacun lisant le champ 7 de `/proc/self/stat` puis
tentant d'ouvrir et d'écrire `/dev/tty` :

| bras | `tty_nr` | ouvrir `/dev/tty` | écrire dessus |
| --- | --- | --- | --- |
| témoin, sans cage | 34842 | oui | oui |
| cage aux drapeaux de `mise` / `storage` | **34842** | **oui** | **oui** |
| même cage + `--new-session` | 0 | non | non |

Les deux cages construites à la main conservent le terminal de contrôle du lanceur : elles peuvent y
lire ce que l'utilisateur tape et y écrire. Le filtre seccomp ne l'atteint pas — il refuse
`ioctl(TIOCSTI)` et `ioctl(TIOCLINUX)`, alors qu'ici il s'agit d'un `open` suivi de `read`/`write`.
La cage `mise` exécute du code téléchargé, et le terminal concerné est celui où l'utilisateur a
lancé sbx.

**Geste, dans cet ordre.**

1. Le test de parité d'abord : il compare le socle du keystone (`to_argv` d'un spec `NewSession`) à
   celui de `mise::bwrap_argv` et à celui de la cage `mkfs` de `storage.rs`. Il est **rouge** avant
   le correctif, sur `--new-session` et sur lui seul.
2. Le correctif : `--new-session` ajouté à `src/sandbox/mise.rs:293` et `src/storage.rs:1054`.
3. Les assertions locales existantes (`src/sandbox/mise.rs:542`, `src/storage.rs:2299`) reçoivent le
   drapeau, faute de quoi le test de parité serait seul à le voir.

**Vérifié avant d'écrire quoi que ce soit.** `--new-session` appelle `setsid()` et retire le
terminal de contrôle, sans toucher à `stdout`/`stderr` : l'affichage des deux outils est intact. Un
chemin qui attendrait une réponse interactive échouerait en revanche — il n'y en a pas, `stdin`
n'étant lu ni dans `src/sandbox/mise.rs` ni dans `src/storage.rs`.

**Preuve.** Le test de parité, rouge puis vert ; et la sonde des trois bras, rejouable.

**Fichiers.** `src/sandbox/argv.rs` (le test, à côté de la garde d'exhaustivité qu'il complète),
`src/sandbox/mise.rs`, `src/storage.rs`.

**Ce dont le test a besoin, relevé pour ne pas être recherché deux fois.** Les trois constructeurs
s'appellent ainsi, et deux visibilités doivent s'élargir pour qu'un test de `sandbox::argv` les
atteigne :

| constructeur | signature | visibilité |
| --- | --- | --- |
| keystone | `argv::to_argv(&SandboxSpec) -> Vec<OsString>` | déjà `pub(crate)` |
| `mise` | `bwrap_argv(store_nix, home_src, project_binds: &[ProjectBind], mise_bin, args: &[OsString]) -> Vec<OsString>` (`src/sandbox/mise.rs:293`) | privée → `pub(super)` |
| `storage` | `mkfs_command(&Mkfs, image, seed, label) -> (Command, Vec<File>)` (`src/storage.rs:1028`) | privée → `pub(crate)` |

`Mkfs` est déjà `pub(crate)` (`src/storage.rs:966`) et sa variante `Owned { bwrap, store_nix, bin }`
se construit directement dans un test. Le spec du keystone se bâtit avec le helper `spec(mounts,
env, net)` des tests d'`argv.rs` (`src/sandbox/argv.rs:342`), dont la politique de terminal par
défaut est `TerminalPolicy::NewSession` — c'est-à-dire le cas non interactif que les deux copies
reproduisent. Les drapeaux de `storage` se lisent sur la `Command` rendue, via `get_args()`.

**La mesure est rejouable.** [`sonde-terminal-de-controle.sh`](sonde-terminal-de-controle.sh) porte
les trois bras, y compris le `script -qec` qui fabrique le pty sans lequel les trois répondent la
même chose.

**Ce que ça casse.** Rien de mesuré. La garde d'exhaustivité (`src/sandbox/argv.rs:921`) ne lit que
les appels à `argv_prefix(`/`compose(`, jamais les drapeaux : elle est indifférente à ce changement.

**Ce que la réalisation a ajouté au plan.** Un second écart, trouvé en écrivant la ligne de base
plutôt qu'en la déduisant de `to_argv`. Les deux cages désolidarisent le namespace UTS sans nommer
d'hôte ; un namespace UTS neuf hérite du nom qui l'a créé, donc le désolidariser sans nommer la
cage est ce qui **révèle** le nom de l'hôte au lieu de le cacher. Mesuré : `hostname` dans la cage
imprimait celui de l'hôte. Les deux se nomment maintenant par `naming::cage_hostname`. La leçon
vaut au-delà de cet item : la prédiction « rouge sur `--new-session` et sur lui seul » était une
conjecture, et l'écrire avant de lancer le test est ce qui a empêché de rétrécir la ligne de base
pour la faire verdir.

## 1. La dérivation CLI — RÉDUITE, PUIS LIVRÉE : un test de parité (`84b8f7f`)

**Ce que l'item proposait.** Retourner le sens de la dérivation : une déclaration typée par option,
dont l'aide serait *rendue* et dont la complétion lirait la grammaire, au lieu de l'analyser dans la
prose des pages. Un refactor traversant quatre-vingt-dix pages, précédé d'une capture d'or.

**Ce que l'histoire du dépôt en dit.** Deux correctifs, dans toute l'histoire, sur les quatre
lecteurs de prose — `bff6ff2` sur `flag_takes_value`, `b7da0e0` sur `operand_slots` ; les autres
commits sont la fonctionnalité qui les a introduits. Et **zéro** du côté du parseur :
`take_override_flag` compte neuf commits, tous des ajouts de drapeaux et un renommage, aucun
correctif de divergence.

**Ce que ça change.** L'accord entre la complétion et le parseur tient depuis toujours ; ce qui
manque n'est pas une architecture, c'est le mécanisme qui *dirait* qu'il a cessé de tenir. Un
refactor traversant achèterait la même propriété au prix d'une réécriture, et en la déplaçant : la
déclaration deviendrait elle-même le lieu où l'erreur se commet. Le geste proportionné est le test
de parité — que le plan prévoyait déjà, mais comme filet d'un refactor plutôt que comme livrable.

**Geste.** Un test qui, pour chaque drapeau documenté sur une page où le parseur d'overrides
s'applique, pose **la même question aux deux côtés** : le mot suivant est-il consommé ? Le côté
parseur répond en s'exécutant — `take_override_flag` sur une tête `[drapeau, sentinelle]`, et la
sentinelle reste ou ne reste pas — et non par une liste recopiée dans le test. La population vient
des pages, donc un drapeau documenté plus tard est couvert sans toucher au test.

**Preuve, et elle a été faite.** Le test est rouge si l'on rétablit le défaut que `bff6ff2` a
corrigé : il nomme alors `--gpu` sur `sbx run`. Il atteint trente-deux couples drapeau/page sur les
trois pages, et porte un plancher sous la valeur d'une page — une page dont les lignes cessent
d'être lues le fait rougir, au lieu de le réduire silencieusement à rien.

**Fichiers.** `src/main.rs`, `src/cli/completion.rs`.

**Ce qui rouvrirait le refactor.** Un troisième correctif de la même famille, ou une page dont la
prose ne peut plus exprimer une grammaire que le parseur accepte.

## 2. Un palier de tests rapide — CLOS, prémisse mesurée fausse

**Ce que le plan supposait.** « La séparation existe déjà dans les faits : elle est portée par
`skip_incapable!` ; il s'agit de l'exposer, pas de l'inventer. » C'est faux à la granularité qu'un
sélecteur de tests peut atteindre.

**Trois mesures, et ce que chacune ferme.**

| mesure | résultat | ce qu'elle élimine |
| --- | --- | --- |
| répartition des sauts | 33 fichiers ; `cgroup.rs` porte 21 tests et 12 sites de saut | un `--skip` par module emporte les tests purs du même module |
| ce que lisent les prédicats | 16 sites gatent sur `bash`, `socat` ou `head` dans le PATH ; d'autres sur l'userns non privilégié | cacher les moteurs par variable d'environnement ne couvre pas la population : l'userns n'est pas une variable |
| l'invocation de la CI | `cargo test --bins` provisionne de vrais stores nix depuis `cache.nixos.org` | le palier ne peut pas être `--bins` tel quel |

**Les trois réalisations écartées, et pourquoi.** Un `--skip` par module : mesuré comme emportant
des tests purs. Une liste de noms, ou une garde qui scanne les sources pour la tenir à jour : elle
se périme, et une garde qui lit du texte pour retrouver la fonction englobante est le mécanisme qui
a déjà donné un faux chiffre dans cet audit. Un `#[ignore]` ou une feature : cela change ce que
`cargo test --bins` lance par défaut, donc ce que la CI lance, et un palier qui retire
silencieusement des tests à la porte est exactement le piège que cet item devait éviter.

**Ce qui reste vrai, et qui n'a pas besoin d'un palier.** `mise run test` rend déjà les sauts
bruyants par `SBX_SKIP_LOG`, et `mise run test-cage` les transforme en échecs. Entre « un filtre »
et « tout », le filtre ciblé reste l'outil, et c'est ce que fait `CLAUDE.md`.

**Ce qui rouvrirait l'item.** Un mécanisme de sélection qui n'existe pas aujourd'hui : une
annotation portée par le test lui-même, lisible par le harnais, qui ne change pas ce qu'une
invocation sans elle exécute.

## 3. Une seule table de configuration convertie — CLOS par sa propre mesure

**L'item était une mesure, et la mesure a répondu.** Son énoncé était « mesurer ce que coûte une
déclaration unique par champ, avant d'engager les 140 types », avec une décision à prendre après.
Lire `[fs]` de bout en bout à travers ses quatre étages *est* cette mesure, et elle dit de s'arrêter
— mais pas pour la raison que le plan prévoyait.

**Ce que le plan supposait.** Que les quatre étages sont quatre représentations parallèles d'une
même chose, dont une déclaration unique pourrait rendre les copies. Le chiffre qui motivait l'item
reste vrai : plus de vingt-cinq commits touchent au moins trois étages dans le même geste. Mais un
champ qui *traverse* quatre étages et un champ qui y est *copié* quatre fois ne sont pas le même
fait, et c'est le second que l'item supposait.

**Trois mesures sur la plus petite table, choisie parce que si la prémisse tenait quelque part,
c'est là qu'elle tiendrait.**

| champ | ce qu'il fait de différent par étage |
| --- | --- |
| `scan_max_kb` | `Option<i64>` au parse, `Option<u64>` résolu — un `u64` refusait `-1` au *parse*, ce qui faisait échouer le fichier entier ; le signe est une décision d'étage |
| `scan_max_kb` | se replie par le **maximum**, et le commentaire dit que le repli a valu `min` une fois, laissant un plafond ambiant battre celui de la ligne de commande |
| `scan_max_kb` | refusé d'un projet non fiable (`src/config/apps.rs:856`), là où les trois listes ne le sont pas |

Chacune est une **sémantique par champ**, pas une copie par étage. Une macro devrait porter le
changement de type, la règle de repli, la porte de confiance et les paragraphes qui expliquent
chacun — ou la déclaration ne serait qu'un index vers une prose restée ailleurs.

**Ce qui reste vrai.** La destructuration exhaustive de `overrides.rs` reste la garde qu'elle est,
et son propre commentaire dit que l'oubli silencieux s'est produit **trois fois** avant elle.
Vingt-cinq commits à trois étages ne sont pas le coût d'avoir des couches : c'est le coût d'avoir
des règles.

**Ce qui rouvrirait l'item.** Une table dont les champs sont homogènes sur les quatre étages —
même type brut et résolu, même règle de repli, aucune porte de confiance, aucune prose par champ.
S'il en existe une, c'est le pilote.

## 4. `httparse` — ABANDONNÉ, et remplacé par ce que sa mesure a trouvé

**Trois faits mesurés, chacun suffisant.**

1. **`parse_head` n'a été corrigé qu'une fois.** `git log -L` sur le corps de la fonction rend deux
   commits, dont un refactor pur d'extraction de module. La densité de correctifs du proxy, qui
   motivait cet item, ne vient pas de là : elle vient de la politique et du cadrage.
2. **`parse_head` analyse les requêtes *et* les réponses.** `response_framing` et
   `response_keeps_alive` lui passent des têtes de réponse. `httparse` a un type par sens, et sa
   ligne de tête n'est pas la même chose des deux côtés.
3. **La ligne de requête est conservée verbatim.** `reserialize_request` la réémet telle quelle.
   `httparse` la décompose en méthode, cible et version ; la recomposer normaliserait les octets sur
   le fil, c'est-à-dire exactement la propriété que ce module construit délibérément.

**Ce que la mesure a trouvé à la place : une seconde orthographe du défaut de pliage.** Voir
l'item 4′ ci-dessous. Ce n'est pas un argument pour `httparse` : un analyseur de bloc d'en-têtes ne
voit pas le relais, et n'aurait rien fermé ici.

## 4′. Une espace avant le deux-points ouvre une désynchronisation côté réponse

**La chaîne, lue de bout en bout dans le code.** `parse_head` découpe sur le premier `:` puis
`trim()` le nom : `Content-Length : 5` est donc lu comme un `content-length` propre.
`response_framing` en tire `Length(5)`. `persistent` devient vrai, et `offer_reuse_in_head` relaie
la tête au client **verbatim** — la ligne malformée comprise — en y ajoutant l'offre de réutilisation
de sbx. sbx lit donc 5 octets de corps et annonce au client qu'une autre réponse suit, sur une tête
que la RFC 9112 §5.1 déclare malformée et qu'un destinataire lit autrement.

C'est la même classe que le pliage obsolète que ce dépôt a déjà fermé — deux vues d'une même tête —
mais par une autre orthographe, et du côté où la tête n'est pas réémise. Le côté requête est
indemne pour la raison inverse : il est réémis, donc normalisé par sbx.

**Preuve, dans cet ordre.** D'abord l'unité : ce que rend `parse_head` sur la tête ci-dessus, puis
ce que rend `response_framing`. Puis la conséquence, qui est ce qui compte : deux réponses sur une
même connexion tenue en vie, la première portant l'espace, et ce que le client reçoit comme seconde
tête.

**Le correctif appartient à `parse_head`, pas à une garde de plus.** Refuser, ce qui dégrade en
`ToEof` et `Connection: close` — le repli que la fonction documente déjà. C'est plus strict que la
normalisation actuelle du côté requête, et c'est la posture du dépôt.

**Un voisin énuméré, et un faux voisin écarté.** Une ligne sans `:` est silencieusement
abandonnée par `parse_head` et relayée verbatim au client sur une réponse ; sans deux-points elle
n'est un en-tête pour personne, donc rien ne s'en cadre, et elle reste une différence de lecture
sans conséquence mesurée. Le découpage sur un `\n` seul, lui, **n'est pas un défaut** : la RFC 9112
§2.2 autorise un destinataire à reconnaître un LF seul comme fin de ligne, et le guide écrit
explicitement que les quatre orthographes de la ligne vide terminent une tête sur chaque plan.
C'est une tolérance choisie et documentée.

**Fichiers.** `src/sandbox/proxy/wire.rs`, `src/sandbox/proxy/tests.rs`.

## 5. Une définition unique du socle de durcissement — LIVRÉ (`179925a`)

**Dû, puisque l'item 0 a conclu à un oubli avec conséquence.** Un drapeau manquait aux deux copies
et rien ne le disait ; le test de parité ferme ce cas précis, une définition partagée ferme la
famille.

**Geste.** Du moins cher au plus complet : une constante partagée décrivant le socle, émise par les
trois constructeurs ; ou un `SandboxSpec::helper(binds, cmd)` rendant la parité structurelle plutôt
que gardée.

**Preuve.** Le test de parité de l'item 0, qui passe sans qu'aucun drapeau soit énuméré deux fois.

**Fichiers.** `src/sandbox/argv.rs`, `src/sandbox/spec.rs`, `src/sandbox/mise.rs`, `src/storage.rs`.

**Ce que ça casse.** Rien : les argv émis sont identiques à l'octet, comparés à une capture prise
avant la bascule. `helper_argv(slug, store_nix)` rend le durcissement et la racine minimale ; chaque
appelant ajoute ensuite ce qui lui est propre. Le keystone ne l'appelle pas, et son commentaire dit
pourquoi plutôt que de le laisser redécouvrir : son émission est conditionnelle drapeau par drapeau.
Les catégories de la garde d'exhaustivité n'ont pas bougé — les filtres et le scope ne sont pas des
drapeaux, ce qui est précisément pourquoi ils ne sont pas passés dans la définition partagée.

## Non planifié

**Le fuzzing du proxy.** Reporté par le mainteneur, sans date. Le constat reste dans l'audit parce
qu'il est mesuré et qu'il ne se périme pas : le module le plus corrigé du dépôt lit des octets
choisis par des tiers, et aucune génération d'entrées ne le couvre. L'item 4 ne s'y substitue pas —
il durcit la tête, là où le cadrage (`inspect_framing`, `response_framing`) reste éprouvé par des
exemples seuls.

## Ce que ce plan ne contient pas, et pourquoi

Le découpage en crates, le remplacement des parseurs d'arguments par une bibliothèque, la
réécriture du proxy sur `hyper` et le basculement vers tokio. Chacun est écarté dans l'audit sur une
mesure, pas sur une préférence : le coût de compilation qui motiverait le premier n'existe pas, les
parseurs sont parmi les modules les plus calmes du dépôt, et les deux derniers perdraient la
fidélité de relais que `wire.rs` construit délibérément.
