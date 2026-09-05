# Plan de travaux — suites de l'audit d'architecture

Découle de [`choix-architecturaux-a-rouvrir.md`](choix-architecturaux-a-rouvrir.md), qui porte les
mesures. Ce document ne les répète pas : il dit quoi faire, dans quel ordre, et à quoi chaque geste
se prouve. Un constat vieillit lentement, un plan vite ; les deux sont séparés pour cette raison.

Chaque item porte sa **preuve** — le test ou la mesure qui le ferme — et les **gardes** du dépôt
qu'il déclenche. Les trois portes courtes (`mise run fmt`, `mise run lint`, `mise run rustdoc`) sont
dues à chaque item et ne sont pas répétées ; la suite complète reste à la main du mainteneur.

**Où en est ce plan.** Les items 0 et 5 sont livrés (`5b632da`, `179925a`). L'item 2 est clos : sa
prémisse a été mesurée fausse. L'item 4 est remplacé — la mesure de sa prémisse a trouvé autre
chose, et cette autre chose est un défaut. Restent 3, puis 1, dans cet ordre : la prémisse du
premier est la mieux tenue des deux.

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

## 1. Retourner le sens de la dérivation CLI

**Objectif.** Que la complétion lise une déclaration d'options, au lieu de deviner la grammaire en
analysant la prose des pages d'aide.

**Prémisse mesurée, et elle est faible.** Les quatre lecteurs de prose totalisent six correctifs
dans toute l'histoire du dépôt : `operand_slots` 2, `metavar_of` 1, `is_literal` 1,
`flag_takes_value` 2. Ce n'est pas une dette active. Ce qui reste vrai est la *forme* du risque, pas
sa fréquence : un désaccord entre la complétion et le parseur ne se signale pas, il se constate. Cet
item se justifie par ce silence, pas par un compteur — et il passe donc après l'item 3, dont la
prémisse se compte.

**Première étape, qui n'est pas du code : une capture d'or.** Enregistrer, avant de toucher quoi
que ce soit, la sortie de l'oracle `__complete` pour tous les verbes et toutes les profondeurs — et
avec elle celle du parseur : `--help` de chaque verbe, et un jeu d'overrides `--config`/`--env`
couvrant les drapeaux à valeur fusionnée comme `--gpu[=true|false]`. Le refactor est censé être sans
effet observable des deux côtés ; sans cette capture, rien ne le prouve, et la comparaison doit être
un diff d'octets.

**Geste.** Introduire dans la table de `help` une déclaration typée par option — nom, présence et
nature de la valeur, fusionnée ou suivante — et faire que la ligne d'aide en soit *rendue*. Puis
remplacer les lecteurs de prose par des lecteurs de cette déclaration : `operand_slots`
(`src/cli/completion.rs:643`), `metavar_of` (`:701`), `is_literal` (`:732`, avec sa stop-list de
mots anglais) et `flag_takes_value` (`:1038`).

**Le sens de la dérivation est une contrainte de sécurité, pas un détail.** `take_override_flag`
(`src/main.rs:482`) n'est pas un lecteur de prose : c'est le parseur des overrides `--config` et
`--env`, qui sont autoritaires et traversent la porte de lecture de configuration. La déclaration
nourrit **la complétion**, et elle seule ; le parseur garde sa logique. Un **test de parité**
compare les deux réponses, drapeau par drapeau, et c'est lui qui remplace l'accord tenu à la main.
À aucun moment le parseur ne lit la déclaration : une déclaration incomplète changerait alors ce
qu'un override consomme, c'est-à-dire le bug que le commentaire de `src/cli/completion.rs:1030`
raconte, déplacé du côté où il compte.

**Preuve.** Le diff d'octets contre la capture d'or, et `tests/completion.rs` qui exerce déjà les
scripts émis et l'oracle `__complete` sur chaque chemin.

**Fichiers.** `src/help/pages.rs`, `src/help.rs`, `src/cli/completion.rs`, `src/main.rs`,
`tests/completion.rs`.

**Ce que ça casse.** C'est le seul item du plan avec une suite dédiée à casser puis rétablir. La
prose des pages doit rester lisible une fois rendue depuis la déclaration — si le rendu appauvrit
une page, la déclaration est trop pauvre, pas la page trop riche.

**Gardes.** La parité aide/complétion et les tests de résolution de page du dispatcher. Aucun verbe
nouveau, donc `docs_coverage` ne bouge pas — sauf si le rendu change le texte d'une page, auquel
cas la garde de wrapping des `///` et celle du guide s'appliquent.

**Découpe.** Faisable verbe par verbe : la déclaration peut coexister avec la prose pendant la
transition, les lecteurs interrogeant la déclaration quand elle existe et la prose sinon.

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

## 3. Une seule table de configuration convertie

**Objectif.** Mesurer ce que coûte une déclaration unique par champ, avant d'engager les 140 types.

**Prémisse mesurée, et c'est la mieux tenue du plan.** Plus de vingt-cinq commits touchent au moins
trois des quatre étages (`src/config/schema.rs`, `mod.rs`, `view.rs`, `src/cli/config/render.rs`)
dans le même geste, et une bonne moitié les touche tous les quatre. Ajouter un champ traverse
réellement les quatre étages, à chaque fois.

**Geste.** Choisir **une** table — `[fs]` est la plus petite, `[network]` la plus représentative —
et faire dériver d'une déclaration unique les quatre étages qu'elle traverse aujourd'hui : le
`Raw*`, le type résolu, la vue, l'entrée de rendu. Macro déclarative de préférence à un type
paramétré par l'étage : moins intrusive, et elle laisse les commentaires par champ où ils sont.

**Preuve.** Aucun changement de comportement observable : la même configuration produit le même
`sbx config show`, les mêmes messages de refus, le même `--json`. Les tests de `src/config/tests.rs`
qui portent sur cette table passent sans être modifiés — s'il faut les toucher, la conversion a
changé quelque chose.

**Fichiers.** `src/config/schema.rs`, `mod.rs`, `view.rs`, `overrides.rs`, `src/cli/config/`.

**Ce que ça casse, et comment on le sait.** Trois propriétés à préserver, dont la première est une
garde de sécurité et demande son propre mécanisme de preuve.

La destructuration exhaustive de `RawConfig` dans `overrides.rs` donne aujourd'hui l'exhaustivité au
compilateur : un champ ajouté sans être traité ne compile pas. Une macro peut rendre cette garde
**inerte sans rien casser de visible** — si la destructuration générée porte un `..`, ou si elle
passe par une méthode elle-même générée, le champ oublié compile et l'override est silencieusement
ignoré. C'est exactement la forme du défaut que ce dépôt a déjà rencontré sur le plan d'override, et
« la macro préserve l'exhaustivité » est une affirmation qui doit être testée, pas déclarée. Le test
qui la ferme : un champ ajouté à la macro dans un cas de compilation qui **doit** échouer
(`compile_fail`), ou à défaut une assertion que le nombre de champs déclarés et le nombre de bras
traités sont égaux. Cet item ne commence pas sans lui.

Les deux autres : la documentation par champ, souvent le seul endroit où une règle est écrite ; et
la lecture des champs par `src/docs_coverage.rs`, qui doit apprendre à lire la macro.

**Gardes.** `docs_coverage` sur les champs de configuration nommés dans le guide. La conversion
n'ajoute aucun champ, donc la garde doit rester verte sans écrire une ligne de prose — si elle
rougit, la macro a rendu un champ invisible, ce qui est précisément le risque à mesurer.

**Décision à prendre après, pas avant.** Généraliser ou s'arrêter là. La conversion d'une table
donne le chiffre qui manque : combien de lignes et de lisibilité une déclaration unique coûte.

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

**Deux voisins de la même famille, énumérés sans être corrigés ici.** Une ligne sans `:` est
silencieusement abandonnée par `parse_head`, et relayée verbatim au client sur une réponse ; et
`parse_head` découpe sur un `\n` seul, là où un client qui n'accepte que CRLF lit une autre tête.
Le plan HTTP/2 n'a ni l'un ni l'autre, HPACK décodant dans des types qui les refusent : la parité
entre plans est ce qui les nomme.

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
