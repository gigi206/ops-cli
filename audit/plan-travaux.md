# Plan de travaux — suites de l'audit d'architecture

Découle de [`choix-architecturaux-a-rouvrir.md`](choix-architecturaux-a-rouvrir.md), qui porte les
mesures. Ce document ne les répète pas : il dit quoi faire, dans quel ordre, et à quoi chaque geste
se prouve. Un constat vieillit lentement, un plan vite ; les deux sont séparés pour cette raison.

Chaque item porte sa **preuve** — le test ou la mesure qui le ferme — et les **gardes** du dépôt
qu'il déclenche. Les trois portes courtes (`mise run fmt`, `mise run lint`, `mise run rustdoc`) sont
dues à chaque item et ne sont pas répétées ; la suite complète reste à la main du mainteneur.

## 0. `--new-session` sur les deux cages construites à la main — correctif de sécurité

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

## 1. Retourner le sens de la dérivation CLI

**Objectif.** Que la complétion lise une déclaration d'options, au lieu de deviner la grammaire en
analysant la prose des pages d'aide.

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

## 2. Un palier de tests rapide

**Objectif.** Une cible entre « un filtre » et « tout », pour les tests qui ne lancent aucun moteur.

**Geste.** Une tâche `mise.toml` — `test-fast` — excluant ce qui exige `bwrap` ou `nix`. La
séparation existe déjà dans les faits : elle est portée par `skip_incapable!` (190 sites) ; il
s'agit de l'exposer, pas de l'inventer.

**Preuve.** La tâche tourne sur un hôte volontairement incapable et ne signale aucun saut : un
palier rapide qui saute des tests n'est pas un palier, c'est la même suite qui ment plus vite.

**Fichiers.** `mise.toml`, et le commentaire qui l'accompagne — les tâches y sont documentées sur
place, ce qui est le seul endroit où ce palier se décrit.

**Ce que ça casse.** Rien, à une condition à écrire dans la description de la tâche : `test-fast`
ne remplace pas `test-cage` avant un envoi. Un palier rapide promu en porte est un piège que ce
dépôt a déjà nommé ailleurs.

**Gardes.** Aucune.

## 3. Une seule table de configuration convertie

**Objectif.** Mesurer ce que coûte une déclaration unique par champ, avant d'engager les 140 types.

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

## 4. `httparse` pour l'analyse de la tête HTTP/1.1

**Décision prise : redéplier derrière `httparse`, comportement inchangé côté réponse.** On ne
change pas l'implémentation et le comportement dans le même geste, sinon la capture d'or ne prouve
plus rien. Durcir reste possible ensuite, sur ses propres mérites. Deux conditions accompagnent ce
choix, et aucune n'est optionnelle.

**Condition 1 — le redépliage doit reproduire l'actuel à l'octet près.** `httparse` rend
`b"hello\r\n there"`. `parse_head` découpe aujourd'hui sur `\r\n` **et** sur `\n` seul
(`src/sandbox/proxy/wire.rs:55`), puis `trim()` la continuation et la joint à la valeur du dessus
par une espace. Le redépliage doit rendre exactement ce résultat, `trim` compris — sans quoi le diff
d'octets rougira sur un cas légitime, et le réflexe sera de corriger le test plutôt que le code.
Trois cas à écrire avant la substitution : `hello\r\n there`, `hello\n\tthere`, et deux folds
consécutifs.

**Condition 2 — côté requête, le comportement change, et c'est voulu.** `httparse` refuse un fold
dans une requête, sans option pour l'accepter, là où `parse_head` le déplie et le relaie. La requête
vient de la cage, c'est-à-dire de l'adversaire dans le modèle de menace, et le dépôt est
fail-closed : le refus est le bon comportement. Mais ce n'est pas un statu quo, donc la capture d'or
doit porter **cette différence-là et elle seule**, comme un écart attendu et documenté — un rouge
non annoncé se lirait comme une régression.

**Geste.** Remplacer le corps de `parse_head` (`src/sandbox/proxy/wire.rs:53`) par `httparse`,
configuré pour refuser les laxismes que ce dépôt a fermés à la main —
`allow_multiple_spaces_in_request_line_delimiters`, `allow_spaces_after_header_name_in_responses`,
`ignore_invalid_headers_in_*` restant à leur valeur stricte. La structure `Head` et tout ce qui la
lit ne bougent pas.

**Preuve, dans cet ordre.** D'abord un test de trois lignes confirmant ce que l'audit infère du type
`Header { name: &'a str }` : casse et ordre du wire préservés. Puis les tests existants de
`src/sandbox/proxy/tests.rs` sur le parsing de tête, sans modification — ils encodent les cas payés
en correctifs, et ce sont eux l'oracle.

**Contrainte de sécurité, non négociable.** `parse_head` refuse aujourd'hui une tête non-UTF-8
(`src/sandbox/proxy/wire.rs:54`). `httparse` rend `value: &'a [u8]`. Une intégration qui convertit
par `from_utf8_lossy`, ou qui conserve les octets dans `Head`, **admettrait** ce que le code refuse
— et `reserialize_request` le réémettrait vers l'amont. La conversion doit donc être `from_utf8`
**strict**, et son échec doit refuser la tête exactement comme aujourd'hui. Le test qui le ferme
envoie un octet non-UTF-8 dans une valeur d'en-tête et attend le refus ; il s'écrit avant la
substitution, pas après.

**Fichiers.** `src/sandbox/proxy/wire.rs`, `Cargo.toml`.

**Ce que ça casse.** `httparse` rend des tranches empruntées là où `Head` possède des `String` :
copier à la frontière, ou propager une durée de vie. La première option est la bonne pour un premier
jet — la seconde traverserait tout le plan. Le type de la valeur, lui, reste `String` : c'est ce qui
porte la contrainte ci-dessus.

**Gardes.** `Cargo.toml` justifie chaque dépendance par un paragraphe et pose une politique « pur
Rust, sans C » ; l'entrée `httparse` doit porter le sien, disant ce qu'il remplace et pourquoi ce
n'est pas `hyper`.

## 5. Une définition unique du socle de durcissement

**Dû, puisque l'item 0 a conclu à un oubli avec conséquence.** Un drapeau manquait aux deux copies
et rien ne le disait ; le test de parité ferme ce cas précis, une définition partagée ferme la
famille.

**Geste.** Du moins cher au plus complet : une constante partagée décrivant le socle, émise par les
trois constructeurs ; ou un `SandboxSpec::helper(binds, cmd)` rendant la parité structurelle plutôt
que gardée.

**Preuve.** Le test de parité de l'item 0, qui passe sans qu'aucun drapeau soit énuméré deux fois.

**Fichiers.** `src/sandbox/argv.rs`, `src/sandbox/spec.rs`, `src/sandbox/mise.rs`, `src/storage.rs`.

**Ce que ça casse.** `mise.rs` compose ensuite avec `cgroup::wrap` et `netns::wrap`, qui prennent un
`(programme, argv)` : le helper doit rendre la même paire. La garde d'exhaustivité de
`src/sandbox/argv.rs:921` sert de filet pendant la bascule — ses six catégories devront être
révisées si les copies cessent d'assembler à la main.

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
