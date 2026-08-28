# Analyse de la branche `ops-v2` — synthèse

Revue complète du crate `sbx` sur la branche `ops-v2`, portant sur la sécurité, la correction du
code, les anomalies, le découpage des modules, la duplication et les optimisations.

| | |
|---|---|
| **Objet** | crate `sbx` — lanceur de sandbox (bubblewrap + nix sans démon) |
| **Branche** | `ops-v2` (`d717a05`) |
| **Périmètre** | `src/`, `proc-shim/`, `tests/`, `build.rs`, `docs-site/docs` |
| **Documents** | [Sécurité](01-securite.md) · [Bugs et anomalies](02-bugs-anomalies.md) · [Découpage](03-decoupage.md) · [Pistes non vérifiées](annexe-non-verifie.md) |

## Le code en chiffres

| Mesure | Valeur |
|---|---|
| Fichiers Rust | 190 |
| Lignes dans `src/` | 210 337 |
| dont code de production | 142 952 |
| dont tests intégrés (`#[cfg(test)]`) | 67 385 (32 %) |
| Tests d'intégration (`tests/`) | 27 842 |
| Densité de commentaires | 22,6 % des lignes |
| Fonctions | 6 197 |
| Blocs `unsafe` | 255 (concentrés sur les appels libc : seccomp, netns, cgroup, pty, memfd) |
| Marqueurs `TODO` / `FIXME` / `HACK` | 0 |
| `cargo clippy --all-targets -- -D warnings` | vert |

Le ratio d'environ deux lignes de test pour trois lignes de production, l'absence totale de dette
marquée et un `clippy` déjà propre placent ce dépôt nettement au-dessus de la moyenne. Les défauts
relevés ci-dessous doivent se lire dans ce contexte : ils ont fallu être cherchés.

## Méthode

Trois vagues d'analyse, chacune découpée en lots indépendants confiés à un analyste dédié, avec un
périmètre de fichiers borné et une consigne de recherche spécifique.

1. **Sécurité** — 18 sous-systèmes à risque (parseur HTTP/1.1, plan HTTP/2, WebSocket, CA MITM,
   SSRF/DNS, allowlist, seccomp et politique d'exec, binds et masques, pipeline de lancement,
   brokers de credentials, chaîne d'approvisionnement des plugins, configuration et secrets, plan
   de contrôle, ouvertures desktop, store et artefacts distants, egress, auto-upgrade).
2. **Correction** — 16 domaines fonctionnels, hors périmètre sécurité, plus deux balayages
   transverses dédiés (panics atteignables depuis une entrée non maîtrisée ; dérive entre la prose
   et le code).
3. **Structure** — un analyste par module de plus de 3 800 lignes, chargé de cartographier ses
   sections réelles puis de proposer un découpage mécanique ; plus des balayages de duplication et
   d'optimisation.

**Chaque défaut relevé a ensuite été soumis à un vérificateur indépendant chargé de le réfuter**,
avec consigne de réfuter par défaut en cas de doute. Le taux de réfutation mesuré est de **29 % en
sécurité** (21 défauts écartés sur 73) et **13 % en correction** (14 sur 105). Seuls les défauts
ayant survécu figurent dans les documents de résultats ; les pistes dont la vérification n'a pas pu
aboutir sont isolées en annexe et explicitement marquées comme non établies.

Une consigne a été donnée à tous les analystes et pèse sur la lecture des résultats : ce dépôt
commente abondamment ses décisions, et une grande partie des « bugs évidents » y sont des choix
délibérés et argumentés. Les analystes devaient lire les commentaires et les tests avant de
conclure — et signaler comme défaut, à l'inverse, tout commentaire qui affirme une propriété que le
code n'a pas.

## Résultats

| Catégorie | Critique | Élevée | Moyenne | Faible | Total |
|---|---|---|---|---|---|
| Sécurité | 1 | 5 | 11 | 23 | **40** |
| Bugs, erreurs, anomalies | — | 1 | 20 | 53 | **74** |
| **Total confirmé** | **1** | **6** | **31** | **76** | **114** |
| Pistes non vérifiées (annexe) | — | 2 | 12 | 15 | 29 |

## Ce qui est solide

Ce point compte autant que la liste des défauts, parce qu'il délimite ce qui n'a pas besoin d'être
retouché. Les propriétés suivantes ont été vérifiées activement, et non supposées :

- **Pas de request smuggling sur le plan HTTP/1.1.** Un seul `inspect_framing` refuse les
  `Content-Length`/`Transfer-Encoding`/`Host` dupliqués et tout `TE` qui n'est pas exactement
  `chunked` ; un corps chunké est systématiquement dé-chunké puis re-cadré avec un
  `Content-Length` synthétisé ; les obs-folds sont dépliés avant tout lecteur ; le LF nu est un
  terminateur pour les trois parseurs ; `request_line_parts` découpe sur SP uniquement.
- **Pas de confusion hôte/cible.** L'hôte du `CONNECT` est celui qui est autorisé, vérifié en SNI,
  vérifié en `Host`, résolu, validé par certificat et composé.
- **Pas de TOCTOU résolution/connexion.** Les cinq chemins de connexion passent par
  `resolve_checked`.
- **Pas de réutilisation d'autorisation par le pool.** Le pool est clé par hôte + port + jeu de
  credentials, et la jambe amont est toujours une poignée de main TLS neuve validée sur la racine.
- **La clé privée de la CA MITM ne quitte jamais la mémoire.** `Ca::ephemeral()` est appelée une
  fois par lancement, le PEM est écrit en `0o600` sous un répertoire `0o700` et monté en lecture
  seule ; les feuilles émises portent `IsCa::NoCa`.
- **Le filtre seccomp est correct.** Les actions `SECCOMP_RET_ERRNO` priment sur le `USER_NOTIF` du
  shim ; le prologue x32 écrit à la main est du cBPF valide et émis sur tous les programmes ; la
  comparaison `MaskedEq`/`Qword` sur `clone` correspond bien au `lower_32_bits` du noyau, et la
  comparaison `ioctl` est faite à la largeur que lit le noyau.
- **La grammaire d'allowlist ne sur-autorise pas.** `apex_or_subdomain` exige le point séparateur
  (`evil-example.com` et `example.com.evil.net` ne matchent pas), les hôtes sont mis en minuscules
  ASCII et le point final est normalisé.
- **`Spec` → argv est bien une fonction pure sans exposition ajoutée.** Chaque chemin de montage et
  chaque élément de commande est positionnel : un argument commençant par `-` ne peut pas devenir
  un drapeau `bwrap`, et l'environnement est tenu hors de l'argv lisible par tous.
- **Il n'y a pas d'auto-remplacement du binaire `sbx`.** `sbx upgrade binary` roule des *paquets*
  `binary:`, et chaque roulement préconstruit est épinglé par un hash de contenu validé `is_sri()`
  des deux côtés. La classe « remplacement de binaire non vérifié / attaque par downgrade »
  n'existe pas dans ce code.
- **Le fence ssh-agent est une vraie liste blanche.** Les types de message sont autorisés
  explicitement, les orthographes SSH-1 sont couvertes, et tout inconnu est refusé avant d'atteindre
  l'agent hôte.

## Les défauts qui comptent

Les six défauts de gravité critique ou élevée, tous confirmés par réfutation. Le détail complet,
avec le scénario et la correction proposée, se trouve dans [01-securite.md](01-securite.md).

### 1. Une arborescence hôte arbitraire montée en écriture dans le cage suivant — `src/sandbox/binds.rs:739`

`home_mountpoint_pins` prend pour *source* de bind des sous-répertoires de `$HOME` que le cage peut
écrire. Un lien symbolique laissé en place par un cage détermine donc ce que le cage **suivant**
monte, en lecture-écriture. C'est le seul défaut classé critique : il transforme une exécution
compromise en persistance sur l'hôte, et il traverse la frontière que tout le reste du programme
défend.

### 2. Un `.sbx.toml` symbolique hérite du verdict de confiance d'un autre projet — `src/trust.rs:189`

Le marqueur de confiance est clé sur le chemin de configuration *résolu*. Un projet non approuvé
peut donc, par un lien symbolique, se présenter avec le verdict d'un projet approuvé — et activer
les champs de sécurité que la porte de confiance existe précisément pour verrouiller.

### 3. Un chemin non encore créé sous un lien symbolique ne produit aucun pin — `src/config/load.rs:290`

La racine du plan de contrôle est épinglée contre le projet, mais si elle n'existe pas encore et que
son chemin traverse un lien symbolique, aucun pin n'est produit. Le cage peut alors y planter un
marqueur de confiance ou un binaire de moteur.

### 4. La politique d'exec est appliquée sur la chaîne brute, non résolue — `src/proc_policy.rs:113`

Les cibles d'`execve` sont comparées telles quelles. Les orthographes `..`, `//` et relatives
traversent donc aussi bien une règle d'autorisation que — ce qui est plus grave — une règle
d'interdiction par glob.

### 5. Le shim d'application est installé après des préambules qui exécutent des binaires réinscriptibles — `src/sandbox/launch.rs:3980`

L'ordre d'installation laisse une fenêtre où du code s'exécute dans le cage avant que la supervision
d'exec et de contenu ne soit en place, en exécutant des binaires du store que le cage peut réécrire.

### 6. Le cage efface ses propres refus du journal — `src/sandbox/control/mod.rs:1404`

Un seul octet de contrôle dans la cible d'une requête suffit à faire disparaître les requêtes
d'egress refusées de `sbx net log`. C'est la trace d'audit elle-même qui est falsifiable par le
sujet observé.

## Deux motifs récurrents

Au-delà des défauts individuels, deux motifs traversent les résultats et méritent une correction
systématique plutôt qu'au cas par cas.

**Les liens symboliques comme source, plutôt que comme cible.** Quatre défauts confirmés
(`binds.rs:739`, `trust.rs:189`, `config/load.rs:290`, `fs_watch.rs:235`) et deux pistes non
vérifiées (`sandbox/forward.rs:290`, `tarball.rs:161`) relèvent du même schéma : un chemin fourni
ou influencé par le cage est utilisé sans résolution ni refus des liens.

Le dépôt a pourtant déjà énoncé la règle une fois. L'en-tête de `src/sandbox/cagedir.rs` décrit
précisément ce risque — « tout ce qui est *sous* le point de montage est une entrée que du code
non fiable dans le cage peut remplacer par un lien symbolique et laisser en place pour le
lancement suivant » — et conclut : « chacun de ces cas a été trouvé comme un défaut à part entière
avant l'existence de ce module, ce qui est la raison pour laquelle la règle vit désormais à un seul
endroit plutôt que dans chacun d'eux ». Les six sites ci-dessus sont les cas qui n'ont pas été
ramenés à cette primitive. Le correctif structurel est de les y faire passer, plutôt que de
corriger six fois.

**La dérive entre la prose et le code.** Le balayage dédié et les lots fonctionnels ont confirmé
une trentaine de cas où un commentaire, une page d'aide ou le guide affirme une propriété que le
code n'a pas : des défauts par eux-mêmes bénins, mais qui dans ce dépôt-ci coûtent cher, puisque la
prose y est le premier outil de revue. Les plus significatifs :
`src/sandbox/locks.rs:23` prétend que la règle « récupérer ou dégrader sur verrou empoisonné » est
décidée une fois et énumère ses exceptions, alors que tout le plan `sandbox/control` panique encore ;
`src/help.rs:1963` et `:2087` documentent des commandes que le dispatcher refuse ;
`src/cli/mod.rs:435` fait que `--detach=false` **active** le drapeau.

## Structure du code

Dix modules de plus de 3 800 lignes ont été cartographiés. Trois reçoivent un verdict de découpage
fortement recommandé, sept un verdict de découpage utile ; aucun n'a été jugé intouchable, mais
chaque proposition détaille explicitement ce qu'elle casse (visibilités à ouvrir, liens intra-doc à
reporter, tests à déplacer, risque de cycle).

| Module | Lignes | Verdict |
|---|---|---|
| `src/sandbox/launch.rs` | 8 880 | Découpage fortement recommandé |
| `src/sandbox/proc_enforce.rs` | 5 750 | Découpage fortement recommandé |
| `src/help.rs` + `src/cli/completion.rs` | 5 701 | Découpage fortement recommandé |
| `src/config/mod.rs` | 5 846 | Découpage utile |
| `src/cli/net.rs` | 5 168 | Découpage utile |
| `src/cli/config.rs` | 5 004 | Découpage utile |
| `src/sandbox/binds.rs` | 4 612 | Découpage utile |
| `src/sandbox/task.rs` + `task_control.rs` | 8 280 | Découpage utile |
| `src/allowlist/mod.rs` | 4 089 | Découpage utile |
| `src/sandbox/proxy/` | — | Découpage utile |

Le cas le plus net est `launch.rs` : ce n'est pas une machine unique mais une machine
(`Prepared` → `build` → cage) à laquelle quatre verbes sans rapport ont été greffés. Le critère de
sortie d'un module est déjà énoncé par le dépôt lui-même — `src/sandbox/mod.rs:114` justifie la
séparation de `projects` par « ne partage aucun état avec le pipeline de lancement » — et `attach`
(lignes 2609-2896) comme `stop` (2904-3055) satisfont ce critère à la lettre : 499 lignes qui ne
touchent jamais `Prepared`, n'appellent jamais `build` et ne résolvent aucune configuration. Avec
`gc` et les deux roulements d'`upgrade`, cela fait environ 2 700 lignes de production qu'un lecteur
auditant « ce qui atteint bubblewrap » doit aujourd'hui traverser sans raison.

Le détail module par module, avec les bornes de lignes vérifiées et le coût de chaque déplacement,
est dans [03-decoupage.md](03-decoupage.md).

## Duplication et optimisation

Les balayages de duplication (CLI, sandbox, proxy, config/plugins) et d'optimisation (chemin de
données par octet, chemin de lancement, tri des signaux `clippy` stricts) sont en cours et seront
livrés dans `04-duplication-optimisation.md`.

Signal mécanique déjà collecté : sur un passage `clippy` en `pedantic + nursery` (au-delà du
garde-fou du projet, qui est vert), 4 084 remontées dont 148 conversions numériques susceptibles de
tronquer ou de perdre le signe, et 70 clones redondants. Ce lot a été filtré et confié à un
analyste chargé de séparer les vrais défauts du bruit stylistique.

## Suite proposée

L'ordre ci-dessous est celui du coût croissant, pas celui de la gravité : les deux premiers points
sont des corrections locales, le troisième est un chantier.

1. **Les six défauts critiques et élevés**, en commençant par `binds.rs:739`. Chacun est une
   correction bornée dont l'emplacement et la forme sont donnés dans la fiche.
2. **Le motif « lien symbolique en source »**, traité une fois pour toutes en faisant passer les
   six sites concernés par `sandbox::cagedir`. C'est le meilleur rapport entre l'effort et la
   surface fermée.
3. **La dérive prose/code**, en priorisant les affirmations qui portent une propriété de sécurité
   (`locks.rs:23`, `ip_refusal`, `gpu.rs:38`) sur les inexactitudes de pages d'aide.
4. **Le découpage de `launch.rs`**, en sortant d'abord `attach`/`stop` : le critère est déjà celui
   du dépôt, la découpe est mécanique, et elle réduit d'un tiers le module que toute revue de
   sécurité doit lire.

## Réserves sur cette analyse

- Les 29 pistes en annexe **n'ont pas été réfutées**. Au taux de réfutation observé, il faut
  s'attendre à ce qu'environ un quart d'entre elles ne tiennent pas.
- La vérification est une lecture contradictoire du code, pas une exécution. Aucun des scénarios
  décrits n'a été reproduit sur une machine.
- L'analyse porte sur `d717a05` et cite des numéros de ligne à cette révision.
