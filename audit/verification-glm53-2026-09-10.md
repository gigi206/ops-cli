# Contre-vérification de `audit_glm53_flash.md`

Arbre : `ops-v2`, HEAD `8ee4721` (le rapport épingle `02d3c70` puis `c0b4b6d2` — les ancres
ont dérivé de 2 à 5 lignes, recalées ci-dessous). Arbre sale : 5 fichiers appartiennent à une
session concurrente ; tout constat qui les cite a été lu à `HEAD`.

Aucun fichier source modifié pendant cette passe.

## Tableau

| # | Verdict | Ancre recalée |
|---|---|---|
| B1 | **RÉEL** (test-only) | `tests/projects.rs:627` (rapport : 624) |
| B2 | **RÉEL** (Low, environnemental) | `binds.rs:37`, `testroot.rs:27`, `load.rs:168`, `view.rs:1576` |
| B3 | **MÉCANISME RÉEL, PRÉCONDITION FAUSSE** | `examples/bundle/kiro.toml:120` |
| S1 | **RÉTROGRADÉ Medium → Info** | idem B3 |
| S2 | **RÉEL mais sans objet** | `catalogue_tests.rs:1146` |
| S3 / O3 | **RÉEL à HEAD, corrigé non commité** | `.gitignore` (+5, non commité) |
| S4 | **RÉEL** (Info) | `cli/config/render.rs:1249` |
| S5 | **RÉEL**, Low-Medium ; **attribution fausse** | `cli/app.rs:2222`, `main.rs:770`, `session.rs:620` |
| S6 | **RÉEL**, Low | `gc.rs:928`, `:1025` |
| O1 | **VRAI mais pas un constat** | `proxy/ca.rs:52`, `:121-131` |
| O2 | **FAUX** | `netlearn.rs:536` |
| O4 (doc) | **RÉEL et DÉJÀ CLOS** | `tests/app.rs:465`, garde `docs_coverage.rs:1390` |
| O4 (perf) | **RÉEL** — CORRIGÉ (`bb125b3`) | `forward.rs:76`, `:284` |
| O5 | **RÉEL** | `proxy/mod.rs:1005`, `:391`, `deadline.rs:54` |
| O6 | **RÉEL** | `proxy/splice.rs:190,196`, `forward.rs:347,352` |
| O7 | **RÉEL** — CORRIGÉ (`ef8a0fd`) | `forward.rs` : 0 `set_nodelay`, 0 `nodelay` |
| O8 | **RÉEL** (Info) | `Cargo.toml` `[profile.release]` |
| O9 | **RÉEL** (Info) | `allowlist/mod.rs:417`, `:713` |

## Les deux qui ne tiennent pas

### B3 / S1 — la précondition se tranche, et elle est fausse

Le mécanisme est réel et reproduit : sans `grep`, `if ! grep -q … 2>/dev/null` lit le 127 comme
« clé absente », le writer est appelé à chaque roulement et l'avis `SBX_UPGRADE` disparaît.

Mais le rapport laisse ouverte la seule question qui décide de la sévérité, et le code la tranche :
`gnugrep` est dans `BASE_TOOLS` (`fhs.rs:50`), son `bin` rejoint `bin_paths` (`fhs.rs:367`), et
`binds.rs:1117` étend le PATH de la cage avec `userland.bin_paths` **sans condition** — un `distro`
déclaré passe seulement devant (`binds.rs:1114`), il ne remplace rien. `provision` tourne dans cette
cage (`schema.rs:465` : « It runs BEFORE that command, in the same cage »). Et `PATH` est un nom
réservé qu'un `[env]` ne peut pas poser (`config/mod.rs:207`), sauf config *approuvée* — qui peut
déjà tout.

La porte du `distro` est fermée aussi : `launch/mod.rs:1102` **mute** un `Userland` déjà construit
par `fhs::` (`userland.distro = Some(root)`) sans toucher à `bin_paths` — les bins du socle restent
sur le PATH, l'image passe seulement devant.

Aucune cage livrée ne présente donc un PATH sans `grep`. Par la règle de sévérité du rapport
lui-même (« Medium si la précondition peut arriver, Low si elle ne le peut prouvablement pas »),
S1 tombe. Le durcissement proposé (sonder par builtin) reste bon, il n'est pas urgent.

### O2 — le test existe, 60 lignes au-dessus de celui que le rapport a lu

Le rapport dit : « ce qu'aucun test n'épingle, c'est le côté synthèse : qu'une règle émise pour un
événement non-`Proto::Http` ne puisse jamais sortir en `http://` ».

`netlearn.rs:536`, `domain_the_plane_shapes_the_scheme_and_the_port_only_the_suffix`, assert sur
l'ensemble **complet** des règles émises pour quatre événements, dont `tls80.test` refusé sur le
port 80 en `Proto::Https` → `{*} https://tls80.test:80`. C'est exactement le cas tentant, et son
commentaire énonce la propriété : « An inspected refusal on 80 is `https://h:80`, not `http://h` —
inferring the scheme from the port would learn a rule for a plane that never refused anything ».

## Les réels, par conséquence

### S5 — fail-open sur la garde d'un verbe destructeur

`cli/app.rs:2222` → `main.rs:770` `session_pids_for_app` → `Registry::live().unwrap_or_default()`.
`scan()` (`session.rs:620`) ne rend `Err` que si `read_dir` du répertoire des sessions échoue
autrement que `NotFound` : EACCES, ENOTDIR, EMFILE, EIO. Cette erreur devient « aucune session
vive », et `sbx app prune <name> --yes` supprime sous un agent qui tourne.

Ce qui rend le constat solide, c'est que `scan` **nomme déjà ce danger** à l'échelon inférieur :
« A single unreadable directory entry must not abort the whole listing: the caller's live-session
guard … would then see zero live sessions and could collect an in-use one. » Le soin est pris par
entrée, puis rendu par le `unwrap_or_default` au-dessus.

Sévérité : Low-Medium plutôt que le Medium du rapport — la classe d'`Err` atteignable est étroite
(un répertoire que le même uid possède). Le correctif fail-closed tient en trois lignes.

**Attribution fausse.** Le rapport écrit « Introduced by `4a0ea79` ». La garde vient de `90d5042`
(24 août), 455 commits plus tôt ; `session_pids_for_app` est plus ancien encore. `4a0ea79` a
seulement élargi le rayon (`--caches`, `--all`).

### B2 / S4 — réels, et la surface n'est pas celle que je pensais d'abord

Prémisse exacte : `SANDBOX_HOME = "/home/sandbox"` est en dur (`binds.rs:37`) et `fixture_root()`
résout sous `$XDG_CACHE_HOME` / `$HOME/.cache` (`testroot.rs:27`, après `SBX_TEST_TMPDIR`). Sur un
hôte dont l'utilisateur est `sandbox`, le bind de fixture nage sous le montage structurel et
`structural_nesting_warning` se déclenche.

La surface a une bifurcation qu'il faut suivre. Les avertissements de la ligne de base partent sur
**stderr** (`cli/config.rs:192` → `diag::warn_config`, préfixe `sbx: warning:`), et `render_config`
ne lit jamais `view.warnings` — c'est ce que j'avais vérifié en premier, et cela ne conclut rien.
Les binds d'une **app** passent par le même pli mais dans `app.warnings` (`load.rs:168-175`), qui
devient `AppView::notes` (`view.rs:1576`) et s'imprime **dans le document, sur stdout**, avec le
préfixe `note:` et six espaces d'indentation (`cli/config/render.rs:1249`) — exactement la forme que
le rapport cite. Les deux tests déclarent leur bind sur une app.

Les deux assertions nommées tombent donc bien : `tests/config.rs:3145`
(`!stdout.contains(canonical)`) et `:2191` (`!stdout.contains("note:")`).

S4 suit : la note imprime `dest.display()` (`binds/nesting.rs:95`), le chemin hôte pleinement
étendu, dans une vue dont le contrat dit « des comptes par défaut, l'expansion sous `--details` ».
Le désaccord contrat/comportement est réel, et il n'est pas limité à un hôte exotique : n'importe
quel bind de `/dev/dri` ou `/etc` déclaré par une app produit la même ligne.

### S6 — TOCTOU sur l'énumération de `.cache`

`contained_in` (`gc.rs:928`) canonicalise puis rend le chemin réel ; `read_dir` (`:1028`) le
re-résout par nom. `.cache` est dans la home que la cage écrit. Un processus in-cage qui gagne la
course entre les deux fait atterrir l'énumération ailleurs. Les racines de suppression restent
défendues (`symlink_metadata` par entrée, `:1049`), donc le mal est borné à la suppression
d'entrées entières de ce sur quoi le lien pointe. Low : il faut un processus in-cage qui court.

### O4 (doc) — réel, et déjà clos

`c0b4b6d` et `64915d2` portent le bloc `///` sans le séparateur nu. La garde
(`docs_coverage.rs:1390`) se déclenche sur cette forme : la ligne `/// available.` finit par `.`,
fait moins que `DOC_WRAP`, et la suivante ouvre par une majuscule. Corrigé dans `0ba2a78`.
Le constat de fond (une porte qui ne tourne pas entre l'édition et le commit) tient.

### Perf : O4/O5/O6/O7/O8/O9 — tous exacts

- **O4** : `ACCEPT_POLL = 20 ms` (`forward.rs:76`), `thread::sleep` sur `WouldBlock` (`:284`).
- **O5** : `read_head_raw` lit 1 octet par `read`, chacun précédé d'un `Instant::now()`
  (`deadline.rs:54`) — et `head_terminated(buf)` re-scanne le tampon à chaque octet, un coût que
  le rapport ne mentionne pas. Un seul appelant de production (`mod.rs:391`).
- **O6** : `splice_copy` **n'appelle pas** `splice(2)` malgré son nom — deux `io::copy` à travers
  des enveloppes maison (`CountingReader`/`CountingWriter`), ce qui écarte en plus la
  spécialisation noyau de std. `pump_tcp_uds` de même.
- **O7** : 0 `set_nodelay` et 0 `nodelay` dans `forward.rs`, contre `cleartext.rs:177`,
  `splice.rs:124`, `broker.rs:1372`, `egress.rs:226`/`:572-573` — qui a même un test qui l'épingle
  (`egress.rs:1739`). L'asymétrie est exacte.
- **O8** : `codegen-units` absent de `[profile.release]` ; `proc-shim/Cargo.toml:29` le pose à 1.
- **O9** : `Request::new` (`allowlist/mod.rs:417`) alloue au moins quatre fois (deux dans
  `canonical_host`, deux `format!`) avant la première règle.

### O1 — vrai, mais le code le dit déjà

Les faits sont exacts (`LEAF_CACHE_CAP = 1024`, frappe avant verdict, `reaches_host_at_all`
n'existe pas, aucun test ne référence le plafond hors `dns.rs:46`). Mais `ca.rs:121-131` documente
la décision, la mesure, et nomme la condition de réouverture : « a way to ask the *existing*
matcher whether a host is reachable at all ». Le « correctif bon marché » d'O1 est mot pour mot
cette clause. C'est une décision consignée, pas un constat.

## Ce que la contre-vérification n'a pas fait

- Les portes mécaniques (`fmt`, `lint`, `rustdoc`) et la suite ciblée n'ont pas été relancées :
  aucun code n'a été modifié, et l'arbre porte le travail non commité d'une session concurrente —
  une mesure sur cet arbre ne dirait rien de HEAD.
- La garde `docs_coverage` a été vérifiée **en lecture** (logique du prédicat contre le texte des
  quatre commits), pas en exécution.
- Les benches d'O5/O6/O9 n'ont pas été lancés : ils exigent le profil release, et le rapport
  lui-même ne prétend pas les avoir chiffrés.

## Addendum — la décision d'O1, et ce qu'elle vaut

### Ce qui est décidé

Frapper le certificat feuille **avant** tout verdict d'egress, et borner la conséquence par deux
plafonds (cache de feuilles à 1024, connexions à 512) plutôt que par un réordonnancement.

Le flux mesuré (`proxy/mod.rs:387-520`) : tête CONNECT lue, autorité analysée, puis **seule** la
décision L4 (`l4_decision`, une règle `tcp://` qui épisse en brut), le refus d'une cible littérale IP,
et la sélection h2. Ensuite le tunnel est accepté (`200 Connection established`) et TLS est terminé —
c'est là que `CertResolver::resolve` (`ca.rs:186`) appelle `leaf_for` sur le SNI. Le verdict
allow/deny arrive après, par requête, dans `serve_tunneled_request`, parce qu'il lui faut la méthode
et le chemin.

### L'argument, et sa partie solide

`ca.rs:121-131` donne trois raisons. Les deux premières tiennent, et elles sont les bonnes :

1. Consulter la politique d'abord voudrait dire poser « une règle pourrait-elle admettre cet hôte »,
   question à laquelle le matcher existant ne répond pas : une correspondance exige un chemin, et une
   règle peut porter un préfixe ou une regex.
2. Donc y répondre demande **un second lecteur des règles** à côté de celui qui décide — et un second
   lecteur en désaccord refuserait un hôte que la politique autorise.

C'est le bon axe. Ajouter un lecteur parallèle sur le chemin d'une décision de sécurité crée une
classe de dérive que ce dépôt a déjà payée ailleurs. Et la condition de réouverture que le commentaire
nomme est la bonne réponse d'ingénierie : « a host-level predicate the decision itself goes through,
not a copy of it » — factoriser le matcher, pas le dupliquer.

### Les deux prémisses qui ne portent pas

La troisième raison en contient deux, et aucune ne se vérifie.

**« the peer that forces one pays a full handshake of its own to do so ».** `resolve` est appelé
pendant le traitement du **ClientHello**, avant que le serveur n'envoie sa volée. Un attaquant
in-cage peut donc envoyer un ClientHello et raccrocher : il ne vérifie aucune chaîne, ne dérive
aucun secret de handshake, et peut réutiliser le même keyshare d'un essai au suivant en ne changeant
que les octets du SNI. Son coût par frappe se réduit à quelques appels système ; celui de l'hôte est
une génération de clé ECDSA P-256 plus une signature CA (`rcgen 0.14`, `KeyPair::generate` →
`PKCS_ECDSA_P256_SHA256`). La symétrie annoncée n'existe pas.

**« what reordering saves was measured ».** Le mot « measured » n'apparaît qu'ici. `proxy/bench.rs`
ne chiffre la frappe nulle part : ses sept bancs mesurent le corps retenu, le WebSocket, le coût par
requête, le débit brut, le coût d'un flux h2 et le coût d'un refus — et ce dernier annonce lui-même
son périmètre, « default-deny, cleartext, **no TLS** and no upstream » (`bench.rs:1290`), donc il ne
traverse jamais le chemin de frappe. La proportion affirmée n'a pas d'artefact dans l'arbre.

### Ce que la réserve n'est PAS

J'ai d'abord écrit que le CPU forcé par cette voie échappe au cgroup de la cage. Le fait est exact —
le proxy tourne hors du cgroup, l'arbre le dit à huit endroits — mais il ne porte pas la conclusion
que j'en tirais : `[limits]` n'expose que `memory_high`, `memory_max` et `tasks_max`
(`schema.rs:591-599`). Aucune cage ne porte de quota CPU, donc il n'y a aucun quota à contourner, et
un agent in-cage peut de toute façon brûler du CPU hôte directement. Ce qui reste est étroit et se
dit sans emphase : une amplification par SNI unique, où l'hôte fait une frappe pour un ClientHello
que le pair n'a pas eu à terminer.

Ce que les plafonds bornent, alors : le cache borne la **mémoire** (1024 feuilles retenues), le
plafond de connexions borne la **concurrence** (`DEFAULT_MAX_CONNECTIONS = 512`,
`allowlist/mod.rs:993`). Aucun ne borne le **débit** de frappes.

### Ce qui rend la réouverture plus atteignable que le commentaire ne le dit

La raison 1 est exacte pour les règles L7 : il leur faut un chemin. Mais le chemin pré-déchiffrement
pose **déjà** deux questions d'hôte à la politique, dans la même fonction : `l4_decision(&connect_host,
port)` (`mod.rs:478`) et `speaks_http2(&connect_host, port)` (`mod.rs:514`). Une ombre d'hôte des
règles L7 à côté de ces deux-là serait la troisième d'un motif existant, pas une nouveauté. Le
« factoriser, ne pas copier » que le commentaire nomme comme condition de réouverture a donc un
précédent dans son propre fichier.

### Verdict

La décision est bonne, et pour la bonne raison. Le refus d'ajouter un second lecteur de règles vaut
plus que le déni de service qu'il éviterait, et la sévérité résiduelle est basse : un agent in-cage
exécute déjà du code arbitraire et n'est borné en CPU par rien, donc l'amplification par frappe ne
lui ouvre aucune capacité qu'il n'avait pas.

Deux réserves, toutes deux sur la *justification*, aucune sur la conclusion.

La première : les deux prémisses de la raison 3 — la symétrie des coûts et la mesure — ne se
vérifient pas. Une décision consignée qui s'appuie dessus se relit plus tard comme chiffrée alors
qu'elle ne l'est pas. Les raisons 1 et 2 suffisent à la porter ; les deux phrases de la raison 3
gagneraient à être retirées plutôt que réparées.

La seconde : le commentaire pose le choix comme binaire — réordonner ou ne pas réordonner — et O1
reprend ce cadrage. Sur le cadrage étroit qui survit à la mesure, l'amplification par SNI unique, il
existe un troisième levier que ni l'un ni l'autre ne considère : borner le **débit** de frappes de
SNI distincts, par connexion ou par session. Il ne pose aucune question aux règles, donc rien de la
dérive contre laquelle tout l'argument est construit. C'est le suivi proportionné ici — le prédicat
d'O1 restant souhaitable, mais comme factorisation du matcher le jour où on y touche, jamais comme
copie.

## Corrections appliquées

Toutes les portes (`fmt`, `lint`, `rustdoc`) sont vertes, et les filtres ci-dessous ont été
exercés. Rien n'est commité : l'arbre porte encore le travail non commité d'une session concurrente.

| Constat | Ce qui a changé | Filtre exercé |
|---|---|---|
| S5 | `cli/app.rs` : le registre est lu **une fois** avant la boucle, et une erreur refuse l'application au lieu de valoir « rien ne tourne ». `session_pids_for_app` reste inchangé pour ses appelants de listage. Doc du verbe mise à jour. | `--test app prune` 13/13 |
| B3 / S1 | `examples/bundle/kiro.toml` : le probe passe de `grep -q` à `$(<fichier)` + `case`, deux builtins bash. Le préambule dit pourquoi la dépendance externe était la partie porteuse. | `--bins the_kiro` 1/1, plus une reproduction des quatre cas |
| B2 / S4 | `sandbox/binds/nesting.rs` : les trois notes de nesting écrivent la home hôte `~`. `elided` est une fonction pure de ses entrées, donc testable sans toucher l'environnement. | `--bins nesting` 3/3, `--test config` 2/2 |
| B2 (test) | `tests/config.rs` : les deux assertions passaient par le préfixe `note:`, satisfait par n'importe quelle note du bloc d'app. Elles disent maintenant `dropping`, qui est ce qu'elles vérifient. | idem |
| B1 | `tests/projects.rs` : `reaped_pid` résout `true` par le `PATH` au lieu de `/bin/true`. | `--test projects gc_sweeps_dead_launch` 1/1 |
| O1 | `proxy/ca.rs` : les deux prémisses invérifiées de la raison 3 sont retirées ; la décision, ses raisons 1 et 2 et sa clause de réouverture restent. | `--bins docs_coverage::` 16/16 |
| O7 | `sandbox/forward.rs` : `nodelay` sur la jambe socat et `set_nodelay` sur le flux accepté. Test qui relit l'option dans le script émis, en miroir de celui d'`egress`. | `--bins forward` 65/65, `--test run forward` 3/3 (141 s, cage réelle) |

### Ce que la correction de S5 a révélé

`app rm --purge`, dans le **même fichier** (`cli/app.rs:1207-1218`), fait déjà exactement ce que
S5 réclamait, et le dit dans son commentaire : « Read once for the batch, and fail closed for all
of it: without the registry no name can be proven idle, so none of them may be purged. »

Les deux verbes destructeurs de la famille `app` posaient donc la même question au registre et n'en
tiraient pas la même conséquence : `rm --purge` refusait, `prune --yes` passait outre. Ce n'était
pas un arbitrage, c'était une divergence. La correction aligne `prune` sur la règle que la maison
appliquait déjà à côté, y compris dans sa forme — une lecture unique avant la boucle plutôt qu'une
par cible.

### Ce que les benches ont tranché : O5, O6, O8, O9 restent des propositions

Lancés en release, `--test-threads=1`, sur cet hôte. Aucun des quatre n'a été appliqué, et c'est la
mesure qui le dit, pas la prudence.

**O5 — la lecture octet par octet de la tête CONNECT.** La ligne décisive n'est pas celle que le
rapport cite. « on one reused client tunnel : 38-44 µs/req » contre « upstream reused : 450-499
µs/req » borne l'ensemble du coût d'établissement à environ 455 µs. Une tête de quelques dizaines
d'octets vaut ~25 à 50 µs là-dedans, soit 2 à 4 % d'une requête froide et rien du tout sur un
tunnel réutilisé. Le remède déplace la frontière exacte où le flux doit s'arrêter avant le
ClientHello, sur un chemin dont aucun test unitaire ne vérifie la position. Le rapport de coût ne
le justifie pas.

**O6 — `splice(2)`.** L'épissure brute mesure 2226 à 2763 MiB/s contre 1040 à 1300 pour le relais
inspecté : elle est déjà deux fois plus rapide, et d'un ordre de grandeur au-dessus de tout lien
réel. L'autre moitié du constat (`pump_tcp_uds`) est dans le fichier qu'une session concurrente
tient. Sans objet.

**O9 — les allocations avant le premier verdict.** Le chemin de refus exécute `Request::new` en
entier plus l'appariement des règles, sans TLS ni amont, pour 55 à 59 µs. Et la ligne
`distinct / same` vaut 1,0x à 500, 2000 et 8000 refus : un hôte neuf à chaque fois coûte le même
prix que le même hôte. La canonicalisation n'est pas visible dans le bruit.

**O8 — `codegen-units = 1`.** Deux bras appariés, à la suite, même session :

| ligne | cu=1 | cu=16 | gain cu=1 |
|---|---|---|---|
| relais simple | 1299 MiB/s | 1142 MiB/s | +13,7 % |
| scan de fuite sortante | 1250 | 1040 | +20,2 % |
| capture = bodies | 1293 | 1300 | -0,5 % |
| épissure L4 brute | 2525 | 2226 | +13,4 % |
| TLS direct, sans proxy | 402 µs | 411 µs | +2,2 % |
| HTTPS, sans reprise amont | 863 | 849 | -1,6 % |
| HTTPS, amont réutilisé | 450 | 469 | +4,1 % |
| Content-Length, sans signer | 547 | 527 | -3,8 % |
| Content-Length, signer + digest | 604 | 568 | -6,3 % |
| chunked, sans signer | 569 | 542 | -5,0 % |

Le rapport annonçait « quelques pour cent ». Ce qui sort est du bruit de plus grande amplitude que
l'effet prédit, **et dans les deux sens** : la famille des corps retenus bouge de 4 à 6 % *contre*
`cu=1`, tandis que `capture = bodies` reste plat à côté d'un `relais simple` qui gagne 14 %. Une
mesure dont les lignes voisines se contredisent ne mesure pas ce qu'elle prétend.

Deux causes probables, et je n'ai pas cherché à les départager : la charge montait pendant la série
(5,29 puis 8,41 sur 16 cœurs, dont une part est de ma faute — j'ai lancé le lint pendant la
compilation du second bras), et un bras dure quelques minutes de compilation de plus, ce qui est
un coût certain contre un bénéfice non établi.

Trancher demanderait des séries répétées sur une machine au repos. C'est l'appel du mainteneur, pas
une décision à prendre en retenant les lignes favorables.

### O4-perf — mesuré, et le rapport se trompait dans le sens qui compte

`forward.rs` s'est libéré quand la session concurrente a commité `318429a`. Le rapport disait
lui-même ce qui manquait pour décider — « a loopback connect-latency micro-bench of the forwarder,
which the bench file does not yet carry ». Écrit : 200 connexions séquentielles, du `connect` au
premier octet relu, en quantiles, parce qu'une moyenne masque la forme qui identifie la cause.

| | min | p50 | p95 | max |
|---|---|---|---|---|
| avant | 19,78 ms | **20,08 ms** | 20,23 ms | 20,42 ms |
| après | 0,08 ms | **0,09 ms** | 0,14 ms | 0,32 ms |

Le rapport annonçait « médiane ~10 ms, queue 20 ms », c'est-à-dire une dispersion de 0 à
l'intervalle. La mesure donne **20 ms plat**. La raison est dans l'ordre des opérations : la boucle
fait sa sieste *après* avoir servi une connexion, donc la suivante d'un appelant séquentiel — un
navigateur, un `curl` — atterrit toujours dedans. C'est le pire cas de la forme, et c'est le cas
interactif réel. Le constat était donc sous-évalué, pas surévalué.

Le correctif est `poll(2)` sur le listener, l'idiome de `fs_watch`. Le contrat de teardown ne
change pas — drapeau plus réveil borné — le listener reste non bloquant, et `ACCEPT_POLL_MS` ne
borne plus que le teardown, ce que son commentaire prétendait déjà. L'autre option (accept bloquant
plus poke, à la `egress`) est écartée : elle change l'invariant qui fait de `WouldBlock` la seule
erreur que la boucle s'autorise à avaler, donc tout son chemin d'erreur.

### Une erreur de ma part, et sa réparation

`ef8a0fd` (les trois jetons `nodelay` d'O7) a **annulé** le correctif `libc::open`/`O_PATH` que la
session concurrente venait de poser dans `318429a`. Le `--stat` annonçait 56 insertions et 23
suppressions pour un changement de trois jetons : les 23 suppressions étaient leur
`dial_cage_socket`. La branche est restée rouge sur leur propre garde
(`no_o_path_open_is_left_to_open_options_to_mask`), et mon message de commit n'en disait rien.

Le mécanisme : l'outil d'édition réécrit le fichier depuis sa copie en cache, prise avant un
redémarrage de session et avant leur commit. Relire par `sed` juste avant d'éditer ne rafraîchit
pas cette copie. L'avertissement « changed on disk » est arrivé après le commit.

Réparé par `bb125b3` : leur fonction restaurée octet pour octet depuis `318429a` (`diff` vide),
leur garde repasse. Commit correctif plutôt que réécriture d'historique, parce que leur session est
vivante sur le dépôt. Les cinq autres commits ont été audités ligne à ligne — chaque suppression y
est exactement ce qui était remplacé, aucun autre clobber. La parade, désormais systématique :
lire `git diff --cached | grep '^-'` avant chaque commit, où une suppression non voulue est le seul
endroit où elle se voit.

### S6 — pourquoi je ne l'ai pas corrigé, et ce qu'il coûte vraiment

Le constat tient (l'énumération re-résout `.cache` par son nom après la vérification de
confinement), mais un correctif partiel serait pire que pas de correctif, et c'est ce qui décide.

Ce qu'il faudrait, mesuré sur l'arbre :

1. Une ouverture confinée composant par composant. `O_NOFOLLOW` ne garde que le **dernier**
   composant : un lien planté à la place de `mise` rouvrirait la fenêtre sur `installs`. La marche
   correcte existe déjà dans l'arbre — `theme_relay.rs:344-374` descend `openat(O_RDONLY |
   O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)` depuis une ancre que la cage ne peut pas avoir échangée —
   mais elle y est **en ligne**, pas en helper. La reprendre telle quelle dans `gc.rs` dupliquerait
   la règle de sécurité à deux endroits, ce que les consignes du dépôt interdisent : il faut
   l'extraire d'abord, donc éditer aussi `theme_relay.rs`.
2. Une suppression récursive relative au descripteur. `force_remove_dir_all` (`gc.rs:1341`) travaille
   par chemin, et c'est la primitive destructrice de tout le module. L'épingler pour la seule
   énumération laisserait la fenêtre entre le `read_dir` et chacun de ses appels : la cellule
   passerait de vide à « remplie » sans que le vecteur soit fermé.
3. Un test de course avec une couture pour être déterministe, sans quoi il ne prouve rien.

Un piège de plus, relevé au passage : `OpenOptions::custom_flags` masque ses drapeaux avec
`!O_ACCMODE`, et musl replie `O_PATH` dedans — la session concurrente vient de payer exactement ça
dans `forward.rs`. `O_DIRECTORY` et `O_NOFOLLOW` échappent au masque, mais un correctif écrit vite
sur ce chemin le rencontrerait.

Total : un helper partagé, une réécriture de la primitive destructrice, deux modules touchés, un
test de course. Sur un constat Low, dans un fichier qu'une session concurrente a grossi de 250
lignes il y a deux heures. C'est un travail à part, avec sa relecture, pas une ligne de lot.

### Deux constats nés de la correction elle-même, non corrigés

**Le diagnostic « cannot read the session registry » est écrit sept fois.** `cli/app.rs:1214`
(`rm --purge`), `cli/app.rs` (`prune`, le mien), `launch/session.rs:86` et `:360`,
`launch/reclaim.rs:97` et `:318`, `main.rs:423`. Aucun helper partagé, et un helper *partiel*
existe pourtant — `live_sessions` (`main.rs:421`) fait la lecture et la conversion en refus, sans
qu'aucun des deux verbes d'`app` l'appelle. J'ai délibérément **ne pas** extrait de helper pour mes
deux sites : dédupliquer deux formes sur sept en ajouterait une huitième sans unifier le motif. Ce
qui appartient au mainteneur, c'est la consolidation des sept, ou la décision de les laisser
diverger volontairement. Mon message a été aligné sur la forme des autres
(`sbx <verbe>: cannot read the session registry (<e>) — refusing to …, because …`), qui est celle
de `reclaim.rs:318`.

**`rm --purge` interroge le registre avec `list`, pas `live`.** `list` range le répertoire au
passage : il supprime les enregistrements morts. La doc de `live` dit exactement pourquoi la
séparation existe — « for a caller that is *asking*, not tidying » — et une garde qui réclame
pendant qu'elle interroge est du même ordre que ce que S5 signalait. Ma correction de `prune`
interroge par `live` ; `rm --purge` n'est pas dans mon périmètre et reste sur `list`. Le signaler
plutôt que le changer : c'est un verbe destructeur, et son comportement actuel a des tests.

### Hors périmètre, et pourquoi

- **S2** (test à `PATH` dépouillé) : `catalogue_tests.rs` s'est libéré, mais `examples/bundle/kiro.toml`
  est redevenu chaud — la session concurrente y ajoute un `[env]` d'opt-out et réécrit le rôle de
  l'étape. Épingler son comportement pendant qu'elle le change collisionne. À écrire quand elle a
  posé.
- **S3 / O3** : le `+5` de `.gitignore` est le correctif de l'auditeur, pas le mien. Laissé tel quel
  pour que le mainteneur décide de son commit.
- **O2** : faux, rien à corriger.
- **O4-doc** : déjà clos par `0ba2a78`.
