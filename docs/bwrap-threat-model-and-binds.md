# `ops` (bwrap) — modèle de menace & layout des binds

> Document de design qui **pilote tout le reste** du nouvel `ops` (substrat
> bubblewrap + nix daemonless ; faisabilité validée dans
> [`bwrap-spike-2026-06-14.md`](bwrap-spike-2026-06-14.md)). Le layout des
> montages, de l'environnement et du réseau découle directement du modèle de
> menace ci-dessous.

## 0. La colonne vertébrale : DEUX modes d'acteur

Toutes les décisions « trou par trou » (réseau, GUI, conteneurs imbriqués,
ssh-agent) se contredisent tant qu'on raisonne sur **un** acteur flou. On les
sépare ; c'est l'axe structurant :

| | **Mode A — shell de dev interactif** | **Mode B — agent autonome** |
|---|---|---|
| Qui pilote | L'**utilisateur** | Les **actions de l'agent** (LLM) |
| Confiance | Semi-fiable (risque surtout pour soi) | **Non fiable** (prompt-injection, dép. empoisonnée) |
| GUI / ssh-agent / conteneurs imbriqués | Commodités | **Canaux d'évasion / exfiltration** |

**Le différenciateur annoncé d'ops = Mode B.** → **Mode B est la posture par
défaut ; Mode A est un opt-in explicite.** Chaque défaut « trou dangereux »
tombe de cet axe au lieu d'être débattu un par un.

## 1. Modèle de menace

### Actifs à protéger
- **Secrets** : `~/.ssh`, `~/.aws`, `~/.config/gh`, `~/.gnupg`, `~/.netrc`,
  cookies navigateur, tokens d'apps, **socket ssh-agent** (`$SSH_AUTH_SOCK`),
  et **variables d'environnement** porteuses de secrets (`ANTHROPIC_API_KEY`,
  `GITHUB_TOKEN`, `AWS_*`…).
- **Intégrité de l'hôte** : écrire hors du projet (rc shells → persistance,
  système, autres projets).
- **Autres projets** présents sur la machine.
- **Position réseau** : exfiltration ; pivot vers `169.254.169.254` (métadonnées
  cloud), `localhost` (bases/serveurs de dev), LAN.
- **Identité de l'utilisateur** : agir en son nom (git push signé, comptes).

### Adversaires
1. **Agent IA dévoyé / prompt-injecté** (page web, README, dép. piégée).
2. **Dépendance malveillante** (postinstall npm/pip, supply chain).
3. **Projet non fiable** lui-même : son `.ops.toml`, ses Makefile/hooks/devshell
   sont **contrôlés par l'attaquant** dès qu'on `cd` dans un repo cloné.

### Frontières de confiance
1. Hôte ↔ sandbox (la frontière bwrap — la principale).
2. Config **fiable** (`~/.config/ops/ops.toml`, écrite par l'utilisateur) ↔
   config **projet non fiable** (`.ops.toml` d'un repo quelconque).
3. `ops` le lanceur (fiable, tourne sur l'hôte) ↔ tout l'intérieur du sandbox.

### Capacités supposées de l'attaquant (dans le sandbox)
- **Exécution de code arbitraire sous l'uid de l'hôte** (le sandbox tourne en
  `uid=1000`, prouvé). ⇒ **pas de barrière uid à l'intérieur** : ce qui est
  visible est compromis. **Le layout des binds EST le contrôle de sécurité.**
- ⇒ **« read-only » protège l'intégrité, PAS la confidentialité.** Un secret
  monté en ro reste **lisible**. Donc **un secret doit être ABSENT, pas ro.**
- Lit toutes les variables d'environnement transmises.

### Hors périmètre (déclaré)
- 0day noyau sur les namespaces/userns (bwrap == sécurité des namespaces
  noyau ; le noyau est dans la TCB).
- Canaux auxiliaires (timing, Spectre).
- DoS / épuisement de ressources (fork bomb, remplissage disque) — atténué plus
  tard (cgroups), pas une garantie v1.
- L'utilisateur qui sabote volontairement son propre sandbox (mais ops rend le
  chemin sûr **par défaut** et le chemin dangereux **explicite et bruyant**).

### ⚠️ Limite de confidentialité à énoncer d'emblée
Le cas d'usage phare (claude-code) exige **à la fois** sa clé API **et** le
réseau vers `api.anthropic.com`. Avec un **réseau ouvert par défaut**, un agent
prompt-injecté peut **exfiltrer n'importe quel secret du sandbox vers
n'importe où**. Donc : **tant que l'allowlist réseau (le travail « nono/greywall
plus tard ») n'existe pas, il n'y a PAS de garantie de confidentialité en v1.**
Bloquer `169.254.169.254` + `localhost` est **nécessaire mais loin d'être
suffisant**. La garantie honnête v1 : *« aucune mutation de l'état système hôte
/ des autres projets / des secrets, et pas d'exfiltration une fois l'allowlist
réseau livrée. »*

## 2. Les zones — système de fichiers (default-deny)

On part de **rien** (pas de `--bind / /`). Seul l'explicite existe.

### Zone 0 — Caché (deny par défaut)
Absents par construction : `~/.ssh`, `~/.aws`, `~/.config/gh`, `~/.gnupg`,
`~/.netrc`, profils navigateur, `$SSH_AUTH_SOCK`, `/root`, les autres projets,
le `$HOME` de l'hôte, l'essentiel de `/etc`.

### Zone 1 — Lecture seule partagée (intégrité, non-secret)
| Montage | Source | Pourquoi |
|---|---|---|
| `/nix` (base) | **store de base fiable d'ops** (ro lower) | append-only, sans secret ; ro = l'agent ne peut pas trafiquer les binaires installés |
| loader FHS | `nixpkgs#glibc.out` → `/lib64/ld-linux-…` | userland 100 % nix (FHS hermétique, cf. spike) |
| `/etc/passwd`, `/etc/group` | **SYNTHÉTIQUES** (sandbox-user + nobody) | résolution uid/gid **sans** fuiter les comptes de l'hôte |
| `/etc/ssl/certs`, `/etc/resolv.conf` | hôte, ro | TLS / DNS (si réseau autorisé) |
| `/dev` | `--dev` minimal (pas le `/dev` hôte) | null/zero/urandom/tty seulement |

Jamais : `/etc/shadow`, `/etc/passwd` **de l'hôte**.

### Zone 2 — Inscriptible (la surface de travail)
| Montage | Source | Notes |
|---|---|---|
| projet | dir projet hôte, **rw** | bind au **même chemin absolu** que sur l'hôte (compat. outils) ; le code n'est pas un secret |
| `$HOME` sandbox | `…/ops/projects/<id>/home`, **rw** | **PAS** le `$HOME` hôte ; caches outils, config de l'agent |
| `/tmp` | tmpfs frais | éphémère, privé |
| store (upper) | overlay per-projet, **rw** | cf. §3 |

## 3. Le modèle de store (corrigé)

⚠️ **Le nix de stock est *input-addressed*, pas content-addressed** (la CA est
expérimentale). En mode single-user daemonless, le dir du store **et**
`/nix/var/nix/db` sont **possédés par l'utilisateur** → un agent same-uid du
projet A peut **trojaniser** un chemin du store ou la db que le projet B (ou la
prochaine session) consomme. « La CA borne le poisoning » est **faux** ici.

**Modèle retenu** (avec l'overlay déjà prouvé au spike) :

```
  store de BASE fiable   →  --overlay-src  (ro lower, peuplé UNIQUEMENT par ops côté hôte)
  upper per-projet (rw)  →  --overlay      (les installs de l'agent atterrissent ici, isolées)
  /nix dans le sandbox   =  union des deux
```

L'agent installe dans **son upper** ; la base partagée reste digne de confiance ;
aucun projet ne contamine un autre.

## 4. Les zones — environnement (2ᵉ layout, même rigueur)

**Prouvé : bwrap N'efface PAS l'env par défaut** (`SPIKE_SECRET` a fuité à
travers). ⇒ **défaut = `--clearenv` + allowlist d'injection explicite**, exactement
le même default-deny que le système de fichiers. `PATH`, `HOME`, `TERM`, `LANG`
reconstruits ; les secrets (`ANTHROPIC_API_KEY`…) **injectés un par un**,
déclarés **uniquement en config fiable**, jamais hérités en masse, jamais depuis
la config projet.

## 5. Les trous délibérés (défaut selon le mode d'acteur)

| Trou | Mode B (agent, défaut) | Mode A (interactif, opt-in) |
|---|---|---|
| **Réseau** | ouvert v1 **mais** bloquer `169.254.169.254` + `localhost` ; **but cible = allowlist** (Landlock/netns) | idem / plus large |
| **GUI** | **off** ; si requis, Wayland (mieux isolé) jamais X11 (un client X keylogge/screenshot les autres fenêtres) | opt-in, Wayland préféré |
| **Conteneurs imbriqués (socket podman)** | **DROPPÉ** — le socket = **équivalent root sur l'hôte** (lancer un conteneur avec `/` bind-monté). Pas « gaté » : **absent**. Un proxy-broker filtrant est du **travail futur**, pas une case v1. | gaté + confirmation |
| **ssh-agent** (`$SSH_AUTH_SOCK`) | **off** (donne TOUTES tes clés pour la durée de vie) | opt-in scoped |
| **Injection de secret** | least-privilege, déclarée en config **fiable** seulement | idem |
| **Persistance des creds d'un outil** (ex. creds propres de claude-code) | un dir de creds **dédié, persistant, isolé**, monté **pour cet outil seul** — jamais tout `~/.config` | idem |

## 6. Le trust gate (sécurité-first) — DÉCIDÉ (option a)

**Décision (2026-06-14) : le trust gate EST la validation.** Faire `ops trust`,
c'est valider le contenu ; un projet fiable voit donc sa config honorée
**intégralement** — schéma symétrique [[config-layering-symmetric]] **réaffirmé**,
le trust gate reste la **seule** frontière.

- **Projet non fiable** (défaut pour tout repo non béni) — son `.ops.toml`
  **peut** : choisir les outils/paquets à installer **dans** le sandbox (depuis
  le **nixpkgs épinglé seulement**), le workdir, l'env projet non-secret. Il
  **ne peut PAS** : ajouter des binds, exposer un chemin hôte, élargir le réseau,
  activer GUI/socket-conteneur/ssh-agent, lancer des hooks côté hôte, injecter
  des secrets, changer le userland, pointer vers des flakes/substituters
  distants. Ces champs sont **ignorés avec avertissement**.
- **Projet fiable** (`ops trust`) : config honorée **intégralement**, à l'égal
  de la config globale.
- **Config globale** (fiable, sur l'hôte) : toujours honorée.

> ✅ **Garde-fou — trust lié au contenu (modèle direnv).** Pour que « trust =
> contenu validé » reste **vrai dans le temps** : `ops trust` enregistre un
> **hash** des champs sécurité de la config. Tout changement ultérieur (ex. après
> `git pull`) **re-déclenche la validation** avant application — exactement comme
> `direnv allow` se ré-arme à l'édition de `.envrc`. Sans ça, un `.ops.toml`
> fiable qui gagne `bind ~/.ssh` au prochain pull l'obtiendrait en silence.

## 7. Supply chain (couplé au fork « install brokeré vs in-sandbox »)
- URL de flake arbitraire = **exécution de code** (l'éval d'un flake peut être
  impure). Restreindre les paquets non fiables au **nixpkgs épinglé**, pas des
  URLs.
- Bloquer aussi `substituters` / `extra-substituters` / `trusted-public-keys`
  d'une config non fiable : **un cache binaire malveillant sert du trojan pour
  tout**, pire qu'un flake.
- Couplage : si les installs sont **brokerés côté hôte**, une URL malveillante =
  exécution **sur l'hôte** (grave) ; si **in-sandbox**, c'est **contenu** mais
  alimente le vecteur de poisoning du store (§3). Les deux forks se décident
  ensemble.

## 8. TOCTOU sur les sources de bind
bwrap résout les **sources** de bind dans le namespace **hôte**, avant le pivot.
Si un chemin de bind dérive d'une entrée contrôlée par le projet, un symlink
`./data → ~/.ssh` fait binder le vrai `~/.ssh`. ⇒ **canonicaliser + confiner les
sources de bind à la racine du projet.** (Les symlinks **internes** au projet
sont sûrs : ils se résolvent **dans** le sandbox — ça tue une fausse inquiétude
courante.)

## 9. Prérequis durs (pas des préférences)
- **User namespaces non-privilégiés** (sinon : pas de produit ; cf. spike).
- **`--unshare-pid`** : le modèle same-uid n'est sûr **que** grâce à l'isolation
  pidns + userns. C'est une **exigence**, pas un défaut.
- **`--clearenv`** + allowlist (prouvé nécessaire).
- Mapping **same-uid** par défaut (écriture directe de `uid_map`, sans helper).
  Le « durcissement subuid » réintroduit les helpers **setuid**
  `newuidmap`/`newgidmap` → va à l'encontre du pitch 100 % non-privilégié ; à
  réserver à un tier de durcissement opt-in.

## 10. Décisions (tranchées 2026-06-14)
1. **Schéma symétrique réaffirmé** : le trust gate est la validation ; projet
   fiable = config honorée intégralement, avec **trust lié au hash du contenu**
   (re-validation à chaque changement, modèle direnv). Cf. §6.
2. **Réseau : traité tout à la fin.** Ouvert par défaut d'ici là. ⇒ **la limite
   de confidentialité (§1) tient jusque-là, et c'est accepté.** Les deux blocages
   quasi-gratuits (`169.254.169.254`, `localhost`) peuvent arriver tôt ;
   l'allowlist complète (couche nono/greywall) est la **dernière** étape.
3. **Installs in-sandbox** (option a) + store base ro + overlay per-projet +
   nixpkgs épinglé pour les non-fiables. Aucun code attaquant ne tourne sur l'hôte.
4. **same-uid par défaut** ; `--unshare-pid` exigé ; subuid = durcissement
   opt-in ultérieur.
