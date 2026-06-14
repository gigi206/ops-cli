# Spike — `ops` sur bubblewrap + nix daemonless (2026-06-14)

> **But du spike.** Décider si `ops` peut abandonner les conteneurs OCI
> (docker/podman/nerdctl) au profit d'un **lanceur de bac à sable
> bubblewrap + nix single-user (sans daemon)**, dont le différenciateur est :
> lancer des outils — dont des **agents IA encapsulés** — qui installent
> toutes les dépendances d'un projet **sans muter l'OS hôte**. À terme :
> contrôle d'accès fichier/réseau façon nono.sh / greywall.io (Landlock).
>
> Réponse courte : **oui, c'est faisable, et le différenciateur est prouvé en
> live.** Restent deux décisions de design (FHS hermétique, trust orienté
> sécurité) et un prérequis dur (user namespaces non-privilégiés).

## Machine de test

| | |
|---|---|
| OS | Ubuntu 26.04 LTS (resolute) |
| Noyau | 7.0.0-22-generic x86_64 |
| `kernel.apparmor_restrict_unprivileged_userns` | `0` (non restreint) |
| `kernel.unprivileged_userns_clone` | `1` |
| Outils présents | `bwrap`, `nix` 2.34.5, `mise`, `nix-user-chroot`, `slirp4netns`, `newuidmap/newgidmap`, `podman`, `docker`, `fusermount3` |
| Absents | `proot`, `nix-portable` |

## Gate A — user namespaces non-privilégiés (le prérequis qui décide de tout)

```bash
sysctl kernel.apparmor_restrict_unprivileged_userns kernel.unprivileged_userns_clone
unshare --user --map-root-user echo ok      # doit réussir SANS root
```

Sur cette machine : **VERT** (`unshare --user` rend `uid=0` sans root, exit 0).

⚠️ **Mais le défaut Ubuntu 24.04+ stock est `…restrict… = 1` (restreint).** Sans
userns non-privilégié, le seul fallback est **proot**, qui est de l'émulation
ptrace : **aucune frontière de sécurité** (contournable). Pour un produit de bac
à sable, « pas de userns » ne signifie pas « plus lent », mais **pas de
produit**. À traiter comme exigence dure, pas comme préférence. Contournements
possibles (chacun = un setup root unique) : flip du sysctl documenté, profil
AppArmor dédié, ou `bwrap` setuid.

## Matrice de faisabilité (tout testé en live)

| Capacité ops actuelle | Verdict | Preuve |
|---|---|---|
| Sandbox non-privilégié | ✅ | `unshare --user` / `bwrap` OK sans root |
| Isolation hôte (`$HOME`, `~/.ssh`, `/etc/shadow`) | ✅ | tous invisibles dans le sandbox |
| Montage projet en lecture/écriture | ✅ | écriture OK |
| **UID/GID hôte préservé** | ✅ **gain** | `uid=1000` → **fini la danse `USER_UID` du build d'image** |
| `$HOME` propre au sandbox | ✅ | isolé de l'hôte, écrivable |
| Réseau on/off | ✅ | `--share-net` joignable ; sans → coupé |
| **Conteneurs imbriqués** | ✅ | docker CLI → socket podman hôte (client 28.4 / serveur 5.7), `docker ps` OK |
| GUI (Chrome/Wayland/X) | ✅ | sockets `wayland-0`, `X0`, `bus` présents et bindables |
| nix lit/exécute dans le sandbox | ✅ | `nix 2.34.5` tourne |
| **Install nix daemonless** (différenciateur) | ✅ **prouvé** | install dans store **user-owned `gigi:gigi`** sans daemon, puis exec sous bwrap → « Bonjour, le monde ! » |
| mise + nix env | ✅\* | install-from-cache OK ; build-from-source → voir fork #1 |
| Config layering `.ops.toml` global+projet | ✅ | logique pure ops, indépendante du substrat |
| Multi-session | ✅ **plus simple** | état dans les dossiers ; 2 process bwrap ; plus de `run_attach`/lock |
| FHS hermétique (userland 100 % nix) | ✅ **prouvé** | node officiel (étranger à nix) tourne en userland 100 % nix via loader+libs du store ; voir spike dédié plus bas |

## Les 3 décisions de design (vrai boulot, pas du portage)

### Fork #1 — build-from-source nix exige `sandbox = false`

Le **userns imbriqué échoue** dans bwrap :

```
unshare: échec d'écriture /proc/self/uid_map: Opération non permise
```

Or le `nix build` de l'hôte tourne avec `sandbox = true`, ce qui crée un userns
de build → **échoue à l'intérieur de bwrap**. L'install-depuis-le-cache
(substitution) n'en a pas besoin → OK. Le build-from-source, si : il faut
**`sandbox = false`** (l'approche de nix-portable).

⚠️ `mise install` == `nix build` : le plugin mise-nix shelle vers
`nix_build_cmd` (`mise/lib/platform.lua`). Même contrainte, pas un risque
moindre.

### Fork #2 — FHS : userland hôte (facile, non-reproductible) vs nix (hermétique)

Le `python3` qui a tourné dans le sandbox marchait parce qu'on bindait le
`/usr` **de l'hôte** en read-only. Ça marche, **mais ça couple le sandbox à la
glibc/userland de l'hôte** → perte de reproductibilité (libs Debian sur Debian,
Arch sur Arch), une régression vs l'image Arch/Debian *contrôlée*
d'aujourd'hui. Le chemin hermétique = userland 100 % nix +
`buildFHSEnv`/`nix-ld`. **C'est l'objet du spike dédié ci-dessous.**

### Fork #3 — ops provisionne SON store, pas celui de l'hôte

Overlayer le `/nix` **multi-user** de l'hôte ne donne **pas** un store
écrivable : il reste `root:nixbld 1775` → nix bascule en mode daemon → socket
mort → échec. Le modèle qui marche = **store user-owned dès le départ**
(`~/.local/share/ops/nix` bindé sur `/nix`, nix statique embarqué,
`sandbox=false`) — c'est le modèle **nix-portable**. Le `nix-daemon` hôte
(socket-activé, trouvé actif) n'est pas réutilisable, et tant mieux : ops apporte
le sien.

## Bornage honnête de « sans impacter l'OS hôte »

Le store d'ops **écrit sur le disque hôte** (`hello` a tiré 574 Mo : source
nixpkgs + closure). La frontière exacte n'est pas « n'écrit rien » mais **aucune
mutation de l'état système hôte / des autres projets / des secrets**. Le store
partagé en lecture seule reste vrai et propre.

## Impact sur le code actuel

- **Disparaît** : `src/build.rs` (~60 K, build d'image), `src/nerdctl.rs`
  (~39 K), tout le wrapping runtime OCI, et le bug « shared volumes mask rebuilt
  tools » (un seul store, plus de double couche image/volume).
- **Devient un composant neuf** : le **trust gate repensé en sécurité-first**
  — un `.ops.toml` de projet non-fiable configure le sandbox dans lequel tourne
  l'agent → vecteur d'évasion à modéliser.
- **Reste** : config layering `.ops.toml` (global+projet), surface CLI/apps,
  plugin mise-nix.

Classe de référence : **nono.sh / greywall.io / landrun**, pas flox/devbox/devenv
(ces derniers ne sandboxent pas — c'est précisément le trou qu'ops comble).

---

## Appendice — commandes reproductibles

### Sandbox de base + isolation + réseau + FHS-hôte + nix

```bash
PROJ=$(mktemp -d); SHOME=$(mktemp -d); printf 'hello\n' > "$PROJ/README"
bwrap \
  --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib \
  --symlink usr/lib64 /lib64 --symlink usr/sbin /sbin \
  --ro-bind /nix /nix \
  --ro-bind-try /etc/resolv.conf /etc/resolv.conf --ro-bind-try /etc/ssl /etc/ssl \
  --ro-bind-try /etc/passwd /etc/passwd --ro-bind-try /etc/group /etc/group \
  --proc /proc --dev /dev --tmpfs /tmp --tmpfs /home \
  --bind "$PROJ" /work --bind "$SHOME" /home/sandbox \
  --setenv HOME /home/sandbox --chdir /work \
  --unshare-all --share-net --die-with-parent \
  /usr/bin/bash -c 'id; ls /home/gigi 2>&1; getent hosts github.com'
```

### Install nix daemonless dans un store user-owned + exécution relocalisée

```bash
STORE="$HOME/ops-spike-store"; mkdir -p "$STORE"
# install SANS daemon (NIX_REMOTE vide) dans un store possédé par l'utilisateur
NIX_REMOTE= nix --extra-experimental-features 'nix-command flakes' \
  --store "$STORE" build --no-link --print-out-paths nixpkgs#hello
stat -c '%U:%G' "$STORE/nix/store"        # -> gigi:gigi
# exécuter le binaire relocalisé en bindant le store user sur /nix
bwrap --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib \
  --symlink usr/lib64 /lib64 --bind "$STORE/nix" /nix \
  --proc /proc --dev /dev --tmpfs /tmp --unshare-all \
  /usr/bin/bash -c '/nix/store/*hello*/bin/hello'
# nettoyage (les chemins du store sont read-only)
chmod -R u+w "$STORE" && rm -rf "$STORE"
```

### Conteneurs imbriqués via le socket podman bindé

```bash
bwrap --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib \
  --symlink usr/lib64 /lib64 --ro-bind /nix /nix \
  --bind /run/user/$(id -u)/podman/podman.sock /run/podman.sock \
  --setenv DOCKER_HOST unix:///run/podman.sock \
  --proc /proc --dev /dev --tmpfs /tmp --unshare-all --share-net \
  /usr/bin/bash -c 'docker version --format "{{.Server.Version}}"; docker ps'
```

## Spike FHS hermétique — résultat : ✅ un binaire étranger tourne en userland 100 % nix

Le fork #2 demandait : un binaire prébuilt **étranger à nix** peut-il tourner
dans un userland **100 % nix** (sans binder le `/usr` de l'hôte) ? Réponse :
**oui.**

**Artefact étranger** : node **v26.3.0** officiel (nodejs.org) — ELF dynamique,
interpréteur `/lib64/ld-linux-x86-64.so.2`, `NEEDED` : `libc`, `libm`, `libdl`,
`libpthread`, `libstdc++`, `libgcc_s`, `libatomic`, `ld-linux`. C'est exactement
le type de binaire qu'un agent tire via npm/pip (manylinux) — et ce dont
claude-code a besoin.

**Contraste :**

| Test | Setup | Résultat |
|---|---|---|
| (a) échec attendu | nix pur, **pas de loader**, pas de `/usr` hôte | `execvp: No such file or directory` (loader `/lib64/ld-linux` absent) |
| (b1) | userland 100 % nix (loader `glibc.out` + `LD_LIBRARY_PATH` = libs nix), **aucun `/usr` hôte** | `node --version` → `v26.3.0` |
| (b2) | idem, init V8 complet (exerce libstdc++/libatomic/libgcc_s) | `V8 14.6.202.34-node.20 | 2+2= 4` |
| (b3) | idem, outil JS réel | `npm --version` → `11.16.0` |

**Conclusion : le chemin hermétique est viable.** Le mécanisme = fournir le
loader + les libs C/C++ depuis le store nix. La **reproductibilité est
préservée** : les libs sont identiques quelle que soit la distrib hôte (plus de
couplage à la glibc de l'hôte). `buildFHSEnv` (nixpkgs) automatise exactement ce
layout, en montant en plus un `/usr` complet — et il utilise lui-même bwrap.

**Nuance honnête** : ce test minimal couvre les binaires **auto-suffisants**
(loader + libs). Pour des charges d'agent plus lourdes (scripts postinstall
lançant `/bin/sh`/`gcc`, lecture de `/etc/...`), utiliser le layout `/usr`
complet de `buildFHSEnv` plutôt que le `LD_LIBRARY_PATH` minimal. Mais le point
dur — loader + runtime C++ pour un binaire non-nix — est prouvé.

```bash
# ingrédients du userland hermétique
GLIBC=$(nix build --no-link --print-out-paths 'nixpkgs#glibc.out')
GCC=$(nix build --no-link --print-out-paths 'nixpkgs#stdenv.cc.cc.lib')
# binaire ÉTRANGER (node officiel) dans un userland 100% nix, sans /usr hôte
bwrap --ro-bind /nix /nix --bind /tmp /tmp \
  --ro-bind "$GLIBC/lib/ld-linux-x86-64.so.2" /lib64/ld-linux-x86-64.so.2 \
  --setenv LD_LIBRARY_PATH "$GLIBC/lib:$GCC/lib" \
  --proc /proc --dev /dev --tmpfs /etc --unshare-all \
  /chemin/vers/node -e 'console.log(process.versions.v8)'
```

## Verdict global du spike

Tout ce qu'`ops` fait aujourd'hui est faisable en bwrap + nix daemonless, **y
compris le FHS hermétique reproductible**. Les forks #1 (sandbox=false) et #2
(FHS hermétique) sont **tranchés et validés**. Reste à concevoir : le store
user-owned embarqué (#3, modèle nix-portable) et le **trust gate sécurité-first**.
Le seul prérequis non maîtrisé par ops est l'**userns non-privilégié** sur les
hôtes cibles (défaut restreint sur Ubuntu 24.04+ stock).
