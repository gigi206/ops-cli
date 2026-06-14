# `ops` (bwrap) — squelette d'architecture

> Blueprint du nouvel `ops` (substrat bubblewrap + nix daemonless). Synthétise la
> faisabilité ([`bwrap-spike-2026-06-14.md`](bwrap-spike-2026-06-14.md)) et le
> modèle de menace + décisions
> ([`bwrap-threat-model-and-binds.md`](bwrap-threat-model-and-binds.md)) en
> modules Rust, surface CLI et ordre des milestones.

## 1. Le pipeline (vue d'ensemble)

```
  config (global + projet)
        │   ← trust gate (hash de contenu, modèle direnv ; non-fiable ⇒ champs sécu ignorés)
        ▼
  résolution des outils  ── mise + nix (daemonless, sandbox=false, nixpkgs épinglé)
        │
        ▼
  ┌──────────────────────────────────────────────┐
  │   SandboxSpec   (LE point d'audit unique)      │   ← le moteur de policy (mode A/B) le produit
  └──────────────────────────────────────────────┘
        │
        ▼
  assembleur bwrap  (binds + env + FHS + namespaces + réseau)  →  argv  (fonction PURE du Spec)
        │
        ▼
  launch : exec bwrap, remise du TTY
```

**Clé de voûte : `SandboxSpec`.** Une struct **déclarative et pure** qui décrit
tout ce que le sandbox expose (binds, env, store, namespaces, trous, cmd). Tout
l'amont la **produit** ; l'assembleur la **consomme**. Invariant de sécurité :
**seul le constructeur de Spec ajoute de l'exposition ; la génération d'argv est
une fonction pure du Spec.** ⇒ la revue de sécurité a **une seule surface** à
auditer.

## 2. Modules Rust

| Module | Rôle | Réutilise l'actuel ? |
|---|---|---|
| `cli/` | surface clap + dispatch | adapte `src/cli.rs` |
| `config/` | parse + layering global/projet (schéma symétrique), validation | **adapte** la machinerie de layering existante |
| `trust/` | trust gate : **hash des champs sécu**, store des hash validés, re-prompt sur changement (direnv) ; gating des champs sécu d'un projet non-fiable | **étend** `src/trust.rs` |
| `store/` | provisionne le **store user-owned daemonless** (nix statique relocalisé) + gère le layout base/overlay, invocation nix daemonless (`NIX_REMOTE=`, `sandbox=false`). ⚠️ **mécanisme PROVISOIRE — voir §7.4** | neuf |
| `provision/` | résout outils/paquets déclarés → chemins du store via **mise+nix** ; pont mise-nix ; **épinglage nixpkgs** pour non-fiables | **adapte** le pont mise-nix (lua) |
| `sandbox/` | **le cœur** — assemble le `SandboxSpec` puis l'argv bwrap | neuf |
| ↳ `sandbox/spec.rs` | la struct `SandboxSpec` + ses invariants | neuf |
| ↳ `sandbox/policy.rs` | mode A/B × trust → quels trous ouverts (la matrice du §5 du modèle de menace) | neuf |
| ↳ `sandbox/binds.rs` | zones 0/1/2 ; canonicalisation TOCTOU ; `/etc/passwd`+`group` **synthétiques** ; userland FHS (loader+libs) | neuf |
| ↳ `sandbox/env.rs` | zone env : `--clearenv` + allowlist + injection de secrets (config fiable only) | neuf |
| ↳ `sandbox/net.rs` | policy réseau (share/unshare ; hook allowlist futur) | neuf |
| ↳ `sandbox/argv.rs` | construction finale de l'argv bwrap (pure) | neuf |
| ↳ `sandbox/launch.rs` | exec bwrap + remise du TTY (modèle exec-replace) | adapte `src/run/` |
| `session/` | **registre de sessions** (pas de daemon → registre sur disque) : liste des sandboxes actifs, « 2ᵉ terminal dans le même env », **GC** des `$HOME`/overlays per-projet | neuf (remplace `status.rs`/`clean.rs`) |
| `app/` | définitions d'apps (claude/gemini/…) : quel outil, **quels secrets requis** (déclarés fiable), quel mode | **adapte** `src/app/` + `apps.toml` |
| `doctor/` | prérequis (**userns** !), santé du store, version nix | **réoriente** `src/doctor.rs` |
| `platform/ term/ util/ download/` | inchangés (download sert à récupérer le nix statique / assets) | garde |

**Disparaissent** : `src/build.rs` (build d'image), `src/nerdctl.rs`, le wrapping
runtime OCI ; `clean.rs` + `status.rs` → fusionnés dans le module **`session/`**
(GC des overlays/`$HOME` + liste des sessions).

## 3. La struct centrale (esquisse)

```rust
struct SandboxSpec {
    mode:       ActorMode,        // Interactive (A) | Agent (B, défaut)
    trust:      TrustTier,        // Untrusted (défaut) | Trusted
    workdir:    PathBuf,
    binds:      Vec<Bind>,        // { src, dest, Ro|Rw } — la seule source d'exposition FS
    store:      StoreLayout,      // { base_ro, overlay_upper_par_projet }
    env:        EnvPolicy,        // { clearenv: true, allowlist, secrets_injectés }
    fhs:        FhsUserland,      // { loader, lib_paths } — userland 100% nix
    net:        NetPolicy,        // Shared{blocks} | Isolated | Allowlist(futur)
    namespaces: NsPolicy,         // pid: REQUIS, user, ipc, uts, mount…
    holes:      Holes,            // { gui: None|Wayland|X11, ssh_agent, container_socket }
    cmd:        Vec<String>,
}
```

Invariants vérifiés à la construction : `namespaces.pid == true` ; aucun bind
hors racine-projet/store/synthétique pour `Untrusted` ; `env.clearenv == true` ;
`holes.container_socket == false` si `mode == Agent`.

## 4. Surface CLI

| Commande | Effet | Mode |
|---|---|---|
| `ops shell` | shell de dev interactif dans le sandbox du projet | A |
| `ops run -- <cmd>` | exécute une commande dans le sandbox | A |
| `ops app <name>` | lance une app packagée (claude/gemini/…) ; le mode est **déclaré par l'app** | B (défaut) |
| `ops install <pkg>` | installe un outil dans le projet (in-sandbox, overlay) | — |
| `ops trust` / `ops untrust` | gère le trust (hash de contenu, re-validation) | — |
| `ops config …` | voit/édite la config layered | — |
| `ops doctor` | vérifie prérequis (**userns**), santé store | — |
| `ops self-update` | maj du binaire | — |

## 5. Ordre des milestones (le DAG)

| M | Titre | Contenu | Livrable |
|---|---|---|---|
| **M0** | Prérequis + bootstrap store | `ops doctor` : **userns absent → hard-fail avec remédiation, JAMAIS de fallback silencieux** (proot = aucune frontière sécu) ; provisionne le store daemonless ; **valider le chemin EXACT du design : base ro + overlay upper + install daemonless + cohérence de la db SQLite nix à travers l'overlay** (≠ ce que le spike a prouvé, qui était un store *plat*) | spike productisé **+ dé-risquage du store (§7.4)** |
| **M1** | Sandbox minimal | `SandboxSpec` + `binds.rs` (zones 0/1/2) + userland FHS + `--clearenv` + `--unshare-pid` + same-uid + **`session/` (registre, 2ᵉ terminal)** ; `ops shell` isole l'hôte | shell utilisable, Mode A |
| **M2** | Config + trust | layering global/projet ; trust gate hash-de-contenu (direnv) ; gating des champs non-fiables | `.ops.toml` pilote le sandbox **sûrement** |
| **M3** | Provisioning d'outils | pont mise+nix ; paquets déclaratifs ; install in-sandbox → overlay per-projet ; nixpkgs épinglé | outils reproductibles |
| **M4** | Apps + **Mode B** | définitions d'apps ; moteur de policy (A/B × trust → trous) ; injection de secret least-privilege. ⚠️ **livre le flagship avec le trou de confidentialité OUVERT jusqu'à M6** (clé API injectée + réseau ouvert = exfiltration possible, cf. §1 du modèle de menace). Option à valider : avancer ici les 2 blocks quasi-gratuits (`169.254.169.254`+localhost) + egress allowlist opt-in (tu as dit réseau en dernier) | **`ops app claude` = le différenciateur, confidentialité-ouverte** |
| **M5** | Trous de parité + GC | GUI (Wayland) ; socket conteneur **Mode A only** ; ssh-agent ; **GC des overlays/`$HOME` per-projet** (`session/`) | commodités opt-in + housekeeping |
| **M6** | **Policy réseau / allowlist** | couche netns + filtrage (nono/greywall) ; blocks métadonnées/localhost → allowlist | **ferme le trou de confidentialité — DERNIER** |
| **M7** | Durcissement (plus tard) | tier subuid ; ACL fichier Landlock ; limites cgroups/DoS | tiers opt-in |

Logique : **M1** livre vite un truc utilisable ; **M4** livre le différenciateur ;
**M6** ferme la confidentialité en dernier (décision actée).

## 6. Invariants transverses
- **`SandboxSpec` = surface d'audit unique** ; argv = fonction pure du Spec.
- **Default-deny** partout (FS, env, réseau plus tard).
- **`--unshare-pid` toujours** (le same-uid n'est sûr qu'avec).
- **Config non-fiable ne touche jamais les champs sécu.**
- **Installs in-sandbox uniquement** ; store de base ro ; overlay per-projet (⚠️ provisoire, cf. §7.4).

## 7. Questions de design encore ouvertes (à trancher avec l'utilisateur)
1. **Modèle de nouns de config.** [[noun-inheritance-model]] verrouille
   `image → container → app` — **périmé** (plus d'image ni de conteneur).
   Remplacement probable : `profile`(userland/outils de base) → `sandbox`(runtime :
   binds/env/net/mode) → `app`. À redéfinir.
2. **Verbe CLI pour les agents.** `ops app <x>` avec mode déclaré par l'app
   (proposé) vs un `ops agent <x>` explicite qui rend la posture B visible.
3. **Comment ops embarque nix.** Binaire nix statique **embarqué** dans l'asset
   ops, ou **téléchargé** au bootstrap (closure de base depuis un cache binaire /
   cachix) ? Impacte la taille de l'asset et le premier `ops doctor`.
4. **⚠️ Mécanisme du store — PROVISOIRE (seul point pouvant forcer un changement
   structurel).** Le spike a prouvé un **store plat user-owned** bindé sur `/nix`
   — **pas** le design « base ro + overlay upper per-projet + install daemonless +
   cohérence de la db SQLite nix à travers l'overlay ». Ce chemin exact est **non
   testé** → à dé-risquer en **M0**. Et un **trilemme** non résolu :

   | Mécanisme | dedup disque | isolation per-projet (anti-poison) | multi-session |
   |---|---|---|---|
   | store plat partagé | ✓ | ✗ | ✓ (locks db nix) |
   | store plat per-projet | ✗ (574 Mo × N) | ✓ | ✓ |
   | **overlay base+upper (le design)** | ✓ | ✓ | **✗** |

   L'overlay achète dedup+isolation mais **casse le multi-session** : overlayfs ne
   supporte pas le même `upperdir` monté par 2 montages concurrents — or 2 sessions
   du même projet **doivent** partager l'upper. Ironie : le store **plat prouvé**
   gère la concurrence seul via les locks de la db nix. Piste (spike, pas
   décision) : la **vérif de signature nix** couvre déjà le poisoning pour les
   chemins **substitués du cache** (seuls les chemins **construits localement** en
   `sandbox=false` sont non signés) → pourrait **rouvrir l'option store plat
   partagé**.
