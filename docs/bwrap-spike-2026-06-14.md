# Spike — `ops` on bubblewrap + daemonless nix (2026-06-14)

> **Goal of the spike.** Decide whether `ops` can drop OCI containers
> (docker/podman/nerdctl) in favor of a **bubblewrap sandbox launcher +
> single-user (daemonless) nix**, whose differentiator is:
> running tools — including **encapsulated AI agents** — that install
> all of a project's dependencies **without mutating the host OS**. Eventually:
> file/network access control in the style of nono.sh / greywall.io (Landlock).
>
> Short answer: **yes, it is feasible, and the differentiator is proven
> live.** Two design decisions remain (hermetic FHS, security-oriented trust)
> plus one hard prerequisite (unprivileged user namespaces).

## Test machine

| | |
|---|---|
| OS | Ubuntu 26.04 LTS (resolute) |
| Kernel | 7.0.0-22-generic x86_64 |
| `kernel.apparmor_restrict_unprivileged_userns` | `0` (unrestricted) |
| `kernel.unprivileged_userns_clone` | `1` |
| Tools present | `bwrap`, `nix` 2.34.5, `mise`, `nix-user-chroot`, `slirp4netns`, `newuidmap/newgidmap`, `podman`, `docker`, `fusermount3` |
| Absent | `proot`, `nix-portable` |

## Gate A — unprivileged user namespaces (the prerequisite that decides everything)

```bash
sysctl kernel.apparmor_restrict_unprivileged_userns kernel.unprivileged_userns_clone
unshare --user --map-root-user echo ok      # doit réussir SANS root
```

On this machine: **GREEN** (`unshare --user` yields `uid=0` without root, exit 0).

⚠️ **But the stock Ubuntu 24.04+ default is `…restrict… = 1` (restricted).** Without
unprivileged userns, the only fallback is **proot**, which is ptrace
emulation: **no security boundary** (bypassable). For a sandbox product,
"no userns" does not mean "slower," it means **no
product**. Treat it as a hard requirement, not a preference. Possible
workarounds (each = a one-time root setup): documented sysctl flip,
dedicated AppArmor profile, or setuid `bwrap`.

## Feasibility matrix (everything tested live)

| Current ops capability | Verdict | Evidence |
|---|---|---|
| Unprivileged sandbox | ✅ | `unshare --user` / `bwrap` OK without root |
| Host isolation (`$HOME`, `~/.ssh`, `/etc/shadow`) | ✅ | all invisible inside the sandbox |
| Read/write project mount | ✅ | write OK |
| **Host UID/GID preserved** | ✅ **win** | `uid=1000` → **no more `USER_UID` dance in the image build** |
| Sandbox-private `$HOME` | ✅ | isolated from the host, writable |
| Network on/off | ✅ | `--share-net` reachable; without → cut off |
| **Nested containers** | ✅ | docker CLI → host podman socket (client 28.4 / server 5.7), `docker ps` OK |
| GUI (Chrome/Wayland/X) | ✅ | `wayland-0`, `X0`, `bus` sockets present and bindable |
| nix reads/executes inside the sandbox | ✅ | `nix 2.34.5` runs |
| **Daemonless nix install** (differentiator) | ✅ **proven** | install into a **user-owned `gigi:gigi`** store without a daemon, then exec under bwrap → "Bonjour, le monde !" |
| mise + nix env | ✅\* | install-from-cache OK; build-from-source → see fork #1 |
| `.ops.toml` config layering global+project | ✅ | pure ops logic, independent of the substrate |
| Multi-session | ✅ **simpler** | state in directories; 2 bwrap processes; no more `run_attach`/lock |
| Hermetic FHS (100% nix userland) | ✅ **proven** | official node (foreign to nix) runs in a 100% nix userland via the store's loader+libs; see the dedicated spike below |

## The 3 design decisions (real work, not porting)

### Fork #1 — build-from-source nix requires `sandbox = false`

The **nested userns fails** inside bwrap:

```
unshare: échec d'écriture /proc/self/uid_map: Opération non permise
```

Now, the host's `nix build` runs with `sandbox = true`, which creates a build
userns → **fails inside bwrap**. Install-from-cache
(substitution) does not need it → OK. Build-from-source does: it requires
**`sandbox = false`** (the nix-portable approach).

⚠️ `mise install` == `nix build`: the mise-nix plugin shells out to
`nix_build_cmd` (`mise/lib/platform.lua`). Same constraint, not a lesser
risk.

### Fork #2 — FHS: host userland (easy, non-reproducible) vs nix (hermetic)

The `python3` that ran in the sandbox worked because we bound the
**host's** `/usr` read-only. It works, **but it couples the sandbox to the
host's glibc/userland** → loss of reproducibility (Debian libs on Debian,
Arch on Arch), a regression versus today's *controlled* Arch/Debian
image. The hermetic path = 100% nix userland +
`buildFHSEnv`/`nix-ld`. **This is the subject of the dedicated spike below.**

### Fork #3 — ops provisions ITS store, not the host's

Overlaying the host's **multi-user** `/nix` does **not** yield a writable
store: it stays `root:nixbld 1775` → nix switches to daemon mode → dead
socket → failure. The model that works = a **user-owned store from the start**
(`~/.local/share/ops/nix` bound onto `/nix`, embedded static nix,
`sandbox=false`) — this is the **nix-portable** model. The host's `nix-daemon`
(socket-activated, found active) is not reusable, and that's just as well: ops brings
its own.

## Honest bounding of "without impacting the host OS"

ops's store **writes to the host disk** (`hello` pulled in 574 MB: nixpkgs
source + closure). The exact boundary is not "writes nothing" but **no
mutation of host system state / other projects / secrets**. The read-only
shared store remains true and clean.

## Impact on the current code

- **Goes away**: `src/build.rs` (~60 K, image build), `src/nerdctl.rs`
  (~39 K), all OCI runtime wrapping, and the "shared volumes mask rebuilt
  tools" bug (a single store, no more dual image/volume layer).
- **Becomes a new component**: the **trust gate redesigned security-first**
  — an untrusted project `.ops.toml` configures the sandbox in which the
  agent runs → an evasion vector to model.
- **Stays**: `.ops.toml` config layering (global+project), CLI/apps surface,
  mise-nix plugin.

Reference class: **nono.sh / greywall.io / landrun**, not flox/devbox/devenv
(the latter do not sandbox — that's precisely the gap ops fills).

---

## Appendix — reproducible commands

### Base sandbox + isolation + network + host-FHS + nix

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

### Daemonless nix install into a user-owned store + relocated execution

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

### Nested containers via the bound podman socket

```bash
bwrap --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib \
  --symlink usr/lib64 /lib64 --ro-bind /nix /nix \
  --bind /run/user/$(id -u)/podman/podman.sock /run/podman.sock \
  --setenv DOCKER_HOST unix:///run/podman.sock \
  --proc /proc --dev /dev --tmpfs /tmp --unshare-all --share-net \
  /usr/bin/bash -c 'docker version --format "{{.Server.Version}}"; docker ps'
```

## Hermetic FHS spike — result: ✅ a foreign binary runs in a 100% nix userland

Fork #2 asked: can a prebuilt binary **foreign to nix** run
in a **100% nix** userland (without binding the host's `/usr`)? Answer:
**yes.**

**Foreign artifact**: official node **v26.3.0** (nodejs.org) — dynamic ELF,
interpreter `/lib64/ld-linux-x86-64.so.2`, `NEEDED`: `libc`, `libm`, `libdl`,
`libpthread`, `libstdc++`, `libgcc_s`, `libatomic`, `ld-linux`. This is exactly
the kind of binary an agent pulls via npm/pip (manylinux) — and what
claude-code needs.

**Contrast:**

| Test | Setup | Result |
|---|---|---|
| (a) expected failure | pure nix, **no loader**, no host `/usr` | `execvp: No such file or directory` (loader `/lib64/ld-linux` absent) |
| (b1) | 100% nix userland (`glibc.out` loader + `LD_LIBRARY_PATH` = nix libs), **no host `/usr`** | `node --version` → `v26.3.0` |
| (b2) | same, full V8 init (exercises libstdc++/libatomic/libgcc_s) | `V8 14.6.202.34-node.20 | 2+2= 4` |
| (b3) | same, real JS tool | `npm --version` → `11.16.0` |

**Conclusion: the hermetic path is viable.** The mechanism = provide the
loader + the C/C++ libs from the nix store. **Reproducibility is
preserved**: the libs are identical regardless of host distro (no more
coupling to the host's glibc). `buildFHSEnv` (nixpkgs) automates exactly this
layout, additionally mounting a full `/usr` — and it itself uses bwrap.

**Honest nuance**: this minimal test covers **self-sufficient** binaries
(loader + libs). For heavier agent workloads (postinstall scripts
spawning `/bin/sh`/`gcc`, reading `/etc/...`), use the full `/usr`
layout of `buildFHSEnv` rather than the minimal `LD_LIBRARY_PATH`. But the
hard point — loader + C++ runtime for a non-nix binary — is proven.

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

## Overall spike verdict

Everything `ops` does today is feasible on bwrap + daemonless nix, **including
reproducible hermetic FHS**. Forks #1 (sandbox=false) and #2
(hermetic FHS) are **settled and validated**. Still to be designed: the
embedded user-owned store (#3, nix-portable model) and the **security-first
trust gate**.
The only prerequisite not under ops's control is **unprivileged userns** on the
target hosts (restricted by default on stock Ubuntu 24.04+).
