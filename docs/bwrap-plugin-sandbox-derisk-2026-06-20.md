# Resolver-plugin host-side sandbox — de-risk (2026-06-20)

> Throwaway spike (host `bwrap` + host `gpg`, nothing installed, throwaway `GNUPGHOME`
> under `target/`, removed after). It de-risks the **runner** for the secret-resolver
> plugin engine (the next increment) by answering one question: **is the already-committed
> `[sandbox]` grammar (`allow_paths` / `allow_env` / `network`, commit `89f5bdb`) expressive
> enough to run a real resolver under least privilege?** The load-bearing case is a
> gpg-backed resolver (`pass`, or sops-with-pgp), because it depends on the gpg-agent
> socket — the thing a naive manifest gets wrong.

## What was run

A `pass`-like resolver (`gpg --decrypt <store>/<path>.gpg | head -1`) and a `vault`-like
network resolver (`curl https://…`), each launched under the bwrap argv the runner would
build: `--unshare-{user,ipc,pid,uts,cgroup}` (+ `--unshare-net` unless `network=true`),
`--clearenv`, host `/usr` + lib symlinks + `/etc/ld.so.cache` bound **read-only** (the
`doctor` smoke precedent, *not* the `mise.rs` `/nix` bind), `--proc`/`--dev`/`--tmpfs /tmp`,
the resolver's declared `allow_paths` as `--ro-bind`, declared `allow_env` via `--setenv`.

## Findings

1. **`allow_paths` read-only is sufficient — IF the live gpg-agent socket is bound.**
   - S2 (PATH + `GNUPGHOME` set, **no gnupg dirs bound**) failed three ways: gpg could not
     read `pubring.kbx`, **could not create a lockfile in `GNUPGHOME`**, and could not
     connect to gpg-agent — then fell back to trying to *spawn its own* agent (which needs
     to write).
   - S3 (`GNUPGHOME` **read-only** + the agent socketdir **read-only**) **succeeded** —
     decrypted, exit 0. With the already-running host agent reachable over the bound socket,
     the client gpg performs **no writes** (the agent holds the keys and does the crypto).
   - S4 (socketdir **read-write**) is identical to S3 → `connect()` to the socket does not
     need a writable mount. **The committed read-only `allow_paths` model holds end-to-end;
     no read-write grant is needed for this class of resolver.**

2. **The real grant is `$GNUPGHOME` + the agent socketdir under `$XDG_RUNTIME_DIR/gnupg/`,
   NOT `~/.gnupg`.** With a non-default `GNUPGHOME`, the agent socket lives at
   `$XDG_RUNTIME_DIR/gnupg/d.<hash>` — a runtime-located, **hashed** subdirectory not
   derivable from the home. Even with the default home, modern GnuPG puts the socket under
   `/run/user/<uid>/gnupg/`. So the committed example manifest
   `allow_paths = ["~/.password-store", "~/.gnupg"]` is **insufficient**: it can never name
   the socket. → **The grammar must let `allow_paths` express `$XDG_RUNTIME_DIR`.** A `~`
   expansion alone is not enough.

3. **The runner must supply a structural environment the manifest does not declare:**
   - a **PATH** (`/usr/bin:/bin`). After `--clearenv` the libc default search path happens
     to resolve binaries, but relying on it is brittle — set PATH explicitly.
   - the **host userland** read-only (`/usr` + lib symlinks + ld cache) — every resolver
     uses host tools (`gpg`, `vault`, `bash`); this is structural, not per-manifest.
   - a structural **HOME** (resolvers key off `HOME`/`GNUPGHOME`).
   - for `network = true`: `/etc/resolv.conf`, `/etc/ssl`, `/etc/nsswitch.conf` (DNS + TLS).

4. **`network` boolean maps cleanly:** N1 `--unshare-net` → `Could not resolve host`
   (fail-closed, exit 6); N2 shared → `200`. No grammar change.

## Decisions this forces (before/with increment 2a)

- **Contract revision (the one genuine grammar change):** `allow_paths` entries support a
  **small, fixed** expansion set — `~`/`$HOME` → home, `$XDG_RUNTIME_DIR` → the runtime dir
  — and **reject any other `$VAR`** (fail-closed; no arbitrary env interpolation into a bind
  path). Fix the example `pass` manifest to
  `allow_paths = ["~/.password-store", "~/.gnupg", "$XDG_RUNTIME_DIR/gnupg"]`.
- **Contract clarification (doc, not grammar):** spell out the structural environment the
  runner provides for free (PATH, host userland, HOME, and — under `network = true` — the
  DNS/TLS binds), so a resolver author declares only the *extra* it needs.
- **No read-write `allow_paths` notion** is introduced now — the read-only model is proven
  sufficient for the gpg/agent class. A genuinely write-needing resolver is a future,
  separately-justified extension.
