//! Resolving the hermetic-FHS userland from sbx's own store.
//!
//! The base userland (an interactive shell, coreutils, the glibc loader and the
//! C/C++ runtime that *foreign* binaries need, the nix-ld shim that routes them to
//! it, nix itself so an agent can self-equip its toolchain into the project's
//! writable store, and a CA bundle so its HTTPS is hermetic) is provisioned into
//! sbx's user-owned store — never the host `/nix`
//! — against the pinned nixpkgs, each output rooted by a gcroot so a later store
//! GC cannot collect it. The store is bound read-only at `/nix` inside the
//! sandbox, so the *logical* `/nix/store/…` paths these provisions report resolve
//! there; their host-side backing (a bind *source*) is the physical path under the
//! store root that [`crate::store::physical_path`] derives.
//!
//! Architecture note: the loader filename is x86-64-specific; multi-arch support
//! is a later concern.

use super::binds::Userland;
use crate::store::Layout;
use std::io;
use std::path::{Path, PathBuf};

/// The dynamic loader a foreign x86-64 binary hard-codes as its interpreter.
const LOADER: &str = "lib/ld-linux-x86-64.so.2";

/// The nix-ld shim, relative to the `nix-ld` output. Bound at the standard
/// interpreter path so a foreign binary that hard-codes it is intercepted; it
/// re-execs the real base loader named in `NIX_LD`.
const NIX_LD_SHIM: &str = "libexec/nix-ld";

/// The curated base CLI tools every cage carries: `(nixpkgs attribute, a binary the output
/// must contain, gcroot name)`. The attribute and the binary name diverge for the GNU
/// userland (`gnugrep` → `grep`, `gnused` → `sed`, `gawk` → `awk`). Kept small and transverse —
/// heavier, language-specific, or GUI-oriented tooling is a project concern, never the base
/// (a desktop helper like `xdg-utils` drags a dbus/glib/X11 stack into a headless cage for no
/// benefit; declare it per project if ever needed).
const BASE_TOOLS: &[(&str, &str, &str)] = &[
    ("curl", "bin/curl", "curl"),
    ("git", "bin/git", "git"),
    ("less", "bin/less", "less"),
    ("gnugrep", "bin/grep", "gnugrep"),
    ("gnused", "bin/sed", "gnused"),
    ("gawk", "bin/awk", "gawk"),
    ("findutils", "bin/find", "findutils"),
    ("jq", "bin/jq", "jq"),
    ("which", "bin/which", "which"),
];

/// The locale always compiled into the cage's archive: a known-good UTF-8 anchor (English) so
/// there is always at least one real named locale and English tooling messages render, on top of
/// glibc's always-available compiled `C.UTF-8`.
const ANCHOR_LOCALE: &str = "en_US.UTF-8";

/// Normalize a host locale env value (e.g. from `LANG`) to the glibc UTF-8 locale name the cage's
/// archive is built for (e.g. `fr_FR.utf8` → `fr_FR.UTF-8`), or `None` if it is not a UTF-8 locale
/// sbx should build. Only an explicit UTF-8 codeset is accepted: a bare `fr_FR`, a non-UTF-8
/// codeset (`fr_FR.ISO-8859-1`), or the built-in `C`/`POSIX`/`C.UTF-8` all yield `None` (the last
/// needs no archive — glibc has it compiled in). A final safe-charset gate (letters, digits, and
/// `_ . - @`) rejects anything that could not be a locale name, so a hostile `LANG` cannot inject
/// into the Nix build expression the name is interpolated into.
fn normalize_utf8_locale(raw: &str) -> Option<String> {
    let (head, modifier) = match raw.trim().split_once('@') {
        Some((h, m)) => (h, Some(m)),
        None => (raw.trim(), None),
    };
    let (name, codeset) = head.split_once('.')?;
    if !codeset.eq_ignore_ascii_case("UTF-8") && !codeset.eq_ignore_ascii_case("utf8") {
        return None;
    }
    if name.is_empty() || name.eq_ignore_ascii_case("C") || name.eq_ignore_ascii_case("POSIX") {
        return None;
    }
    let normalized = match modifier {
        Some(m) => format!("{name}.UTF-8@{m}"),
        None => format!("{name}.UTF-8"),
    };
    normalized
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '@'))
        .then_some(normalized)
}

/// The UTF-8 locales to compile into the cage's archive, derived from the host's own locale
/// (`LC_ALL` then `LANG` — the general selectors the cage inherits through the passthrough) so
/// each machine's cage renders that machine's language, plus the [`ANCHOR_LOCALE`] English
/// fallback. A host locale sbx cannot recognize is simply omitted (the cage falls back to the
/// compiled-in `C.UTF-8`, still UTF-8-clean); `C.UTF-8` stays the structural `LANG` default
/// regardless.
fn host_locales() -> Vec<String> {
    locale_set(
        ["LC_ALL", "LANG"]
            .iter()
            .filter_map(|k| std::env::var(k).ok()),
    )
}

/// Pure core of [`host_locales`]: normalize the raw locale values, add the anchor, and dedup +
/// sort for a stable build expression (so an unchanged host locale re-uses the built archive).
/// Separated from the environment read so the derivation is unit-testable.
fn locale_set(raw: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut set: Vec<String> = raw
        .into_iter()
        .filter_map(|v| normalize_utf8_locale(&v))
        .collect();
    set.push(ANCHOR_LOCALE.to_string());
    set.sort();
    set.dedup();
    set
}

/// Provision a UTF-8 locale archive carrying exactly `locales` into sbx's store, gcrooted under
/// `roots`. Built with `glibcLocales.override` (a curated set, ~3 MB) rather than the stock
/// `glibcLocales` (every locale, ~230 MB) — and *not* the stock `glibcLocalesUtf8`, whose archive
/// lists locales but does not actually load them. Built against the base's own `nixpkgs`
/// reference, so the archive and the base glibc stay version-locked (glibc ignores an archive
/// built for another version). Every interpolated value is sbx-controlled or charset-validated
/// (the resolved reference, the detected system, and the normalized locale names), so the
/// expression carries nothing to escape.
///
/// The gcroot is the fixed name `locales` (not keyed by the locale set): `provision_expr` always
/// runs `nix build`, which rebuilds and repoints the out-link when the set changes, so no stale
/// archive is ever used. Two concurrent launches with *different* host locales race to repoint
/// that shared out-link; the loser's archive simply loses its root and becomes GC-able in the
/// shared store — each project's own seeded copy is unaffected, so no launch fails.
fn provision_locale_archive(
    nix: &Path,
    layout: &Layout,
    roots: &Path,
    nixpkgs: &str,
    system: &str,
    locales: &[String],
) -> io::Result<PathBuf> {
    let locale_list = locales
        .iter()
        .map(|l| format!("\"{l}/UTF-8\""))
        .collect::<Vec<_>>()
        .join(" ");
    let expr = format!(
        "(builtins.getFlake \"{nixpkgs}\").legacyPackages.{system}.glibcLocales.override \
         {{ allLocales = false; locales = [ {locale_list} ]; }}"
    );
    crate::store::provision_expr(
        nix,
        layout,
        &roots.join("locales"),
        &expr,
        "glibcLocales",
        "lib/locale/locale-archive",
    )
}

/// Provision the base hermetic userland into sbx's store and report its paths.
/// The launcher resolves the userland before assembling a spec; on a project's
/// first launch this fetches the base closure from the binary cache. `nixpkgs` is
/// the pinned reference for the OS substrate (glibc, stdcpp, bash, coreutils, nix-ld,
/// nix, socat, cacert, and a curated CLI toolset), resolved once by the caller so it is
/// shared with the project's own
/// package provisioning (and so a future channel override is plumbed in a single
/// place). `engine_ref` is the **separately-locked** reference for mise alone (see
/// below) — usually the same revision, but advanced on its own by `sbx upgrade mise`.
pub(crate) fn resolve_userland(
    nix: &Path,
    layout: &Layout,
    nixpkgs: &str,
    engine_ref: &str,
) -> io::Result<Userland> {
    // The base userland is shared by every launch on the same revision, so its
    // gcroots are keyed by revision (not per-project): one physical copy per channel
    // serves all projects on it, while a project pinned to a different channel roots
    // its own base beside it (the whole sandbox is one channel — see the launcher).
    let roots = layout
        .data_dir()
        .join("gcroots")
        .join("base")
        .join(crate::store::revision_of(nixpkgs));
    let realise = |attr: &str, marker: &str, name: &str| {
        crate::store::provision(nix, layout, &roots.join(name), nixpkgs, attr, marker)
    };

    // glibc supplies the loader (for foreign binaries) and libc; the C++ runtime
    // (libstdc++/libgcc_s, from stdenv's compiler `.lib` output — NOT the compiler
    // itself: no gcc/g++/headers ship in the cage) is what heavier foreign binaries
    // (Electron/Chromium, Node with C++ native addons) dlopen.
    let glibc = realise("glibc.out", LOADER, "glibc")?;
    let stdcpp = realise("stdenv.cc.cc.lib", "lib/libstdc++.so.6", "stdcpp")?;
    // zlib supplies `libz.so.1`, a near-universal dependency a foreign dynamic binary
    // dlopens (Node native addons, some bundled CLIs, many bundled tools) that is absent
    // from glibc/stdcpp. It joins the nix-ld foreign library path so a binary the cage
    // loads through the shim resolves it without a per-profile override.
    let zlib = realise("zlib", "lib/libz.so.1", "zlib")?;
    // the interactive shell and coreutils make the sandbox a usable shell; a
    // fuller toolset is project provisioning, not a bootstrap concern.
    let bash = realise("bashInteractive", "bin/bash", "bash")?;
    let coreutils = realise("coreutils", "bin/ls", "coreutils")?;
    // nix-ld is the shim a foreign binary's standard interpreter resolves to; it
    // re-execs the real base loader (named in NIX_LD), so the base glibc reaches
    // foreign binaries without being forced onto the global LD_LIBRARY_PATH.
    let nix_ld = realise("nix-ld", NIX_LD_SHIM, "nix-ld")?;
    // nix itself, so an agent in the open cage self-equips: it builds and installs a
    // project's toolchain into the project's own writable store (the cage's `/nix`).
    // nix's compiled defaults already do the heavy lifting unconfigured — they resolve
    // the store to the local `/nix`, build from the seeded base offline, and substitute
    // new tools from the default cache over HTTPS (the cage binds sbx's own CA bundle at
    // nix's default certificate path, so trust does not depend on the host — see `cacert`
    // below). sbx adds three settings via `NIX_CONFIG` (set by the assembler):
    // `extra-experimental-features = nix-command flakes`, which the mise `nix:`
    // plugin's `nix build` needs (`extra-`, so purely additive — it does not touch
    // `substituters` or `require-sigs`, leaving the offline base build unaffected),
    // and `sandbox = false` + `filter-syscalls = false`. The latter two reconcile
    // with the cage's seccomp denylist, which refuses the nested-namespace syscalls
    // (`unshare`/`clone(NEWNS)`, `mount`, `pivot_root`) nix's *inner* build sandbox
    // would use: the cage is the boundary, so an in-cage build runs without that
    // redundant inner sandbox. Forcing it off makes that deterministic instead of
    // relying on nix's silent `sandbox-fallback`. (A btrfs-backed store adds a
    // fourth setting so nix leaves the inherited compression attribute in place —
    // see the assembler's `mise_env`.)
    let nix_pkg = realise("nix", "bin/nix", "nix")?;
    // mise, the dev-tool front-end an agent drives to self-equip a project's
    // `nix:` toolchain (`mise install nix:<pkg>`) into the project's own writable
    // store. Carried in every cage — an agent may self-equip from any launch, not
    // only the dedicated passthrough. Unlike the rest of the base, mise is provisioned
    // against its OWN engine reference and gcrooted under the mise tree (not the base),
    // so `sbx upgrade mise` rolls the engine while `sbx upgrade nix` leaves it put. This
    // is safe to run on a different revision than the base because the cage exposes no
    // global `LD_LIBRARY_PATH`: mise finds its own glibc by RPATH, like any cross-channel
    // nix tool. One consequence, recorded consciously: where the in-cage mise once
    // followed a project's channel pin, it now follows the (global) engine channel — an
    // improvement (a current engine even on a project pinned to an old base), at the cost
    // of a project pin's seed carrying both the base glibc and the engine's.
    let mise = super::mise::provision_engine(nix, layout, engine_ref)?;
    // socat is the in-cage egress forwarder: under a network allowlist a wrapper runs
    // `socat TCP-LISTEN:…,fork UNIX-CONNECT:<bound socket>` so the cage's loopback bridges
    // to the host filtering proxy over the bound Unix socket (Model B). It is nix-built, so
    // it shares the base glibc (the one-channel rule) and runs in the relocated store; carried
    // in every cage (like nix and mise) so the posture stays a launch decision, not a different
    // base. Only the allowlist posture references it; other postures simply never invoke it.
    let socat = realise("socat", "bin/socat", "socat")?;
    // cacert: a bundle of trusted CA roots from sbx's own store, so the cage's TLS does not
    // depend on the host carrying one. Its `ca-bundle.crt` is bound read-only at the standard
    // certificate paths (replacing any host bind) and named by the CA-bundle environment
    // variables, so an HTTPS fetch — an agent self-equipping over the default cache, or a
    // later `git`/`curl` — is hermetic. It ships no binary (so it is off PATH); only its
    // certificate bundle matters. Under a network allowlist the egress proxy injects its own
    // per-session CA over the same variables, so that leaf still wins; for every other posture
    // this is the trust anchor.
    let cacert = realise("cacert", "etc/ssl/certs/ca-bundle.crt", "cacert")?;
    // A compiled UTF-8 locale archive, so the cage's glibc can fully load a UTF-8 `LANG`
    // (e.g. `fr_FR.UTF-8`) — rendering accented text and filenames correctly and giving
    // locale-aware collation and messages. A hermetic cage has no host `/usr/lib/locale`, so
    // without an archive glibc silently falls back to the C locale and byte-escapes non-ASCII
    // (an accented filename then shows as `$'\303\251'` under `ls` on a terminal). Like `cacert`
    // it ships only a data file (the archive), no binary, so it is off PATH; the assembler names
    // it in `LOCALE_ARCHIVE`. The locale set is derived from the host's own locale
    // ([`host_locales`]), so each machine's cage renders that machine's language. Best-effort: a
    // host locale glibc cannot build would fail the whole set, so on failure it retries with just
    // the known-good anchor — the host locale then falls back to the compiled-in `C.UTF-8`
    // (still UTF-8-clean) rather than bricking the launch.
    let system = super::current_system();
    let locales = provision_locale_archive(nix, layout, &roots, nixpkgs, &system, &host_locales())
        .or_else(|e| {
            crate::diag::warn(&format!(
                "could not build the host locale archive ({e}); \
                 falling back to {ANCHOR_LOCALE}"
            ));
            provision_locale_archive(
                nix,
                layout,
                &roots,
                nixpkgs,
                &system,
                &[ANCHOR_LOCALE.to_string()],
            )
        })?;

    // Curated base CLI tools: a small, broadly-useful set every project gets without
    // per-project provisioning — an HTTP client, version control, a pager, the text-processing
    // trio, file search, a JSON query tool, and `which`. Each is nix-built, so it shares the
    // base glibc (the one-channel rule) and runs from the relocated store; its closure joins the
    // seed and its `bin` joins the base PATH. Heavier or language-specific tooling stays a
    // project concern (`[packages]` or a `nix:` mise tool), not the base.
    let tools = BASE_TOOLS
        .iter()
        .map(|(attr, marker, name)| realise(attr, marker, name))
        .collect::<io::Result<Vec<_>>>()?;

    // Root the channel's own flake source, which every provision above materialized but none
    // rooted — otherwise the shared-store collector reclaims it and the next command that resolves
    // the channel writes it straight back. Placed here, after the provisions, so the source it
    // roots is the one they evaluated. Best-effort and a no-op once warm; see the function.
    crate::store::root_channel_source(nix, layout, &roots, nixpkgs);

    // The logical roots whose closures a project's own store must carry to run the base —
    // surfaced from the very provisions above, so none is forgotten. The nix-ld root is
    // included even though its shim is bound separately: its own closure (its glibc) must be
    // in the store the cage reads.
    let mut base_roots = vec![
        glibc.clone(),
        stdcpp.clone(),
        zlib.clone(),
        bash.clone(),
        coreutils.clone(),
        nix_ld.clone(),
        nix_pkg.clone(),
        mise.clone(),
        socat.clone(),
        cacert.clone(),
        locales.clone(),
    ];
    base_roots.extend(tools.iter().cloned());

    // nix's and mise's bins join the base PATH so the agent can drive them directly, then the
    // curated CLI tools; the project's own tools still precede the base (prepended by the
    // launcher).
    let mut bin_paths = vec![
        bash.join("bin"),
        coreutils.join("bin"),
        nix_pkg.join("bin"),
        mise.join("bin"),
    ];
    bin_paths.extend(tools.iter().map(|t| t.join("bin")));

    Ok(Userland {
        base_roots,
        // The nix-ld shim is a host-side bind source, so physical; in-sandbox paths
        // stay logical (they resolve through the store bound at `/nix`).
        interp_src: crate::store::physical_path(layout, &nix_ld.join(NIX_LD_SHIM)),
        // The CA bundle file is a host-side bind source (it backs the `/etc/ssl/certs/…`
        // mounts), so physical, like the shim above.
        ca_bundle_src: crate::store::physical_path(
            layout,
            &cacert.join("etc/ssl/certs/ca-bundle.crt"),
        ),
        interp_dest: PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
        // The real base loader the shim re-execs is an in-sandbox path, so logical.
        base_loader: glibc.join(LOADER),
        foreign_lib_paths: vec![glibc.join("lib"), stdcpp.join("lib"), zlib.join("lib")],
        bin_paths,
        shell_bin: bash.join("bin/bash"),
        // The coreutils `env` `/usr/bin/env` links to, so an interpreted tool's
        // `#!/usr/bin/env <interp>` shebang resolves. Logical, like the shell above.
        env_bin: coreutils.join("bin/env"),
        // The forwarder is invoked by absolute store path from the egress wrapper, never via
        // PATH (so it does not need to be a user-visible tool), so socat's bin stays off the
        // base PATH above.
        socat_bin: socat.join("bin/socat"),
        // mise is on the base PATH (the agent drives it), but the auto-equip wrapper invokes
        // it by absolute path so a persisted `mise` shim cannot shadow it.
        mise_bin: mise.join("bin/mise"),
        // nix is on the base PATH too, but the `flake:` build wrapper invokes it by absolute
        // path for the same reason — a persisted shim must not shadow the build.
        nix_bin: nix_pkg.join("bin/nix"),
        // The UTF-8 locale archive, named in `LOCALE_ARCHIVE` so the cage's glibc loads a
        // UTF-8 `LANG`. An in-sandbox logical path (it resolves through the store at `/nix`).
        locale_archive: locales.join("lib/locale/locale-archive"),
    })
}

/// The host-locale derivation is pure (no nix, no store), so it is unit-tested directly.
#[cfg(test)]
mod locale_tests {
    use super::*;

    #[test]
    fn normalizes_utf8_locales_and_rejects_the_rest() {
        // a UTF-8 locale normalizes to glibc's canonical spelling
        assert_eq!(
            normalize_utf8_locale("fr_FR.UTF-8").as_deref(),
            Some("fr_FR.UTF-8")
        );
        assert_eq!(
            normalize_utf8_locale("fr_FR.utf8").as_deref(),
            Some("fr_FR.UTF-8")
        );
        assert_eq!(
            normalize_utf8_locale("de_DE.UTF-8").as_deref(),
            Some("de_DE.UTF-8")
        );
        assert_eq!(
            normalize_utf8_locale("ja_JP.UTF-8").as_deref(),
            Some("ja_JP.UTF-8")
        );
        // a @modifier is preserved after the normalized codeset
        assert_eq!(
            normalize_utf8_locale("sr_RS.UTF-8@latin").as_deref(),
            Some("sr_RS.UTF-8@latin")
        );
        // the built-in C.UTF-8 needs no archive entry; C/POSIX and a bare or non-UTF-8 locale
        // are not UTF-8 archive locales
        assert_eq!(normalize_utf8_locale("C.UTF-8"), None);
        assert_eq!(normalize_utf8_locale("C"), None);
        assert_eq!(normalize_utf8_locale("POSIX"), None);
        assert_eq!(normalize_utf8_locale("en_US"), None);
        assert_eq!(normalize_utf8_locale("fr_FR.ISO-8859-1"), None);
    }

    #[test]
    fn a_hostile_locale_value_cannot_inject_into_the_build_expression() {
        // a value carrying quote/space/shell metacharacters fails the safe-charset gate, so it
        // never reaches the Nix `--expr` string
        assert_eq!(
            normalize_utf8_locale("fr_FR.UTF-8\" ]; evil = 1; x = [ \"y"),
            None
        );
        assert_eq!(normalize_utf8_locale("a b.UTF-8"), None);
        assert_eq!(normalize_utf8_locale("$(touch pwned).UTF-8"), None);
    }

    #[test]
    fn the_locale_set_adds_the_anchor_dedups_and_sorts() {
        // the host's own locale is kept, C is dropped, the anchor is always present, sorted+deduped
        assert_eq!(
            locale_set(["fr_FR.UTF-8".into(), "C".into(), "de_DE.utf8".into()]),
            vec![
                "de_DE.UTF-8".to_string(),
                "en_US.UTF-8".to_string(),
                "fr_FR.UTF-8".to_string(),
            ]
        );
        // no host locale → just the anchor
        assert_eq!(locale_set([]), vec!["en_US.UTF-8".to_string()]);
        // a host locale equal to the anchor does not duplicate it
        assert_eq!(
            locale_set(["en_US.UTF-8".into()]),
            vec!["en_US.UTF-8".to_string()]
        );
    }
}

/// Provisioning the userland needs a real nix and store, so this is an
/// integration check: it skips (does not fail) where nix is absent, and otherwise
/// asserts the reported paths are well-formed — bind sources physically present in
/// sbx's store, in-sandbox paths logical and backed by the store.
#[cfg(test)]
mod resolve_tests {
    use super::*;
    use crate::store::{Layout, physical_path};
    use crate::testutil::TmpDir;

    #[test]
    fn resolves_a_usable_hermetic_userland_from_sbx_store() {
        let Some(nix) = crate::store::resolve_nix(None) else {
            eprintln!("skipping userland resolution: no nix on PATH");
            return;
        };

        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let nixpkgs = crate::store::LockTarget::global(&layout, None)
            .resolve(&nix, &layout)
            .expect("resolve nixpkgs");
        // engine == base here (the decoupling is exercised by the launcher and its own
        // tests); this check is about the userland being usable from sbx's store.
        let Ok(u) = resolve_userland(&nix, &layout, &nixpkgs, &nixpkgs) else {
            eprintln!(
                "skipping userland resolution: base provisioning failed (cache or channel drift)"
            );
            return;
        };

        // the base roots are logical store paths, each backed by sbx's store and each a
        // top-level store path (no `bin`/`lib` sub-path), since they are the closure
        // roots the per-project store is seeded from. The expected base set is present:
        // the eleven core provisions plus one root per curated CLI tool.
        assert_eq!(
            u.base_roots.len(),
            11 + BASE_TOOLS.len(),
            "glibc, stdcpp, zlib, bash, coreutils, nix-ld, nix, mise, socat, cacert, locales + the curated tools"
        );
        // every curated tool is reachable by name: its marker binary physically exists in
        // one of the base PATH directories (so it is both realised and on PATH).
        for (_, marker, name) in BASE_TOOLS {
            let bin = marker.strip_prefix("bin/").unwrap();
            assert!(
                u.bin_paths
                    .iter()
                    .any(|p| physical_path(&layout, &p.join(bin)).exists()),
                "curated tool {name} ({bin}) is not reachable on the base PATH"
            );
        }
        for root in &u.base_roots {
            assert_eq!(
                root.parent().and_then(|p| p.to_str()),
                Some("/nix/store"),
                "a base root is not a top-level store path: {}",
                root.display()
            );
            assert!(
                physical_path(&layout, root).is_dir(),
                "a base root is not backed by sbx's store: {}",
                root.display()
            );
        }
        // the interpreter bound at /lib64/ld-linux is the nix-ld shim, present in
        // sbx's store as a physical bind source
        assert!(
            u.interp_src.exists(),
            "nix-ld shim missing: {}",
            u.interp_src.display()
        );
        assert!(
            u.interp_src.starts_with(layout.store_dir()),
            "nix-ld shim is not under sbx's store: {}",
            u.interp_src.display()
        );

        // the CA bundle bound under /etc/ssl/certs is sbx's own cacert: a physical bind
        // source under sbx's store, the very file nix and OpenSSL verify against
        assert!(
            u.ca_bundle_src.starts_with(layout.store_dir()),
            "CA bundle is not under sbx's store: {}",
            u.ca_bundle_src.display()
        );
        assert!(
            u.ca_bundle_src.is_file(),
            "CA bundle missing from sbx's cacert: {}",
            u.ca_bundle_src.display()
        );

        // in-sandbox paths are logical (`/nix/store/…`) and backed by the store —
        // including the base loader the shim re-execs (carried in NIX_LD)
        for p in u
            .bin_paths
            .iter()
            .chain(&u.foreign_lib_paths)
            .chain(std::iter::once(&u.base_loader))
            .chain(std::iter::once(&u.shell_bin))
            .chain(std::iter::once(&u.env_bin))
        {
            assert!(
                p.starts_with("/nix/store"),
                "not a logical path: {}",
                p.display()
            );
            assert!(
                physical_path(&layout, p).exists(),
                "logical path not backed by the store: {}",
                p.display()
            );
        }

        // nix-ld exposes `libz.so.1` to foreign binaries: zlib's lib dir is on the
        // foreign library path and the library file is backed by sbx's store. A binary
        // the cage loads through the shim (some bundled CLIs, Node native addons) dlopens it.
        let zlib_lib = u
            .foreign_lib_paths
            .iter()
            .find(|p| physical_path(&layout, &p.join("libz.so.1")).exists())
            .unwrap_or_else(|| panic!("no foreign lib path carries libz.so.1"));
        assert!(
            zlib_lib.starts_with("/nix/store"),
            "zlib lib path is not a logical store path: {}",
            zlib_lib.display()
        );

        // the base gcroots were created under the channel revision (so GC cannot
        // collect the userland, and a different channel roots its own base beside it)
        let rev_roots = data
            .path()
            .join("gcroots/base")
            .join(crate::store::revision_of(&nixpkgs));
        assert!(
            rev_roots.is_dir(),
            "per-revision base gcroots directory missing: {}",
            rev_roots.display()
        );
    }
}
