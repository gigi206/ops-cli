//! Resolving the hermetic-FHS userland from ops's own store.
//!
//! The base userland (an interactive shell, coreutils, the glibc loader and the
//! C/C++ runtime that *foreign* binaries need, the nix-ld shim that routes them to
//! it, nix itself so an agent can self-equip its toolchain into the project's
//! writable store, and a CA bundle so its HTTPS is hermetic) is provisioned into
//! ops's user-owned store — never the host `/nix`
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
    ("which", "bin/which", "which"),
];

/// Provision the base hermetic userland into ops's store and report its paths.
/// The launcher resolves the userland before assembling a spec; on a project's
/// first launch this fetches the base closure from the binary cache. `nixpkgs` is
/// the pinned reference for the OS substrate (glibc, gcc, bash, coreutils, nix-ld,
/// nix, socat, cacert, and a curated CLI toolset), resolved once by the caller so it is
/// shared with the project's own
/// package provisioning (and so a future channel override is plumbed in a single
/// place). `engine_ref` is the **separately-locked** reference for mise alone (see
/// below) — usually the same revision, but advanced on its own by `ops upgrade mise`.
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

    // glibc supplies the loader (for foreign binaries) and libc; the gcc runtime
    // supplies libstdc++/libgcc that heavier foreign binaries need.
    let glibc = realise("glibc.out", LOADER, "glibc")?;
    let gcc = realise("stdenv.cc.cc.lib", "lib/libstdc++.so.6", "gcc")?;
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
    // new tools from the default cache over HTTPS (the cage binds ops's own CA bundle at
    // nix's default certificate path, so trust does not depend on the host — see `cacert`
    // below). The only
    // configuration ops adds is `extra-experimental-features = nix-command flakes` (via
    // `NIX_CONFIG`, set by the assembler), which the mise `nix:` plugin's `nix build`
    // needs; being `extra-`, it is purely additive — it does not touch `sandbox`,
    // `substituters`, or `require-sigs`, so the offline base build is unaffected. That
    // the build sandbox works *at all* in-cage rests on the cage carrying no syscall
    // filter yet: nix's build sandbox creates nested namespaces (`unshare`/`clone`,
    // `mount`, `pivot_root`) and installs a seccomp filter, so a later cage-level
    // seccomp denylist must allowlist those — or force nix's `sandbox`/`filter-syscalls`
    // off — or it will silently break in-cage builds.
    let nix_pkg = realise("nix", "bin/nix", "nix")?;
    // mise, the dev-tool front-end an agent drives to self-equip a project's
    // `nix:` toolchain (`mise install nix:<pkg>`) into the project's own writable
    // store. Carried in every cage — an agent may self-equip from any launch, not
    // only the dedicated passthrough. Unlike the rest of the base, mise is provisioned
    // against its OWN engine reference and gcrooted under the mise tree (not the base),
    // so `ops upgrade mise` rolls the engine while `ops upgrade nix` leaves it put. This
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
    // cacert: a bundle of trusted CA roots from ops's own store, so the cage's TLS does not
    // depend on the host carrying one. Its `ca-bundle.crt` is bound read-only at the standard
    // certificate paths (replacing any host bind) and named by the CA-bundle environment
    // variables, so an HTTPS fetch — an agent self-equipping over the default cache, or a
    // later `git`/`curl` — is hermetic. It ships no binary (so it is off PATH); only its
    // certificate bundle matters. Under a network allowlist the egress proxy injects its own
    // per-session CA over the same variables, so that leaf still wins; for every other posture
    // this is the trust anchor.
    let cacert = realise("cacert", "etc/ssl/certs/ca-bundle.crt", "cacert")?;

    // Curated base CLI tools: a small, broadly-useful set every project gets without
    // per-project provisioning — an HTTP client, version control, a pager, the text-processing
    // trio, file search, and `which`. Each is nix-built, so it shares the base glibc (the
    // one-channel rule) and runs from the relocated store; its closure joins the seed and its
    // `bin` joins the base PATH. Heavier or language-specific tooling stays a project concern
    // (`[packages]` or a `nix:` mise tool), not the base.
    let tools = BASE_TOOLS
        .iter()
        .map(|(attr, marker, name)| realise(attr, marker, name))
        .collect::<io::Result<Vec<_>>>()?;

    // The logical roots whose closures a project's own store must carry to run the base —
    // surfaced from the very provisions above, so none is forgotten. The nix-ld root is
    // included even though its shim is bound separately: its own closure (its glibc) must be
    // in the store the cage reads.
    let mut base_roots = vec![
        glibc.clone(),
        gcc.clone(),
        bash.clone(),
        coreutils.clone(),
        nix_ld.clone(),
        nix_pkg.clone(),
        mise.clone(),
        socat.clone(),
        cacert.clone(),
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
        foreign_lib_paths: vec![glibc.join("lib"), gcc.join("lib")],
        bin_paths,
        shell_bin: bash.join("bin/bash"),
        // The forwarder is invoked by absolute store path from the egress wrapper, never via
        // PATH (so it does not need to be a user-visible tool), so socat's bin stays off the
        // base PATH above.
        socat_bin: socat.join("bin/socat"),
    })
}

/// Provisioning the userland needs a real nix and store, so this is an
/// integration check: it skips (does not fail) where nix is absent, and otherwise
/// asserts the reported paths are well-formed — bind sources physically present in
/// ops's store, in-sandbox paths logical and backed by the store.
#[cfg(test)]
mod resolve_tests {
    use super::*;
    use crate::store::{physical_path, Layout};
    use crate::testutil::TmpDir;

    #[test]
    fn resolves_a_usable_hermetic_userland_from_ops_store() {
        let Some(nix) = crate::store::resolve_nix() else {
            eprintln!("skipping userland resolution: no nix on PATH");
            return;
        };

        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let nixpkgs = crate::store::LockTarget::global(&layout, None)
            .resolve(&nix, &layout)
            .expect("resolve nixpkgs");
        // engine == base here (the decoupling is exercised by the launcher and its own
        // tests); this check is about the userland being usable from ops's store.
        let u = resolve_userland(&nix, &layout, &nixpkgs, &nixpkgs).expect("resolve userland");

        // the base roots are logical store paths, each backed by ops's store and each a
        // top-level store path (no `bin`/`lib` sub-path), since they are the closure
        // roots the per-project store is seeded from. The expected base set is present:
        // the nine core provisions plus one root per curated CLI tool.
        assert_eq!(
            u.base_roots.len(),
            9 + BASE_TOOLS.len(),
            "glibc, gcc, bash, coreutils, nix-ld, nix, mise, socat, cacert + the curated tools"
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
                "a base root is not backed by ops's store: {}",
                root.display()
            );
        }
        // the interpreter bound at /lib64/ld-linux is the nix-ld shim, present in
        // ops's store as a physical bind source
        assert!(
            u.interp_src.exists(),
            "nix-ld shim missing: {}",
            u.interp_src.display()
        );
        assert!(
            u.interp_src.starts_with(layout.store_dir()),
            "nix-ld shim is not under ops's store: {}",
            u.interp_src.display()
        );

        // the CA bundle bound under /etc/ssl/certs is ops's own cacert: a physical bind
        // source under ops's store, the very file nix and OpenSSL verify against
        assert!(
            u.ca_bundle_src.starts_with(layout.store_dir()),
            "CA bundle is not under ops's store: {}",
            u.ca_bundle_src.display()
        );
        assert!(
            u.ca_bundle_src.is_file(),
            "CA bundle missing from ops's cacert: {}",
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
