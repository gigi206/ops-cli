use super::*;
use crate::testutil::{TmpDir, fingerprint};
use std::process::Command;

/// `(bwrap, nix)` when bwrap, a capability-bearing userns, and nix are all
/// present; otherwise `None` to skip.
fn prerequisites() -> Option<(PathBuf, PathBuf)> {
    let bwrap = crate::pathfind::find_on_path("bwrap")?;
    if !matches!(crate::probe_userns(), crate::Userns::Ok) {
        return None;
    }
    let nix = crate::store::resolve_nix(None)?;
    Some((bwrap, nix))
}

#[test]
fn the_generated_argv_launches_a_working_hermetic_shell() {
    let Some((bwrap, nix)) = prerequisites() else {
        skip_incapable!("skipping hermetic smoke: need bwrap, userns, and nix");
        return;
    };

    // a throwaway data dir + project; build_spec lays out the runtime exactly
    // as the launcher will, provisioning the userland into this store.
    let data = TmpDir::new();
    let layout = crate::store::Layout::under(data.path());
    let nixpkgs = crate::store::LockTarget::global(&layout, None)
        .resolve(&nix, &layout)
        .expect("resolve nixpkgs");
    let Ok(userland) = super::super::fhs::resolve_userland(&nix, &layout, &nixpkgs, &nixpkgs)
    else {
        skip_unreachable!("skipping: base userland provisioning failed (cache or channel drift)");
        return;
    };

    let project = TmpDir::new();
    std::fs::write(project.path().join("README"), b"hi").unwrap();

    let cmd = vec![
        userland.shell_bin.clone().into_os_string(),
        OsString::from("-c"),
        // resolve the synthetic user, list `/usr` whole (the minimal synthetic tree, never
        // the host's), show `/usr/bin/env` resolves into sbx's store, list the project
        OsString::from(
            "id -un; echo USR=$(ls /usr | tr '\\n' ','); echo ENV=$(readlink /usr/bin/env); ls",
        ),
    ];
    let env = [("TERM".to_string(), "dumb".to_string())];
    let overlay = Overlay {
        env: &env,
        binds: &[],
        bin_paths: &[],
        timezone: DEFAULT_ZONE,
        fresh_release_tokens: &[],
        ignored_mise_paths: &[],
    };
    // this smoke exercises the userland against the shared store, read-only — the
    // writable per-project store is the launcher's concern.
    let nix_mount = NixMount {
        src: crate::store::physical_path(&layout, Path::new("/nix")),
        writable: false,
        on_btrfs: false,
    };
    let spec = build_spec(
        data.path(),
        project.path(),
        Runtime::ProjectDefault,
        &userland,
        &nix_mount,
        &overlay,
        &[],
        NetPolicy::Shared,
        "",
        &Default::default(),
        crate::sandbox::seccomp::SeccompPolicy::default(),
        &[],
        &Default::default(),
        cmd,
    )
    .expect("build spec");

    let out = super::super::argv::run_bwrap(&bwrap, &spec).expect("spawn bwrap");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "bwrap failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // the synthetic passwd resolved the uid to the sandbox name
    assert!(
        stdout.contains("sandbox"),
        "synthetic identity not resolved:\n{stdout}"
    );
    // hermetic: `/usr` is the minimal synthetic tree — `bin` (the `env` symlink and the
    // `xdg-open` stub) and `share` (the zone database), each one the cage staged itself, never
    // the host's `/usr`, which would carry `lib`, `local`, `sbin`, … alongside. Matched as the
    // whole line: `ls` sorts, `bin` sorts first, so a `contains("USR=bin,")` holds even on a
    // full host `/usr` — the leak this is here to catch.
    assert!(
        stdout.lines().any(|l| l == "USR=bin,share,"),
        "/usr is not the minimal synthetic tree (host /usr may have leaked):\n{stdout}"
    );
    // `/usr/bin/env` is the synthetic symlink into sbx's store, so an interpreted
    // tool's `#!/usr/bin/env <interp>` shebang resolves
    assert!(
        stdout.contains("ENV=/nix/store") && stdout.contains("bin/env"),
        "/usr/bin/env does not resolve into sbx's store:\n{stdout}"
    );
    // nix coreutils ran and saw the project
    assert!(
        stdout.contains("README"),
        "coreutils did not see the project:\n{stdout}"
    );
}

/// The nix-ld substitution that replaces the global `LD_LIBRARY_PATH` with the
/// shim must hold both ends at once: a *foreign* binary (one that hard-codes the
/// standard `/lib64/ld-linux` and finds libc only through the loader) still runs,
/// now served by the shim via `NIX_LD`; AND a nix tool from a *different* channel,
/// and so a different glibc, runs without a skew. The old global `LD_LIBRARY_PATH`
/// served foreign binaries but forced every tool onto the base glibc — an ABI
/// mismatch (`GLIBC_PRIVATE`) for a differently-pinned one — while the shim serves
/// foreign binaries and leaves each nix tool on its own glibc via RPATH. Both
/// halves share one base userland (and so provision and run sequentially), which
/// keeps a cold-cache suite run from standing up two userlands at once.
#[test]
fn the_nix_ld_shim_serves_foreign_binaries_and_unskews_cross_channel_tools() {
    use std::os::unix::fs::PermissionsExt;
    let Some((bwrap, nix)) = prerequisites() else {
        skip_incapable!("skipping nix-ld smoke: need bwrap, userns, and nix");
        return;
    };

    let data = TmpDir::new();
    let layout = crate::store::Layout::under(data.path());
    let base_ref = crate::store::LockTarget::global(&layout, None)
        .resolve(&nix, &layout)
        .expect("resolve base channel");
    let Ok(userland) = super::super::fhs::resolve_userland(&nix, &layout, &base_ref, &base_ref)
    else {
        skip_unreachable!("skipping: base userland provisioning failed (cache or channel drift)");
        return;
    };
    // both halves consume the shared store read-only (the userland is what is under
    // test); the writable per-project store is the launcher's concern.
    let nix_mount = NixMount {
        src: crate::store::physical_path(&layout, Path::new("/nix")),
        writable: false,
        on_btrfs: false,
    };

    // Realise `<flake_ref>#<attr>` and report its logical store path.
    let realise = |flake_ref: &str, attr: &str, marker: &str, name: &str| {
        crate::store::provision(
            &nix,
            &layout,
            &data.path().join("roots").join(name),
            flake_ref,
            attr,
            marker,
        )
        .expect("provision")
    };
    let run =
        |spec: &SandboxSpec| super::super::argv::run_bwrap(&bwrap, spec).expect("spawn bwrap");

    // --- a foreign binary is served by the shim --------------------------------
    // Forge one: take a nix `hello`, repoint its interpreter at the standard
    // loader path and strip its RPATH, so — like a real npm/pip artefact — it can
    // only reach libc through the loader the sandbox provides, never its own
    // store path. Host-side patching needs the physical store path.
    let hello_base =
        crate::store::physical_path(&layout, &realise(&base_ref, "hello", "bin/hello", "hello"))
            .join("bin/hello");
    let patchelf = crate::store::physical_path(
        &layout,
        &realise(&base_ref, "patchelf", "bin/patchelf", "patchelf"),
    )
    .join("bin/patchelf");

    let project = TmpDir::new();
    let proj = project.path().canonicalize().unwrap();
    let foreign = proj.join("foreign-hello");
    std::fs::copy(&hello_base, &foreign).unwrap();
    std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o755)).unwrap();
    // Forging runs the provisioned `patchelf` host-side. Its ELF interpreter is an absolute
    // `/nix/store/<glibc>/…ld-linux` path that resolves against the *host* store, not this
    // relocated one — so on a host whose system `/nix` lacks the channel's exact glibc build
    // (a fresh rolling-channel revision), `execve` returns ENOENT. That is an environment
    // limitation of host-side forging, not a sandbox fault: skip, do not fail.
    let pe = match Command::new(&patchelf)
        .args([
            "--set-interpreter",
            "/lib64/ld-linux-x86-64.so.2",
            "--remove-rpath",
        ])
        .arg(&foreign)
        .output()
    {
        Ok(pe) => pe,
        Err(e) => {
            skip_incapable!(
                "skipping nix-ld smoke: cannot run a relocated-store patchelf host-side \
                 (its loader is not in the host /nix store): {e}"
            );
            return;
        }
    };
    if !pe.status.success() {
        skip_incapable!(
            "skipping nix-ld smoke: patchelf failed: {}",
            String::from_utf8_lossy(&pe.stderr)
        );
        return;
    }

    let bare = Overlay {
        env: &[],
        binds: &[],
        bin_paths: &[],
        timezone: DEFAULT_ZONE,
        fresh_release_tokens: &[],
        ignored_mise_paths: &[],
    };
    let foreign_spec = build_spec(
        data.path(),
        &proj,
        Runtime::ProjectDefault,
        &userland,
        &nix_mount,
        &bare,
        &[],
        NetPolicy::Shared,
        "",
        &Default::default(),
        crate::sandbox::seccomp::SeccompPolicy::default(),
        &[],
        &Default::default(),
        vec![foreign.clone().into_os_string()],
    )
    .expect("build foreign spec");
    let foreign_out = run(&foreign_spec);
    assert!(
        foreign_out.status.success(),
        "foreign binary failed under nix-ld: {}",
        String::from_utf8_lossy(&foreign_out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&foreign_out.stdout).contains("Hello, world!"),
        "foreign binary did not run through the shim: {}",
        String::from_utf8_lossy(&foreign_out.stdout)
    );

    // --- a cross-channel nix tool runs without a glibc skew --------------------
    let cross_ref = crate::store::LockTarget::global(&layout, Some("nixos-23.11"))
        .resolve(&nix, &layout)
        .expect("resolve cross channel");
    if cross_ref == base_ref {
        skip_incapable!(
            "skipping the cross-channel half: both channels resolved to the same revision"
        );
        return;
    }
    // the cross-channel tool's logical bin dir, prepended to PATH
    let bin_paths = vec![realise(&cross_ref, "hello", "bin/hello", "hello-cross").join("bin")];
    let with_tool = Overlay {
        env: &[],
        binds: &[],
        bin_paths: &bin_paths,
        timezone: DEFAULT_ZONE,
        fresh_release_tokens: &[],
        ignored_mise_paths: &[],
    };
    let cross_spec = build_spec(
        data.path(),
        &proj,
        Runtime::ProjectDefault,
        &userland,
        &nix_mount,
        &with_tool,
        &[],
        NetPolicy::Shared,
        "",
        &Default::default(),
        crate::sandbox::seccomp::SeccompPolicy::default(),
        &[],
        &Default::default(),
        vec![OsString::from("hello")],
    )
    .expect("build cross spec");
    let cross_out = run(&cross_spec);
    assert!(
        cross_out.status.success(),
        "cross-channel tool failed — glibc skew not resolved: {}",
        String::from_utf8_lossy(&cross_out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&cross_out.stdout).contains("Hello, world!"),
        "cross-channel hello did not run: {}",
        String::from_utf8_lossy(&cross_out.stdout)
    );
}

/// The open-cage flip: a cage backed by a *writable per-project store* — seeded
/// from the shared store with the base closure — must run the base userland
/// entirely from that per-project store, with the shared store's `nix/store` not
/// bound at `/nix` at all. This proves what the pure argv test cannot: the seed
/// carried the *complete* base closure (a missing root would leave the shell unable
/// to resolve a library), and the real `build_spec` path binds the per-project
/// store read-write at `/nix`. The completeness check has teeth — every surfaced
/// base root must be present in the per-project store, while a package realised into
/// the shared store but left out of the seeded roots must be *absent*, so "present"
/// means "seeded", not merely "somewhere in the shared store".
#[test]
fn the_cage_runs_from_a_writable_per_project_store_seeded_with_the_base_closure() {
    let Some((bwrap, nix)) = prerequisites() else {
        skip_incapable!("skipping per-project store flip smoke: need bwrap, userns, and nix");
        return;
    };
    let Some(nix_store) = crate::store::resolve_nix_store(None) else {
        skip_incapable!("skipping per-project store flip smoke: need nix-store");
        return;
    };

    // provision the base userland into a throwaway shared store, plus an unrelated
    // package (`hello`) the seed must NOT drag in — it is not among the seeded roots,
    // nor in any base root's closure (a curated base tool would taint a closure-shared
    // witness, so this one is deliberately a leaf nothing in the base depends on).
    let data = TmpDir::new();
    let layout = crate::store::Layout::under(data.path());
    let base_ref = crate::store::LockTarget::global(&layout, None)
        .resolve(&nix, &layout)
        .expect("resolve base channel");
    let Ok(userland) = super::super::fhs::resolve_userland(&nix, &layout, &base_ref, &base_ref)
    else {
        skip_unreachable!("skipping: base userland provisioning failed (cache or channel drift)");
        return;
    };
    let unseeded = crate::store::provision(
        &nix,
        &layout,
        &data.path().join("roots").join("hello"),
        &base_ref,
        "hello",
        "bin/hello",
    )
    .expect("provision hello");

    // a project whose own store is seeded with exactly the base roots (the launcher
    // collects base ∪ packages ∪ tools; the base closure is what backs the shell).
    let project = TmpDir::new();
    let proj = project.path().canonicalize().unwrap();
    std::fs::write(proj.join("MARKER"), b"x").unwrap();
    let id = super::project_runtime_id(&proj).expect("project id");
    let store = super::super::projectstore::prepare(&nix_store, &layout, &id, &userland.base_roots)
        .expect("seed the per-project store");
    let in_store = |logical: &Path| {
        store
            .store_dir()
            .join("nix")
            .join("store")
            .join(logical.file_name().unwrap())
            .exists()
    };

    // every surfaced base root is present in the per-project store...
    for root in &userland.base_roots {
        assert!(
            in_store(root),
            "a base root is missing from the seeded store: {}",
            root.display()
        );
    }
    // ...while the unrelated package — in the shared store but not a seeded root —
    // is absent, so the completeness check distinguishes seeded from shared-at-large.
    assert!(
        !in_store(&unseeded),
        "an unseeded package leaked into the per-project store"
    );

    // the seeded store is internally consistent
    let verify = Command::new(&nix_store)
        .env("NIX_REMOTE", "")
        .arg("--store")
        .arg(store.store_dir())
        .args(["--verify", "--check-contents"])
        .output()
        .expect("spawn nix-store --verify");
    assert!(
        verify.status.success(),
        "the seeded per-project store failed verification: {}",
        String::from_utf8_lossy(&verify.stderr)
    );

    // back the cage with the per-project store, read-write — the shared store's
    // nix/store is not bound at /nix, so the shell, coreutils, and glibc must all
    // resolve from the per-project store.
    let nix_mount = NixMount {
        src: store.store_dir().join("nix"),
        writable: true,
        on_btrfs: false,
    };
    let overlay = Overlay {
        env: &[],
        binds: &[],
        bin_paths: &[],
        timezone: DEFAULT_ZONE,
        fresh_release_tokens: &[],
        ignored_mise_paths: &[],
    };
    // the cage reads the base userland AND writes into `/nix` — proving the rw bind
    // through the wired path. The write succeeding is itself proof `/nix` is
    // writable; where it lands is the multi-tenant non-negotiable, asserted below.
    let cmd = vec![
        userland.shell_bin.clone().into_os_string(),
        OsString::from("-c"),
        OsString::from("id -un; ls; echo poison > /nix/POISON"),
    ];
    let spec = build_spec(
        data.path(),
        &proj,
        Runtime::ProjectDefault,
        &userland,
        &nix_mount,
        &overlay,
        &[],
        NetPolicy::Shared,
        "",
        &Default::default(),
        crate::sandbox::seccomp::SeccompPolicy::default(),
        &[],
        &Default::default(),
        cmd,
    )
    .expect("build spec");

    // fingerprint the shared store's content paths just before the cage writes, so
    // any mutation through the rw `/nix` would show as a changed fingerprint after.
    let shared_paths = layout.store_dir().join("nix").join("store");
    let before = fingerprint(&shared_paths);

    let out = super::super::argv::run_bwrap(&bwrap, &spec).expect("spawn bwrap");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "the cage failed to run from / write to the per-project store: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("sandbox"),
        "the synthetic identity did not resolve from the per-project store:\n{stdout}"
    );
    assert!(
        stdout.contains("MARKER"),
        "coreutils from the per-project store did not see the project:\n{stdout}"
    );

    // the in-cage write landed in the project's OWN store copy...
    assert_eq!(
        std::fs::read_to_string(store.store_dir().join("nix").join("POISON"))
            .expect("the in-cage write did not land in the per-project store")
            .trim(),
        "poison"
    );
    // ...and the shared store's content paths are byte-identical — the write could
    // not reach it (it is not in the cage), the multi-tenant non-negotiable.
    assert_eq!(
        before,
        fingerprint(&shared_paths),
        "the shared store changed under an in-cage write"
    );
}

/// The open-cage payoff: the cage carries nix, and an agent uses it to build a
/// **fresh** derivation **offline from the seeded base** — proving the per-project
/// store is a self-sufficient nix store the agent can self-equip into, not just a
/// read-only base. nix is invoked by *name* (so this also proves it is on the cage
/// PATH), `substituters` is emptied (no network fetch is possible — the shared store
/// is not even bound in the cage), and the derivation is novel with its output
/// asserted **absent before** and **present after**, so a successful build can only
/// be a real local build from the seeded bash+coreutils. nix needs *no* sbx-supplied
/// configuration: its compiled defaults resolve the store to the local `/nix` and
/// build there. The teeth: a sibling derivation whose only input is a package realised
/// into the shared store but **left out of the seed** must *fail* offline — proving
/// "present" means "seeded", and the shared store is genuinely absent from the cage.
#[test]
fn the_cage_builds_a_fresh_derivation_offline_from_the_seeded_base() {
    let Some((bwrap, nix)) = prerequisites() else {
        skip_incapable!("skipping nix-in-cage smoke: need bwrap, userns, and nix");
        return;
    };
    let Some(nix_store) = crate::store::resolve_nix_store(None) else {
        skip_incapable!("skipping nix-in-cage smoke: need nix-store");
        return;
    };

    let data = TmpDir::new();
    let layout = crate::store::Layout::under(data.path());
    let base_ref = crate::store::LockTarget::global(&layout, None)
        .resolve(&nix, &layout)
        .expect("resolve base channel");
    // the base userland now carries nix among its roots, so seeding the base closure
    // brings nix and its closure into the per-project store.
    let Ok(userland) = super::super::fhs::resolve_userland(&nix, &layout, &base_ref, &base_ref)
    else {
        skip_unreachable!("skipping: base userland provisioning failed (cache or channel drift)");
        return;
    };
    // hello: realised into the shared store but NOT a seeded root — the discriminant's
    // non-seeded dependency. (jq was the original probe but is now in the curated base
    // toolset, so it IS seeded and could no longer serve as the non-seeded discriminant.)
    let hello = crate::store::provision(
        &nix,
        &layout,
        &data.path().join("roots").join("hello"),
        &base_ref,
        "hello",
        "bin/hello",
    )
    .expect("provision hello");

    let project = TmpDir::new();
    let proj = project.path().canonicalize().unwrap();
    let id = super::project_runtime_id(&proj).expect("project id");
    let store = super::super::projectstore::prepare(&nix_store, &layout, &id, &userland.base_roots)
        .expect("seed the per-project store");

    // the reuse derivation: build closure is bash + coreutils only, both seeded.
    // `builtins.storePath` validates them against the per-project store's own DB, so
    // a successful build proves the seeded store (paths AND database) is sufficient.
    let bash_store = userland.shell_bin.parent().unwrap().parent().unwrap();
    let cu_store = userland.bin_paths[1].parent().unwrap();
    let reuse = proj.join("reuse.nix");
    std::fs::write(
        &reuse,
        r#"let b = builtins.storePath "@BASH@"; c = builtins.storePath "@CU@"; in derivation { name = "sbx-reuse-proof"; system = builtins.currentSystem; builder = "${b}/bin/bash"; args = ["-c" "${c}/bin/mkdir -p $out; ${c}/bin/echo ok > $out/result"]; }"#
            .replace("@BASH@", &bash_store.to_string_lossy())
            .replace("@CU@", &cu_store.to_string_lossy()),
    )
    .unwrap();
    // the discriminant: its only input is hello, which is in the shared store but not
    // in the seed — `builtins.storePath` against the per-project store rejects it, so
    // the build fails offline. That a *seeded* path succeeds while this one fails
    // proves the cage runs from the seed, not from the shared store at large.
    let discriminant = proj.join("discriminant.nix");
    std::fs::write(
        &discriminant,
        r#"let j = builtins.storePath "@HELLO@"; in derivation { name = "sbx-discriminant"; system = builtins.currentSystem; builder = "${j}/bin/hello"; args = []; }"#
            .replace("@HELLO@", &hello.to_string_lossy()),
    )
    .unwrap();

    // The agent's commands. nix is invoked by name (cage PATH), with substituters
    // emptied so nothing can be fetched. Pre/post existence of the reuse output is
    // probed against the cage's own store (`/nix` = the per-project store).
    let script = format!(
        "set +e\n\
         command -v nix-build > /dev/null && echo 'NIX_ON_PATH=yes' || echo 'NIX_ON_PATH=no'\n\
         drv=$(nix-instantiate {reuse} 2>/dev/null)\n\
         outp=$(nix-store -q --outputs \"$drv\" 2>/dev/null)\n\
         echo \"OUTPATH=$outp\"\n\
         if [ -e \"$outp\" ]; then echo PRE=present; else echo PRE=absent; fi\n\
         nix-build --no-out-link --option substituters '' --option builders '' {reuse} > /dev/null 2>&1\n\
         echo \"REUSE_EXIT=$?\"\n\
         if [ -e \"$outp\" ]; then echo POST=present; else echo POST=absent; fi\n\
         echo \"RESULT=$(cat \"$outp/result\" 2>/dev/null)\"\n\
         nix-build --no-out-link --option substituters '' --option builders '' {disc} > /dev/null 2>&1\n\
         echo \"DISC_EXIT=$?\"\n",
        reuse = reuse.display(),
        disc = discriminant.display(),
    );

    let nix_mount = NixMount {
        src: store.store_dir().join("nix"),
        writable: true,
        on_btrfs: false,
    };
    let overlay = Overlay {
        env: &[],
        binds: &[],
        bin_paths: &[],
        timezone: DEFAULT_ZONE,
        fresh_release_tokens: &[],
        ignored_mise_paths: &[],
    };
    let cmd = vec![
        userland.shell_bin.clone().into_os_string(),
        OsString::from("-c"),
        OsString::from(script),
    ];
    let spec = build_spec(
        data.path(),
        &proj,
        Runtime::ProjectDefault,
        &userland,
        &nix_mount,
        &overlay,
        &[],
        NetPolicy::Shared,
        "",
        &Default::default(),
        crate::sandbox::seccomp::SeccompPolicy::default(),
        &[],
        &Default::default(),
        cmd,
    )
    .expect("build spec");

    // the shared store must not change under an in-cage build (multi-tenant).
    let shared_paths = layout.store_dir().join("nix").join("store");
    let before = fingerprint(&shared_paths);

    let out = super::super::argv::run_bwrap(&bwrap, &spec).expect("spawn bwrap");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "the cage script failed: {}\nstdout:\n{stdout}",
        String::from_utf8_lossy(&out.stderr)
    );
    let marker = |key: &str| {
        stdout
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("missing marker {key} in:\n{stdout}"))
    };

    // nix is on the cage PATH, the agent reached it by name
    assert_eq!(
        marker("NIX_ON_PATH"),
        "yes",
        "nix-build not on the cage PATH"
    );
    // the reuse output was absent before and present after — a genuine fresh build
    assert_eq!(marker("PRE"), "absent", "the reuse output pre-existed");
    assert_eq!(marker("REUSE_EXIT"), "0", "the offline reuse build failed");
    assert_eq!(
        marker("POST"),
        "present",
        "the reuse output was not produced"
    );
    assert_eq!(marker("RESULT"), "ok", "the builder did not run");
    // the output landed in the per-project store (the only store bound at /nix)
    let outp = marker("OUTPATH");
    let outp_name = Path::new(outp).file_name().expect("an output path");
    assert!(
        store
            .store_dir()
            .join("nix")
            .join("store")
            .join(outp_name)
            .exists(),
        "the build output is not in the per-project store: {outp}"
    );
    // the discriminant — a non-seeded dependency — failed offline, so "present"
    // really means "seeded", not "anywhere in the shared store"
    assert_ne!(
        marker("DISC_EXIT"),
        "0",
        "a build whose only input is unseeded succeeded offline — the cage is not running from the seed alone"
    );

    // the shared store is byte-identical: the in-cage build could not reach it
    assert_eq!(
        before,
        fingerprint(&shared_paths),
        "the shared store changed under an in-cage build"
    );
}

/// Best-effort TCP reach of the binary cache, so the network smoke below skips
/// (does not fail) when offline — its install fetches from nixhub and the cache.
fn network_reachable() -> bool {
    use std::net::ToSocketAddrs;
    let Ok(mut addrs) = ("cache.nixos.org", 443).to_socket_addrs() else {
        return false;
    };
    addrs.any(|addr| {
        std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(5)).is_ok()
    })
}

/// The `sbx mise` payoff: an agent self-equips a project's `nix:` tool from inside
/// the open cage. The cage carries mise (in the base userland) with the embedded
/// `nix:` backend plugin registered, so `mise install nix:jq` resolves jq through
/// nixhub and builds it into the project's **own** writable store. Two things are
/// proven: the tool genuinely installs and runs (the plugin path works end to end
/// against the relocated single-user store), and — the multi-tenant boundary — the
/// **shared store stays byte-identical**, since an in-cage install can only reach
/// the project's store. Untrusted by construction (no `sbx trust`): the open-cage
/// self-equip posture works regardless of trust, unlike host-side provisioning.
///
/// This is the project's first *network* smoke (nixhub + the binary cache), heavier
/// than the offline ones; it skips when the network is unreachable, and uses jq
/// (cache-substitutable) to stay fast.
#[test]
fn the_cage_self_equips_a_nix_tool_via_mise() {
    let Some((bwrap, nix)) = prerequisites() else {
        skip_incapable!("skipping mise self-equip smoke: need bwrap, userns, and nix");
        return;
    };
    let Some(nix_store) = crate::store::resolve_nix_store(None) else {
        skip_incapable!("skipping mise self-equip smoke: need nix-store");
        return;
    };
    if !network_reachable() {
        skip_unreachable!("skipping mise self-equip smoke: the binary cache is unreachable");
        return;
    }

    let data = TmpDir::new();
    let layout = crate::store::Layout::under(data.path());
    let base_ref = crate::store::LockTarget::global(&layout, None)
        .resolve(&nix, &layout)
        .expect("resolve base channel");
    // the base userland carries mise, so seeding the base closure brings mise and
    // its closure into the per-project store — the agent reaches it by name.
    let Ok(userland) = super::super::fhs::resolve_userland(&nix, &layout, &base_ref, &base_ref)
    else {
        skip_unreachable!("skipping: base userland provisioning failed (cache or channel drift)");
        return;
    };

    let project = TmpDir::new();
    let proj = project.path().canonicalize().unwrap();
    let id = super::project_runtime_id(&proj).expect("project id");
    let store = super::super::projectstore::prepare(&nix_store, &layout, &id, &userland.base_roots)
        .expect("seed the per-project store");

    // The agent's commands: self-equip jq, then prove it installed and runs. A
    // successful `mise install nix:<pkg>` is itself the proof the plugin is wired —
    // the backend resolved and built — so no separate registration check is needed
    // (a first `mise --version` warms the data dir, as a real session would). The
    // install writes to the cage's `/nix` (the per-project store); its diagnostics
    // go to the test's stderr.
    let script = "set +e\n\
         mise --version > /dev/null 2>&1\n\
         mise install nix:jq 1>&2\n\
         echo \"INSTALL_EXIT=$?\"\n\
         p=$(ls -d /nix/store/*-jq-*/bin/jq 2>/dev/null | head -1)\n\
         if [ -n \"$p\" ]; then echo JQSTORE=present; echo \"JQVER=$(\"$p\" --version 2>/dev/null)\"; \
         else echo JQSTORE=absent; echo JQVER=; fi\n";

    let nix_mount = NixMount {
        src: store.store_dir().join("nix"),
        writable: true,
        on_btrfs: false,
    };
    let overlay = Overlay {
        env: &[],
        binds: &[],
        bin_paths: &[],
        timezone: DEFAULT_ZONE,
        fresh_release_tokens: &[],
        ignored_mise_paths: &[],
    };
    let cmd = vec![
        userland.shell_bin.clone().into_os_string(),
        OsString::from("-c"),
        OsString::from(script),
    ];
    let spec = build_spec(
        data.path(),
        &proj,
        Runtime::ProjectDefault,
        &userland,
        &nix_mount,
        &overlay,
        &[],
        NetPolicy::Shared,
        "",
        &Default::default(),
        crate::sandbox::seccomp::SeccompPolicy::default(),
        &[],
        &Default::default(),
        cmd,
    )
    .expect("build spec");

    // the shared store must not change under an in-cage install (multi-tenant).
    let shared_paths = layout.store_dir().join("nix").join("store");
    let before = fingerprint(&shared_paths);

    let out = super::super::argv::run_bwrap(&bwrap, &spec).expect("spawn bwrap");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "the cage script failed: {}\nstdout:\n{stdout}",
        String::from_utf8_lossy(&out.stderr)
    );
    let marker = |key: &str| {
        stdout
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("missing marker {key} in:\n{stdout}"))
    };

    // jq self-equipped: the install succeeded, which means the embedded `nix:`
    // backend plugin resolved through nixhub and built into the cage's store.
    assert_eq!(
        marker("INSTALL_EXIT"),
        "0",
        "`mise install nix:jq` failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // it landed in the per-project store — the only store bound at `/nix`
    assert_eq!(
        marker("JQSTORE"),
        "present",
        "the installed jq is not in the per-project store"
    );
    // and it actually runs (the binary executes from the self-equipped install)
    assert!(
        marker("JQVER").starts_with("jq"),
        "the self-equipped jq did not run: {}",
        marker("JQVER")
    );
    // the boundary: the shared store is byte-identical — the in-cage install
    // could not reach it
    assert_eq!(
        before,
        fingerprint(&shared_paths),
        "the shared store changed under an in-cage mise install"
    );
}

/// The activation payoff: a tool the agent *activates* in the cage (`mise use -g
/// nix:<pkg>`) is on PATH in a **later, separate** launch — without re-declaring it
/// and without touching the project's repo. Both mechanisms are proven against a
/// fresh spec over the same project: the **shims dir on PATH** for the
/// non-interactive `sbx run` (a bare `jq` resolves *through the shim*), and
/// **`mise activate`** for the interactive shell (bash started with the synthetic
/// `--rcfile` puts the *real* tool bin on PATH). The first cage activates jq into the
/// project's own store and persistent home; the second is a brand-new spec, so "on
/// PATH" can only come from the persisted activation. The shared store stays
/// byte-identical throughout. A network smoke (the activation needs jq actually
/// installed): it skips when the cache is unreachable.
#[test]
fn a_mise_used_tool_is_activated_on_path_in_a_later_launch() {
    let Some((bwrap, nix)) = prerequisites() else {
        skip_incapable!("skipping mise activation smoke: need bwrap, userns, and nix");
        return;
    };
    let Some(nix_store) = crate::store::resolve_nix_store(None) else {
        skip_incapable!("skipping mise activation smoke: need nix-store");
        return;
    };
    if !network_reachable() {
        skip_unreachable!("skipping mise activation smoke: the binary cache is unreachable");
        return;
    }

    let data = TmpDir::new();
    let layout = crate::store::Layout::under(data.path());
    let base_ref = crate::store::LockTarget::global(&layout, None)
        .resolve(&nix, &layout)
        .expect("resolve base channel");
    let Ok(userland) = super::super::fhs::resolve_userland(&nix, &layout, &base_ref, &base_ref)
    else {
        skip_unreachable!("skipping: base userland provisioning failed (cache or channel drift)");
        return;
    };

    let project = TmpDir::new();
    let proj = project.path().canonicalize().unwrap();
    let id = super::project_runtime_id(&proj).expect("project id");

    // Run `script` in a fresh spec over the same project — exactly as a separate
    // launch would: re-seed (a top-up, so jq installed by an earlier cage survives),
    // back `/nix` read-write, build, run. Returns (success, stdout, stderr).
    let run_script = |script: &str| {
        let store =
            super::super::projectstore::prepare(&nix_store, &layout, &id, &userland.base_roots)
                .expect("seed the per-project store");
        let nix_mount = NixMount {
            src: store.store_dir().join("nix"),
            writable: true,
            on_btrfs: false,
        };
        let overlay = Overlay {
            env: &[],
            binds: &[],
            bin_paths: &[],
            timezone: DEFAULT_ZONE,
            fresh_release_tokens: &[],
            ignored_mise_paths: &[],
        };
        let cmd = vec![
            userland.shell_bin.clone().into_os_string(),
            OsString::from("-c"),
            OsString::from(script.to_string()),
        ];
        let spec = build_spec(
            data.path(),
            &proj,
            Runtime::ProjectDefault,
            &userland,
            &nix_mount,
            &overlay,
            &[],
            NetPolicy::Shared,
            "",
            &Default::default(),
            crate::sandbox::seccomp::SeccompPolicy::default(),
            &[],
            &Default::default(),
            cmd,
        )
        .expect("build spec");
        let out = super::super::argv::run_bwrap(&bwrap, &spec).expect("spawn bwrap");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };

    // the shared store must stay byte-identical across the whole sequence
    let shared_paths = layout.store_dir().join("nix").join("store");
    let before = fingerprint(&shared_paths);

    // cage 1: activate tree — writes the global mise config + a shim into the persistent
    // home, builds tree into the project's own store. The tool has to sit OUTSIDE the
    // curated base toolset (`fhs::BASE_TOOLS`): a base tool's own bin is already on PATH,
    // which would muddy the shim-vs-real-bin distinction this test asserts. That rules out
    // `jq`, and now `rg`, `fd` and `yq` as well.
    let (ok, _out, err) = run_script("mise use -g nix:tree 1>&2");
    assert!(ok, "`mise use -g nix:tree` failed:\n{err}");

    // cage 2: a brand-new spec. The shims dir on PATH resolves tree for a direct
    // (non-interactive) command; bash with the synthetic `--rcfile` activates mise,
    // which puts the real tree bin on PATH. The inner interactive bash has no
    // controlling terminal here, so its job-control notice is sent to /dev/null.
    let script = "set +e\n\
         echo \"SHIM_WHICH=$(command -v tree || echo NONE)\"\n\
         echo \"SHIM_VER=$(tree --version 2>/dev/null)\"\n\
         bash --rcfile /opt/sbx/bashrc -i -c 'echo \"ACT_WHICH=$(command -v tree || echo NONE)\"; echo \"ACT_VER=$(tree --version 2>/dev/null)\"' 2>/dev/null\n";
    let (ok, out, err) = run_script(script);
    assert!(ok, "the later launch failed:\n{err}\nstdout:\n{out}");
    let marker = |key: &str| {
        out.lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("missing marker {key} in:\n{out}"))
    };

    // `sbx run` (non-interactive): tree is on PATH via the shims dir, resolved through
    // the shim itself, and runs.
    assert!(
        marker("SHIM_WHICH").ends_with("/shims/tree"),
        "tree did not resolve through the shims dir: {}",
        marker("SHIM_WHICH")
    );
    assert!(
        marker("SHIM_VER").starts_with("tree"),
        "the shimmed tree did not run: {}",
        marker("SHIM_VER")
    );

    // an interactive `sbx run`: mise activate (via `--rcfile`) puts the *real* tool
    // bin on PATH — ending in `/bin/tree`, not `/shims/tree`, so this proves activation
    // engaged rather than the shim doing the work again.
    assert!(
        marker("ACT_WHICH").ends_with("/bin/tree") && marker("ACT_WHICH").contains("/nix/store/"),
        "mise activate did not put the real tree bin on PATH: {}",
        marker("ACT_WHICH")
    );
    assert!(
        marker("ACT_VER").starts_with("tree"),
        "the activated tree did not run: {}",
        marker("ACT_VER")
    );

    // the shared store is byte-identical — every launch only read it
    assert_eq!(
        before,
        fingerprint(&shared_paths),
        "the shared store changed under the activation launches"
    );
}

#[test]
fn a_global_app_cage_puts_both_mise_shims_dirs_on_path_and_splits_the_pool() {
    // The real launch path (build_spec → to_argv → bwrap) must thread the global-app mise
    // split all the way into the cage: mise's primary at the per-project pool, the app-global
    // installs as the read-only fallback, and BOTH shims dirs on PATH. A unit test proves the
    // spec; only a real launch proves the generated argv carries it.
    let Some((bwrap, nix)) = prerequisites() else {
        skip_incapable!("skipping mise-split smoke: need bwrap, userns, and nix");
        return;
    };
    let data = TmpDir::new();
    let layout = crate::store::Layout::under(data.path());
    let nixpkgs = crate::store::LockTarget::global(&layout, None)
        .resolve(&nix, &layout)
        .expect("resolve nixpkgs");
    let Ok(userland) = super::super::fhs::resolve_userland(&nix, &layout, &nixpkgs, &nixpkgs)
    else {
        skip_unreachable!("skipping: base userland provisioning failed (cache or channel drift)");
        return;
    };

    let project = TmpDir::new();
    std::fs::write(project.path().join("README"), b"hi").unwrap();

    let cmd = vec![
        userland.shell_bin.clone().into_os_string(),
        OsString::from("-c"),
        OsString::from(
            "printf 'PATH=%s\\nDATA=%s\\nSHARED=%s\\n' \
             \"$PATH\" \"$MISE_DATA_DIR\" \"$MISE_SHARED_INSTALL_DIRS\"",
        ),
    ];
    let env = [("TERM".to_string(), "dumb".to_string())];
    let overlay = Overlay {
        env: &env,
        binds: &[],
        bin_paths: &[],
        timezone: DEFAULT_ZONE,
        fresh_release_tokens: &[],
        ignored_mise_paths: &[],
    };
    let nix_mount = NixMount {
        src: crate::store::physical_path(&layout, Path::new("/nix")),
        writable: false,
        on_btrfs: false,
    };
    let spec = build_spec(
        data.path(),
        project.path(),
        Runtime::GlobalApp("demo-app"),
        &userland,
        &nix_mount,
        &overlay,
        &[],
        NetPolicy::Shared,
        "",
        &Default::default(),
        crate::sandbox::seccomp::SeccompPolicy::default(),
        &[],
        &Default::default(),
        cmd,
    )
    .expect("build spec");

    let out = super::super::argv::run_bwrap(&bwrap, &spec).expect("spawn bwrap");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "bwrap failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // both shims dirs are on PATH (the per-project primary's and the app-global fallback's)
    assert!(
        stdout.contains(&format!("{MISE_PROJECT_INCAGE}/shims")),
        "per-project shims dir missing from PATH:\n{stdout}"
    );
    assert!(
        stdout.contains(&format!("{SANDBOX_HOME}/{MISE_SHIMS_REL}")),
        "app-global shims dir missing from PATH:\n{stdout}"
    );
    // mise's primary is the per-project pool, with the app-global installs as the fallback
    assert!(
        stdout.contains(&format!("DATA={MISE_PROJECT_INCAGE}")),
        "MISE_DATA_DIR is not the per-project pool:\n{stdout}"
    );
    assert!(
        stdout.contains(&format!("SHARED={SANDBOX_HOME}/{MISE_DATA_REL}/installs")),
        "MISE_SHARED_INSTALL_DIRS is not the app-global installs:\n{stdout}"
    );
}

/// A declared distribution really is the cage's root filesystem: the image's own userland answers,
/// its loader and its shell are the ones in use, and everything sbx mounts still lands on top.
///
/// Only a launch can show this. The unit tests pin the plan, but the plan is an argv, and what
/// bubblewrap makes of it — layer 0 first, a read-only root that still accepts every later mount,
/// a tmpfs where the image had nothing — is a property of the kernel, not of the vector.
#[test]
fn a_declared_distribution_is_the_cage_root_and_every_mount_still_lands() {
    let Some((bwrap, nix)) = prerequisites() else {
        skip_incapable!("skipping distribution smoke: need bwrap, userns, and nix");
        return;
    };

    let data = TmpDir::new();
    let layout = crate::store::Layout::under(data.path());
    let nixpkgs = crate::store::LockTarget::global(&layout, None)
        .resolve(&nix, &layout)
        .expect("resolve nixpkgs");
    let Ok(mut userland) = super::super::fhs::resolve_userland(&nix, &layout, &nixpkgs, &nixpkgs)
    else {
        skip_unreachable!("skipping: base userland provisioning failed (cache or channel drift)");
        return;
    };

    let locator = "oci:docker.io/library/debian:10-slim";
    let lock = data.path().join("distro.lock");
    match crate::sandbox::distro::store::provision(&layout, locator, &lock, "smoke000", None, None)
    {
        Ok(root) => userland.distro = Some(root),
        Err(e) => {
            skip_unreachable!("skipping distribution smoke: {e}");
            return;
        }
    }

    let project = TmpDir::new();
    std::fs::write(project.path().join("README"), b"hi").unwrap();

    let cmd = vec![
        std::ffi::OsString::from("/bin/sh"),
        OsString::from("-c"),
        OsString::from(
            "echo ID=$(. /etc/os-release; echo $ID$VERSION_ID); \
             echo ENV=$(readlink -f /usr/bin/env); \
             echo LD=$(readlink -f /lib64/ld-linux-x86-64.so.2); \
             echo NIX=$(ls /nix | tr '\\n' ','); \
             echo HOME_OK=$(touch $HOME/w && echo yes); \
             echo PROJ=$(ls); \
             echo GREP=$(command -v grep); \
             echo APT=$(command -v apt-get); \
             echo ROOT_RO=$(touch /etc/intruder >/dev/null 2>&1 && echo writable || echo readonly)",
        ),
    ];
    let env = [("TERM".to_string(), "dumb".to_string())];
    let overlay = Overlay {
        env: &env,
        binds: &[],
        bin_paths: &[],
        timezone: DEFAULT_ZONE,
        fresh_release_tokens: &[],
        ignored_mise_paths: &[],
    };
    let nix_mount = NixMount {
        src: crate::store::physical_path(&layout, Path::new("/nix")),
        writable: false,
        on_btrfs: false,
    };
    let spec = build_spec(
        data.path(),
        project.path(),
        Runtime::ProjectDefault,
        &userland,
        &nix_mount,
        &overlay,
        &[],
        NetPolicy::Shared,
        "",
        &Default::default(),
        crate::sandbox::seccomp::SeccompPolicy::default(),
        &[],
        &Default::default(),
        cmd,
    )
    .expect("build spec");

    let out = super::super::argv::run_bwrap(&bwrap, &spec).expect("spawn bwrap");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "bwrap failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Layer 0 landed, and it is what `/` is: the image's own release file answered, which no
    // hermetic cage carries at all.
    assert!(
        stdout.contains("ID=debian10"),
        "not the image's root:\n{stdout}"
    );
    // The paths a distribution supplies are the distribution's. `env` resolving into `/nix` would
    // mean sbx's symlink had shadowed the image's, and the loader is the sharper of the two: a
    // foreign binary going through the nix-ld shim is exactly the ABI skew a declared image avoids.
    assert!(
        stdout
            .lines()
            .any(|l| l.starts_with("ENV=") && !l.contains("/nix/store")),
        "/usr/bin/env is not the image's:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|l| l.starts_with("LD=") && !l.contains("/nix/store")),
        "the loader is not the image's:\n{stdout}"
    );
    // And everything sbx mounts still landed on top: the store at a mountpoint the image had no
    // idea about, the writable home inside a tmpfs where the image had an empty directory, and the
    // project at its own absolute path.
    assert!(
        stdout.contains("NIX=store,"),
        "the store did not mount:\n{stdout}"
    );
    assert!(
        stdout.contains("HOME_OK=yes"),
        "the home is not writable:\n{stdout}"
    );
    assert!(
        stdout.contains("README"),
        "the project is not visible:\n{stdout}"
    );
    // The distribution's own tools are the ones a build finds: its `grep` ahead of the base
    // userland's, and its package manager reachable at all, which a hermetic PATH never was.
    assert!(
        stdout
            .lines()
            .any(|l| l.starts_with("GREP=") && !l.contains("/nix/store")),
        "the base userland's grep shadows the distribution's:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|l| l.starts_with("APT=/usr/bin/apt-get")),
        "the distribution's own tools are not on PATH:\n{stdout}"
    );
    // The root itself is not: one cage must not be able to alter the tree every other cage on the
    // same image reads.
    assert!(
        stdout.contains("ROOT_RO=readonly"),
        "the root is writable:\n{stdout}"
    );
}
