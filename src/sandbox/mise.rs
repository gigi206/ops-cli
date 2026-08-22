//! Provisioning and driving the mise engine.
//!
//! A trusted project may declare its tools (and environment) in a mise file. sbx
//! uses mise as a *front-end*: it drives mise as a subprocess to map those into the
//! sandbox. mise itself is provisioned via nix into sbx's own user-owned store —
//! never the host's mise — and run from that store, so the engine is reproducible
//! and independent of whatever the host happens to have installed.
//!
//! Two properties are built in here, where the driver is born:
//!
//! - **It tracks the global channel, not a project's pin.** mise runs in its own
//!   relocated-store view (its own `/nix`), so the one-channel rule that forces a
//!   sandbox's base and tools onto a single glibc does not reach it: the engine is
//!   not loaded next to the project's foreign binaries. Keying mise to the global
//!   channel gives one stable shared engine for every project rather than a fresh
//!   copy per distinctly-pinned project, and a project pinned to an old channel
//!   still gets a current engine to drive its provisioning.
//!
//! - **It never mutates the host.** `HOME` and every `MISE_*_DIR` are redirected
//!   into sbx's data directory, and the run is wrapped in a minimal bubblewrap that
//!   exposes only sbx's store (read-only) and that private home (read-write) — so
//!   mise reads and writes nothing under the user's real `~/.config/mise` or
//!   `~/.local/share/mise`.
//!
//! Running a relocated-store binary: a nix-built binary hard-codes its interpreter
//! and library paths under `/nix/store/…`, which on the host live under sbx's store
//! root instead. Binding sbx's store at `/nix` inside a mount namespace makes those
//! logical paths resolve — the same mechanism the sandbox uses for its userland,
//! applied to a tool sbx runs itself.

use crate::store::{self, Layout};
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The nixpkgs attribute providing the mise engine.
const MISE_ATTR: &str = "mise";

/// mise's executable, relative to its store output — also the marker that selects
/// the bin-bearing output of the realised derivation.
const MISE_BIN: &str = "bin/mise";

/// In-sandbox mount point for sbx's private mise home. `HOME` and every
/// `MISE_*_DIR` live under it, so mise's reads and writes are confined to the one
/// directory sbx binds read-write — never the user's real mise state.
const MISE_HOME: &str = "/mise";

/// In-sandbox directory holding the project's mise file(s) when mise reads a
/// trusted project. Only the *authorized* files are bound here (one read-only bind
/// each), and mise is run from here — so its config discovery, which walks up from
/// the working directory, finds exactly that set and nothing outside it (a
/// parent-directory config, the user-global config, an env-specific `mise.<env>.toml`):
/// the mount layout is what keeps mise's inputs equal to the trust-hashed set.
const MISE_PROJECT: &str = "/project";

/// One project mise file as exposed to mise: a host source (the materialized,
/// already-hashed bytes) bound read-only at an in-sandbox destination under
/// [`MISE_PROJECT`].
struct ProjectBind {
    /// Host path of the staged file to bind read-only.
    src: PathBuf,
    /// In-sandbox path it appears at (`/project/<filename>`), also what mise
    /// attributes as the `source` of the variables it sets.
    dest: PathBuf,
}

/// Provision the mise engine into sbx's store against `engine_ref` (the **dedicated
/// engine channel** — see the module note on why mise does not follow a project pin, and
/// [`crate::store::LockTarget::engine`] on why it has its own lock) and return its logical
/// store **root** (`/nix/store/…`, which resolves once the store is bound at `/nix`). The
/// output is rooted per engine revision under `<data>/gcroots/mise/<rev>/`, so every
/// project on that engine revision shares one engine and a rolled engine roots its own
/// beside it. Callers derive the `mise` binary with [`bin`] (to exec) or its `bin`
/// directory (for `PATH`) from this root.
pub(crate) fn provision_engine(
    nix: &Path,
    layout: &Layout,
    engine_ref: &str,
) -> io::Result<PathBuf> {
    let gcroot = layout
        .data_dir()
        .join("gcroots")
        .join("mise")
        .join(store::revision_of(engine_ref))
        .join(MISE_ATTR);
    store::provision(nix, layout, &gcroot, engine_ref, MISE_ATTR, MISE_BIN)
}

/// The `mise` binary within an engine store root provisioned by [`provision_engine`].
pub(crate) fn bin(root: &Path) -> PathBuf {
    root.join(MISE_BIN)
}

/// A bubblewrap command that runs the provisioned `mise_bin` with `args`, hermetic
/// and offline: sbx's store read-only at `/nix`, a private writable home, an
/// isolated network namespace, and an environment cleared and rebuilt from exactly
/// the keys mise needs. `project_binds` exposes the authorized project mise files
/// (empty for a config-free invocation such as `--version`). Ensures the private
/// home exists (owner-only) before returning the command.
fn command(
    bwrap: &Path,
    layout: &Layout,
    mise_bin: &Path,
    project_binds: &[ProjectBind],
    args: &[OsString],
) -> io::Result<(Command, Vec<std::fs::File>)> {
    let home_src = ensure_home(layout)?;
    let store_nix = store::physical_path(layout, Path::new("/nix"));
    let mut cmd = Command::new(bwrap);
    // The mandatory syscall denylist, as every other cage sbx builds carries it. This one is
    // assembled by hand rather than through the `SandboxSpec` keystone, which is how it came to have
    // the namespaces and the dropped capabilities but not the filters — and this is the cage that
    // runs tool installation, the part of provisioning most shaped by what a project asks for.
    // Nothing relaxes it: `[seccomp] allow` is a launch's grant to its own cage, not to a helper.
    let seccomp = super::seccomp::memfds(&super::seccomp::SeccompPolicy::default())?;
    let mut argv = super::seccomp::argv_prefix(&seccomp);
    argv.extend(bwrap_argv(
        &store_nix,
        &home_src,
        project_binds,
        mise_bin,
        args,
    ));
    cmd.args(argv);
    // Returned alongside, never dropped here: the descriptors are not close-on-exec and bwrap reads
    // them at the exec, so closing one before the caller runs the command turns into `Invalid fd`.
    Ok((cmd, seccomp))
}

/// Resolve a trusted project's mise `[env]` into sandbox environment variables.
///
/// Binds only the authorized, already-hashed mise files read-only, runs `mise env
/// --json-extended` from that mount, and keeps a variable only when mise attributes
/// it to one of those files. A variable mise merely echoes (notably `PATH`) carries
/// no such source and is dropped, so the sandbox's own `PATH` is never disturbed;
/// the source check also means a value pulled from an unhashed file (say via a
/// dotenv directive) could never ride along.
///
/// `files` are the validated `(filename, bytes)` captured at config load; they are
/// materialized owner-only into `stage_dir` — which must lie outside every writable
/// mount — so mise reads exactly those bytes and cannot rewrite them through a
/// writable alias.
pub(crate) fn resolve_env(
    bwrap: &Path,
    layout: &Layout,
    mise_bin: &Path,
    files: &[(String, Vec<u8>)],
    stage_dir: &Path,
) -> io::Result<Vec<(String, String)>> {
    let binds = stage_files(stage_dir, files)?;
    let args = [OsString::from("env"), OsString::from("--json-extended")];
    let (mut cmd, _seccomp) = command(bwrap, layout, mise_bin, &binds, &args)?;
    let out = cmd.output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "mise env failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let value: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| io::Error::other(format!("parsing mise env output: {e}")))?;
    let authorized: Vec<&Path> = binds.iter().map(|b| b.dest.as_path()).collect();
    Ok(project_env_from_json(&value, &authorized))
}

/// Materialize each validated mise file into `stage_dir` (created owner-only) and
/// return the read-only binds that expose them under [`MISE_PROJECT`]. Writing the
/// already-hashed bytes here — outside any writable mount — is what lets mise read
/// the authorized content without a path back to the live, possibly-edited file.
fn stage_files(stage_dir: &Path, files: &[(String, Vec<u8>)]) -> io::Result<Vec<ProjectBind>> {
    use std::fs::{DirBuilder, OpenOptions};
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(stage_dir)?;
    std::fs::set_permissions(stage_dir, std::fs::Permissions::from_mode(0o700))?;

    let mut binds = Vec::with_capacity(files.len());
    for (name, bytes) in files {
        let src = stage_dir.join(name);
        // Write owner-only to a temp sibling, then rename into place. Two concurrent
        // launches staging the same project then race to a whole-file rename, never a
        // half-truncated read (the bytes are identical, so this only rules out a torn
        // mid-write read that would spuriously fail the launch). Owner-only from
        // creation so a loose umask never opens a window.
        let tmp = stage_dir.join(format!("{name}.{}.tmp", std::process::id()));
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?
            .write_all(bytes)?;
        std::fs::rename(&tmp, &src)?;
        binds.push(ProjectBind {
            src,
            dest: Path::new(MISE_PROJECT).join(name),
        });
    }
    Ok(binds)
}

/// Extract a project's `[env]` from mise's `--json-extended` output: an object of
/// `name -> { "source": <file>, "value": <string> }`. A variable is kept only when
/// it carries a `source` within `authorized` — exactly the bound mise files. mise
/// emits some variables it merely computes (notably `PATH`) with no `source`; those,
/// and any whose source is not authorized, are dropped. Pure, so the filter is
/// testable without running mise.
fn project_env_from_json(value: &serde_json::Value, authorized: &[&Path]) -> Vec<(String, String)> {
    let Some(obj) = value.as_object() else {
        return Vec::new();
    };
    obj.iter()
        .filter_map(|(name, entry)| {
            let source = entry.get("source")?.as_str()?;
            if !authorized.contains(&Path::new(source)) {
                return None;
            }
            let value = entry.get("value")?.as_str()?;
            Some((name.clone(), value.to_string()))
        })
        .collect()
}

/// The host directory backing sbx's private mise home, under the data directory.
fn home_dir(layout: &Layout) -> PathBuf {
    layout.data_dir().join("mise")
}

/// Create the private mise home owner-only and return it. Created from the start
/// with `0o700` so a loose umask never leaves a world-readable window, and tightened
/// if it already existed with looser bits — the same fail-closed stance the store
/// takes.
fn ensure_home(layout: &Layout) -> io::Result<PathBuf> {
    use std::fs::{DirBuilder, Permissions};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let dir = home_dir(layout);
    DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
    std::fs::set_permissions(&dir, Permissions::from_mode(0o700))?;
    Ok(dir)
}

/// Build the bubblewrap argument list that runs mise hermetically. Pure: the whole
/// invocation is one auditable argv, like the sandbox's own. It binds sbx's store
/// read-only (so the relocated binary's logical paths resolve), binds the private
/// home read-write (the **only** writable mount), isolates every namespace
/// including the network, clears the environment, and rebuilds it from keys that
/// all point inside the private home — so the run cannot read or write the user's
/// real mise state, reach the network, or inherit a host variable.
///
/// `project_binds` exposes the authorized project mise files (read-only) under
/// [`MISE_PROJECT`], from where mise is then run so its discovery finds exactly that
/// set; their in-sandbox paths are also named in `MISE_TRUSTED_CONFIG_PATHS` so mise
/// loads them without a trust prompt. Empty for a config-free invocation, which is
/// run from the private home instead and trusts nothing.
fn bwrap_argv(
    store_nix: &Path,
    home_src: &Path,
    project_binds: &[ProjectBind],
    mise_bin: &Path,
    args: &[OsString],
) -> Vec<OsString> {
    let lit = |s: &str| OsString::from(s);
    let path = |p: &Path| p.as_os_str().to_os_string();
    let home = |sub: &str| OsString::from(format!("{MISE_HOME}{sub}"));

    let mut a: Vec<OsString> = Vec::new();

    // Isolate every namespace, the network included — provisioning the engine and
    // running it offline needs no connectivity (a later, online step toggles this).
    for ns in [
        "--unshare-user",
        "--unshare-ipc",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-uts",
        "--unshare-cgroup",
    ] {
        a.push(lit(ns));
    }
    // Start from a clean environment and die with the launcher, so no host variable
    // leaks into mise and no helper outlives sbx.
    a.push(lit("--clearenv"));
    a.push(lit("--die-with-parent"));
    // The same unconditional capability drop the main cage's `to_argv` applies (bwrap then also
    // sets no_new_privs itself). This argv is hand-built — mise runs before a `SandboxSpec` exists —
    // so it is set explicitly here rather than inherited; keep it in step with `to_argv`'s baseline.
    a.push(lit("--cap-drop"));
    a.push(lit("ALL"));

    // The store backs the relocated binary; the private home is the sole writable
    // surface. `/proc`, `/dev`, and a `/tmp` tmpfs round out a minimal usable root.
    a.push(lit("--ro-bind"));
    a.push(path(store_nix));
    a.push(lit("/nix"));
    a.push(lit("--proc"));
    a.push(lit("/proc"));
    a.push(lit("--dev"));
    a.push(lit("/dev"));
    a.push(lit("--tmpfs"));
    a.push(lit("/tmp"));
    a.push(lit("--bind"));
    a.push(path(home_src));
    a.push(lit(MISE_HOME));

    // The authorized project mise files, each read-only under `/project` — the only
    // configs mise can see, so its discovery cannot reach an unhashed sibling.
    for b in project_binds {
        a.push(lit("--ro-bind"));
        a.push(path(&b.src));
        a.push(path(&b.dest));
    }

    // Confine every mise directory to the private home, auto-confirm so a prompt
    // never blocks a non-interactive run, and force offline so mise never reaches
    // the network for a self-version check.
    for (key, val) in [
        ("HOME", home("")),
        ("MISE_DATA_DIR", home("/data")),
        ("MISE_CACHE_DIR", home("/cache")),
        ("MISE_STATE_DIR", home("/state")),
        ("MISE_CONFIG_DIR", home("/config")),
        ("MISE_YES", lit("1")),
        ("MISE_OFFLINE", lit("1")),
    ] {
        a.push(lit("--setenv"));
        a.push(lit(key));
        a.push(val);
    }
    // Name the bound files as trusted, so mise loads them without prompting and
    // never treats one as an untrusted config to ignore.
    if !project_binds.is_empty() {
        a.push(lit("--setenv"));
        a.push(lit("MISE_TRUSTED_CONFIG_PATHS"));
        a.push(join_paths(project_binds.iter().map(|b| b.dest.as_path())));
    }

    // Pin the working directory: into the project mount when reading a config (so
    // discovery starts there), else the private home. The launching cwd does not
    // exist inside this minimal root, and leaving it unset would make mise's cwd
    // non-deterministic.
    a.push(lit("--chdir"));
    a.push(lit(if project_binds.is_empty() {
        MISE_HOME
    } else {
        MISE_PROJECT
    }));

    // The command after `--`, so mise's own flags are never parsed by bwrap.
    a.push(lit("--"));
    a.push(path(mise_bin));
    a.extend(args.iter().cloned());
    a
}

/// Join in-sandbox paths into a single `:`-separated `OsString`, for
/// `MISE_TRUSTED_CONFIG_PATHS`. The paths are sbx-constructed under [`MISE_PROJECT`]
/// (ASCII), so a colon separator is unambiguous.
fn join_paths<'a>(paths: impl Iterator<Item = &'a Path>) -> OsString {
    let mut out = OsString::new();
    for (i, p) in paths.enumerate() {
        if i > 0 {
            out.push(":");
        }
        out.push(p);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;

    /// Positions of `needle` in the argv, for ordering and adjacency asserts.
    fn index_of(argv: &[OsString], needle: &str) -> Option<usize> {
        argv.iter().position(|a| a == needle)
    }

    /// The value bwrap is told to set for `key` (the token after its `--setenv key`).
    fn setenv<'a>(argv: &'a [OsString], key: &str) -> Option<&'a OsString> {
        argv.windows(3)
            .find(|w| w[0] == "--setenv" && w[1] == key)
            .map(|w| &w[2])
    }

    /// The cage carries the mandatory syscall denylist, like every other cage sbx builds.
    ///
    /// It is assembled here by hand rather than through the `SandboxSpec` keystone, which is how it
    /// came to have the namespaces and the dropped capabilities but not the filters. Asserted on
    /// what [`command`] hands to bwrap, since the filters are descriptors prefixed at that step and
    /// are not part of [`bwrap_argv`] at all.
    #[test]
    fn the_cage_carries_the_mandatory_seccomp_denylist() {
        let dir = crate::testutil::TmpDir::new();
        let layout = Layout::under(&dir.path().join("sbx"));
        let (cmd, keep_open) = command(
            Path::new("/nix/store/abc-bwrap/bin/bwrap"),
            &layout,
            Path::new("/nix/store/abc-mise/bin/mise"),
            &[],
            &[OsString::from("--version")],
        )
        .expect("a cage command");

        let argv: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let fds: Vec<usize> = argv
            .iter()
            .enumerate()
            .filter(|(_, a)| *a == "--add-seccomp-fd")
            .map(|(i, _)| i)
            .collect();
        assert_eq!(fds, vec![0, 2], "{argv:?}");
        assert_eq!(
            keep_open.len(),
            2,
            "each filter's descriptor is held open until bwrap has read it"
        );
        // ...and the hardening this cage already had is still behind them.
        for flag in [
            "--unshare-user",
            "--unshare-net",
            "--cap-drop",
            "--clearenv",
        ] {
            assert!(argv.iter().any(|a| a == flag), "missing {flag}: {argv:?}");
        }
    }

    #[test]
    fn the_argv_is_hermetic_offline_and_writes_only_to_the_private_home() {
        let argv = bwrap_argv(
            Path::new("/data/store/nix"),
            Path::new("/data/mise"),
            &[],
            Path::new("/nix/store/abc-mise/bin/mise"),
            &[OsString::from("--version")],
        );

        // every namespace is isolated, including the network (offline by construction)
        for ns in [
            "--unshare-user",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-uts",
            "--unshare-cgroup",
        ] {
            assert!(index_of(&argv, ns).is_some(), "missing {ns}: {argv:?}");
        }
        // the environment is cleared before anything is set into it
        let clear = index_of(&argv, "--clearenv").expect("--clearenv present");
        let first_set = index_of(&argv, "--setenv").expect("--setenv present");
        assert!(clear < first_set, "clearenv must precede setenv: {argv:?}");

        // the store is read-only; the private home is the ONLY writable bind — the
        // structural guarantee that mise cannot mutate the host
        let ro = index_of(&argv, "--ro-bind").expect("--ro-bind present");
        assert_eq!(argv[ro + 1], OsString::from("/data/store/nix"));
        assert_eq!(argv[ro + 2], OsString::from("/nix"));
        let writable: Vec<_> = argv
            .windows(3)
            .filter(|w| w[0] == "--bind")
            .map(|w| (w[1].clone(), w[2].clone()))
            .collect();
        assert_eq!(
            writable,
            vec![(OsString::from("/data/mise"), OsString::from("/mise"))],
            "the private mise home must be the only writable mount"
        );

        // every mise directory is confined under that private home, and the run is
        // non-interactive and offline
        assert_eq!(setenv(&argv, "HOME"), Some(&OsString::from("/mise")));
        for (key, val) in [
            ("MISE_DATA_DIR", "/mise/data"),
            ("MISE_CACHE_DIR", "/mise/cache"),
            ("MISE_STATE_DIR", "/mise/state"),
            ("MISE_CONFIG_DIR", "/mise/config"),
        ] {
            assert_eq!(setenv(&argv, key), Some(&OsString::from(val)), "{key}");
        }
        assert_eq!(setenv(&argv, "MISE_YES"), Some(&OsString::from("1")));
        assert_eq!(setenv(&argv, "MISE_OFFLINE"), Some(&OsString::from("1")));
        // a config-free invocation trusts nothing — no project file is exposed
        assert_eq!(setenv(&argv, "MISE_TRUSTED_CONFIG_PATHS"), None);

        // the working directory is pinned to the private home (deterministic, and
        // not the launching cwd that does not exist inside this root), immediately
        // before the command
        let dashes = index_of(&argv, "--").expect("-- present");
        assert_eq!(argv[dashes - 2], OsString::from("--chdir"));
        assert_eq!(argv[dashes - 1], OsString::from("/mise"));

        // the command is last, after `--`, so mise's flags are not parsed by bwrap
        assert_eq!(
            argv[dashes + 1],
            OsString::from("/nix/store/abc-mise/bin/mise")
        );
        assert_eq!(argv[dashes + 2], OsString::from("--version"));
    }

    #[test]
    fn ensure_home_creates_the_private_home_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));

        let home = ensure_home(&layout).unwrap();
        assert_eq!(home, base.join("sbx/mise"));
        let mode = std::fs::metadata(&home).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "the private mise home must be owner-only");
        // idempotent
        ensure_home(&layout).unwrap();
    }

    #[test]
    fn the_argv_binds_only_authorized_project_files_and_trusts_them() {
        let binds = vec![
            ProjectBind {
                src: PathBuf::from("/stage/.mise.toml"),
                dest: PathBuf::from("/project/.mise.toml"),
            },
            ProjectBind {
                src: PathBuf::from("/stage/mise.toml"),
                dest: PathBuf::from("/project/mise.toml"),
            },
        ];
        let argv = bwrap_argv(
            Path::new("/data/store/nix"),
            Path::new("/data/mise"),
            &binds,
            Path::new("/nix/store/abc-mise/bin/mise"),
            &[OsString::from("env"), OsString::from("--json-extended")],
        );

        // each authorized file is bound read-only at its /project path — and these
        // are the only configs mise can see
        let ro_project: Vec<(OsString, OsString)> = argv
            .windows(3)
            .filter(|w| w[0] == "--ro-bind" && w[2].to_string_lossy().starts_with("/project/"))
            .map(|w| (w[1].clone(), w[2].clone()))
            .collect();
        assert_eq!(
            ro_project,
            vec![
                (
                    OsString::from("/stage/.mise.toml"),
                    OsString::from("/project/.mise.toml")
                ),
                (
                    OsString::from("/stage/mise.toml"),
                    OsString::from("/project/mise.toml")
                ),
            ]
        );
        // they are read-only; the private home is still the only writable mount
        let writable: Vec<_> = argv
            .windows(3)
            .filter(|w| w[0] == "--bind")
            .map(|w| w[2].clone())
            .collect();
        assert_eq!(writable, vec![OsString::from("/mise")]);

        // named trusted (colon-joined) so mise loads them without prompting
        assert_eq!(
            setenv(&argv, "MISE_TRUSTED_CONFIG_PATHS"),
            Some(&OsString::from("/project/.mise.toml:/project/mise.toml"))
        );

        // mise runs from the project mount (discovery starts there), then the command
        let dashes = index_of(&argv, "--").expect("-- present");
        assert_eq!(argv[dashes - 2], OsString::from("--chdir"));
        assert_eq!(argv[dashes - 1], OsString::from("/project"));
        assert_eq!(
            argv[dashes + 1],
            OsString::from("/nix/store/abc-mise/bin/mise")
        );
        assert_eq!(argv[dashes + 2], OsString::from("env"));
        assert_eq!(argv[dashes + 3], OsString::from("--json-extended"));
    }

    #[test]
    fn project_env_from_json_keeps_only_authorized_sourced_vars() {
        // FOO/GREETING come from an authorized file; PATH is echoed by mise with no
        // source; SNUCK claims an unauthorized source. Only the first two survive.
        let json = serde_json::json!({
            "FOO": { "source": "/project/.mise.toml", "value": "bar" },
            "GREETING": { "source": "/project/.mise.toml", "value": "hello world" },
            "PATH": { "value": "/usr/bin:/bin" },
            "SNUCK": { "source": "/project/.env", "value": "nope" },
        });
        let authorized = [
            Path::new("/project/.mise.toml"),
            Path::new("/project/mise.toml"),
        ];
        let mut env = project_env_from_json(&json, &authorized);
        env.sort();
        assert_eq!(
            env,
            vec![
                ("FOO".to_string(), "bar".to_string()),
                ("GREETING".to_string(), "hello world".to_string()),
            ]
        );
    }

    #[test]
    fn stage_files_writes_owner_only_bytes_and_binds_under_project() {
        use std::os::unix::fs::PermissionsExt;
        let base = TmpDir::new();
        let stage = base.join("mise-config");
        let body = b"[env]\nFOO = \"bar\"\n".to_vec();
        let files = vec![(".mise.toml".to_string(), body.clone())];

        let binds = stage_files(&stage, &files).unwrap();
        assert_eq!(binds.len(), 1);
        assert_eq!(binds[0].dest, PathBuf::from("/project/.mise.toml"));
        assert_eq!(binds[0].src, stage.join(".mise.toml"));
        // exactly the hashed bytes are written, owner-only, in an owner-only dir
        assert_eq!(std::fs::read(&binds[0].src).unwrap(), body);
        assert_eq!(
            std::fs::metadata(&binds[0].src)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&stage).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}

/// Provisioning and running real mise needs a real nix, a real bwrap, and a
/// capability-bearing user namespace, so this is an integration check: it skips
/// (does not fail) where any is absent, and otherwise proves mise runs from sbx's
/// own store, hermetically, writing only into sbx's data directory.
#[cfg(test)]
mod run_tests {
    use super::*;
    use crate::testutil::TmpDir;

    #[test]
    fn runs_mise_from_sbx_store_hermetically_and_writes_only_into_sbx_data() {
        let Some(nix) = store::resolve_nix(None) else {
            skip_incapable!("skipping mise run: no nix on PATH");
            return;
        };
        let Some(bwrap) = crate::pathfind::find_on_path("bwrap") else {
            skip_incapable!("skipping mise run: no bwrap on PATH");
            return;
        };
        if !matches!(crate::probe_userns(), crate::Userns::Ok) {
            skip_incapable!("skipping mise run: no capability-bearing user namespace");
            return;
        }

        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));
        let nixpkgs = store::LockTarget::global(&layout, None)
            .resolve(&nix, &layout)
            .expect("resolve the global channel");

        // the engine is provisioned into sbx's own store, never the host's mise
        let mise_bin = bin(&provision_engine(&nix, &layout, &nixpkgs).expect("provision mise"));
        assert!(
            mise_bin.starts_with("/nix/store") && mise_bin.ends_with("bin/mise"),
            "not a logical mise path: {}",
            mise_bin.display()
        );
        assert!(
            store::physical_path(&layout, &mise_bin).exists(),
            "mise missing from sbx's store: {}",
            mise_bin.display()
        );
        // it is rooted per channel revision, so a store GC cannot collect it
        let rev_root = layout
            .data_dir()
            .join("gcroots/mise")
            .join(store::revision_of(&nixpkgs));
        assert!(rev_root.is_dir(), "per-revision mise gcroot missing");

        // run `mise --version` from sbx's store, hermetic and offline
        let (mut cmd, _seccomp) = command(
            &bwrap,
            &layout,
            &mise_bin,
            &[],
            &[OsString::from("--version")],
        )
        .expect("build the mise command");
        let out = cmd.output().expect("run mise");
        assert!(
            out.status.success(),
            "mise --version failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        // mise prints its version (e.g. `2026.6.0 linux-x64 …`); a leading digit is
        // enough to prove the real engine ran without pinning an exact version
        let version = String::from_utf8_lossy(&out.stdout);
        assert!(
            version
                .trim()
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit()),
            "unexpected mise --version output: {version:?}"
        );
        // the driver runs clean: offline (no network self-check warning) and with a
        // valid working directory (no bubblewrap cwd warning)
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr.contains("VERSION attempt"),
            "mise reached the network despite the offline driver: {stderr}"
        );
        assert!(
            !stderr.contains("current working directory"),
            "the driver left the working directory unpinned: {stderr}"
        );

        // host-write hygiene: mise's writes landed in sbx's private home, and that
        // home is the only writable mount (asserted structurally above), so nothing
        // touched the user's real mise state
        assert!(
            home_dir(&layout).join("data").exists() || home_dir(&layout).join("cache").exists(),
            "mise wrote nothing into sbx's private home"
        );
    }

    #[test]
    fn resolve_env_maps_authorized_env_and_ignores_unauthorized_siblings() {
        let Some(nix) = store::resolve_nix(None) else {
            skip_incapable!("skipping mise resolve_env: no nix on PATH");
            return;
        };
        let Some(bwrap) = crate::pathfind::find_on_path("bwrap") else {
            skip_incapable!("skipping mise resolve_env: no bwrap on PATH");
            return;
        };
        if !matches!(crate::probe_userns(), crate::Userns::Ok) {
            skip_incapable!("skipping mise resolve_env: no capability-bearing user namespace");
            return;
        }

        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));
        let nixpkgs = store::LockTarget::global(&layout, None)
            .resolve(&nix, &layout)
            .expect("resolve the global channel");
        let mise_bin = bin(&provision_engine(&nix, &layout, &nixpkgs).expect("provision mise"));

        // a project whose authorized same-directory files declare `[env]`: the
        // canonical `.mise.toml` and the local override `mise.local.toml` (both in the
        // trust-hashed set). Beside them, a PARENT-directory `mise.toml` — which mise
        // discovers by walking up from the working directory, but which the trust gate
        // never hashes, anchored as it is on the project root. So it must never reach
        // resolution: the project is nested under a parent that carries one.
        let parent = TmpDir::new();
        let proj = parent.join("project");
        std::fs::create_dir(&proj).unwrap();
        std::fs::write(proj.join(".sbx.toml"), b"").unwrap();
        std::fs::write(
            proj.join(".mise.toml"),
            b"[env]\nFOO = \"bar\"\nGREETING = \"hello world\"\n",
        )
        .unwrap();
        std::fs::write(
            proj.join("mise.local.toml"),
            b"[env]\nLOCAL_VAR = \"from-local\"\n",
        )
        .unwrap();
        std::fs::write(parent.join("mise.toml"), b"[env]\nSNUCK = \"nope\"\n").unwrap();

        // the trust-hashed set is exactly the same-directory files — it includes the
        // local override (now honored) and excludes the parent-directory config
        let files = crate::trust::mise_inputs_for(&proj.join(".sbx.toml"))
            .expect("read the authorized mise files");
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            names.contains(&"mise.local.toml") && names.contains(&".mise.toml"),
            "the local override and canonical config must both be authorized: {names:?}"
        );

        let stage = layout.data_dir().join("mise-stage");
        let env = resolve_env(&bwrap, &layout, &mise_bin, &files, &stage)
            .expect("resolve mise [env] (config bound read-only)");

        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        // happy path: the authorized `[env]` entries are mapped, from both the
        // canonical config and the now-honored local override...
        assert_eq!(get("FOO"), Some("bar"));
        assert_eq!(get("GREETING"), Some("hello world"));
        assert_eq!(
            get("LOCAL_VAR"),
            Some("from-local"),
            "the local override is in the widened set, so its [env] is mapped"
        );
        // ...the parent-directory config's var never reached resolution (the mount
        // layout binds only the project's own files, not what mise would walk up to)...
        assert_eq!(
            get("SNUCK"),
            None,
            "a parent-directory mise file must not contribute env"
        );
        // ...and mise's echoed PATH is dropped (it carries no source), so the
        // sandbox's own PATH is left intact.
        assert_eq!(get("PATH"), None, "mise's echoed PATH must not be mapped");
    }
}
