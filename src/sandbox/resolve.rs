//! The shared **resolve-command** machinery: run a trusted profile's `resolve = [argv]` command in a
//! hermetic cage and return the download URL it prints, for a prebuilt-binary backend whose upstream
//! URL is version-stamped with no stable `latest` alias.
//!
//! A `tarball:resolve` / `deb:resolve` package embeds a command (e.g. a `curl … | grep … | sed …`
//! pipeline over a vendor version API) that prints the *current* download URL on stdout; sbx runs it,
//! validates the URL, and pins its content hash. `sbx upgrade` re-runs it and rolls forward; a warm
//! launch reuses the pin **without** re-running it (the offline invariant). This module owns the part
//! that is backend-agnostic — the least-privilege cage the command runs in and the URL capture — while
//! each backend supplies its own URL validator (`.tar.gz` vs `.deb`) and builds the resolved URL its
//! own way.

use super::spec::{Mount, NetPolicy, SandboxSpec};
use crate::store::Layout;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The cage's scratch directory (also `HOME`): a private tmpfs, so a resolve command that writes a
/// temp file has somewhere ephemeral without any host path.
const RESOLVE_HOME: &str = "/tmp";
/// Where sbx's CA bundle is bound, and what the command's TLS clients are pointed at.
const RESOLVE_CA_DEST: &str = "/etc/ssl/certs/ca-bundle.crt";

/// The least-privilege sandbox a `resolve` command runs in: a hermetic bubblewrap cage carrying sbx's
/// base userland (never the host `/usr`), so the command is portable by construction — it sees exactly
/// the shell, coreutils and the curated base tools ([`super::fhs`] is the single source of truth for
/// that set) plus whatever `nix:` tools the app declared (their bins on `PATH`), and a command
/// reaching for a tool that is not there fails cleanly rather than silently depending on the host.
pub(crate) struct ResolveCage<'a> {
    /// The bubblewrap engine to exec.
    pub(crate) bwrap: &'a Path,
    /// The host-side physical path of sbx's store, bound read-only at `/nix`.
    pub(crate) store_src: PathBuf,
    /// The base shell (a logical `/nix/store/…/bin/bash`), symlinked to `/bin/sh`.
    pub(crate) shell_bin: &'a Path,
    /// The host-side physical path of sbx's CA bundle, bound so the command's HTTPS is hermetic.
    pub(crate) ca_bundle: &'a Path,
    /// The `PATH` bin directories (logical store paths): sbx's base tools plus the **project's**
    /// baseline `[packages]` `nix:`/`flake:` bins, so a resolve command can use a tool the base does
    /// not carry by declaring it (e.g. `yq = "nix:yq-go"`).
    ///
    /// Narrower than what a launch puts on `PATH`, and deliberately: the mise `nix:` tools, the
    /// direct prebuilt bins and any app overlay are not here, because assembling them means
    /// provisioning them, which is the expensive half of a launch and not something `sbx upgrade`
    /// should do for every resolver reference. A resolve command that reaches for one of those
    /// fails at upgrade — loudly, one `re-resolve failed` line per package — while launches keep
    /// working off the pin already recorded.
    pub(crate) bins: Vec<PathBuf>,
}

/// The owning counterpart of [`ResolveCage`], for `sbx upgrade`. A [`ResolveCage`] borrows its
/// engine, shell and CA bundle, so something must hold them for the whole upgrade; this is that
/// something. Every prebuilt backend needs the identical set, so it is assembled once here rather
/// than three times.
pub(crate) struct UpgradeCage {
    bwrap: PathBuf,
    store_src: PathBuf,
    shell_bin: PathBuf,
    ca_bundle: PathBuf,
    bins: Vec<PathBuf>,
}

impl UpgradeCage {
    /// Assemble the resolver sandbox for `sbx upgrade`: the same hermetic base userland a launch
    /// gives a resolve command, plus the project's baseline `[packages]` bins. Not the launch cage's
    /// whole `PATH` — see [`ResolveCage::bins`] for what is left out and why. Best-effort: `None`
    /// when the host cannot resolve an engine or a sandbox, and the caller then reports each
    /// resolver reference as un-rollable rather than silently frozen.
    pub(crate) fn build(
        nix: &Path,
        layout: &Layout,
        project: &Path,
        cfg: &crate::config::Resolved,
    ) -> Option<Self> {
        let bwrap = crate::store::resolve_bwrap(Some(layout))?.path;
        // The project's channel, never an app's: the prebuilt backends this cage serves are not
        // app-scoped (`sbx upgrade --app` narrows the in-cage rolls only), so there is no app whose
        // lock could apply. A resolver command runs against the same base its project does.
        let nixpkgs = super::launch::effective_lock_target(project, layout, cfg, None)
            .ok()?
            .resolve(nix, layout)
            .ok()?;
        let engine_ref = crate::store::resolve_engine_ref(
            nix,
            layout,
            cfg.mise_engine.as_deref(),
            cfg.nixpkgs_global.as_deref(),
        )
        .ok()?;
        let userland = super::fhs::resolve_userland(nix, layout, &nixpkgs, &engine_ref).ok()?;
        let mut bins = userland.bin_paths.clone();
        // The project's baseline `[packages]` bins, so a resolve command using e.g. `jq` finds it
        // here as it does at launch. Best-effort — the base tools are always present regardless.
        // This is the baseline layer only; `cfg.apps` is not walked and the mise/prebuilt layers are
        // not provisioned, so the set is narrower than a launch's.
        if let Ok(p) = super::packages::provision(nix, layout, project, &nixpkgs, &cfg.packages) {
            bins.extend(p.bins);
        }
        Some(UpgradeCage {
            bwrap,
            store_src: crate::store::physical_path(layout, Path::new("/nix")),
            shell_bin: userland.shell_bin.clone(),
            ca_bundle: userland.ca_bundle_src.clone(),
            bins,
        })
    }

    /// Lend the borrowed cage a resolve command runs in, valid for as long as this value lives.
    pub(crate) fn as_cage(&self) -> ResolveCage<'_> {
        ResolveCage {
            bwrap: self.bwrap.as_path(),
            store_src: self.store_src.clone(),
            shell_bin: self.shell_bin.as_path(),
            ca_bundle: self.ca_bundle.as_path(),
            bins: self.bins.clone(),
        }
    }
}

/// Build the sandbox spec for one resolve-command run. Pure (the cage inputs in, a [`SandboxSpec`]
/// out), so the bind/env/network shape is testable without launching bubblewrap.
fn resolve_cage_spec(
    cage: &ResolveCage,
    command: &[String],
) -> Result<SandboxSpec, super::spec::SpecError> {
    let mounts = vec![
        // sbx's store, read-only — the base tools and any `nix:` tool resolve their libraries here.
        Mount::RoBind {
            src: cage.store_src.clone(),
            dest: PathBuf::from("/nix"),
        },
        // `/bin/sh` for a `["sh", "-c", …]` command; `/bin` joins PATH below so bare `sh` resolves.
        Mount::Symlink {
            target: cage.shell_bin.to_path_buf(),
            dest: PathBuf::from("/bin/sh"),
        },
        Mount::Proc {
            dest: PathBuf::from("/proc"),
        },
        Mount::Dev {
            dest: PathBuf::from("/dev"),
        },
        Mount::Tmpfs {
            dest: PathBuf::from(RESOLVE_HOME),
        },
        // Host DNS so the command can resolve the vendor API host; `try`, so a host missing one does
        // not fail the run (it fails closed inside if it genuinely needs what is absent).
        Mount::RoBindTry {
            src: PathBuf::from("/etc/resolv.conf"),
            dest: PathBuf::from("/etc/resolv.conf"),
        },
        Mount::RoBindTry {
            src: PathBuf::from("/etc/nsswitch.conf"),
            dest: PathBuf::from("/etc/nsswitch.conf"),
        },
        Mount::RoBindTry {
            src: PathBuf::from("/etc/hosts"),
            dest: PathBuf::from("/etc/hosts"),
        },
        // sbx's own CA bundle (not the host's), so the command's HTTPS trust is hermetic.
        Mount::RoBind {
            src: cage.ca_bundle.to_path_buf(),
            dest: PathBuf::from(RESOLVE_CA_DEST),
        },
    ];

    // PATH: `/bin` (the `sh` symlink) first, then the base tools + the app's `nix:` bins.
    let mut path = String::from("/bin");
    for dir in &cage.bins {
        path.push(':');
        path.push_str(&dir.to_string_lossy());
    }
    let env = vec![
        ("HOME".to_string(), RESOLVE_HOME.to_string()),
        ("PATH".to_string(), path),
        ("SSL_CERT_FILE".to_string(), RESOLVE_CA_DEST.to_string()),
        ("CURL_CA_BUNDLE".to_string(), RESOLVE_CA_DEST.to_string()),
    ];

    SandboxSpec::new(
        PathBuf::from(RESOLVE_HOME),
        mounts,
        env,
        // Shared network: the resolver must reach the vendor version API. It is trusted (a trusted
        // profile), sandboxed (no host FS, no secrets), and its printed URL is validated — the same
        // posture a network-granted secret-resolver plugin runs under.
        NetPolicy::Shared,
        command.iter().map(OsString::from).collect(),
    )
}

/// Run a `resolve` command in its hermetic cage and return the validated download URL it prints. Fails
/// closed: a non-zero exit folds the command's **stderr** (never its stdout); empty output, non-UTF-8
/// output, or output that `validate` rejects is a hard error. `validate` is the backend's URL check
/// (so an arbitrary command still cannot point sbx at a non-`https` or shell/nix-injecting source) and
/// `kind` names the expected shape (e.g. `` `.tar.gz` `` / `` `.deb` ``) in the error message.
///
/// `allow_insecure_http` is the launch's resolved posture, handed to `validate` so this URL — which
/// the command chose, and which therefore never passed through config validation — is judged by the
/// same rule a declared locator is. Without it the two would answer differently on the same value.
pub(crate) fn resolve_url(
    cage: &ResolveCage,
    name: &str,
    command: &[String],
    validate: fn(&str, bool) -> bool,
    allow_insecure_http: bool,
    kind: &str,
) -> io::Result<String> {
    let spec = resolve_cage_spec(cage, command).map_err(|e| {
        io::Error::other(format!(
            "cannot build the resolve sandbox for `{name}`: {e:?}"
        ))
    })?;
    // `env` keeps the descriptor carrying the cage's environment open until bwrap has read it, and
    // is read below to prepare the exec that inherits it.
    let (argv, env) = super::argv::compose(&spec)?;
    let mut command = Command::new(cage.bwrap);
    command
        .args(argv)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // The descriptor is close-on-exec here; this is what carries it across the one exec that needs
    // it. See [`super::memfd::write`].
    if let Some(env) = env.as_ref() {
        super::memfd::inherit_across_exec(&mut command, std::slice::from_ref(env));
    }
    let out = command.output().map_err(|e| {
        io::Error::other(format!("could not run the `{name}` resolve command: {e}"))
    })?;
    if !out.status.success() {
        let detail = String::from_utf8_lossy(&out.stderr);
        let detail = detail.trim();
        return Err(io::Error::other(format!(
            "the `{name}` resolve command failed{}",
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        )));
    }
    validate_download_url(name, out.stdout, validate, allow_insecure_http, kind)
}

/// Validate a resolve command's captured stdout as a download URL: valid UTF-8, non-empty after
/// trimming, and accepted by the backend's `validate` (so an arbitrary command cannot point sbx at a
/// non-`https` or injecting source). Pure over the raw bytes, so it is testable without bubblewrap.
fn validate_download_url(
    name: &str,
    stdout: Vec<u8>,
    validate: fn(&str, bool) -> bool,
    allow_insecure_http: bool,
    kind: &str,
) -> io::Result<String> {
    let url = String::from_utf8(stdout)
        .map_err(|_| {
            io::Error::other(format!(
                "the `{name}` resolve command printed non-UTF-8 output"
            ))
        })?
        .trim()
        .to_string();
    if url.is_empty() {
        return Err(io::Error::other(format!(
            "the `{name}` resolve command printed no download URL"
        )));
    }
    if !validate(&url, allow_insecure_http) {
        return Err(io::Error::other(format!(
            "the `{name}` resolve command printed a URL that is not a valid {kind} source: {url}"
        )));
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_cage(store: &Path, shell: &Path, ca: &Path, bins: &[&str]) -> ResolveCage<'static> {
        // A leaked `bwrap` path so the returned cage can be `'static` in a unit test — the spec is
        // built purely (no exec), so the path is never run.
        let bwrap: &'static Path = Box::leak(PathBuf::from("/run/bwrap").into_boxed_path());
        ResolveCage {
            bwrap,
            store_src: store.to_path_buf(),
            shell_bin: Box::leak(shell.to_path_buf().into_boxed_path()),
            ca_bundle: Box::leak(ca.to_path_buf().into_boxed_path()),
            bins: bins.iter().map(PathBuf::from).collect(),
        }
    }

    fn contains_pair(argv: &[OsString], flag: &str, first: &str) -> bool {
        argv.windows(2).any(|w| w[0] == flag && w[1] == first)
    }
    fn contains_setenv(argv: &[OsString], key: &str, val: &str) -> bool {
        argv.windows(3)
            .any(|w| w[0] == "--setenv" && w[1] == key && w[2] == val)
    }

    #[test]
    fn the_resolve_cage_is_hermetic_networked_and_runs_the_command_as_argv() {
        let cage = a_cage(
            Path::new("/data/store/nix"),
            Path::new("/nix/store/abc-bash/bin/bash"),
            Path::new("/data/store/nix/store/def-cacert/etc/ssl/certs/ca-bundle.crt"),
            &["/nix/store/ghi-curl/bin"],
        );
        let command = vec!["sh".to_string(), "-c".to_string(), "curl -s x".to_string()];
        let spec = resolve_cage_spec(&cage, &command).expect("valid spec");
        let argv = super::super::argv::to_argv(&spec);
        // The cage's variables travel on a descriptor, not in the world-readable argument list.
        let env = super::super::argv::env_args(&spec);

        // sbx's store is bound at /nix (hermetic — never the host /usr), /bin/sh points at the base bash
        assert!(contains_pair(&argv, "--ro-bind", "/data/store/nix"));
        assert!(contains_pair(
            &argv,
            "--symlink",
            "/nix/store/abc-bash/bin/bash"
        ));
        // the network is SHARED (the resolver must reach the vendor API) — no empty netns
        assert!(!argv.iter().any(|a| a == "--unshare-net"), "{argv:?}");
        // sbx's own CA bundle is bound and pointed at (hermetic TLS, not the host store)
        assert!(contains_pair(
            &argv,
            "--ro-bind",
            "/data/store/nix/store/def-cacert/etc/ssl/certs/ca-bundle.crt"
        ));
        assert!(contains_setenv(
            &env,
            "SSL_CERT_FILE",
            "/etc/ssl/certs/ca-bundle.crt"
        ));
        // PATH is /bin (for the sh symlink) plus the app's nix: bins (so `jq = "nix:jq"` reaches it)
        assert!(contains_setenv(
            &env,
            "PATH",
            "/bin:/nix/store/ghi-curl/bin"
        ));
        assert!(
            !argv.iter().any(|a| a == "--setenv"),
            "no variable may reach the argument list: {argv:?}"
        );
        // the command is passed verbatim as the argv after `--`
        let dashes = argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(
            &argv[dashes + 1..],
            &[
                OsString::from("sh"),
                OsString::from("-c"),
                OsString::from("curl -s x"),
            ]
        );
    }

    #[test]
    fn validate_download_url_enforces_utf8_nonempty_and_the_backend_validator() {
        // The backend supplies the URL shape; here a stand-in `.tar.gz` validator (https + `.tar.gz`).
        fn is_targz(u: &str, allow_insecure_http: bool) -> bool {
            (u.starts_with("https://") || (allow_insecure_http && u.starts_with("http://")))
                && u.ends_with(".tar.gz")
        }
        // a valid URL passes (trimmed of the trailing newline a command prints)
        let ok = validate_download_url(
            "app",
            b"https://e/App.tar.gz\n".to_vec(),
            is_targz,
            false,
            "x",
        )
        .unwrap();
        assert_eq!(ok, "https://e/App.tar.gz");
        // empty output, a validator-rejected URL, and a plaintext/non-URL are each fail-closed
        assert!(validate_download_url("app", b"  \n".to_vec(), is_targz, false, "x").is_err());
        assert!(
            validate_download_url("app", b"https://e/app.zip".to_vec(), is_targz, false, "x")
                .is_err()
        );
        assert!(validate_download_url("app", b"not-a-url".to_vec(), is_targz, false, "x").is_err());
        // a non-https (injecting/plaintext) URL is refused before any fetch
        assert!(
            validate_download_url("app", b"http://e/App.tar.gz".to_vec(), is_targz, false, "x")
                .is_err()
        );
        // ...and admitted only under the launch's `allow_insecure_http`, which is the point of
        // carrying it here: this URL was chosen by the resolve command, so it never passed through
        // config validation, and it has to get the same answer a declared locator would get. The
        // `false` arm above and this one are the same call differing in that one bit.
        assert_eq!(
            validate_download_url(
                "app",
                b"http://e/App.tar.gz\n".to_vec(),
                is_targz,
                true,
                "x"
            )
            .unwrap(),
            "http://e/App.tar.gz"
        );
        // The opt-in widens the scheme and nothing else: the shape check still refuses.
        assert!(
            validate_download_url("app", b"http://e/app.zip".to_vec(), is_targz, true, "x")
                .is_err()
        );
    }
}
