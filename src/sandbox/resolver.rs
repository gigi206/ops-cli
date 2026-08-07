//! The host-side sandboxed runner for resolver plugins.
//!
//! A resolver plugin turns a secret reference (`scheme://locator`) into the secret's
//! plaintext. sbx runs it **host-side, in its own bubblewrap cage** — never inside the
//! agent's cage — because a resolver is in the trusted computing base (it touches the
//! plaintext) yet is third-party code, so it is confined to exactly the least-privilege
//! grant its manifest declares ([`crate::plugins::SandboxGrant`]).
//!
//! The contract the runner implements:
//!
//! - the full ref is passed as the program's single argument (`argv[1]`);
//! - the program prints the plaintext to **stdout** and nothing else;
//! - **exit 0 with non-empty stdout** is a resolved secret; **exit 0 with empty stdout** is a
//!   clean *absent* (the caller falls through to the next source in a `from` chain); a
//!   **non-zero exit** is a hard, fail-closed error (the launch aborts, named, the next source
//!   is *not* tried — a resolver error must never silently downgrade to a weaker source). The
//!   absent-vs-resolved split is applied by the caller's shared `classify_value`, so a plugin is
//!   uniform with the `env`/`file`/`sops` built-ins and is safe in a non-terminal chain position.
//! - **stderr** is the program's diagnostic channel and must never carry the value. It is folded
//!   into the error of a failed run, and relayed as a warning when a run resolves *nothing* — so a
//!   plugin can say *why* it found nothing (a misspelled entry, an empty field) without turning a
//!   fall-through into a hard failure. A run that resolves a value stays silent: relaying its
//!   stderr could put a plaintext a careless plugin logged in front of the user.
//!
//! The plaintext lives only in sbx's own memory (host-side, in the trusted computing base) and is
//! never logged: neither the error nor the warning ever carries the plugin's stdout. What is
//! relayed is reduced to one bounded line first — a plugin is third-party code, and a diagnostic
//! is the wrong place to let it drive the user's terminal with escape sequences.
//!
//! The cage is built from the audited [`SandboxSpec`]/[`to_argv`](super::argv::to_argv) keystone, so every cage gets
//! the unconditional hardening (all namespaces, dropped capabilities, a cleared environment, a
//! fresh session, die-with-parent) for free; the runner only adds the manifest's grant on top.

use super::spec::{Mount, NetPolicy, SandboxSpec, SpecError};
use crate::plugins::ResolverPlugin;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The cage's scratch directory, which doubles as `HOME`: a private tmpfs, so a resolver that
/// writes a cache or a lockfile has somewhere ephemeral to do it without any host path.
const CAGE_HOME: &str = "/tmp";

/// Where a manifest's `programs` are bound, and the first entry of the cage's `PATH`, so a plugin
/// invokes each one by name. Deliberately not under `/opt/sbx`, which the *agent's* cage already
/// uses for its own furniture (the proc shim, the fonts config, the egress CA): the two cages
/// never meet, but one prefix meaning two unrelated things is a trap for a later reader.
const CAGE_PROGRAMS: &str = "/run/sbx-programs";

/// Run `plugin` to resolve `reff`, returning its raw stdout on success (the caller classifies
/// empty-as-absent). Fails closed: a non-zero exit, a runner that cannot spawn, or non-UTF-8
/// output is a hard error naming the resolver — never the secret, and never the resolver's stdout.
pub(crate) fn run(bwrap: &Path, plugin: &ResolverPlugin, reff: &str) -> io::Result<String> {
    // The executable is in the trusted computing base. The perimeter is the data directory's
    // owner-only permissions (a project cannot write there), but defend the thing we actually
    // exec directly: refuse it unless it is a regular file owned by us and not writable by group
    // or other. An attacker can only create files owned by *their* uid, so the owner check is the
    // load-bearing one against a planted executable. (`sbx plugins` surfaces the same verdict.)
    plugin.check_exec().map_err(|why| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing to run the resolver plugin {}: {why}",
                plugin.exec.display()
            ),
        )
    })?;

    let mut allow_env = resolve_allow_env(&plugin.sandbox.allow_env);
    // The path-valued variables resolve the same way, and their values are additionally bound.
    // They join `allow_env` because naming one in `allow_env_paths` *is* the pass-through: binding
    // the path without handing the tool the variable pointing at it would leave the tool reading
    // its default, with the grant paid for nothing.
    let env_paths = resolve_env_paths(&plugin.sandbox.allow_env_paths);
    allow_env.extend(env_paths.iter().cloned());
    let programs = resolve_programs(plugin)?;
    // A nix-installed program is not a self-contained file, so the paths it needs come with it.
    let closure = nix_closures(&programs)?;
    let spec = cage_spec(plugin, reff, &allow_env, &env_paths, &programs, &closure).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "cannot build the resolver sandbox for `{}`: {e:?}",
                plugin.scheme
            ),
        )
    })?;

    // `_env` holds the descriptor the cage's environment is read from open until bwrap has run —
    // and the reason it is a descriptor is this cage in particular: a plugin's `allow_env` is how a
    // resolver is handed its *own* credential (a vault token, an age key), and an argument list is
    // world-readable.
    let (argv, _env) = super::argv::compose(&spec)?;
    let out = Command::new(bwrap)
        .args(argv)
        // No stdin: a resolver must not read or block on sbx's stdin.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| {
            io::Error::other(format!(
                "could not run the `{}` resolver plugin: {e}",
                plugin.scheme
            ))
        })?;

    if !out.status.success() {
        // Fold in the plugin's stderr (its diagnostics) but never its stdout (the plaintext).
        let detail = one_line_detail(&out.stderr);
        return Err(io::Error::other(format!(
            "the `{}` resolver plugin failed{}",
            plugin.scheme,
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        )));
    }

    let value = String::from_utf8(out.stdout).map_err(|_| {
        io::Error::other(format!(
            "the `{}` resolver plugin produced output that is not valid UTF-8",
            plugin.scheme
        ))
    })?;

    // This run resolved nothing, so the caller is about to fall through in silence. Relay the
    // plugin's own account of why: a misspelled locator and a source that genuinely does not hold
    // the secret are otherwise indistinguishable, and only the plugin can tell them apart.
    if let Some(detail) = absent_detail(&value, &out.stderr) {
        crate::diag::warn(&format!(
            "the `{}` resolver plugin resolved nothing: {detail}",
            plugin.scheme
        ));
    }
    Ok(value)
}

/// The longest plugin diagnostic sbx repeats. A resolver's stderr is text of its own choosing, so
/// bound how much of it can reach a terminal or a log line.
const DETAIL_MAX: usize = 200;

/// Reduce a plugin's stderr to one safe display line: control characters (a newline that would
/// forge a second diagnostic, an escape that would drive the terminal) become spaces, runs of
/// whitespace collapse, and the result is truncated. Never rejects — a diagnostic is a label, so a
/// sloppy one is cleaned rather than dropped. Non-UTF-8 bytes are replaced, not refused: a plugin
/// that garbles its own message must still be able to name the problem.
fn one_line_detail(raw: &[u8]) -> String {
    let cleaned: String = String::from_utf8_lossy(raw)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let mut out = String::with_capacity(cleaned.len());
    for word in cleaned.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    if out.chars().count() > DETAIL_MAX {
        out = out.chars().take(DETAIL_MAX - 1).collect::<String>() + "…";
    }
    out
}

/// The diagnostic to relay for a **successful** run, or `None` for silence. Pure, so the rule that
/// decides whether a plugin gets a voice is testable without launching bubblewrap.
///
/// A run that produced a value has nothing to explain and is kept silent — its stderr is dropped
/// rather than repeated, because a careless plugin that logged the secret there would otherwise put
/// the plaintext in front of the user. Only a run that produced **nothing** speaks, and "nothing"
/// is decided by the very rule the caller classifies values with
/// ([`super::egress::strip_trailing_line_ending`]), so the warning cannot disagree with the
/// fall-through it explains.
fn absent_detail(stdout: &str, stderr: &[u8]) -> Option<String> {
    if !super::egress::strip_trailing_line_ending(stdout).is_empty() {
        return None;
    }
    let detail = one_line_detail(stderr);
    (!detail.is_empty()).then_some(detail)
}

/// Read each declared `allow_env` variable from sbx's environment, keeping only the ones that
/// are set: an unset variable is simply not passed (the resolver sees a cleared environment plus
/// exactly these). A non-Unicode value cannot become a `--setenv` value, so it is skipped with a
/// warning rather than silently dropped.
fn resolve_allow_env(keys: &[String]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for key in keys {
        match std::env::var(key) {
            Ok(v) => out.push((key.clone(), v)),
            Err(std::env::VarError::NotPresent) => {}
            Err(std::env::VarError::NotUnicode(_)) => {
                crate::diag::warn(&format!(
                    "not passing ${key} to a resolver plugin — its value is not valid Unicode"
                ));
            }
        }
    }
    out
}

/// Read each declared `allow_env_paths` variable from sbx's environment, keeping the ones that
/// are set to a usable path. The caller both passes these through as environment *and* binds
/// their values, so this is the single place the two can agree.
///
/// A **relative** value is dropped with a warning rather than bound. It is the user's own value,
/// not a plugin's, so it is a mistake to report rather than a grant to refuse a launch over — but
/// it cannot be bound: `--ro-bind-try foo foo` names a path relative to a working directory the
/// cage does not share, so it would silently mean something other than what the user wrote. This
/// mirrors the posture `$SBX_DATA_DIR` takes on a relative override.
///
/// A value naming a path that does not exist is kept for the environment and simply binds
/// nothing (the mount is a `try`): the tool then reports what it could not find, which is a
/// better diagnostic than a bind failure the user cannot place.
fn resolve_env_paths(keys: &[String]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (key, value) in resolve_allow_env(keys) {
        if !Path::new(&value).is_absolute() {
            crate::diag::warn(&format!(
                "not binding ${key} for a resolver plugin — its value `{value}` is not an \
                 absolute path"
            ));
            continue;
        }
        out.push((key, value));
    }
    out
}

/// Locate every program the manifest declares, on **sbx's own `PATH`** — the one the user's
/// shell hands us, so a tool found by the user is found by the resolver, whatever installed it.
/// Returns each name with the path to bind, or fails closed naming what is missing.
///
/// The resolved binary enters the trusted computing base: it is `execve`d inside the resolver's
/// cage, on the plaintext path. So each candidate is held to the verdict sbx applies to an engine
/// it picks off `PATH` ([`crate::store::host_exec_verdict`]): a regular file, owned by us or by
/// root, not world-writable. Every match is scanned rather than just the first, so a
/// world-writable early entry does not shadow a legitimate binary further down `PATH` — it is
/// skipped, with a warning, exactly as the engine lookup does.
///
/// The path is canonicalized because binding the *symlink* would bind a dangling name: a nix
/// profile's `bin/x` points into `/nix/store`, which the cage does not have.
fn resolve_programs(plugin: &ResolverPlugin) -> io::Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::with_capacity(plugin.sandbox.programs.len());
    for name in &plugin.sandbox.programs {
        let Some(path) = locate_program(name) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "the `{}` resolver plugin needs the program `{name}`, which is not on \
                     sbx's PATH — install it, or add its directory to PATH before running sbx",
                    plugin.scheme
                ),
            ));
        };
        out.push((name.clone(), path));
    }
    Ok(out)
}

/// How many store paths a launch would bind for these declared programs, or `None` when none of
/// them lives in the nix store and no closure is involved.
///
/// For `sbx plugins info`. A closure is the one part of a grant a reader cannot infer from the
/// manifest, which names no store path at all, so leaving it off the inspection view would hide
/// the largest thing a launch binds. Resolved exactly as a launch resolves it. An error is
/// reported as no closure rather than failing the inspection: `info` describes a grant, and a
/// launch is where an unreadable closure has to be fatal.
pub(crate) fn nix_closure_paths(programs: &[String]) -> Option<usize> {
    let resolved: Vec<(String, PathBuf)> = programs
        .iter()
        .filter_map(|n| locate_program(n).map(|p| (n.clone(), p)))
        .collect();
    if !resolved.iter().any(|(_, p)| p.starts_with(NIX_STORE)) {
        return None;
    }
    nix_closures(&resolved).ok().map(|c| c.len())
}

/// The store paths every nix-resolved program among `programs` needs, deduplicated.
///
/// Only programs that actually resolved under `/nix/store` are queried, so a host with no nix
/// package pays nothing — no subprocess, no requirement that `nix-store` exist. Deduplicated
/// because two programs from one profile share most of their closure, and each entry becomes a
/// bind argument.
fn nix_closures(programs: &[(String, PathBuf)]) -> io::Result<Vec<PathBuf>> {
    let mut seen = std::collections::BTreeSet::new();
    for (_, path) in programs {
        if !path.starts_with(NIX_STORE) {
            continue;
        }
        seen.extend(nix_closure(path)?);
    }
    Ok(seen.into_iter().collect())
}

/// The nix store prefix. A program resolving under it is not a self-contained file: its
/// interpreter line, its libraries and the helpers it shells out to are all other store paths.
const NIX_STORE: &str = "/nix/store/";

/// Every store path a nix-installed program needs, itself included, or an error naming why the
/// question could not be answered.
///
/// A `pass` from nix is a wrapper script whose shebang is a store path and whose helpers are
/// more of them; a `keepassxc-cli` from nix links against a Qt closure. Binding the resolved
/// file alone leaves both unable to start, which is why manifests used to grant the **whole**
/// store to run one program. `nix-store -qR` names exactly the paths that program needs, so the
/// grant becomes the closure rather than the store.
///
/// Fails rather than falling back to binding nothing. A silent fallback would reproduce the trap
/// this repository already paid for once: a binary that is present and executable and still dies
/// at `execve`, surfacing as a bare exit 127 with nothing pointing at the cause.
fn nix_closure(program: &Path) -> io::Result<Vec<PathBuf>> {
    let nix_store = crate::store::resolve_nix_store(None).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "`{}` is a nix store path, so the paths it needs must be read with `nix-store`, \
                 which is not on sbx's PATH — install nix, or use a build of that program which \
                 does not come from the store",
                program.display()
            ),
        )
    })?;
    let out = Command::new(&nix_store)
        .arg("--query")
        .arg("--requisites")
        .arg(program)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| io::Error::other(format!("could not run {}: {e}", nix_store.display())))?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "could not read the store paths `{}` needs: {}",
            program.display(),
            one_line_detail(&out.stderr)
        )));
    }
    let text = String::from_utf8(out.stdout)
        .map_err(|_| io::Error::other("`nix-store --query --requisites` produced non-UTF-8"))?;
    Ok(text.lines().map(PathBuf::from).collect())
}

/// The path a declared program resolves to, or `None` when nothing usable is on `PATH`. Shared
/// with `sbx plugins info`, so what a user is shown is what a launch would bind — a second
/// lookup would be a second chance to disagree.
pub(crate) fn locate_program(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let euid = unsafe { libc::geteuid() };
    for cand in crate::pathfind::find_all_on_path(name) {
        let Ok(meta) = std::fs::metadata(&cand) else {
            continue;
        };
        match crate::store::host_exec_verdict(meta.uid(), meta.mode(), euid) {
            // Canonicalized: binding the *symlink* would bind a dangling name, since a nix
            // profile's `bin/x` points into `/nix/store`, which the cage does not have.
            Ok(()) => return std::fs::canonicalize(&cand).ok().or(Some(cand)),
            Err(why) => crate::diag::warn(&format!(
                "ignoring {} for the program `{name}` ({why})",
                cand.display()
            )),
        }
    }
    None
}

/// Build the cage for one resolver run. Pure: a plugin grant, the already-resolved `allow_env`
/// values and the already-located `programs` in, a [`SandboxSpec`] out, so the bind/env/network
/// shape is testable without launching bubblewrap.
fn cage_spec(
    plugin: &ResolverPlugin,
    reff: &str,
    allow_env: &[(String, String)],
    env_paths: &[(String, String)],
    programs: &[(String, PathBuf)],
    closure: &[PathBuf],
) -> Result<SandboxSpec, SpecError> {
    let ro = |p: &str| Mount::RoBind {
        src: PathBuf::from(p),
        dest: PathBuf::from(p),
    };
    let ro_try = |p: &str| Mount::RoBindTry {
        src: PathBuf::from(p),
        dest: PathBuf::from(p),
    };
    let symlink = |target: &str, dest: &str| Mount::Symlink {
        target: PathBuf::from(target),
        dest: PathBuf::from(dest),
    };

    let mut mounts = vec![
        // The host userland, read-only — every resolver runs host tools (gpg, vault, curl).
        ro("/usr"),
        symlink("usr/lib", "/lib"),
        symlink("usr/lib64", "/lib64"),
        symlink("usr/bin", "/bin"),
        // The dynamic loader cache, where the host has one.
        ro_try("/etc/ld.so.cache"),
        // The plugin itself, read-only at its real path so `exec` resolves and any sibling helper
        // it ships is reachable; a same-uid write cannot tamper with it through a read-only bind.
        Mount::RoBind {
            src: plugin.dir.clone(),
            dest: plugin.dir.clone(),
        },
    ];

    // The structural pseudo-filesystems first, so the grant's own binds layer ON TOP of them. In
    // particular the `/tmp` tmpfs must precede the grant paths: `CAGE_HOME` is `/tmp`, and bwrap
    // applies mounts in argv order, so a tmpfs mounted AFTER a grant path under `/tmp` would shadow
    // it (a manifest granting e.g. an agent socket under `/tmp/...` would silently vanish).
    mounts.push(Mount::Proc {
        dest: PathBuf::from("/proc"),
    });
    mounts.push(Mount::Dev {
        dest: PathBuf::from("/dev"),
    });
    mounts.push(Mount::Tmpfs {
        dest: PathBuf::from(CAGE_HOME),
    });

    // The grant's extra read-only paths, layered over the structural mounts above. Each becomes a
    // separate `--ro-bind-try <src> <dest>` argv pair (see [`to_argv`](super::argv::to_argv)) — never interpolated into a
    // shell string — so a residual `$` a manifest's small path expansion left behind is an inert
    // literal here, not an injection. `try` keeps a manifest portable: a path that names a runtime
    // artifact (e.g. the gpg-agent socket directory under `$XDG_RUNTIME_DIR`) is skipped where it is
    // absent, and the resolver fails closed inside if it genuinely needs what is missing.
    for p in &plugin.sandbox.allow_paths {
        mounts.push(Mount::RoBindTry {
            src: p.clone(),
            dest: p.clone(),
        });
    }

    // The paths named by `allow_env_paths`, bound at their own location so the variable the tool
    // reads and the path it finds are the same string. `try`, like the grant paths above: a
    // variable pointing at something that is not there yet is the user's problem to see reported
    // by the tool, not a launch sbx refuses to start.
    for (_, value) in env_paths {
        mounts.push(Mount::RoBindTry {
            src: PathBuf::from(value),
            dest: PathBuf::from(value),
        });
    }

    // The declared programs, each bound read-only under one directory that the cage's `PATH`
    // starts with, so the plugin calls the tool by name and never has to guess where a package
    // manager put it. `RoBind` rather than `RoBindTry`: the path was just resolved, so a failure
    // to bind it is a real fault and not a portability allowance. Same layering rule as the
    // grant paths above — after the structural pseudo-filesystems, never before.
    for (name, host) in programs {
        mounts.push(Mount::RoBind {
            src: host.clone(),
            dest: PathBuf::from(CAGE_PROGRAMS).join(name),
        });
    }

    // The store paths a nix-installed program needs, each at its own location because that is the
    // only place its own interpreter line and library references can find it. This is what a
    // manifest used to buy by granting the entire store: the closure is what the program actually
    // reads, and nothing else in the store comes with it.
    for path in closure {
        mounts.push(Mount::RoBindTry {
            src: path.clone(),
            dest: path.clone(),
        });
    }

    // A network grant shares the host network and binds the DNS + TLS files a resolver needs to
    // reach a remote secret store; without it the cage gets an empty network namespace (no egress
    // at all — fail-closed). The files are `try`, so a host missing one does not fail the launch.
    let net = if plugin.sandbox.network {
        for f in [
            "/etc/resolv.conf",
            "/etc/nsswitch.conf",
            "/etc/hosts",
            "/etc/ssl",
        ] {
            mounts.push(ro_try(f));
        }
        NetPolicy::Shared
    } else {
        NetPolicy::Isolated
    };

    // The grant's pass-throughs first, then sbx's structural HOME/PATH last so the cage's own
    // identity always wins over a manifest that happens to name them (self-harm at worst).
    let mut env: Vec<(String, String)> = allow_env.to_vec();
    env.push(("HOME".to_string(), CAGE_HOME.to_string()));
    // The programs directory leads the cage's `PATH` when the manifest declares any, so a
    // declared tool wins over a same-named one in the host userland: the plugin runs the binary
    // sbx resolved and vetted, not whatever `/usr/bin` happens to hold.
    let path = if programs.is_empty() {
        "/usr/bin:/bin".to_string()
    } else {
        format!("{CAGE_PROGRAMS}:/usr/bin:/bin")
    };
    env.push(("PATH".to_string(), path));

    SandboxSpec::new(
        PathBuf::from(CAGE_HOME),
        mounts,
        env,
        net,
        vec![plugin.exec.as_os_str().to_os_string(), OsString::from(reff)],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::{ResolverPlugin, SandboxGrant};
    use crate::testutil::TmpDir;
    use std::os::unix::fs::PermissionsExt;

    fn plugin_in(dir: &Path, grant: SandboxGrant) -> ResolverPlugin {
        ResolverPlugin {
            name: "test".to_string(),
            scheme: "test".to_string(),
            dir: dir.to_path_buf(),
            exec: dir.join("resolve"),
            sandbox: grant,
            version: None,
            description: None,
        }
    }

    #[test]
    fn cage_spec_isolates_the_network_and_passes_the_ref_as_argv1() {
        let dir = TmpDir::new();
        let grant = SandboxGrant {
            programs: vec![],
            allow_paths: vec![PathBuf::from("/home/u/.gnupg")],
            allow_env: vec![],
            allow_env_paths: vec![],
            network: false,
        };
        let p = plugin_in(dir.path(), grant);
        let spec = cage_spec(
            &p,
            "test://secret",
            &[("GNUPGHOME".into(), "/home/u/.gnupg".into())],
            &[],
            &[],
            &[],
        )
        .expect("valid spec");
        let argv = super::super::argv::to_argv(&spec);
        // The cage's variables are not in the argument list at all — a plugin's `allow_env` is how a
        // resolver is handed its own credential, so they travel on a descriptor.
        let env = super::super::argv::env_args(&spec);

        // an empty network namespace when the grant does not ask for the network
        assert!(argv.iter().any(|a| a == "--unshare-net"), "{argv:?}");
        // the command is exactly the executable plus the ref
        let dashes = argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(
            &argv[dashes + 1..],
            &[
                p.exec.as_os_str().to_os_string(),
                OsString::from("test://secret"),
            ]
        );
        // the plugin directory is bound read-only, the allow_path read-only (try)
        assert!(contains_pair(&argv, "--ro-bind", &p.dir.to_string_lossy()));
        assert!(contains_pair(&argv, "--ro-bind-try", "/home/u/.gnupg"));
        // the pass-through env is present, and structural HOME/PATH are set
        assert!(contains_pair(&env, "--setenv", "GNUPGHOME"));
        assert!(contains_setenv(&env, "HOME", CAGE_HOME));
        assert!(contains_setenv(&env, "PATH", "/usr/bin:/bin"));
        // structural HOME/PATH come last, so they win over any pass-through naming them
        let gnupg = setenv_index(&env, "GNUPGHOME").unwrap();
        let home = setenv_index(&env, "HOME").unwrap();
        assert!(home > gnupg, "structural env must follow the pass-throughs");
        // and none of it is readable off `/proc/<pid>/cmdline`
        assert!(
            !argv.iter().any(|a| a == "--setenv"),
            "no variable may reach the argument list: {argv:?}"
        );
    }

    #[test]
    fn cage_spec_shares_the_network_and_binds_dns_tls_under_a_network_grant() {
        let dir = TmpDir::new();
        let grant = SandboxGrant {
            programs: vec![],
            allow_paths: vec![],
            allow_env: vec![],
            allow_env_paths: vec![],
            network: true,
        };
        let spec =
            cage_spec(&plugin_in(dir.path(), grant), "vault://x", &[], &[], &[], &[]).expect("valid spec");
        let argv = super::super::argv::to_argv(&spec);
        assert!(
            !argv.iter().any(|a| a == "--unshare-net"),
            "network grant shares the net"
        );
        assert!(contains_pair(&argv, "--ro-bind-try", "/etc/resolv.conf"));
        assert!(contains_pair(&argv, "--ro-bind-try", "/etc/ssl"));
    }

    #[test]
    fn cage_spec_binds_declared_programs_and_leads_the_cage_path_with_them() {
        let dir = TmpDir::new();
        let grant = SandboxGrant {
            programs: vec!["vault".to_string()],
            ..SandboxGrant::default()
        };
        let p = plugin_in(dir.path(), grant);
        // The runner resolved it to a store path a nix profile would have symlinked to; the cage
        // must see it under its own name, not under that one.
        let resolved = PathBuf::from("/nix/store/abc-vault-1.2.3/bin/vault");
        let spec = cage_spec(
            &p,
            "test://x",
            &[],
            &[],
            &[("vault".to_string(), resolved.clone())],
            &[],
        )
        .expect("valid spec");
        let argv = super::super::argv::to_argv(&spec);
        let env = super::super::argv::env_args(&spec);

        assert!(
            argv.windows(3).any(|w| w[0] == "--ro-bind"
                && w[1] == resolved.as_os_str()
                && w[2] == "/run/sbx-programs/vault"),
            "the resolved binary is bound under its plain name: {argv:?}"
        );
        assert!(
            contains_setenv(&env, "PATH", "/run/sbx-programs:/usr/bin:/bin"),
            "the programs directory leads the cage PATH: {env:?}"
        );
        // The tmpfs must still precede it, as it does for the grant paths.
        let tmpfs = argv.iter().position(|a| a == "--tmpfs").expect("tmpfs");
        let bind = argv
            .iter()
            .position(|a| a == "/run/sbx-programs/vault")
            .expect("program bind");
        assert!(tmpfs < bind, "structural mounts come first: {argv:?}");
    }

    #[test]
    fn cage_spec_leaves_the_path_alone_when_no_program_is_declared() {
        let dir = TmpDir::new();
        let spec = cage_spec(
            &plugin_in(dir.path(), SandboxGrant::default()),
            "test://x",
            &[],
            &[],
            &[],
            &[],
        )
        .expect("valid spec");
        let env = super::super::argv::env_args(&spec);
        assert!(contains_setenv(&env, "PATH", "/usr/bin:/bin"), "{env:?}");
        assert!(
            !super::super::argv::to_argv(&spec)
                .iter()
                .any(|a| a.to_string_lossy().contains("sbx-programs")),
            "no programs directory is created for a plugin that declares none"
        );
    }

    // --- helpers over the bwrap argv ------------------------------------------------

    fn contains_pair(argv: &[OsString], flag: &str, first: &str) -> bool {
        argv.windows(2).any(|w| w[0] == flag && w[1] == first)
    }
    fn contains_setenv(argv: &[OsString], key: &str, val: &str) -> bool {
        argv.windows(3)
            .any(|w| w[0] == "--setenv" && w[1] == key && w[2] == val)
    }
    fn setenv_index(argv: &[OsString], key: &str) -> Option<usize> {
        argv.windows(2)
            .position(|w| w[0] == "--setenv" && w[1] == key)
    }

    #[test]
    fn cage_spec_binds_a_nix_closure_at_its_own_paths() {
        let dir = TmpDir::new();
        // Store paths must be bound where they say they are: a nix wrapper's interpreter line and
        // its library references are absolute store paths, so anywhere else is unreachable.
        let closure = [
            PathBuf::from("/nix/store/aaa-bash-5.3/bin/bash"),
            PathBuf::from("/nix/store/bbb-pass-1.7.4"),
        ];
        let spec = cage_spec(
            &plugin_in(dir.path(), SandboxGrant::default()),
            "test://x",
            &[],
            &[],
            &[],
            &closure,
        )
        .expect("valid spec");
        let argv = super::super::argv::to_argv(&spec);
        for p in &closure {
            let p = p.to_string_lossy().to_string();
            assert!(
                argv.windows(3)
                    .any(|w| w[0] == "--ro-bind-try" && w[1] == p.as_str() && w[2] == p.as_str()),
                "closure path {p} bound at its own location: {argv:?}"
            );
        }
    }

    #[test]
    fn run_binds_a_nix_programs_closure_so_a_wrapper_script_can_start() {
        let Some(bwrap) = sandbox_prereqs() else {
            eprintln!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        // Needs a real nix-installed program to be meaningful; skip where there is none.
        let Some(pass) = locate_program("pass") else { return };
        if !pass.starts_with(NIX_STORE) {
            eprintln!("skipping nix closure run: `pass` is not a store path here");
            return;
        }
        // The case the closure exists for. A nix `pass` is a wrapper script whose shebang is a
        // store path, so binding the resolved file alone leaves it unable to start — which is why
        // the manifest used to grant the whole store. Nothing here grants /nix/store: if the
        // closure were not bound, this exec would fail.
        let (_dir, p) = fake_resolver_with(
            "pass --help >/dev/null 2>&1; echo started=$?",
            SandboxGrant {
                programs: vec!["pass".to_string()],
                ..SandboxGrant::default()
            },
        );
        let out = run(&bwrap, &p, "test://x").expect("the resolver should run");
        assert_eq!(out.trim_end(), "started=0");
    }

    #[test]
    fn a_program_outside_the_nix_store_is_never_queried_for_a_closure() {
        // The guard that keeps a host without nix from paying anything: no subprocess, and no
        // requirement that `nix-store` exist. A regression here would fail closed on every
        // non-nix host, so it is pinned rather than left to the happy path.
        let programs = [("env".to_string(), PathBuf::from("/usr/bin/env"))];
        assert_eq!(
            nix_closures(&programs).expect("no query, no error"),
            Vec::<PathBuf>::new()
        );
    }

    #[test]
    fn cage_spec_binds_an_env_path_at_its_own_location() {
        let dir = TmpDir::new();
        let spec = cage_spec(
            &plugin_in(dir.path(), SandboxGrant::default()),
            "test://x",
            &[("PASSWORD_STORE_DIR".into(), "/data/secrets".into())],
            &[("PASSWORD_STORE_DIR".into(), "/data/secrets".into())],
            &[],
            &[],
        )
        .expect("valid spec");
        let argv = super::super::argv::to_argv(&spec);
        // Bound at its own path, so the value the tool reads and the path it finds are one string.
        assert!(
            argv.windows(3).any(|w| w[0] == "--ro-bind-try"
                && w[1] == "/data/secrets"
                && w[2] == "/data/secrets"),
            "the env path is bound at its own location: {argv:?}"
        );
        // The variable itself travels on the descriptor, never in the argument list — it can name
        // a private location, and an argv is readable by every user on the machine.
        let env = super::super::argv::env_args(&spec);
        assert!(
            contains_setenv(&env, "PASSWORD_STORE_DIR", "/data/secrets"),
            "and the variable naming it is passed through: {env:?}"
        );
    }

    // --- live runs through real bwrap (skipped where the host cannot sandbox) -------

    /// `bwrap` plus a capability-bearing user namespace, or `None` to skip.
    fn sandbox_prereqs() -> Option<PathBuf> {
        let bwrap = crate::pathfind::find_on_path("bwrap")?;
        matches!(crate::probe_userns(), crate::Userns::Ok).then_some(bwrap)
    }

    /// Stage an executable fake resolver `resolve` in a fresh plugin directory.
    fn fake_resolver(body: &str) -> (TmpDir, ResolverPlugin) {
        fake_resolver_with(body, SandboxGrant::default())
    }

    /// The same, under a chosen grant.
    fn fake_resolver_with(body: &str, grant: SandboxGrant) -> (TmpDir, ResolverPlugin) {
        let dir = TmpDir::new();
        let exec = dir.join("resolve");
        std::fs::write(&exec, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755)).unwrap();
        let p = plugin_in(dir.path(), grant);
        (dir, p)
    }

    #[test]
    fn run_binds_a_declared_program_so_the_plugin_calls_it_by_name() {
        let Some(bwrap) = sandbox_prereqs() else {
            eprintln!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        // `env` exists on every host this runs on, so what the test pins is not its presence but
        // where the cage resolves it: the bound copy, not the one in the host userland. That is
        // the whole point of the mechanism — a plugin never has to know where a tool was installed.
        let (_dir, p) = fake_resolver_with(
            "command -v env",
            SandboxGrant {
                programs: vec!["env".to_string()],
                ..SandboxGrant::default()
            },
        );
        let out = run(&bwrap, &p, "test://x").expect("the resolver should run");
        assert_eq!(out.trim_end(), "/run/sbx-programs/env");
    }

    #[test]
    fn run_binds_the_path_an_allow_env_paths_variable_names() {
        let Some(bwrap) = sandbox_prereqs() else {
            eprintln!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        // The case the field exists for: a user whose store is not where the manifest guessed.
        // The manifest cannot name this directory — it did not exist when the plugin was signed —
        // so the only thing that can reach it is the variable the user set. The variable name is
        // unique to this test: these run as threads of one process, so a shared name would let two
        // tests overwrite each other's environment.
        const VAR: &str = "SBX_TEST_RESOLVER_ABS_STORE";
        let store = TmpDir::new();
        std::fs::write(store.join("entry"), "the-fixture-wrote-this").unwrap();
        let (_dir, p) = fake_resolver_with(
            &format!("cat \"${VAR}/entry\""),
            SandboxGrant {
                allow_env_paths: vec![VAR.to_string()],
                ..SandboxGrant::default()
            },
        );
        std::env::set_var(VAR, store.path());
        let out = run(&bwrap, &p, "test://x");
        std::env::remove_var(VAR);
        // A hard-coded literal, so the assertion cannot be met by the test recomputing whatever
        // the code produced. Dropping the bind in `cage_spec` makes `cat` fail instead.
        assert_eq!(out.expect("the resolver should run"), "the-fixture-wrote-this");
    }

    #[test]
    fn run_drops_a_relative_allow_env_paths_value_rather_than_binding_it() {
        let Some(bwrap) = sandbox_prereqs() else {
            eprintln!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        // A relative value cannot mean what it says inside a cage sharing no working directory, so
        // it is dropped rather than bound — and the variable goes with it, because passing it while
        // binding nothing would aim the tool at a path the cage does not have, which is the exact
        // failure this field exists to remove.
        const VAR: &str = "SBX_TEST_RESOLVER_REL_STORE";
        let (_dir, p) = fake_resolver_with(
            &format!("echo \"[${{{VAR}-unset}}]\""),
            SandboxGrant {
                allow_env_paths: vec![VAR.to_string()],
                ..SandboxGrant::default()
            },
        );
        std::env::set_var(VAR, "relative/store");
        let out = run(&bwrap, &p, "test://x");
        std::env::remove_var(VAR);
        assert_eq!(out.expect("the resolver should run").trim_end(), "[unset]");
    }

    #[test]
    fn run_fails_closed_when_a_declared_program_is_not_on_the_path() {
        let Some(bwrap) = sandbox_prereqs() else {
            eprintln!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        let (_dir, p) = fake_resolver_with(
            "printf x",
            SandboxGrant {
                programs: vec!["sbx-no-such-program".to_string()],
                ..SandboxGrant::default()
            },
        );
        let err = run(&bwrap, &p, "test://x").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        let msg = err.to_string();
        assert!(
            msg.contains("sbx-no-such-program") && msg.contains("PATH"),
            "the refusal names the program and the remedy: {msg}"
        );
    }

    #[test]
    fn run_returns_the_plugins_stdout_for_the_passed_ref() {
        let Some(bwrap) = sandbox_prereqs() else {
            eprintln!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        let (_dir, p) = fake_resolver("printf 'resolved:%s' \"$1\"");
        let out = run(&bwrap, &p, "test://hello").expect("the resolver should run");
        assert_eq!(out, "resolved:test://hello");
    }

    #[test]
    fn run_fails_closed_on_a_nonzero_exit_folding_stderr_not_stdout() {
        let Some(bwrap) = sandbox_prereqs() else {
            eprintln!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        // prints a plaintext to stdout but exits non-zero — the error must fold stderr, never stdout
        let (_dir, p) = fake_resolver("printf 'the-secret' ; echo 'boom: no key' >&2 ; exit 7");
        let err = run(&bwrap, &p, "test://x").unwrap_err().to_string();
        assert!(
            err.contains("test") && err.contains("boom: no key"),
            "{err}"
        );
        assert!(
            !err.contains("the-secret"),
            "stdout must never leak into the error: {err}"
        );
    }

    #[test]
    fn run_returns_empty_for_a_clean_absent_so_the_caller_can_fall_through() {
        let Some(bwrap) = sandbox_prereqs() else {
            eprintln!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        // exit 0, nothing on stdout — the contract's "absent"; the caller's classify_value turns
        // this empty string into a fall-through to the next source.
        let (_dir, p) = fake_resolver("exit 0");
        assert_eq!(run(&bwrap, &p, "test://x").expect("absent is exit 0"), "");
    }

    // --- what a plugin is allowed to say -------------------------------------------

    #[test]
    fn a_run_that_resolved_a_value_never_repeats_its_stderr() {
        // The load-bearing half: a plugin that logged the secret to stderr must not have it echoed
        // back at the user just because it was chatty. The trailing newline case matters too — the
        // caller strips one before classifying, so "resolved" must be read the same way here.
        assert_eq!(
            absent_detail("the-secret", b"debug: opened the vault"),
            None
        );
        assert_eq!(absent_detail("the-secret\n", b"debug: the-secret"), None);
    }

    #[test]
    fn a_run_that_resolved_nothing_relays_the_plugins_account() {
        assert_eq!(
            absent_detail("", b"entry 'agents/githb' is not in the vault\n"),
            Some("entry 'agents/githb' is not in the vault".to_string())
        );
        // A bare line ending is the same "absent" the caller sees, so the plugin still gets a voice.
        assert_eq!(
            absent_detail("\n", b"the `password` field is empty"),
            Some("the `password` field is empty".to_string())
        );
    }

    #[test]
    fn an_absent_run_from_a_silent_plugin_says_nothing() {
        // Nothing to relay must stay nothing — never an empty `resolved nothing:` line.
        assert_eq!(absent_detail("", b""), None);
        assert_eq!(absent_detail("", b"  \n \t "), None);
    }

    #[test]
    fn a_relayed_diagnostic_is_one_bounded_line() {
        // A plugin's text reaches a terminal: no escape may survive to drive it, and no newline may
        // forge a second diagnostic line.
        let out = one_line_detail(b"\x1b[31mred\x1b[0m\nsecond line");
        assert!(!out.contains('\u{1b}'), "{out}");
        assert!(!out.contains('\n'), "{out}");
        assert_eq!(out, "[31mred [0m second line");

        let long = one_line_detail(&b"a".repeat(DETAIL_MAX * 2));
        assert_eq!(long.chars().count(), DETAIL_MAX);
        assert!(long.ends_with('…'), "{long}");
    }

    #[test]
    fn run_returns_the_value_of_a_chatty_plugin_untouched() {
        let Some(bwrap) = sandbox_prereqs() else {
            eprintln!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        // A plugin that logs while it resolves. The value comes back verbatim, and the run is not
        // an absent — so the runner stays silent about that stderr rather than repeating a line in
        // which a careless plugin put the plaintext.
        let (_dir, p) = fake_resolver("printf 'the-secret' ; echo 'debug: the-secret' >&2");
        assert_eq!(
            run(&bwrap, &p, "test://x").expect("the resolver should run"),
            "the-secret"
        );
    }

    #[test]
    fn run_sanitizes_the_stderr_it_folds_into_an_error() {
        let Some(bwrap) = sandbox_prereqs() else {
            eprintln!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        let (_dir, p) = fake_resolver("printf 'boom\\033[2J\\nsbx: fake line' >&2 ; exit 3");
        let err = run(&bwrap, &p, "test://x").unwrap_err().to_string();
        assert!(err.contains("boom"), "{err}");
        assert!(
            !err.contains('\u{1b}'),
            "no escape reaches the terminal: {err}"
        );
        assert!(!err.contains('\n'), "no forged second line: {err}");
    }

    #[test]
    fn run_refuses_a_group_writable_executable() {
        let Some(bwrap) = sandbox_prereqs() else {
            eprintln!("skipping resolver run: no bwrap or no capability-bearing userns");
            return;
        };
        let (_dir, p) = fake_resolver("printf x");
        std::fs::set_permissions(&p.exec, std::fs::Permissions::from_mode(0o775)).unwrap();
        let err = run(&bwrap, &p, "test://x").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("group or other"), "{err}");
    }
}
