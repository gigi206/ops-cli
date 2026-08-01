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
//! The cage is built from the audited [`SandboxSpec`]/[`to_argv`] keystone, so every cage gets
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

    let allow_env = resolve_allow_env(&plugin.sandbox.allow_env);
    let spec = cage_spec(plugin, reff, &allow_env).map_err(|e| {
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

/// Build the cage for one resolver run. Pure: a plugin grant and the already-resolved
/// `allow_env` values in, a [`SandboxSpec`] out, so the bind/env/network shape is testable
/// without launching bubblewrap.
fn cage_spec(
    plugin: &ResolverPlugin,
    reff: &str,
    allow_env: &[(String, String)],
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
    // separate `--ro-bind-try <src> <dest>` argv pair (see [`to_argv`]) — never interpolated into a
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
    env.push(("PATH".to_string(), "/usr/bin:/bin".to_string()));

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
            allow_paths: vec![PathBuf::from("/home/u/.gnupg")],
            allow_env: vec![],
            network: false,
        };
        let p = plugin_in(dir.path(), grant);
        let spec = cage_spec(
            &p,
            "test://secret",
            &[("GNUPGHOME".into(), "/home/u/.gnupg".into())],
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
            allow_paths: vec![],
            allow_env: vec![],
            network: true,
        };
        let spec = cage_spec(&plugin_in(dir.path(), grant), "vault://x", &[]).expect("valid spec");
        let argv = super::super::argv::to_argv(&spec);
        assert!(
            !argv.iter().any(|a| a == "--unshare-net"),
            "network grant shares the net"
        );
        assert!(contains_pair(&argv, "--ro-bind-try", "/etc/resolv.conf"));
        assert!(contains_pair(&argv, "--ro-bind-try", "/etc/ssl"));
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

    // --- live runs through real bwrap (skipped where the host cannot sandbox) -------

    /// `bwrap` plus a capability-bearing user namespace, or `None` to skip.
    fn sandbox_prereqs() -> Option<PathBuf> {
        let bwrap = crate::pathfind::find_on_path("bwrap")?;
        matches!(crate::probe_userns(), crate::Userns::Ok).then_some(bwrap)
    }

    /// Stage an executable fake resolver `resolve` in a fresh plugin directory.
    fn fake_resolver(body: &str) -> (TmpDir, ResolverPlugin) {
        let dir = TmpDir::new();
        let exec = dir.join("resolve");
        std::fs::write(&exec, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755)).unwrap();
        let p = plugin_in(dir.path(), SandboxGrant::default());
        (dir, p)
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
