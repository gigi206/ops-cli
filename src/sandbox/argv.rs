//! Pure translation of a [`SandboxSpec`] into a bubblewrap argv.
//!
//! This is the security keystone's second half: [`to_argv`] adds *no* exposure
//! of its own. Every mount, variable, and namespace it emits comes from the
//! Spec; the only things it adds unconditionally are the mandatory hardening
//! flags, and those only ever *remove* privilege. The returned vector is the
//! argument list for `bwrap` — the `bwrap` program itself is not included.

use super::spec::{Mount, NetPolicy, SandboxSpec, TerminalPolicy};
use std::ffi::OsString;
use std::path::Path;

fn lit(s: &str) -> OsString {
    OsString::from(s)
}

fn path(p: &Path) -> OsString {
    p.as_os_str().to_os_string()
}

/// Build the bubblewrap argument list for `spec`. Pure: same Spec in, same argv
/// out, no I/O and no globals read. The launcher feeds the result to `bwrap`.
pub(crate) fn to_argv(spec: &SandboxSpec) -> Vec<OsString> {
    let mut a: Vec<OsString> = Vec::new();

    // Namespaces: isolate everything. The pid namespace is mandatory — the
    // same-uid model is only safe behind a pid + user namespace — and the rest
    // remove ambient access to host IPC, hostname, and the cgroup tree.
    for ns in [
        "--unshare-user",
        "--unshare-ipc",
        "--unshare-pid",
        "--unshare-uts",
        "--unshare-cgroup",
    ] {
        a.push(lit(ns));
    }
    if spec.net == NetPolicy::Isolated {
        a.push(lit("--unshare-net"));
    }

    // Free hardening — pure removals, always emitted: start from a clean
    // environment (before anything is set into it), drop every capability, and
    // die with the launcher so no sandbox outlives ops.
    a.push(lit("--clearenv"));
    a.push(lit("--die-with-parent"));
    a.push(lit("--cap-drop"));
    a.push(lit("ALL"));

    // Terminal session: a new session blocks terminal injection for a
    // non-interactive launch. The private-pty path establishes its own session
    // (and holds the pty master), so it must omit this — `--new-session` would
    // `setsid` away from that private controlling terminal.
    if spec.terminal == TerminalPolicy::NewSession {
        a.push(lit("--new-session"));
    }

    // Environment: rebuilt from nothing, entry by entry in declaration order.
    // The clear above guarantees no host variable survives.
    for (k, v) in &spec.env {
        a.push(lit("--setenv"));
        a.push(lit(k));
        a.push(lit(v));
    }

    // Filesystem: the Spec's mounts, in order. A later mount shadows an earlier
    // one at the same path, so the order is load-bearing — it is the Spec's
    // responsibility and is faithfully preserved here.
    for m in &spec.mounts {
        match m {
            Mount::RoBind { src, dest } => {
                a.push(lit("--ro-bind"));
                a.push(path(src));
                a.push(path(dest));
            }
            Mount::RoBindTry { src, dest } => {
                a.push(lit("--ro-bind-try"));
                a.push(path(src));
                a.push(path(dest));
            }
            Mount::Bind { src, dest } => {
                a.push(lit("--bind"));
                a.push(path(src));
                a.push(path(dest));
            }
            Mount::Symlink { target, dest } => {
                a.push(lit("--symlink"));
                a.push(path(target));
                a.push(path(dest));
            }
            Mount::Proc { dest } => {
                a.push(lit("--proc"));
                a.push(path(dest));
            }
            Mount::Dev { dest } => {
                a.push(lit("--dev"));
                a.push(path(dest));
            }
            Mount::Tmpfs { dest } => {
                a.push(lit("--tmpfs"));
                a.push(path(dest));
            }
        }
    }

    // Working directory, then the command after `--` so the command's own flags
    // are never parsed by bwrap.
    a.push(lit("--chdir"));
    a.push(path(&spec.workdir));
    a.push(lit("--"));
    a.extend(spec.cmd.iter().cloned());

    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn spec(mounts: Vec<Mount>, env: Vec<(String, String)>, net: NetPolicy) -> SandboxSpec {
        SandboxSpec::new(
            PathBuf::from("/work"),
            mounts,
            env,
            net,
            vec![
                OsString::from("/bin/sh"),
                OsString::from("-c"),
                OsString::from("id"),
            ],
        )
        .expect("valid spec")
    }

    /// Positions of `needle` in the argv, as a convenience for ordering asserts.
    fn index_of(argv: &[OsString], needle: &str) -> Option<usize> {
        argv.iter().position(|a| a == needle)
    }

    #[test]
    fn hardening_is_emitted_unconditionally() {
        let argv = to_argv(&spec(vec![], vec![], NetPolicy::Shared));
        for flag in [
            "--unshare-user",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-uts",
            "--unshare-cgroup",
            "--clearenv",
            "--new-session",
            "--die-with-parent",
        ] {
            assert!(index_of(&argv, flag).is_some(), "missing {flag}: {argv:?}");
        }
        // capabilities are dropped as a pair
        let i = index_of(&argv, "--cap-drop").expect("--cap-drop present");
        assert_eq!(argv[i + 1], OsString::from("ALL"));
    }

    #[test]
    fn the_private_tty_terminal_omits_new_session() {
        // the default (non-interactive) terminal keeps --new-session
        let default = to_argv(&spec(vec![], vec![], NetPolicy::Shared));
        assert!(index_of(&default, "--new-session").is_some());

        // the private-pty terminal omits it (the supervisor owns the session)
        let pty = to_argv(&spec(vec![], vec![], NetPolicy::Shared).with_private_tty());
        assert!(
            index_of(&pty, "--new-session").is_none(),
            "private-tty must omit --new-session: {pty:?}"
        );
        // the pure-removal hardening is unchanged
        for flag in [
            "--clearenv",
            "--cap-drop",
            "--unshare-pid",
            "--die-with-parent",
        ] {
            assert!(index_of(&pty, flag).is_some(), "missing {flag}: {pty:?}");
        }
    }

    #[test]
    fn shared_network_is_not_unshared_isolated_is() {
        let shared = to_argv(&spec(vec![], vec![], NetPolicy::Shared));
        assert!(index_of(&shared, "--unshare-net").is_none());

        let isolated = to_argv(&spec(vec![], vec![], NetPolicy::Isolated));
        assert!(index_of(&isolated, "--unshare-net").is_some());
    }

    #[test]
    fn the_environment_is_cleared_before_anything_is_set() {
        let env = vec![
            ("HOME".to_string(), "/home/sandbox".to_string()),
            ("TERM".to_string(), "dumb".to_string()),
        ];
        let argv = to_argv(&spec(vec![], env, NetPolicy::Shared));

        let clear = index_of(&argv, "--clearenv").expect("--clearenv present");
        let first_set = index_of(&argv, "--setenv").expect("--setenv present");
        assert!(clear < first_set, "clearenv must precede setenv: {argv:?}");

        // each variable is emitted as the triple [--setenv, KEY, VALUE]
        assert_eq!(argv[first_set + 1], OsString::from("HOME"));
        assert_eq!(argv[first_set + 2], OsString::from("/home/sandbox"));
    }

    #[test]
    fn mounts_map_to_flags_in_declaration_order() {
        let mounts = vec![
            Mount::RoBind {
                src: PathBuf::from("/nix"),
                dest: PathBuf::from("/nix"),
            },
            Mount::Symlink {
                target: PathBuf::from("usr/bin"),
                dest: PathBuf::from("/bin"),
            },
            Mount::Proc {
                dest: PathBuf::from("/proc"),
            },
            Mount::Dev {
                dest: PathBuf::from("/dev"),
            },
            Mount::Tmpfs {
                dest: PathBuf::from("/tmp"),
            },
            Mount::Bind {
                src: PathBuf::from("/host/proj"),
                dest: PathBuf::from("/host/proj"),
            },
        ];
        let argv = to_argv(&spec(mounts, vec![], NetPolicy::Shared));

        // the mount region of the argv, in order
        let expected: Vec<OsString> = [
            "--ro-bind",
            "/nix",
            "/nix",
            "--symlink",
            "usr/bin",
            "/bin",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--bind",
            "/host/proj",
            "/host/proj",
        ]
        .iter()
        .map(|s| OsString::from(*s))
        .collect();

        let start = index_of(&argv, "--ro-bind").expect("mounts present");
        assert_eq!(&argv[start..start + expected.len()], expected.as_slice());
    }

    #[test]
    fn ro_bind_try_maps_to_the_try_variant() {
        let mounts = vec![Mount::RoBindTry {
            src: PathBuf::from("/etc/resolv.conf"),
            dest: PathBuf::from("/etc/resolv.conf"),
        }];
        let argv = to_argv(&spec(mounts, vec![], NetPolicy::Shared));
        let i = index_of(&argv, "--ro-bind-try").expect("--ro-bind-try present");
        assert_eq!(argv[i + 1], OsString::from("/etc/resolv.conf"));
        assert_eq!(argv[i + 2], OsString::from("/etc/resolv.conf"));
    }

    #[test]
    fn the_command_comes_last_after_a_double_dash_preceded_by_chdir() {
        let argv = to_argv(&spec(vec![], vec![], NetPolicy::Shared));

        let dashes = index_of(&argv, "--").expect("-- present");
        // --chdir <workdir> immediately precedes the `--` separator
        assert_eq!(argv[dashes - 2], OsString::from("--chdir"));
        assert_eq!(argv[dashes - 1], OsString::from("/work"));
        // everything after `--` is exactly the command
        let cmd: Vec<OsString> = argv[dashes + 1..].to_vec();
        assert_eq!(
            cmd,
            vec![
                OsString::from("/bin/sh"),
                OsString::from("-c"),
                OsString::from("id")
            ]
        );
    }
}
