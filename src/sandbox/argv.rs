//! Translation of a [`SandboxSpec`] into a bubblewrap argv.
//!
//! This is the security keystone's second half: [`to_argv`] adds *no* exposure
//! of its own. Every mount, variable, and namespace it emits comes from the
//! Spec; the only things it adds unconditionally are the mandatory hardening
//! flags, and those only ever *remove* privilege. The returned vector is the
//! argument list for `bwrap` — the `bwrap` program itself is not included.
//!
//! Two hardening flags are read off the Spec rather than added unconditionally, and both
//! describe a relationship rather than a removal: `--new-session` (omitted for the private-pty
//! terminal, which establishes its own) and `--die-with-parent` (omitted for the one launch with
//! no supervising process to die with — see [`SandboxSpec::dies_with_launcher`]).
//!
//! The cage's **environment** is the one thing that does not travel in that list. A process's
//! arguments are world-readable (`/proc/<pid>/cmdline` is mode `444`) while its environment is not
//! (`400`), so `--setenv VAR <value>` publishes every value to every uid on the machine for as long
//! as the cage runs. The variables go on a descriptor instead ([`compose`]), which is where the two
//! halves meet: [`to_argv`] stays pure and marks the place, and `compose` — the one impure step —
//! creates the descriptor and fills its number in.

use super::spec::{Mount, NetPolicy, SandboxSpec, TerminalPolicy};
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::Path;

fn lit(s: &str) -> OsString {
    OsString::from(s)
}

fn path(p: &Path) -> OsString {
    p.as_os_str().to_os_string()
}

/// What stands in for the descriptor carrying the cage's environment until [`compose`] can create
/// it. Not a number, so a spec that skipped that step cannot accidentally name a descriptor this
/// process happens to hold — bwrap refuses it loudly instead.
pub(crate) const ENV_ARGS_PLACEHOLDER: &str = "@sbx-env-args";

/// The bubblewrap argument list for `spec`, ready to exec, plus the descriptor it must inherit to
/// read the cage's environment (`None` when the cage sets no variables at all).
///
/// **Hold the returned file** until bwrap has read it: the descriptor is deliberately not
/// close-on-exec, and dropping the `File` closes the number the argv points at.
pub(crate) fn compose(spec: &SandboxSpec) -> io::Result<(Vec<OsString>, Option<File>)> {
    let mut argv = to_argv(spec);
    let Some(file) = env_fd(spec)? else {
        return Ok((argv, None));
    };
    // The placeholder becomes the descriptor's number here, and only here: this is the one step that
    // can create it, which is what keeps [`to_argv`] pure.
    //
    // The slot is found by its **position** — the word after the `--args` that [`to_argv`] wrote —
    // and not by comparing every element to the placeholder text. This vector also carries every
    // bind path and the cage's own command, so a substitution by value rewrote any of them that
    // happened to equal the marker: `sbx run -- printf '%s\n' @sbx-env-args` printed a descriptor
    // number. The literal is special in exactly one slot, the one sbx put it in; everywhere else it
    // is a word the caller chose and sbx has no business touching.
    //
    // The first `--args` pair is that slot: [`to_argv`] writes it before the cage command, which is
    // pushed last, so nothing a caller supplies can be found ahead of it.
    let at = argv
        .windows(2)
        .position(|w| w[0] == "--args" && w[1] == ENV_ARGS_PLACEHOLDER)
        .map(|i| i + 1)
        .ok_or_else(|| {
            io::Error::other(
                "the composed argv carries no `--args` placeholder for the environment descriptor",
            )
        })?;
    argv[at] = OsString::from(file.as_raw_fd().to_string());
    Ok((argv, Some(file)))
}

/// The descriptor carrying the cage's environment, in bwrap's own `--args` encoding (NUL-separated
/// arguments), or `None` when the cage sets no variables.
///
/// Credentials are written **first**, so a variable named after the cage's own plumbing (`PATH`,
/// `HOME`) wins over a credential that took its name — the plumbing is what the cage needs to work,
/// and a credential is never the right answer to `PATH`. (Declaring one name as both is already
/// refused at load: one name, one source.)
///
/// **A NUL byte in a name or a value refuses the launch.** NUL is the separator here, so a value
/// carrying one would end its own argument and turn everything after it into further bwrap
/// arguments — `--bind /home /home` written by whoever supplied the value. Refused rather than
/// stripped: silently removing a byte would change a credential's value, and a launch that ran with
/// a *different* secret than the one declared is worse than one that did not run.
fn env_fd(spec: &SandboxSpec) -> io::Result<Option<File>> {
    if spec.env.is_empty() && spec.secret_env.is_empty() {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    for (key, value) in spec.secret_env.iter().chain(spec.env.iter()) {
        // Which half carried it decides what the message may quote, and the two are not the same
        // case. A NUL in the *value* is reported by naming the key: that is what a person needs to
        // find the declaration, and printing the value would print a credential. A NUL in the
        // *name* is reported without quoting anything — the old message said "the value of `{key}`"
        // and then printed `key`, so it both mislabelled the half and echoed the poisoned bytes it
        // exists to refuse into the terminal reading it.
        let carrier = if key.as_bytes().contains(&0) {
            Some("a variable name".to_string())
        } else if value.as_bytes().contains(&0) {
            Some(format!("the value of `{key}`"))
        } else {
            None
        };
        if let Some(carrier) = carrier {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "refusing to launch: {carrier} contains a NUL byte, which would break out of \
                     its own argument and add arguments of its own"
                ),
            ));
        }
        for part in ["--setenv", key.as_str(), value.as_str()] {
            bytes.extend_from_slice(part.as_bytes());
            bytes.push(0);
        }
    }
    super::memfd::write(c"sbx-args", &bytes).map(Some)
}

/// Build the bubblewrap argument list for `spec`. Pure: same Spec in, same argv
/// out, no I/O and no globals read. The environment is represented by the
/// [`ENV_ARGS_PLACEHOLDER`] that [`compose`] resolves — nothing here is what
/// bwrap is finally given.
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
    match &spec.netns_dummy {
        // Ordinary path: bwrap creates the cage's network namespace itself. An isolated posture
        // gets an empty namespace (loopback only); a shared one inherits the host's.
        None => {
            if spec.net == NetPolicy::Isolated {
                a.push(lit("--unshare-net"));
            }
        }
        // Holder path: the network namespace is pre-created by the netns holder (with a `dummy0`
        // interface up) and inherited across the holder's exec, so bwrap must *not* unshare its
        // own — that would replace the holder's namespace with an empty one and lose the dummy.
        // The holder runs as root in its user namespace, so map the cage back to the host uid/gid
        // to keep the same-uid model (bwrap's default would otherwise leave the cage as uid 0).
        Some(nd) => {
            a.push(lit("--uid"));
            a.push(OsString::from(nd.uid.to_string()));
            a.push(lit("--gid"));
            a.push(OsString::from(nd.gid.to_string()));
        }
    }
    // A fresh UTS namespace inherits the host's hostname at creation, so set the cage's own —
    // `sbx-<slug>`, naming the cage after its app/project. It still never reveals the *host's*
    // hostname (the reason the UTS namespace is unshared), and it makes `$HOSTNAME`, `uname -n`,
    // and a `\h`-based shell prompt identify which cage this is instead of a shared `sandbox`.
    a.push(lit("--hostname"));
    a.push(OsString::from(super::naming::cage_hostname(
        &spec.cage_slug,
    )));

    // Free hardening — pure removals, always emitted: start from a clean
    // environment (before anything is set into it) and drop every capability.
    a.push(lit("--clearenv"));
    a.push(lit("--cap-drop"));
    a.push(lit("ALL"));

    // Die with the launcher, so no sandbox outlives the process that supervises it. Conditional
    // for one shape only, and [`SandboxSpec::dies_with_launcher`] states which: a detached launch
    // that replaces its own daemon with bwrap has no supervisor to outlive, and the flag would
    // arm `PR_SET_PDEATHSIG` against the short-lived launcher instead.
    if spec.dies_with_launcher {
        a.push(lit("--die-with-parent"));
    }

    // Terminal session: a new session blocks terminal injection for a
    // non-interactive launch. The private-pty path establishes its own session
    // (and holds the pty master), so it must omit this — `--new-session` would
    // `setsid` away from that private controlling terminal.
    if spec.terminal == TerminalPolicy::NewSession {
        a.push(lit("--new-session"));
    }

    // Environment: rebuilt from nothing, entry by entry in declaration order — but on a descriptor,
    // never here. A value in the argument list is readable by every uid on the machine; the same
    // value in the environment is not. This is only the placeholder marking where the descriptor's
    // arguments are spliced in, filled in by `compose`; one that reached bwrap is refused as an
    // invalid fd, loudly, rather than silently dropping the cage's environment.
    //
    // Position is load-bearing: after `--clearenv`, which would otherwise wipe everything the
    // descriptor sets. What is *inside* it is ordered by `env_fd`.
    if !spec.env.is_empty() || !spec.secret_env.is_empty() {
        a.push(lit("--args"));
        a.push(lit(ENV_ARGS_PLACEHOLDER));
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
            Mount::DevBind { src, dest } => {
                // `-try` so a device absent on this host is skipped rather than aborting the
                // launch — a portable profile may grant a device (a GPU, kvm) some hosts lack.
                a.push(lit("--dev-bind-try"));
                a.push(path(src));
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

/// Launch `spec` through the real bwrap and wait for it. The one correct way to do that from a
/// test: the descriptor stays open across the run, which a hand-assembled `Command` would drop —
/// bwrap then reports `Invalid fd` instead of a result.
#[cfg(test)]
pub(super) fn run_bwrap(bwrap: &Path, spec: &SandboxSpec) -> io::Result<std::process::Output> {
    let (argv, _env) = compose(spec)?;
    std::process::Command::new(bwrap).args(argv).output()
}

/// The arguments the descriptor carries, read back as bwrap will parse them — the cage's
/// environment, which is no longer anywhere in the argv. The one way a test can ask "what variables
/// does this cage actually get?", so no module has to reimplement the encoding to find out.
#[cfg(test)]
pub(super) fn env_args(spec: &SandboxSpec) -> Vec<OsString> {
    use std::io::Read;
    let Some(mut file) = env_fd(spec).expect("a descriptor for the cage environment") else {
        return Vec::new();
    };
    let mut raw = Vec::new();
    file.read_to_end(&mut raw).expect("read the descriptor");
    raw.split(|b| *b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| OsString::from(String::from_utf8_lossy(part).into_owned()))
        .collect()
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
        ] {
            assert!(index_of(&argv, flag).is_some(), "missing {flag}: {argv:?}");
        }
        // capabilities are dropped as a pair
        let i = index_of(&argv, "--cap-drop").expect("--cap-drop present");
        assert_eq!(argv[i + 1], OsString::from("ALL"));
        // the cage's own hostname is set as a pair (`sbx-<slug>`, here the default-slug spec's
        // `sbx-cage`), so the fresh UTS namespace never inherits — nor reveals — the host's
        let h = index_of(&argv, "--hostname").expect("--hostname present");
        assert_eq!(argv[h + 1], OsString::from("sbx-cage"));
    }

    #[test]
    fn die_with_parent_rides_every_launch_but_the_one_with_no_parent_to_die_with() {
        // The flag is armed against the process supervising the cage, so it belongs on every
        // launch that has one — which is every launch but the detached, guardless branch, where
        // the daemon `exec`s bwrap and leaves it parented to a launcher whose job is to exit.
        let supervised = spec(vec![], vec![], NetPolicy::Shared);
        assert!(
            index_of(&to_argv(&supervised), "--die-with-parent").is_some(),
            "a supervised launch keeps the flag"
        );

        let detached = spec(vec![], vec![], NetPolicy::Shared).outliving_its_launcher();
        let argv = to_argv(&detached);
        assert!(
            index_of(&argv, "--die-with-parent").is_none(),
            "the detached exec-replace drops it: {argv:?}"
        );

        // Nothing else moves. Written as the whole-argv difference rather than as a second list of
        // flags to re-assert, so a hardening flag added later is covered here without being named
        // twice — and so this cannot pass by dropping something it never thought to check.
        let expected: Vec<_> = to_argv(&supervised)
            .into_iter()
            .filter(|a| a != "--die-with-parent")
            .collect();
        assert_eq!(argv, expected, "only the one flag differs");
    }

    #[test]
    fn the_hostname_names_the_cage_after_its_slug() {
        let s = spec(vec![], vec![], NetPolicy::Shared).with_cage_slug("demo-app".to_string());
        let argv = to_argv(&s);
        let h = index_of(&argv, "--hostname").expect("--hostname present");
        assert_eq!(argv[h + 1], OsString::from("sbx-demo-app"));
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
    fn the_holder_netns_replaces_unshare_net_with_a_uid_gid_map() {
        // With the netns holder providing the (dummy-carrying) namespace, bwrap must NOT unshare its
        // own network namespace — that would discard the holder's namespace — and must map the cage
        // back to the host credentials (the holder runs root-in-userns).
        let s = spec(vec![], vec![], NetPolicy::Isolated).with_netns_dummy(
            super::super::spec::NetnsDummy {
                uid: 4242,
                gid: 4343,
                holder_exe: PathBuf::from("/opt/sbx"),
            },
        );
        let argv = to_argv(&s);
        assert!(
            index_of(&argv, "--unshare-net").is_none(),
            "holder mode must not unshare-net: {argv:?}"
        );
        let uid = index_of(&argv, "--uid").expect("--uid present");
        assert_eq!(argv[uid + 1], OsString::from("4242"));
        let gid = index_of(&argv, "--gid").expect("--gid present");
        assert_eq!(argv[gid + 1], OsString::from("4343"));
    }

    /// The environment is set from nothing, and set **off the argument list**: a value there is
    /// readable by every uid on the machine (`/proc/<pid>/cmdline` is mode `444`) while the same
    /// value in the environment is not (`400`).
    #[test]
    fn the_environment_is_cleared_and_then_set_off_the_argument_list() {
        let env = vec![
            ("HOME".to_string(), "/home/sandbox".to_string()),
            ("TERM".to_string(), "dumb".to_string()),
        ];
        let s = spec(vec![], env, NetPolicy::Shared);
        let argv = to_argv(&s);

        assert!(
            index_of(&argv, "--setenv").is_none(),
            "no variable may be an argument: {argv:?}"
        );
        let clear = index_of(&argv, "--clearenv").expect("--clearenv present");
        let args = index_of(&argv, "--args").expect("--args present");
        assert!(
            clear < args,
            "spliced before the clear, the descriptor's variables would be wiped: {argv:?}"
        );
        assert_eq!(argv[args + 1], OsString::from(ENV_ARGS_PLACEHOLDER));

        // On the descriptor, each variable is the same triple bwrap would have taken as arguments.
        let carried = env_args(&s);
        assert_eq!(
            carried,
            [
                "--setenv",
                "HOME",
                "/home/sandbox",
                "--setenv",
                "TERM",
                "dumb"
            ]
            .map(OsString::from)
            .to_vec()
        );
    }

    /// Credentials are written ahead of the plain environment, so a credential that took the name of
    /// the cage's own plumbing loses to the plumbing rather than replacing it.
    #[test]
    fn a_credential_is_applied_before_the_plumbing_that_could_share_its_name() {
        let s = spec(
            vec![],
            vec![("PATH".to_string(), "/bin".to_string())],
            NetPolicy::Shared,
        )
        .with_secret_env(vec![("TOKEN".to_string(), "s3cret".to_string())]);
        let carried = env_args(&s);
        let token = carried.iter().position(|a| a == "TOKEN").expect("TOKEN");
        let path = carried.iter().position(|a| a == "PATH").expect("PATH");
        assert!(token < path, "{carried:?}");
    }

    /// A cage that sets nothing needs no descriptor, and says nothing about one.
    #[test]
    fn a_cage_with_no_environment_names_no_descriptor() {
        let argv = to_argv(&spec(vec![], vec![], NetPolicy::Shared));
        assert!(index_of(&argv, "--args").is_none(), "{argv:?}");
    }

    /// NUL is the separator on the descriptor, so a value carrying one ends its own argument and
    /// everything after it becomes further bwrap arguments — a mount of the author's choosing.
    ///
    /// Measured on a live launch: an untrusted `.sbx.toml` bound the host `$HOME` into the cage.
    ///
    /// Refused, not stripped. Removing the byte would run the cage with a *different* value than the
    /// one declared, which for a credential is worse than not running at all. Checked here rather
    /// than at config load because this is the single choke point every source passes through: a
    /// project's `[env]`, a resolver plugin's `allow_env` pass-through, and a resolved credential.
    #[test]
    fn a_nul_in_the_environment_refuses_the_launch_rather_than_adding_bwrap_arguments() {
        let injected = "a\0--bind\0/home\0/home".to_string();

        let plain = spec(
            vec![],
            vec![("FOO".to_string(), injected.clone())],
            NetPolicy::Shared,
        );
        let e = compose(&plain).expect_err("a NUL-bearing value must refuse the launch");
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
        assert!(e.to_string().contains("FOO"), "{e}");
        assert!(
            !e.to_string().contains("--bind"),
            "the message names the variable, never its value: {e}"
        );

        // The same for a resolved credential, whose value is third-party bytes (a resolver plugin's
        // stdout), and for a name — bwrap reads both off the same descriptor.
        let secret = spec(vec![], vec![], NetPolicy::Shared)
            .with_secret_env(vec![("TOKEN".to_string(), injected)]);
        assert!(compose(&secret).is_err());
        let named = spec(
            vec![],
            vec![("A\0--bind".to_string(), "x".to_string())],
            NetPolicy::Shared,
        );
        assert!(compose(&named).is_err());

        // An ordinary environment is untouched by the check.
        let fine = spec(
            vec![],
            vec![("PATH".to_string(), "/bin".to_string())],
            NetPolicy::Shared,
        );
        assert!(compose(&fine).is_ok());
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
    fn dev_bind_maps_to_the_dev_bind_try_variant() {
        // A `[devices]` grant is a `--dev-bind-try` (skips a device absent on this host) binding the
        // host device at its own path with device access.
        let mounts = vec![Mount::DevBind {
            src: PathBuf::from("/dev/dri"),
            dest: PathBuf::from("/dev/dri"),
        }];
        let argv = to_argv(&spec(mounts, vec![], NetPolicy::Shared));
        let i = index_of(&argv, "--dev-bind-try").expect("--dev-bind-try present");
        assert_eq!(argv[i + 1], OsString::from("/dev/dri"));
        assert_eq!(argv[i + 2], OsString::from("/dev/dri"));
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

    /// Only the slot [`to_argv`] wrote becomes a descriptor number — a cage argument that happens
    /// to equal the marker is left alone.
    ///
    /// The substitution used to be a value comparison over the whole vector, which also carries
    /// every bind path and the cage's own command: `sbx run -- printf '%s\n' @sbx-env-args`
    /// printed a descriptor number instead of the word the caller wrote.
    #[test]
    fn compose_resolves_the_slot_it_wrote_and_not_a_cage_argument_that_looks_like_it() {
        let mut with_env = spec(
            Vec::new(),
            vec![("SHELL".to_string(), "/bin/sh".to_string())],
            NetPolicy::Shared,
        );
        with_env.cmd = vec![
            OsString::from("printf"),
            OsString::from("%s\n"),
            OsString::from(ENV_ARGS_PLACEHOLDER),
        ];
        let (argv, file) = compose(&with_env).expect("compose");
        let file = file.expect("the spec sets variables, so there is a descriptor");

        let args = argv
            .iter()
            .position(|a| a == "--args")
            .expect("`to_argv` writes `--args` when the cage has an environment");
        assert_eq!(
            argv[args + 1],
            OsString::from(file.as_raw_fd().to_string()),
            "the slot after `--args` is the descriptor's number"
        );
        assert_eq!(
            argv.iter().filter(|a| *a == ENV_ARGS_PLACEHOLDER).count(),
            1,
            "the cage's own argument still reads as the word the caller wrote: {argv:?}"
        );
        assert_eq!(
            argv.last().map(|a| a.as_os_str()),
            Some(OsString::from(ENV_ARGS_PLACEHOLDER).as_os_str()),
            "and it is still the last argument, where the command was put"
        );
    }

    /// A NUL in a variable *name* and a NUL in its *value* are different refusals, and neither
    /// quotes the bytes it exists to reject.
    ///
    /// One message served both: it said "the value of `{key}`" and then printed `key`, so a
    /// poisoned name was both mislabelled and echoed into the terminal reading the refusal.
    #[test]
    fn a_nul_refusal_names_the_half_that_carried_it_and_quotes_no_payload() {
        let poisoned_value = spec(
            Vec::new(),
            vec![("API_KEY".to_string(), "a\0b".to_string())],
            NetPolicy::Shared,
        );
        let err = compose(&poisoned_value).unwrap_err().to_string();
        assert!(
            err.contains("the value of `API_KEY`"),
            "a poisoned value is found by naming its key: {err}"
        );

        let poisoned_name = spec(
            Vec::new(),
            vec![("PO\0ISON".to_string(), "harmless".to_string())],
            NetPolicy::Shared,
        );
        let err = compose(&poisoned_name).unwrap_err().to_string();
        assert!(
            err.contains("a variable name contains a NUL byte"),
            "a poisoned name is described, not quoted: {err}"
        );
        assert!(
            !err.contains("PO"),
            "the refusal must not echo the bytes it refuses: {err:?}"
        );
    }
}
