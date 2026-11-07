//! A live preflight: launch a minimal sandbox through the real argv builder and
//! ask the kernel whether the result is actually hardened.
//!
//! `doctor` used to decide the security boundary from a stand-in — a raw
//! `unshare` in a forked child (still kept, as a launch's first answer and a
//! failure classifier). A launch whose stand-in says no runs this probe before it
//! refuses, since a path-profiled `bwrap` can keep capabilities that sbx's own
//! process is denied. The decisive test is the one sbx itself performs at launch: feed
//! [`super::argv::to_argv`] to the real `bwrap` and read `/proc/self/status` from
//! inside. A successful launch reporting `CapEff=0` and `NoNewPrivs=1` proves the
//! user namespace is capability-bearing more conclusively than the stand-in can —
//! bubblewrap cannot nest the mount and pid namespaces on a cap-stripped userns,
//! so reaching a hardened process at all means every layer worked.
//!
//! The probe binds host `/usr` only to give itself a userland to run in, and, where the host's
//! `/bin/sh` resolves outside `/usr` (NixOS, or a cage running sbx), the store directory that shell
//! lives in, read-only. The hardening it verifies is userland-independent, so it provisions nothing.
//! Its working directory is a throwaway temp dir, removed on drop, so the check leaves nothing
//! behind on the host.

use super::spec::{Mount, NetPolicy, SandboxSpec};
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// What a live launch revealed about the sandbox. Each field is a fact the kernel
/// reported from inside the running sandbox, so a caller can both decide go/no-go
/// and attribute a failure precisely.
#[derive(Clone)]
pub(crate) struct SmokeReport {
    /// `bwrap` accepted the argv and the command exited successfully.
    pub(crate) launched: bool,
    /// `no_new_privs` was set — bubblewrap leaves it implicit, so this confirms it.
    pub(crate) no_new_privs: bool,
    /// Every effective capability was dropped (`CapEff` all zero).
    pub(crate) caps_dropped: bool,
    /// The host `$HOME` was absent inside the sandbox — the bind layout held.
    pub(crate) host_home_absent: bool,
    /// `bwrap`'s own stderr, so a launch failure the namespace probe cannot
    /// explain (a present, capability-bearing userns yet a failed launch) can be
    /// attributed to the engine.
    pub(crate) stderr: String,
}

impl SmokeReport {
    /// The boundary is real: the launch succeeded and the kernel confirms the
    /// privilege-removing hardening. Hermeticity (`host_home_absent`) is a
    /// property of the bind layout, asserted separately, not a go/no-go gate here.
    pub(crate) fn is_hardened(&self) -> bool {
        self.launched && self.no_new_privs && self.caps_dropped
    }
}

/// What the probe runs: the kernel's view of its privilege, then whether the host home — a path
/// that must never be visible — leaked into the sandbox.
///
/// The home is the script's one positional argument, never part of its text. Interpolated between
/// bare quotes, a home containing an apostrophe closed the string and the rest of the path became
/// shell words; read as text, a home that is not UTF-8 was replaced by `/root`. Either way the
/// consequence was not a loud failure but a test run against some other path, answering `ABSENT`:
/// this check reporting that the host home did not leak into the cage when it had not looked. A
/// hardening probe that can be made to pass by the shape of a path is not one. As an argument the
/// home reaches `[ -e ]` as the bytes it is. `/root` stands in only for a home that is not set.
///
/// The script uses shell builtins alone, because the shell is all the probe is sure to have: a host
/// whose userland lives in a store has no `cat` under `/usr`.
fn probe_argv(shell: &Path, host_home: Option<&OsStr>) -> Vec<OsString> {
    vec![
        shell.as_os_str().to_os_string(),
        OsString::from("-c"),
        OsString::from(
            "while IFS= read -r line; do printf '%s\\n' \"$line\"; done < /proc/self/status; \
             printf 'HOSTHOME='; \
             if [ -e \"$1\" ]; then echo PRESENT; else echo ABSENT; fi",
        ),
        // `$0`, a label.
        OsString::from("sbx-probe"),
        host_home.unwrap_or(OsStr::new("/root")).to_os_string(),
    ]
}

/// How long the probe launch may take before `doctor` reports it as stuck rather than waiting on it.
///
/// The probe starts a minimal cage and reads `/proc/self/status`. It provisions nothing, touches no
/// network and runs no workload, so a host where it has not finished in this long has a problem
/// worth reporting, which is what `doctor` exists to do. Unbounded, the one command whose job is to
/// diagnose a broken launch path was the one that hung on it, with no output to say why.
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);

/// How often the probe is checked for exit while [`PROBE_TIMEOUT`] runs.
///
/// Finer than the cadence a build or a download is polled at: the probe reads a few lines of
/// `/proc` and is expected back in well under a second, so a coarse one would spend more of
/// `doctor`'s answer sleeping than the probe spends running.
const PROBE_POLL: Duration = Duration::from_millis(20);

/// Launch the minimal hardened probe via `bwrap` and report what the kernel saw.
///
/// Errors only when the probe could not be run at all (the spec is constant and
/// valid, so a failure is bubblewrap not spawning); a launch that runs but is not
/// hardened is a successful call returning a non-hardened report.
pub(crate) fn run(bwrap: &Path) -> io::Result<SmokeReport> {
    let home = std::env::var_os("HOME");
    let (shell, store) = probe_shell(
        std::fs::canonicalize("/bin/sh").ok(),
        home.as_deref().map(Path::new),
    );
    launch(bwrap, &shell, store, home.as_deref())
}

/// [`run`] with the shell and its store already chosen.
fn launch(
    bwrap: &Path,
    shell: &Path,
    store: Option<PathBuf>,
    home: Option<&OsStr>,
) -> io::Result<SmokeReport> {
    let work = ScratchDir::new()?;
    let spec = probe_spec(work.path(), store, probe_argv(shell, home))?;
    // The composed list carries the mandatory seccomp filters, so `doctor` proves the real launch
    // path — hardening *and* filter — works on this host, not just the namespaces. The anonymous
    // files behind it (the filters, and the cage's environment) are the command's own, open for as
    // long as it is, because bwrap reads them at startup.
    let mut command = super::argv::compose(bwrap, &spec)?.into_command();
    // Spawned rather than run through `output()`, which waits without a deadline. The pipes are
    // asked for explicitly because `spawn` does not inherit `output()`'s: the probe writes a few
    // lines of `/proc` and never fills one.
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn()?;
    let deadline = Instant::now() + PROBE_TIMEOUT;
    let (_, timed_out) = super::cagewait::wait_capped(&mut child, deadline, PROBE_POLL)?;
    if timed_out {
        drop(command);
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "the sandbox probe did not finish within {}s",
                PROBE_TIMEOUT.as_secs()
            ),
        ));
    }
    let out = child.wait_with_output()?;
    drop(command);
    let stdout = String::from_utf8_lossy(&out.stdout);

    Ok(SmokeReport {
        launched: out.status.success(),
        no_new_privs: stdout.contains("NoNewPrivs:\t1"),
        caps_dropped: stdout.contains("CapEff:\t0000000000000000"),
        host_home_absent: stdout.contains("HOSTHOME=ABSENT"),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// The shell the probe runs, and the directory to bind read-only for it when it lives outside `/usr`.
///
/// The cage's `/bin` is a link to `usr/bin`, which holds a shell on a distribution that keeps its
/// userland there and none on one that keeps it in a store, where the host's `/bin/sh` is a link to
/// `/nix/store/…`. The probe follows that link and runs the shell by the path it reaches, binding the
/// two leading components of that path (`/nix/store`), which hold the shell and the libraries it was
/// linked against. A directory that holds the host home is never bound, since the probe's other
/// question is whether that home is visible: the probe keeps `/bin/sh` there, and a launch failure
/// is reported as before.
///
/// `resolved` is where `/bin/sh` leads, `None` when it could not be followed.
fn probe_shell(resolved: Option<PathBuf>, home: Option<&Path>) -> (PathBuf, Option<PathBuf>) {
    let fallback = (PathBuf::from("/bin/sh"), None);
    let Some(shell) = resolved else {
        return fallback;
    };
    if shell.starts_with("/usr") {
        return fallback;
    }
    let root: PathBuf = shell.components().take(3).collect();
    if root == shell || home.is_some_and(|h| h.starts_with(&root)) {
        return fallback;
    }
    (shell, Some(root))
}

/// The canonical minimal hardened spec: host `/usr` bound read-only for a
/// userland, the usual FHS symlinks, fresh proc/dev/tmpfs, a throwaway rw
/// workdir, and the store directory [`probe_shell`] found, if any. The hardening itself is added
/// unconditionally by `to_argv`, so this only supplies the userland the probe runs in.
fn probe_spec(work: &Path, store: Option<PathBuf>, argv: Vec<OsString>) -> io::Result<SandboxSpec> {
    // The userland is the canonical minimal set; the probe adds its throwaway rw workdir and the
    // store its shell lives in.
    let mut mounts = super::spec::minimal_userland_mounts();
    if let Some(store) = store {
        mounts.push(Mount::RoBind {
            src: store.clone(),
            dest: store,
        });
    }
    mounts.push(Mount::Bind {
        src: work.to_path_buf(),
        dest: PathBuf::from("/work"),
    });
    let env = vec![
        ("HOME".to_string(), "/work".to_string()),
        ("PATH".to_string(), "/usr/bin:/bin".to_string()),
        ("TERM".to_string(), "dumb".to_string()),
    ];
    SandboxSpec::new(PathBuf::from("/work"), mounts, env, NetPolicy::Shared, argv).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid probe spec: {e:?}"),
        )
    })
}

/// A temp dir the probe owns outright, removed on drop, so the check leaves nothing
/// behind on the host.
///
/// The directory is bound read-write into the cage as the probe's home, so the path
/// it lands on decides what gets mounted there. A name built from the pid alone is
/// one a bystander can compute and prepare ahead of the run — a pid recycles, and a
/// crashed run leaves its own behind — so the name carries six characters drawn from
/// the system CSPRNG as well. The pid stays, because a directory left on the host
/// should still say which run left it.
///
/// `create_dir` rather than `create_dir_all`: it fails on a path that already exists,
/// whatever it is, instead of adopting a file, a symlink or a directory prepared by
/// someone else. With an unguessable name a collision is a fault to report, not a
/// state to recover from, so no retry.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new() -> io::Result<Self> {
        use ring::rand::SecureRandom;
        let mut bytes = [0u8; 3];
        ring::rand::SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| io::Error::other("no system randomness for the probe scratch name"))?;
        let suffix: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let mut dir = std::env::temp_dir();
        dir.push(format!("sbx-doctor-smoke-{}-{suffix}", std::process::id()));
        std::fs::create_dir(&dir)?;
        Ok(ScratchDir(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `bwrap` plus a capability-bearing user namespace, or `None` to skip on a
    /// host that cannot sandbox.
    fn prerequisites() -> Option<PathBuf> {
        let bwrap = crate::pathfind::find_on_path("bwrap")?;
        matches!(crate::probe_userns(), crate::Userns::Ok).then_some(bwrap)
    }

    /// The probe tests `[ -e "$1" ]` inside the cage, with the host home as `$1`. A home that holds
    /// an apostrophe, or a name that is not UTF-8, is still the path tested — run rather than read,
    /// since only a shell can say what its test reached: `PRESENT` for each home that exists, and
    /// `ABSENT` for one that does not, so the test does not pass on anything.
    #[test]
    fn a_home_of_any_shape_is_still_the_path_the_probe_tests() {
        use std::os::unix::ffi::OsStrExt as _;
        let dir = crate::testutil::TmpDir::new();
        let runs = |home: &Path| {
            let argv = probe_argv(Path::new("/bin/sh"), Some(home.as_os_str()));
            assert_eq!(argv.last().map(OsString::as_os_str), Some(home.as_os_str()));
            let out = std::process::Command::new(&argv[0])
                .args(&argv[1..])
                .output()
                .expect("run the probe's own script");
            let stdout = String::from_utf8_lossy(&out.stdout);
            stdout
                .lines()
                .find_map(|l| l.strip_prefix("HOSTHOME="))
                .unwrap_or_else(|| panic!("no answer for {home:?}: {stdout}"))
                .to_string()
        };
        for name in [&b"it's a home"[..], b"caf\xe9 home"] {
            let home = dir.path().join(OsStr::from_bytes(name));
            std::fs::create_dir_all(&home).unwrap();
            assert_eq!(runs(&home), "PRESENT", "{home:?} reaches `[ -e ]` whole");
        }
        for name in [&b"no'such"[..], b"no\xffsuch"] {
            assert_eq!(runs(&dir.path().join(OsStr::from_bytes(name))), "ABSENT");
        }
        // Unset is the one case answered by a stand-in.
        assert_eq!(
            probe_argv(Path::new("/bin/sh"), None)
                .last()
                .map(OsString::as_os_str),
            Some(OsStr::new("/root"))
        );
    }

    #[test]
    fn a_real_launch_is_hardened_and_hermetic() {
        let Some(bwrap) = prerequisites() else {
            skip_incapable!("skipping bwrap smoke: no bwrap or no capability-bearing userns");
            return;
        };
        let report = run(&bwrap).expect("the probe should run where the host can sandbox");
        assert!(
            report.launched,
            "bwrap did not launch; stderr:\n{}",
            report.stderr
        );
        assert!(report.no_new_privs, "no_new_privs not set");
        assert!(report.caps_dropped, "effective capabilities not dropped");
        assert!(
            report.host_home_absent,
            "the host home leaked into the sandbox"
        );
        assert!(report.is_hardened());
    }

    /// The probe's script needs nothing but its shell. Where `/bin/sh` lives in a store, the cage's
    /// `/usr/bin` holds no `cat`, `grep` or the like, so a script that called one read nothing and
    /// the launch reported no hardening. Run with a `PATH` that names no directory, the script must
    /// still print the kernel's status lines and answer for the home.
    #[test]
    fn the_probe_script_runs_on_shell_builtins_alone() {
        let dir = crate::testutil::TmpDir::new();
        let argv = probe_argv(Path::new("/bin/sh"), Some(dir.path().as_os_str()));
        let out = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .env_clear()
            .env("PATH", dir.path().join("no-such-dir"))
            .output()
            .expect("run the probe's own script");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "the script failed: {}\n{stdout}{stderr}",
            out.status
        );
        assert!(
            stdout.lines().any(|l| l.starts_with("NoNewPrivs:\t"))
                && stdout.lines().any(|l| l.starts_with("CapEff:\t")),
            "the status lines were not read without a program on PATH:\n{stdout}{stderr}"
        );
        assert!(
            stdout.lines().any(|l| l == "HOSTHOME=PRESENT"),
            "the home was not answered without a program on PATH:\n{stdout}{stderr}"
        );
    }

    /// A shell under `/usr` is run as `/bin/sh` with nothing more bound; one in a store is run by
    /// its own path with the store's directory bound; and that directory is never one holding the
    /// host home, nor a shell the probe could not follow.
    #[test]
    fn the_probe_runs_a_store_shell_from_its_store() {
        let sh = || (PathBuf::from("/bin/sh"), None);
        let bash = PathBuf::from("/nix/store/abc-bash-5.3/bin/bash");
        assert_eq!(probe_shell(Some("/usr/bin/dash".into()), None), sh());
        assert_eq!(
            probe_shell(Some(bash.clone()), Some(Path::new("/home/u"))),
            (bash.clone(), Some(PathBuf::from("/nix/store")))
        );
        assert_eq!(
            probe_shell(Some(bash.clone()), Some(Path::new("/nix/store/home"))),
            sh()
        );
        assert_eq!(probe_shell(Some("/sh".into()), None), sh());
        assert_eq!(probe_shell(None, None), sh());
        let work = Path::new("/tmp/w");
        let spec = probe_spec(
            work,
            Some(PathBuf::from("/nix/store")),
            probe_argv(&bash, None),
        )
        .unwrap();
        assert!(spec.mounts().iter().any(|m| matches!(m,
            Mount::RoBind { src, dest } if src == Path::new("/nix/store") && dest == src)));
    }

    /// The case the store binding exists for, launched: a shell from the host's nix store, run by
    /// its own path with only `/usr` and that store bound, reaches a hardened process. Before, the
    /// probe asked for `/bin/sh` through the cage's `/usr/bin` and read the status with `cat`, and a
    /// host whose shell lives in a store has neither there.
    #[test]
    fn a_shell_from_a_store_launches_a_hardened_probe() {
        let Some(bwrap) = prerequisites() else {
            skip_incapable!("skipping store-shell smoke: no bwrap or no capability-bearing userns");
            return;
        };
        let Some(bash) = std::fs::read_dir("/nix/store").ok().and_then(|dir| {
            dir.flatten()
                .map(|e| e.path().join("bin/bash"))
                .find(|p| p.is_file())
        }) else {
            skip_incapable!("skipping store-shell smoke: no bash in /nix/store");
            return;
        };
        let report = launch(
            &bwrap,
            &bash,
            Some(PathBuf::from("/nix/store")),
            std::env::var_os("HOME").as_deref(),
        )
        .expect("the probe should run where the host can sandbox");
        assert!(
            report.is_hardened(),
            "{bash:?} did not launch hardened; stderr:\n{}",
            report.stderr
        );
        assert!(
            report.host_home_absent,
            "the host home leaked into the sandbox"
        );
    }

    #[test]
    fn is_hardened_requires_launch_and_both_privilege_facts() {
        let base = SmokeReport {
            launched: true,
            no_new_privs: true,
            caps_dropped: true,
            host_home_absent: true,
            stderr: String::new(),
        };
        assert!(base.is_hardened());
        assert!(
            !SmokeReport {
                launched: false,
                ..base.clone()
            }
            .is_hardened()
        );
        assert!(
            !SmokeReport {
                no_new_privs: false,
                ..base.clone()
            }
            .is_hardened()
        );
        assert!(
            !SmokeReport {
                caps_dropped: false,
                ..base.clone()
            }
            .is_hardened()
        );
        // hermeticity is reported, not gated on here
        assert!(
            SmokeReport {
                host_home_absent: false,
                ..base.clone()
            }
            .is_hardened()
        );
    }

    #[test]
    fn scratch_dir_removes_itself_on_drop() {
        let path = {
            let scratch = ScratchDir::new().expect("create scratch dir");
            let p = scratch.path().to_path_buf();
            assert!(p.is_dir(), "scratch dir should exist while held");
            p
        };
        assert!(!path.exists(), "scratch dir should be gone after drop");
    }

    /// The scratch dir is bound read-write into the probe cage as its home, so its path must not
    /// be one a bystander can predict and prepare. The pid keeps a leftover attributable to the
    /// run that made it; the random suffix is what makes the path unguessable. A later change
    /// that dropped the suffix would restore a computable name without failing anything else,
    /// so the shape is asserted here.
    #[test]
    fn the_scratch_name_carries_a_pid_and_a_random_suffix() {
        let scratch = ScratchDir::new().expect("create scratch dir");
        let name = scratch
            .path()
            .file_name()
            .and_then(|n| n.to_str())
            .expect("scratch dir has a UTF-8 name")
            .to_string();
        let prefix = format!("sbx-doctor-smoke-{}-", std::process::id());
        let suffix = name
            .strip_prefix(&prefix)
            .unwrap_or_else(|| panic!("scratch name is not {prefix}<suffix>: {name}"));
        assert_eq!(suffix.len(), 6, "suffix should be six characters: {name}");
        assert!(
            suffix
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "suffix should be lowercase hex: {name}"
        );
    }
}
