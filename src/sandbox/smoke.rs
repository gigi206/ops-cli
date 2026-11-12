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
/// home reaches `[ -e ]` as the bytes it is.
///
/// `/root` stands in for a home that is not set, and for one that is not an absolute path, since
/// neither names a host path to test. An empty home makes `[ -e "" ]`, false without looking at
/// anything, and a relative one is looked for under the cage's working directory: either would
/// answer `ABSENT` for a home it never tested.
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
        host_home
            .filter(|home| Path::new(home).is_absolute())
            .unwrap_or(OsStr::new("/root"))
            .to_os_string(),
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
    // asked for explicitly because `spawn` does not inherit `output()`'s.
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn()?;
    // Both streams are read on threads of their own while the probe is waited on. Read after the
    // wait, output past what a pipe holds would leave the cage blocked writing until the ceiling
    // killed it, and a probe that had answered would be reported as stuck.
    let out_reader = read_capped(child.stdout.take());
    let err_reader = read_capped(child.stderr.take());
    let deadline = Instant::now() + PROBE_TIMEOUT;
    let waited = super::cagewait::wait_capped(&mut child, deadline, PROBE_POLL);
    // Joined before the wait's answer is read, a timeout or an error included, so neither reader
    // outlives this call. The joins cannot hang: the wait returns once `bwrap` is dead, and the
    // cage dies with it, since its pid namespace is unshared and `--die-with-parent` is armed
    // ([`SandboxSpec::new`]), so nothing is left holding a pipe.
    let stdout = joined(out_reader);
    let stderr = joined(err_reader);
    let (status, timed_out) = waited?;
    if timed_out {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "the sandbox probe did not finish within {}s",
                PROBE_TIMEOUT.as_secs()
            ),
        ));
    }
    let answers = read_answers(&String::from_utf8_lossy(&stdout));

    Ok(SmokeReport {
        launched: status.success(),
        no_new_privs: answers.no_new_privs,
        caps_dropped: answers.caps_dropped,
        host_home_absent: answers.host_home_absent,
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    })
}

/// How much of each of the probe's streams is kept.
///
/// The probe prints `/proc/self/status` and one line of its own, a few kilobytes, and `doctor`
/// shows at most three lines of what `bwrap` says when the launch fails; the ceiling is far past
/// both. It is there because the bytes are the cage's, and a buffer grown to whatever the cage
/// prints is not one the process reading it should hold.
const PROBE_OUTPUT_CAP: usize = 64 * 1024;

/// Read `pipe` to its end on a thread of its own, keeping at most [`PROBE_OUTPUT_CAP`] bytes.
fn read_capped<R: io::Read + Send + 'static>(
    pipe: Option<R>,
) -> Option<std::thread::JoinHandle<Vec<u8>>> {
    pipe.map(|mut pipe| {
        std::thread::spawn(move || super::cagewait::drain_capped(&mut pipe, PROBE_OUTPUT_CAP).0)
    })
}

/// What a reader from [`read_capped`] kept: nothing for a pipe that was not there, or for a reader
/// that panicked, which the answers then read as no.
fn joined(reader: Option<std::thread::JoinHandle<Vec<u8>>>) -> Vec<u8> {
    reader
        .and_then(|reader| reader.join().ok())
        .unwrap_or_default()
}

/// The probe's answers, as its script printed them.
struct Answers {
    no_new_privs: bool,
    caps_dropped: bool,
    host_home_absent: bool,
}

/// Read the probe's answers from its output, each from one whole line.
///
/// A status line is found by its key and judged by its whole value: `NoNewPrivs` must be `1`, and
/// every digit of `CapEff` zero, however many the kernel prints. Searched for as a substring,
/// `NoNewPrivs:\t1` is also found in `NoNewPrivs:\t10`, and sixteen zeros at the head of a wider
/// `CapEff` that is not zero, so the hardening check would pass on a value it never read. The home
/// answer is the script's own line, not a match inside another one. A missing line answers no.
fn read_answers(stdout: &str) -> Answers {
    let field = |key: &str| {
        stdout.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name == key).then(|| value.trim())
        })
    };
    Answers {
        no_new_privs: field("NoNewPrivs") == Some("1"),
        caps_dropped: field("CapEff")
            .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b == b'0')),
        host_home_absent: stdout.lines().any(|line| line == "HOSTHOME=ABSENT"),
    }
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
        // Unset is answered by a stand-in.
        assert_eq!(
            probe_argv(Path::new("/bin/sh"), None)
                .last()
                .map(OsString::as_os_str),
            Some(OsStr::new("/root"))
        );
    }

    /// A home that names no host path, empty or relative, is answered by the stand-in, as an unset
    /// one is: passed as it is, `[ -e ]` would answer `ABSENT` without having looked at the host.
    #[test]
    fn a_home_that_is_not_an_absolute_path_is_answered_by_the_stand_in() {
        for home in ["", "relative/home"] {
            assert_eq!(
                probe_argv(Path::new("/bin/sh"), Some(OsStr::new(home)))
                    .last()
                    .map(OsString::as_os_str),
                Some(OsStr::new("/root")),
                "{home:?} names no host path to test"
            );
        }
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

    /// Run [`launch`] against a stand-in for `bwrap`: a `/bin/sh` script running `body`, written on
    /// shell builtins alone so it does the same whatever environment it is handed.
    fn launch_stand_in(body: &str) -> io::Result<SmokeReport> {
        let dir = crate::testutil::TmpDir::new();
        let bwrap = dir.path().join("bwrap");
        crate::testutil::write_script(&bwrap, body);
        crate::testutil::result_past_etxtbsy("the stand-in bwrap", || {
            launch(&bwrap, Path::new("/bin/sh"), None, None)
        })
    }

    /// Each answer is read from its own whole line. The canonical output is the control that the
    /// stand-in's lines are read at all; each value after it is one a substring search accepts and
    /// a read of the field does not.
    #[test]
    fn each_answer_is_read_from_its_own_whole_line() {
        let report = |lines: &str| {
            launch_stand_in(&format!("printf '{lines}'")).expect("the stand-in bwrap runs")
        };
        let canonical = report(HARDENED);
        assert!(canonical.launched, "the stand-in exits 0");
        assert!(canonical.no_new_privs, "`NoNewPrivs: 1` is read");
        assert!(canonical.caps_dropped, "a zero `CapEff` is read");
        assert!(canonical.host_home_absent, "`HOSTHOME=ABSENT` is read");

        assert!(
            !report(r"NoNewPrivs:\t10\nCapEff:\t0000000000000000\nHOSTHOME=ABSENT\n").no_new_privs,
            "`10` is not `1`"
        );
        assert!(
            !report(r"NoNewPrivs:\t1\nCapEff:\t00000000000000001\nHOSTHOME=ABSENT\n").caps_dropped,
            "a `CapEff` wider than sixteen digits keeps the capability its last digit sets"
        );
        assert!(
            !report(r"Name:\tHOSTHOME=ABSENT\nNoNewPrivs:\t1\nCapEff:\t0000000000000000\nHOSTHOME=PRESENT\n")
                .host_home_absent,
            "the home answer is the script's own line, not a match inside another one"
        );
    }

    /// What a hardened probe prints, as `printf` words.
    const HARDENED: &str = r"NoNewPrivs:\t1\nCapEff:\t0000000000000000\nHOSTHOME=ABSENT\n";

    /// A shell function, `flood`, that writes 256 lines of a kilobyte each on builtins alone: four
    /// times what a pipe holds, and four times [`PROBE_OUTPUT_CAP`].
    const FLOOD: &str = "flood() { s=xxxxxxxxxxxxxxxx; for j in 1 2 3 4 5 6; do s=$s$s; done; \
                         i=0; while [ $i -lt 256 ]; do echo \"$s\"; i=$((i + 1)); done; }";

    /// A probe that says more on stderr than a pipe holds still answers within its ceiling: the
    /// stream is read while it runs, and what is kept of it stops at the cap. Read only after the
    /// wait, the stand-in would stay blocked writing until the ceiling killed it.
    #[test]
    fn a_probe_that_floods_its_stderr_is_read_while_it_runs() {
        let report = launch_stand_in(&format!("{FLOOD}; flood >&2; printf '{HARDENED}'"))
            .expect("the probe answers within its ceiling");
        assert!(report.is_hardened(), "the answers after the flood are read");
        assert_eq!(
            report.stderr.len(),
            PROBE_OUTPUT_CAP,
            "what is kept of the stream stops at the cap"
        );
    }

    /// The same for stdout, which carries the answers. A test of its own, because a probe left
    /// blocked on the first stream would never reach the second.
    #[test]
    fn a_probe_that_floods_its_stdout_is_read_while_it_runs() {
        let report = launch_stand_in(&format!("{FLOOD}; printf '{HARDENED}'; flood"))
            .expect("the probe answers within its ceiling");
        assert!(
            report.is_hardened(),
            "the answers before the flood are read"
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
