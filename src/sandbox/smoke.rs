//! A live preflight: launch a minimal sandbox through the real argv builder and
//! ask the kernel whether the result is actually hardened.
//!
//! `doctor` used to decide the security boundary from a stand-in — a raw
//! `unshare` in a forked child (still kept, as a fast launch gate and a failure
//! classifier). The decisive test is the one sbx itself performs at launch: feed
//! [`super::argv::to_argv`] to the real `bwrap` and read `/proc/self/status` from
//! inside. A successful launch reporting `CapEff=0` and `NoNewPrivs=1` proves the
//! user namespace is capability-bearing more conclusively than the stand-in can —
//! bubblewrap cannot nest the mount and pid namespaces on a cap-stripped userns,
//! so reaching a hardened process at all means every layer worked.
//!
//! The probe binds host `/usr` only to give itself a userland to run in; the
//! hardening it verifies is userland-independent, so this neither needs nor
//! touches nix or the store. Its working directory is a throwaway temp dir,
//! removed on drop, so the check leaves nothing behind on the host.

use super::spec::{Mount, NetPolicy, SandboxSpec};
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

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

/// Launch the minimal hardened probe via `bwrap` and report what the kernel saw.
/// Errors only when the probe could not be run at all (the spec is constant and
/// valid, so a failure is bubblewrap not spawning); a launch that runs but is not
/// hardened is a successful call returning a non-hardened report.
pub(crate) fn run(bwrap: &Path) -> io::Result<SmokeReport> {
    let work = ScratchDir::new()?;

    // Report the kernel's view of our privilege, then whether the host home — a
    // path that must never be visible — leaked into the sandbox.
    let host_home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let script = format!(
        "cat /proc/self/status; printf 'HOSTHOME='; \
         if [ -e '{host_home}' ]; then echo PRESENT; else echo ABSENT; fi",
    );

    let spec = probe_spec(work.path(), script)?;
    // Load the mandatory seccomp filters too, so `doctor` proves the real launch
    // path — hardening *and* filter — works on this host, not just the namespaces.
    // The anonymous files (the filters, and the cage's environment) stay alive
    // until `output` returns, because bwrap reads them at startup.
    let seccomp = super::seccomp::memfds(&spec.seccomp)?;
    let mut argv = super::seccomp::argv_prefix(&seccomp);
    let (spec_argv, env) = super::argv::compose(&spec)?;
    argv.extend(spec_argv);
    let out = Command::new(bwrap).args(argv).output()?;
    drop((seccomp, env));
    let stdout = String::from_utf8_lossy(&out.stdout);

    Ok(SmokeReport {
        launched: out.status.success(),
        no_new_privs: stdout.contains("NoNewPrivs:\t1"),
        caps_dropped: stdout.contains("CapEff:\t0000000000000000"),
        host_home_absent: stdout.contains("HOSTHOME=ABSENT"),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// The canonical minimal hardened spec: host `/usr` bound read-only for a
/// userland, the usual FHS symlinks, fresh proc/dev/tmpfs, and a throwaway rw
/// workdir. The hardening itself is added unconditionally by `to_argv`, so this
/// only supplies the userland the probe runs in.
fn probe_spec(work: &Path, script: String) -> io::Result<SandboxSpec> {
    let mounts = vec![
        Mount::RoBind {
            src: PathBuf::from("/usr"),
            dest: PathBuf::from("/usr"),
        },
        Mount::Symlink {
            target: PathBuf::from("usr/lib"),
            dest: PathBuf::from("/lib"),
        },
        Mount::Symlink {
            target: PathBuf::from("usr/lib64"),
            dest: PathBuf::from("/lib64"),
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
            src: work.to_path_buf(),
            dest: PathBuf::from("/work"),
        },
    ];
    let env = vec![
        ("HOME".to_string(), "/work".to_string()),
        ("PATH".to_string(), "/usr/bin:/bin".to_string()),
        ("TERM".to_string(), "dumb".to_string()),
    ];
    SandboxSpec::new(
        PathBuf::from("/work"),
        mounts,
        env,
        NetPolicy::Shared,
        vec![
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from(script),
        ],
    )
    .map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid probe spec: {e:?}"),
        )
    })
}

/// A process-unique temp dir, removed on drop, so the probe leaves nothing on the
/// host. The pid+counter name is collision-free for the single probe `doctor`
/// runs; a leftover from a crashed run is overwritten, never trusted.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new() -> io::Result<Self> {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut dir = std::env::temp_dir();
        dir.push(format!("sbx-doctor-smoke-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
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

    #[test]
    fn a_real_launch_is_hardened_and_hermetic() {
        let Some(bwrap) = prerequisites() else {
            eprintln!("skipping bwrap smoke: no bwrap or no capability-bearing userns");
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
}
