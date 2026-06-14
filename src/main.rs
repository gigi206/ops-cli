//! ops — sandbox launcher (bubblewrap + daemonless nix).
//!
//! This is the M0 entry point. For now it exposes a single `doctor` preflight
//! that verifies the load-bearing runtime requirements before anything else can
//! run. Unprivileged user namespaces are the requirement everything else rests
//! on: without them there is no security boundary at all, so their absence is a
//! hard failure with remediation — never a silent fallback to a weaker engine.

use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("doctor") => doctor(),
        Some(other) => {
            eprintln!("ops: unknown command '{other}' (only 'doctor' exists at this stage)");
            ExitCode::from(2)
        }
        None => {
            eprintln!("ops: usage: ops doctor");
            ExitCode::from(2)
        }
    }
}

/// Report the runtime prerequisites and fail hard if a load-bearing one is
/// missing.
fn doctor() -> ExitCode {
    println!("ops doctor — runtime preflight\n");

    let mut hard_fail = false;

    // The sandbox engine itself.
    match find_on_path("bwrap") {
        Some(p) => println!("  [ ok ] bubblewrap        {}", p.display()),
        None => {
            println!("  [FAIL] bubblewrap        not found on PATH");
            hard_fail = true;
        }
    }

    // The security boundary. A real attempt is the only decisive test; the
    // sysctls below are advisory context for the remediation hint.
    match probe_userns() {
        Userns::Ok => {
            println!("  [ ok ] user namespaces   capability-bearing unprivileged namespace")
        }
        Userns::Unsupported => {
            println!("  [FAIL] user namespaces   cannot create one without privilege");
            hard_fail = true;
        }
        Userns::CapStripped => {
            println!(
                "  [FAIL] user namespaces   created but stripped of capabilities (restricted)"
            );
            hard_fail = true;
        }
    }
    if let Some(v) = read_sysctl("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") {
        println!("         · kernel.apparmor_restrict_unprivileged_userns = {v}");
    }
    if let Some(v) = read_sysctl("/proc/sys/kernel/unprivileged_userns_clone") {
        println!("         · kernel.unprivileged_userns_clone = {v}");
    }

    println!();
    if hard_fail {
        eprintln!("ops: missing prerequisite — ops CANNOT run without capability-bearing");
        eprintln!(
            "     unprivileged user namespaces (no security boundary otherwise; no fallback)."
        );
        eprintln!("     Possible remediation (distro-dependent, needs root once):");
        eprintln!("       • sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0");
        eprintln!("       • or an AppArmor profile allowing unprivileged userns for ops");
        ExitCode::FAILURE
    } else {
        println!("ops: prerequisites OK.");
        ExitCode::SUCCESS
    }
}

/// Search `$PATH` for an executable file with the given name.
fn find_on_path(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    find_in_dirs(name, std::env::split_paths(&path))
}

/// Pure core of [`find_on_path`]: the first directory whose `name` entry is
/// executable. Split out so it can be tested without mutating the process `PATH`.
fn find_in_dirs(
    name: &str,
    dirs: impl Iterator<Item = std::path::PathBuf>,
) -> Option<std::path::PathBuf> {
    dirs.map(|dir| dir.join(name))
        .find(|cand| is_executable(cand))
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Outcome of probing unprivileged user-namespace support.
#[derive(Debug, PartialEq, Eq)]
enum Userns {
    /// A capability-bearing user namespace can be created — bwrap will work.
    Ok,
    /// `unshare(CLONE_NEWUSER)` itself fails — userns disabled outright.
    Unsupported,
    /// The namespace is created but stripped of capabilities (the restricted
    /// Ubuntu 24.04+ default): `unshare(CLONE_NEWUSER)` succeeds, yet the child
    /// cannot create the further namespaces bwrap needs. It looks available but
    /// is not — so it must be reported distinctly from outright absence.
    CapStripped,
}

/// Map the probe child's exit status to an outcome. Kept separate from the
/// unsafe fork machinery so this policy is unit-testable: the child exits `1`
/// when the user namespace cannot be created, `2` when it is created but lacks
/// the capabilities to nest a mount namespace, and `0` when both succeed.
fn classify_probe_exit(code: i32) -> Userns {
    match code {
        0 => Userns::Ok,
        2 => Userns::CapStripped,
        _ => Userns::Unsupported,
    }
}

/// Ground-truth probe in a forked child: create a user namespace, then create a
/// mount namespace inside it. The second step needs `CAP_SYS_ADMIN` in the new
/// userns, so it succeeds only when the namespace is capability-bearing — which
/// is exactly what bubblewrap requires. Doing it in a child keeps the parent's
/// namespaces untouched; only a real attempt is decisive (sysctls can lie).
fn probe_userns() -> Userns {
    // SAFETY: the child path touches only async-signal-safe calls (`unshare`,
    // `_exit`) before exiting; the parent only reaps it and classifies.
    unsafe {
        match libc::fork() {
            0 => {
                if libc::unshare(libc::CLONE_NEWUSER) != 0 {
                    libc::_exit(1);
                }
                if libc::unshare(libc::CLONE_NEWNS) != 0 {
                    libc::_exit(2);
                }
                libc::_exit(0);
            }
            -1 => Userns::Unsupported,
            pid => {
                let mut status: libc::c_int = 0;
                if libc::waitpid(pid, &mut status, 0) == -1 || !libc::WIFEXITED(status) {
                    return Userns::Unsupported;
                }
                classify_probe_exit(libc::WEXITSTATUS(status))
            }
        }
    }
}

fn read_sysctl(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// A fresh, unique temp directory per call (no external test-helper deps).
    fn tmpdir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut d = std::env::temp_dir();
        d.push(format!("ops-doctor-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write_exec(path: &Path) {
        std::fs::write(path, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn is_executable_reads_mode_bits() {
        let dir = tmpdir();
        let exe = dir.join("runme");
        write_exec(&exe);
        assert!(is_executable(&exe));

        let plain = dir.join("data");
        std::fs::write(&plain, b"x").unwrap();
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!is_executable(&plain));

        assert!(!is_executable(&dir.join("missing")));
    }

    #[test]
    fn find_in_dirs_picks_first_executable_match() {
        let a = tmpdir();
        let b = tmpdir();
        let tool = b.join("tool");
        write_exec(&tool);

        // present only in `b`, and executable
        let found = find_in_dirs("tool", [a.clone(), b.clone()].into_iter());
        assert_eq!(found.as_deref(), Some(tool.as_path()));

        // absent everywhere
        assert!(find_in_dirs("absent", [a, b].into_iter()).is_none());
    }

    #[test]
    fn read_sysctl_trims_value_and_handles_absence() {
        let dir = tmpdir();
        let f = dir.join("val");
        std::fs::write(&f, b"1\n").unwrap();
        assert_eq!(read_sysctl(f.to_str().unwrap()).as_deref(), Some("1"));
        assert_eq!(read_sysctl(dir.join("nope").to_str().unwrap()), None);
    }

    #[test]
    fn classify_probe_exit_maps_status_to_outcome() {
        assert_eq!(classify_probe_exit(0), Userns::Ok);
        assert_eq!(classify_probe_exit(2), Userns::CapStripped);
        assert_eq!(classify_probe_exit(1), Userns::Unsupported);
        assert_eq!(classify_probe_exit(42), Userns::Unsupported);
    }
}
