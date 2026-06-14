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
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|cand| is_executable(cand))
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Outcome of probing unprivileged user-namespace support.
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

/// Ground-truth probe in a forked child: create a user namespace, then create a
/// mount namespace inside it. The second step needs `CAP_SYS_ADMIN` in the new
/// userns, so it succeeds only when the namespace is capability-bearing — which
/// is exactly what bubblewrap requires. Doing it in a child keeps the parent's
/// namespaces untouched; only a real attempt is decisive (sysctls can lie).
fn probe_userns() -> Userns {
    // SAFETY: the child path touches only async-signal-safe calls (`unshare`,
    // `_exit`) before exiting; the parent only reaps it.
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
                match libc::WEXITSTATUS(status) {
                    0 => Userns::Ok,
                    2 => Userns::CapStripped,
                    _ => Userns::Unsupported,
                }
            }
        }
    }
}

fn read_sysctl(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}
