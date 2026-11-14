//! The host-side step between sbx's resource scope and the cage: move into a cgroup one level below
//! the scope, then become the command.
//!
//! ## Why the cage does not stay in the scope's own cgroup
//!
//! The resource limits are properties of the scope's cgroup (`memory.max`, `pids.max`, …), and the
//! user manager creates that cgroup with this user's ownership. bubblewrap gives the cage a cgroup
//! namespace rooted at the cgroup it starts in. A cage whose seccomp relaxation lets it create a
//! user namespace and mount can then mount a cgroup2 filesystem of its own, which shows that root,
//! and write the scope's limits away: the files belong to the uid the nested namespace maps to
//! root.
//!
//! Started one level down, the cage's cgroup namespace is rooted at a cgroup with no controller
//! enabled, so its own view carries no limit file at all, while the scope above it — outside every
//! view the cage can mount — still bounds it, its processes included.
//!
//! ## Best-effort
//!
//! Resource limits never decide whether a cage starts. A move that fails is reported and the
//! command runs anyway, in the scope's own cgroup, exactly as it would without this step.
//!
//! ## Usage
//!
//! `sbx-cgroup-leaf -- <absolute program> <args…>`

#![cfg_attr(
    not(test),
    warn(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]
#![warn(clippy::undocumented_unsafe_blocks)]

use std::ffi::{CString, OsString};
use std::io::{self, Write as _};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// The name of the cgroup the cage is placed in, below the scope's.
const LEAF: &str = "cage";

/// Exit codes for the two failures that keep the command from running.
mod exit {
    /// The argument vector was not `-- <absolute program> <args…>`.
    pub const USAGE: i32 = 2;
    /// The command could not be executed.
    pub const NOT_EXECUTABLE: i32 = 127;
}

/// Write one line to stderr, dropping it if stderr cannot take it: the exit code is what the
/// launcher reads, and a panic on the write would replace it.
fn say(message: &str) {
    let _ = writeln!(io::stderr(), "sbx-cgroup-leaf: {message}");
}

fn main() {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let command = match args.split_first() {
        Some((sep, command))
            if sep == "--" && command.first().is_some_and(|p| Path::new(p).is_absolute()) =>
        {
            command
        }
        _ => {
            say("usage: sbx-cgroup-leaf -- <absolute program> <args…>");
            std::process::exit(exit::USAGE)
        }
    };
    if let Err(e) = enter_leaf(Path::new("/proc/self/cgroup"), Path::new("/sys/fs/cgroup")) {
        say(&format!(
            "the cage stays in its resource scope's own cgroup, where a cage allowed to mount \
             can change its limits: {e}"
        ));
    }
    exec(command)
}

/// The cgroup v2 directory this process is in, read from `cgroup_file` (the `0::<path>` line) and
/// resolved under `cgroupfs`.
fn own_cgroup(cgroup_file: &Path, cgroupfs: &Path) -> io::Result<PathBuf> {
    let text = std::fs::read_to_string(cgroup_file)?;
    let relative = text
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| io::Error::other("no cgroup v2 entry in /proc/self/cgroup"))?;
    // A path the kernel prints for a cgroup outside this process's cgroup namespace starts with
    // `/..`; nothing below such a path is this process's to create.
    if relative.split('/').any(|part| part == "..") {
        return Err(io::Error::other(format!(
            "the cgroup {relative} is outside this namespace"
        )));
    }
    Ok(cgroupfs.join(relative.trim_start_matches('/')))
}

/// Create [`LEAF`] below this process's cgroup and move this process into it.
fn enter_leaf(cgroup_file: &Path, cgroupfs: &Path) -> io::Result<()> {
    let leaf = own_cgroup(cgroup_file, cgroupfs)?.join(LEAF);
    match std::fs::create_dir(&leaf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    std::fs::write(leaf.join("cgroup.procs"), std::process::id().to_string())
}

/// `execv` the command, replacing this process. Returns only on failure.
fn exec(command: &[OsString]) -> ! {
    let args: Vec<CString> = command
        .iter()
        .filter_map(|a| CString::new(a.as_bytes()).ok())
        .collect();
    if args.len() != command.len() {
        say("an argument contains a NUL byte");
        std::process::exit(exit::USAGE);
    }
    let mut ptrs: Vec<*const libc::c_char> = args.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: `args` holds `args.len() >= 1` NUL-terminated strings (the usage check requires a
    // program), `ptrs` points into them and ends with a null pointer, and both outlive the call,
    // which returns only on failure.
    unsafe { libc::execv(args[0].as_ptr(), ptrs.as_ptr()) };
    say(&format!(
        "cannot execute {}: {}",
        command[0].to_string_lossy(),
        io::Error::last_os_error()
    ));
    std::process::exit(exit::NOT_EXECUTABLE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_leaf_is_created_below_the_cgroup_named_in_the_v2_line() {
        let root = std::env::temp_dir().join(format!("sbx-cgroup-leaf-{}", std::process::id()));
        let scope = root.join("user.slice/app.slice/sbx-demo-0-42.scope");
        std::fs::create_dir_all(&scope).unwrap();
        let file = root.join("cgroup");
        std::fs::write(&file, "0::/user.slice/app.slice/sbx-demo-0-42.scope\n").unwrap();

        enter_leaf(&file, &root).unwrap();
        let written = std::fs::read_to_string(scope.join(LEAF).join("cgroup.procs")).unwrap();
        assert_eq!(written, std::process::id().to_string());

        std::fs::write(&file, "0::/../escape\n").unwrap();
        assert!(
            enter_leaf(&file, &root).is_err(),
            "a path outside the namespace is refused"
        );
        std::fs::write(&file, "1:name=systemd:/x\n").unwrap();
        assert!(enter_leaf(&file, &root).is_err(), "no v2 line, no leaf");
        std::fs::remove_dir_all(&root).unwrap();
    }
}
