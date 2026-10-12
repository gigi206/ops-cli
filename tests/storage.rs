//! `sbx storage` end to end.
//!
//! `sbx storage init` on a host without `btrfs-progs`, where sbx formats the volume with a copy it
//! provisions for itself. Where that copy is built decides whether the data directory can still
//! adopt the volume: a `store` left in it reads as data `sbx storage use` would strand, and `use`
//! refuses. Skipped, not failed, where the host cannot run the provisioned copy or the binary cache
//! is out of reach.
//!
//! The first interactive launch on a host a volume is worth it on, which adopts one without asking,
//! and keeps the plain directory when the volume cannot be set up. `udisksctl` and `mkfs.btrfs` are
//! stand-ins there, so no loop device is attached and nothing is mounted. Skipped where the host is
//! not one a volume is adopted on.

#[macro_use]
mod common;
use common::fixture::TmpDir;
use common::pty::{Pty, Reaped};

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// A `PATH` of one directory under `root`, linking the programs a volume creation provisions with,
/// as the inherited `PATH` finds them, and no `mkfs.btrfs`, so sbx has to build its own. Leaving out
/// whole directories of the host's would take whatever else they hold with them: a runner may keep
/// `bwrap` beside its `mkfs.btrfs`.
fn path_without_mkfs_btrfs(root: &Path) -> PathBuf {
    let dir = root.join("bin");
    std::fs::create_dir_all(&dir).unwrap();
    let inherited = std::env::var_os("PATH").unwrap_or_default();
    for name in ["nix", "nix-store", "bwrap"] {
        if let Some(found) = common::program_in(name, &inherited) {
            std::os::unix::fs::symlink(found, dir.join(name)).unwrap();
        }
    }
    dir
}

#[test]
fn a_volume_formatted_with_provisioned_btrfs_progs_leaves_the_data_directory_adoptable() {
    let root = TmpDir::prefixed("st", "noprogs");
    let data_home = root.join("data");
    let image = root.join("img/x.btrfs");
    // A directory of the user's own beside the image, under the name a store built beside the
    // image would take.
    let theirs = root.join("img/x.tools/keep");
    std::fs::create_dir_all(&theirs).unwrap();
    std::fs::write(theirs.join("file"), b"theirs").unwrap();

    // Built once: the probe runs its launch a second time after a download failure.
    let path = path_without_mkfs_btrfs(root.path());
    let out = probe_or_skip!(
        "storage init without btrfs-progs",
        common::isolated_sbx("st-")
            .args(["storage", "init", "--size", "2G", "--image"])
            .arg(&image)
            .env("PATH", &path)
            .env("XDG_DATA_HOME", &data_home)
            .env_remove("SBX_DATA_DIR")
            .output()
            .expect("spawn sbx storage init")
    );
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        said.contains("formatting with sbx's own btrfs-progs"),
        "the volume was not formatted with the copy sbx provisions: {said}"
    );
    assert!(image.is_file(), "no image was created: {said}");

    let data = data_home.join("sbx");
    assert!(
        data.join("store").symlink_metadata().is_err(),
        "the provisioned btrfs-progs was built into the data directory's store, which `sbx \
         storage use` then refuses to strand"
    );
    assert!(
        data.join("storage-tools").symlink_metadata().is_err(),
        "the store btrfs-progs was built into outlived the format"
    );
    assert_eq!(
        std::fs::read(theirs.join("file")).ok().as_deref(),
        Some(&b"theirs"[..]),
        "a directory beside the image that sbx did not create was removed"
    );
}

/// Install a stand-in for the host program `name` in `dir`: a script that appends its arguments to
/// `log`, one call per line, and exits `status` after printing `stderr` there.
///
/// Written by a child shell, so the descriptor that writes it is never open in this process: a test
/// running beside this one that forked while it was would hold it across its own `exec`, and the
/// stand-in would then fail to run as a busy text file.
fn stand_in(dir: &Path, name: &str, log: &Path, status: i32, stderr: &str) {
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {log}\nprintf '%s\\n' {stderr} >&2\nexit {status}\n",
        log = common::sh(log),
        stderr = common::sh_word(stderr),
    );
    install_script(&dir.join(name), &script);
}

/// Write `script` to `path` as an executable, from a child shell for the reason [`stand_in`] gives.
fn install_script(path: &Path, script: &str) {
    let written = std::process::Command::new("/bin/sh")
        .args([
            "-c",
            "printf '%s' \"$1\" > \"$2\" && chmod 755 \"$2\"",
            "sh",
        ])
        .arg(script)
        .arg(path)
        .status()
        .expect("spawn /bin/sh");
    assert!(written.success(), "writing the stand-in {}", path.display());
}

/// The host programs a first-launch adoption runs, as stand-ins in `root/bin`, every call recorded
/// in `root/calls.log`: a format that succeeds without writing anything, and an attach udisks
/// refuses, as it does outside a local active session, so the volume is created and never mounted.
/// Returns the directory to put on `PATH` and the log.
fn adoption_stand_ins(root: &Path) -> (PathBuf, PathBuf) {
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let calls = root.join("calls.log");
    stand_in(&bin, "mkfs.btrfs", &calls, 0, "");
    stand_in(
        &bin,
        "udisksctl",
        &calls,
        1,
        "Error setting up loop device: Not authorized to perform operation",
    );
    (bin, calls)
}

/// Launch `sbx run` on a terminal, with `bin` as the whole `PATH` and `data_home` as the data home,
/// and read the terminal until it exits, never past a minute. The launch stops on its configuration
/// before it builds anything, so all it does is the first-launch step.
///
/// A question on the terminal is a failure here: nothing answers it, so waiting would only wait out
/// the minute. Returns whether it exited, and what it wrote.
fn first_launch(project: &Path, bin: &Path, data_home: &Path) -> (bool, String) {
    let mut pty = Pty::open(None);
    let mut child = Reaped(
        common::isolated_sbx("st-")
            .args(["run", "--config", "x = = not toml", "--", "true"])
            .current_dir(project)
            .env("PATH", bin)
            .env("XDG_DATA_HOME", data_home)
            .env_remove("SBX_DATA_DIR")
            .env_remove("SSH_CONNECTION")
            .env_remove("SSH_TTY")
            .stdin(pty.stdio())
            .stdout(pty.stdio())
            .stderr(pty.stdio())
            .spawn()
            .expect("spawn sbx run on a terminal"),
    );
    pty.release_slave();

    let mut out = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    let exited = loop {
        pty.read_into(&mut out, 300);
        assert!(
            !String::from_utf8_lossy(&out).contains("[y/N]"),
            "the first launch asked instead of adopting: {}",
            String::from_utf8_lossy(&out)
        );
        if child.0.try_wait().expect("poll sbx run").is_some() {
            for _ in 0..10 {
                if !pty.read_into(&mut out, 100) {
                    break;
                }
            }
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
    };
    (exited, String::from_utf8_lossy(&out).into_owned())
}

#[test]
fn a_first_interactive_launch_adopts_a_volume_without_asking_and_keeps_the_plain_directory_when_it_cannot()
 {
    let root = TmpDir::prefixed("st", "first");
    let data_home = root.join("data");
    let project = root.join("proj");
    std::fs::create_dir_all(&project).unwrap();
    let (bin, calls) = adoption_stand_ins(root.path());

    let (exited, said) = first_launch(&project, &bin, &data_home);
    assert!(exited, "the launch did not end within a minute: {said}");

    let data = data_home.join("sbx");
    if !data.join(".storage-offered").exists() {
        skip_incapable!(
            "skipping first-launch adoption: this host is not one a volume is adopted on ({said})"
        );
        return;
    }
    let calls = std::fs::read_to_string(&calls).unwrap_or_default();
    assert!(
        calls.lines().any(|c| c.starts_with("loop-setup")),
        "the volume was never attached; the stand-ins saw {calls:?}: {said}"
    );
    assert!(
        !data.join("storage.toml").exists(),
        "a volume that never mounted was adopted: {said}"
    );
    assert!(
        said.contains("continuing on the plain data directory"),
        "the launch did not say it kept the plain directory: {said}"
    );
    assert!(
        data_home
            .join("sbx-storage.btrfs")
            .symlink_metadata()
            .is_err(),
        "the volume that could not be set up stayed behind, where `sbx storage init` meets it: \
         {said}"
    );
}

/// A storage verb run by hand settles where the data lives, so the first interactive launch after
/// it adopts nothing: after `sbx storage unuse`, a volume adopted there would undo what was just
/// asked for. Gated on a launch in a second, untouched data home adopting one, so a host where no
/// launch would cannot pass this by doing nothing.
#[test]
fn a_storage_verb_run_by_hand_settles_the_first_launch() {
    let root = TmpDir::prefixed("st", "byhand");
    let project = root.join("proj");
    std::fs::create_dir_all(&project).unwrap();
    let (bin, calls) = adoption_stand_ins(root.path());

    let untouched = root.join("untouched");
    let (exited, said) = first_launch(&project, &bin, &untouched);
    assert!(exited, "the launch did not end within a minute: {said}");
    if !untouched.join("sbx/.storage-offered").exists() {
        skip_incapable!(
            "skipping first-launch adoption: this host is not one a volume is adopted on ({said})"
        );
        return;
    }

    let data_home = root.join("data");
    let unuse = common::isolated_sbx("st-")
        .args(["storage", "unuse"])
        .env("XDG_DATA_HOME", &data_home)
        .env_remove("SBX_DATA_DIR")
        .output()
        .expect("spawn sbx storage unuse");
    assert!(
        unuse.status.success(),
        "{}",
        String::from_utf8_lossy(&unuse.stderr)
    );
    std::fs::remove_file(&calls).unwrap();

    let (exited, said) = first_launch(&project, &bin, &data_home);
    assert!(exited, "the launch did not end within a minute: {said}");
    assert_eq!(
        std::fs::read_to_string(&calls).unwrap_or_default(),
        "",
        "the first launch after `sbx storage unuse` set up a volume: {said}"
    );
    assert!(
        data_home
            .join("sbx-storage.btrfs")
            .symlink_metadata()
            .is_err(),
        "the first launch after `sbx storage unuse` created a volume: {said}"
    );
}

/// A volume created by hand with `sbx storage init` is not adopted by the next interactive launch:
/// nothing changes until `sbx storage use`. Without the record `init` leaves, the launch would find
/// the image and attach it. Gated on a launch in an untouched data home adopting one, as above.
#[test]
fn a_volume_created_by_hand_waits_for_use_rather_than_the_first_launch() {
    let root = TmpDir::prefixed("st", "byinit");
    let project = root.join("proj");
    std::fs::create_dir_all(&project).unwrap();
    let (bin, calls) = adoption_stand_ins(root.path());

    let untouched = root.join("untouched");
    let (exited, said) = first_launch(&project, &bin, &untouched);
    assert!(exited, "the launch did not end within a minute: {said}");
    if !untouched.join("sbx/.storage-offered").exists() {
        skip_incapable!(
            "skipping first-launch adoption: this host is not one a volume is adopted on ({said})"
        );
        return;
    }

    let data_home = root.join("data");
    let init = common::isolated_sbx("st-")
        .args(["storage", "init", "--size", "2G"])
        .env("PATH", &bin)
        .env("XDG_DATA_HOME", &data_home)
        .env_remove("SBX_DATA_DIR")
        .output()
        .expect("spawn sbx storage init");
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let image = data_home.join("sbx-storage.btrfs");
    assert!(image.is_file(), "`sbx storage init` created no image");
    std::fs::remove_file(&calls).unwrap();

    let (exited, said) = first_launch(&project, &bin, &data_home);
    assert!(exited, "the launch did not end within a minute: {said}");
    let calls = std::fs::read_to_string(&calls).unwrap_or_default();
    assert!(
        !calls.lines().any(|c| c.starts_with("loop-setup")),
        "the first launch attached the volume `sbx storage init` created: {said}"
    );
    assert!(
        image.is_file(),
        "the first launch removed the volume `sbx storage init` created: {said}"
    );
}

/// A `udisksctl` stand-in whose `loop-setup` attaches `/dev/loop99` and whose `mount` runs
/// `mount`, every call recorded in `log`; any other subcommand succeeds.
fn udisks_stand_in(dir: &Path, log: &Path, mount: &str) {
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {log}\ncase \"$1\" in\n\
         loop-setup) printf 'Mapped file %s as /dev/loop99.\\n' \"$3\" ;;\n\
         mount) {mount} ;;\nesac\n",
        log = common::sh(log),
    );
    install_script(&dir.join("udisksctl"), &script);
}

/// `sbx storage up` that attached a loop device and then could not mount it, or mounted it where
/// this process cannot see it, leaves no loop device behind: udisks attaches without autoclear
/// (measured: `/sys/block/loopN/loop/autoclear` reads 0, and the device stays attached), so a device
/// nothing releases stays until `down`. A mount this call made is undone first; one it did not make,
/// because `mount` failed, is not touched.
#[test]
fn an_up_that_cannot_mount_releases_the_loop_device_it_attached() {
    let root = TmpDir::prefixed("st", "upfail");
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let image = root.join("vol.btrfs");
    std::fs::write(&image, b"").unwrap();

    let mut wrong = Vec::new();
    for (shape, mount, unmounts) in [
        (
            "a mount that fails",
            "echo 'Error mounting /dev/loop99: wrong fs type' >&2; exit 1",
            false,
        ),
        (
            "a mount report that cannot be read",
            "echo 'something else'",
            true,
        ),
        (
            "a mount this process cannot see",
            "echo 'Mounted /dev/loop99 at /run/media/u/vol.'",
            true,
        ),
    ] {
        let calls = root.join(format!("calls-{}.log", shape.replace(' ', "-")));
        udisks_stand_in(&bin, &calls, mount);
        let out = common::isolated_sbx("st-")
            .args(["storage", "up", "--image"])
            .arg(&image)
            .env("PATH", &bin)
            .env("XDG_DATA_HOME", root.join("data"))
            .env_remove("SBX_DATA_DIR")
            .output()
            .expect("spawn sbx storage up");
        let said = String::from_utf8_lossy(&out.stderr).into_owned();
        if said.contains("this host cannot mount") {
            skip_incapable!("skipping: this host cannot mount a volume ({said})");
            return;
        }
        let calls = std::fs::read_to_string(&calls).unwrap_or_default();
        if out.status.success() {
            wrong.push(format!("{shape}: `up` succeeded: {said}"));
        }
        if !calls.lines().any(|c| c == "loop-delete -b /dev/loop99") {
            wrong.push(format!(
                "{shape}: the loop device was left attached: {calls:?}"
            ));
        }
        if calls.lines().any(|c| c == "unmount -b /dev/loop99") != unmounts {
            wrong.push(format!(
                "{shape}: unmounted {}, as a mount this call {} made: {calls:?}",
                if unmounts { "nothing" } else { "a device" },
                if unmounts { "had" } else { "had not" }
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
