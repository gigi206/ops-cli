//! Integration tests for `sbx upgrade`, exercising the built binary end to end.

#[macro_use]
mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

fn sbx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sbx"))
}

/// Where this suite's throwaway fixtures live: the repo's own test tree, overridable with
/// `SBX_TEST_TMPDIR`.
///
/// Deliberately **not** `std::env::temp_dir()`, which resolves to `/tmp` when `TMPDIR` is unset. A
/// fixture here may hold a provisioned nix store, which is inode-heavy enough to exhaust a tmpfs's
/// machine-wide inode budget — surfacing as "no space left on device" in *unrelated* work while the
/// disk is nearly empty. Disk has inodes to spare, it matches production (the store lives on disk),
/// and it is reclaimed by removing that tree.
fn fixture_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("SBX_TEST_TMPDIR") {
        return PathBuf::from(dir);
    }
    // Outside the workspace by default, and that is the point rather than an accident: a language
    // server watching the repository spends one inotify watch per directory, one run of this suite
    // leaves hundreds of thousands of them, and the machine's `max_user_watches` is what runs out.
    // Still on disk rather than a tmpfs, whose fixed inode budget a provisioned nix store exhausts.
    // Falls back inside the workspace only when neither variable names a home to use.
    let mut d = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target"));
    d.push("sbx/test-tmp");
    d
}

/// A unique temp dir removed on drop, so the binary's lock writes land in a throwaway
/// location instead of the real `$HOME`.
struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut d = fixture_root();
        d.push(format!("upg-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        TmpDir(d)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        force_remove(&self.0);
    }
}

/// Remove a tree that may contain read-only directories: a provisioned nix store
/// makes its directories `0555`, so add write on the way down before deleting.
fn force_remove(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_dir() {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                force_remove(&entry.path());
            }
        }
        let _ = std::fs::remove_dir(path);
    } else {
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn upgrade_rejects_an_unknown_target() {
    // The target is parsed before anything else, so this needs neither nix nor a data
    // directory.
    let out = sbx()
        .args(["upgrade", "bogus"])
        .output()
        .expect("spawn sbx upgrade");
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("unknown upgrade target"),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The revision the per-project flake lock records for `reference`, if any. The lock lives under
/// the single project's directory; each line is `<reference>\t<rev>\t<locked-ref>`.
fn flake_lock_rev(data: &Path, reference: &str) -> Option<String> {
    let projects = data.join("sbx").join("projects");
    for entry in std::fs::read_dir(&projects).ok()?.flatten() {
        let lock = entry.path().join("flake-packages.lock");
        if let Ok(text) = std::fs::read_to_string(&lock) {
            for line in text.lines() {
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.first() == Some(&reference) {
                    return parts.get(1).map(|s| s.to_string());
                }
            }
        }
    }
    None
}

#[test]
fn upgrade_flake_pins_and_locks_a_declared_flake_package() {
    // A real resolution of a declared `flake:` package: `sbx upgrade flake` resolves the floating
    // reference to its current immutable revision with `nix flake metadata` and writes the
    // per-project flake lock — a host-side lock rewrite (the new pin builds in-cage at the next
    // launch). Teeth: the lock records a 40-hex revision for the declared reference, and a second
    // run moments later re-resolves to the *same* revision ("unchanged" — idempotent). Needs nix
    // and the network (github); skipped (not failed) where the resolution cannot run.
    let data = TmpDir::new();
    let proj = TmpDir::new();
    let state = TmpDir::new();
    let reference = "github:numtide/flake-utils";
    std::fs::write(
        proj.path().join(".sbx.toml"),
        format!("[packages]\nfutil = \"flake:{reference}\"\n"),
    )
    .unwrap();

    // The flake package is a trusted-only field, so the project must be trusted to be rolled.
    let trusted = sbx()
        .args(["trust", ".sbx.toml"])
        .current_dir(proj.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", state.path())
        .output()
        .expect("spawn sbx trust");
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    let run = || {
        sbx()
            .args(["upgrade", "flake"])
            .current_dir(proj.path())
            .env("XDG_DATA_HOME", data.path())
            .env("XDG_STATE_HOME", state.path())
            .output()
            .expect("spawn sbx upgrade flake")
    };

    let first = run();
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&first.stderr),
        String::from_utf8_lossy(&first.stdout)
    );
    if !first.status.success() || log.contains("re-resolve failed") {
        skip_incapable!("skipping flake upgrade resolution: {log}");
        return;
    }
    assert!(
        String::from_utf8_lossy(&first.stdout).contains("newly pinned"),
        "a first resolution must pin the flake package:\n{log}"
    );

    let rev1 = flake_lock_rev(data.path(), reference)
        .expect("the flake lock must record a revision for the declared reference");
    assert!(
        rev1.len() == 40 && rev1.bytes().all(|b| b.is_ascii_hexdigit()),
        "the lock revision must be 40-hex, got {rev1}"
    );

    // `sbx config show` surfaces the pin the upgrade just wrote — host-side, no nix, no network.
    // This is the make-or-break for the display: the lock key the upgrade wrote must be the
    // locator the view looks up by, or no rev would ever show. The project is trusted, so the
    // flake package is admitted (not withheld).
    let shown = sbx()
        .args(["config", "show"])
        .current_dir(proj.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", state.path())
        .output()
        .expect("spawn sbx config show");
    assert!(
        shown.status.success(),
        "sbx config show failed: {}",
        String::from_utf8_lossy(&shown.stderr)
    );
    let out = String::from_utf8_lossy(&shown.stdout);
    let short = &rev1[..7];
    assert!(
        out.contains(&format!("futil -> flake:{reference}"))
            && out.contains(&format!("@ {short}"))
            && out.contains("pinned"),
        "sbx config show must display the pinned flake revision {short}:\n{out}"
    );

    // A second upgrade moments later resolves the same HEAD — an idempotent no-op.
    let again = run();
    assert!(again.status.success());
    assert!(
        String::from_utf8_lossy(&again.stdout).contains("unchanged"),
        "a repeat flake upgrade should be unchanged:\n{}",
        String::from_utf8_lossy(&again.stdout)
    );
    assert_eq!(
        flake_lock_rev(data.path(), reference).unwrap(),
        rev1,
        "an idempotent re-resolution keeps the same revision"
    );
}

#[test]
fn upgrade_resolves_and_locks_the_default_channel() {
    // A real resolution of the rolling channel: needs nix and the network. Skipped
    // (not failed) where the first `sbx upgrade` cannot run.
    let data = TmpDir::new();
    let proj = TmpDir::new();
    let run = || {
        sbx()
            .args(["upgrade", "nix"])
            .current_dir(proj.path())
            .env("XDG_DATA_HOME", data.path())
            .output()
            .expect("spawn sbx upgrade")
    };

    let first = run();
    if !first.status.success() {
        skip_incapable!(
            "skipping upgrade resolution: {}",
            String::from_utf8_lossy(&first.stderr)
        );
        return;
    }
    let stdout = String::from_utf8_lossy(&first.stdout);
    assert!(stdout.contains("channel"), "stdout:\n{stdout}");
    assert!(
        stdout.contains("first pin"),
        "a first resolution must say so:\n{stdout}"
    );
    // the first resolution writes the global lock
    assert!(
        data.path().join("sbx/nixpkgs.lock").is_file(),
        "upgrade must write the global lock"
    );

    // a second upgrade moments later finds the same channel HEAD — an explicit no-op
    let again = run();
    assert!(again.status.success());
    assert!(
        String::from_utf8_lossy(&again.stdout).contains("already at the latest"),
        "a repeat upgrade should be a no-op:\n{}",
        String::from_utf8_lossy(&again.stdout)
    );
}

/// Write an app profile at `<config>/sbx/apps/<name>.toml` — an imported profile, trusted by
/// location, so its packages are admitted without a trust gate standing in the way.
fn write_profile(config_home: &Path, name: &str, body: &str) {
    let dir = config_home.join("sbx/apps");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{name}.toml")), body).unwrap();
}

fn app_upgrade(config: &Path, data: &Path, proj: &Path, name: &str) -> std::process::Output {
    sbx()
        .args(["app", "upgrade", name])
        .current_dir(proj)
        .env("XDG_CONFIG_HOME", config)
        .env("XDG_DATA_HOME", data)
        .env("LC_ALL", "C.UTF-8")
        .output()
        .expect("spawn sbx app upgrade")
}

/// The routing case, which is what sixteen of the shipped profiles are: every package the app rides
/// is pinned in a project-wide lock, so the verb names the channel that advances it and rolls
/// nothing itself.
///
/// The load-bearing half is the negative one. A per-app verb that quietly rewrote the project's
/// `nix:` lock would look identical in a test that only checked the exit code, and would advance
/// every other app in the project under a command that reads as "only this one". So this asserts
/// that neither in-cage roll announced itself, and that the run needed no nix at all — it completes
/// where `sbx upgrade nix` would have to be skipped for want of one.
#[test]
fn app_upgrade_names_the_project_wide_channels_and_rolls_nothing_itself() {
    let (config, data, proj) = (TmpDir::new(), TmpDir::new(), TmpDir::new());
    write_profile(
        config.path(),
        "reader",
        "cmd = [\"reader\"]\n\
         [packages]\n\
         reader = \"deb:https://example.invalid/reader.deb\"\n\
         toolkit = \"nix:hello\"\n",
    );

    let out = app_upgrade(config.path(), data.path(), proj.path(), "reader");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout:\n{stdout}");
    assert!(stdout.contains("sbx app upgrade — reader"), "{stdout}");
    // Both channels named, each with the command that rolls it.
    assert!(stdout.contains("`deb:`, `nix:`"), "{stdout}");
    assert!(
        stdout.contains("`sbx upgrade deb`, `sbx upgrade nix`"),
        "{stdout}"
    );
    assert!(stdout.contains("not with one app"), "{stdout}");
    // And nothing was rolled: neither in-cage roll prints its header.
    assert!(
        !stdout.contains("mise packages") && !stdout.contains("install steps"),
        "a project-wide-only app builds no cage:\n{stdout}"
    );
}

/// The two refusals a name can earn, each with its own answer and its own exit code.
#[test]
fn app_upgrade_refuses_a_name_that_is_not_a_launchable_app() {
    let (config, data, proj) = (TmpDir::new(), TmpDir::new(), TmpDir::new());
    write_profile(config.path(), "ghost", "[packages]\nx = \"nix:hello\"\n");

    // A name no app carries — the typo, pointed at the listing.
    let unknown = app_upgrade(config.path(), data.path(), proj.path(), "nope");
    assert_eq!(unknown.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&unknown.stderr);
    assert!(stderr.contains("no app named `nope`"), "{stderr}");
    assert!(stderr.contains("sbx app ls"), "{stderr}");
    // The verb names itself, not the channel command it shares the sentence with.
    assert!(stderr.contains("sbx: app upgrade:"), "{stderr}");

    // An app with no command never launches, so there is no cage to roll anything in.
    let dead = app_upgrade(config.path(), data.path(), proj.path(), "ghost");
    assert_eq!(dead.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&dead.stderr);
    assert!(stderr.contains("declares no command"), "{stderr}");
}

/// An app that declares nothing at all says so, rather than printing a header and exiting 0 —
/// which would read as a roll that happened.
#[test]
fn app_upgrade_says_when_an_app_declares_nothing_to_advance() {
    let (config, data, proj) = (TmpDir::new(), TmpDir::new(), TmpDir::new());
    write_profile(config.path(), "bare", "cmd = [\"bare\"]\n");

    let out = app_upgrade(config.path(), data.path(), proj.path(), "bare");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout:\n{stdout}");
    assert!(stdout.contains("nothing to advance"), "{stdout}");
}

/// A routing answer is complete even when the data directory is unusable.
///
/// The property under test is that the answer does **not depend on the store**: sixteen of the
/// shipped profiles roll nothing at all, and for them this verb is a question about where their
/// packages advance, which the config alone answers. Pinned against a directory sbx refuses (too
/// long to hold a Unix socket path), so a change that made the routing path reach for the store
/// would turn a clean reply into a failure here.
///
/// It deliberately does **not** assert the refusal is silent. `config::load` resolves the data
/// directory to discover resolver plugins, so every verb that loads config reports an unusable one
/// once; that is the product's existing behaviour, not this verb's, and asserting otherwise would
/// pin a claim the binary does not make.
#[test]
fn a_routing_answer_survives_an_unusable_data_directory() {
    let (config, data, proj) = (TmpDir::new(), TmpDir::new(), TmpDir::new());
    write_profile(
        config.path(),
        "reader",
        "cmd = [\"reader\"]\n[packages]\nreader = \"nix:hello\"\n",
    );
    // Past the 74-byte cap the socket paths impose.
    let long = data.path().join("d".repeat(80));
    std::fs::create_dir_all(&long).unwrap();

    let run = |args: &[&str]| {
        sbx()
            .args(args)
            .current_dir(proj.path())
            .env("XDG_CONFIG_HOME", config.path())
            .env("XDG_DATA_HOME", &long)
            .env("LC_ALL", "C.UTF-8")
            .output()
            .expect("spawn sbx")
    };

    // The fixture really is over the cap: a verb that needs the store says so.
    let control = run(&["app", "ls"]);
    assert!(
        String::from_utf8_lossy(&control.stderr).contains("data directory"),
        "the fixture must actually trip the length cap; stderr:\n{}",
        String::from_utf8_lossy(&control.stderr)
    );

    let out = run(&["app", "upgrade", "reader"]);
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert_eq!(out.status.code(), Some(0), "stdout:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("`sbx upgrade nix`"),
        "the answer must be whole without a store:\n{stdout}"
    );
}
