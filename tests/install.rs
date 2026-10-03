//! Integration tests for `install.sh`, the script the installation page pipes into `sh`.
//!
//! Each case feeds the script to `sh` on its standard input, the way the documented command does,
//! against a release laid out in a fixture directory and served over `file://`, so nothing here
//! reaches the network. A fake `uname` put first on `PATH` answers for another machine where a
//! case needs one.

#[macro_use]
mod common;
use common::fixture::TmpDir;

use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The binary a fake release publishes. It answers `--version`, and `doctor` exits with the code
/// `FAKE_DOCTOR_RC` asks for.
const FAKE_SBX: &str = "#!/bin/sh\ncase \"$1\" in\n  --version) echo \"sbx 9.9.9\" ;;\n  \
                        doctor) echo \"doctor ran\"; exit \"${FAKE_DOCTOR_RC:-0}\" ;;\nesac\n";

/// The Lima template a fake release publishes for macOS. The script hands it to `limactl` and
/// never reads it.
const FAKE_TEMPLATE: &str = "vmType: \"vz\"\n";

/// The script as it ships, read from the checkout.
fn script() -> Vec<u8> {
    std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("install.sh"))
        .expect("install.sh is readable")
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A release tree, an API answer and a home, all under one fixture directory.
struct Release {
    root: TmpDir,
}

/// What one run of the script left: its exit code and everything it printed.
struct Run {
    code: Option<i32>,
    text: String,
}

impl Release {
    fn new() -> Self {
        Self {
            root: TmpDir::prefixed("install", "rel"),
        }
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    /// Where the script installs by default.
    fn installed(&self) -> PathBuf {
        self.home().join(".local/bin/sbx")
    }

    /// Publish `body` as `asset` under `tag`, with `checksum` as its `.sha256`, or the real one.
    fn publish(&self, tag: &str, asset: &str, body: &str, checksum: Option<&str>) {
        let dir = self.root.join("download").join(tag);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(asset), body).unwrap();
        let sum = checksum.map_or_else(|| sha256_hex(body.as_bytes()), str::to_string);
        std::fs::write(dir.join(format!("{asset}.sha256")), format!("{sum}\n")).unwrap();
    }

    /// Publish the macOS template and wrapper as the repository holds them at `tag`.
    fn publish_macos(&self, tag: &str) {
        let dir = self.root.join("source").join(tag).join("dist/macos");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("sbx.yaml"), FAKE_TEMPLATE).unwrap();
        std::fs::write(dir.join("sbx"), FAKE_SBX).unwrap();
    }

    /// A directory holding a `limactl` that appends each call to [`Release::lima_log`], and lists
    /// an instance named `sbx` when `FAKE_LIMA_EXISTS` is set.
    fn fake_limactl(&self) -> PathBuf {
        let bin = self.root.join("limabin");
        std::fs::create_dir_all(&bin).unwrap();
        let path = bin.join("limactl");
        let body = format!(
            "#!/bin/sh\necho \"$*\" >> {log}\n\
             case \"$1\" in list) [ -z \"${{FAKE_LIMA_EXISTS:-}}\" ] || echo sbx ;; esac\n",
            log = self.lima_log().display()
        );
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        bin
    }

    fn lima_log(&self) -> PathBuf {
        self.root.join("limactl.log")
    }

    /// Every `limactl` call the script made, one per line.
    fn lima_calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.lima_log())
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Make the releases API name `tag` as the newest stable release, in the shape GitHub prints.
    fn announce(&self, tag: &str) {
        let api = self.root.join("api");
        std::fs::create_dir_all(&api).unwrap();
        let body =
            format!("{{\n  \"url\": \"x\",\n  \"tag_name\": \"{tag}\",\n  \"name\": \"x\"\n}}\n");
        std::fs::write(api.join("latest"), body).unwrap();
    }

    /// A directory holding a `uname` that answers `kernel` and `machine`, to put first on `PATH`.
    fn fake_uname(&self, kernel: &str, machine: &str) -> PathBuf {
        let bin = self.root.join("fakebin");
        std::fs::create_dir_all(&bin).unwrap();
        let path = bin.join("uname");
        let body = format!(
            "#!/bin/sh\ncase \"$1\" in\n  -s) echo {kernel} ;;\n  -m) echo {machine} ;;\nesac\n"
        );
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        bin
    }

    /// Feed `script` to `sh` on its standard input, with only the environment named here and
    /// `path_first` ahead of the system directories on `PATH`.
    fn run(&self, script: &[u8], env: &[(&str, &str)], path_first: &[&Path]) -> Run {
        let mut path: Vec<String> = path_first.iter().map(|d| d.display().to_string()).collect();
        path.extend(["/usr/bin".to_string(), "/bin".to_string()]);
        let path = path.join(":");
        let mut cmd = Command::new("sh");
        cmd.env_clear()
            .env("PATH", path)
            .env("HOME", self.home())
            .env(
                "SBX_DOWNLOAD_BASE",
                format!("file://{}", self.root.join("download").display()),
            )
            .env(
                "SBX_RELEASES_API",
                format!("file://{}", self.root.join("api").display()),
            )
            .env(
                "SBX_SOURCE_BASE",
                format!("file://{}", self.root.join("source").display()),
            )
            .current_dir(self.root.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in env {
            cmd.env(key, value);
        }
        let mut child = cmd.spawn().expect("spawn sh");
        child
            .stdin
            .take()
            .expect("a piped stdin")
            .write_all(script)
            .expect("feed the script to sh");
        let out = child.wait_with_output().expect("wait for sh");
        Run {
            code: out.status.code(),
            text: format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        }
    }
}

#[test]
fn the_newest_stable_release_is_installed_by_default_and_checked() {
    let fx = Release::new();
    fx.announce("v2.0.0");
    fx.publish("v2.0.0", "sbx-linux-x86_64", FAKE_SBX, None);
    let run = fx.run(&script(), &[], &[&fx.fake_uname("Linux", "x86_64")]);

    assert_eq!(run.code, Some(0), "{}", run.text);
    assert!(
        run.text.contains("downloading sbx-linux-x86_64 (v2.0.0)")
            && run.text.contains("installed sbx 9.9.9")
            && run.text.contains("doctor ran"),
        "the newest stable tag is installed and doctor runs:\n{}",
        run.text
    );
    let installed = fx.installed();
    assert_eq!(std::fs::read_to_string(&installed).unwrap(), FAKE_SBX);
    let mode = std::fs::metadata(&installed).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o755, "{mode:o}");
    assert!(
        run.text.contains("is not on PATH") && run.text.contains("export PATH="),
        "a directory off PATH is named with the line to add:\n{}",
        run.text
    );
    let leftovers: Vec<_> = std::fs::read_dir(installed.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        leftovers,
        ["sbx"],
        "nothing but the binary is left beside it"
    );
}

#[test]
fn a_directory_already_on_path_gets_no_hint() {
    let fx = Release::new();
    fx.announce("v2.0.0");
    fx.publish("v2.0.0", "sbx-linux-x86_64", FAKE_SBX, None);
    let bin = fx.home().join(".local/bin");
    std::fs::create_dir_all(&bin).unwrap();
    let run = fx.run(&script(), &[], &[&bin, &fx.fake_uname("Linux", "x86_64")]);

    assert_eq!(run.code, Some(0), "{}", run.text);
    assert!(!run.text.contains("is not on PATH"), "{}", run.text);
    assert!(!run.text.contains("another sbx"), "{}", run.text);
}

#[test]
fn with_no_stable_release_nothing_is_installed_and_the_way_out_is_named() {
    let fx = Release::new();
    fx.publish("latest", "sbx-linux-x86_64", FAKE_SBX, None);
    let run = fx.run(&script(), &[], &[]);

    assert_ne!(run.code, Some(0), "{}", run.text);
    assert!(
        run.text.contains("could not look up the newest release")
            && run.text.contains("SBX_VERSION"),
        "{}",
        run.text
    );
    assert!(!fx.installed().exists());

    let fx = Release::new();
    let api = fx.root.join("api");
    std::fs::create_dir_all(&api).unwrap();
    std::fs::write(api.join("latest"), "{\"message\": \"odd\"}\n").unwrap();
    let run = fx.run(&script(), &[], &[]);
    assert_ne!(run.code, Some(0), "{}", run.text);
    assert!(run.text.contains("named no tag"), "{}", run.text);
    assert!(!fx.installed().exists());
}

#[test]
fn a_version_is_installed_when_asked_for_and_refused_when_it_is_not_a_tag() {
    let fx = Release::new();
    fx.publish("latest", "sbx-linux-x86_64", FAKE_SBX, None);
    let uname = fx.fake_uname("Linux", "x86_64");
    let run = fx.run(&script(), &[("SBX_VERSION", "latest")], &[&uname]);
    assert_eq!(run.code, Some(0), "{}", run.text);
    assert!(run.text.contains("(latest)"), "{}", run.text);

    let fx = Release::new();
    for bad in ["../v2", "v2 0", "v2/x"] {
        let run = fx.run(&script(), &[("SBX_VERSION", bad)], &[]);
        assert_ne!(run.code, Some(0), "{bad}: {}", run.text);
        assert!(
            run.text.contains("is not a release tag"),
            "{bad}: {}",
            run.text
        );
    }
    assert!(!fx.installed().exists());
}

#[test]
fn a_download_that_does_not_match_its_checksum_installs_nothing() {
    let fx = Release::new();
    fx.announce("v2.0.0");
    fx.publish(
        "v2.0.0",
        "sbx-linux-x86_64",
        FAKE_SBX,
        Some(&"0".repeat(64)),
    );
    let run = fx.run(&script(), &[], &[&fx.fake_uname("Linux", "x86_64")]);
    assert_ne!(run.code, Some(0), "{}", run.text);
    assert!(
        run.text.contains("checksum mismatch") && run.text.contains("nothing was installed"),
        "{}",
        run.text
    );
    assert!(!fx.installed().exists());
    let bin = fx.home().join(".local/bin");
    assert!(
        !bin.exists() || std::fs::read_dir(&bin).unwrap().next().is_none(),
        "no partial file is left in the directory"
    );

    for malformed in ["abc", &"G".repeat(64), ""] {
        let fx = Release::new();
        fx.announce("v2.0.0");
        fx.publish("v2.0.0", "sbx-linux-x86_64", FAKE_SBX, Some(malformed));
        let run = fx.run(&script(), &[], &[&fx.fake_uname("Linux", "x86_64")]);
        assert_ne!(run.code, Some(0), "{malformed:?}: {}", run.text);
        assert!(
            run.text.contains("is not a SHA-256"),
            "{malformed:?}: {}",
            run.text
        );
        assert!(!fx.installed().exists());
    }
}

#[test]
fn plain_http_a_relative_directory_and_a_malformed_repository_are_refused() {
    let fx = Release::new();
    let run = fx.run(
        &script(),
        &[
            ("SBX_VERSION", "v2.0.0"),
            ("SBX_DOWNLOAD_BASE", "http://127.0.0.1:9/download"),
        ],
        &[&fx.fake_uname("Linux", "x86_64")],
    );
    assert_ne!(run.code, Some(0), "{}", run.text);
    assert!(
        run.text.contains("could not download http://"),
        "{}",
        run.text
    );
    assert!(!fx.installed().exists());

    let run = fx.run(
        &script(),
        &[("SBX_VERSION", "v2.0.0"), ("SBX_INSTALL_DIR", "bin")],
        &[],
    );
    assert_ne!(run.code, Some(0), "{}", run.text);
    assert!(
        run.text.contains("must be an absolute path"),
        "{}",
        run.text
    );

    for repo in ["gigi206", "a/b/c", "/ops-cli", "gigi206/", "a b/c", "a/b;x"] {
        let run = fx.run(&script(), &[("SBX_REPO", repo)], &[]);
        assert_ne!(run.code, Some(0), "{repo}: {}", run.text);
        assert!(
            run.text.contains("SBX_REPO must be owner/name"),
            "{repo}: {}",
            run.text
        );
    }
    assert!(!fx.installed().exists());
}

#[test]
fn the_asset_follows_the_machine_and_an_unknown_one_is_refused() {
    let fx = Release::new();
    fx.announce("v2.0.0");
    let arm = FAKE_SBX.replace("9.9.9", "9.9.9-arm");
    fx.publish("v2.0.0", "sbx-linux-aarch64", &arm, None);
    let run = fx.run(&script(), &[], &[&fx.fake_uname("Linux", "aarch64")]);
    assert_eq!(run.code, Some(0), "{}", run.text);
    assert_eq!(std::fs::read_to_string(fx.installed()).unwrap(), arm);

    for (kernel, machine, said) in [
        ("Linux", "riscv64", "no release is published for riscv64"),
        ("FreeBSD", "amd64", "not on FreeBSD"),
    ] {
        let fx = Release::new();
        fx.announce("v2.0.0");
        let run = fx.run(&script(), &[], &[&fx.fake_uname(kernel, machine)]);
        assert_ne!(run.code, Some(0), "{kernel}/{machine}: {}", run.text);
        assert!(run.text.contains(said), "{kernel}/{machine}: {}", run.text);
        assert!(!fx.installed().exists());
    }
}

#[test]
fn a_doctor_that_reports_a_problem_leaves_the_install_in_place() {
    let fx = Release::new();
    fx.announce("v2.0.0");
    fx.publish("v2.0.0", "sbx-linux-x86_64", FAKE_SBX, None);
    let run = fx.run(
        &script(),
        &[("FAKE_DOCTOR_RC", "1")],
        &[&fx.fake_uname("Linux", "x86_64")],
    );
    assert_eq!(run.code, Some(0), "{}", run.text);
    assert!(
        run.text
            .contains("sbx is installed, but doctor reported a problem"),
        "{}",
        run.text
    );
    assert!(fx.installed().exists());
}

#[test]
fn a_script_cut_short_in_the_pipe_runs_nothing() {
    // Cut just after the line that puts the binary in place: a script run line by line as it
    // arrives would already have downloaded and installed by then.
    let fx = Release::new();
    fx.announce("v2.0.0");
    fx.publish("v2.0.0", "sbx-linux-x86_64", FAKE_SBX, None);
    let whole = script();
    let text = String::from_utf8(whole.clone()).unwrap();
    let marker = "mv -f \"$partial\" \"$dir/sbx\"\n";
    let cut = text
        .find(marker)
        .expect("the install line is in the script")
        + marker.len();
    let run = fx.run(&whole[..cut], &[], &[&fx.fake_uname("Linux", "x86_64")]);

    assert_ne!(run.code, Some(0), "{}", run.text);
    assert!(!run.text.contains("downloading"), "{}", run.text);
    assert!(!fx.installed().exists());
}

#[test]
fn on_macos_the_guest_is_created_and_the_wrapper_installed() {
    let fx = Release::new();
    fx.publish_macos("latest");
    let run = fx.run(
        &script(),
        &[("SBX_VERSION", "latest")],
        &[&fx.fake_limactl(), &fx.fake_uname("Darwin", "arm64")],
    );

    assert_eq!(run.code, Some(0), "{}", run.text);
    assert_eq!(
        std::fs::read_to_string(fx.installed()).unwrap(),
        FAKE_SBX,
        "the wrapper is what lands on PATH"
    );
    assert!(fx.home().join("Projects").is_dir(), "{}", run.text);
    let calls = fx.lima_calls();
    assert!(
        calls.iter().any(|c| c.starts_with(
            "create --tty=false --name sbx --param projects=Projects --param release=latest "
        )),
        "the guest is created for the release asked for, seeing ~/Projects: {calls:?}"
    );
    assert!(
        calls.iter().any(|c| c == "start --tty=false sbx"),
        "{calls:?}"
    );
    assert!(run.text.contains("doctor ran"), "{}", run.text);
}

#[test]
fn on_macos_an_existing_guest_is_kept() {
    let fx = Release::new();
    fx.publish_macos("latest");
    let run = fx.run(
        &script(),
        &[("SBX_VERSION", "latest"), ("FAKE_LIMA_EXISTS", "1")],
        &[&fx.fake_limactl(), &fx.fake_uname("Darwin", "x86_64")],
    );

    assert_eq!(run.code, Some(0), "{}", run.text);
    let calls = fx.lima_calls();
    assert!(
        calls
            .iter()
            .all(|c| !c.starts_with("create") && !c.starts_with("delete")),
        "an existing guest is neither recreated nor deleted: {calls:?}"
    );
    assert!(run.text.contains("is kept as it is"), "{}", run.text);
    assert_eq!(std::fs::read_to_string(fx.installed()).unwrap(), FAKE_SBX);
}

#[test]
fn on_macos_without_lima_or_with_a_bad_projects_directory_nothing_is_installed() {
    let fx = Release::new();
    fx.publish_macos("latest");
    let run = fx.run(
        &script(),
        &[("SBX_VERSION", "latest")],
        &[&fx.fake_uname("Darwin", "arm64")],
    );
    assert_ne!(run.code, Some(0), "{}", run.text);
    assert!(
        run.text.contains("limactl is not on PATH") && run.text.contains("brew install lima"),
        "{}",
        run.text
    );
    assert!(!fx.installed().exists());

    for bad in ["/Users/x", "..", "a/../b", "a//b", "a b", "a\"b"] {
        let run = fx.run(
            &script(),
            &[("SBX_VERSION", "latest"), ("SBX_LIMA_PROJECTS", bad)],
            &[&fx.fake_limactl(), &fx.fake_uname("Darwin", "arm64")],
        );
        assert_ne!(run.code, Some(0), "{bad:?}: {}", run.text);
        assert!(
            run.text.contains("SBX_LIMA_PROJECTS must be"),
            "{bad:?}: {}",
            run.text
        );
        assert!(!fx.installed().exists(), "{bad:?}");
    }
    assert!(fx.lima_calls().is_empty(), "{:?}", fx.lima_calls());
}

#[test]
fn on_macos_a_release_without_the_template_is_named() {
    let fx = Release::new();
    let run = fx.run(
        &script(),
        &[("SBX_VERSION", "v1.9.0")],
        &[&fx.fake_limactl(), &fx.fake_uname("Darwin", "arm64")],
    );
    assert_ne!(run.code, Some(0), "{}", run.text);
    assert!(
        run.text.contains("may predate the macOS support"),
        "{}",
        run.text
    );
    assert!(!fx.installed().exists());
    assert!(fx.lima_calls().is_empty(), "{:?}", fx.lima_calls());
}
