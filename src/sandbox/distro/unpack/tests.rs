use super::*;
use crate::testutil::TmpDir;
use std::path::PathBuf;

/// The media type of an uncompressed layer.
const TAR: &str = "application/vnd.oci.image.layer.v1.tar";

/// A tar of regular files, `(path, contents)`.
fn layer_of(files: &[(&str, &str)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, body) in files {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(body.len() as u64);
        header.set_entry_type(tar::EntryType::Regular);
        builder
            .append_data(&mut header, path, body.as_bytes())
            .unwrap();
    }
    builder.into_inner().unwrap()
}

/// `bytes` written to a file under `dir`, as a fetched blob is.
fn blob(dir: &TmpDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

/// A layer lands in the tree, and what it spent is carried on: the next layer starts from it, and
/// the budget after both is the sum.
#[test]
fn a_layer_lands_and_the_budget_it_spent_is_carried_to_the_next() {
    let tmp = TmpDir::new();
    let rootfs = tmp.join("rootfs");
    let bwrap = Path::new("bwrap");
    let mut budget = Budget::new();
    let mut time = TIME_PER_IMAGE;
    let first = blob(&tmp, "one", &layer_of(&[("etc/os-release", "ID=test\n")]));
    apply(bwrap, &first, TAR, &rootfs, &mut budget, &mut time).expect("the first layer applies");
    let after_one = budget.spent();
    assert_eq!(
        after_one,
        (8, 2),
        "one member and the directory made for it"
    );

    let second = blob(&tmp, "two", &layer_of(&[("etc/hostname", "cage\n")]));
    apply(bwrap, &second, TAR, &rootfs, &mut budget, &mut time).expect("the second layer applies");
    assert_eq!(
        budget.spent(),
        (13, 3),
        "the second layer adds to the first"
    );
    assert_eq!(
        std::fs::read_to_string(rootfs.join("etc/os-release")).unwrap(),
        "ID=test\n"
    );
    assert_eq!(
        std::fs::read_to_string(rootfs.join("etc/hostname")).unwrap(),
        "cage\n"
    );
}

/// The unpack counts from what it was handed, not from zero: a layer that stays under the ceiling
/// on its own is refused once the layers before it have spent up to it.
#[test]
fn a_layer_is_refused_by_the_budget_the_layers_before_it_spent() {
    let tmp = TmpDir::new();
    let rootfs = tmp.join("rootfs");
    let layer = blob(&tmp, "near", &layer_of(&[("a", "x"), ("b", "y")]));
    let mut budget = Budget::resumed(0, layers::MAX_MEMBERS - 1);
    let mut time = TIME_PER_IMAGE;
    let err = apply(
        Path::new("bwrap"),
        &layer,
        TAR,
        &rootfs,
        &mut budget,
        &mut time,
    )
    .expect_err("two entries past one left are refused");
    assert!(
        err.to_string().contains("entries"),
        "the refusal is the entry ceiling: {err}"
    );
    assert_eq!(
        budget.spent(),
        (0, layers::MAX_MEMBERS - 1),
        "a refused layer spends nothing the next one would start from"
    );
}

/// An ending of the unpack, for [`outcome`].
fn ended(status: ExitStatus, out: &[u8], message: &[u8]) -> Ended {
    Ended {
        status,
        out: bounded(out, RESULT_MAX),
        message: bounded(message, MESSAGE_MAX),
        out_of_time: false,
    }
}

fn exited(code: i32) -> ExitStatus {
    ExitStatus::from_raw(code << 8)
}

/// Success is an exit of 0 **and** the one line, exactly: a line missing, cut short, carrying a
/// sign or a third count, or followed by another, is a failure.
#[test]
fn a_success_is_an_exit_of_zero_and_its_one_line() {
    assert_eq!(
        outcome(&ended(exited(0), b"spent 5 7\n", b"")).unwrap(),
        (5, 7)
    );
    for out in [
        &b""[..],
        b"spent 5 7",
        b"spent 5\n",
        b"spent 5 7 9\n",
        b"spent +5 7\n",
        b"spent 5  7\n",
        b"spent 5 7\nspent 1 1\n",
        b"spent 99999999999999999999 7\n",
    ] {
        let err = outcome(&ended(exited(0), out, b"")).expect_err("not the one line");
        assert!(
            err.to_string().contains("without saying what it spent"),
            "{:?}: {err}",
            String::from_utf8_lossy(out)
        );
    }
    let long = [b'1'; RESULT_MAX + 1];
    assert!(outcome(&ended(exited(0), &long, b"")).is_err());
}

/// A failure says why: the unpack's own words when it wrote some, its status or signal when it did
/// not, and that the words were cut when they ran past the bound.
#[test]
fn a_failure_is_named_by_what_the_unpack_said_or_how_it_ended() {
    let said =
        outcome(&ended(exited(1), b"", b"refusing layer member `x`\n")).expect_err("a refusal");
    assert_eq!(said.to_string(), "refusing layer member `x`");
    let silent = outcome(&ended(exited(3), b"spent 1 1\n", b"")).expect_err("a non-zero exit");
    assert_eq!(silent.to_string(), "a layer's unpack exited with status 3");
    let killed = outcome(&ended(ExitStatus::from_raw(9), b"", b"")).expect_err("a signal");
    assert_eq!(
        killed.to_string(),
        "a layer's unpack was killed by signal 9"
    );
    let long = vec![b'x'; MESSAGE_MAX + 10];
    let cut = outcome(&ended(exited(1), b"", &long)).expect_err("a long refusal");
    assert!(
        cut.to_string()
            .ends_with(&format!("[cut at {MESSAGE_MAX} bytes]")),
        "{}",
        &cut.to_string()[MESSAGE_MAX - 10..]
    );
}

/// A bounded read keeps what fits and still reads the rest, so the writer is never left waiting on
/// a pipe nobody empties.
#[test]
fn a_bounded_read_keeps_its_bound_and_drains_the_rest() {
    let bytes = vec![7u8; 100_000];
    let mut reader = io::Cursor::new(&bytes);
    let read = bounded(&mut reader, 16);
    assert_eq!(read.kept, vec![7u8; 16]);
    assert!(read.cut);
    assert_eq!(reader.position(), 100_000, "the rest was read");
    let whole = bounded(&b"spent 1 1\n"[..], RESULT_MAX);
    assert_eq!(whole.kept, b"spent 1 1\n");
    assert!(!whole.cut);
}

/// A layer's unpack takes its time out of the image's, and an image whose time is spent unpacks no
/// further layer: the next is refused before its cage is started, and the tree is left as it was.
#[test]
fn a_layer_spends_the_images_time_and_none_left_refuses_the_next() {
    let tmp = TmpDir::new();
    let rootfs = tmp.join("rootfs");
    let layer = blob(&tmp, "one", &layer_of(&[("etc/hostname", "cage\n")]));
    let mut budget = Budget::new();
    let mut time = TIME_PER_IMAGE;
    apply(
        Path::new("bwrap"),
        &layer,
        TAR,
        &rootfs,
        &mut budget,
        &mut time,
    )
    .expect("a layer with time left applies");
    assert!(
        time < TIME_PER_IMAGE,
        "the layer spent some of the image's time"
    );

    let untouched = tmp.join("untouched");
    let mut none = Duration::ZERO;
    let err = apply(
        Path::new("bwrap"),
        &layer,
        TAR,
        &untouched,
        &mut budget,
        &mut none,
    )
    .expect_err("no time is left for it");
    assert_eq!(
        err.to_string(),
        "this image's layers take more than 60 minutes to unpack: stopping rather than waiting on \
         them"
    );
    assert!(!untouched.exists(), "nothing was started for it");
    assert_eq!(budget.spent(), (5, 2), "a refused layer spends nothing");
}

/// An unpack still running at its deadline is killed, and said to be out of time rather than
/// killed by a signal: the parent's wait, run here on a child that never ends.
#[test]
fn an_unpack_still_running_at_its_deadline_is_killed_and_named() {
    let child = std::process::Command::new("sleep")
        .arg("30")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("sleep can be spawned");
    let started = Instant::now();
    let ended =
        collect(child, started + Duration::from_millis(200)).expect("the child is waited for");
    assert!(ended.out_of_time, "the deadline ended it");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the wait ended at the deadline, not with the child: {:?}",
        started.elapsed()
    );
    let err = outcome(&ended).expect_err("an unpack out of time applied nothing");
    assert!(err.to_string().contains("60 minutes"), "{err}");
}

/// An unpack that ends before its deadline is read whole off both of its streams, and is not out
/// of time.
#[test]
fn an_unpack_that_ends_in_time_is_read_off_both_streams() {
    let child = std::process::Command::new("sh")
        .args(["-c", "printf 'spent 3 4\\n'; printf 'said' >&2"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("a shell can be spawned");
    let ended =
        collect(child, Instant::now() + Duration::from_secs(30)).expect("the child is waited for");
    assert!(!ended.out_of_time);
    assert_eq!(ended.message.kept, b"said");
    assert_eq!(outcome(&ended).expect("it said what it spent"), (3, 4));
}

/// The unpack's cage names nothing of the host but the userland, the binary and the tree: the one
/// writable bind is the tree at [`ROOT`], there is no network, and no device or process table.
#[test]
fn the_unpacks_cage_holds_its_binary_the_userland_and_the_tree_alone() {
    let rootfs = Path::new("/data/distro/x.partial.1.1/rootfs");
    let args = vec!["__unpack".into(), TAR.into(), "0".into(), "0".into()];
    for copy in [false, true] {
        let argv: Vec<String> =
            crate::sandbox::argv::to_argv(&cage(9, copy, rootfs, args.clone()).unwrap())
                .iter()
                .map(|w| w.to_string_lossy().into_owned())
                .collect();
        let has = |run: &[&str]| argv.windows(run.len()).any(|w| w == run);
        assert!(has(&["--unshare-net"]), "{argv:?}");
        assert!(has(&["--bind", rootfs.to_str().unwrap(), ROOT]), "{argv:?}");
        let binds: Vec<(&str, &str)> = argv
            .windows(3)
            .filter(|w| w[0] == "--bind")
            .map(|w| (w[1].as_str(), w[2].as_str()))
            .collect();
        assert_eq!(binds, [(rootfs.to_str().unwrap(), ROOT)], "{argv:?}");
        let sources: Vec<&str> = argv
            .windows(2)
            .filter(|w| w[0].starts_with("--") && w[0].contains("bind"))
            .map(|w| w[1].as_str())
            .collect();
        let allowed = [
            "/usr",
            "/etc/ld.so.cache",
            "/proc/self/fd/9",
            rootfs.to_str().unwrap(),
        ];
        assert!(sources.iter().all(|s| allowed.contains(s)), "{sources:?}");
        for absent in ["--dev", "--dev-bind", "--dev-bind-try", "--proc"] {
            assert!(!argv.iter().any(|w| w == absent), "{absent} in {argv:?}");
        }
        assert!(
            argv.ends_with(&["--", "/sbx", "__unpack", TAR, "0", "0"].map(String::from)),
            "{argv:?}"
        );
    }
}

/// A layer that takes every path of the applier the unpack's filters have to let through: a
/// directory, a file, a symlink, a hard link, a whiteout, an opaque marker, a file replaced by a
/// directory and a directory by a file, and a mode that shuts its owner out.
fn every_kind_of_member() -> Vec<u8> {
    use tar::EntryType::{Directory, Link, Regular, Symlink};
    let mut builder = tar::Builder::new(Vec::new());
    let mut add = |path: &str, kind: tar::EntryType, body: &str, mode: u32, link: Option<&str>| {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(kind);
        header.set_mode(mode);
        header.set_mtime(DATED);
        header.set_size(body.len() as u64);
        match link {
            Some(target) => builder.append_link(&mut header, path, target).unwrap(),
            None => builder
                .append_data(&mut header, path, body.as_bytes())
                .unwrap(),
        }
    };
    add("etc", Directory, "", 0o755, None);
    add("etc/os-release", Regular, "ID=caged\n", 0o644, None);
    add("etc/link", Symlink, "", 0o777, Some("os-release"));
    add("etc/hard", Link, "", 0o644, Some("etc/os-release"));
    // The two markers reach what [`lower_layer`] left, and the opaque one keeps what this layer
    // wrote before it.
    add(".wh.gone", Regular, "", 0o644, None);
    add("opq/x", Regular, "x", 0o644, None);
    add("opq/.wh..wh..opq", Regular, "", 0o644, None);
    add("was", Regular, "w", 0o644, None);
    add("was", Directory, "", 0o755, None);
    add("dir2/y", Regular, "y", 0o644, None);
    add("dir2", Regular, "now a file", 0o644, None);
    add("locked", Regular, "l", 0o000, None);
    // A GNU sparse member: a mebibyte long, one byte at its middle and holes around it, the last
    // spelled as GNU tar spells it, an empty extent where the file ends.
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::GNUSparse);
    header.set_mode(0o644);
    header.set_size(1);
    let gnu = header.as_gnu_mut().unwrap();
    gnu.sparse[0].set_offset(SPARSE_LEN / 2);
    gnu.sparse[0].set_length(1);
    gnu.sparse[1].set_offset(SPARSE_LEN);
    gnu.sparse[1].set_length(0);
    gnu.set_real_size(SPARSE_LEN);
    header.set_path("sparse").unwrap();
    header.set_cksum();
    builder.append(&header, &b"s"[..]).unwrap();
    builder.into_inner().unwrap()
}

/// The length of the sparse member of [`every_kind_of_member`].
const SPARSE_LEN: u64 = 1024 * 1024;

/// The date every member of [`every_kind_of_member`] carries but the sparse one.
const DATED: u64 = 1_000_000_000;

/// What a layer below [`every_kind_of_member`] left in `root`, for its markers to hide.
fn lower_layer(root: &Path) {
    std::fs::write(root.join("gone"), b"g").unwrap();
    std::fs::create_dir_all(root.join("opq")).unwrap();
    std::fs::write(root.join("opq/old"), b"o").unwrap();
}

/// What [`every_kind_of_member`] leaves in `root` once applied over [`lower_layer`].
fn assert_every_kind_of_member_landed(root: &Path) {
    let read = |name: &str| std::fs::read_to_string(root.join(name)).unwrap();
    assert_eq!(read("etc/os-release"), "ID=caged\n");
    assert_eq!(
        std::fs::read_link(root.join("etc/link")).unwrap(),
        Path::new("os-release")
    );
    assert_eq!(read("etc/hard"), "ID=caged\n", "the hard link");
    assert!(
        root.join("gone").symlink_metadata().is_err(),
        "the whiteout removed it"
    );
    let opq: Vec<_> = std::fs::read_dir(root.join("opq"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        opq,
        ["x"],
        "the opaque marker emptied it of the lower layer and kept its own"
    );
    assert!(root.join("was").is_dir(), "a file replaced by a directory");
    assert_eq!(read("dir2"), "now a file", "a directory replaced by a file");
    assert_eq!(read("locked"), "l");
    let sparse = std::fs::read(root.join("sparse")).unwrap();
    assert_eq!(sparse.len() as u64, SPARSE_LEN);
    assert_eq!(sparse[SPARSE_LEN as usize / 2], b's');
    let blocks = std::os::unix::fs::MetadataExt::blocks(&root.join("sparse").metadata().unwrap());
    assert!(
        blocks * 512 < SPARSE_LEN / 2,
        "its holes stay holes: {blocks} blocks"
    );
    for dated in ["etc", "etc/os-release", "etc/link"] {
        let date = root
            .join(dated)
            .symlink_metadata()
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(
            date.duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            DATED,
            "{dated} keeps the date the image gives it"
        );
    }
}

/// The variable that tells [`probe_in_the_unpacks_cage`] it runs in the unpack's cage, and names
/// the file of the host it must not find there.
const PROBE_HOST_FILE: &str = "SBX_UNPACK_CAGE_PROBE";

/// What a process in the unpack's cage reaches, one line `sbx-probe: <what> <errno>` each, `0` for
/// what succeeded: before its filters, a file and a route of the host; then the unpack as the child
/// runs it ([`run`], filters first) of the layer on its standard input over [`ROOT`]; then, under
/// those filters, a socket and a program. Run in the cage by
/// [`a_layer_unpacked_in_its_cage_lands_in_the_tree_and_reaches_nothing_else`]; anywhere else it
/// does nothing.
///
/// It ends its process itself: libtest runs it on a thread of its own, and nothing on the unpack's
/// list ends a thread.
#[test]
#[ignore = "run in the unpack's cage by the test that reads what it prints"]
fn probe_in_the_unpacks_cage() {
    let Some(host_file) = std::env::var_os(PROBE_HOST_FILE) else {
        return;
    };
    let errno = |r: io::Result<()>| r.map_or_else(|e| e.raw_os_error().unwrap_or(-1), |()| 0);
    let say = |what: &str, outcome: i32| println!("sbx-probe: {what} {outcome}");
    let host_file = Path::new(&host_file);
    say("host-file", errno(File::open(host_file).map(drop)));
    say("host-write", errno(std::fs::write(host_file, b"y")));
    // An address no network of the cage's leads to: without a route the call is refused at once,
    // and with one it would time out.
    let to = (std::net::Ipv4Addr::new(192, 0, 2, 1), 443).into();
    let connect = std::net::TcpStream::connect_timeout(&to, std::time::Duration::from_secs(1));
    say("connect", errno(connect.map(drop)));
    let args = [TAR, "0", "0"].map(OsString::from);
    let code = run(&args, &mut io::stdout().lock(), &mut io::stderr().lock());
    say("unpack", i32::from(code));
    say(
        "socket",
        errno(std::os::unix::net::UnixDatagram::unbound().map(drop)),
    );
    let program = [c"/nonexistent".as_ptr(), std::ptr::null()];
    let environment = [std::ptr::null()];
    // SAFETY: NUL-terminated strings in null-terminated lists that outlive the call. The path does
    // not exist, so a call the kernel reaches fails and returns: `ENOENT`, where the filter answers
    // `EPERM`.
    unsafe { libc::execve(program[0], program.as_ptr(), environment.as_ptr()) };
    say(
        "exec",
        io::Error::last_os_error().raw_os_error().unwrap_or(-1),
    );
    let _ = io::stdout().flush();
    // SAFETY: ends the process without running anything more of it.
    unsafe { libc::_exit(0) };
}

/// A layer unpacked in the unpack's own cage lands in the tree on the host, while the process
/// that parsed it found no file of the host, could write none, and had no network. The process is
/// this test's own binary, in the cage [`cage`] builds, run as [`probe_in_the_unpacks_cage`].
#[test]
fn a_layer_unpacked_in_its_cage_lands_in_the_tree_and_reaches_nothing_else() {
    let Some(bwrap) = crate::pathfind::find_on_path("bwrap")
        .filter(|_| matches!(crate::probe_userns(), crate::Userns::Ok))
    else {
        skip_incapable!("skipping the unpack's cage: no bwrap or no capability-bearing userns");
        return;
    };
    let tmp = TmpDir::new();
    let host_file = tmp.join("of-the-host");
    std::fs::write(&host_file, b"x").unwrap();
    let rootfs = tmp.join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();
    lower_layer(&rootfs);
    let layer = blob(&tmp, "layer", &every_kind_of_member());

    let binary = File::open("/proc/self/exe").unwrap();
    let mut spec = cage(
        std::os::fd::AsRawFd::as_raw_fd(&binary),
        false,
        &rootfs,
        Vec::new(),
    )
    .unwrap();
    spec.cmd = [
        selfcage::BINARY,
        "sandbox::distro::unpack::tests::probe_in_the_unpacks_cage",
        "--exact",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ]
    .map(OsString::from)
    .to_vec();
    spec.env = vec![(
        PROBE_HOST_FILE.to_string(),
        host_file.to_string_lossy().into_owned(),
    )];
    let (mut command, files) = selfcage::command(&bwrap, &spec, binary).unwrap();
    command.stdin(File::open(&layer).unwrap());
    crate::sandbox::memfd::inherit_across_exec(&mut command, &files);
    let ran = crate::testutil::run_within(&mut command, "the probe in the unpack's cage");
    drop(files);
    let stdout = &ran.stdout;
    let seen: Vec<&str> = stdout
        .lines()
        .filter_map(|l| l.split_once("sbx-probe: ").map(|(_, said)| said))
        .collect();
    let expected = [
        format!("host-file {}", libc::ENOENT),
        format!("host-write {}", libc::ENOENT),
        format!("connect {}", libc::ENETUNREACH),
        "unpack 0".to_string(),
        format!("socket {}", libc::EPERM),
        format!("exec {}", libc::EPERM),
    ];
    assert_eq!(seen, expected, "{stdout}{}", ran.stderr);
    assert!(
        stdout.lines().any(|l| l.starts_with("spent ")),
        "the unpack said what it spent: {stdout}"
    );
    assert_every_kind_of_member_landed(&rootfs);
    assert_eq!(
        std::fs::read(&host_file).unwrap(),
        b"x",
        "the host file is untouched"
    );
}

/// No production code applies a layer in the process that fetched it: the one caller of
/// [`layers::apply`] is the unpack's own process, and the store goes through [`apply`].
///
/// Read from the sources because the failure is a substitution: under test the unpack runs in this
/// process anyway (see `process`), so a store that called [`layers::apply`] itself would pass every
/// other test here, and differ only in running a stranger's archive with the user's files in reach.
#[test]
fn no_production_code_applies_a_layer_outside_the_unpacks_process() {
    let root = format!("{}/", env!("CARGO_MANIFEST_DIR"));
    let test_only = crate::testutil::test_only_sources();
    let mut appliers = Vec::new();
    let mut store_goes_through_the_cage = false;
    for file in crate::testutil::crate_sources() {
        if crate::testutil::is_test_only_source(&file) || test_only.contains(&file) {
            continue;
        }
        let text = std::fs::read_to_string(&file).unwrap_or_default();
        let production = crate::testutil::production_half(&text);
        let relative = file.display().to_string().replacen(&root, "", 1);
        if crate::testutil::calls_function(production, "layers::apply(") {
            appliers.push(relative.clone());
        }
        if relative == "src/sandbox/distro/store.rs" {
            store_goes_through_the_cage =
                crate::testutil::calls_function(production, "unpack::apply(");
        }
    }
    assert_eq!(
        appliers,
        ["src/sandbox/distro/unpack.rs"],
        "a layer applied outside its cage"
    );
    assert!(
        store_goes_through_the_cage,
        "the store applies its layers through `unpack::apply`"
    );
}
