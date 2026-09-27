//! One layer of an image applied by a process of its own: what `sbx __unpack` runs, and how a
//! provision starts one.
//!
//! A layer is a third party's archive: the registry chose its bytes and the image's author its
//! members. [`super::layers`] refuses every member that would land outside the tree, and this puts
//! a wall behind that check. The process that parses the layer runs in a cage whose only writable
//! path is the tree being assembled, with no network and nothing else of the host but the
//! read-only userland and sbx's own binary ([`crate::sandbox::selfcage`]). A flaw in where a member
//! lands then writes inside that tree, and nowhere else.
//!
//! ## One process per layer
//!
//! The layers of an image share nothing in memory but the budget, two counts. Everything else a
//! layer reads of the ones before it (the target of a whiteout, a directory an opaque marker
//! empties, the source of a hard link) it reads from the tree on disk. So the budget crosses as
//! arguments and comes back as one line, and each layer is parsed by a process that has seen no
//! other.
//!
//! `sbx __unpack <media type> <bytes spent> <entries spent>` reads the layer on its standard input
//! and applies it over [`ROOT`]. It prints `spent <bytes> <entries>` and exits 0, or prints why it
//! stopped on its standard error and exits 1. Both are read bounded ([`RESULT_MAX`],
//! [`MESSAGE_MAX`]), and an exit of 0 without that one line is a failure.
//!
//! ## What the cage holds against
//!
//! A bug that would place a member outside the tree: the cage has nothing else to write to. The
//! budget is still enforced by the code in the child, so it holds against what it held against
//! before, and not against a child made to lie about what it spent. The cage bounds where the
//! child writes, not how much.

use super::layers::{self, Budget};
use crate::sandbox::selfcage;
use crate::sandbox::spec::{Mount, NetPolicy, SandboxSpec};
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, RawFd};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{ExitCode, ExitStatus};

/// Where the tree being assembled is, inside the unpack's cage.
const ROOT: &str = "/rootfs";

/// The most of the unpack's standard output read. Its one line, `spent <bytes> <entries>`, is at
/// most 48 bytes.
const RESULT_MAX: usize = 64;

/// The most of a refusal's text kept. A refusal quotes the member it refused, whose path is bounded
/// only by what the tar reader may hold (a megabyte); what is past this is read and dropped, so the
/// child never waits on a full pipe, and the message says it was cut.
const MESSAGE_MAX: usize = 16 * 1024;

/// Apply the layer at `blob` over `rootfs`, in a cage of its own started by `bwrap`, carrying
/// `budget` from the layers before it on to the ones after.
pub(super) fn apply(
    bwrap: &Path,
    blob: &Path,
    media_type: &str,
    rootfs: &Path,
    budget: &mut Budget,
) -> io::Result<()> {
    // The cage binds the tree, so it has to exist before the first layer does.
    std::fs::create_dir_all(rootfs)?;
    let layer = File::open(blob)?;
    let (bytes, entries) = budget.spent();
    let args = vec![
        OsString::from("__unpack"),
        media_type.into(),
        bytes.to_string().into(),
        entries.to_string().into(),
    ];
    let (bytes, entries) = outcome(&process::run(bwrap, rootfs, layer, args)?)?;
    *budget = Budget::resumed(bytes, entries);
    Ok(())
}

/// `sbx __unpack <media type> <bytes spent> <entries spent>`: apply the layer on standard input over
/// [`ROOT`], and say what the image has spent with it. Started by [`apply`], in its cage.
pub(crate) fn main(argv: &[OsString]) -> ExitCode {
    let layer = match io::stdin().as_fd().try_clone_to_owned() {
        Ok(fd) => File::from(fd),
        Err(e) => {
            eprintln!("sbx: __unpack: cannot read the layer on standard input: {e}");
            return ExitCode::FAILURE;
        }
    };
    ExitCode::from(serve(
        argv,
        layer,
        Path::new(ROOT),
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    ))
}

/// The unpack of one layer over `root`, as [`main`] runs it in the cage, answering on `out` and
/// `err`. Returns the exit code.
fn serve(
    argv: &[OsString],
    layer: File,
    root: &Path,
    out: &mut impl Write,
    err: &mut impl Write,
) -> u8 {
    let parsed = match argv {
        [media, bytes, entries] => media.to_str().zip(
            bytes
                .to_str()
                .and_then(|b| b.parse::<u64>().ok())
                .zip(entries.to_str().and_then(|e| e.parse::<u64>().ok())),
        ),
        _ => None,
    };
    let Some((media_type, (bytes, entries))) = parsed else {
        let _ = writeln!(
            err,
            "sbx: __unpack: expects a media type, then the bytes and the entries spent so far"
        );
        return 2;
    };
    let mut budget = Budget::resumed(bytes, entries);
    match layers::apply(layer, media_type, root, &mut budget) {
        Ok(()) => {
            let (bytes, entries) = budget.spent();
            match writeln!(out, "spent {bytes} {entries}").and_then(|()| out.flush()) {
                Ok(()) => 0,
                Err(_) => 1,
            }
        }
        Err(e) => {
            let _ = writeln!(err, "{e}");
            1
        }
    }
}

/// How one layer's unpack ended: its status, and what it wrote on each stream, bounded.
struct Ended {
    status: ExitStatus,
    out: Bounded,
    message: Bounded,
}

/// What a stream held, up to a bound, and whether it held more.
#[derive(Default)]
struct Bounded {
    kept: Vec<u8>,
    cut: bool,
}

/// Read `from` to its end, keeping at most `max` bytes. The rest is read and dropped rather than
/// left unread, so a writer at the other end of a pipe is never left blocked on it.
fn bounded(mut from: impl Read, max: usize) -> Bounded {
    let mut kept = Vec::new();
    let _ = (&mut from).take(max as u64).read_to_end(&mut kept);
    let cut = io::copy(&mut from, &mut io::sink()).is_ok_and(|n| n > 0);
    Bounded { kept, cut }
}

/// What the image has spent once a layer's unpack ended, or why the layer was not applied.
fn outcome(ended: &Ended) -> io::Result<(u64, u64)> {
    if ended.status.success() {
        return spent(&ended.out).ok_or_else(|| {
            io::Error::other("a layer's unpack ended without saying what it spent")
        });
    }
    let said = String::from_utf8_lossy(&ended.message.kept);
    let said = said.trim_end();
    let why = match (said.is_empty(), ended.status.code()) {
        (false, _) if ended.message.cut => format!("{said} [cut at {MESSAGE_MAX} bytes]"),
        (false, _) => said.to_string(),
        (true, Some(code)) => format!("a layer's unpack exited with status {code}"),
        (true, None) => format!(
            "a layer's unpack was killed by signal {}",
            ended.status.signal().unwrap_or_default()
        ),
    };
    Err(io::Error::other(why))
}

/// The one line a successful unpack prints, `spent <bytes> <entries>`, and nothing else.
fn spent(out: &Bounded) -> Option<(u64, u64)> {
    if out.cut {
        return None;
    }
    let line = std::str::from_utf8(&out.kept).ok()?.strip_suffix('\n')?;
    let mut words = line.strip_prefix("spent ")?.split(' ');
    let count = |word: Option<&str>| {
        word.filter(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_digit()))?
            .parse::<u64>()
            .ok()
    };
    let bytes = count(words.next())?;
    let entries = count(words.next())?;
    words.next().is_none().then_some((bytes, entries))
}

/// The cage a layer's unpack runs in ([`selfcage::spec`]): no network, and nothing of the host but
/// the read-only userland, the binary open as `binary` (`copy`'d when its file is gone), and the
/// tree `rootfs`, writable, at [`ROOT`].
fn cage(binary: RawFd, copy: bool, rootfs: &Path, args: Vec<OsString>) -> io::Result<SandboxSpec> {
    selfcage::spec(
        "a layer's unpack",
        binary,
        copy,
        vec![Mount::Bind {
            src: rootfs.to_path_buf(),
            dest: ROOT.into(),
        }],
        NetPolicy::Isolated,
        args,
    )
}

/// The unpack as a process in its cage.
#[cfg(not(test))]
mod process {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::process::Stdio;

    /// Run `sbx` with `args` in the cage [`cage`] describes, `layer` on its standard input, and
    /// wait for it. The thread that starts it is the one that waits, so the parent-death signal
    /// bubblewrap arms, which follows the starting thread, cannot fire early.
    pub(super) fn run(
        bwrap: &Path,
        rootfs: &Path,
        layer: File,
        args: Vec<OsString>,
    ) -> io::Result<Ended> {
        let (binary, copy) = selfcage::running()?;
        let spec = cage(binary.as_raw_fd(), copy, rootfs, args)?;
        let (mut command, files) = selfcage::command(bwrap, &spec, binary)?;
        command
            .stdin(layer)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        crate::sandbox::memfd::inherit_across_exec(&mut command, &files);
        let started = command.spawn();
        drop(files);
        let mut child = started?;
        // Standard error is drained on a thread of its own while standard output is read here, so
        // a child that fills one pipe is never left waiting while this reads the other.
        let stderr = child.stderr.take();
        let message = match std::thread::Builder::new()
            .name("sbx-unpack-err".into())
            .spawn(move || stderr.map(|e| bounded(e, MESSAGE_MAX)).unwrap_or_default())
        {
            Ok(message) => message,
            // Not returned before the child is gone: the caller removes the tree on an error, and
            // a child still writing into it would race that removal.
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };
        let out = child
            .stdout
            .take()
            .map(|o| bounded(o, RESULT_MAX))
            .unwrap_or_default();
        let status = child.wait()?;
        let message = message.join().unwrap_or_default();
        Ok(Ended {
            status,
            out,
            message,
        })
    }
}

/// The unpack run by this process instead.
#[cfg(test)]
mod process {
    use super::*;

    /// A test binary is not sbx and cannot be started as `sbx __unpack`, and a host without user
    /// namespaces has no cage to start. This runs [`serve`] here instead, over `rootfs` itself, and
    /// reads what it wrote through the same bounds, so everything but the process and the cage is
    /// the unpack's own. The cage is tested on its own, by running this test binary in it.
    pub(super) fn run(
        _bwrap: &Path,
        rootfs: &Path,
        layer: File,
        args: Vec<OsString>,
    ) -> io::Result<Ended> {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = serve(&args[1..], layer, rootfs, &mut out, &mut err);
        Ok(Ended {
            status: ExitStatus::from_raw(i32::from(code) << 8),
            out: bounded(&out[..], RESULT_MAX),
            message: bounded(&err[..], MESSAGE_MAX),
        })
    }
}

#[cfg(test)]
mod tests;
