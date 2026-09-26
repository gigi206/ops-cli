use super::*;

/// Whether the host has the `gzip` these tests compress and decompress *with*.
///
/// The inflater under test is sbx's own; `gzip` is the oracle it is held against, and an oracle is a
/// host prerequisite like bwrap or nix. Absent, the tests that need it are counted as skipped rather
/// than failing on a program that was never the subject — the repo's rule for a precondition that is
/// decided at runtime.
fn gzip_on_path() -> bool {
    std::process::Command::new("gzip")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The skip every test in this file takes when its oracle is missing, so the reason is written once.
macro_rules! need_gzip {
    () => {
        if !gzip_on_path() {
            skip_incapable!("skipping: no `gzip` on PATH to compress the fixtures with");
            return;
        }
    };
}

/// Compress `data` the way a registry's layer is compressed, so the reader is exercised against a
/// real gzip member rather than one this test also invented.
fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut child = std::process::Command::new("gzip")
        .arg("-c")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("gzip on PATH");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(data)
        .expect("write");
    let out = child.wait_with_output().expect("gzip ran");
    assert!(out.status.success());
    out.stdout
}

fn inflate_all(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut reader = GzipReader::new(io::BufReader::new(bytes))?;
    let mut out = Vec::new();
    reader.read_to_end(&mut out)?;
    Ok(out)
}

#[test]
fn a_gzip_member_round_trips() {
    need_gzip!();
    for payload in [
        Vec::new(),
        b"hello".to_vec(),
        // Larger than one output chunk, so the loop that refills is exercised.
        b"the quick brown fox ".repeat(20_000),
    ] {
        let compressed = gzip(&payload);
        assert_eq!(inflate_all(&compressed).expect("inflates"), payload);
    }
}

#[test]
fn the_optional_header_fields_are_skipped_not_inflated() {
    need_gzip!();
    // `gzip -N` writes the original name into the header (FNAME), which the reader must consume
    // before the deflate stream starts. A reader that did not would inflate the name as data.
    let dir = crate::testutil::TmpDir::new();
    let path = dir.join("payload.txt");
    std::fs::write(&path, b"named payload").unwrap();
    let out = std::process::Command::new("gzip")
        .args(["-N", "-c"])
        .arg(&path)
        .output()
        .expect("gzip ran");
    assert!(out.status.success());
    assert_eq!(
        inflate_all(&out.stdout).expect("inflates"),
        b"named payload"
    );
}

#[test]
fn something_that_is_not_gzip_is_refused_at_the_header() {
    for bad in [
        &b""[..],
        &b"\x1f"[..],
        &b"PK\x03\x04"[..],
        &b"\x1f\x8b\x01"[..],
    ] {
        assert!(inflate_all(bad).is_err(), "{bad:?} is not a gzip member");
    }
}

#[test]
fn a_truncated_member_is_an_error_not_a_short_read() {
    need_gzip!();
    // The failure that matters: a layer cut in half must not look like a layer that ended.
    let compressed = gzip(&b"payload that will be cut".repeat(500));
    let truncated = &compressed[..compressed.len() / 2];
    assert!(
        inflate_all(truncated).is_err(),
        "a truncated member is an error"
    );
}

/// A gzip file made of several members inflates to all of them, the way `gzip -dc` reads it.
///
/// RFC 1952 §2.2 says a file is a sequence of members, and a tool that appends to a layer, an
/// eStargz index, or a plain `cat a.gz b.gz` all produce one. Stopping at the first member left the
/// rest of a layer's tar unread while the unpack reported success: files the image declares that
/// the cage never sees. The witness is the same bytes through `gzip -dc`, which is what an image's
/// other readers do.
#[test]
fn a_file_of_several_gzip_members_inflates_to_all_of_them() {
    need_gzip!();
    let first = b"the first member\n".repeat(3000);
    let second = b"the second member\n".repeat(3000);
    let mut concatenated = gzip(&first);
    concatenated.extend_from_slice(&gzip(&second));

    let mut whole = first.clone();
    whole.extend_from_slice(&second);
    assert_eq!(
        gunzip(&concatenated),
        whole,
        "the witness: `gzip -dc` reads both members"
    );
    assert_eq!(inflate_all(&concatenated).expect("inflates"), whole);

    // The zero padding some tools leave after the last member is skipped, as `gzip` skips it.
    let mut padded = concatenated.clone();
    padded.extend_from_slice(&[0u8; 512]);
    assert_eq!(inflate_all(&padded).expect("inflates"), whole);

    // Anything else after the last member is refused rather than silently dropped.
    let mut trailing = concatenated.clone();
    trailing.extend_from_slice(b"not a member");
    let err = inflate_all(&trailing).expect_err("trailing data is refused");
    assert!(err.to_string().contains("trailing data"), "{err}");
}

/// Decompress with the host's `gzip`, so a test's expectation is not this module's own answer.
fn gunzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut child = std::process::Command::new("gzip")
        .arg("-dc")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("gzip on PATH");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(data)
        .expect("write");
    let out = child.wait_with_output().expect("gzip ran");
    assert!(out.status.success());
    out.stdout
}

/// One gzip member around `payload`, deflated in process, for a test whose expectation is its own
/// input rather than the host's `gzip`. The trailer is zeros: this reader does not check it.
fn member_of(payload: &[u8]) -> Vec<u8> {
    let mut member = vec![0x1f, 0x8b, DEFLATE, 0, 0, 0, 0, 0, 0, 3];
    member.extend(miniz_oxide::deflate::compress_to_vec(payload, 6));
    member.extend([0u8; 8]);
    member
}

/// A read into an empty buffer returns nothing and costs nothing of what is already inflated.
///
/// The refill replaces the inflated output rather than adding to it, and an empty buffer used to
/// fall through to it with output still unread: that output was dropped, and the refill ran again
/// until the member ended. The payload spans several output chunks, so there is unread output when
/// the empty read arrives and more to inflate after it.
#[test]
fn an_empty_read_keeps_the_output_not_yet_read() {
    let payload: Vec<u8> = (0..200_000u32)
        .map(|i| (i.wrapping_mul(7) % 251) as u8)
        .collect();
    let member = member_of(&payload);
    let mut reader = GzipReader::new(io::BufReader::new(&member[..])).expect("a gzip header");
    let mut first = [0u8; 5];
    reader.read_exact(&mut first).expect("the first bytes");
    assert_eq!(reader.read(&mut []).expect("an empty read"), 0);
    let mut rest = Vec::new();
    reader.read_to_end(&mut rest).expect("the rest");
    assert_eq!(rest.len(), payload.len() - first.len());
    assert!([&first[..], &rest[..]].concat() == payload);
}

/// The bytes of `bytes`, read through a buffer, with one `fill_buf` interrupted: the first one
/// asked at `at`. `fired` says whether it was.
struct InterruptedAt<'a> {
    bytes: &'a [u8],
    pos: usize,
    at: usize,
    fired: &'a std::cell::Cell<bool>,
}

impl Read for InterruptedAt<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for InterruptedAt<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.pos == self.at && !self.fired.get() {
            self.fired.set(true);
            return Err(io::ErrorKind::Interrupted.into());
        }
        Ok(&self.bytes[self.pos..])
    }

    fn consume(&mut self, n: usize) {
        self.pos += n;
    }
}

/// A read of the layer interrupted where one member ends is retried, and loses nothing.
///
/// The reader consumes a member's end before it looks for the next member, and keeps the output of
/// its last round only after. An interruption in between was handed back with that output lost and
/// the stream already closed, so the caller's retry found nothing more to inflate: with zeros after
/// the member, a clean end short of the whole output. The interruption here falls exactly there.
#[test]
fn a_read_interrupted_where_a_member_ends_loses_nothing() {
    let payload = b"the member's contents\n".repeat(100);
    let mut file = member_of(&payload);
    let end = file.len();
    file.extend([0u8; 16]);
    let fired = std::cell::Cell::new(false);
    let layer = InterruptedAt {
        bytes: &file,
        pos: 0,
        at: end,
        fired: &fired,
    };
    let mut out = Vec::new();
    GzipReader::new(layer)
        .expect("a gzip header")
        .read_to_end(&mut out)
        .expect("the retried read ends");
    assert!(
        fired.get(),
        "the read was interrupted where the member ends"
    );
    assert_eq!(out.len(), payload.len());
    assert!(out == payload);
}
