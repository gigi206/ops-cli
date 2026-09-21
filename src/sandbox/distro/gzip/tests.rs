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
