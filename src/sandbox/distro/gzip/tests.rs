use super::*;

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
    // The failure that matters: a layer cut in half must not look like a layer that ended.
    let compressed = gzip(&b"payload that will be cut".repeat(500));
    let truncated = &compressed[..compressed.len() / 2];
    assert!(
        inflate_all(truncated).is_err(),
        "a truncated member is an error"
    );
}
