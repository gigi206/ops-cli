use super::*;
use crate::testutil::Trickle;
use proptest::collection::vec;
use proptest::prelude::{Just, Strategy, any, prop_oneof};
use proptest::sample::Index;

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

/// How a generated member's deflate stream is made: by `miniz_oxide` at a level, or as stored
/// blocks of at most so many bytes, written here. The second is an encoder that shares nothing with
/// the decoder under test.
#[derive(Clone, Debug)]
enum Encoding {
    Miniz(u8),
    Stored(usize),
}

/// One generated gzip member: what it inflates to, how it is deflated, and its header fields.
///
/// `fixed` is the modification time, the extra flags and the system byte, which the reader skips.
/// The trailer is arbitrary because the reader does not check it.
#[derive(Clone, Debug)]
struct Generated {
    payload: Vec<u8>,
    encoding: Encoding,
    fixed: [u8; 6],
    extra: Option<Vec<u8>>,
    name: Option<Vec<u8>>,
    comment: Option<Vec<u8>>,
    hcrc: Option<[u8; 2]>,
    trailer: [u8; 8],
}

impl Generated {
    fn encode(&self) -> Vec<u8> {
        let flag = |present: bool, bit: u8| if present { bit } else { 0 };
        let flags = flag(self.extra.is_some(), FEXTRA)
            | flag(self.name.is_some(), FNAME)
            | flag(self.comment.is_some(), FCOMMENT)
            | flag(self.hcrc.is_some(), FHCRC);
        let mut out = vec![MAGIC[0], MAGIC[1], DEFLATE, flags];
        out.extend(self.fixed);
        if let Some(extra) = &self.extra {
            out.extend((extra.len() as u16).to_le_bytes());
            out.extend(extra);
        }
        for field in [&self.name, &self.comment].into_iter().flatten() {
            out.extend(field);
            out.push(0);
        }
        if let Some(hcrc) = self.hcrc {
            out.extend(hcrc);
        }
        match self.encoding {
            Encoding::Miniz(level) => {
                out.extend(miniz_oxide::deflate::compress_to_vec(&self.payload, level));
            }
            Encoding::Stored(block) => out.extend(stored(&self.payload, block)),
        }
        out.extend(self.trailer);
        out
    }
}

/// `payload` as a raw deflate stream of stored blocks of at most `block` bytes, the last one final.
fn stored(payload: &[u8], block: usize) -> Vec<u8> {
    let mut blocks: Vec<&[u8]> = payload.chunks(block).collect();
    if blocks.is_empty() {
        blocks.push(&[]);
    }
    let last = blocks.len() - 1;
    let mut out = Vec::new();
    for (i, data) in blocks.into_iter().enumerate() {
        // BFINAL, then BTYPE 00, then padding to the byte: a stored block starts on a byte.
        out.push(u8::from(i == last));
        let len = data.len() as u16;
        out.extend(len.to_le_bytes());
        out.extend((!len).to_le_bytes());
        out.extend(data);
    }
    out
}

fn payloads() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        vec(any::<u8>(), 0..2000),
        // Runs, so a member reaches several output chunks from a few bytes of input.
        (vec(any::<u8>(), 1..16), 1usize..20_000).prop_map(|(unit, times)| unit.repeat(times)),
    ]
}

fn generated() -> impl Strategy<Value = Generated> {
    let field = || proptest::option::of(vec(1u8..=255, 0..20));
    (
        payloads(),
        prop_oneof![
            (0u8..=10).prop_map(Encoding::Miniz),
            (1usize..=65_535).prop_map(Encoding::Stored),
        ],
        any::<[u8; 6]>(),
        proptest::option::of(vec(any::<u8>(), 0..40)),
        (field(), field()),
        proptest::option::of(any::<[u8; 2]>()),
        any::<[u8; 8]>(),
    )
        .prop_map(
            |(payload, encoding, fixed, extra, (name, comment), hcrc, trailer)| Generated {
                payload,
                encoding,
                fixed,
                extra,
                name,
                comment,
                hcrc,
                trailer,
            },
        )
}

/// A gzip file of generated members and the zeros some tools leave after the last one, with where
/// each member ends in it and what the whole inflates to.
struct File {
    bytes: Vec<u8>,
    ends: Vec<usize>,
    payloads: Vec<Vec<u8>>,
}

fn file_of(members: &[Generated], padding: usize) -> File {
    let mut bytes = Vec::new();
    let mut ends = Vec::new();
    for member in members {
        bytes.extend(member.encode());
        ends.push(bytes.len());
    }
    bytes.resize(bytes.len() + padding, 0);
    File {
        bytes,
        ends,
        payloads: members.iter().map(|m| m.payload.clone()).collect(),
    }
}

/// What a caller asking for `sizes` bytes at a time, in turn, reads from `reader` to its end,
/// retrying an interrupted read as `read_to_end` does. Past `most` reads into a buffer that is not
/// empty, the reader is taken to be spinning. `sizes` holds one that is not zero.
fn read_in_turns(reader: &mut impl Read, sizes: &[usize], most: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut reads = 0;
    for turn in 0.. {
        let mut buf = vec![0; sizes[turn % sizes.len()]];
        if !buf.is_empty() {
            reads += 1;
            if reads > most {
                break;
            }
        }
        match reader.read(&mut buf) {
            Ok(0) if !buf.is_empty() => return Ok(out),
            Ok(n) => out.extend(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other(format!("no end after {most} reads")))
}

/// What a reader that stops making progress reports, rather than hanging the run.
const SPUN: &str = "fill_buf was asked past its bound: the reader spins";

/// `inner`, failing with [`SPUN`] once `fill_buf` has been asked `left` times. A reader that loops
/// without consuming or producing then shows as an error a property names, not as a run that never
/// ends.
struct Spin<R> {
    inner: R,
    left: usize,
}

impl<R: BufRead> Read for Spin<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: BufRead> BufRead for Spin<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.left == 0 {
            return Err(io::Error::other(SPUN));
        }
        self.left -= 1;
        self.inner.fill_buf()
    }

    fn consume(&mut self, n: usize) {
        self.inner.consume(n);
    }
}

/// `bytes` inflated to their end, through a [`Spin`] far more patient than any gzip file of this
/// size needs.
fn inflate_bounded(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut reader = GzipReader::new(Spin {
        inner: bytes,
        left: 10_000,
    })?;
    let mut out = Vec::new();
    reader.read_to_end(&mut out)?;
    Ok(out)
}

/// Bytes after the last member that are neither zeros nor another member: a first byte that is
/// neither, the magic's first byte alone, or that byte followed by one that is not the second.
fn trailing() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        (1u8..=255, vec(any::<u8>(), 0..20))
            .prop_filter("not the magic", |(first, _)| *first != MAGIC[0])
            .prop_map(|(first, rest)| [vec![first], rest].concat()),
        Just(vec![MAGIC[0]]),
        (any::<u8>(), vec(any::<u8>(), 0..20))
            .prop_filter("not the magic", |(second, _)| *second != MAGIC[1])
            .prop_map(|(second, rest)| [vec![MAGIC[0], second], rest].concat()),
    ]
}

/// `bytes`, each of `mutations` made to it in turn: a byte replaced, the flags or the extra field's
/// length of the member starting at one of `bounds` replaced, the file cut at one of `bounds` or up
/// to two bytes past it, the file cut anywhere, or bytes inserted. `bounds` are where each member
/// starts and where the last one ends: a cut drawn anywhere seldom falls beside one.
fn mutated(mut bytes: Vec<u8>, bounds: &[usize], mutations: &[(u8, Index, u16)]) -> Vec<u8> {
    for &(how, at, value) in mutations {
        let start = bounds[at.index(bounds.len())];
        match how {
            0 if !bytes.is_empty() => {
                let at = at.index(bytes.len());
                bytes[at] = value as u8;
            }
            1 if start + 4 <= bytes.len() => bytes[start + 3] = value as u8,
            2 if start + 12 <= bytes.len() => {
                bytes[start + 10..start + 12].copy_from_slice(&value.to_le_bytes());
            }
            3 => bytes.truncate(at.index(bytes.len() + 1)),
            4 => bytes.truncate(start + usize::from(value % 3)),
            _ => {
                let at = at.index(bytes.len() + 1);
                bytes.splice(at..at, value.to_le_bytes());
            }
        }
    }
    bytes
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]

    /// A gzip file inflates to its members' contents in order, however its bytes arrive and
    /// however the caller asks for them: in pieces of any size, interrupted, through a buffer as
    /// small as a byte, and with reads into an empty buffer among the others.
    #[test]
    fn a_gzip_file_inflates_to_its_members_in_order_however_it_is_read(
        members in vec(generated(), 1..4),
        padding in prop_oneof![Just(0usize), 1usize..600],
        capacity in prop_oneof![Just(1usize), 2usize..300, Just(8192)],
        pieces in vec(1usize..5000, 1..8),
        interrupts in vec(proptest::bool::weighted(0.2), 1..8),
        first in 1usize..70_000,
        then in vec(prop_oneof![Just(0usize), 1usize..70_000], 0..7),
    ) {
        let file = file_of(&members, padding);
        let expected = file.payloads.concat();
        let most = 4 * (expected.len() + file.bytes.len()) + 100;
        let channel = Spin {
            inner: io::BufReader::with_capacity(capacity, Trickle::new(&file.bytes, pieces, interrupts)),
            left: most,
        };
        let mut reader = GzipReader::new(channel)
            .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("header: {e}")))?;
        let sizes: Vec<usize> = std::iter::once(first).chain(then).collect();
        let out = read_in_turns(&mut reader, &sizes, most);
        proptest::prop_assert!(
            matches!(&out, Ok(out) if *out == expected),
            "{} members, {} bytes, inflated to {:?} of {} expected",
            members.len(),
            file.bytes.len(),
            out.map(|out| out.len()),
            expected.len()
        );
    }

    /// A gzip file cut short inflates to the members before the cut when it is cut where one of
    /// them ends or among the zeros after the last, and is an error anywhere else: a member cut in
    /// half never reads as a member that ended. Lengthened by bytes that are neither zeros nor
    /// another member, it is refused rather than read as far as it makes sense.
    #[test]
    fn a_gzip_file_cut_or_lengthened_reads_as_its_whole_members_or_an_error(
        members in vec(generated(), 1..4),
        padding in prop_oneof![Just(0usize), 1usize..600],
        how in 0u8..3,
        at in any::<Index>(),
        tail in trailing(),
    ) {
        let file = file_of(&members, padding);
        let last = file.ends[file.ends.len() - 1];
        let (bytes, clean) = match how {
            // Where a member ends or among the zeros: a uniform cut seldom falls there.
            0 => {
                let clean: Vec<usize> = file.ends.iter().copied().chain(last..=file.bytes.len()).collect();
                (file.bytes[..clean[at.index(clean.len())]].to_vec(), true)
            }
            1 => {
                let cut = at.index(file.bytes.len() + 1);
                let clean = cut > 0 && (file.ends.contains(&cut) || cut >= last);
                (file.bytes[..cut].to_vec(), clean)
            }
            _ => ([&file.bytes[..], &tail[..]].concat(), false),
        };
        let whole = file.ends.iter().filter(|&&end| end <= bytes.len()).count();
        let out = inflate_bounded(&bytes);
        if clean {
            proptest::prop_assert!(
                matches!(&out, Ok(out) if *out == file.payloads[..whole].concat()),
                "cut at {} of {}, after {} whole members: {:?}",
                bytes.len(),
                file.bytes.len(),
                whole,
                out.map(|out| out.len())
            );
        } else {
            proptest::prop_assert!(
                matches!(&out, Err(e) if e.to_string() != SPUN),
                "{} bytes, {} of them the file's, read as {:?}",
                bytes.len(),
                file.bytes.len().min(bytes.len()),
                out.map(|out| out.len())
            );
        }
    }

    /// Whatever bytes a layer holds, inflating them comes to an end without a panic and without
    /// spinning. The bytes are gzip files, then changed: a byte, a member's flags, its extra
    /// field's length, the file cut short, beside where a member ends or anywhere, or lengthened.
    #[test]
    fn any_bytes_are_inflated_to_an_end_without_a_panic(
        members in vec(generated(), 1..4),
        padding in prop_oneof![Just(0usize), 1usize..600],
        mutations in vec((0u8..6, any::<Index>(), any::<u16>()), 1..5),
    ) {
        let file = file_of(&members, padding);
        let bounds: Vec<usize> = std::iter::once(0).chain(file.ends.iter().copied()).collect();
        let bytes = mutated(file.bytes, &bounds, &mutations);
        let out = inflate_bounded(&bytes);
        proptest::prop_assert!(
            !matches!(&out, Err(e) if e.to_string() == SPUN),
            "{} bytes spun",
            bytes.len()
        );
    }
}
