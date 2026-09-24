//! The bytes a proxy's report crosses in: one frame per event, read by the supervisor.
//!
//! A frame is a JSON document followed by raw pieces the document names by position. Only a
//! capture has pieces, its seven parts: as JSON, bytes are an array of numbers, several times their
//! size and slow to write and read, and a captured body reaches a mebibyte. Every other field is
//! small text and crosses in the document.
//!
//! ```text
//! doc_len: u32 LE | pieces: u32 LE | doc (JSON) | pieces × (len: u32 LE | bytes)
//! ```
//!
//! The supervisor reads what the proxy chose to write, and once the proxy runs apart that may be
//! what an attacker controls. So a frame is bounded before anything is allocated for it
//! ([`MAX_FRAME`]), a piece count other than the one the document's event takes refuses the frame,
//! and a frame that cannot be read ends the channel: past it, the reader cannot know where the next
//! one starts.

use super::ProxyEvent;
use crate::sandbox::control::{CAPTURE_PARTS, CaptureBytes, Masked};
use std::io::{self, Read};

/// The largest frame either side handles.
///
/// Above the queue's own byte bound, so an event the queue admits on its own is not refused for its
/// size, and far above any event a request produces: the largest, a capture at the highest caps,
/// holds two heads and four bodies of at most a mebibyte each.
pub(super) const MAX_FRAME: usize = super::QUEUE_BYTES + 1024 * 1024;

/// The fixed part of a frame: the document's length and the number of pieces after it.
const HEADER: usize = 8;

/// What crosses, with its capture as `C`: the proxy's [`Masked`], or [`CaptureDoc`] in the
/// document.
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub(super) enum Frame<C> {
    /// Something the proxy did.
    Event(ProxyEvent<C>),
    /// A mark the supervisor acknowledges once everything written before it is applied.
    Barrier(u64),
}

/// A capture as the document holds it: the number it is filed under and whether each part was cut
/// at its cap. The parts' bytes are the frame's pieces, in [`Masked::into_parts`] order.
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub(super) struct CaptureDoc {
    seq: u64,
    truncated: [bool; CAPTURE_PARTS],
}

/// `frame` as the bytes that cross, or `None` when they would exceed [`MAX_FRAME`]: an event no
/// request can have produced, which the supervisor would refuse and the channel with it.
pub(super) fn encode(frame: Frame<Masked>) -> io::Result<Option<Vec<u8>>> {
    let mut pieces = Vec::new();
    let doc = match frame {
        Frame::Barrier(n) => Frame::Barrier(n),
        Frame::Event(event) => Frame::Event(event.try_map_capture(|masked| {
            let (seq, parts) = masked.into_parts();
            let truncated = parts.each_ref().map(|part| part.truncated);
            pieces.extend(parts.map(|part| part.bytes));
            Ok::<_, io::Error>(CaptureDoc { seq, truncated })
        })?),
    };
    let doc = serde_json::to_vec(&doc).map_err(io::Error::other)?;
    let size = pieces
        .iter()
        .try_fold(HEADER.saturating_add(doc.len()), |size: usize, piece| {
            size.checked_add(4)?.checked_add(piece.len())
        });
    let Some(size) = size.filter(|&size| size <= MAX_FRAME) else {
        return Ok(None);
    };
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(&length(doc.len())?);
    out.extend_from_slice(&length(pieces.len())?);
    out.extend_from_slice(&doc);
    for piece in pieces {
        out.extend_from_slice(&length(piece.len())?);
        out.extend_from_slice(&piece);
    }
    Ok(Some(out))
}

/// The next frame from `from`, or `None` where the channel ends between two frames. Every other
/// failure is an `Err`, and the channel is then unreadable.
pub(super) fn read(from: &mut impl Read) -> io::Result<Option<Frame<Masked>>> {
    let mut header = [0u8; HEADER];
    if !fill_or_end(from, &mut header)? {
        return Ok(None);
    }
    let [a, b, c, d, e, f, g, h] = header;
    let doc_len = to_usize(u32::from_le_bytes([a, b, c, d]))?;
    let count = to_usize(u32::from_le_bytes([e, f, g, h]))?;
    if count > CAPTURE_PARTS {
        return Err(invalid("more pieces than any event carries"));
    }
    let mut size = HEADER.saturating_add(doc_len);
    if size > MAX_FRAME {
        return Err(invalid("a document larger than a frame carries"));
    }
    let doc = take(from, doc_len)?;
    let mut pieces = Vec::with_capacity(count);
    for _ in 0..count {
        let mut len = [0u8; 4];
        from.read_exact(&mut len)?;
        let len = to_usize(u32::from_le_bytes(len))?;
        size = size.saturating_add(4).saturating_add(len);
        if size > MAX_FRAME {
            return Err(invalid("a frame larger than the channel carries"));
        }
        pieces.push(take(from, len)?);
    }
    let doc: Frame<CaptureDoc> =
        serde_json::from_slice(&doc).map_err(|_| invalid("a document that does not parse"))?;
    let mut pieces = pieces.into_iter();
    let frame = match doc {
        Frame::Barrier(n) => Frame::Barrier(n),
        Frame::Event(event) => Frame::Event(event.try_map_capture(|doc| {
            let mut parts: [CaptureBytes; CAPTURE_PARTS] = Default::default();
            for (part, truncated) in parts.iter_mut().zip(doc.truncated) {
                let bytes = pieces
                    .next()
                    .ok_or_else(|| invalid("fewer pieces than the capture has parts"))?;
                *part = CaptureBytes { bytes, truncated };
            }
            Ok::<_, io::Error>(Masked::received(doc.seq, parts))
        })?),
    };
    if pieces.next().is_some() {
        return Err(invalid("pieces the document does not name"));
    }
    Ok(Some(frame))
}

/// Fill `buf`, or report `false` when the channel ended before its first byte.
fn fill_or_end(from: &mut impl Read, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match from.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// The next `len` bytes, `len` already held to [`MAX_FRAME`].
fn take(from: &mut impl Read, len: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    from.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// A length as it is written, which [`MAX_FRAME`] keeps within a `u32`.
fn length(len: usize) -> io::Result<[u8; 4]> {
    u32::try_from(len)
        .map(u32::to_le_bytes)
        .map_err(|_| invalid("a length past what a frame carries"))
}

/// A length as it is read.
fn to_usize(len: u32) -> io::Result<usize> {
    usize::try_from(len).map_err(|_| invalid("a length past what this host addresses"))
}

/// A frame the supervisor refuses, saying `what` is wrong with it.
fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("proxy report: {what}"))
}
