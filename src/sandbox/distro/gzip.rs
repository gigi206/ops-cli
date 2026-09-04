//! A streaming gzip reader, so a layer is inflated as it is read rather than held in memory.
//!
//! Written rather than taken as a dependency for the reason the proxy's own inflate was (its
//! WebSocket frame reader already drives `miniz_oxide` in streaming mode): the
//! decompressor is already in the tree, and what gzip adds over raw deflate is a fixed header, a
//! handful of optional fields, and a trailer. Adding a crate to skip fifty lines of framing would
//! buy nothing and cost a dependency.
//!
//! The trailer's CRC is **not** checked, deliberately, and the reason is worth stating: the caller
//! has already verified the compressed blob against the digest that named it, so the bytes going
//! in are exactly the bytes the registry published. A CRC over the same data answers a question
//! already answered by a stronger hash.

use miniz_oxide::inflate::stream::{InflateState, inflate};
use miniz_oxide::{DataFormat, MZFlush, MZStatus};
use std::io::{self, BufRead, Read};

/// The gzip magic and the one compression method the format defines.
const MAGIC: [u8; 2] = [0x1f, 0x8b];
const DEFLATE: u8 = 8;

/// Header flag bits, in the order their fields appear after the fixed header.
const FEXTRA: u8 = 1 << 2;
const FNAME: u8 = 1 << 3;
const FCOMMENT: u8 = 1 << 4;
const FHCRC: u8 = 1 << 1;

/// How much inflated output to produce per read of the underlying stream. Large enough that a
/// layer is not inflated a handful of bytes at a time, small enough to stay a buffer rather than a
/// copy of the layer.
const CHUNK: usize = 64 * 1024;

/// A `Read` over the inflated contents of a gzip stream.
pub(super) struct GzipReader<R> {
    inner: R,
    state: Box<InflateState>,
    /// Inflated bytes not yet handed to the caller, and how far into them we are.
    out: Vec<u8>,
    at: usize,
    done: bool,
}

impl<R: BufRead> GzipReader<R> {
    /// Read and check the gzip header, leaving `inner` positioned at the deflate stream.
    pub(super) fn new(mut inner: R) -> io::Result<Self> {
        let mut fixed = [0u8; 10];
        inner.read_exact(&mut fixed)?;
        if fixed[0..2] != MAGIC {
            return Err(io::Error::other("not a gzip stream"));
        }
        if fixed[2] != DEFLATE {
            return Err(io::Error::other(format!(
                "gzip compression method {} is not deflate",
                fixed[2]
            )));
        }
        let flags = fixed[3];
        if flags & FEXTRA != 0 {
            let mut len = [0u8; 2];
            inner.read_exact(&mut len)?;
            let len = u16::from_le_bytes(len) as u64;
            io::copy(&mut inner.by_ref().take(len), &mut io::sink())?;
        }
        for flag in [FNAME, FCOMMENT] {
            if flags & flag != 0 {
                skip_zero_terminated(&mut inner)?;
            }
        }
        if flags & FHCRC != 0 {
            let mut crc = [0u8; 2];
            inner.read_exact(&mut crc)?;
        }
        Ok(GzipReader {
            inner,
            // Raw, because the gzip framing is handled here and what follows is a bare deflate
            // stream with no zlib header of its own.
            state: InflateState::new_boxed(DataFormat::Raw),
            // Empty, not CHUNK-sized: this buffer holds *inflated* bytes, and a pre-sized one would
            // hand the caller a block of zeros before a single byte had been inflated.
            out: Vec::new(),
            at: 0,
            done: false,
        })
    }
}

/// Consume a zero-terminated header field.
fn skip_zero_terminated<R: BufRead>(inner: &mut R) -> io::Result<()> {
    let mut byte = [0u8; 1];
    loop {
        inner.read_exact(&mut byte)?;
        if byte[0] == 0 {
            return Ok(());
        }
    }
}

impl<R: BufRead> Read for GzipReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            // Hand back what is already inflated before asking for more.
            if self.at < self.out.len() {
                let n = (self.out.len() - self.at).min(buf.len());
                if n > 0 {
                    buf[..n].copy_from_slice(&self.out[self.at..self.at + n]);
                    self.at += n;
                    return Ok(n);
                }
            }
            if self.done {
                return Ok(0);
            }
            let input = self.inner.fill_buf()?;
            let eof = input.is_empty();
            let mut produced = vec![0u8; CHUNK];
            let result = inflate(
                &mut self.state,
                input,
                &mut produced,
                if eof { MZFlush::Finish } else { MZFlush::None },
            );
            self.inner.consume(result.bytes_consumed);
            match result.status {
                Ok(MZStatus::StreamEnd) => self.done = true,
                Ok(_) => {
                    // No progress on either side with input still expected means the stream ended
                    // mid-member; reporting it is better than spinning.
                    if eof && result.bytes_written == 0 {
                        return Err(io::Error::other("gzip stream ended mid-member"));
                    }
                }
                Err(e) => return Err(io::Error::other(format!("inflating gzip: {e:?}"))),
            }
            produced.truncate(result.bytes_written);
            self.out = produced;
            self.at = 0;
        }
    }
}

#[cfg(test)]
mod tests;
