//! A deliberately small OpenPGP reader: enough to verify the clearsigned `InRelease` an apt
//! repository publishes, and nothing else.
//!
//! Security keystone. This is not an OpenPGP implementation and must never grow into one. It
//! accepts exactly the shape the chain it serves actually uses and refuses everything else, so the
//! surface a reviewer has to audit is the list below rather than the standard:
//!
//! * a clearsigned document carrying **exactly one** signature packet — a second one is refused
//!   rather than searched, because "accept if any signature verifies" is the bypass this whole
//!   module exists to prevent (an attacker appends a packet of their own beside the real one);
//! * a **version 4** signature over a **canonical text document** (type `0x01`);
//! * **RSA** (public-key algorithm 1) with **SHA-512** or **SHA-256** — the two an apt vendor
//!   signs with. MD5 and SHA-1 are refused, not merely deprecated;
//! * a **version 4** RSA public key, as a single packet.
//!
//! Everything is parsed from byte slices with checked indexing, so a malformed input is an error
//! and never a panic. The one thing this module does not do is decide *what* to trust: a caller
//! hands it the fingerprint it pinned, and the key material is bound to that fingerprint **before**
//! the key reaches the verifier, so a successful verification under the wrong key is not reachable.

use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA512};

/// A v4 OpenPGP fingerprint: the 20 bytes that name a key, and the only trust anchor this module
/// takes. Rendered as the uppercase hex a vendor publishes.
pub(crate) type Fingerprint = [u8; 20];

/// Render a fingerprint the way OpenPGP tooling prints it, so a mismatch names both sides in a form
/// the user can compare against `gpg --fingerprint`. The encoding itself is the crate's one hex
/// writer; only the case is this module's, OpenPGP fingerprints being published in upper case.
pub(crate) fn hex(fpr: &Fingerprint) -> String {
    crate::plugins::catalogue::to_hex(fpr).to_uppercase()
}

/// The RSA public key this module verifies with: the two components `ring` needs, plus the
/// fingerprint they hash to. Built only by [`parse_public_key`], so a value of this type has always
/// had its fingerprint derived from the very bytes that carry `n` and `e`.
pub(crate) struct PublicKey {
    pub(crate) fingerprint: Fingerprint,
    modulus: Vec<u8>,
    exponent: Vec<u8>,
}

/// The header an armored block opens with, and the one it closes with.
const KEY_ARMOR: (&str, &str) = ("-----BEGIN PGP PUBLIC KEY BLOCK-----", "-----END PGP");
const CLEARSIGN_HEADER: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
const SIGNATURE_HEADER: &str = "-----BEGIN PGP SIGNATURE-----";

/// Strip an ASCII-armored block down to the bytes it encodes: drop the armor headers, the blank
/// line that ends them, the `=`-prefixed CRC line and the trailing armor. The CRC is **not**
/// checked — it is a transmission checksum, not a security property, and the signature (or the
/// fingerprint, for a key) is what actually holds here.
fn dearmor(text: &str, begin: &str) -> Result<Vec<u8>, String> {
    let start = text
        .find(begin)
        .ok_or_else(|| format!("no `{begin}` block"))?;
    let mut body = String::new();
    // Armor headers (`Version:`, `Comment:`) run until the first blank line; everything after that,
    // up to the closing armor, is base64 except the CRC line.
    let mut in_headers = true;
    for line in text[start..].lines().skip(1) {
        let line = line.trim();
        if line.starts_with("-----END") {
            return base64_decode(&body);
        }
        if in_headers {
            if line.is_empty() {
                in_headers = false;
            } else if !line.contains(':') {
                // A block with no armor headers at all: this line is already base64.
                in_headers = false;
                body.push_str(line);
            }
            continue;
        }
        if line.starts_with('=') || line.is_empty() {
            continue;
        }
        body.push_str(line);
    }
    Err("armored block is not terminated".to_string())
}

/// Decode standard base64 with no padding tolerance beyond the trailing `=`. Written out rather
/// than pulled in: the input is a few hundred bytes and adding a dependency for it would widen the
/// supply chain of a security path to save twenty lines.
fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let v = ALPHABET
            .iter()
            .position(|&a| a == c)
            .ok_or("armored block carries a non-base64 character")? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

/// Split an OpenPGP byte stream into `(tag, body)` packets. Both the old and the new header format
/// are read, because a signature travels in the old format (`0x89`) while a key served by a
/// keyserver arrives in the new one (`0xc6`). Partial and indeterminate lengths are refused: they
/// cannot occur in the two artefacts this module reads, and accepting them would mean guessing
/// where a packet ends.
fn packets(mut buf: &[u8]) -> Result<Vec<(u8, &[u8])>, String> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        let ctb = buf[0];
        if ctb & 0x80 == 0 {
            return Err("not an OpenPGP packet header".to_string());
        }
        let (tag, len, header) = if ctb & 0x40 == 0 {
            // Old format: the tag is bits 5..2 and the length type is bits 1..0.
            let tag = (ctb >> 2) & 0x0f;
            match ctb & 0x03 {
                0 => (
                    tag,
                    *buf.get(1).ok_or("truncated packet header")? as usize,
                    2,
                ),
                1 => (
                    tag,
                    u16::from_be_bytes([
                        *buf.get(1).ok_or("truncated packet header")?,
                        *buf.get(2).ok_or("truncated packet header")?,
                    ]) as usize,
                    3,
                ),
                2 => {
                    let b = buf.get(1..5).ok_or("truncated packet header")?;
                    (
                        tag,
                        u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize,
                        5,
                    )
                }
                _ => return Err("indeterminate packet length is refused".to_string()),
            }
        } else {
            // New format: the tag is the low six bits and the length is self-describing.
            let tag = ctb & 0x3f;
            let first = *buf.get(1).ok_or("truncated packet header")?;
            match first {
                0..=191 => (tag, first as usize, 2),
                192..=223 => {
                    let second = *buf.get(2).ok_or("truncated packet header")?;
                    (
                        tag,
                        ((first as usize - 192) << 8) + second as usize + 192,
                        3,
                    )
                }
                255 => {
                    let b = buf.get(2..6).ok_or("truncated packet header")?;
                    (
                        tag,
                        u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize,
                        6,
                    )
                }
                _ => return Err("partial packet length is refused".to_string()),
            }
        };
        let body = buf
            .get(header..header + len)
            .ok_or("packet runs past the end of the block")?;
        out.push((tag, body));
        buf = &buf[header + len..];
    }
    Ok(out)
}

/// Read one multiprecision integer — a two-byte bit count followed by that many bits, big-endian —
/// returning it and the offset just past it.
fn mpi(body: &[u8], at: usize) -> Result<(&[u8], usize), String> {
    let bits = u16::from_be_bytes([
        *body.get(at).ok_or("truncated MPI")?,
        *body.get(at + 1).ok_or("truncated MPI")?,
    ]) as usize;
    let len = bits.div_ceil(8);
    let value = body
        .get(at + 2..at + 2 + len)
        .ok_or("MPI runs past the end of the packet")?;
    Ok((value, at + 2 + len))
}

/// Parse an armored RSA public key into the components `ring` verifies with, deriving its
/// fingerprint from the packet body as OpenPGP defines it: `SHA-1` over `0x99`, the two-byte body
/// length, and the body. SHA-1 is used here because the v4 fingerprint **is** that construction —
/// it names a key, it does not attest anything, and the signature is what carries the security.
pub(crate) fn parse_public_key(armored: &str) -> Result<PublicKey, String> {
    let bytes = dearmor(armored, KEY_ARMOR.0)?;
    let packets = packets(&bytes)?;
    // A keyserver may serve a certificate carrying user IDs, their self-signatures and subkeys.
    // Only the primary key is read, and it must come first, as OpenPGP requires: taking "the first
    // public-key packet" rather than searching means a subkey appended by someone else is never
    // what gets pinned.
    let (tag, body) = *packets.first().ok_or("the key block carries no packet")?;
    if tag != 6 {
        return Err("the key block does not open with a public-key packet".to_string());
    }
    if *body.first().ok_or("empty public-key packet")? != 4 {
        return Err("only a version 4 public key is read".to_string());
    }
    // v4 body: version, 4-byte creation time, algorithm, then the algorithm's MPIs.
    if *body.get(5).ok_or("truncated public-key packet")? != 1 {
        return Err("only an RSA public key is read".to_string());
    }
    let (modulus, at) = mpi(body, 6)?;
    let (exponent, _) = mpi(body, at)?;
    // SHA-1 is reached for through `ring`'s legacy handle rather than a new dependency: the v4
    // fingerprint *is* this construction, it names a key rather than attesting anything, and the
    // signature verified above it is what carries the security.
    let mut h = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    h.update(&[0x99]);
    h.update(
        &u16::try_from(body.len())
            .map_err(|_| "public-key packet is too long to fingerprint".to_string())?
            .to_be_bytes(),
    );
    h.update(body);
    let mut fingerprint = [0u8; 20];
    fingerprint.copy_from_slice(h.finish().as_ref());
    Ok(PublicKey {
        fingerprint,
        modulus: modulus.to_vec(),
        exponent: exponent.to_vec(),
    })
}

/// A clearsigned document, split into the bytes that were signed and the signature over them.
struct Clearsigned {
    /// The message in the canonical form a text-document signature hashes: dash-unescaped, trailing
    /// whitespace removed from every line, lines joined with CRLF and no terminator after the last.
    signed: Vec<u8>,
    /// The message as it reads, which is what a caller consumes once the signature holds.
    plain: String,
    signature: Vec<u8>,
}

/// Split a clearsigned document per OpenPGP's rules for one. The two forms of the message are
/// produced together, from the same lines, so the bytes a caller reads can never be a different
/// text from the bytes that were verified.
fn split_clearsigned(text: &str) -> Result<Clearsigned, String> {
    if !text.starts_with(CLEARSIGN_HEADER) {
        return Err("not a clearsigned document".to_string());
    }
    // The armor headers (`Hash: SHA512`) end at the first blank line.
    let after_headers = text
        .find("\n\n")
        .ok_or("clearsigned document has no armor header block")?
        + 2;
    let signature_at = text
        .find(SIGNATURE_HEADER)
        .ok_or("clearsigned document carries no signature")?;
    let body = text
        .get(after_headers..signature_at)
        .ok_or("clearsigned document is malformed")?;
    // The newline that ends the last message line belongs to the armor that follows, not to the
    // message; strip exactly one.
    let body = body.strip_suffix('\n').unwrap_or(body);
    let mut signed = Vec::with_capacity(body.len() + 64);
    let mut plain = String::with_capacity(body.len());
    for (i, line) in body.split('\n').enumerate() {
        // Dash-escaping: a line the signer prefixed with "- " to keep it from reading as armor.
        let line = line.strip_prefix("- ").unwrap_or(line);
        if i > 0 {
            signed.extend_from_slice(b"\r\n");
            plain.push('\n');
        }
        signed.extend_from_slice(line.trim_end_matches([' ', '\t', '\r']).as_bytes());
        plain.push_str(line);
    }
    Ok(Clearsigned {
        signed,
        plain,
        signature: dearmor(text.get(signature_at..).unwrap_or(""), SIGNATURE_HEADER)?,
    })
}

/// What a signature packet carries that this module acts on.
struct Signature {
    hash_algorithm: u8,
    /// The bytes hashed after the message: the signature's own metadata, as OpenPGP prescribes.
    trailer: Vec<u8>,
    value: Vec<u8>,
}

/// Parse the single signature packet a clearsigned document carries, refusing anything outside the
/// shape this module serves. The count is checked before the contents: a document carrying a second
/// signature is refused outright rather than searched for one that verifies.
fn parse_signature(bytes: &[u8]) -> Result<Signature, String> {
    let packets = packets(bytes)?;
    let signatures: Vec<_> = packets.iter().filter(|(tag, _)| *tag == 2).collect();
    if signatures.len() != 1 || packets.len() != 1 {
        return Err(format!(
            "expected exactly one signature packet, found {} packet(s) of which {} are signatures",
            packets.len(),
            signatures.len()
        ));
    }
    let body = signatures[0].1;
    let head = body.get(0..6).ok_or("truncated signature packet")?;
    if head[0] != 4 {
        return Err("only a version 4 signature is read".to_string());
    }
    if head[1] != 0x01 {
        return Err("only a signature over a canonical text document is read".to_string());
    }
    if head[2] != 1 {
        return Err("only an RSA signature is read".to_string());
    }
    if head[3] != 8 && head[3] != 10 {
        return Err("only a SHA-256 or SHA-512 signature is read".to_string());
    }
    let hashed_len = u16::from_be_bytes([head[4], head[5]]) as usize;
    let hashed = body
        .get(6..6 + hashed_len)
        .ok_or("hashed subpackets run past the end of the signature")?;
    let at = 6 + hashed_len;
    let unhashed_len = u16::from_be_bytes([
        *body.get(at).ok_or("truncated signature packet")?,
        *body.get(at + 1).ok_or("truncated signature packet")?,
    ]) as usize;
    // Past the unhashed subpackets and the two-byte digest prefix lies the signature MPI. The
    // prefix is a transmission check the verifier does not need: `ring` recomputes the digest.
    let (value, _) = mpi(body, at + 2 + unhashed_len + 2)?;
    let mut trailer = body[0..6].to_vec();
    trailer.extend_from_slice(hashed);
    let hashed_count =
        u32::try_from(trailer.len()).map_err(|_| "signature metadata is too long".to_string())?;
    let mut full = trailer.clone();
    full.extend_from_slice(&[0x04, 0xff]);
    full.extend_from_slice(&hashed_count.to_be_bytes());
    Ok(Signature {
        hash_algorithm: head[3],
        trailer: full,
        value: value.to_vec(),
    })
}

/// Verify a clearsigned document against a key already bound to the fingerprint the caller pinned,
/// returning the message **only** when the signature holds over exactly those bytes.
///
/// The order here is the security property, not a style: the fingerprint is compared first, so the
/// key never reaches the verifier unless it is the pinned one, and no observable outcome
/// distinguishes "verified under a key you did not pin" from "refused". Fail-closed at every step,
/// with one opaque class of error, so nothing here answers questions about a key it rejected.
pub(crate) fn verify_clearsigned(
    text: &str,
    key: &PublicKey,
    pinned: &Fingerprint,
) -> Result<String, String> {
    if key.fingerprint != *pinned {
        return Err(format!(
            "this signing key is not the pinned one\n  pinned: {}\n  offered: {}",
            hex(pinned),
            hex(&key.fingerprint)
        ));
    }
    let doc = split_clearsigned(text)?;
    let signature = parse_signature(&doc.signature)?;
    let mut message = doc.signed;
    message.extend_from_slice(&signature.trailer);
    let algorithm = if signature.hash_algorithm == 10 {
        &RSA_PKCS1_2048_8192_SHA512
    } else {
        &RSA_PKCS1_2048_8192_SHA256
    };
    ring::signature::RsaPublicKeyComponents {
        n: key.modulus.as_slice(),
        e: key.exponent.as_slice(),
    }
    .verify(algorithm, &message, &signature.value)
    .map_err(|_| "signature verification failed".to_string())?;
    Ok(doc.plain)
}

/// The fingerprint a signature names as its issuer, read from hashed subpacket 33 (issuer
/// fingerprint). Used **only** to learn which key to fetch on a first pin; it is a claim by whoever
/// wrote the signature and attests nothing, which is why the key fetched by it is bound back to it
/// before any verification happens.
pub(crate) fn issuer_fingerprint(text: &str) -> Result<Fingerprint, String> {
    let doc = split_clearsigned(text)?;
    let packets = packets(&doc.signature)?;
    let (_, body) = packets
        .iter()
        .find(|(tag, _)| *tag == 2)
        .ok_or("the document carries no signature packet")?;
    let hashed_len = u16::from_be_bytes([
        *body.get(4).ok_or("truncated signature packet")?,
        *body.get(5).ok_or("truncated signature packet")?,
    ]) as usize;
    let mut at = 6;
    let end = 6 + hashed_len;
    while at < end {
        // Subpacket framing: a length (one, two or five bytes) then a type byte and its data.
        let first = *body.get(at).ok_or("truncated subpacket")? as usize;
        let (len, header) = match first {
            0..=191 => (first, 1),
            192..=254 => (
                ((first - 192) << 8)
                    + *body.get(at + 1).ok_or("truncated subpacket")? as usize
                    + 192,
                2,
            ),
            _ => {
                let b = body.get(at + 1..at + 5).ok_or("truncated subpacket")?;
                (u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize, 5)
            }
        };
        let data = body
            .get(at + header..at + header + len)
            .ok_or("subpacket runs past the hashed area")?;
        // Type 33 is `issuer fingerprint`, whose first byte is the key version.
        // The high bit of the type byte marks a subpacket critical; it is not part of the type.
        if data.first().is_some_and(|t| t & 0x7f == 33) {
            let value = data.get(2..22).ok_or("issuer fingerprint is truncated")?;
            let mut out = [0u8; 20];
            out.copy_from_slice(value);
            return Ok(out);
        }
        at += header + len;
    }
    Err("the signature does not name its issuer's fingerprint".to_string())
}

#[cfg(test)]
mod tests;
