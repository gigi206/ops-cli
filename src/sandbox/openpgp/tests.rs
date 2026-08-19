//! What this module has to get right is not "a good signature verifies" — that is the easy half,
//! and a parser that ignored the message entirely would pass it. Each test below names the bypass
//! it closes.

use super::*;

/// A clearsigned `Release`-shaped document and the RSA-4096 key that signed it, produced by GnuPG
/// with SHA-512 so the fixtures are a real implementation's output rather than this module's own
/// encoder read back. The key is exported twice: as a certificate carrying its user ID (the old
/// packet framing, which is what an export gives) and as the bare primary key packet (the new
/// framing, which is what a keyserver serves) — both must read to the same fingerprint.
const CLEARSIGNED: &str = include_str!("clearsigned.txt");
const KEY: &str = include_str!("key.asc");
const KEY_BARE: &str = include_str!("key_bare.asc");
const KEY_OTHER: &str = include_str!("key_other.asc");

/// The fingerprint of the signing key, written out rather than derived, so a bug that changed how
/// fingerprints are computed cannot move the expectation with the code.
const FINGERPRINT: &str = "1FFE0D7662DDC9747DAFECFEB1F5346541A3CC25";

/// The pin a caller would hold. Taken from the key rather than re-parsed from text, because that is
/// how production holds it: a pinned key file is the anchor, and its fingerprint is derived from the
/// very bytes that verify. The literal above is what binds that derivation to a value GnuPG prints.
fn pinned() -> Fingerprint {
    parse_public_key(KEY)
        .expect("the fixture key parses")
        .fingerprint
}

#[test]
fn a_key_reads_to_its_published_fingerprint_in_either_packet_framing() {
    let cert = parse_public_key(KEY).expect("the exported certificate parses");
    let bare = parse_public_key(KEY_BARE).expect("the bare primary key parses");
    // Derived from the packet bytes, so it holds against the value GnuPG prints for the same key.
    assert_eq!(hex(&cert.fingerprint), FINGERPRINT);
    // The two framings — old (`0x99`) and new (`0xc6`) — must not read to different keys, or which
    // form a keyserver happened to serve would decide whether a pin matches.
    assert_eq!(cert.fingerprint, bare.fingerprint);
    assert_eq!(
        hex(&parse_public_key(KEY_OTHER).unwrap().fingerprint).len(),
        40
    );
    assert_ne!(
        parse_public_key(KEY_OTHER).unwrap().fingerprint,
        cert.fingerprint
    );
}

#[test]
fn a_signature_verifies_and_yields_the_text_that_was_signed() {
    let key = parse_public_key(KEY).unwrap();
    let message = verify_clearsigned(CLEARSIGNED, &key, &pinned()).expect("the fixture verifies");
    // The value handed back is the message, not the armored document: a caller that parsed the
    // whole file would be parsing the signature armor as if it were signed content.
    assert!(message.starts_with("Origin: demo-repo"));
    assert!(!message.contains("BEGIN PGP"));
    assert!(message.contains("main/binary-amd64/Packages"));
}

#[test]
fn a_document_signed_by_another_key_is_refused_before_the_key_is_used() {
    let other = parse_public_key(KEY_OTHER).unwrap();
    let err = verify_clearsigned(CLEARSIGNED, &other, &pinned()).expect_err("must refuse");
    // The refusal names the pin mismatch, which is the check that must fire FIRST: were the
    // signature verified before the fingerprint were compared, a wrong key that happened to verify
    // would be observable. Reaching the verifier at all would produce the other message.
    assert!(err.contains("not the pinned one"), "{err}");
    assert!(!err.contains("verification failed"), "{err}");
    // The control that makes the ordering visible: pin the very key being offered, so the
    // fingerprint gate passes, and the same call now fails at the *signature* instead. Two distinct
    // refusals for two distinct reasons — which is what "the fingerprint is compared first" means,
    // and a single collapsed error would not show.
    let past_the_pin = verify_clearsigned(CLEARSIGNED, &other, &other.fingerprint)
        .expect_err("a document this key did not sign must not verify");
    assert!(
        past_the_pin.contains("verification failed"),
        "{past_the_pin}"
    );
}

#[test]
fn a_changed_message_is_refused_even_though_the_signature_is_untouched() {
    let key = parse_public_key(KEY).unwrap();
    // Flip one digit of the digest the document attests. This is the whole point of the module: an
    // index swapped under a signature that still parses must not verify.
    let tampered =
        CLEARSIGNED.replacen("main/binary-amd64/Packages", "main/binary-i386/Packages", 1);
    assert_ne!(tampered, CLEARSIGNED, "the fixture must contain the line");
    let err = verify_clearsigned(&tampered, &key, &pinned()).expect_err("must refuse");
    assert!(err.contains("verification failed"), "{err}");
}

#[test]
fn a_second_signature_is_refused_rather_than_searched_for_a_good_one() {
    let key = parse_public_key(KEY).unwrap();
    let doc = split_clearsigned(CLEARSIGNED).unwrap();
    // Append the very signature that verifies to itself. A verifier that iterated packets and
    // accepted the first one that held would pass this; so would one that accepted the last. Both
    // are the bypass: an attacker appends a packet beside a real one.
    let mut two = doc.signature.clone();
    two.extend_from_slice(&doc.signature);
    let err = parse_signature(&two)
        .err()
        .expect("two signature packets must be refused");
    assert!(err.contains("exactly one signature packet"), "{err}");
    // One packet still reads, so the refusal is about the count and not about the concatenation
    // being unparseable.
    assert!(parse_signature(&doc.signature).is_ok());
    assert!(verify_clearsigned(CLEARSIGNED, &key, &pinned()).is_ok());
}

#[test]
fn the_canonical_form_is_what_is_hashed_and_the_plain_form_is_what_is_returned() {
    let doc = split_clearsigned(CLEARSIGNED).unwrap();
    // A text-document signature hashes CRLF line endings; the message as read has none. Both come
    // out of the same pass over the same lines, so they cannot describe different texts.
    assert!(doc.signed.windows(2).any(|w| w == b"\r\n"));
    assert!(!doc.plain.contains('\r'));
    assert_eq!(
        doc.signed.iter().filter(|b| **b == b'\n').count(),
        doc.plain.matches('\n').count()
    );
    // Neither form carries the armor that frames them.
    assert!(!doc.plain.contains("-----"));
}

#[test]
fn dash_escaped_lines_are_unescaped_before_they_are_hashed() {
    // A signer escapes a line that would otherwise read as armor. Both forms must drop the escape:
    // hashing it would break verification, and returning it would hand the caller a line the signer
    // never wrote.
    let escaped = CLEARSIGNED.replacen("Origin: demo-repo", "- Origin: demo-repo", 1);
    let doc = split_clearsigned(&escaped).unwrap();
    assert!(doc.plain.starts_with("Origin: demo-repo"), "{}", doc.plain);
    assert!(doc.signed.starts_with(b"Origin: demo-repo"));
    // And with the escape removed the document is byte-for-byte the one that verifies.
    let key = parse_public_key(KEY).unwrap();
    assert!(verify_clearsigned(&escaped, &key, &pinned()).is_ok());
}

#[test]
fn a_signature_names_the_issuer_whose_key_a_first_pin_must_fetch() {
    // Read from the signature's own hashed area, which is what a first pin has to go on. It is a
    // claim and not a proof, which is why the fetched key is bound back to it before use — the
    // property under test here is only that the claim is read correctly.
    assert_eq!(hex(&issuer_fingerprint(CLEARSIGNED).unwrap()), FINGERPRINT);
}

#[test]
fn malformed_input_is_an_error_and_never_a_panic() {
    let key = parse_public_key(KEY).unwrap();
    // Every prefix of the document: each one truncates a different structure — the armor headers,
    // the message, the base64, a packet header, a subpacket, an MPI. None may panic.
    for cut in 0..CLEARSIGNED.len() {
        if !CLEARSIGNED.is_char_boundary(cut) {
            continue;
        }
        let _ = verify_clearsigned(&CLEARSIGNED[..cut], &key, &pinned());
        let _ = issuer_fingerprint(&CLEARSIGNED[..cut]);
    }
    for cut in 0..KEY.len() {
        if KEY.is_char_boundary(cut) {
            let _ = parse_public_key(&KEY[..cut]);
        }
    }
    // A truncated document must not verify, whatever else it does.
    assert!(verify_clearsigned(&CLEARSIGNED[..CLEARSIGNED.len() - 40], &key, &pinned()).is_err());
    assert!(parse_public_key("").is_err());
    assert!(parse_public_key(CLEARSIGNED).is_err());
}

#[test]
fn trailing_whitespace_is_stripped_before_hashing_so_a_padded_line_still_verifies() {
    let key = parse_public_key(KEY).unwrap();
    // A canonical text signature is computed over lines with their trailing whitespace removed, so
    // whitespace added in transit — by a proxy, an editor, a transport that pads — must not change
    // the verdict. Padding a line here and still verifying is what proves the stripping happens: a
    // canonicaliser that only dropped `\r` would hash different bytes and refuse a document its
    // signer did sign.
    let padded = CLEARSIGNED.replacen("Suite: stable", "Suite: stable \t ", 1);
    assert_ne!(padded, CLEARSIGNED, "the fixture must contain the line");
    assert!(verify_clearsigned(&padded, &key, &pinned()).is_ok());
    // The message handed back is the line as transmitted; only the hash input is canonicalised.
    let doc = split_clearsigned(&padded).unwrap();
    assert!(doc.plain.contains("Suite: stable \t "));
    assert!(!doc.signed.windows(4).any(|w| w == b"le \t"));
}
