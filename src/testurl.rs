// A fixture path as a `file://` URL, one definition shared by the unit tests and the integration
// tests.
//
// This file is **included**, not linked, for the reason `testroot.rs` gives: the integration tests
// are separate crates and cannot see into the binary, so `src/testutil.rs` and `tests/common`
// `include!` this text.

/// `path` as a `file://` URL, every byte outside the unreserved characters and `/` percent-encoded.
///
/// git and curl both decode the path of a `file://` URL, so a fixture root holding a `%` would
/// otherwise name another directory (`pc%41` is read as `pcA`). Encoding every other byte also
/// makes the URL plain ASCII whatever the root holds, so it reaches a verb that takes the URL as
/// text even when the path is not UTF-8.
pub fn file_url(path: &std::path::Path) -> String {
    use std::fmt::Write as _;
    use std::os::unix::ffi::OsStrExt as _;
    let mut url = String::from("file://");
    for &byte in path.as_os_str().as_bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~/".contains(&byte) {
            url.push(char::from(byte));
        } else {
            let _ = write!(url, "%{byte:02X}");
        }
    }
    url
}
