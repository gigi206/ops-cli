//! CA trust for Chromium/Electron GUI apps under a filtering egress posture.
//!
//! Under an allowlist ops runs a TLS-terminating proxy with a per-session CA and injects that
//! CA into the cage through the CA-file environment variables (`SSL_CERT_FILE`,
//! `NODE_EXTRA_CA_CERTS`, …). Command-line tools honour those, but **Chromium/Electron does
//! not** — it verifies server certificates against its own **NSS database** (`~/.pki/nssdb`),
//! so a graphical app rejects ops's CA (`ERR_CERT_AUTHORITY_INVALID`) and its UI cannot load.
//!
//! This is conceptually part of the Wayland GUI hole (like fonts): when a GUI cage also runs a
//! filtering posture, ops provisions `certutil` and prepends a step that imports the bound CA
//! into the cage's NSS db before the app runs. No new trust is granted — the cage already trusts
//! ops's MITM CA via the env vars; this only extends the *same* trust to the store Chromium
//! reads. Only GUI + filtering cages pay for it (a CLI tool needs nothing, and a `shared`/`none`
//! posture has no MITM CA), so the cost is gated to exactly the cages that need it.

use crate::store::{self, Layout};
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

/// The nixpkgs attribute providing `certutil`, the directory-relative marker its output must
/// contain, and the gcroot name. `nss.tools` is the NSS command-line tools output.
const CERTUTIL: (&str, &str, &str) = ("nss.tools", "bin/certutil", "nss-tools");

/// The NSS nickname for ops's imported CA, and the prefix the wrap purges. Every per-session CA
/// shares the **same subject DN** (`CN=ops egress proxy CA`) with a different key, so if several
/// accumulate in the persistent home's `~/.pki/nssdb`, an NSS issuer lookup (which matches by
/// subject) can pick a *stale* one and reject the current MITM cert — the app then fails every
/// HTTPS with `ERR_CERT_AUTHORITY_INVALID`. So the wrap **purges every `ops-mitm*` entry before
/// re-adding the current CA under this fixed nickname**, keeping exactly one. (This supersedes an
/// earlier content-keyed-nickname scheme that kept every session's CA to dodge a delete-then-add
/// race — the accumulation was assumed harmless; it is not, and frequent breakage in a persistent
/// home outweighs that rare race. See the concurrency note in `wrap`.)
const CA_NICKNAME: &str = "ops-mitm";

/// The provisioned certutil: the binary to invoke and the store root whose closure the project
/// store must seed (so the cage reads it through `/nix`).
pub(crate) struct CaTrust {
    /// The `certutil` binary, invoked by absolute path from the wrap (never relying on PATH).
    pub(crate) certutil: PathBuf,
    /// The logical store root, to seed into the project store like the font packages.
    pub(crate) root: PathBuf,
}

/// Provision `certutil` into ops's store against the pinned `nixpkgs`, sharing the revision-keyed
/// `gui` gcroot directory with the fonts (both are GUI-hole provisions on the same channel).
pub(crate) fn provision(nix: &Path, layout: &Layout, nixpkgs: &str) -> io::Result<CaTrust> {
    let (attr, marker, name) = CERTUTIL;
    let gcroot = layout
        .data_dir()
        .join("gcroots")
        .join("gui")
        .join(store::revision_of(nixpkgs))
        .join(name);
    let logical = store::provision(nix, layout, &gcroot, nixpkgs, attr, marker)?;
    Ok(CaTrust {
        certutil: logical.join(marker),
        root: logical,
    })
}

/// Wrap `cmd` so it imports the bound MITM CA into the cage's NSS db, then `exec`s the command.
///
/// The command rides `"$@"` positionally (after the `$0` label), so nothing from config is
/// interpolated into the script — the only interpolated values are the ops-controlled certutil
/// store path and the fixed cage CA path, neither of which carries a shell metacharacter. Each
/// certutil step is best-effort (`|| true`): a missing/already-initialised db or a concurrent
/// same-home launch must not block the app, and a genuinely broken import degrades to the app's
/// own `ERR_CERT` rather than a launch failure.
pub(crate) fn wrap(
    certutil: &Path,
    bash: &Path,
    ca_cage_path: &str,
    cmd: Vec<OsString>,
) -> Vec<OsString> {
    // Every certutil call reads from `/dev/null`: `-N` on an *existing* db (the persistent home
    // is reused across launches) prompts for confirmation on stdin and would otherwise hang the
    // launch (no tty). The `-N` is also guarded on the db not already existing, so it runs once;
    // stdin redirection is the belt-and-suspenders that keeps any certutil step non-blocking.
    //
    // Purge every prior `ops-mitm*` CA before re-adding the current one under a fixed nickname, so
    // the persistent home's db holds exactly one. Each session's CA shares the same subject DN with
    // a different key, so several accumulated entries collide on NSS issuer lookup and Chromium
    // rejects the current MITM cert (`ERR_CERT_AUTHORITY_INVALID`) — the accumulation is NOT
    // harmless. This purge is a delete-then-add, superseding the earlier content-keyed nickname that
    // kept every session's CA to avoid a concurrency race: frequent total breakage in a persistent
    // home outweighs that race. Residual (accepted): a concurrent SECOND launch of the same app can
    // delete the CA of the first, still-running instance from the shared db; that instance may then
    // fail *new* TLS validations until its next restart (Chromium plausibly caches trust at startup,
    // so an already-running instance may be unaffected). Rare regardless, because these are
    // single-instance GUI apps (a second `ops app <name>` hands off to the running one rather than
    // starting a second cage).
    let script = format!(
        "DB=\"$HOME/.pki/nssdb\"\n\
         mkdir -p \"$DB\"\n\
         [ -f \"$DB/cert9.db\" ] || '{c}' -d \"sql:$DB\" -N --empty-password </dev/null 2>/dev/null || true\n\
         for n in $('{c}' -d \"sql:$DB\" -L 2>/dev/null | grep -oE '{nick}[0-9a-f-]*'); do '{c}' -d \"sql:$DB\" -D -n \"$n\" </dev/null 2>/dev/null || true; done\n\
         '{c}' -d \"sql:$DB\" -A -n {nick} -t 'C,,' -i '{ca}' </dev/null 2>/dev/null || true\n\
         exec \"$@\"",
        c = certutil.to_string_lossy(),
        nick = CA_NICKNAME,
        ca = ca_cage_path,
    );
    let mut out = vec![
        bash.as_os_str().to_os_string(),
        OsString::from("-c"),
        OsString::from(script),
        // `$0` — a label; the command is what remains, run via `exec "$@"`.
        OsString::from("ops-ca-trust"),
    ];
    out.extend(cmd);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_imports_the_ca_then_execs_the_command_positionally() {
        let cmd: Vec<OsString> = ["opencode-desktop", "--no-sandbox"]
            .iter()
            .map(OsString::from)
            .collect();
        let out = wrap(
            Path::new("/nix/store/abc-nss-tools/bin/certutil"),
            Path::new("/nix/store/def-bash/bin/bash"),
            "/opt/ops/egress-ca.pem",
            cmd,
        );

        assert_eq!(out[0], OsString::from("/nix/store/def-bash/bin/bash"));
        assert_eq!(out[1], OsString::from("-c"));
        let script = out[2].to_string_lossy();
        // imports the bound CA into the NSS db Chromium reads, under the fixed nickname
        assert!(script.contains("sql:$DB"));
        assert!(script.contains("-A -n ops-mitm -t 'C,,' -i '/opt/ops/egress-ca.pem'"));
        assert!(script.contains("/nix/store/abc-nss-tools/bin/certutil"));
        // purges every prior `ops-mitm*` entry first, so the persistent db never accumulates
        // several same-subject CAs (which collide on issuer lookup → ERR_CERT_AUTHORITY_INVALID)
        assert!(script.contains("grep -oE 'ops-mitm[0-9a-f-]*'"));
        assert!(script.contains("-D -n \"$n\""));
        // `-N` only when the db is absent, and every certutil step reads /dev/null so an
        // existing-db confirmation prompt can never hang a tty-less launch (the bug this guards).
        assert!(script.contains("[ -f \"$DB/cert9.db\" ] ||"));
        assert_eq!(script.matches("</dev/null").count(), 3);
        assert!(script.trim_end().ends_with("exec \"$@\""));
        // the label, then the command verbatim after it (positional, never in the script)
        assert_eq!(out[3], OsString::from("ops-ca-trust"));
        assert_eq!(out[4], OsString::from("opencode-desktop"));
        assert_eq!(out[5], OsString::from("--no-sandbox"));
        // the command tokens never leak into the script text
        assert!(!script.contains("opencode-desktop"));
    }
}
