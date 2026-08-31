//! The in-cage tool-equip vocabulary: the two mise invocations, the command wraps that write them
//! into a launch, and the sanitizer that puts a token on a terminal.
//!
//! The halves are kept as one unit because neither is correct alone: the pairing of the pin at
//! equip time with the bump on the roll is what [`MISE_EQUIP_VERB`] states, and a file carrying
//! only one of them would carry half a rule. The equip half is reached from the builder, the roll
//! half from `sbx upgrade`, and the constants both read sit beside the prose that explains why.
//!
//! Everything a wrap emits is written as separate argv elements rather than pasted into a shell
//! string: a package token comes from a project file, so it is data, and a shell that re-read it
//! would find syntax.

use super::*;

/// The mise invocation that equips an app's `[packages] mise:` tools, and the one that rolls them.
///
/// They are a pair and are kept side by side because neither is correct alone: `--pin` freezes the
/// cage's config at the installed version (without it the tool's shim re-resolves on every exec and
/// the app stops launching the day upstream publishes), and `--bump` is what still advances an
/// exact pin (a plain `upgrade` keeps the config's range, and after a pin that range is one
/// version, so the roll would report everything up to date and move nothing). Named constants
/// rather than literals at the call sites, so the pairing is one thing a test can hold.
pub(super) const MISE_EQUIP_VERB: &str = "use -g --pin";
const MISE_ROLL_FLAG: &str = "--bump";

/// The line a launch prints before equipping an app's `mise:` tools.
///
/// Built here rather than formatted at the call site so the announcement and the invocation read
/// from the same constant: a launch that names one command and runs another sends whoever reads the
/// transcript looking for the wrong thing, and that is precisely what a hand-written copy of the
/// verb drifts into.
pub(super) fn equip_announcement(tokens: &[String]) -> String {
    format!(
        "sbx: equipping app packages in-cage via mise {MISE_EQUIP_VERB}: {}",
        tokens.join(", ")
    )
}

/// The `mise upgrade <tokens>` command for one roll group. The rolled tokens are the group's
/// `[packages] mise:` tools, which for a **global app** live in the app-global home pool (Lane-1
/// `mise use -g` pins them there). The cage's ambient primary for a global app is the *per-project*
/// pool, which does not hold them, so a plain `mise upgrade` there would find nothing and silently
/// roll nothing — a regression of a shipped command. So for a global app the roll is pinned to the
/// app-global pool via a bash `MISE_DATA_DIR=<app-global>` prefix; the tokens ride `"$@"`
/// positionally (no shell injection — only the sbx-owned mise path and fixed cage data dir are
/// interpolated), and `exec` keeps the roll the cage's main process. Other runtimes have a single
/// pool (the home), already the ambient primary, so the plain command runs unwrapped.
///
/// `--bump` is the other half of the launch's `use -g --pin`. A plain `mise upgrade` keeps whatever
/// range the config states, and after a pin that range is one exact version: the roll would report
/// every tool as already up to date and move nothing, which is a shipped command going quiet.
///
/// `--bump` takes the latest and rewrites the pin, so the version advances here and only here —
/// which is the whole contract. Measured against a config still saying `latest` (every app before
/// its first launch on this code): `--bump` behaves exactly as the plain form did, so the change
/// carries no regression for a pool that has not been pinned yet.
pub(super) fn mise_upgrade_cmd(
    runtime: binds::Runtime,
    mise: &Path,
    bash: &Path,
    tokens: &[String],
) -> Vec<OsString> {
    if matches!(runtime, binds::Runtime::GlobalApp(_)) {
        let data_dir = binds::mise_app_global_data_dir();
        let script = format!(
            "MISE_DATA_DIR='{data_dir}' exec {mise} upgrade {MISE_ROLL_FLAG} \"$@\"",
            mise = mise.to_string_lossy(),
        );
        let mut cmd = vec![
            bash.as_os_str().to_os_string(),
            OsString::from("-c"),
            OsString::from(script),
            // `$0` — a label; the tokens are `$1..$n`.
            OsString::from("sbx-mise-upgrade"),
        ];
        cmd.extend(tokens.iter().map(OsString::from));
        cmd
    } else {
        let mut cmd = vec![
            mise.as_os_str().to_os_string(),
            OsString::from("upgrade"),
            OsString::from(MISE_ROLL_FLAG),
        ];
        cmd.extend(tokens.iter().map(OsString::from));
        cmd
    }
}

/// A list of mise tool tokens, rendered for the launching terminal.
///
/// The tokens [`auto_equip_tokens`] produces are a `[tools]` key and version copied verbatim out of
/// the project's `.mise.toml` — a file the trust gate never approves and a hostile repo fully
/// controls. A quoted TOML key is an arbitrary string, so it can carry `\r`, `\n` or a CSI
/// sequence, and both of the launch messages that name these tools go straight to the terminal that
/// started sbx. Printed raw, a tool called `"x\u{1b}[2K\rsbx: trusted"` scrubs the trust warnings
/// sbx printed just above it and writes its own in their place, which is the one thing the launching
/// terminal is there to say. [`crate::sandbox::sanitize`] is applied per token rather than once over
/// the joined line so that a legitimately long list is not truncated to a single value's cap.
///
/// Display only — the tokens actually handed to mise stay raw, since they ride `"$@"` positionally
/// (see [`wrap_mise_equip`]) and must reach it exactly as the project wrote them.
pub(super) fn mise_token_display<'a>(tokens: impl IntoIterator<Item = &'a String>) -> String {
    tokens
        .into_iter()
        .map(|t| crate::sandbox::sanitize(t))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The `<token>@<version>` install specs for the project's non-`nix:` mise tools — the tools
/// the launcher auto-equips in-cage rather than host-provisioning. Empty when the project
/// declares no mise file. A pure re-parse of the already-loaded mise files, independent of
/// the host-side `nix:` path, and trust-independent: this is the open self-equip path, so the
/// tools are equipped whether or not the project is trusted (the egress allowlist is the
/// control over where they may be fetched from).
pub(super) fn auto_equip_tokens(cfg: &crate::config::Resolved) -> Vec<String> {
    cfg.mise
        .as_ref()
        .map(|m| {
            crate::sandbox::nixhub::parse_nix_tools(&m.files)
                .non_nix
                .into_iter()
                .map(|t| format!("{}@{}", t.token, t.version))
                .collect()
        })
        .unwrap_or_default()
}

/// Wrap `cmd` so the cage equips a set of mise tools before running it: a static bash that runs
/// `mise <verb> <tokens>` (its stdout redirected to stderr so a piped command's stdout stays
/// clean) and then `exec`s the real command — which therefore stays the cage's main process,
/// leaving an interactive `sbx run`'s pty job control unchanged. The `verb` is an sbx-chosen literal
/// (`install` for the project's local `.mise.toml` tools, `use -g` for the app's `[packages]
/// mise:` ones); the tokens and the command ride `"$@"` positionally, so only the absolute mise
/// path, the sbx-chosen verb, and the integer token count are interpolated into the script — a
/// token from an untrusted config can never inject shell. Best-effort: a failed equip does not
/// abort the command (the missing tool surfaces when it is used), matching the self-equip
/// posture rather than the host `nix:` hard-fail guarantee.
///
/// `mise_data_dir`, when `Some`, pins **only the equip step's** `MISE_DATA_DIR` (the exec'd command
/// keeps the cage's ambient value). This is how a global app's Lane-1 `mise use -g` installs an app
/// package into the app-global home pool while the ambient primary is the per-project pool: the
/// value is an sbx-owned fixed cage path ([`binds::mise_app_global_data_dir`]), so single-quoting it
/// in the assignment is injection-safe.
pub(super) fn wrap_mise_equip(
    mise: &Path,
    bash: &Path,
    verb: &str,
    tokens: &[String],
    mise_data_dir: Option<&str>,
    cmd: Vec<OsString>,
) -> Vec<OsString> {
    let n = tokens.len();
    let data_dir_prefix = match mise_data_dir {
        Some(dir) => format!("MISE_DATA_DIR='{dir}' "),
        None => String::new(),
    };
    let script = format!(
        "{data_dir_prefix}{mise} {verb} \"${{@:1:{n}}}\" 1>&2; shift {n}; exec \"$@\"",
        mise = mise.to_string_lossy(),
    );
    let mut out = vec![
        bash.as_os_str().to_os_string(),
        OsString::from("-c"),
        OsString::from(script),
        // `$0` — a label; the tokens are `$1..$n`, the command is what remains after `shift`.
        OsString::from("sbx-mise-equip"),
    ];
    out.extend(tokens.iter().map(OsString::from));
    out.extend(cmd);
    out
}

/// Wrap `cmd` so the cage builds a set of flake packages before running it: a static bash
/// that, for each `(ref, out-link, key)` triple, runs `nix build <ref> --no-write-lock-file
/// --out-link <out-link>` unless the out-link is already realised, registers a host-resolvable gc
/// root for the build,
/// then `exec`s the real command (which stays the cage's main process, leaving an interactive `sbx run`'s pty
/// job control unchanged). Only the absolute `nix` path, the out-link parent directory, and the
/// integer triple count are interpolated into the script — the refs, out-links, and keys ride
/// `"$@"` positionally, so a value from config can never inject shell. The short-circuit
/// `[ -e "$out/bin" ]` dereferences the out-link symlink into the cage's `/nix` (the per-project
/// store): a path already present skips the build (a warm no-op that also works offline), while a
/// dangling cross-project out-link (the `home_scope = "global"` residual) rebuilds.
///
/// The gc root is the same pattern mise's plugin uses for its installs: a symlink under
/// `/nix/var/nix/gcroots/` whose target is the build's `/nix/store/<hash>` path — host-resolvable
/// (the relocated store reads it both in-cage and host-side), unlike the in-cage `--out-link`
/// indirect root nix also creates, whose `/home/sandbox/…` target dangles host-side. Keyed by the
/// **package name** and overwritten (`ln -sfn`) every launch: a roll re-points the one root to the
/// new build, dropping the old store path, so a host-side `sbx gc` keeps the current build and
/// collects the rolled-away one with no per-home enumeration. Written unconditionally (warm or
/// fresh) so an older store missing the root self-heals. Best-effort: a failed build leaves no
/// out-link, so the `readlink` yields nothing and no root is written (the missing tool surfaces
/// when it is used), matching the in-cage self-equip posture. `mkdir`/`ln`/`readlink` are invoked
/// by name (the base coreutils); a persisted tool shadowing one on PATH is a trusted layer harming
/// its own cage — the self-equip self-harm class already accepted, never a cross-tenant concern.
pub(super) fn wrap_flake_equip(
    nix: &Path,
    bash: &Path,
    flake_dir: &Path,
    quads: &[(String, PathBuf, PathBuf, String)],
    cmd: Vec<OsString>,
) -> Vec<OsString> {
    let n = quads.len();
    // Per package (`$1` ref, `$2` build target, `$3` good out-link, `$4` key): build the target if
    // it is neither warm nor already known-failed (a `<target>.failed` marker, so a broken pin is
    // retried once per build target, not on every launch, and an edited flake — a new
    // content-keyed target — is attempted afresh). On success the good out-link (what PATH resolves
    // through) is promoted to the
    // fresh build and any marker cleared; on failure it is left at the last good build so the app
    // still runs, with a loud notice. Only the target/good pair is marked (never a package whose
    // target *is* its good — it has no second key to clear the marker, so it retries as before).
    // The hard-fail (exit 1) is reserved for the case where no prior good build exists at all.
    let script = format!(
        "mkdir -p '{dir}'\n\
         n={n}\n\
         while [ \"$n\" -gt 0 ]; do\n\
         ref=\"$1\"; target=\"$2\"; good=\"$3\"; key=\"$4\"\n\
         if [ ! -e \"$target/bin\" ] && [ ! -e \"$target.failed\" ]; then\n\
         '{nix}' build \"$ref\" --no-write-lock-file --out-link \"$target\" 1>&2\n\
         [ -e \"$target/bin\" ] || [ \"$target\" = \"$good\" ] || touch \"$target.failed\"\n\
         fi\n\
         if [ -e \"$target/bin\" ]; then\n\
         rm -f \"$target.failed\"\n\
         sp=$(readlink -f \"$target\")\n\
         [ \"$target\" != \"$good\" ] && ln -sfn \"$sp\" \"$good\"\n\
         elif [ -e \"$good/bin\" ]; then\n\
         sp=$(readlink -f \"$good\")\n\
         echo \"sbx: flake '$key': build failed — falling back to the last good build; a new revision (or, for an inline flake, an edit) triggers a fresh build\" 1>&2\n\
         else\n\
         echo \"sbx: flake '$key': the build failed and there is no prior build to fall back to\" 1>&2\n\
         exit 1\n\
         fi\n\
         [ -n \"$sp\" ] && mkdir -p /nix/var/nix/gcroots \
         && ln -sfn \"$sp\" \"/nix/var/nix/gcroots/sbx-flake-$key\"\n\
         shift 4\n\
         n=$((n - 1))\n\
         done\n\
         exec \"$@\"",
        dir = flake_dir.to_string_lossy(),
        nix = nix.to_string_lossy(),
    );
    let mut out = vec![
        bash.as_os_str().to_os_string(),
        OsString::from("-c"),
        OsString::from(script),
        // `$0` — a label; the quads are `$1..$4n`, the command is what remains after the shifts.
        OsString::from("sbx-flake-equip"),
    ];
    for (reference, target, good, key) in quads {
        out.push(OsString::from(reference));
        out.push(target.as_os_str().to_os_string());
        out.push(good.as_os_str().to_os_string());
        out.push(OsString::from(key));
    }
    out.extend(cmd);
    out
}

#[cfg(test)]
mod tests;
