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

use super::startup::shell_quote;
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
/// positionally, the two interpolated values go through [`shell_quote`], and `exec` keeps the roll
/// the cage's main process. Both values are sbx's own — the mise path it resolved and a fixed cage
/// path — so nothing untrusted reaches the script either way; quoting them makes that a property of
/// how the line is built rather than of what the values happen to contain, which is the form that
/// survives a path acquiring a space. Other runtimes have a single pool (the home), already the
/// ambient primary, so the plain command runs unwrapped.
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
            "MISE_DATA_DIR={data_dir} exec {mise} upgrade {MISE_ROLL_FLAG} \"$@\"",
            data_dir = shell_quote(&data_dir),
            mise = shell_quote(&mise.to_string_lossy()),
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
/// mise:` ones) and is interpolated **unquoted**, because `use -g` has to reach mise as two words;
/// the tokens and the command ride `"$@"` positionally, and the mise path goes through
/// [`shell_quote`], so a token from an untrusted config can never inject shell. Best-effort: a
/// failed equip does not abort the command (the missing tool surfaces when it is used), matching
/// the self-equip posture rather than the host `nix:` hard-fail guarantee.
///
/// `mise_data_dir`, when `Some`, pins **only the equip step's** `MISE_DATA_DIR` (the exec'd command
/// keeps the cage's ambient value). This is how a global app's Lane-1 `mise use -g` installs an app
/// package into the app-global home pool while the ambient primary is the per-project pool. The
/// value is an sbx-owned fixed cage path ([`binds::mise_app_global_data_dir`]) and it is quoted
/// through [`shell_quote`] rather than wrapped in a pair of literal quotes, so the assignment holds
/// whatever the path turns out to contain instead of holding because of what it contains today.
///
/// A `pipx:` token is also **repaired** before the equip, when its install no longer runs. mise's
/// pipx backend builds a virtualenv whose `bin/python` links to the absolute store path of the
/// interpreter it was built on. When the home's nixpkgs pin moves, that interpreter leaves the cage
/// and the link dangles, while mise still counts the version as installed: the equip does nothing,
/// a roll with no newer upstream release does nothing, and the app no longer starts. So each
/// installed version whose `bin/python` link dangles is reinstalled with `mise install --force` at
/// the same version, in the same data dir the equip uses, with a notice naming the tool. Only the
/// tokens handed in here are repaired, never a directory the cage created on its own; the version
/// alias links mise keeps beside the real directories are skipped; and the check is bash tests and
/// globs only, so a launch where nothing is broken runs no extra process.
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
        Some(dir) => format!("MISE_DATA_DIR={} ", shell_quote(dir)),
        None => String::new(),
    };
    let mise = shell_quote(&mise.to_string_lossy());
    // `(locator, install directory, display name)` per `pipx:` token. The directory name is
    // derived from the token here, never read back from the cage, and all three ride `"$@"`.
    let repairs: Vec<[String; 3]> = tokens
        .iter()
        .filter_map(|token| {
            let (locator, _) = crate::sandbox::taskpool::split_version(token);
            locator.starts_with("pipx:").then(|| {
                [
                    locator.to_string(),
                    crate::sandbox::inspect::mise_munge(locator),
                    crate::sandbox::sanitize(locator),
                ]
            })
        })
        .collect();
    let m = repairs.len();
    let repair = if m == 0 {
        String::new()
    } else {
        let data_dir = match mise_data_dir {
            Some(dir) => shell_quote(dir),
            None => "\"${MISE_DATA_DIR:-$HOME/.local/share/mise}\"".to_string(),
        };
        format!(
            "d={data_dir}\n\
             a=$(({n} + 1)); k={m}\n\
             while [ \"$k\" -gt 0 ]; do\n\
             loc=\"${{!a}}\"; b=$((a + 1)); dir=\"${{!b}}\"; c=$((a + 2)); shown=\"${{!c}}\"\n\
             for v in \"$d/installs/$dir\"/*; do\n\
             [ -d \"$v\" ] && [ ! -L \"$v\" ] || continue\n\
             for py in \"$v\"/*/bin/python; do\n\
             if [ -L \"$py\" ] && [ ! -e \"$py\" ]; then\n\
             echo \"sbx: $shown: the Python its environment was built on is no longer in the cage; reinstalling it\" 1>&2\n\
             {data_dir_prefix}{mise} install --force \"$loc@${{v##*/}}\" 1>&2\n\
             break\n\
             fi\n\
             done\n\
             done\n\
             a=$((a + 3)); k=$((k - 1))\n\
             done\n"
        )
    };
    let script = format!(
        "{repair}{data_dir_prefix}{mise} {verb} \"${{@:1:{n}}}\" 1>&2; shift {shifted}; exec \"$@\"",
        shifted = n + 3 * m,
    );
    let mut out = vec![
        bash.as_os_str().to_os_string(),
        OsString::from("-c"),
        OsString::from(script),
        // `$0` — a label; the tokens are `$1..$n`, then one `(locator, directory, display name)`
        // triple per repaired `pipx:` token; the command is what remains after `shift`.
        OsString::from("sbx-mise-equip"),
    ];
    out.extend(tokens.iter().map(OsString::from));
    out.extend(repairs.into_iter().flatten().map(OsString::from));
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
/// when it is used), matching the in-cage self-equip posture. `mkdir`/`ln`/`readlink`/`touch`/`rm`
/// are invoked by absolute store path like `nix` itself, not by name: this preamble is the cage's
/// first process and runs before the `[proc]` shim installs its filter, while the cage's PATH leads
/// through directories the cage can write (its own store, its mise shims) — a bare name there would
/// let in-cage code choose what runs unfiltered. `plumbing_pins` pins the coreutils store root
/// read-only, which is what makes the absolute path worth more than the name.
pub(super) fn wrap_flake_equip(
    nix: &Path,
    bash: &Path,
    env_bin: &Path,
    flake_dir: &Path,
    quads: &[(String, PathBuf, PathBuf, String)],
    cmd: Vec<OsString>,
) -> Vec<OsString> {
    let n = quads.len();
    let mkdir = env_bin.with_file_name("mkdir");
    let touch = env_bin.with_file_name("touch");
    let rm = env_bin.with_file_name("rm");
    let readlink = env_bin.with_file_name("readlink");
    let ln = env_bin.with_file_name("ln");
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
        "'{mkdir}' -p '{dir}'\n\
         n={n}\n\
         while [ \"$n\" -gt 0 ]; do\n\
         ref=\"$1\"; target=\"$2\"; good=\"$3\"; key=\"$4\"\n\
         if [ ! -e \"$target/bin\" ] && [ ! -e \"$target.failed\" ]; then\n\
         '{nix}' build \"$ref\" --no-write-lock-file --out-link \"$target\" 1>&2\n\
         [ -e \"$target/bin\" ] || [ \"$target\" = \"$good\" ] || '{touch}' \"$target.failed\"\n\
         fi\n\
         if [ -e \"$target/bin\" ]; then\n\
         '{rm}' -f \"$target.failed\"\n\
         sp=$('{readlink}' -f \"$target\")\n\
         [ \"$target\" != \"$good\" ] && '{ln}' -sfn \"$sp\" \"$good\"\n\
         elif [ -e \"$good/bin\" ]; then\n\
         sp=$('{readlink}' -f \"$good\")\n\
         echo \"sbx: flake '$key': build failed — falling back to the last good build; a new revision (or, for an inline flake, an edit) triggers a fresh build\" 1>&2\n\
         else\n\
         echo \"sbx: flake '$key': the build failed and there is no prior build to fall back to\" 1>&2\n\
         exit 1\n\
         fi\n\
         [ -n \"$sp\" ] && '{mkdir}' -p /nix/var/nix/gcroots \
         && '{ln}' -sfn \"$sp\" \"/nix/var/nix/gcroots/sbx-flake-$key\"\n\
         shift 4\n\
         n=$((n - 1))\n\
         done\n\
         exec \"$@\"",
        dir = flake_dir.to_string_lossy(),
        nix = nix.to_string_lossy(),
        mkdir = mkdir.to_string_lossy(),
        touch = touch.to_string_lossy(),
        rm = rm.to_string_lossy(),
        readlink = readlink.to_string_lossy(),
        ln = ln.to_string_lossy(),
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
