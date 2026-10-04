//! The config binds' sources, held open from the launch to the cage, and the check the cage runs on
//! them before anything else.
//!
//! A held source is mounted from its descriptor ([`super::super::spec::HeldSource`]), and bwrap
//! looks up where that object is as it sets the cage up and mounts that path. From 0.10.0 it then
//! checks that what it mounted is the object; Ubuntu 24.04's backport of the option to 0.9.0 does
//! not, so there a parent swapped between that look-up and the mount goes unnoticed. The cage closes
//! that gap from the inside: its first act compares what each held source's path shows with what
//! the launch held, and runs nothing on a difference.

use std::ffi::OsString;
use std::path::Path;

use super::super::spec::{HeldSource, SandboxSpec};

/// Hold each config-declared bind's source open by `O_PATH`, every link on its path refused, for
/// bubblewrap to mount from the descriptor ([`HeldSource`]).
///
/// The paths were canonicalised when the config was read, so a link found on one now is a component
/// replaced since, and the launch is refused rather than the bind dropped: a read-only bind left out
/// can leave the read-write bind it sits in writable beneath it, and a bind the user declared that
/// silently goes missing is a launch that runs on something other than what was asked.
pub(crate) fn hold_bind_sources(binds: &[crate::config::Bind]) -> Result<Vec<HeldSource>, String> {
    binds
        .iter()
        .map(|b| {
            let rel = b.path.strip_prefix("/").unwrap_or(&b.path);
            super::super::cagedir::hold_entry_beneath(Path::new("/"), rel)
                .map(|fd| HeldSource::new(b.path.clone(), fd))
                .map_err(|e| {
                    format!(
                        "cannot hold the bind source {}: {e}. It was resolved when the config was \
                         read, so a component of its path has been replaced or removed since",
                        b.path.display()
                    )
                })
        })
        .collect()
}

/// The script [`held_source_check`] runs. Its arguments, in order: the `stat` to run, the number of
/// pairs, each pair's path and the identity held for it, then the command.
///
/// Everything it reads arrives as an argument, so a path from the config is data and never syntax.
/// A path that cannot be read is a difference like any other.
const CHECK: &str = r#"stat=$1; n=$2; shift 2
while [ "$n" -gt 0 ]; do
  found=$("$stat" -c %d:%i -- "$1" 2>&1) || found="unreadable: $found"
  if [ "$found" != "$2" ]; then
    printf 'sbx: the bind at %s is not the source the launch opened (found %s, opened %s), so the command was not run\n' "$1" "$found" "$2" >&2
    exit 125
  fi
  shift 2
  n=$((n - 1))
done
exec "$@"
"#;

/// The argument list that has the cage check, before it runs its command, that each held source it
/// sees is the object the launch held: empty when the cage sees none.
///
/// It compares the device and inode `stat` reports at the source's path inside the cage with those
/// of the held descriptor, which is what bwrap 0.10.0 and later compare once they have mounted it.
/// The check detects a swap and does not prevent one: a parent replaced while bwrap set the cage up
/// still lands its target there, and the cage exits 125 with the bind named instead of running
/// anything on it. It runs on every bwrap that is handed the descriptors, those that check for
/// themselves included, so the one code path is the one every launch exercises.
///
/// It runs ahead of every wrap the launch composed, so nothing in the cage starts on a mount it has
/// not checked, and it `exec`s the command, which keeps the pid, the signals and the exit status the
/// command would have had. The shell is started with `-p`, which skips the startup file `BASH_ENV`
/// names and the functions the environment exports: a trusted config may set either, and both would
/// run before the check. They still reach the command, in the environment it inherits. `stat` is
/// run by absolute path from the same coreutils as `env_bin`, whose store path the launch pins
/// read-only, like every program a preamble runs before the cage is filtered.
///
/// The sources checked are the ones the cage sees ([`SandboxSpec::seen_held_sources`]): one mounted
/// and then covered by a later mount would compare that mount and refuse a launch that is sound.
pub(crate) fn held_source_check(
    shell: &Path,
    env_bin: &Path,
    spec: &SandboxSpec,
) -> Result<Vec<OsString>, String> {
    let seen = spec.seen_held_sources();
    if seen.is_empty() {
        return Ok(Vec::new());
    }
    let mut argv = vec![
        shell.as_os_str().to_owned(),
        OsString::from("-p"),
        OsString::from("-c"),
        OsString::from(CHECK),
        // `$0`, a label: the arguments the script reads follow it.
        OsString::from("sbx-bind-check"),
        env_bin.with_file_name("stat").into_os_string(),
        OsString::from(seen.len().to_string()),
    ];
    for held in &seen {
        let identity = held.identity().map_err(|e| {
            format!(
                "cannot read the bind source {} it holds: {e}",
                held.path().display()
            )
        })?;
        argv.push(held.path().as_os_str().to_owned());
        argv.push(OsString::from(identity));
    }
    Ok(argv)
}
