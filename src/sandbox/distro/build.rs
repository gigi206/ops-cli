//! Running a `[distro] run` list on an unpacked base, to derive a project's own userland.
//!
//! ## What sbx understands of the commands: nothing
//!
//! Each entry is a line handed to the image's own `/bin/sh`. There is no package-manager knowledge
//! here, no name translation, and nothing that has to be taught a new distribution: what a command
//! means is what that distribution means by it. This is the same property the consuming path has,
//! and it is why both work on a distribution nobody here has heard of.
//!
//! ## One cage per command
//!
//! Not one shell running the list. A cage per command is what lets a failure name the command that
//! failed rather than a line number in a script sbx assembled, and it is what puts the deadline on
//! each command rather than on the list — a wedged download in the third of five would otherwise
//! spend the whole budget before the first two were credited.
//!
//! ## The cage
//!
//! The tree is bound **read-write** at `/`, which is the one place in this module where that is
//! right: nothing names the tree yet, it is renamed into place only if every command succeeded, and
//! writing to it is the entire point. Everything else is the minimum a command needs to run and no
//! more — no `/nix`, no home, and above all **not the project**: a build is not a launch, and a
//! command that could read the project could carry it into an image other projects then share.
//!
//! The launch's egress posture applies unchanged, on the rule the bundles' install step already
//! follows: a command that downloads needs its host in the project's own allowlist, visible rather
//! than implied. Under an allowlist that means a proxy of this build's own, because the userland
//! has to exist before the launch's proxy does. It runs on its own control plane
//! ([`crate::sandbox::control::Plane::Build`]) so a build's refusal can never widen the agent's
//! allowlist through `--net-learn`.
//!
//! Two things the cage deliberately lacks, and both are consequences rather than omissions: no
//! `[secret]` injection reaches it (a build is not the agent, and an image is shared), and no
//! `tcp://` rule applies (those are served by an in-cage forwarder this cage does not carry).

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::sandbox::binds::{CAGE_CA_BUNDLE, DISTRO_BIN_DIRS};
use crate::sandbox::spec::{Mount, NetPolicy, SandboxSpec};

/// The wall-clock ceiling on one command. Generous, because installing a toolchain legitimately
/// takes minutes, but present: a command that waits on a prompt nobody can answer, or on a
/// connection that never closes, would otherwise hang the launch before the agent ever starts.
///
/// The same shape and the same reason as the task pool's install ceiling. Fixed rather than
/// configurable: a knob here would be a knob for making a launch hang longer.
const BUILD_TIMEOUT: Duration = Duration::from_secs(600);

/// How often the runner checks for exit while enforcing [`BUILD_TIMEOUT`].
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// What a build needs from the launch that asked for it.
///
/// Assembled by the caller because every field is something only a launch knows, and passing them
/// as one value keeps the signature honest about the fact that a build is not a free function of
/// the tree it writes into.
pub(crate) struct Context<'a> {
    /// The commands, in order.
    pub(crate) commands: &'a [String],
    /// The `bwrap` this host launches cages with.
    pub(crate) bwrap: &'a Path,
    /// sbx's own CA bundle, bound at the standard certificate paths so a command that fetches over
    /// TLS has roots to check against. Under an allowlist it is also what the proxy's own
    /// certificate is paired with.
    pub(crate) ca_bundle: &'a Path,
    /// The egress the launch declared, applied unchanged.
    pub(crate) network: &'a crate::config::NetworkPolicy,
    /// Where sbx keeps its data, for a proxy that needs sockets under it.
    pub(crate) layout: &'a crate::store::Layout,
    /// The project this build is for. Never bound into the cage: it is here because a resolver
    /// plugin resolving a credential for the proxy resolves relative paths against it.
    pub(crate) project_root: &'a Path,
    /// The store to mount at `/nix`, read-only, and the two binaries out of it the forwarder
    /// script needs. Under an allowlist the cage's egress is a loopback port that exists only
    /// because `socat` is running there to bridge it to the proxy's Unix socket — the same
    /// arrangement a launch gets, and the reason a build cage carries the store at all.
    pub(crate) nix_store: &'a Path,
    pub(crate) socat: &'a Path,
    pub(crate) shell: &'a Path,
}

/// Run every command of `ctx` on the tree at `rootfs`, in order, stopping at the first failure.
///
/// The tree is left as the last successful command left it. That is not a rollback gap: the caller
/// assembles under a name nothing will ever look up and renames only on success, so a failed build
/// leaves a directory no launch can reach rather than a half-derived userland.
pub(crate) fn run(rootfs: &Path, ctx: &Context<'_>) -> io::Result<()> {
    if ctx.commands.is_empty() {
        return Ok(());
    }
    // A shell is what every command is handed to, so its absence is the failure to report — before
    // standing up a proxy and a cage for a command that cannot start.
    if !rootfs.join("bin/sh").symlink_metadata().is_ok() {
        return Err(io::Error::other(
            "the image carries no `/bin/sh`, so there is nothing to run `[distro] run` with",
        ));
    }

    // One proxy for the whole list rather than one per command: it is the *launch's* policy being
    // enforced, not each command's, and standing one up per command would multiply sockets under
    // the data directory for no property gained.
    let egress = match ctx.network {
        crate::config::NetworkPolicy::Allowlist(policy) => Some(crate::sandbox::egress::start(
            ctx.layout,
            (**policy).clone(),
            // No `[secret]` injection: a build is not the agent, and what it produces is shared by
            // every project on the same image.
            &[],
            ctx.project_root,
            ctx.bwrap,
            None,
            false,
            Some(ctx.ca_bundle),
            // Short, because these become `AF_UNIX` paths and the kernel caps their length.
            "b",
            None,
            crate::sandbox::redact::MIN_LEN_DEFAULT,
            // The launch stands its brokers up long after the userland it is about to run on has to
            // exist, so a resolver plugin that reaches one has nothing to reach here.
            &[],
            None,
            crate::sandbox::control::Plane::Build,
            None,
            crate::sandbox::egress::Unresolved::Abort,
        )?),
        _ => None,
    };
    let wiring = egress.as_ref().map(|(_, w)| w);

    for command in ctx.commands {
        one(rootfs, command, ctx, wiring)?;
    }
    Ok(())
}

/// Run one command, bounded.
fn one(
    rootfs: &Path,
    command: &str,
    ctx: &Context<'_>,
    wiring: Option<&crate::sandbox::egress::Wiring>,
) -> io::Result<()> {
    let mut mounts = vec![
        // Layer 0, read-write. See the module note for why that is right exactly here.
        Mount::Bind {
            src: rootfs.to_path_buf(),
            dest: PathBuf::from("/"),
        },
        Mount::Proc {
            dest: PathBuf::from("/proc"),
        },
        Mount::Dev {
            dest: PathBuf::from("/dev"),
        },
        Mount::Tmpfs {
            dest: PathBuf::from("/tmp"),
        },
        // Names to resolve and roots to check them against. Without the first, no command that
        // downloads gets past DNS; without the second, none gets past the TLS handshake.
        Mount::RoBindTry {
            src: PathBuf::from("/etc/resolv.conf"),
            dest: PathBuf::from("/etc/resolv.conf"),
        },
        Mount::RoBind {
            src: ctx.ca_bundle.to_path_buf(),
            dest: PathBuf::from("/etc/ssl/certs/ca-certificates.crt"),
        },
        Mount::RoBind {
            src: ctx.ca_bundle.to_path_buf(),
            dest: PathBuf::from(CAGE_CA_BUNDLE),
        },
    ];
    let mut env = vec![
        ("PATH".to_string(), DISTRO_BIN_DIRS.join(":")),
        ("HOME".to_string(), "/root".to_string()),
        // Enough of a terminal that a tool which asks does not conclude it has none and switch to a
        // mode nobody asked for; not enough to make one think it is interactive.
        ("TERM".to_string(), "dumb".to_string()),
    ];
    if let Some(wiring) = wiring {
        // The store, read-only, and only because the forwarder is a binary out of it: nothing of it
        // reaches the build's `PATH`, so a command still gets the distribution's tools and not
        // sbx's. Emitted here rather than always, so a build that needs no forwarder needs no
        // store. The mountpoint is created by bubblewrap itself, which is one of the two things
        // the read-write root buys.
        mounts.push(Mount::RoBind {
            src: ctx.nix_store.to_path_buf(),
            dest: PathBuf::from("/nix"),
        });
        mounts.extend(wiring.binds.iter().map(|b| {
            if b.writable {
                Mount::Bind {
                    src: b.src.clone(),
                    dest: b.dest.clone(),
                }
            } else {
                Mount::RoBind {
                    src: b.src.clone(),
                    dest: b.dest.clone(),
                }
            }
        }));
        env.extend(wiring.env.iter().cloned());
    }

    // The posture the project declared, applied unchanged. Under an allowlist the cage is
    // *isolated* and reaches the world only through the Unix socket the wiring binds — the same
    // shape a launch gets, and the reason a build cannot route around the policy by knowing an IP.
    let net = match ctx.network {
        crate::config::NetworkPolicy::Shared => NetPolicy::Shared,
        crate::config::NetworkPolicy::Isolated | crate::config::NetworkPolicy::Allowlist(_) => {
            NetPolicy::Isolated
        }
    };

    let mut argv = vec![
        OsString::from("/bin/sh"),
        OsString::from("-c"),
        OsString::from(command),
    ];
    if wiring.is_some() {
        // Under an allowlist the proxy listens on a Unix socket the cage cannot address. The
        // forwarder opens the loopback port `HTTPS_PROXY` names and bridges it, then execs the
        // command — the same wrapper a launch uses, so there is one definition of that bridge.
        argv = crate::sandbox::egress::wrap_command(ctx.socat, ctx.shell, argv, &[]);
    }
    let spec = SandboxSpec::new(PathBuf::from("/"), mounts, env, net, argv)
        .map(SandboxSpec::rooted_in_its_namespace)
        .map_err(|e| io::Error::other(format!("building the cage for `{command}`: {e:?}")))?;

    // Through the launcher rather than by composing an argv here: the cage's environment travels in
    // a memfd, and a `Command` built without the descriptors that carry it fails at the exec with
    // `bwrap: Invalid fd`.
    let (mut cage, held) = crate::sandbox::argv::command_for(ctx.bwrap, &spec)?;
    let mut child = cage
        .stdin(std::process::Stdio::null())
        .spawn()
        .map_err(|e| io::Error::other(format!("running `{command}`: {e}")))?;

    let deadline = Instant::now() + BUILD_TIMEOUT;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                // Killing bwrap tears the cage down with it: it is the pid-namespace init for
                // everything inside, so a wedged command does not outlive the ceiling.
                timed_out = true;
                let _ = child.kill();
                break child.wait()?;
            }
            None => std::thread::sleep(POLL_INTERVAL),
        }
    };
    drop(held);
    if timed_out {
        return Err(io::Error::other(format!(
            "`{command}` passed its {}s ceiling and was killed",
            BUILD_TIMEOUT.as_secs()
        )));
    }
    if !status.success() {
        return Err(io::Error::other(format!(
            "`{command}` exited {}",
            status
                .code()
                .map_or_else(|| "on a signal".to_string(), |c| c.to_string())
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
