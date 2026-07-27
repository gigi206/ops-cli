//! `sbx doctor`: report the runtime prerequisites (user namespaces, bubblewrap, nix, engines,
//! resource limits) and fail hard when a load-bearing one is missing. The userns/engine probes it
//! reads are crate-root domain primitives (shared with the launch path); this module is their
//! human-facing report.

use std::io::IsTerminal;
use std::path::Path;
use std::process::ExitCode;

use crate::{
    config, nix_version, probe_userns, read_sysctl, sandbox, short_rev, storage, store, style,
    Userns,
};

/// Remediation for a missing capability-bearing user namespace — the boundary
/// the whole sandbox rests on. Distro-dependent and needs root once.
const USERNS_REMEDIATION: &str = "enable capability-bearing unprivileged user namespaces \
(no security boundary without them; no fallback): \
`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`, \
or an AppArmor profile allowing unprivileged userns for sbx";

/// Remediation when the namespace itself is fine but a real launch still failed —
/// the fault is the engine, not the boundary.
const BWRAP_LAUNCH_REMEDIATION: &str = "bubblewrap is installed and user namespaces work, \
but launching a sandbox failed — check that bubblewrap is built to use unprivileged user \
namespaces (not a setuid helper) and review the messages above";

/// Report the runtime prerequisites and fail hard if a load-bearing one is
/// missing. Each failing check contributes its own remediation hint, so the
/// summary never points at the wrong cause.
/// A colored `[ ok ]` status tag (green when the stream is a terminal, plain otherwise).
fn tag_ok(p: &style::Palette) -> String {
    format!("{}[ ok ]{}", p.ok, p.reset)
}

/// A colored `[warn]` status tag (yellow when colored).
fn tag_warn(p: &style::Palette) -> String {
    format!("{}[warn]{}", p.warn, p.reset)
}

/// A colored `[FAIL]` status tag (bold red when colored).
fn tag_fail(p: &style::Palette) -> String {
    format!("{}[FAIL]{}", p.err, p.reset)
}

pub(crate) fn doctor() -> ExitCode {
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, r) = (pal.head, pal.reset);
    println!("{h}sbx doctor{r} — runtime preflight\n");

    let mut remediation: Vec<&str> = Vec::new();

    // The data directory, resolved once and reused for the engines and the store/channel
    // report below. Read-only in that it derives paths from the environment; resolving the
    // engines may materialize one sbx ships (the bundled-* builds), which is intended.
    let layout = store::Layout::from_env();

    // The sandbox engine itself. Hold the choice: a present engine is what lets the
    // boundary be proven by a real launch rather than a stand-in, and its source explains
    // which `bwrap` ran and why — the bundled engine, the host's, or an override.
    let bwrap = store::resolve_bwrap(layout.as_ref());
    match &bwrap {
        Some(c) => {
            println!("  {} bubblewrap        {}", tag_ok(&pal), c.path.display());
            let note = if c.apparmor_restricted {
                " — AppArmor userns restriction active (host engine required)"
            } else {
                ""
            };
            println!(
                "         {dim}· {}{note}{r}",
                c.source.label(),
                dim = pal.dim
            );
        }
        None => {
            println!("  {} bubblewrap        not found", tag_fail(&pal));
            remediation.push("install bubblewrap (the sandbox engine)");
        }
    }

    // The security boundary, proven the way sbx actually uses it: a real bwrap
    // launch through the argv builder. A hardened process (CapEff=0,
    // NoNewPrivs=1) proves the user namespace is capability-bearing more
    // conclusively than a raw `unshare` can — bubblewrap cannot nest its
    // namespaces on a cap-stripped one. The `unshare` stand-in survives only to
    // classify a failure (and as the fast gate the launch path uses). The
    // sysctls below are advisory context for the remediation hint.
    report_security_boundary(
        &pal,
        bwrap.as_ref().map(|c| c.path.as_path()),
        &mut remediation,
    );
    if let Some(v) = read_sysctl("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") {
        println!(
            "         {dim}· kernel.apparmor_restrict_unprivileged_userns = {v}{r}",
            dim = pal.dim
        );
    }
    if let Some(v) = read_sysctl("/proc/sys/kernel/unprivileged_userns_clone") {
        println!(
            "         {dim}· kernel.unprivileged_userns_clone = {v}{r}",
            dim = pal.dim
        );
    }
    report_resource_limits(&pal, &config::global_limits());

    // The nix that drives the store. Its absence is load-bearing too — without
    // nix, sbx cannot provision a project's tools. Resolution follows override,
    // then an sbx-owned engine, then `PATH`; it makes no store or config change,
    // though a `bundled-nix` build materializes its embedded engine under
    // `<data>/engine/` on first use (idempotent), which a launch would do anyway.
    match store::resolve_nix(layout.as_ref()) {
        Some(nix) => {
            println!("  {} nix               {}", tag_ok(&pal), nix.display());
            if let Some(v) = nix_version(&nix) {
                println!("         {dim}· {v}{r}", dim = pal.dim);
            }
        }
        None => {
            println!("  {} nix               not found", tag_fail(&pal));
            remediation.push("install nix (the store engine sbx drives daemonlessly)");
        }
    }

    // git fetches a remote plugin store (`sbx plugins store add`). It is not on the launch
    // path — a sandbox runs without it — so its absence is a feature gap reported for
    // context, never a boundary failure that blocks `sbx run`.
    match store::resolve_git() {
        Some(git) => {
            println!("  {} git               {}", tag_ok(&pal), git.display());
            // Say it plainly even when present: unlike bubblewrap and nix above, git is not a
            // prerequisite — a sandbox launches without it. It only enables `sbx plugins store`.
            println!(
                "         {}",
                style::dim_prose(
                    "· optional — needed only for `sbx plugins store`, not to run a sandbox",
                    &pal
                )
            );
        }
        None => println!(
            "  {} {}",
            tag_warn(&pal),
            style::prose(
                "git               not found on PATH — optional, needed only for \
                 `sbx plugins store`",
                &pal
            )
        ),
    }

    // Where the user-owned store lives, and which channel revision it is pinned to.
    // Both are reported read-only: sbx creates the store lazily on first use and
    // seeds the channel lock on first launch, so their absence here is informational,
    // not a failure. The channel state is the host-level global lock (doctor has no
    // project context), shown straight from disk.
    match layout.as_ref() {
        Some(layout) => {
            let dir = layout.store_dir();
            let state = if dir.is_dir() {
                "present"
            } else {
                "absent — created on first use"
            };
            let origin = if store::data_dir_overridden() {
                ", via $SBX_DATA_DIR"
            } else {
                ""
            };
            println!(
                "  {} store             {} ({state}{origin})",
                tag_ok(&pal),
                dir.display()
            );
            match store::read_global_lock(layout) {
                Some((source, rev)) => println!(
                    "  {} channel           {source} @ {} (locked)",
                    tag_ok(&pal),
                    short_rev(&rev)
                ),
                None => {
                    println!(
                        "  {} channel           not yet resolved — seeded on first launch",
                        tag_ok(&pal)
                    )
                }
            }
        }
        None => {
            println!(
                "  {} store             unresolved (no $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)",
                tag_warn(&pal)
            );
            println!(
                "  {} channel           unresolved (no data directory)",
                tag_warn(&pal)
            );
        }
    }

    // Storage is opt-in and never a prerequisite, so this line is always [ ok ]/[warn], never a
    // failure: it reports whether the data directory lives in a volume, and — when it does not —
    // whether one is worth adopting on this host. It is the standing discoverability anchor, so a
    // one-time proposal declined elsewhere still leaves the path visible here.
    report_storage(&pal);

    println!();
    if remediation.is_empty() {
        println!("sbx: prerequisites OK.");
        ExitCode::SUCCESS
    } else {
        let epal = style::Palette::for_stream(std::io::stderr().is_terminal());
        crate::diag::error(&format!(
            "{}sbx: missing prerequisite(s) — sbx CANNOT run until these are resolved:{}",
            epal.err, epal.reset
        ));
        for hint in remediation {
            crate::diag::hint(&format!("       {}•{} {hint}", epal.err, epal.reset));
        }
        ExitCode::FAILURE
    }
}

/// Report best-effort cgroup v2 resource limiting (anti-DoS). Unlike the security
/// boundary, resource limits are hardening: where they cannot be applied the cage
/// still runs, so an unavailable limiter is reported for context and never
/// recorded as a missing prerequisite. The probe launches a real transient scope,
/// so a green line means limiting actually works on this host.
fn report_resource_limits(pal: &style::Palette, limits: &sandbox::cgroup::Limits) {
    // Reflect the *global* config's limits — they apply to every launch regardless of project,
    // and the live probe validates them, so a bad global value surfaces here. A trusted project
    // may further tune them per project; `sbx config` is the project-aware view.
    let report: sandbox::LimitReport = sandbox::resource_limits(limits);
    if report.verified {
        println!(
            "  {} resource limits   cage capped via a systemd scope ({})",
            tag_ok(pal),
            report.properties.join(", ")
        );
    } else if let Some(note) = report.note {
        println!("  {} resource limits   {note}", tag_warn(pal));
    }
}

/// Report the storage posture: whether the data directory lives in an encapsulated volume, and
/// when it does not, whether one is available on this host. Read-only and best-effort — it reads
/// the pointer and probes capabilities, mounting nothing and creating nothing. Anchored to the
/// *default* data directory (where the image and pointer live), not the possibly-followed one.
fn report_storage(pal: &style::Palette) {
    let Some(default_dir) = store::Layout::default_data_dir() else {
        return;
    };
    let ok = tag_ok(pal);
    let warn = tag_warn(pal);
    let (dim, r) = (pal.dim, pal.reset);

    // Set to follow a volume? Read the pointer directly, so the answer stands even when the
    // volume happens to be unmounted right now. The type leads — `volume (<fs>)` here, `local
    // (<fs>)` below — the one distinction that says whether sbx manages the backing or borrows
    // the host's.
    if let Some(image) = storage::read_pointer(&default_dir) {
        match storage::state(&image) {
            Ok(storage::State::Mounted { mount_point, .. }) => {
                let fs = storage::fs_kind(&mount_point)
                    .map(|k| k.name())
                    .unwrap_or_else(|| "btrfs".to_string());
                let comp = storage::compression(&mount_point).unwrap_or_else(|| "off".to_string());
                println!(
                    "  {ok} storage           type: volume ({fs}) at {}",
                    mount_point.display()
                );
                println!(
                    "         {dim}· compression {comp}; the data directory costs the host a \
                     single inode{r}"
                );
            }
            _ => println!(
                "  {warn} storage           type: volume — set to use {} but it is not mounted",
                image.display()
            ),
        }
        return;
    }

    // No volume: the data directory sits directly on a host filesystem — type `local (<fs>)` —
    // and the note says whether an encapsulated volume is worth adopting.
    let pre = storage::Preflight::probe(&default_dir);
    let fs = pre
        .host_fs
        .map(|k| k.name())
        .unwrap_or_else(|| "unknown".to_string());
    let ty = format!("type: local ({fs})");

    if pre.host_fs.is_some_and(|k| k.is_ephemeral()) {
        // Checked before anything about volumes: that the data directory is in RAM outranks
        // whether one could be mounted, and a volume would not make it survive a reboot either.
        println!("  {warn} storage           {ty} — nothing here survives a reboot");
        println!(
            "         {}",
            style::dim_prose(
                "· $SBX_DATA_DIR can point sbx at a directory that persists",
                pal
            )
        );
    } else if pre.host_fs.is_some_and(|k| k.is_cow()) {
        println!("  {ok} storage           {ty} — already copy-on-write");
        println!("         {dim}· an encapsulated volume would add little{r}");
    } else if pre.recommends_volume() {
        println!("  {ok} storage           {ty} — a compressed btrfs volume is available");
        println!(
            "         {}",
            style::dim_prose("· adopt one with `sbx storage init`", pal)
        );
    } else if let Some(blocker) = pre.mount_blocker() {
        println!("  {warn} storage           {ty} — no encapsulated volume here: {blocker}");
        println!("         {dim}· $SBX_DATA_DIR can still point sbx at an existing btrfs mount{r}");
    } else if pre.remote_session {
        // Mountable in principle, but udisks needs a local active session to do it unattended.
        println!("  {ok} storage           {ty} — a volume needs a local active session");
        println!(
            "         {}",
            style::dim_prose(
                "· udisks asks for authentication over SSH; `sbx storage init` to try",
                pal
            )
        );
    } else if !pre.kernel_btrfs {
        println!("  {ok} storage           {ty} — btrfs kernel support not detected");
        println!(
            "         {}",
            style::dim_prose(
                "· a mount would try to autoload it; `sbx storage init` to try",
                pal
            )
        );
    } else {
        println!("  {ok} storage           {ty}");
    }
}

/// Report the security boundary. When bubblewrap is present, a real launch
/// decides the green path and the `unshare` stand-in does not run at all. On
/// failure — or when there is no engine to launch — the stand-in classifies the
/// cause so the report blames the right layer and never the wrong one.
fn report_security_boundary(
    pal: &style::Palette,
    bwrap: Option<&Path>,
    remediation: &mut Vec<&'static str>,
) {
    let (dim, r) = (pal.dim, pal.reset);
    let Some(bwrap) = bwrap else {
        // No engine to launch: the stand-in is the only available signal for the
        // boundary. Report it for context (the missing-engine remediation is
        // already recorded), and still flag a broken namespace as its own fault.
        match probe_userns() {
            Userns::Ok => println!(
                "         {dim}· user namespaces: capability-bearing (cannot prove without bubblewrap){r}"
            ),
            other => classify_namespace_failure(pal, other, remediation),
        }
        return;
    };

    match sandbox::smoke(bwrap) {
        Ok(report) if report.is_hardened() => {
            println!(
                "  {} sandbox           bubblewrap launched a hardened process",
                tag_ok(pal)
            );
            println!(
                "         {dim}· user namespaces: capability-bearing — proven by the launch{r}"
            );
            println!("         {dim}· no_new_privs set, every capability dropped{r}");
            if report.host_home_absent {
                println!("         {dim}· host $HOME absent — the bind layout did not leak it{r}");
            } else {
                println!(
                    "         {dim}· note: the host $HOME was visible inside the probe sandbox{r}"
                );
            }
        }
        Ok(report) => classify_launch_failure(pal, Some(&report.stderr), remediation),
        Err(e) => {
            // The probe could not even spawn bwrap; surface why, then classify.
            println!("         {dim}· could not run the launch probe: {e}{r}");
            classify_launch_failure(pal, None, remediation);
        }
    }
}

/// A real launch did not yield a hardened process. A capability-bearing namespace
/// means the engine itself failed, so blame bubblewrap and surface its own
/// diagnosis; otherwise the namespace is the cause and is classified as such.
fn classify_launch_failure(
    pal: &style::Palette,
    bwrap_stderr: Option<&str>,
    remediation: &mut Vec<&'static str>,
) {
    let (dim, r) = (pal.dim, pal.reset);
    match probe_userns() {
        Userns::Ok => {
            println!(
                "  {} sandbox           bubblewrap could not launch a hardened process",
                tag_fail(pal)
            );
            println!("         {dim}· user namespaces: capability-bearing (the failure is in bubblewrap, not the namespace){r}");
            for line in bwrap_stderr
                .unwrap_or_default()
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .take(3)
            {
                println!("         {dim}· {line}{r}");
            }
            remediation.push(BWRAP_LAUNCH_REMEDIATION);
        }
        other => classify_namespace_failure(pal, other, remediation),
    }
}

/// Report a user namespace that cannot bear the capabilities bubblewrap needs,
/// distinguishing outright absence from the capability-stripped case so the
/// remediation points at the real cause. The caller has already established the
/// namespace is not `Ok`.
fn classify_namespace_failure(
    pal: &style::Palette,
    userns: Userns,
    remediation: &mut Vec<&'static str>,
) {
    let fail = tag_fail(pal);
    match userns {
        Userns::Unsupported => {
            println!("  {fail} user namespaces   cannot create one without privilege");
        }
        Userns::CapStripped => {
            println!(
                "  {fail} user namespaces   created but stripped of capabilities (restricted)"
            );
        }
        // The caller only reaches here with a non-`Ok` namespace; a transient
        // flip to `Ok` is still a failure to launch, so it is flagged, not hidden.
        Userns::Ok => println!("  {fail} user namespaces   transient namespace probe failure"),
    }
    remediation.push(USERNS_REMEDIATION);
}
