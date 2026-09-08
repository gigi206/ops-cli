//! `sbx doctor`: report the runtime prerequisites (user namespaces, bubblewrap, nix, engines,
//! resource limits) and fail hard when a load-bearing one is missing. The userns/engine probes it
//! reads are crate-root domain primitives (shared with the launch path); this module is their
//! human-facing report.

use std::io::IsTerminal;
use std::path::Path;
use std::process::ExitCode;

use crate::{
    Userns, config, nix_version, probe_userns, read_sysctl, sandbox, short_rev, storage, store,
    style,
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

/// Remediation for an engine override sbx refused: the binary is present at the path the variable
/// names, and sbx will not silently substitute another one against the same store. An install hint
/// would be wrong here — nothing is missing — so the remedy names the two things that actually
/// clear it.
const NIX_OVERRIDE_REMEDIATION: &str = "fix the ownership or permissions of the nix binary \
SBX_NIX_BIN names (it must be owned by you or root, and not world-writable), or unset SBX_NIX_BIN \
to let sbx resolve nix itself";

/// [`NIX_OVERRIDE_REMEDIATION`] for the sandbox engine.
const BWRAP_OVERRIDE_REMEDIATION: &str = "fix the ownership or permissions of the bubblewrap \
binary SBX_BWRAP_BIN names (it must be owned by you or root, and not world-writable), or unset \
SBX_BWRAP_BIN to let sbx resolve bubblewrap itself";

/// One preflight check: what was probed, how it came out, and the context lines under it.
///
/// The struct exists so `--json` and the human report answer from the *same* pass. A second pass
/// that re-probed for the document could disagree with the one the reader saw, and on a preflight
/// that is the worst possible place for two answers.
struct Check {
    name: String,
    /// `ok`, `warn` or `fail` — the machine-readable form of the `[ ok ]`/`[warn]`/`[FAIL]` tag.
    status: &'static str,
    detail: String,
    /// The `· …` lines under the check: context, never a verdict of their own.
    notes: Vec<String>,
}

/// The preflight report as it is built: it prints each check as it is decided (so a slow probe's
/// result appears before the next one starts) unless a document was asked for, in which case
/// nothing is printed and everything is collected.
struct Report<'a> {
    json: bool,
    pal: &'a style::Palette,
    checks: Vec<Check>,
}

impl<'a> Report<'a> {
    fn new(json: bool, pal: &'a style::Palette) -> Self {
        Report {
            json,
            pal,
            checks: Vec::new(),
        }
    }

    /// Record one check, printing it unless a document was asked for. The label is padded to the
    /// column every check shares, so the details line up whatever the probe was called.
    fn check(&mut self, status: &'static str, name: &str, detail: &str) {
        if !self.json {
            let tag = match status {
                "ok" => tag_ok(self.pal),
                "warn" => tag_warn(self.pal),
                _ => tag_fail(self.pal),
            };
            if detail.is_empty() {
                println!("  {tag} {name}");
            } else {
                println!("  {tag} {name:<18}{}", style::prose(detail, self.pal));
            }
        }
        self.checks.push(Check {
            name: name.to_string(),
            status,
            detail: detail.to_string(),
            notes: Vec::new(),
        });
    }

    /// Add a context line under the check just recorded. A note with no check open is dropped in
    /// silence, which cannot happen from this module: every note here follows a check.
    fn note(&mut self, text: &str) {
        if !self.json {
            println!(
                "         {}",
                style::dim_prose(&format!("· {text}"), self.pal)
            );
        }
        if let Some(last) = self.checks.last_mut() {
            last.notes.push(text.to_string());
        }
    }

    /// The document `--json` prints, once every check has been recorded. `remediation` is carried
    /// because it is the part a caller acts on: a red check says what is wrong, the hint says what
    /// to do, and splitting them across two outputs would make the document the less useful half.
    fn to_json(&self, remediation: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "checks": self
                .checks
                .iter()
                .map(|c| serde_json::json!({
                    "name": c.name,
                    "status": c.status,
                    "detail": c.detail,
                    "notes": c.notes,
                }))
                .collect::<Vec<_>>(),
            "ok": remediation.is_empty(),
            "remediation": remediation,
        })
    }
}

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

/// Report the runtime prerequisites and fail hard if a load-bearing one is
/// missing. Each failing check contributes its own remediation hint, so the
/// summary never points at the wrong cause.
pub(crate) fn doctor(json: bool) -> ExitCode {
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal() && !json);
    let (h, r) = (pal.head, pal.reset);
    if !json {
        println!("{h}sbx doctor{r} — runtime preflight\n");
    }
    let mut rep = Report::new(json, &pal);

    let mut remediation: Vec<&str> = Vec::new();

    // The data directory, resolved once and reused for the engines and the store/channel
    // report below. Read-only in that it derives paths from the environment; resolving the
    // engines may materialize one sbx ships (the bundled-* builds), which is intended.
    let layout = store::Layout::from_env();

    // The sandbox engine itself. Hold the choice: a present engine is what lets the
    // boundary be proven by a real launch rather than a stand-in, and its source explains
    // which `bwrap` ran and why — the bundled engine, the host's, or an override.
    let bwrap = store::try_resolve_bwrap(layout.as_ref());
    match &bwrap {
        Ok(c) => {
            rep.check("ok", "bubblewrap", &c.path.display().to_string());
            let note = if c.apparmor_restricted {
                " — AppArmor userns restriction active (host engine required)"
            } else {
                ""
            };
            rep.note(&format!("{}{note}", c.source.label()));
        }
        Err(store::EngineMiss::NotFound) => {
            rep.check("fail", "bubblewrap", "not found");
            remediation.push("install bubblewrap (the sandbox engine)");
        }
        Err(store::EngineMiss::Refused { env, path }) => {
            rep.check(
                "fail",
                "bubblewrap",
                &format!("refused: {env}={}", path.display()),
            );
            remediation.push(BWRAP_OVERRIDE_REMEDIATION);
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
        &mut rep,
        bwrap.as_ref().ok().map(|c| c.path.as_path()),
        &mut remediation,
    );
    if let Some(v) = read_sysctl("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") {
        rep.note(&format!(
            "kernel.apparmor_restrict_unprivileged_userns = {v}"
        ));
    }
    if let Some(v) = read_sysctl("/proc/sys/kernel/unprivileged_userns_clone") {
        rep.note(&format!("kernel.unprivileged_userns_clone = {v}"));
    }
    report_resource_limits(&mut rep, &config::global_limits());
    report_transparent_capture(&mut rep);

    // The nix that drives the store. Its absence is load-bearing too — without
    // nix, sbx cannot provision a project's tools. Resolution follows override,
    // then an sbx-owned engine, then `PATH`; it makes no store or config change,
    // though a `bundled-nix` build materializes its embedded engine under
    // `<data>/engine/` on first use (idempotent), which a launch would do anyway.
    match store::try_resolve_nix(layout.as_ref()) {
        Ok(nix) => {
            rep.check("ok", "nix", &nix.display().to_string());
            if let Some(v) = nix_version(&nix) {
                rep.note(&v);
            }
        }
        Err(store::EngineMiss::NotFound) => {
            rep.check("fail", "nix", "not found");
            remediation.push("install nix (the store engine sbx drives daemonlessly)");
        }
        // Not "not found", and not an install hint: the engine is installed — sbx declined to run
        // the one the override names. Telling this user to install nix would send them after a
        // package they already have.
        Err(store::EngineMiss::Refused { env, path }) => {
            rep.check("fail", "nix", &format!("refused: {env}={}", path.display()));
            remediation.push(NIX_OVERRIDE_REMEDIATION);
        }
    }

    // git fetches a remote plugin store (`sbx plugins store add`). It is not on the launch
    // path — a sandbox runs without it — so its absence is a feature gap reported for
    // context, never a boundary failure that blocks `sbx run`.
    match store::resolve_git() {
        Some(git) => {
            rep.check("ok", "git", &git.display().to_string());
            // Say it plainly even when present: unlike bubblewrap and nix above, git is not a
            // prerequisite — a sandbox launches without it. It only enables `sbx plugins store`.
            rep.note("optional — needed only for `sbx plugins store`, not to run a sandbox");
        }
        None => rep.check(
            "warn",
            "git",
            "not found on PATH — optional, needed only for `sbx plugins store`",
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
            rep.check(
                "ok",
                "store",
                &format!("{} ({state}{origin})", dir.display()),
            );
            match store::read_global_lock(layout) {
                Some((source, rev)) => rep.check(
                    "ok",
                    "channel",
                    &format!("{source} @ {} (locked)", short_rev(&rev)),
                ),
                None => rep.check("ok", "channel", "not yet resolved — seeded on first launch"),
            }
            report_distro(&mut rep, layout);
        }
        None => {
            rep.check(
                "warn",
                "store",
                "unresolved (no $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)",
            );
            rep.check("warn", "channel", "unresolved (no data directory)");
        }
    }

    // Storage is opt-in and never a prerequisite, so this line is always [ ok ]/[warn], never a
    // failure: it reports whether the data directory lives in a volume, and — when it does not —
    // whether one is worth adopting on this host. It is the standing discoverability anchor, so a
    // one-time proposal declined elsewhere still leaves the path visible here.
    report_storage(&mut rep);

    // The document is printed instead of the summary, not beside it: a caller asked for one
    // output, and the remediation it would otherwise miss rides inside it.
    if json {
        if let Err(code) = crate::print_json("doctor", &rep.to_json(&remediation)) {
            return code;
        }
        return if remediation.is_empty() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }

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

/// Report whether a filtering launch can capture the traffic of a client that ignores the proxy
/// environment variables.
///
/// Context, never a prerequisite — the same standing as resource limits, and for the same reason:
/// where it is unavailable the cage still runs and still filters, the difference being that such a
/// client fails at `connect(2)` instead of being routed and named. Reported here because that is
/// otherwise invisible: a launch says nothing about it, precisely so a host without the machinery
/// is not nagged on every run.
///
/// The answer comes from actually installing the rules in a throwaway namespace. Reading kernel
/// configuration instead would be inference: whether an unprivileged namespace may autoload the nat
/// modules is not stated in any single file, and it is the question that decides this.
fn report_transparent_capture(rep: &mut Report<'_>) {
    let Ok(exe) = std::env::current_exe() else {
        rep.note("transparent capture: unknown (sbx cannot locate its own binary)");
        return;
    };
    match sandbox::probe_capture(&exe) {
        sandbox::CaptureSupport::Ready => {
            rep.check(
                "ok",
                "capture",
                "a client that ignores the proxy variables is still routed",
            );
            rep.note("proven by installing the redirect rules in a throwaway namespace");
        }
        other => {
            rep.check(
                "warn",
                "capture",
                "proxy-blind clients will fail to connect, not be routed",
            );
            if let sandbox::CaptureSupport::Refused(why) = &other {
                rep.note(&format!("the kernel refused: {why}"));
            }
            if let Some(hint) = other.remediation() {
                rep.note(hint);
            }
        }
    }
}

/// Report best-effort cgroup v2 resource limiting (anti-DoS). Unlike the security
/// boundary, resource limits are hardening: where they cannot be applied the cage
/// still runs, so an unavailable limiter is reported for context and never
/// recorded as a missing prerequisite. The probe launches a real transient scope,
/// so a green line means limiting actually works on this host.
fn report_resource_limits(rep: &mut Report<'_>, limits: &sandbox::cgroup::Limits) {
    // Reflect the *global* config's limits — they apply to every launch regardless of project,
    // and the live probe validates them, so a bad global value surfaces here. A trusted project
    // may further tune them per project; `sbx config` is the project-aware view.
    let report: sandbox::LimitReport = sandbox::resource_limits(limits);
    if report.verified {
        rep.check(
            "ok",
            "resource limits",
            &format!(
                "cage capped via a systemd scope ({})",
                report.properties.join(", ")
            ),
        );
    } else if let Some(note) = report.note {
        rep.check("warn", "resource limits", &note);
    }
}

/// The host-level distribution image, when one is pinned: which image, which digest, and whether
/// its tree is unpacked.
///
/// Read straight from the shared lock, like the channel line above, because doctor has no project
/// context. A project that declares its own image pins it in its own lock, which this cannot see;
/// what it answers is the host-level question.
///
/// Silent when no image is pinned. Every other line here is a prerequisite, and a cage on the
/// hermetic nix userland has no distribution to check: a line reporting its absence would read as
/// something missing rather than as the ordinary case.
fn report_distro(rep: &mut Report<'_>, layout: &store::Layout) {
    use crate::sandbox::distro::store::DISTRO_LOCK;
    let Some((locator, Some(digest))) =
        store::read_lock_lines(&layout.data_dir().join(DISTRO_LOCK))
    else {
        return;
    };
    let dir = layout
        .distro_dir()
        .join(digest.replacen(':', "-", 1))
        .join("rootfs");
    let state = if dir.is_dir() {
        "unpacked"
    } else {
        "not unpacked — fetched on the next launch"
    };
    rep.check(
        "ok",
        "distro",
        &format!(
            "{locator} @ {} ({state})",
            short_rev(digest.trim_start_matches("sha256:"))
        ),
    );
}

/// Report the storage posture: whether the data directory lives in an encapsulated volume, and
/// when it does not, whether one is available on this host. Read-only and best-effort — it reads
/// the pointer and probes capabilities, mounting nothing and creating nothing. Anchored to the
/// *default* data directory (where the image and pointer live), not the possibly-followed one.
fn report_storage(rep: &mut Report<'_>) {
    let Some(default_dir) = store::Layout::default_data_dir() else {
        return;
    };

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
                rep.check(
                    "ok",
                    "storage",
                    &format!("type: volume ({fs}) at {}", mount_point.display()),
                );
                rep.note(&format!(
                    "compression {comp}; the data directory costs the host a single inode"
                ));
            }
            _ => rep.check(
                "warn",
                "storage",
                &format!(
                    "type: volume — set to use {} but it is not mounted",
                    image.display()
                ),
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
        rep.check(
            "warn",
            "storage",
            &format!("{ty} — nothing here survives a reboot"),
        );
        rep.note("$SBX_DATA_DIR can point sbx at a directory that persists");
    } else if pre.host_fs.is_some_and(|k| k.is_cow()) {
        rep.check("ok", "storage", &format!("{ty} — already copy-on-write"));
        rep.note("an encapsulated volume would add little");
    } else if pre.recommends_volume() {
        rep.check(
            "ok",
            "storage",
            &format!("{ty} — a compressed btrfs volume is available"),
        );
        rep.note("adopt one with `sbx storage init`");
    } else if let Some(blocker) = pre.mount_blocker() {
        rep.check(
            "warn",
            "storage",
            &format!("{ty} — no encapsulated volume here: {blocker}"),
        );
        rep.note("$SBX_DATA_DIR can still point sbx at an existing btrfs mount");
    } else if pre.remote_session {
        // Mountable in principle, but udisks needs a local active session to do it unattended.
        rep.check(
            "ok",
            "storage",
            &format!("{ty} — a volume needs a local active session"),
        );
        rep.note("udisks asks for authentication over SSH; `sbx storage init` to try");
    } else if !pre.kernel_btrfs {
        rep.check(
            "ok",
            "storage",
            &format!("{ty} — btrfs kernel support not detected"),
        );
        rep.note("a mount would try to autoload it; `sbx storage init` to try");
    } else {
        rep.check("ok", "storage", &ty);
    }
}

/// Report the security boundary. When bubblewrap is present, a real launch
/// decides the green path and the `unshare` stand-in does not run at all. On
/// failure — or when there is no engine to launch — the stand-in classifies the
/// cause so the report blames the right layer and never the wrong one.
fn report_security_boundary(
    rep: &mut Report<'_>,
    bwrap: Option<&Path>,
    remediation: &mut Vec<&'static str>,
) {
    let Some(bwrap) = bwrap else {
        // No engine to launch: the stand-in is the only available signal for the
        // boundary. Report it for context (the missing-engine remediation is
        // already recorded), and still flag a broken namespace as its own fault.
        match probe_userns() {
            Userns::Ok => {
                rep.note("user namespaces: capability-bearing (cannot prove without bubblewrap)")
            }
            other => classify_namespace_failure(rep, &other, remediation),
        }
        return;
    };

    match sandbox::smoke(bwrap) {
        Ok(report) if report.is_hardened() => {
            rep.check("ok", "sandbox", "bubblewrap launched a hardened process");
            rep.note("user namespaces: capability-bearing — proven by the launch");
            rep.note("no_new_privs set, every capability dropped");
            if report.host_home_absent {
                rep.note("host $HOME absent — the bind layout did not leak it");
            } else {
                rep.note("note: the host $HOME was visible inside the probe sandbox");
            }
        }
        Ok(report) => classify_launch_failure(rep, Some(&report.stderr), remediation),
        Err(e) => {
            // The probe could not even spawn bwrap; surface why, then classify.
            rep.note(&format!("could not run the launch probe: {e}"));
            classify_launch_failure(rep, None, remediation);
        }
    }
}

/// A real launch did not yield a hardened process. A capability-bearing namespace
/// means the engine itself failed, so blame bubblewrap and surface its own
/// diagnosis; otherwise the namespace is the cause and is classified as such.
fn classify_launch_failure(
    rep: &mut Report<'_>,
    bwrap_stderr: Option<&str>,
    remediation: &mut Vec<&'static str>,
) {
    match probe_userns() {
        Userns::Ok => {
            rep.check(
                "fail",
                "sandbox",
                "bubblewrap could not launch a hardened process",
            );
            rep.note(
                "user namespaces: capability-bearing (the failure is in bubblewrap, not the namespace)",
            );
            for line in bwrap_stderr
                .unwrap_or_default()
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .take(3)
            {
                rep.note(line);
            }
            remediation.push(BWRAP_LAUNCH_REMEDIATION);
        }
        other => classify_namespace_failure(rep, &other, remediation),
    }
}

/// Report a user namespace that cannot bear the capabilities bubblewrap needs,
/// distinguishing outright absence from the capability-stripped case so the
/// remediation points at the real cause. The caller has already established the
/// namespace is not `Ok`.
fn classify_namespace_failure(
    rep: &mut Report<'_>,
    userns: &Userns,
    remediation: &mut Vec<&'static str>,
) {
    let detail = match userns {
        Userns::Unsupported => "cannot create one without privilege",
        Userns::CapStripped => "created but stripped of capabilities (restricted)",
        // The caller only reaches here with a non-`Ok` namespace; a transient
        // flip to `Ok` is still a failure to launch, so it is flagged, not hidden.
        Userns::Ok => "transient namespace probe failure",
    };
    rep.check("fail", "user namespaces", detail);
    remediation.push(USERNS_REMEDIATION);
}
