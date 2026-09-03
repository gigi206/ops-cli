//! The one function that stands up a cage, alone with the helpers only it uses.
//!
//! `build` is a single linear assembly and is kept whole deliberately. Its blocks — the
//! provisioning of packages, tools, fonts, GPU, audio and portals; the project store seed; then the
//! wired planes: notification sink, process enforcement, the mise and flake equip lanes, the
//! forwarder, the brokers, the egress proxy, the ssh-agent, the fs masks, the control-plane pins,
//! the task socket and the environment layering — each contribute values that three statements at
//! the end consume together. Carving a block out would move eight or ten locals across a signature
//! and would split the surface [`super::super`] asks a security review to audit in one place; the
//! file boundary is what sharpens that surface instead, by making it something a reader opens
//! rather than a range they scroll to.
//!
//! Everything the cage keeps hold of on the host — the supervisor threads, the temporary trees, the
//! sockets — is owned by [`LaunchGuard`], whose drop order is part of the contract rather than an
//! accident of field order.

use super::equip::{
    MISE_EQUIP_VERB, auto_equip_tokens, equip_announcement, mise_token_display, wrap_flake_equip,
    wrap_mise_equip,
};
use super::startup::compose_startup_cmd;
use super::*;

/// The programs the in-cage task client is written against: the **cage's** shell, its `socat`, and
/// coreutils' `head`.
///
/// All three are store paths as the cage resolves them, never the host's copies — the client runs
/// inside, where a host path would either be absent or name a different build than the one the cage
/// has. `head` is not carried on the userland directly; it sits beside the `env` that is.
fn task_client_programs(userland: &binds::Userland) -> (PathBuf, PathBuf, PathBuf) {
    (
        userland.shell_bin.clone(),
        userland.socat_bin.clone(),
        userland.env_bin.with_file_name("head"),
    )
}

/// Provision one optional host-side layer, or degrade to `None` with a warning.
///
/// The five GUI/hardware holes — fonts, GUI data, mesa, the audio userspace, certutil — share one
/// doctrine and one shape: each is wanted only under some posture, each is fetched by a
/// `provision(nix, layout, nixpkgs)` of the same signature, and none of them may fail a launch. A
/// hole that cannot be provisioned costs the feature it serves, never the process the user asked
/// for; `explain` says which feature, in the terms of the posture that asked for it.
///
/// Written once so that doctrine is stated once. The desktop portal is deliberately not routed
/// through here: it shares the callee signature but not the shape, since its site also creates a
/// host directory, starts two relays, and warns on a second condition of its own.
fn optional_layer<T>(
    prep: &Prepared,
    wanted: bool,
    provision: fn(&Path, &Layout, &str) -> io::Result<T>,
    explain: impl FnOnce(&io::Error) -> String,
) -> Option<T> {
    if !wanted {
        return None;
    }
    match provision(&prep.nix, &prep.layout, &prep.nixpkgs) {
        Ok(layer) => Some(layer),
        Err(e) => {
            crate::diag::warn(&explain(&e));
            None
        }
    }
}

/// The read-write binds a launch pins its control plane against: the config's own, plus the project
/// root.
///
/// The project is the one that used to be missing, and it is the one most likely to contain a
/// control-plane root. `binds::build_spec` binds it read-write at its own path *structurally* — it
/// is the work surface, not a configured bind — so it never appeared in `cfg.binds` and never
/// reached [`crate::config::control_plane_pins`]. A session launched from a directory containing a
/// root therefore handed the cage sbx's data dir, trust store and global config read-write and
/// unpinned; `cd ~ && sbx run` is the whole of it, since all three roots live under `$HOME`.
///
/// Pure, and separate from the launch it serves, so the containment can be asserted without one.
///
/// The project path is canonicalized to match what it is compared against:
/// `sbx_control_plane_roots` resolves symlinks, so a symlinked `$HOME` component would otherwise
/// walk straight past the containment test. A path that cannot be canonicalized (it must exist to
/// be a project, so this is the unusual case) is carried through as written rather than dropped —
/// pinning on the literal path is worth more than pinning on nothing.
fn pin_sources(binds: &[crate::config::Bind], project: &Path) -> Vec<crate::config::Bind> {
    let mut sources = binds.to_vec();
    sources.push(crate::config::Bind {
        path: std::fs::canonicalize(project).unwrap_or_else(|_| project.to_path_buf()),
        writable: true,
    });
    sources
}

/// Establish the mountpoint-chain pins that protect sbx's control plane: create each pin's host
/// path (they are sbx's own directories — creating a not-yet-existent root here is what stops the
/// agent pre-creating it unpinned) and turn it into the extra bind that freezes it. On the first
/// path that cannot be created, return the error so the caller can fail the launch closed: a pin
/// that cannot be established would leave the containing read-write bind unprotected.
fn establish_control_plane_pins(pins: &[crate::config::Bind]) -> io::Result<Vec<binds::ExtraBind>> {
    pins.iter()
        .map(|pin| {
            std::fs::create_dir_all(&pin.path)
                .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", pin.path.display())))?;
            Ok(binds::ExtraBind {
                src: pin.path.clone(),
                dest: pin.path.clone(),
                writable: pin.writable,
            })
        })
        .collect()
}

/// The host-side resources a launch must keep alive for the whole session — a filtering egress
/// proxy, an forward loopback forwarder, or both — returned by [`build()`] and held by the
/// supervisor paths ([`run_supervised`], the `--detach` child) so the proxy/forwarder threads
/// outlive the cage. `None` means no such resource: the launcher exec-replaces (the command's
/// exit status becomes sbx's). Dropping the guard drops both, unlinking the on-disk artifacts and
/// closing the listeners; the threads are detached and exit when their listener closes.
pub(super) struct LaunchGuard {
    pub(super) egress: Option<egress::Egress>,
    /// The filtering ssh-agent broker (`[ssh_agent] allow`), when one is running. Its accept loop is
    /// a detached host thread that must outlive the cage; this owns the socket file, unlinked when
    /// the launch ends.
    pub(super) ssh_agent: Option<sshagent::SshAgent>,
    /// The broker plugins standing in front of a host resource (`[broker.<name>]`), one guard per
    /// binding. Same reason as the agent's: each owns a socket file and a detached accept loop that
    /// must outlive the cage, and dropping it unlinks the socket. Holding these in a local would
    /// unlink them before the cage is even built.
    pub(super) brokers: Vec<broker::Broker>,
    /// The reader's end of the brokers' shared decision record, when this launch declared any. Held
    /// here for the same reason the brokers themselves are, and one more: it belongs to the session
    /// rather than to any one broker, so it must outlive the first of them to be torn down.
    pub(super) broker_feed: Option<broker::BrokerFeed>,
    /// The reader's end of the signer record, when this launch declared a signer. Shared by the
    /// agent's proxy and every per-invocation proxy a declared operation stands up, so it outlives
    /// all of them.
    pub(super) signer_feed: Option<crate::sandbox::signer_control::SignerFeed>,
    pub(super) forward: Option<forward::Forwarder>,
    /// The in-cage desktop-notifications relay (`dbus = true`), when one is running. It runs on a
    /// host thread bridging the private bus to the host notifications daemon, so it must outlive the
    /// cage; dropping it stops the thread. Dropped before `portal`, so it disconnects from the private
    /// bus before the portal's host directory (and its socket) is removed.
    pub(super) notify: Option<crate::sandbox::notify_relay::NotifyRelay>,
    /// The in-cage live-theme relay (`dbus = true`), when one is running. It runs on a host thread
    /// mirroring host light/dark changes into the cage's GSettings keyfile, so it must outlive the
    /// cage; dropping it stops the thread. It writes only a host-side file (no private-bus dependency),
    /// so its drop order relative to `portal` is not load-bearing.
    pub(super) theme: Option<crate::sandbox::theme_relay::ThemeRelay>,
    /// The in-cage portal's host runtime directory (`dbus = true`), when one is bound. The
    /// private bus socket lives under it on the host, so it must be cleaned up when the launch ends
    /// rather than leaked by an exec — its presence forces the supervised path; dropping it removes
    /// the directory (socket and generated config).
    pub(super) portal: Option<crate::sandbox::portal::HostDir>,
    /// The refusal notifier (`[notify]`), held for as long as any lens can still refuse something.
    /// Dropping the guard stops delivery and reports whatever the queue could not hold — explicitly,
    /// rather than leaving that to whichever `Arc` happens to fall last.
    pub(super) notify_sink: Option<Arc<crate::sandbox::notify_sink::NotifyWiring>>,
    /// The exec-enforcement supervisor (`[proc] mode = enforce|ask`), when one is running. Its
    /// receive loop is a host thread deciding every notified `execve`, so it must outlive the cage;
    /// its presence forces the supervised path (a live parent). Dropping it stops the supervisor and
    /// unlinks the handoff socket.
    pub(super) proc_enforce: Option<crate::sandbox::proc_enforce::ProcEnforce>,
    /// The task control plane (`[task.*]` declared), when one is serving. Its two listeners are host
    /// threads — one reachable from the cage to invoke a task, one host-only carrying the invocation
    /// log — so it must outlive the cage; its presence forces the supervised path (a live parent, and
    /// an exec-replaced launch would leave nobody serving). Dropping it removes both sockets.
    pub(super) task: Option<crate::sandbox::task_control::TaskPlane>,
}

impl LaunchGuard {
    /// The egress decisions this launch logged, or empty when there is no filtering proxy (a
    /// `shared`/`none` posture, or a forward-only guard). Snapshotted after the run for
    /// `--net-learn`.
    pub(super) fn observed_events(&self) -> Vec<crate::sandbox::control::LogEvent> {
        self.egress
            .as_ref()
            .map(|e| e.observed_events())
            .unwrap_or_default()
    }
}

impl Drop for LaunchGuard {
    fn drop(&mut self) {
        // The inner guards' Drops unlink the proxy/forwarder artifacts and close the listeners.
        // Taking them here runs those Drops explicitly (and reads the fields, so the RAII holds
        // are not flagged as unused — their whole purpose is to stay alive until this drop).
        // First: stop announcing and say what was dropped. Before the lenses below are torn down,
        // so a refusal decided in the last moments still finds a live delivery thread.
        if let Some(notify) = self.notify_sink.take() {
            notify.notifier.finish();
        }
        if let Some(egress) = self.egress.take() {
            drop(egress);
        }
        if let Some(forward) = self.forward.take() {
            drop(forward);
        }
        if let Some(ssh_agent) = self.ssh_agent.take() {
            drop(ssh_agent);
        }
        // Beside the agent, and for the same reason: each unlinks its socket, and closing the
        // listener ends the detached accept loop. Taken as a whole so a launch running several
        // brokers tears them all down.
        for broker in std::mem::take(&mut self.brokers) {
            drop(broker);
        }
        // Then the record they shared, which outlives every one of them: a reader following it
        // sees the last decision of the last broker before the socket goes.
        if let Some(feed) = self.broker_feed.take() {
            drop(feed);
        }
        // The signer record, after the proxy that pushed into it: `egress` above is gone by now, so
        // nothing can still be signing when the socket goes.
        if let Some(feed) = self.signer_feed.take() {
            drop(feed);
        }
        // Before the portal directory: the relay must disconnect from the private bus before its
        // socket is removed.
        if let Some(notify) = self.notify.take() {
            drop(notify);
        }
        if let Some(theme) = self.theme.take() {
            drop(theme);
        }
        if let Some(portal) = self.portal.take() {
            drop(portal);
        }
        if let Some(proc_enforce) = self.proc_enforce.take() {
            drop(proc_enforce);
        }
        // Last: the task plane's Drop unlinks both sockets, and an invocation may still have been
        // running when the cage ended.
        if let Some(task) = self.task.take() {
            drop(task);
        }
    }
}

/// Which zone name this cage was asked for: whatever `TZ` will finally read, and the `timezone`
/// field when nothing set `TZ`.
///
/// The variable comes first *because* it wins. The assembler sets a structural `TZ` from the zone
/// and every overlay layer upserts over it, so a `[env] TZ` (or a one-shot `--env TZ=`) decides what
/// the cage's clock reads whether or not its author thought of it as choosing a zone. Deriving the
/// `/etc/localtime` link from the same value is what keeps the two halves from disagreeing —
/// otherwise the clock moves and the link stays, and an FHS resolver answers the old zone with no
/// error anywhere. `env` is layered lowest-first, so the winning entry is the last one.
///
/// This grants nothing: `timezone` is a free field, so a layer that can write `[env] TZ` could
/// already have written the zone directly.
fn declared_zone<'a>(env: &'a [(String, String)], field: Option<&'a str>) -> Option<&'a str> {
    env.iter()
        .rev()
        .find(|(k, _)| k == "TZ")
        .map(|(_, v)| v.as_str())
        .or(field)
}

/// The IANA zone this cage runs in: the one a config named, when the provisioned database carries
/// it, and [`binds::DEFAULT_ZONE`] otherwise.
///
/// The existence check is here, not in the config layer, for the reason the config layer says: only
/// the launcher has a database to hold a name against. A name it does not carry is a **warning, not
/// a refusal** — a cage that will not start because a zone was misspelled trades a wrong clock for
/// no session at all, and the fallback is a zone that resolves.
///
/// The shape check is [`crate::config::is_zone_name`], the same rule the config validator applies,
/// called again rather than assumed: the name is about to be joined onto the database path and
/// written as a link target, and this is the join site.
fn cage_timezone(declared: Option<&str>, zoneinfo_src: &Path) -> String {
    let fallback = || binds::DEFAULT_ZONE.to_string();
    let Some(zone) = declared else {
        return fallback();
    };
    if !crate::config::is_zone_name(zone) {
        return fallback();
    }
    if zoneinfo_src.join(zone).is_file() {
        return zone.to_string();
    }
    crate::diag::warn_config(&format!(
        "the zone database carries no `{zone}` — the cage's clock reads {} instead",
        binds::DEFAULT_ZONE
    ));
    fallback()
}

/// Build the spec for `cmd`, reporting a clean error as an `ExitCode`. The
/// configuration resolved in [`prepare`] drives this: a trust-gated `.sbx.toml` adds
/// environment and host binds — read-only, or read-write with `mode = "rw"` (its security
/// fields honored only once trusted)
/// and provisions its declared tools onto `PATH`. Whatever the gate dropped or
/// withheld is surfaced as a warning; a declared tool that fails to realise is fatal,
/// since it is a stated requirement.
pub(super) fn build(
    prep: &Prepared,
    runtime: binds::Runtime,
    cmd: Vec<OsString>,
) -> Result<(SandboxSpec, Option<LaunchGuard>), ExitCode> {
    for warning in &prep.cfg.warnings {
        crate::diag::warn_config(warning);
    }

    // Reclaim the per-launch runtime files of launches that are gone, before standing up our own.
    // Their RAII guards unlink on a clean exit, but a cage normally ends on a signal (Ctrl-C,
    // `sbx session stop`, a detached session killed later) and a `Drop` does not run then — so each
    // cage tidies up after its predecessors. Silent and best-effort: routine housekeeping, and a
    // live launch's files are never touched (its pid still reads as live). The same self-healing
    // doctrine the session registry applies to its records.
    //
    // This sits in `build` — the one function that actually stands up a cage — rather than in
    // `prepare`, which `sbx gc` also calls: a gc *dry run* must touch nothing, and sweeping from
    // there would have deleted these files while reporting them as merely reclaimable.
    crate::sandbox::gc::sweep_runtime_dirs(prep.layout.data_dir(), true);
    crate::sandbox::gc::fold_egress_counters(prep.layout.data_dir(), true);

    // Provision the project's declared tools into sbx's store, against the project's
    // effective nixpkgs reference; their bin dirs are prepended to PATH below. A
    // withheld (untrusted) tool only warns; an admitted tool that fails to realise is
    // fatal.
    let mut packages = match crate::sandbox::packages::provision(
        &prep.nix,
        &prep.layout,
        &prep.cwd,
        &prep.nixpkgs,
        &prep.cfg.packages,
    ) {
        Ok(v) => v,
        Err(e) => {
            crate::diag::error(&format!("sbx: {e}"));
            return Err(ExitCode::FAILURE);
        }
    };
    for warning in &packages.warnings {
        crate::diag::warn_config(warning);
    }

    // Provision a trusted project's `nix:` mise tools — the exact-pinned dev toolchain.
    // Their bin dirs go ahead of the native `[packages]` ones, so a project's pinned
    // tool wins over the coarser package layer on a name clash.
    let tools = mise_tools(prep)?;
    for warning in &tools.warnings {
        crate::diag::warn_config(warning);
    }
    let mut bin_paths = tools.bins;
    bin_paths.extend(packages.bins);

    // The prebuilt backends — `deb:`, `appimage:`, `tarball:` — are provisioned host-side (like
    // `nix:` and a remote `flake:`, not in-cage like an inline `[flakes.<name>]`): sbx resolves
    // each declared locator to a hash (pinned in the
    // per-project lock), builds the generated unpack+autoPatchelf derivation into sbx's store,
    // prepends its bin to PATH, and seeds its closure (its root joins `packages.roots`). All three
    // unpack at *build* time — an AppImage's squashfs is never self-mounted at runtime, which the
    // seccomp cage forbids anyway. A declared package is a requirement: a provisioning failure aborts
    // the launch naming it, never runs without it.
    let ctx = prebuilt_ctx(prep);
    for kind in crate::sandbox::prebuilt::DIRECT_ORDER {
        for (name, url) in kind.packages(&prep.cfg.packages) {
            let libs = crate::sandbox::prebuilt::libs_of(&prep.cfg.packages, &name);
            match crate::sandbox::prebuilt::provision(kind, &ctx, &name, &url, &libs) {
                Ok((bin, root)) => {
                    bin_paths.push(bin);
                    packages.roots.push(root);
                }
                Err(e) => {
                    crate::diag::error(&format!(
                        "sbx: cannot provision {} package `{name}` ({url}): {e}",
                        kind.name()
                    ));
                    return Err(ExitCode::FAILURE);
                }
            }
        }
    }

    // The `<backend>:resolve` packages are the auto-upgrade form: sbx runs the profile's resolve
    // command in a hermetic sandbox to discover the newest download URL, then resolves+builds it
    // exactly like the direct form (same per-project lock and gcroot). A warm launch reuses the pin
    // offline and does NOT run the command. The command runs with sbx's base tools plus the app's own
    // `nix:` bins and every direct package's bin on PATH (so a command that needs e.g. `jq` declares
    // it), and sbx's own store + CA bundle bound. The cage is built once, here: a resolver never sees
    // another resolver's bin, only the direct layer's.
    let resolve_cage = {
        let mut bins = prep.userland.bin_paths.clone();
        bins.extend(bin_paths.iter().cloned());
        crate::sandbox::resolve::ResolveCage {
            bwrap: prep.bwrap.as_path(),
            store_src: crate::store::physical_path(&prep.layout, std::path::Path::new("/nix")),
            shell_bin: prep.userland.shell_bin.as_path(),
            ca_bundle: prep.userland.ca_bundle_src.as_path(),
            bins,
        }
    };
    for kind in crate::sandbox::prebuilt::RESOLVE_ORDER {
        for (name, command) in kind.resolve_packages(&prep.cfg.packages) {
            let libs = crate::sandbox::prebuilt::libs_of(&prep.cfg.packages, &name);
            match crate::sandbox::prebuilt::provision_resolve(
                kind,
                &ctx,
                &name,
                &command,
                &resolve_cage,
                &libs,
            ) {
                Ok((bin, root)) => {
                    bin_paths.push(bin);
                    packages.roots.push(root);
                }
                Err(e) => {
                    crate::diag::error(&format!(
                        "sbx: cannot provision {} resolver package `{name}`: {e}",
                        kind.name()
                    ));
                    return Err(ExitCode::FAILURE);
                }
            }
        }
    }

    // A remote `flake:` package is built host-side into the shared store and seeded per project (see
    // `packages::provision`), so it lands once and is reused everywhere like a `nix:` tool — its `bin/`
    // is already on PATH via the provisioned package bins. Only inline `[flakes.<name>]` flakes still
    // build in-cage here: an inline flake is local content the user staged, and building local content
    // host-side is exactly what `is_valid_flake_ref` refuses for a remote ref, so the inline case stays
    // contained in the cage. Their out-link `bin` directories join PATH now, ahead of the base like
    // every other declared tool, and need not exist yet: the in-cage `nix build` creates each one
    // before the command runs, exactly as the mise shims dir is on PATH before mise populates it.
    // Each quad carries the build ref, the content-hash-keyed build *target*
    // out-link, the stable *good* out-link PATH resolves through (kept at the last good build on a
    // failure), and the flake name.
    let mut flake_pairs: Vec<(String, PathBuf, PathBuf, String)> = Vec::new();
    let mut inline_flake_names: Vec<String> = Vec::new();

    // Inline `[flakes.<name>]` flakes: stage each `flake.nix` to a content-keyed directory on disk,
    // bind it read-only into the cage at `/opt/sbx/flakes/<name>`, and build `path:<dir>#<attr>`
    // through the *same* in-cage wrap as a `flake:` package (appended to `flake_pairs`). The out-link
    // is keyed by the source's content hash, so editing the flake in the config rebuilds at the next
    // launch — a fresh hash the warm short-circuit misses — while an unchanged flake reuses the warm
    // build. Trusted-only, like `flake_packages`. Best-effort: a staging failure warns and skips that
    // one flake rather than failing the launch.
    let mut inline_flake_binds: Vec<binds::ExtraBind> = Vec::new();
    for (name, content, attr) in crate::sandbox::packages::flake_inline_packages(&prep.cfg.packages)
    {
        let (dir, hash) =
            match crate::sandbox::flake_inline::stage(prep.layout.data_dir(), &content) {
                Ok(v) => v,
                Err(e) => {
                    crate::diag::warn_config(&format!(
                        "inline flake `{name}` could not be staged ({e}) — skipping it"
                    ));
                    continue;
                }
            };
        let incage = binds::flake_inline_incage(&name);
        let build_ref = format!("path:{}#{attr}", incage.display());
        // The content-hash-keyed target rebuilds when the inline flake is edited; the name-only good
        // out-link is the stable PATH entry the wrap keeps at the last good build on a failure.
        let target = binds::flake_out_link_hash(&name, &hash);
        let good = binds::flake_out_link(&name);
        inline_flake_binds.push(binds::ExtraBind {
            src: dir,
            dest: incage,
            writable: false,
        });
        bin_paths.push(good.join("bin"));
        inline_flake_names.push(name.clone());
        flake_pairs.push((build_ref, target, good, name));
    }

    // Under `gui = "wayland"`, provision the GUI font set host-side so the cage renders text
    // rather than boxes. Provisioned here — before the seed — so its store roots join the
    // project store and the cage reads the fonts through `/nix`. Best-effort, like the display
    // socket below: a font fetch that fails (no network on a first launch) warns and the app
    // runs without fonts rather than failing the launch.
    let font_layer = optional_layer(
        prep,
        prep.cfg.gui.renders(),
        crate::sandbox::fonts::provision,
        |e| {
            format!(
                "this `gui` posture renders but the font set could not be provisioned \
                 ({e}) — text may not render"
            )
        },
    );
    let font_roots: &[PathBuf] = font_layer.as_ref().map_or(&[], |l| l.roots.as_slice());

    // Under `gui = "wayland"`, provision the GUI data set (GSettings schemas + GTK themes)
    // host-side. A GTK dialog (the file chooser Electron falls back to without a desktop portal)
    // aborts FATAL without the schemas (`No GSettings schemas are installed`); the themes let the
    // in-cage portal's file dialog render in the host light/dark theme. Provisioned here — before
    // the seed — so its store root joins the project store. Best-effort like the fonts: a fetch
    // that fails warns and the app runs (a GTK dialog will still crash, but the rest is unaffected).
    let guidata_layer = optional_layer(
        prep,
        matches!(prep.cfg.gui, crate::config::GuiPolicy::Wayland),
        crate::sandbox::guidata::provision,
        |e| {
            format!(
                "`gui = \"wayland\"` but the GUI data (GSettings schemas + themes) could not \
                 be provisioned ({e}) — a GTK dialog (file chooser) may crash"
            )
        },
    );

    // In-cage desktop portal: under `gui = "wayland"` AND `dbus = true`, provision the portal
    // stack (dbus + xdg-desktop-portal + the GTK backend) host-side — before the seed, so its roots
    // join the project store — and read the host theme, best-effort, to seed the cage's light/dark
    // scheme at launch. The wrap that starts the private bus is applied after every other command
    // wrap (below), so the bus is up before the app. Best-effort: a provisioning failure warns and
    // the app runs without an in-cage portal (its file chooser then falls back to its own dialog).
    // Requires the Wayland display (the GTK backend renders through the compositor), so it is gated
    // on both. Unlike the filtered host bus, the private bus touches no host socket, so the network
    // posture does not gate it.
    // The portal's host-side runtime directory, bound into the cage so the in-cage dbus-daemon's
    // socket is reachable from the host (the notifications relay attaches there). Created alongside
    // the provision so `portal` being `Some` implies the directory exists; a create failure drops the
    // portal (fail-closed: no bus rather than a broken one). Held until the launch ends by the guard.
    let mut portal_host: Option<crate::sandbox::portal::HostDir> = None;
    let mut notify_relay: Option<crate::sandbox::notify_relay::NotifyRelay> = None;
    let mut theme_relay: Option<crate::sandbox::theme_relay::ThemeRelay> = None;
    let portal = if prep.cfg.dbus && matches!(prep.cfg.gui, crate::config::GuiPolicy::Wayland) {
        match crate::sandbox::portal::provision(&prep.nix, &prep.layout, &prep.nixpkgs) {
            Ok(p) => match crate::sandbox::portal::HostDir::create(&prep.layout) {
                Ok(hd) => {
                    // Start the desktop-notifications relay against the private-bus socket the portal
                    // exposes on the host. It waits for the in-cage dbus-daemon to create the socket,
                    // then owns `org.freedesktop.Notifications` on the private bus and forwards to the
                    // host daemon (re-emitting its signals back). Best-effort: no host bus or a socket
                    // that never appears just leaves the app without notifications — the in-cage picker
                    // and at-launch theme are unaffected.
                    notify_relay = Some(crate::sandbox::notify_relay::NotifyRelay::start(
                        hd.socket(),
                    ));
                    // Start the live-theme relay: it mirrors later host light/dark switches into the
                    // in-cage GSettings keyfile (through the home bind), so the in-cage portal
                    // re-emits SettingChanged and the app follows the change live. The home is
                    // derived exactly as `build_spec` binds it, so both target the same file — and it
                    // is handed over unjoined because the relay walks the rest of the way itself,
                    // refusing a symlink at every cage-writable component.
                    // Best-effort: a home path that cannot be resolved just leaves the at-launch theme.
                    if let Ok(home) = binds::home_src(prep.layout.data_dir(), &prep.cwd, runtime) {
                        theme_relay = Some(crate::sandbox::theme_relay::ThemeRelay::start(home));
                    }
                    portal_host = Some(hd);
                    Some(p)
                }
                Err(e) => {
                    crate::diag::warn(&format!(
                        "`dbus = true` but the portal runtime directory could not be created \
                         ({e}) — running without an in-cage file chooser"
                    ));
                    None
                }
            },
            Err(e) => {
                crate::diag::warn(&format!(
                    "`dbus = true` but the in-cage portal could not be provisioned ({e}) — \
                     running without an in-cage file chooser"
                ));
                None
            }
        }
    } else if prep.cfg.dbus {
        // `dbus = true` without a display: the in-cage portal's GTK backend renders on the
        // compositor, so it cannot stand up. Warn rather than silently doing nothing.
        crate::diag::warn(
            "`dbus = true` needs `gui = \"wayland\"` (the in-cage portal renders on the \
             compositor) — running without a desktop portal",
        );
        None
    } else {
        None
    };
    // The host light/dark preference, read host-side (best-effort) to seed the cage theme. Read
    // over the session bus directly rather than by running a provisioned `dbus-send`: a binary in
    // sbx's relocated store names an interpreter under a `/nix` the host does not have, so it
    // could not be executed here at all.
    let portal_scheme = portal
        .as_ref()
        .and_then(|_| crate::sandbox::theme_relay::read_host_color_scheme());

    // CA trust for a Chromium/Electron engine under a filtering posture: Chromium ignores the
    // CA-file env vars sbx sets and reads its own NSS db, so under the egress MITM it rejects
    // sbx's per-session CA and every page fails to load. When the cage BOTH renders (`gui =
    // "wayland"` for a window, `"offscreen"` for a headless browser) AND filters egress,
    // provision `certutil` (part of the rendering hole, like the fonts) so the command wrap below
    // can import the bound CA into the cage's NSS db. Gated to exactly those cages — a plain CLI
    // tool needs nothing (its env-reading TLS already trusts the CA), and `shared`/`none` has no
    // MITM CA. Best-effort: a provisioning failure warns and the app runs (and fails its own
    // HTTPS) rather than blocking the launch.
    let ca_trust = optional_layer(
        prep,
        prep.cfg.gui.renders()
            && matches!(prep.cfg.network, crate::config::NetworkPolicy::Allowlist(_)),
        crate::sandbox::catrust::provision,
        |e| {
            format!(
                "this `gui` posture renders under a network allowlist but certutil could not \
                 be provisioned ({e}) — a Chromium/Electron engine will not trust the egress \
                 proxy"
            )
        },
    );

    // Under `gpu = true`, provision mesa's DRI drivers host-side so the cage can render with
    // hardware acceleration. Provisioned here — before the seed — so mesa's store root joins the
    // project store and the cage reads the drivers through `/nix`; the env pointing libgbm/libEGL
    // at them is applied in the launch block below. Best-effort, like the fonts: a fetch that fails
    // warns and the app runs (falling back to software rendering) rather than failing the launch.
    let gpu_layer = optional_layer(prep, prep.cfg.gpu, crate::sandbox::gpu::provision, |e| {
        format!(
            "`gpu = true` but the mesa drivers could not be provisioned \
                 ({e}) — rendering may fall back to software"
        )
    });

    // Under `audio = true`, provision the PulseAudio client library (`libpulse.so.0`) host-side so
    // the cage can open capture/playback streams. Provisioned here — before the seed — so its store
    // root joins the project store and the cage reads the library through `/nix`; the env pointing
    // the app's loader at it (and the socket bind) is applied in the launch block below. Best-effort,
    // like the fonts and mesa: a fetch that fails warns and the app runs (without audio).
    let audio_layer = optional_layer(
        prep,
        prep.cfg.audio,
        crate::sandbox::audio::provision,
        |e| {
            format!(
                "`audio = true` but the audio userspace could not be provisioned \
                 ({e}) — the app runs without audio"
            )
        },
    );

    // The GUI-hole store roots to seed: the fonts plus (when present) certutil, mesa, and
    // libpulseaudio, so the cage reads them all through `/nix`.
    let mut gui_roots: Vec<PathBuf> = font_roots.to_vec();
    if let Some(ct) = &ca_trust {
        gui_roots.push(ct.root.clone());
    }
    if let Some(layer) = &gpu_layer {
        gui_roots.push(layer.root.clone());
    }
    if let Some(layer) = &audio_layer {
        gui_roots.extend(layer.roots.iter().cloned());
    }
    if let Some(layer) = &guidata_layer {
        gui_roots.push(layer.root.clone());
    }
    if let Some(p) = &portal {
        gui_roots.extend(p.roots.iter().cloned());
    }

    // Seed the project's own writable store with the closure of everything the cage
    // resolves through `/nix` — the base userland, every provisioned tool, and (under the
    // GUI hole) the fonts and certutil — then back `/nix` with it read-write. The cage reads and
    // writes only its own store, so an agent that installs a toolchain writes into the project's
    // copy. Which store backs `/nix` is sbx's
    // decision, not a configurable field, so an untrusted project cannot keep the shared
    // store mounted or widen its access. The shared store reaches the cage only through the
    // read-only plumbing pins below (see [`plumbing_pins`]), which is the one place a cage sees
    // any of it — and only as bytes it cannot write.
    let project_store = match seed_project_store(prep, &packages.roots, &tools.roots, &gui_roots) {
        Ok(s) => s,
        Err(e) => {
            crate::diag::error(&format!("sbx: cannot prepare the project's store: {e}"));
            return Err(ExitCode::FAILURE);
        }
    };
    let nix_mount = {
        let src = project_store.store_dir().join("nix");
        // Probed here (host-side, real path) so assembly stays pure: a btrfs-backed
        // store makes the in-cage nix leave the inherited `btrfs.compression`
        // attribute in place, else its canonicalisation aborts a build.
        let on_btrfs = crate::storage::on_btrfs(&src);
        binds::NixMount {
            src,
            writable: true,
            on_btrfs,
        }
    };

    // Mise-backed tools are equipped in-cage at launch rather than host-provisioned, in two
    // distinct lanes. The app's `[packages] mise:` tools are durable, trusted-only declarations,
    // equipped **globally** (`mise use -g`, written to the home's global mise config). The
    // project's local `.mise.toml` non-`nix:` tools (an `aqua:`/`npm:`/registry backend) are the
    // **open** self-equip toolchain, equipped **locally** (`mise install`) with the in-cage mise
    // told to trust the project config so they resolve through the shims on PATH. Both fetch, so
    // both wrap the command *before* the egress wrap below — under an allowlist the forwarder is
    // up before either install — and both are skipped under `network = "none"`.
    // The wraps each block below contributes. They are nested by `WrapLayer`, not by the order the
    // blocks run in, so a block may register its wrap wherever the value it needs becomes available.
    let mut wraps: Vec<(WrapLayer, CommandWrap)> = Vec::new();

    // Exec enforcement (`[proc] mode = enforce|ask`): stand up the seccomp user-notification
    // supervisor and wrap the command with the in-cage shim, **innermost** — so only the agent
    // command and its children are filtered, not the provisioning/egress plumbing wrapped around it
    // below. What makes that exemption safe rather than a hole is `plumbing_pins`: the programs
    // those outer preambles run are pinned read-only from the shared store, so an unfiltered
    // preamble cannot be an agent-supplied one. Its guard forces the supervised path (a live parent
    // for the supervisor thread).
    // Fail-closed: if the supervisor cannot be stood up, the launch is refused rather than running the
    // command unenforced.
    // The refusal notifier (`[notify]`), stood up before the first lens that can refuse anything and
    // held for the whole launch. The credential set it redacts against is filled in below, once the
    // egress proxy has resolved this launch's secrets — the exec supervisor needs the notifier before
    // that resolution happens, and nothing can be refused in between.
    let notify_needles: crate::sandbox::notify_sink::Needles = Arc::new(RwLock::new(Vec::new()));
    // Which sandbox every announcement names. The pid is this launcher's — the one `sbx session ls`
    // lists and `sbx session attach`/`sbx session stop` take — so a notification points at something
    // to act on.
    let notify_origin = crate::notify::Origin {
        app: match runtime {
            binds::Runtime::GlobalApp(name) | binds::Runtime::ProjectApp(name) => name.to_string(),
            binds::Runtime::ProjectDefault => String::new(),
        },
        project: prep
            .cwd
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        pid: std::process::id(),
    };
    let notify_wiring = Arc::new(crate::sandbox::notify_sink::NotifyWiring {
        notifier: Arc::new(crate::sandbox::notify_sink::Notifier::start(
            prep.cfg.notify,
            Arc::clone(&notify_needles),
            &notify_origin,
        )),
        needles: notify_needles,
    });

    // The trust lens: a security field this project declared and sbx dropped, because the config
    // carrying it is not trusted. Announced here, once the notifier exists, because the symptom
    // otherwise arrives much later and in disguise — a cage that is not shaped the way its config
    // plainly reads, with the explanation buried in the launch's warning list.
    for warning in prep
        .cfg
        .warnings
        .iter()
        .filter(|w| crate::config::is_trust_drop(w))
    {
        notify_wiring.notifier.block(crate::notify::Block {
            event: crate::notify::NotifyEvent::Trust,
            subject: warning.clone(),
            reason: "not-trusted".to_string(),
            detail: String::new(),
            fix: "sbx trust".to_string(),
        });
    }

    let mut proc_enforce_guard = None;
    let mut proc_binds: Vec<binds::ExtraBind> = Vec::new();
    // The content lens rides the same supervisor as exec enforcement — it is the same notification
    // listener, read for a different syscall. So `[fs] scan` brings the supervisor up on its own:
    // making it depend on `[proc]` would tie one guarantee to an unrelated one.
    let content_lens = if prep.cfg.fs.scan.is_empty() {
        None
    } else {
        let ceiling = prep
            .cfg
            .fs
            .scan_max_kb
            .and_then(|kb| usize::try_from(kb.saturating_mul(1024)).ok())
            .unwrap_or(crate::open_policy::MAX_SCAN_DEFAULT);
        match crate::open_policy::OpenPolicy::compile(&prep.cfg.fs.scan, ceiling) {
            Ok(policy) => policy.map(|policy| {
                // Canonical, because the bound is applied to paths the kernel has resolved.
                let root = std::fs::canonicalize(&prep.cwd).unwrap_or_else(|_| prep.cwd.clone());
                (policy, root)
            }),
            Err(e) => {
                // Refused rather than dropped: a launch that ran with a scan it could not build
                // would report a protection it does not have.
                crate::diag::error(&format!(
                    "sbx: cannot build the `[fs] scan` content scanner: {e}"
                ));
                return Err(ExitCode::FAILURE);
            }
        }
    };
    if prep.cfg.proc.enforcing() || content_lens.is_some() {
        // The shim is sbx's own embedded binary, laid down under the data directory. Refusing when
        // it cannot be placed is the point: the alternative would be binding some other executable
        // into the cage, which is the exposure the dedicated shim exists to remove.
        let shim_bin = crate::store::ensure_proc_shim(&prep.layout).map_err(|e| {
            crate::diag::error(&format!("sbx: cannot place the exec-enforcement shim: {e}"));
            ExitCode::FAILURE
        })?;
        // With `[proc]` off, the exec side is a denylist with nothing on it: every `execve` is
        // notified and allowed, which is what the shim's filter produces anyway. The lens is what
        // this launch asked for.
        let exec_policy = if prep.cfg.proc.enforcing() {
            prep.cfg.proc.clone()
        } else {
            crate::proc_policy::ProcPolicy::new(crate::proc_policy::ProcMode::Enforce, &[], &[])
        };
        let (guard, wiring) = crate::sandbox::proc_enforce::start(
            prep.layout.data_dir(),
            &shim_bin,
            exec_policy,
            content_lens,
            Arc::clone(&notify_wiring.notifier),
        )
        .map_err(|e| {
            crate::diag::error(&format!("sbx: cannot start exec enforcement: {e}"));
            ExitCode::FAILURE
        })?;
        // The flag rides in the closure so the filter the cage installs matches the lens the
        // supervisor was started with — the two are decided once, together.
        let open_lens = wiring.open_lens;
        wraps.push((
            WrapLayer::ProcEnforce,
            Box::new(move |cmd| crate::sandbox::proc_enforce::wrap_command(cmd, open_lens)),
        ));
        proc_binds = wiring.binds;
        proc_enforce_guard = Some(guard);
    }

    let mut autoequip_env: Vec<(String, String)> = Vec::new();
    let global_mise = crate::sandbox::packages::mise_packages(&prep.cfg.packages);
    let auto_equip = auto_equip_tokens(&prep.cfg);
    // A global app's Lane-1 `mise use -g` must install an app `[packages] mise:` tool into the
    // app-global home pool (installed once, shared across projects, and where `sbx app show`/`list`/
    // `gc` read), not the ambient per-project primary. Pin the equip step there for a global app;
    // for `sbx run`/a per-project app the ambient primary is already the app-global home, so no pin.
    let app_global_mise_dir =
        matches!(runtime, binds::Runtime::GlobalApp(_)).then(binds::mise_app_global_data_dir);
    if !global_mise.is_empty() || !auto_equip.is_empty() {
        if matches!(prep.cfg.network, crate::config::NetworkPolicy::Isolated) {
            // `network = "none"`: a mise tool cannot be fetched, so skip the equip (it would only
            // fail). An already-equipped tool still resolves through its persisted shim, so this
            // is a warning, not a hard error.
            let declared = mise_token_display(global_mise.iter().chain(auto_equip.iter()));
            crate::diag::warn_config(&format!(
                "mise tools [{declared}] are declared but `network = \"none\"` — they \
                 cannot be fetched and will be absent unless already equipped"
            ));
        } else {
            if !auto_equip.is_empty() {
                if !prep.quiet_equip {
                    // The display copy only. The tokens handed to `wrap_mise_equip` below stay raw
                    // on purpose: they ride `\"$@\"` positionally and must reach mise exactly as the
                    // project wrote them.
                    let shown = mise_token_display(auto_equip.iter());
                    crate::diag::error(&format!(
                        "sbx: equipping non-nix tools in-cage via mise: {shown} (each backend's \
                         host must be in [network].allow under an allowlist)"
                    ));
                }
                wraps.push((
                    WrapLayer::MiseEquip,
                    Box::new(move |cmd| {
                        wrap_mise_equip(
                            &prep.userland.mise_bin,
                            &prep.userland.shell_bin,
                            // `install`, and deliberately no `--pin` here: this lane equips the
                            // tools the PROJECT's own `.mise.toml` asks for, and that file belongs
                            // to the user. `install` reads it and writes nothing; pinning would
                            // rewrite a version the project chose to leave floating, in a file sbx
                            // does not own. The pin belongs to lane 1 below, whose config file is
                            // the cage's own and is sbx's to write.
                            "install",
                            &auto_equip,
                            // Lane 2 (project `.mise.toml` tools) runs under the ambient primary —
                            // the per-project pool for a global app, which is where these belong.
                            None,
                            cmd,
                        )
                    }),
                ));
                // Tell the in-cage mise to trust the project config so the installed tools
                // resolve. This applies for the whole launch, so an agent's own `sbx mise` in a
                // project that declares non-`nix:` tools also trusts the project config — a
                // conscious, slightly wider reach than autoequip alone, and consistent with the
                // open self-equip posture. A distinct key, so its position in the env layering is
                // immaterial; a trusted config could still override it (self-harm only).
                autoequip_env.push((
                    "MISE_TRUSTED_CONFIG_PATHS".to_string(),
                    prep.cwd.to_string_lossy().into_owned(),
                ));
            }
            if !global_mise.is_empty() {
                if !prep.quiet_equip {
                    eprintln!("{}", equip_announcement(&global_mise));
                }
                wraps.push((
                    WrapLayer::MiseEquip,
                    Box::new(move |cmd| {
                        wrap_mise_equip(
                            &prep.userland.mise_bin,
                            &prep.userland.shell_bin,
                            // `--pin` writes the RESOLVED version into the cage's mise config
                            // instead of the floating request. Without it the config keeps saying
                            // `latest`, and the tool on the cage PATH is a shim — a symlink back to
                            // mise — which re-resolves that request on every exec: the day upstream
                            // publishes a version the pool does not hold, the shim refuses to run
                            // and the app stops launching, with nothing about the cage having
                            // changed. Pinning is what actually freezes a launch at the installed
                            // version. Its other half is `--bump` on the roll (see
                            // [`mise_upgrade_cmd`]): an exact pin is a range `mise upgrade` would
                            // consider already satisfied, so without it the roll would go quiet.
                            // Neither half works alone.
                            MISE_EQUIP_VERB,
                            &global_mise,
                            // Pin the install to the app-global home pool for a global app (see
                            // above); None for other runtimes, where the ambient primary is already
                            // app-global.
                            app_global_mise_dir.as_deref(),
                            cmd,
                        )
                    }),
                ));
            }
        }
    }

    // Inline `[flakes.<name>]` flakes are built in-cage with `nix build --out-link` — the local
    // content the user staged is contained by the cage, never built host-side (which
    // `is_valid_flake_ref` refuses for a remote ref; a remote `flake:` package is built host-side by
    // `packages::provision`). The build fetches its inputs, so (like the mise equip) it wraps the
    // command *before* the egress wrap and is skipped under `network = "none"`. The wrap
    // short-circuits when the out-link is already realised in the project's store, so a warm launch is
    // a no-op and an already-built flake runs offline.
    if !flake_pairs.is_empty() {
        if matches!(prep.cfg.network, crate::config::NetworkPolicy::Isolated) {
            crate::diag::warn_config(&format!(
                "inline flakes [{}] are declared but `network = \"none\"` — they \
                 cannot be built and will be absent unless already present",
                inline_flake_names.join(", ")
            ));
        } else {
            crate::diag::error(&format!(
                "sbx: building inline flakes in-cage via nix build: {} (each flake's fetch \
                 host must be in [network].allow under an allowlist)",
                inline_flake_names.join(", ")
            ));
            wraps.push((
                WrapLayer::FlakeEquip,
                Box::new(|cmd| {
                    wrap_flake_equip(
                        &prep.userland.nix_bin,
                        &prep.userland.shell_bin,
                        &binds::flake_roots_dir(),
                        &flake_pairs,
                        cmd,
                    )
                }),
            ));
        }
    }

    // A network allowlist runs the Model-B egress path: stand up the host filtering
    // proxy on a per-launch socket, wire the cage to reach it (the bound socket, the
    // CA it trusts, the proxy environment) and wrap the command so the cage starts the
    // forwarder before running it. The cage's netns is empty (`net_policy` maps the
    // allowlist to isolation), so this bound socket is the only egress. The guard keeps
    // the proxy's artifacts until the launch ends; the proxy thread outlives the cage
    // because the launcher supervises rather than exec-replacing (see `run`). Other
    // postures never touch any of this.
    let mut egress_guard = None;
    let mut egress_binds: Vec<binds::ExtraBind> = Vec::new();
    let mut egress_env: Vec<(String, String)> = Vec::new();

    // Forwarder loopback forward ports: a declared `forward` opens a host loopback port and
    // bridges it into the cage, so a host process (an OAuth `localhost:<port>` callback, or a
    // dev server) can reach a service the agent started inside the empty-netns cage. Applied
    // *before* the egress wrap below, so under an allowlist both forwarders are up before the
    // command runs (the egress wrap is the outermost, backgrounds its socat, execs the inner
    // which backgrounds the forward socats, execs the real command). Skipped under
    // `network = "shared"`: the cage shares the host netns, so a cage loopback service is already
    // on host loopback and the forwarder is a redundant no-op (noted, not wired). A port already
    // in use fails the launch closed inside `forward::start`.
    let mut forward_guard = None;
    let mut forward_binds: Vec<binds::ExtraBind> = Vec::new();
    if !prep.cfg.forward.is_empty() {
        if matches!(prep.cfg.network, crate::config::NetworkPolicy::Shared) {
            crate::diag::warn(&format!(
                "forward ports {} declared but `network = \"shared\"` already exposes the \
                 cage loopback to the host — no forwarder needed",
                prep.cfg
                    .forward
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        } else {
            let (guard, wiring) =
                forward::start(&prep.layout, prep.cfg.forward.clone()).map_err(|e| {
                    crate::diag::error(&format!("sbx: {e}"));
                    ExitCode::FAILURE
                })?;
            let forwards = wiring.forwards;
            wraps.push((
                WrapLayer::Forward,
                Box::new(move |cmd| {
                    forward::wrap_command(
                        &prep.userland.socat_bin,
                        &prep.userland.shell_bin,
                        &forwards,
                        cmd,
                    )
                }),
            ));
            forward_binds = wiring.binds;
            forward_guard = Some(guard);
        }
    }
    // Broker plugins: the same shape as the ssh-agent broker below, for a protocol sbx does not
    // implement itself. Each `[broker.<name>]` pairs an installed plugin with the host resource
    // the global config bound it to; sbx serves the socket, holds the host connection, and the
    // plugin only ever answers verdicts about frames.
    //
    // Ahead of the egress proxy, and that order is load-bearing rather than incidental: a resolver
    // plugin may be given a broker (`[sandbox] brokers`), and the proxy resolves this launch's
    // secrets as it starts. A broker stood up afterwards would not exist at the moment the resolver
    // that needs it runs.
    //
    // Every failure here degrades to *no broker* rather than to an unfenced one, and says so: a
    // cage without a broker is a cage that cannot reach that resource, which is the fail-closed
    // direction. Only standing up a broker the config did ask for and could otherwise have is
    // fatal, like the egress proxy's and the agent's.
    let mut broker_guards: Vec<broker::Broker> = Vec::new();
    let mut brokers: Vec<broker::Reachable> = Vec::new();
    // The reader's end of the shared record, held for the launch's lifetime. `None` until a config
    // that declares a broker stands it up, and `None` too when that could not be done.
    let mut broker_feed: Option<broker::BrokerFeed> = None;
    if !prep.cfg.brokers.is_empty() {
        // The perimeter every plugin's trust rests on, established before the first plugin runs —
        // a resolver is run only because it sits under `<data>/plugins`, a tree a project cannot
        // write, and that rests on `<data>` being owner-only. The egress proxy opens with the same
        // call for the same reason; standing brokers up ahead of it moved the first plugin-backed
        // resolution in this process to here.
        if let Err(e) = crate::store::ensure(&prep.layout) {
            crate::diag::error(&format!("sbx: cannot prepare the data directory: {e}"));
            return Err(ExitCode::FAILURE);
        }
        let mut plugin_warnings = Vec::new();
        let registry =
            crate::plugins::PluginRegistry::load(&prep.layout.plugins_dir(), &mut plugin_warnings);
        for w in &plugin_warnings {
            crate::diag::warn_config(w);
        }
        // The session's decision record, stood up once and shared by every broker below — one ring
        // and one socket, whatever the config declares. The guard lives as long as the brokers do,
        // so a reader's `--follow` ends with the launch rather than with whichever broker was torn
        // down first.
        let (ring, feed) = broker::stand_up_feed(&prep.layout);
        broker_feed = Some(feed);
        for binding in &prep.cfg.brokers {
            let name = &binding.name;
            let Some(plugin) = registry.broker(name) else {
                // Told apart, because the remedy differs: an ambiguous name is fixed by removing a
                // plugin, a missing one by installing it.
                match registry.name_conflict(name) {
                    Some(claimants) => crate::diag::warn_config(&format!(
                        "`[broker.{name}]` names a broker claimed by more than one installed \
                         plugin ({}) — they are all disabled, so the cage gets no broker",
                        crate::plugins::quoted_list(claimants)
                    )),
                    None => crate::diag::warn_config(&format!(
                        "`[broker.{name}]` names no installed broker plugin — install one with \
                         `sbx plugins install`, or drop the table. The cage gets no broker."
                    )),
                }
                continue;
            };
            // Two checks, and the second is the one that keeps a single answer to "where may this
            // cage go".
            match &binding.socket {
                // A Unix socket has to be there *now*: a broker in front of nothing would accept
                // the cage's connections and fail every frame, which reads as the resource
                // misbehaving rather than as a configuration that does not hold.
                crate::config::BrokerTarget::Unix(path) if !path.exists() => {
                    crate::diag::warn_config(&format!(
                        "`[broker.{name}] socket` names {}, which does not exist — the cage gets \
                         no broker",
                        path.display()
                    ));
                    continue;
                }
                crate::config::BrokerTarget::Unix(_) => {}
                // A protocol whose clients compute the socket's path has no path to compute when
                // the resource is an endpoint: the two declarations are answering different
                // questions, and standing the broker up anyway would put it where nothing looks.
                crate::config::BrokerTarget::Tcp { .. } if plugin.broker.at_host_path => {
                    crate::diag::warn_config(&format!(
                        "`[broker.{name}] socket` names a tcp:// endpoint, but the plugin's clients \
                         find the socket at a fixed path (`at_host_path`) — a tcp:// target has \
                         none, so the cage gets no broker"
                    ));
                    continue;
                }
                // A TCP target is a way out of the cage, so it is admitted only where the network
                // allowlist already admits it — decided by the very function the proxy and
                // `sbx test net` decide through, so the three cannot drift apart. Without this
                // there would be two different answers to what the cage may reach, and the one a
                // reader checks would not be the one that decides.
                crate::config::BrokerTarget::Tcp { host, port } => {
                    let admitted = match &prep.cfg.network {
                        crate::config::NetworkPolicy::Allowlist(policy) => matches!(
                            policy.l4_decision(host, *port),
                            crate::allowlist::L4Decision::Splice(_)
                        ),
                        _ => false,
                    };
                    if !admitted {
                        crate::diag::warn_config(&format!(
                            "`[broker.{name}] socket` names tcp://{host}:{port}, which the \
                             network allowlist does not admit — add `tcp://{host}:{port}` to \
                             `[network] allow`, or the cage gets no broker"
                        ));
                        continue;
                    }
                }
            }
            // The credential is resolved host-side, here, before anything is stood up: a broker
            // that was promised one and cannot get it must not run, or it would put an
            // unauthenticated connection in front of the cage and look like the resource refusing
            // it. The plugin never receives this value — only a marker standing in for it.
            let secret = if binding.secret.is_empty() {
                None
            } else if !plugin.broker.uses_secret {
                // The grant is the manifest's to make: a credential is not handed to a plugin that
                // was not written to place one, whatever the config says.
                crate::diag::warn_config(&format!(
                    "`[broker.{name}] secret` names a credential, but the plugin's manifest does \
                     not declare `uses_secret` — the broker runs without it"
                ));
                None
            } else {
                // Resolved with **no** broker wired, which is what keeps the graph acyclic: a
                // broker's own credential cannot be read through a broker, least of all through the
                // one being stood up. A resolver that needs one fails here on its own terms, so say
                // which declaration made it impossible rather than leaving the tool's error to
                // stand for it.
                for source in &binding.secret {
                    if let crate::config::SecretSource::Plugin { plugin, .. } = source
                        && !plugin.sandbox.brokers.is_empty()
                    {
                        crate::diag::warn_config(&format!(
                            "`[broker.{name}] secret` resolves through the `{}` plugin, which needs \
                             the {} broker — a broker's own credential is resolved before any \
                             broker is standing, so that grant is not answered here",
                            plugin.scheme,
                            crate::plugins::quoted_list(&plugin.sandbox.brokers)
                        ));
                    }
                }
                match egress::resolve_chain(&binding.secret, name, &prep.cwd, &prep.bwrap, &[]) {
                    Ok(value) => {
                        // Said once, at the launch that decided it, rather than per connection: a
                        // credential under the redaction floor is placed on the wire but not
                        // watched on the way back, and that is a fact about this config.
                        if value.len() < prep.cfg.redact_min_len {
                            crate::diag::warn_config(&format!(
                                "the credential for the `{name}` broker is {} bytes, under the \
                                 {}-byte `[redact] min_len` floor — it is placed on the wire, but \
                                 a reply carrying it back is not blocked (a scan that short \
                                 refuses innocent traffic more often than it catches a leak)",
                                value.len(),
                                prep.cfg.redact_min_len
                            ));
                        }
                        Some((value, prep.cfg.redact_min_len))
                    }
                    Err(e) => {
                        crate::diag::error(&format!(
                            "sbx: cannot resolve the secret for the `{name}` broker: {e}"
                        ));
                        return Err(ExitCode::FAILURE);
                    }
                }
            };
            // What this host answers the plugin, from `[plugin.<name>]`. Applied to a copy rather
            // than to the registry's instance, which is shared and read-only here: the config
            // validated the table against this very manifest, and the copy is what runs.
            let mut plugin = plugin.clone();
            plugin.host = binding.host.clone();
            match broker::start(
                &prep.layout,
                binding,
                &plugin,
                &prep.bwrap,
                secret,
                ring.clone(),
            ) {
                Ok((guard, reachable)) => {
                    crate::diag::note(&format!(
                        "broker: `{name}` stands in front of {}{}",
                        binding.socket.describe(),
                        match binding.allow.len() {
                            0 => String::new(),
                            n => format!(" ({n} allow entr{})", if n == 1 { "y" } else { "ies" }),
                        }
                    ));
                    // Two brokers claiming one variable would silently last-wins, leaving a client
                    // pointed at whichever was stood up second and a broker serving nobody. Named
                    // instead, like the secrets layer names a duplicated destination header.
                    for (key, _) in &reachable.env {
                        if brokers
                            .iter()
                            .any(|b: &broker::Reachable| b.env.iter().any(|(k, _)| k == key))
                        {
                            crate::diag::warn_config(&format!(
                                "broker `{name}` and an earlier broker both set ${key} in the cage \
                                 — the later one wins, so one of them is unreachable"
                            ));
                        }
                    }
                    brokers.push(reachable);
                    broker_guards.push(guard);
                }
                Err(e) => {
                    crate::diag::error(&format!("sbx: cannot start the `{name}` broker: {e}"));
                    return Err(ExitCode::FAILURE);
                }
            }
        }
        // Nothing stood up, so nothing has decisions to record. Dropping the feed unlinks its socket
        // and takes this launch back to what it would have been without the block: a launch with no
        // broker, which needs no live parent and can exec-replace. Held any longer, a bound socket
        // with no owner would force the supervised path on a config whose brokers all fell away.
        if brokers.is_empty() {
            broker_feed = None;
        }
    }

    // Where each `tcp://` destination lives inside the cage. Computed before the launch because two
    // things need it: the preamble's listeners, and the `/etc/hosts` entries that make the
    // declaration's own host name resolve to them.
    let mut tcp_plan = egress::TcpPlan::default();
    if let crate::config::NetworkPolicy::Allowlist(policy) = &prep.cfg.network {
        tcp_plan = egress::tcp_destinations(policy);
        for skipped in &tcp_plan.skipped {
            crate::diag::warn(&format!(
                "no in-cage listener for {skipped} — the rule still governs the proxy, but a client \
                 that cannot speak an HTTP CONNECT proxy will have to tunnel itself"
            ));
        }
        // An inspected rule naming a loopback host is permitted by the policy and taken by nothing:
        // the cage exempts those hosts from its proxy, and only a `tcp://` rule earns a listener. A
        // warning, not a note — the rule reads as allowed on every surface that reports a verdict,
        // so an author who is not told concludes the host's loopback is out of reach.
        for rule in egress::unreachable_loopback_rules(policy) {
            crate::diag::warn_config(&format!(
                "`{rule}` allows a host the cage reaches through no client: {exempt} are exempt \
                 from the cage's proxy (`no_proxy`, so the agent's own in-cage services stay \
                 intra-cage), and only a `tcp://` rule gets an in-cage listener — declare \
                 `tcp://<host>:<port>` to reach the service on YOUR loopback",
                exempt = egress::PROXY_EXEMPT_HOSTS.join(", ")
            ));
        }
        // A privileged port has no listener either, but ssh is wired for it — so this is a note,
        // not a warning: what an author must know is that *ssh* works as written while another
        // client on such a port still has to ask the proxy itself.
        for dest in &tcp_plan.connect_only {
            let ports: Vec<String> = dest.ports.iter().map(u16::to_string).collect();
            crate::diag::note(&format!(
                "tcp://{}:{} is a privileged port, which the cage cannot listen on — ssh reaches it \
                 through the cage's CONNECT proxy (wired in /etc/ssh/ssh_config); another client \
                 has to ask for that CONNECT itself",
                dest.host,
                ports.join(",")
            ));
        }
    }
    // The session's signer record, stood up when a signer is named anywhere this launch will run
    // one: a `[[secret]]` the agent's own proxy resolves, or a `[task.<name>.inject]` a declared
    // operation's proxy will. One ring and one socket for all of them, like the notifier — a proxy
    // that built its own would record where no reader can look.
    //
    // The task half reads the same `prep.cfg.tasks` the engine below is built from, in this one
    // function, off an immutable `prep`. So the set scanned here and the set that can actually
    // invoke a signer are the same set, whatever layer contributed a task — there is no ordering
    // to get wrong, and a late-arriving declaration cannot slip past the feed.
    let signs = prep.cfg.secrets.iter().any(|s| s.signer.is_some())
        || prep
            .cfg
            .tasks
            .iter()
            .any(|t| t.injections.iter().any(|i| i.signer.is_some()));
    let (signer_ring, signer_feed) = match signs {
        true => {
            let (ring, feed) = crate::sandbox::signer_control::stand_up_feed(&prep.layout);
            (Some(ring), feed)
        }
        false => (None, None),
    };

    if let crate::config::NetworkPolicy::Allowlist(policy) = &prep.cfg.network {
        // An `sbx app <name>` launch tags its egress stats with the app, so `sbx net stats --app`
        // can scope to it; a plain `run`/`shell` records under the project with no app tag.
        let app = match &runtime {
            binds::Runtime::GlobalApp(name) | binds::Runtime::ProjectApp(name) => Some(*name),
            binds::Runtime::ProjectDefault => None,
        };
        let (guard, wiring) = egress::start(
            &prep.layout,
            (**policy).clone(),
            &prep.cfg.secrets,
            &prep.cwd,
            &prep.bwrap,
            app,
            prep.cfg.egress_stats,
            // The base roots to pair the per-session MITM CA with, for a policy that lets a client
            // reach a server this proxy does not stand in for. Which policies those are, and what the
            // pairing costs when it buys nothing, is decided where the file is written.
            Some(prep.userland.ca_bundle_src.as_path()),
            // The session's own proxy: a launch stands up exactly one, so the pid already names it.
            "",
            Some(&notify_wiring),
            prep.cfg.redact_min_len,
            &brokers,
            // The session's own proxy opens the ring every reader finds; a task's shares it.
            None,
            // This is the agent's plane: what it is refused is what `--net-learn` may learn.
            crate::sandbox::control::Plane::Agent,
            signer_ring.clone(),
            prep.unresolved_secret,
        )
        .map_err(|e| {
            // Through `diag::error` despite carrying no backtick of its own: the error it
            // interpolates is the credential chain's, and a resolver plugin's failure names the
            // plugin in backticks. The guard on raw diagnostics reads format strings, so this is
            // the one site where that reading is known to come up short.
            crate::diag::error(&format!(
                "sbx: cannot start the egress filtering proxy: {e}"
            ));
            ExitCode::FAILURE
        })?;
        // The wrap owns its copy: `tcp_plan` is read again further down, when the same destinations
        // become the cage's `/etc/hosts` entries.
        let destinations = tcp_plan.destinations.clone();
        wraps.push((
            WrapLayer::Egress,
            Box::new(move |cmd| {
                egress::wrap_command(
                    &prep.userland.socat_bin,
                    &prep.userland.shell_bin,
                    cmd,
                    &destinations,
                )
            }),
        ));
        // For a GUI cage, import sbx's MITM CA into the cage's NSS db before the app runs, so a
        // Chromium/Electron app trusts the egress proxy (it ignores the CA-file env vars). It sits
        // outside the egress wrap — it runs, then execs the egress-wrapped command. Only present
        // when `ca_trust` was provisioned (gui = "wayland" under this allowlist).
        if let Some(ct) = &ca_trust {
            wraps.push((
                WrapLayer::CaTrust,
                Box::new(|cmd| {
                    crate::sandbox::catrust::wrap(
                        &ct.certutil,
                        &prep.userland.shell_bin,
                        egress::CAGE_CA,
                        cmd,
                    )
                }),
            ));
        }
        egress_binds = wiring.binds;
        egress_env = wiring.env;
        egress_guard = Some(guard);
    }

    // The ssh-agent broker: a filtering agent socket in front of the host's own, so the cage can
    // sign with the keys `[ssh_agent] allow` names and do nothing else — not list the rest, not add
    // a key, not wipe the set. Independent of the network posture: it rides a bound Unix socket, so
    // the empty netns is untouched. Where a signature is then *spent* is the egress allowlist's
    // business: a `git push` also needs a `tcp://<host>:22` rule, and — since a capability-less cage
    // cannot bind a privileged port — an explicit `CONNECT` to reach it.
    //
    // A grant that resolves to nothing is a warning and no agent, never a silent partial: the two
    // ways that happens — no agent running, no held key matching — are both a mistake worth naming
    // at the moment it is made. Only a failure to *stand up* the broker is fatal, like the egress
    // proxy's: the user asked for it and it cannot be provided.
    let mut sshagent_guard = None;
    let mut sshagent_binds: Vec<binds::ExtraBind> = Vec::new();
    let mut sshagent_env: Vec<(String, String)> = Vec::new();
    if !prep.cfg.ssh_agent.is_empty() {
        let grant = prep.cfg.ssh_agent.join(", ");
        match sshagent::host_socket() {
            None => crate::diag::warn_config(&format!(
                "`[ssh_agent] allow` names {grant} but no agent is running on the host \
                 (`$SSH_AUTH_SOCK` is unset) — the cage gets no agent"
            )),
            Some(host_sock) => {
                let filter = sshagent::Filter::new(&prep.cfg.ssh_agent);
                match sshagent::admission(&host_sock, &filter) {
                    Err(e) => crate::diag::warn(&format!(
                        "cannot reach the host ssh-agent at {} ({e}) — the cage gets no agent",
                        host_sock.display()
                    )),
                    Ok(a) if a.admitted.is_empty() => crate::diag::warn_config(&format!(
                        "no key the host agent holds matches `[ssh_agent] allow` ({grant}) — the \
                         cage gets no agent. `ssh-add -l` prints the fingerprint and comment an \
                         entry may name."
                    )),
                    // `confirm` asks for a prompt on every signature, which takes an askpass helper
                    // on the host. Resolved once, before anything is stood up, so the decision to
                    // refuse and the wiring that follows it cannot be answered by two searches.
                    Ok(a) => match sshagent::confirmation(
                        prep.cfg.ssh_agent_confirm,
                        sshagent::Confirmer::askpass(),
                    ) {
                        // The absence of a helper refuses the grant: running the broker anyway
                        // would hand the cage a key *and* silently drop the one condition the
                        // grant was made under.
                        sshagent::Confirmation::NoHelper => crate::diag::warn(&format!(
                            "`[ssh_agent] confirm` asks for a prompt on every signature, but no \
                             askpass helper was found on the host (`$SSH_ASKPASS`, `ssh-askpass` on \
                             PATH, or OpenSSH's own) — the cage gets no agent rather than a grant \
                             whose confirmation would never appear. Install one (e.g. the \
                             `ssh-askpass` package), or drop `confirm`. Grant: {}",
                            a.admitted.join(", ")
                        )),
                        confirmation => {
                            let (guard, wiring) = sshagent::start(
                                &prep.layout,
                                &prep.cfg.ssh_agent,
                                &host_sock,
                                confirmation.helper(),
                                Arc::clone(&notify_wiring.notifier),
                            )
                            .map_err(|e| {
                                crate::diag::error(&format!(
                                    "sbx: cannot start the ssh-agent broker: {e}"
                                ));
                                ExitCode::FAILURE
                            })?;
                            crate::diag::note(&format!(
                                "ssh-agent: the cage may sign with {}{}{}",
                                a.admitted.join(", "),
                                match a.withheld {
                                    0 => String::new(),
                                    1 => " (1 other key withheld)".to_string(),
                                    n => format!(" ({n} other keys withheld)"),
                                },
                                if prep.cfg.ssh_agent_confirm {
                                    " — each signature asks you first"
                                } else {
                                    ""
                                }
                            ));
                            sshagent_binds = wiring.binds;
                            sshagent_env = wiring.env;
                            sshagent_guard = Some(guard);
                        }
                    },
                }
            }
        }
    }

    // GUI hole: under `gui = "wayland"`, bind the host's Wayland compositor socket read-only so a
    // graphical app can map a window. The cage runs same-uid, so a read-only bind suffices to
    // connect(). Only the socket *file* is bound, never `$XDG_RUNTIME_DIR` itself — that directory
    // also holds the dbus session bus, pulse, and the gpg/ssh agents, which binding the directory
    // would hand to the cage. Best-effort: with no compositor socket found, warn and run without
    // it (the app fails on its own) — not binding is the fail-closed direction for a display hole.
    // The cage env (`WAYLAND_DISPLAY`/`XDG_RUNTIME_DIR`) is fixed here by sbx; an untrusted
    // `[env]` could only mispoint a client at a nonexistent socket (self-DoS), never redirect the
    // bind, whose source path is set by sbx — so these keys need no denylist entry.
    let mut gui_binds: Vec<binds::ExtraBind> = Vec::new();
    let mut gui_env: Vec<(String, String)> = Vec::new();

    // Resolved once: the libraries are bound in the GPU block below and the device nodes are
    // granted with the render nodes further down, and neither should walk the host's directories
    // a second time.
    let nvidia = prep
        .cfg
        .gpu
        .then(crate::sandbox::gpu::nvidia_bridge)
        .flatten();

    // Fonts: bind the generated fontconfig configuration read-only and name it to the cage's
    // fontconfig. The font *files* were provisioned and seeded above; this points fontconfig at
    // them so text renders rather than boxes — and a browser engine renders nothing at all
    // without it (it dies mid-page), which is why this is wired for every posture that draws,
    // `offscreen` included, not only for a windowed one. Independent of the compositor socket
    // below and best-effort (a staging failure warns, the app runs without fonts).
    // `FONTCONFIG_FILE` is fixed by sbx; a project `[env]` could override it (highest
    // precedence), but that only re-points the agent's own in-cage fontconfig at its own config —
    // self-sabotage, not an escape (it already controls what runs in the cage) — so the key needs
    // no denylist entry, exactly like `WAYLAND_DISPLAY`.
    if let Some(layer) = &font_layer {
        let conf = crate::sandbox::fonts::fonts_conf_for(layer);
        match crate::sandbox::fonts::stage(prep.layout.data_dir(), &conf) {
            Ok(path) => {
                gui_binds.push(binds::ExtraBind {
                    src: path,
                    dest: PathBuf::from(crate::sandbox::fonts::FONTS_CONF_INCAGE),
                    writable: false,
                });
                gui_env.push((
                    "FONTCONFIG_FILE".to_string(),
                    crate::sandbox::fonts::FONTS_CONF_INCAGE.to_string(),
                ));
            }
            Err(e) => crate::diag::warn(&format!(
                "this `gui` posture renders but the font configuration could not be \
                 staged ({e}) — text may not render"
            )),
        }
    }

    if matches!(prep.cfg.gui, crate::config::GuiPolicy::Wayland) {
        let display = std::env::var("WAYLAND_DISPLAY").ok();
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR").ok();
        match resolve_wayland_hole(display.as_deref(), runtime_dir.as_deref()) {
            Ok((socket, env)) if socket.exists() => {
                gui_binds.push(binds::ExtraBind {
                    src: socket.clone(),
                    dest: socket,
                    writable: false,
                });
                gui_env.extend(env);
            }
            Ok((socket, _)) => crate::diag::warn(&format!(
                "`gui = \"wayland\"` but the compositor socket `{}` does not exist — \
                 running without a display",
                socket.display()
            )),
            Err(reason) => crate::diag::warn(&format!(
                "`gui = \"wayland\"` but {reason} — running without a display"
            )),
        }

        // GUI data: point the cage's glib/GTK at the provisioned, seeded schemas + themes via one
        // `XDG_DATA_DIRS` entry, so a GTK dialog finds `org.gtk.Settings.FileChooser` (else it
        // aborts) and the in-cage portal's file dialog finds the named `Adwaita-dark` theme. An
        // app's own launcher prepends its GTK data dirs, so sbx's entry (carrying the themes) stays
        // reachable at the tail. `XDG_DATA_DIRS` is a data path, not a code-load path (unlike the
        // mesa driver vars), so it needs no untrusted-`[env]` denylist entry — a project that
        // re-points it only sabotages its own cage's schema/theme lookup.
        if let Some(layer) = &guidata_layer {
            gui_env.extend(layer.env.iter().cloned());
        }

        // In-cage portal: point the app's D-Bus/portal client at the private bus and the GTK
        // backend (the bus itself is started by the outermost command wrap, below). The `XDG_*`
        // keys are data paths, not code-load paths, so — like `WAYLAND_DISPLAY` — a project `[env]`
        // that re-points them only self-DoSes its own cage's portal lookup and needs no denylist.
        if let Some(p) = &portal {
            gui_env.extend(crate::sandbox::portal::env(&p.gtk_root));
            // Bind the portal's host runtime directory (read-write) at the cage path the bus config,
            // env, and command wrap all reference, so the in-cage dbus-daemon writes its config and
            // creates its socket there — and the socket is reachable from the host for the relay.
            if let Some(hd) = &portal_host {
                gui_binds.push(binds::ExtraBind {
                    src: hd.dir().to_path_buf(),
                    dest: PathBuf::from(crate::sandbox::portal::CAGE_DIR),
                    writable: true,
                });
            }
        }
    }

    // GPU: when `gpu = true`, point the cage's libgbm/libEGL at mesa's own drivers (provisioned and
    // seeded above) and read-only-bind the minimal `/sys` DRM subtree the driver reads to enumerate
    // the device. The render node itself is granted through the device-bind mechanism below. Mostly
    // best-effort: a failed mesa provision or an absent render node degrades to software rendering.
    // The `/sys` paths are checked for existence at enumeration (`drm_sys_paths`) and bound firmly —
    // the same firm-`--ro-bind`-after-`.exists()` shape the Wayland socket uses — so a device
    // vanishing between enumeration and exec (a GPU hot-unplug) would fail the launch, an accepted
    // rarity, not "never fails".
    // The driver-path env vars mesa `dlopen`s from are sbx-controlled *and* reserved against an
    // untrusted `[env]` (they load code, so `is_reserved_env_key` denylists them alongside `LD_*`);
    // a *trusted* config may still override them — self-harm on its own cage, not an escape.
    if prep.cfg.gpu {
        if let Some(layer) = &gpu_layer {
            gui_env.extend(layer.env.iter().cloned());
        }
        for path in crate::sandbox::gpu::drm_sys_paths() {
            gui_binds.push(binds::ExtraBind {
                src: path.clone(),
                dest: path,
                writable: false,
            });
        }
        // Under WSL the render node above is real and its driver is mesa's `d3d12`, which reaches
        // the GPU through libraries Windows provides in this directory rather than nixpkgs. Both
        // halves are needed and neither works alone: bound and not on the loader path, the cage
        // still answers `cannot open shared object file`; on the path and not bound, there is
        // nothing to open. `LD_LIBRARY_PATH` is in the same reserved class as the driver-path
        // variables above, for the same reason — it loads code, so it is sbx's to set and an
        // untrusted `[env]` may not.
        if let Some(bridge) = crate::sandbox::gpu::wsl_bridge() {
            gui_env.push(("LD_LIBRARY_PATH".to_string(), bridge.display().to_string()));
            gui_binds.push(binds::ExtraBind {
                src: bridge.clone(),
                dest: bridge,
                writable: false,
            });
        }

        // The NVIDIA bridge: this host's proprietary userspace, which is version-locked to its
        // kernel module and so cannot be provisioned hermetically the way mesa is. Same shape as
        // the WSL bridge above — host libraries plus the loader path — with the one difference
        // that is the whole trick: each real file is bound *under the name the loader asks for*,
        // because a soname bound onto itself resolves to its versioned target and disappears.
        //
        // Scope is compute (CUDA) and offscreen rendering. On a hybrid host a windowed client
        // still renders on the integrated GPU, inside the cage exactly as outside it: the
        // compositor holds that device, and the one workaround is GLX under X11, which sbx never
        // offers. Nothing here approaches that refusal.
        if let Some(nv) = &nvidia {
            for (src, dest) in &nv.libs {
                gui_binds.push(binds::ExtraBind {
                    src: src.clone(),
                    dest: dest.clone(),
                    writable: false,
                });
            }
            gui_env.push((
                "LD_LIBRARY_PATH".to_string(),
                PathBuf::from(crate::sandbox::gpu::CAGE_NVIDIA)
                    .join("lib")
                    .display()
                    .to_string(),
            ));

            // Both vendors have to stay reachable: mesa's, in the seeded store, drives the
            // Wayland and GBM platforms, and dropping it would take those platforms away with it.
            // `__EGL_VENDOR_LIBRARY_DIRS` names a *list*, so the answer is the union — NVIDIA's
            // directory ahead of mesa's, the order this was measured working in. Composed from
            // the layer's own value rather than enumerated on the host: what the layer holds is
            // the path as seen *from the cage*, and the store lives elsewhere on the host.
            match &nv.vendor_json {
                Some((src, dest)) => {
                    gui_binds.push(binds::ExtraBind {
                        src: src.clone(),
                        dest: dest.clone(),
                        writable: false,
                    });
                    let nvidia_dir = PathBuf::from(crate::sandbox::gpu::CAGE_NVIDIA)
                        .join("egl_vendor.d")
                        .display()
                        .to_string();
                    let mesa_dirs = gpu_layer.as_ref().and_then(|layer| {
                        layer
                            .env
                            .iter()
                            .find(|(k, _)| k == "__EGL_VENDOR_LIBRARY_DIRS")
                            .map(|(_, v)| v.clone())
                    });
                    gui_env.push((
                        "__EGL_VENDOR_LIBRARY_DIRS".to_string(),
                        match mesa_dirs {
                            Some(mesa) => format!("{nvidia_dir}:{mesa}"),
                            None => nvidia_dir,
                        },
                    ));
                }
                None => crate::diag::warn(
                    "`gpu = true`: the NVIDIA driver libraries are here but their GLVND \
                     declaration (`10_nvidia.json`) is not — the cage renders on mesa",
                ),
            }

            // Without these NVIDIA's vendor does not expose `EGL_EXT_platform_wayland`, so a
            // Wayland client falls back to mesa without ever saying why.
            if nv.platforms.is_empty() {
                crate::diag::warn(
                    "`gpu = true`: no NVIDIA EGL external-platform declaration was found under \
                     `/usr/share/egl/egl_external_platform.d` — the cage's NVIDIA vendor will not \
                     offer the Wayland platform",
                );
            }
            for (src, dest) in &nv.platforms {
                gui_binds.push(binds::ExtraBind {
                    src: src.clone(),
                    dest: dest.clone(),
                    writable: false,
                });
            }
            if !nv.platforms.is_empty() {
                gui_env.push((
                    "__EGL_EXTERNAL_PLATFORM_CONFIG_DIRS".to_string(),
                    PathBuf::from(crate::sandbox::gpu::CAGE_NVIDIA)
                        .join("egl_external_platform.d")
                        .display()
                        .to_string(),
                ));
            }

            // Vulkan chooses its driver through a manifest too, so the card needs its own beside
            // mesa's. `VK_DRIVER_FILES` names a list of manifests *and* directories, so this is
            // again a union rather than a replacement: NVIDIA's one file ahead of the directory
            // holding mesa's, composed from what the layer already set for the same reason the
            // EGL vendor directories are.
            if let Some((src, dest)) = &nv.icd {
                gui_binds.push(binds::ExtraBind {
                    src: src.clone(),
                    dest: dest.clone(),
                    writable: false,
                });
                let mesa_icd = gpu_layer.as_ref().and_then(|layer| {
                    layer
                        .env
                        .iter()
                        .find(|(k, _)| k == "VK_DRIVER_FILES")
                        .map(|(_, v)| v.clone())
                });
                let nvidia_icd = dest.display().to_string();
                gui_env.push((
                    "VK_DRIVER_FILES".to_string(),
                    match mesa_icd {
                        Some(mesa) => format!("{nvidia_icd}:{mesa}"),
                        None => nvidia_icd,
                    },
                ));
            }

            // A userspace that does not match the loaded kernel module fails the same silent way
            // a missing soname does: the vendor never registers and EGL reports an empty
            // extension string. Name it instead of leaving the reader to derive it from a blank.
            if let (Some(user), Some(kernel)) = (
                nv.version.as_deref(),
                std::fs::read_to_string("/proc/driver/nvidia/version")
                    .ok()
                    .and_then(|t| crate::sandbox::gpu::kernel_module_version(&t)),
            ) && user != kernel
            {
                crate::diag::warn(&format!(
                    "`gpu = true`: the NVIDIA userspace on this host is {user} but the loaded \
                     kernel module is {kernel} — the cage will find no NVIDIA device"
                ));
            }
        }
    }

    // Audio: when `audio = true`, bind the host PulseAudio socket read-only at the fixed cage path
    // and point the app's loader at the provisioned libpulse (both provisioned/seeded above). Both
    // pieces must be present — no host socket, or a failed provision, means no audio (best-effort, a
    // warning, never a failed launch). The socket bind is read-only: same-uid, so a `connect()` still
    // works (exactly like the Wayland socket). `PULSE_SERVER` is a data path (an untrusted `[env]`
    // only self-DoSes its own cage's audio), so it needs no denylist entry; `LD_LIBRARY_PATH` is
    // already reserved against an untrusted `[env]` (a code-load path, alongside `LD_*`).
    if prep.cfg.audio {
        let host_socket =
            crate::sandbox::audio::host_socket(std::env::var("XDG_RUNTIME_DIR").ok().as_deref());
        match host_socket {
            Some(sock) if sock.exists() => {
                // The socket bind + `PULSE_SERVER` are firm (independent of the userspace provision);
                // the client libraries, the ALSA→pulse shim's `asound.conf`, and its env are added
                // only when the userspace was provisioned (best-effort — a failed provision already
                // warned, and the app then simply finds no audio).
                gui_binds.push(binds::ExtraBind {
                    src: sock,
                    dest: PathBuf::from(crate::sandbox::audio::CAGE_SOCK),
                    writable: false,
                });
                if let Some(alsa) = audio_layer.as_ref().and_then(|l| l.alsa.as_ref()) {
                    gui_binds.push(binds::ExtraBind {
                        src: alsa.asound_conf.clone(),
                        dest: PathBuf::from(crate::sandbox::audio::ASOUND_CONF_INCAGE),
                        writable: false,
                    });
                }
                // The `find_library` shim directory (for a Python PortAudio tool), bound read-only and
                // placed on `PYTHONPATH` by `audio::env`. Present only when PortAudio provisioned.
                if let Some(pyshim) = audio_layer.as_ref().and_then(|l| l.pyshim.as_ref()) {
                    gui_binds.push(binds::ExtraBind {
                        src: pyshim.clone(),
                        dest: PathBuf::from(crate::sandbox::audio::PYSHIM_INCAGE),
                        writable: false,
                    });
                }
                // Pass the base C++/glibc runtime dirs (the same set as NIX_LD_LIBRARY_PATH) so a
                // voice speech-to-text engine's `dlopen`ed native library (ctranslate2/onnxruntime)
                // finds `libstdc++.so.6` — `dlopen` consults LD_LIBRARY_PATH, not NIX_LD_LIBRARY_PATH.
                gui_env.extend(crate::sandbox::audio::env(
                    audio_layer.as_ref(),
                    &prep.userland.foreign_lib_paths,
                ));
            }
            _ => crate::diag::warn(
                "`audio = true` but no PulseAudio socket was found at \
                 `$XDG_RUNTIME_DIR/pulse/native` — the app runs without audio",
            ),
        }
    }

    // In-cage portal: wrap the command so the private session bus is stood up before the app runs.
    // The **outermost** layer, so its preamble (`dbus-daemon --fork`, which blocks until the socket
    // is ready) runs first, then execs the rest of the wrapped command. Only present under
    // `gui = "wayland"` + `dbus = true` with a successful provision.
    if let Some(p) = &portal {
        wraps.push((
            WrapLayer::Portal,
            Box::new(|cmd| {
                crate::sandbox::portal::wrap_command(
                    &prep.userland.shell_bin,
                    &p.dbus_daemon,
                    &p.xdp_root,
                    &p.gtk_root,
                    &p.update_desktop_db,
                    portal_scheme.as_deref(),
                    cmd,
                )
            }),
        ));
    }

    // The launcher's extra binds, emitted after the structural mounts: the egress machinery
    // (socket + CA) and the GUI socket. Their destinations are sbx's or the host's, never a
    // project path, so they neither shadow nor are shadowed by a structural mount.
    let mut extra_binds = egress_binds;
    extra_binds.extend(sshagent_binds);
    extra_binds.extend(brokers.iter().map(broker::Reachable::bind));
    extra_binds.extend(forward_binds);
    extra_binds.extend(gui_binds);
    extra_binds.extend(inline_flake_binds);
    extra_binds.extend(proc_binds);
    // The store paths every wrap's preamble runs from, pinned read-only over the project's
    // writable store. Emitted here, with the launcher's other extra binds, because that is what
    // puts them *after* the structural `/nix` — a pin emitted before it would be covered by it,
    // exactly as for the `[fs]` masks below. See [`plumbing_pins`] for what they protect.
    //
    // The two GUI holes add programs of their own to that set — the portal's `dbus-daemon` and the
    // desktop-database updater it runs first, and the CA import's `certutil` — and each exists only
    // under `gui = "wayland"`, so they are collected from the layers here rather than carried on
    // `Userland` with the ones every posture has.
    let mut gui_programs: Vec<&Path> = Vec::new();
    if let Some(p) = &portal {
        gui_programs.push(&p.dbus_daemon);
        gui_programs.push(&p.update_desktop_db);
    }
    if let Some(ct) = &ca_trust {
        gui_programs.push(&ct.certutil);
    }
    extra_binds.extend(plumbing_pins(&prep.userland, &gui_programs, &prep.layout));

    // Close the project paths `[fs]` names. Emitted among the launcher's extra binds — that is,
    // *after* the structural mounts — because a mask emitted before the project's own mount would
    // be covered by it, which is exactly why a `binds` entry aimed inside the project masks nothing
    // today. Unlike the rest of this block their destinations *are* project paths, which is the
    // point: they are the only binds here meant to land on one.
    let fs_masks = crate::sandbox::fsmask::expand(&prep.cwd, &prep.cfg.fs);
    for warning in &fs_masks.warnings {
        crate::diag::warn_config(warning);
    }
    if let Some(reason) = &fs_masks.refused {
        crate::diag::error(&format!("sbx: {reason}"));
        return Err(ExitCode::FAILURE);
    }
    let fs_decoys = if fs_masks.is_empty() {
        None
    } else {
        let dir = crate::sandbox::fsmask::mask_dir(prep.layout.data_dir(), std::process::id());
        match crate::sandbox::fsmask::stage_decoys(&dir) {
            Ok(decoys) => {
                extra_binds.extend(crate::sandbox::fsmask::agent_binds(&fs_masks, &decoys));
                Some(decoys)
            }
            Err(e) => {
                // Fail closed: without the decoys nothing masks those paths, and a session that
                // ran anyway would leave open exactly the files the config asked to close.
                crate::diag::error(&format!(
                    "sbx: cannot stage the `[fs]` masks ({e}) — the paths they name would stay open"
                ));
                return Err(ExitCode::FAILURE);
            }
        }
    };

    // Pin sbx's own control plane in place whenever a read-write bind contains it: each root's host
    // path is frozen as a mountpoint chain (read-write intermediates, a read-only leaf), so in-cage
    // code cannot rename a writable parent to move a control-plane root aside and recreate a forged
    // one at the same path — which sbx would otherwise read or `execve` on its next run. The bind
    // stays read-write; only these specific host paths are protected. Emitted after the structural
    // mounts — the containing read-write bind has to be in place before the pin lands on it. Binds
    // are appended after this block (the task control plane below); the rule they have to respect
    // is stated on `control_plane_pins`, and it is about their destination, not their position.
    //
    // Interdependency: the protection assumes in-cage code cannot `umount` a pin. That holds because
    // bwrap drops all capabilities (no `CAP_SYS_ADMIN` in the cage's user namespace) and the seccomp
    // filter denies `umount2`/`unshare`/`mount` — a change loosening either would silently break it.
    // The project counts as one of those read-write binds, and used not to. It is bound read-write
    // at its own path by `binds::build_spec` structurally rather than as a config bind, so it never
    // reached this computation — and a session launched from a directory that *contains* a
    // control-plane root (`cd ~ && sbx run` is the whole of it, since all three roots live under
    // `$HOME`) handed the cage sbx's data dir, trust store and global config read-write, unpinned.
    // `build_spec`'s own doc states the contract that closes it — "a caller launching an untrusted
    // actor must first confine the project root" — and no caller implements it, so pinning is what
    // this one can do without changing which directories a person may launch from.
    //
    // Canonicalized to match: `sbx_control_plane_roots` resolves symlinks, and a bind is compared
    // against them canonicalized, so a symlinked `$HOME` component would otherwise walk past the
    // containment test.
    let sources = pin_sources(&prep.cfg.binds, &prep.cwd);
    match establish_control_plane_pins(&crate::config::control_plane_pins(&sources)) {
        Ok(pins) => extra_binds.extend(pins),
        Err(e) => {
            // Fail closed: if a pin cannot be established the containing read-write bind would be
            // unprotected, so abort the launch rather than run with a gap. An extreme case — a
            // mkdir failing in sbx's own data/config tree.
            crate::diag::error(&format!(
                "sbx: cannot protect sbx's control plane ({e}) — a read-write bind contains it"
            ));
            return Err(ExitCode::FAILURE);
        }
    }

    // Declared operations: when this session has any, the task control socket crosses into the cage
    // and a generated client is bound read-only beside it, so an in-cage caller can list and invoke
    // a task. Both paths are derived here (before the spec) and both are created below (before the
    // launch), so bwrap finds them present. This is the ONE control plane that crosses — its surface
    // is three commands, and the invocation log lives on a second, host-only socket that the
    // recorded party cannot read.
    let mut task_env: Vec<(String, String)> = Vec::new();
    let task_socket = (!prep.cfg.tasks.is_empty()).then(|| {
        let path =
            crate::sandbox::task_control::task_dir(prep.layout.data_dir(), std::process::id())
                .join("control.sock");
        extra_binds.push(binds::ExtraBind {
            src: path.clone(),
            // Writable so a connect is never refused on a permission subtlety; the *file* is bound,
            // never its directory, so in-cage code cannot unlink it and serve its own listener at
            // the same path.
            dest: PathBuf::from(crate::sandbox::task_control::CAGE_TASK_UDS),
            writable: true,
        });
        task_env.push((
            crate::sandbox::task_control::TASK_SOCKET_ENV.to_string(),
            crate::sandbox::task_control::CAGE_TASK_UDS.to_string(),
        ));
        // The client is a generated script, never sbx itself: the cage must not hold a binary able
        // to act on sbx's own state, and "it cannot because nothing it needs is mounted" is a
        // property no test could hold onto. See `task_shim`.
        extra_binds.push(binds::ExtraBind {
            src: crate::sandbox::task_control::shim_path(
                prep.layout.data_dir(),
                std::process::id(),
            ),
            dest: PathBuf::from(crate::sandbox::task_control::TASK_SHIM_INCAGE),
            writable: false,
        });
        task_env.push((
            "SBX_TASK_CLI".to_string(),
            crate::sandbox::task_control::TASK_SHIM_INCAGE.to_string(),
        ));
        // Where an `output`-declaring task's artifacts become readable. Bound **read-only**, and only
        // when some task declares `output` — an agent that can write here could plant the input a
        // credential-bearing command later reads back, which is the one thing the direction of this
        // mount has to prevent.
        //
        // The *parent* is bound, because a cage's mounts are fixed when it is built and no
        // invocation can add one afterwards: each task's directory then appears inside it as it is
        // created, since a bind mount shows the tree rather than a copy of it.
        if prep.cfg.tasks.iter().any(|t| t.output) {
            let root = crate::sandbox::task::output_root_for(&prep.layout, &prep.cwd)
                .and_then(|root| std::fs::create_dir_all(&root).map(|()| root));
            if let Err(e) = &root {
                crate::diag::warn(&format!(
                    "cannot create this project's task output directory ({e}) — an operation \
                     declaring `output` will refuse rather than run"
                ));
            } else if let Ok(root) = root {
                extra_binds.push(binds::ExtraBind {
                    src: root,
                    dest: PathBuf::from(crate::sandbox::task::TASK_OUT_AGENT),
                    writable: false,
                });
            }
        }
        path
    });

    // Two holes contribute directories to the cage's loader path — the audio client libraries and,
    // under WSL, the GPU bridge — and each pushed its own entry. A shared key is won by one source,
    // so a cage with both grants kept whichever came last and silently lost the other's
    // directories, which for `claude-desktop` is both of them.
    merge_loader_path(&mut gui_env);

    // Environment. Each source is tagged with where it belongs, and `EnvLayer` — not this list's
    // order — decides which one wins a shared key. The structural HOME/PATH/... are added by the
    // assembler, which upserts all of these over them. An untrusted config has already lost its
    // reserved keys upstream — including the proxy and CA keys — so it can neither redirect the
    // egress nor swap the CA; a trusted config overriding them only harms its own cage.
    let extra_env = extra_cage_env(vec![
        (EnvLayer::Passthrough, passthrough_env()),
        (EnvLayer::Cacert, binds::cacert_env()),
        (EnvLayer::Gui, gui_env),
        (EnvLayer::AutoEquip, autoequip_env),
        (EnvLayer::Mise, mise_env(prep)?),
        (EnvLayer::Egress, egress_env),
        (EnvLayer::SshAgent, sshagent_env),
        (
            EnvLayer::Broker,
            brokers.iter().flat_map(|b| b.env.clone()).collect(),
        ),
        (EnvLayer::Task, task_env),
        (EnvLayer::Config, prep.cfg.env.clone()),
    ]);

    // The cage's zone, checked against the database that will actually be bound — assembly is pure,
    // so this is the last place a name can be held against something real. Read off the assembled
    // environment, not off the field alone: see `declared_zone`.
    let timezone = cage_timezone(
        declared_zone(&extra_env, prep.cfg.timezone.as_deref()),
        &prep.userland.zoneinfo_src,
    );
    // Resolved from the post-`merge_app` config, so the app's names and its bundles' are already
    // unioned onto the baseline's and each is held against the package set this cage actually
    // equips — a name whose package another project declares resolves to nothing here.
    let fresh_release_tokens = crate::sandbox::packages::fresh_release_tokens(
        &prep.cfg.packages,
        &prep.cfg.accepts_fresh_releases,
    );
    let overlay = binds::Overlay {
        env: &extra_env,
        binds: &prep.cfg.binds,
        bin_paths: &bin_paths,
        timezone: &timezone,
        fresh_release_tokens: &fresh_release_tokens,
        ignored_mise_paths: &prep.cfg.mise_ignored,
    };
    // Generate the in-cage contract from the resolved (post-`merge_app`) config, so a process
    // inside the cage can see which hosts it can reach, why a direct connection or `ping` fails,
    // and which declared operations it may invoke. The tasks are the gated ones — the same list the
    // task plane serves — so the file never advertises an operation the socket would refuse to run.
    // Informational only; bound read-only by `build_spec`.
    let egress_contract =
        crate::sandbox::contract::cage_contract(&prep.cfg.network, &prep.cfg.tasks);
    // The device grant: the resolved `[devices]` plus, under `gpu = true`, this host's DRM **render**
    // nodes (`/dev/dri/renderD*`), so the cage can reach the GPU. Both become `--dev-bind-try`
    // mounts. Never the whole `/dev/dri` directory: that carries the `card*` primary nodes in with
    // them, and a primary node with no DRM master makes its first opener the master — modesetting
    // and a GEM flink namespace, neither of which offscreen rendering needs. See
    // [`crate::sandbox::gpu::render_nodes`]. A `card*` node reaches a cage only when a trusted config names
    // it under `[devices]`.
    // Deduped: a trusted `[devices] allow = [...]` alongside `gpu = true` must not emit a bind twice.
    let mut devices = prep.cfg.devices.clone();
    if prep.cfg.gpu {
        let nvidia_nodes = nvidia.iter().flat_map(|nv| nv.devices.iter().cloned());
        for node in crate::sandbox::gpu::render_nodes()
            .into_iter()
            .chain(nvidia_nodes)
        {
            if !devices.contains(&node) {
                devices.push(node);
            }
        }
    }
    // A command with nothing declared ahead of it is passed through untouched, so the ordinary
    // launch keeps the process it would have had — the same pid, the same signals, the same exit
    // status — and only a launch that actually declared something gains a shell above it.
    let nothing_to_compose = prep.cfg.provisions.is_empty() && prep.cfg.service.is_empty();
    let startup_cmd = if cmd.is_empty() || nothing_to_compose {
        cmd
    } else {
        compose_startup_cmd(&prep.cfg.provisions, &prep.cfg.service, &extra_env, cmd)
    };

    // Every wrap this launch contributed, nested by `WrapLayer` rather than by the order the blocks
    // above happened to run in — and nested **around the composed startup**, which is the whole
    // point of doing it here rather than before the composition.
    //
    // An install step is not a peer of the command; it is the thing that finishes making the command
    // runnable, so it needs everything the command needs. Wrapped the other way round the step ran
    // *outside* every layer: before the mise equip lanes, so a step asking `mise where` about a
    // package found nothing and failed the launch before the equip that would have installed it; and
    // before the egress forwarder, so a step that downloads got its `https_proxy` pointed at a port
    // with nothing listening yet. `provision`'s own documentation already says a step runs "in the
    // same cage, under the same posture and allowlist" as the command, and this is what makes that
    // true.
    //
    // `WrapLayer`'s ordering is unchanged: this moves the composed startup to where the app's bare
    // command already was, so every pairwise constraint the enum documents holds exactly as before.
    let startup_cmd = wrap_cage_command(startup_cmd, wraps);
    let spec = binds::build_spec(
        prep.layout.data_dir(),
        &prep.cwd,
        runtime,
        &prep.userland,
        &nix_mount,
        &overlay,
        &extra_binds,
        net_policy(&prep.cfg.network),
        &egress_contract,
        // The `tcp://` destinations get `/etc/hosts` entries pointing at the addresses the preamble
        // above listens on, so a declaration reads the same inside the cage as outside it — and the
        // ones whose port is privileged, which can have no such listener, get a generated ssh
        // `ProxyCommand` toward the cage's CONNECT proxy instead.
        &tcp_plan,
        // The trusted seccomp relaxation from the resolved (post-`merge_app`) config, so an app's
        // `[seccomp] allow` union is in effect for `sbx app`, exactly like its limits.
        prep.cfg.seccomp.clone(),
        // The trusted device grant from the resolved (post-`merge_app`) config, plus the GPU
        // render node under `gpu = true`, so an app's `[devices]` union is in effect for `sbx app`,
        // exactly like its seccomp relaxation.
        &devices,
        // The URI handlers from the resolved (post-`merge_app`) config, so an app's `[open]` folds
        // over the baseline's for `sbx app` the way its packages and environment do.
        &prep.cfg.open,
        // The command, with the launch's whole start-up composed ahead of it: the app's bundle
        // install steps, then its services. Composed here — the one function that stands up a cage —
        // so every path reaching a cage gets the same start-up in the same order, and so both read
        // the config *after* the app overlay and any one-shot override have had their say.
        startup_cmd,
    )
    .map_err(|e| {
        crate::diag::error(&format!("sbx: cannot prepare the sandbox: {e}"));
        ExitCode::FAILURE
    })?;
    // A graphical cage under an isolated network namespace (any filtering posture — the namespace
    // is empty but for loopback) reads as *offline* to an in-cage browser: Chromium decides
    // `navigator.onLine` from the presence of a non-loopback interface, not from real reachability,
    // so a graphical agent panel freezes on "No internet" even though proxy egress works. Route the
    // launch through the netns holder (see `crate::sandbox::netns`), which pre-creates the namespace with a
    // black-hole `dummy0` interface so the browser reports online — no egress is opened (the dummy
    // has no route; all traffic still goes through the proxy on loopback). Gated to the rendering
    // postures, the only ones running a browser engine (a headless `offscreen` engine reads
    // `navigator.onLine` the same way a windowed one does), and only when sbx's own path is
    // resolvable, so the launch never falls back to a cage without `--unshare-net` (which would
    // share the host network).
    let spec = if prep.cfg.gui.renders() && spec.net == NetPolicy::Isolated {
        match std::env::current_exe() {
            Ok(exe) => spec.with_netns_dummy(crate::sandbox::spec::NetnsDummy {
                uid: unsafe { libc::getuid() },
                gid: unsafe { libc::getgid() },
                holder_exe: exe,
            }),
            Err(e) => {
                crate::diag::error(&format!(
                    "sbx: netns holder unavailable ({e}); the cage runs without an online signal"
                ));
                spec
            }
        }
    } else {
        spec
    };
    // Stand the task plane up now: the spec is final (so a task cage can be derived from it) and the
    // launch has not happened yet (so bwrap finds the bound socket present). A failure here aborts
    // the launch rather than running a cage whose declared operations silently do not exist — the
    // agent would keep trying and never learn why.
    let task_plane = match &task_socket {
        None => None,
        Some(_) => {
            let engine = crate::sandbox::task::TaskEngine::from_cage(
                &prep.bwrap,
                &spec,
                &prep.layout,
                &prep.cwd,
                // A relative `sops://` file resolves against the config's directory, exactly as it
                // does for a wire injection.
                &prep.cwd,
                prep.cfg.tasks.clone(),
                prep.cfg.limits.clone(),
                spec.cage_slug(),
                Some(prep.userland.ca_bundle_src.as_path()),
                crate::sandbox::task::CageForwarder {
                    socat: prep.userland.socat_bin.clone(),
                    shell: prep.userland.shell_bin.clone(),
                },
                prep.cfg.redact_min_len,
            )
            .with_notifier(Arc::clone(&notify_wiring))
            .with_brokers(brokers.clone())
            .with_signer_log(signer_ring.clone())
            // A task's proxy appends to the session's egress ring rather than opening one of its
            // own, which nothing would read: see `Egress::event_log`.
            .with_egress_log(
                egress_guard
                    .as_ref()
                    .map(crate::sandbox::egress::Egress::event_log),
            );
            // Carry the session's `[fs]` masks into every task cage, so a denied path is closed
            // there too unless the task's own `unmask` names it. The decoys are the ones this
            // launch already staged: a task cage is derived from the agent's, and pointing it at a
            // second set would be two answers to one question.
            let engine = match (&fs_decoys, fs_masks.is_empty()) {
                (Some(decoys), false) => engine.with_fs_masks(fs_masks.clone(), decoys.clone()),
                _ => engine,
            };
            // The task tool pool, when any task declares a `mise:` tool. Filled host-side now — a
            // cold fill is minutes long, so it belongs at launch where the user is watching, not
            // inside the first invocation. Best-effort, unlike the `nix:` package path: a pool tool
            // that will not install is one task's problem, and aborting the whole session over it
            // would take the agent down with it. The task then fails naming the missing tool, and
            // `sbx task list` flags it before it is ever invoked.
            let engine = match crate::sandbox::binds::project_runtime_id(&prep.cwd) {
                Ok(id) => engine.with_pool(
                    crate::sandbox::taskpool::pool_dir(prep.layout.data_dir(), &id),
                    prep.userland.mise_bin.clone(),
                ),
                Err(e) => {
                    if prep.cfg.tasks.iter().any(|t| !t.packages.is_empty()) {
                        crate::diag::warn(&format!(
                            "the task tool pool has no home for this project ({e}) — tasks \
                             declaring `packages` will not find their tools"
                        ));
                    }
                    engine
                }
            };
            if let Err(e) = engine.ensure_pool() {
                crate::diag::warn(&format!("the task tool pool could not be prepared: {e}"));
            }
            let (bash, socat, head) = task_client_programs(&prep.userland);
            let client = crate::sandbox::task_control::ClientPrograms {
                bash: &bash,
                socat: &socat,
                head: &head,
            };
            match crate::sandbox::task_control::start(
                prep.layout.data_dir(),
                std::process::id(),
                engine,
                &client,
            ) {
                Ok(plane) => Some(plane),
                Err(e) => {
                    crate::diag::error(&format!("sbx: cannot start the task control plane: {e}"));
                    return Err(ExitCode::FAILURE);
                }
            }
        }
    };

    let guard = if egress_guard.is_some()
        || sshagent_guard.is_some()
        || !broker_guards.is_empty()
        || broker_feed.is_some()
        || signer_feed.is_some()
        || forward_guard.is_some()
        || portal_host.is_some()
        || proc_enforce_guard.is_some()
        || task_plane.is_some()
    {
        Some(LaunchGuard {
            notify_sink: Some(Arc::clone(&notify_wiring)),
            egress: egress_guard,
            ssh_agent: sshagent_guard,
            brokers: broker_guards,
            broker_feed,
            signer_feed,
            forward: forward_guard,
            notify: notify_relay,
            theme: theme_relay,
            portal: portal_host,
            proc_enforce: proc_enforce_guard,
            task: task_plane,
        })
    } else {
        None
    };
    Ok((spec, guard))
}

/// Translate the resolved configuration's network posture into the cage's net
/// policy. The two enums are kept separate on purpose: the config vocabulary
/// (`none`/`shared`/`deny`/`allow`/`ask`) is the user's, while the cage's posture type is the
/// sandbox's. A filtering posture maps to an **isolated** (empty) namespace by
/// design — that is the Model-B foundation: with no route of its own, the cage's only
/// egress is the bound socket `build` wires to the host filtering proxy. So the netns
/// is identical to `none`; the filtering lives in the proxy on top, not in the netns.
fn net_policy(network: &crate::config::NetworkPolicy) -> NetPolicy {
    match network {
        crate::config::NetworkPolicy::Shared => NetPolicy::Shared,
        crate::config::NetworkPolicy::Isolated => NetPolicy::Isolated,
        crate::config::NetworkPolicy::Allowlist(_) => NetPolicy::Isolated,
    }
}

/// Resolve the host's Wayland compositor socket and the cage environment that points a
/// graphical app at it, from the host `WAYLAND_DISPLAY`/`XDG_RUNTIME_DIR`. Pure: the impure
/// existence check and the bind are the caller's, so the path/env computation is unit-tested.
///
/// Per the Wayland convention an absolute `WAYLAND_DISPLAY` is the socket path verbatim;
/// otherwise it is a name resolved under `XDG_RUNTIME_DIR`. The returned path is always the
/// socket **file** — never the runtime directory, which also holds the dbus session bus, pulse,
/// and the gpg/ssh agents; the caller binds exactly this file read-only, so none of those is
/// exposed (the whole point of gating the GUI hole trusted-only). The returned env carries
/// `WAYLAND_DISPLAY` and, when known, `XDG_RUNTIME_DIR`, so the in-cage client finds the same
/// socket at the same path (the cage runs same-uid, so a read-only bind is enough to connect).
fn resolve_wayland_hole(
    display: Option<&str>,
    runtime_dir: Option<&str>,
) -> Result<(PathBuf, Vec<(String, String)>), String> {
    let display = display.ok_or("WAYLAND_DISPLAY is unset")?;
    if display.is_empty() {
        return Err("WAYLAND_DISPLAY is empty".to_string());
    }
    let mut env = vec![("WAYLAND_DISPLAY".to_string(), display.to_string())];
    if Path::new(display).is_absolute() {
        // An absolute display is the socket path itself; XDG_RUNTIME_DIR is not needed to
        // locate it, but pass it through when set (some clients still read it).
        if let Some(dir) = runtime_dir {
            env.push(("XDG_RUNTIME_DIR".to_string(), dir.to_string()));
        }
        Ok((PathBuf::from(display), env))
    } else {
        let dir =
            runtime_dir.ok_or("XDG_RUNTIME_DIR is unset (needed to locate the Wayland socket)")?;
        env.push(("XDG_RUNTIME_DIR".to_string(), dir.to_string()));
        Ok((Path::new(dir).join(display), env))
    }
}

/// The store paths this launch's own in-cage plumbing runs from, re-bound **read-only** from the
/// shared store over the project's writable one.
///
/// Every wrap but [`WrapLayer::ProcEnforce`] prepends a preamble that runs an sbx-chosen program by
/// absolute store path — the shell each of them wraps its script in, `socat` for the egress and
/// loopback forwarders, `mise` for an equip lane, `nix` for an inline flake build, and under the
/// GUI holes the portal's bus daemon and the CA import's `certutil` (`gui_programs`) — and every one
/// of those preambles runs *before* the enforcement shim installs its filter, which is what makes
/// the shim's innermost position affordable. That reasoning only holds while those programs are
/// sbx's own bytes. They are not: `/nix` is the project's own store, bound read-write so an agent
/// can self-equip into it, and the seed places every path owner-writable — so in-cage code can
/// replace `bin/bash` or `bin/socat` in it and have its replacement execute as the cage's first
/// process, outside the `[proc]` exec policy and the `[fs] scan` content lens that the same launch
/// reports as active. Nothing re-copies or re-checks a store path that is already there, so one
/// write persists across every later launch of that project.
///
/// Pinning them closes that. The source is sbx's **shared** store — the copy no cage has ever been
/// able to write — rather than the project's, because shadowing the project's copy with itself
/// would pin whatever an earlier session left there. The base loader is pinned alongside the
/// programs: every one of them is interpreted by it, so a writable loader would substitute the same
/// code one level down. The rest of the seeded closure stays writable, which is the point of a
/// per-project store; what this fixes is the set sbx itself execs before the cage is filtered.
///
/// Each pin covers the whole store path, not the binary file inside it: binding only the file would
/// leave its directory writable, and a directory that can be renamed aside can be rebuilt around a
/// forged binary at the same path. Pure, so the set is unit-tested without a store.
fn plumbing_pins(
    userland: &Userland,
    gui_programs: &[&Path],
    layout: &Layout,
) -> Vec<binds::ExtraBind> {
    let mut roots: Vec<PathBuf> = Vec::new();
    for logical in [
        userland.shell_bin.as_path(),
        userland.socat_bin.as_path(),
        userland.mise_bin.as_path(),
        userland.nix_bin.as_path(),
        userland.base_loader.as_path(),
    ]
    .into_iter()
    .chain(gui_programs.iter().copied())
    {
        if let Some(root) = store_root_of(logical)
            && !roots.contains(&root)
        {
            roots.push(root);
        }
    }
    roots
        .into_iter()
        .map(|root| binds::ExtraBind {
            src: crate::store::physical_path(layout, &root),
            dest: root,
            writable: false,
        })
        .collect()
}

/// The store path an in-sandbox logical path belongs to: `/nix/store/<name>` for any
/// `/nix/store/<name>/…`. `None` for anything else, so a path that does not resolve through the
/// store is never mistaken for one and mounted over.
fn store_root_of(logical: &Path) -> Option<PathBuf> {
    let store = Path::new("/nix/store");
    match logical.strip_prefix(store).ok()?.components().next()? {
        std::path::Component::Normal(name) => Some(store.join(name)),
        _ => None,
    }
}

/// Resolve a trusted project's mise `[env]` into environment entries. Empty when
/// the project declares no mise file, or it is withheld — an untrusted or changed
/// mise file only warns (its `[env]` is held back, like its security fields).
///
/// mise is provisioned via nix and driven from sbx's store against the **engine**
/// channel — never this launch's possibly-pinned base reference (mise runs in its own
/// store view, free of the one-channel rule; see [`Prepared::engine_ref`]). The files
/// it reads are materialized from the bytes trust validated, outside any writable
/// mount, so it sees exactly the authorized, hashed inputs. A trusted `[env]` that
/// cannot be resolved is fatal, like a declared tool that fails to realise.
fn mise_env(prep: &Prepared) -> Result<Vec<(String, String)>, ExitCode> {
    let Some(mise_cfg) = &prep.cfg.mise else {
        return Ok(Vec::new());
    };
    if mise_cfg.state != crate::trust::TrustState::Trusted {
        crate::diag::warn_config(&format!(
            "mise file `{}` withheld ({}): its `[env]` is not applied",
            mise_cfg.name,
            crate::config::untrusted_reason(mise_cfg.state)
        ));
        return Ok(Vec::new());
    }

    // The same engine reference the in-cage mise uses, already resolved in `prepare`.
    let mise_root =
        crate::sandbox::mise::provision_engine(&prep.nix, &prep.layout, &prep.engine_ref).map_err(
            |e| {
                crate::diag::error(&format!("sbx: cannot provision the mise engine: {e}"));
                ExitCode::FAILURE
            },
        )?;
    let mise_bin = crate::sandbox::mise::bin(&mise_root);
    // Stage the authorized files in a per-project directory that sits outside every
    // writable mount (a sibling of the writable home, like the synthetic identity).
    let id = binds::project_runtime_id(&prep.cwd).map_err(|e| {
        crate::diag::error(&format!("sbx: cannot identify the project: {e}"));
        ExitCode::FAILURE
    })?;
    let stage = prep
        .layout
        .data_dir()
        .join("projects")
        .join(id)
        .join("mise-config");
    crate::sandbox::mise::resolve_env(
        &prep.bwrap,
        &prep.layout,
        &mise_bin,
        &mise_cfg.files,
        &stage,
    )
    .map_err(|e| {
        crate::diag::error(&format!("sbx: mise [env] resolution failed: {e}"));
        ExitCode::FAILURE
    })
}

/// Host variables worth carrying through the cleared environment for a usable
/// session. Secrets are never passed this way. `LANG`/`LC_ALL` carry the host's locale so the
/// cage renders text in the user's language; the base userland builds a matching locale archive
/// (see `fhs::host_locales`), and both upsert over the structural `LANG=C.UTF-8` floor.
fn passthrough_env() -> Vec<(String, String)> {
    keep_passthrough(
        ["TERM", "LANG", "LC_ALL"]
            .iter()
            .filter_map(|k| std::env::var(k).ok().map(|v| ((*k).to_string(), v))),
    )
}

/// Drop a `LANG`/`LC_ALL` whose value is the non-UTF-8 `C`/`POSIX` builtin, so a host that
/// selects it (a developer forcing deterministic tooling on the host) cannot override the cage's
/// structural `LANG=C.UTF-8` floor and byte-escape accented text — almost never the intent inside
/// an agent cage, and a config `[env]` remains the explicit escape hatch. Every other value — a
/// real locale, or `C.UTF-8` itself — is kept and upserts over the floor; `TERM` and any
/// non-locale key pass unconditionally. Pure, so the rule is unit-tested without the environment.
fn keep_passthrough(vars: impl IntoIterator<Item = (String, String)>) -> Vec<(String, String)> {
    vars.into_iter()
        .filter(|(k, v)| {
            !matches!(k.as_str(), "LANG" | "LC_ALL")
                || (!v.eq_ignore_ascii_case("C") && !v.eq_ignore_ascii_case("POSIX"))
        })
        .collect()
}

/// Where a command wrap sits in the nesting a launch builds around the cage's command, innermost
/// first.
///
/// Every wrap prepends a preamble that starts something inside the cage and then `exec`s what it
/// wraps, so the **last** one applied is the outermost and its preamble runs **first**. The
/// constraints the wraps have on each other are pairwise (a forwarder up before the fetch that needs
/// it, a CA imported after the proxy whose CA it is), and each variant below carries the one it is
/// subject to. Ordering by this enum is what keeps those constraints from depending on where in
/// [`build()`] each block happens to sit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum WrapLayer {
    /// The exec-enforcement shim. Innermost, so it filters the agent command and its children and
    /// not the provisioning and egress plumbing wrapped around it. That exemption is only sound
    /// while the plumbing is sbx's own bytes, which is what [`plumbing_pins`] holds: every program
    /// an outer preamble execs is re-bound read-only from the shared store, out of the cage's
    /// reach.
    ProcEnforce,
    /// A mise equip lane. Both lanes fetch, so they sit inside the egress wrap: under an allowlist
    /// the forwarder is up before either install runs.
    MiseEquip,
    /// The inline `[flakes.<name>]` build. Fetches its inputs, so it sits inside the egress wrap for
    /// the same reason as [`WrapLayer::MiseEquip`].
    FlakeEquip,
    /// The loopback forwarders. Inside the egress wrap, so under an allowlist both forwarders are up
    /// before the command runs.
    Forward,
    /// The egress forwarder.
    Egress,
    /// The MITM CA's import into the cage's NSS db, for a Chromium/Electron app that ignores the
    /// CA-file environment. Outside the egress wrap, since it is that proxy's per-session CA it
    /// imports.
    CaTrust,
    /// The in-cage portal's private session bus. Outermost, so `dbus-daemon --fork` — which blocks
    /// until its socket is ready — has finished before anything else in the cage starts.
    Portal,
}

/// One contributed wrap: it takes the command built so far and returns it wrapped.
type CommandWrap<'a> = Box<dyn FnOnce(Vec<OsString>) -> Vec<OsString> + 'a>;

/// Nest the wraps a launch contributed around `cmd`, innermost [`WrapLayer`] first.
///
/// The caller registers them wherever its blocks happen to run; the nesting is this function's, not
/// the caller's. The sort is stable, so two wraps of the same layer — the two mise equip lanes —
/// nest in the order they were registered.
fn wrap_cage_command(
    cmd: Vec<OsString>,
    mut wraps: Vec<(WrapLayer, CommandWrap<'_>)>,
) -> Vec<OsString> {
    wraps.sort_by_key(|(layer, _)| *layer);
    wraps.into_iter().fold(cmd, |cmd, (_, wrap)| wrap(cmd))
}

/// Where a source of cage environment sits in the precedence order, lowest first. The assembler
/// upserts these over the structural defaults and takes the last occurrence of a key, so a later
/// variant wins.
///
/// The order lives in this declaration rather than in the order a caller happens to list its
/// layers. Every layer is a `Vec<(String, String)>`, so two of them swapped at a call site would
/// compile in silence and change which CA the cage trusts; sorting by this enum makes the
/// precedence a property of one documented place instead of a property of an argument list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum EnvLayer {
    /// The host variables carried through unchanged. Lowest on purpose: passthrough is a separate
    /// channel, not filtered by the untrusted-config denylist, so a host CA variable must not be
    /// able to clobber sbx's hermetic bundle.
    Passthrough,
    /// sbx's hermetic CA bundle.
    Cacert,
    /// The Wayland GUI hole. Its keys (`WAYLAND_DISPLAY`/`XDG_RUNTIME_DIR`) collide with nothing
    /// else, so the position is immaterial; it sits here to keep one documented order.
    Gui,
    /// The non-`nix:` auto-equip variable.
    AutoEquip,
    /// A trusted project's mise `[env]`.
    Mise,
    /// The egress machinery: the proxy variables and the per-session MITM CA, which must beat
    /// [`EnvLayer::Cacert`] so a cage under an allowlist trusts the proxy standing in for its
    /// servers.
    Egress,
    /// The ssh-agent broker's socket.
    SshAgent,
    /// A broker plugin's socket, under whichever names its manifest declared. Beside the
    /// first-party broker above, and after it: the two never name the same variable, since a
    /// manifest cannot claim a reserved key and `SSH_AUTH_SOCK` is sbx's to set.
    Broker,
    /// The task plane's discovery handles.
    Task,
    /// The `.sbx.toml` `[env]`: the sbx-native config has the final say. An untrusted one has
    /// already lost its reserved keys upstream, so overriding here is self-harm only.
    Config,
}

/// Layer the cage's extra environment by [`EnvLayer`] precedence, lowest first.
///
/// Fold repeated `LD_LIBRARY_PATH` entries into one, joined in the order they were added.
///
/// Only that key. It names a *list* of directories, so two producers of it both have something to
/// say and the answer is their union; every other shared key names one value, where the last
/// writer winning is the intended rule and merging would produce something neither meant.
fn merge_loader_path(env: &mut Vec<(String, String)>) {
    const KEY: &str = "LD_LIBRARY_PATH";
    let joined = env
        .iter()
        .filter(|(k, _)| k == KEY)
        .map(|(_, v)| v.as_str())
        .collect::<Vec<_>>()
        .join(":");
    if joined.is_empty() {
        return;
    }
    let mut first = true;
    env.retain(|(k, _)| k != KEY || std::mem::replace(&mut first, false));
    if let Some(slot) = env.iter_mut().find(|(k, _)| k == KEY) {
        slot.1 = joined;
    }
}

/// The caller may list its layers in any order — they are sorted here. Two entries carrying the
/// same layer keep the order they were given, since the sort is stable.
fn extra_cage_env(mut layers: Vec<(EnvLayer, Vec<(String, String)>)>) -> Vec<(String, String)> {
    layers.sort_by_key(|(layer, _)| *layer);
    layers.into_iter().flat_map(|(_, env)| env).collect()
}

#[cfg(test)]
mod tests;
