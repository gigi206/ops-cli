//! The configuration views as a terminal is to show them.
//!
//! Most of what `config show` prints is text a config file chose, and a project's file is shown
//! before anyone has approved it: that is what the command is for. A control character in such a
//! value would drive the terminal, a line break would forge a line of the document, and a
//! character that reorders a line would make it read as something else. So both text renderers
//! start from a copy of their view with every string written the way [`crate::diag::visible`]
//! writes it: nothing is cut, and what was escaped stays visible to the reader. The JSON documents
//! serialize the views themselves and keep their bytes.
//!
//! Two kinds of value are left as they are, because the renderers already fold them where they
//! print them, through [`crate::sandbox::sanitize`]: an environment variable's key and value, and
//! the three `[fs]` lists.
//!
//! Every struct is taken apart field by field with no `..`, so a field added to a view does not
//! compile until this module says how it is shown.

use crate::config::view::{
    AppDetailView, AppEnvVar, AppLimitsView, AppNetworkView, AppProvisionView, AppView, BindView,
    BrokerView, ChannelView, ConfigView, EnvVar, GuiView, LimitView, LimitsView, MiseView,
    NetworkView, NixToolView, NonNixToolView, NotifyView, OpenView, PackageView, PluginView,
    ProcView, SecretView, ServiceView, TaskView, ToolsView,
};

/// The baseline view [`super::render::render_config`] prints.
pub(super) fn config_view(view: &ConfigView) -> ConfigView {
    let ConfigView {
        cwd,
        env,
        binds,
        open,
        service,
        packages,
        mise,
        tools,
        nixpkgs,
        engine,
        network,
        network_origin,
        egress_stats,
        redact_min_len,
        redact_min_len_origin,
        observe_record,
        observe_record_origin,
        proc,
        proc_origin,
        notify,
        notify_origin,
        gui,
        gui_origin,
        distro,
        distro_origin,
        distro_auth,
        timezone,
        timezone_origin,
        gpu,
        gpu_origin,
        allow_insecure_http,
        allow_insecure_http_origin,
        apps_share_install_pools,
        apps_share_install_pools_origin,
        audio,
        audio_origin,
        dbus,
        dbus_origin,
        forward,
        forward_origin,
        seccomp,
        seccomp_origin,
        devices,
        devices_origin,
        fs_deny,
        fs_readonly,
        fs_scan,
        fs_scan_max_kb,
        fs_git_writable,
        fs_origin,
        tasks,
        ssh_agent,
        ssh_agent_origin,
        ssh_agent_confirm,
        brokers,
        limits,
        secrets,
        plugins,
        apps,
        warnings,
    } = view;
    ConfigView {
        cwd: text(cwd),
        env: env.iter().map(env_var).collect(),
        binds: binds.iter().map(bind).collect(),
        open: open.iter().map(open_handler).collect(),
        service: service.iter().map(service_entry).collect(),
        packages: packages.iter().map(package).collect(),
        mise: mise.as_ref().map(mise_file),
        tools: tools_view(tools),
        nixpkgs: channel(nixpkgs),
        engine: channel(engine),
        network: network_view(network),
        network_origin: *network_origin,
        egress_stats: *egress_stats,
        redact_min_len: *redact_min_len,
        redact_min_len_origin: *redact_min_len_origin,
        observe_record: *observe_record,
        observe_record_origin: *observe_record_origin,
        proc: proc_view(proc),
        proc_origin: *proc_origin,
        notify: notify_view(notify),
        notify_origin: *notify_origin,
        gui: gui_view(gui),
        gui_origin: *gui_origin,
        distro: optional(distro),
        distro_origin: *distro_origin,
        distro_auth: optional(distro_auth),
        timezone: text(timezone),
        timezone_origin: *timezone_origin,
        gpu: *gpu,
        gpu_origin: *gpu_origin,
        allow_insecure_http: *allow_insecure_http,
        allow_insecure_http_origin: *allow_insecure_http_origin,
        apps_share_install_pools: *apps_share_install_pools,
        apps_share_install_pools_origin: *apps_share_install_pools_origin,
        audio: *audio,
        audio_origin: *audio_origin,
        dbus: *dbus,
        dbus_origin: *dbus_origin,
        forward: forward.clone(),
        forward_origin: *forward_origin,
        seccomp: texts(seccomp),
        seccomp_origin: *seccomp_origin,
        devices: texts(devices),
        devices_origin: *devices_origin,
        fs_deny: fs_deny.clone(),
        fs_readonly: fs_readonly.clone(),
        fs_scan: fs_scan.clone(),
        fs_scan_max_kb: *fs_scan_max_kb,
        fs_git_writable: *fs_git_writable,
        fs_origin: *fs_origin,
        tasks: tasks.iter().map(task).collect(),
        ssh_agent: texts(ssh_agent),
        ssh_agent_origin: *ssh_agent_origin,
        ssh_agent_confirm: *ssh_agent_confirm,
        brokers: brokers.iter().map(broker).collect(),
        limits: limits_view(limits),
        secrets: secrets.iter().map(secret).collect(),
        plugins: plugins.iter().map(plugin).collect(),
        apps: apps.iter().map(app).collect(),
        warnings: texts(warnings),
    }
}

/// The one app's view [`super::app_detail::render_app_detail`] prints.
pub(super) fn app_detail_view(view: &AppDetailView) -> AppDetailView {
    let AppDetailView {
        name,
        cwd,
        cmd,
        cmd_origin,
        contract,
        provisions,
        home_scope,
        home_scope_origin,
        network,
        network_origin,
        proc,
        proc_origin,
        notify,
        notify_origin,
        gui,
        gui_origin,
        gpu,
        gpu_origin,
        allow_insecure_http,
        allow_insecure_http_origin,
        audio,
        audio_origin,
        dbus,
        dbus_origin,
        forward,
        forward_origin,
        seccomp,
        seccomp_origin,
        devices,
        devices_origin,
        fs_deny,
        fs_readonly,
        fs_scan,
        fs_scan_max_kb,
        fs_git_writable,
        fs_origin,
        ssh_agent,
        ssh_agent_origin,
        ssh_agent_confirm,
        limits,
        env,
        env_inherited,
        binds,
        binds_inherited,
        packages,
        packages_inherited,
        nixpkgs,
        secrets,
        secrets_inherited,
        open,
        service,
        notes,
        warnings,
    } = view;
    AppDetailView {
        name: text(name),
        cwd: text(cwd),
        cmd: optional(cmd),
        cmd_origin: *cmd_origin,
        contract: optional(contract),
        provisions: provisions.iter().map(provision).collect(),
        home_scope: text(home_scope),
        home_scope_origin: *home_scope_origin,
        network: network_view(network),
        network_origin: *network_origin,
        proc: proc_view(proc),
        proc_origin: *proc_origin,
        notify: notify_view(notify),
        notify_origin: *notify_origin,
        gui: gui_view(gui),
        gui_origin: *gui_origin,
        gpu: *gpu,
        gpu_origin: *gpu_origin,
        allow_insecure_http: *allow_insecure_http,
        allow_insecure_http_origin: *allow_insecure_http_origin,
        audio: *audio,
        audio_origin: *audio_origin,
        dbus: *dbus,
        dbus_origin: *dbus_origin,
        forward: forward.clone(),
        forward_origin: *forward_origin,
        seccomp: texts(seccomp),
        seccomp_origin: *seccomp_origin,
        devices: texts(devices),
        devices_origin: *devices_origin,
        fs_deny: fs_deny.clone(),
        fs_readonly: fs_readonly.clone(),
        fs_scan: fs_scan.clone(),
        fs_scan_max_kb: *fs_scan_max_kb,
        fs_git_writable: *fs_git_writable,
        fs_origin: *fs_origin,
        ssh_agent: texts(ssh_agent),
        ssh_agent_origin: *ssh_agent_origin,
        ssh_agent_confirm: *ssh_agent_confirm,
        limits: limits_view(limits),
        env: env.iter().map(app_env_var).collect(),
        env_inherited: *env_inherited,
        binds: binds.iter().map(bind).collect(),
        binds_inherited: *binds_inherited,
        packages: packages.iter().map(package).collect(),
        packages_inherited: *packages_inherited,
        nixpkgs: channel(nixpkgs),
        secrets: secrets.iter().map(secret).collect(),
        secrets_inherited: *secrets_inherited,
        open: open.iter().map(open_handler).collect(),
        service: service.iter().map(service_entry).collect(),
        notes: texts(notes),
        warnings: texts(warnings),
    }
}

/// One string as a terminal is to show it: escaped by [`crate::diag::visible`], nothing cut.
fn text(value: &str) -> String {
    crate::diag::visible(value)
}

/// [`text`] over a value the view may not carry.
fn optional(value: &Option<String>) -> Option<String> {
    value.as_deref().map(text)
}

/// [`text`] over every string of a list.
fn texts(values: &[String]) -> Vec<String> {
    values.iter().map(|v| text(v)).collect()
}

/// A baseline environment variable, left as it is: the renderer folds its key and value where it
/// prints them.
fn env_var(var: &EnvVar) -> EnvVar {
    let EnvVar { key, value, layer } = var;
    EnvVar {
        key: key.clone(),
        value: value.clone(),
        layer: *layer,
    }
}

/// An app's environment variable, left as it is for the reason [`env_var`] gives.
fn app_env_var(var: &AppEnvVar) -> AppEnvVar {
    let AppEnvVar { key, value } = var;
    AppEnvVar {
        key: key.clone(),
        value: value.clone(),
    }
}

/// A bind: its path, beside whether it is writable and which layer declared it.
fn bind(bind: &BindView) -> BindView {
    let BindView {
        path,
        writable,
        layer,
    } = bind;
    BindView {
        path: text(path),
        writable: *writable,
        layer: *layer,
    }
}

/// An `[open]` handler: the scheme it routes, the command and the mode.
fn open_handler(handler: &OpenView) -> OpenView {
    let OpenView { scheme, cmd, mode } = handler;
    OpenView {
        scheme: text(scheme),
        cmd: text(cmd),
        mode: text(mode),
    }
}

/// A `[service]` entry: its name, its command and the conditions it starts under. Its readiness
/// gate is a port and a timeout, numbers only.
fn service_entry(service: &ServiceView) -> ServiceView {
    let ServiceView {
        name,
        cmd,
        enable,
        ready,
    } = service;
    ServiceView {
        name: text(name),
        cmd: text(cmd),
        enable: optional(enable),
        ready: *ready,
    }
}

/// A declared package: its name, backend and locator, how it is realised, and why it was
/// withheld or which revision it is pinned at.
fn package(package: &PackageView) -> PackageView {
    let PackageView {
        name,
        backend,
        locator,
        realised,
        trusted,
        withheld_reason,
        pinned_rev,
    } = package;
    PackageView {
        name: text(name),
        backend: text(backend),
        locator: text(locator),
        realised: text(realised),
        trusted: *trusted,
        withheld_reason: optional(withheld_reason),
        pinned_rev: optional(pinned_rev),
    }
}

/// The project's mise file: its name, and why it is withheld when it is.
fn mise_file(mise: &MiseView) -> MiseView {
    let MiseView {
        name,
        trusted,
        withheld_reason,
    } = mise;
    MiseView {
        name: text(name),
        trusted: *trusted,
        withheld_reason: optional(withheld_reason),
    }
}

/// The `[tools]` table: each `nix:` tool, each tool mise equips in the cage, and each token
/// neither of them reads.
fn tools_view(tools: &ToolsView) -> ToolsView {
    let ToolsView {
        nix,
        non_nix,
        malformed,
    } = tools;
    ToolsView {
        nix: nix
            .iter()
            .map(|tool| {
                let NixToolView {
                    pkg,
                    version,
                    trusted,
                    withheld_reason,
                } = tool;
                NixToolView {
                    pkg: text(pkg),
                    version: text(version),
                    trusted: *trusted,
                    withheld_reason: optional(withheld_reason),
                }
            })
            .collect(),
        non_nix: non_nix
            .iter()
            .map(|tool| {
                let NonNixToolView {
                    token,
                    version,
                    equipped,
                } = tool;
                NonNixToolView {
                    token: text(token),
                    version: text(version),
                    equipped: *equipped,
                }
            })
            .collect(),
        malformed: texts(malformed),
    }
}

/// A nixpkgs or engine channel: its source, where that was chosen, and the revision it is locked
/// at.
fn channel(channel: &ChannelView) -> ChannelView {
    let ChannelView {
        source,
        origin,
        locked_rev,
    } = channel;
    ChannelView {
        source: text(source),
        origin: text(origin),
        locked_rev: optional(locked_rev),
    }
}

/// The baseline network posture, and under an allowlist every rule list and label it carries.
fn network_view(network: &NetworkView) -> NetworkView {
    match network {
        NetworkView::Shared => NetworkView::Shared,
        NetworkView::Isolated => NetworkView::Isolated,
        NetworkView::Allowlist {
            default_action,
            ask_timeout,
            ask_notice,
            allow,
            deny,
            mute,
            http2,
            shared_credential,
            capture,
            capture_max_kb,
            websocket_secret,
            pool,
            ca_roots,
            dns_cache_ttl,
            idle_timeout,
            max_connections,
            body_max_mb,
            builtin,
        } => NetworkView::Allowlist {
            default_action: *default_action,
            ask_timeout: optional(ask_timeout),
            ask_notice: *ask_notice,
            allow: texts(allow),
            deny: texts(deny),
            mute: texts(mute),
            http2: texts(http2),
            shared_credential: shared_credential.iter().map(|set| texts(set)).collect(),
            capture: text(capture),
            capture_max_kb: *capture_max_kb,
            websocket_secret: text(websocket_secret),
            pool: *pool,
            ca_roots: *ca_roots,
            dns_cache_ttl: *dns_cache_ttl,
            idle_timeout: *idle_timeout,
            max_connections: *max_connections,
            body_max_mb: *body_max_mb,
            builtin: texts(builtin),
        },
    }
}

/// An app's own network posture, the narrower shape of [`network_view`]'s.
fn app_network_view(network: &AppNetworkView) -> AppNetworkView {
    match network {
        AppNetworkView::Shared => AppNetworkView::Shared,
        AppNetworkView::Isolated => AppNetworkView::Isolated,
        AppNetworkView::Allowlist {
            default_action,
            ask_timeout,
            ask_notice,
            allow,
            deny,
            builtin,
        } => AppNetworkView::Allowlist {
            default_action: *default_action,
            ask_timeout: optional(ask_timeout),
            ask_notice: *ask_notice,
            allow: texts(allow),
            deny: texts(deny),
            builtin: texts(builtin),
        },
    }
}

/// The GUI posture. It carries no text; it is rebuilt variant by variant so that a variant added
/// later has to be placed here.
fn gui_view(gui: &GuiView) -> GuiView {
    match gui {
        GuiView::None => GuiView::None,
        GuiView::Offscreen => GuiView::Offscreen,
        GuiView::Wayland => GuiView::Wayland,
    }
}

/// The `[proc]` posture: its mode and both rule lists.
fn proc_view(proc: &ProcView) -> ProcView {
    let ProcView { mode, allow, deny } = proc;
    ProcView {
        mode: text(mode),
        allow: texts(allow),
        deny: texts(deny),
    }
}

/// The `[notify]` table: each event with its mode, and how long before a notice repeats.
fn notify_view(notify: &NotifyView) -> NotifyView {
    let NotifyView {
        events,
        repeat_after,
    } = notify;
    NotifyView {
        events: events
            .iter()
            .map(|(event, mode)| (text(event), text(mode)))
            .collect(),
        repeat_after: text(repeat_after),
    }
}

/// The baseline resource limits, each through [`limit`].
fn limits_view(limits: &LimitsView) -> LimitsView {
    let LimitsView {
        memory_high,
        memory_max,
        tasks_max,
    } = limits;
    LimitsView {
        memory_high: limit(memory_high),
        memory_max: limit(memory_max),
        tasks_max: limit(tasks_max),
    }
}

/// One resource limit's value, beside the layer that set it.
fn limit(limit: &LimitView) -> LimitView {
    let LimitView { value, origin } = limit;
    LimitView {
        value: text(value),
        origin: *origin,
    }
}

/// An app's own resource limits, each present only when the app sets it.
fn app_limits_view(limits: &AppLimitsView) -> AppLimitsView {
    let AppLimitsView {
        memory_high,
        memory_max,
        tasks_max,
    } = limits;
    AppLimitsView {
        memory_high: optional(memory_high),
        memory_max: optional(memory_max),
        tasks_max: optional(tasks_max),
    }
}

/// A `[broker.<name>]` binding: its name, the socket it exposes, what it allows, and the locators
/// its credential is read from.
fn broker(broker: &BrokerView) -> BrokerView {
    let BrokerView {
        name,
        socket,
        allow,
        secret,
        origin,
    } = broker;
    BrokerView {
        name: text(name),
        socket: text(socket),
        allow: texts(allow),
        secret: texts(secret),
        origin: *origin,
    }
}

/// A declared operation: its name, its description and the layer that declared it.
fn task(task: &TaskView) -> TaskView {
    let TaskView {
        name,
        description,
        origin,
    } = task;
    TaskView {
        name: text(name),
        description: optional(description),
        origin: text(origin),
    }
}

/// A wire-injected credential: its header, destination, shape and sources, by locator.
fn secret(secret: &SecretView) -> SecretView {
    let SecretView {
        header,
        to,
        shape,
        sources,
        optional,
    } = secret;
    SecretView {
        header: text(header),
        to: text(to),
        shape: text(shape),
        sources: text(sources),
        optional: *optional,
    }
}

/// A plugin: its name, the environment it is handed and the programs it may run.
fn plugin(plugin: &PluginView) -> PluginView {
    let PluginView {
        name,
        env,
        programs,
    } = plugin;
    PluginView {
        name: text(name),
        env: texts(env),
        programs: texts(programs),
    }
}

/// One install step an app runs: the bundle that declared it and its command.
fn provision(step: &AppProvisionView) -> AppProvisionView {
    let AppProvisionView { bundle, cmd } = step;
    AppProvisionView {
        bundle: text(bundle),
        cmd: text(cmd),
    }
}

/// One declared app as the baseline listing shows it: every string it carries, its environment
/// and `[fs]` lists left as the module note says.
fn app(app: &AppView) -> AppView {
    let AppView {
        name,
        cmd,
        contract,
        provisions,
        home_scope,
        env,
        binds,
        open,
        service,
        packages,
        network,
        gui,
        gpu,
        allow_insecure_http,
        audio,
        dbus,
        forward,
        seccomp,
        devices,
        fs_deny,
        fs_readonly,
        fs_scan,
        ssh_agent,
        limits,
        secrets,
        notes,
    } = app;
    AppView {
        name: text(name),
        cmd: optional(cmd),
        contract: optional(contract),
        provisions: provisions.iter().map(provision).collect(),
        home_scope: text(home_scope),
        env: env.iter().map(app_env_var).collect(),
        binds: binds.iter().map(bind).collect(),
        open: open.iter().map(open_handler).collect(),
        service: service.iter().map(service_entry).collect(),
        packages: packages.iter().map(package).collect(),
        network: network.as_ref().map(app_network_view),
        gui: gui.as_ref().map(gui_view),
        gpu: *gpu,
        allow_insecure_http: *allow_insecure_http,
        audio: *audio,
        dbus: *dbus,
        forward: forward.clone(),
        seccomp: texts(seccomp),
        devices: texts(devices),
        fs_deny: fs_deny.clone(),
        fs_readonly: fs_readonly.clone(),
        fs_scan: fs_scan.clone(),
        ssh_agent: texts(ssh_agent),
        limits: limits.as_ref().map(app_limits_view),
        secrets: secrets.iter().map(secret).collect(),
        notes: texts(notes),
    }
}
