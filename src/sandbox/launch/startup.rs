//! The cage's start-up script: the bundle install chain, the declared services and their readiness
//! gate, and the shell quoting all three rest on.
//!
//! One script rather than nested wrappers, because the order is the point and nesting settles it by
//! accident — an install that puts a program on `PATH` has to run before a service that starts it.
//! [`compose_startup_cmd`] writes that order down once; `sbx upgrade provision` takes the same
//! chain without the command's tail, which is why the two live together rather than inside the
//! builder that composes them.
//!
//! Nothing here touches the host or the cage: every item is pure over its arguments and returns
//! the script text, or the argv, that the cage will be handed.

use super::*;

/// The install steps as one `&&` chain, without the app's command.
///
/// Each step is itself an argv, rendered through `shell_quote` so a step's own arguments survive
/// the shell that chains them: an argument holding a space, a quote or a `$` is data, and a shell
/// that re-parsed it would read it as syntax. `&&` carries the same fail-closed rule in both
/// callers — a step that exits non-zero stops the chain.
fn provision_chain(provisions: &[crate::config::BundleProvision]) -> String {
    provisions
        .iter()
        .map(|step| {
            step.argv
                .iter()
                .map(|a| shell_quote(a))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join(" && ")
}

/// Where a service's output goes, inside the cage's own home: `~/.sbx-service-<name>.log`.
///
/// A service outlives the call that started it and shares the terminal with the app, so its output
/// cannot stay there — a chatty daemon would bury the app's own. The file is never rotated; it is
/// the first place to look when an app starts but the thing beside it never answers.
fn service_log_path(name: &str) -> String {
    format!("\"${{HOME:-/tmp}}\"/.sbx-service-{name}.log")
}

/// Render one argv element for the start-up script, expanding a leading `~/` against the cage's home.
///
/// The expansion is the one substitution a service's argv gets, and it exists because a service is
/// declared where the home's path is not knowable — `~/chroma-data` is the only way to name a
/// directory under a home whose location sbx chooses. Everything else is quoted verbatim: a `$VAR`
/// stays four characters, because the argv is data and a shell that re-read it would find syntax.
fn service_arg(arg: &str) -> String {
    match arg.strip_prefix("~/") {
        Some(rest) => format!("\"${{HOME}}\"/{}", shell_quote(rest)),
        None => shell_quote(arg),
    }
}

/// The start-up script's lines for one service: the launch, and the readiness wait.
///
/// The launch is a subshell redirected to the service's log and backgrounded — the same shape the
/// hand-written `nohup … &` had, and for the same reason (the cage ships no `setsid`). It is not
/// supervised: if it dies, it stays dead, and the app is not told. What the readiness gate buys is
/// only that the app does not *race* it.
///
/// A service whose `enable` condition does not hold never reaches here: it is left out of the script
/// entirely, decided against the environment the launch composed rather than by a shell test in the
/// cage. See [`compose_startup_cmd`].
fn service_lines(name: &str, svc: &crate::config::ServiceSpec) -> String {
    let mut out = String::new();
    let argv = svc
        .argv
        .iter()
        .map(|a| service_arg(a))
        .collect::<Vec<_>>()
        .join(" ");
    let log = service_log_path(name);
    out.push_str(&format!("( {argv} ) >>{log} 2>&1 </dev/null &\n"));
    if let Some(ready) = svc.ready {
        // A tenth-of-the-budget poll on bash's own `/dev/tcp`, so the wait needs no tool the base
        // userland might not carry. The connection is opened in a subshell and dropped immediately:
        // the question is whether anything accepts, and a fd left open in the launch would outlive
        // the answer. On expiry the launch goes on — a gate that failed here would turn a slow
        // auxiliary process into a broken app, which is the outcome it exists to avoid.
        let attempts = ready.timeout.as_millis().div_ceil(500).max(1);
        let port = ready.tcp;
        out.push_str(&format!(
            "sbx_ready=0\n\
             for _ in $(seq 1 {attempts}); do\n\
             \x20 if ( exec 3<>/dev/tcp/127.0.0.1/{port} ) 2>/dev/null; then sbx_ready=1; break; fi\n\
             \x20 sleep 0.5\n\
             done\n\
             if [ \"$sbx_ready\" != 1 ]; then\n\
             \x20 echo \"sbx: service {name} did not answer on port {port} within {}s — starting anyway; see {log}\" >&2\n\
             fi\n",
            ready.timeout.as_secs().max(1)
        ));
    }
    out
}

/// Compose the cage's whole start-up ahead of the command it was launched to run: the app's install
/// steps, then its services, then the command itself.
///
/// One script rather than nested wrappers, because the order is the point and nesting decides it by
/// accident: an install that puts a program on `PATH` must run before a service that starts it. The
/// install chain keeps its fail-closed `&&` — a step that exits non-zero stops everything, so no
/// service and no command runs after a broken install. The services do not: one that fails to start
/// is a degraded app, not a failed launch, which is the trade every hand-written `nohup` here
/// already made.
///
/// The command's argv is passed as positional parameters rather than pasted in: an element holding a
/// quote, a space or a `$` is data, and a shell that re-parsed it would read it as syntax.
///
/// A service's `enable` condition is answered **here**, against `env` — the environment this launch
/// composed for the cage — and a service that fails it is simply not written into the script. sbx
/// builds that environment itself, from a cleared one, so the answer is knowable at the moment the
/// script is written; emitting a shell `if` instead would push a decision sbx has already made into
/// a language the field is not.
pub(super) fn compose_startup_cmd(
    provisions: &[crate::config::BundleProvision],
    services: &std::collections::BTreeMap<String, crate::config::ServiceSpec>,
    env: &[(String, String)],
    cmd: Vec<OsString>,
) -> Vec<OsString> {
    let mut script = String::new();
    if !provisions.is_empty() {
        script.push_str(&provision_chain(provisions));
        script.push_str(" || exit $?\n");
    }
    for (name, svc) in services {
        if svc.enable.iter().all(|cond| cond.holds(env)) {
            script.push_str(&service_lines(name, svc));
        }
    }
    script.push_str("exec \"$@\"\n");
    let mut out: Vec<OsString> = vec![
        OsString::from("bash"),
        OsString::from("-c"),
        OsString::from(script),
        // `$0` for the composed script; the command's argv follows as `$1 …`.
        OsString::from("sbx"),
    ];
    out.extend(cmd);
    out
}

/// The install steps alone, as a cage command — what `sbx upgrade provision` runs.
///
/// The same chain the launch composes, minus the `exec "$@"` tail: the point of an upgrade run is
/// the install, and running the agent afterwards would turn a version roll into a launch. The steps
/// see the app's own cage (its home, packages, egress and environment), so what they install is
/// what the next launch finds; `SBX_UPGRADE` is what tells them to re-install rather than honor
/// their own "already installed" guard, and it is set by the caller, not here.
pub(super) fn provision_only_cmd(provisions: &[crate::config::BundleProvision]) -> Vec<OsString> {
    vec![
        OsString::from("bash"),
        OsString::from("-c"),
        OsString::from(provision_chain(provisions)),
        // `$0` — a label; the chain takes no positional arguments.
        OsString::from("sbx-provision"),
    ]
}

/// Quote one argv element for the shell that chains the install steps: single quotes, with an
/// embedded single quote closed and re-opened around an escaped one.
fn shell_quote(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests;
