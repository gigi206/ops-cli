//! `sbx secret <subcommand>`: the credential inventory — what this project's configuration declares,
//! by name.
//!
//! One subcommand, `list`. It answers "which credentials does this configuration carry, and what are
//! they for" from the resolved config: the wire-injected ones (`[secret."host"]`, brokered into a
//! request by the egress proxy) and the ones a declared operation reads from its environment
//! (`[task.<name>.secret]`).
//!
//! It never reads a value, and it never resolves a source: an inventory that had to decrypt a sops
//! file to list a name would be a way to make sbx decrypt on demand. What it prints is the
//! declaration — name, destination or task, and description — plus *where the value would come from*
//! by locator (a variable name, a file path), which is the declaration too.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::process::ExitCode;

use crate::{config, diag, help, style};

/// `sbx secret <subcommand>`: currently `list`.
pub(crate) fn secret_cmd(args: Vec<OsString>) -> ExitCode {
    if let Some(code) = help::maybe_help("secret", &args) {
        return code;
    }
    match args.first().and_then(|a| a.to_str()) {
        Some("list") | Some("ls") => secret_list(&args[1..]),
        None => {
            eprint!("{}", help::page_usage(&["secret"]).unwrap_or_default());
            ExitCode::from(2)
        }
        Some(other) => {
            diag::error(&format!("sbx: secret: unknown subcommand `{other}`"));
            diag::hint("       run `sbx help secret` for usage.");
            ExitCode::from(2)
        }
    }
}

/// `sbx secret list [--app <name>] [--sources]`: the declared credentials, by name.
fn secret_list(args: &[OsString]) -> ExitCode {
    let mut app: Option<String> = None;
    let mut sources = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].to_str() {
            Some("--sources") => {
                sources = true;
                i += 1;
            }
            Some("-a") | Some("--app") => match args.get(i + 1).and_then(|a| a.to_str()) {
                Some(v) => {
                    app = Some(v.to_string());
                    i += 2;
                }
                None => {
                    diag::error("sbx: secret list: `--app` needs a name");
                    return ExitCode::from(2);
                }
            },
            other => {
                diag::error(&format!(
                    "sbx: secret list: unexpected argument {:?}",
                    other.unwrap_or_default()
                ));
                eprint!(
                    "{}",
                    help::page_usage(&["secret", "list"]).unwrap_or_default()
                );
                return ExitCode::from(2);
            }
        }
    }

    let Ok(cwd) = std::env::current_dir() else {
        diag::error("sbx: cannot determine the current directory");
        return ExitCode::FAILURE;
    };
    let mut resolved = config::load(&cwd);
    for w in &resolved.warnings {
        diag::warn(w);
    }
    // Fold an app's overlay so the inventory is the effective set that app would launch with, the
    // same way `sbx net rules --app` reads the effective policy.
    if let Some(name) = &app
        && let Err(e) = crate::fold_app_overlay(&mut resolved, name)
    {
        diag::error(&format!("sbx: secret list: {e}"));
        return ExitCode::from(2);
    }

    let palette = style::Palette::for_stream(std::io::stdout().is_terminal());
    let mut any = false;
    for secret in &resolved.secrets {
        any = true;
        let mut line = format!(
            "{}{}{}  wire -> {} ({})",
            palette.name, secret.name, palette.reset, secret.to, secret.header
        );
        if sources {
            line.push_str(&format!("  from {}", secret.describe_sources()));
        }
        if let Some(desc) = &secret.description {
            line.push_str(&format!("  — {desc}"));
        }
        println!("{line}");
    }
    for task in &resolved.tasks {
        for secret in &task.secrets {
            any = true;
            let mut line = format!(
                "{}{}{}  env of task `{}` ({})",
                palette.name,
                secret.var,
                palette.reset,
                task.name,
                secret.encode.as_str()
            );
            if sources {
                line.push_str(&format!(
                    "  from {}",
                    secret
                        .sources
                        .iter()
                        .map(config::SecretSource::describe)
                        .collect::<Vec<_>>()
                        .join(", then ")
                ));
            }
            if let Some(desc) = &secret.description {
                line.push_str(&format!("  — {desc}"));
            }
            println!("{line}");
        }
        for injection in &task.injections {
            any = true;
            println!(
                "{}{}{}  wire of task `{}` -> {} ({})",
                palette.name,
                injection.name,
                palette.reset,
                task.name,
                injection.to,
                injection.header
            );
        }
    }
    if !any {
        println!("no credentials are declared for this project");
    }
    ExitCode::SUCCESS
}
