//! `sbx gc [--prune] [--all]`: reclaim the nix-store side of a project's footprint (the
//! project-tree lifecycle lives under `sbx projects`).

use std::ffi::OsString;
use std::io::IsTerminal;
use std::process::ExitCode;

use crate::{help, sandbox, style};

pub(crate) fn run(args: Vec<OsString>) -> ExitCode {
    let mut prune = false;
    let mut all = false;
    let mut optimise = false;
    for a in &args {
        match a.to_str() {
            Some("--prune") => prune = true,
            Some("--all") => all = true,
            Some("--optimise") | Some("--optimize") => optimise = true,
            Some(_) => {
                eprintln!("sbx: usage: {}", help::synopsis("gc"));
                return ExitCode::from(2);
            }
            None => {
                eprintln!("sbx: gc: argument is not valid UTF-8");
                return ExitCode::from(2);
            }
        }
    }
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    sandbox::gc(prune, all, optimise, &pal)
}
