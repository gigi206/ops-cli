//! The command-line surface: argument parsing, dispatch, and per-command handlers, one module
//! per command family. `main` parses argv and routes here; each family owns its argument
//! parsing, orchestration, and output rendering.

pub(crate) mod app;
pub(crate) mod config;
pub(crate) mod doctor;
pub(crate) mod fs;
pub(crate) mod gc;
pub(crate) mod plugins;
pub(crate) mod proc;
pub(crate) mod projects;
pub(crate) mod search;
pub(crate) mod session;
pub(crate) mod test;
pub(crate) mod trust;
pub(crate) mod upgrade;
