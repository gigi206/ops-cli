//! The command-line surface: argument parsing, dispatch, and per-command handlers, one module
//! per command family. `main` parses argv and routes here; each family owns its argument
//! parsing, orchestration, and output rendering.

pub(crate) mod gc;
pub(crate) mod search;
pub(crate) mod session;
pub(crate) mod trust;
