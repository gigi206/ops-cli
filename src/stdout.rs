//! Standard output that survives a reader going away.
//!
//! Rust ignores `SIGPIPE`, so a `print!` or `println!` whose write fails **panics**: `sbx version`
//! into a pipe whose reader had already gone ended in `failed printing to stdout` and exit 101, on a
//! pipeline the shell reports as having worked. `out!` and `outln!` format the same way and
//! write through [`crate::cli::print_document`], so every line sbx prints keeps the one rule that
//! function states: a failed write is discarded, and whatever the command still has to say goes to
//! stderr. The `clippy::print_stdout` gate in `main.rs` is what keeps a bare `print!` from coming
//! back.
//!
//! Under `cfg(test)` both write with `print!` instead, which the test harness captures: a unit test
//! that calls a renderer keeps its output out of the run's own report, as it always has. What the
//! shipped binary does is what the integration suites run, and they run it with a closed pipe.

/// [`print!`] for sbx's standard output, written through [`crate::cli::print_document`].
macro_rules! out {
    ($($arg:tt)*) => {{
        #[cfg(not(test))]
        $crate::cli::print_document(&format!($($arg)*));
        #[cfg(test)]
        print!($($arg)*);
    }};
}

/// [`println!`] for sbx's standard output, on the same terms as `out!`.
macro_rules! outln {
    () => {
        out!("\n")
    };
    ($($arg:tt)*) => {
        out!("{}\n", format_args!($($arg)*))
    };
}
