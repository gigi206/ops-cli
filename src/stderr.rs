//! Standard error that survives a stream it cannot write to.
//!
//! An `eprint!` or `eprintln!` whose write fails **panics**: with stderr on `/dev/full` or on a pipe
//! whose reader had gone, `sbx app show nope` ended in `failed printing to stderr` and exit 101,
//! where the refusal's own answer is 2, and so did every verb that warned on its way to a success.
//! `err!` and `errln!` format the same way and write through [`crate::diag::emit`], which drops a
//! write that failed and leaves the exit code to the verb. The `clippy::print_stderr` gate in
//! `main.rs` is what keeps a bare `eprint!` from coming back.
//!
//! Under `cfg(test)` both write with `eprint!` instead, which the test harness captures, as `out!`
//! does for standard output.

/// [`eprint!`] for sbx's standard error, written through [`crate::diag::emit`].
macro_rules! err {
    ($($arg:tt)*) => {{
        #[cfg(not(test))]
        $crate::diag::emit(format_args!($($arg)*));
        #[cfg(test)]
        eprint!($($arg)*);
    }};
}

/// [`eprintln!`] for sbx's standard error, on the same terms as `err!`.
macro_rules! errln {
    () => {
        err!("\n")
    };
    ($($arg:tt)*) => {
        err!("{}\n", format_args!($($arg)*))
    };
}
