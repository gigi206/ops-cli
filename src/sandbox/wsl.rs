//! Whether the host this launch runs on is WSL.
//!
//! One question, answered in one place. Under WSL the "host" is Windows, which answers elsewhere
//! than a Linux host does: the theme lives in the registry rather than a portal, notifications go
//! through the Toast API rather than a freedesktop daemon, and the PulseAudio socket is served from
//! `/mnt/wslg` rather than the session's runtime dir. Each of those lives with its own subject; what
//! they share is only this predicate, so it sits apart from all three rather than in whichever one
//! happened to need it first.
//!
//! Paths that are WSL-specific stay with their domain (the WSLg audio socket is
//! [`super::audio::WSLG_SOCK`]): this module holds the detection, not a catalogue of Windows facts.

/// Whether this kernel is a WSL one, from what `/proc/sys/kernel/osrelease` holds. Pure.
///
/// Microsoft's own marker: a WSL2 kernel names itself `…-microsoft-standard-WSL2`. Read as a
/// substring rather than a suffix because the release carries a version prefix that changes, and
/// case-insensitively because the spelling has changed across WSL generations.
pub(crate) fn is_wsl_release(osrelease: &str) -> bool {
    osrelease.to_ascii_lowercase().contains("microsoft")
}

/// Whether the kernel this launch runs on is a WSL one, read from `/proc/sys/kernel/osrelease`.
/// A file that cannot be read answers `false`, which keeps every WSL fallback shut on a host whose
/// `/proc` is not the one this expects rather than opening it on a guess.
pub(crate) fn host_is_wsl() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .is_ok_and(|release| is_wsl_release(&release))
}

#[cfg(test)]
mod tests {
    /// The marker Microsoft writes, and the shapes that are not it.
    #[test]
    fn a_wsl_kernel_is_told_from_an_ordinary_one() {
        assert!(super::is_wsl_release("6.18.33.2-microsoft-standard-WSL2"));
        assert!(super::is_wsl_release("5.15.0-MICROSOFT-standard"));
        assert!(!super::is_wsl_release("6.11.0-19-generic"));
        assert!(!super::is_wsl_release("6.6.87.1-lts"));
    }

    /// The reader answers for the kernel this test runs on, whichever it is: the point is that it
    /// agrees with the pure predicate over the same file, never that the host is one or the other.
    #[test]
    fn the_reader_agrees_with_the_predicate_over_the_running_kernel() {
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
        assert_eq!(super::host_is_wsl(), super::is_wsl_release(&release));
    }
}
