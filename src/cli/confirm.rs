//! `sbx` transactional confirmation renderers — the short, colored "what just changed"
//! lines printed by the write verbs (`config set/unset`, `app import/export/rm`, `plugins
//! install/rm`, `plugins store add/update/publish`, and the trust prompts). Grouped here
//! because one cross-family pair of tests (`transactional_confirmations_*`) exercises them
//! together; each family calls the ones it needs via `crate::cli::confirm::`.

use std::path::Path;

use crate::style;

/// The confirmation for a config write: the verb (`set`/`updated`/`unset`) in green over the
/// dotted key, with the target file highlighted. A pure presenter — every span is empty under a
/// non-terminal, so captured output is byte-for-byte the plain text the management tests pin.
pub(crate) fn render_config_write(
    verb: &str,
    key: &str,
    path: &Path,
    pal: &style::Palette,
) -> String {
    let (ok, n, r) = (pal.ok, pal.name, pal.reset);
    format!(
        "sbx: {ok}{verb}{r} {} in {n}{}{r}",
        style::paint_spans(&format!("`{key}`"), pal.name, "", pal),
        path.display()
    )
}

/// The no-op confirmation for `sbx config unset` on a key that was not set — dimmed, since nothing
/// changed (and so trust is never re-armed). A pure presenter.
pub(crate) fn render_config_unchanged(key: &str, path: &Path, pal: &style::Palette) -> String {
    let (dim, r) = (pal.dim, pal.reset);
    format!(
        "sbx: {} {dim}was not set in {}{r}",
        style::paint_spans(&format!("`{key}`"), pal.name, "", pal),
        path.display()
    )
}

/// The confirmation that `--trust` re-blessed a whole file after a write or edit: `trusted` in
/// green over the path, the scope note dimmed. A pure presenter, shared by `set`/`unset`/`edit`.
pub(crate) fn render_trusted_whole_file(path: &Path, pal: &style::Palette) -> String {
    let (ok, n, dim, r) = (pal.ok, pal.name, pal.dim, pal.reset);
    format!(
        "sbx: {ok}trusted{r} {n}{}{r} {dim}(the whole file is now trusted){r}",
        path.display()
    )
}

/// The import confirmation: `imported` in green over the app name and destination, the granted
/// posture introduced by a dimmed label (the summary lines themselves stay plain — they carry the
/// posture detail), and the launch hint dimmed with the name highlighted. A pure presenter — every
/// span is empty under a non-terminal, so a captured stream is the plain text the tests pin.
pub(crate) fn render_app_imported(
    name: &str,
    dest: &Path,
    summary: &[String],
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (ok, n, dim, r) = (pal.ok, pal.name, pal.dim, pal.reset);
    let mut o = String::new();
    let _ = writeln!(
        o,
        "{ok}imported{r} app profile '{n}{name}{r}' -> {n}{}{r}",
        dest.display()
    );
    let _ = writeln!(
        o,
        "  {dim}granted posture (trusted by location — honored even on an untrusted project):{r}"
    );
    for line in summary {
        let _ = writeln!(o, "    {line}");
    }
    let _ = write!(o, "  {dim}launch it with: sbx app{r} {n}{name}{r}");
    o
}

/// The export confirmation (only on `--out`, since the default writes the profile bytes to
/// stdout): `exported` in green over the app name and destination. Goes to stderr, so its palette
/// is decided from stderr's stream. A pure presenter.
pub(crate) fn render_app_exported(name: &str, path: &Path, pal: &style::Palette) -> String {
    let (ok, n, r) = (pal.ok, pal.name, pal.reset);
    format!(
        "{ok}exported{r} app {} -> {n}{}{r}",
        style::paint_spans(&format!("`{name}`"), pal.name, "", pal),
        path.display()
    )
}

/// The confirmation for a placed plugin: `installed` in green (the change happened), the plugin
/// name and its scheme highlighted, and the removal hint dimmed. `from_store` names the store an
/// install came from, when one did. A pure presenter — every span is empty under a non-terminal,
/// so a captured stream is byte-for-byte the plain text the integration tests pin.
pub(crate) fn render_plugin_installed(
    name: &str,
    scheme: &str,
    from_store: Option<&str>,
    pal: &style::Palette,
) -> String {
    let (ok, n, dim, r) = (pal.ok, pal.name, pal.dim, pal.reset);
    let from = match from_store {
        Some(s) => format!(" from store '{n}{s}{r}'"),
        None => String::new(),
    };
    format!(
        "{ok}installed{r} '{n}{name}{r}' {dim}({scheme}://){r}{from} \
         {dim}— remove with: sbx plugins rm {name}{r}"
    )
}

/// The confirmation for a removed thing: `removed` in green over the name. `label` names what kind
/// (`store`, `app profile`), or `None` for a bare resolver plugin. A pure presenter.
pub(crate) fn render_removed(label: Option<&str>, name: &str, pal: &style::Palette) -> String {
    let (ok, n, r) = (pal.ok, pal.name, pal.reset);
    match label {
        Some(l) => format!("{ok}removed{r} {l} '{n}{name}{r}'"),
        None => format!("{ok}removed{r} '{n}{name}{r}'"),
    }
}

/// The trust-on-first-use caution for a freshly added store — yellow, since it pinned a key sbx
/// could not pre-verify. The pinned key is highlighted for an out-of-band comparison; the
/// follow-up hint is dimmed. Goes to stderr, so its palette is decided from stderr's stream.
pub(crate) fn render_store_tofu(pubkey_hex: &str, name: &str, pal: &style::Palette) -> String {
    let (warn, n, r) = (pal.warn, pal.name, pal.reset);
    format!(
        "{warn}⚠ trust-on-first-use: pinned the key this store ships, unverified{r}\n  \
         pinned key: {n}{pubkey_hex}{r}\n  {}",
        style::dim_prose(
            &format!("verify it out of band; re-shown by `sbx plugins store info {name}`"),
            pal
        )
    )
}

/// The configured-store report: `configured store` in green over the name, the revision and count
/// dimmed, then each plugin by name with its scheme and version dimmed. A pure presenter over the
/// catalogue's plugin lines as `(name, scheme, version)` triples.
pub(crate) fn render_store_configured(
    name: &str,
    rev: u64,
    plugins: &[(&str, &str, &str)],
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (ok, n, dim, r) = (pal.ok, pal.name, pal.dim, pal.reset);
    let plural = if plugins.len() == 1 { "" } else { "s" };
    let mut o = String::new();
    let _ = writeln!(
        o,
        "{ok}configured store{r} '{n}{name}{r}' {dim}(rev {rev}, {} plugin{plural}):{r}",
        plugins.len()
    );
    for (pname, scheme, version) in plugins {
        let _ = write!(o, "  {n}{pname}{r}  {dim}({scheme}://){r}");
        if !version.is_empty() {
            let _ = write!(o, "  {dim}v{version}{r}");
        }
        let _ = writeln!(o);
    }
    o
}

/// The keep-the-key-secret caution after a publish — yellow, over the highlighted key path. Goes
/// to stderr, so its palette is decided from stderr's stream.
pub(crate) fn render_publish_key_warning(key_path: &Path, pal: &style::Palette) -> String {
    let (warn, r) = (pal.warn, pal.reset);
    format!(
        "{warn}⚠ keep the signing key{r} {} \
         {warn}secret — it is this store's identity{r}",
        style::paint_spans(&format!("`{}`", key_path.display()), pal.name, "", pal)
    )
}

/// The published-store report: `published store` in green, the plugins by name, the public key
/// consumers pin highlighted, and the commit-and-host hint dimmed (with the key echoed in it). A
/// pure presenter over the published plugin lines as `(name, scheme)` pairs.
pub(crate) fn render_published(
    rev: u64,
    plugins: &[(&str, &str)],
    pubkey_hex: &str,
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (ok, n, dim, r) = (pal.ok, pal.name, pal.dim, pal.reset);
    let plural = if plugins.len() == 1 { "" } else { "s" };
    let mut o = String::new();
    let _ = writeln!(
        o,
        "{ok}published store{r} at rev {rev} {dim}({} plugin{plural}):{r}",
        plugins.len()
    );
    for (name, scheme) in plugins {
        let _ = writeln!(o, "  {n}{name}{r}  {dim}({scheme}://){r}");
    }
    let _ = writeln!(o, "pubkey: {n}{pubkey_hex}{r}");
    let _ = write!(
        o,
        "{dim}commit and host the directory, then consumers add it with: \
         sbx plugins store add --name <n> --url <git-url> --key {pubkey_hex}{r}"
    );
    o
}

/// The update report for one store: `updated store` in green with the revision bump when it
/// advanced, or a dimmed already-current line when nothing moved (a no-op takes the dim hue). A
/// pure presenter.
pub(crate) fn render_store_updated(
    name: &str,
    old_rev: u64,
    new_rev: u64,
    count: usize,
    pal: &style::Palette,
) -> String {
    let (ok, n, dim, r) = (pal.ok, pal.name, pal.dim, pal.reset);
    let plural = if count == 1 { "" } else { "s" };
    if new_rev > old_rev {
        format!(
            "{ok}updated store{r} '{n}{name}{r}' \
             {dim}(rev {old_rev} → {new_rev}, {count} plugin{plural}){r}"
        )
    } else {
        format!(
            "store '{n}{name}{r}' is {dim}already at revision {new_rev} ({count} plugin{plural}){r}"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transactional_confirmations_are_plain_text_when_uncolored() {
        // The OFF path the integration capture and the existing substring assertions rely on:
        // empty spans, byte-identical plain text. Each line of the original wording is preserved.
        let p = style::Palette::plain();
        assert_eq!(
            render_plugin_installed("pass", "pass", None, &p),
            "installed 'pass' (pass://) — remove with: sbx plugins rm pass"
        );
        assert_eq!(
            render_plugin_installed("vault", "vault", Some("hub"), &p),
            "installed 'vault' (vault://) from store 'hub' — remove with: sbx plugins rm vault"
        );
        assert_eq!(render_removed(None, "pass", &p), "removed 'pass'");
        assert_eq!(
            render_removed(Some("store"), "hub", &p),
            "removed store 'hub'"
        );
        assert_eq!(
            render_removed(Some("app profile"), "demo-app", &p),
            "removed app profile 'demo-app'"
        );
        assert_eq!(
            render_store_tofu("ab12", "hub", &p),
            "⚠ trust-on-first-use: pinned the key this store ships, unverified\n  \
             pinned key: ab12\n  \
             verify it out of band; re-shown by `sbx plugins store info hub`"
        );
        assert_eq!(
            render_store_configured("hub", 3, &[("vault", "vault", "1.0"), ("pass", "pass", "")], &p),
            "configured store 'hub' (rev 3, 2 plugins):\n  vault  (vault://)  v1.0\n  pass  (pass://)\n"
        );
        assert_eq!(
            render_publish_key_warning(Path::new("/k/key.pem"), &p),
            "⚠ keep the signing key `/k/key.pem` secret — it is this store's identity"
        );
        assert_eq!(
            render_published(5, &[("vault", "vault")], "deadbeef", &p),
            "published store at rev 5 (1 plugin):\n  vault  (vault://)\npubkey: deadbeef\n\
             commit and host the directory, then consumers add it with: \
             sbx plugins store add --name <n> --url <git-url> --key deadbeef"
        );
        assert_eq!(
            render_store_updated("hub", 3, 5, 2, &p),
            "updated store 'hub' (rev 3 → 5, 2 plugins)"
        );
        assert_eq!(
            render_store_updated("hub", 5, 5, 1, &p),
            "store 'hub' is already at revision 5 (1 plugin)"
        );
        assert_eq!(
            render_app_imported(
                "demo-app",
                Path::new("/c/demo-app.toml"),
                &["command: x".into(), "network: allowlist".into()],
                &p
            ),
            "imported app profile 'demo-app' -> /c/demo-app.toml\n  \
             granted posture (trusted by location — honored even on an untrusted project):\n    \
             command: x\n    network: allowlist\n  launch it with: sbx app demo-app"
        );
        assert_eq!(
            render_app_exported("demo-app", Path::new("/c/out.toml"), &p),
            "exported app `demo-app` -> /c/out.toml"
        );
        let cfg = Path::new("/p/.sbx.toml");
        assert_eq!(
            render_config_write("set", "env.FOO", cfg, &p),
            "sbx: set `env.FOO` in /p/.sbx.toml"
        );
        assert_eq!(
            render_config_write("unset", "env.FOO", cfg, &p),
            "sbx: unset `env.FOO` in /p/.sbx.toml"
        );
        assert_eq!(
            render_config_unchanged("env.FOO", cfg, &p),
            "sbx: `env.FOO` was not set in /p/.sbx.toml"
        );
        assert_eq!(
            render_trusted_whole_file(cfg, &p),
            "sbx: trusted /p/.sbx.toml (the whole file is now trusted)"
        );
    }

    #[test]
    fn transactional_confirmations_color_their_key_spans() {
        // The ON path: the success verb takes the `ok` hue, a caution takes `warn`, a no-op takes
        // `dim`, and identifiers ride the `name` span — a swapped hue (invisible to the plain
        // assertions above) only shows here.
        let p = style::Palette::colored();

        let installed = render_plugin_installed("pass", "pass", None, &p);
        assert!(installed.contains(&format!("{}installed{}", p.ok, p.reset)));
        assert!(installed.contains(&format!("'{}pass{}'", p.name, p.reset)));

        assert!(render_removed(Some("store"), "hub", &p)
            .contains(&format!("{}removed{}", p.ok, p.reset)));

        let tofu = render_store_tofu("ab12", "hub", &p);
        assert!(
            tofu.contains(p.warn),
            "the tofu caution must ride the warn hue:\n{tofu}"
        );
        assert!(tofu.contains(&format!("{}ab12{}", p.name, p.reset)));

        let configured = render_store_configured("hub", 3, &[("vault", "vault", "1.0")], &p);
        assert!(configured.contains(&format!("{}configured store{}", p.ok, p.reset)));
        assert!(configured.contains(&format!("{}vault{}", p.name, p.reset)));

        let keywarn = render_publish_key_warning(Path::new("/k/key.pem"), &p);
        assert!(
            keywarn.contains(p.warn),
            "the key caution must ride the warn hue:\n{keywarn}"
        );

        let published = render_published(5, &[("vault", "vault")], "deadbeef", &p);
        assert!(published.contains(&format!("{}published store{}", p.ok, p.reset)));
        assert!(published.contains(&format!("{}deadbeef{}", p.name, p.reset)));

        let rolled = render_store_updated("hub", 3, 5, 2, &p);
        assert!(rolled.contains(&format!("{}updated store{}", p.ok, p.reset)));
        let noop = render_store_updated("hub", 5, 5, 1, &p);
        assert!(
            noop.contains(p.dim),
            "a no-op update must take the dim hue:\n{noop}"
        );

        let imported = render_app_imported("demo-app", Path::new("/c/demo-app.toml"), &[], &p);
        assert!(imported.contains(&format!("{}imported{}", p.ok, p.reset)));
        assert!(imported.contains(&format!("'{}demo-app{}'", p.name, p.reset)));

        let exported = render_app_exported("demo-app", Path::new("/c/out.toml"), &p);
        assert!(exported.contains(&format!("{}exported{}", p.ok, p.reset)));

        let cfg = Path::new("/p/.sbx.toml");
        let set = render_config_write("set", "env.FOO", cfg, &p);
        assert!(set.contains(&format!("{}set{}", p.ok, p.reset)));
        // Color replaces the backtick markup — the key rides the name hue, ticks dropped.
        assert!(set.contains(&format!("{}env.FOO{}", p.name, p.reset)));
        assert!(!set.contains('`'));
        let unchanged = render_config_unchanged("env.FOO", cfg, &p);
        assert!(
            unchanged.contains(p.dim),
            "a no-op config write must take the dim hue:\n{unchanged}"
        );
        let retrust = render_trusted_whole_file(cfg, &p);
        assert!(retrust.contains(&format!("{}trusted{}", p.ok, p.reset)));
    }
}
