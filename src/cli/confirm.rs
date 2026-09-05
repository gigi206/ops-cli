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

/// The confirmation that `sbx config add`/`rm` changed one entry of a list: the entry and the key it
/// moved in or out of, over the file it was written to. A pure presenter.
pub(crate) fn render_list_edit(
    done: &str,
    preposition: &str,
    entry: &str,
    key: &str,
    path: &Path,
    pal: &style::Palette,
) -> String {
    let (ok, n, r) = (pal.ok, pal.name, pal.reset);
    format!(
        "sbx: {ok}{done}{r} {} {preposition} {} in {n}{}{r}",
        style::paint_spans(&format!("`{entry}`"), pal.name, "", pal),
        style::paint_spans(&format!("`{key}`"), pal.name, "", pal),
        path.display()
    )
}

/// The no-op confirmation for `sbx config add`/`rm` when the list already reads that way — dimmed,
/// since nothing changed and so trust is not re-armed. A pure presenter.
pub(crate) fn render_list_unchanged(
    entry: &str,
    why: &str,
    key: &str,
    path: &Path,
    pal: &style::Palette,
) -> String {
    let (dim, r) = (pal.dim, pal.reset);
    format!(
        "sbx: {} {dim}{why}{r} {} {dim}in {} (no change){r}",
        style::paint_spans(&format!("`{entry}`"), pal.name, "", pal),
        style::paint_spans(&format!("`{key}`"), pal.name, "", pal),
        path.display()
    )
}

/// The no-op confirmation for `sbx config set` on a key that already holds the value asked for -
/// dimmed, since nothing was written and so trust is not re-armed. A pure presenter.
pub(crate) fn render_config_same_value(key: &str, path: &Path, pal: &style::Palette) -> String {
    let (dim, r) = (pal.dim, pal.reset);
    format!(
        "sbx: {} {dim}already reads that way in {} (no change){r}",
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
    let _ = write!(o, "  {dim}launch it with: sbx app run{r} {n}{name}{r}");
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
    scheme: Option<&str>,
    kind: crate::plugins::PluginKind,
    from_store: Option<&str>,
    pal: &style::Palette,
) -> String {
    let (ok, n, dim, r) = (pal.ok, pal.name, pal.dim, pal.reset);
    let from = match from_store {
        Some(s) => format!(" from store '{n}{s}{r}'"),
        None => String::new(),
    };
    // A resolver is placed under the namespace it answers for, so that is what the line shows. The
    // other kinds claim none and are reached by their name, which the line already carries — so
    // each is named by its type instead of by a namespace it does not have. The type is passed in
    // rather than inferred from the missing scheme: more than one kind has none, so "no scheme"
    // names nothing.
    let what = match scheme {
        Some(scheme) => format!("{scheme}://"),
        None => kind.token().to_string(),
    };
    format!(
        "{ok}installed{r} '{n}{name}{r}' {dim}({what}){r}{from} \
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

/// The trust-on-first-use caution for a freshly added store — yellow, since it pinned a key
/// nothing outside the store confirms. Three parts, deliberately separated: what happened, the key
/// itself on its own line, and the **next action** with the command it needs. The action is not
/// dimmed — a step the user is expected to take, rendered as grey prose between two other grey
/// sentences, reads as boilerplate and is skipped. The command carries `<the key you obtained>`
/// rather than the key just printed: pre-filling it would turn confirmation into a paste of what
/// the store itself supplied. Goes to stderr, so its palette is decided from stderr's stream.
pub(crate) fn render_store_tofu(pubkey_hex: &str, name: &str, pal: &style::Palette) -> String {
    let (warn, n, r) = (pal.warn, pal.name, pal.reset);
    format!(
        "{warn}⚠ pinned the key this store ships — nothing outside the store confirms it{r}\n\n  \
         pinned key: {n}{pubkey_hex}{r}\n\n  \
         next: get that key from a source this store does not control — its author, a release\n        \
         page, a channel you already trust — compare the two, then run:\n\n    \
         {n}sbx plugins store verify {name} --key <the key you obtained>{r}\n\n  {}\n",
        style::dim_prose(
            "until then the store works normally, and a later key change is refused.",
            pal
        )
    )
}

/// The confirmation that a store's key was matched against one supplied from elsewhere: `verified`
/// in green over the name, then what changed and what did not, dimmed. It names the flag exactly as
/// the listing shows it (`unconfirmed`), since a confirmation that describes the flag it clears
/// under some other name leaves the user unsure which one was cleared. `already` is the idempotent
/// case: the key was supplied out of band when the store was added.
pub(crate) fn render_store_verified(name: &str, already: bool, pal: &style::Palette) -> String {
    let (ok, n, r) = (pal.ok, pal.name, pal.reset);
    if already {
        return format!(
            "{ok}verified{r} store '{n}{name}{r}' {}",
            style::dim_prose(
                "— its key was supplied out of band when it was added; nothing to confirm",
                pal
            )
        );
    }
    format!(
        "{ok}verified{r} store '{n}{name}{r}' — the pinned key is the one you supplied\n  {}",
        style::dim_prose(
            "it is no longer flagged as unconfirmed. The key is unchanged, so every fetch \
             enforces exactly what it did before",
            pal
        )
    )
}

/// What `store add` says when no trust anchor was supplied: the key the store *ships*, shown
/// prominently, and the two commands that act on it — one pinning it, one accepting it unverified.
/// Nothing has been configured at this point; the key is shown so the decision is made with it in
/// view rather than after the fact.
///
/// It leads with what the key is worth: a key the store ships cannot authenticate the store,
/// because whoever controls the URL controls the key too. That is the whole difference between the
/// two commands below it, so it is stated before either.
pub(crate) fn render_store_needs_key(
    name: &str,
    url: &str,
    pubkey_hex: &str,
    pal: &style::Palette,
) -> String {
    let (warn, n, r) = (pal.warn, pal.name, pal.reset);
    format!(
        "{warn}this store needs a trust anchor{r} — it ships this key:\n\n    \
         {n}{pubkey_hex}{r}\n\n  {}\n\n  {}\n    sbx plugins store add --name {name} --url {url} \
         --key {n}{pubkey_hex}{r}\n\n  {}\n    sbx plugins store add --name {name} --url {url} \
         --trust\n",
        style::dim_prose(
            "a key the store ships confirms nothing: whoever controls the URL controls the key \
             and the signature over the catalogue alike. Accepting it only detects a LATER key \
             change.",
            pal
        ),
        style::dim_prose("if you verified this key out of band, pin it:", pal),
        style::dim_prose("to accept it unverified on first use (weaker):", pal),
    )
}

/// The alert shown before a key rotation, and the report shown after it — the same facts, in the
/// tense the moment calls for. A rotation is the one operation that makes a store's whole history
/// of signatures irrelevant and hands that authority to a new key, so both keys are shown in full
/// and what an unannounced rotation means is stated rather than implied.
pub(crate) fn render_store_rekey_alert(
    name: &str,
    old_hex: &str,
    new_hex: &str,
    pal: &style::Palette,
) -> String {
    let (warn, n, r) = (pal.warn, pal.name, pal.reset);
    format!(
        "{warn}⚠ SECURITY — you are about to change the signing identity of store \
         '{n}{name}{r}{warn}'{r}\n\n  \
         pinned now: {n}{old_hex}{r}\n  \
         replacing with: {n}{new_hex}{r}\n\n  {}\n",
        style::dim_prose(
            "everything signed by the old key stops being accepted, and everything the new key \
             signs starts being. A rotation the author announced is routine; an unannounced one \
             is indistinguishable from someone else taking over the repository.",
            pal
        )
    )
}

/// The report of a completed rotation: `rotated` in green over the name, the key now in force, the
/// one it replaced (so the change is on the record where it happened, not only in the alert that
/// preceded it), and — when the new key was taken from the store itself — that it carries the same
/// unconfirmed status a first-use acceptance does.
pub(crate) fn render_store_rekeyed(
    name: &str,
    old_hex: &str,
    new_hex: &str,
    tofu: bool,
    rev: u64,
    plugins: usize,
    pal: &style::Palette,
) -> String {
    let (ok, n, r) = (pal.ok, pal.name, pal.reset);
    let tail = if tofu {
        style::dim_prose(
            "it was taken from the store itself, so it is flagged as unconfirmed until a second \
             source confirms it",
            pal,
        )
    } else {
        style::dim_prose("the previous key is no longer accepted", pal)
    };
    format!(
        "{ok}rotated{r} the key of store '{n}{name}{r}' {}(rev {rev}, {plugins} plugin{}){}\n  \
         now pinned: {n}{new_hex}{r}\n  {}\n  {tail}",
        pal.dim,
        if plugins == 1 { "" } else { "s" },
        r,
        style::dim_prose(&format!("previously:  {old_hex}"), pal)
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
    for (pname, what, version) in plugins {
        // Already the whole label the caller wants shown — `pass://` for a resolver, `broker` for
        // a plugin that claims no namespace. Composed by the caller, because only it knows which
        // kind it holds.
        let _ = write!(o, "  {n}{pname}{r}  {dim}({what}){r}");
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
/// pure presenter over the published plugin lines as `(name, label)` pairs — the label already
/// spelled by the publisher, which is the only side that knows whether a plugin has a namespace to
/// name at all.
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
    for (name, label) in plugins {
        let _ = writeln!(o, "  {n}{name}{r}  {dim}({label}){r}");
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
/// advanced, or a `refetched store` line when the revision stayed where it was, dimmed because
/// nothing the rollback floor governs moved. A pure presenter.
///
/// The second line says *refetched* rather than "already at revision N" because that is what
/// happened: `update` clones the store afresh and exchanges the cache for the result, so a store
/// that republishes a different tree under the same `rev` has its new bytes installed here. The
/// floor is what it is documented to be, a revision that may not go backwards; it never made the
/// tree at one revision fixed, and a line reading as a no-op would say it did.
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
            "{dim}refetched store{r} '{n}{name}{r}' \
             {dim}(still revision {new_rev}, {count} plugin{plural}; the cache holds what the \
             store serves now){r}"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::PluginKind as Kind;

    /// An update that does not advance the revision is not an update that did nothing.
    ///
    /// `update` always clones the store afresh and exchanges the cache for it, so a store that
    /// republishes a different tree under the same `rev` is fetched and installed while the line
    /// reads as a no-op. The rollback floor is what it is documented to be — a revision may not go
    /// backwards — and it never claimed the tree at one revision is fixed. So the line has to say
    /// what happened: the cache was refetched, and the revision did not move.
    #[test]
    fn an_update_that_does_not_advance_still_says_the_cache_was_refetched() {
        let p = style::Palette::plain();
        let line = render_store_updated("hub", 5, 5, 1, &p);
        assert!(
            !line.contains("already at revision"),
            "the cache was replaced, so nothing may read as a no-op: {line}"
        );
        assert!(line.contains("refetched"), "{line}");
        assert!(line.contains("revision 5"), "{line}");
        assert!(line.contains("1 plugin"), "{line}");
    }

    #[test]
    fn transactional_confirmations_are_plain_text_when_uncolored() {
        // The OFF path the integration capture and the existing substring assertions rely on:
        // empty spans, byte-identical plain text. Each line of the original wording is preserved.
        let p = style::Palette::plain();
        assert_eq!(
            render_plugin_installed("pass", Some("pass"), Kind::Resolver, None, &p),
            "installed 'pass' (pass://) — remove with: sbx plugins rm pass"
        );
        assert_eq!(
            render_plugin_installed("vault", Some("vault"), Kind::Resolver, Some("hub"), &p),
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
            "⚠ pinned the key this store ships — nothing outside the store confirms it\n\n  \
             pinned key: ab12\n\n  \
             next: get that key from a source this store does not control — its author, a release\n        \
             page, a channel you already trust — compare the two, then run:\n\n    \
             sbx plugins store verify hub --key <the key you obtained>\n\n  \
             until then the store works normally, and a later key change is refused.\n"
        );
        assert_eq!(
            render_store_verified("hub", true, &p),
            "verified store 'hub' — its key was supplied out of band when it was added; \
             nothing to confirm"
        );
        assert_eq!(
            render_store_verified("hub", false, &p),
            "verified store 'hub' — the pinned key is the one you supplied\n  \
             it is no longer flagged as unconfirmed. The key is unchanged, so every fetch \
             enforces exactly what it did before"
        );
        assert_eq!(
            render_store_rekey_alert("hub", "ab12", "cd34", &p),
            "⚠ SECURITY — you are about to change the signing identity of store 'hub'\n\n  \
             pinned now: ab12\n  replacing with: cd34\n\n  \
             everything signed by the old key stops being accepted, and everything the new key \
             signs starts being. A rotation the author announced is routine; an unannounced one \
             is indistinguishable from someone else taking over the repository.\n"
        );
        assert_eq!(
            render_store_rekeyed("hub", "ab12", "cd34", false, 7, 2, &p),
            "rotated the key of store 'hub' (rev 7, 2 plugins)\n  now pinned: cd34\n  \
             previously:  ab12\n  the previous key is no longer accepted"
        );
        assert_eq!(
            render_store_rekeyed("hub", "ab12", "cd34", true, 7, 1, &p),
            "rotated the key of store 'hub' (rev 7, 1 plugin)\n  now pinned: cd34\n  \
             previously:  ab12\n  it was taken from the store itself, so it is flagged as \
             unconfirmed until a second source confirms it"
        );
        assert_eq!(
            render_store_needs_key("hub", "https://example.invalid/s.git", "ab12", &p),
            "this store needs a trust anchor — it ships this key:\n\n    ab12\n\n  \
             a key the store ships confirms nothing: whoever controls the URL controls the key \
             and the signature over the catalogue alike. Accepting it only detects a LATER key \
             change.\n\n  \
             if you verified this key out of band, pin it:\n    \
             sbx plugins store add --name hub --url https://example.invalid/s.git --key ab12\n\n  \
             to accept it unverified on first use (weaker):\n    \
             sbx plugins store add --name hub --url https://example.invalid/s.git --trust\n"
        );
        assert_eq!(
            render_store_configured(
                "hub",
                3,
                &[("vault", "vault://", "1.0"), ("pass", "pass://", "")],
                &p
            ),
            "configured store 'hub' (rev 3, 2 plugins):\n  vault  (vault://)  v1.0\n  pass  (pass://)\n"
        );
        assert_eq!(
            render_publish_key_warning(Path::new("/k/key.pem"), &p),
            "⚠ keep the signing key `/k/key.pem` secret — it is this store's identity"
        );
        assert_eq!(
            render_published(5, &[("vault", "vault://")], "deadbeef", &p),
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
            "refetched store 'hub' (still revision 5, 1 plugin; the cache holds what the store \
             serves now)"
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
             command: x\n    network: allowlist\n  launch it with: sbx app run demo-app"
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

        let installed = render_plugin_installed("pass", Some("pass"), Kind::Resolver, None, &p);
        assert!(installed.contains(&format!("{}installed{}", p.ok, p.reset)));
        assert!(installed.contains(&format!("'{}pass{}'", p.name, p.reset)));

        assert!(
            render_removed(Some("store"), "hub", &p)
                .contains(&format!("{}removed{}", p.ok, p.reset))
        );

        let tofu = render_store_tofu("ab12", "hub", &p);
        assert!(
            tofu.contains(p.warn),
            "the tofu caution must ride the warn hue:\n{tofu}"
        );
        assert!(tofu.contains(&format!("{}ab12{}", p.name, p.reset)));

        let needs = render_store_needs_key("hub", "https://example.invalid/s.git", "ab12", &p);
        assert!(
            needs.contains(p.warn),
            "the missing-anchor line must ride the warn hue:\n{needs}"
        );
        // The key is the one thing the user has to look at, on its own indented line and in the
        // name hue — both where it is shown and where it is pasted into the pinning command.
        assert_eq!(
            needs.matches(&format!("{}ab12{}", p.name, p.reset)).count(),
            2,
            "the key must stand out in the display and in the --key command:\n{needs}"
        );
        assert!(needs.contains(&format!("\n\n    {}ab12{}\n\n", p.name, p.reset)));

        let alert = render_store_rekey_alert("hub", "ab12", "cd34", &p);
        assert!(
            alert.contains(p.warn),
            "a key rotation must ride the warn hue:\n{alert}"
        );
        // Both keys stand out: the whole decision is comparing them.
        assert!(alert.contains(&format!("{}ab12{}", p.name, p.reset)));
        assert!(alert.contains(&format!("{}cd34{}", p.name, p.reset)));
        let rekeyed = render_store_rekeyed("hub", "ab12", "cd34", false, 7, 2, &p);
        assert!(rekeyed.contains(&format!("{}rotated{}", p.ok, p.reset)));

        let configured = render_store_configured("hub", 3, &[("vault", "vault://", "1.0")], &p);
        assert!(configured.contains(&format!("{}configured store{}", p.ok, p.reset)));
        assert!(configured.contains(&format!("{}vault{}", p.name, p.reset)));

        let keywarn = render_publish_key_warning(Path::new("/k/key.pem"), &p);
        assert!(
            keywarn.contains(p.warn),
            "the key caution must ride the warn hue:\n{keywarn}"
        );

        let published = render_published(5, &[("vault", "vault://")], "deadbeef", &p);
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
