//! The resolved configuration value types — the data model the resolution engine
//! ([`super::resolve`]) produces and the rest of the crate consumes. Pure data plus small
//! self-contained impls (parsing, display, base64); no I/O and no resolution policy.

use super::*;

/// Which provider realises a declared package, parsed from the mandatory backend
/// prefix on the value: `nix:<attr>`, `mise:<token>`, or `flake:<ref>`. There is no
/// bare form — a value without a recognized prefix is dropped with a warning, so a
/// package's source is always explicit and never silently mis-routed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Backend {
    /// `nix:<attr>` — a nixpkgs attribute, provisioned host-side into sbx's store
    /// (seeded, offline-reusable). nixpkgs is curated, so building it host-side is
    /// justified; realising it can run a build, so it is honored only from a trusted
    /// source.
    Nix(String),
    /// `mise:<token>` — a mise backend token (e.g. `aqua:example/demo-tool`, `bare-tool`,
    /// `npm:@scope/pkg`, or `nix:<pkg>` for nixhub), equipped in-cage globally via
    /// `mise use -g` (durable, on PATH, fetched at launch). The token after `mise:`
    /// is passed to mise verbatim — sbx adds no per-backend logic of its own.
    Mise(String),
    /// `flake:<ref>` — an arbitrary nix flake reference (e.g.
    /// `github:owner/repo#attr`), built **in-cage** with `nix build --out-link` into
    /// the project's own writable store. A third-party flake is uncurated, so unlike
    /// `nix:` it is *not* built host-side: its eval + build are contained by the cage
    /// (the same posture as the in-cage `mise:nix:` self-equip). On PATH at launch and
    /// later launches via a persistent out-link under the home.
    Flake(String),
    /// A `[flakes.<name>]` inline flake — the full `flake.nix` source written directly in the
    /// config, plus the output attribute to build. Unlike [`Backend::Flake`] (a reference to an
    /// external flake) the source is ours: sbx stages it, binds it read-only into the cage, and
    /// builds `path:<dir>#<attr>` **in-cage**, so the same containment as `flake:` applies to
    /// arbitrary inline build code. The out-link is keyed by the source's content hash, so editing
    /// the flake in the config rebuilds at the next launch. It floats — no persisted lock, no
    /// `sbx upgrade` — so inputs are pinned inside the `flake.nix` for reproducibility.
    FlakeInline { content: String, attr: String },
    /// `deb:<url>` — a prebuilt Debian package (a `.deb`) at an `https://` URL, provisioned
    /// **host-side** into sbx's store (seeded, offline-reusable, like `nix:`): sbx resolves the
    /// URL to a content hash, then builds a generated derivation that unpacks the `.deb` and
    /// `autoPatchelfHook`s it against a curated Electron/Chromium library set. Extraction runs no
    /// build script (`dontBuild`), so evaluating it host-side is safe (unlike a `flake:`). Meant
    /// for a GUI/desktop app distributed only as a `.deb`. Two forms: a direct `https://…/….deb`
    /// URL (a GitHub `…/releases/latest/download/<stable-name>.deb` URL already rolls forward), or
    /// `github:<owner>/<repo>` — which queries the repo's latest release and selects its linux
    /// `.deb` asset, so a project whose asset name embeds the version still rolls forward on
    /// `sbx upgrade`. The stored string is the raw locator (the URL or `github:<owner>/<repo>`);
    /// [`super::sandbox::deb`] dispatches on its shape.
    Deb(String),
    /// `appimage:<url>` — a prebuilt AppImage at an `https://` URL, provisioned **host-side** into
    /// sbx's store exactly like `deb:` (seeded, offline-reusable): sbx resolves the URL to a content
    /// hash, then builds a generated derivation that extracts the AppImage's squashfs and
    /// `autoPatchelfHook`s it against the same curated Electron/Chromium library set. Extraction runs
    /// no build script (`dontBuild`) — and, crucially, the AppImage is unpacked at BUILD time rather
    /// than self-mounted at runtime, since the runtime FUSE/namespace path is blocked by the cage's
    /// seccomp denylist. Meant for a GUI/desktop app distributed only as an `.AppImage`. Two forms: a
    /// direct `https://…/….AppImage` URL, or `github:<owner>/<repo>` — which queries the repo's
    /// latest release and selects its linux `.AppImage` asset, so a project whose asset name embeds
    /// the version still rolls forward on `sbx upgrade`. The stored string is the raw locator (the URL
    /// or `github:<owner>/<repo>`); [`super::sandbox::appimage`] dispatches on its shape.
    AppImage(String),
    /// `tarball:<url>` — a prebuilt application `.tar.gz`/`.tgz` at an `https://` URL, provisioned
    /// **host-side** into sbx's store exactly like `deb:`/`appimage:` (seeded, offline-reusable): sbx
    /// resolves the URL to a content hash, then builds a generated derivation that `tar -xz`-extracts
    /// it and `autoPatchelfHook`s it against the same curated Electron/Chromium library set.
    /// Extraction runs no build script (`dontBuild`) and happens at BUILD time (a plain `tar`, no
    /// runtime namespace op — the FUSE/namespace path is blocked in-cage), so evaluating it host-side
    /// is safe. Meant for a GUI/desktop app distributed only as a plain tarball. One form: a direct
    /// `https://…/….tar.gz` URL — the stored string is the raw locator;
    /// [`super::sandbox::tarball`] resolves and builds it.
    Tarball(String),
    /// `tarball:resolve` — the auto-upgrade form of [`Backend::Tarball`], for a prebuilt `.tar.gz`
    /// app whose download URL is version-stamped (no stable `latest` alias). Declared as a
    /// `[packages]` sentinel `<name> = "tarball:resolve"` paired with a `[tarball.<name>]` table
    /// (see [`RawResolve`]) carrying a `resolve` **command** that prints the newest release's
    /// download URL. sbx runs the command **sandboxed** (a hermetic bubblewrap cage with sbx's base
    /// tools + the app's own `nix:` `[packages]` on `PATH`), validates the printed URL, prefetches
    /// its hash, and pins it — so it seeds/pins/builds exactly like the direct form, but `sbx upgrade
    /// tarball` can re-run the command and roll the pin forward. The command is arbitrary code, so it
    /// comes only from a trusted layer and never runs for an untrusted one; its printed URL is
    /// re-validated by `is_valid_tarball_url` before any fetch.
    TarballResolve { command: Vec<String> },
    /// `deb:resolve` — the auto-upgrade form of [`Backend::Deb`], the exact `deb:` analogue of
    /// [`Backend::TarballResolve`]. Declared as a `[packages]` sentinel `<name> = "deb:resolve"`
    /// paired with a `[deb.<name>]` table (see [`RawResolve`]) carrying a `resolve` **command** that
    /// prints the newest release's `.deb` download URL. sbx runs the command sandboxed, validates the
    /// printed URL (`is_valid_deb_url`), prefetches its hash, and pins it — so it builds exactly like
    /// the direct `deb:` form, but `sbx upgrade deb` can re-run the command and roll the pin forward.
    /// Arbitrary code, so it comes only from a trusted layer and never runs for an untrusted one.
    DebResolve { command: Vec<String> },
    /// `appimage:resolve` — the auto-upgrade form of [`Backend::AppImage`], the exact `appimage:`
    /// analogue of [`Backend::TarballResolve`]/[`Backend::DebResolve`]. Declared as a `[packages]`
    /// sentinel `<name> = "appimage:resolve"` paired with an `[appimage.<name>]` table (see
    /// [`RawResolve`]) carrying a `resolve` **command** that prints the newest release's `.AppImage`
    /// download URL. sbx runs the command sandboxed, validates the printed URL
    /// (`is_valid_appimage_url`), prefetches its hash, and pins it — so it builds exactly like the
    /// direct `appimage:` form, but `sbx upgrade appimage` can re-run the command and roll the pin
    /// forward. Arbitrary code, so it comes only from a trusted layer and never runs for an untrusted
    /// one.
    AppImageResolve { command: Vec<String> },
}

impl Backend {
    /// The backend-specific locator as declared: the nixpkgs attribute, the mise
    /// token, or the flake reference. Used for display and as the value the
    /// provisioner consumes.
    pub(crate) fn locator(&self) -> &str {
        match self {
            Backend::Nix(attr) => attr,
            Backend::Mise(token) => token,
            Backend::Flake(reference) => reference,
            Backend::Deb(url) => url,
            Backend::AppImage(url) => url,
            Backend::Tarball(url) => url,
            // A fixed short token (the sentinel form), so `sbx config` reads `tarball:resolve`; the
            // actual command is not a one-line locator, and the per-project lock keys the pin by the
            // package name, not this string.
            Backend::TarballResolve { .. } => "resolve",
            // Same fixed short token as `TarballResolve`; the pin is keyed by the package name.
            Backend::DebResolve { .. } => "resolve",
            // Same fixed short token as the other resolvers; the pin is keyed by the package name.
            Backend::AppImageResolve { .. } => "resolve",
            // The output attribute — a short locator for display; the bulky flake source is not
            // itself a one-line locator (rendered as `flake (inline) #<attr>` by the config view).
            Backend::FlakeInline { attr, .. } => attr,
        }
    }

    /// A short label naming the provider, for `sbx config` and warnings.
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Backend::Nix(_) => "nix",
            Backend::Mise(_) => "mise",
            Backend::Flake(_) => "flake",
            Backend::Deb(_) => "deb",
            Backend::AppImage(_) => "appimage",
            Backend::Tarball(_) => "tarball",
            Backend::TarballResolve { .. } => "tarball",
            Backend::DebResolve { .. } => "deb",
            Backend::AppImageResolve { .. } => "appimage",
            Backend::FlakeInline { .. } => "flake",
        }
    }
}

/// A tool the configuration asks the sandbox to provide: a free `name` (the merge
/// key across layers and the on-disk root name) bound to a `backend` that names how
/// to realise it (a nixpkgs attribute host-side, or a mise token in-cage). Each
/// carries whether the layer that supplied its value is trusted, so the launcher can
/// decide — outside this pure layering — whether to provision it. Both backends are
/// security-relevant (each can fetch or build), so the decision is *deferred*, not
/// made here: this stage drops nothing for trust, it only records the verdict the
/// launcher will weigh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Package {
    /// The free label: merge key and on-disk root name.
    pub(crate) name: String,
    /// How to realise this package: a nixpkgs attribute (host-side) or a mise token
    /// (in-cage), parsed from the value's mandatory backend prefix.
    pub(crate) backend: Backend,
    /// The trust of the layer that supplied this value (global is always
    /// `Trusted`, by location; a project carries its own verdict). The full state
    /// is kept, not a bool, so a *changed* project is distinguished from a
    /// never-trusted one — they call for different action (re-approval vs first
    /// approval), and the build-vs-fetch relaxation still needs the distinction.
    pub(crate) state: TrustState,
}

/// A project's mise file as the resolved configuration sees it: the discovered
/// filename(s) for display, the trust verdict gating it, and the validated bytes
/// captured at load. The launcher maps a trusted mise `[env]` into the sandbox;
/// this records the file's presence, whether it would be honored, and the exact
/// content the verdict covers. `None` when the project declares no mise file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MiseConfig {
    /// The discovered filename(s), e.g. `.mise.toml` — for display only.
    pub(crate) name: String,
    /// The project's trust verdict — a mise file is honored only when `Trusted`.
    pub(crate) state: TrustState,
    /// The `(filename, bytes)` of each mise file, read once through the safety gate
    /// in [`load`] — the *exact* bytes the trust hash was computed over. The launcher
    /// materializes these for mise rather than letting it re-read from disk, so mise
    /// sees precisely the authorized, already-hashed content (closing the window
    /// between the trust check and the read). Empty when no mise file was safely
    /// readable — then `state` is `Untrusted` and nothing is honored.
    pub(crate) files: trust::MiseInputs,
}

/// The sandbox's resolved network posture. A security choice: honored from the
/// global config (trusted by location) or a trusted project, ignored from an
/// untrusted one. The default keeps the host network — there is no confidentiality
/// guarantee until the filtered-egress allowlist is enforced, so cutting the network
/// off entirely is the one posture that fully contains exfiltration today.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum NetworkPolicy {
    /// Keep the host network namespace (the default).
    #[default]
    Shared,
    /// A fresh, empty network namespace: the sandbox has no connectivity at all.
    Isolated,
    /// Filtered egress: the cage reaches only what the policy permits (an allow list with
    /// deny carve-outs), through a host-side proxy. Until that proxy is wired, the launcher
    /// treats this fail-closed (full isolation), never fail-open.
    Allowlist(crate::allowlist::EgressPolicy),
}

/// The sandbox's resolved GUI posture. A security choice, gated exactly like
/// [`NetworkPolicy`]: honored from the global config (trusted by location) or a trusted
/// project, ignored from an untrusted one. The default exposes no display — a graphical app
/// cannot reach the host's compositor. X11 is deliberately never offered (an X client could snoop
/// and drive every other window, which Wayland's per-client isolation prevents on a well-behaved
/// compositor).
///
/// The postures are ordered by host exposure: `None` < `Offscreen` < `Wayland`. `Offscreen` is
/// the posture of a browser engine that renders but never maps a window (a headless Chromium
/// driving page automation): it supplies what such an engine needs *in* the cage and grants no
/// host access at all, while `Wayland` additionally binds the compositor socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum GuiPolicy {
    /// No display access (the default): a graphical app cannot reach a compositor.
    #[default]
    None,
    /// Render off-screen: provision fonts and — under a filtering egress posture — import the
    /// proxy's CA into the cage's NSS database, without exposing any display. A headless browser
    /// needs both (it dies mid-render without fonts, and rejects every page without the CA, since
    /// it reads its own NSS store rather than the CA-file environment variables).
    Offscreen,
    /// Bind the host's Wayland compositor socket read-only so a graphical app can map a window.
    /// Carries everything `Offscreen` provides.
    Wayland,
}

impl GuiPolicy {
    /// Whether the cage hosts something that draws — a window under `Wayland`, or a page under
    /// `Offscreen`. The single predicate behind the in-cage rendering prerequisites (fonts, the
    /// NSS CA import, the network-namespace dummy interface), so they cannot drift apart as the
    /// postures grow.
    pub(crate) fn renders(self) -> bool {
        matches!(self, Self::Offscreen | Self::Wayland)
    }
}

/// A credential the egress proxy injects into matching outbound requests as an HTTP
/// header. The plaintext is deliberately **not** here — only how to obtain it host-side
/// at launch ([`SecretSource`]), where to inject it ([`Self::to`]), and how to shape it
/// ([`HeaderShape`]). Reading the source to a value happens later, host-side and
/// fail-closed, so this declaration carries no secret and is safe to log. A security
/// field: honored from the global config or a trusted project, dropped from an untrusted
/// one, and only effective under a network allowlist (the proxy that performs the
/// injection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeaderSecret {
    /// The credential's logical name — what the inventory lists and what a redacted value is
    /// named after. Defaults to the destination host when the declaration omits it. A label
    /// only: it never selects a source, so two secrets may share it (with a warning).
    pub(crate) name: String,
    /// A one-line description of what the credential is for, or `None`. Printed beside the name;
    /// validated free text (no control characters, length-capped).
    pub(crate) description: Option<String>,
    /// The resolver chain sbx reads the plaintext from at launch — host-side, never inside the
    /// cage — tried in order, the first that resolves winning (a later one is a fallback).
    pub(crate) sources: Vec<SecretSource>,
    /// The concrete host (and optional path) the injection is scoped to: a request to
    /// anything else never receives the header. A `*.` wildcard or `re:` regex is
    /// rejected at validation, so a credential reaches exactly one known destination.
    pub(crate) to: Rule,
    /// The header name to set, e.g. `Authorization`.
    pub(crate) header: String,
    /// How the plaintext becomes the header value.
    pub(crate) shape: HeaderShape,
}

impl HeaderSecret {
    /// A human label for `sbx config` — the resolver chain by locator (a variable name or file
    /// path), never a value. A single source reads as itself; a fallback chain is joined with
    /// `, then ` so the precedence is visible.
    pub(crate) fn describe_sources(&self) -> String {
        self.sources
            .iter()
            .map(SecretSource::describe)
            .collect::<Vec<_>>()
            .join(", then ")
    }
}

/// One resolver ref in a secret's source chain — where sbx reads the plaintext, host-side at
/// launch. Only the locator is kept here, never the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SecretSource {
    /// A host environment variable, by name (not its value).
    Env(String),
    /// An absolute host file path, read host-side and never bound into the cage.
    File(PathBuf),
    /// A SOPS-encrypted file, decrypted host-side with the `sops` CLI. `file` is the encrypted
    /// path (relative ones resolve against the project root); `key` is an optional dotted path
    /// into the decrypted document (`db.password`), or the whole file when absent.
    Sops { file: PathBuf, key: Option<String> },
    /// A resolver plugin claims this ref's scheme. The launcher runs the plugin host-side under
    /// least privilege, passing `locator` (the part after `scheme://`) and reading the plaintext
    /// from its stdout. The validated manifest travels with the source so the launch runs exactly
    /// the plugin the config layer validated.
    Plugin {
        plugin: crate::plugins::ResolverPlugin,
        locator: String,
    },
}

impl SecretSource {
    /// A human label for `sbx config` — the variable name, file path, or sops file/key, none of
    /// which is the secret itself.
    pub(crate) fn describe(&self) -> String {
        match self {
            SecretSource::Env(var) => format!("env {var}"),
            SecretSource::File(path) => format!("file {}", path.display()),
            SecretSource::Sops { file, key: Some(k) } => format!("sops {}#{k}", file.display()),
            SecretSource::Sops { file, key: None } => format!("sops {}", file.display()),
            SecretSource::Plugin { plugin, locator } => format!("{} {locator}", plugin.scheme),
        }
    }
}

/// How a header value is built from the plaintext: a `prefix` prepended to the secret,
/// the secret optionally base64-encoded first (HTTP Basic). `type = "bearer"` is
/// `prefix = "Bearer "`, `"raw"` is an empty prefix, `"basic"` is `prefix = "Basic "`
/// over base64; an explicit `prefix` overrides the type's default. The value never lives
/// here — [`Self::format`] takes the plaintext and returns the formed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeaderShape {
    pub(crate) prefix: String,
    pub(crate) base64: bool,
}

impl HeaderShape {
    /// Build the header value for `secret`: `prefix` then the secret, base64-encoded when
    /// `base64` (Basic auth, where the plaintext is a `user:pass` pair).
    pub(crate) fn format(&self, secret: &str) -> String {
        if self.base64 {
            format!("{}{}", self.prefix, base64_encode(secret.as_bytes()))
        } else {
            format!("{}{secret}", self.prefix)
        }
    }

    /// The secret-bearing byte strings that must never leave the cage verbatim in an outbound
    /// request — the needles of the egress leak tripwire. Always the raw plaintext (what
    /// `bearer`/`raw` carry on the wire after the static prefix), plus — when the shape
    /// base64-encodes it (Basic auth) — the base64 form, since that is what travels on the wire
    /// and is what a reflecting upstream echoes back. Built with the same `base64_encode`
    /// [`Self::format`] uses, so a needle matches the byte-for-byte wire form.
    pub(crate) fn needles(&self, secret: &str) -> Vec<Vec<u8>> {
        let mut out = vec![secret.as_bytes().to_vec()];
        if self.base64 {
            out.push(base64_encode(secret.as_bytes()).into_bytes());
        }
        out
    }

    /// Construct a shape directly — `prefix` prepended to the secret, base64-encoded first
    /// when `base64`. For tests that build an injection without parsing a `type`.
    #[cfg(test)]
    pub(crate) fn new(prefix: impl Into<String>, base64: bool) -> Self {
        Self {
            prefix: prefix.into(),
            base64,
        }
    }

    /// A short label for `sbx config` — the *effective* type, reconstructed from the
    /// shape, so `raw` with a `"Bearer "` prefix reads as `bearer` (the value is identical);
    /// a non-standard prefix is shown so the effective form is never hidden.
    pub(crate) fn describe(&self) -> String {
        match (self.base64, self.prefix.as_str()) {
            (true, "Basic ") => "basic".to_string(),
            (true, p) => format!("basic, prefix {p:?}"),
            (false, "Bearer ") => "bearer".to_string(),
            (false, "") => "raw".to_string(),
            (false, p) => format!("raw, prefix {p:?}"),
        }
    }
}

/// Standard base64 (RFC 4648) with `=` padding, for HTTP Basic credentials and — with the padding
/// trimmed — an ssh key fingerprint. Hand-rolled rather than pulling a dependency for one short,
/// well-specified transform.
pub(crate) fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

/// Where a resolved value came from — the provenance `sbx config` surfaces so a value's origin
/// is never a mystery. `Default` is sbx's built-in; `Global`/`Project` are the two config files.
/// A later layer overrides an earlier one at the same key, so for a value this is the *winning*
/// source. The launcher ignores it (provenance is a display affordance). Inheritance — an app
/// field taking the baseline's value — is a *display* concept derived at view time (the resolution
/// never inherits), so it lives only on the view-side [`view::ProvenanceView`](super::view), not
/// here.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(crate) enum Provenance {
    /// sbx's built-in default — no config layer set this value.
    #[default]
    Default,
    /// The global `sbx.toml` (trusted by location).
    Global,
    /// The project `.sbx.toml`.
    Project,
    /// A one-shot command-line/environment override (`--config`/`--env`/`SBX_*`), trusted by
    /// invocation — the final word, applied over every config layer.
    Override,
}

/// The per-field provenance of the cage's cgroup limits. Each of the three limits is a standalone
/// scalar with its own default, set independently by either config layer (the `env` model), so
/// each carries its own [`Provenance`].
#[derive(Clone, Copy, Default)]
pub(crate) struct LimitsOrigin {
    pub(crate) memory_high: Provenance,
    pub(crate) memory_max: Provenance,
    pub(crate) tasks_max: Provenance,
}

/// One resolved host bind: the canonical source/destination path and whether the cage may
/// write to it. Read-only (the default) exposes the path's *contents*; read-write additionally
/// lets the cage write *through* to the host path — strictly more privilege, so both are only
/// honored from a trusted source (an untrusted project gets no bind at all).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Bind {
    /// The host path, bound at the same absolute path inside the cage.
    pub(crate) path: PathBuf,
    /// Whether the cage may write through to the host path (`mode = "rw"`); read-only otherwise.
    pub(crate) writable: bool,
}

/// A validated declared operation: a fixed command sbx runs in an ephemeral sibling cage on a
/// caller's behalf, with a credential the caller never holds.
///
/// Everything a caller can influence is enumerated here — the declared [`params`](Self::params) and
/// the environment names in [`env_allow`](Self::env_allow). The program itself is not: `cmd[0]` is
/// resolved host-side against a tree no cage can write, which is what makes "sbx fixes the program"
/// true rather than aspirational.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskSpec {
    /// The task's name, as declared (`[task.<name>]`) — how a caller addresses it.
    pub(crate) name: String,
    /// The one-line description listed to a caller, or `None`.
    pub(crate) description: Option<String>,
    /// The command as an argv list, `{param}` placeholders unsubstituted. Never a shell string.
    pub(crate) cmd: Vec<String>,
    /// The declared parameters, in declaration order.
    pub(crate) params: Vec<TaskParam>,
    /// Credentials injected into the command's environment, keyed by variable name.
    pub(crate) secrets: Vec<TaskSecret>,
    /// Credentials injected on the wire by this task's own proxy — the plaintext never enters the
    /// task cage at all.
    pub(crate) injections: Vec<HeaderSecret>,
    /// Fixed environment from the declaration.
    pub(crate) env: BTreeMap<String, String>,
    /// The variable names a caller may set for one invocation. An allowlist of names.
    pub(crate) env_allow: Vec<String>,
    /// Whether the caller receives stdout.
    pub(crate) stdout: OutputDisposition,
    /// Whether the caller receives stderr.
    pub(crate) stderr: OutputDisposition,
    /// The wall-clock ceiling for one invocation.
    pub(crate) timeout: std::time::Duration,
    /// The captured-output ceiling per stream, in bytes. Output past it is truncated, and the
    /// truncation is reported — never silently dropped.
    pub(crate) max_output: u64,
    /// The egress the task cage gets, as classified allowlist rules. Empty means no network at all.
    pub(crate) network: Vec<Rule>,
    /// Whether a substituted credential is named with a per-invocation nonce (`${NAME@a91f3c}`)
    /// rather than the plain `${NAME}`. Inherited from `[task.defaults] nonce`, like the ceilings.
    pub(crate) nonce: bool,
    /// The mise tools this task's command needs, as **bare mise tokens** with the declaration's
    /// `mise:` prefix already stripped (`aqua:cli/gh`, `node@22`). They are installed host-side into
    /// the project's task pool, which the task cage mounts read-only — so the program a task runs
    /// comes from a tree no cage can write, exactly like a store-built package.
    pub(crate) packages: Vec<String>,
    /// Whether the invocation gets a writable output directory that outlives it, which `{out}` and
    /// `SBX_TASK_OUT` point at. Everything else a task cage can write dies with the invocation.
    pub(crate) output: bool,
    /// What the command may run beside itself, as declared. `None` is no exec supervision at all —
    /// the command runs as it always has. `Some` stands up a supervisor and confines the cage to the
    /// command plus these entries, **including when the list is empty** (a command that must run
    /// nothing else). Entries are declaration text; the launch resolves a bare name to the absolute
    /// in-cage path it will run as.
    pub(crate) spawn: Option<Vec<String>>,
    /// What each of *those* programs may run in turn, keyed by the entry that named it. Empty is the
    /// ordinary case: a program with no node of its own may run nothing.
    ///
    /// This is what lets a declaration permit a **chain** without granting a **shortcut**. A flat
    /// set that has to name `git`, `ssh` and `gpg` so that git can reach ssh and ssh can reach gpg
    /// also lets the command run `gpg` itself, with the credential in hand and nothing in between.
    /// A node reaching only the next link does not.
    pub(crate) exec: std::collections::BTreeMap<String, Vec<String>>,
    /// Where this operation's `[task.<name>]` block is. Display-only: it answers "which of my
    /// configs put this here?", which the name alone cannot once a project, an app and its bundles
    /// each contribute operations to one session. It decides nothing — a task's identity is its
    /// name, which is what the last-wins fold compares.
    ///
    /// It claims exactly what it says and no more: **where the block is**, not where every effective
    /// value came from. A ceiling the block does not set is inherited from a `[task.defaults]` in
    /// some layer, which may not be this one — [`timeout_from`](Self::timeout_from) and
    /// [`max_output_from`](Self::max_output_from) are what say so.
    pub(crate) origin: TaskOrigin,
    /// Where [`timeout`](Self::timeout) came from, when the task did not set it itself.
    pub(crate) timeout_from: Ceiling,
    /// Where [`max_output`](Self::max_output) came from, when the task did not set it itself.
    pub(crate) max_output_from: Ceiling,
}

/// Where a ceiling came from, for display. An operation is genuinely composed of two layers — its
/// own block plus whatever `[task.defaults]` it inherits — and naming only the block would let a
/// reader go and edit a file that does not contain the value they are looking at.
///
/// Only the two ceilings shown by `sbx task show` carry one. `nonce` is inherited the same way but
/// is not displayed, and provenance nothing reads is provenance that rots.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum Ceiling {
    /// The task's own `[task.<name>]` block set it. The ordinary case, and the one a reader assumes.
    #[default]
    Declared,
    /// A `[task.defaults]` table, in the layer named. Only the global config and a trusted project
    /// have one — an app tunes a ceiling on the task itself.
    Defaults(TaskOrigin),
    /// sbx's built-in ceiling: no config set one at all.
    BuiltIn,
}

impl Ceiling {
    /// How it reads beside the value, or `None` when the task declared the value itself — where
    /// saying so would repeat what the reader already assumes.
    pub(crate) fn label(&self) -> Option<String> {
        match self {
            Ceiling::Declared => None,
            Ceiling::Defaults(origin) => Some(format!("{} [task.defaults]", origin.label())),
            Ceiling::BuiltIn => Some("sbx default".to_string()),
        }
    }
}

/// Which layer an operation came from, for display.
///
/// A bundle keeps its own identity even though the load folds a bundle into the app that names it
/// before validation: "which app is this from" and "which tool did the app pull it in with" are
/// different answers, and the second is the one that says where to go and edit.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum TaskOrigin {
    /// The global config's own `[task]` section.
    #[default]
    Global,
    /// The project's `.sbx.toml` `[task]` section.
    Project,
    /// An app profile's `[task]` section, by app name.
    App(String),
    /// A bundle's `[task]` section, folded into an app that names it in `use`.
    Bundle(String),
}

impl TaskOrigin {
    /// How the origin reads in a listing: a kind, joined to a name by a colon where there is one.
    ///
    /// One token, `kind:name`, because that is how the rest of sbx already names a kind and its
    /// instance — `sbx session ls` shows `app:<name>` in its `KIND` column, and `sbx config show`
    /// tags a value `app:global`. A reader should not have to learn a second spelling per listing.
    pub(crate) fn label(&self) -> String {
        match self {
            TaskOrigin::Global => "global".to_string(),
            TaskOrigin::Project => "project".to_string(),
            TaskOrigin::App(name) => format!("app:{name}"),
            TaskOrigin::Bundle(name) => format!("bundle:{name}"),
        }
    }
}

/// Whether a captured stream is returned to the caller. Substitution of secret values happens
/// either way — `Hide` withholds the stream, it is not what protects the credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum OutputDisposition {
    /// Return the stream (after substitution). The default.
    #[default]
    Show,
    /// Withhold the stream; the caller still gets the exit status.
    Hide,
}

impl OutputDisposition {
    /// The declared spelling, for `sbx config`/`sbx task list`.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            OutputDisposition::Show => "show",
            OutputDisposition::Hide => "hide",
        }
    }
}

/// One declared parameter: the name a `{name}` placeholder in `cmd` refers to, the bound its value
/// must satisfy, and an optional default (which is what makes it optional).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskParam {
    pub(crate) name: String,
    pub(crate) bound: ParamBound,
    /// The value used when the caller supplies none. `None` makes the parameter required — a
    /// missing value is an error, never an empty substitution (`psql -c ""` is a different
    /// command than the one declared).
    pub(crate) default: Option<String>,
}

/// What a parameter's value must satisfy. Bounds are load-bearing, not ergonomics: a value loose
/// enough to embed a comparison can rebuild an exit-status oracle over the credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParamBound {
    /// The whole value must match this regular expression. Kept as the source pattern (validated
    /// compilable here) and compiled at invocation, so the spec stays comparable and cloneable.
    Pattern(String),
    /// The value must be one of these.
    Choices(Vec<String>),
}

/// One credential a task's command reads from its environment. The variable name **is** the
/// credential's name, so what a substituted value is reported as (`${PGPASSWORD}`) is what the
/// declaration already called it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskSecret {
    /// The environment variable the command reads.
    pub(crate) var: String,
    /// The resolver chain, tried in order — read host-side per invocation, never held for a session.
    pub(crate) sources: Vec<SecretSource>,
    /// How the resolved value is rendered into the variable.
    pub(crate) encode: Encoding,
    /// A one-line description for the inventory, or `None`.
    pub(crate) description: Option<String>,
}

/// How a resolved plaintext is rendered into a task's environment variable.
///
/// The set is deliberately **closed**: each variant must also be able to state its rendered form as
/// a substitution needle ([`Self::variants`]), so a value can never reach a text sink in a spelling
/// the substituter does not recognize. An open-ended transform would be a leak channel with a
/// friendly name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Encoding {
    /// The plaintext as-is.
    #[default]
    Raw,
    /// Standard base64 with padding.
    Base64,
    /// Percent-encoded for use inside a URL component.
    Url,
    /// Escaped as the inside of a JSON string (no surrounding quotes).
    JsonString,
}

impl Encoding {
    /// Parse the declared spelling.
    pub(crate) fn parse(s: &str) -> Option<Encoding> {
        match s {
            "raw" => Some(Encoding::Raw),
            "base64" => Some(Encoding::Base64),
            "url" => Some(Encoding::Url),
            "json-string" => Some(Encoding::JsonString),
            _ => None,
        }
    }

    /// The declared spelling, for `sbx config`/`sbx secret list`.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Encoding::Raw => "raw",
            Encoding::Base64 => "base64",
            Encoding::Url => "url",
            Encoding::JsonString => "json-string",
        }
    }

    /// Render the plaintext into the form the variable carries.
    pub(crate) fn render(self, plaintext: &str) -> String {
        match self {
            Encoding::Raw => plaintext.to_string(),
            Encoding::Base64 => base64_encode(plaintext.as_bytes()),
            Encoding::Url => percent_encode(plaintext),
            Encoding::JsonString => json_escape(plaintext),
        }
    }

    /// Every spelling of this value a text sink might carry: the plaintext **and** the rendered
    /// form. Both, because the command sees the rendered form while an error message it composes
    /// (or a log of what was resolved) may carry either. Registering both here is what makes
    /// "adding an encoding without its substitution variant" impossible.
    pub(crate) fn variants(self, plaintext: &str) -> Vec<Vec<u8>> {
        let mut out = vec![plaintext.as_bytes().to_vec()];
        let rendered = self.render(plaintext);
        if rendered.as_bytes() != out[0].as_slice() {
            out.push(rendered.into_bytes());
        }
        out
    }
}

/// Percent-encode everything outside the unreserved set (RFC 3986), so a value is safe inside any
/// URL component. Deliberately strict — `/`, `&`, `=`, `?` and `+` all encode — since a credential
/// in a URL must never be read as structure.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

/// Escape a value for use inside a JSON string literal (the caller supplies the quotes). Control
/// characters become `\uXXXX` escapes, so a value can neither close the string nor inject a
/// structural character.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every encoding must be able to state the spelling it produces, or a value could reach a text
    // sink in a form the substituter does not recognize. Pin render and variants together.
    #[test]
    fn every_encoding_registers_its_rendered_form_as_a_variant() {
        let plaintext = "p@ss word/1+2=3\n";
        for encoding in [
            Encoding::Raw,
            Encoding::Base64,
            Encoding::Url,
            Encoding::JsonString,
        ] {
            let rendered = encoding.render(plaintext);
            let variants = encoding.variants(plaintext);
            assert!(
                variants.contains(&plaintext.as_bytes().to_vec()),
                "{}: the plaintext is always a variant",
                encoding.as_str()
            );
            assert!(
                variants.contains(&rendered.clone().into_bytes()),
                "{}: the rendered form must be a variant, else it is unredactable",
                encoding.as_str()
            );
            assert_eq!(
                Encoding::parse(encoding.as_str()),
                Some(encoding),
                "the spelling round-trips"
            );
        }
    }

    // The renderings themselves: a credential must never be readable as structure by whatever
    // consumes it.
    #[test]
    fn the_encodings_render_their_declared_form() {
        assert_eq!(Encoding::Raw.render("a b"), "a b");
        assert_eq!(Encoding::Base64.render("foobar"), "Zm9vYmFy");
        assert_eq!(Encoding::Url.render("a b/c&d=e+f"), "a%20b%2Fc%26d%3De%2Bf");
        assert_eq!(
            Encoding::JsonString.render("say \"hi\"\n\\"),
            "say \\\"hi\\\"\\n\\\\"
        );
        assert_eq!(Encoding::JsonString.render("\u{1}"), "\\u0001");
    }

    // An unknown encoding is not a silent fallback to raw: it must fail validation, since the
    // author asked for a transform sbx cannot substitute back out.
    #[test]
    fn an_unknown_encoding_does_not_parse() {
        assert_eq!(Encoding::parse("rot13"), None);
        assert_eq!(Encoding::parse("RAW"), None);
    }

    #[test]
    fn base64_encode_matches_rfc_4648_vectors() {
        for (input, want) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(input.as_bytes()), want, "base64({input:?})");
        }
    }
}
