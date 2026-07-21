//! Project and global configuration: parse, layer the global and project files,
//! and gate the project's security-relevant fields by its trust.
//!
//! A config file is attacker-controlled the moment you `cd` into a cloned repo,
//! so reading one is itself a security operation. [`safety`] refuses any file that
//! is not a plain, owner-owned, non-world-writable regular file before its bytes
//! are ever acted on; the trust gate then decides whether the project's
//! security-relevant fields apply at all.
//!
//! The layering and gating ([`resolve`]) are pure — they turn already-read configs
//! and an already-decided trust verdict into the resolved set of environment and
//! binds — so the whole policy matrix is unit-testable without touching the
//! filesystem. [`load`] is the thin I/O around it, and is the one place that ties
//! a project's bytes, its trust verdict, and its parse together so all three act
//! on the same inode.

pub(crate) mod manage;
pub(crate) mod overrides;
pub(crate) mod safety;
mod schema;
pub(crate) mod view;

pub(crate) use overrides::{CliOverrides, Override};

use crate::allowlist::{Layer, Methods, Rule, RuleKind};
use crate::plugins::PluginRegistry;
use crate::trust::{self, TrustState};
use schema::{
    NetworkField, NetworkTable, RawApp, RawBind, RawConfig, RawHostSecret, RawHostSecrets,
    RawInlineFlake, RawResolve, RawSecretDefaults, SecretFrom,
};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};

/// The global config file name, under `…/sbx/`.
const GLOBAL_CONFIG: &str = "sbx.toml";
/// The project config file name, in the project root.
pub(crate) const PROJECT_CONFIG: &str = ".sbx.toml";
/// The source label a one-shot override's warnings carry, so a dropped/malformed override field
/// reads as `override: …` rather than as coming from a config file.
const OVERRIDE_SOURCE: &str = "override";
/// The directory of imported app profiles, beside the global config (`…/sbx/apps/`). A profile
/// is a standalone TOML file (a top-level [`schema::RawApp`]) whose *filename* is the app name;
/// it is trusted by location, exactly like the global config, so its apps join the global app
/// layer. (Note: under the *config* root this `apps` directory holds profiles, while under the
/// *data* root an `apps` directory holds each app's persistent home — two distinct trees.)
const PROFILES_DIR: &str = "apps";

/// Environment keys an *untrusted or changed* project may not set. The point is
/// not to contain the agent — in Mode B it already runs arbitrary code inside the
/// cage, so a config-set `LD_PRELOAD` grants it nothing new. It is to stop an
/// untrusted project from silently reconfiguring the *execution environment* of
/// the user's own later (Mode A) sessions and the trusted tools they run in that
/// project. So the list mirrors what glibc itself strips under `AT_SECURE`, for
/// exactly this threat: the dynamic loader (`LD_*`), the libraries that iconv /
/// locale / the resolver load by path (`GCONV_PATH`, `LOCPATH`, `NLSPATH`,
/// `RESOLV_HOST_CONF`, `HOSTALIASES`), glibc's tunables (`GLIBC_TUNABLES`), and
/// the shell startup hooks (`BASH_ENV`, `ENV`, `IFS`); plus the structural
/// userland sbx owns (`HOME`, `PATH`) and the loader the sandbox routes foreign
/// binaries through (`NIX_LD`, `NIX_LD_LIBRARY_PATH` — the same `AT_SECURE` concern
/// as `LD_*`, since they steer what code a foreign binary loads). A trusted config
/// is exempt — vouching for it honors the whole schema, and overriding these harms
/// only its own sandbox.
///
/// The cage carries a nix the agent self-equips with, so the three variables that
/// inject nix configuration (`NIX_CONFIG` inline, `NIX_USER_CONF_FILES` and
/// `NIX_CONF_DIR` pointing at config files) join the list: an untrusted project
/// could otherwise aim the *user's* later Mode-A nix at an attacker's substituter
/// with `require-sigs` off, serving backdoored binaries. In-cage this is not an
/// escalation (the agent already runs arbitrary code), but the same Mode-A
/// protection applies, so it is closed for symmetry — completely, since a single
/// missed pointer leaves the hole open.
///
/// Under a network allowlist the cage's only egress is the sbx-managed filtering
/// proxy (Model B): the proxy-control variables (`http_proxy`/`https_proxy`/
/// `all_proxy`/`no_proxy`, either case) and the CA-bundle variables the cage trusts
/// sbx's per-session CA through ([`crate::sandbox::egress::CA_FILE_ENV_KEYS`]) are
/// reserved for the same reason. In-cage a redirected proxy or a swapped CA only
/// fails closed (empty netns, sbx-minted certs), but the same Mode-A protection as
/// `NIX_CONFIG` applies, and the keys sbx *sets* are exactly the keys it protects.
fn is_reserved_env_key(key: &str) -> bool {
    key.starts_with("LD_")
        || is_proxy_env_key(key)
        // The CA-bundle keys are matched case-insensitively: env names are case-sensitive, but a
        // nonstandard tool reading a lowercase variant must not slip a swapped CA past the gate.
        || crate::sandbox::egress::CA_FILE_ENV_KEYS
            .iter()
            .any(|k| k.eq_ignore_ascii_case(key))
        || matches!(
            key,
            "HOME"
                | "PATH"
                | "NIX_LD"
                | "NIX_LD_LIBRARY_PATH"
                | "NIX_CONFIG"
                | "NIX_USER_CONF_FILES"
                | "NIX_CONF_DIR"
                | "BASH_ENV"
                | "ENV"
                // Interactive-shell code-exec hooks: bash runs `PROMPT_COMMAND` before each prompt
                // and evaluates `$(...)` in `PS1`, so an untrusted `[env]` setting them would run
                // code in the user's later Mode-A interactive `sbx run`, exactly like `BASH_ENV`/`ENV`.
                | "PROMPT_COMMAND"
                | "PS1"
                | "IFS"
                | "GCONV_PATH"
                | "GLIBC_TUNABLES"
                | "LOCPATH"
                | "NLSPATH"
                | "RESOLV_HOST_CONF"
                | "HOSTALIASES"
                // GPU driver-load paths: mesa's libgbm/libEGL `dlopen` a `<driver>_dri.so` / gbm
                // backend from these, so — like `LD_*`/`NIX_LD` — an untrusted `[env]` could aim a
                // trusted GPU-enabled app's mesa at an attacker `.so` in the project tree and run
                // code in the app's cage. Data-redirection vars (`FONTCONFIG_FILE`) stay free; these
                // are code-load paths. sbx sets them for `gpu = true`; a trusted config still may.
                | "LIBGL_DRIVERS_PATH"
                | "GBM_BACKENDS_PATH"
                | "__EGL_VENDOR_LIBRARY_DIRS"
        )
}

/// The proxy-control variables, matched case-insensitively (tools honor both
/// `http_proxy` and `HTTP_PROXY`). `no_proxy`/`all_proxy` and the WebSocket variants
/// (`ws_proxy`/`wss_proxy`, which sbx sets so a WS client routes through the proxy too)
/// are reserved alongside the HTTP ones, so an untrusted project can neither redirect the
/// cage's egress nor carve a hole around it.
fn is_proxy_env_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "http_proxy" | "https_proxy" | "all_proxy" | "no_proxy" | "ws_proxy" | "wss_proxy"
    )
}

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
/// cannot reach the host's compositor. `Wayland` binds the compositor socket read-only so a
/// window can map; X11 is deliberately never offered (an X client could snoop and drive every
/// other window, which Wayland's per-client isolation prevents on a well-behaved compositor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum GuiPolicy {
    /// No display access (the default): a graphical app cannot reach a compositor.
    #[default]
    None,
    /// Bind the host's Wayland compositor socket read-only so a graphical app can map a window.
    Wayland,
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
    prefix: String,
    base64: bool,
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

/// Standard base64 (RFC 4648) with `=` padding, for HTTP Basic credentials. Hand-rolled
/// rather than pulling a dependency for one short, well-specified transform.
fn base64_encode(input: &[u8]) -> String {
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

/// The resolved configuration the launcher applies: the layered environment and
/// the host binds, the declared tools, plus any warnings worth surfacing
/// (dropped fields, an unparseable or unsafe file). Nothing here is a hard error —
/// a missing or broken config yields empty defaults, never a failed launch.
#[derive(Clone)]
pub(crate) struct Resolved {
    /// Extra environment, in application order; a later entry overrides an earlier
    /// one at the same key.
    pub(crate) env: Vec<(String, String)>,
    /// Which layer each `env` key's winning value came from. Keyed by the env key (stable, so
    /// the lookup matches what `env` lists). A display affordance for `sbx config`; only the
    /// baseline resolution records it (an app overlay does not), and the launcher ignores it.
    pub(crate) env_layer: BTreeMap<String, Provenance>,
    /// Extra host paths to bind, each read-only or read-write.
    pub(crate) binds: Vec<Bind>,
    /// Which layer each effective bind came from, keyed by the *canonical* path `binds`
    /// lists (re-keyed after canonicalization in [`load`], so the lookup matches the displayed
    /// path). A display affordance for `sbx config`, recorded only at the baseline.
    pub(crate) bind_layer: BTreeMap<PathBuf, Provenance>,
    /// Declared tools, in declaration order, each tagged with its source's trust.
    /// Admission (and the nix work it implies) is the launcher's, not decided here.
    pub(crate) packages: Vec<Package>,
    /// The global config's `nixpkgs` override (trusted by location), or `None` for
    /// the default channel. Drives the base userland and is the default source for a
    /// project's tools.
    pub(crate) nixpkgs_global: Option<String>,
    /// A trusted project's `nixpkgs` override, or `None`. Pins *this project's* tools
    /// to its own source; an untrusted or changed project's value is dropped (it is a
    /// supply-chain-relevant choice), so this is never set from one.
    pub(crate) nixpkgs_project: Option<String>,
    /// The project's mise file, when one is present beside a `.sbx.toml`. Its tools
    /// are resolved (trusted-only) by a later stage; here it records the file's
    /// presence and the gating verdict. Discovered in [`load`] (it is I/O), so the
    /// pure [`resolve`] always leaves it `None`.
    pub(crate) mise: Option<MiseConfig>,
    /// The resolved network posture: the default (`Shared`) unless the global config
    /// or a trusted project asked for `"none"`. An untrusted project's choice is
    /// dropped with a warning — it may not narrow or widen the network.
    pub(crate) network: NetworkPolicy,
    /// Which layer supplied the winning `network` posture (`Default` when neither config set it).
    /// A display affordance for `sbx config`; the launcher ignores it.
    pub(crate) network_origin: Provenance,
    /// Whether the egress proxy records its per-host decision counters (`sbx net stats`). On by
    /// default; a trusted layer's `[network] stats = false` turns the audit off. Gated like the
    /// rest of `[network]` — an untrusted project's table (and so its `stats`) is dropped, so it
    /// cannot disable the auditing of its own egress. Baseline-only: a `stats` key inside an
    /// `[app.<name>.network]` table is ignored (warned), and `sbx config show --app` does not surface
    /// the inherited value — the app inherits this baseline.
    pub(crate) egress_stats: bool,
    /// The resolved process/exec posture: the default (`off`) unless the global config or a trusted
    /// project set a mode. An untrusted project's choice is dropped with a warning — it may not forge
    /// or loosen the enforcement of its own agent.
    pub(crate) proc: crate::proc_policy::ProcPolicy,
    /// Which layer supplied the winning `proc` posture (`Default` when neither config set it).
    pub(crate) proc_origin: Provenance,
    /// The resolved GUI posture: the default (`None`) unless the global config or a trusted
    /// project asked for `"wayland"`. An untrusted project's choice is dropped with a warning
    /// — it may not open a display.
    pub(crate) gui: GuiPolicy,
    /// Which layer supplied the winning `gui` posture (`Default` when neither config set it).
    pub(crate) gui_origin: Provenance,
    /// Whether hardware-accelerated GPU rendering is open (the default `false` unless the global
    /// config or a trusted project set `gpu = true`). A security field, gated like `gui` — an
    /// untrusted project may not open a render node and the `/sys` device tree.
    pub(crate) gpu: bool,
    /// Which layer supplied the winning `gpu` posture (`Default` when neither config set it).
    pub(crate) gpu_origin: Provenance,
    /// Whether audio (microphone + playback) is open (the default `false` unless the global config
    /// or a trusted project set `audio = true`). A security field, gated like `gui`/`gpu` — an
    /// untrusted project may not open the PulseAudio bus (which exposes the microphone and every
    /// system-audio `.monitor` source).
    pub(crate) audio: bool,
    /// Which layer supplied the winning `audio` posture (`Default` when neither config set it).
    pub(crate) audio_origin: Provenance,
    /// Whether the cage gets a private in-cage desktop portal (`dbus = true`; default `false` unless
    /// the global config or a trusted project set it). A security field, gated like `gui`/`gpu` — an
    /// untrusted project may not stand up an in-cage portal.
    pub(crate) dbus: bool,
    /// Which layer supplied the winning `dbus` posture (`Default` when neither config set it).
    pub(crate) dbus_origin: Provenance,
    /// Host loopback TCP ports forwarded into the cage (see [`RawConfig::forward`]). A security
    /// field, gated like `network`/`gui`; the merged set is the union of the global and a trusted
    /// project's ports (an untrusted project's ports are dropped, never added), so a trusted
    /// layer's ports survive an untrusted overlay. Empty when no layer declared any.
    pub(crate) forward: Vec<u16>,
    /// Which layer supplied the winning `forward` set. The union means a value here is the
    /// *highest-trust* layer that contributed any port (`Default` when none did). A display
    /// affordance for `sbx config`; the launcher ignores it.
    pub(crate) forward_origin: Provenance,
    /// The resolved cgroup resource limits (anti-DoS): the built-in defaults, with any field a
    /// trusted `[limits]` table (global or project) overrode. A security field, gated like
    /// `network`/`gui` — an untrusted project may not loosen a limit. Each of the three fields is
    /// layered independently (global under a trusted project), like `env`.
    pub(crate) limits: crate::sandbox::cgroup::Limits,
    /// The per-field provenance of `limits`: which layer set each of the three, or `Default` for a
    /// field no config overrode. A display affordance for `sbx config`.
    pub(crate) limits_origin: LimitsOrigin,
    /// The trusted relaxation of the cage's mandatory seccomp denylist (the built-in denylist plus
    /// any syscall a trusted `[seccomp] allow` re-permits). A security field, gated like
    /// `network`/`limits` — an untrusted project may not relax it. The default (empty) is the full
    /// mandatory denylist. The layering unions (a project adds to the global set), like `forward`.
    pub(crate) seccomp: crate::sandbox::seccomp::SeccompPolicy,
    /// Which layer supplied the seccomp relaxation — the highest-trust layer that lifted anything
    /// (`Default` when neither config did), like `forward_origin`. A display affordance for
    /// `sbx config`; the launcher ignores it.
    pub(crate) seccomp_origin: Provenance,
    /// Host device nodes granted into the cage from a trusted `[devices] allow` (each an absolute
    /// path under `/dev/`). A security field, gated like `network`/`seccomp` — an untrusted project
    /// may not expose a host device. The default (empty) leaves the cage's minimal, hostless `/dev`.
    /// The layering unions (a project adds to the global set), like `forward`; sorted and deduped.
    pub(crate) devices: Vec<PathBuf>,
    /// Which layer supplied the device grant — the highest-trust layer that granted anything
    /// (`Default` when neither config did), like `forward_origin`. A display affordance for
    /// `sbx config`; the launcher ignores it.
    pub(crate) devices_origin: Provenance,
    /// Credentials the egress proxy injects into matching requests (the plaintext never
    /// enters the cage). A security field, gated like `binds`; cleared with a warning
    /// unless the posture is an allowlist, since the filtering proxy is what injects them.
    pub(crate) secrets: Vec<HeaderSecret>,
    /// The baseline credentials *before* the posture clear — what an app overlay inherits. An app
    /// may open a filtering posture (`deny`/`allow`/`ask`) over a non-filtering baseline, in which
    /// case the proxy would inject these; [`Resolved::merge_app`] (and the `--app` view) re-derive
    /// the effective set from this, not from the posture-cleared `secrets`, so a baseline credential
    /// the baseline posture would clear is still inheritable. The baseline launch/display use
    /// `secrets`; only the per-app fold reads this.
    pub(crate) declared_secrets: Vec<HeaderSecret>,
    /// Named application launch profiles, each a gated overlay over this baseline. Keyed
    /// by name; `sbx app <name>` looks one up and folds it on with [`Resolved::merge_app`].
    /// `sbx run` ignore them.
    pub(crate) apps: BTreeMap<String, ResolvedApp>,
    /// Human-readable notes about what was dropped or ignored and why.
    pub(crate) warnings: Vec<String>,
}

/// Where an app's persistent `$HOME` (its config, login state, history) is keyed. The home
/// is always per-app and isolated from the project's default shell home; this chooses whether
/// it is *also* per-project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AppHomeScope {
    /// One home per app, shared across every project — the app keeps a single identity
    /// wherever it runs. The default. Carries a residual: an agent run on an untrusted
    /// project writes into the same home a trusted project's run uses (`"project"` isolates).
    Global,
    /// A home per (project, app) — what the agent writes in one project is invisible to
    /// another. Aligned with running an agent on untrusted code.
    Project,
}

/// An app's resolved overlay over the sandbox baseline: the command to run plus the extra
/// environment, binds, packages, network posture, and credentials it declares — each
/// already gated by the trust of the layer that supplied it (the global config, trusted by
/// location, or a project layer by its verdict). `sbx app <name>` folds this onto the
/// baseline with [`Resolved::merge_app`].
#[derive(Clone)]
pub(crate) struct ResolvedApp {
    /// The argv to run. Empty when no layer declared a `cmd` — a launch error, never a
    /// silent default.
    pub(crate) cmd: Vec<String>,
    /// Where this app's persistent home is keyed (`Global` by default). Integrity-gated like
    /// `cmd`: an untrusted project may set its own app's scope but not flip a trusted app from
    /// `Project` to `Global`.
    pub(crate) home_scope: AppHomeScope,
    /// Extra environment, in application order; folded over the baseline's so the app wins.
    pub(crate) env: Vec<(String, String)>,
    /// Extra host binds this app adds (absolute; canonicalized in [`load`], like the baseline),
    /// each read-only or read-write.
    pub(crate) binds: Vec<Bind>,
    /// Extra tools, each tagged with its source's trust; override a baseline tool by name.
    pub(crate) packages: Vec<Package>,
    /// The app's own network posture, set only when a trusted source declared one. `Some`
    /// overrides the baseline; `None` leaves the baseline posture in place.
    pub(crate) network: Option<NetworkPolicy>,
    /// The app's own process/exec posture, set only when a trusted source declared one. `Some`
    /// overrides the baseline; `None` leaves the baseline posture in place.
    pub(crate) proc: Option<crate::proc_policy::ProcPolicy>,
    /// The app's own GUI posture, set only when a trusted source declared one. `Some` overrides
    /// the baseline; `None` leaves the baseline posture in place.
    pub(crate) gui: Option<GuiPolicy>,
    /// The app's own GPU posture, set only when a trusted source declared one. `Some` overrides
    /// the baseline; `None` leaves the baseline posture in place. Gated like the app's `gui`.
    pub(crate) gpu: Option<bool>,
    /// The app's own audio posture, set only when a trusted source declared one. `Some` overrides
    /// the baseline; `None` leaves the baseline posture in place. Gated like the app's `gpu`.
    pub(crate) audio: Option<bool>,
    /// The app's own D-Bus posture, set only when a trusted source declared one. `Some` overrides
    /// the baseline; `None` leaves the baseline posture in place. Gated like the app's `gpu`.
    pub(crate) dbus: Option<bool>,
    /// The app's own cgroup limit overrides, set only from a trusted source (an untrusted
    /// project's app `[limits]` is dropped whole, like its `network`/`gui`). Each set field
    /// overrides the baseline at [`merge_app`]; an unset one keeps the baseline value. All-`None`
    /// means the app tunes nothing and inherits the baseline limits.
    pub(crate) limits: crate::sandbox::cgroup::Limits,
    /// The app's own seccomp relaxation, set only from a trusted source (an untrusted project's app
    /// `[seccomp]` is dropped, like its `network`/`limits`). Unions onto the baseline at
    /// [`merge_app`]; empty means the app relaxes nothing and inherits the baseline relaxation. A
    /// security field, gated like the baseline `[seccomp]`.
    pub(crate) seccomp: crate::sandbox::seccomp::SeccompPolicy,
    /// The app's own host device grant, set only from a trusted source (an untrusted project's app
    /// `[devices]` is dropped, like its `network`/`seccomp`). Unions onto the baseline at
    /// [`merge_app`]; empty means the app grants no device and inherits the baseline grant. A
    /// security field, gated like the baseline `[devices]`.
    pub(crate) devices: Vec<PathBuf>,
    /// The app's own host loopback forward ports, set only from a trusted source (an untrusted
    /// project's app `forward` is dropped, like its `network`/`gui`). The set **unions** onto the
    /// baseline's at [`merge_app`]; an empty vec means the app adds none and inherits the baseline
    /// set. A security field, gated like the baseline `forward`.
    pub(crate) forward: Vec<u16>,
    /// Credentials to inject for this app (gated; the plaintext never enters the cage).
    pub(crate) secrets: Vec<HeaderSecret>,
    /// The verbs this app's unscoped (`{...}`-less) allow rules default to — its read-by-default
    /// posture. Every Mode-B app defaults to `Only(["GET","HEAD"])`; an `[app.<name>.network]
    /// default_methods` override sets a different set (or `Any` for `["*"]`, all verbs). Applied to
    /// the app's effective allowlist at [`merge_app`]; the baseline `sbx run` never gets
    /// it (Mode A stays all-verbs).
    pub(crate) default_methods: crate::allowlist::Methods,
    /// Per-field provenance of this app's *scalar* overlay fields, for the per-app `sbx config`
    /// view — which app layer (`Global`/`Project`) set each. Read only when the app actually set
    /// the field; an unset scalar is shown as inherited from the baseline. `home_scope_origin` is
    /// `None` for the built-in default (`Global`), since the home scope is an app-only concept with
    /// no baseline to inherit. The launcher ignores all of these (a display affordance).
    pub(crate) cmd_origin: Provenance,
    pub(crate) network_origin: Provenance,
    pub(crate) proc_origin: Provenance,
    pub(crate) gui_origin: Provenance,
    pub(crate) gpu_origin: Provenance,
    pub(crate) audio_origin: Provenance,
    pub(crate) dbus_origin: Provenance,
    pub(crate) limits_origin: LimitsOrigin,
    /// Which app layer (`Global`/`Project`) supplied the app's own `forward` ports, or `Default`
    /// when the app declared none. The merged effective set is the app's own ∪ the baseline's;
    /// a port the app did not contribute is shown as inherited from the baseline.
    pub(crate) forward_origin: Provenance,
    /// Which app layer (`Global`/`Project`) supplied the app's own seccomp relaxation, or `Default`
    /// when the app declared none. The merged effective relaxation is the app's own ∪ the baseline's.
    pub(crate) seccomp_origin: Provenance,
    /// Which app layer (`Global`/`Project`) supplied the app's own device grant, or `Default` when
    /// the app declared none. The merged effective grant is the app's own ∪ the baseline's.
    pub(crate) devices_origin: Provenance,
    pub(crate) home_scope_origin: Option<Provenance>,
    /// Notes about what this app's resolution dropped or ignored — surfaced when the app is
    /// launched, not on every `sbx run`.
    pub(crate) warnings: Vec<String>,
}

impl Resolved {
    /// Fold an app's overlay onto this baseline with precedence **app > baseline**: the
    /// app's environment upserts over the baseline's, its packages override by name, its
    /// binds and credentials add, its network/GUI posture (when it set one) replaces the
    /// baseline's, and its cgroup limits override the baseline's per field. Every value was
    /// gated at resolve time, so this is a pure merge — no re-gating. The secret-vs-posture
    /// consistency is re-checked at the end, since the overlay can add secrets or change the
    /// posture.
    pub(crate) fn merge_app(&mut self, app: ResolvedApp) {
        for (key, val) in app.env {
            upsert(&mut self.env, key, val);
        }
        for pkg in app.packages {
            upsert_package(&mut self.packages, pkg.name, pkg.backend, pkg.state);
        }
        // Merge by *path*: an app bind whose path the baseline already exposes overrides it in
        // place (so a dest is never mounted twice, and the app's mode wins), consistent with how
        // every other overlay field resolves — `env`/`packages`/`network`/`gui` all let the app
        // win. Both layers are trusted, so this is a precedence choice, not a security one: an app
        // may thus flip a baseline bind's mode (ro↔rw) or add a new path.
        for bind in app.binds {
            if let Some(existing) = self.binds.iter_mut().find(|b| b.path == bind.path) {
                *existing = bind;
            } else {
                self.binds.push(bind);
            }
        }
        if let Some(network) = app.network {
            self.network = network;
        }
        // Apply the app's read-by-default verb posture to its *effective* allowlist — the app's own
        // (just merged) or, when the app set none, the inherited baseline. Only Mode-B `sbx app`
        // launches reach `merge_app`; `sbx run` (Mode A) never do, so they stay all-verbs.
        if let NetworkPolicy::Allowlist(policy) = &mut self.network {
            policy.apply_default_methods(&app.default_methods);
        }
        // The app's exec posture replaces the baseline's when it declared one (its own trusted
        // policy for its own agent); otherwise the baseline's stands.
        if let Some(proc) = app.proc {
            self.proc = proc;
        }
        if let Some(gui) = app.gui {
            self.gui = gui;
        }
        if let Some(gpu) = app.gpu {
            self.gpu = gpu;
        }
        if let Some(audio) = app.audio {
            self.audio = audio;
        }
        if let Some(dbus) = app.dbus {
            self.dbus = dbus;
        }
        // The app's ports union onto the baseline's — an app adds ports, never removes or
        // overrides the trusted baseline set (the flagship "agent on untrusted code" property,
        // which holds because the untrusted contribution was dropped at resolve time).
        union_forward(&mut self.forward, app.forward);
        overlay_limits(&mut self.limits, app.limits);
        // The app's seccomp relaxation unions onto the baseline's — an app adds lifts, never
        // removes the trusted baseline's (the flagship "agent on untrusted code" property, which
        // holds because the untrusted contribution was dropped at resolve time).
        self.seccomp.union(&app.seccomp);
        // The app's device grant unions onto the baseline's — an app adds devices, never removes
        // the trusted baseline's (the same flagship property, holding for the same reason).
        union_devices(&mut self.devices, app.devices);
        // Drop the baseline secret-posture warning: it judged the *baseline* network, but the app's
        // posture re-decides injection just below — keeping it would let `sbx app <name>` both inject
        // a credential and print "ignoring N HTTP-header secret(s)". The re-check re-emits it only if
        // the *merged* posture still drops them.
        self.warnings
            .retain(|w| !w.contains("HTTP-header secret(s)"));
        self.warnings.extend(app.warnings);
        // Re-derive the effective credentials from the *declared* baseline (not the posture-cleared
        // `secrets`), so an app that opens a filtering posture inherits a baseline credential the
        // baseline posture would have cleared. App credentials fold through the same `(to, header)`
        // upsert a single layer uses, so an app credential shadows its baseline twin (like
        // env/packages) instead of injecting a second identical header line upstream.
        self.secrets = self.declared_secrets.clone();
        for secret in app.secrets {
            upsert_secret(&mut self.secrets, &mut self.warnings, "app overlay", secret);
        }
        enforce_secret_posture(&self.network, &mut self.secrets, &mut self.warnings);
    }

    /// Apply a one-shot override's **nixpkgs channel**, if it set one, as the authoritative pin for
    /// this launch. Called from `prepare` *before* the lock target is chosen, because the channel
    /// decides which lock the whole launch (base userland and tools alike) resolves against — too
    /// late to set once [`crate::sandbox::effective_lock_target`] has read it.
    ///
    /// It reuses `nixpkgs_project` (the highest-precedence effective source), so an override wins
    /// over a trusted project's own pin. One display residual: the channel line then reads as a
    /// project-level source rather than "override" — the launched value is correct, only its label
    /// is coarse. The rest of the override is applied by [`Resolved::apply_override`], after any app
    /// overlay merges.
    /// A set-but-invalid channel is a **hard error** (`Err`): unlike a config layer, an override has
    /// no safe fallback — keeping the baseline would resolve a *different* source than the user's
    /// (mistyped) explicit one, a silent fail-open on a supply-chain field. The caller aborts the
    /// launch. `Ok(())` when the override set no channel or set a valid one.
    pub(crate) fn apply_override_channel(&mut self, ov: &Override) -> Result<(), String> {
        let Some(value) = ov.raw.nixpkgs.clone() else {
            return Ok(());
        };
        let mut notes = Vec::new();
        match validate_nixpkgs(&mut notes, OVERRIDE_SOURCE, value) {
            Some(valid) => {
                self.nixpkgs_project = Some(valid);
                Ok(())
            }
            None => Err(notes
                .into_iter()
                .next()
                .unwrap_or_else(|| format!("{OVERRIDE_SOURCE}: invalid `nixpkgs` value"))),
        }
    }

    /// Apply a one-shot override as the authoritative **final word** on this resolved configuration
    /// — after the project layer (for `sbx run`) or after a named app's overlay (for
    /// `sbx app`), so it beats both. Consumes the override. The nixpkgs channel is handled earlier
    /// by [`Resolved::apply_override_channel`] (the lock is already chosen by now), so it is skipped.
    ///
    /// Trusted **by invocation**: every field is honored, since the invoker owns the process argv
    /// and environment (no lower-trust context can reach them). This includes the two fields a config
    /// file gates trusted-only — `[seccomp]` (relax the syscall denylist) and `[devices]` (grant a
    /// host device): the justification is **parity with the trusted config** — the invoker strictly
    /// outranks any config layer, so it may declare exactly the relaxation/grant a *trusted* config
    /// already can. (Not the `network`/`binds` axis: relaxing the denylist re-permits a syscall whose
    /// only containment was the filter, widening the in-cage kernel attack surface.) Each field it
    /// sets is stamped
    /// [`Provenance::Override`] for `sbx config show`; its binds are canonicalized and its secret
    /// posture re-checked exactly as the layered fields are, so this is a faithful final layer, not
    /// a raw assignment. `[net.groups]`/`[app.*]` in an override are ignored (noticed at collection
    /// time), so they never reach here.
    ///
    /// A set-but-invalid **scalar security posture** (`network`/`gui`/`[limits]`) is a **hard error**
    /// (`Err`, the launch aborts): there is no safe fallback — silently keeping the baseline could
    /// leave a *wider* posture than the user's explicit (mistyped) intent, the exact fail-open this
    /// feature must not have. The additive fields (`env`/`binds`/`packages`/`seccomp`/`devices`)
    /// instead fail *closed* by dropping a bad entry (a missing bind, an unbuilt tool, an unknown
    /// syscall token, or a malformed device path is *less* capability/relaxation, never a wider
    /// posture), so they warn and skip rather than abort. On a hard error nothing is applied (the
    /// scalars are validated up front, before any mutation), so a caller that surfaces the error can
    /// still show the untouched baseline.
    pub(crate) fn apply_override(&mut self, ov: Override) -> Result<(), Vec<String>> {
        let Override { raw, .. } = ov;
        let RawConfig {
            env,
            binds,
            packages,
            network,
            gui,
            gpu,
            audio,
            dbus,
            limits,
            secret,
            forward,
            seccomp,
            devices,
            proc,
            // The channel is applied earlier (before the lock is chosen); groups/apps are not
            // launch-shaping and were noticed and dropped at collection time. An override's inline
            // `[flakes]`, `[tarball]`, `[deb]`, and `[appimage]` tables are dropped (fail-closed): a
            // one-shot `--config` blob is no place for a multiline `flake.nix` or an auto-upgrade
            // resolver command, so all are declared in a profile or project config.
            nixpkgs: _,
            net: _,
            app: _,
            flakes: _,
            tarball: _,
            deb: _,
            appimage: _,
        } = raw;

        // Validate the scalar security postures FIRST, into locals — a set-but-invalid one is fatal,
        // and nothing must be mutated before that verdict. Validation warnings accumulate locally so
        // a *fatal* one is promoted into the returned error (printed before aborting) rather than
        // lost with the dropped config; on success they merge into `self.warnings`.
        let mut notes = Vec::new();
        let (scalars, fatal) = build_override_scalars(
            &self.network,
            &self.proc,
            network,
            gui,
            proc,
            limits,
            &mut notes,
        );
        if !fatal.is_empty() {
            return Err(override_fatal_error(fatal, notes));
        }
        let OverrideScalars {
            network: new_network,
            gui: new_gui,
            proc: new_proc,
            limits: new_limits,
        } = scalars;

        // No fatal — apply. Promote the (non-fatal) validation notes to the resolved warnings.
        self.warnings.extend(notes);

        // `env` — a free field; upsert over the resolved set, stamping the override provenance.
        apply_env(
            &mut self.env,
            Some((Provenance::Override, &mut self.env_layer)),
            &mut self.warnings,
            OVERRIDE_SOURCE,
            env,
            false,
        );

        // `binds` — validate to absolute, canonicalize (as `load` does for the layered binds), then
        // merge by canonical path so the override's mode wins on a collision. The provenance is
        // recorded keyed by the *canonical* path, matching the displayed bind. Fail-closed: a
        // malformed/missing entry is warned and skipped (fewer binds, never a wider exposure).
        if !binds.is_empty() {
            let mut resolved_binds: Vec<Bind> = Vec::new();
            apply_binds(
                &mut resolved_binds,
                None,
                &mut self.warnings,
                OVERRIDE_SOURCE,
                binds,
            );
            let roots = sbx_control_plane_roots();
            for bind in canonicalize_binds(resolved_binds, &roots, &mut self.warnings) {
                self.bind_layer
                    .insert(bind.path.clone(), Provenance::Override);
                if let Some(existing) = self.binds.iter_mut().find(|b| b.path == bind.path) {
                    *existing = bind;
                } else {
                    self.binds.push(bind);
                }
            }
        }

        // `packages` — trusted by invocation; upsert by name over the resolved set.
        if !packages.is_empty() {
            apply_packages(
                &mut self.packages,
                &mut self.warnings,
                OVERRIDE_SOURCE,
                packages,
                TrustState::Trusted,
                false,
            );
        }

        // The scalar postures validated above.
        if let Some((policy, stats)) = new_network {
            if let Some(b) = stats {
                self.egress_stats = b;
            }
            self.network = policy;
            self.network_origin = Provenance::Override;
        }
        if let Some(policy) = new_gui {
            self.gui = policy;
            self.gui_origin = Provenance::Override;
        }
        // `proc` — the exec posture, validated above (a bad mode is fatal, like `gui`/`network`). The
        // override is the final word, so it may raise, lower, or disable enforcement for this launch
        // regardless of the config/app layers — an invoker disabling a trusted app's `enforce` for one
        // run is by design (top authority, the same as `--gpu=false`).
        if let Some(policy) = new_proc {
            self.proc = policy;
            self.proc_origin = Provenance::Override;
        }
        // `gpu` — a bool, so no value can be invalid (unlike `gui`/`network`); apply directly. The
        // override is trusted by invocation and the final word, so it may open or close GPU for this
        // launch regardless of the config layers.
        if let Some(value) = gpu {
            self.gpu = value;
            self.gpu_origin = Provenance::Override;
        }
        // `audio` — a bool, like `gpu`; apply directly. Trusted by invocation and the final word, so
        // it may open or close audio for this launch regardless of the config layers.
        if let Some(value) = audio {
            self.audio = value;
            self.audio_origin = Provenance::Override;
        }
        // `dbus` — a bool, like `gpu`/`audio`; apply directly. Trusted by invocation and the final
        // word, so it may stand up or drop the in-cage portal for this launch regardless of layers.
        if let Some(value) = dbus {
            self.dbus = value;
            self.dbus_origin = Provenance::Override;
        }
        if let Some(over) = new_limits {
            mark_limit_origins(&mut self.limits_origin, &over, Provenance::Override);
            overlay_limits(&mut self.limits, over);
        }

        // `forward` — trusted by invocation; the ports add to the effective set (a collection, so a
        // bad port — only `0` is possible after parse — is warned and skipped, not fatal). The
        // override is the final word and additive: its ports union onto the resolved set, and the
        // origin stamps `Override` when it contributes any (it cannot remove a baseline's ports,
        // matching the additive model of `--bind`/`--package`).
        if let Some(raw) = forward {
            let validated = validate_forward(&mut self.warnings, OVERRIDE_SOURCE, &raw);
            if !validated.is_empty() {
                self.forward_origin = Provenance::Override;
            }
            union_forward(&mut self.forward, validated);
        }

        // `[seccomp]` / `[devices]` — trusted by invocation, so the override may relax the mandatory
        // syscall denylist and grant a host device for this launch. Both are additive collections
        // (union onto the resolved policy/set; a bad token/path is warned and skipped by
        // `apply_seccomp`/`apply_devices`, never fatal — the invoker can only *add* here). The origin
        // stamps `Override` when the override contributed any, for `sbx config show`.
        if seccomp.is_some() {
            let over = apply_seccomp(&mut self.warnings, OVERRIDE_SOURCE, seccomp);
            if !over.is_empty() {
                self.seccomp.union(&over);
                self.seccomp_origin = Provenance::Override;
            }
        }
        if devices.is_some() {
            let over = apply_devices(&mut self.warnings, OVERRIDE_SOURCE, devices);
            if !over.is_empty() {
                union_devices(&mut self.devices, over);
                self.devices_origin = Provenance::Override;
            }
        }

        // `[secret]` — trusted by invocation; the credentials add to the effective set, resolved
        // through the override's own `[secret.defaults]`. The plaintext still never enters the cage
        // (the proxy injects it host-side). The secret↔posture invariant is re-checked against the
        // possibly-just-overridden posture below.
        if let Some(section) = secret {
            let defaults = section
                .defaults
                .as_ref()
                .map(SecretDefaults::from_raw)
                .unwrap_or_default();
            let plugins = match crate::store::Layout::from_env() {
                Some(layout) => PluginRegistry::load(&layout.plugins_dir(), &mut self.warnings),
                None => PluginRegistry::default(),
            };
            apply_secret_section(
                &mut self.secrets,
                &mut self.warnings,
                OVERRIDE_SOURCE,
                section.hosts,
                &defaults,
                &plugins,
            );
        }
        enforce_secret_posture(&self.network, &mut self.secrets, &mut self.warnings);
        Ok(())
    }

    /// Validate a one-shot override's scalar security postures **without applying anything**, so a
    /// launch can reject a mistyped value *before* the expensive channel/userland resolution rather
    /// than after. Same verdict [`Resolved::apply_override`] would reach for those fields (the
    /// baseline is the mode-inheritance parent — and a mode-less table never *fails*, only resolves
    /// to a different valid policy, so validating against the baseline catches exactly the fatal
    /// values an app overlay would too). Borrows the override, so the scalar fields are cloned.
    pub(crate) fn validate_override(&self, ov: &Override) -> Result<(), Vec<String>> {
        let mut notes = Vec::new();
        let (_, fatal) = build_override_scalars(
            &self.network,
            &self.proc,
            ov.raw.network.clone(),
            ov.raw.gui.clone(),
            ov.raw.proc.clone(),
            ov.raw.limits.clone(),
            &mut notes,
        );
        if fatal.is_empty() {
            Ok(())
        } else {
            Err(override_fatal_error(fatal, notes))
        }
    }
}

/// The validated scalar security postures a one-shot override sets: each `Some` only when the
/// override declared it and it validated. Built once by [`build_override_scalars`] and consumed by
/// both the pre-launch check ([`Resolved::validate_override`], which discards it) and the real
/// application ([`Resolved::apply_override`], which assigns from it).
#[derive(Default)]
struct OverrideScalars {
    /// The resolved network policy plus the egress-stats toggle the `[network]` table carried.
    network: Option<(NetworkPolicy, Option<bool>)>,
    gui: Option<GuiPolicy>,
    /// The resolved process/exec posture (`Some` only when the override set `proc` and it validated).
    proc: Option<crate::proc_policy::ProcPolicy>,
    limits: Option<crate::sandbox::cgroup::Limits>,
}

/// Validate an override's scalar security postures (`network`/`gui`/`[limits]`) against `baseline`
/// (the mode-inheritance parent). Returns the built policies and the list of *fatal* field names —
/// a set-but-invalid one, which has no safe fallback for an override. Non-fatal validator notes are
/// pushed to `notes`. Consuming (the fields move into the validators), so a borrowing caller clones.
#[allow(clippy::too_many_arguments)]
fn build_override_scalars(
    baseline: &NetworkPolicy,
    baseline_proc: &crate::proc_policy::ProcPolicy,
    network: Option<NetworkField>,
    gui: Option<String>,
    proc: Option<schema::ProcField>,
    limits: Option<schema::RawLimits>,
    notes: &mut Vec<String>,
) -> (OverrideScalars, Vec<String>) {
    let mut fatal = Vec::new();
    let mut scalars = OverrideScalars::default();

    if let Some(field) = network {
        let stats = network_stats_of(&field);
        warn_if_baseline_sets_default_methods(notes, OVERRIDE_SOURCE, &field);
        // An override has no `@group` vocabulary (groups are a global-config concept), so a
        // mode-less table inherits from `baseline` and an `@ref` fails closed at the matcher.
        let groups = build_net_groups(notes, BTreeMap::new());
        match validate_network(notes, OVERRIDE_SOURCE, field, &groups, baseline) {
            Some(policy) => scalars.network = Some((policy, stats)),
            None => fatal.push("network".to_string()),
        }
    }
    if let Some(value) = gui {
        match validate_gui(notes, OVERRIDE_SOURCE, value) {
            Some(policy) => scalars.gui = Some(policy),
            None => fatal.push("gui".to_string()),
        }
    }
    // `proc` — a mode-less `[proc]` table inherits `baseline_proc`'s mode (so a `--config` blob's
    // `[proc]\ndeny=[…]` keeps the effective mode); an *unknown* mode is fatal, exactly like `gui` —
    // keeping the baseline could leave *less* enforcement than the user's mistyped intent, a fail-open.
    if let Some(field) = proc {
        match validate_proc(notes, OVERRIDE_SOURCE, field, baseline_proc) {
            Some(policy) => scalars.proc = Some(policy),
            None => fatal.push("proc".to_string()),
        }
    }
    if let Some(raw_limits) = limits {
        // Which fields the override set — a set field that validates to `None` is invalid.
        let set = (
            raw_limits.memory_high.is_some(),
            raw_limits.memory_max.is_some(),
            raw_limits.tasks_max.is_some(),
        );
        let over = validate_limits(notes, OVERRIDE_SOURCE, Some(raw_limits));
        if set.0 && over.memory_high.is_none() {
            fatal.push("limits.memory_high".to_string());
        }
        if set.1 && over.memory_max.is_none() {
            fatal.push("limits.memory_max".to_string());
        }
        if set.2 && over.tasks_max.is_none() {
            fatal.push("limits.tasks_max".to_string());
        }
        scalars.limits = Some(over);
    }
    (scalars, fatal)
}

/// Assemble the hard-error message list for a one-shot override with invalid scalar values: a
/// summary naming the offending fields, then the specific validator notes (so the exact reason
/// survives the aborted launch, which discards `self.warnings`).
fn override_fatal_error(fatal: Vec<String>, notes: Vec<String>) -> Vec<String> {
    let fields = fatal
        .iter()
        .map(|f| format!("`{f}`"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut errs = vec![format!(
        "{OVERRIDE_SOURCE}: invalid value for {fields} — refusing to launch (a one-shot override \
         must be exact; it does not fall back to the baseline for a security field)"
    )];
    errs.extend(notes);
    errs
}

/// Warn about any `mise:nix:<pkg>` package. Routing `nix:` content through the mise backend pins the
/// install record app-global (Lane-1 `mise use -g`, so a global app's declared `mise:` tool installs
/// once and is shared) while the built store path is per-project — so the record and content misalign
/// across projects, the same failure the per-project mise split fixes for `nix:`-via-mise self-equips.
/// The fix is a plain `nix:<pkg>`, which is host-provisioned and seeded into each project's store,
/// per-project-aligned by construction — so this warns rather than rerouting. Trusted-only: a withheld
/// package never equips, so it stays silent. `source` prefixes the message (e.g. `` `app <name> ` ``).
fn warn_mise_nix_packages(source: &str, packages: &[Package], warnings: &mut Vec<String>) {
    for pkg in packages {
        if pkg.state != TrustState::Trusted {
            continue;
        }
        if let Backend::Mise(token) = &pkg.backend {
            if let Some(attr) = token.strip_prefix("nix:") {
                warnings.push(format!(
                    "{source}package `{}` uses `mise:nix:{attr}`: for a global app its install record \
                     is pinned app-global while its `/nix` store path is per-project, so it misaligns \
                     across projects — declare it as `nix:{attr}` (host-provisioned, \
                     per-project-aligned) instead",
                    pkg.name
                ));
            }
        }
    }
}

/// Layer the global config (trusted by location) under the project config, gating
/// the project's security-relevant fields by its trust verdict. Pure: the policy
/// matrix is decided here from already-read inputs.
///
/// Free fields (`env`) apply from any project, minus the reserved-key denylist for
/// an untrusted one. Security fields (`binds`) apply only from a trusted project;
/// an untrusted or since-changed project's binds are dropped with a warning.
fn resolve(
    mut global: RawConfig,
    mut project: Option<(RawConfig, TrustState)>,
    plugins: &PluginRegistry,
) -> Resolved {
    // Lift the app overlays out before the baseline fields are consumed below; they are
    // resolved and gated on their own at the end (each app a self-contained overlay).
    let global_apps = std::mem::take(&mut global.app);
    let project_apps = project
        .as_mut()
        .map(|(proj, state)| (std::mem::take(&mut proj.app), *state));

    let mut warnings = Vec::new();
    let mut env: Vec<(String, String)> = Vec::new();
    let mut env_layer: BTreeMap<String, Provenance> = BTreeMap::new();
    let mut binds: Vec<Bind> = Vec::new();
    let mut bind_layer: BTreeMap<PathBuf, Provenance> = BTreeMap::new();
    let mut packages: Vec<Package> = Vec::new();
    let mut secrets: Vec<HeaderSecret> = Vec::new();

    // Reusable egress groups are defined only in the global config (trusted by location) and
    // pre-classified once here; a `[network]` `allow`/`deny` list references one with `@<name>`.
    // A project's `[net.groups]` is a security-relevant input it may not supply, so it is ignored.
    let net_groups = build_net_groups(&mut warnings, std::mem::take(&mut global.net.groups));
    if let Some((proj, _)) = &project {
        if !proj.net.groups.is_empty() {
            warnings.push(format!(
                "{PROJECT_CONFIG}: ignoring `[net.groups]` — egress groups are defined in the \
                 global config only; a project's `[network]` may reference them with `@<name>`"
            ));
        }
    }

    // The global config is trusted by location, so it is honored in full: no
    // denylist, only key validation and the absolute-bind requirement.
    apply_env(
        &mut env,
        Some((Provenance::Global, &mut env_layer)),
        &mut warnings,
        GLOBAL_CONFIG,
        global.env,
        false,
    );
    apply_binds(
        &mut binds,
        Some((Provenance::Global, &mut bind_layer)),
        &mut warnings,
        GLOBAL_CONFIG,
        global.binds,
    );
    apply_tools(
        &mut packages,
        &mut warnings,
        GLOBAL_CONFIG,
        global.packages,
        global.flakes,
        global.tarball,
        global.deb,
        global.appimage,
        TrustState::Trusted,
        false,
    );
    let nixpkgs_global = global
        .nixpkgs
        .and_then(|v| validate_nixpkgs(&mut warnings, GLOBAL_CONFIG, v));
    // The network posture is trusted by location at the global layer; an invalid or
    // unset value falls back to the default (shared). The origin is recorded as `Global` only
    // when the layer actually supplied a valid posture, so a `Default` is never mistaken for one.
    let mut network_origin = Provenance::Default;
    // The egress-stats toggle rides the `[network]` table (the global layer is trusted by location);
    // extract it before the field moves into `validate_network`. Default on.
    let mut egress_stats = true;
    if let Some(b) = global.network.as_ref().and_then(network_stats_of) {
        egress_stats = b;
    }
    if let Some(field) = global.network.as_ref() {
        warn_if_baseline_sets_default_methods(&mut warnings, GLOBAL_CONFIG, field);
    }
    // The parent of the global layer is sbx's built-in default (`Shared`): a global `[network]`
    // table that omits `mode` has no lower posture to inherit, so it falls back to `deny`.
    let mut network = match global.network.and_then(|v| {
        validate_network(
            &mut warnings,
            GLOBAL_CONFIG,
            v,
            &net_groups,
            &NetworkPolicy::default(),
        )
    }) {
        Some(policy) => {
            network_origin = Provenance::Global;
            policy
        }
        None => NetworkPolicy::default(),
    };
    // The GUI posture is trusted by location at the global layer; an invalid or unset value
    // falls back to the default (no display).
    // The process/exec posture is trusted by location at the global layer. `parent` is the built-in
    // default (off) — the global layer has no lower config to inherit a table's omitted mode from.
    let mut proc_origin = Provenance::Default;
    let mut proc = match global.proc.and_then(|v| {
        validate_proc(
            &mut warnings,
            GLOBAL_CONFIG,
            v,
            &crate::proc_policy::ProcPolicy::off(),
        )
    }) {
        Some(policy) => {
            proc_origin = Provenance::Global;
            policy
        }
        None => crate::proc_policy::ProcPolicy::off(),
    };
    let mut gui_origin = Provenance::Default;
    let mut gui = match global
        .gui
        .and_then(|v| validate_gui(&mut warnings, GLOBAL_CONFIG, v))
    {
        Some(policy) => {
            gui_origin = Provenance::Global;
            policy
        }
        None => GuiPolicy::default(),
    };
    // The GPU posture is trusted by location at the global layer; the origin records `Global`
    // whenever the layer set the flag at all (so `gpu = true` reads distinctly from the default).
    let mut gpu_origin = Provenance::Default;
    let mut gpu = match global.gpu {
        Some(value) => {
            gpu_origin = Provenance::Global;
            value
        }
        None => false,
    };
    // The audio posture is trusted by location at the global layer; the origin records `Global`
    // whenever the layer set the flag at all (so `audio = true` reads distinctly from the default).
    let mut audio_origin = Provenance::Default;
    let mut audio = match global.audio {
        Some(value) => {
            audio_origin = Provenance::Global;
            value
        }
        None => false,
    };
    // The D-Bus posture is trusted by location at the global layer; the origin records `Global`
    // whenever the layer set the flag at all (so `dbus = true` reads distinctly from the default).
    let mut dbus_origin = Provenance::Default;
    let mut dbus = match global.dbus {
        Some(value) => {
            dbus_origin = Provenance::Global;
            value
        }
        None => false,
    };
    // `forward` ports are trusted by location at the global layer; each invalid port is dropped
    // (warned) and the rest kept. The merged set is a union (a project adds ports, never
    // replaces), so the origin is `Global` only when this layer contributed any port.
    let mut forward_origin = Provenance::Default;
    let mut forward = global
        .forward
        .as_deref()
        .map(|r| validate_forward(&mut warnings, GLOBAL_CONFIG, r))
        .unwrap_or_default();
    if !forward.is_empty() {
        forward_origin = Provenance::Global;
    }
    // Resource limits are trusted by location at the global layer; each invalid field is dropped
    // (warned) and the built-in default kept. The origin is recorded per field that the layer set.
    let mut limits = validate_limits(&mut warnings, GLOBAL_CONFIG, global.limits);
    let mut limits_origin = LimitsOrigin::default();
    mark_limit_origins(&mut limits_origin, &limits, Provenance::Global);
    // The seccomp relaxation is trusted by location at the global layer; a bad `allow` entry is
    // dropped (warned) and the rest kept. A project's unions onto this, so the origin records
    // `Global` only when this layer actually lifted something.
    let mut seccomp = apply_seccomp(&mut warnings, GLOBAL_CONFIG, global.seccomp);
    let mut seccomp_origin = if seccomp.is_empty() {
        Provenance::Default
    } else {
        Provenance::Global
    };
    // The device grant is trusted by location at the global layer; a bad entry is dropped (warned)
    // and the rest kept. A project's unions onto this, so the origin records `Global` only when this
    // layer actually granted a device.
    let mut devices = apply_devices(&mut warnings, GLOBAL_CONFIG, global.devices);
    let mut devices_origin = if devices.is_empty() {
        Provenance::Default
    } else {
        Provenance::Global
    };
    // Secrets are trusted by location at the global layer. The `[secret.defaults]` table is
    // captured for the global hosts and as the base a trusted project may extend.
    let mut secret_defaults = SecretDefaults::default();
    if let Some(section) = global.secret {
        if let Some(raw_defaults) = &section.defaults {
            secret_defaults = SecretDefaults::from_raw(raw_defaults);
        }
        apply_secret_section(
            &mut secrets,
            &mut warnings,
            GLOBAL_CONFIG,
            section.hosts,
            &secret_defaults,
            plugins,
        );
    }

    let mut nixpkgs_project = None;
    // The secret resolver defaults a PROJECT-LOCAL app resolves against: the global defaults, plus
    // a trusted project's own `[secret.defaults]` (captured below), so an app declared in the
    // project's `.sbx.toml` honors the project's resolver order/bindings. A GLOBAL app keeps the
    // global defaults, so a project can never steer how a globally-declared app's credentials
    // resolve. Stays global when there is no project or the project sets no `[secret.defaults]`.
    let mut project_secret_defaults = secret_defaults.clone();
    if let Some((proj, state)) = project {
        let trusted = state == TrustState::Trusted;
        // `env` is a free field — applied from any project, minus the reserved-key
        // denylist for an untrusted or changed one.
        apply_env(
            &mut env,
            Some((Provenance::Project, &mut env_layer)),
            &mut warnings,
            PROJECT_CONFIG,
            proj.env,
            !trusted,
        );
        // `binds` is a security field — honored only from a trusted project.
        if !proj.binds.is_empty() {
            if trusted {
                apply_binds(
                    &mut binds,
                    Some((Provenance::Project, &mut bind_layer)),
                    &mut warnings,
                    PROJECT_CONFIG,
                    proj.binds,
                );
            } else {
                warnings.push(dropped_binds_warning(state, proj.binds.len()));
            }
        }
        // `packages` are carried with the project's trust stamped on each — never
        // dropped here. Whether an untrusted project's tools are actually realised
        // is the launcher's call, the one place that can weigh it against the work
        // a tool would have to build.
        apply_tools(
            &mut packages,
            &mut warnings,
            PROJECT_CONFIG,
            proj.packages,
            proj.flakes,
            proj.tarball,
            proj.deb,
            proj.appimage,
            state,
            false,
        );
        // `nixpkgs` is a security field — a trusted project may pin its tools'
        // source; an untrusted or changed one may not point the catalogue elsewhere.
        if let Some(value) = proj.nixpkgs {
            if trusted {
                nixpkgs_project = validate_nixpkgs(&mut warnings, PROJECT_CONFIG, value);
            } else {
                warnings.push(format!(
                    "{PROJECT_CONFIG}: ignoring `nixpkgs` override ({})",
                    untrusted_reason(state)
                ));
            }
        }
        // `network` is a security field — a trusted project may change the posture;
        // an untrusted or changed one may not narrow or widen the network.
        if let Some(value) = proj.network {
            if trusted {
                // The stats toggle rides the same trusted `[network]` table — honor it before the
                // field moves into `validate_network`, so a trusted project may turn its own audit
                // off (or back on). An untrusted project never reaches here, so it cannot.
                if let Some(b) = network_stats_of(&value) {
                    egress_stats = b;
                }
                warn_if_baseline_sets_default_methods(&mut warnings, PROJECT_CONFIG, &value);
                // A project `[network]` table without a `mode` inherits it from the resolved global
                // posture (`network` as it stands after the global layer).
                if let Some(policy) =
                    validate_network(&mut warnings, PROJECT_CONFIG, value, &net_groups, &network)
                {
                    network = policy;
                    network_origin = Provenance::Project;
                }
            } else {
                warnings.push(format!(
                    "{PROJECT_CONFIG}: ignoring `network` policy ({})",
                    untrusted_reason(state)
                ));
            }
        }
        // `proc` is a security field — a trusted project may set its agent's exec posture; an
        // untrusted or changed one may not forge or loosen the enforcement of its own agent.
        if let Some(value) = proj.proc {
            if trusted {
                // A project `[proc]` table without a `mode` inherits it from the resolved global
                // posture (`proc` as it stands after the global layer).
                if let Some(policy) = validate_proc(&mut warnings, PROJECT_CONFIG, value, &proc) {
                    proc = policy;
                    proc_origin = Provenance::Project;
                }
            } else {
                warnings.push(format!(
                    "{PROJECT_CONFIG}: ignoring `proc` policy ({})",
                    untrusted_reason(state)
                ));
            }
        }
        // `gui` is a security field — a trusted project may open a display; an untrusted or
        // changed one may not (exposing a compositor socket is a confidentiality and integrity
        // choice an untrusted project must not make).
        if let Some(value) = proj.gui {
            if trusted {
                if let Some(policy) = validate_gui(&mut warnings, PROJECT_CONFIG, value) {
                    gui = policy;
                    gui_origin = Provenance::Project;
                }
            } else {
                warnings.push(format!(
                    "{PROJECT_CONFIG}: ignoring `gui` posture ({})",
                    untrusted_reason(state)
                ));
            }
        }
        // `gpu` is a security field — a trusted project may open GPU rendering; an untrusted or
        // changed one may not (a render node and the `/sys` device tree widen the kernel attack
        // surface, a choice an untrusted project must not make).
        if let Some(value) = proj.gpu {
            if trusted {
                gpu = value;
                gpu_origin = Provenance::Project;
            } else {
                warnings.push(format!(
                    "{PROJECT_CONFIG}: ignoring `gpu` posture ({})",
                    untrusted_reason(state)
                ));
            }
        }
        // `audio` is a security field — a trusted project may open audio; an untrusted or changed one
        // may not (the PulseAudio bus exposes the microphone and every system-audio `.monitor`
        // source, a choice an untrusted project must not make).
        if let Some(value) = proj.audio {
            if trusted {
                audio = value;
                audio_origin = Provenance::Project;
            } else {
                warnings.push(format!(
                    "{PROJECT_CONFIG}: ignoring `audio` posture ({})",
                    untrusted_reason(state)
                ));
            }
        }
        // `dbus` is a security field — a trusted project may stand up the in-cage portal; an
        // untrusted or changed one may not (a session bus, near the keyring and the portals, is a
        // choice an untrusted project must not make).
        if let Some(value) = proj.dbus {
            if trusted {
                dbus = value;
                dbus_origin = Provenance::Project;
            } else {
                warnings.push(format!(
                    "{PROJECT_CONFIG}: ignoring `dbus` posture ({})",
                    untrusted_reason(state)
                ));
            }
        }
        // `forward` is a security field — a trusted project may add host loopback forward ports;
        // an untrusted or changed one may not (opening a host port is a deliberate inbound hole).
        // The ports union onto the global set: a project adds, never replaces (the flagship
        // property holds because the untrusted contribution is dropped here, before the union).
        if let Some(raw) = proj.forward {
            if trusted {
                let project_forward = validate_forward(&mut warnings, PROJECT_CONFIG, &raw);
                if !project_forward.is_empty() {
                    forward_origin = Provenance::Project;
                }
                union_forward(&mut forward, project_forward);
            } else {
                warnings.push(format!(
                    "{PROJECT_CONFIG}: ignoring `forward` ports ({})",
                    untrusted_reason(state)
                ));
            }
        }
        // `[limits]` is a security field — a trusted project may tune the cgroup limits; an
        // untrusted or changed one may not (loosening them weakens the anti-DoS control). The
        // three fields layer independently: a project's set field overrides the global one, an
        // unset field keeps the global (or built-in) value — the `env` model, not a wholesale
        // replace, since each limit is a standalone scalar with its own default.
        if let Some(raw) = proj.limits {
            if trusted {
                let project_limits = validate_limits(&mut warnings, PROJECT_CONFIG, Some(raw));
                mark_limit_origins(&mut limits_origin, &project_limits, Provenance::Project);
                overlay_limits(&mut limits, project_limits);
            } else {
                warnings.push(format!(
                    "{PROJECT_CONFIG}: ignoring `[limits]` ({})",
                    untrusted_reason(state)
                ));
            }
        }
        // `[seccomp]` is a security field — a trusted project may relax the denylist; an untrusted
        // or changed one may not (loosening the kernel-attack-surface control). The relaxation
        // unions onto the global set: a project adds lifts, never removes (the flagship property
        // holds because the untrusted contribution is dropped here, before the union).
        if let Some(raw) = proj.seccomp {
            if trusted {
                let project_seccomp = apply_seccomp(&mut warnings, PROJECT_CONFIG, Some(raw));
                if !project_seccomp.is_empty() {
                    seccomp_origin = Provenance::Project;
                }
                seccomp.union(&project_seccomp);
            } else {
                warnings.push(format!(
                    "{PROJECT_CONFIG}: ignoring `[seccomp]` ({})",
                    untrusted_reason(state)
                ));
            }
        }
        // `[devices]` is a security field — a trusted project may grant a host device; an untrusted
        // or changed one may not (exposing a device widens the kernel attack surface). The grant
        // unions onto the global set: a project adds devices, never removes (the flagship property
        // holds because the untrusted contribution is dropped here, before the union).
        if let Some(raw) = proj.devices {
            if trusted {
                let project_devices = apply_devices(&mut warnings, PROJECT_CONFIG, Some(raw));
                if !project_devices.is_empty() {
                    devices_origin = Provenance::Project;
                }
                union_devices(&mut devices, project_devices);
            } else {
                warnings.push(format!(
                    "{PROJECT_CONFIG}: ignoring `[devices]` ({})",
                    untrusted_reason(state)
                ));
            }
        }
        // The `[secret]` section is a security field — a trusted project may inject
        // credentials (and extend the resolver defaults); an untrusted or changed one may
        // not (it would aim the user's secrets at a host of its choosing). The whole
        // section — defaults included — is dropped, with one count warning.
        if let Some(section) = proj.secret {
            if trusted {
                let effective = match &section.defaults {
                    Some(raw_defaults) => secret_defaults.merged_with(raw_defaults),
                    None => secret_defaults.clone(),
                };
                // Carry these merged defaults to the project's own apps (below).
                project_secret_defaults = effective.clone();
                apply_secret_section(
                    &mut secrets,
                    &mut warnings,
                    PROJECT_CONFIG,
                    section.hosts,
                    &effective,
                    plugins,
                );
            } else {
                let n = count_host_secrets(&section.hosts);
                if n > 0 {
                    warnings.push(format!(
                        "{PROJECT_CONFIG}: ignoring {n} secret(s) ({})",
                        untrusted_reason(state)
                    ));
                }
            }
        }
    }

    // Capture the declared baseline credentials before the posture clear: an app overlay that
    // opens a filtering posture inherits these (re-judged on its effective posture), even when the
    // baseline posture clears them from the baseline-effective `secrets`.
    let declared_secrets = secrets.clone();
    enforce_secret_posture(&network, &mut secrets, &mut warnings);
    warn_l4_l7_conflicts(&network, &mut warnings);

    let apps = resolve_apps(
        &mut warnings,
        global_apps,
        project_apps,
        &secret_defaults,
        &project_secret_defaults,
        &net_groups,
        &network,
        &proc,
        plugins,
    );

    // An *app* `[packages] mise:nix:<pkg>` re-introduces the per-project misalignment the mise split
    // otherwise fixes: a global app's Lane-1 pin lands the install record app-global while the `/nix`
    // store path is per-project. Warn per app, pointing at the aligned `nix:<pkg>` form. A *baseline*
    // `mise:nix:` (used by `sbx run`, whose home is already per-project) is aligned, so it is not
    // flagged. Trusted-only.
    for (app_name, app) in &apps {
        warn_mise_nix_packages(&format!("app `{app_name}` "), &app.packages, &mut warnings);
    }

    Resolved {
        env,
        env_layer,
        binds,
        bind_layer,
        packages,
        nixpkgs_global,
        nixpkgs_project,
        // A mise file is discovered by I/O in `load`; the pure layering never sees one.
        mise: None,
        network,
        network_origin,
        egress_stats,
        proc,
        proc_origin,
        gui,
        gui_origin,
        gpu,
        gpu_origin,
        audio,
        audio_origin,
        dbus,
        dbus_origin,
        forward,
        forward_origin,
        limits,
        limits_origin,
        seccomp,
        seccomp_origin,
        devices,
        devices_origin,
        secrets,
        declared_secrets,
        apps,
        warnings,
    }
}

/// The egress-stats toggle a `network` field carries, or `None` if it does not mention it (the bare
/// string form never does; only the `[network]` table's `stats =` key). Pulled out so the resolver
/// can honor it from a trusted layer before the field is consumed by `validate_network`.
fn network_stats_of(field: &NetworkField) -> Option<bool> {
    match field {
        NetworkField::Table(t) => t.stats,
        NetworkField::Posture(_) => None,
    }
}

/// The `default_methods` override a `[network]` table carries, if any (peeked before the field moves
/// into `validate_network`). The string posture form never carries one.
fn network_default_methods_of(field: &NetworkField) -> Option<&Vec<String>> {
    match field {
        NetworkField::Table(t) => t.default_methods.as_ref(),
        NetworkField::Posture(_) => None,
    }
}

/// The built-in app default: a Mode-B agent's unscoped allow rules default to `{GET,HEAD}` (read by
/// default; declare `{*}`/`{POST}` per host, or `default_methods` per app, to write). The baseline
/// `sbx run` (Mode A) never gets this — it stays all-verbs.
fn builtin_app_default_methods() -> crate::allowlist::Methods {
    crate::allowlist::Methods::Only(vec!["GET".to_string(), "HEAD".to_string()])
}

/// Resolve an app layer's `default_methods` override (the raw verbs, peeked before the network field
/// moved into `validate_network`) into the effective app default, warning (and falling back to the
/// built-in `{GET,HEAD}`) on a malformed value. `None` (the layer set none) leaves the running
/// default unchanged. Called only when the layer's network was honored, so an invalid value is not
/// warned about for a dropped/untrusted network.
fn resolve_app_default_methods(
    warnings: &mut Vec<String>,
    source: &str,
    raw: Option<Vec<String>>,
) -> Option<crate::allowlist::Methods> {
    let verbs = raw?;
    Some(
        crate::allowlist::parse_default_methods(&verbs).unwrap_or_else(|e| {
            warnings.push(format!(
                "{source}: ignoring invalid `default_methods` — {e}; using the built-in {{GET,HEAD}} \
                 app default"
            ));
            builtin_app_default_methods()
        }),
    )
}

/// Warn when the **baseline** `[network]` carries a `default_methods`: it is an app-only posture
/// (Mode-B agents read by default), and `sbx run` (Mode A) deliberately stay all-verbs,
/// so a baseline value is parsed but ignored. Surfacing it keeps a user from believing they made
/// their interactive shell read-only when they did not.
fn warn_if_baseline_sets_default_methods(
    warnings: &mut Vec<String>,
    source: &str,
    field: &NetworkField,
) {
    if network_default_methods_of(field).is_some() {
        warnings.push(format!(
            "{source}: ignoring `default_methods` under the baseline `[network]` — it is an app-only \
             posture; `sbx run` stay all-verbs. Set it on an `[app.<name>.network]`"
        ));
    }
}

/// Warn when an app's `[network]` table carries a `stats` toggle: the egress-stats switch is
/// baseline-only (it applies to every launch), so an `[app.<name>.network] stats = …` is parsed but
/// has no effect. Surfacing it (rather than silently dropping it) keeps a profile author from
/// believing they disabled an agent's audit when they did not.
fn warn_if_app_sets_stats(warnings: &mut Vec<String>, source: &str, field: &NetworkField) {
    if network_stats_of(field).is_some() {
        warnings.push(format!(
            "{source}: ignoring `stats` under `[network]` — the egress-stats toggle is baseline-only; \
             set `[network] stats` at the top level (it applies to every launch)"
        ));
    }
}

/// Validate a `[limits]` table into the resolved [`cgroup::Limits`](crate::sandbox::cgroup::Limits),
/// dropping any field whose value systemd would not accept (with a warning naming the field) so a
/// bad value can never reach `systemd-run` and brick a launch. A `None` table, or one whose every
/// field is unset or invalid, yields all-`None` — the built-in defaults. The per-field validators
/// mirror systemd's grammar exactly (verified against a live scope in the cgroup tests).
fn validate_limits(
    warnings: &mut Vec<String>,
    source: &str,
    raw: Option<schema::RawLimits>,
) -> crate::sandbox::cgroup::Limits {
    let mut out = crate::sandbox::cgroup::Limits::default();
    let Some(raw) = raw else {
        return out;
    };
    out.memory_high = validate_memory_limit(warnings, source, "memory_high", raw.memory_high);
    out.memory_max = validate_memory_limit(warnings, source, "memory_max", raw.memory_max);
    out.tasks_max = validate_tasks_limit(warnings, source, raw.tasks_max);
    out
}

/// Overlay one set of limit overrides onto another, per field: a `Some` field in `over` replaces
/// the matching field in `base`; an unset (`None`) one leaves `base`'s value in place. The `env`
/// model — each limit is a standalone scalar with its own default — shared by every `[limits]`
/// layering: the baseline project-over-global merge, an app's project-over-global resolution, and
/// the app overlay onto the baseline.
fn overlay_limits(base: &mut crate::sandbox::cgroup::Limits, over: crate::sandbox::cgroup::Limits) {
    if over.memory_high.is_some() {
        base.memory_high = over.memory_high;
    }
    if over.memory_max.is_some() {
        base.memory_max = over.memory_max;
    }
    if over.tasks_max.is_some() {
        base.tasks_max = over.tasks_max;
    }
}

/// Resolve a `[seccomp] allow` table into a [`SeccompPolicy`]: split each string on commas, trim,
/// and resolve each token against the mandatory denylist. A malformed or unknown entry is dropped
/// with a warning (fail-closed — an unrecognized token loosens nothing); an entry that reopens a
/// real escape surface is accepted but flagged with a caution. A collection field — drop-bad-entry,
/// keep-the-rest — like `forward`/`binds`, not an all-or-nothing scalar. Called only from a layer
/// already gated as trusted, so a bad entry warns for a relaxation that *is* being applied.
fn apply_seccomp(
    warnings: &mut Vec<String>,
    source: &str,
    raw: Option<schema::RawSeccomp>,
) -> crate::sandbox::seccomp::SeccompPolicy {
    let mut policy = crate::sandbox::seccomp::SeccompPolicy::default();
    let Some(raw) = raw else {
        return policy;
    };
    for entry in &raw.allow {
        for token in entry.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            match crate::sandbox::seccomp::resolve_allow(token) {
                Ok((allow, caution)) => {
                    policy.allow(allow);
                    if let Some(c) = caution {
                        warnings.push(format!(
                            "{source}: `[seccomp] allow` includes `{token}`, which reopens {}",
                            c.reopens()
                        ));
                    }
                }
                Err(reason) => warnings.push(format!(
                    "{source}: ignoring `[seccomp] allow` entry `{token}` ({reason})"
                )),
            }
        }
    }
    policy
}

/// Resolve one `[devices] allow` list into the host device paths to grant into the cage. Each entry
/// must be an **absolute path under `/dev/`** naming a device (or a directory of them). Validation is
/// purely lexical (no filesystem I/O, so [`resolve`] stays pure): a device absent on this host is
/// *not* an error here — it is skipped at launch by the `--dev-bind-try` mount, so a portable profile
/// that lists a device some hosts lack still launches everywhere. A malformed entry (not absolute,
/// outside `/dev/`, or containing `..`) is dropped with a warning (fail-closed — a bad path never
/// widens exposure). The result is sorted and deduped so two equivalent layers produce one canonical
/// set.
fn apply_devices(
    warnings: &mut Vec<String>,
    source: &str,
    raw: Option<schema::RawDevices>,
) -> Vec<PathBuf> {
    let mut devices: Vec<PathBuf> = Vec::new();
    let Some(raw) = raw else {
        return devices;
    };
    for entry in &raw.allow {
        let path = entry.trim();
        if path.is_empty() {
            continue;
        }
        match validate_device_path(path) {
            Ok(p) => devices.push(p),
            Err(reason) => warnings.push(format!(
                "{source}: ignoring `[devices] allow` entry `{path}` ({reason})"
            )),
        }
    }
    devices.sort();
    devices.dedup();
    devices
}

/// Validate one `[devices]` entry lexically: an absolute path *strictly under* `/dev/`, with no `..`
/// component (which could escape `/dev`). Returns the `PathBuf`, or a reason it was rejected. No I/O
/// — the device need not exist here (a portable profile may list a device some hosts lack; a missing
/// one is skipped at launch by `--dev-bind-try`). `/dev` itself (and a bare `/dev/`) is refused:
/// rebinding the whole tree would defeat the cage's minimal, hostless `/dev`.
///
/// The check is on the path *spelling*, not the resolved target: the source is deliberately **not**
/// canonicalized. Canonicalizing would need I/O (breaking this function's — and [`resolve`]'s —
/// purity) and would require the device to exist, defeating the portable-profile property above. So
/// a symlink under `/dev` pointing elsewhere (`/dev/foo -> /etc`) would dev-bind its target. Since
/// `[devices]` is trusted-only, that is **self-harm equivalent to a plain read-write bind of the
/// target** (a trusted config can already write `binds = [{ path = "/etc", mode = "rw" }]`), not a
/// new capability — so the lexical check is the proportionate guard.
fn validate_device_path(path: &str) -> Result<PathBuf, &'static str> {
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err("must be an absolute path");
    }
    if p.components().any(|c| c == std::path::Component::ParentDir) {
        return Err("must not contain a `..` component");
    }
    // Strictly under `/dev/`: a `/dev`-prefixed path with a name beyond it. The component count rules
    // out both a non-`/dev` path and the degenerate `/dev` / `/dev/`, which would rebind the whole
    // minimal device tree rather than grant one device.
    if !path.starts_with("/dev/") || p.components().count() <= 2 {
        return Err("must be a path under `/dev/` (e.g. /dev/dri, /dev/kvm)");
    }
    Ok(p.to_path_buf())
}

/// Union `extra` ports into `base`, deduped and sorted. The `forward` model — a layer adds
/// ports, never replaces — shared by the baseline project-over-global merge and the app overlay
/// onto the baseline. A port already present is kept (idempotent); the result is sorted so two
/// equivalent layers produce one canonical set.
fn union_forward(base: &mut Vec<u16>, extra: Vec<u16>) {
    for port in extra {
        if !base.contains(&port) {
            base.push(port);
        }
    }
    base.sort_unstable();
}

/// Union `extra` device paths into `base`, deduped and sorted — the same additive model as
/// [`union_forward`]: a layer (a trusted project overlay, an app) adds device grants, never removes
/// another layer's. A path already present is kept (idempotent); the result is sorted so two
/// equivalent layers produce one canonical set.
fn union_devices(base: &mut Vec<PathBuf>, extra: Vec<PathBuf>) {
    for dev in extra {
        if !base.contains(&dev) {
            base.push(dev);
        }
    }
    base.sort();
}

/// Validate one `forward` port list: drop a port of `0` (not a real port; the range ceiling is
/// already enforced by the `u16` type) with a per-port warning, keeping the rest. A collection —
/// the drop-bad-entry, keep-the-rest shape (like a malformed `binds` entry), not the all-or-nothing
/// of a scalar posture — so one bad port does not void the valid ones.
fn validate_forward(warnings: &mut Vec<String>, source: &str, raw: &[u16]) -> Vec<u16> {
    let mut out = Vec::with_capacity(raw.len());
    for &port in raw {
        if port == 0 {
            warnings.push(format!(
                "{source}: ignoring `forward` port `0` (not a real port)"
            ));
        } else {
            out.push(port);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Record `layer` as the provenance of each limit field that `limits` actually sets (a `Some`
/// value), leaving the others untouched. Called once per layer in declaration order — global, then
/// a trusted project overlay — so each field ends attributed to the last layer that set it, which
/// is exactly the layer whose value [`overlay_limits`] kept.
fn mark_limit_origins(
    origin: &mut LimitsOrigin,
    limits: &crate::sandbox::cgroup::Limits,
    layer: Provenance,
) {
    if limits.memory_high.is_some() {
        origin.memory_high = layer;
    }
    if limits.memory_max.is_some() {
        origin.memory_max = layer;
    }
    if limits.tasks_max.is_some() {
        origin.tasks_max = layer;
    }
}

/// Validate one memory limit (`memory_high`/`memory_max`): reject a value systemd would not
/// accept, and — the likely-typo guard — reject a *bare small byte count*, which is almost always
/// a percentage written without its `%` (`memory_max = 90` meaning 90 bytes, below the kernel
/// floor, which would brick the launch). Either rejection falls back to the field's default.
fn validate_memory_limit(
    warnings: &mut Vec<String>,
    source: &str,
    field: &str,
    value: Option<schema::RawLimit>,
) -> Option<String> {
    use crate::sandbox::cgroup;
    let token = value?.as_token();
    if !cgroup::is_valid_memory_value(&token) {
        warnings.push(format!(
            "{source}: ignoring invalid `limits.{field}` value `{token}`"
        ));
        return None;
    }
    if cgroup::is_bare_byte_count_below_floor(&token) {
        warnings.push(format!(
            "{source}: ignoring `limits.{field} = {token}` — a bare number is bytes, so this is \
             {token} bytes (below the usable minimum); did you mean \"{token}%\" or e.g. \
             \"{token}G\"?"
        ));
        return None;
    }
    Some(token)
}

/// Validate `tasks_max`: accept `infinity` or a positive integer, dropping anything else with a
/// warning so it falls back to the default.
fn validate_tasks_limit(
    warnings: &mut Vec<String>,
    source: &str,
    value: Option<schema::RawLimit>,
) -> Option<String> {
    let token = value?.as_token();
    if crate::sandbox::cgroup::is_valid_tasks_value(&token) {
        Some(token)
    } else {
        warnings.push(format!(
            "{source}: ignoring invalid `limits.tasks_max` value `{token}`"
        ));
        None
    }
}

/// The global config's resource limits, for `doctor` (host-level, with no project context). Reads
/// the global config — trusted by location — and validates its `[limits]`, discarding warnings:
/// `doctor` surfaces availability, while `sbx config` is the project-aware, warning-bearing view.
/// An absent or limit-free global config yields the built-in defaults (all-`None`).
pub(crate) fn global_limits() -> crate::sandbox::cgroup::Limits {
    let mut warnings = Vec::new();
    let global = read_global(&mut warnings);
    validate_limits(&mut warnings, GLOBAL_CONFIG, global.limits)
}

/// Clear injected credentials unless the posture is a filtering one. Injection is performed by
/// the filtering proxy, which exists only under a `deny`/`allow` (filtered-egress) posture; under
/// `shared` (no proxy) or `none` (no traffic) there is nowhere to inject, so the secrets are
/// cleared with a loud warning rather than left as a no-op the user mistakes for working injection.
/// (The plaintext is never read, so dropping is fail-safe.) Shared by the baseline resolution and
/// the per-app overlay, which can add secrets or change the posture.
fn enforce_secret_posture(
    network: &NetworkPolicy,
    secrets: &mut Vec<HeaderSecret>,
    warnings: &mut Vec<String>,
) {
    if !secrets.is_empty() && !matches!(network, NetworkPolicy::Allowlist(_)) {
        warnings.push(format!(
            "ignoring {} HTTP-header secret(s): credential injection requires a filtering \
             network posture (`[network] mode = \"deny\"`, `\"allow\"`, or `\"ask\"`, the proxy that injects them)",
            secrets.len()
        ));
        secrets.clear();
    }
}

/// Warn when a host carries both a raw `tcp://` (L4) allow and an inspected (L7) rule on overlapping
/// ports: the splice is uninspected, so the L7 path/method/regex/redaction on that host:port is
/// silently ineffective. A config-quality hint (the layer partition is the actual control), so it
/// drops nothing — it points the user at keeping one layer per host:port. Checked on the **baseline**
/// policy (where rules are written); a per-app `[app.<name>.network]` override is not re-checked, to
/// avoid duplicating the baseline warning for the common inherit-the-network app.
fn warn_l4_l7_conflicts(network: &NetworkPolicy, warnings: &mut Vec<String>) {
    if let NetworkPolicy::Allowlist(policy) = network {
        for host in policy.l4_l7_conflicts() {
            warnings.push(format!(
                "host `{host}` has both a raw `tcp://` (L4) rule and an inspected (L7) rule on \
                 overlapping ports — the splice is uninspected, so the L7 rule does not apply to it \
                 (use one layer per host:port)"
            ));
        }
    }
}

/// Resolve every declared app into a gated overlay. The set of names is the union of the
/// global and project app tables; each app is layered global-under-project and gated by the
/// trust of the layer that supplied each field — identical to the baseline. An app whose name
/// is not a safe path component is dropped with a warning before it can ever key a directory.
#[allow(clippy::too_many_arguments)]
fn resolve_apps(
    warnings: &mut Vec<String>,
    mut global_apps: BTreeMap<String, RawApp>,
    project_apps: Option<(BTreeMap<String, RawApp>, TrustState)>,
    secret_defaults: &SecretDefaults,
    project_secret_defaults: &SecretDefaults,
    net_groups: &NetGroups,
    baseline_network: &NetworkPolicy,
    baseline_proc: &crate::proc_policy::ProcPolicy,
    plugins: &PluginRegistry,
) -> BTreeMap<String, ResolvedApp> {
    let (mut project_apps, project_state) = match project_apps {
        Some((map, state)) => (map, Some(state)),
        None => (BTreeMap::new(), None),
    };
    let names: BTreeSet<String> = global_apps
        .keys()
        .chain(project_apps.keys())
        .cloned()
        .collect();
    let mut out = BTreeMap::new();
    for name in names {
        if !is_valid_app_name(&name) {
            warnings.push(format!(
                "ignoring app `{name}`: a name must be 1–64 of [A-Za-z0-9._-] and not `.`/`..` \
                 (it keys an on-disk home directory)"
            ));
            continue;
        }
        let global = global_apps.remove(&name);
        let project = project_apps.remove(&name).zip(project_state);
        let resolved = resolve_app(
            &name,
            global,
            project,
            secret_defaults,
            project_secret_defaults,
            net_groups,
            baseline_network,
            baseline_proc,
            plugins,
        );
        out.insert(name, resolved);
    }
    out
}

/// Whether an app name is safe to use as a single on-disk path component (it keys the app's
/// persistent home directory and, for an imported profile, its file). Restricted to a conservative
/// charset and length, and `.`/`..` are rejected outright so a name can never traverse out of a
/// directory. A name that coincides with a `sbx app` subcommand verb (`run`, `show`, …) is
/// perfectly valid: launching always goes through `sbx app run <name>`, so the name never collides
/// with the subcommand.
pub(crate) fn is_valid_app_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Resolve one app: layer its global definition (trusted by location) under its project
/// definition (gated by the project's verdict), reusing the baseline's per-field gating. The
/// project layer overrides the global per field. Security fields (`binds`/`network`/`secret`)
/// are honored only from a trusted source; `env` is free (denylisted for an untrusted
/// project); the command may come from either (the project wins). Each app collects its own
/// warnings, surfaced when the app is launched rather than on every `sbx run`.
#[allow(clippy::too_many_arguments)]
fn resolve_app(
    name: &str,
    global: Option<RawApp>,
    project: Option<(RawApp, TrustState)>,
    secret_defaults: &SecretDefaults,
    project_secret_defaults: &SecretDefaults,
    net_groups: &NetGroups,
    baseline_network: &NetworkPolicy,
    baseline_proc: &crate::proc_policy::ProcPolicy,
    plugins: &PluginRegistry,
) -> ResolvedApp {
    let mut warnings = Vec::new();
    let mut env: Vec<(String, String)> = Vec::new();
    let mut binds: Vec<Bind> = Vec::new();
    let mut packages: Vec<Package> = Vec::new();
    let mut secrets: Vec<HeaderSecret> = Vec::new();
    let mut network: Option<NetworkPolicy> = None;
    // Every Mode-B app reads by default ({GET,HEAD}); a trusted layer's `default_methods` overrides it.
    let mut default_methods = builtin_app_default_methods();
    let mut proc: Option<crate::proc_policy::ProcPolicy> = None;
    let mut gui: Option<GuiPolicy> = None;
    let mut gpu: Option<bool> = None;
    let mut audio: Option<bool> = None;
    let mut dbus: Option<bool> = None;
    // The app's own cgroup limit overrides, accumulated like `network`/`gui`: the global layer
    // sets them by location, a trusted project overlays per field, an untrusted one is dropped.
    let mut limits = crate::sandbox::cgroup::Limits::default();
    // The app's own seccomp relaxation, accumulated like the limits: global by location, a trusted
    // project unions, an untrusted one dropped. Empty means the app inherits the baseline's.
    let mut seccomp = crate::sandbox::seccomp::SeccompPolicy::default();
    let mut seccomp_origin = Provenance::Default;
    // The app's own device grant, accumulated like the seccomp relaxation: global by location, a
    // trusted project unions, an untrusted one dropped. Empty means the app inherits the baseline's.
    let mut devices: Vec<PathBuf> = Vec::new();
    let mut devices_origin = Provenance::Default;
    let mut cmd: Vec<String> = Vec::new();
    // Whether the current `cmd` came from a trusted layer. An untrusted project may define its
    // *own* app's command, but may not override the command of an app a trusted layer defined
    // — else `sbx app <name>` against an untrusted repo would silently run the repo's command
    // under the trusted app's posture (an integrity-of-intent hijack).
    let mut cmd_trusted = false;
    // The persistent-home keying, defaulting to one global home per app. Integrity-gated by
    // `home_scope_trusted` for the same reason as `cmd`: an untrusted project may set the scope
    // of its own app, but must not flip a trusted app from `Project` to `Global` — that would
    // route the untrusted run into the home a trusted run shares.
    let mut home_scope = AppHomeScope::Global;
    let mut home_scope_trusted = false;
    // Per-field provenance of the scalar overlay fields, for the per-app `sbx config` view: which
    // app layer set each, recorded at the same point the value is. A scalar the overlay never sets
    // stays `Default` here and the view shows it inherited from the baseline; `home_scope_origin`
    // stays `None` for the built-in default.
    let mut cmd_origin = Provenance::Default;
    let mut network_origin = Provenance::Default;
    let mut proc_origin = Provenance::Default;
    let mut gui_origin = Provenance::Default;
    let mut gpu_origin = Provenance::Default;
    let mut audio_origin = Provenance::Default;
    let mut dbus_origin = Provenance::Default;
    // The app's own loopback forward ports — a security field, gated like `network`/`gui`. The
    // merged effective set (app ∪ baseline) is computed at `merge_app`; this holds only the app's
    // own contribution, with its origin for the per-app view.
    let mut forward: Vec<u16> = Vec::new();
    let mut forward_origin = Provenance::Default;
    let mut limits_origin = LimitsOrigin::default();
    let mut home_scope_origin: Option<Provenance> = None;

    // The global layer — trusted by location, honored in full.
    if let Some(app) = global {
        let source = app_source(GLOBAL_CONFIG, name);
        apply_env(&mut env, None, &mut warnings, &source, app.env, false);
        apply_binds(&mut binds, None, &mut warnings, &source, app.binds);
        apply_tools(
            &mut packages,
            &mut warnings,
            &source,
            app.packages,
            app.flakes,
            app.tarball,
            app.deb,
            app.appimage,
            TrustState::Trusted,
            false,
        );
        if let Some(field) = app.network {
            warn_if_app_sets_stats(&mut warnings, &source, &field);
            let raw_dm = network_default_methods_of(&field).cloned();
            // A mode-less app `[network]` inherits its mode from the resolved baseline (the app's
            // own rules are kept). At the global app layer nothing has overridden it yet, so the
            // parent is the baseline.
            let parent = network.as_ref().unwrap_or(baseline_network);
            let resolved = validate_network(&mut warnings, &source, field, net_groups, parent);
            if let Some(policy) = resolved {
                network = Some(policy);
                network_origin = Provenance::Global;
                if let Some(m) = resolve_app_default_methods(&mut warnings, &source, raw_dm) {
                    default_methods = m;
                }
            }
        }
        if let Some(field) = app.proc {
            // A table without a mode inherits from the app's own proc so far, else the baseline.
            let parent = proc.as_ref().unwrap_or(baseline_proc);
            if let Some(policy) = validate_proc(&mut warnings, &source, field, parent) {
                proc = Some(policy);
                proc_origin = Provenance::Global;
            }
        }
        if let Some(value) = app.gui {
            if let Some(policy) = validate_gui(&mut warnings, &source, value) {
                gui = Some(policy);
                gui_origin = Provenance::Global;
            }
        }
        if let Some(value) = app.gpu {
            gpu = Some(value);
            gpu_origin = Provenance::Global;
        }
        if let Some(value) = app.audio {
            audio = Some(value);
            audio_origin = Provenance::Global;
        }
        if let Some(value) = app.dbus {
            dbus = Some(value);
            dbus_origin = Provenance::Global;
        }
        // `forward` is trusted by location at the global app layer; invalid ports are dropped
        // (warned). The app's own set is kept separate here — it unions onto the baseline at
        // `merge_app` — so the origin records only that this layer contributed.
        if let Some(raw) = app.forward.as_deref() {
            let validated = validate_forward(&mut warnings, &source, raw);
            if !validated.is_empty() {
                forward_origin = Provenance::Global;
            }
            union_forward(&mut forward, validated);
        }
        let global_limits = validate_limits(&mut warnings, &source, app.limits);
        mark_limit_origins(&mut limits_origin, &global_limits, Provenance::Global);
        overlay_limits(&mut limits, global_limits);
        let global_seccomp = apply_seccomp(&mut warnings, &source, app.seccomp);
        if !global_seccomp.is_empty() {
            seccomp_origin = Provenance::Global;
        }
        seccomp.union(&global_seccomp);
        let global_devices = apply_devices(&mut warnings, &source, app.devices);
        if !global_devices.is_empty() {
            devices_origin = Provenance::Global;
        }
        union_devices(&mut devices, global_devices);
        if let Some(section) = app.secret {
            apply_app_secret(
                &mut secrets,
                &mut warnings,
                &source,
                section,
                secret_defaults,
                plugins,
            );
        }
        if let Some(c) = app.cmd {
            cmd = c.into_argv();
            cmd_trusted = true;
            cmd_origin = Provenance::Global;
        }
        if let Some(raw) = app.home_scope {
            if let Some(scope) = validate_home_scope(&mut warnings, &source, &raw) {
                home_scope = scope;
                home_scope_trusted = true;
                home_scope_origin = Some(Provenance::Global);
            }
        }
    }

    // The project layer — gated by the project's verdict, overriding the global per field.
    if let Some((app, state)) = project {
        let trusted = state == TrustState::Trusted;
        let source = app_source(PROJECT_CONFIG, name);
        apply_env(&mut env, None, &mut warnings, &source, app.env, !trusted);
        if !app.binds.is_empty() {
            if trusted {
                apply_binds(&mut binds, None, &mut warnings, &source, app.binds);
            } else {
                warnings.push(dropped_binds_warning(state, app.binds.len()));
            }
        }
        // An untrusted project may add its own app's packages but may not override a package a
        // trusted layer supplied (the `cmd`-integrity guard, applied to the tool).
        apply_tools(
            &mut packages,
            &mut warnings,
            &source,
            app.packages,
            app.flakes,
            app.tarball,
            app.deb,
            app.appimage,
            state,
            !trusted,
        );
        if let Some(field) = app.network {
            if trusted {
                warn_if_app_sets_stats(&mut warnings, &source, &field);
                let raw_dm = network_default_methods_of(&field).cloned();
                // A mode-less table inherits from whatever posture is in effect so far — the app's
                // own global layer if it set one, else the baseline.
                let parent = network.as_ref().unwrap_or(baseline_network);
                let resolved = validate_network(&mut warnings, &source, field, net_groups, parent);
                if let Some(policy) = resolved {
                    network = Some(policy);
                    network_origin = Provenance::Project;
                    if let Some(m) = resolve_app_default_methods(&mut warnings, &source, raw_dm) {
                        default_methods = m;
                    }
                }
            } else {
                warnings.push(format!(
                    "{source}: ignoring `network` policy ({})",
                    untrusted_reason(state)
                ));
            }
        }
        // `proc` mirrors `network`: an untrusted project may not set an exec posture, on its own app
        // or by overriding a trusted one (the flagship property — an agent runs *on* untrusted code
        // without that code being able to forge or loosen the enforcement of its own agent).
        if let Some(field) = app.proc {
            if trusted {
                let parent = proc.as_ref().unwrap_or(baseline_proc);
                if let Some(policy) = validate_proc(&mut warnings, &source, field, parent) {
                    proc = Some(policy);
                    proc_origin = Provenance::Project;
                }
            } else {
                warnings.push(format!(
                    "{source}: ignoring `proc` policy ({})",
                    untrusted_reason(state)
                ));
            }
        }
        // `gui` mirrors `network`: an untrusted project may not open a display, on its own app
        // or by overriding a trusted one (the flagship property — an agent runs *on* untrusted
        // code without that code being able to expose the user's compositor).
        if let Some(value) = app.gui {
            if trusted {
                if let Some(policy) = validate_gui(&mut warnings, &source, value) {
                    gui = Some(policy);
                    gui_origin = Provenance::Project;
                }
            } else {
                warnings.push(format!(
                    "{source}: ignoring `gui` posture ({})",
                    untrusted_reason(state)
                ));
            }
        }
        // `gpu` mirrors `gui`: an untrusted project may not open GPU rendering, on its own app or
        // by overriding a trusted one (a render node and the `/sys` device tree widen the kernel
        // attack surface).
        if let Some(value) = app.gpu {
            if trusted {
                gpu = Some(value);
                gpu_origin = Provenance::Project;
            } else {
                warnings.push(format!(
                    "{source}: ignoring `gpu` posture ({})",
                    untrusted_reason(state)
                ));
            }
        }
        // `audio` mirrors `gpu`: an untrusted project may not open audio, on its own app or by
        // overriding a trusted one (the PulseAudio bus exposes the microphone and all system audio).
        if let Some(value) = app.audio {
            if trusted {
                audio = Some(value);
                audio_origin = Provenance::Project;
            } else {
                warnings.push(format!(
                    "{source}: ignoring `audio` posture ({})",
                    untrusted_reason(state)
                ));
            }
        }
        // `dbus` mirrors `gpu`: an untrusted project may not stand up the in-cage portal, on its own
        // app or by overriding a trusted one (a bus sits near the keyring and the portals).
        if let Some(value) = app.dbus {
            if trusted {
                dbus = Some(value);
                dbus_origin = Provenance::Project;
            } else {
                warnings.push(format!(
                    "{source}: ignoring `dbus` posture ({})",
                    untrusted_reason(state)
                ));
            }
        }
        // `[limits]` mirrors `network`/`gui`: a trusted project may tune the cage's limits, on its
        // own app or by overriding a trusted one; an untrusted project may not (loosening them
        // weakens the anti-DoS control). Dropping the untrusted layer here — before any overlay —
        // is what keeps a globally-defined app's tight limits intact under an untrusted project.
        if let Some(raw) = app.limits {
            if trusted {
                let project_limits = validate_limits(&mut warnings, &source, Some(raw));
                mark_limit_origins(&mut limits_origin, &project_limits, Provenance::Project);
                overlay_limits(&mut limits, project_limits);
            } else {
                warnings.push(format!(
                    "{source}: ignoring `[limits]` ({})",
                    untrusted_reason(state)
                ));
            }
        }
        // `[seccomp]` mirrors `[limits]`: a trusted project may relax the denylist for its own app
        // or a trusted one; an untrusted project may not (loosening the kernel-attack-surface
        // control). Dropping the untrusted layer here — before the union — is what keeps a global
        // app's relaxation from being widened by an untrusted project.
        if let Some(raw) = app.seccomp {
            if trusted {
                let project_seccomp = apply_seccomp(&mut warnings, &source, Some(raw));
                if !project_seccomp.is_empty() {
                    seccomp_origin = Provenance::Project;
                }
                seccomp.union(&project_seccomp);
            } else {
                warnings.push(format!(
                    "{source}: ignoring `[seccomp]` ({})",
                    untrusted_reason(state)
                ));
            }
        }
        // `[devices]` mirrors `[seccomp]`: a trusted project may grant a host device to its own app
        // or a trusted one; an untrusted project may not (a device widens the kernel attack surface).
        // Dropping the untrusted layer here — before the union — is what keeps a global app's device
        // grant from being widened by an untrusted project.
        if let Some(raw) = app.devices {
            if trusted {
                let project_devices = apply_devices(&mut warnings, &source, Some(raw));
                if !project_devices.is_empty() {
                    devices_origin = Provenance::Project;
                }
                union_devices(&mut devices, project_devices);
            } else {
                warnings.push(format!(
                    "{source}: ignoring `[devices]` ({})",
                    untrusted_reason(state)
                ));
            }
        }
        // `forward` mirrors `network`/`gui`: a trusted project may add forward ports to its own
        // app or a trusted one; an untrusted project may not (opening a host port is an inbound
        // hole). The ports union onto the app's own set, so the project adds, never replaces.
        if let Some(raw) = app.forward {
            if trusted {
                let project_forward = validate_forward(&mut warnings, &source, &raw);
                if !project_forward.is_empty() {
                    forward_origin = Provenance::Project;
                }
                union_forward(&mut forward, project_forward);
            } else {
                warnings.push(format!(
                    "{source}: ignoring `forward` ports ({})",
                    untrusted_reason(state)
                ));
            }
        }
        if let Some(section) = app.secret {
            if trusted {
                // A project-local app resolves its secrets against the project-effective defaults
                // (global + the project's own `[secret.defaults]`), unlike the global-layer site
                // above which uses the global defaults — a project's resolver order/bindings reach
                // its own apps, never a globally-declared one.
                apply_app_secret(
                    &mut secrets,
                    &mut warnings,
                    &source,
                    section,
                    project_secret_defaults,
                    plugins,
                );
            } else {
                let n = count_host_secrets(&section.hosts);
                if n > 0 {
                    warnings.push(format!(
                        "{source}: ignoring {n} secret(s) ({})",
                        untrusted_reason(state)
                    ));
                }
            }
        }
        if let Some(c) = app.cmd {
            if trusted || !cmd_trusted {
                cmd = c.into_argv();
                cmd_origin = Provenance::Project;
            } else {
                warnings.push(format!(
                    "{source}: ignoring `cmd` override of a trusted app ({})",
                    untrusted_reason(state)
                ));
            }
        }
        if let Some(raw) = app.home_scope {
            // A trusted project may set any scope; an untrusted one may set its own app's scope
            // (nothing trusted to override) but not flip a trusted app — which could only widen
            // it to the shared `Global` home, the contamination vector.
            if trusted || !home_scope_trusted {
                if let Some(scope) = validate_home_scope(&mut warnings, &source, &raw) {
                    home_scope = scope;
                    home_scope_origin = Some(Provenance::Project);
                }
            } else {
                warnings.push(format!(
                    "{source}: ignoring `home_scope` override of a trusted app ({})",
                    untrusted_reason(state)
                ));
            }
        }
    }

    ResolvedApp {
        cmd,
        home_scope,
        env,
        binds,
        packages,
        network,
        proc,
        gui,
        gpu,
        audio,
        dbus,
        limits,
        seccomp,
        devices,
        forward,
        secrets,
        default_methods,
        cmd_origin,
        network_origin,
        proc_origin,
        gui_origin,
        gpu_origin,
        audio_origin,
        dbus_origin,
        forward_origin,
        seccomp_origin,
        devices_origin,
        limits_origin,
        home_scope_origin,
        warnings,
    }
}

/// Parse an app's `home_scope` string into [`AppHomeScope`]. An unrecognized value is dropped
/// with a warning and the caller keeps the prior (defaulting to `Global`) — fail-safe, never a
/// silent mis-scope.
fn validate_home_scope(
    warnings: &mut Vec<String>,
    source: &str,
    raw: &str,
) -> Option<AppHomeScope> {
    match raw {
        "global" => Some(AppHomeScope::Global),
        "project" => Some(AppHomeScope::Project),
        other => {
            warnings.push(format!(
                "{source}: ignoring unknown home_scope `{other}` (expected \"global\" or \"project\")"
            ));
            None
        }
    }
}

/// Apply an app's `[app.<name>.secret]` section, merging any app-level `defaults` over the
/// base resolver defaults before resolving each host's credential — the same shape as the
/// baseline `[secret]` section.
fn apply_app_secret(
    out: &mut Vec<HeaderSecret>,
    warnings: &mut Vec<String>,
    source: &str,
    section: schema::RawSecretSection,
    base_defaults: &SecretDefaults,
    plugins: &PluginRegistry,
) {
    let effective = match &section.defaults {
        Some(raw) => base_defaults.merged_with(raw),
        None => base_defaults.clone(),
    };
    apply_secret_section(out, warnings, source, section.hosts, &effective, plugins);
}

/// The warning source label for a field of `[app.<name>]` in a given config file — e.g.
/// `".sbx.toml [app.demo-app]"` — so a dropped app field reads as clearly as a baseline one.
fn app_source(config: &str, name: &str) -> String {
    format!("{config} [app.{name}]")
}

/// Fold a layer's environment into `out`: drop a malformed key, drop a reserved
/// key when `deny_reserved` (an untrusted or changed project), and upsert the rest
/// so a later layer overrides an earlier one at the same key.
fn apply_env(
    out: &mut Vec<(String, String)>,
    mut origin: Option<(Provenance, &mut BTreeMap<String, Provenance>)>,
    warnings: &mut Vec<String>,
    source: &str,
    env: BTreeMap<String, String>,
    deny_reserved: bool,
) {
    for (key, val) in env {
        if !is_valid_env_key(&key) {
            warnings.push(format!("{source}: ignoring malformed env key `{key}`"));
            continue;
        }
        if deny_reserved && is_reserved_env_key(&key) {
            warnings.push(format!(
                "{source}: ignoring reserved env key `{key}` \
                 (an untrusted or changed project may not set it)"
            ));
            continue;
        }
        // Record the admitting layer at the upsert point — admission depends on the checks
        // above, so it cannot be reconstructed from outside. A later layer overwrites the key
        // here too, so the recorded layer always matches the value `out` ends up holding.
        if let Some((layer, map)) = origin.as_mut() {
            map.insert(key.clone(), *layer);
        }
        upsert(out, key, val);
    }
}

/// Interpret a bind table's optional `mode`: `None`/`"ro"` → read-only, `"rw"` → read-write. An
/// unrecognized value falls closed to read-only — the safe direction for a security field, never
/// a wider exposure than declared — returning a reason (with a case-variant hint) so the caller
/// can warn. The one place `"ro"`/`"rw"` are given meaning, shared by resolution and the display.
fn bind_mode(mode: Option<&str>) -> (bool, Option<String>) {
    match mode {
        None | Some("ro") => (false, None),
        Some("rw") => (true, None),
        Some(other) => {
            let hint = if other.eq_ignore_ascii_case("rw") || other.eq_ignore_ascii_case("ro") {
                format!(" (did you mean `\"{}\"`?)", other.to_ascii_lowercase())
            } else {
                String::new()
            };
            (
                false,
                Some(format!(
                    "has unknown mode `{other}`, binding read-only (use `\"ro\"` or `\"rw\"`){hint}"
                )),
            )
        }
    }
}

/// Fold a layer's binds into `out`, requiring each to be an absolute path. A
/// relative bind is dropped with a warning: the project is already mounted in
/// full, so an extra bind is by definition an out-of-project path, and resolving a
/// relative one against the working directory would be a surprise.
fn apply_binds(
    out: &mut Vec<Bind>,
    mut origin: Option<(Provenance, &mut BTreeMap<PathBuf, Provenance>)>,
    warnings: &mut Vec<String>,
    source: &str,
    binds: Vec<RawBind>,
) {
    // A leading `~`/`$HOME`/`$XDG_RUNTIME_DIR` is expanded from the environment of the user
    // launching sbx, so a portable config need not hard-code an absolute home path. Read once.
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    for b in binds {
        let (raw_path, writable) = match b {
            RawBind::Path(p) => (p, false),
            RawBind::Detailed(t) => {
                // A table without a `path` is skipped with a warning — never dropped the whole
                // layer (the parse layer keeps `path` optional exactly so one such typo cannot).
                let Some(path) = t.path else {
                    warnings.push(format!("{source}: ignoring a bind table without a `path`"));
                    continue;
                };
                let (writable, reason) = bind_mode(t.mode.as_deref());
                if let Some(reason) = reason {
                    warnings.push(format!("{source}: bind `{path}` {reason}"));
                }
                (path, writable)
            }
        };
        let p = match expand_bind_path(&raw_path, home.as_deref(), runtime.as_deref()) {
            Ok(p) => p,
            Err(reason) => {
                warnings.push(format!("{source}: ignoring bind `{raw_path}`: {reason}"));
                continue;
            }
        };
        if p.is_absolute() {
            // Record the layer keyed by the expanded path; [`load`] re-keys it to the canonical
            // form when it canonicalizes, so the displayed path is the lookup key. The `Bind` and
            // the origin entry use the same `PathBuf` so a later `raw_layer.get(&bind.path)` hits.
            if let Some((layer, map)) = origin.as_mut() {
                map.insert(p.clone(), *layer);
            }
            out.push(Bind { path: p, writable });
        } else {
            warnings.push(format!("{source}: ignoring non-absolute bind `{raw_path}`"));
        }
    }
}

/// Expand a leading `~`, `$HOME`, or `$XDG_RUNTIME_DIR` in a `binds` source to an absolute host
/// path, using the environment of the user launching sbx (a config need not hard-code
/// `/home/<user>`). Only the head component — before the first `/` — is a variable; an
/// unrecognized `$VAR` at the head is rejected (fail closed: no arbitrary environment
/// interpolation into a mount source). A path with no recognized head is returned unchanged, and
/// the caller's absolute-path check still applies to the result.
///
/// The expandable-prefix set is deliberately identical to the resolver-plugin `allow_paths`
/// expander, so the user sees one variable vocabulary. It differs in one intentional way: a
/// literal `$` **past** the head is kept verbatim here, because a bind source is a real filesystem
/// path that may legitimately contain one (e.g. an exFAT/NTFS mount's `$RECYCLE.BIN`), whereas a
/// resolver allowlist can afford to reject any stray `$`. Do not merge the two behind one helper.
fn expand_bind_path(
    raw: &str,
    home: Option<&Path>,
    runtime: Option<&Path>,
) -> Result<PathBuf, String> {
    let (head, rest) = match raw.split_once('/') {
        Some((h, r)) => (h, Some(r)),
        None => (raw, None),
    };
    let base = match head {
        "~" | "$HOME" => home
            .ok_or_else(|| "needs `$HOME`, which is not set".to_string())?
            .to_path_buf(),
        "$XDG_RUNTIME_DIR" => runtime
            .ok_or_else(|| "needs `$XDG_RUNTIME_DIR`, which is not set".to_string())?
            .to_path_buf(),
        other if other.starts_with('$') => {
            return Err("uses an unsupported variable \
                        (only `~`, `$HOME`, `$XDG_RUNTIME_DIR` are expanded)"
                .to_string());
        }
        _ => return Ok(PathBuf::from(raw)),
    };
    Ok(match rest {
        Some(r) => base.join(r),
        None => base,
    })
}

/// Fold a layer's packages into `out`, validating the label and parsing the value's
/// mandatory backend prefix, stamping each with whether its source layer is trusted. A
/// later layer overrides an earlier one at the same name, so a project can pin a tool
/// the global set named. Nothing is dropped for trust here — that belongs to the
/// launcher; this is a pure merge. A malformed label, or a value with no `nix:`/`mise:`
/// prefix, *is* dropped (with a warning): it could never realise, and a label names an
/// on-disk path — fail-closed, never a silent mis-route.
fn apply_packages(
    out: &mut Vec<Package>,
    warnings: &mut Vec<String>,
    source: &str,
    packages: BTreeMap<String, String>,
    state: TrustState,
    protect_trusted: bool,
) {
    for (name, value) in packages {
        if !is_valid_package_name(&name) {
            warnings.push(format!(
                "{source}: ignoring malformed package name `{name}`"
            ));
            continue;
        }
        // When `protect_trusted` is set (an untrusted project layering over a trusted app),
        // a package a trusted layer already supplied may not be overridden — the integrity-of-
        // intent guard `cmd` has, applied to the tool: else an untrusted project could swap a
        // trusted app's `demo-tool` for its own attribute and either run attacker code (closed
        // separately by `[packages]` being trusted-only) or simply deny the app its tool. A new
        // name may still be added.
        if protect_trusted
            && out
                .iter()
                .any(|p| p.name == name && p.state == TrustState::Trusted)
        {
            warnings.push(format!(
                "{source}: ignoring package `{name}` override of a trusted app ({})",
                untrusted_reason(state)
            ));
            continue;
        }
        let backend = match parse_backend(&value) {
            Ok(b) => b,
            Err(reason) => {
                warnings.push(format!("{source}: ignoring package `{name}`: {reason}"));
                continue;
            }
        };
        upsert_package(out, name, backend, state);
    }
}

/// Fold a layer's `[packages]` and `[flakes]` into `out` as one tool set, upserting by name.
/// Packages are applied first, then inline flakes, so a name declared in both — a config mistake —
/// resolves to the `[flakes]` inline source, and the collision is warned rather than silently
/// last-winning. `state`/`protect_trusted` gate both exactly like [`apply_packages`], so an
/// untrusted project's inline flake is stamped untrusted (withheld at launch) and cannot override
/// a trusted app's tool. The collision check is per-layer, so a *legitimate* cross-layer override
/// (a project flake replacing a global package of the same name) does not trip it — the two sit in
/// different `apply_tools` calls.
#[allow(clippy::too_many_arguments)]
fn apply_tools(
    out: &mut Vec<Package>,
    warnings: &mut Vec<String>,
    source: &str,
    mut packages: BTreeMap<String, String>,
    flakes: BTreeMap<String, RawInlineFlake>,
    tarball: BTreeMap<String, RawResolve>,
    deb: BTreeMap<String, RawResolve>,
    appimage: BTreeMap<String, RawResolve>,
    state: TrustState,
    protect_trusted: bool,
) {
    // A `<name> = "tarball:resolve"` / `"deb:resolve"` / `"appimage:resolve"` entry is a sentinel, not
    // a real backend locator: pull each out of the ordinary packages before `apply_packages` (which
    // would reject the bare prefix) and hand the names to `apply_resolvers`, which binds each to its
    // `[tarball.<name>]` / `[deb.<name>]` / `[appimage.<name>]` table.
    let collect_sentinel =
        |packages: &BTreeMap<String, String>, sentinel: &str| -> BTreeSet<String> {
            packages
                .iter()
                .filter(|(_, v)| v.as_str() == sentinel)
                .map(|(k, _)| k.clone())
                .collect()
        };
    let tarball_names = collect_sentinel(&packages, TARBALL_RESOLVE_SENTINEL);
    let deb_names = collect_sentinel(&packages, DEB_RESOLVE_SENTINEL);
    let appimage_names = collect_sentinel(&packages, APPIMAGE_RESOLVE_SENTINEL);
    packages.retain(|_, v| {
        v.as_str() != TARBALL_RESOLVE_SENTINEL
            && v.as_str() != DEB_RESOLVE_SENTINEL
            && v.as_str() != APPIMAGE_RESOLVE_SENTINEL
    });

    for name in packages.keys() {
        if flakes.contains_key(name) {
            warnings.push(format!(
                "{source}: `{name}` is declared as both a [packages] entry and a [flakes] table; \
                 the [flakes] inline source is used"
            ));
        }
    }
    apply_packages(out, warnings, source, packages, state, protect_trusted);
    apply_flakes(out, warnings, source, flakes, state, protect_trusted);
    apply_resolvers(
        out,
        warnings,
        source,
        tarball,
        &tarball_names,
        state,
        protect_trusted,
        TARBALL_RESOLVE_SENTINEL,
        "tarball",
        |command| Backend::TarballResolve { command },
    );
    apply_resolvers(
        out,
        warnings,
        source,
        deb,
        &deb_names,
        state,
        protect_trusted,
        DEB_RESOLVE_SENTINEL,
        "deb",
        |command| Backend::DebResolve { command },
    );
    apply_resolvers(
        out,
        warnings,
        source,
        appimage,
        &appimage_names,
        state,
        protect_trusted,
        APPIMAGE_RESOLVE_SENTINEL,
        "appimage",
        |command| Backend::AppImageResolve { command },
    );
}

/// Bind each `<name> = "<label>:resolve"` sentinel to its `[<label>.<name>]` table, folding it into
/// `out` as the backend `make_backend` builds from the command. Shared by the `tarball:resolve` and
/// `deb:resolve` forms (the two differ only in the sentinel, the table label, and the backend built).
/// Modelled on [`apply_flakes`]: a malformed name, an empty `resolve` command, or the `protect_trusted`
/// override of a trusted app's tool is dropped with a warning (fail-closed). Both mismatch directions
/// are warned loudly so a half-declared package never silently vanishes: a `[<label>.<name>]` table
/// with no matching sentinel is ignored (the sentinel is the opt-in that keeps `[packages]` the
/// canonical tool list), and a sentinel with no table cannot resolve. Trust is *recorded*, not enforced
/// here — the launcher withholds an untrusted resolver package and **never runs its command**.
#[allow(clippy::too_many_arguments)]
fn apply_resolvers(
    out: &mut Vec<Package>,
    warnings: &mut Vec<String>,
    source: &str,
    tables: BTreeMap<String, RawResolve>,
    resolve_names: &BTreeSet<String>,
    state: TrustState,
    protect_trusted: bool,
    sentinel: &str,
    label: &str,
    make_backend: fn(Vec<String>) -> Backend,
) {
    // Which sentinels actually have a `[<label>.<name>]` table (valid or not) — so the no-table
    // warning below fires only for a truly-orphan sentinel, never a second time for one whose table
    // was present but rejected above.
    let table_names: BTreeSet<String> = tables.keys().cloned().collect();
    for (name, raw) in tables {
        if !resolve_names.contains(&name) {
            warnings.push(format!(
                "{source}: ignoring [{label}.{name}] — no matching `{name} = \
                 \"{sentinel}\"` in [packages]"
            ));
            continue;
        }
        if !is_valid_package_name(&name) {
            warnings.push(format!(
                "{source}: ignoring malformed {label} name `{name}`"
            ));
            continue;
        }
        if protect_trusted
            && out
                .iter()
                .any(|p| p.name == name && p.state == TrustState::Trusted)
        {
            warnings.push(format!(
                "{source}: ignoring {label} resolver `{name}` override of a trusted app ({})",
                untrusted_reason(state)
            ));
            continue;
        }
        if raw.resolve.iter().all(|a| a.trim().is_empty()) {
            warnings.push(format!(
                "{source}: ignoring [{label}.{name}]: the `resolve` command is empty"
            ));
            continue;
        }
        upsert_package(out, name, make_backend(raw.resolve), state);
    }
    // A sentinel with no `[<label>.<name>]` table at all can never resolve — warn rather than
    // silently drop the package (a sentinel whose table was present but invalid was already warned).
    for name in resolve_names {
        if !table_names.contains(name) {
            warnings.push(format!(
                "{source}: ignoring package `{name}`: `{sentinel}` needs a `[{label}.{name}]` \
                 table declaring a `resolve` command"
            ));
        }
    }
}

/// Fold a layer's inline flakes (`[flakes.<name>]`) into `out` as [`Backend::FlakeInline`] tools,
/// stamping each with whether its source layer is trusted. Modelled on [`apply_packages`]: a
/// malformed name, an empty `flake` body, or an invalid output attribute is dropped with a warning
/// (fail-closed — a name keys an on-disk path and an empty flake could never build), and the
/// `protect_trusted` guard refuses an untrusted override of a trusted app's tool. The default
/// output attribute is `default`. Trust is *recorded*, not enforced here — the launcher withholds
/// an untrusted inline flake, exactly as for `flake:`.
fn apply_flakes(
    out: &mut Vec<Package>,
    warnings: &mut Vec<String>,
    source: &str,
    flakes: BTreeMap<String, RawInlineFlake>,
    state: TrustState,
    protect_trusted: bool,
) {
    for (name, raw) in flakes {
        if !is_valid_package_name(&name) {
            warnings.push(format!("{source}: ignoring malformed flake name `{name}`"));
            continue;
        }
        if protect_trusted
            && out
                .iter()
                .any(|p| p.name == name && p.state == TrustState::Trusted)
        {
            warnings.push(format!(
                "{source}: ignoring inline flake `{name}` override of a trusted app ({})",
                untrusted_reason(state)
            ));
            continue;
        }
        let content = raw.flake;
        if content.trim().is_empty() {
            warnings.push(format!(
                "{source}: ignoring inline flake `{name}`: the `flake` field is empty"
            ));
            continue;
        }
        let attr = raw.attr.unwrap_or_else(|| "default".to_string());
        if !is_valid_attr(&attr) {
            warnings.push(format!(
                "{source}: ignoring inline flake `{name}`: invalid output attribute `{attr}`"
            ));
            continue;
        }
        upsert_package(out, name, Backend::FlakeInline { content, attr }, state);
    }
}

/// Parse a `[packages]` value into its [`Backend`] from the mandatory prefix. `nix:<attr>`
/// routes to host-side nixpkgs provisioning, `mise:<token>` to the in-cage mise equip,
/// `flake:<ref>` to an in-cage `nix build` of an arbitrary flake; a value with no recognized
/// prefix is rejected (there is no bare form, so the backend is always explicit). The part
/// after `mise:` is the full mise token — including a `nix:`-prefixed nixhub token
/// (`mise:nix:<pkg>`), which is mise's concern, not a third nix code path here. `flake:` is
/// matched before `nix:` only by being a distinct prefix; the two never overlap.
fn parse_backend(value: &str) -> Result<Backend, String> {
    if let Some(attr) = value.strip_prefix("nix:") {
        if !is_valid_attr(attr) {
            return Err(format!("invalid nix attribute `{attr}`"));
        }
        Ok(Backend::Nix(attr.to_string()))
    } else if let Some(token) = value.strip_prefix("mise:") {
        if !is_valid_mise_token(token) {
            return Err(format!("invalid mise token `{token}`"));
        }
        Ok(Backend::Mise(token.to_string()))
    } else if let Some(reference) = value.strip_prefix("flake:") {
        if !is_valid_flake_ref(reference) {
            return Err(format!("invalid flake reference `{reference}`"));
        }
        Ok(Backend::Flake(reference.to_string()))
    } else if value == DEB_RESOLVE_SENTINEL {
        // Checked before the `deb:` strip below, or `deb:resolve` would parse as a `deb:` URL and be
        // rejected as invalid. Bound to its `[deb.<name>]` table by `apply_tools`; reaching here means
        // the table is missing or a context without one (e.g. a one-shot `--config` blob).
        Err(format!(
            "`{DEB_RESOLVE_SENTINEL}` needs a matching `[deb.<name>]` table declaring a \
             `resolve` command"
        ))
    } else if let Some(rest) = value.strip_prefix("deb:") {
        if !is_valid_deb_url(rest)
            && !is_valid_deb_github_locator(rest)
            && !is_valid_deb_apt_locator(rest)
        {
            return Err(format!(
                "invalid deb reference `{rest}` — use an `https://` URL ending in `.deb`, \
                 `github:<owner>/<repo>` to track the latest release's `.deb`, \
                 or `apt:<https-Packages-index-url>` to track an apt repo's latest `.deb`"
            ));
        }
        Ok(Backend::Deb(rest.to_string()))
    } else if value == APPIMAGE_RESOLVE_SENTINEL {
        // Checked before the `appimage:` strip below, or `appimage:resolve` would parse as an
        // `appimage:` URL and be rejected as invalid. Bound to its `[appimage.<name>]` table by
        // `apply_tools`; reaching here means the table is missing or a context without one (e.g. a
        // one-shot `--config` blob).
        Err(format!(
            "`{APPIMAGE_RESOLVE_SENTINEL}` needs a matching `[appimage.<name>]` table declaring a \
             `resolve` command"
        ))
    } else if let Some(rest) = value.strip_prefix("appimage:") {
        if !is_valid_appimage_url(rest) && !is_valid_deb_github_locator(rest) {
            return Err(format!(
                "invalid appimage reference `{rest}` — use an `https://` URL ending in `.AppImage`, \
                 or `github:<owner>/<repo>` to track the latest release's `.AppImage`"
            ));
        }
        Ok(Backend::AppImage(rest.to_string()))
    } else if value == TARBALL_RESOLVE_SENTINEL {
        // The auto-upgrade sentinel is bound to its `[tarball.<name>]` table by `apply_tools`
        // (which strips it before this point), so reaching here means the table is missing or the
        // sentinel was used in a context without one (e.g. a one-shot `--config` blob) — fail closed.
        Err(format!(
            "`{TARBALL_RESOLVE_SENTINEL}` needs a matching `[tarball.<name>]` table declaring a \
             `resolve` command"
        ))
    } else if let Some(rest) = value.strip_prefix("tarball:") {
        if !is_valid_tarball_url(rest) {
            return Err(format!(
                "invalid tarball reference `{rest}` — use an `https://` URL ending in `.tar.gz` \
                 or `.tgz`, or `tarball:resolve` with a `[tarball.<name>]` table"
            ));
        }
        Ok(Backend::Tarball(rest.to_string()))
    } else {
        Err(format!(
            "`{value}` needs a backend prefix — use `nix:<attribute>`, `mise:<token>`, \
             `flake:<ref>`, `deb:<url>` / `deb:github:<owner>/<repo>` / `deb:resolve`, \
             `appimage:<url>` / `appimage:github:<owner>/<repo>` / `appimage:resolve`, \
             `tarball:<url>`, or `tarball:resolve`"
        ))
    }
}

/// The `[packages]` value that opts a package into the auto-upgrade resolver form: it declares the
/// package in `[packages]` (keeping that the canonical tool list) while its `resolve` command lives
/// in a paired `[tarball.<name>]` table. Not a real backend locator — [`apply_tools`] strips it
/// before [`apply_packages`] runs and binds it to the table by name.
const TARBALL_RESOLVE_SENTINEL: &str = "tarball:resolve";

/// The `[packages]` value that opts a package into the `deb:` auto-upgrade resolver form — the exact
/// `deb:` analogue of [`TARBALL_RESOLVE_SENTINEL`]. Its `resolve` command lives in a paired
/// `[deb.<name>]` table; [`apply_tools`] strips it before [`apply_packages`] and binds it by name.
const DEB_RESOLVE_SENTINEL: &str = "deb:resolve";

/// The `[packages]` value that opts a package into the `appimage:` auto-upgrade resolver form — the
/// exact `appimage:` analogue of [`TARBALL_RESOLVE_SENTINEL`]. Its `resolve` command lives in a
/// paired `[appimage.<name>]` table; [`apply_tools`] strips it before [`apply_packages`] and binds it
/// by name.
const APPIMAGE_RESOLVE_SENTINEL: &str = "appimage:resolve";

/// A `deb:` URL: an `https://` URL to a prebuilt `.deb`. Required to be HTTPS (the fetch is not
/// authenticated beyond TLS, and a `.deb` is executed after autoPatchelf, so a plaintext source is
/// refused) and to end in `.deb` (so a mistyped value is caught, not silently built). The character
/// set is the unreserved URL set plus the sub-delims a release URL uses, so the value carries no
/// shell/nix metacharacter — it is interpolated into a generated nix expression and a
/// `nix store prefetch-file` argument, both of which must stay injection-free.
pub(crate) fn is_valid_deb_url(url: &str) -> bool {
    url.strip_prefix("https://").is_some_and(|rest| {
        !rest.is_empty()
            && url.ends_with(".deb")
            && url.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, ':' | '/' | '.' | '-' | '_' | '~' | '%')
            })
    })
}

/// An `appimage:` URL: an `https://` URL to a prebuilt `.AppImage`. The sibling of [`is_valid_deb_url`]
/// — required to be HTTPS (the fetch is unauthenticated beyond TLS and the bundle is executed after
/// autoPatchelf, so a plaintext source is refused) and to end in `.AppImage` (case-insensitively, so
/// a `.appimage` spelling is accepted; a mistyped value is caught, not silently built). The character
/// set is the same injection-free URL set, so the value carries no shell/nix metacharacter — it is
/// interpolated into a generated nix expression and a `nix store prefetch-file` argument.
pub(crate) fn is_valid_appimage_url(url: &str) -> bool {
    url.strip_prefix("https://").is_some_and(|rest| {
        !rest.is_empty()
            && url.to_ascii_lowercase().ends_with(".appimage")
            && url.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, ':' | '/' | '.' | '-' | '_' | '~' | '%')
            })
    })
}

/// A `tarball:` URL: an `https://` URL to a prebuilt application `.tar.gz`/`.tgz`. The sibling of
/// [`is_valid_deb_url`] — required to be HTTPS (the fetch is unauthenticated beyond TLS and the
/// bundle is executed after autoPatchelf, so a plaintext source is refused) and to end in `.tar.gz`
/// or `.tgz` (case-insensitively; a mistyped value is caught, not silently built). The character set
/// is the same injection-free URL set (including `%`, so a percent-encoded space like a vendor's
/// `My%20App.tar.gz` is accepted), so the value carries no shell/nix metacharacter — it is
/// interpolated into a generated nix expression and a `nix store prefetch-file` argument.
pub(crate) fn is_valid_tarball_url(url: &str) -> bool {
    url.strip_prefix("https://").is_some_and(|rest| {
        let lower = url.to_ascii_lowercase();
        !rest.is_empty()
            && (lower.ends_with(".tar.gz") || lower.ends_with(".tgz"))
            && url.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, ':' | '/' | '.' | '-' | '_' | '~' | '%')
            })
    })
}

/// A `deb:github:<owner>/<repo>` locator: track the newest GitHub release's linux `.deb` asset,
/// instead of pinning one versioned URL by hand. `owner` and `repo` are restricted to GitHub's
/// identifier set (`[A-Za-z0-9._-]`, exactly two segments, no empty or bare-dot segment), so the
/// value carries no shell/nix metacharacter — it is interpolated into a
/// `https://api.github.com/repos/<owner>/<repo>/releases/latest` request that must stay
/// injection-free, and the asset URL that request returns is re-validated by [`is_valid_deb_url`]
/// before it is fetched or built.
pub(crate) fn is_valid_deb_github_locator(s: &str) -> bool {
    let Some(path) = s.strip_prefix("github:") else {
        return false;
    };
    let mut parts = path.split('/');
    let (Some(owner), Some(repo), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    [owner, repo].iter().all(|seg| {
        !seg.is_empty()
            && *seg != "."
            && *seg != ".."
            && seg
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    })
}

/// A `deb:apt:<packages-url>` locator: track the newest `.deb` in an apt repository's uncompressed
/// `Packages` index, for a vendor apt pool that publishes versioned filenames with no `latest` alias
/// (so a hand-pinned URL goes stale). The `<packages-url>` is an `https://` URL restricted to the
/// same injection-free character set as [`is_valid_deb_url`] (it is interpolated into a
/// `builtins.fetchurl`), but it points at the index, not a `.deb`, so the `.deb` suffix is **not**
/// required. sbx fetches the index, selects the highest version's `.deb`, and **re-validates that
/// derived URL through [`is_valid_deb_url`]** before it is fetched or built — so the remote index
/// cannot inject a bad URL. Scope (documented, not a gap): the index must be the **uncompressed**
/// `Packages` (no `.gz`/`.xz` decompression), sbx does **no** `InRelease`/GPG signature check, and it
/// expects a **single-application** repo — the same TLS-plus-unpack trust level as a direct `deb:`
/// URL, not a general Debian mirror.
pub(crate) fn is_valid_deb_apt_locator(s: &str) -> bool {
    let Some(url) = s.strip_prefix("apt:") else {
        return false;
    };
    url.strip_prefix("https://").is_some_and(|rest| {
        !rest.is_empty()
            && url.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, ':' | '/' | '.' | '-' | '_' | '~' | '%')
            })
    })
}

/// Set the package named `name` to `backend` with the supplying layer's trust,
/// overriding an existing entry so a later layer wins while preserving declaration
/// order.
fn upsert_package(out: &mut Vec<Package>, name: String, backend: Backend, state: TrustState) {
    match out.iter_mut().find(|p| p.name == name) {
        Some(slot) => {
            slot.backend = backend;
            slot.state = state;
        }
        None => out.push(Package {
            name,
            backend,
            state,
        }),
    }
}

/// The actionable reason a project's security-relevant value is held back, phrased
/// for the action it implies: a since-*changed* project points at re-approval, a
/// never-trusted one at first approval. Shared by the package launcher and
/// `sbx config` so the two never phrase the same verdict differently.
pub(crate) fn untrusted_reason(state: TrustState) -> &'static str {
    match state {
        TrustState::Changed => "changed since it was trusted — re-run `sbx trust`",
        _ => "untrusted — run `sbx trust`",
    }
}

/// Validate a `nixpkgs` override source, returning it when well-formed and warning
/// when not. Dropping a malformed source keeps a bad value from reaching nix.
fn validate_nixpkgs(
    warnings: &mut Vec<String>,
    source_label: &str,
    value: String,
) -> Option<String> {
    if is_valid_nixpkgs_source(&value) {
        Some(value)
    } else {
        warnings.push(format!(
            "{source_label}: ignoring malformed nixpkgs source `{value}`"
        ));
        None
    }
}

/// Validate a `gui` posture string into [`GuiPolicy`], warning on anything unrecognized. A
/// typo must never silently leave the GUI in the wrong posture; returning `None` keeps the
/// prior (default or global) posture rather than guessing. There is intentionally no `x11`
/// value — X is never offered.
fn validate_gui(
    warnings: &mut Vec<String>,
    source_label: &str,
    value: String,
) -> Option<GuiPolicy> {
    match value.as_str() {
        "none" => Some(GuiPolicy::None),
        "wayland" => Some(GuiPolicy::Wayland),
        other => {
            warnings.push(format!(
                "{source_label}: ignoring unknown gui posture `{other}` \
                 (expected \"none\" or \"wayland\")"
            ));
            None
        }
    }
}

/// Validate a `proc` field — either a bare mode string or a `[proc]` table — mapping it to a
/// [`ProcPolicy`] and warning on an unknown mode. A typo must never silently leave enforcement in the
/// wrong posture; returning `None` keeps the prior (default or parent) policy rather than guessing.
/// `parent` is the policy of the layer immediately below: a `[proc]` table that omits `mode` inherits
/// its mode from `parent` while keeping its own `allow`/`deny` rules.
fn validate_proc(
    warnings: &mut Vec<String>,
    source_label: &str,
    field: crate::config::schema::ProcField,
    parent: &crate::proc_policy::ProcPolicy,
) -> Option<crate::proc_policy::ProcPolicy> {
    use crate::config::schema::ProcField;
    use crate::proc_policy::{ProcMode, ProcPolicy};
    let (mode_str, allow, deny) = match field {
        ProcField::Mode(m) => (Some(m), Vec::new(), Vec::new()),
        ProcField::Table(t) => (t.mode, t.allow, t.deny),
    };
    let mode = match mode_str {
        Some(m) => match ProcMode::parse(&m) {
            Some(pm) => pm,
            None => {
                warnings.push(format!(
                    "{source_label}: ignoring unknown proc mode `{m}` \
                     (expected \"off\", \"observe\", \"enforce\", or \"ask\")"
                ));
                return None;
            }
        },
        // A table with no mode inherits the parent layer's mode, keeping this table's own rules.
        None => parent.mode,
    };
    Some(ProcPolicy::new(mode, &allow, &deny))
}

/// Validate a `network` field — either a posture string or a `[network]` table — mapping it to a
/// policy and warning on anything unrecognized. A typo must never silently leave the network in the
/// wrong posture; returning `None` keeps the prior (default or global) posture rather than guessing.
/// `parent` is the network of the layer immediately below (the global default for the baseline
/// global layer, the resolved baseline for a project/app): a `[network]` table that omits `mode`
/// inherits its mode from `parent` (see [`mode_from_parent`]).
fn validate_network(
    warnings: &mut Vec<String>,
    source_label: &str,
    field: NetworkField,
    groups: &NetGroups,
    parent: &NetworkPolicy,
) -> Option<NetworkPolicy> {
    match field {
        NetworkField::Posture(value) => match value.as_str() {
            "none" => Some(NetworkPolicy::Isolated),
            "shared" => Some(NetworkPolicy::Shared),
            // The filtered-egress modes in bare-string form (no carve-out lists): `deny` =
            // deny-by-default (only the built-in set reaches), `allow` = allow-by-default (a
            // denylist; the proxy stays active). Carve-out lists need the `[network]` table.
            "deny" => Some(NetworkPolicy::Allowlist(
                crate::allowlist::EgressPolicy::default(),
            )),
            "allow" => Some(NetworkPolicy::Allowlist(
                crate::allowlist::EgressPolicy::default()
                    .with_default(crate::allowlist::DefaultAction::Allow),
            )),
            // `ask` in bare-string form parks every unmatched request with no timeout (an
            // indefinite wait); a bound needs the `[network]` table's `ask_timeout`.
            "ask" => Some(NetworkPolicy::Allowlist(
                crate::allowlist::EgressPolicy::default()
                    .with_default(crate::allowlist::DefaultAction::Ask),
            )),
            other => {
                warnings.push(format!(
                    "{source_label}: ignoring unknown network policy `{other}` (expected \
                     \"none\", \"shared\", \"deny\", \"allow\", \"ask\", or an `[network]` table)"
                ));
                None
            }
        },
        NetworkField::Table(table) => {
            validate_network_table(warnings, source_label, table, groups, parent)
        }
    }
}

/// The default action a mode-less `[network]` table inherits from its parent config layer. Only a
/// filtering `Deny`/`Ask` is inherited; an `Allow` (allow-by-default denylist), `Shared`, or
/// `Isolated` parent falls back to the safe `Deny`, so a table that lists `allow` rules is never
/// silently turned into a wide-open denylist (which would make its own allow-list inert — the exact
/// `allow`-vs-`deny` footgun) or into the open host network.
fn mode_from_parent(parent: &NetworkPolicy) -> crate::allowlist::DefaultAction {
    use crate::allowlist::DefaultAction;
    match parent {
        NetworkPolicy::Allowlist(p) => match p.default_action() {
            DefaultAction::Ask => DefaultAction::Ask,
            DefaultAction::Deny | DefaultAction::Allow => DefaultAction::Deny,
        },
        NetworkPolicy::Shared | NetworkPolicy::Isolated => DefaultAction::Deny,
    }
}

/// Parse the `[network] http2` entries into the proxy's host matchers. Each is a `host` or
/// `host:port`; a malformed entry is dropped with a warning (fail-closed — that host keeps
/// HTTP/1.1). Unlike `allow`/`deny`, these are not egress rules and carry no `@group`/path/method
/// grammar — HTTP/2 is a transport choice, orthogonal to the verdict.
fn parse_http2_hosts(
    warnings: &mut Vec<String>,
    source_label: &str,
    entries: Vec<String>,
) -> Vec<crate::allowlist::Http2Host> {
    let mut hosts = Vec::with_capacity(entries.len());
    for entry in entries {
        match crate::allowlist::Http2Host::parse(&entry) {
            Some(h) => hosts.push(h),
            None => warnings.push(format!(
                "{source_label}: ignoring malformed `http2` entry `{entry}` \
                 (expected a host or host:port); that host keeps HTTP/1.1"
            )),
        }
    }
    hosts
}

/// Validate the table form of `network`: `none`/`shared` behave as the string form; `deny`/`allow`/
/// `ask` classify each declared entry (a malformed one is dropped with a warning, fail-closed —
/// that host simply stays unreachable, never silently allowed); and an **omitted** `mode` inherits
/// the filtering mode from `parent` while keeping this table's own rules.
fn validate_network_table(
    warnings: &mut Vec<String>,
    source_label: &str,
    table: NetworkTable,
    groups: &NetGroups,
    parent: &NetworkPolicy,
) -> Option<NetworkPolicy> {
    use crate::allowlist::DefaultAction;
    // The default action: from an explicit `mode`, or — when omitted — inherited from the parent
    // layer. `none`/`shared` are non-filtering postures that carry no rules, so they return early.
    let action = match table.mode.as_deref() {
        Some("none") => return Some(NetworkPolicy::Isolated),
        Some("shared") => return Some(NetworkPolicy::Shared),
        // `deny` = deny-by-default (only what `allow` lists reaches). `allow` = the denylist
        // (everything public reaches except the `deny` carve-outs, proxy still active). `ask` parks
        // an unmatched request for a live decision (allow rules auto-pass, deny rules auto-fail).
        Some("deny") => DefaultAction::Deny,
        Some("allow") => DefaultAction::Allow,
        Some("ask") => DefaultAction::Ask,
        Some(other) => {
            warnings.push(format!(
                "{source_label}: ignoring unknown network mode `{other}` (expected \"none\", \
                 \"shared\", \"deny\", \"allow\", or \"ask\")"
            ));
            return None;
        }
        None => mode_from_parent(parent),
    };
    let allow = classify_entries(warnings, source_label, "allow", table.allow, groups);
    let deny = classify_entries(warnings, source_label, "deny", table.deny, groups);
    // `mute` (SELinux `dontaudit`) suppresses a *denied* request's log line — never a verdict — so
    // it classifies with the same grammar as `allow`/`deny` (including `@group` expansion) and is
    // carried on the policy for the proxy to consult at logging time.
    let mute = classify_entries(warnings, source_label, "mute", table.mute, groups);
    // `http2` names the hosts the proxy speaks HTTP/2 to (ALPN `h2`, for gRPC). It is not an egress
    // rule (no path/method/verdict) — just a host[:port] the proxy MITMs as h2 — so it parses on its
    // own, dropping a malformed entry with a warning (fail-closed: that host keeps HTTP/1.1).
    let http2 = parse_http2_hosts(warnings, source_label, table.http2);
    let mut policy = crate::allowlist::EgressPolicy::new(allow, deny)
        .with_default(action)
        .with_mute(mute)
        .with_http2(http2);
    if action == DefaultAction::Ask {
        // A configured `ask_timeout` bounds the parked wait; a malformed value falls back to
        // indefinite (warned), never a hard config failure.
        let timeout = match &table.ask_timeout {
            None => None,
            Some(raw) => parse_ask_timeout(raw).unwrap_or_else(|reason| {
                warnings.push(format!(
                    "{source_label}: ignoring invalid `ask_timeout` — {reason}; \
                     parked requests will wait indefinitely"
                ));
                None
            }),
        };
        policy = policy
            .with_ask_timeout(timeout)
            .with_ask_notice(table.ask_notice.unwrap_or(true));
    } else {
        // `ask_timeout`/`ask_notice` are moot outside the effective `ask` mode — flag them rather
        // than silently drop (the effective mode may be inherited, so key off `action`, not the raw
        // `mode` string).
        if table.ask_timeout.is_some() {
            warnings.push(format!(
                "{source_label}: `ask_timeout` is only meaningful under `mode = \"ask\"` — ignored"
            ));
        }
        if table.ask_notice.is_some() {
            warnings.push(format!(
                "{source_label}: `ask_notice` is only meaningful under `mode = \"ask\"` — ignored"
            ));
        }
    }
    // DNS cache TTL for the proxy's resolver (every filtering posture runs one). The proxy resolves
    // each allowed host once and reuses the address for this long, so a long build fetching from one
    // host thousands of times does not re-hit the resolver each request. Optional; default 60s, `0`
    // disables the cache.
    if let Some(secs) = table.dns_cache_ttl {
        policy = policy.with_dns_cache_ttl(Some(std::time::Duration::from_secs(secs)));
    }
    Some(NetworkPolicy::Allowlist(policy))
}

/// Parse an `ask_timeout` duration string: a non-negative integer with an optional unit suffix
/// (`s` seconds [the default], `m` minutes, `h` hours), e.g. `"90s"`, `"5m"`, `"2h"`, or a bare
/// `"90"`. A zero-valued form (`"0"`, `"0m"`) means no timeout — an indefinite wait, the same as
/// omitting the field — so it returns `Ok(None)`; a positive value returns `Ok(Some(duration))`.
/// A malformed value is `Err(reason)` so the caller can warn and fall back to indefinite.
fn parse_ask_timeout(raw: &str) -> Result<Option<std::time::Duration>, String> {
    let s = raw.trim();
    let malformed = || format!("`{raw}` is not a duration (try \"90s\", \"5m\", \"2h\")");
    let (digits, unit) = if let Some(n) = s.strip_suffix('s') {
        (n, 1u64)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3600)
    } else {
        (s, 1)
    };
    let n: u64 = digits.trim().parse().map_err(|_| malformed())?;
    let secs = n
        .checked_mul(unit)
        .ok_or_else(|| format!("`{raw}` is too large"))?;
    Ok((secs > 0).then(|| std::time::Duration::from_secs(secs)))
}

/// Pre-classified reusable egress groups: each `[net.groups]` name mapped to the rules its
/// entries classify to. Built once from the global config (trusted by location) and consulted
/// when a `[network]` `allow`/`deny` list references a group with `@<name>`.
type NetGroups = BTreeMap<String, Vec<crate::allowlist::Rule>>;

/// Classify the entries of one egress list (`allow` or `deny`), expanding a leading `@<name>`
/// into the rules of that named group (from `[net.groups]`). A malformed entry is dropped with
/// a warning that names which list it was in; an unknown `@<name>` reference is dropped with a
/// *loud* warning — a miss in a `deny` list silently drops a carve-out (the host would no longer
/// be blocked), the one case where a typo fails open in intent, so an unresolved reference must
/// never pass unnoticed. Only a leading `@` is a reference: a `@` anywhere else (a URL path like
/// `host/@user`, a `re:` pattern) is a legitimate part of the entry and is classified as written.
fn classify_entries(
    warnings: &mut Vec<String>,
    source_label: &str,
    list: &str,
    entries: Vec<String>,
    groups: &NetGroups,
) -> Vec<crate::allowlist::Rule> {
    let mut rules = Vec::new();
    for entry in entries {
        if let Some(name) = entry.trim().strip_prefix('@') {
            match groups.get(name) {
                Some(group_rules) => rules.extend(group_rules.iter().cloned()),
                None => warnings.push(format!(
                    "{source_label}: {list} references undefined group `@{name}` — define it under \
                     `[net.groups]` in the global config, or remove the reference (the entry is \
                     ignored, so nothing is {} for it)",
                    if list == "deny" { "denied" } else { "allowed" }
                )),
            }
            continue;
        }
        match crate::allowlist::classify(&entry) {
            Ok(rule) => rules.push(rule),
            Err(e) => warnings.push(format!("{source_label}: ignoring {list} entry — {e}")),
        }
    }
    rules
}

/// Validate and pre-classify the global `[net.groups]` table into a [`NetGroups`] map. Each
/// group's name is charset-validated (an invalid name is skipped with a warning), and each entry
/// is classified like an `allow`/`deny` entry — a malformed one is dropped with a warning naming
/// the group. A nested reference (`@other` inside a group) is rejected: a group is a flat list of
/// egress entries in this version, so an unbounded or cyclic expansion is impossible by
/// construction. Building every defined group here (not only referenced ones) surfaces a typo in
/// an unused group early rather than only when some app first references it.
fn build_net_groups(warnings: &mut Vec<String>, raw: BTreeMap<String, Vec<String>>) -> NetGroups {
    let mut groups = NetGroups::new();
    for (name, entries) in raw {
        if !is_valid_group_name(&name) {
            warnings.push(format!(
                "{GLOBAL_CONFIG}: ignoring net group `{name}`: a name must be 1–64 of [A-Za-z0-9._-]"
            ));
            continue;
        }
        let mut rules = Vec::new();
        for entry in entries {
            if entry.trim().starts_with('@') {
                warnings.push(format!(
                    "{GLOBAL_CONFIG}: net group `{name}`: ignoring nested reference `{}` — a group \
                     is a flat list of egress entries and may not reference another group",
                    entry.trim()
                ));
                continue;
            }
            match crate::allowlist::classify(&entry) {
                // Tag each rule with the group it came from, so a `@<name>` expansion carries its
                // origin into the resolved policy for `sbx net rules` to render (excluded from the
                // rule's equality, so this affects only display).
                Ok(mut rule) => {
                    rule.group = Some(name.clone());
                    rules.push(rule);
                }
                Err(e) => warnings.push(format!(
                    "{GLOBAL_CONFIG}: net group `{name}`: ignoring entry `{entry}` — {e}"
                )),
            }
        }
        groups.insert(name, rules);
    }
    groups
}

/// Whether a `[net.groups]` name is a safe, referenceable identifier. A group name is not a path
/// component (unlike an app name), so `.`/`..` are harmless; it is charset- and length-bounded so
/// a reference `@<name>` is unambiguous and the name renders cleanly in warnings and `sbx net`.
/// Shared with the `sbx net allow/deny` write path so a persisted `@<name>` reference is validated
/// by the same rule the resolver uses to name a group.
pub(crate) fn is_valid_group_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Validate and fold a layer's `[secret]` host entries into `out`, expanding any terse `key`
/// through `defaults`. Each entry is fully validated (kind, source, target, header, type); a
/// malformed one is dropped with a warning naming the host — fail-closed, since a credential
/// injection is security-relevant. A later entry for the same (host, header) overrides an
/// earlier one (last-wins) with a warning, so a duplicate destination never silently emits two
/// header copies upstream.
fn apply_secret_section(
    out: &mut Vec<HeaderSecret>,
    warnings: &mut Vec<String>,
    source: &str,
    hosts: BTreeMap<String, RawHostSecrets>,
    defaults: &SecretDefaults,
    plugins: &PluginRegistry,
) {
    for (host, entry) in hosts {
        let list = match entry {
            RawHostSecrets::One(s) => vec![s],
            RawHostSecrets::Many(v) => v,
        };
        for raw in list {
            match validate_host_secret(&host, raw, defaults, plugins) {
                Ok(secret) => upsert_secret(out, warnings, source, secret),
                Err(e) => warnings.push(format!("{source}: ignoring secret for `{host}` — {e}")),
            }
        }
    }
}

/// Total host secrets in a section — counting each element of a `[[secret."host"]]` array — for
/// the one-line warning when an untrusted project's whole section is dropped.
fn count_host_secrets(hosts: &BTreeMap<String, RawHostSecrets>) -> usize {
    hosts
        .values()
        .map(|h| match h {
            RawHostSecrets::One(_) => 1,
            RawHostSecrets::Many(v) => v.len(),
        })
        .sum()
}

/// Set the secret for its (target, header) pair, overriding an existing one (last-wins)
/// with a warning while preserving declaration order. Two secrets to the same host and
/// header would otherwise inject two copies of the header upstream.
fn upsert_secret(
    out: &mut Vec<HeaderSecret>,
    warnings: &mut Vec<String>,
    source: &str,
    secret: HeaderSecret,
) {
    match out
        .iter_mut()
        .find(|s| s.to == secret.to && s.header.eq_ignore_ascii_case(&secret.header))
    {
        Some(slot) => {
            warnings.push(format!(
                "{source}: a later secret overrides an earlier one for `{}` -> {}",
                secret.header, secret.to
            ));
            *slot = secret;
        }
        None => out.push(secret),
    }
}

/// Validate one host entry into a [`HeaderSecret`], or report why it is malformed. `host` is the
/// section key (the injection target). Every check fails closed: an unknown kind, a missing or
/// both-set source, a non-concrete target, a bad header name, or a missing/unknown type each
/// drops the secret. `kind` is optional, defaulting to the only kind today.
fn validate_host_secret(
    host: &str,
    raw: RawHostSecret,
    defaults: &SecretDefaults,
    plugins: &PluginRegistry,
) -> Result<HeaderSecret, String> {
    let kind = raw.kind.as_deref().unwrap_or("http-header");
    if kind != "http-header" {
        return Err(format!(
            "unknown kind `{kind}` (the only secret kind today is \"http-header\")"
        ));
    }
    let sources = resolve_host_sources(&raw, defaults, plugins)?;
    let to = validate_secret_target(host)?;
    // `header` and `type` may come from the entry or fall back to `[secret.defaults]`; an entry
    // that names neither (on itself or in the defaults) is the same explicit error as before —
    // there is no silent built-in default.
    let header = raw
        .header
        .as_deref()
        .or(defaults.header.as_deref())
        .ok_or_else(|| {
            "set `header` (or a `[secret.defaults] header`) — the request header to set".to_string()
        })?;
    validate_header_name(header)?;
    let value_type = raw.value_type.as_deref().or(defaults.value_type.as_deref());
    let shape = validate_header_shape(value_type, raw.prefix.as_deref())?;
    Ok(HeaderSecret {
        sources,
        to,
        header: header.to_string(),
        shape,
    })
}

/// The resolver chain for a host secret: either the explicit `from` (a single `scheme://locator`
/// ref or a list tried in order) or the terse `key` expanded through `defaults` — exactly one of
/// the two. Both set, or neither, is rejected; an empty `from` list is rejected. The values are
/// not read here; that is host-side at launch.
fn resolve_host_sources(
    raw: &RawHostSecret,
    defaults: &SecretDefaults,
    plugins: &PluginRegistry,
) -> Result<Vec<SecretSource>, String> {
    match (raw.key.as_deref(), &raw.from) {
        (Some(_), Some(_)) => {
            Err("set `key` or `from`, not both — a secret has one source form".to_string())
        }
        (None, None) => Err(
            "set `key` or `from` — a secret needs a source (e.g. `key = \"github_token\"` \
                 or `from = \"env://VAR\"`)"
                .to_string(),
        ),
        (Some(key), None) => expand_key(key, defaults),
        (None, Some(from)) => {
            let refs: &[String] = match from {
                SecretFrom::One(one) => std::slice::from_ref(one),
                SecretFrom::Many(list) => {
                    if list.is_empty() {
                        return Err(
                            "`from` is an empty list — declare at least one resolver ref"
                                .to_string(),
                        );
                    }
                    list
                }
            };
            refs.iter().map(|r| parse_secret_ref(r, plugins)).collect()
        }
    }
}

/// The validated `[secret.defaults]` — the resolver order and per-resolver bindings a terse `key`
/// expands through, plus a default `header`/`type` an entry may omit. Built per config layer;
/// bindings and the header/type are validated lazily, when an entry actually uses them, so a
/// defaults table no entry references never blocks a launch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SecretDefaults {
    /// Resolver names to try, in order, for an unpinned key.
    order: Vec<String>,
    /// The sops file a terse sops key reads from (`sops://<file>#<key>`).
    sops_file: Option<String>,
    /// How to case a terse key before using it as a variable name (`upper`/`lower`/`asis`).
    env_case: Option<String>,
    /// The base directory a terse file key reads from (`file://<dir>/<key>`).
    file_dir: Option<String>,
    /// The default header name for an entry that omits `header`.
    header: Option<String>,
    /// The default value type for an entry that omits `type`.
    value_type: Option<String>,
}

impl SecretDefaults {
    /// The defaults declared in one `[secret.defaults]` table.
    fn from_raw(raw: &RawSecretDefaults) -> Self {
        Self {
            order: raw.order.clone(),
            sops_file: raw.sops.as_ref().map(|s| s.file.clone()),
            env_case: raw.env.as_ref().and_then(|e| e.case.clone()),
            file_dir: raw.file.as_ref().map(|f| f.dir.clone()),
            header: raw.header.clone(),
            value_type: raw.value_type.clone(),
        }
    }

    /// These defaults overridden field-by-field by a project's `[secret.defaults]`: an order, a
    /// binding, or a header/type the project sets wins; anything it omits inherits the global value.
    fn merged_with(&self, raw: &RawSecretDefaults) -> Self {
        Self {
            order: if raw.order.is_empty() {
                self.order.clone()
            } else {
                raw.order.clone()
            },
            sops_file: raw
                .sops
                .as_ref()
                .map(|s| s.file.clone())
                .or_else(|| self.sops_file.clone()),
            env_case: raw
                .env
                .as_ref()
                .and_then(|e| e.case.clone())
                .or_else(|| self.env_case.clone()),
            file_dir: raw
                .file
                .as_ref()
                .map(|f| f.dir.clone())
                .or_else(|| self.file_dir.clone()),
            header: raw.header.clone().or_else(|| self.header.clone()),
            value_type: raw.value_type.clone().or_else(|| self.value_type.clone()),
        }
    }
}

/// Expand a terse `key` spec into a resolver chain. The spec is `name[@resolver[,resolver…]]`:
/// without a `@` pin the default `order` is used; with one, exactly those resolvers in that
/// order, for this secret only. The `name` is validated as a conservative dotted key (so it can
/// never carry a path separator into the `file`/`sops` locator), each resolver builds a
/// `scheme://locator` ref, and the existing [`parse_secret_ref`] validates it — one validation
/// path for terse and explicit sources alike. A missing binding or an empty order fails closed.
fn expand_key(spec: &str, defaults: &SecretDefaults) -> Result<Vec<SecretSource>, String> {
    let (name, resolvers) = match spec.rsplit_once('@') {
        Some((name, pin)) => {
            let list: Vec<String> = pin.split(',').map(|r| r.trim().to_string()).collect();
            if list.iter().any(String::is_empty) {
                return Err(format!(
                    "the key `{spec}` has an empty resolver name after `@`"
                ));
            }
            (name, list)
        }
        None => (spec, defaults.order.clone()),
    };
    validate_terse_key(name)?;
    if resolvers.is_empty() {
        return Err(format!(
            "no resolver for key `{name}`: set `[secret.defaults] order` or pin it (e.g. \
             `{name}@env`)"
        ));
    }
    // A terse `key` only ever expands to a built-in resolver ref (`build_ref` emits `env://`,
    // `sops://`, or `file://`), so the registry is intentionally empty here: terse plugin
    // bindings (`key@<plugin>`) are a deliberate later addition, not silently in scope.
    let builtins_only = PluginRegistry::default();
    resolvers
        .iter()
        .map(|r| parse_secret_ref(&build_ref(r, name, defaults)?, &builtins_only))
        .collect()
}

/// Build a `scheme://locator` ref for one resolver from a terse `key`, applying that resolver's
/// binding: `env` cases the key into a variable name; `sops` joins the key onto the bound file
/// (`<file>#<key>`); `file` joins it onto the bound base directory (`<dir>/<key>`). A resolver
/// whose binding is unset, or an unknown resolver name, fails closed.
fn build_ref(resolver: &str, key: &str, defaults: &SecretDefaults) -> Result<String, String> {
    match resolver {
        "env" => {
            let name = match defaults.env_case.as_deref() {
                None | Some("asis") => key.to_string(),
                Some("upper") => key.to_ascii_uppercase(),
                Some("lower") => key.to_ascii_lowercase(),
                Some(other) => {
                    return Err(format!(
                        "unknown env `case` `{other}` (expected \"upper\", \"lower\", or \"asis\")"
                    ))
                }
            };
            Ok(format!("env://{name}"))
        }
        "sops" => {
            let file = defaults.sops_file.as_deref().ok_or_else(|| {
                format!("key `{key}` uses the sops resolver, but `[secret.defaults.sops] file` is unset")
            })?;
            if file.contains('#') {
                return Err(format!(
                    "the sops file `{file}` contains `#`, reserved by the `sops://<file>#<key>` form"
                ));
            }
            Ok(format!("sops://{file}#{key}"))
        }
        "file" => {
            let dir = defaults.file_dir.as_deref().ok_or_else(|| {
                format!(
                    "key `{key}` uses the file resolver, but `[secret.defaults.file] dir` is unset"
                )
            })?;
            if !std::path::Path::new(dir).is_absolute() {
                return Err(format!(
                    "the `[secret.defaults.file] dir` `{dir}` must be an absolute path"
                ));
            }
            let sep = if dir.ends_with('/') { "" } else { "/" };
            Ok(format!("file://{dir}{sep}{key}"))
        }
        other => Err(format!(
            "unknown resolver `{other}` for key `{key}` (built-in: env, file, sops)"
        )),
    }
}

/// Validate a terse `key`: dot-separated segments, each non-empty and made of letters, digits,
/// `_`, or `-`. Stricter than an env variable name on purpose — it forbids `/` and `..`, so a key
/// joined onto a `file`/`sops` locator can never carry a path separator or traverse out of the
/// bound directory.
fn validate_terse_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("a terse `key` is empty".to_string());
    }
    for seg in key.split('.') {
        if seg.is_empty() {
            return Err(format!("the key `{key}` has an empty segment"));
        }
        if !seg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(format!(
                "the key `{key}` has an invalid segment `{seg}` (allowed: letters, digits, _, -, \
                 separated by `.`)"
            ));
        }
    }
    Ok(())
}

/// Parse one `from` entry — a `scheme://locator` resolver ref — into a [`SecretSource`]. The
/// built-in schemes are `env`, `file`, and `sops`; any other scheme must be claimed by an
/// installed resolver plugin, else it is an error. A bare token with no `://` is an error too
/// (fail-closed: never a silent mis-read as a path or a variable).
fn parse_secret_ref(reff: &str, plugins: &PluginRegistry) -> Result<SecretSource, String> {
    let Some((scheme, locator)) = reff.split_once("://") else {
        return Err(format!(
            "a secret source needs a scheme, e.g. `env://VAR` or `file:///abs/path` (`{reff}`)"
        ));
    };
    match scheme {
        "env" => env_source(locator),
        "file" => file_source(locator),
        "sops" => sops_source(locator),
        other => match plugins.resolver(other) {
            Some(plugin) => {
                validate_plugin_locator(other, locator)?;
                Ok(SecretSource::Plugin {
                    plugin: plugin.clone(),
                    locator: locator.to_string(),
                })
            }
            None => Err(format!(
                "unknown secret resolver scheme `{other}://` (built-in: env, file, sops; \
                 or install a resolver plugin that claims it)"
            )),
        },
    }
}

/// Validate a plugin ref's locator before it becomes the plugin's `argv[1]`: non-empty and free
/// of control characters (a NUL would truncate the argument, a newline could confuse a
/// line-oriented resolver). The trust gate is the real control — an untrusted project's secrets
/// are dropped before this is reached — so this is belt-and-suspenders for the trusted path.
fn validate_plugin_locator(scheme: &str, locator: &str) -> Result<(), String> {
    if locator.is_empty() {
        return Err(format!("the `{scheme}://` ref has an empty locator"));
    }
    if locator.chars().any(char::is_control) {
        return Err(format!(
            "the `{scheme}://` ref locator contains a control character"
        ));
    }
    Ok(())
}

/// An `env` source from a variable name, validated as a usable shell variable name.
fn env_source(var: &str) -> Result<SecretSource, String> {
    if !is_valid_env_key(var) {
        return Err(format!("`{var}` is not a valid environment variable name"));
    }
    Ok(SecretSource::Env(var.to_string()))
}

/// A `sops` source from `<file>[#<dotted.key>]`. The `#` is split off the **end** (a sops key
/// cannot contain `#`, so a `#` in the file path is preserved); the key, when present, is
/// charset-validated so it can never malform the `["seg"]["seg"]` extract expression sops parses.
/// The file may be relative (resolved against the project root host-side) or absolute.
fn sops_source(locator: &str) -> Result<SecretSource, String> {
    let (file, key) = match locator.rsplit_once('#') {
        Some((f, k)) => (f, Some(k)),
        None => (locator, None),
    };
    if file.is_empty() {
        return Err("a sops source needs a file path `sops://<file>[#<key>]`".to_string());
    }
    if let Some(k) = key {
        validate_sops_key(k)?;
    }
    Ok(SecretSource::Sops {
        file: PathBuf::from(file),
        key: key.map(String::from),
    })
}

/// Validate a sops `--extract` key path: dot-separated segments, each non-empty and made of
/// letters, digits, `_`, or `-`. Rejects an empty key (a trailing `#`), an empty segment
/// (`a..b`, `.a`, `a.`), and any character that could break the bracketed extract expression.
fn validate_sops_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("the sops source has an empty key after `#`".to_string());
    }
    for seg in key.split('.') {
        if seg.is_empty() {
            return Err(format!("the sops key `{key}` has an empty path segment"));
        }
        if !seg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(format!(
                "the sops key `{key}` has an invalid segment `{seg}` (allowed: letters, digits, _, -)"
            ));
        }
    }
    Ok(())
}

/// A `file` source from an absolute host path (a relative path is rejected — it would resolve
/// against an unpredictable working directory).
fn file_source(file: &str) -> Result<SecretSource, String> {
    let path = PathBuf::from(file);
    if !path.is_absolute() {
        return Err(format!(
            "a file secret path must be an absolute path `{file}`"
        ));
    }
    Ok(SecretSource::File(path))
}

/// Classify a secret's `to` into a concrete-host rule. A credential goes to one known
/// destination, so only an exact host, IP, or `host[:port]/path` URL is allowed — a
/// `*.domain` wildcard or a `re:` regex is rejected, since either could match a host the
/// user never meant to hand the secret to.
fn validate_secret_target(to: &str) -> Result<Rule, String> {
    let rule = crate::allowlist::classify(to).map_err(|e| format!("invalid `to` target — {e}"))?;
    // A credential is host-scoped — injected into every request to the destination, regardless of
    // verb — so a `{...}` (or `{*}`) method prefix on the `to` host is meaningless and would only
    // confuse. A bare `to` host classifies as `Methods::Unspecified`; anything else is an explicit
    // prefix, rejected fail-closed (a method constraint belongs only on an allow/deny rule).
    if rule.methods != Methods::Unspecified {
        return Err(format!(
            "a secret `to` host carries no method prefix — remove the `{{...}}` from `{to}` \
             (a credential is injected for the host on every method)"
        ));
    }
    // A credential is an HTTP-header injection, which only the inspected-over-TLS (MITM) path can
    // perform. A `tcp://` (raw L4) destination is spliced byte-for-byte, so there is no request head
    // to inject into; an `http://` (cleartext L7) destination has a head, but sending a bearer in the
    // clear would downgrade the credential. Reject either fail-closed rather than silently never
    // injecting (or injecting over plaintext).
    if rule.layer != Layer::L7 {
        let scheme = if rule.layer == Layer::L4 {
            "tcp://"
        } else {
            "http://"
        };
        return Err(format!(
            "a secret `to` host must be an inspected-over-TLS destination — remove the `{scheme}` \
             from `{to}` (a header credential is never injected into a raw or a cleartext stream)"
        ));
    }
    match rule.kind {
        RuleKind::Ip(..) | RuleKind::Host(..) | RuleKind::Url { .. } => Ok(rule),
        RuleKind::Subdomain(..) => Err(format!(
            "`to` must be a concrete host, not the `*.` wildcard `{to}` \
             (a credential is sent to one known host)"
        )),
        RuleKind::Regex { .. } => Err(format!(
            "`to` must be a concrete host, not the regex `{to}` \
             (a credential is sent to one known host)"
        )),
    }
}

/// A header name usable in a request head: a non-empty token free of control characters,
/// whitespace, and `:`, so it can never split the head or carry a second header.
fn validate_header_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("the `header` name is empty".to_string());
    }
    if name
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == ':')
    {
        return Err(format!("invalid `header` name `{name}`"));
    }
    Ok(())
}

/// Build the [`HeaderShape`] from the required `type` and the optional `prefix`. The type
/// is required — there is no default, so an omitted type is an explicit error rather than a
/// silent (and likely wrong) transform. A given `prefix` may carry no control character,
/// since it becomes part of the header value.
fn validate_header_shape(
    value_type: Option<&str>,
    prefix: Option<&str>,
) -> Result<HeaderShape, String> {
    if let Some(p) = prefix {
        if p.chars().any(char::is_control) {
            return Err("the `prefix` contains a control character".to_string());
        }
    }
    let (default_prefix, base64) =
        match value_type {
            Some("bearer") => ("Bearer ", false),
            Some("raw") => ("", false),
            Some("basic") => ("Basic ", true),
            Some(other) => {
                return Err(format!(
                    "unknown `type` `{other}` (expected \"bearer\", \"basic\", or \"raw\")"
                ))
            }
            None => return Err(
                "missing `type` (one of \"bearer\", \"basic\", or \"raw\"; set it on the secret \
                 or as a `[secret.defaults] type`)"
                    .to_string(),
            ),
        };
    Ok(HeaderShape {
        prefix: prefix.unwrap_or(default_prefix).to_string(),
        base64,
    })
}

/// A nixpkgs source: a branch/channel name (`nixos-23.11`) or a 40-hex revision
/// under `NixOS/nixpkgs`. Restricted to the characters those use so a declared value
/// can never widen into a different flake reference (a fork, a `git+https`/`path:`
/// URL) or smuggle shell-significant characters into a nix invocation — even from a
/// trusted config. Arbitrary flake references are a later, additive feature.
fn is_valid_nixpkgs_source(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
}

/// An env key usable with `--setenv`: non-empty, and free of `=` and control
/// characters (NUL, newline). A malformed key — reachable through a quoted TOML
/// key — is dropped rather than handed to the sandbox.
fn is_valid_env_key(key: &str) -> bool {
    !key.is_empty() && !key.contains('=') && !key.chars().any(char::is_control)
}

/// A package label usable as a single path component (it names a garbage-collection
/// root) and a stable merge key: non-empty, neither `.` nor `..`, and built only
/// from portable filename characters — so it can never carry a path separator,
/// escape its directory, or collide with a traversal element.
fn is_valid_package_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// A nixpkgs attribute path: a dotted chain of attribute names (e.g.
/// `python3Packages.requests`). Restricted to the characters a real attribute uses
/// so a declared value can never widen into a different flake reference or smuggle
/// shell- or flake-significant characters, even though it is passed to nix as a
/// single argument.
fn is_valid_attr(attr: &str) -> bool {
    !attr.is_empty()
        && attr
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+'))
}

/// A mise backend token (the part after `mise:`), e.g. `aqua:example/demo-tool`, `bare-tool`,
/// `npm:@example/demo-tool`, or `aqua:example/demo-tool@0.141.0`. It rides the equip
/// wrapper positionally, so it cannot inject shell whatever it contains; the charset is
/// still restricted to what a real token uses (no whitespace or control characters) so a
/// malformed value is refused rather than handed to mise. The `[`, `]`, and `,` are admitted
/// for PEP 508 extras (`pipx:demo-agent[web]`, `pipx:demo-agent[web,messaging]`) — a
/// Python install selects optional dependency groups that way. They are not shell or nix
/// metacharacters in any backend (the token is positional argv to mise, and the equip never
/// interpolates it into a nix expression or a shell string), so admitting them adds no
/// injection surface; a backend that does not understand them simply rejects the token.
fn is_valid_mise_token(token: &str) -> bool {
    !token.is_empty()
        && token.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, ':' | '/' | '@' | '.' | '_' | '-' | '+' | '[' | ']' | ',')
        })
}

/// A flake reference (the part after `flake:`), e.g. `github:owner/repo#attr`,
/// `github:owner/repo/rev#attr`, or `git+https://host/repo?ref=main#attr`. It rides the
/// in-cage build wrapper positionally, so it cannot inject shell whatever it contains; the
/// charset is still restricted to what a real flake ref uses — the URL-significant
/// characters (`:` `/` `#` `?` `=` `&` `~`) plus the identifier set — so a malformed or
/// shell/space-bearing value is refused rather than handed to nix. **Local sources are
/// rejected** so a package declaration can never point the in-cage build at a filesystem
/// path: not only the explicit local schemes (`path:`, and any `file:` or `+file:` scheme —
/// `file://`, `git+file:`, `tarball+file:`, …) but also a **bare path-flakeref** — nix treats a
/// ref starting with `/`, `.`, or `~` as a local path — and an ambiguous registry-indirect ref
/// (`nixpkgs`), by *requiring an explicit scheme* (a `:`). A real remote ref always carries one
/// (`github:`, `git+https:`, `gitlab:`, …).
fn is_valid_flake_ref(reference: &str) -> bool {
    if reference.is_empty()
        || reference.starts_with("path:")
        || reference.starts_with("file:")
        || reference.contains("+file:")
        || reference.starts_with('/')
        || reference.starts_with('.')
        || reference.starts_with('~')
        || !reference.contains(':')
    {
        return false;
    }
    reference.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                ':' | '/' | '#' | '?' | '=' | '&' | '~' | '@' | '.' | '_' | '-' | '+'
            )
    })
}

/// Set `key` to `val`, overriding an existing entry so a later layer wins over an
/// earlier one at the same key while preserving declaration order.
fn upsert(env: &mut Vec<(String, String)>, key: String, val: String) {
    match env.iter_mut().find(|(k, _)| *k == key) {
        Some(slot) => slot.1 = val,
        None => env.push((key, val)),
    }
}

/// The warning for security binds dropped from an untrusted project, made
/// actionable: a *changed* file points at re-approval, a never-trusted one at the
/// first approval.
fn dropped_binds_warning(state: TrustState, count: usize) -> String {
    match state {
        TrustState::Changed => format!(
            "{PROJECT_CONFIG} changed since it was trusted: dropping {count} bind(s) — \
             re-run `sbx trust` to re-approve"
        ),
        _ => format!(
            "{PROJECT_CONFIG} is untrusted: dropping {count} bind(s) — \
             run `sbx trust` to apply them"
        ),
    }
}

/// Which configuration layers feed a resolution. `All` is what a launch and the full `sbx config
/// show` use; the restricted forms back the single-source `sbx config show --global/--local/
/// --default` views, each showing what one layer contributes (over the built-in defaults) so the
/// provenance tags read as that layer's own additions. Plugins and bind canonicalization are
/// unaffected — only which config *files* are read changes.
#[derive(Clone, Copy)]
pub(crate) enum Source {
    /// Global config (and imported profiles) layered under the project — the default.
    All,
    /// The global config and imported profiles only; the project layer is ignored.
    Global,
    /// The project config only; the global config and imported profiles are ignored.
    Local,
    /// Neither config; the built-in defaults alone.
    Default,
}

impl Source {
    fn includes_global(self) -> bool {
        matches!(self, Source::All | Source::Global)
    }

    fn includes_project(self) -> bool {
        matches!(self, Source::All | Source::Local)
    }
}

/// Load and resolve the configuration for a project rooted at `cwd`. Infallible by
/// design: every failure mode (absent, unsafe, unparseable, no trust store)
/// degrades to a warning and a dropped layer, so a command is never blocked by a
/// bad config — least of all an attacker-controlled project one.
pub(crate) fn load(cwd: &Path) -> Resolved {
    load_scoped(cwd, Source::All)
}

/// Resolve the configuration for `cwd` restricted to `source`'s layers. `load_scoped(cwd,
/// Source::All)` is [`load`] — the launch and full-view path; the restricted forms read fewer
/// config files but are otherwise byte-identical (same plugins, mise gating, bind
/// canonicalization, and warning assembly), so a single-source view stays a faithful slice of
/// the same resolution rather than a parallel code path.
pub(crate) fn load_scoped(cwd: &Path, source: Source) -> Resolved {
    let mut warnings = Vec::new();
    // Imported app profiles live beside the global config and are trusted by location, so they
    // join the global app layer before resolution — `resolve_app`/`resolve_apps` then gate and
    // layer them exactly like an inline global app, with no special casing. They ride the global
    // layer, so a `--local` (project-only) view omits them just as it omits the global config.
    let global = if source.includes_global() {
        let mut global = read_global(&mut warnings);
        let profiles = read_profile_apps(&mut warnings);
        merge_profile_apps(&mut global, profiles, &mut warnings);
        global
    } else {
        RawConfig::default()
    };
    let project = if source.includes_project() {
        read_project(cwd, &mut warnings)
    } else {
        None
    };

    // Discover installed resolver plugins (trusted by location, under the data dir). With no
    // usable data directory there are simply no plugins; a malformed one warns and is dropped.
    let plugins = match crate::store::Layout::from_env() {
        Some(layout) => PluginRegistry::load(&layout.plugins_dir(), &mut warnings),
        None => PluginRegistry::default(),
    };

    // Capture the mise file, its verdict, and its validated bytes before `resolve`
    // consumes the project layer. A mise file is anchored on the `.sbx.toml`: with no
    // usable project config there is nothing to gate it, so it is only flagged, not
    // honored. The bytes travel into `MiseConfig` so the launcher maps exactly the
    // content the verdict covered, without a second read.
    let project_state = project.as_ref().map(|(_, state, _)| *state);
    let mise_files = project
        .as_ref()
        .map(|(_, _, files)| files.clone())
        .unwrap_or_default();
    let mise = mise_status(cwd, project_state, mise_files, &mut warnings);

    let mut resolved = resolve(
        global,
        project.map(|(raw, state, _)| (raw, state)),
        &plugins,
    );
    resolved.mise = mise;

    // Canonicalize the (already absolute) bind sources, dropping any that cannot be
    // resolved — so `binds` is the *effective* list, identical to what the
    // launch will bind, and `sbx config` cannot advertise a bind the launch would
    // silently skip. Following symlinks here also pins each source against a swap.
    // The bind's read-only/read-write mode carries through unchanged; the per-layer
    // provenance is re-keyed from the raw declared path to the canonical one as we go,
    // so a lookup against the displayed (canonical) path resolves.
    let sbx_roots = sbx_control_plane_roots();
    let declared = std::mem::take(&mut resolved.binds);
    let raw_layer = std::mem::take(&mut resolved.bind_layer);
    let mut canon_binds: Vec<Bind> = Vec::with_capacity(declared.len());
    let mut canon_layer = BTreeMap::new();
    for bind in declared {
        let Some(canon) = canonicalize_one(&bind.path, &mut resolved.warnings) else {
            continue;
        };
        // A read-write bind overlapping sbx's own control plane is either forced read-only (a bind
        // at or under a root — fail closed: writing there is host-side code execution or a forged
        // trust/config, beyond the accepted self-harm class) or kept read-write with its
        // control-plane paths pinned in place by the launcher (a bind that merely contains a root).
        let writable = control_plane_mode(
            canon.as_path(),
            bind.writable,
            &sbx_roots,
            &mut resolved.warnings,
        );
        if let Some(layer) = raw_layer.get(&bind.path) {
            canon_layer.insert(canon.clone(), *layer);
        }
        // Merge by canonical path: the last declaration of a path wins (project over global),
        // updated in place so a destination is never mounted twice — matching how `merge_app`
        // folds an app's binds, so `sbx config` shows exactly what the launch mounts.
        if let Some(existing) = canon_binds.iter_mut().find(|b| b.path == canon) {
            existing.writable = writable;
        } else {
            canon_binds.push(Bind {
                path: canon,
                writable,
            });
        }
    }
    // Nesting warnings once per effective bind (after dedup, so the reported mode is the one the
    // launch will use): a bind that nests with a structural mount will not behave as declared (a
    // descendant is shadowed, an ancestor over-exposes). Trusted-only field, so this warns
    // without dropping the bind.
    for bind in &canon_binds {
        if let Some(w) = crate::sandbox::structural_nesting_warning(&bind.path, bind.writable) {
            resolved.warnings.push(w);
        }
    }
    resolved.binds = canon_binds;
    resolved.bind_layer = canon_layer;

    // Each app's binds are canonicalized the same way, into that app's own warnings — so an
    // app overlay also advertises only the binds the launch would actually make.
    for app in resolved.apps.values_mut() {
        let declared = std::mem::take(&mut app.binds);
        app.binds = canonicalize_binds(declared, &sbx_roots, &mut app.warnings);
    }

    // I/O-level notes (unsafe/unparseable files) come first, then the gating notes.
    warnings.extend(std::mem::take(&mut resolved.warnings));
    resolved.warnings = warnings;
    resolved
}

/// Canonicalize one bind source, dropping it with a warning if it cannot be resolved (a
/// missing path or a broken symlink) — bwrap could not bind it anyway. Following symlinks
/// here also pins the source against a later swap.
fn canonicalize_one(p: &Path, warnings: &mut Vec<String>) -> Option<PathBuf> {
    match p.canonicalize() {
        Ok(canon) => Some(canon),
        Err(e) => {
            warnings.push(format!("ignoring bind {}: {e}", p.display()));
            None
        }
    }
}

/// Canonicalize each bind source, dropping with a warning any that cannot be resolved; resolving a
/// read-write bind that overlaps an sbx control-plane root (forced read-only when it is at or under
/// one, kept read-write with its control-plane paths pinned when it merely contains one — see
/// [`control_plane_mode`]); de-duplicating by canonical path (last wins); and warning (without
/// dropping) any whose destination nests with a structural mount. The same treatment the baseline
/// binds get, so an app overlay advertises exactly what its launch would mount.
fn canonicalize_binds(
    binds: Vec<Bind>,
    roots: &[PathBuf],
    warnings: &mut Vec<String>,
) -> Vec<Bind> {
    let mut out: Vec<Bind> = Vec::with_capacity(binds.len());
    for bind in binds {
        let Some(canon) = canonicalize_one(&bind.path, warnings) else {
            continue;
        };
        let writable = control_plane_mode(canon.as_path(), bind.writable, roots, warnings);
        if let Some(existing) = out.iter_mut().find(|b| b.path == canon) {
            existing.writable = writable;
        } else {
            out.push(Bind {
                path: canon,
                writable,
            });
        }
    }
    for bind in &out {
        if let Some(w) = crate::sandbox::structural_nesting_warning(&bind.path, bind.writable) {
            warnings.push(w);
        }
    }
    out
}

/// The sbx-owned control-plane roots a read-write config bind must never expose to the cage: the
/// data directory (its engine binaries are `execve`'d host-side; its plugin and store trees run
/// host-side too), the trust-marker store (a forged marker would approve another project's config),
/// and the global-config directory (trusted by location). Resolved from the environment like every
/// other sbx path; a component whose base does not resolve is simply omitted.
fn sbx_control_plane_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(layout) = crate::store::Layout::from_env() {
        roots.push(layout.data_dir().to_path_buf());
    }
    if let Some(trusted) = trust::default_store_dir() {
        roots.push(trusted);
    }
    if let Some(dir) = global_path().and_then(|p| p.parent().map(Path::to_path_buf)) {
        roots.push(dir);
    }
    // Canonicalize best-effort: a config bind is compared canonicalized (symlinks resolved), so the
    // roots must be too, or a symlinked `$HOME` component would let a bind slip past the guard. A
    // root that does not exist yet keeps its raw form (nothing to resolve).
    roots
        .into_iter()
        .map(|r| r.canonicalize().unwrap_or(r))
        .collect()
}

/// Decide the read-write mode of a config bind `canon` that may overlap sbx's control plane, and
/// warn. Three cases, resolved in this order so the fail-closed one wins any ambiguity:
///
/// - The bind is **at or under** a control-plane root: the whole bind is control plane, there is
///   nothing to keep writable, so it is forced **read-only** with a warning naming the consequence.
///   Fail closed — a writable bind there is host-side code execution or a forged trust/config,
///   beyond the accepted (single-project, self-harm) class.
/// - The bind **strictly contains** one or more roots: it stays **read-write** — the launcher pins
///   each contained root's path in place ([`control_plane_pins`]), so the cage cannot substitute
///   what sbx runs or trusts on the host while the rest of the bound tree stays writable. An
///   informational note names the protected paths.
/// - The bind is unrelated to the control plane: its mode is returned unchanged.
///
/// The two overlaps are checked in the above order because the root set is disjoint (no root
/// contains another), so a bind cannot be both — but checking the read-only case first means any
/// future overlap defaults to the safe direction.
fn control_plane_mode(
    canon: &Path,
    writable: bool,
    roots: &[PathBuf],
    warnings: &mut Vec<String>,
) -> bool {
    if !writable {
        return false;
    }
    // At or under a root: the bind is entirely control plane → read-only.
    if let Some(root) = roots.iter().find(|r| canon.starts_with(r)) {
        warnings.push(format!(
            "bind `{}` is read-write over sbx's own control plane `{}` — binding it read-only \
             instead (a writable bind there could alter what sbx runs or trusts on the host)",
            canon.display(),
            root.display()
        ));
        return false;
    }
    // Strictly contains one or more roots: stays read-write; the launcher pins those roots' host
    // paths so the cage cannot rename a writable parent to substitute them.
    let contained: Vec<String> = roots
        .iter()
        .filter(|r| r.starts_with(canon) && r.as_path() != canon)
        .map(|r| r.display().to_string())
        .collect();
    if !contained.is_empty() {
        warnings.push(format!(
            "bind `{}` is read-write and contains sbx's own control plane ({}) — the tree stays \
             writable, but those paths are pinned read-only in place so the cage cannot alter what \
             sbx runs or trusts on the host",
            canon.display(),
            contained.join(", ")
        ));
    }
    true
}

/// The mountpoint-chain pins that protect sbx's control plane from path substitution when a
/// read-write bind strictly contains it. Without them a read-write ancestor bind lets in-cage code
/// rename a writable parent directory to move a control-plane root aside and recreate a forged one
/// at the same host path — which sbx would then read or `execve` on its next run. Each root is
/// pinned by making every path component below the containing bind a mountpoint (a mountpoint
/// cannot be renamed or removed — the kernel refuses with `EBUSY`): the intermediates read-write
/// (the rest of the tree stays writable), the root itself read-only (its host contents cannot be
/// written through).
///
/// Returns those mounts as host binds (source == destination), deduplicated and ordered
/// shallow-to-deep so a parent mountpoint is always established before its child — a child bound
/// first would be shadowed when the parent is later mounted over it, silently defeating the
/// protection. The caller binds them last (the final word on those paths) and creates each before
/// binding (a root the agent could otherwise create fresh). Iterates the same root set as
/// [`control_plane_mode`], so a root added there is pinned here automatically.
pub(crate) fn control_plane_pins(binds: &[Bind]) -> Vec<Bind> {
    control_plane_pins_for(binds, &sbx_control_plane_roots())
}

/// The pure core of [`control_plane_pins`], taking the roots explicitly so it is testable without
/// the environment.
fn control_plane_pins_for(binds: &[Bind], roots: &[PathBuf]) -> Vec<Bind> {
    let mut pins: Vec<Bind> = Vec::new();
    let mut seen: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
    for bind in binds.iter().filter(|b| b.writable) {
        for root in roots
            .iter()
            .filter(|r| r.starts_with(&bind.path) && r.as_path() != bind.path)
        {
            // Each directory strictly between the containing bind and the root, shallow-to-deep: a
            // mountpoint (read-write) so it cannot be renamed to substitute the path below it.
            for ancestor in ancestors_between(&bind.path, root) {
                if seen.insert(ancestor.clone()) {
                    pins.push(Bind {
                        path: ancestor,
                        writable: true,
                    });
                }
            }
            // The root itself, read-only: a mountpoint (cannot be renamed/removed) whose host
            // contents also cannot be written through.
            if seen.insert(root.clone()) {
                pins.push(Bind {
                    path: root.clone(),
                    writable: false,
                });
            }
        }
    }
    pins
}

/// The directories strictly between `bind` (exclusive) and `root` (exclusive), shallow-to-deep.
/// `bind` must be an ancestor of `root`. Used to enumerate the intermediate mountpoints a pin needs.
fn ancestors_between(bind: &Path, root: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = root
        .ancestors()
        .filter(|a| *a != root && *a != bind && a.starts_with(bind))
        .map(Path::to_path_buf)
        .collect();
    // `Path::ancestors` yields deep-to-shallow; pins need shallow-to-deep (parent before child).
    v.reverse();
    v
}

/// Read the global config (trusted by location, so no trust marker), defaulting to
/// empty when it is absent, unsafe, or unparseable.
fn read_global(warnings: &mut Vec<String>) -> RawConfig {
    let Some(path) = global_path() else {
        return RawConfig::default();
    };
    read_layer(&path, warnings).unwrap_or_default()
}

/// The reusable egress groups declared in the global config (`[net.groups]`), as their raw authored
/// entries keyed by name, plus any load warnings. Global-only — matching the resolver, which honors
/// groups only from the global config — so this lists exactly the set a `@<name>` reference can
/// resolve to. A read-only, network-free view for `sbx net groups`; entries are returned verbatim
/// (unclassified), so the caller displays them as declared and may flag a malformed one on its own.
pub(crate) fn net_groups() -> (BTreeMap<String, Vec<String>>, Vec<String>) {
    let mut warnings = Vec::new();
    let global = read_global(&mut warnings);
    (global.net.groups, warnings)
}

/// Read a portable `[net.groups]` fragment from `path` (the file `sbx net groups import` is given),
/// returning its groups. The file goes through the same safety gate as any config (owner-owned,
/// non-world-writable, a plain regular file). An error names why: unsafe/unreadable, not valid TOML,
/// or carrying no `[net.groups]` (the tell-tale of the wrong file). The entries are returned
/// verbatim — the caller validates the group names before writing them, and a malformed entry is
/// flagged at load like any other, so the import is deliberately not a second validation surface.
pub(crate) fn read_net_groups_fragment(
    path: &Path,
) -> Result<BTreeMap<String, Vec<String>>, String> {
    let bytes = safety::read_safe_bytes(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let raw = schema::parse(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    if raw.net.groups.is_empty() {
        return Err(format!(
            "{} has no `[net.groups]` table to import (is it an export of `sbx net groups export`?)",
            path.display()
        ));
    }
    Ok(raw.net.groups)
}

/// Read the project config and decide its trust on the *same bytes* it parses, so
/// the verdict and the applied content cannot belong to two different files. An
/// absent file is simply no project layer; an unsafe or unparseable one is dropped
/// with a warning. A config that cannot be trust-checked (no store) is treated as
/// untrusted — fail closed.
///
/// Returns the parsed config, its trust verdict, and the validated `(filename,
/// bytes)` of every sibling mise file — read here, once, through the safety gate.
/// Threading those bytes out (rather than re-reading them later) means the launcher
/// maps exactly the content the verdict covers, and the safety gate runs once.
fn read_project(
    cwd: &Path,
    warnings: &mut Vec<String>,
) -> Option<(RawConfig, TrustState, trust::MiseInputs)> {
    let path = cwd.join(PROJECT_CONFIG);
    let bytes = match safety::read_safe_bytes(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(e) => {
            warnings.push(format!("ignoring {}: {e}", path.display()));
            return None;
        }
    };

    // Fold a sibling mise file into the verdict — trust covers both declarative
    // inputs. A present-but-unsafe mise file is unverifiable, so it forces the
    // project untrusted: its `.sbx.toml` still parses (its free `env` applies under
    // untrusted rules), but its security fields drop. Verdict over the exact bytes
    // that will be parsed (closes the trust→parse window): hash these bytes —
    // framed with the mise bytes — and compare to the marker, never re-reading.
    let (state, mise_inputs) = match trust::mise_inputs_for(&path) {
        Err(e) => {
            warnings.push(format!("treating {} as untrusted: {e}", path.display()));
            (TrustState::Untrusted, Vec::new())
        }
        Ok(mise_inputs) => {
            let state = match trust::default_store_dir() {
                Some(store) => trust::verdict_for_hash(
                    &store,
                    &path,
                    &trust::content_hash(&bytes, &mise_inputs),
                ),
                None => {
                    warnings.push(format!(
                        "cannot locate the trust store; treating {} as untrusted",
                        path.display()
                    ));
                    TrustState::Untrusted
                }
            };
            (state, mise_inputs)
        }
    };

    match schema::parse(&bytes) {
        Ok(cfg) => Some((cfg, state, mise_inputs)),
        Err(e) => {
            warnings.push(format!("ignoring {}: {e}", path.display()));
            None
        }
    }
}

/// The project's mise file, the verdict gating it, and its validated bytes, for
/// `sbx config` and the launcher's `[env]` mapping. `None` when the project declares
/// none. A mise file present without a usable `.sbx.toml` to anchor it is not honored
/// — when there is no `.sbx.toml` at all, the no-op is surfaced as a warning so it is
/// never silent; an unsafe or unparseable `.sbx.toml` already warned on its own
/// account. `validated` carries the safety-gated `(filename, bytes)` read in
/// [`read_project`] (empty when none was safely readable).
fn mise_status(
    cwd: &Path,
    project_state: Option<TrustState>,
    validated: trust::MiseInputs,
    warnings: &mut Vec<String>,
) -> Option<MiseConfig> {
    let files = trust::mise_files_for(&cwd.join(PROJECT_CONFIG));
    if files.is_empty() {
        return None;
    }
    // List every discovered file — all of them are folded into trust and would be
    // read together, so showing only the first would understate the gated surface.
    let name = files
        .iter()
        .filter_map(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(", ");
    match project_state {
        Some(state) => Some(MiseConfig {
            name,
            state,
            files: validated,
        }),
        None => {
            if !cwd.join(PROJECT_CONFIG).exists() {
                warnings.push(format!(
                    "mise file ({name}) ignored: mise is anchored on `{PROJECT_CONFIG}`, \
                     which is missing — add one (it may be empty) to enable it"
                ));
            }
            None
        }
    }
}

/// Read, safety-gate, and parse a config file with no trust marker (the global
/// layer). `None` when the file is absent, unsafe, or unparseable — each of the
/// latter two leaving a warning.
fn read_layer(path: &Path, warnings: &mut Vec<String>) -> Option<RawConfig> {
    match safety::read_safe_bytes(path) {
        Ok(bytes) => match schema::parse(&bytes) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                warnings.push(format!("ignoring {}: {e}", path.display()));
                None
            }
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => {
            warnings.push(format!("ignoring {}: {e}", path.display()));
            None
        }
    }
}

/// The global config path: `$XDG_CONFIG_HOME/sbx/sbx.toml` when that is absolute,
/// else `$HOME/.config/sbx/sbx.toml`. `None` when neither yields an absolute base
/// (the same fail-closed stance the trust store takes — never resolve against the
/// current directory).
fn global_path() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        let p = PathBuf::from(xdg);
        if p.is_absolute() {
            return Some(p.join("sbx").join(GLOBAL_CONFIG));
        }
    }
    let home = PathBuf::from(std::env::var_os("HOME")?);
    home.is_absolute()
        .then(|| home.join(".config/sbx").join(GLOBAL_CONFIG))
}

/// The imported-profiles directory (`…/sbx/apps/`), a sibling of the global config. `None` when
/// no config base resolves, like [`global_path`]; `sbx app import`/`rm`/`list` and [`load`] all
/// route through this one place so the location can never drift.
pub(crate) fn profiles_dir() -> Option<PathBuf> {
    global_path().and_then(|p| p.parent().map(|d| d.join(PROFILES_DIR)))
}

/// The profile file for app `name` (`…/sbx/apps/<name>.toml`), or `None` when no config base
/// resolves. The counterpart of [`profiles_dir`] for a single app — the target an app-scoped
/// global write (`sbx net allow -a <name> --save -g`, `sbx config … --app <name> -g`) reaches.
pub(crate) fn profile_path(name: &str) -> Option<PathBuf> {
    profiles_dir().map(|d| d.join(format!("{name}.toml")))
}

/// The posture an importable app profile would grant, in human-readable lines — shown so the
/// deliberate `sbx app import` is informed (it is the consent act; an imported profile is then
/// honored even on an untrusted project, so what it grants must be visible).
#[derive(Debug)]
pub(crate) struct ProfilePreview {
    /// Display lines: the command, home scope, tools, binds, network, and each credential by
    /// destination + source *locator* (never a plaintext value — a profile carries only a locator).
    pub(crate) summary: Vec<String>,
}

/// Validate bytes as an importable app profile: they must parse as a top-level [`schema::RawApp`]
/// and declare a `cmd`. The `cmd` requirement is both a real rule (a profile with no command is
/// not launchable) and the guard against the wrong shape — a file wrapped in `[app.<name>]` parses
/// as an empty app, which this refuses with a hint rather than importing a silently-empty profile.
/// Returns the granted posture for display, or a human-readable reason to refuse. Reads nothing
/// from disk and resolves no secret — only the *shape* and *locators* are inspected.
pub(crate) fn validate_profile(bytes: &[u8]) -> Result<ProfilePreview, String> {
    let app = schema::parse_app(bytes)?;
    if app.cmd.is_none() {
        return Err(
            "a profile must declare a `cmd` (the command to run). A profile file holds the \
                    app's fields at the top level — if you wrapped it in an `[app.<name>]` table, \
                    remove the wrapper (the name comes from the file name)"
                .to_string(),
        );
    }
    Ok(ProfilePreview {
        summary: describe_app_posture(&app),
    })
}

/// Render one raw bind for the import posture summary: its path, with a ` (rw)` marker when the
/// bind is read-write (the more-privileged, exceptional case worth flagging before import). An
/// unrecognized mode is shown verbatim (`(mode X?)`) so a typo is visible, and a table missing its
/// `path` reads as `(bind without a path)` so a malformed entry is not silently blank.
fn describe_raw_bind(bind: &RawBind) -> String {
    match bind {
        RawBind::Path(p) => p.clone(),
        RawBind::Detailed(t) => {
            let path = t.path.as_deref().unwrap_or("(bind without a path)");
            match t.mode.as_deref() {
                None | Some("ro") => path.to_string(),
                Some("rw") => format!("{path} (rw)"),
                Some(other) => format!("{path} (mode {other}?)"),
            }
        }
    }
}

/// Build the posture summary for a raw app profile: the command, the persistent-home scope, the
/// extra tools, the binds (each read-only or read-write, a `(rw)` marker flagging the latter), the
/// network posture, and each injected credential by destination and source *locator*. A profile
/// never carries a plaintext secret — only a locator (`env://VAR`, a `key`) — so this is safe to
/// display and to share.
fn describe_app_posture(app: &RawApp) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(cmd) = &app.cmd {
        lines.push(format!("command: {}", cmd.clone().into_argv().join(" ")));
    }
    lines.push(format!(
        "home: {}",
        app.home_scope.as_deref().unwrap_or("global")
    ));
    if !app.packages.is_empty() {
        let names: Vec<&str> = app.packages.keys().map(String::as_str).collect();
        lines.push(format!("packages: {}", names.join(", ")));
    }
    if !app.binds.is_empty() {
        let descs: Vec<String> = app.binds.iter().map(describe_raw_bind).collect();
        lines.push(format!("binds: {}", descs.join(", ")));
    }
    match &app.network {
        None => {}
        Some(NetworkField::Posture(p)) => lines.push(format!("network: {p}")),
        Some(NetworkField::Table(t)) => {
            let mut s = format!(
                "network: {}",
                t.mode
                    .as_deref()
                    .unwrap_or("(mode inherited from the parent layer)")
            );
            if !t.allow.is_empty() {
                s.push_str(&format!(" — allow {}", t.allow.join(", ")));
            }
            if !t.deny.is_empty() {
                s.push_str(&format!(" — deny {}", t.deny.join(", ")));
            }
            lines.push(s);
        }
    }
    if let Some(gui) = &app.gui {
        lines.push(format!("gui: {gui}"));
    }
    if let Some(section) = &app.secret {
        let mut any = false;
        for (host, entry) in &section.hosts {
            let secrets: &[RawHostSecret] = match entry {
                RawHostSecrets::One(s) => std::slice::from_ref(s),
                RawHostSecrets::Many(v) => v.as_slice(),
            };
            for s in secrets {
                lines.push(format!("secret: {host} <- {}", describe_secret_source(s)));
                any = true;
            }
        }
        // A credential is injected only under a filtering posture (`deny`/`allow`/`ask` — the proxy
        // performs the injection). If the profile declares secrets but not its own filtering
        // posture, say so — otherwise the summary reads as if they would be injected when,
        // standalone, they would not. Any filtering spelling counts (table or bare string); a
        // mode-less table inherits a filtering mode (`deny`/`ask`, or the `deny` fallback), so it
        // counts too.
        let filtered = match &app.network {
            Some(NetworkField::Table(t)) => {
                matches!(t.mode.as_deref(), None | Some("deny" | "allow" | "ask"))
            }
            Some(NetworkField::Posture(p)) => matches!(p.as_str(), "deny" | "allow" | "ask"),
            None => false,
        };
        if any && !filtered {
            lines.push(
                "note: secrets are injected only under a filtering network posture (declare \
                 `[network] mode = \"deny\"`, `\"allow\"`, or `\"ask\"`)"
                    .to_string(),
            );
        }
    }
    lines
}

/// A one-line description of where a credential is read from: the terse `key`, or the explicit
/// `from` ref/chain. The locator only — never a value (a profile carries none).
fn describe_secret_source(s: &RawHostSecret) -> String {
    if let Some(key) = &s.key {
        return format!("key `{key}`");
    }
    match &s.from {
        Some(SecretFrom::One(r)) => format!("from {r}"),
        Some(SecretFrom::Many(rs)) => format!("from {}", rs.join(" | ")),
        None => "from (unspecified)".to_string(),
    }
}

/// Read every imported app profile from the profiles directory, keyed by filename stem.
/// Delegates to [`read_profile_apps_from`] with the resolved [`profiles_dir`]; the split keeps the
/// directory-reading logic unit-testable against an arbitrary directory, without depending on the
/// process environment.
fn read_profile_apps(warnings: &mut Vec<String>) -> BTreeMap<String, RawApp> {
    match profiles_dir() {
        Some(dir) => read_profile_apps_from(&dir, warnings),
        None => BTreeMap::new(),
    }
}

/// Read every `<name>.toml` profile under `dir`, keyed by its filename stem (the app name). Each
/// file is a standalone top-level [`schema::RawApp`], trusted by location. Infallible, like the
/// rest of [`load`]: an absent directory yields nothing; an unsafe, unparseable, or unsafely-named
/// file is dropped with a warning, never aborting the load. Entries are processed in sorted order
/// so warnings are deterministic.
fn read_profile_apps_from(dir: &Path, warnings: &mut Vec<String>) -> BTreeMap<String, RawApp> {
    let mut out = BTreeMap::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return out,
        Err(e) => {
            warnings.push(format!(
                "ignoring profiles directory {}: {e}",
                dir.display()
            ));
            return out;
        }
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        // Only `*.toml` files are profiles; anything else under the directory is ignored silently.
        if path.extension().and_then(|x| x.to_str()) != Some("toml") {
            continue;
        }
        let Some(name) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(str::to_string)
        else {
            warnings.push(format!(
                "ignoring profile {}: its file name is not valid UTF-8",
                path.display()
            ));
            continue;
        };
        if !is_valid_app_name(&name) {
            warnings.push(format!(
                "ignoring profile {}: `{name}` is not a usable app name",
                path.display()
            ));
            continue;
        }
        let bytes = match safety::read_safe_bytes(&path) {
            Ok(b) => b,
            Err(e) => {
                warnings.push(format!("ignoring profile {}: {e}", path.display()));
                continue;
            }
        };
        match schema::parse_app(&bytes) {
            Ok(app) => {
                out.insert(name, app);
            }
            Err(e) => warnings.push(format!("ignoring profile {}: {e}", path.display())),
        }
    }
    out
}

/// Make the imported profile apps the sole source of the global app layer. A global app lives only
/// as a profile file under `apps/<name>.toml` — an inline `[app.<name>]` in `sbx.toml` is forbidden
/// (it used to shadow an entire imported profile: `cmd`/`packages`/`binds`/`env` and the profile's
/// `[network]` all dropped, bricking the app). Any inline app present in the global config is
/// therefore dropped inert with a loud, per-app migration warning, and the profiles take its place
/// unconditionally — there is exactly one declaration site, so no collision is possible. `load`
/// stays infallible: a bad state reachable only by manual editing never wedges the sandbox.
fn merge_profile_apps(
    global: &mut RawConfig,
    profiles: BTreeMap<String, RawApp>,
    warnings: &mut Vec<String>,
) {
    let apps_dir = profiles_dir()
        .map(|d| d.display().to_string())
        .unwrap_or_else(|| format!("<config>/{PROFILES_DIR}"));
    for name in global.app.keys() {
        // Two shapes of the forbidden state need different remedies. When a profile of the same name
        // already exists it is the one that runs, so the inline block is pure dead weight — say to
        // delete it. Otherwise the inline block carries the only definition, so point at `export` to
        // migrate it to a profile before it is dropped.
        let remedy = if profiles.contains_key(name) {
            format!(
                "the profile {PROFILES_DIR}/{name}.toml already provides it — delete the inline \
                 [app.{name}] from {GLOBAL_CONFIG}"
            )
        } else {
            format!(
                "migrate it with `sbx app export {name} --out {apps_dir}/{name}.toml`, then delete \
                 the inline [app.{name}] from {GLOBAL_CONFIG}"
            )
        };
        warnings.push(format!(
            "app `{name}`: an inline [app.{name}] in {GLOBAL_CONFIG} is forbidden — global apps \
             live as profile files under {PROFILES_DIR}/<name>.toml. The inline declaration is \
             ignored; {remedy}."
        ));
    }
    global.app.clear();
    for (name, app) in profiles {
        global.app.insert(name, app);
    }
}

/// Produce the portable profile bytes for `name`, for `sbx app export`. An **imported profile**
/// (`<config>/sbx/apps/<name>.toml`) is emitted **verbatim**, so the author's comments and
/// formatting survive a round-trip through the store; otherwise an app declared **inline** — in the
/// project `.sbx.toml` (preferred, the local definition one would share) or the global `sbx.toml` —
/// has its `RawApp` **serialized** to a minimal top-level profile. The app is exported **as
/// authored**, security fields and all, regardless of trust: import is the trust act, not export.
/// Returns the bytes to emit, or a human-readable reason none was found.
///
/// Note the precedence here is the **inverse** of [`merge_profile_apps`] at load: export prefers
/// the imported profile, whereas a launch drops an inline `[app.<name>]` in the global config
/// (forbidden — see [`merge_profile_apps`]). They only diverge when one name is *both* an imported
/// profile and an inline definition — a state the load-time migration warning already pushes the
/// user to resolve — so `sbx app export <name>` may emit the profile while `sbx app <name>` would
/// launch the profile (the inline is inert). Exporting the inline is itself the migration path off
/// the forbidden form. Keep at most one definition per name.
pub(crate) fn export_profile(cwd: &Path, name: &str) -> Result<Vec<u8>, String> {
    // 1. An imported profile: emit it verbatim (fidelity over re-serialization).
    if let Some(dir) = profiles_dir() {
        let path = dir.join(format!("{name}.toml"));
        if path.exists() {
            return safety::read_safe_bytes(&path).map_err(|e| e.to_string());
        }
    }
    // 2. An inline app: serialize its raw definition. The project layer is preferred over the
    //    global (the local definition is the one being packaged for sharing).
    let mut warnings = Vec::new();
    if let Some((mut project, _, _)) = read_project(cwd, &mut warnings) {
        if let Some(app) = project.app.remove(name) {
            return schema::serialize_app(&app).map(String::into_bytes);
        }
    }
    let mut global = read_global(&mut warnings);
    if let Some(app) = global.app.remove(name) {
        return schema::serialize_app(&app).map(String::into_bytes);
    }
    Err(format!(
        "no app `{name}` to export (not an imported profile, nor an inline [app.{name}] in \
         {PROJECT_CONFIG} or {GLOBAL_CONFIG})"
    ))
}

#[cfg(test)]
mod tests;
