//! Provisioning a project's declared tools.
//!
//! A project (or the global config) names tools as `name = "<backend>:<locator>"`. This
//! module realises the **host-side** backends into sbx's store and reports the `bin`
//! directories to prepend to the sandbox `PATH`: **`nix:`** (a pinned nixpkgs attribute) and
//! **`flake:`** (a remote flake ref). Both build once (content-addressed → a second project
//! is a cache hit) and are seeded per project, so a `flake:` tool no longer rebuilds in each
//! project. The **`mise:`** ones are not realised here — they are equipped in-cage at launch
//! by `mise use -g` ([`mise_packages`] collects the tokens); an inline `[flakes.<name>]` is
//! built in-cage too (local content). [`flake_packages`] still names the remote `(name, ref)`
//! flake packages for `sbx upgrade flake`'s pin resolution.
//!
//! Admission is a security decision for every backend: provisioning a tool can fetch or
//! build, so an untrusted project's packages are withheld until the project is trusted.
//! A declared `nix:` tool is a stated requirement, so a failure to realise an *admitted*
//! one is a hard error naming the attribute — never a silent drop, unlike a best-effort
//! bind.

use crate::config::{untrusted_reason, Backend, Package, PROJECT_CONFIG};
use crate::store::{self, Layout};
use crate::trust::TrustState;
use std::io;
use std::path::{Path, PathBuf};

/// The output subdirectory a tool exposes its executables under. Doubles as the
/// marker that selects the bin-bearing output of a multi-output package — a tool's
/// contract is its executables, so the output carrying `bin/` is the one to expose.
const BIN: &str = "bin";

/// One layer of tools realised into sbx's store. `bins` are the `bin` directories to
/// prepend to the sandbox `PATH`; `roots` are the logical store paths whose closures
/// back them, surfaced so a project's own store can be seeded with exactly those
/// closures (rather than reconstructing them by stripping the `bin` suffix back off);
/// `warnings` cover anything withheld or left to another handler. The two
/// tool-provisioning layers — native `[packages]` and `nix:` mise tools — both report
/// this shape.
pub(crate) struct Provisioned {
    /// `bin` directories to prepend to `PATH`, in declaration order.
    pub(crate) bins: Vec<PathBuf>,
    /// Logical store roots whose closures the project's store must carry.
    pub(crate) roots: Vec<PathBuf>,
    /// Warnings for withheld or unhandled tools, surfaced by the caller.
    pub(crate) warnings: Vec<String>,
}

/// Split declared packages into the ones admitted for provisioning and the warnings
/// for those withheld. A package is admitted when the layer that supplied its value
/// is trusted; an untrusted project's tools are held back with an actionable hint.
/// Pure, so `sbx config` could show the same verdict without touching nix.
fn admit(packages: &[Package]) -> (Vec<&Package>, Vec<String>) {
    let mut admitted = Vec::new();
    let mut warnings = Vec::new();
    for p in packages {
        if p.state == TrustState::Trusted {
            admitted.push(p);
        } else {
            // Only a project can be non-trusted (global is trusted by location), and
            // the message distinguishes a changed project from a never-trusted one.
            warnings.push(format!(
                "{PROJECT_CONFIG}: withholding package `{}` ({})",
                p.name,
                untrusted_reason(p.state)
            ));
        }
    }
    (admitted, warnings)
}

/// Provision every admitted package into sbx's store against `nixpkgs`, rooting
/// each under the project's identity so housekeeping can later reclaim a project's
/// tools with the rest of its runtime. Returns the `bin` directories to prepend to
/// the sandbox `PATH` (in declaration order), the logical store roots whose closures
/// back them, and the warnings for any withheld tool. An empty admitted set does no
/// work and touches nix not at all.
pub(crate) fn provision(
    nix: &Path,
    layout: &Layout,
    project: &Path,
    nixpkgs: &str,
    packages: &[Package],
) -> io::Result<Provisioned> {
    let (admitted, warnings) = admit(packages);
    if admitted.is_empty() {
        return Ok(Provisioned {
            bins: Vec::new(),
            roots: Vec::new(),
            warnings,
        });
    }

    let id = super::binds::project_runtime_id(project)?;
    let gcroots = layout.data_dir().join("gcroots").join("projects").join(&id);
    // A `flake:` package builds host-side into the shared store like a `nix:` one (built once,
    // content-addressed → a second project is a cache hit; seeded per project). The pin selects the
    // immutable build target — the locked ref when `flake-packages.lock` pins it, else the declared
    // ref (which floats, frozen warm until `sbx upgrade flake`, like a floating `mise:` tool).
    let flake_pins = super::flake::pins(layout, &id);

    let mut bins = Vec::with_capacity(admitted.len());
    let mut roots = Vec::with_capacity(admitted.len());
    for p in admitted {
        // A declared tool is a requirement: surface a realisation failure naming the package,
        // never drop it silently.
        let logical = match &p.backend {
            // A `nix:` package: a pinned nixpkgs attribute, built host-side into the shared store.
            // Unfree is permitted here — a `[packages]` declaration is trusted-only, and some agent
            // CLIs ship proprietary (unfree) nixpkgs derivations; see [`store::provision_unfree`] for
            // why this is licensing, not a security relaxation.
            Backend::Nix(attr) => {
                store::provision_unfree(nix, layout, &gcroots.join(&p.name), nixpkgs, attr, BIN)
                    .map_err(|e| {
                        io::Error::other(format!(
                            "cannot provision package `{}` ({attr}): {e}",
                            p.name
                        ))
                    })?
            }
            // A `flake:` package: build its (possibly pinned) target host-side, same store/seed path.
            Backend::Flake(reference) => {
                let target = flake_pins
                    .get(reference)
                    .map(|pin| pin.locked_ref.clone())
                    .unwrap_or_else(|| reference.clone());
                store::provision_flake(nix, layout, &gcroots.join(&p.name), &target, &p.name, BIN)
                    .map_err(|e| {
                    io::Error::other(format!(
                        "cannot provision flake package `{}` ({reference}): {e}",
                        p.name
                    ))
                })?
            }
            // `mise:` is equipped in-cage by `mise use -g`; an inline `[flakes.<name>]` is built
            // in-cage (local content); the prebuilt trio is provisioned by their own modules.
            _ => continue,
        };
        bins.push(logical.join(BIN));
        roots.push(logical);
    }
    Ok(Provisioned {
        bins,
        roots,
        warnings,
    })
}

/// The mise tokens of the *admitted* `mise:` packages — the ones the launcher equips
/// in-cage globally with `mise use -g`. Trusted-only, exactly like the host-side `nix:`
/// path: an untrusted project's `mise:` package is dropped here (its withholding is
/// warned once by [`provision`]'s admission, so this stays a quiet pure filter). The
/// token is what follows `mise:`, passed to mise verbatim.
pub(crate) fn mise_packages(packages: &[Package]) -> Vec<String> {
    packages
        .iter()
        .filter(|p| p.state == TrustState::Trusted)
        .filter_map(|p| match &p.backend {
            Backend::Mise(token) => Some(token.clone()),
            Backend::Nix(_)
            | Backend::Flake(_)
            | Backend::FlakeInline { .. }
            | Backend::Deb(_)
            | Backend::AppImage(_)
            | Backend::Tarball(_)
            | Backend::TarballResolve { .. }
            | Backend::DebResolve { .. }
            | Backend::AppImageResolve { .. } => None,
        })
        .collect()
}

/// The `(name, ref)` of the *admitted* remote `flake:` packages — the trusted references
/// `sbx upgrade flake` re-resolves and pins (see [`super::flake`]). Trusted-only, like the host-side
/// `nix:` path and the global `mise:` one: an untrusted project's `flake:` package is dropped here
/// (its withholding is warned once by [`provision`]'s admission, so this stays a quiet pure filter).
/// The name is the package name; the ref is the flake reference. The build itself is host-side (see
/// [`provision`]), keyed by name under `<data>/gcroots/projects/<id>/`.
pub(crate) fn flake_packages(packages: &[Package]) -> Vec<(String, String)> {
    packages
        .iter()
        .filter(|p| p.state == TrustState::Trusted)
        .filter_map(|p| match &p.backend {
            Backend::Flake(reference) => Some((p.name.clone(), reference.clone())),
            Backend::Nix(_)
            | Backend::Mise(_)
            | Backend::FlakeInline { .. }
            | Backend::Deb(_)
            | Backend::AppImage(_)
            | Backend::Tarball(_)
            | Backend::TarballResolve { .. }
            | Backend::DebResolve { .. }
            | Backend::AppImageResolve { .. } => None,
        })
        .collect()
}

/// The data-dir gcroot names of every **declared** host-provisioned `[packages]` backend — the
/// backends that write a `<data>/gcroots/projects/<id>/<name>` out-link: `nix:` and a remote `flake:`
/// (both bare `<name>`) and the prebuilt trio `deb:`/`appimage:`/`tarball:` (each direct **and**
/// `:resolve` form, keyed `deb-`/`appimage-`/`tarball-<name>`). `mise:` (equipped in-cage) and an
/// inline `[flakes.<name>]` (rooted inside the project store as `sbx-flake-<name>`) write nothing here
/// and are excluded. This is the keep-set `sbx gc` reconciles those out-links against so a *removed*
/// package's leaked out-link — and, with it, its per-project store copy — is reclaimed.
///
/// Deliberately **declared-not-trusted**, unlike the trusted-only provisioning filters
/// ([`deb_packages`] and friends): a package the user still declares but whose project trust has
/// lapsed (an edit turns the config Changed) must **not** have its build reclaimed — for a heavy
/// prebuilt (a multi-hundred-MB desktop app) that would force a full re-download on the next trusted
/// launch. Only a package no longer declared at all is a removal, and a removal is absent from this
/// set whatever its trust was. Keep the `deb-{name}`/`appimage-{name}`/`tarball-{name}` prefixes in
/// step with the write sites (deb.rs/appimage.rs/tarball.rs) and the bare-`<name>` nix site
/// ([`provision`]).
pub(crate) fn project_gcroot_names(packages: &[Package]) -> Vec<String> {
    packages
        .iter()
        .filter_map(|p| match &p.backend {
            // `nix:` and a remote `flake:` are both built host-side under a bare `<name>` out-link.
            Backend::Nix(_) | Backend::Flake(_) => Some(p.name.clone()),
            Backend::Deb(_) | Backend::DebResolve { .. } => Some(format!("deb-{}", p.name)),
            Backend::AppImage(_) | Backend::AppImageResolve { .. } => {
                Some(format!("appimage-{}", p.name))
            }
            Backend::Tarball(_) | Backend::TarballResolve { .. } => {
                Some(format!("tarball-{}", p.name))
            }
            // `mise:` is equipped in-cage; an inline `[flakes.<name>]` roots in the project store as
            // `sbx-flake-<name>` — neither writes a data-dir out-link here.
            Backend::Mise(_) | Backend::FlakeInline { .. } => None,
        })
        .collect()
}

/// The `(name, url)` of the *admitted* `deb:` packages — the ones the launcher provisions
/// host-side (resolve the URL to a hash, then build a generated unpack+autoPatchelf derivation).
/// Trusted-only, exactly like the other backends: an untrusted project's `deb:` package is dropped
/// here. The name keys the per-package gcroot; the url is the `.deb` source sbx resolves and fetches.
pub(crate) fn deb_packages(packages: &[Package]) -> Vec<(String, String)> {
    packages
        .iter()
        .filter(|p| p.state == TrustState::Trusted)
        .filter_map(|p| match &p.backend {
            Backend::Deb(url) => Some((p.name.clone(), url.clone())),
            Backend::Nix(_)
            | Backend::Mise(_)
            | Backend::Flake(_)
            | Backend::FlakeInline { .. }
            | Backend::AppImage(_)
            | Backend::Tarball(_)
            | Backend::TarballResolve { .. }
            | Backend::DebResolve { .. }
            | Backend::AppImageResolve { .. } => None,
        })
        .collect()
}

/// The `(name, url)` of the *admitted* `tarball:` packages — the ones the launcher provisions
/// host-side (resolve the URL to a hash, then build a generated `tar -xz`-extract+autoPatchelf
/// derivation). Trusted-only, exactly like the other backends: an untrusted project's `tarball:`
/// package is dropped here. The name keys the per-package gcroot; the url is the `.tar.gz` source
/// sbx resolves and fetches.
pub(crate) fn tarball_packages(packages: &[Package]) -> Vec<(String, String)> {
    packages
        .iter()
        .filter(|p| p.state == TrustState::Trusted)
        .filter_map(|p| match &p.backend {
            Backend::Tarball(url) => Some((p.name.clone(), url.clone())),
            // The auto-upgrade `tarball:resolve` form is provisioned separately (it carries a
            // resolver command, not a direct URL) — see [`tarball_resolve_packages`].
            Backend::Nix(_)
            | Backend::Mise(_)
            | Backend::Flake(_)
            | Backend::FlakeInline { .. }
            | Backend::Deb(_)
            | Backend::AppImage(_)
            | Backend::TarballResolve { .. }
            | Backend::DebResolve { .. }
            | Backend::AppImageResolve { .. } => None,
        })
        .collect()
}

/// The `(name, resolver-command)` of the *admitted* `tarball:resolve` packages — the auto-upgrade
/// form the launcher provisions host-side (run the command sandboxed to print the newest download
/// URL, then resolve+build exactly like the direct `tarball:` form). Trusted-only, exactly like
/// [`tarball_packages`]: an untrusted project's resolver package is dropped here, so **its command
/// is never executed**. The name keys the same per-package gcroot as the direct form.
pub(crate) fn tarball_resolve_packages(packages: &[Package]) -> Vec<(String, Vec<String>)> {
    packages
        .iter()
        .filter(|p| p.state == TrustState::Trusted)
        .filter_map(|p| match &p.backend {
            Backend::TarballResolve { command } => Some((p.name.clone(), command.clone())),
            Backend::Nix(_)
            | Backend::Mise(_)
            | Backend::Flake(_)
            | Backend::FlakeInline { .. }
            | Backend::Deb(_)
            | Backend::AppImage(_)
            | Backend::Tarball(_)
            | Backend::DebResolve { .. }
            | Backend::AppImageResolve { .. } => None,
        })
        .collect()
}

/// The `(name, resolver-command)` of the *admitted* `deb:resolve` packages — the `deb:` auto-upgrade
/// twin of [`tarball_resolve_packages`]: the launcher runs the command sandboxed to print the newest
/// `.deb` URL, then resolves+builds exactly like the direct `deb:` form. Trusted-only: an untrusted
/// project's resolver package is dropped here, so **its command is never executed**. The name keys the
/// same per-package gcroot as the direct `deb:` form.
pub(crate) fn deb_resolve_packages(packages: &[Package]) -> Vec<(String, Vec<String>)> {
    packages
        .iter()
        .filter(|p| p.state == TrustState::Trusted)
        .filter_map(|p| match &p.backend {
            Backend::DebResolve { command } => Some((p.name.clone(), command.clone())),
            Backend::Nix(_)
            | Backend::Mise(_)
            | Backend::Flake(_)
            | Backend::FlakeInline { .. }
            | Backend::Deb(_)
            | Backend::AppImage(_)
            | Backend::Tarball(_)
            | Backend::TarballResolve { .. }
            | Backend::AppImageResolve { .. } => None,
        })
        .collect()
}

/// The `(name, resolver-command)` of the *admitted* `appimage:resolve` packages — the `appimage:`
/// auto-upgrade twin of [`tarball_resolve_packages`]/[`deb_resolve_packages`]: the launcher runs the
/// command sandboxed to print the newest `.AppImage` URL, then resolves+builds exactly like the direct
/// `appimage:` form. Trusted-only: an untrusted project's resolver package is dropped here, so **its
/// command is never executed**. The name keys the same per-package gcroot as the direct form.
pub(crate) fn appimage_resolve_packages(packages: &[Package]) -> Vec<(String, Vec<String>)> {
    packages
        .iter()
        .filter(|p| p.state == TrustState::Trusted)
        .filter_map(|p| match &p.backend {
            Backend::AppImageResolve { command } => Some((p.name.clone(), command.clone())),
            Backend::Nix(_)
            | Backend::Mise(_)
            | Backend::Flake(_)
            | Backend::FlakeInline { .. }
            | Backend::Deb(_)
            | Backend::AppImage(_)
            | Backend::Tarball(_)
            | Backend::TarballResolve { .. }
            | Backend::DebResolve { .. } => None,
        })
        .collect()
}

/// The `(name, url)` of the *admitted* `appimage:` packages — the ones the launcher provisions
/// host-side (resolve the URL to a hash, then build a generated squashfs-extract+autoPatchelf
/// derivation). Trusted-only, exactly like the other backends: an untrusted project's `appimage:`
/// package is dropped here. The name keys the per-package gcroot; the url is the `.AppImage` source
/// sbx resolves and fetches.
pub(crate) fn appimage_packages(packages: &[Package]) -> Vec<(String, String)> {
    packages
        .iter()
        .filter(|p| p.state == TrustState::Trusted)
        .filter_map(|p| match &p.backend {
            Backend::AppImage(url) => Some((p.name.clone(), url.clone())),
            Backend::Nix(_)
            | Backend::Mise(_)
            | Backend::Flake(_)
            | Backend::FlakeInline { .. }
            | Backend::Deb(_)
            | Backend::Tarball(_)
            | Backend::TarballResolve { .. }
            | Backend::DebResolve { .. }
            | Backend::AppImageResolve { .. } => None,
        })
        .collect()
}

/// The `(name, content, attr)` of the *admitted* inline-flake packages — the ones the launcher
/// stages, binds read-only into the cage, and builds `path:<dir>#<attr>` in-cage. Trusted-only,
/// exactly like [`flake_packages`] and the other backends: an untrusted project's inline flake is
/// dropped here. The name keys the per-package out-link (with the content hash) and the
/// `sbx-flake-<name>` gcroot; the content is the `flake.nix` source staged to a file, the attr the
/// output to build.
pub(crate) fn flake_inline_packages(packages: &[Package]) -> Vec<(String, String, String)> {
    packages
        .iter()
        .filter(|p| p.state == TrustState::Trusted)
        .filter_map(|p| match &p.backend {
            Backend::FlakeInline { content, attr } => {
                Some((p.name.clone(), content.clone(), attr.clone()))
            }
            Backend::Nix(_)
            | Backend::Mise(_)
            | Backend::Flake(_)
            | Backend::Deb(_)
            | Backend::AppImage(_)
            | Backend::Tarball(_)
            | Backend::TarballResolve { .. }
            | Backend::DebResolve { .. }
            | Backend::AppImageResolve { .. } => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(name: &str, attr: &str, state: TrustState) -> Package {
        Package {
            name: name.to_string(),
            backend: Backend::Nix(attr.to_string()),
            state,
        }
    }

    fn mise_package(name: &str, token: &str, state: TrustState) -> Package {
        Package {
            name: name.to_string(),
            backend: Backend::Mise(token.to_string()),
            state,
        }
    }

    fn flake_package(name: &str, reference: &str, state: TrustState) -> Package {
        Package {
            name: name.to_string(),
            backend: Backend::Flake(reference.to_string()),
            state,
        }
    }

    fn tarball_package(name: &str, url: &str, state: TrustState) -> Package {
        Package {
            name: name.to_string(),
            backend: Backend::Tarball(url.to_string()),
            state,
        }
    }

    fn inline_flake_package(name: &str, content: &str, attr: &str, state: TrustState) -> Package {
        Package {
            name: name.to_string(),
            backend: Backend::FlakeInline {
                content: content.to_string(),
                attr: attr.to_string(),
            },
            state,
        }
    }

    #[test]
    fn flake_inline_packages_yields_only_trusted_inline_flakes() {
        // Trusted-only, like every other backend collector: an untrusted inline flake is dropped
        // here (its withholding is warned once by `admit`), and only inline flakes are returned.
        let pkgs = [
            inline_flake_package(
                "keep",
                "{ outputs = {...}: {}; }",
                "default",
                TrustState::Trusted,
            ),
            inline_flake_package("drop", "{ }", "default", TrustState::Untrusted),
            flake_package("remote", "github:o/r#default", TrustState::Trusted),
            package("nixtool", "jq", TrustState::Trusted),
        ];
        let got = flake_inline_packages(&pkgs);
        assert_eq!(
            got,
            vec![(
                "keep".to_string(),
                "{ outputs = {...}: {}; }".to_string(),
                "default".to_string()
            )],
            "only the trusted inline flake, carrying its content and attr"
        );
    }

    #[test]
    fn admit_keeps_trusted_packages_and_withholds_the_rest_by_state() {
        let pkgs = [
            package("node", "nodejs_20", TrustState::Trusted),
            package("python", "python311", TrustState::Untrusted),
            package("ripgrep", "ripgrep", TrustState::Trusted),
            package("go", "go", TrustState::Changed),
        ];
        let (admitted, warnings) = admit(&pkgs);

        let names: Vec<&str> = admitted.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            ["node", "ripgrep"],
            "only trusted tools are admitted"
        );
        assert_eq!(warnings.len(), 2, "one warning per withheld tool");
        // the never-trusted one points at first approval...
        let py = warnings.iter().find(|w| w.contains("python")).unwrap();
        assert!(py.contains("untrusted") && py.contains("sbx trust"));
        // ...the changed one at re-approval (the distinction the bool collapsed).
        let go = warnings.iter().find(|w| w.contains("`go`")).unwrap();
        assert!(go.contains("changed since it was trusted") && go.contains("re-run"));
    }

    #[test]
    fn admit_of_an_empty_set_is_empty() {
        let (admitted, warnings) = admit(&[]);
        assert!(admitted.is_empty());
        assert!(warnings.is_empty());
    }

    #[test]
    fn mise_packages_returns_only_trusted_mise_tokens() {
        let pkgs = [
            mise_package("demo-tool", "aqua:example/demo-tool", TrustState::Trusted),
            package("node", "nodejs_20", TrustState::Trusted), // a nix package is not a mise token
            mise_package("evil", "aqua:attacker/x", TrustState::Untrusted), // untrusted: dropped
            mise_package("other-tool", "other-tool", TrustState::Trusted),
        ];
        // Trusted `mise:` tokens only, in declaration order; nix, flake, and untrusted are excluded.
        let pkgs_with_flake = [
            pkgs[0].clone(),
            flake_package(
                "flake-tool",
                "github:example/flake-tool#tui",
                TrustState::Trusted,
            ),
        ];
        assert_eq!(
            mise_packages(&pkgs),
            vec![
                "aqua:example/demo-tool".to_string(),
                "other-tool".to_string()
            ]
        );
        assert_eq!(
            mise_packages(&pkgs_with_flake),
            vec!["aqua:example/demo-tool".to_string()],
            "a flake package is not a mise token"
        );
    }

    #[test]
    fn tarball_packages_returns_only_trusted_urls_by_name() {
        let resolver = |name: &str, state| Package {
            name: name.to_string(),
            backend: Backend::TarballResolve {
                command: vec!["sh".into(), "-c".into(), "echo https://e/app.tar.gz".into()],
            },
            state,
        };
        let pkgs = [
            tarball_package("app", "https://e/app.tar.gz", TrustState::Trusted),
            package("node", "nodejs_20", TrustState::Trusted), // a nix package is not a tarball
            tarball_package("evil", "https://e/evil.tar.gz", TrustState::Untrusted), // dropped
            resolver("rz", TrustState::Trusted), // the resolve form is NOT a direct tarball url
        ];
        assert_eq!(
            tarball_packages(&pkgs),
            vec![("app".to_string(), "https://e/app.tar.gz".to_string())],
            "only the trusted DIRECT tarball url, keyed by name; nix, resolve and untrusted excluded"
        );
    }

    #[test]
    fn tarball_resolve_packages_returns_only_trusted_commands_by_name() {
        let resolver = |name: &str, state| Package {
            name: name.to_string(),
            backend: Backend::TarballResolve {
                command: vec!["sh".into(), "-c".into(), "echo url".into()],
            },
            state,
        };
        let pkgs = [
            resolver("keep", TrustState::Trusted),
            tarball_package("direct", "https://e/app.tar.gz", TrustState::Trusted), // not a resolver
            resolver("drop", TrustState::Untrusted),                                // dropped
        ];
        assert_eq!(
            tarball_resolve_packages(&pkgs),
            vec![(
                "keep".to_string(),
                vec!["sh".to_string(), "-c".to_string(), "echo url".to_string()]
            )],
            "only the trusted resolver (name, command); direct and untrusted excluded"
        );
    }

    #[test]
    fn flake_packages_returns_only_trusted_flake_refs_by_name() {
        let pkgs = [
            flake_package(
                "flake-tool",
                "github:example/flake-tool#tui",
                TrustState::Trusted,
            ),
            package("node", "nodejs_20", TrustState::Trusted), // a nix package is not a flake ref
            mise_package("other-tool", "other-tool", TrustState::Trusted), // nor a mise token
            flake_package("evil", "github:attacker/x#bin", TrustState::Untrusted), // untrusted: dropped
        ];
        // Trusted `flake:` (name, ref) pairs only, in declaration order; nix, mise, and
        // untrusted are excluded.
        assert_eq!(
            flake_packages(&pkgs),
            vec![(
                "flake-tool".to_string(),
                "github:example/flake-tool#tui".to_string()
            )]
        );
    }
}
