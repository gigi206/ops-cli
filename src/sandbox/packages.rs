//! Provisioning a project's declared tools.
//!
//! A project (or the global config) names tools as `name = "<backend>:<locator>"`. This
//! module handles the **`nix:`** ones — realising each admitted nixpkgs attribute against
//! the pinned nixpkgs into ops's store and reporting the `bin` directories to prepend to
//! the sandbox `PATH`. The **`mise:`** and **`flake:`** ones are not realised here: they
//! are equipped in-cage at launch — [`mise_packages`] collects the mise tokens (`mise use
//! -g`), [`flake_packages`] the `(name, ref)` of the flake packages (`nix build
//! --out-link`).
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

/// One layer of tools realised into ops's store. `bins` are the `bin` directories to
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
/// Pure, so `ops config` could show the same verdict without touching nix.
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

/// Provision every admitted package into ops's store against `nixpkgs`, rooting
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

    let mut bins = Vec::with_capacity(admitted.len());
    let mut roots = Vec::with_capacity(admitted.len());
    for p in admitted {
        // A `mise:` package is equipped in-cage by `mise use -g` at launch, not host-side;
        // only the `nix:` ones are realised here.
        let Backend::Nix(attr) = &p.backend else {
            continue;
        };
        // A declared tool is a requirement: surface a realisation failure naming the
        // package and attribute, never drop it silently.
        let logical = store::provision(nix, layout, &gcroots.join(&p.name), nixpkgs, attr, BIN)
            .map_err(|e| {
                io::Error::other(format!(
                    "cannot provision package `{}` ({attr}): {e}",
                    p.name
                ))
            })?;
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
            Backend::Nix(_) | Backend::Flake(_) => None,
        })
        .collect()
}

/// The `(name, ref)` of the *admitted* `flake:` packages — the ones the launcher builds
/// in-cage with `nix build --out-link`. Trusted-only, like the host-side `nix:` path and the
/// global `mise:` one: an untrusted project's `flake:` package is dropped here (its
/// withholding is warned once by [`provision`]'s admission, so this stays a quiet pure
/// filter). The name keys the per-package out-link under the home; the ref is the flake
/// reference passed to nix positionally.
pub(crate) fn flake_packages(packages: &[Package]) -> Vec<(String, String)> {
    packages
        .iter()
        .filter(|p| p.state == TrustState::Trusted)
        .filter_map(|p| match &p.backend {
            Backend::Flake(reference) => Some((p.name.clone(), reference.clone())),
            Backend::Nix(_) | Backend::Mise(_) => None,
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
        assert!(py.contains("untrusted") && py.contains("ops trust"));
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
            mise_package(
                "claude-code",
                "aqua:anthropics/claude-code",
                TrustState::Trusted,
            ),
            package("node", "nodejs_20", TrustState::Trusted), // a nix package is not a mise token
            mise_package("evil", "aqua:attacker/x", TrustState::Untrusted), // untrusted: dropped
            mise_package("opencode", "opencode", TrustState::Trusted),
        ];
        // Trusted `mise:` tokens only, in declaration order; nix, flake, and untrusted are excluded.
        let pkgs_with_flake = [
            pkgs[0].clone(),
            flake_package(
                "hermes",
                "github:NousResearch/hermes-agent#tui",
                TrustState::Trusted,
            ),
        ];
        assert_eq!(
            mise_packages(&pkgs),
            vec![
                "aqua:anthropics/claude-code".to_string(),
                "opencode".to_string()
            ]
        );
        assert_eq!(
            mise_packages(&pkgs_with_flake),
            vec!["aqua:anthropics/claude-code".to_string()],
            "a flake package is not a mise token"
        );
    }

    #[test]
    fn flake_packages_returns_only_trusted_flake_refs_by_name() {
        let pkgs = [
            flake_package(
                "hermes",
                "github:NousResearch/hermes-agent#tui",
                TrustState::Trusted,
            ),
            package("node", "nodejs_20", TrustState::Trusted), // a nix package is not a flake ref
            mise_package("opencode", "opencode", TrustState::Trusted), // nor a mise token
            flake_package("evil", "github:attacker/x#bin", TrustState::Untrusted), // untrusted: dropped
        ];
        // Trusted `flake:` (name, ref) pairs only, in declaration order; nix, mise, and
        // untrusted are excluded.
        assert_eq!(
            flake_packages(&pkgs),
            vec![(
                "hermes".to_string(),
                "github:NousResearch/hermes-agent#tui".to_string()
            )]
        );
    }
}
