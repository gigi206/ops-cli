//! Provisioning a project's declared tools into ops's store.
//!
//! A project (or the global config) names tools as `name = "<nixpkgs attribute>"`.
//! This module realises the *admitted* ones against the pinned nixpkgs and reports
//! the `bin` directories to prepend to the sandbox `PATH`.
//!
//! Admission is a security decision: realising a tool can run a build, so an
//! untrusted project's tools are withheld until the project is trusted. (A later
//! relaxation will admit an untrusted tool when it needs no build, only a fetch
//! from the signed cache — the build-vs-fetch gate.) A declared tool is a stated
//! requirement, so a failure to realise an *admitted* one is a hard error naming
//! the attribute — never a silent drop, unlike a best-effort bind.

use crate::config::{untrusted_reason, Package, PROJECT_CONFIG};
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
        // A declared tool is a requirement: surface a realisation failure naming the
        // package and attribute, never drop it silently.
        let logical = store::provision(nix, layout, &gcroots.join(&p.name), nixpkgs, &p.attr, BIN)
            .map_err(|e| {
                io::Error::other(format!(
                    "cannot provision package `{}` ({}): {e}",
                    p.name, p.attr
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

#[cfg(test)]
mod tests {
    use super::*;

    fn package(name: &str, attr: &str, state: TrustState) -> Package {
        Package {
            name: name.to_string(),
            attr: attr.to_string(),
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
}
