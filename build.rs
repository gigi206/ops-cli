//! Build script: embed source trees, and (optionally) a static nix engine, into the binary.
//!
//! 1. The bundled mise "nix" backend plugin (`mise/`). A hermetic sandbox has no host copy
//!    of the plugin to point mise at, so the tree is carried inside the binary and
//!    materialized at launch.
//! 2. With the `bundled-nix` / `bundled-bwrap` features, statically-linked `nix` and `bwrap`
//!    binaries, so the shipped sbx drives its own store and launches its own sandbox with no
//!    host engines. Each binary is supplied out-of-band via an env var (`SBX_BUNDLED_NIX` /
//!    `SBX_BUNDLED_BWRAP`, produced by `mise run build-bundled`), keeping this script free of
//!    any fetch mechanism, and is verified against a pinned hash so a drift fails here,
//!    loudly, rather than at a user's first launch.
//!
//! 3. The in-cage exec-enforcement shim (`proc-shim/`), built here from its own crate and
//!    embedded unconditionally. It is sbx's own component rather than a third-party engine,
//!    and the enforcement path has no fallback: what gets bound inside a sandbox has to be a
//!    program that can do those three steps and nothing else.
//!
//! Each tree is walked into a `(path, bytes)` table that a module includes. Both re-run
//! whenever a source file changes, so the embedded copies never drift.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A static engine sbx can embed under a `bundled-*` feature, pinned for reproducibility.
/// Each is produced by `mise run build-bundled` from a pinned `pkgsStatic` attribute and
/// supplied to this script by path; the build fails if the supplied bytes do not hash to
/// the pinned `expected_sha`, so a drift is caught here rather than at a user's first launch.
struct Engine {
    /// Cargo feature flag that gates the embed (e.g. `CARGO_FEATURE_BUNDLED_NIX`).
    feature_env: &'static str,
    /// Env var supplying the path to the prebuilt static binary (e.g. `SBX_BUNDLED_NIX`).
    src_env: &'static str,
    /// The SHA-256 the supplied binary's bytes must match.
    expected_sha: &'static str,
    /// Basename of the generated blob/module (`bundled_nix` → `bundled_nix.bin`/`.rs`).
    stem: &'static str,
    /// Name of the generated `pub static … : &[u8]` bytes constant (e.g. `NIX_BIN`).
    bytes_const: &'static str,
    /// Name of the generated `pub const … : &str` hash constant (e.g. `NIX_SHA256`).
    sha_const: &'static str,
    /// Human label for diagnostics (e.g. `nix`).
    human: &'static str,
}

/// The engines sbx can embed. Each `expected_sha` is the SHA-256 of the static binary
/// `mise run static-<engine>` realises from the pinned nixpkgs ref recorded in `mise.toml`;
/// bump the ref and this hash together. `nix` is 2.34.7, `bwrap` (bubblewrap) is 0.11.2,
/// both x86_64 static musl.
const ENGINES: &[Engine] = &[
    Engine {
        feature_env: "CARGO_FEATURE_BUNDLED_NIX",
        src_env: "SBX_BUNDLED_NIX",
        expected_sha: "8ebec57b2f50bd10e62ac2e4ae27058a22019f8840ae278e2da9a7efe16faf80",
        stem: "bundled_nix",
        bytes_const: "NIX_BIN",
        sha_const: "NIX_SHA256",
        human: "nix",
    },
    Engine {
        feature_env: "CARGO_FEATURE_BUNDLED_BWRAP",
        src_env: "SBX_BUNDLED_BWRAP",
        expected_sha: "9c58a5a4e81e2295b235cd5179e948b758a430607befd446766665ebb46badaa",
        stem: "bundled_bwrap",
        bytes_const: "BWRAP_BIN",
        sha_const: "BWRAP_SHA256",
        human: "bwrap",
    },
];

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    emit_mise_plugin(&manifest, &out_dir);
    emit_proc_shim(&manifest, &out_dir);
    for engine in ENGINES {
        emit_bundled_engine(&out_dir, engine);
    }
}

/// Build the in-cage exec-enforcement shim from `proc-shim/` and embed it, with the hash sbx
/// stamps beside the materialized copy so a newer sbx replaces an older shim.
///
/// Built here rather than supplied by path like the engines, and embedded unconditionally rather
/// than behind a feature, because this is sbx's own code and enforcement has no second choice: a
/// launch that cannot bind the shim refuses. A feature-gated shim would mean some builds silently
/// binding something else, which is the situation this exists to end.
///
/// It is built for the same `TARGET` as sbx, so the shim inside a static release binary is itself
/// static, and a development build's shim matches the loader that build already relies on.
fn emit_proc_shim(manifest: &Path, out_dir: &Path) {
    let crate_dir = manifest.join("proc-shim");
    for file in ["Cargo.toml", "Cargo.lock", "src/main.rs"] {
        println!("cargo:rerun-if-changed={}", crate_dir.join(file).display());
    }

    let target = env::var("TARGET").expect("TARGET is set for a build script");
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let shim_target_dir = out_dir.join("proc-shim-target");

    let mut cmd = Command::new(&cargo);
    cmd.arg("build")
        .arg("--release")
        .arg("--locked")
        .arg("--target")
        .arg(&target)
        .arg("--manifest-path")
        .arg(crate_dir.join("Cargo.toml"))
        .env("CARGO_TARGET_DIR", &shim_target_dir);
    // A build script inherits the outer build's cargo/rustc environment, which describes a build
    // this one shares nothing with: sbx's flags, its jobserver, its chosen target. Handing them
    // down would silently reshape the shim, so drop them and let the inner build stand alone.
    for var in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_BUILD_TARGET",
        "CARGO_MAKEFLAGS",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
    ] {
        cmd.env_remove(var);
    }
    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("running `cargo build` for the exec shim: {e}"));
    assert!(
        status.success(),
        "building the exec shim (proc-shim/) failed — sbx cannot be built without it"
    );

    let bin = shim_target_dir
        .join(&target)
        .join("release")
        .join("sbx-proc-shim");
    let bytes = fs::read(&bin)
        .unwrap_or_else(|e| panic!("reading the built exec shim ({}): {e}", bin.display()));
    let sha = sha256_hex(&bytes);
    let blob = out_dir.join("proc_shim.bin");
    fs::write(&blob, &bytes).unwrap();
    let generated = format!(
        "// @generated by build.rs — the embedded in-cage exec-enforcement shim.\n\
         pub static PROC_SHIM_BIN: &[u8] = include_bytes!({path:?});\n\
         pub const PROC_SHIM_SHA256: &str = {sha:?};\n",
        path = blob.to_str().expect("OUT_DIR path is valid UTF-8"),
    );
    fs::write(out_dir.join("proc_shim.rs"), generated).unwrap();
}

/// Embed `engine`'s static binary when its feature is on, writing the module its `store`
/// resolver includes (the bytes constant + their hash). The binary is read from the path in
/// `engine.src_env` and verified against `engine.expected_sha`. With the feature off (the
/// default), this is a no-op: sbx resolves the engine from its override env / `PATH`.
fn emit_bundled_engine(out_dir: &Path, engine: &Engine) {
    // Re-run if the supplying var changes, so a re-point re-embeds.
    println!("cargo:rerun-if-env-changed={}", engine.src_env);
    if env::var_os(engine.feature_env).is_none() {
        return;
    }
    let src = env::var_os(engine.src_env).unwrap_or_else(|| {
        panic!(
            "the bundled-{0} feature is enabled but {1} is unset — point it at a static \
             `{0}` binary (use `mise run build-bundled`, which produces one)",
            engine.human, engine.src_env,
        )
    });
    let src = PathBuf::from(src);
    println!("cargo:rerun-if-changed={}", src.display());
    let bytes = fs::read(&src)
        .unwrap_or_else(|e| panic!("reading {} ({}): {e}", engine.src_env, src.display()));
    let got = sha256_hex(&bytes);
    assert_eq!(
        got,
        engine.expected_sha,
        "bundled {human} sha256 mismatch — {src_env} ({src}) is not the pinned engine \
         (got {got}, expected {expected}); rebuild it from the pinned nixpkgs ref or bump \
         the pin in build.rs",
        human = engine.human,
        src_env = engine.src_env,
        src = src.display(),
        expected = engine.expected_sha,
    );
    let bin = out_dir.join(format!("{}.bin", engine.stem));
    fs::write(&bin, &bytes).unwrap();
    let generated = format!(
        "// @generated by build.rs — the embedded static {human} engine.\n\
         pub static {bytes_const}: &[u8] = include_bytes!({path:?});\n\
         pub const {sha_const}: &str = {sha:?};\n",
        human = engine.human,
        bytes_const = engine.bytes_const,
        path = bin.to_str().expect("OUT_DIR path is valid UTF-8"),
        sha_const = engine.sha_const,
        sha = engine.expected_sha,
    );
    fs::write(out_dir.join(format!("{}.rs", engine.stem)), generated).unwrap();
}

/// Hex SHA-256 of `bytes`, for the build-time integrity check on the embedded engine.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Embed the `mise/` tree as a flat `(relative path, bytes)` table the `sandbox::miseplugin`
/// module includes.
fn emit_mise_plugin(manifest: &Path, out_dir: &Path) {
    let plugin_root = manifest.join("mise");
    println!("cargo:rerun-if-changed={}", plugin_root.display());

    let mut files: Vec<(String, PathBuf)> = Vec::new();
    collect(&plugin_root, &plugin_root, &mut files);
    // Deterministic order, so the generated table (and any hash of it) is stable.
    files.sort();

    let mut out = String::from(
        "// @generated by build.rs — the embedded mise \"nix\" backend plugin tree.\n\
         /// Each entry is (path relative to the plugin root, file bytes).\n\
         pub(crate) static PLUGIN_FILES: &[(&str, &[u8])] = &[\n",
    );
    for (rel, abs) in &files {
        println!("cargo:rerun-if-changed={}", abs.display());
        out.push_str(&format!(
            "    ({:?}, include_bytes!({:?})),\n",
            rel,
            abs.to_str().expect("plugin path is valid UTF-8"),
        ));
    }
    out.push_str("];\n");

    fs::write(out_dir.join("mise_plugin_files.rs"), out).unwrap();
}

/// Collect every file under `dir` as `(path relative to `root`, absolute path)`, recursing into
/// subdirectories. The relative path is forward-slashed, which is what an in-sandbox path needs.
fn collect(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect(root, &path, out);
        } else {
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_str()
                .expect("plugin path is valid UTF-8")
                .to_string();
            out.push((rel, path));
        }
    }
}
