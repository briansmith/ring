// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! Cargo-specific build logic that isn't specific to this project.

use super::{Profile, Target, target::Endian};
// Avoid `std::env` here; use `self::env` instead.
use std::{
    fs::{self},
    path::{Path, PathBuf},
};

pub mod env {
    use std::ffi::OsString;

    macro_rules! define_env {
        { $vis:vis $NAME:ident : $ty:ident } => {
            $vis const $NAME: EnvVar = EnvVar {
                name: stringify!($NAME),
                ty: EnvVarTy::$ty,
            };
        };
    }

    enum EnvVarTy {
        RerunIfChanged,
        SetByCargo,
    }

    pub struct EnvVar {
        pub name: &'static str,
        ty: EnvVarTy,
    }

    /// Read an environment variable and optionally tell Cargo that we depend on it.
    ///
    /// The env var is static since we intend to only read a static set of environment
    /// variables.
    pub fn var_os(env_var: &'static EnvVar) -> Option<OsString> {
        match env_var.ty {
            EnvVarTy::RerunIfChanged => {
                println!("cargo:rerun-if-env-changed={}", env_var.name);
            }
            EnvVarTy::SetByCargo => {}
        }
        std::env::var_os(env_var.name)
    }

    pub fn var(env_var: &'static EnvVar) -> Option<String> {
        var_os(env_var).and_then(|value| value.into_string().ok())
    }

    // In alphabetical order
    define_env! { pub(super) CARGO_CFG_TARGET_ARCH: SetByCargo }
    define_env! { pub(super) CARGO_CFG_TARGET_ENDIAN: SetByCargo }
    define_env! { pub(super) CARGO_CFG_TARGET_ENV: SetByCargo }
    define_env! { pub(super) CARGO_CFG_TARGET_OS: SetByCargo }
    define_env! { pub(super) CARGO_MANIFEST_DIR: SetByCargo }
    define_env! { pub(super) CARGO_MANIFEST_LINKS: SetByCargo }
    define_env! { pub(super) CARGO_PKG_NAME: SetByCargo }
    define_env! { pub(super) CARGO_PKG_VERSION_MAJOR: SetByCargo }
    define_env! { pub(super) CARGO_PKG_VERSION_MINOR: SetByCargo }
    define_env! { pub(super) CARGO_PKG_VERSION_PATCH: SetByCargo }
    define_env! { pub(super) CARGO_PKG_VERSION_PRE: SetByCargo }
    define_env! { pub(super) DEBUG: SetByCargo }
    define_env! { pub(super) OUT_DIR: SetByCargo }

    // XXX: These don't belong here.
    define_env! { pub PERL_EXECUTABLE: RerunIfChanged }
    define_env! { pub RING_PREGENERATE_ASM: RerunIfChanged }
}

pub fn root_dir() -> PathBuf {
    // Avoid assuming the working directory is the same is the $CARGO_MANIFEST_DIR so that toolchains
    // which may assume other working directories can still build this code.
    PathBuf::from(
        env::var_os(&env::CARGO_MANIFEST_DIR).expect("CARGO_MANIFEST_DIR should always be set"),
    )
}

pub fn extern_c_prefix(component: &str) -> String {
    // Keep in sync with `core_name_and_version!` in prefixed.rs.
    let core_name_and_version = [
        &env::var(&env::CARGO_PKG_NAME).unwrap(),
        component,
        &env::var(&env::CARGO_PKG_VERSION_MAJOR).unwrap(),
        &env::var(&env::CARGO_PKG_VERSION_MINOR).unwrap(),
        &env::var(&env::CARGO_PKG_VERSION_PATCH).unwrap(),
        &env::var(&env::CARGO_PKG_VERSION_PRE).unwrap(), // Often empty
    ]
    .join("_");
    // Ensure `links` in Cargo.toml is consistent with the version.
    assert_eq!(
        &env::var(&env::CARGO_MANIFEST_LINKS).unwrap(),
        &core_name_and_version
    );
    core_name_and_version
}

impl Target {
    pub fn new_from_env() -> Self {
        let arch = env::var(&env::CARGO_CFG_TARGET_ARCH).unwrap();
        let os = env::var(&env::CARGO_CFG_TARGET_OS).unwrap();
        let env = env::var(&env::CARGO_CFG_TARGET_ENV).unwrap();
        let endian = env::var(&env::CARGO_CFG_TARGET_ENDIAN).unwrap();
        let endian = if endian == "little" {
            Endian::Little
        } else {
            Endian::Other
        };

        let out_dir = PathBuf::from(env::var_os(&env::OUT_DIR).unwrap());

        Self {
            arch,
            os,
            env,
            endian,
            out_dir,
        }
    }
}

impl Profile {
    pub fn new_from_env(root_dir: &Path) -> Self {
        let is_git = fs::metadata(root_dir.join(".git")).is_ok();

        // Published builds are always built in release mode.
        let is_debug = is_git && env::var(&env::DEBUG).unwrap() != "false";

        // During local development, force warnings in non-Rust code to be treated
        // as errors. Since warnings are highly compiler-dependent and compilers
        // don't maintain backward compatibility w.r.t. which warnings they issue,
        // don't do this for packaged builds.
        let force_warnings_into_errors = is_git;

        Self {
            is_git,
            is_debug,
            force_warnings_into_errors,
        }
    }
}

// TODO: We should emit `cargo:rerun-if-changed-env` for the various
// environment variables that affect the build.
pub fn emit_rerun_if_changed<'a>(paths: impl Iterator<Item = &'a Path>) {
    paths.for_each(|path| {
        println!("cargo:rerun-if-changed={}", path.to_str().unwrap());
    })
}
