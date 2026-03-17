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

//! Build the non-Rust components.

#![allow(clippy::too_many_arguments)]

use self::build::{
    AsmTarget, Endian, PREGENERATED, Profile, Target, Tools, build_c_code,
    generate_sources_and_preassemble, walk_non_root_sources,
};
// Avoid `std::env` here; use `self::env` instead.
use std::{
    ffi::OsStr,
    fs::{self},
    path::{Path, PathBuf},
};

mod build;

mod env {
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
    define_env! { pub CARGO_CFG_TARGET_ARCH: SetByCargo }
    define_env! { pub CARGO_CFG_TARGET_ENDIAN: SetByCargo }
    define_env! { pub CARGO_CFG_TARGET_ENV: SetByCargo }
    define_env! { pub CARGO_CFG_TARGET_OS: SetByCargo }
    define_env! { pub CARGO_MANIFEST_DIR: SetByCargo }
    define_env! { pub CARGO_MANIFEST_LINKS: SetByCargo }
    define_env! { pub CARGO_PKG_NAME: SetByCargo }
    define_env! { pub CARGO_PKG_VERSION_MAJOR: SetByCargo }
    define_env! { pub CARGO_PKG_VERSION_MINOR: SetByCargo }
    define_env! { pub CARGO_PKG_VERSION_PATCH: SetByCargo }
    define_env! { pub CARGO_PKG_VERSION_PRE: SetByCargo }
    define_env! { pub DEBUG: SetByCargo }
    define_env! { pub OUT_DIR: SetByCargo }
    define_env! { pub PERL_EXECUTABLE: RerunIfChanged }
    define_env! { pub RING_PREGENERATE_ASM: RerunIfChanged }
}

fn main() {
    // Avoid assuming the working directory is the same is the $CARGO_MANIFEST_DIR so that toolchains
    // which may assume other working directories can still build this code.
    let c_root_dir = PathBuf::from(
        env::var_os(&env::CARGO_MANIFEST_DIR).expect("CARGO_MANIFEST_DIR should always be set"),
    );

    // Keep in sync with `core_name_and_version!` in prefixed.rs.
    let core_name_and_version = [
        &env::var(&env::CARGO_PKG_NAME).unwrap(),
        "core",
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

    let perl_exe = get_perl_exe();
    let nasm_exe: &OsStr = "./target/tools/windows/nasm/nasm".as_ref();

    let tools = Tools {
        perl_exe: &perl_exe,
        nasm_exe,
    };

    match env::var_os(&env::RING_PREGENERATE_ASM).as_deref() {
        Some(s) if s == "1" => {
            pregenerate_asm_main(&tools, &c_root_dir, &core_name_and_version);
        }
        None => ring_build_rs_main(&tools, &c_root_dir, &core_name_and_version),
        _ => {
            panic!("${} has an invalid value", &env::RING_PREGENERATE_ASM.name);
        }
    }
}

fn ring_build_rs_main(tools: &Tools, c_root_dir: &Path, core_name_and_version: &str) {
    let out_dir = env::var_os(&env::OUT_DIR).unwrap();
    let out_dir = PathBuf::from(out_dir);

    let arch = env::var(&env::CARGO_CFG_TARGET_ARCH).unwrap();
    let os = env::var(&env::CARGO_CFG_TARGET_OS).unwrap();
    let env = env::var(&env::CARGO_CFG_TARGET_ENV).unwrap();
    let endian = env::var(&env::CARGO_CFG_TARGET_ENDIAN).unwrap();
    let endian = if endian == "little" {
        Endian::Little
    } else {
        Endian::Other
    };

    let is_git = fs::metadata(c_root_dir.join(".git")).is_ok();

    // Published builds are always built in release mode.
    let is_debug = is_git && env::var(&env::DEBUG).unwrap() != "false";

    // During local development, force warnings in non-Rust code to be treated
    // as errors. Since warnings are highly compiler-dependent and compilers
    // don't maintain backward compatibility w.r.t. which warnings they issue,
    // don't do this for packaged builds.
    let force_warnings_into_errors = is_git;

    let target = Target {
        arch,
        os,
        env,
        endian,
    };
    let profile = Profile {
        is_debug,
        force_warnings_into_errors,
    };

    let asm_target = AsmTarget::for_target(&target);

    // If `.git` exists then assume this is the "local hacking" case where
    // we want to make it easy to build *ring* using `cargo build`/`cargo test`
    // without a prerequisite `package` step, at the cost of needing additional
    // tools like `Perl` and/or `nasm`.
    //
    // If `.git` doesn't exist then assume that this is a packaged build where
    // we want to optimize for minimizing the build tools required: No Perl,
    // no nasm, etc.
    let generated_dir = if !is_git {
        c_root_dir.join(PREGENERATED)
    } else {
        generate_sources_and_preassemble(
            tools,
            &out_dir,
            asm_target.into_iter(),
            c_root_dir,
            core_name_and_version,
        );
        out_dir.clone()
    };

    build_c_code(
        asm_target,
        &target,
        &profile,
        &generated_dir,
        c_root_dir,
        &out_dir,
        core_name_and_version,
    );
    emit_rerun_if_changed()
}

fn pregenerate_asm_main(tools: &Tools, c_root_dir: &Path, core_name_and_version: &str) {
    let pregenerated = c_root_dir.join(PREGENERATED);
    fs::create_dir(&pregenerated).unwrap();
    generate_sources_and_preassemble(
        tools,
        &pregenerated,
        AsmTarget::all(),
        c_root_dir,
        core_name_and_version,
    );
}

// TODO: We should emit `cargo:rerun-if-changed-env` for the various
// environment variables that affect the build.
fn emit_rerun_if_changed() {
    walk_non_root_sources(|path| {
        println!("cargo:rerun-if-changed={}", path.to_str().unwrap());
    })
}

fn get_perl_exe() -> PathBuf {
    get_command(&env::PERL_EXECUTABLE, "perl")
}

fn get_command(var: &'static env::EnvVar, default: &str) -> PathBuf {
    PathBuf::from(env::var_os(var).unwrap_or_else(|| default.into()))
}
