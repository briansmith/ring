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

use build::{
    Profile, Target, cargo,
    core::{
        AsmTarget, PREGENERATED, Tools, build_c_code, generate_sources_and_preassemble,
        walk_non_root_sources,
    },
};
// Avoid `std::env` here; use `cargo::env` instead.
use std::{
    ffi::OsStr,
    fs::{self},
    iter,
    path::{Path, PathBuf},
};

mod build;

fn main() {
    // Avoid assuming the working directory is the same is the $CARGO_MANIFEST_DIR so that toolchains
    // which may assume other working directories can still build this code.
    let c_root_dir = cargo::root_dir();

    // Keep in sync with `core_name_and_version!` in prefixed.rs.
    let core_name_and_version = cargo::extern_c_prefix("core");

    let perl_exe = get_perl_exe();
    let nasm_exe: &OsStr = "./target/tools/windows/nasm/nasm".as_ref();

    let tools = Tools {
        perl_exe: &perl_exe,
        nasm_exe,
    };

    match cargo::env::var_os(&cargo::env::RING_PREGENERATE_ASM).as_deref() {
        Some(s) if s == "1" => {
            pregenerate_asm_main(&tools, &c_root_dir, &core_name_and_version);
        }
        None => ring_build_rs_main(&tools, &c_root_dir, &core_name_and_version),
        _ => {
            panic!(
                "${} has an invalid value",
                &cargo::env::RING_PREGENERATE_ASM.name
            );
        }
    }
}

fn ring_build_rs_main(tools: &Tools, c_root_dir: &Path, core_name_and_version: &str) {
    let target = Target::new_from_env();
    let profile = Profile::new_from_env(c_root_dir);

    let asm_target = AsmTarget::for_target(&target);

    // If `.git` exists then assume this is the "local hacking" case where
    // we want to make it easy to build *ring* using `cargo build`/`cargo test`
    // without a prerequisite `package` step, at the cost of needing additional
    // tools like `Perl` and/or `nasm`.
    //
    // If `.git` doesn't exist then assume that this is a packaged build where
    // we want to optimize for minimizing the build tools required: No Perl,
    // no nasm, etc.
    let generated_dir = if !profile.is_git {
        &c_root_dir.join(PREGENERATED)
    } else {
        generate_sources_and_preassemble(
            tools,
            &target.out_dir,
            asm_target.into_iter(),
            c_root_dir,
            core_name_and_version,
        );
        &target.out_dir
    };

    build_c_code(
        asm_target,
        &target,
        &profile,
        generated_dir,
        c_root_dir,
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
    let build_non_rust: &Path = &PathBuf::from("build_non_rust");
    cargo::emit_rerun_if_changed(iter::once(build_non_rust));
    walk_non_root_sources(|path| cargo::emit_rerun_if_changed(iter::once(path)))
}

fn get_perl_exe() -> PathBuf {
    get_command(&cargo::env::PERL_EXECUTABLE, "perl")
}

fn get_command(var: &'static cargo::env::EnvVar, default: &str) -> PathBuf {
    PathBuf::from(cargo::env::var_os(var).unwrap_or_else(|| default.into()))
}
