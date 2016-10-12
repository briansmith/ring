// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#![allow(
    box_pointers, // TODO
    missing_docs)]
#![deny(
    const_err,
    dead_code,
    deprecated,
    exceeding_bitshifts,
    fat_ptr_transmutes,
    improper_ctypes,
    missing_copy_implementations,
    missing_debug_implementations,
    mutable_transmutes,
    no_mangle_const_items,
    non_camel_case_types,
    non_shorthand_field_patterns,
    non_snake_case,
    non_upper_case_globals,
    overflowing_literals,
    path_statements,
    plugin_as_library,
    private_no_mangle_fns,
    private_no_mangle_statics,
    stable_features,
    trivial_casts,
    trivial_numeric_casts,
    unconditional_recursion,
    unknown_crate_types,
    unknown_lints,
    unreachable_code,
    unsafe_code,
    unstable_features,
    unused_allocation,
    unused_assignments,
    unused_attributes,
    unused_comparisons,
    unused_extern_crates,
    unused_features,
    unused_import_braces,
    unused_imports,
    unused_must_use,
    unused_mut,
    unused_parens,
    unused_qualifications,
    unused_results,
    unused_unsafe,
    unused_variables,
    variant_size_differences,
    warnings,
    while_true,
)]

use std::env;
use std::path::Path;


const LIB_NAME: &'static str = "ring";

fn main() {
    for (key, value) in env::vars() {
        println!("{}: {}", key, value);
    }

    let out_dir = env::var("OUT_DIR").unwrap();

    build_c_code(&out_dir).unwrap();
}

fn build_c_code(out_dir: &str) -> Result<(), std::env::VarError> {
    let host_str = try!(env::var("HOST"));
    let host_triple = host_str.split('-').collect::<Vec<&str>>();

    let target_str = try!(env::var("TARGET"));
    let target_triple = target_str.split('-').collect::<Vec<&str>>();

    let use_msbuild = host_triple.contains(&"msvc") &&
                      target_triple.contains(&"msvc");

    let opt_level = try!(env::var("OPT_LEVEL"));
    let disable_opt = opt_level == "0";

    let num_jobs = try!(env::var("NUM_JOBS"));

    // TODO: deal with link-time-optimization flag.

    let lib_path = Path::new(out_dir).join("lib");

    if !use_msbuild {
        // Environment variables |CC|, |CXX|, etc. will be inherited from this
        // process.
        let cmake_build_type = if disable_opt {
            "DEBUG"
        } else {
            "RELWITHDEBINFO"
        };
        let args = vec![
            format!("-j{}", num_jobs),
            format!("TARGET={}", target_str),
            format!("CMAKE_BUILD_TYPE={}", cmake_build_type),
            format!("BUILD_PREFIX={}/", out_dir),
        ];
        // If $MAKE is given, use it as the make command. If not, use `gmake` for
        // BSD systems and `make` for other systems.
        let make = env::var_os("MAKE").unwrap_or_else(|| {
            let m = if target_triple[2].contains("bsd") {
                "gmake"
            } else {
                "make"
            };
            std::ffi::OsString::from(m)
        });
        run_command_with_args(&make, &args);
    } else {
        let arch = target_triple[0];
        let (platform, optional_amd64) = match arch {
            "i686" => ("Win32", None),
            "x86_64" => ("x64", Some("amd64")),
            _ => panic!("unexpected ARCH: {}", arch)
        };

        fn find_msbuild_exe(program_files_env_var: &str,
                            optional_amd64: Option<&str>)
                            -> Result<std::ffi::OsString, ()> {
            let program_files = env::var(program_files_env_var).unwrap();
            let mut msbuild = std::path::PathBuf::from(&program_files);
            msbuild.push("MSBuild");
            msbuild.push("14.0");
            msbuild.push("bin");
            if let Some(amd64) = optional_amd64 {
                msbuild.push(amd64);
            }
            msbuild.push("msbuild.exe");
            let _ = try!(std::fs::metadata(&msbuild).map_err(|_| ()));
            Ok(msbuild.into_os_string())
        }

        let msbuild =
            find_msbuild_exe("ProgramFiles", optional_amd64)
                .or_else(|_| find_msbuild_exe("ProgramFiles(x86)",
                                              optional_amd64))
                .unwrap();

        // .gitignore isn't packaged, so if it exists then this is not a
        // packaged build. Otherwise, assume it is a packaged build, and use
        // the prepackaged libs so that we don't require Perl and Yasm being
        // installed.
        let use_prepackaged_asm = std::fs::metadata(".gitignore").is_err();

        let configuration = if disable_opt { "Debug" } else { "Release" };
        let args = vec![
            format!("/m:{}", num_jobs),
            format!("/p:Platform={}", platform),
            format!("/p:Configuration={}", configuration),
            format!("/p:OutRootDir={}/", out_dir),
        ];
        if !use_prepackaged_asm {
            let mut asm_args = args.clone();
            asm_args.push(String::from("crypto/libring-asm.Windows.vcxproj"));
            run_command_with_args(&msbuild, &asm_args);
        } else {
            let pregenerated_lib_name =
                format!("msvc-{}-asm-{}.lib", LIB_NAME, arch);
            let mut pregenerated_lib = std::path::PathBuf::from("pregenerated");
            pregenerated_lib.push(pregenerated_lib_name);

            let ring_asm_lib_name = format!("{}-asm.lib", LIB_NAME);
            let mut ring_asm_lib = lib_path.clone();
            ring_asm_lib.push(&ring_asm_lib_name);
            println!("{:?} -> {:?}", &pregenerated_lib, &ring_asm_lib);

            std::fs::create_dir_all(&lib_path).unwrap();
            let _ = std::fs::copy(&pregenerated_lib, &ring_asm_lib).unwrap();
        }
        println!("cargo:rustc-link-lib=static={}-asm", LIB_NAME);

        let mut core_args = args.clone();
        core_args.push(String::from("crypto/libring.Windows.vcxproj"));
        run_command_with_args(&msbuild, &core_args);

        let mut test_args = args.clone();
        test_args.push(String::from("crypto/libring-test.Windows.vcxproj"));
        run_command_with_args(&msbuild, &test_args);
    }

    println!("cargo:rustc-link-search=native={}", lib_path.to_str().unwrap());
    println!("cargo:rustc-link-lib=static={}-core", LIB_NAME);

    // XXX: Ideally, this would only happen for `cargo test`, but we don't know
    // how to do that yet.
    println!("cargo:rustc-link-lib=static={}-test", LIB_NAME);
    if !use_msbuild {
        println!("cargo:rustc-flags=-l dylib=stdc++");
    }

    Ok(())
}

fn run_command_with_args<S>(command_name: S, args: &Vec<String>)
                            where S: AsRef<std::ffi::OsStr> + Copy {
    if !std::process::Command::new(command_name)
            .args(&args)
            .status()
            .unwrap_or_else(|e| { panic!("failed to execute {}: {}",
                            command_name.as_ref().to_str().unwrap(), e); })
            .success() {
        panic!("{} execution failed", command_name.as_ref().to_str().unwrap());
    }
}
