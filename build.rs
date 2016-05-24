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
    drop_with_repr_extern,
    exceeding_bitshifts,
    fat_ptr_transmutes,
    improper_ctypes,
    match_of_unit_variant_via_paren_dotdot,
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

extern crate num;

#[path="src/ec/ec_build.rs"] mod ec_build;
#[path="src/ec/curves.rs"] mod curves;

use std::env;
use std::path::Path;


const LIB_NAME: &'static str = "ring";

fn main() {
    for (key, value) in env::vars() {
        println!("{}: {}", key, value);
    }

    let out_dir = env::var("OUT_DIR").unwrap();

    ec_build::generate_code(&out_dir).unwrap();
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

    let command_name;
    let args;
    if !use_msbuild {
        command_name = "make";
        // Environment variables |CC|, |CXX|, etc. will be inherited from this
        // process.
        let cmake_build_type = if disable_opt {
            "DEBUG"
        } else {
            "RELWITHDEBINFO"
        };
        args = vec![
            format!("-j{}", num_jobs),
            format!("TARGET={}", target_str),
            format!("CMAKE_BUILD_TYPE={}", cmake_build_type),
            format!("BUILD_PREFIX={}/", out_dir),
            format!("GENERATED_CODE_DIR={}", out_dir),
        ];
    } else {
        // TODO: This assumes that the package is being built under a
        // {VS2013,VS2015} {x86,x64} Native Tools Command Prompt. It would be
        // nice if we didn't require that to be the case. At least it should be
        // documented.
        command_name = "msbuild";
        let platform = match target_triple[0] {
            "i686" => "Win32",
            "x86_64" => "x64",
            _ => panic!("unexpected ARCH: {}", target_triple[0])
        };
        let configuration = if disable_opt { "Debug" } else { "Release" };
        args = vec![
            format!("{}.sln", LIB_NAME),
            format!("/m:{}", num_jobs),
            format!("/p:Platform={}", platform),
            format!("/p:Configuration={}", configuration),
            format!("/p:OutRootDir={}/", out_dir),
            format!("/p:GENERATED_CODE_DIR={}", out_dir),
        ];
    }

    if !std::process::Command::new(command_name)
            .args(&args)
            .status()
            .unwrap_or_else(|e| { panic!("failed to execute {}: {}",
                            command_name, e); })
            .success() {
        panic!("{} execution failed", command_name);
    }

    let lib_path = Path::new(out_dir).join("lib");
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
