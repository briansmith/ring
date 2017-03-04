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

// TODO: Deny `unused_qualifications` after
// https://github.com/rust-lang/rust/issues/37345 is fixed.
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
    unused_results,
    unused_unsafe,
    unused_variables,
    variant_size_differences,
    warnings,
    while_true,
)]

extern crate gcc;
extern crate target_build_utils;
extern crate rayon;

use std::env;
use std::path::{Path, PathBuf};
use std::fs::{self, DirEntry};
use target_build_utils::TargetInfo;
use rayon::par_iter::{ParallelIterator, IntoParallelIterator,
                      IntoParallelRefIterator};

const LIB_NAME: &'static str = "ring";

#[cfg_attr(rustfmt, rustfmt_skip)]
const RING_SRC: &'static [&'static str] =
    &["crypto/aes/aes.c",
      "crypto/bn/add.c",
      "crypto/bn/bn.c",
      "crypto/bn/cmp.c",
      "crypto/bn/convert.c",
      "crypto/bn/div.c",
      "crypto/bn/exponentiation.c",
      "crypto/bn/gcd.c",
      "crypto/bn/generic.c",
      "crypto/bn/montgomery.c",
      "crypto/bn/montgomery_inv.c",
      "crypto/bn/mul.c",
      "crypto/bn/random.c",
      "crypto/bn/shift.c",
      "crypto/cipher/e_aes.c",
      "crypto/crypto.c",
      "crypto/curve25519/curve25519.c",
      "crypto/ec/ecp_nistz.c",
      "crypto/ec/ecp_nistz256.c",
      "crypto/ec/gfp_p256.c",
      "crypto/ec/gfp_p384.c",
      "crypto/mem.c",
      "crypto/modes/gcm.c",
      "crypto/rand/sysrand.c",
      "crypto/limbs/limbs.c"];

const RING_INTEL_SHARED_SRCS: &'static [&'static str] = &["crypto/cpu-intel.c"];

const RING_X86_SRCS: &'static [&'static str] =
    &["crypto/aes/asm/aes-586.pl",
      "crypto/aes/asm/aesni-x86.pl",
      "crypto/aes/asm/vpaes-x86.pl",
      "crypto/bn/asm/x86-mont.pl",
      "crypto/chacha/asm/chacha-x86.pl",
      "crypto/ec/asm/ecp_nistz256-x86.pl",
      "crypto/modes/asm/ghash-x86.pl",
      "crypto/poly1305/asm/poly1305-x86.pl",
      "crypto/sha/asm/sha256-586.pl",
      "crypto/sha/asm/sha512-586.pl"];

const RING_X86_64_SRC: &'static [&'static str] =
    &["crypto/aes/asm/aes-x86_64.pl",
      "crypto/aes/asm/aesni-x86_64.pl",
      "crypto/aes/asm/bsaes-x86_64.pl",
      "crypto/aes/asm/vpaes-x86_64.pl",
      "crypto/bn/asm/x86_64-mont.pl",
      "crypto/bn/asm/x86_64-mont5.pl",
      "crypto/chacha/asm/chacha-x86_64.pl",
      "crypto/curve25519/asm/x25519-asm-x86_64.S",
      "crypto/curve25519/x25519-x86_64.c",
      "crypto/ec/asm/ecp_nistz256-x86_64.pl",
      "crypto/ec/asm/p256-x86_64-asm.pl",
      "crypto/modes/asm/aesni-gcm-x86_64.pl",
      "crypto/modes/asm/ghash-x86_64.pl",
      "crypto/poly1305/asm/poly1305-x86_64.pl",
      "crypto/sha/asm/sha256-x86_64.pl",
      "crypto/sha/asm/sha512-x86_64.pl"];

#[cfg_attr(rustfmt, rustfmt_skip)]
const RING_ARM_SHARED_SRCS: &'static [&'static str] =
    &["crypto/cpu-arm.c",
      "crypto/cpu-arm-linux.c",
      "crypto/aes/asm/aesv8-armx.pl",
      "crypto/modes/asm/ghashv8-armx.pl"];

const RING_ARM_SRCS: &'static [&'static str] =
    &["crypto/aes/asm/aes-armv4.pl",
      "crypto/aes/asm/bsaes-armv7.pl",
      "crypto/bn/asm/armv4-mont.pl",
      "crypto/chacha/asm/chacha-armv4.pl",
      "crypto/curve25519/asm/x25519-asm-arm.S",
      "crypto/ec/asm/ecp_nistz256-armv4.pl",
      "crypto/modes/asm/ghash-armv4.pl",
      "crypto/poly1305/asm/poly1305-armv4.pl",
      "crypto/sha/asm/sha256-armv4.pl",
      "crypto/sha/asm/sha512-armv4.pl"];

const RING_AARCH64_SRCS: &'static [&'static str] =
    &["crypto/cpu-aarch64-linux.c",
      "crypto/bn/asm/armv8-mont.pl",
      "crypto/chacha/asm/chacha-armv8.pl",
      "crypto/ec/asm/ecp_nistz256-armv8.pl",
      "crypto/poly1305/asm/poly1305-armv8.pl",
      "crypto/sha/asm/sha256-armv8.pl",
      "crypto/sha/asm/sha512-armv8.pl"];

#[cfg_attr(rustfmt, rustfmt_skip)]
const RING_PPC_SRCS: &'static [&'static str] =
    &["crypto/aes/asm/aesp8-ppc.pl",
      "crypto/cpu-ppc64le.c"];

const RING_TEST_SRCS: &'static [&'static str] =
    &["crypto/bn/bn_test.cc",
      "crypto/constant_time_test.c",
      "crypto/test/bn_test_convert.c",
      "crypto/test/bn_test_lib.c",
      "crypto/test/bn_test_new.c",
      "crypto/test/file_test.cc"];

#[cfg_attr(rustfmt, rustfmt_skip)]
const RING_HEADERS: &'static [&'static str] =
    &["crypto/poly1305/internal.h",
      "crypto/test/scoped_types.h",
      "crypto/test/rand.h",
      "crypto/curve25519/internal.h",
      "crypto/cipher/internal.h",
      "crypto/bn/rsaz_exp.h",
      "crypto/bn/internal.h",
      "crypto/internal.h",
      "crypto/rsa/internal.h",
      "crypto/modes/internal.h",
      "crypto/ec/ecp_nistz.h",
      "crypto/ec/ecp_nistz384.h",
      "crypto/ec/ecp_nistz256.h",
      "crypto/ec/gfp_internal.h",
      "crypto/limbs/limbs.h",
      "include/openssl/type_check.h",
      "include/openssl/mem.h",
      "include/openssl/bn.h",
      "include/openssl/opensslconf.h",
      "include/openssl/arm_arch.h",
      "include/openssl/cpu.h",
      "include/openssl/rsa.h",
      "include/openssl/aes.h",
      "include/openssl/base.h",
      "include/openssl/err.h"];

const RING_TEST_HEADERS: &'static [&'static str] =
    &["crypto/test/bn_test_lib.h",
      "crypto/test/file_test.h",
      "crypto/test/bn_test_util.h"];

#[cfg_attr(rustfmt, rustfmt_skip)]
const RING_INLINE_FILES: &'static [&'static str] =
    &["crypto/ec/ecp_nistz256_table.inl",
      "crypto/ec/ecp_nistz384.inl",
      "crypto/ec/gfp_limbs.inl",
      "crypto/ec/ecp_nistz384_mul.inl",
      "crypto/limbs/limbs.inl"];

#[cfg_attr(rustfmt, rustfmt_skip)]
const RING_PERL_INCLUDES: &'static [&'static str] =
    &["crypto/sha/asm/sha-x86_64.pl",
      "crypto/sha/asm/sha-armv8.pl",
      "crypto/perlasm/x86masm.pl",
      "crypto/perlasm/x86gas.pl",
      "crypto/perlasm/x86nasm.pl",
      "crypto/perlasm/x86asm.pl",
      "crypto/perlasm/x86_64-xlate.pl",
      "crypto/perlasm/arm-xlate.pl",
      "crypto/perlasm/ppc-xlate.pl"];

const RING_BUILD_FILE: &'static [&'static str] = &["build.rs"];

#[cfg_attr(rustfmt, rustfmt_skip)]
const C_FLAGS: &'static [&'static str] =
    &["-std=c1x", // GCC 4.6 requires "c1x" instead of "c11"
      "-Wbad-function-cast",
      "-Wmissing-prototypes",
      "-Wnested-externs",
      "-Wstrict-prototypes"];

// GCC 4.6 requires "c++0x" instead of "c++11"
const CXX_FLAGS: &'static [&'static str] = &["-std=c++0x"];

#[cfg_attr(rustfmt, rustfmt_skip)]
const CPP_FLAGS: &'static [&'static str] =
    &["-D_XOPEN_SOURCE=700",
      "-fdata-sections",
      "-ffunction-sections",
      "-pedantic",
      "-pedantic-errors",
      "-Wall",
      "-Werror",
      "-Wextra",
      "-Wcast-align",
      "-Wcast-qual",
      "-Wenum-compare",
      "-Wfloat-equal",
      "-Wformat=2",
      "-Winline",
      "-Winvalid-pch",
      "-Wmissing-declarations",
      "-Wmissing-field-initializers",
      "-Wmissing-include-dirs",
      "-Wredundant-decls",
      "-Wshadow",
      "-Wsign-compare",
      "-Wundef",
      "-Wuninitialized",
      "-Wwrite-strings",
      "-DBORINGSSL_IMPLEMENTATION",
      "-fno-strict-aliasing",
      "-fvisibility=hidden",
      "-Wno-cast-align"];

const LD_FLAGS: &'static [&'static str] = &[];

fn main() {
    for (key, value) in env::vars() {
        println!("{}: {}", key, value);
    }

    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir = PathBuf::from(out_dir);

    // copied from gcc
    let mut cfg = rayon::Configuration::new();
    if let Ok(amt) = env::var("NUM_JOBS") {
        if let Ok(amt) = amt.parse() {
            cfg = cfg.set_num_threads(amt);
        }
    }
    rayon::initialize(cfg).unwrap();

    let _ = rayon::join(check_all_files_tracked, || build_c_code(out_dir));
}

fn build_c_code(out_dir: PathBuf) {
    let target_info = TargetInfo::new().expect("Could not get target");
    let use_msvcbuild = target_info.target_env() == "msvc";
    if use_msvcbuild {
        let opt = env::var("OPT_LEVEL").expect("Cargo sets this");
        build_msvc(&target_info,
                   opt == "0",
                   &env::var("NUM_JOBS").expect("Cargo sets this"),
                   out_dir);
    } else {
        build_unix(&target_info, out_dir);
    }
}

fn build_msvc(target_info: &TargetInfo, disable_opt: bool, num_jobs: &str,
              out_dir: PathBuf) {
    let lib_path = Path::new(&out_dir).join("lib");

    let (platform, optional_amd64) = match target_info.target_arch() {
        "x86" => ("Win32", None),
        "x86_64" => ("x64", Some("amd64")),
        arch => panic!("unexpected ARCH: {}", arch),
    };

    fn find_msbuild_exe(program_files_env_var: &str,
                        optional_amd64: Option<&str>)
                        -> Result<std::ffi::OsString, ()> {
        let program_files = env::var(program_files_env_var).unwrap();
        let mut msbuild = PathBuf::from(&program_files);
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

    let msbuild = find_msbuild_exe("ProgramFiles", optional_amd64)
        .or_else(|_| find_msbuild_exe("ProgramFiles(x86)", optional_amd64))
        .unwrap();

    println!("cargo:rustc-link-search=native={}", lib_path.to_str().unwrap());

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
        format!("/p:OutRootDir={}/", out_dir.to_str().unwrap()),
    ];
    if !use_prepackaged_asm {
        let mut asm_args = args.clone();
        asm_args.push(String::from("crypto/libring-asm.Windows.vcxproj"));
        run_command_with_args(&msbuild, &asm_args);
    } else {
        let pregenerated_lib_name =
            format!("msvc-{}-asm-{}.lib", LIB_NAME, target_info.target_arch());
        let mut pregenerated_lib = PathBuf::from("pregenerated");
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
    println!("cargo:rustc-link-lib=static={}-core", LIB_NAME);

    let mut test_args = args.clone();
    test_args.push(String::from("crypto/libring-test.Windows.vcxproj"));
    run_command_with_args(&msbuild, &test_args);
    println!("cargo:rustc-link-lib=static={}-test", LIB_NAME);
}

fn build_unix(target_info: &TargetInfo, out_dir: PathBuf) {
    let mut lib_target = out_dir.clone();
    lib_target.push("libring-core.a");
    let lib_target = lib_target.as_path();

    let mut test_target = out_dir.clone();
    test_target.push("libring-test.a");
    let test_target = test_target.as_path();

    let lib_header_change = RING_HEADERS.par_iter()
        .chain(RING_INLINE_FILES.par_iter())
        .chain(RING_BUILD_FILE.par_iter())
        .map(Path::new)
        .any(|p| need_run(&p, lib_target));
    let test_header_change = RING_TEST_HEADERS.par_iter()
        .map(Path::new)
        .any(|p| need_run(&p, test_target)) ||
                             lib_header_change;

    let srcs = match target_info.target_arch() {
        "x86_64" => vec![RING_X86_64_SRC, RING_INTEL_SHARED_SRCS],
        "x86" => vec![RING_X86_SRCS, RING_INTEL_SHARED_SRCS],
        "arm" => vec![RING_ARM_SHARED_SRCS, RING_ARM_SRCS],
        "aarch64" => vec![RING_ARM_SHARED_SRCS, RING_AARCH64_SRCS],
        _ => Vec::new(),
    };

    let additional = srcs.into_par_iter()
        .weight_max()
        .flat_map(|additional_src| {
            additional_src.par_iter()
                .map(|src| make_asm(src, out_dir.clone(), &target_info))
        });
    build_library(lib_target,
                  additional,
                  RING_SRC,
                  target_info,
                  out_dir.clone(),
                  lib_header_change);

    // XXX: Ideally, this would only happen for `cargo test`,
    // but we don't know how to do that yet.
    build_library(test_target,
                  Vec::new().into_par_iter(),
                  RING_TEST_SRCS,
                  target_info,
                  out_dir.clone(),
                  test_header_change);

    let libcxx = if use_libcxx(target_info) {
        "c++"
    } else {
        "stdc++"
    };
    println!("cargo:rustc-flags=-l dylib={}", libcxx);
    print_rerun();
}


fn build_library<P>(target: &Path, additional: P,
                    lib_src: &'static [&'static str],
                    target_info: &TargetInfo, out_dir: PathBuf,
                    header_changed: bool)
    where P: ParallelIterator<Item = String>
{
    // Compile all the (dirty) source files into object files.
    let objs = additional.chain(lib_src.par_iter().map(|a| String::from(*a)))
        .weight_max()
        .map(|f| compile(&f, &target_info, out_dir.clone(), header_changed))
        .map(|v| vec![v])
        .reduce(Vec::new,
                &|mut a: Vec<String>, b: Vec<String>| -> Vec<String> {
                    a.extend(b.into_iter());
                    a
                });

    //Rebuild the library if necessary.
    if objs.par_iter()
        .map(|f| Path::new(f))
        .any(|p| need_run(&p, target)) {
        let mut c = gcc::Config::new();

        for f in LD_FLAGS {
            let _ = c.flag(&f);
        }
        match target_info.target_os() {
            "macos" => {
                let _ = c.flag("-fPIC");
                let _ = c.flag("-Wl,-dead_strip");
            },
            _ => {
                let _ = c.flag("-Wl,--gc-sections".into());
            },
        }
        for o in objs {
            let _ = c.object(o);
        }
        c.compile(target.file_name()
            .and_then(|f| f.to_str())
            .expect("No filename"));
    }
}

fn compile(file: &str, target_info: &TargetInfo, mut out_dir: PathBuf,
           header_change: bool)
           -> String {
    let p = Path::new(file);
    out_dir.push(p.file_name().expect("There is a filename"));
    out_dir.set_extension("o");
    if header_change || need_run(&p, out_dir.as_path()) {
        let mut c = gcc::Config::new();
        let _ = c.include("include");
        match p.extension().map(|p| p.to_str()) {
            Some(Some("c")) => {
                for f in C_FLAGS {
                    let _ = c.flag(f);
                }
            },
            Some(Some("cc")) => {
                for f in CXX_FLAGS {
                    let _ = c.flag(f);
                }
                let _ = c.cpp(true);
                if use_libcxx(target_info) {
                     let _ = c.cpp_set_stdlib(Some("c++"));
                }
            },
            Some(Some("S")) => {},
            e => panic!("Unsupported filextension: {:?}", e),
        };
        for f in CPP_FLAGS {
            let _ = c.flag(&f);
        }
        if target_info.target_os() != "none" &&
           target_info.target_os() != "redox" {
            let _ = c.flag("-fstack-protector");
        }
        let _ = match (target_info.target_os(), target_info.target_arch()) {
            // ``-gfull`` is required for Darwin's |-dead_strip|.
            ("macos", _) => c.flag("-gfull"),
            _ => c.flag("-g3"),
        };
        if env::var("OPT_LEVEL").unwrap() != "0" {
            let _ = c.define("NDEBUG", None);
        }
        let mut c = c.get_compiler().to_command();
        let _ = c.arg("-c")
            .arg("-o")
            .arg(format!("{}", out_dir.to_str().expect("Invalid path")))
            .arg(file);
        println!("{:?}", c);
        if !c.status()
            .expect(&format!("Failed to compile {}", file))
            .success() {
            panic!("Failed to compile {}", file)
        }
    }
    out_dir.to_str().expect("Invalid path").into()
}

fn use_libcxx(target_info: &TargetInfo) -> bool {
    // target_vendor is only set if a nightly version of rustc is used
    target_info.target_vendor()
        .map(|v| v == "apple")
        .unwrap_or(target_info.target_os() == "macos" ||
                   target_info.target_os() == "ios") ||
                    target_info.target_os() == "freebsd"
}

fn run_command_with_args<S>(command_name: S, args: &[String])
    where S: AsRef<std::ffi::OsStr> + Copy
{
    let status = std::process::Command::new(command_name)
        .args(args)
        .status()
        .unwrap_or_else(|e| {
            panic!("failed to execute {}: {}",
                   command_name.as_ref().to_str().unwrap(),
                   e);
        });

    if !status.success() {
        panic!("{} execution failed", command_name.as_ref().to_str().unwrap());
    }
}

fn make_asm(source: &str, mut dst: PathBuf, target_info: &TargetInfo)
            -> String {
    let p = Path::new(source);
    if p.extension().expect("File without extension").to_str() == Some("pl") {
        dst.push(p.file_name().expect("File without filename??"));
        dst.set_extension("S");
        let r: String = dst.to_str().expect("Could not convert path").into();
        let perl_include_changed = RING_PERL_INCLUDES.iter()
            .any(|i| need_run(&Path::new(i), dst.as_path()));
        if need_run(&p, dst.as_path()) || perl_include_changed {
            let mut args = vec![source.to_owned()];
            match (target_info.target_os(), target_info.target_arch()) {
                ("macos", _) => args.push("macosx".into()),
                ("ios", "arm") => args.push("ios32".into()),
                ("ios", "aarch64") => args.push("ios64".into()),
                ("linux", "x86_64") => args.push("elf".into()),
                ("linux", "x86") => {
                    args.push("elf".into());
                    args.push("-fPIC".into());
                    args.push("-DOPENSSL_IA32_SSE2".into());
                },
                ("linux", "aarch64") |
                ("android", "aarch64") => args.push("linux64".into()),
                ("linux", "arm") |
                ("android", "arm") => args.push("linux32".into()),
                ("windows", _) => panic!("Don't run this on windows"),
                (e, _) => panic!("{} is unsupported", e),
            }
            args.push(r.clone());
            run_command_with_args(&get_command("PERL_EXECUTABLE", "perl"),
                                  &args);
        }
        r
    } else {
        p.to_str().expect("Could not convert path").into()
    }
}

fn need_run(source: &Path, target: &Path) -> bool {
    let s = std::fs::metadata(source);
    let t = std::fs::metadata(target);
    if s.is_err() || t.is_err() {
        true
    } else {
        match (s.unwrap().modified(), t.unwrap().modified()) {
            (Ok(s), Ok(t)) => s >= t,
            _ => true,
        }
    }
}

fn get_command(var: &str, default: &str) -> String {
    env::var(var).unwrap_or(default.into())
}

fn check_all_files_tracked() {
    let _ = rayon::join(|| walk_dir(&PathBuf::from("crypto"), &is_tracked),
                        || walk_dir(&PathBuf::from("include"), &is_tracked));
}

fn is_tracked(file: &DirEntry) {
    let p = file.path();
    let cmp = |f| p == PathBuf::from(f);
    let tracked = match p.extension().and_then(|p| p.to_str()) {
        Some("h") => {
            RING_HEADERS.iter().chain(RING_TEST_HEADERS.iter()).any(cmp)
        },
        Some("inl") => RING_INLINE_FILES.iter().any(cmp),
        Some("c") | Some("cc") => {
            RING_SRC.iter()
                .chain(RING_AARCH64_SRCS.iter())
                .chain(RING_ARM_SHARED_SRCS.iter())
                .chain(RING_ARM_SRCS.iter())
                .chain(RING_INTEL_SHARED_SRCS.iter())
                .chain(RING_TEST_SRCS.iter())
                .chain(RING_X86_64_SRC.iter())
                .chain(RING_X86_SRCS.iter())
                .chain(RING_PPC_SRCS.iter())
                .any(cmp)
        },
        Some("S") => {
            RING_AARCH64_SRCS.iter()
                .chain(RING_ARM_SHARED_SRCS.iter())
                .chain(RING_ARM_SRCS.iter())
                .chain(RING_INTEL_SHARED_SRCS.iter())
                .chain(RING_X86_64_SRC.iter())
                .chain(RING_X86_SRCS.iter())
                .any(cmp)
        },
        Some("pl") => {
            RING_AARCH64_SRCS.iter()
                .chain(RING_ARM_SHARED_SRCS.iter())
                .chain(RING_ARM_SRCS.iter())
                .chain(RING_INTEL_SHARED_SRCS.iter())
                .chain(RING_X86_64_SRC.iter())
                .chain(RING_X86_SRCS.iter())
                .chain(RING_PPC_SRCS.iter())
                .chain(RING_PERL_INCLUDES.iter())
                .any(cmp)
        },
        _ => true,
    };
    if !tracked {
        panic!("{:?} is not tracked in build.rs", p);
    }
}

fn walk_dir<F>(dir: &Path, cb: &F)
    where F: Fn(&DirEntry)
{
    if dir.is_dir() {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                walk_dir(&path, cb);
            } else {
                cb(&entry);
            }
        }
    }
}

fn print_rerun() {
    for s in RING_ARM_SHARED_SRCS.iter()
        .chain(RING_SRC.iter())
        .chain(RING_TEST_SRCS.iter())
        .chain(RING_AARCH64_SRCS.iter())
        .chain(RING_ARM_SRCS.iter())
        .chain(RING_X86_64_SRC.iter())
        .chain(RING_X86_SRCS.iter())
        .chain(RING_INTEL_SHARED_SRCS.iter())
        .chain(RING_PPC_SRCS.iter())
        .chain(RING_HEADERS.iter())
        .chain(RING_TEST_HEADERS.iter())
        .chain(RING_PERL_INCLUDES.iter())
        .chain(RING_INLINE_FILES.iter()) {
        println!("cargo:rerun-if-changed={}", s);
    }
    println!("cargo:rerun-if-changed=build.rs");
}
