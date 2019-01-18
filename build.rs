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

//! Build the non-Rust components.

#![deny(box_pointers)]
#![forbid(
    anonymous_parameters,
    legacy_directory_ownership,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    variant_size_differences,
    warnings
)]

// In the `pregenerate_asm_main()` case we don't want to access (Cargo)
// environment variables at all, so avoid `use std::env` here.

use std::{
    fs::{self, DirEntry},
    path::{Path, PathBuf},
    process::Command,
    time::SystemTime,
};

const X86: &str = "x86";
const X86_64: &str = "x86_64";
const AARCH64: &str = "aarch64";
const ARM: &str = "arm";
const NEVER: &str = "Don't ever build this file.";

#[cfg_attr(rustfmt, rustfmt_skip)]
const RING_SRCS: &[(&[&str], &str)] = &[
    (&[], "crypto/block.c"),
    (&[], "crypto/fipsmodule/bn/generic.c"),
    (&[], "crypto/fipsmodule/bn/montgomery.c"),
    (&[], "crypto/fipsmodule/bn/montgomery_inv.c"),
    (&[], "crypto/crypto.c"),
    (&[], "crypto/fipsmodule/ec/ecp_nistz.c"),
    (&[], "crypto/fipsmodule/ec/ecp_nistz256.c"),
    (&[], "crypto/fipsmodule/ec/gfp_p256.c"),
    (&[], "crypto/fipsmodule/ec/gfp_p384.c"),
    (&[], "crypto/limbs/limbs.c"),
    (&[], "crypto/mem.c"),
    (&[], "crypto/fipsmodule/modes/gcm.c"),
    (&[], "third_party/fiat/curve25519.c"),

    (&[X86_64, X86], "crypto/cpu-intel.c"),

    (&[X86], "crypto/fipsmodule/aes/asm/aes-586.pl"),
    (&[X86], "crypto/fipsmodule/aes/asm/aesni-x86.pl"),
    (&[X86], "crypto/fipsmodule/aes/asm/vpaes-x86.pl"),
    (&[X86], "crypto/fipsmodule/bn/asm/x86-mont.pl"),
    (&[X86], "crypto/chacha/asm/chacha-x86.pl"),
    (&[X86], "crypto/fipsmodule/ec/asm/ecp_nistz256-x86.pl"),
    (&[X86], "crypto/fipsmodule/modes/asm/ghash-x86.pl"),
    (&[X86], "crypto/poly1305/asm/poly1305-x86.pl"),
    (&[X86], "crypto/fipsmodule/sha/asm/sha256-586.pl"),
    (&[X86], "crypto/fipsmodule/sha/asm/sha512-586.pl"),

    (&[X86_64], "crypto/fipsmodule/aes/asm/aes-x86_64.pl"),
    (&[X86_64], "crypto/fipsmodule/aes/asm/aesni-x86_64.pl"),
    (&[X86_64], "crypto/fipsmodule/aes/asm/vpaes-x86_64.pl"),
    (&[X86_64], "crypto/fipsmodule/bn/asm/x86_64-mont.pl"),
    (&[X86_64], "crypto/fipsmodule/bn/asm/x86_64-mont5.pl"),
    (&[X86_64], "crypto/chacha/asm/chacha-x86_64.pl"),
    (&[NEVER], "crypto/cipher_extra/asm/aes128gcmsiv-x86_64.pl"),
    (&[X86_64], "crypto/fipsmodule/ec/asm/p256-x86_64-asm.pl"),
    (&[NEVER], "crypto/fipsmodule/ec/asm/p256_beeu-x86_64-asm.pl"),
    (&[X86_64], "crypto/fipsmodule/modes/asm/aesni-gcm-x86_64.pl"),
    (&[X86_64], "crypto/fipsmodule/modes/asm/ghash-x86_64.pl"),
    (&[X86_64], "crypto/poly1305/asm/poly1305-x86_64.pl"),
    (&[X86_64], SHA512_X86_64),

    (&[AARCH64, ARM], "crypto/fipsmodule/aes/asm/aesv8-armx.pl"),
    (&[AARCH64, ARM], "crypto/fipsmodule/modes/asm/ghashv8-armx.pl"),

    (&[ARM], "crypto/fipsmodule/aes/asm/aes-armv4.pl"),
    (&[ARM], "crypto/fipsmodule/aes/asm/bsaes-armv7.pl"),
    (&[ARM], "crypto/fipsmodule/bn/asm/armv4-mont.pl"),
    (&[ARM], "crypto/chacha/asm/chacha-armv4.pl"),
    (&[ARM], "crypto/curve25519/asm/x25519-asm-arm.S"),
    (&[ARM], "crypto/fipsmodule/ec/asm/ecp_nistz256-armv4.pl"),
    (&[ARM], "crypto/fipsmodule/modes/asm/ghash-armv4.pl"),
    (&[ARM], "crypto/poly1305/asm/poly1305-armv4.pl"),
    (&[ARM], "crypto/fipsmodule/sha/asm/sha256-armv4.pl"),
    (&[ARM], "crypto/fipsmodule/sha/asm/sha512-armv4.pl"),

    (&[AARCH64], "crypto/fipsmodule/aes/aes.c"),
    (&[AARCH64], "crypto/fipsmodule/bn/asm/armv8-mont.pl"),
    (&[AARCH64], "crypto/chacha/asm/chacha-armv8.pl"),
    (&[AARCH64], "crypto/fipsmodule/ec/asm/ecp_nistz256-armv8.pl"),
    (&[AARCH64], "crypto/poly1305/asm/poly1305-armv8.pl"),
    (&[AARCH64], SHA512_ARMV8),
];

const SHA256_X86_64: &str = "crypto/fipsmodule/sha/asm/sha256-x86_64.pl";
const SHA512_X86_64: &str = "crypto/fipsmodule/sha/asm/sha512-x86_64.pl";

const SHA256_ARMV8: &str = "crypto/fipsmodule/sha/asm/sha256-armv8.pl";
const SHA512_ARMV8: &str = "crypto/fipsmodule/sha/asm/sha512-armv8.pl";

const RING_TEST_SRCS: &[&str] = &[("crypto/constant_time_test.c")];

#[cfg_attr(rustfmt, rustfmt_skip)]
const RING_INCLUDES: &[&str] =
    &["crypto/fipsmodule/bn/internal.h",
      "crypto/fipsmodule/ec/ecp_nistz256_table.inl",
      "crypto/fipsmodule/ec/ecp_nistz384.inl",
      "crypto/fipsmodule/ec/ecp_nistz.h",
      "crypto/fipsmodule/ec/ecp_nistz384.h",
      "crypto/fipsmodule/ec/ecp_nistz256.h",
      "crypto/block.h",
      "crypto/internal.h",
      "crypto/limbs/limbs.h",
      "crypto/limbs/limbs.inl",
      "crypto/fipsmodule/modes/internal.h",
      "include/GFp/aes.h",
      "include/GFp/arm_arch.h",
      "include/GFp/base.h",
      "include/GFp/cpu.h",
      "include/GFp/mem.h",
      "include/GFp/type_check.h",
      "third_party/fiat/curve25519_tables.h",
      "third_party/fiat/internal.h",
    ];

#[cfg_attr(rustfmt, rustfmt_skip)]
const RING_PERL_INCLUDES: &[&str] =
    &["crypto/perlasm/arm-xlate.pl",
      "crypto/perlasm/x86gas.pl",
      "crypto/perlasm/x86nasm.pl",
      "crypto/perlasm/x86asm.pl",
      "crypto/perlasm/x86_64-xlate.pl"];

const RING_BUILD_FILE: &[&str] = &["build.rs"];

const PREGENERATED: &'static str = "pregenerated";

fn c_flags(target: &Target) -> &'static [&'static str] {
    if target.env != MSVC {
        static NON_MSVC_FLAGS: &[&str] = &[
            "-std=c1x", // GCC 4.6 requires "c1x" instead of "c11"
            "-Wbad-function-cast",
            "-Wmissing-prototypes",
            "-Wnested-externs",
            "-Wstrict-prototypes",
        ];
        NON_MSVC_FLAGS
    } else {
        &[]
    }
}

fn cpp_flags(target: &Target) -> &'static [&'static str] {
    if target.env != MSVC {
        static NON_MSVC_FLAGS: &[&str] = &[
            "-pedantic",
            "-pedantic-errors",
            "-Wall",
            "-Wextra",
            "-Wcast-align",
            "-Wcast-qual",
            "-Wconversion",
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
            "-Wsign-conversion",
            "-Wundef",
            "-Wuninitialized",
            "-Wwrite-strings",
            "-fno-strict-aliasing",
            "-fvisibility=hidden",
        ];
        NON_MSVC_FLAGS
    } else {
        static MSVC_FLAGS: &[&str] = &[
            "/GS",   // Buffer security checks.
            "/Gy",   // Enable function-level linking.
            "/EHsc", // C++ exceptions only, only in C++.
            "/GR-",  // Disable RTTI.
            "/Zc:wchar_t",
            "/Zc:forScope",
            "/Zc:inline",
            "/Zc:rvalueCast",
            // Warnings.
            "/sdl",
            "/Wall",
            "/wd4127", // C4127: conditional expression is constant
            "/wd4464", // C4464: relative include path contains '..'
            "/wd4514", // C4514: <name>: unreferenced inline function has be
            "/wd4710", // C4710: function not inlined
            "/wd4711", // C4711: function 'function' selected for inline expansion
            "/wd4820", // C4820: <struct>: <n> bytes padding added after <name>
            "/wd5045", /* C5045: Compiler will insert Spectre mitigation for memory load if
                        * /Qspectre switch specified */
        ];
        MSVC_FLAGS
    }
}

const LD_FLAGS: &[&str] = &[];

// None means "any OS" or "any target". The first match in sequence order is
// taken.
const ASM_TARGETS: &[(&str, Option<&str>, &str)] = &[
    ("x86_64", Some("ios"), "macosx"),
    ("x86_64", Some("macos"), "macosx"),
    ("x86_64", Some(WINDOWS), "nasm"),
    ("x86_64", None, "elf"),
    ("aarch64", Some("ios"), "ios64"),
    ("aarch64", None, "linux64"),
    ("x86", Some(WINDOWS), "win32n"),
    ("x86", Some("ios"), "macosx"),
    ("x86", None, "elf"),
    ("arm", Some("ios"), "ios32"),
    ("arm", None, "linux32"),
];

const WINDOWS: &'static str = "windows";
const MSVC: &'static str = "msvc";
const MSVC_OBJ_OPT: &'static str = "/Fo";
const MSVC_OBJ_EXT: &'static str = "obj";

fn main() {
    if let Ok(package_name) = std::env::var("CARGO_PKG_NAME") {
        if package_name == "ring" {
            ring_build_rs_main();
            return;
        }
    }

    pregenerate_asm_main();
}

fn ring_build_rs_main() {
    use std::env;

    for (key, value) in env::vars() {
        println!("{}: {}", key, value);
    }

    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir = PathBuf::from(out_dir);

    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let env = env::var("CARGO_CFG_TARGET_ENV").unwrap();
    let (obj_ext, obj_opt) = if env == MSVC {
        (MSVC_OBJ_EXT, MSVC_OBJ_OPT)
    } else {
        ("o", "-o")
    };

    let is_debug = env::var("DEBUG").unwrap() != "false";
    let target = Target {
        arch,
        os,
        env,
        obj_ext,
        obj_opt,
        is_debug,
    };
    let pregenerated = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join(PREGENERATED);

    build_c_code(&target, pregenerated, &out_dir);
    check_all_files_tracked()
}

fn pregenerate_asm_main() {
    let pregenerated = PathBuf::from(PREGENERATED);
    std::fs::create_dir(&pregenerated).unwrap();
    let pregenerated_tmp = pregenerated.join("tmp");
    std::fs::create_dir(&pregenerated_tmp).unwrap();

    for &(target_arch, target_os, perlasm_format) in ASM_TARGETS {
        // For Windows, package pregenerated object files instead of
        // pregenerated assembly language source files, so that the user
        // doesn't need to install the assembler.
        let asm_dir = if target_os == Some(WINDOWS) {
            &pregenerated_tmp
        } else {
            &pregenerated
        };

        let perlasm_src_dsts = perlasm_src_dsts(&asm_dir, target_arch, target_os, perlasm_format);
        perlasm(&perlasm_src_dsts, target_arch, perlasm_format, None);

        if target_os == Some(WINDOWS) {
            //let lib_name = ring_asm_name(target_arch);
            let srcs = asm_srcs(perlasm_src_dsts);
            for src in srcs {
                let src_path = PathBuf::from(src);
                let obj_path = obj_path(&pregenerated, &src_path, MSVC_OBJ_EXT);
                run_command(yasm(&src_path, target_arch, &obj_path));
            }
        }
    }
}

struct Target {
    arch: String,
    os: String,
    env: String,
    obj_ext: &'static str,
    obj_opt: &'static str,
    is_debug: bool,
}

impl Target {
    pub fn arch(&self) -> &str { &self.arch }
    pub fn os(&self) -> &str { &self.os }
    pub fn env(&self) -> &str { &self.env }
    pub fn is_debug(&self) -> bool { self.is_debug }
}

fn build_c_code(target: &Target, pregenerated: PathBuf, out_dir: &Path) {
    let includes_modified = RING_INCLUDES
        .iter()
        .chain(RING_BUILD_FILE.iter())
        .chain(RING_PERL_INCLUDES.iter())
        .map(|f| file_modified(Path::new(*f)))
        .max()
        .unwrap();

    fn is_none_or_equals<T>(opt: Option<T>, other: T) -> bool
    where
        T: PartialEq,
    {
        if let Some(value) = opt {
            value == other
        } else {
            true
        }
    }

    let (_, _, perlasm_format) = ASM_TARGETS
        .iter()
        .find(|entry| {
            let &(entry_arch, entry_os, _) = *entry;
            entry_arch == target.arch() && is_none_or_equals(entry_os, target.os())
        })
        .unwrap();

    let is_git = std::fs::metadata(".git").is_ok();

    let use_pregenerated = !is_git;
    let warnings_are_errors = is_git;

    let asm_dir = if use_pregenerated {
        &pregenerated
    } else {
        out_dir
    };

    let perlasm_src_dsts =
        perlasm_src_dsts(asm_dir, target.arch(), Some(target.os()), perlasm_format);

    if !use_pregenerated {
        perlasm(
            &perlasm_src_dsts[..],
            target.arch(),
            perlasm_format,
            Some(includes_modified),
        );
    }

    let mut asm_srcs = asm_srcs(perlasm_src_dsts);

    // For Windows we also pregenerate the object files for non-Git builds so
    // the user doesn't need to install the assembler. On other platforms we
    // assume the C compiler also assembles.
    if use_pregenerated && target.os() == WINDOWS {
        // The pregenerated object files always use ".obj" as the extension,
        // even when the C/C++ compiler outputs files with the ".o" extension.
        asm_srcs = asm_srcs
            .iter()
            .map(|src| obj_path(&pregenerated, src.as_path(), "obj"))
            .collect::<Vec<_>>();
    }

    let core_srcs = sources_for_arch(target.arch())
        .into_iter()
        .filter(|p| !is_perlasm(&p))
        .collect::<Vec<_>>();

    let test_srcs = RING_TEST_SRCS.iter().map(PathBuf::from).collect::<Vec<_>>();

    let libs = [
        ("ring-core", &core_srcs[..], &asm_srcs[..]),
        ("ring-test", &test_srcs[..], &[]),
    ];

    // XXX: Ideally, ring-test would only be built for `cargo test`, but Cargo
    // can't do that yet.
    libs.into_iter()
        .for_each(|&(lib_name, srcs, additional_srcs)| {
            build_library(
                &target,
                &out_dir,
                lib_name,
                srcs,
                additional_srcs,
                warnings_are_errors,
                includes_modified,
            )
        });

    println!(
        "cargo:rustc-link-search=native={}",
        out_dir.to_str().expect("Invalid path")
    );
}

fn build_library(
    target: &Target, out_dir: &Path, lib_name: &str, srcs: &[PathBuf], additional_srcs: &[PathBuf],
    warnings_are_errors: bool, includes_modified: SystemTime,
) {
    // Compile all the (dirty) source files into object files.
    #[allow(box_pointers)] // XXX
    let objs = additional_srcs
        .into_iter()
        .chain(srcs.into_iter())
        .filter(|f| target.env() != "msvc" || f.extension().unwrap().to_str().unwrap() != "S")
        .map(|f| compile(f, target, warnings_are_errors, out_dir, includes_modified))
        .collect::<Vec<_>>();

    // Rebuild the library if necessary.
    let lib_path = PathBuf::from(out_dir).join(format!("lib{}.a", lib_name));

    if objs
        .iter()
        .map(Path::new)
        .any(|p| need_run(&p, &lib_path, includes_modified))
    {
        let mut c = cc::Build::new();

        for f in LD_FLAGS {
            let _ = c.flag(&f);
        }
        match target.os() {
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

        // Handled below.
        let _ = c.cargo_metadata(false);

        c.compile(
            lib_path
                .file_name()
                .and_then(|f| f.to_str())
                .expect("No filename"),
        );
    }

    // Link the library. This works even when the library doesn't need to be
    // rebuilt.
    println!("cargo:rustc-link-lib=static={}", lib_name);
}

fn compile(
    p: &Path, target: &Target, warnings_are_errors: bool, out_dir: &Path,
    includes_modified: SystemTime,
) -> String {
    let ext = p.extension().unwrap().to_str().unwrap();
    if ext == "obj" {
        p.to_str().expect("Invalid path").into()
    } else {
        let mut out_path = out_dir.clone().join(p.file_name().unwrap());
        assert!(out_path.set_extension(target.obj_ext));
        if need_run(&p, &out_path, includes_modified) {
            let cmd = if target.os() != WINDOWS || ext != "asm" {
                cc(p, ext, target, warnings_are_errors, &out_path)
            } else {
                yasm(p, target.arch(), &out_path)
            };

            run_command(cmd);
        }
        out_path.to_str().expect("Invalid path").into()
    }
}

fn obj_path(out_dir: &Path, src: &Path, obj_ext: &str) -> PathBuf {
    let mut out_path = out_dir.clone().join(src.file_name().unwrap());
    assert!(out_path.set_extension(obj_ext));
    out_path
}

fn cc(
    file: &Path, ext: &str, target: &Target, warnings_are_errors: bool, out_dir: &Path,
) -> Command {
    let mut c = cc::Build::new();
    let _ = c.include("include");
    match ext {
        "c" =>
            for f in c_flags(target) {
                let _ = c.flag(f);
            },
        "S" => (),
        e => panic!("Unsupported file extension: {:?}", e),
    };
    for f in cpp_flags(target) {
        let _ = c.flag(&f);
    }
    if target.os() != "none" && target.os() != "redox" && target.os() != "windows" {
        let _ = c.flag("-fstack-protector");
    }

    match (target.os(), target.env()) {
        // ``-gfull`` is required for Darwin's |-dead_strip|.
        ("macos", _) => {
            let _ = c.flag("-gfull");
        },
        (_, "msvc") => (),
        _ => {
            let _ = c.flag("-g3");
        },
    };
    if !target.is_debug() {
        let _ = c.define("NDEBUG", None);
    }

    if target.env() == "msvc" {
        if std::env::var("OPT_LEVEL").unwrap() == "0" {
            let _ = c.flag("/Od"); // Disable optimization for debug builds.
                                   // run-time checking: (s)tack frame, (u)ninitialized variables
            let _ = c.flag("/RTCsu");
        } else {
            let _ = c.flag("/Ox"); // Enable full optimization.
        }
    }

    if target.env() != "msvc" {
        let _ = c.define("_XOPEN_SOURCE", Some("700"));
    }

    if warnings_are_errors {
        let flag = if target.env() != "msvc" {
            "-Werror"
        } else {
            "/WX"
        };
        let _ = c.flag(flag);
    }
    if target.env() == "musl" {
        // Some platforms enable _FORTIFY_SOURCE by default, but musl
        // libc doesn't support it yet. See
        // http://wiki.musl-libc.org/wiki/Future_Ideas#Fortify
        // http://www.openwall.com/lists/musl/2015/02/04/3
        // http://www.openwall.com/lists/musl/2015/06/17/1
        let _ = c.flag("-U_FORTIFY_SOURCE");
    }

    let mut c = c.get_compiler().to_command();
    let _ = c
        .arg("-c")
        .arg(format!(
            "{}{}",
            target.obj_opt,
            out_dir.to_str().expect("Invalid path")
        ))
        .arg(file);
    c
}

fn yasm(file: &Path, arch: &str, out_file: &Path) -> Command {
    let (oformat, machine) = match arch {
        "x86_64" => ("--oformat=win64", "--machine=amd64"),
        "x86" => ("--oformat=win32", "--machine=x86"),
        _ => panic!("unsupported arch: {}", arch),
    };
    let mut c = Command::new("yasm.exe");
    let _ = c
        .arg("-X")
        .arg("vc")
        .arg("--dformat=cv8")
        .arg(oformat)
        .arg(machine)
        .arg("-o")
        .arg(out_file.to_str().expect("Invalid path"))
        .arg(file);
    c
}

fn run_command_with_args<S>(command_name: S, args: &[String])
where
    S: AsRef<std::ffi::OsStr> + Copy,
{
    let mut cmd = Command::new(command_name);
    let _ = cmd.args(args);
    run_command(cmd)
}

fn run_command(mut cmd: Command) {
    println!("running {:?}", cmd);
    let status = cmd.status().unwrap_or_else(|e| {
        panic!("failed to execute [{:?}]: {}", cmd, e);
    });
    if !status.success() {
        panic!("execution failed");
    }
}

fn sources_for_arch(arch: &str) -> Vec<PathBuf> {
    RING_SRCS
        .iter()
        .filter(|&&(archs, _)| archs.is_empty() || archs.contains(&arch))
        .map(|&(_, p)| PathBuf::from(p))
        .collect::<Vec<_>>()
}

fn perlasm_src_dsts(
    out_dir: &Path, arch: &str, os: Option<&str>, perlasm_format: &str,
) -> Vec<(PathBuf, PathBuf)> {
    let srcs = sources_for_arch(arch);
    let mut src_dsts = srcs
        .iter()
        .filter(|p| is_perlasm(p))
        .map(|src| (src.clone(), asm_path(out_dir, src, os, perlasm_format)))
        .collect::<Vec<_>>();

    // Some PerlAsm source files need to be run multiple times with different
    // output paths.
    {
        // Appease the borrow checker.
        let mut maybe_synthesize = |concrete, synthesized| {
            let concrete_path = PathBuf::from(concrete);
            if srcs.contains(&concrete_path) {
                let synthesized_path = PathBuf::from(synthesized);
                src_dsts.push((
                    concrete_path,
                    asm_path(out_dir, &synthesized_path, os, perlasm_format),
                ))
            }
        };
        maybe_synthesize(SHA512_X86_64, SHA256_X86_64);
        maybe_synthesize(SHA512_ARMV8, SHA256_ARMV8);
    }

    src_dsts
}

fn asm_srcs(perlasm_src_dsts: Vec<(PathBuf, PathBuf)>) -> Vec<PathBuf> {
    perlasm_src_dsts
        .into_iter()
        .map(|(_src, dst)| dst)
        .collect::<Vec<_>>()
}

fn is_perlasm(path: &PathBuf) -> bool { path.extension().unwrap().to_str().unwrap() == "pl" }

fn asm_path(out_dir: &Path, src: &Path, os: Option<&str>, perlasm_format: &str) -> PathBuf {
    let src_stem = src.file_stem().expect("source file without basename");

    let dst_stem = src_stem.to_str().unwrap();
    let dst_extension = if os == Some("windows") { "asm" } else { "S" };
    let dst_filename = format!("{}-{}.{}", dst_stem, perlasm_format, dst_extension);
    out_dir.join(dst_filename)
}

fn perlasm(
    src_dst: &[(PathBuf, PathBuf)], arch: &str, perlasm_format: &str,
    includes_modified: Option<SystemTime>,
) {
    for (src, dst) in src_dst {
        if let Some(includes_modified) = includes_modified {
            if !need_run(src, dst, includes_modified) {
                continue;
            }
        }

        let mut args = Vec::<String>::new();
        args.push(src.to_string_lossy().into_owned());
        args.push(perlasm_format.to_owned());
        if arch == "x86" {
            args.push("-fPIC".into());
            args.push("-DOPENSSL_IA32_SSE2".into());
        }
        // Work around PerlAsm issue for ARM and AAarch64 targets by replacing
        // back slashes with forward slashes.
        let dst = dst
            .to_str()
            .expect("Could not convert path")
            .replace("\\", "/");
        args.push(dst);
        run_command_with_args(&get_command("PERL_EXECUTABLE", "perl"), &args);
    }
}

fn need_run(source: &Path, target: &Path, includes_modified: SystemTime) -> bool {
    let s_modified = file_modified(source);
    if let Ok(target_metadata) = std::fs::metadata(target) {
        let target_modified = target_metadata.modified().unwrap();
        s_modified >= target_modified || includes_modified >= target_modified
    } else {
        // On error fetching metadata for the target file, assume the target
        // doesn't exist.
        true
    }
}

fn file_modified(path: &Path) -> SystemTime {
    let path = Path::new(path);
    let path_as_str = format!("{:?}", path);
    std::fs::metadata(path)
        .expect(&path_as_str)
        .modified()
        .expect("nah")
}

fn get_command(var: &str, default: &str) -> String { std::env::var(var).unwrap_or(default.into()) }

fn check_all_files_tracked() {
    for path in &["crypto", "include", "third_party/fiat"] {
        walk_dir(&PathBuf::from(path), &is_tracked);
    }
}

fn is_tracked(file: &DirEntry) {
    let p = file.path();
    let cmp = |f| p == PathBuf::from(f);
    let tracked = match p.extension().and_then(|p| p.to_str()) {
        Some("h") | Some("inl") => RING_INCLUDES.iter().any(cmp),
        Some("c") | Some("S") | Some("asm") =>
            RING_SRCS.iter().any(|(_, f)| cmp(f)) || RING_TEST_SRCS.iter().any(cmp),
        Some("pl") => RING_SRCS.iter().any(|(_, f)| cmp(f)) || RING_PERL_INCLUDES.iter().any(cmp),
        _ => true,
    };
    if !tracked {
        panic!("{:?} is not tracked in build.rs", p);
    }
}

fn walk_dir<F>(dir: &Path, cb: &F)
where
    F: Fn(&DirEntry),
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
