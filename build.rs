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

// It seems like it would be a good idea to use `log!` for logging, but it
// isn't worth having the external dependencies (one for the `log` crate, and
// another for the concrete logging implementation). Instead we use `eprintln!`
// to log everything to stderr.

use std::{
    fs::{self, DirEntry},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

const X86: &str = "x86";
const X86_64: &str = "x86_64";
const AARCH64: &str = "aarch64";
const ARM: &str = "arm";

#[rustfmt::skip]
const RING_SRCS: &[(&[&str], &str)] = &[
    (&[], "crypto/curve25519/curve25519.c"),
    (&[], "crypto/fipsmodule/aes/aes_nohw.c"),
    (&[], "crypto/fipsmodule/bn/montgomery.c"),
    (&[], "crypto/fipsmodule/bn/montgomery_inv.c"),
    (&[], "crypto/fipsmodule/rsa/padding.c"),
    (&[], "crypto/limbs/limbs.c"),
    (&[], "crypto/mem.c"),
    (&[], "crypto/poly1305/poly1305.c"),

    (&[AARCH64, ARM, X86_64, X86], "crypto/crypto.c"),
    (&[AARCH64, ARM, X86_64, X86], "crypto/fipsmodule/ec/ecp_nistz.c"),
    (&[AARCH64, ARM, X86_64, X86], "crypto/fipsmodule/ec/gfp_p256.c"),
    (&[AARCH64, ARM, X86_64, X86], "crypto/fipsmodule/ec/gfp_p384.c"),
    (&[AARCH64, ARM, X86_64, X86], "crypto/fipsmodule/ec/p256.c"),

    (&[X86_64, X86], "crypto/cpu-intel.c"),

    (&[X86], "crypto/fipsmodule/aes/asm/aesni-x86.pl"),
    (&[X86], "crypto/fipsmodule/aes/asm/vpaes-x86.pl"),
    (&[X86], "crypto/fipsmodule/bn/asm/x86-mont.pl"),
    (&[X86], "crypto/chacha/asm/chacha-x86.pl"),
    (&[X86], "crypto/fipsmodule/modes/asm/ghash-x86.pl"),

    (&[X86_64], "crypto/chacha/asm/chacha-x86_64.pl"),
    (&[X86_64], "crypto/fipsmodule/aes/asm/aesni-x86_64.pl"),
    (&[X86_64], "crypto/fipsmodule/aes/asm/vpaes-x86_64.pl"),
    (&[X86_64], "crypto/fipsmodule/bn/asm/x86_64-mont.pl"),
    (&[X86_64], "crypto/fipsmodule/bn/asm/x86_64-mont5.pl"),
    (&[X86_64], "crypto/fipsmodule/ec/p256-x86_64.c"),
    (&[X86_64], "crypto/fipsmodule/ec/asm/p256-x86_64-asm.pl"),
    (&[X86_64], "crypto/fipsmodule/modes/asm/aesni-gcm-x86_64.pl"),
    (&[X86_64], "crypto/fipsmodule/modes/asm/ghash-x86_64.pl"),
    (&[X86_64], "crypto/poly1305/poly1305_vec.c"),
    (&[X86_64], SHA512_X86_64),
    (&[X86_64], "crypto/cipher_extra/asm/chacha20_poly1305_x86_64.pl"),

    (&[AARCH64, ARM], "crypto/fipsmodule/aes/asm/aesv8-armx.pl"),
    (&[AARCH64, ARM], "crypto/fipsmodule/modes/asm/ghashv8-armx.pl"),

    (&[ARM], "crypto/fipsmodule/aes/asm/bsaes-armv7.pl"),
    (&[ARM], "crypto/fipsmodule/aes/asm/vpaes-armv7.pl"),
    (&[ARM], "crypto/fipsmodule/bn/asm/armv4-mont.pl"),
    (&[ARM], "crypto/chacha/asm/chacha-armv4.pl"),
    (&[ARM], "crypto/curve25519/asm/x25519-asm-arm.S"),
    (&[ARM], "crypto/fipsmodule/modes/asm/ghash-armv4.pl"),
    (&[ARM], "crypto/poly1305/poly1305_arm.c"),
    (&[ARM], "crypto/poly1305/poly1305_arm_asm.S"),
    (&[ARM], "crypto/fipsmodule/sha/asm/sha256-armv4.pl"),
    (&[ARM], "crypto/fipsmodule/sha/asm/sha512-armv4.pl"),

    (&[AARCH64], "crypto/fipsmodule/aes/asm/vpaes-armv8.pl"),
    (&[AARCH64], "crypto/fipsmodule/bn/asm/armv8-mont.pl"),
    (&[AARCH64], "crypto/chacha/asm/chacha-armv8.pl"),
    (&[AARCH64], "crypto/fipsmodule/modes/asm/ghash-neon-armv8.pl"),
    (&[AARCH64], SHA512_ARMV8),
];

const SHA256_X86_64: &str = "crypto/fipsmodule/sha/asm/sha256-x86_64.pl";
const SHA512_X86_64: &str = "crypto/fipsmodule/sha/asm/sha512-x86_64.pl";

const SHA256_ARMV8: &str = "crypto/fipsmodule/sha/asm/sha256-armv8.pl";
const SHA512_ARMV8: &str = "crypto/fipsmodule/sha/asm/sha512-armv8.pl";

const RING_TEST_SRCS: &[&str] = &[("crypto/constant_time_test.c")];

const PREGENERATED: &str = "pregenerated";

fn c_flags(target: &Target) -> &'static [&'static str] {
    if target.env != MSVC {
        static NON_MSVC_FLAGS: &[&str] = &[
            "-std=c1x", // GCC 4.6 requires "c1x" instead of "c11"
            "-Wbad-function-cast",
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
const ASM_TARGETS: &[AsmTarget] = &[
    AsmTarget {
        oss: LINUX_ABI,
        arch: "aarch64",
        perlasm_format: "linux64",
        asm_extension: "S",
        preassemble: false,
    },
    AsmTarget {
        oss: LINUX_ABI,
        arch: "arm",
        perlasm_format: "linux32",
        asm_extension: "S",
        preassemble: false,
    },
    AsmTarget {
        oss: LINUX_ABI,
        arch: "x86",
        perlasm_format: "elf",
        asm_extension: "S",
        preassemble: false,
    },
    AsmTarget {
        oss: LINUX_ABI,
        arch: "x86_64",
        perlasm_format: "elf",
        asm_extension: "S",
        preassemble: false,
    },
    AsmTarget {
        oss: MACOS_ABI,
        arch: "aarch64",
        perlasm_format: "ios64",
        asm_extension: "S",
        preassemble: false,
    },
    AsmTarget {
        oss: MACOS_ABI,
        arch: "x86_64",
        perlasm_format: "macosx",
        asm_extension: "S",
        preassemble: false,
    },
    AsmTarget {
        oss: &[WINDOWS],
        arch: "x86",
        perlasm_format: "win32n",
        asm_extension: "asm",
        preassemble: true,
    },
    AsmTarget {
        oss: &[WINDOWS],
        arch: "x86_64",
        perlasm_format: "nasm",
        asm_extension: "asm",
        preassemble: true,
    },
];

struct AsmTarget {
    /// Operating systems.
    oss: &'static [&'static str],

    /// Architectures.
    arch: &'static str,

    /// The PerlAsm format name.
    perlasm_format: &'static str,

    /// The filename extension for assembly files.
    asm_extension: &'static str,

    /// Whether pre-assembled object files should be included in the Cargo
    /// package instead of the asm sources. This way, the user doesn't need
    /// to install an assembler for the target. This is particularly important
    /// for x86/x86_64 Windows since an assembler doesn't come with the C
    /// compiler.
    preassemble: bool,
}

/// Operating systems that have the same ABI as Linux on every architecture
/// mentioned in `ASM_TARGETS`.
const LINUX_ABI: &[&str] = &[
    "android",
    "dragonfly",
    "freebsd",
    "fuchsia",
    "illumos",
    "netbsd",
    "openbsd",
    "linux",
    "solaris",
];

/// Operating systems that have the same ABI as macOS on every architecture
/// mentioned in `ASM_TARGETS`.
const MACOS_ABI: &[&str] = &["ios", "macos"];

const WINDOWS: &str = "windows";

const MSVC: &str = "msvc";
const MSVC_OBJ_OPT: &str = "/Fo";
const MSVC_OBJ_EXT: &str = "obj";

/// Read an environment variable and tell Cargo that we depend on it.
///
/// This needs to be used for any environment variable that isn't a standard
/// Cargo-supplied variable.
///
/// The name is static since we intend to only read a static set of environment
/// variables.
fn read_env_var(name: &'static str) -> Result<String, std::env::VarError> {
    println!("cargo:rerun-if-env-changed={}", name);
    std::env::var(name)
}

fn main() {
    const RING_PREGENERATE_ASM: &str = "RING_PREGENERATE_ASM";
    match read_env_var(RING_PREGENERATE_ASM).as_deref() {
        Ok("1") => {
            pregenerate_asm_main();
        }
        Err(std::env::VarError::NotPresent) => ring_build_rs_main(),
        _ => {
            panic!("${} has an invalid value", RING_PREGENERATE_ASM);
        }
    }
}

fn ring_build_rs_main() {
    use std::env;

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

    let is_git = std::fs::metadata(".git").is_ok();

    // Published builds are always release builds.
    let is_debug = is_git && env::var("DEBUG").unwrap() != "false";

    let target = Target {
        arch,
        os,
        env,
        obj_ext,
        obj_opt,
        is_git,
        is_debug,
    };
    let pregenerated = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join(PREGENERATED);

    build_c_code(&target, pregenerated, &out_dir, &ring_core_prefix());
    emit_rerun_if_changed()
}

fn pregenerate_asm_main() {
    println!("cargo:rustc-cfg=pregenerate_asm_only");

    let pregenerated = PathBuf::from(PREGENERATED);
    std::fs::create_dir(&pregenerated).unwrap();
    let pregenerated_tmp = pregenerated.join("tmp");
    std::fs::create_dir(&pregenerated_tmp).unwrap();

    let mut generated_prefix_headers = false;

    for asm_target in ASM_TARGETS {
        // For Windows, package pregenerated object files instead of
        // pregenerated assembly language source files, so that the user
        // doesn't need to install the assembler.
        let asm_dir = if asm_target.preassemble {
            &pregenerated_tmp
        } else {
            &pregenerated
        };

        let perlasm_src_dsts = perlasm_src_dsts(&asm_dir, asm_target);
        perlasm(&perlasm_src_dsts, asm_target);

        if asm_target.preassemble {
            if !std::mem::replace(&mut generated_prefix_headers, true) {
                generate_prefix_symbols_nasm(&pregenerated, &ring_core_prefix()).unwrap();
            }
            let srcs = asm_srcs(perlasm_src_dsts);
            for src in srcs {
                let obj_path = obj_path(&pregenerated, &src, MSVC_OBJ_EXT);
                run_command(nasm(&src, asm_target.arch, &obj_path, &pregenerated));
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
    is_git: bool,
    is_debug: bool,
}

fn build_c_code(target: &Target, pregenerated: PathBuf, out_dir: &Path, ring_core_prefix: &str) {
    println!("cargo:rustc-env=RING_CORE_PREFIX={}", ring_core_prefix);

    #[cfg(not(feature = "wasm32_c"))]
    {
        if &target.arch == "wasm32" {
            return;
        }
    }

    let asm_target = ASM_TARGETS.iter().find(|asm_target| {
        asm_target.arch == target.arch && asm_target.oss.contains(&target.os.as_ref())
    });

    let use_pregenerated = !target.is_git;
    let warnings_are_errors = target.is_git;

    let asm_dir = if use_pregenerated {
        &pregenerated
    } else {
        out_dir
    };

    generate_prefix_symbols(target, out_dir, ring_core_prefix).unwrap();

    let asm_srcs = if let Some(asm_target) = asm_target {
        let perlasm_src_dsts = perlasm_src_dsts(asm_dir, asm_target);

        if !use_pregenerated {
            perlasm(&perlasm_src_dsts[..], asm_target);
        }

        let mut asm_srcs = asm_srcs(perlasm_src_dsts);

        // For Windows we also pregenerate the object files for non-Git builds so
        // the user doesn't need to install the assembler. On other platforms we
        // assume the C compiler also assembles.
        if use_pregenerated && target.os == WINDOWS {
            // The pregenerated object files always use ".obj" as the extension,
            // even when the C/C++ compiler outputs files with the ".o" extension.
            asm_srcs = asm_srcs
                .iter()
                .map(|src| obj_path(&pregenerated, src.as_path(), "obj"))
                .collect::<Vec<_>>();
        }

        asm_srcs
    } else {
        Vec::new()
    };

    let core_srcs = sources_for_arch(&target.arch)
        .into_iter()
        .filter(|p| !is_perlasm(&p))
        .collect::<Vec<_>>();

    let test_srcs = RING_TEST_SRCS.iter().map(PathBuf::from).collect::<Vec<_>>();

    let libs = [
        ("", &core_srcs[..], &asm_srcs[..]),
        ("test", &test_srcs[..], &[]),
    ];

    // XXX: Ideally, ring-test would only be built for `cargo test`, but Cargo
    // can't do that yet.
    libs.iter()
        .for_each(|&(lib_name_suffix, srcs, additional_srcs)| {
            let lib_name = String::from(ring_core_prefix) + lib_name_suffix;
            build_library(
                &target,
                &out_dir,
                &lib_name,
                srcs,
                additional_srcs,
                warnings_are_errors,
            )
        });

    println!(
        "cargo:rustc-link-search=native={}",
        out_dir.to_str().expect("Invalid path")
    );
}

fn build_library(
    target: &Target,
    out_dir: &Path,
    lib_name: &str,
    srcs: &[PathBuf],
    additional_srcs: &[PathBuf],
    warnings_are_errors: bool,
) {
    // Compile all the (dirty) source files into object files.
    let objs = additional_srcs
        .iter()
        .chain(srcs.iter())
        .filter(|f| &target.env != "msvc" || f.extension().unwrap().to_str().unwrap() != "S")
        .map(|f| compile(f, target, warnings_are_errors, out_dir))
        .collect::<Vec<_>>();

    // Rebuild the library if necessary.
    let lib_path = PathBuf::from(out_dir).join(format!("lib{}.a", lib_name));

    let mut c = cc::Build::new();

    for f in LD_FLAGS {
        let _ = c.flag(&f);
    }
    match target.os.as_str() {
        "macos" => {
            let _ = c.flag("-fPIC");
            let _ = c.flag("-Wl,-dead_strip");
        }
        _ => {
            let _ = c.flag("-Wl,--gc-sections");
        }
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

    // Link the library. This works even when the library doesn't need to be
    // rebuilt.
    println!("cargo:rustc-link-lib=static={}", lib_name);
}

fn compile(p: &Path, target: &Target, warnings_are_errors: bool, out_dir: &Path) -> String {
    let ext = p.extension().unwrap().to_str().unwrap();
    if ext == "obj" {
        p.to_str().expect("Invalid path").into()
    } else {
        let mut out_path = out_dir.join(p.file_name().unwrap());
        assert!(out_path.set_extension(target.obj_ext));
        let cmd = if target.os != WINDOWS || ext != "asm" {
            cc(p, ext, target, warnings_are_errors, &out_path, out_dir)
        } else {
            nasm(p, &target.arch, &out_path, out_dir)
        };

        run_command(cmd);
        out_path.to_str().expect("Invalid path").into()
    }
}

fn obj_path(out_dir: &Path, src: &Path, obj_ext: &str) -> PathBuf {
    let mut out_path = out_dir.join(src.file_name().unwrap());
    assert!(out_path.set_extension(obj_ext));
    out_path
}

fn cc(
    file: &Path,
    ext: &str,
    target: &Target,
    warnings_are_errors: bool,
    out_path: &Path,
    include_dir: &Path,
) -> Command {
    let is_musl = target.env.starts_with("musl");

    let mut c = cc::Build::new();
    let _ = c.include("include");
    let _ = c.include(include_dir);
    match ext {
        "c" => {
            for f in c_flags(target) {
                let _ = c.flag(f);
            }
        }
        "S" => (),
        e => panic!("Unsupported file extension: {:?}", e),
    };
    for f in cpp_flags(target) {
        let _ = c.flag(&f);
    }
    if target.os != "none"
        && target.os != "redox"
        && target.os != "windows"
        && target.arch != "wasm32"
    {
        let _ = c.flag("-fstack-protector");
    }

    match (target.os.as_str(), target.env.as_str()) {
        // ``-gfull`` is required for Darwin's |-dead_strip|.
        ("macos", _) => {
            let _ = c.flag("-gfull");
        }
        (_, "msvc") => (),
        _ => {
            let _ = c.flag("-g3");
        }
    };
    if !target.is_debug {
        let _ = c.define("NDEBUG", None);
    }

    if &target.env == "msvc" {
        if std::env::var("OPT_LEVEL").unwrap() == "0" {
            let _ = c.flag("/Od"); // Disable optimization for debug builds.
                                   // run-time checking: (s)tack frame, (u)ninitialized variables
            let _ = c.flag("/RTCsu");
        } else {
            let _ = c.flag("/Ox"); // Enable full optimization.
        }
    }

    // Allow cross-compiling without a target sysroot for these targets.
    //
    // poly1305_vec.c requires <emmintrin.h> which requires <stdlib.h>.
    if (target.arch == "wasm32" && target.os == "unknown")
        || (target.os == "linux" && is_musl && target.arch != "x86_64")
    {
        if let Ok(compiler) = c.try_get_compiler() {
            // TODO: Expand this to non-clang compilers in 0.17.0 if practical.
            if compiler.is_like_clang() {
                let _ = c.flag("-nostdlibinc");
                let _ = c.define("RING_CORE_NOSTDLIBINC", "1");
            }
        }
    }

    if warnings_are_errors {
        let flag = if &target.env != "msvc" {
            "-Werror"
        } else {
            "/WX"
        };
        let _ = c.flag(flag);
    }
    if is_musl {
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
            out_path.to_str().expect("Invalid path")
        ))
        .arg(file);
    c
}

fn nasm(file: &Path, arch: &str, out_file: &Path, include_dir: &Path) -> Command {
    let oformat = match arch {
        "x86_64" => ("win64"),
        "x86" => ("win32"),
        _ => panic!("unsupported arch: {}", arch),
    };

    // Nasm requires that the path end in a path separator.
    let mut include_dir = include_dir.as_os_str().to_os_string();
    include_dir.push(std::ffi::OsString::from(String::from(
        std::path::MAIN_SEPARATOR,
    )));

    let mut c = Command::new("./target/tools/windows/nasm/nasm");
    let _ = c
        .arg("-o")
        .arg(out_file.to_str().expect("Invalid path"))
        .arg("-f")
        .arg(oformat)
        .arg("-i")
        .arg("include/")
        .arg("-i")
        .arg(include_dir)
        .arg("-Xgnu")
        .arg("-gcv8")
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
    eprintln!("running {:?}", cmd);
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

fn perlasm_src_dsts(out_dir: &Path, asm_target: &AsmTarget) -> Vec<(PathBuf, PathBuf)> {
    let srcs = sources_for_arch(asm_target.arch);
    let mut src_dsts = srcs
        .iter()
        .filter(|p| is_perlasm(p))
        .map(|src| (src.clone(), asm_path(out_dir, src, asm_target)))
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
                    asm_path(out_dir, &synthesized_path, asm_target),
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

fn is_perlasm(path: &PathBuf) -> bool {
    path.extension().unwrap().to_str().unwrap() == "pl"
}

fn asm_path(out_dir: &Path, src: &Path, asm_target: &AsmTarget) -> PathBuf {
    let src_stem = src.file_stem().expect("source file without basename");

    let dst_stem = src_stem.to_str().unwrap();
    let dst_filename = format!(
        "{}-{}.{}",
        dst_stem, asm_target.perlasm_format, asm_target.asm_extension
    );
    out_dir.join(dst_filename)
}

fn perlasm(src_dst: &[(PathBuf, PathBuf)], asm_target: &AsmTarget) {
    for (src, dst) in src_dst {
        let mut args = Vec::<String>::new();
        args.push(src.to_string_lossy().into_owned());
        args.push(asm_target.perlasm_format.to_owned());
        if asm_target.arch == "x86" {
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

fn get_command(var: &'static str, default: &str) -> String {
    read_env_var(var).unwrap_or_else(|_| default.into())
}

// TODO: We should emit `cargo:rerun-if-changed-env` for the various
// environment variables that affect the build.
fn emit_rerun_if_changed() {
    for path in &["crypto", "include", "third_party/fiat"] {
        walk_dir(&PathBuf::from(path), &|entry| {
            let path = entry.path();
            match path.extension().and_then(|ext| ext.to_str()) {
                Some("c") | Some("S") | Some("h") | Some("inl") | Some("pl") | None => {
                    println!("cargo:rerun-if-changed={}", path.to_str().unwrap());
                }
                _ => {
                    // Ignore other types of files.
                }
            }
        })
    }
}

fn walk_dir(dir: &Path, cb: &impl Fn(&DirEntry)) {
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

fn ring_core_prefix() -> String {
    let links = std::env::var("CARGO_MANIFEST_LINKS").unwrap();

    let computed = {
        let name = std::env::var("CARGO_PKG_NAME").unwrap();
        let version = std::env::var("CARGO_PKG_VERSION").unwrap();
        name + "_core_" + &version.replace(&['-', '.'][..], "_")
    };

    assert_eq!(links, computed);

    links + "_"
}

/// Creates the necessary header file for symbol renaming and returns the path of the
/// generated include directory.
fn generate_prefix_symbols(
    target: &Target,
    out_dir: &Path,
    prefix: &str,
) -> Result<(), std::io::Error> {
    generate_prefix_symbols_header(out_dir, "prefix_symbols.h", '#', None, prefix)?;

    if target.os == "windows" {
        let _ = generate_prefix_symbols_nasm(out_dir, prefix)?;
    } else {
        generate_prefix_symbols_header(
            out_dir,
            "prefix_symbols_asm.h",
            '#',
            Some("#if defined(__APPLE__)"),
            prefix,
        )?;
    }

    Ok(())
}

fn generate_prefix_symbols_nasm(out_dir: &Path, prefix: &str) -> Result<(), std::io::Error> {
    generate_prefix_symbols_header(
        out_dir,
        "prefix_symbols_nasm.inc",
        '%',
        Some("%ifidn __OUTPUT_FORMAT__,win32"),
        prefix,
    )
}

fn generate_prefix_symbols_header(
    out_dir: &Path,
    filename: &str,
    pp: char,
    prefix_condition: Option<&str>,
    prefix: &str,
) -> Result<(), std::io::Error> {
    let dir = out_dir.join("ring_core_generated");
    std::fs::create_dir_all(&dir)?;

    let path = dir.join(filename);
    let mut file = std::fs::File::create(&path)?;

    let filename_ident = filename.replace(".", "_").to_uppercase();
    writeln!(
        file,
        r#"
{pp}ifndef ring_core_generated_{filename_ident}
{pp}define ring_core_generated_{filename_ident}
"#,
        pp = pp,
        filename_ident = filename_ident
    )?;

    if let Some(prefix_condition) = prefix_condition {
        writeln!(file, "{}", prefix_condition)?;
        writeln!(file, "{}", prefix_all_symbols(pp, "_", prefix))?;
        writeln!(file, "{pp}else", pp = pp)?;
    };
    writeln!(file, "{}", prefix_all_symbols(pp, "", prefix))?;
    if prefix_condition.is_some() {
        writeln!(file, "{pp}endif", pp = pp)?
    }

    writeln!(file, "{pp}endif", pp = pp)?;

    Ok(())
}

fn prefix_all_symbols(pp: char, prefix_prefix: &str, prefix: &str) -> String {
    static SYMBOLS_TO_PREFIX: &[&str] = &[
        "CRYPTO_poly1305_finish",
        "CRYPTO_poly1305_finish_neon",
        "CRYPTO_poly1305_init",
        "CRYPTO_poly1305_init_neon",
        "CRYPTO_poly1305_update",
        "CRYPTO_poly1305_update_neon",
        "ChaCha20_ctr32",
        "LIMBS_add_mod",
        "LIMBS_are_even",
        "LIMBS_are_zero",
        "LIMBS_equal",
        "LIMBS_equal_limb",
        "LIMBS_less_than",
        "LIMBS_less_than_limb",
        "LIMBS_reduce_once",
        "LIMBS_select_512_32",
        "LIMBS_shl_mod",
        "LIMBS_sub_mod",
        "LIMBS_window5_split_window",
        "LIMBS_window5_unsplit_window",
        "LIMB_shr",
        "OPENSSL_armcap_P",
        "OPENSSL_cpuid_setup",
        "OPENSSL_ia32cap_P",
        "OPENSSL_memcmp",
        "RSA_padding_check_oaep",
        "aes_hw_ctr32_encrypt_blocks",
        "aes_hw_encrypt",
        "aes_hw_set_encrypt_key",
        "aes_nohw_ctr32_encrypt_blocks",
        "aes_nohw_encrypt",
        "aes_nohw_set_encrypt_key",
        "aesni_gcm_decrypt",
        "aesni_gcm_encrypt",
        "bn_from_montgomery",
        "bn_from_montgomery_in_place",
        "bn_gather5",
        "bn_mul_mont",
        "bn_mul_mont_gather5",
        "bn_neg_inv_mod_r_u64",
        "bn_power5",
        "bn_scatter5",
        "bn_sqr8x_internal",
        "bn_sqrx8x_internal",
        "bsaes_ctr32_encrypt_blocks",
        "bssl_constant_time_test_main",
        "chacha20_poly1305_open",
        "chacha20_poly1305_seal",
        "gcm_ghash_avx",
        "gcm_ghash_clmul",
        "gcm_ghash_neon",
        "gcm_gmult_clmul",
        "gcm_gmult_neon",
        "gcm_init_avx",
        "gcm_init_clmul",
        "gcm_init_neon",
        "limbs_mul_add_limb",
        "little_endian_bytes_from_scalar",
        "nistz256_neg",
        "nistz256_select_w5",
        "nistz256_select_w7",
        "nistz384_point_add",
        "nistz384_point_double",
        "nistz384_point_mul",
        "p256_mul_mont",
        "p256_point_add",
        "p256_point_add_affine",
        "p256_point_double",
        "p256_point_mul",
        "p256_point_mul_base",
        "p256_scalar_mul_mont",
        "p256_scalar_sqr_rep_mont",
        "p256_sqr_mont",
        "p384_elem_div_by_2",
        "p384_elem_mul_mont",
        "p384_elem_neg",
        "p384_elem_sub",
        "p384_scalar_mul_mont",
        "poly1305_neon2_addmulmod",
        "poly1305_neon2_blocks",
        "sha256_block_data_order",
        "sha512_block_data_order",
        "vpaes_ctr32_encrypt_blocks",
        "vpaes_encrypt",
        "vpaes_encrypt_key_to_bsaes",
        "vpaes_set_encrypt_key",
        "x25519_NEON",
        "x25519_fe_invert",
        "x25519_fe_isnegative",
        "x25519_fe_mul_ttt",
        "x25519_fe_neg",
        "x25519_fe_tobytes",
        "x25519_ge_double_scalarmult_vartime",
        "x25519_ge_frombytes_vartime",
        "x25519_ge_scalarmult_base",
        "x25519_public_from_private_generic_masked",
        "x25519_sc_mask",
        "x25519_sc_muladd",
        "x25519_sc_reduce",
        "x25519_scalar_mult_generic_masked",
    ];

    let mut out = String::new();

    for symbol in SYMBOLS_TO_PREFIX {
        let line = format!(
            "{pp}define {prefix_prefix}{symbol} {prefix_prefix}{prefix}{symbol}\n",
            pp = pp,
            prefix_prefix = prefix_prefix,
            prefix = prefix,
            symbol = symbol
        );
        out += &line;
    }

    out
}
