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
    ffi::{OsStr, OsString},
    fs::{self, DirEntry},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

const X86: &str = "x86";
const X86_64: &str = "x86_64";
const AARCH64: &str = "aarch64";
const ARM: &str = "arm";
const WASM32: &str = "wasm32";

#[rustfmt::skip]
const RING_SRCS: &[(&[&str], &str)] = &[
    (&[], "crypto/curve25519/curve25519.c"),
    (&[], "crypto/fipsmodule/aes/aes_nohw.c"),
    (&[], "crypto/fipsmodule/bn/montgomery.c"),
    (&[], "crypto/fipsmodule/bn/montgomery_inv.c"),
    (&[], "crypto/fipsmodule/ec/ecp_nistz.c"),
    (&[], "crypto/fipsmodule/ec/gfp_p256.c"),
    (&[], "crypto/fipsmodule/ec/gfp_p384.c"),
    (&[], "crypto/fipsmodule/ec/p256.c"),
    (&[], "crypto/limbs/limbs.c"),
    (&[], "crypto/mem.c"),
    (&[], "crypto/poly1305/poly1305.c"),

    (&[AARCH64, ARM, X86_64, X86], "crypto/crypto.c"),

    (&[X86_64, X86], "crypto/cpu_intel.c"),

    (&[X86], "crypto/fipsmodule/aes/asm/aesni-x86.pl"),
    (&[X86], "crypto/fipsmodule/aes/asm/vpaes-x86.pl"),
    (&[X86], "crypto/fipsmodule/bn/asm/x86-mont.pl"),
    (&[X86], "crypto/chacha/asm/chacha-x86.pl"),
    (&[X86], "crypto/fipsmodule/modes/asm/ghash-x86.pl"),

    (&[X86_64], "crypto/chacha/asm/chacha-x86_64.pl"),
    (&[X86_64], "crypto/curve25519/curve25519_64_adx.c"),
    (&[X86_64], "crypto/fipsmodule/aes/asm/aesni-x86_64.pl"),
    (&[X86_64], "crypto/fipsmodule/aes/asm/vpaes-x86_64.pl"),
    (&[X86_64], "crypto/fipsmodule/bn/asm/x86_64-mont.pl"),
    (&[X86_64], "crypto/fipsmodule/bn/asm/x86_64-mont5.pl"),
    (&[X86_64], "crypto/fipsmodule/ec/asm/p256-x86_64-asm.pl"),
    (&[X86_64], "crypto/fipsmodule/modes/asm/aesni-gcm-x86_64.pl"),
    (&[X86_64], "crypto/fipsmodule/modes/asm/ghash-x86_64.pl"),
    (&[X86_64], "crypto/poly1305/poly1305_vec.c"),
    (&[X86_64], SHA512_X86_64),
    (&[X86_64], "crypto/cipher_extra/asm/chacha20_poly1305_x86_64.pl"),
    (&[X86_64], "third_party/fiat/asm/fiat_curve25519_adx_mul.S"),
    (&[X86_64], "third_party/fiat/asm/fiat_curve25519_adx_square.S"),

    (&[AARCH64, X86_64], "crypto/fipsmodule/ec/p256-nistz.c"),

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

    (&[AARCH64], "crypto/chacha/asm/chacha-armv8.pl"),
    (&[AARCH64], "crypto/cipher_extra/asm/chacha20_poly1305_armv8.pl"),
    (&[AARCH64], "crypto/fipsmodule/aes/asm/vpaes-armv8.pl"),
    (&[AARCH64], "crypto/fipsmodule/bn/asm/armv8-mont.pl"),
    (&[AARCH64], "crypto/fipsmodule/ec/asm/p256-armv8-asm.pl"),
    (&[AARCH64], "crypto/fipsmodule/modes/asm/ghash-neon-armv8.pl"),
    (&[AARCH64], "crypto/fipsmodule/modes/asm/aesv8-gcm-armv8.pl"),
    (&[AARCH64], SHA512_ARMV8),
];

const SHA256_X86_64: &str = "crypto/fipsmodule/sha/asm/sha256-x86_64.pl";
const SHA512_X86_64: &str = "crypto/fipsmodule/sha/asm/sha512-x86_64.pl";

const SHA256_ARMV8: &str = "crypto/fipsmodule/sha/asm/sha256-armv8.pl";
const SHA512_ARMV8: &str = "crypto/fipsmodule/sha/asm/sha512-armv8.pl";

const RING_TEST_SRCS: &[&str] = &[("crypto/constant_time_test.c")];

const PREGENERATED: &str = "pregenerated";

fn cpp_flags(compiler: &cc::Tool) -> &'static [&'static str] {
    if !compiler.is_like_msvc() {
        static NON_MSVC_FLAGS: &[&str] = &[
            "-fvisibility=hidden",
            "-std=c1x", // GCC 4.6 requires "c1x" instead of "c11"
            "-Wall",
            "-Wbad-function-cast",
            "-Wcast-align",
            "-Wcast-qual",
            "-Wconversion",
            "-Wmissing-field-initializers",
            "-Wmissing-include-dirs",
            "-Wnested-externs",
            "-Wredundant-decls",
            "-Wshadow",
            "-Wsign-compare",
            "-Wsign-conversion",
            "-Wstrict-prototypes",
            "-Wundef",
            "-Wuninitialized",
        ];
        NON_MSVC_FLAGS
    } else {
        static MSVC_FLAGS: &[&str] = &[
            "/Gy", // Enable function-level linking.
            "/Zc:wchar_t",
            "/Zc:forScope",
            "/Zc:inline",
            // Warnings.
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

// None means "any OS" or "any target". The first match in sequence order is
// taken.
const ASM_TARGETS: &[AsmTarget] = &[
    AsmTarget {
        oss: LINUX_ABI,
        arch: AARCH64,
        perlasm_format: "linux64",
        asm_extension: "S",
        preassemble: false,
    },
    AsmTarget {
        oss: LINUX_ABI,
        arch: ARM,
        perlasm_format: "linux32",
        asm_extension: "S",
        preassemble: false,
    },
    AsmTarget {
        oss: LINUX_ABI,
        arch: X86,
        perlasm_format: "elf",
        asm_extension: "S",
        preassemble: false,
    },
    AsmTarget {
        oss: LINUX_ABI,
        arch: X86_64,
        perlasm_format: "elf",
        asm_extension: "S",
        preassemble: false,
    },
    AsmTarget {
        oss: MACOS_ABI,
        arch: AARCH64,
        perlasm_format: "ios64",
        asm_extension: "S",
        preassemble: false,
    },
    AsmTarget {
        oss: MACOS_ABI,
        arch: X86_64,
        perlasm_format: "macosx",
        asm_extension: "S",
        preassemble: false,
    },
    AsmTarget {
        oss: &[WINDOWS],
        arch: X86,
        perlasm_format: "win32n",
        asm_extension: "asm",
        preassemble: true,
    },
    AsmTarget {
        oss: &[WINDOWS],
        arch: X86_64,
        perlasm_format: "nasm",
        asm_extension: "asm",
        preassemble: true,
    },
    AsmTarget {
        oss: &[WINDOWS],
        arch: AARCH64,
        perlasm_format: "win64",
        asm_extension: "S",
        preassemble: false,
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
    "haiku",
    "illumos",
    "netbsd",
    "openbsd",
    "linux",
    "redox",
    "solaris",
];

/// Operating systems that have the same ABI as macOS on every architecture
/// mentioned in `ASM_TARGETS`.
const MACOS_ABI: &[&str] = &["ios", MACOS, "tvos"];

const MACOS: &str = "macos";
const WINDOWS: &str = "windows";

/// Read an environment variable and tell Cargo that we depend on it.
///
/// This needs to be used for any environment variable that isn't a standard
/// Cargo-supplied variable.
///
/// The name is static since we intend to only read a static set of environment
/// variables.
fn read_env_var(name: &'static str) -> Option<OsString> {
    println!("cargo:rerun-if-env-changed={}", name);
    std::env::var_os(name)
}

fn main() {
    const RING_PREGENERATE_ASM: &str = "RING_PREGENERATE_ASM";
    match read_env_var(RING_PREGENERATE_ASM).as_deref() {
        Some(s) if s == "1" => {
            pregenerate_asm_main();
        }
        None => ring_build_rs_main(),
        _ => {
            panic!("${} has an invalid value", RING_PREGENERATE_ASM);
        }
    }
}

fn ring_build_rs_main() {
    use std::env;

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = PathBuf::from(out_dir);

    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let is_musl = {
        let env = env::var("CARGO_CFG_TARGET_ENV").unwrap();
        env.starts_with("musl")
    };

    let is_git = std::fs::metadata(".git").is_ok();

    // Published builds are always built in release mode.
    let is_debug = is_git && env::var("DEBUG").unwrap() != "false";

    // If `.git` exists then assume this is the "local hacking" case where
    // we want to make it easy to build *ring* using `cargo build`/`cargo test`
    // without a prerequisite `package` step, at the cost of needing additional
    // tools like `Perl` and/or `nasm`.
    //
    // If `.git` doesn't exist then assume that this is a packaged build where
    // we want to optimize for minimizing the build tools required: No Perl,
    // no nasm, etc.
    let use_pregenerated = !is_git;

    // During local development, force warnings in non-Rust code to be treated
    // as errors. Since warnings are highly compiler-dependent and compilers
    // don't maintain backward compatibility w.r.t. which warnings they issue,
    // don't do this for packaged builds.
    let force_warnings_into_errors = is_git;

    let target = Target {
        arch,
        os,
        is_musl,
        is_debug,
        force_warnings_into_errors,
    };
    let pregenerated = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join(PREGENERATED);

    build_c_code(
        &target,
        pregenerated,
        &out_dir,
        &ring_core_prefix(),
        use_pregenerated,
    );
    emit_rerun_if_changed()
}

fn pregenerate_asm_main() {
    println!("cargo:rustc-cfg=pregenerate_asm_only");

    let pregenerated = PathBuf::from(PREGENERATED);
    std::fs::create_dir(&pregenerated).unwrap();
    let pregenerated_tmp = pregenerated.join("tmp");
    std::fs::create_dir(&pregenerated_tmp).unwrap();

    generate_prefix_symbols_asm_headers(&pregenerated_tmp, &ring_core_prefix()).unwrap();

    for asm_target in ASM_TARGETS {
        // For Windows, package pregenerated object files instead of
        // pregenerated assembly language source files, so that the user
        // doesn't need to install the assembler.
        let asm_dir = if asm_target.preassemble {
            &pregenerated_tmp
        } else {
            &pregenerated
        };

        let perlasm_src_dsts = perlasm_src_dsts(asm_dir, asm_target);
        perlasm(&perlasm_src_dsts, asm_target);

        if asm_target.preassemble {
            // Preassembly is currently only done for Windows targets.
            assert_eq!(&asm_target.oss, &[WINDOWS]);
            let os = WINDOWS;

            let srcs = asm_srcs(perlasm_src_dsts);

            let target = Target {
                arch: asm_target.arch.to_owned(),
                os: os.to_owned(),
                is_musl: false,
                is_debug: false,
                force_warnings_into_errors: true,
            };

            let b = new_build(&target, &pregenerated_tmp);
            for src in srcs {
                win_asm(&b, &src, &target, &pregenerated_tmp, &pregenerated);
            }
        }
    }
}

struct Target {
    arch: String,
    os: String,

    /// Is the target one that uses the musl C standard library instead of the default?
    is_musl: bool,

    /// Is this a debug build? This affects whether assertions might be enabled
    /// in the C code. For packaged builds, this should always be `false`.
    is_debug: bool,

    /// true: Force warnings to be treated as errors.
    /// false: Use the default behavior (perhaps determined by `$CFLAGS`, etc.)
    force_warnings_into_errors: bool,
}

fn build_c_code(
    target: &Target,
    pregenerated: PathBuf,
    out_dir: &Path,
    ring_core_prefix: &str,
    use_pregenerated: bool,
) {
    println!("cargo:rustc-env=RING_CORE_PREFIX={}", ring_core_prefix);

    let asm_target = ASM_TARGETS.iter().find(|asm_target| {
        asm_target.arch == target.arch && asm_target.oss.contains(&target.os.as_ref())
    });

    let asm_dir = if use_pregenerated {
        &pregenerated
    } else {
        out_dir
    };

    generate_prefix_symbols_header(out_dir, "prefix_symbols.h", '#', None, ring_core_prefix)
        .unwrap();

    generate_prefix_symbols_asm_headers(out_dir, ring_core_prefix).unwrap();

    let (asm_srcs, obj_srcs) = if let Some(asm_target) = asm_target {
        let perlasm_src_dsts = perlasm_src_dsts(asm_dir, asm_target);

        if !use_pregenerated {
            perlasm(&perlasm_src_dsts[..], asm_target);
        }

        let asm_srcs = asm_srcs(perlasm_src_dsts);

        // For Windows we also pregenerate the object files for non-Git builds so
        // the user doesn't need to install the assembler.
        if use_pregenerated && target.os == WINDOWS && asm_target.preassemble {
            let obj_srcs = asm_srcs
                .iter()
                .map(|src| obj_path(&pregenerated, src.as_path()))
                .collect::<Vec<_>>();
            (vec![], obj_srcs)
        } else {
            (asm_srcs, vec![])
        }
    } else {
        (vec![], vec![])
    };

    let core_srcs = sources_for_arch(&target.arch)
        .into_iter()
        .filter(|p| !is_perlasm(p))
        .filter(|p| {
            if let Some(extension) = p.extension() {
                // We don't (and can't) use any .S on Windows since MSVC and NASM can't assemble
                // them.
                if extension == "S"
                    && (target.arch == X86_64 || target.arch == X86)
                    && target.os == WINDOWS
                {
                    return false;
                }
            }
            true
        })
        .collect::<Vec<_>>();

    let test_srcs = RING_TEST_SRCS.iter().map(PathBuf::from).collect::<Vec<_>>();

    let libs = [
        ("", &core_srcs[..], &asm_srcs[..], &obj_srcs[..]),
        ("test", &test_srcs[..], &[], &[]),
    ];

    // XXX: Ideally, ring-test would only be built for `cargo test`, but Cargo
    // can't do that yet.
    libs.iter()
        .for_each(|&(lib_name_suffix, srcs, asm_srcs, obj_srcs)| {
            let lib_name = String::from(ring_core_prefix) + lib_name_suffix;
            let srcs = srcs.iter().chain(asm_srcs);
            build_library(target, out_dir, &lib_name, srcs, obj_srcs)
        });

    println!(
        "cargo:rustc-link-search=native={}",
        out_dir.to_str().expect("Invalid path")
    );
}

fn new_build(target: &Target, include_dir: &Path) -> cc::Build {
    let mut b = cc::Build::new();
    configure_cc(&mut b, target, include_dir);
    b
}

fn build_library<'a>(
    target: &Target,
    out_dir: &Path,
    lib_name: &str,
    srcs: impl Iterator<Item = &'a PathBuf>,
    preassembled_objs: &[PathBuf],
) {
    let mut c = new_build(target, out_dir);

    // Compile all the (dirty) source files into object files.
    srcs.for_each(|src| {
        // XXX: `b.file(p)` isn't enough to assemble an '.S' with clang on aarch64-pc-windows-msvc
        // presumably due to a bug in cc-rs; it doesn't pass clang `-c` like it does for other
        // targets.
        if target.os != WINDOWS || !matches!(src.extension(), Some(e) if e == "S" || e == "asm") {
            c.file(src);
        } else {
            let obj = win_asm(&c, src, target, out_dir, out_dir);
            c.object(obj);
        }
    });

    preassembled_objs.iter().for_each(|obj| {
        c.object(obj);
    });

    // Rebuild the library if necessary.
    let lib_path = PathBuf::from(out_dir).join(format!("lib{}.a", lib_name));

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

fn win_asm(
    b: &cc::Build,
    p: &Path,
    target: &Target,
    include_dir: &Path,
    out_dir: &Path,
) -> PathBuf {
    let ext = p.extension().unwrap().to_str().unwrap();
    let out_file = obj_path(out_dir, p);
    let cmd = if target.os != WINDOWS || ext != "asm" {
        cc_asm(b, p, &out_file)
    } else {
        nasm(p, &target.arch, include_dir, &out_file)
    };

    run_command(cmd);
    out_file
}

fn obj_path(out_dir: &Path, src: &Path) -> PathBuf {
    let mut out_path = out_dir.join(src.file_name().unwrap());
    // To eliminate unnecessary conditional logic, use ".o" as the extension,
    // even when the compiler (e.g. MSVC) would normally use something else
    // (e.g. ".obj"). cc-rs seems to do the same.
    assert!(out_path.set_extension("o"));
    out_path
}

fn configure_cc(c: &mut cc::Build, target: &Target, include_dir: &Path) {
    // FIXME: On Windows AArch64 we currently must use Clang to compile C code
    if target.os == WINDOWS && target.arch == AARCH64 && !c.get_compiler().is_like_clang() {
        let _ = c.compiler("clang");
    }

    let compiler = c.get_compiler();

    let _ = c.include("include");
    let _ = c.include(include_dir);
    for f in cpp_flags(&compiler) {
        let _ = c.flag(f);
    }

    if target.os.as_str() == MACOS {
        // ``-gfull`` is required for Darwin's |-dead_strip|.
        let _ = c.flag("-gfull");
    } else if !compiler.is_like_msvc() {
        let _ = c.flag("-g3");
    };

    if !target.is_debug {
        let _ = c.define("NDEBUG", None);
    }

    // Allow cross-compiling without a target sysroot for these targets.
    //
    // poly1305_vec.c requires <emmintrin.h> which requires <stdlib.h>.
    if (target.arch == WASM32) || (target.os == "linux" && target.is_musl && target.arch != X86_64)
    {
        if let Ok(compiler) = c.try_get_compiler() {
            // TODO: Expand this to non-clang compilers in 0.17.0 if practical.
            if compiler.is_like_clang() {
                let _ = c.flag("-nostdlibinc");
                let _ = c.define("RING_CORE_NOSTDLIBINC", "1");
            }
        }
    }

    if target.force_warnings_into_errors {
        c.warnings_into_errors(true);
    }
}

/// Assembles the assemply language source `file` into the object file
/// `out_file`.
fn cc_asm(b: &cc::Build, file: &Path, out_file: &Path) -> Command {
    let cc = b.get_compiler();
    let obj_opt = if cc.is_like_msvc() { "/Fo" } else { "-o" };
    let mut arg = OsString::from(obj_opt);
    arg.push(out_file);

    let mut c = cc.to_command();
    let _ = c.arg("-c").arg(arg).arg(file);
    c
}

fn nasm(file: &Path, arch: &str, include_dir: &Path, out_file: &Path) -> Command {
    let oformat = match arch {
        x if x == X86_64 => "win64",
        x if x == X86 => "win32",
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

fn run_command_with_args(command_name: &OsStr, args: &[String]) {
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

fn is_perlasm(path: &Path) -> bool {
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
        let mut args = vec![
            src.to_string_lossy().into_owned(),
            asm_target.perlasm_format.to_owned(),
        ];
        if asm_target.arch == X86 {
            args.push("-fPIC".into());
            args.push("-DOPENSSL_IA32_SSE2".into());
        }
        // Work around PerlAsm issue for ARM and AAarch64 targets by replacing
        // back slashes with forward slashes.
        let dst = dst
            .to_str()
            .expect("Could not convert path")
            .replace('\\', "/");
        args.push(dst);
        run_command_with_args(&get_command("PERL_EXECUTABLE", "perl"), &args);
    }
}

fn get_command(var: &'static str, default: &str) -> OsString {
    read_env_var(var).unwrap_or_else(|| default.into())
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

/// Creates the necessary header files for symbol renaming that are included by
/// assembly code.
///
/// For simplicity, both non-Nasm- and Nasm- style headers are always
/// generated, even though local non-packaged builds need only one of them.
fn generate_prefix_symbols_asm_headers(out_dir: &Path, prefix: &str) -> Result<(), std::io::Error> {
    generate_prefix_symbols_header(
        out_dir,
        "prefix_symbols_asm.h",
        '#',
        Some("#if defined(__APPLE__)"),
        prefix,
    )?;

    generate_prefix_symbols_header(
        out_dir,
        "prefix_symbols_nasm.inc",
        '%',
        Some("%ifidn __OUTPUT_FORMAT__,win32"),
        prefix,
    )?;

    Ok(())
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
    let mut file = std::fs::File::create(path)?;

    let filename_ident = filename.replace('.', "_").to_uppercase();
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
    // Rename some nistz256 assembly functions to match the names of their
    // polyfills.
    static SYMBOLS_TO_RENAME: &[(&str, &str)] = &[
        ("ecp_nistz256_point_double", "p256_point_double"),
        ("ecp_nistz256_point_add", "p256_point_add"),
        ("ecp_nistz256_point_add_affine", "p256_point_add_affine"),
        ("ecp_nistz256_ord_mul_mont", "p256_scalar_mul_mont"),
        ("ecp_nistz256_ord_sqr_mont", "p256_scalar_sqr_rep_mont"),
        ("ecp_nistz256_mul_mont", "p256_mul_mont"),
        ("ecp_nistz256_sqr_mont", "p256_sqr_mont"),
    ];

    static SYMBOLS_TO_PREFIX: &[&str] = &[
        "CRYPTO_memcmp",
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
        "aes_hw_ctr32_encrypt_blocks",
        "aes_hw_encrypt",
        "aes_hw_set_encrypt_key",
        "aes_nohw_ctr32_encrypt_blocks",
        "aes_nohw_encrypt",
        "aes_nohw_set_encrypt_key",
        "aesni_gcm_decrypt",
        "aesni_gcm_encrypt",
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
        "bssl_constant_time_test_conditional_memcpy",
        "bssl_constant_time_test_conditional_memxor",
        "bssl_constant_time_test_main",
        "chacha20_poly1305_open",
        "chacha20_poly1305_seal",
        "fiat_curve25519_adx_mul",
        "fiat_curve25519_adx_square",
        "gcm_ghash_avx",
        "gcm_ghash_clmul",
        "gcm_ghash_neon",
        "gcm_gmult_clmul",
        "gcm_gmult_neon",
        "gcm_init_avx",
        "gcm_init_clmul",
        "gcm_init_neon",
        "aes_gcm_enc_kernel",
        "aes_gcm_dec_kernel",
        "k25519Precomp",
        "limbs_mul_add_limb",
        "little_endian_bytes_from_scalar",
        "ecp_nistz256_neg",
        "ecp_nistz256_select_w5",
        "ecp_nistz256_select_w7",
        "p256_mul_mont",
        "p256_point_add",
        "p256_point_add_affine",
        "p256_point_double",
        "p256_point_mul",
        "p256_point_mul_base",
        "p256_point_mul_base_vartime",
        "p256_scalar_mul_mont",
        "p256_scalar_sqr_rep_mont",
        "p256_sqr_mont",
        "p384_elem_div_by_2",
        "p384_elem_mul_mont",
        "p384_elem_neg",
        "p384_elem_sub",
        "p384_point_add",
        "p384_point_double",
        "p384_point_mul",
        "p384_scalar_mul_mont",
        "openssl_poly1305_neon2_addmulmod",
        "openssl_poly1305_neon2_blocks",
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
        "x25519_ge_scalarmult_base_adx",
        "x25519_public_from_private_generic_masked",
        "x25519_sc_mask",
        "x25519_sc_muladd",
        "x25519_sc_reduce",
        "x25519_scalar_mult_adx",
        "x25519_scalar_mult_generic_masked",
    ];

    let mut out = String::new();

    for (old, new) in SYMBOLS_TO_RENAME {
        let line = format!(
            "{pp}define {prefix_prefix}{old} {prefix_prefix}{new}\n",
            pp = pp,
            prefix_prefix = prefix_prefix,
            old = old,
            new = new
        );
        out += &line;
    }

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
