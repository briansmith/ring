// Copyright 2015-2026 Brian Smith.
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

//! A wrapper around cc-rs.

// Avoid `std::env` here. All configuration should be done through `Target`,
// `Profile`, and `Tools`.
use super::target::*;
use std::path::{Path, PathBuf};

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
            "/W4",
            "/wd4127", // C4127: conditional expression is constant
            "/wd4464", // C4464: relative include path contains '..'
            "/wd5045", /* C5045: Compiler will insert Spectre mitigation for memory load if
                        * /Qspectre switch specified */
        ];
        MSVC_FLAGS
    }
}

pub struct Profile {
    /// Is this a debug build? This affects whether assertions might be enabled
    /// in the C code. For packaged builds, this should always be `false`.
    pub is_debug: bool,

    /// true: Force warnings to be treated as errors.
    /// false: Use the default behavior (perhaps determined by `$CFLAGS`, etc.)
    pub force_warnings_into_errors: bool,

    pub is_git: bool,
}

fn new_build(
    target: &Target,
    profile: &Profile,
    c_root_dir: &Path,
    include_dir: &Path,
) -> cc::Build {
    let mut b = cc::Build::new();
    configure_cc(&mut b, target, profile, c_root_dir, include_dir);
    b
}

pub fn build_library<'a>(
    target: &Target,
    profile: &Profile,
    c_root_dir: &Path,
    lib_name: &str,
    srcs: impl Iterator<Item = &'a PathBuf>,
    include_dir: &Path,
    preassembled_objs: &[PathBuf],
) {
    let mut c = new_build(target, profile, c_root_dir, include_dir);

    // Compile all the (dirty) source files into object files.
    srcs.for_each(|src| {
        c.file(c_root_dir.join(src));
    });

    preassembled_objs.iter().for_each(|obj| {
        c.object(obj);
    });

    // Rebuild the library if necessary.
    let lib_path = target.out_dir.join(format!("lib{lib_name}.a"));

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
    println!("cargo:rustc-link-lib=static={lib_name}");
    println!(
        "cargo:rustc-link-search=native={}",
        target.out_dir.to_str().expect("Invalid path")
    );
}

fn configure_cc(
    c: &mut cc::Build,
    target: &Target,
    profile: &Profile,
    c_root_dir: &Path,
    include_dir: &Path,
) {
    // FIXME: On Windows AArch64 we currently must use Clang to compile C code.
    // clang-cl emulates the cl.exe command line, `$CFLAGS`, etc.
    if target.os == WINDOWS && target.arch == AARCH64 {
        let _: &_ = c.prefer_clang_cl_over_msvc(true);
    };
    let compiler = c.get_compiler();

    let _ = c.include(c_root_dir.join("include"));
    let _ = c.include(include_dir);
    for f in cpp_flags(&compiler) {
        let _ = c.flag(f);
    }

    if APPLE_ABI.contains(&target.os.as_str()) {
        // ``-gfull`` is required for Darwin's |-dead_strip|.
        let _ = c.flag("-gfull");
    } else if !compiler.is_like_msvc() {
        let _ = c.flag("-g3");
    };

    if !profile.is_debug {
        let _ = c.define("NDEBUG", None);
    }

    if target.arch == X86 {
        let is_msvc_not_clang_cl = compiler.is_like_msvc() && !compiler.is_like_clang_cl();
        if !is_msvc_not_clang_cl {
            let _ = c.flag("-msse2");
        }
    }

    // Allow cross-compiling without a target sysroot for these targets.
    if (target.arch == WASM32)
        || (target.os == "linux" && target.env == "musl" && target.arch != X86_64)
    {
        // TODO: Expand this to non-clang compilers in 0.17.0 if practical.
        if compiler.is_like_clang() {
            let _ = c.flag("-nostdlibinc");
            let _ = c.define("RING_CORE_NOSTDLIBINC", "1");
        }
    }

    if profile.force_warnings_into_errors {
        c.warnings_into_errors(true);
    }
}
