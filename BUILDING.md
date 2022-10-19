Building *ring*
===============

*ring*'s Rust crate is named `ring`. See https://crates.io/crates/ring to see
what the latest version is and to see how to add a dependency on it to your
project.

When hacking on *ring* itself, you can build it using `cargo build` and
`cargo test` as usual. *ring* includes some C, C++, and assembly language
components, and its build script (build.rs) builds all those things
automatically.


Packaged Builds
---------------

When you build *ring* from its package (e.g. the ones on crates.io), you only
need the Rust toolchain and a C/C++ compiler. For Windows targets, the packaged
crate contains precompiled object files for the assembly language modules so no
macro assembler is required. On other platforms, *ring*'s build script assumes
the C/C++ compiler knows how to build `.S` files (assembly language sources
with C preprocessor directives).


Builds directly from Git
------------------------

If you want to hack on *ring* then you need to build it directly from its Git
repository. There are some additional requirements for doing this that do not
apply when building from crates.io:

* For any target for which *ring* has assembly language implementations of
  primitives (32- and 64- bit Intel, and 32- and 64-bit ARM), Perl must be
  installed and in `$PATH`.

* For Windows targets except ARM64, `target/tools/windows/nasm/nasm[.exe]`
  is used as the assembler. The version to use and how to download it is
  documented in [.github/workflows/ci.yml](.github/workflows/ci.yml).

* For Windows ARM64 target, Clang is used as the C compiler and the assembler.
  See below "Building for Windows ARM64" section.

Cross Compiling
---------------

When you build *ring* for a target that is different than the one you are using
for the build process you need to install the rust tool chain and a C/C++
compiler that can produce binaries for the intended target.

Besides the required dependencies you need to set the environment variables
`TARGET_CC` and `TARGET_AR` to the full path of the cross-compiler and the
cross-archiver respectively.


Supported Toolchains
--------------------

*ring* targets the current stable release of Rust and Cargo. We also verify
that the current beta and nightly releases work.

On Windows, *ring* supports the x86_64-pc-windows-msvc and i686-pc-windows-msvc
targets best. These targets require the “Visual C++ Build Tools
2015” package or Visual Studio 2015 Update 3 or later to be installed.
*ring* now also supports the aarch64-pc-windows-msvc target. For the detailed
instructions please see the next section.
Patches to get it working on other variants, including in particular Visual Studio 2017
([#338]), Windows Universal Platform, Windows XP (the v140_xp toolchain; [#339]),
and the -gnu targets ([#330]) are welcome.

For other platforms, GCC 4.6 or later and Clang 3.5 or later are currently
supported best. The build script passes options to the C/C++ compiler that are
GCC- and Clang- specific. Pull requests to support other compilers will be
considered.

Note in particular that if you are cross-compiling an x86 build on a 64-bit
version of Linux, then you need to have the proper gcc-multilibs and
g++-multilibs packages or equivalent installed.


Building for Windows ARM64
--------------------------

Windows ARM64 target requires the “Visual C++ Build Tools 2019” package or
Visual Studio 2019 or later to be installed. “Desktop development with C++”
workflow should be installed, as well as
“MSVC v142 - VS 2019 C++ ARM64 build tools” component.

To build *ring* for Windows ARM64, you will need to install Clang as it is used
as the C compiler and the assembler for that platform. You can either use
the version of Clang installed by Visual Studio, a standalone version from
llvm.org, or a mingw64 version of Clang, for example, from [llvm-mingw
project](https://github.com/mstorsjo/llvm-mingw).

If you're buiding *ring* on an ARM64 device like Surface Pro X, please note
that llvm.org and llvm-mingw have native ARM64 versions of Clang available.
Also, if you're building *ring* on an ARM64 device, you might want to use
`aarch64-pc-windows-msvc` Rustup toolchain, which can be installed using
`rustup toolchain add aarch64-pc-windows-msvc`.

When building on an ARM64 device, due to a bug in the Visual Studio installer,
if you're using `rustc` version < 1.55 you would need to run `cargo build` /
`cargo test` commands from x86_arm64 Developer Command Prompt. You can use
`C:\Program Files (x86)\Microsoft Visual Studio\2019\<edition>\VC\Auxiliary\Build\vcvarsx86_arm64.bat`
batch script to configure the environment. If you use `rustc` 1.55 beta or newer,
you can run `cargo` commands without configuring the dev environment beforehand.


Additional Features that are Useful for Development
---------------------------------------------------
The `slow_tests` feature runs additional tests that are too slow to run during
a normal edit-compile-test cycle.

The `test_logging` feature prints out the input test vectors when a test fails.


[#321]: https://github.com/briansmith/ring/pull/321
[#330]: https://github.com/briansmith/ring/issues/330
[#334]: https://github.com/briansmith/ring/issues/334
[#336]: https://github.com/briansmith/ring/issues/336
[#337]: https://github.com/briansmith/ring/issues/337
[#338]: https://github.com/briansmith/ring/issues/338
[#339]: https://github.com/briansmith/ring/issues/339
[#340]: https://github.com/briansmith/ring/issues/340
