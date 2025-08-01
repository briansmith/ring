Building *ring*
===============

Supported Toolchains and Cross-compiling
----------------------------------------

*ring* currently requires a C (but not C++) toolchain.

When cross-compiling, a sysroot for the target is usually required too;
[mk/install-build-tools.sh](mk/install-build-tools.sh)  documents, in code,
one way to get a working toolchain for various targets. `TARGET_CC` and
`TARGET_AR` (or equivalents) must be set. [mk/cargo.sh](mk/cargo.sh)
documents, in code, one way to successfully cross-compile for various targets.

Except for Windows x86/x86-64 targets, *ring*'s build script assumes the
C/C++ compiler knows how to build `.S` files (assembly language sources
with C preprocessor directives) for target architectures for which we have
assembly language code (ARM, Aarch64, i686, x86-64).

For Windows targets, “Build Tools for Visual Studio 2022” (or a higher
edition of Visual Studio, like Community, Standard, or Enterprise). The
“Desktop development with C++” workflow must be installed. The Visual Studio
version used by default in GitHub Actions is the one that is primarily
supported.

For Windows ARM64 targets (aarch64-pc-windows-msvc), the Visual Studio Build
Tools “VS 2022 C++ ARM64 build tools” and "clang" components must be installed.
Add Microsoft's provided version of `clang` to `%PATH%`, which will allow the
build to work in GitHub Actions without installing anything:
```
$env:Path += ";C:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise\VC\Tools\Llvm\x64\bin"
```
If you (locally) have “Build Tools for Visual Studio 2022” instead, use:
```
$env:Path += ";C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\Llvm\x64\bin"
```
Alternatively, if the host machine is already a Windows ARM64 then use:
```
$env:Path += ";C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\Llvm\ARM64\bin"
```

Packaged Builds
---------------

The *ring* crate released on crates.io needs fewer tools than are required
for building *ring* from Git. Perl isn't required because the output of
the Perl build steps is packaged into the crate. For Windows x86 and x86-64,
the packaged crate contains precompiled object files for the assembly
language modules so no macro assembler. 

Builds directly from Git
------------------------

If you want to hack on *ring* then you need to build it directly from its Git
repository. There are some additional requirements for doing this that do not
apply when building from crates.io:

* For any target for which *ring* has assembly language implementations of
  primitives (32- and 64- bit Intel, and 32- and 64- bit ARM), Perl must be
  installed. Perl must be in `$PATH` or `$PERL_EXECUTABLE` must be set.

* For Windows x86 and x86-64 targets only, `target/tools/windows/nasm/nasm[.exe]`
  is used as the assembler. The version to use, how to download it, and where
  to put it, is all documented in [mk/install-build-tools.ps1](mk/install-build-tools.ps1).

For Windows hosts, it is easiest to work in a Git Bash prompt as this will
make Perl available automatically. You should not need to mess with
VCVARSALL/etc since cc-rs will find MSVC. When targeting
aarch64-pc-windows-msvc, just add the Visual-Studio-supplied LLVM directory
to the PATH by transliterating the relevant PowerShell commands into Bash
syntax; this copy of clang will be able to find all the headers, etc.


Additional Features that are Useful for Development
---------------------------------------------------
The `slow_tests` feature runs additional tests that are too slow to run during
a normal edit-compile-test cycle.

The `test_logging` feature prints out the input test vectors when a test fails.
