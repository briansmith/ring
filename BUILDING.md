Building *ring*
===============

*ring*'s Rust crate is named ```ring```. You can build it
using ```cargo build --release``` and you can run the tests
with ```cargo test --release```.



Building *ring* on Windows
--------------------------

The directory containing yasm.exe must be in `%PATH%`, where yasm.exe is
[Yasm](http://yasm.tortall.net/Download.html) 1.3 or later. 

The directory containing perl.exe must be in `%PATH%`.
[Strawberry Perl](strawberryperl.com) is recommended. 

*ring* uses Visual Studio's native build system (msbuild) on Windows to build
its C, C++, and assembly language parts, so it must be able to find MSBuild.
Visual Studio 2015 Update 2 (and later) is supported. It seems Cargo sets
things up so that it mostly works automatically, at least when the host
architecture is the target architecture. Because using MSBuild in
`cargo build` is a little unusual, I would be particularly grateful if you
could report any problems building (or using) *ring* that might be due to this.

If you have trouble building, make sure that there isn't an old version of
`msbuild` ahead of MSBuild 14.0 in your `%PATH%`. Failing that, try starting
the build from within a "Visual Studio Native Tools Command Prompt."



Building *ring* on Other Platforms
----------------------------------

For building the C code (and C++ code for some tests), GCC 4.6 and later, and
Clang 3.5 and later are currently supported. Other compilers probably work.
Perl is required for preprocessing the assembly language code. A makefile,
requiring GNU make, drives the build of the non-Rust code. Variables like
`$(CC)`, `$(CXX)`, `$(AS)`, etc. are supported.

Note in particular that if you are cross-compiling an x86 build on a 64-bit
version of Linux, then you need to have the proper gcc-multilibs and
g++-multilibs packages or equivalent installed.



This Sucks. What are you doing to fix it?
----------------------------------------

We are fully aware that this sucks. We want to get rid of the dependencies on
GNU make, msbuild, Perl, and Yasm.

If/when we get around to packaging *ring* as a crate on crates.io, we should
implement some workarounds to ensure that Perl, Yasm, etc. aren't required.
For example, we can generate the assembly language code from Perlasm for all
platforms, and then package the generated assembly language code into the
crate. That would avoid the need for Perl for *users* of the crate. We could
take this idea further to eliminate most of the other dependencies (C compilers,
C++ compilers, assemblers, GNU make, msbuild, etc.) for *users* of the crate.



Additional features that are useful for Development
---------------------------------------------------

The `internal_benches` feature enable benchmarks of internal functions. These
benchmarks are only useful for people hacking on the implementation of *ring*.
(The benchmarks for the *ring* API are in the
[crypto-bench](https://github.com/briansmith/crypto-bench) project.)

The `slow_tests` feature runs additional tests that are too slow to run during
a normal edit-compile-test cycle.

The `test_logging` feature prints out additional logging information during
tests, in particular the contents of the test input files, as tests execute.
When a test fails, the most recently-logged stuff indicates which test vectors
failed. This isn't enabled by default because it uses too much memory on small
targets, due to the way that Rust buffers the output until (unless) the test
fails. For small (embedded) targets, use
`cargo test --release --no-run --features=test_logging` to build the tests, and
then run the tests on the target with `<executable-name> --nocapture' to see
the log.
