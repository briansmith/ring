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
repository. In this case, you must also have Perl installed, because the
assembly language modules inherited from BoringSSL (inherited from OpenSSL)
use Perl as a macro assembly language.

When building from Git for Windows, directories containing yasm.exe and
perl.exe must be in `%PATH%`, where yasm.exe is
[Yasm](http://yasm.tortall.net/Download.html) 1.3 or later and where perl.exe
is recommended to be [Strawberry Perl](http://strawberryperl.com). 


Supported Toolchains
--------------------

*ring* targets the current stable release of Rust and Cargo. We also verify
that the current beta and nightly releases work.

On Windows, *ring* supports the x86_64-pc-windows-msvc and i686-pc-windows-msvc
targets best. These targets require the “Visual C++ Build Tools
2015” package or Visual Studio 2015 Update 3 or later to be installed. Patches
to get it working on other variants, including in particular Visual Studio 2017
([#338]), Windows ARM platforms, Windows Universal Platform, Windows XP (the
v140_xp toolchain; [#339]), and the -gnu targets ([#330]) are welcome.

For other platforms, GCC 4.6 or later and Clang 3.5 or later are currently
supported best. The build script passes options to the C/C++ compiler that are
GCC- and Clang- specific. Pull requests to support other compilers will be
considered.

Note in particular that if you are cross-compiling an x86 build on a 64-bit
version of Linux, then you need to have the proper gcc-multilibs and
g++-multilibs packages or equivalent installed.



Additional Features that are Useful for Development
---------------------------------------------------

The `use_heap` feature enables functionality that uses the heap. This is on by
default. Disabling it is useful for code running in kernel space and some
embedded applications. For now some RSA, ECDH, and ECDSA signing functionality
still uses the heap. This feature will go away once RSA signing is the only
feature that uses the heap.

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


[#321]: https://github.com/briansmith/ring/pull/321
[#330]: https://github.com/briansmith/ring/issues/330
[#334]: https://github.com/briansmith/ring/issues/334
[#336]: https://github.com/briansmith/ring/issues/336
[#337]: https://github.com/briansmith/ring/issues/337
[#338]: https://github.com/briansmith/ring/issues/338
[#339]: https://github.com/briansmith/ring/issues/339
[#340]: https://github.com/briansmith/ring/issues/340
