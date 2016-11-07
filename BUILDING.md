Building *ring*
===============

*ring*'s Rust crate is named `ring`. See https://crates.io/crates/ring to see
what the latest version is and to see how to add a dependency on it to your
project.

When hacking on *ring* itself, you can build it using `cargo build` and
`cargo test` as usual. *ring* includes some C, C++, and assembly language
components, and its build script (build.rs) builds all those things
automatically.



Building *ring* on Windows
--------------------------

On Windows, *ring* supports the x86_64-pc-windows-msvc and i686-pc-windows-msvc
targets best. These targets require Visual Studio 2015 Update 3 or later to be
installed; currently it isn't enough to install the “Visual C++ Build Tools
2015” package ([#337]). Patches to get it working on other variants, including
in particular Visual Studio “15” ([#338]), ARM platforms, Windows Universal
Platform, Windows XP compatibility (the v140_xp toolchain; [#339]), and the
-gnu targets ([#330]) are welcome.

Currently, *ring*'s build script (build.rs) uses Visual Studio's MSBuild to
build its non-Rust components, so it must be able to find MSBuild. Cargo
usually sets things up so that it mostly works automatically, at least when the
host architecture is the target architecture. If you have trouble building,
make sure that there isn't an old version of msbuild.exe ahead of MSBuild 14.0
in `%PATH%`. Failing that, try starting the build from within "VS2015 Native
Tools Command Prompt." In the near future, we plan to remove the dependencies
on MSBuild ([https://github.com/briansmith/ring/issues/340]).

When building a packaged release (e.g. from crates.io), it is not necessary to
have Yasm or Perl. When building from Git, the directories containing yasm.exe
and perl.exe must be in `%PATH%`, where yasm.exe is
[Yasm](http://yasm.tortall.net/Download.html) 1.3 or later and where perl.exe
is recommended to be [Strawberry Perl](http://strawberryperl.com). (Packaged
releases contain precompiled libraries comtaining the assembly language code
for x86_64-pc-windows-msvc and i686-pc-windows-msvc targets.)



Building *ring* on Other Platforms
----------------------------------

Currently, *ring*'s build script (build.rs) uses GNU make on non-Windows
platforms. By default it tries to invoke GNU make using `make` on non-BSD
platforms (including in particular Linux and macOS) and `gmake` on BSD
platforms. This can be overriden with the `$MAKE` environment variable. Work is
underway to remove the GNU make dependency completely ([#321]).

A C and C++ compiler is required; GCC 4.6 or later, and Clang 3.5 or later are
currently supported best. Other compilers probably work. Environment variables
like `$(CC)`, `$(CXX)`, `$(AS)`, etc. are supported for controlling this.

Perl is required for preprocessing the assembly language code. In the near
future, packaged releases won't require Perl because we'll include the
preprocessed assembly language code in the packages ([#334]; this is already
the case for \*-pc-windows-msvc targets).

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
