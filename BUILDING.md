Building *ring*
===============

*ring*'s Rust crate is named ```ring```. You can build it
using ```cargo build --release``` and you can run the tests
with ```cargo test --release```. When you use ```cargo``` to build *ring,
the build script [build.rs](build.rs) automatically builds the C and
assembly language components of *ring*.

Currently on Windows you must currently invoke cargo from a Visual Studio
Native Tools Command Prompt. Otherwise the build will likely fail in confusing
ways because either msbuild won't be found or there will be a version mismatch
between the toolchain used to build the C parts of the library and the toolchain
used by cargo/rustc for linking. Visual Studio 2015 Update 1 and Visual Studio
2013 Update 5 are supported.

*ring* uses Visual Studio's native build system (msbuild) on Windows, and GNU
Make otherwise. Because this is a little unusual, I would be particularly grateful
if you could report any problems building (or using) *ring*'s Rust crate.

GCC 4.8 and later, and Clang 3.4 and later are supported. Other compilers
will also probably work without too much trouble. Note in particular that if
you are cross-compiling an x86 build on a 64-bit version of Linux, then you
need to have the proper gcc-multilibs and g++-multilibs packages or equivalent
installed.

