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



Prerequisites for Regenerating `crypto/chacha/chacha_vec_arm.S`
===============================================================

If you change `crypto/chacha/chacha_vec.c`, you will need the
arm-linux-gnueabihf-gcc compiler:

```
wget https://releases.linaro.org/14.11/components/toolchain/binaries/arm-linux-gnueabihf/gcc-linaro-4.9-2014.11-x86_64_arm-linux-gnueabihf.tar.xz && \
echo bc4ca2ced084d2dc12424815a4442e19cb1422db87068830305d90075feb1a3b  gcc-linaro-4.9-2014.11-x86_64_arm-linux-gnueabihf.tar.xz | sha256sum -c && \
tar xf gcc-linaro-4.9-2014.11-x86_64_arm-linux-gnueabihf.tar.xz && \
sudo mv gcc-linaro-4.9-2014.11-x86_64_arm-linux-gnueabihf /opt/
```
