# Building BoringSSL

## Build Prerequisites

  * [CMake] [1] 2.8.8 or later is required.

  * Perl 5.6.1 or later is required. On Windows, [Strawberry Perl] [2] and MSYS
    Perl have both been reported to work. If not found by CMake, it may be
    configured explicitly by setting `PERL_EXECUTABLE`.

  * On Windows you currently must use [Ninja] [3] to build; on other platforms,
    it is not required, but recommended, because it makes builds faster.

  * If you need to build Ninja from source, then a recent version of
    [Python] [4] is required (Python 2.7.5 works).

  * On Windows only, [Yasm] [5] is required. If not found by CMake, it may be
    configured explicitly by setting `CMAKE_ASM_NASM_COMPILER`.

  * A C compiler is required. On Windows, MSVC 12 (Visual Studio 2013) or later
    with Platform SDK 8.1 or later are supported. Recent versions of GCC and
    Clang should work on non-Windows platforms, and maybe on Windows too.

  * [Go] [6] is required. If not found by CMake, the go executable may be
    configured explicitly by setting `GO_EXECUTABLE`.

## Building

Using Ninja (note the 'N' is capitalized in the cmake invocation):

    mkdir build
    cd build
    cmake -GNinja ..
    ninja

Using Make (does not work on Windows):

    mkdir build
    cd build
    cmake ..
    make

You usually don't need to run `cmake` again after changing `CMakeLists.txt`
files because the build scripts will detect changes to them and rebuild
themselves automatically.

Note that the default build flags in the top-level `CMakeLists.txt` are for
debugging—optimisation isn't enabled.

If you want to cross-compile then there is an example toolchain file for 32-bit
Intel in `util/`. Wipe out the build directory, recreate it and run `cmake` like
this:

    cmake -DCMAKE_TOOLCHAIN_FILE=../util/32-bit-toolchain.cmake -GNinja ..

If you want to build as a shared library, pass `-DBUILD_SHARED_LIBS=1`. On
Windows, where functions need to be tagged with `dllimport` when coming from a
shared library, define `BORINGSSL_SHARED_LIBRARY` in any code which `#include`s
the BoringSSL headers.

### Building for Android

It's possible to build BoringSSL with the Android NDK using CMake. This has
been tested with version 10d of the NDK.

Unpack the Android NDK somewhere and export `ANDROID_NDK` to point to the
directory. Clone https://github.com/taka-no-me/android-cmake into `util/`.  Then
make a build directory as above and run CMake *twice* like this:

    cmake -DANDROID_NATIVE_API_LEVEL=android-9 \
          -DANDROID_ABI=armeabi-v7a \
          -DCMAKE_TOOLCHAIN_FILE=../util/android-cmake/android.toolchain.cmake \
          -DANDROID_NATIVE_API_LEVEL=16 \
          -GNinja ..

Once you've run that twice, Ninja should produce Android-compatible binaries.
You can replace `armeabi-v7a` in the above with `arm64-v8a` to build aarch64
binaries.

## Known Limitations on Windows

  * Versions of CMake since 3.0.2 have a bug in its Ninja generator that causes
    yasm to output warnings

        yasm: warning: can open only one input file, only the last file will be processed

    These warnings can be safely ignored. The cmake bug is
    http://www.cmake.org/Bug/view.php?id=15253.

  * CMake can generate Visual Studio projects, but the generated project files
    don't have steps for assembling the assembly language source files, so they
    currently cannot be used to build BoringSSL.

## Embedded ARM

ARM, unlike Intel, does not have an instruction that allows applications to
discover the capabilities of the processor. Instead, the capability information
has to be provided by the operating system somehow.

BoringSSL will try to use `getauxval` to discover the capabilities and, failing
that, will probe for NEON support by executing a NEON instruction and handling
any illegal-instruction signal. But some environments don't support that sort
of thing and, for them, it's possible to configure the CPU capabilities
at compile time.

If you define `OPENSSL_STATIC_ARMCAP` then you can define any of the following
to enabling the corresponding ARM feature.

  * `OPENSSL_STATIC_ARMCAP_NEON` or `__ARM_NEON__` (note that the latter is set by compilers when NEON support is enabled).
  * `OPENSSL_STATIC_ARMCAP_AES`
  * `OPENSSL_STATIC_ARMCAP_SHA1`
  * `OPENSSL_STATIC_ARMCAP_SHA256`
  * `OPENSSL_STATIC_ARMCAP_PMULL`

Note that if a feature is enabled in this way, but not actually supported at
run-time, BoringSSL will likely crash.

# Running tests

There are two sets of tests: the C/C++ tests and the blackbox tests. For former
are built by Ninja and can be run from the top-level directory with `go run
util/all_tests.go`. The latter have to be run separately by running `go test`
from within `ssl/test/runner`.


 [1]: http://www.cmake.org/download/
 [2]: http://strawberryperl.com/
 [3]: https://martine.github.io/ninja/
 [4]: https://www.python.org/downloads/
 [5]: http://yasm.tortall.net/
 [6]: https://golang.org/dl/
