# Additional interop for things like macros and inlined functions.
add_library(rust_wrapper STATIC rust_wrapper.c)
target_link_libraries(rust_wrapper crypto)


# Generate architecture-specific wrappers.
set(WRAPPER_TARGET ${CMAKE_BINARY_DIR}/rust/bssl-sys/src/wrapper_${RUST_BINDINGS}.rs)
set(COMMAND ${BINDGEN_EXECUTABLE} wrapper.h
            -o ${WRAPPER_TARGET}
            --no-derive-default
            --enable-function-attribute-detection
            --use-core
            --default-macro-constant-type=signed
            --rustified-enum=point_conversion_form_t
            # These regexes need to accept both / and \ to handle Windows file
            # path differences, due a bindgen issue. See
            # https://crbug.com/boringssl/595. Ideally, we would write [/\\],
            # but there are many layers of escaping here. First, CMake
            # interprets backslashes. Then CMake generates a Ninja or Make file.
            # That, in turn, launches passes inputs to the shell on POSIX, and
            # does something else on Windows.
            #
            # It is unlikely that every layer here has sufficiently well-defined
            # escaping and correctly handled the next layer's escaping. On top
            # of that, we'd likely need to detect Windows vs POSIX hosts and
            # change the input. Instead, just use [[:punct:]] which is more
            # permissive than necessary, but we only need to exclude unwanted
            # libc heaaders.
            #
            # If bindgen ever supports some file-based config (see
            # https://github.com/rust-lang/rust-bindgen/issues/2508), we can
            # switch to that.
            --allowlist-file=".*[[:punct:]]include[[:punct:]]openssl[[:punct:]].*\\.h"
            --allowlist-file=".*[[:punct:]]rust_wrapper\\.h"
            -- # these are LLVM arg passthroughs
            -I../../include
            # https://doc.rust-lang.org/nightly/rustc/platform-support.html
            --target=${RUST_BINDINGS})

add_custom_target(
  bindgen_rust_${RUST_BINDINGS}
  ALL
  ${COMMAND}
  BYPRODUCTS ${WRAPPER_TARGET}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

# move files into build directory
configure_file("src/lib.rs" "src/lib.rs")

if(NOT BUILD_SHARED_LIBS)
  configure_file("build.rs" "build.rs" COPYONLY)
endif()

configure_file("Cargo.toml" "Cargo.toml" COPYONLY)
