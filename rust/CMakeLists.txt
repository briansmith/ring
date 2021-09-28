# additional interop for things like macros and inlined functions
add_library(
  rust_wrapper
  STATIC
  rust_wrapper.c
)

# generate architecture specific wrappers
foreach(TARGET
    aarch64-unknown-linux-gnu
    i686-pc-windows-gnu
    x86_64-unknown-linux-gnu
  )

  set(WRAPPER_TARGET ${CMAKE_BINARY_DIR}/rust/src/wrapper_${TARGET}.rs)
  set(COMMAND ${BINDGEN_EXECUTABLE} "wrapper.h"
              -o ${WRAPPER_TARGET}
              --no-derive-default
              --enable-function-attribute-detection
              --use-core
              --size_t-is-usize
              --default-macro-constant-type="signed"
              --rustified-enum="point_conversion_form_t"
              # These are not BoringSSL symbols, they are from glibc
              # and are not relevant to the build besides throwing warnings
              # about their 'long double' (aka u128) not being FFI safe.
              # We block those functions so that the build doesn't
              # spam warnings.
              #
              # https://github.com/rust-lang/rust-bindgen/issues/1549 describes the current problem
              # and other folks' solutions.
              #
              # We will explore migrating to https://github.com/rust-lang/rust-bindgen/pull/2122
              # when it lands
              --blocklist-function="strtold"
              --blocklist-function="qecvt"
              --blocklist-function="qecvt_r"
              --blocklist-function="qgcvt"
              --blocklist-function="qfcvt"
              --blocklist-function="qfcvt_r"
              -- # these are LLVM arg passthroughs
              -I../include
              --target=${TARGET})

  add_custom_target(
    bindgen_rust_${TARGET}
    ALL
    ${COMMAND}
    BYPRODUCTS ${WRAPPER_TARGET}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  )
  string(REPLACE "-" ";" TARGET_LIST ${TARGET})
  list(GET TARGET_LIST 0 ARCH)
  list(GET TARGET_LIST 1 VENDOR)

  set(INCLUDES "${INCLUDES}\
  #[cfg(all(target_arch = \"${ARCH}\", target_vendor = \"${VENDOR}\"))]\n\
  include!(\"wrapper_${TARGET}.rs\");\n")
endforeach()

# move files into build directory
configure_file("src/lib.rs" "src/lib.rs")

if(NOT BUILD_SHARED_LIBS)
  configure_file("build.rs" "build.rs" COPYONLY)
endif()

configure_file("Cargo.toml" "Cargo.toml" COPYONLY)
