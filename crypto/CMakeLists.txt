# TODO(crbug.com/boringssl/524): Avoid needing this transform by instead moving
# this up a directory.
list(TRANSFORM BCM_SOURCES_ASM PREPEND "../")
list(TRANSFORM BCM_SOURCES_NASM PREPEND "../")
list(TRANSFORM CRYPTO_SOURCES_ASM PREPEND "../")
list(TRANSFORM CRYPTO_SOURCES_NASM PREPEND "../")
list(TRANSFORM CRYPTO_SOURCES PREPEND "../")

if(OPENSSL_ASM)
  list(APPEND CRYPTO_SOURCES_ASM_USED ${CRYPTO_SOURCES_ASM})
  list(APPEND BCM_SOURCES_ASM_USED ${BCM_SOURCES_ASM})
endif()
if(OPENSSL_NASM)
  list(APPEND CRYPTO_SOURCES_ASM_USED ${CRYPTO_SOURCES_NASM})
  list(APPEND BCM_SOURCES_ASM_USED ${BCM_SOURCES_NASM})
endif()

if(FIPS_DELOCATE AND FIPS_SHARED)
  message(FATAL_ERROR "Can't set both delocate and shared mode for FIPS build")
endif()

if(FIPS_DELOCATE)
  add_library(bcm_c_generated_asm STATIC fipsmodule/bcm.c)
  add_dependencies(bcm_c_generated_asm boringssl_prefix_symbols)
  target_include_directories(bcm_c_generated_asm PRIVATE ${PROJECT_SOURCE_DIR}/include)
  set_target_properties(bcm_c_generated_asm PROPERTIES COMPILE_OPTIONS "-S")
  set_target_properties(bcm_c_generated_asm PROPERTIES POSITION_INDEPENDENT_CODE ON)

  set(TARGET_FLAG "")
  if(CMAKE_ASM_COMPILER_TARGET)
    set(TARGET_FLAG "--target=${CMAKE_ASM_COMPILER_TARGET}")
  endif()

  go_executable(delocate boringssl.googlesource.com/boringssl/util/fipstools/delocate)
  add_custom_command(
    OUTPUT bcm-delocated.S
    COMMAND
    ${CMAKE_CURRENT_BINARY_DIR}/delocate
    -a $<TARGET_FILE:bcm_c_generated_asm>
    -o ${CMAKE_CURRENT_BINARY_DIR}/bcm-delocated.S
    -cc ${CMAKE_ASM_COMPILER}
    -cc-flags "${TARGET_FLAG} ${CMAKE_ASM_FLAGS}"
    ${PROJECT_SOURCE_DIR}/include/openssl/arm_arch.h
    ${PROJECT_SOURCE_DIR}/include/openssl/asm_base.h
    ${PROJECT_SOURCE_DIR}/include/openssl/target.h
    ${BCM_SOURCES_ASM_USED}
    DEPENDS
    bcm_c_generated_asm
    delocate
    ${BCM_SOURCES_ASM_USED}
    ${PROJECT_SOURCE_DIR}/include/openssl/arm_arch.h
    ${PROJECT_SOURCE_DIR}/include/openssl/asm_base.h
    ${PROJECT_SOURCE_DIR}/include/openssl/target.h
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  )

  add_library(bcm_hashunset STATIC bcm-delocated.S)
  set_target_properties(bcm_hashunset PROPERTIES POSITION_INDEPENDENT_CODE ON)
  set_target_properties(bcm_hashunset PROPERTIES LINKER_LANGUAGE C)

  go_executable(inject_hash
                boringssl.googlesource.com/boringssl/util/fipstools/inject_hash)
  add_custom_command(
    OUTPUT bcm.o
    COMMAND ./inject_hash -o bcm.o -in-archive $<TARGET_FILE:bcm_hashunset>
    DEPENDS bcm_hashunset inject_hash
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )
  set(CRYPTO_FIPS_OBJECTS bcm.o)
elseif(FIPS_SHARED)
  if(NOT BUILD_SHARED_LIBS)
    message(FATAL_ERROR "FIPS_SHARED set but not BUILD_SHARED_LIBS")
  endif()

  add_library(bcm_library STATIC fipsmodule/bcm.c ${BCM_SOURCES_ASM_USED})
  add_dependencies(bcm_library boringssl_prefix_symbols)
  target_include_directories(bcm_library PRIVATE ${PROJECT_SOURCE_DIR}/include)

  add_custom_command(
    OUTPUT bcm.o
    COMMAND ${CMAKE_LINKER} -r -T ${CMAKE_CURRENT_SOURCE_DIR}/fipsmodule/fips_shared.lds -o bcm.o --whole-archive $<TARGET_FILE:bcm_library>
    DEPENDS bcm_library fipsmodule/fips_shared.lds
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )
  set(CRYPTO_FIPS_OBJECTS bcm.o)
else()
  add_library(fipsmodule OBJECT fipsmodule/bcm.c ${BCM_SOURCES_ASM_USED})
  add_dependencies(fipsmodule boringssl_prefix_symbols)
  target_include_directories(fipsmodule PRIVATE ${PROJECT_SOURCE_DIR}/include)
  set(CRYPTO_FIPS_OBJECTS $<TARGET_OBJECTS:fipsmodule>)
endif()

add_library(crypto ${CRYPTO_SOURCES} ${CRYPTO_FIPS_OBJECTS} ${CRYPTO_SOURCES_ASM_USED})
target_include_directories(crypto PUBLIC
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
install_if_enabled(TARGETS crypto EXPORT OpenSSLTargets ${INSTALL_DESTINATION_DEFAULT})
set_property(TARGET crypto PROPERTY EXPORT_NAME Crypto)

if(FIPS_SHARED)
  # Rewrite libcrypto.so to inject the correct module hash value. This assumes
  # UNIX-style library naming, but we only support FIPS mode on Linux anyway.
  add_custom_command(
    TARGET crypto POST_BUILD
    COMMAND ${GO_EXECUTABLE} run
    ${CMAKE_CURRENT_SOURCE_DIR}/../util/fipstools/inject_hash/inject_hash.go
    -o libcrypto.so -in-object libcrypto.so
    # The DEPENDS argument to a POST_BUILD rule appears to be ignored. Thus
    # go_executable isn't used (as it doesn't get built), but we list this
    # dependency anyway in case it starts working in some CMake version.
    DEPENDS ../util/fipstools/inject_hash/inject_hash.go
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )
endif()

add_dependencies(crypto boringssl_prefix_symbols)
if(WIN32)
  target_link_libraries(crypto ws2_32)
endif()

# CMAKE_SYSTEM_NAME is "Generic" for embedded OSes:
# https://cmake.org/cmake/help/book/mastering-cmake/chapter/Cross%20Compiling%20With%20CMake.html#toolchain-files
#
# For now we assume embedded OSes do not have threads. Additionally, the Threads
# package does not work with Android, but Android does not require any extra
# parameters to link pthreads.
if(NOT CMAKE_SYSTEM_NAME MATCHES "^(Generic|Android)$")
  find_package(Threads REQUIRED)
  target_link_libraries(crypto Threads::Threads)
endif()

# Every target depends on crypto, so we add libcxx as a dependency here to
# simplify injecting it everywhere.
if(USE_CUSTOM_LIBCXX)
  target_link_libraries(crypto libcxx)
endif()
