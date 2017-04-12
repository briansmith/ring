include_directories(../../include)

if (${ARCH} STREQUAL "x86_64")
  set(
    BCM_ASM_SOURCES

    md5-x86_64.${ASM_EXT}
    sha1-x86_64.${ASM_EXT}
    sha256-x86_64.${ASM_EXT}
    sha512-x86_64.${ASM_EXT}
  )
endif()

if (${ARCH} STREQUAL "x86")
  set(
    BCM_ASM_SOURCES

    md5-586.${ASM_EXT}
    sha1-586.${ASM_EXT}
    sha256-586.${ASM_EXT}
    sha512-586.${ASM_EXT}
  )
endif()

if (${ARCH} STREQUAL "arm")
  set(
    BCM_ASM_SOURCES

    sha1-armv4-large.${ASM_EXT}
    sha256-armv4.${ASM_EXT}
    sha512-armv4.${ASM_EXT}
  )
endif()

if (${ARCH} STREQUAL "aarch64")
  set(
    BCM_ASM_SOURCES

    sha1-armv8.${ASM_EXT}
    sha256-armv8.${ASM_EXT}
    sha512-armv8.${ASM_EXT}
  )
endif()

perlasm(md5-586.${ASM_EXT} md5/asm/md5-586.pl)
perlasm(md5-x86_64.${ASM_EXT} md5/asm/md5-x86_64.pl)
perlasm(sha1-586.${ASM_EXT} sha/asm/sha1-586.pl)
perlasm(sha1-armv4-large.${ASM_EXT} sha/asm/sha1-armv4-large.pl)
perlasm(sha1-armv8.${ASM_EXT} sha/asm/sha1-armv8.pl)
perlasm(sha1-x86_64.${ASM_EXT} sha/asm/sha1-x86_64.pl)
perlasm(sha256-586.${ASM_EXT} sha/asm/sha256-586.pl)
perlasm(sha256-armv4.${ASM_EXT} sha/asm/sha256-armv4.pl)
perlasm(sha256-armv8.${ASM_EXT} sha/asm/sha512-armv8.pl)
perlasm(sha256-x86_64.${ASM_EXT} sha/asm/sha512-x86_64.pl)
perlasm(sha512-586.${ASM_EXT} sha/asm/sha512-586.pl)
perlasm(sha512-armv4.${ASM_EXT} sha/asm/sha512-armv4.pl)
perlasm(sha512-armv8.${ASM_EXT} sha/asm/sha512-armv8.pl)
perlasm(sha512-x86_64.${ASM_EXT} sha/asm/sha512-x86_64.pl)

if(FIPS)
  add_library(
    bcm_c_generated_asm

    STATIC

    bcm.c
  )

  SET_TARGET_PROPERTIES(bcm_c_generated_asm PROPERTIES COMPILE_OPTIONS "-S")
  SET_TARGET_PROPERTIES(bcm_c_generated_asm PROPERTIES POSITION_INDEPENDENT_CODE ON)

  function(JOIN VALUES GLUE OUTPUT)
    string (REPLACE ";" "${GLUE}" _TMP_STR "${VALUES}")
    set (${OUTPUT} "${_TMP_STR}" PARENT_SCOPE)
  endfunction()

  JOIN("${BCM_ASM_SOURCES}" ",${CMAKE_CURRENT_BINARY_DIR}/" BCM_ASM_SOURCES_COMMA_SEP)

  add_custom_command(
    OUTPUT bcm-delocated.S
    COMMAND ${GO_EXECUTABLE} run crypto/fipsmodule/delocate.go crypto/fipsmodule/ar.go crypto/fipsmodule/const.go -a $<TARGET_FILE:bcm_c_generated_asm> -as ${CMAKE_CURRENT_BINARY_DIR}/${BCM_ASM_SOURCES_COMMA_SEP} -o ${CMAKE_CURRENT_BINARY_DIR}/bcm-delocated.S
    DEPENDS bcm_c_generated_asm ${BCM_ASM_SOURCES} delocate.go ar.go const.go
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  )

  add_library(
    bcm_hashunset

    STATIC

    bcm-delocated.S
  )

  set_target_properties(bcm_hashunset PROPERTIES POSITION_INDEPENDENT_CODE ON)
  set_target_properties(bcm_hashunset PROPERTIES LINKER_LANGUAGE C)

  add_custom_command(
    OUTPUT bcm.o
    COMMAND ${GO_EXECUTABLE} run crypto/fipsmodule/inject-hash.go crypto/fipsmodule/ar.go crypto/fipsmodule/const.go -o ${CMAKE_CURRENT_BINARY_DIR}/bcm.o -in $<TARGET_FILE:bcm_hashunset>
    DEPENDS bcm_hashunset inject-hash.go ar.go const.go
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  )

  # The outputs of add_custom_command cannot be referenced outside of the
  # CMakeLists.txt that defines it. Thus we have to wrap bcm.o in a custom target
  # so that crypto can depend on it.
  add_custom_target(bcm_o_target DEPENDS bcm.o)

  add_library(
    fipsmodule

    OBJECT

    is_fips.c
  )

  set_target_properties(fipsmodule PROPERTIES LINKER_LANGUAGE C)
else()
  add_library(
    fipsmodule

    OBJECT

    bcm.c
    is_fips.c

    ${BCM_ASM_SOURCES}
  )
endif()
