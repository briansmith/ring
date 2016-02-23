include_directories(../../include)

if (${ARCH} STREQUAL "arm")
  set(
    POLY1305_ARCH_SOURCES

    poly1305-armv4.${ASM_EXT}
  )
endif()

if (${ARCH} STREQUAL "aarch64")
  set(
    POLY1305_ARCH_SOURCES

    poly1305-armv8.${ASM_EXT}
  )
endif()

if (${ARCH} STREQUAL "x86")
  set(
    POLY1305_ARCH_SOURCES

    poly1305-x86.${ASM_EXT}
  )
endif()

if (${ARCH} STREQUAL "x86_64")
  set(
    POLY1305_ARCH_SOURCES

    poly1305-x86_64.${ASM_EXT}
  )
endif()

add_library(
  poly1305

  OBJECT

  poly1305.c

  ${POLY1305_ARCH_SOURCES}
)

add_executable(
  poly1305_test

  poly1305_test.cc
  $<TARGET_OBJECTS:test_support>
)

target_link_libraries(poly1305_test crypto)
add_dependencies(all_tests poly1305_test)

perlasm(poly1305-armv4.${ASM_EXT} asm/poly1305-armv4.pl)
perlasm(poly1305-armv8.${ASM_EXT} asm/poly1305-armv8.pl)
perlasm(poly1305-x86.${ASM_EXT} asm/poly1305-x86.pl)
perlasm(poly1305-x86_64.${ASM_EXT} asm/poly1305-x86_64.pl)
