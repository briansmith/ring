include_directories(../../include)

if (${ARCH} STREQUAL "x86_64")
  set(
    RAND_ARCH_SOURCES

    rdrand-x86_64.${ASM_EXT}
  )
endif()

add_library(
  rand

  OBJECT

  ctrdrbg.c
  deterministic.c
  fuchsia.c
  rand.c
  urandom.c
  windows.c

  ${RAND_ARCH_SOURCES}
)

perlasm(rdrand-x86_64.${ASM_EXT} asm/rdrand-x86_64.pl)

add_executable(
  ctrdrbg_vector_test

  ctrdrbg_vector_test.cc

  $<TARGET_OBJECTS:test_support>
)

target_link_libraries(ctrdrbg_vector_test crypto)
add_dependencies(all_tests ctrdrbg_vector_test)
