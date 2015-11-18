include_directories(../../include)

if (${ARCH} STREQUAL "arm")
  set(
    CURVE25519_ARCH_SOURCES

    asm/x25519-arm.S
  )
endif()

add_library(
  curve25519

  OBJECT

  curve25519.c

  ${CURVE25519_ARCH_SOURCES}
)

add_executable(
  ed25519_test

  ed25519_test.cc
  $<TARGET_OBJECTS:test_support>
)

target_link_libraries(ed25519_test crypto)
add_dependencies(all_tests ed25519_test)

add_executable(
  x25519_test

  x25519_test.cc
)

target_link_libraries(x25519_test crypto)
add_dependencies(all_tests x25519_test)
