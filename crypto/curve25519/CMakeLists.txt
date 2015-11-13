include_directories(../../include)

add_library(
  curve25519

  OBJECT

  curve25519.c
)

add_executable(
  ed25519_test

  ed25519_test.cc
  $<TARGET_OBJECTS:test_support>
)

target_link_libraries(ed25519_test crypto)

add_executable(
  x25519_test

  x25519_test.cc
)

target_link_libraries(x25519_test crypto)
