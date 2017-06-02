include_directories(../../include)

add_library(
  pkcs8_lib

  OBJECT

  pkcs8.c
  pkcs8_x509.c
  p5_pbev2.c
)

add_executable(
  pkcs12_test

  pkcs12_test.cc

  $<TARGET_OBJECTS:test_support>
)

target_link_libraries(pkcs12_test crypto)
add_dependencies(all_tests pkcs12_test)
