include_directories(../../include)

add_library(
  pkcs7

  OBJECT

  pkcs7.c
  pkcs7_x509.c
)

add_executable(
  pkcs7_test

  pkcs7_test.c

  $<TARGET_OBJECTS:test_support>
)

target_link_libraries(pkcs7_test crypto)
add_dependencies(all_tests pkcs7_test)
