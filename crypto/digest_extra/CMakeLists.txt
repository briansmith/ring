include_directories(../../include)

add_library(
  digest_extra

  OBJECT

  digest_extra.c
)

add_executable(
  digest_test

  digest_test.cc

  $<TARGET_OBJECTS:test_support>
)

target_link_libraries(digest_test crypto)
add_dependencies(all_tests digest_test)
