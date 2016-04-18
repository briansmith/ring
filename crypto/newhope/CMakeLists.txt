add_library(
  newhope

  OBJECT

  error_correction.c
  newhope.c
  ntt.c
  poly.c
  precomp.c
  reduce.c
)

add_executable(
  newhope_test

  newhope_test.c
  $<TARGET_OBJECTS:test_support>
)

target_link_libraries(newhope_test crypto)
add_dependencies(all_tests newhope_test)
