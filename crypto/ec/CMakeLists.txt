include_directories(../../include)

add_library(
  ec

  OBJECT

  ec.c
  ec_key.c
  ec_montgomery.c
  oct.c
  p256-64.c
  util-64.c
  simple.c
  wnaf.c
)

add_executable(
  example_mul

  example_mul.c

  $<TARGET_OBJECTS:test_support>
)

target_link_libraries(example_mul crypto)
