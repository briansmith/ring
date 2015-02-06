include_directories(. .. ../../include)

add_library(
  ec

  OBJECT

  ec.c
  oct.c
  simple.c
  ec_montgomery.c
  wnaf.c
  ec_key.c
  ec_asn1.c
)

add_executable(
  example_mul

  example_mul.c
)

add_executable(
  ec_test

  ec_test.c
)

target_link_libraries(example_mul crypto)
target_link_libraries(ec_test crypto)
