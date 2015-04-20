include_directories(. .. ../../include)

add_library(
  ec

  OBJECT

  ec.c
  ec_asn1.c
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
)

add_executable(
  ec_test

  ec_test.cc
)

target_link_libraries(example_mul crypto)
target_link_libraries(ec_test crypto)
