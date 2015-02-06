include_directories(. .. ../../include)

add_library(
  ecdsa

  OBJECT

  ecdsa.c
  ecdsa_asn1.c
)


add_executable(
  ecdsa_test

  ecdsa_test.c
)

target_link_libraries(ecdsa_test crypto)
