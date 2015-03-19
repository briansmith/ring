include_directories(../../include)

add_library(
  evp

  OBJECT

  digestsign.c
  evp.c
  evp_ctx.c
  p_ec.c
  p_ec_asn1.c
  p_rsa.c
  p_rsa_asn1.c
  pbkdf.c
  sign.c
)


add_executable(
  pbkdf_test

  pbkdf_test.cc

  $<TARGET_OBJECTS:test_support>
)

target_link_libraries(pbkdf_test crypto)
