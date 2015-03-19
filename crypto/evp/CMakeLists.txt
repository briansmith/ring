include_directories(. .. ../../include)

add_library(
  evp

  OBJECT

  digestsign.c
  evp.c
  evp_ctx.c
  p_ec.c
  p_rsa.c
  pbkdf.c
  sign.c
)


add_executable(
  pbkdf_test

  pbkdf_test.cc

  $<TARGET_OBJECTS:test_support>
)

target_link_libraries(pbkdf_test crypto)
