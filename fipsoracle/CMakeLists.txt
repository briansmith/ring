include_directories(../include)

if (FIPS)
  add_executable(
    cavp_aes_test

    cavp_aes_test.cc
    cavp_test_util.cc
    $<TARGET_OBJECTS:test_support>
  )

  add_executable(
    cavp_aes_gcm_test

    cavp_aes_gcm_test.cc
    cavp_test_util.cc
    $<TARGET_OBJECTS:test_support>
  )

  add_executable(
    cavp_ecdsa2_keypair_test

    cavp_ecdsa2_keypair_test.cc
    cavp_test_util.cc
    $<TARGET_OBJECTS:test_support>
  )

  add_executable(
    cavp_ecdsa2_pkv_test

    cavp_ecdsa2_pkv_test.cc
    cavp_test_util.cc
    $<TARGET_OBJECTS:test_support>
  )

  add_executable(
    cavp_ecdsa2_siggen_test

    cavp_ecdsa2_siggen_test.cc
    cavp_test_util.cc
    $<TARGET_OBJECTS:test_support>
  )

  add_executable(
    cavp_ecdsa2_sigver_test

    cavp_ecdsa2_sigver_test.cc
    cavp_test_util.cc
    $<TARGET_OBJECTS:test_support>
  )

  add_executable(
    cavp_rsa2_keygen_test

    cavp_rsa2_keygen_test.cc
    cavp_test_util.cc
    $<TARGET_OBJECTS:test_support>
  )

  add_executable(
    cavp_rsa2_siggen_test

    cavp_rsa2_siggen_test.cc
    cavp_test_util.cc
    $<TARGET_OBJECTS:test_support>
  )

  add_executable(
    cavp_rsa2_sigver_test

    cavp_rsa2_sigver_test.cc
    cavp_test_util.cc
    $<TARGET_OBJECTS:test_support>
  )

  add_executable(
    cavp_hmac_test

    cavp_hmac_test.cc
    cavp_test_util.cc
    $<TARGET_OBJECTS:test_support>
  )

  add_executable(
    cavp_tdes_test

    cavp_tdes_test.cc
    cavp_test_util.cc
    $<TARGET_OBJECTS:test_support>
  )

  add_executable(
    cavp_sha_test

    cavp_sha_test.cc
    cavp_test_util.cc
    $<TARGET_OBJECTS:test_support>
  )

  add_executable(
    cavp_sha_monte_test

    cavp_sha_monte_test.cc
    cavp_test_util.cc
    $<TARGET_OBJECTS:test_support>
  )

  add_executable(
    cavp_ctr_drbg_test

    cavp_ctr_drbg_test.cc
    cavp_test_util.cc
    $<TARGET_OBJECTS:test_support>
  )

  add_executable(
    cavp_keywrap_test

    cavp_keywrap_test.cc
    cavp_test_util.cc
    $<TARGET_OBJECTS:test_support>
  )

  target_link_libraries(cavp_aes_test crypto)
  target_link_libraries(cavp_aes_gcm_test crypto)
  target_link_libraries(cavp_ctr_drbg_test crypto)
  target_link_libraries(cavp_ecdsa2_keypair_test crypto)
  target_link_libraries(cavp_ecdsa2_pkv_test crypto)
  target_link_libraries(cavp_ecdsa2_siggen_test crypto)
  target_link_libraries(cavp_ecdsa2_sigver_test crypto)
  target_link_libraries(cavp_hmac_test crypto)
  target_link_libraries(cavp_keywrap_test crypto)
  target_link_libraries(cavp_rsa2_keygen_test crypto)
  target_link_libraries(cavp_rsa2_siggen_test crypto)
  target_link_libraries(cavp_rsa2_sigver_test crypto)
  target_link_libraries(cavp_sha_test crypto)
  target_link_libraries(cavp_sha_monte_test crypto)
  target_link_libraries(cavp_tdes_test crypto)
endif()
