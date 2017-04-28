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
    cavp_ecdsa2_pkv_test

    cavp_ecdsa2_pkv_test.cc
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
    cavp_sha_test

    cavp_sha_test.cc
    cavp_test_util.h
    cavp_test_util.cc
    $<TARGET_OBJECTS:test_support>
  )

  add_executable(
    cavp_sha_monte_test

    cavp_sha_monte_test.cc
    cavp_test_util.h
    cavp_test_util.cc
    $<TARGET_OBJECTS:test_support>
  )

  target_link_libraries(cavp_aes_test crypto)
  target_link_libraries(cavp_aes_gcm_test crypto)

  target_link_libraries(cavp_ecdsa2_pkv_test crypto)
  target_link_libraries(cavp_ecdsa2_sigver_test crypto)

  target_link_libraries(cavp_sha_test crypto)
  target_link_libraries(cavp_sha_monte_test crypto)
endif()
