include_directories(../../include)

if (FIPS)
  add_executable(
    cavp_aes_test

    cavp_aes_test.cc
    cavp_test_util.h
    cavp_test_util.cc
    $<TARGET_OBJECTS:test_support>
  )

  add_executable(
    cavp_aes_gcm_test

    cavp_aes_gcm_test.cc
    cavp_test_util.h
    cavp_test_util.cc
    $<TARGET_OBJECTS:test_support>
  )

  target_link_libraries(cavp_aes_test crypto)
  target_link_libraries(cavp_aes_gcm_test crypto)
endif()
