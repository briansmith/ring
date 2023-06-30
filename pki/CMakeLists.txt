if(APPLE)
  set(PKI_CXX_FLAGS "-fno-aligned-new")
endif()

file(STRINGS pki_sources.txt pki_sources)
file(STRINGS pki_test_sources.txt pki_test_sources)

add_library(
  pki

  ${pki_sources}
)
set_target_properties(
  pki
  PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
  COMPILE_FLAGS "${PKI_CXX_FLAGS}")
target_compile_definitions(pki PRIVATE _BORINGSSL_LIBPKI_)
target_link_libraries(pki ssl crypto)

add_executable(
  pki_test

  ${pki_test_sources}
#  encode_values_unittest.cc  # Currently does a bunch of time goo..
#  ocsp_unittest.cc           # Not sure we will keep this here.. 
)
set_target_properties(
  pki_test
  PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
  COMPILE_FLAGS "${PKI_CXX_FLAGS}")
target_compile_definitions(
  pki_test
  PRIVATE
  _BORINGSSL_LIBPKI_)
target_link_libraries(pki_test test_support_lib boringssl_gtest_main pki ssl crypto)
add_dependencies(all_tests pki_test)


