if(APPLE)
  set(PKI_CXX_FLAGS "-fno-aligned-new")
endif()

add_library(
  pki

  fillins/ip_address.cc
  fillins/utf_string_conversions.cc
  fillins/string_util.cc
  fillins/base64.cc
  fillins/openssl_util.cc
  string_util.cc
  trust_store.cc
  trust_store_collection.cc
  parse_certificate.cc
  parsed_certificate.cc
  parser.cc
  parse_values.cc
  parse_name.cc
  parsed_certificate.cc
  name_constraints.cc
  input.cc
  tag.cc
  cert_errors.cc
  general_names.cc
  pem.cc
  crl.cc
  revocation_util.cc
  encode_values.cc
  verify_name_match.cc
  cert_errors.cc
  common_cert_errors.cc
  parse_certificate.cc
  parsed_certificate.cc
  extended_key_usage.cc
  certificate_policies.cc
  verify_certificate_chain.cc
  verify_signed_data.cc
  signature_algorithm.cc
  cert_error_id.cc
  cert_error_params.cc
  trust_store.cc
  trust_store_collection.cc
  trust_store_in_memory.cc
  simple_path_builder_delegate.cc
  cert_issuer_source_static.cc
  path_builder.cc
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

  fillins/path_service.cc
  fillins/file_util.cc
  test_helpers.cc
  string_util_unittest.cc
  parser_unittest.cc
  parse_values_unittest.cc
  input_unittest.cc
  signature_algorithm_unittest.cc
  extended_key_usage_unittest.cc
  parse_name_unittest.cc
  verify_name_match_unittest.cc
  verify_signed_data_unittest.cc
  parse_certificate_unittest.cc
  parsed_certificate_unittest.cc
  simple_path_builder_delegate_unittest.cc
  trust_store_collection_unittest.cc
  certificate_policies_unittest.cc
  verify_certificate_chain_unittest.cc
  nist_pkits_unittest.cc
  path_builder_pkits_unittest.cc
  name_constraints_unittest.cc
  cert_issuer_source_static_unittest.cc
  path_builder_unittest.cc
  mock_signature_verify_cache.cc
  path_builder_verify_certificate_chain_unittest.cc
  verify_certificate_chain_pkits_unittest.cc
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


