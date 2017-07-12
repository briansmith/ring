include_directories(../include)

add_library(
  ssl

  bio_ssl.cc
  custom_extensions.cc
  d1_both.cc
  d1_lib.cc
  d1_pkt.cc
  d1_srtp.cc
  dtls_method.cc
  dtls_record.cc
  handshake_client.cc
  handshake_server.cc
  s3_both.cc
  s3_lib.cc
  s3_pkt.cc
  ssl_aead_ctx.c
  ssl_asn1.cc
  ssl_buffer.cc
  ssl_cert.cc
  ssl_cipher.cc
  ssl_ecdh.cc
  ssl_file.c
  ssl_lib.c
  ssl_privkey.c
  ssl_privkey_cc.cc
  ssl_session.c
  ssl_stat.c
  ssl_transcript.c
  ssl_versions.c
  ssl_x509.cc
  t1_enc.c
  t1_lib.c
  tls_method.c
  tls_record.c
  tls13_both.c
  tls13_client.c
  tls13_enc.c
  tls13_server.c
)

target_link_libraries(ssl crypto)

add_executable(
  ssl_test

  ssl_test.cc

  $<TARGET_OBJECTS:gtest_main>
  $<TARGET_OBJECTS:test_support>
)

target_link_libraries(ssl_test ssl crypto gtest)
if (WIN32)
  target_link_libraries(ssl_test ws2_32)
endif()
add_dependencies(all_tests ssl_test)
