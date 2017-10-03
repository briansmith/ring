include_directories(../include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-missing-prototypes")

add_executable(
  bn_mod_exp

  bn_mod_exp.cc
)

target_link_libraries(bn_mod_exp Fuzzer)
target_link_libraries(bn_mod_exp crypto)

add_executable(
  bn_div

  bn_div.cc
)

target_link_libraries(bn_div Fuzzer)
target_link_libraries(bn_div crypto)

add_executable(
  privkey

  privkey.cc
)

target_link_libraries(privkey Fuzzer)
target_link_libraries(privkey crypto)

add_executable(
  cert

  cert.cc
)

target_link_libraries(cert Fuzzer)
target_link_libraries(cert crypto)

add_executable(
  spki

  spki.cc
)

target_link_libraries(spki Fuzzer)
target_link_libraries(spki crypto)

add_executable(
  pkcs8

  pkcs8.cc
)

target_link_libraries(pkcs8 Fuzzer)
target_link_libraries(pkcs8 crypto)

add_executable(
  server

  server.cc
)

target_link_libraries(server Fuzzer)
target_link_libraries(server crypto)
target_link_libraries(server ssl)

add_executable(
  client

  client.cc
)

target_link_libraries(client Fuzzer)
target_link_libraries(client crypto)
target_link_libraries(client ssl)

add_executable(
  dtls_server

  dtls_server.cc
)

target_link_libraries(dtls_server Fuzzer)
target_link_libraries(dtls_server crypto)
target_link_libraries(dtls_server ssl)

add_executable(
  dtls_client

  dtls_client.cc
)

target_link_libraries(dtls_client Fuzzer)
target_link_libraries(dtls_client crypto)
target_link_libraries(dtls_client ssl)

add_executable(
  read_pem

  read_pem.cc
)

target_link_libraries(read_pem Fuzzer)
target_link_libraries(read_pem crypto)

add_executable(
  ssl_ctx_api

  ssl_ctx_api.cc
)

target_link_libraries(ssl_ctx_api Fuzzer)
target_link_libraries(ssl_ctx_api crypto)
target_link_libraries(ssl_ctx_api ssl)

add_executable(
  session

  session.cc

  $<TARGET_OBJECTS:test_support>
)

target_link_libraries(session Fuzzer)
target_link_libraries(session crypto)
target_link_libraries(session ssl)
