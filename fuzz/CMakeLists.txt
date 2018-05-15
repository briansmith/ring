include_directories(../include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-missing-prototypes")

add_executable(bn_mod_exp bn_mod_exp.cc)
target_link_libraries(bn_mod_exp Fuzzer crypto)

add_executable(bn_div bn_div.cc)
target_link_libraries(bn_div Fuzzer crypto)

add_executable(privkey privkey.cc)
target_link_libraries(privkey Fuzzer crypto)

add_executable(cert cert.cc)
target_link_libraries(cert Fuzzer crypto)

add_executable(spki spki.cc)
target_link_libraries(spki Fuzzer crypto)

add_executable(pkcs8 pkcs8.cc)
target_link_libraries(pkcs8 Fuzzer crypto)

add_executable(pkcs12 pkcs12.cc)
target_link_libraries(pkcs12 Fuzzer crypto)

add_executable(server server.cc)
target_link_libraries(server Fuzzer crypto ssl)

add_executable(client client.cc)
target_link_libraries(client Fuzzer crypto ssl)

add_executable(dtls_server dtls_server.cc)
target_link_libraries(dtls_server Fuzzer crypto ssl)

add_executable(dtls_client dtls_client.cc)
target_link_libraries(dtls_client Fuzzer crypto ssl)

add_executable(read_pem read_pem.cc)
target_link_libraries(read_pem Fuzzer crypto)

add_executable(ssl_ctx_api ssl_ctx_api.cc)
target_link_libraries(ssl_ctx_api Fuzzer crypto ssl)

add_executable(session session.cc)
target_link_libraries(session Fuzzer crypto ssl)
