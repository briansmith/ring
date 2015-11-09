include_directories(../include)

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
