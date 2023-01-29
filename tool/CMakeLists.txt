include_directories(../include)

add_executable(
  bssl

  args.cc
  ciphers.cc
  client.cc
  const.cc
  digest.cc
  fd.cc
  file.cc
  generate_ech.cc
  generate_ed25519.cc
  genrsa.cc
  pkcs12.cc
  rand.cc
  server.cc
  sign.cc
  speed.cc
  tool.cc
  transport_common.cc
)
install(TARGETS bssl DESTINATION ${CMAKE_INSTALL_BINDIR})
add_dependencies(bssl global_target)
target_link_libraries(bssl ssl crypto)
