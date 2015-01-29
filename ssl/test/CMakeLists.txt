include_directories(../../include)

add_executable(
  bssl_shim

  async_bio.cc
  bssl_shim.cc
  malloc.cc
  packeted_bio.cc
  test_config.cc
)

target_link_libraries(bssl_shim ssl crypto)
if (NOT APPLE AND NOT WIN32)
  target_link_libraries(bssl_shim dl)
endif()
