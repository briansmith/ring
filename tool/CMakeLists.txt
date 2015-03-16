include_directories(../include)

add_executable(
  bssl

  args.cc
  const.cc
  digest.cc
  genrsa.cc
  pkcs12.cc
  rand.cc
  speed.cc
  tool.cc
)

if (APPLE OR WIN32 OR ANDROID)
  target_link_libraries(bssl crypto)
else()
  find_library(FOUND_LIBRT rt)
  if (FOUND_LIBRT)
    target_link_libraries(bssl crypto -lrt)
  else()
    target_link_libraries(bssl crypto)
  endif()
endif()
