include_directories(. .. ../../include)

add_library(
  digest

  OBJECT

  digest.c
  digests.c
)

add_executable(
  digest_test

  digest_test.c
)

target_link_libraries(digest_test crypto)
