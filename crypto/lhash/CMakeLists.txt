include_directories(. .. ../../include)

add_library(
  lhash

  OBJECT

  lhash.c
)

add_executable(
  lhash_test

  lhash_test.c
)

target_link_libraries(lhash_test crypto)
