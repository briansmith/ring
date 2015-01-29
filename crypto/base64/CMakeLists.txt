include_directories(. .. ../../include)

add_library(
  base64

  OBJECT

  base64.c
)

add_executable(
  base64_test

  base64_test.c
)

target_link_libraries(base64_test crypto)
