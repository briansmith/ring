include_directories(. .. ../../include)

add_library(
  err

  OBJECT

  err.c
)

add_executable(
  err_test

  err_test.cc

  $<TARGET_OBJECTS:test_support>
)

target_link_libraries(err_test crypto)
