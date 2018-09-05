include_directories(../../include)

add_library(
  poly1305

  OBJECT

  poly1305.c
  poly1305_arm.c
  poly1305_vec.c
)
