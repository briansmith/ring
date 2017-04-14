include_directories(../../include)

add_library(
  rand_extra

  OBJECT

  forkunsafe.c
  fuchsia.c
  rand_extra.c
  windows.c
)
