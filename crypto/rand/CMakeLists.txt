include_directories(. .. ../../include)

add_library(
  rand

  OBJECT

  rand.c
  urandom.c
  windows.c
)
