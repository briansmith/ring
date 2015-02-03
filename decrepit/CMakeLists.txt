add_subdirectory(cast)
add_subdirectory(blowfish)

add_library(
  decrepit

  $<TARGET_OBJECTS:cast>
  $<TARGET_OBJECTS:blowfish>
)
