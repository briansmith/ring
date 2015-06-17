add_subdirectory(cast)
add_subdirectory(blowfish)
add_subdirectory(bio)

add_library(
  decrepit

  $<TARGET_OBJECTS:bio_decrepit>
  $<TARGET_OBJECTS:blowfish>
  $<TARGET_OBJECTS:cast>
)
