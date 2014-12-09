include_directories(. .. ../../include)

add_library(
	hkdf

	OBJECT

	hkdf.c
	hkdf_error.c
)

add_executable(
	hkdf_test

	hkdf_test.c
)

target_link_libraries(hkdf_test crypto)
