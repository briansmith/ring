include_directories(. .. ../../include)

add_library(
	bytestring

	OBJECT

	cbs.c
	cbb.c
)

add_executable(
	bytestring_test

	bytestring_test.c
)

target_link_libraries(bytestring_test crypto)
