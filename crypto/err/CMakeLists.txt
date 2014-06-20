include_directories(. .. ../../include)

add_library(
	err

	OBJECT

	err.c
	err_impl.c
)

add_executable(
	err_test

	err_test.c
)

target_link_libraries(err_test crypto)
