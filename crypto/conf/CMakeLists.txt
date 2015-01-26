include_directories(. .. ../../include)

add_library(
	conf

	OBJECT

	conf.c
	conf_error.c
)

add_executable(
	conf_test

	conf_test.c
)

target_link_libraries(conf_test crypto)
