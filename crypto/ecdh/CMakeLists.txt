include_directories(. .. ../../include)

add_library(
	ecdh

	OBJECT

	ecdh.c
	ecdh_error.c
)
