include_directories(. .. ../../include)

add_library(
	cipher

	OBJECT

	cipher.c
	cipher_error.c
	derive_key.c

	e_null.c
	e_rc4.c
	e_des.c
	e_aes.c
)

add_executable(
	cipher_test

	cipher_test.c
)

target_link_libraries(cipher_test crypto)
