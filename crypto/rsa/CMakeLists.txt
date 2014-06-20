include_directories(. .. ../../include)

add_library(
	rsa

	OBJECT

	rsa.c
	rsa_impl.c
	blinding.c
	padding.c
	rsa_asn1.c
	rsa_error.c
)

add_executable(
	rsa_test

	rsa_test.c
)

target_link_libraries(rsa_test crypto)
