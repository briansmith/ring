include_directories(. .. ../../include)

add_library(
	evp

	OBJECT

	algorithm.c
	asn1.c
	digestsign.c
	evp.c
	evp_ctx.c
	evp_error.c
	p_ec.c
	p_ec_asn1.c
	p_hmac.c
	p_hmac_asn1.c
	p_rsa.c
	p_rsa_asn1.c
	pbkdf.c
	sign.c
)


add_executable(
	evp_test

	evp_test.c
)

target_link_libraries(evp_test crypto)
