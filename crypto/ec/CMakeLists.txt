include_directories(. .. ../../include)

add_library(
	ec

	OBJECT

	ec.c
	oct.c
	simple.c
	ec_montgomery.c
	wnaf.c
	ec_key.c
	ec_asn1.c
	ec_error.c
)

add_executable(
	example_mul

	example_mul.c
)

target_link_libraries(example_mul crypto)
