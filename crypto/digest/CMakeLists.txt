include_directories(. .. ../../include)

add_library(
	digest

	OBJECT

	digest.c
	digests.c
	digest_error.c
)
