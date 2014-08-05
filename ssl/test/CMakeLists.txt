include_directories(../../include)

add_executable(
	bssl_shim

	async_bio.cc
	bssl_shim.cc
)

target_link_libraries(bssl_shim ssl crypto)
