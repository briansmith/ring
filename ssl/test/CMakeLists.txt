include_directories(../../include)

add_executable(
	bssl_shim

	bssl_shim.cc
)

target_link_libraries(bssl_shim ssl crypto)
