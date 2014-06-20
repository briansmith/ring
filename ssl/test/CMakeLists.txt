include_directories(../../include)

add_executable(
	client_shim

	client_shim.cc
)

target_link_libraries(client_shim ssl crypto)
