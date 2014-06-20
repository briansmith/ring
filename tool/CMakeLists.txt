include_directories(../include)

add_executable(
	bssl

	args.cc
	client.cc
	const.cc
	speed.cc
	tool.cc
)

target_link_libraries(bssl ssl crypto -lrt)
