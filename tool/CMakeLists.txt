include_directories(../include)

add_executable(
	bssl

	tool.cc
	const.cc
)

target_link_libraries(bssl ssl crypto -lrt)
