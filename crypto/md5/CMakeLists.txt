include_directories(. .. ../../include)

if (${ARCH} STREQUAL "x86_64")
	set(
		MD5_ARCH_SOURCES

		md5-x86_64.${ASM_EXT}
	)
endif()

if (${ARCH} STREQUAL "x86")
	set(
		MD5_ARCH_SOURCES

		md5-586.${ASM_EXT}
	)
endif()

add_library(
	md5

	OBJECT

	md5.c

	${MD5_ARCH_SOURCES}
)

perlasm(md5-x86_64.${ASM_EXT} asm/md5-x86_64.pl)
perlasm(md5-586.${ASM_EXT} asm/md5-586.pl)

add_executable(
	md5_test

	md5_test.c
)

target_link_libraries(md5_test crypto)
