cmake_minimum_required (VERSION 2.8.10)

project (BoringSSL)

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -ggdb")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror -ggdb -std=c++0x")
elseif(MSVC)
	# Disable warnings for implicit integer narrowing.
	set(CMAKE_C_FLAGS "/wd4267")
	set(CMAKE_CXX_FLAGS "/wd4267")
endif()

if((CMAKE_COMPILER_IS_GNUCXX AND CMAKE_C_COMPILER_VERSION VERSION_GREATER "4.5.99") OR
   CMAKE_CXX_COMPILER_ID MATCHES "Clang")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wshadow")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wshadow")
endif()

add_definitions(-DBORINGSSL_IMPLEMENTATION)

if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
	set(ARCH "x86_64")
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "amd64")
	set(ARCH "x86_64")
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "AMD64")
	# cmake reports AMD64 on Windows, but we might be building for 32-bit.
	if (CMAKE_CL_64)
		set(ARCH "x86_64")
	else()
		set(ARCH "x86")
	endif()
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86")
	set(ARCH "x86")
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "i386")
	set(ARCH "x86")
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "i686")
	set(ARCH "x86")
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "arm")
	set(ARCH "arm")
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
	set(ARCH "aarch64")
else()
	message(FATAL_ERROR "Unknown processor:" ${CMAKE_SYSTEM_PROCESSOR})
endif()

if (${ARCH} STREQUAL "x86" AND APPLE)
	# With CMake 2.8.x, ${CMAKE_SYSTEM_PROCESSOR} evalutes to i386 on OS X,
	# but clang defaults to 64-bit builds on OS X unless otherwise told.
	# Set ARCH to x86_64 so clang and CMake agree. This is fixed in CMake 3.
	set(ARCH "x86_64")
endif()

add_subdirectory(crypto)
add_subdirectory(ssl)
add_subdirectory(ssl/test)
add_subdirectory(tool)
