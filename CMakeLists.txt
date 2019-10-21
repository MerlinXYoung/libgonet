cmake_minimum_required(VERSION 3.15)


##################################################################################
project(libgonet CXX)

if (CMAKE_BUILD_TYPE)
else()
    set(CMAKE_BUILD_TYPE RELEASE)
endif()

set(CMAKE_CXX_STANDARD_REQUIRED 11)
set(CMAKE_CXX_STANDARD 11)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/prefix.cmake)

option(ENABLE_TUTORIAL "enable build tutorial" ON)
option(ENABLE_AZMQ "enable build tutorial" OFF)
set(GONET_AZMQ  0)
# if(ENABLE_SYS_LIBGO)
# 	set(Libgo_DIR /usr/local/libgo)
# 	message(STATUS "ENABLE_SYS_LIBGO:${ENABLE_SYS_LIBGO} ${Libgo_DIR}")
# endif()
if(ENABLE_AZMQ)
    set(GONET_AZMQ 1)
endif()
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/libgonet/cmake_config.h.in ${CMAKE_CURRENT_SOURCE_DIR}/libgonet/cmake_config.h)

message("CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")


set(CMAKE_CXX_FLAGS " -Wall -Werror -fPIC -g -pg")
set(CMAKE_CXX_FLAGS_DEBUG "-g -pg ${CMAKE_CXX_FLAGS}")


find_package(Boost 1.65 COMPONENTS context system log date_time thread chrono regex random REQUIRED)
include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIRS})

find_package(Libgo 3.1 REQUIRED)
include_directories(${Libgo_INCLUDE_DIR})
link_directories(${Libgo_LIBRARY_DIR})
if(ENABLE_AZMQ)
    find_package(ZeroMQ 4.0 REQUIRED)
    include_directories(${ZeroMQ_INCLUDE_DIRS})

    include_directories(/usr/local/azmq/include)
endif()
file(GLOB_RECURSE SRC_LIST "libgonet/*.cpp" "libgonet/*.h")
include_directories("${PROJECT_SOURCE_DIR}")
include_directories("${PROJECT_SOURCE_DIR}/libgonet")


set(TARGET "libgonet")

add_library("${TARGET}" STATIC ${SRC_LIST})

# add_subdirectory(test)

# add_subdirectory(app)

install(TARGETS ${TARGET} LIBRARY DESTINATION "lib" ARCHIVE DESTINATION "lib")
install(DIRECTORY libgonet/ DESTINATION "include/libgonet" FILES_MATCHING PATTERN "*.h")


if(ENABLE_TUTORIAL)
	add_subdirectory(tutorial)
endif()
