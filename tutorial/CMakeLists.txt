cmake_minimum_required(VERSION 2.8)

###################################################################################
project(tutorial)

set(CMAKE_CXX_FLAGS "-std=c++11 -Wall")

if (CMAKE_BUILD_TYPE)
else()
    set(CMAKE_BUILD_TYPE RELEASE)
endif()

#aux_source_directory(${PROJECT_SOURCE_DIR} SRC_LIST)
file(GLOB SRC_LIST "*.cpp")
message(STATUS "tutorial")
include_directories("${PROJECT_SOURCE_DIR}/../")
link_directories(${PROJECT_BINARY_DIR}/../)
link_directories(${Libgo_LIBRARY_DIR})
message(STATUS "libgo:${Libgo_LIBRARY_DIR}")
set(LINK_ARGS libgonet libgo  boost_context boost_regex boost_system boost_thread pthread dl)
set(LINK_ARGS ${LINK_ARGS} ssl crypto)

foreach(var ${SRC_LIST})
    string(REGEX REPLACE ".*/" "" var ${var})
    string(REGEX REPLACE ".cpp" "" tgt ${var})

    set(target ${tgt}.t)
    add_executable(${target} ${var})
    target_link_libraries(${target} ${LINK_ARGS} rt)
endforeach(var)

