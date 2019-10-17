
list(APPEND CMAKE_PREFIX_PATH /usr/local/googletest)
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})
message(STATUS "gtest:${GTEST_INCLUDE_DIRS}")

add_subdirectory(unit_test)
add_subdirectory(test)
# add_custom_target(build_unit_test ALL
# COMMAND export CXX_INCLUDE_PATH=${GTest_INCLUDE_DIR}:${Boost_INCLUDE_DIR}
# COMMAND ${CMAKE_MAKE_PROGRAM}
# WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/unit_test
# COMMENT "Original unit_test makefile target"
# DEPEND libgonet
# )

# add_custom_target(build_test ALL
# COMMAND ${CMAKE_MAKE_PROGRAM}
# WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test
# COMMENT "Original test makefile target"
# DEPEND libgonet
# )

# add_custom_target(build_httpd ALL
#     COMMAND ${CMAKE_MAKE_PROGRAM}
#     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/httpd
#     COMMENT "Original httpd makefile target"
#     DEPEND libgonet
# )

# add_custom_target(build_httpd_complete ALL
#     COMMAND ${CMAKE_MAKE_PROGRAM}
#     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/httpd_complete
#     COMMENT "Original httpd_complet makefile target"
#     DEPEND libgonet
# )

# add_custom_target(build_httpd_recursive_epoll ALL
#     COMMAND ${CMAKE_MAKE_PROGRAM}
#     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/httpd_recursive_epoll
#     COMMENT "Original httpd_recursive_epoll makefile target"
#     DEPEND libgonet
# )

# add_custom_target(build_httpd_syscall ALL
#     COMMAND ${CMAKE_MAKE_PROGRAM}
#     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/httpd_syscall
#     COMMENT "Original httpd makefile target"
#     DEPEND libgonet
# )

# add_custom_target(build_pingpong ALL
#     COMMAND ${CMAKE_MAKE_PROGRAM}
#     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/pingpong
#     COMMENT "Original pingpong makefile target"
#     DEPEND libgonet
# )

add_subdirectory(pingpong)
