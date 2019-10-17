

file(GLOB SRCS "*.cpp")

foreach( var ${SRCS})

    string(REGEX REPLACE ".*/" "" var ${var})

    set(target ${var}.t)
    add_executable(${target} ${var})
    target_link_libraries(${target} libgonet libgo dl GTest::Main GTest::GTest pthread 
     	 boost_coroutine boost_context boost_thread boost_system boost_regex pthread)

endforeach()