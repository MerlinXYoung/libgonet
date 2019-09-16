
find_path(Libgo_INCLUDE_DIR
libgo/libgo.h
PATHS /usr/include /usr/local/include ${Libgo_DIR}/include
)

find_library(Libgo_LIBRARIES
libgo
PATHS /usr/lib /usr/local/lib ${Libgo_DIR}/lib
)
message(STATUS "Libgo:${Libgo_INCLUDE_DIR} ${Libgo_LIBRARIES}")
string(COMPARE NOTEQUAL "${Libgo_INCLUDE_DIR}"  "" Libgo_INCLUDE_DIR-NOTFOUND)
string(COMPARE NOTEQUAL "${Libgo_LIBRARIES}"  "" Libgo_LIBRARIES-NOTFOUND)
#message(STATUS "Libgo:${Libgo_INCLUDE_DIR-NOTFOUND} ${Libgo_LIBRARIES-NOTFOUND}")
if(Libgo_INCLUDE_DIR-NOTFOUND)
message(WARNING "Libgo_INCLUDE_DIR-NOTFOUND")
set(Libgo-NOTFOUND ON)
elseif(Libgo_LIBRARIES-NOTFOUND)
message(WARNING "Libgo_LIBRARIES-NOTFOUND")
set(Libgo-NOTFOUND ON)
else()
set(Libgo_FOUND ON)
string(REPLACE "/liblibgo.a" "" Libgo_LIBRARY_DIR ${Libgo_LIBRARIES})
string(COMPARE EQUAL ${Libgo_LIBRARY_DIR} ${Libgo_LIBRARIES} _EQUAL)
if(_EQUAL)
string(REPLACE "/liblibgo.so" "" Libgo_LIBRARY_DIR ${Libgo_LIBRARIES})
endif()
message(STATUS "Libgo_LIBRARY_DIR:${Libgo_LIBRARY_DIR}")
endif()