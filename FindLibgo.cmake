
find_path(Libgo_INCLUDE_DIR
    libgo/coroutine.h
    PATHS /usr/include /usr/local/include ${Libgo_DIR}/include
)

find_library(Libgo_LIBRARIES
    libgo 
    PATHS /usr/lib /usr/local/lib ${Libgo_DIR}/lib 
)

if(NOT Libgo_INCLUDE_DIR) 
    set(Libgo_NOTFOUND ON)
    message(WARNING "libgo not found! include")
elseif(NOT Libgo_LIBRARIES)
    set(Libgo_NOTFOUND ON)  
    message(WARNING "libgo not found! lib")
else()
    string(REPLACE "liblibgo.a" "" ${Libgo_LIBRARIES} Libgo_LIBRARY_DIR)
endif()