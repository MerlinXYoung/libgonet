# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

#[=======================================================================[.rst:
FindLibgo
-------

Finds the Libgo library.

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``Libgo::Libgo``
  The Libgo library

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``Libgo_FOUND``
  True if the system has the Libgo library.
# ``Libgo_VERSION``
#   The version of the Libgo library which was found.
``Libgo_INCLUDE_DIRS``
  Include directories needed to use Libgo.
``Libgo_LIBRARIES``
  Libraries needed to link to Libgo.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``Libgo_INCLUDE_DIR``
  The directory containing ``libgo.h``.
``Libgo_LIBRARY``
  The path to the Libgo library.

HINTS
^^^^^
Libgo_ROOT_DIR
Where to find the base directory of Libgo.

#]=======================================================================]
find_path(Libgo_INCLUDE_DIR
    libgo/libgo.h
    # PATHS /usr/include /usr/local/include ${Libgo_DIR}/include
    HINTS ${Libgo_DIR}/include
    # PATH_SUFFIXES libgo
)

find_library(Libgo_LIBRARY
    libgo
    PATHS /usr/lib /usr/local/lib ${Libgo_DIR}/lib
)

include( FindPackageHandleStandardArgs )

find_package_handle_standard_args(Libgo  
    DEBAULT_MSG
    Libgo_INCLUDE_DIR Libgo_LIBRARY

) 

# find_package_handle_standard_args(Libgo  
#     FOUND_VAR Libgo_FOUND
#     REQUIRED_VARS Libgo_INCLUDE_DIR Libgo_LIBRARY
# #   [VERSION_VAR <version-var>]
# #   [HANDLE_COMPONENTS]
# #   [CONFIG_MODE]
#     FAIL_MESSAGE "Can't Find Libgo !"
# ) 

if(Libgo-FOUND)
    message(STATUS "Libgo:${Libgo_INCLUDE_DIR}")
    set(Libgo_LIBRARIES ${Libgo_LIBRARY})
    set(Libgo_INCLUDE_DIRS ${Libgo_INCLUDE_DIR})
    # set(Libgo_DEFINITIONS ${PC_Libgo_CFLAGS_OTHER})
    mark_as_advanced(
    Libgo_INCLUDE_DIR
    Libgo_LIBRARY
    )
endif()

if(Libgo_FOUND AND NOT TARGET Libgo::Libgo)
  add_library(Libgo::Libgo UNKNOWN IMPORTED)
  set_target_properties(Libgo::Libgo PROPERTIES
    IMPORTED_LOCATION "${Libgo_LIBRARY}"
    # INTERFACE_COMPILE_OPTIONS "${PC_Libgo_CFLAGS_OTHER}"
    INTERFACE_INCLUDE_DIRECTORIES "${Libgo_INCLUDE_DIR}"
  )
endif()

# if(Libgo_FOUND)
#   if (NOT TARGET Libgo::Libgo)
#     add_library(Libgo::Libgo UNKNOWN IMPORTED)
#   endif()
#   if (Libgo_LIBRARY_RELEASE)
#     set_property(TARGET Libgo::Libgo APPEND PROPERTY
#       IMPORTED_CONFIGURATIONS RELEASE
#     )
#     set_target_properties(Libgo::Libgo PROPERTIES
#       IMPORTED_LOCATION_RELEASE "${Libgo_LIBRARY_RELEASE}"
#     )
#   endif()
#   if (Libgo_LIBRARY_DEBUG)
#     set_property(TARGET Libgo::Libgo APPEND PROPERTY
#       IMPORTED_CONFIGURATIONS DEBUG
#     )
#     set_target_properties(Libgo::Libgo PROPERTIES
#       IMPORTED_LOCATION_DEBUG "${Libgo_LIBRARY_DEBUG}"
#     )
#   endif()
#   set_target_properties(Libgo::Libgo PROPERTIES
#     # INTERFACE_COMPILE_OPTIONS "${PC_Libgo_CFLAGS_OTHER}"
#     INTERFACE_INCLUDE_DIRECTORIES "${Libgo_INCLUDE_DIR}"
#   )
# endif()
