# FindWine.cmake - Locate Wine development libraries
#
# This module defines:
#  WINE_FOUND - System has Wine development libraries
#  WINE_INCLUDE_DIRS - Wine include directories
#  WINE_LIBRARIES - Wine libraries to link against
#  WINE_LIBRARY_DIRS - Wine library directories
#  WINE_VERSION - Wine version

# Try to find wine using pkg-config first
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(PC_WINE QUIET wine)
endif()

# Find wine executable to determine version and paths
find_program(WINE_EXECUTABLE
    NAMES wine wine64
    HINTS ${PC_WINE_PREFIX}
    PATH_SUFFIXES bin
)

if(WINE_EXECUTABLE)
    execute_process(
        COMMAND ${WINE_EXECUTABLE} --version
        OUTPUT_VARIABLE WINE_VERSION_OUTPUT
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    string(REGEX REPLACE "wine-([0-9]+\\.[0-9]+\\.?[0-9]*)" "\\1" WINE_VERSION "${WINE_VERSION_OUTPUT}")
endif()

# Common Wine include paths
set(WINE_INCLUDE_SEARCH_PATHS
    /usr/include/wine
    /usr/include/wine/windows
    /usr/local/include/wine
    /usr/local/include/wine/windows
    /opt/wine-stable/include
    /opt/wine-stable/include/wine
    /opt/wine-devel/include
    /opt/wine-devel/include/wine
    ${PC_WINE_INCLUDE_DIRS}
)

# Find Wine Windows headers
find_path(WINE_INCLUDE_DIR
    NAMES windows.h windef.h
    PATHS ${WINE_INCLUDE_SEARCH_PATHS}
    PATH_SUFFIXES wine/windows windows
)

# Find Wine MSVCRT headers (for CRT functions)
find_path(WINE_MSVCRT_INCLUDE_DIR
    NAMES msvcrt/stdio.h
    PATHS ${WINE_INCLUDE_SEARCH_PATHS}
    PATH_SUFFIXES wine/msvcrt msvcrt
)

# Common Wine library paths
set(WINE_LIBRARY_SEARCH_PATHS
    /usr/lib/wine
    /usr/lib64/wine
    /usr/lib/x86_64-linux-gnu/wine
    /usr/lib/i386-linux-gnu/wine
    /usr/local/lib/wine
    /usr/local/lib64/wine
    /opt/wine-stable/lib
    /opt/wine-stable/lib64
    /opt/wine-devel/lib
    /opt/wine-devel/lib64
    ${PC_WINE_LIBRARY_DIRS}
)

# Find essential Wine libraries
# Wine libraries typically have .dll.so extension
find_library(WINE_KERNEL32
    NAMES kernel32.dll.so kernel32
    PATHS ${WINE_LIBRARY_SEARCH_PATHS}
    PATH_SUFFIXES wine x86_64-linux-gnu/wine i386-linux-gnu/wine
)

find_library(WINE_NTDLL
    NAMES ntdll.dll.so ntdll
    PATHS ${WINE_LIBRARY_SEARCH_PATHS}
    PATH_SUFFIXES wine x86_64-linux-gnu/wine i386-linux-gnu/wine
)

find_library(WINE_ADVAPI32
    NAMES advapi32.dll.so advapi32
    PATHS ${WINE_LIBRARY_SEARCH_PATHS}
    PATH_SUFFIXES wine x86_64-linux-gnu/wine i386-linux-gnu/wine
)

find_library(WINE_PSAPI
    NAMES psapi.dll.so psapi
    PATHS ${WINE_LIBRARY_SEARCH_PATHS}
    PATH_SUFFIXES wine x86_64-linux-gnu/wine i386-linux-gnu/wine
)

find_library(WINE_DBGHELP
    NAMES dbghelp.dll.so dbghelp
    PATHS ${WINE_LIBRARY_SEARCH_PATHS}
    PATH_SUFFIXES wine x86_64-linux-gnu/wine i386-linux-gnu/wine
)

find_library(WINE_IMAGEHLP
    NAMES imagehlp.dll.so imagehlp
    PATHS ${WINE_LIBRARY_SEARCH_PATHS}
    PATH_SUFFIXES wine x86_64-linux-gnu/wine i386-linux-gnu/wine
)

find_library(WINE_SHLWAPI
    NAMES shlwapi.dll.so shlwapi
    PATHS ${WINE_LIBRARY_SEARCH_PATHS}
    PATH_SUFFIXES wine x86_64-linux-gnu/wine i386-linux-gnu/wine
)

# Set include directories
set(WINE_INCLUDE_DIRS
    ${WINE_INCLUDE_DIR}
    ${WINE_MSVCRT_INCLUDE_DIR}
)

# Set library list
set(WINE_LIBRARIES)
if(WINE_KERNEL32)
    list(APPEND WINE_LIBRARIES ${WINE_KERNEL32})
endif()
if(WINE_NTDLL)
    list(APPEND WINE_LIBRARIES ${WINE_NTDLL})
endif()
if(WINE_ADVAPI32)
    list(APPEND WINE_LIBRARIES ${WINE_ADVAPI32})
endif()
if(WINE_PSAPI)
    list(APPEND WINE_LIBRARIES ${WINE_PSAPI})
endif()
if(WINE_DBGHELP)
    list(APPEND WINE_LIBRARIES ${WINE_DBGHELP})
endif()
if(WINE_IMAGEHLP)
    list(APPEND WINE_LIBRARIES ${WINE_IMAGEHLP})
endif()
if(WINE_SHLWAPI)
    list(APPEND WINE_LIBRARIES ${WINE_SHLWAPI})
endif()

# Extract library directory
if(WINE_KERNEL32)
    get_filename_component(WINE_LIBRARY_DIR ${WINE_KERNEL32} DIRECTORY)
    set(WINE_LIBRARY_DIRS ${WINE_LIBRARY_DIR})
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Wine
    REQUIRED_VARS
        WINE_INCLUDE_DIR
        WINE_LIBRARIES
    VERSION_VAR WINE_VERSION
)

mark_as_advanced(
    WINE_INCLUDE_DIR
    WINE_MSVCRT_INCLUDE_DIR
    WINE_KERNEL32
    WINE_NTDLL
    WINE_ADVAPI32
    WINE_PSAPI
    WINE_DBGHELP
    WINE_IMAGEHLP
    WINE_SHLWAPI
)

# Debug output
if(Wine_FOUND AND NOT Wine_FIND_QUIETLY)
    message(STATUS "Found Wine: ${WINE_VERSION}")
    message(STATUS "  Include dirs: ${WINE_INCLUDE_DIRS}")
    message(STATUS "  Libraries: ${WINE_LIBRARIES}")
endif()
