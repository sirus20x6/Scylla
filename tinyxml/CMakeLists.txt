# TinyXML library
cmake_minimum_required(VERSION 3.15)

# Check if source files exist locally
set(TINYXML_SOURCES
    tinystr.cpp
    tinyxml.cpp
    tinyxmlerror.cpp
    tinyxmlparser.cpp
)

set(TINYXML_HEADERS
    tinystr.h
    tinyxml.h
)

# Check if sources exist
set(SOURCES_EXIST TRUE)
foreach(src ${TINYXML_SOURCES})
    if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${src})
        set(SOURCES_EXIST FALSE)
        break()
    endif()
endforeach()

if(NOT SOURCES_EXIST)
    # Try to use system tinyxml
    message(STATUS "TinyXML sources not found locally, trying system package...")
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(TINYXML tinyxml)
    endif()

    if(TINYXML_FOUND)
        message(STATUS "Using system TinyXML")
        add_library(tinyxml INTERFACE)
        target_link_libraries(tinyxml INTERFACE ${TINYXML_LIBRARIES})
        target_include_directories(tinyxml INTERFACE ${TINYXML_INCLUDE_DIRS})
    else()
        message(FATAL_ERROR "TinyXML not found. Please install libtinyxml-dev (apt install libtinyxml-dev) or provide sources locally.")
    endif()
else()
    message(STATUS "Using local TinyXML sources")

    # Create library from local sources
    add_library(tinyxml STATIC
        ${TINYXML_SOURCES}
    )

    target_include_directories(tinyxml PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif()

# Only apply these settings if we built tinyxml ourselves (not using system package)
get_target_property(TINYXML_TYPE tinyxml TYPE)
if(NOT TINYXML_TYPE STREQUAL "INTERFACE_LIBRARY")
    # Disable warnings for third-party code
    if(MSVC)
        target_compile_options(tinyxml PRIVATE /W0)
    else()
        target_compile_options(tinyxml PRIVATE -w)
    endif()

    # Set proper compile definitions
    target_compile_definitions(tinyxml PRIVATE
        TIXML_USE_STL
    )

    # Export for parent project
    set_target_properties(tinyxml PROPERTIES
        POSITION_INDEPENDENT_CODE ON
    )
endif()
