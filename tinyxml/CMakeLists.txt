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
    message(STATUS "TinyXML sources not found locally, fetching from repository...")
    include(FetchContent)

    FetchContent_Declare(
        tinyxml_src
        URL https://sourceforge.net/projects/tinyxml/files/tinyxml/2.6.2/tinyxml_2_6_2.zip
        URL_HASH MD5=2a0aaf609c9e670ec9748cd01ed52dae
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )

    FetchContent_MakeAvailable(tinyxml_src)

    # Create library from fetched content
    add_library(tinyxml STATIC
        ${tinyxml_src_SOURCE_DIR}/tinystr.cpp
        ${tinyxml_src_SOURCE_DIR}/tinyxml.cpp
        ${tinyxml_src_SOURCE_DIR}/tinyxmlerror.cpp
        ${tinyxml_src_SOURCE_DIR}/tinyxmlparser.cpp
    )

    target_include_directories(tinyxml PUBLIC
        ${tinyxml_src_SOURCE_DIR}
    )
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
