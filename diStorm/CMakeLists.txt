# diStorm disassembler library
cmake_minimum_required(VERSION 3.15)

# Collect source files
file(GLOB DISTORM_SOURCES
    src/*.c
)

file(GLOB DISTORM_HEADERS
    include/*.h
)

# Create static library
add_library(diStorm STATIC
    ${DISTORM_SOURCES}
)

# Include directories
target_include_directories(diStorm PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Disable warnings for third-party code
if(MSVC)
    target_compile_options(diStorm PRIVATE /W0)
else()
    target_compile_options(diStorm PRIVATE -w)
endif()

# Platform-specific settings
if(WIN32)
    target_compile_definitions(diStorm PRIVATE
        DISTORM_STATIC
    )
endif()

# Set properties
set_target_properties(diStorm PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    C_STANDARD 99
)
