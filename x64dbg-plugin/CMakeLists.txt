# Scylla x64dbg Plugin
cmake_minimum_required(VERSION 3.15)

project(ScyllaX64DbgPlugin)

# This plugin is Windows-only
if(NOT WIN32)
    message(STATUS "x64dbg plugin is Windows-only, skipping...")
    return()
endif()

# Plugin source files
set(PLUGIN_SOURCES
    ScyllaPlugin.cpp
    plugin.h
    pluginmain.h
)

# Build as shared library (DLL)
add_library(ScyllaX64Dbg SHARED ${PLUGIN_SOURCES})

# Set output name
set_target_properties(ScyllaX64Dbg PROPERTIES
    OUTPUT_NAME "ScyllaX64Dbg"
    PREFIX ""  # No 'lib' prefix
    SUFFIX ".dp32"  # x64dbg 32-bit plugin extension
)

# For 64-bit build
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(ScyllaX64Dbg PROPERTIES
        SUFFIX ".dp64"  # x64dbg 64-bit plugin extension
    )
endif()

# Compile definitions
target_compile_definitions(ScyllaX64Dbg PRIVATE
    _UNICODE
    UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

# C++17
target_compile_features(ScyllaX64Dbg PRIVATE cxx_std_17)

# Link against Windows libraries
target_link_libraries(ScyllaX64Dbg PRIVATE
    user32
    kernel32
    comdlg32
)

# Optional: Link against ScyllaLib for full functionality
if(TARGET ScyllaLib)
    target_link_libraries(ScyllaX64Dbg PRIVATE ScyllaLib)
    target_compile_definitions(ScyllaX64Dbg PRIVATE SCYLLA_LIB_AVAILABLE)
endif()

# Installation
install(TARGETS ScyllaX64Dbg
    RUNTIME DESTINATION x64dbg/plugins
    LIBRARY DESTINATION x64dbg/plugins
)

# Installation instructions
install(FILES README.md
    DESTINATION x64dbg/plugins/Scylla
)

message(STATUS "Scylla x64dbg plugin configured")
message(STATUS "  Output: ${CMAKE_CURRENT_BINARY_DIR}/ScyllaX64Dbg.dp{32|64}")
message(STATUS "  Install to: x64dbg/plugins directory")
