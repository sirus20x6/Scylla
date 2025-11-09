cmake_minimum_required(VERSION 3.15)

# Project definition
project(Scylla
    VERSION 0.9.9
    DESCRIPTION "Advanced PE import table reconstruction tool"
    LANGUAGES CXX C
)

# C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build" FORCE)
endif()

# Options
option(BUILD_GUI "Build the GUI application (Windows/Wine only)" ON)
option(BUILD_IMGUI_GUI "Build the Dear ImGui GUI (cross-platform)" ON)
option(BUILD_CLI "Build the command-line interface" ON)
option(BUILD_SHARED_LIB "Build Scylla as a shared library" ON)
option(BUILD_STATIC_LIB "Build Scylla as a static library" ON)
option(BUILD_PYTHON_BINDINGS "Build Python bindings (pybind11)" OFF)
option(ENABLE_WINE_SUPPORT "Enable Wine-specific compatibility features" ON)
option(BUILD_TESTS "Build test suite" OFF)

# Platform detection
if(WIN32)
    set(SCYLLA_PLATFORM "Windows")
    add_compile_definitions(SCYLLA_WINDOWS)
elseif(UNIX AND NOT APPLE)
    set(SCYLLA_PLATFORM "Linux")
    add_compile_definitions(SCYLLA_LINUX)
elseif(APPLE)
    set(SCYLLA_PLATFORM "macOS")
    add_compile_definitions(SCYLLA_MACOS)
endif()

# Wine detection
if(ENABLE_WINE_SUPPORT AND WIN32)
    add_compile_definitions(SCYLLA_WINE_COMPAT)
endif()

message(STATUS "Scylla ${PROJECT_VERSION} for ${SCYLLA_PLATFORM}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")

# Compiler settings
if(MSVC)
    # MSVC-specific settings
    add_compile_options(/W4 /WX- /MP)
    add_compile_definitions(_UNICODE UNICODE _CRT_SECURE_NO_WARNINGS)
    # Enable static runtime for release builds
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
    endif()
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # GCC/Clang settings
    add_compile_options(
        -Wall
        -Wextra
        -pedantic
        -Wno-unused-parameter
        -Wno-missing-field-initializers
    )

    # MinGW-specific settings for cross-compilation
    if(MINGW)
        add_compile_options(-municode)
        add_compile_definitions(UNICODE _UNICODE)
    endif()
endif()

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Dependencies
add_subdirectory(tinyxml)
add_subdirectory(diStorm)

# Core library
add_subdirectory(libScylla)

# GUI application (Windows/Wine only)
if(BUILD_GUI AND (WIN32 OR MINGW))
    add_subdirectory(ScyllaGUI)
endif()

# CLI application (cross-platform)
if(BUILD_CLI)
    add_subdirectory(ScyllaCLI)
endif()

# Dear ImGui GUI (cross-platform)
if(BUILD_IMGUI_GUI)
    add_subdirectory(gui-imgui)
endif()

# Plugins
add_subdirectory(Plugins)

# Tests
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Python bindings
if(BUILD_PYTHON_BINDINGS)
    add_subdirectory(python)
endif()

# Installation rules
include(GNUInstallDirs)

# Install license and documentation
install(FILES
    LICENSE
    README.md
    COMPILING
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
)

# Package configuration
set(CPACK_PACKAGE_NAME "Scylla")
set(CPACK_PACKAGE_VENDOR "Scylla Project")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "PE Import Table Reconstruction Tool")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_INSTALL_DIRECTORY "Scylla")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")

if(WIN32)
    set(CPACK_GENERATOR "ZIP;NSIS")
else()
    set(CPACK_GENERATOR "TGZ;DEB;RPM")
endif()

include(CPack)

# Print configuration summary
message(STATUS "")
message(STATUS "Configuration Summary:")
message(STATUS "  Platform: ${SCYLLA_PLATFORM}")
message(STATUS "  Build GUI: ${BUILD_GUI}")
message(STATUS "  Build ImGui GUI: ${BUILD_IMGUI_GUI}")
message(STATUS "  Build CLI: ${BUILD_CLI}")
message(STATUS "  Build Shared Library: ${BUILD_SHARED_LIB}")
message(STATUS "  Build Static Library: ${BUILD_STATIC_LIB}")
message(STATUS "  Build Python Bindings: ${BUILD_PYTHON_BINDINGS}")
message(STATUS "  Wine Support: ${ENABLE_WINE_SUPPORT}")
message(STATUS "  Build Tests: ${BUILD_TESTS}")
message(STATUS "")
