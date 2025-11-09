# libScylla - Core Scylla library (cross-platform)
cmake_minimum_required(VERSION 3.15)

# Source directory (original sources are in ../Scylla)
set(SCYLLA_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../Scylla)

# Core library sources (non-GUI)
set(LIBSCYLLA_CORE_SOURCES
    ${SCYLLA_SRC_DIR}/ApiReader.cpp
    ${SCYLLA_SRC_DIR}/Architecture.cpp
    ${SCYLLA_SRC_DIR}/Configuration.cpp
    ${SCYLLA_SRC_DIR}/ConfigurationHolder.cpp
    ${SCYLLA_SRC_DIR}/DeviceNameResolver.cpp
    ${SCYLLA_SRC_DIR}/DllInjection.cpp
    ${SCYLLA_SRC_DIR}/DllInjectionPlugin.cpp
    ${SCYLLA_SRC_DIR}/FunctionExport.cpp
    ${SCYLLA_SRC_DIR}/IATReferenceScan.cpp
    ${SCYLLA_SRC_DIR}/IATSearch.cpp
    ${SCYLLA_SRC_DIR}/ImportRebuilder.cpp
    ${SCYLLA_SRC_DIR}/ImportsHandling.cpp
    ${SCYLLA_SRC_DIR}/Logger.cpp
    ${SCYLLA_SRC_DIR}/NativeWinApi.cpp
    ${SCYLLA_SRC_DIR}/PeParser.cpp
    ${SCYLLA_SRC_DIR}/PeRebuild.cpp
    ${SCYLLA_SRC_DIR}/PluginLoader.cpp
    ${SCYLLA_SRC_DIR}/ProcessAccessHelp.cpp
    ${SCYLLA_SRC_DIR}/ProcessLister.cpp
    ${SCYLLA_SRC_DIR}/Scylla.cpp
    ${SCYLLA_SRC_DIR}/StringConversion.cpp
    ${SCYLLA_SRC_DIR}/SystemInformation.cpp
    ${SCYLLA_SRC_DIR}/TreeImportExport.cpp
)

# Platform abstraction layer sources
set(LIBSCYLLA_PLATFORM_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/PlatformAbstraction.h
)

# Add platform-specific implementation
if(WIN32)
    list(APPEND LIBSCYLLA_PLATFORM_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/PlatformWindows.cpp
    )
elseif(APPLE)
    list(APPEND LIBSCYLLA_PLATFORM_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/PlatformMacOS.cpp
    )
elseif(UNIX)
    list(APPEND LIBSCYLLA_PLATFORM_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/PlatformLinux.cpp
    )
endif()

# Enhanced features
set(LIBSCYLLA_ENHANCED_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/ParallelIATScanner.h
    ${CMAKE_CURRENT_SOURCE_DIR}/ParallelIATScanner.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Cache.h
    ${CMAKE_CURRENT_SOURCE_DIR}/Cache.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/PackerDetector.h
    ${CMAKE_CURRENT_SOURCE_DIR}/PackerDetector.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Configuration.h
    ${CMAKE_CURRENT_SOURCE_DIR}/Configuration.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SecurityAnalyzer.h
    ${CMAKE_CURRENT_SOURCE_DIR}/SecurityAnalyzer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/SymbolResolver.h
    ${CMAKE_CURRENT_SOURCE_DIR}/SymbolResolver.cpp
)

set(LIBSCYLLA_CORE_HEADERS
    ${SCYLLA_SRC_DIR}/ApiReader.h
    ${SCYLLA_SRC_DIR}/Architecture.h
    ${SCYLLA_SRC_DIR}/Configuration.h
    ${SCYLLA_SRC_DIR}/ConfigurationHolder.h
    ${SCYLLA_SRC_DIR}/DeviceNameResolver.h
    ${SCYLLA_SRC_DIR}/DllInjection.h
    ${SCYLLA_SRC_DIR}/DllInjectionPlugin.h
    ${SCYLLA_SRC_DIR}/FunctionExport.h
    ${SCYLLA_SRC_DIR}/IATReferenceScan.h
    ${SCYLLA_SRC_DIR}/IATSearch.h
    ${SCYLLA_SRC_DIR}/ImportRebuilder.h
    ${SCYLLA_SRC_DIR}/ImportsHandling.h
    ${SCYLLA_SRC_DIR}/Logger.h
    ${SCYLLA_SRC_DIR}/NativeWinApi.h
    ${SCYLLA_SRC_DIR}/PeParser.h
    ${SCYLLA_SRC_DIR}/PickApiGui.h
    ${SCYLLA_SRC_DIR}/PickDllGui.h
    ${SCYLLA_SRC_DIR}/PluginLoader.h
    ${SCYLLA_SRC_DIR}/ProcessAccessHelp.h
    ${SCYLLA_SRC_DIR}/ProcessLister.h
    ${SCYLLA_SRC_DIR}/Scylla.h
    ${SCYLLA_SRC_DIR}/StringConversion.h
    ${SCYLLA_SRC_DIR}/SystemInformation.h
    ${SCYLLA_SRC_DIR}/Thunks.h
    ${SCYLLA_SRC_DIR}/TreeImportExport.h
)

# Build shared library if requested
if(BUILD_SHARED_LIB)
    add_library(ScyllaLib SHARED
        ${LIBSCYLLA_CORE_SOURCES}
        ${LIBSCYLLA_CORE_HEADERS}
        ${LIBSCYLLA_PLATFORM_SOURCES}
        ${LIBSCYLLA_ENHANCED_SOURCES}
    )

    target_compile_definitions(ScyllaLib PRIVATE
        SCYLLA_EXPORTS
    )

    set_target_properties(ScyllaLib PROPERTIES
        OUTPUT_NAME "Scylla"
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )

    # Install shared library
    install(TARGETS ScyllaLib
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()

# Build static library if requested
if(BUILD_STATIC_LIB)
    add_library(ScyllaLibStatic STATIC
        ${LIBSCYLLA_CORE_SOURCES}
        ${LIBSCYLLA_CORE_HEADERS}
        ${LIBSCYLLA_PLATFORM_SOURCES}
        ${LIBSCYLLA_ENHANCED_SOURCES}
    )

    set_target_properties(ScyllaLibStatic PROPERTIES
        OUTPUT_NAME "ScyllaStatic"
        POSITION_INDEPENDENT_CODE ON
    )

    # Install static library
    install(TARGETS ScyllaLibStatic
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()

# Configure both libraries with same settings
foreach(target ScyllaLib ScyllaLibStatic)
    if(TARGET ${target})
        # Include directories
        target_include_directories(${target} PUBLIC
            ${SCYLLA_SRC_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/../diStorm/include
            ${CMAKE_CURRENT_SOURCE_DIR}/../tinyxml
        )

        # Link dependencies
        target_link_libraries(${target} PUBLIC
            diStorm
            tinyxml
        )

        # Platform-specific settings
        if(WIN32)
            target_compile_definitions(${target} PRIVATE
                _UNICODE
                UNICODE
                WIN32_LEAN_AND_MEAN
                NOMINMAX
            )

            target_link_libraries(${target} PUBLIC
                psapi
                dbghelp
                shlwapi
                wintrust
                imagehlp
            )
        elseif(UNIX)
            # For Linux/macOS we'll need to implement process access differently
            target_compile_definitions(${target} PRIVATE
                SCYLLA_POSIX
            )

            if(APPLE)
                # macOS specific libraries
                find_library(COREFOUNDATION_LIBRARY CoreFoundation)
                target_link_libraries(${target} PUBLIC ${COREFOUNDATION_LIBRARY})
            else()
                # Linux specific libraries
                target_link_libraries(${target} PUBLIC dl pthread)
            endif()
        endif()

        # C++17 features
        target_compile_features(${target} PUBLIC cxx_std_17)

        # Compiler warnings
        if(MSVC)
            target_compile_options(${target} PRIVATE /W4)
        else()
            target_compile_options(${target} PRIVATE
                -Wall -Wextra -pedantic
                -Wno-unused-parameter
                -Wno-missing-field-initializers
            )
        endif()
    endif()
endforeach()

# Install headers
install(FILES ${LIBSCYLLA_CORE_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/scylla
)

# Create an alias for easier linking
if(TARGET ScyllaLib)
    add_library(Scylla::Scylla ALIAS ScyllaLib)
elseif(TARGET ScyllaLibStatic)
    add_library(Scylla::Scylla ALIAS ScyllaLibStatic)
endif()
