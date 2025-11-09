# ScyllaCLI - Cross-platform command-line interface
cmake_minimum_required(VERSION 3.15)

# CLI source files
set(SCYLLA_CLI_SOURCES
    enhanced_cli_main.cpp
    Commands.h
    AnalyzeCommand.cpp
    InfoCommand.cpp
    DumpCommand.h
    DumpCommand.cpp
    Utilities.cpp
)

# Create executable
add_executable(ScyllaCLI
    ${SCYLLA_CLI_SOURCES}
)

# Set executable name
set_target_properties(ScyllaCLI PROPERTIES
    OUTPUT_NAME "scylla-cli"
)

# Link with core library
if(TARGET ScyllaLib)
    target_link_libraries(ScyllaCLI PRIVATE Scylla::Scylla)
elseif(TARGET ScyllaLibStatic)
    target_link_libraries(ScyllaCLI PRIVATE Scylla::Scylla)
else()
    message(FATAL_ERROR "ScyllaCLI requires ScyllaLib or ScyllaLibStatic")
endif()

# Platform-specific libraries
if(UNIX AND NOT APPLE)
    target_link_libraries(ScyllaCLI PRIVATE pthread dl)
elseif(APPLE)
    find_library(COREFOUNDATION_LIBRARY CoreFoundation)
    target_link_libraries(ScyllaCLI PRIVATE ${COREFOUNDATION_LIBRARY})
elseif(WIN32)
    target_link_libraries(ScyllaCLI PRIVATE
        psapi
        dbghelp
        shlwapi
    )
endif()

# Installation
install(TARGETS ScyllaCLI
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
