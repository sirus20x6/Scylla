# Scylla REST API Server
cmake_minimum_required(VERSION 3.15)

# API Server sources
set(SCYLLA_API_SOURCES
    APIServer.h
    APIServer.cpp
    main.cpp
)

# Create executable
add_executable(ScyllaAPI
    ${SCYLLA_API_SOURCES}
)

# Set executable name
set_target_properties(ScyllaAPI PROPERTIES
    OUTPUT_NAME "scylla-api"
)

# Link with core library
if(TARGET ScyllaLib)
    target_link_libraries(ScyllaAPI PRIVATE Scylla::Scylla)
elseif(TARGET ScyllaLibStatic)
    target_link_libraries(ScyllaAPI PRIVATE Scylla::Scylla)
else()
    message(FATAL_ERROR "ScyllaAPI requires ScyllaLib or ScyllaLibStatic")
endif()

# Include directories
target_include_directories(ScyllaAPI PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../libScylla
    ${CMAKE_CURRENT_SOURCE_DIR}/../Scylla
)

# Platform-specific libraries
if(UNIX AND NOT APPLE)
    target_link_libraries(ScyllaAPI PRIVATE pthread dl)
elseif(APPLE)
    find_library(COREFOUNDATION_LIBRARY CoreFoundation)
    target_link_libraries(ScyllaAPI PRIVATE ${COREFOUNDATION_LIBRARY})
elseif(WIN32)
    target_link_libraries(ScyllaAPI PRIVATE
        ws2_32
        psapi
        dbghelp
    )
endif()

# C++17 features
target_compile_features(ScyllaAPI PUBLIC cxx_std_17)

# Installation
install(TARGETS ScyllaAPI
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install examples
install(DIRECTORY examples/
    DESTINATION share/scylla/api-examples
    FILES_MATCHING PATTERN "*.py" PATTERN "*.sh"
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                GROUP_READ GROUP_EXECUTE
                WORLD_READ WORLD_EXECUTE
)

message(STATUS "Configured Scylla REST API Server")
