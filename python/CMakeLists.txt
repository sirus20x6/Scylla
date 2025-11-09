# Python Bindings for Scylla
cmake_minimum_required(VERSION 3.15)

# Find Python
find_package(Python COMPONENTS Interpreter Development REQUIRED)

# Find pybind11
find_package(pybind11 CONFIG)

if(NOT pybind11_FOUND)
    # Download pybind11 if not found
    include(FetchContent)
    FetchContent_Declare(
        pybind11
        GIT_REPOSITORY https://github.com/pybind/pybind11.git
        GIT_TAG v2.11.1
    )
    FetchContent_MakeAvailable(pybind11)
endif()

# Create Python module
pybind11_add_module(pyscylla
    scylla_bindings.cpp
)

# Link with Scylla library
if(TARGET ScyllaLib)
    target_link_libraries(pyscylla PRIVATE ScyllaLib)
elseif(TARGET ScyllaLibStatic)
    target_link_libraries(pyscylla PRIVATE ScyllaLibStatic)
else()
    message(FATAL_ERROR "pyscylla requires ScyllaLib or ScyllaLibStatic")
endif()

# Include directories
target_include_directories(pyscylla PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../libScylla
    ${CMAKE_CURRENT_SOURCE_DIR}/../Scylla
)

# Set output name
set_target_properties(pyscylla PROPERTIES
    OUTPUT_NAME "pyscylla"
    PREFIX "${PYTHON_MODULE_PREFIX}"
    SUFFIX "${PYTHON_MODULE_EXTENSION}"
)

# Installation
install(TARGETS pyscylla
    LIBRARY DESTINATION ${Python_SITEARCH}
)

# Install Python examples
install(DIRECTORY examples/
    DESTINATION share/pyscylla/examples
    FILES_MATCHING PATTERN "*.py"
)
