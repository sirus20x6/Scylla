# Scylla Dear ImGui GUI
cmake_minimum_required(VERSION 3.15)

# Find or fetch Dear ImGui
set(IMGUI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../imgui" CACHE PATH "Dear ImGui directory")

if(NOT EXISTS "${IMGUI_DIR}/imgui.h")
    message(STATUS "Dear ImGui not found, downloading...")
    include(FetchContent)
    FetchContent_Declare(
        imgui
        GIT_REPOSITORY https://github.com/ocornut/imgui.git
        GIT_TAG v1.90.9
    )
    FetchContent_MakeAvailable(imgui)
    set(IMGUI_DIR "${imgui_SOURCE_DIR}")
endif()

# Find or fetch GLFW
find_package(glfw3 3.3 QUIET)

if(NOT glfw3_FOUND)
    message(STATUS "GLFW not found, downloading...")
    include(FetchContent)
    FetchContent_Declare(
        glfw
        GIT_REPOSITORY https://github.com/glfw/glfw.git
        GIT_TAG 3.3.8
    )
    set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
    set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(glfw)
endif()

# Find OpenGL
find_package(OpenGL REQUIRED)

# Dear ImGui sources
set(IMGUI_SOURCES
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_demo.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
    ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
)

# Scylla GUI executable
add_executable(ScyllaGUI
    main.cpp
    ScyllaGUI.h
    ScyllaGUI.cpp
    ${IMGUI_SOURCES}
)

# Include directories
target_include_directories(ScyllaGUI PRIVATE
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
    ${CMAKE_CURRENT_SOURCE_DIR}/../libScylla
)

# Link libraries
target_link_libraries(ScyllaGUI PRIVATE
    glfw
    OpenGL::GL
)

# Link with Scylla library if available
if(TARGET ScyllaLib)
    target_link_libraries(ScyllaGUI PRIVATE ScyllaLib)
elseif(TARGET ScyllaLibStatic)
    target_link_libraries(ScyllaGUI PRIVATE ScyllaLibStatic)
endif()

# C++17
target_compile_features(ScyllaGUI PRIVATE cxx_std_17)

# Platform-specific settings
if(WIN32)
    # Windows-specific settings
    target_compile_definitions(ScyllaGUI PRIVATE
        _UNICODE
        UNICODE
        NOMINMAX
    )

    # Set subsystem to Windows GUI
    set_target_properties(ScyllaGUI PROPERTIES
        WIN32_EXECUTABLE TRUE
    )
elseif(APPLE)
    # macOS-specific settings
    find_library(COCOA_LIBRARY Cocoa)
    find_library(IOKIT_LIBRARY IOKit)
    find_library(COREVIDEO_LIBRARY CoreVideo)
    target_link_libraries(ScyllaGUI PRIVATE
        ${COCOA_LIBRARY}
        ${IOKIT_LIBRARY}
        ${COREVIDEO_LIBRARY}
    )
elseif(UNIX)
    # Linux-specific settings
    target_link_libraries(ScyllaGUI PRIVATE
        dl
        pthread
    )
endif()

# Installation
install(TARGETS ScyllaGUI
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Copy Dear ImGui license
if(EXISTS "${IMGUI_DIR}/LICENSE.txt")
    install(FILES "${IMGUI_DIR}/LICENSE.txt"
        DESTINATION ${CMAKE_INSTALL_DOCDIR}/licenses
        RENAME imgui-LICENSE.txt
    )
endif()
