# ScyllaGUI - Windows GUI application using WTL
cmake_minimum_required(VERSION 3.15)

# Only build on Windows/MinGW
if(NOT WIN32 AND NOT MINGW)
    message(FATAL_ERROR "ScyllaGUI can only be built on Windows or with MinGW cross-compilation")
endif()

# Source directory
set(SCYLLA_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../Scylla)

# GUI-specific sources
set(SCYLLA_GUI_SOURCES
    ${SCYLLA_SRC_DIR}/main.cpp
    ${SCYLLA_SRC_DIR}/MainGui.cpp
    ${SCYLLA_SRC_DIR}/AboutGui.cpp
    ${SCYLLA_SRC_DIR}/DisassemblerGui.cpp
    ${SCYLLA_SRC_DIR}/DonateGui.cpp
    ${SCYLLA_SRC_DIR}/DumpMemoryGui.cpp
    ${SCYLLA_SRC_DIR}/DumpSectionGui.cpp
    ${SCYLLA_SRC_DIR}/OptionsGui.cpp
    ${SCYLLA_SRC_DIR}/PickApiGui.cpp
    ${SCYLLA_SRC_DIR}/PickDllGui.cpp
)

set(SCYLLA_GUI_HEADERS
    ${SCYLLA_SRC_DIR}/MainGui.h
    ${SCYLLA_SRC_DIR}/AboutGui.h
    ${SCYLLA_SRC_DIR}/DisassemblerGui.h
    ${SCYLLA_SRC_DIR}/DonateGui.h
    ${SCYLLA_SRC_DIR}/DumpMemoryGui.h
    ${SCYLLA_SRC_DIR}/DumpSectionGui.h
    ${SCYLLA_SRC_DIR}/OptionsGui.h
    ${SCYLLA_SRC_DIR}/PickApiGui.h
    ${SCYLLA_SRC_DIR}/PickDllGui.h
    ${SCYLLA_SRC_DIR}/resource.h
    ${SCYLLA_SRC_DIR}/hexedit.h
    ${SCYLLA_SRC_DIR}/multitree.h
)

# Resource file
set(SCYLLA_GUI_RESOURCES
    ${SCYLLA_SRC_DIR}/MainGui.rc
)

# Create executable
add_executable(ScyllaGUI WIN32
    ${SCYLLA_GUI_SOURCES}
    ${SCYLLA_GUI_HEADERS}
    ${SCYLLA_GUI_RESOURCES}
)

# Set executable name
set_target_properties(ScyllaGUI PROPERTIES
    OUTPUT_NAME "Scylla"
)

# Include directories
target_include_directories(ScyllaGUI PRIVATE
    ${SCYLLA_SRC_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../WTL/Include
    ${CMAKE_CURRENT_SOURCE_DIR}/../diStorm/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../tinyxml
)

# Link with core library
if(TARGET ScyllaLib)
    target_link_libraries(ScyllaGUI PRIVATE Scylla::Scylla)
elseif(TARGET ScyllaLibStatic)
    target_link_libraries(ScyllaGUI PRIVATE Scylla::Scylla)
else()
    # Fallback: link directly with dependencies
    target_link_libraries(ScyllaGUI PRIVATE
        diStorm
        tinyxml
    )
endif()

# Windows libraries
target_link_libraries(ScyllaGUI PRIVATE
    comctl32
    comdlg32
    psapi
    dbghelp
    shlwapi
)

# Compile definitions
target_compile_definitions(ScyllaGUI PRIVATE
    _UNICODE
    UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

# Wine compatibility improvements
if(ENABLE_WINE_SUPPORT)
    target_compile_definitions(ScyllaGUI PRIVATE
        SCYLLA_WINE_COMPAT
    )
endif()

# Compiler-specific settings
if(MSVC)
    # Use modern Windows subsystem version
    target_link_options(ScyllaGUI PRIVATE
        /SUBSYSTEM:WINDOWS
        /MANIFEST:EMBED
    )

    # Enable common controls v6
    target_sources(ScyllaGUI PRIVATE ${SCYLLA_SRC_DIR}/MainGui.rc)

elseif(MINGW)
    # MinGW settings
    target_link_options(ScyllaGUI PRIVATE
        -mwindows
        -municode
    )
    target_compile_options(ScyllaGUI PRIVATE -municode)
endif()

# Installation
install(TARGETS ScyllaGUI
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install icons and resources
install(FILES
    ${SCYLLA_SRC_DIR}/scylla.ico
    ${SCYLLA_SRC_DIR}/check.ico
    ${SCYLLA_SRC_DIR}/error.ico
    ${SCYLLA_SRC_DIR}/warning.ico
    DESTINATION ${CMAKE_INSTALL_DATADIR}/scylla/icons
)
