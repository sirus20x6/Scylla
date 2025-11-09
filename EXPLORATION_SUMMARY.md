# Scylla Codebase Exploration Summary

## Quick Facts

| Aspect | Details |
|--------|---------|
| **Project Name** | Scylla |
| **Purpose** | Windows PE Import Table Reconstruction Tool |
| **Language** | C++ (C++98/03) |
| **Total Source Files** | 86 files |
| **Main Source Code** | 69 files (~17,335 LOC) |
| **Build System** | Visual Studio 2008+ (MSBuild) |
| **Platform** | Windows only (7/Vista/XP) |
| **Architectures** | x86 and x64 |
| **GUI Framework** | WTL (Windows Template Library) |
| **Development Mode** | Both GUI and DLL interface available |

## What Scylla Does

Scylla is a specialized reverse-engineering tool that **reconstructs Import Address Tables (IAT) for Windows PE (Portable Executable) files**. It's commonly used in:

- **Malware Analysis**: Fixing imports in dumped/unpacked malware samples
- **Reverse Engineering**: Recovering import tables from packed executables
- **Security Research**: Analyzing how programs interact with system APIs

The tool can:
- Parse PE files and extract/rebuild import tables
- Access running processes and dump memory regions
- Scan for Import Address Tables using advanced algorithms
- Inject DLLs for analysis
- Support ImpREC plugins for extensibility
- Export/import analysis results via XML

## Architecture Overview

### Core Layers

1. **GUI Layer** (WTL-based dialog application)
   - Main window with process/module selection
   - Tree view for imports display
   - Multiple dialog windows for specialized tasks
   - Resizable interface with logging

2. **Business Logic Layer** (Import Analysis & PE Handling)
   - PE file parsing and rebuilding
   - Import table analysis and resolution
   - IAT searching and pattern matching
   - Process memory access and manipulation

3. **System Access Layer** (Windows API Wrappers)
   - Process enumeration and manipulation
   - Memory reading/writing in target processes
   - DLL injection mechanism
   - Native Windows API wrappers

4. **Utility Layer** (Configuration, Logging, etc.)
   - Logger with file and window output
   - INI-based configuration system
   - Platform detection (x86 vs x64)
   - String conversion utilities

### Key Components by Responsibility

**PE Parsing & Rebuilding:**
- PeParser.cpp - PE file structure parsing
- PeRebuild.cpp - PE file modification and rebuilding

**Import Analysis:**
- ImportsHandling.cpp - Import table management
- ApiReader.cpp - System API extraction
- IATSearch.cpp - IAT location detection
- IATReferenceScan.cpp - Import reference scanning

**Process Access:**
- ProcessAccessHelp.cpp - Core process memory operations
- ProcessLister.cpp - Process enumeration
- NativeWinApi.h - Windows NT API wrappers

**DLL Injection & Plugins:**
- DllInjection.cpp - Remote DLL loading
- PluginLoader.cpp - ImpREC plugin system

**Memory Operations:**
- DumpMemoryGui.cpp - Memory region dumping
- DumpSectionGui.cpp - PE section dumping

**GUI:**
- MainGui.cpp - Main application window
- DisassemblerGui.cpp - Disassembly viewer
- Multiple dialog windows for specialized tasks

## Dependencies

### External Libraries (Included)
1. **diStorm** - Disassembly engine (for x86/x64 instruction decoding)
2. **tinyxml** - XML parsing library (for import tree export/import)
3. **WTL v8** - Windows Template Library (GUI framework)

### Windows Runtime Dependencies
- kernel32.dll - Core Windows API
- ntdll.dll - Windows NT layer
- Psapi.dll - Process enumeration APIs
- Shlwapi.dll - Shell utility functions
- User32.dll, Gdi32.dll - GUI libraries

## Platform Support

### Windows Operating Systems
- Windows 7 x64 (primary target - recommended)
- Windows Vista (x64 and x86)
- Windows XP (x64 and x86 - with known limitations)

### Architecture Support
- **x86 (32-bit)** - Separate build configuration
- **x64 (64-bit)** - Separate build configuration

### Platform Constraints
- **Exclusively Windows** - No cross-platform support
- **Requires Admin Privileges** - For process access
- **PE Format Dependent** - Windows executable format specific
- **No Abstraction Layer** - Direct Win32 API calls throughout

## Windows-Specific Design

### Critical Windows Dependencies

The codebase is deeply integrated with Windows and uses:

1. **Process Manipulation**
   - `OpenProcess()`, `ReadProcessMemory()`, `WriteProcessMemory()`
   - `CreateRemoteThread()` for DLL injection
   - Different mechanisms required for Linux/Unix (ptrace) or macOS (task_for_pid)

2. **PE File Format**
   - Uses Windows IMAGE_* structures
   - PE format is Windows-exclusive (unlike ELF on Linux or Mach-O on macOS)

3. **GUI Framework (WTL)**
   - Windows-only framework built on ATL/COM
   - Message-based event handling (Windows-centric)
   - Would require complete rewrite for cross-platform

4. **Native Windows APIs**
   - Undocumented NT kernel APIs (`NtOpenProcess`, etc.)
   - Registry access for configuration
   - Unicode handling (UTF-16 WCHAR)

5. **File Path & System**
   - Assumes backslash path separators
   - Windows device path format
   - Case-insensitive file system assumptions

### Code Patterns

```cpp
// Architecture detection (x86 vs x64)
#ifdef _WIN64
    // 64-bit specific code
#else
    // 32-bit specific code
#endif

// Windows types throughout
HANDLE hProcess;
DWORD_PTR address;
WCHAR filePath[MAX_PATH];

// Windows API calls
ReadProcessMemory(hProcess, address, buffer, size, NULL);
OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
```

## Project Structure

```
Scylla/
├── Scylla/                    # Main application (69 files, 17K+ LOC)
│   ├── GUI Components         # MainGui, AboutGui, OptionsGui, etc.
│   ├── Core Logic            # PeParser, ImportsHandling, IATSearch
│   ├── System Access         # ProcessAccessHelp, NativeWinApi
│   ├── Utilities             # Logger, Configuration, Architecture
│   └── Supporting Libraries  # multitree.h, hexedit.h
│
├── diStorm/                   # Disassembly engine (third-party)
├── WTL/                       # GUI framework (third-party, header-only)
├── tinyxml/                   # XML parsing (third-party)
├── Plugins/                   # Plugin system and examples
├── ScyllaDllTest/             # DLL mode tests
│
├── Scylla.sln                 # Main Visual Studio solution
├── COMPILING                  # Build instructions
└── README.md                  # Project documentation
```

## Build System

### Requirements
- Visual Studio 2008 or later (v90+ toolset)
- Windows Platform SDK (included with Visual Studio)
- Manual download of: WTL (header-only), tinyxml sources

### Configurations
- Debug|Win32
- Debug|x64
- Release|Win32
- Release|x64

### Output Structure
```
$(SolutionDir)/$(Platform)/$(Configuration)/
├── Scylla.exe
├── Scylla.lib (for DLL mode)
├── diStorm.lib
└── tinyxml.lib
```

## DLL Mode

Beyond the GUI application, Scylla can be used as a DLL library:

**Exported Functions** (FunctionExport.cpp):
- `ScyllaRebuildFileW/A()` - Rebuild PE file imports
- `ScyllaDumpCurrentProcessW/A()` - Dump current process
- `ScyllaDumpProcessW/A()` - Dump another process
- `ScyllaStartGui()` - Launch GUI mode
- `ScyllaIatSearch()` - Search for IAT in process
- `ScyllaIatFixAutoW()` - Auto-fix IAT in file

This allows integration with other tools via DLL injection and exported functions.

## Plugin System

Scylla supports ImpREC-compatible plugins:

- Plugin loader in `PluginLoader.cpp`
- Plugins directory with examples (PECompact, PESpin)
- Plugin development headers in `Plugins/Include_Headers/`
- Supports DLL injection plugins for specialized unpacking

## Cross-Platform Modernization Branch

**Current Branch**: `claude/modernize-scylla-crossplatform-011CUwaQMtFiD8SgCiUEscZ3`

This branch is designated for:
- Modernizing the codebase architecture
- Adding cross-platform support capabilities
- Updating build system (likely CMake)
- Creating platform abstraction layers

### Key Modernization Areas Needed

1. **Platform Abstraction Layer**
   - Abstract process access (Windows OpenProcess vs ptrace/task_for_pid)
   - Abstract file path handling
   - Abstract memory operations

2. **GUI Modernization**
   - Replace WTL with cross-platform framework (Qt, GTK, wxWidgets)
   - Modern C++ (C++11 or later)
   - Platform-independent window/dialog handling

3. **Build System**
   - Migrate from MSBuild to CMake
   - Support for multiple platforms
   - Conditional compilation based on target OS

4. **Configuration System**
   - Replace Windows-specific INI approach
   - Support for Linux/macOS configuration standards

5. **Code Modernization**
   - Update C++ standard (C++98 → C++11/14/17)
   - Remove Windows-specific types and assumptions
   - Improve error handling and resource management

## Development Insights

### Code Organization
- Modular component design (one responsibility per file pair)
- Clear separation between GUI, business logic, and system access
- Static helper classes for shared functionality
- Global configuration singleton pattern

### Design Patterns
- Dialog-based GUI with message maps (WTL pattern)
- Static factory/helper classes (ProcessAccessHelp, ApiReader)
- Resource management with RAII concepts
- Plugin loader pattern for extensibility

### Testing
- DLL test projects included (ScyllaDllTest solution)
- Both GUI and non-GUI test scenarios
- Integration with plugin system

## Summary

Scylla is a **mature, well-structured Windows-native tool** for PE import table reconstruction. The codebase demonstrates:

✓ **Strengths:**
- Clear modular architecture
- Good separation of concerns
- Comprehensive Windows API integration
- Both GUI and DLL modes for flexibility
- Plugin system for extensibility
- Mature feature set (0.9.8 version)

✗ **Limitations:**
- Tightly coupled to Windows and WTL
- No cross-platform abstraction
- Legacy C++ standard (C++98)
- MSBuild-only build system
- No modern C++ memory management (new/delete instead of smart pointers)

The modernization branch is set up to address these limitations and enable cross-platform support while maintaining backward compatibility and the tool's core functionality.

## Documentation Generated

Three detailed documents have been created in the repository:

1. **CODEBASE_OVERVIEW.md** - Complete technical overview
2. **ARCHITECTURE.txt** - Component relationships and data flow diagrams
3. **WINDOWS_DEPENDENCIES.txt** - Detailed Windows API analysis and portability assessment

