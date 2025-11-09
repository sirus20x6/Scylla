# Scylla Codebase Documentation Index

## Overview

This directory contains comprehensive documentation about the Scylla codebase, its architecture, dependencies, and cross-platform modernization considerations.

## Generated Documentation Files

### 1. **EXPLORATION_SUMMARY.md** (START HERE)
   - Executive summary of the entire exploration
   - Quick facts and statistics
   - High-level architecture overview
   - Windows-specific design patterns
   - Summary of strengths and limitations
   - Modernization areas for cross-platform support

### 2. **CODEBASE_OVERVIEW.md**
   Complete technical reference covering:
   - What Scylla is and its purpose
   - Detailed project structure breakdown
   - Programming languages and frameworks used
   - Current platform support (Windows only)
   - Build system and dependencies
   - Existing cross-platform considerations (or lack thereof)
   - Summary statistics and metrics

### 3. **ARCHITECTURE.txt**
   Visual and structural documentation including:
   - Component relationship diagrams
   - Data flow for import reconstruction workflow
   - Class hierarchy for key components
   - File organization by functionality
   - Core layer descriptions
   - Dependency trees

### 4. **WINDOWS_DEPENDENCIES.txt**
   Deep-dive analysis of Windows integration:
   - Critical Windows-specific components breakdown
   - Process manipulation API analysis
   - PE file format dependencies
   - Native Windows API usage
   - DLL injection mechanisms
   - GUI framework (WTL) dependencies
   - Code portability analysis
   - Estimated effort for cross-platform support

## Key Findings Summary

### What is Scylla?
Scylla is a **Windows PE (Portable Executable) import table reconstruction tool** for reverse engineering and malware analysis. It helps rebuild Import Address Tables (IAT) for dumped or packed PE files.

### Technology Stack
- **Language**: C++ (C++98/03)
- **GUI**: Windows Template Library (WTL) v8
- **Build**: Visual Studio 2008+ (MSBuild)
- **Code Size**: 17,335+ lines across 69 source files
- **Dependencies**: diStorm (disassembly), tinyxml (XML), WTL (GUI)

### Architecture Layers
1. **GUI Layer** - WTL-based dialog application
2. **Business Logic** - PE parsing, import analysis, IAT searching
3. **System Access** - Windows API wrappers, process manipulation
4. **Utilities** - Configuration, logging, platform detection

### Platform Status
- **Currently**: Windows-only (7/Vista/XP)
- **Architectures**: x86 and x64 builds
- **Requirements**: Administrator privileges
- **No Cross-Platform Support**: All Windows-specific

### Windows Dependencies
- **Process APIs**: OpenProcess, ReadProcessMemory, CreateRemoteThread
- **PE Format**: IMAGE_* structures (Windows-exclusive)
- **GUI Framework**: WTL (Windows-only)
- **Native APIs**: NT kernel APIs, registry access

## Cross-Platform Modernization Branch

**Current Branch**: `claude/modernize-scylla-crossplatform-011CUwaQMtFiD8SgCiUEscZ3`

This branch is designated for modernizing Scylla to support multiple platforms while maintaining core functionality.

### Key Modernization Areas
1. Platform abstraction layer for OS-specific calls
2. GUI framework replacement (Qt/GTK/wxWidgets)
3. Build system migration (CMake)
4. C++ standard upgrade (C++98 → C++11/14/17)
5. Smart pointer usage
6. Configuration system abstraction

## Statistics

| Metric | Value |
|--------|-------|
| Total Files | 86 (.cpp, .h) |
| Main Source Files | 69 |
| Total LOC | 17,335+ |
| Build System | MSBuild (Visual Studio) |
| Primary Language | C++ |
| GUI Framework | WTL |
| Windows-Only APIs | 100+ references |
| Cross-Platform Abstraction | None |

## Quick Navigation

### For Understanding Current Architecture
→ Read: **ARCHITECTURE.txt** (Component relationships, data flow)

### For Technical Deep Dive
→ Read: **CODEBASE_OVERVIEW.md** (Complete technical details)

### For Windows API Analysis
→ Read: **WINDOWS_DEPENDENCIES.txt** (Detailed API breakdown)

### For Executive Summary
→ Read: **EXPLORATION_SUMMARY.md** (High-level overview)

## Key Code Locations

| Functionality | Files |
|---------------|-------|
| GUI Application | MainGui.cpp/h, AboutGui.cpp/h, OptionsGui.cpp/h |
| PE File Handling | PeParser.cpp/h, PeRebuild.cpp/h |
| Process Access | ProcessAccessHelp.cpp/h, ProcessLister.cpp/h |
| Import Analysis | ImportsHandling.cpp/h, ApiReader.cpp/h |
| IAT Operations | IATSearch.cpp/h, IATReferenceScan.cpp/h |
| Memory Dump | DumpMemoryGui.cpp/h, DumpSectionGui.cpp/h |
| Plugin System | PluginLoader.cpp/h, DllInjection.cpp/h |
| DLL Export API | FunctionExport.cpp/h |
| Configuration | ConfigurationHolder.cpp/h |
| Logging | Logger.cpp/h |
| Windows APIs | NativeWinApi.h |

## Development Insights

### Strengths
- Clear modular architecture
- Good separation of concerns (GUI, Logic, System Access)
- Comprehensive feature set
- Both GUI and DLL interface modes
- Plugin system for extensibility
- Well-organized component responsibilities

### Limitations
- Tightly coupled to Windows and WTL
- No cross-platform abstraction layer
- Legacy C++ standard (C++98)
- Manual memory management (new/delete)
- MSBuild-only build system
- No modern C++ practices

### Code Organization
- One file pair per major component
- Static helper classes for shared functionality
- Global configuration singleton
- Resource management with RAII concepts
- WTL message map pattern for GUI

## Compilation & Dependencies

### Build Requirements
- Visual Studio 2008 or later
- Windows Platform SDK (included with VS)
- Manual downloads: WTL (header-only), tinyxml sources

### Build Output
```
$(SolutionDir)/$(Platform)/$(Configuration)/
├── Scylla.exe (application)
├── Scylla.lib (for DLL mode)
├── diStorm.lib (disassembly engine)
└── tinyxml.lib (XML parsing)
```

### Supported Configurations
- Debug|Win32, Debug|x64
- Release|Win32, Release|x64

## Related Files in Repository

- **README.md** - Original project documentation
- **COMPILING** - Build instructions
- **Scylla.sln** - Main Visual Studio solution
- **Scylla_Exports.txt** - DLL export documentation
- **Plugins/** - Plugin system and examples
- **ScyllaDllTest/** - DLL mode test projects

## Notes for Modernization

The current branch is set up for cross-platform modernization. Key considerations:

1. **PE Format Remains Windows-Specific**
   - The core purpose (PE import rebuilding) is inherently Windows-only
   - Could add support for other formats (ELF, Mach-O) for parity

2. **Process Access Varies by OS**
   - Windows: OpenProcess/ReadProcessMemory
   - Linux: ptrace system call
   - macOS: task_for_pid
   - Would require significant abstraction

3. **GUI Modernization Priority**
   - WTL replacement is critical for cross-platform
   - Qt/GTK would be good alternatives
   - Would need refactoring of dialog-based UI

4. **Build System Migration**
   - CMake recommended for cross-platform builds
   - Better support for dependency management
   - Easier integration with different toolchains

5. **C++ Modernization Opportunity**
   - Update to C++11/14/17
   - Use smart pointers (unique_ptr, shared_ptr)
   - Use standard containers and algorithms
   - Improve error handling

## Document Information

- **Created**: November 9, 2025
- **Branch**: claude/modernize-scylla-crossplatform-011CUwaQMtFiD8SgCiUEscZ3
- **Repository**: Scylla (PE Import Table Reconstruction Tool)
- **Total Documentation**: ~48KB across 4 files

---

**Start with EXPLORATION_SUMMARY.md for a quick overview, or jump to specific documents based on your needs above.**
