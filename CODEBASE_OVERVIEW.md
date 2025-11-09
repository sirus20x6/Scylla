# Scylla Codebase Comprehensive Overview

## 1. What is Scylla? What does it do?

**Scylla** is a specialized PE (Portable Executable) import table reconstruction tool for Windows. It's designed to rebuild the Import Address Table (IAT) for dumped or packed PE files (both x86 and x64 architectures).

### Core Purpose:
- Reconstruct missing or corrupted import tables in PE files
- Replace functionality previously provided by ImpREC, CHimpREC, and similar import fixing tools
- Provide improved accuracy and support for modern Windows versions (Windows 7 x64)

### Key Features:
- x64 and x86 support (dual architecture)
- Full Unicode support
- Process dumping capabilities
- IAT (Import Address Table) automatic search and analysis
- Memory region dumping
- Direct import scanning (pattern matching for LEA, MOV, PUSH, CALL, JMP instructions)
- PE file rebuilding and validation
- Plugin support (ImpREC plugin compatibility)
- GUI and DLL interface
- Disassembler integration
- XML-based tree import/export

## 2. Current Project Structure and Architecture

```
Scylla/
├── Scylla/                 # Main application source code (~69 files, 17K+ LOC)
│   ├── Main GUI layer      # MainGui.cpp/h, AboutGui.cpp/h, OptionsGui.cpp/h
│   ├── PE handling         # PeParser.cpp/h, PeRebuild.cpp/h
│   ├── Process access      # ProcessAccessHelp.cpp/h, ProcessLister.cpp/h
│   ├── Import analysis     # ImportsHandling.cpp/h, ApiReader.cpp/h
│   ├── IAT operations      # IATSearch.cpp/h, IATReferenceScan.cpp/h
│   ├── Memory operations   # DumpMemoryGui.cpp/h, DumpSectionGui.cpp/h
│   ├── Disassembly         # DisassemblerGui.cpp/h
│   ├── DLL injection       # DllInjection.cpp/h, DllInjectionPlugin.cpp/h
│   ├── Utilities           # Logger.cpp/h, Configuration.cpp/h, Architecture.cpp/h
│   ├── Plugin system       # PluginLoader.cpp/h
│   ├── Tree management     # TreeImportExport.cpp/h, multitree.h
│   └── Scylla.cpp/h        # Core application initialization
│
├── diStorm/                # Disassembly engine (third-party dependency)
│   ├── include/            # diStorm headers
│   └── src/                # diStorm source
│
├── WTL/                    # Windows Template Library (third-party GUI framework)
│   └── README              # Download instructions
│
├── tinyxml/                # XML parsing library (third-party)
│   └── README              # Download instructions
│
├── Plugins/                # Plugin and extension framework
│   ├── ImpRec_Plugins/     # Pre-built ImpREC compatible plugins
│   ├── Include_Headers/    # Plugin development headers
│   └── Sources/            # Plugin source examples
│
├── ScyllaDllTest/          # DLL mode test suite
│   ├── ScyllaDllTest.sln   # Test solution
│   ├── ScyllaDllTest/      # DLL test project
│   └── ScyllaTestExe/      # Executable test project
│
├── Scylla.sln              # Main Visual Studio solution
├── README.md               # Project documentation
└── COMPILING               # Compilation instructions
```

## 3. Programming Languages and Frameworks

### Primary Language:
- **C++ (C++98/03 standard)** - Complete application written in modern C++ for Windows

### Key Frameworks and Libraries:

1. **WTL (Windows Template Library) v8**
   - GUI framework (modern alternative to MFC)
   - Dialog-based application
   - Message map macros for event handling
   - Control wrapping and data exchange

2. **diStorm3**
   - Disassembly engine for x86/x64
   - Used for instruction decoding during IAT analysis
   - Pattern matching for import references

3. **tinyxml**
   - XML parsing and generation
   - Used for import tree save/load functionality

4. **Win32 API**
   - Process management (OpenProcess, GetProcessModules, etc.)
   - Memory access (ReadProcessMemory, WriteProcessMemory, etc.)
   - File handling
   - Registry access
   - Native NT API wrappers

### Build System:
- **Visual Studio 2008+** (MSBuild toolchain)
- **Visual Studio project files** (.vcxproj, .sln format)
- Supports VS2010, VS2013, VS2015+ with toolset upgrades
- Dual platform configurations: Win32 (x86) and x64

## 4. Current Platform Support

### Exclusively Windows
- **Windows 7 x64** (primary target/recommended)
- **Windows Vista x64/x86** (supported, with caveats)
- **Windows XP x64** (supported, with known limitations)
- **Windows XP x86** (legacy support)

### Architecture Support:
- **x86 (Win32)** - 32-bit architecture
- **x64** - 64-bit architecture
- Separate build configurations for each
- Compile-time detection via `_WIN64` preprocessor directive

### Windows-Specific APIs Used:

**Process Management:**
- OpenProcess, CloseHandle, GetCurrentProcess
- CreateRemoteThread, GetThreadContext, SetThreadContext
- SuspendProcess, ResumeProcess, TerminateProcess
- GetProcessModules, EnumProcessModules

**Memory Access:**
- ReadProcessMemory, WriteProcessMemory
- VirtualQueryEx, VirtualAllocEx
- CreateFileMappingA/W, MapViewOfFile

**File Operations:**
- CreateFileA/W, ReadFile, WriteFile
- GetFileSize, SetFilePointer
- CreateBackupFile using system APIs

**Native Windows APIs:**
- NtOpenProcess, NtQueryInformationProcess
- NtQuerySystemInformation
- RtlGetVersion, GetVersion
- SetUnhandledExceptionFilter

**GUI/Desktop APIs:**
- SetWindowPos, InvalidateRect
- MessageBox, DialogBox
- GetDesktopWindow
- Shell integration APIs

**Device/Path APIs:**
- QueryDosDeviceW for device name resolution
- GetMappedFileNameW for file mapping resolution

**Registry:**
- HKEY_LOCAL_MACHINE access for system information

### Platform Constraints:
- Requires Windows operating system
- Requires administrator privileges for process manipulation
- Depends on PE file format (Windows-specific executable format)
- No cross-platform support currently
- No Linux, macOS, or Unix compatibility

## 5. Build System and Dependencies

### Build Configuration:
```
Visual Studio 2008 (v90) or newer
- Primary toolset: Visual Studio 2010 (v100)
- Support for VS2013, VS2015+ via toolset upgrades

Build Configurations:
├── Debug|Win32
├── Debug|x64
├── Release|Win32
└── Release|x64
```

### Core Dependencies:

1. **diStorm** (Disassembly)
   - Static library (.lib)
   - Included in solution
   - Separate build target
   - Dependencies: None (standalone)

2. **tinyxml** (XML)
   - Static library (.lib)
   - Included in solution
   - Separate build target
   - Pure C++, no external deps

3. **WTL** (GUI)
   - Header-only framework
   - Must be downloaded separately
   - Located in WTL/Include/
   - No compilation needed

### External Dependencies:

**Windows SDK Requirements:**
- Windows Platform SDK (included with Visual Studio)
- For process APIs: Psapi.lib (PSAPI library)
- For shell APIs: Shlwapi.lib (Shell Lightweight Utility library)
- For base APIs: kernel32.lib, ntdll.lib

### Dependency Tree:
```
Scylla.exe
├── diStorm.lib (static)
├── tinyxml.lib (static)
├── kernel32.dll (runtime)
├── ntdll.dll (runtime)
├── Psapi.dll (runtime - process enumeration)
├── Shlwapi.dll (runtime - shell utilities)
└── User32.dll, Gdi32.dll (GUI runtime)
```

### Compilation:
```bash
# Requirements from COMPILING file:
- VS2008 or later
- Source codes for diStorm, tinyxml, WTL
- Platform SDK (included with Visual Studio)

# Process:
1. Download WTL and extract to WTL/
2. Download tinyxml and copy files to tinyxml/
3. Build solution via Visual Studio or MSBuild
4. Outputs go to $(Platform)\$(Configuration)\ directories
```

## 6. Existing Cross-Platform Considerations

### Current State: ZERO Cross-Platform Support

The codebase is **exclusively Windows-focused**:

#### Windows-Specific Code Patterns:
1. **Conditional Compilation:**
   ```cpp
   #ifdef _WIN64
   // 64-bit specific code
   #else
   // 32-bit specific code
   #endif
   ```

2. **Windows Types Everywhere:**
   - HANDLE, DWORD, DWORD_PTR
   - WCHAR (Unicode Windows strings)
   - HWND (Window handles)
   - HINSTANCE (Module handles)

3. **PE Format Dependency:**
   - All functionality depends on Windows PE (Portable Executable) format
   - Uses IMAGE_NT_HEADERS, IMAGE_SECTION_HEADER, etc.
   - Directly manipulates PE structures

4. **Process-Level Access:**
   - OpenProcess to access other processes
   - ReadProcessMemory/WriteProcessMemory for memory manipulation
   - These are Windows-specific APIs with no direct equivalents on other OSes

5. **GUI Framework (WTL):**
   - WTL is Windows-only (ATL/COM based)
   - No cross-platform GUI support
   - Dialog-based architecture tied to Win32

#### Key Non-Portable Subsystems:

1. **Process Access Layer** (ProcessAccessHelp.cpp)
   - All methods use Win32 APIs
   - No abstraction layer

2. **Native API Wrapper** (NativeWinApi.h)
   - Direct Windows NT kernel API declarations
   - SYSTEM_INFORMATION_CLASS, UNICODE_STRING, etc.

3. **DLL Injection** (DllInjection.cpp)
   - Uses CreateRemoteThread
   - Windows-only functionality

4. **Disassembler Integration**
   - diStorm is architecture-independent but used for x86/x64
   - Not applicable to other platforms

5. **File Path Handling**
   - Uses WCHAR and backslash separators
   - Registry access via Windows APIs

#### Reasons for Windows-Only Design:

1. **PE Format is Windows-Specific**
   - Only relevant on Windows
   - Cross-platform tools exist but this tool is Windows PE focused

2. **Process Manipulation APIs**
   - OpenProcess, ReadProcessMemory are Windows-specific
   - Different on other OSes (ptrace on Unix, etc.)

3. **Import Tables (IAT)**
   - Windows PE concept
   - Different executable formats on other platforms

4. **Target Use Case**
   - Designed for Windows malware analysis/reverse engineering
   - Primary audience: security researchers on Windows

### No Abstraction Layer
- **No platform abstraction** - direct Win32 calls throughout
- **No conditional compilation for cross-platform** - only Win32/Win64 variations
- **No configuration for other OSes** - COMPILING file only mentions Windows prerequisites

### CI/CD Observations:
- Current branch: `claude/modernize-scylla-crossplatform-011CUwaQMtFiD8SgCiUEscZ3`
- This is the **planned modernization effort** for cross-platform support
- Original codebase has zero cross-platform considerations

## Summary Statistics

| Metric | Value |
|--------|-------|
| Total Source Files | 86 files (.cpp, .h) |
| Main Source (.cpp + .h) | 69 files |
| Lines of Code (Main Source) | 17,335+ LOC |
| Build System | MSBuild (Visual Studio) |
| Primary Language | C++ |
| GUI Framework | WTL (Windows Template Library) |
| Platform Support | Windows Only (7/Vista/XP) |
| Architecture Support | x86, x64 |
| Dependencies | 3 (diStorm, tinyxml, WTL) |
| Development Approach | Windows-native |

