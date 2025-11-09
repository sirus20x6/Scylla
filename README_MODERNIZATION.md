# Scylla Modernization & Cross-Platform Support

## 🎉 What's New

Scylla has been modernized with cross-platform support and enhanced Wine compatibility! This document describes the new features and improvements.

## ✨ Key Improvements

### 🌍 Cross-Platform Support
- **Windows** - Native support (MSVC, MinGW)
- **Linux** - Command-line interface with ptrace-based process access
- **macOS** - Command-line interface with Mach kernel APIs
- **Wine** - Optimized for excellent Wine compatibility

### 🏗️ Modern Build System
- **CMake** - Replaces Visual Studio-only builds
- **Multi-platform CI** - GitHub Actions for automated builds
- **Cross-compilation** - Build Windows binaries on Linux
- **Flexible options** - Build GUI, CLI, or library components

### 🎯 Platform Abstraction Layer
- Clean API for process/memory access
- Platform-specific implementations
- Runtime Wine detection
- Graceful degradation on unsupported features

### 📦 New Artifacts
- **Scylla GUI** - Windows-only WTL-based GUI (works in Wine)
- **Scylla CLI** - Cross-platform command-line interface
- **libScylla** - Shared/static library for integration
- **Multiple builds** - Windows (x86/x64), Linux, macOS

## 🚀 Quick Start

### Building

See **[BUILD.md](BUILD.md)** for comprehensive build instructions.

#### Windows (Quick)
```cmd
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

#### Linux (Quick)
```bash
mkdir build && cd build
cmake .. -G Ninja -DBUILD_GUI=OFF
cmake --build .
./bin/scylla-cli info
```

#### Wine (Quick)
```bash
# Use pre-built Windows binaries
wine Scylla.exe

# Or build with MinGW on Linux
cmake .. -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-mingw64.cmake
cmake --build .
wine build/bin/Scylla.exe
```

### Running

#### Windows
```cmd
# GUI
Scylla.exe

# CLI
scylla-cli.exe info
```

#### Linux
```bash
# CLI only
./scylla-cli info
./scylla-cli analyze binary.exe

# Or run Windows version in Wine
wine Scylla.exe
```

#### macOS
```bash
# CLI only
./scylla-cli info
./scylla-cli analyze binary
```

## 📚 Documentation

- **[BUILD.md](BUILD.md)** - Detailed build instructions for all platforms
- **[WINE.md](WINE.md)** - Wine compatibility guide and tips
- **[README.md](README.md)** - Original Scylla documentation
- **[COMPILING](COMPILING)** - Legacy Visual Studio build instructions

## 🍷 Wine Support

Scylla now has **first-class Wine support**:

### Features
✅ Automatic Wine detection
✅ Wine-optimized API calls
✅ Compatibility mode for Wine 5.0+
✅ Full GUI support under Wine
✅ Enhanced error handling

### Testing
```bash
wine Scylla.exe
wine scylla-cli.exe info
```

See **[WINE.md](WINE.md)** for complete Wine documentation.

## 🔧 Build Options

Configure your build with CMake options:

```bash
cmake .. \
  -DBUILD_GUI=ON \              # Windows GUI (requires WTL)
  -DBUILD_CLI=ON \              # Cross-platform CLI
  -DBUILD_SHARED_LIB=ON \       # Dynamic library
  -DBUILD_STATIC_LIB=ON \       # Static library
  -DENABLE_WINE_SUPPORT=ON \    # Wine compatibility
  -DCMAKE_BUILD_TYPE=Release    # Release build
```

## 🏛️ Architecture

### Original Scylla
```
Scylla.exe (Windows GUI)
  ├── WTL GUI
  ├── PE Parser
  ├── IAT Reconstructor
  └── Windows APIs (Process, Memory)
```

### Modernized Scylla
```
┌─────────────────────────────────────┐
│         Scylla Applications          │
├─────────────┬───────────────────────┤
│ Scylla GUI  │   Scylla CLI          │
│ (Windows)   │   (Cross-platform)    │
└─────────────┴───────────────────────┘
         │              │
         v              v
┌────────────────────────────────────┐
│         libScylla Core             │
│  ├── PE Parser                     │
│  ├── IAT Reconstructor             │
│  ├── Import Analyzer               │
│  └── Platform Abstraction          │
└────────────────────────────────────┘
         │
         v
┌────────────────────────────────────┐
│   Platform Implementations         │
│  ├── Windows (Win32 API)           │
│  ├── Linux (ptrace, /proc)         │
│  ├── macOS (Mach kernel)           │
│  └── Wine (optimized Windows)      │
└────────────────────────────────────┘
```

## 📊 Platform Feature Matrix

| Feature | Windows | Linux | macOS | Wine |
|---------|---------|-------|-------|------|
| PE Analysis | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| IAT Rebuild | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| GUI | ✅ Yes | ❌ No | ❌ No | ✅ Yes |
| CLI | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| Process Enum | ✅ Full | ✅ Full | ✅ Full | ✅ Good |
| Memory Read | ✅ Fast | ⚠️ Slower | ⚠️ Slower | ⚠️ Good |
| Memory Write | ✅ Full | ⚠️ Limited | ⚠️ Limited | ⚠️ Good |
| DLL Injection | ✅ Full | ❌ No | ❌ No | ⚠️ Limited |
| Thread Control | ✅ Full | ❌ No | ✅ Yes | ⚠️ Limited |

## 🔬 Technical Details

### C++ Standard
- Upgraded to **C++17** from C++98
- Modern features: `auto`, `nullptr`, range-based loops
- Future: Smart pointers, STL algorithms

### Dependencies
- **diStorm** - Disassembler (cross-platform)
- **TinyXML** - XML parsing (auto-fetched)
- **WTL** - GUI framework (Windows only)

### Platform APIs

**Windows/Wine:**
```cpp
CreateToolhelp32Snapshot()  // Process enumeration
ReadProcessMemory()         // Memory access
VirtualQueryEx()            // Memory queries
```

**Linux:**
```cpp
ptrace()                    // Process control
/proc filesystem           // Process information
readlink()                 // Path resolution
```

**macOS:**
```cpp
task_for_pid()             // Process access
mach_vm_read()             // Memory reading
sysctl()                   // Process enumeration
```

## 🎯 Use Cases

### Reverse Engineering
- Analyze packed/protected executables
- Reconstruct import tables
- Dump process memory
- Fix broken imports

### Malware Analysis
- Unpack malware samples
- Analyze API usage
- Rebuild import tables
- Cross-platform analysis

### Wine Compatibility Testing
- Test Windows executables in Wine
- Debug Wine-specific issues
- Verify API compatibility

### Cross-Platform Development
- Integrate PE analysis into Linux tools
- Build analysis pipelines
- Automated binary analysis

## 🤝 Contributing

Contributions welcome! Areas of interest:

- **Platform support** - Improve Linux/macOS implementations
- **Wine compatibility** - Test and fix Wine-specific issues
- **GUI alternatives** - Qt/GTK GUI for Linux
- **Documentation** - Improve guides and examples
- **Testing** - Add test cases and CI improvements

## 📜 Version History

### v0.9.9 - Modernization Release (2024)
- ✨ CMake build system
- 🌍 Cross-platform support (Windows, Linux, macOS)
- 🍷 Enhanced Wine compatibility
- 🏗️ Platform abstraction layer
- 📦 Command-line interface
- 🔧 C++17 standard
- 🚀 GitHub Actions CI

### v0.9.8 - Last Legacy Release
- Bug fixes for x64, IAT Search
- diStorm3 update
- Windows-only

See [README.md](README.md) for complete changelog.

## 📄 License

GNU General Public License v3.0

See [LICENSE](LICENSE) for full text.

## 🙏 Credits

**Original Scylla:**
- Created by NtQuery
- Community contributions from Tuts4You

**Modernization:**
- Cross-platform architecture
- CMake build system
- Wine compatibility enhancements
- Platform abstraction layer

## 🔗 Links

- **GitHub**: https://github.com/NtQuery/Scylla
- **Issues**: https://github.com/NtQuery/Scylla/issues
- **Forum**: https://forum.tuts4you.com/

## 📞 Support

- **Build issues**: See [BUILD.md](BUILD.md) troubleshooting
- **Wine issues**: See [WINE.md](WINE.md)
- **Bug reports**: GitHub Issues
- **General help**: README.md

---

**Made with ❤️ for the reverse engineering community**
