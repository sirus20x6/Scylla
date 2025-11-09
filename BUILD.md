# Building Scylla - Cross-Platform Edition

This document describes how to build Scylla on various platforms using the new CMake-based build system.

## Table of Contents

- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Platform-Specific Instructions](#platform-specific-instructions)
  - [Windows (Native)](#windows-native)
  - [Windows (MinGW/MSYS2)](#windows-mingwmsys2)
  - [Linux](#linux)
  - [macOS](#macos)
  - [Cross-Compilation](#cross-compilation)
- [Wine Support](#wine-support)
- [Build Options](#build-options)
- [Troubleshooting](#troubleshooting)

## Requirements

### All Platforms
- CMake 3.15 or later
- C++17-compatible compiler
- Git (for cloning the repository)

### Windows
- Visual Studio 2017 or later (recommended)
- OR MinGW-w64 (GCC 7.0+)
- OR MSYS2 with MinGW toolchain

### Linux
- GCC 7.0+ or Clang 5.0+
- Development packages: `build-essential`, `cmake`, `ninja-build`

### macOS
- Xcode 10.0 or later (for Apple Clang)
- Homebrew (optional, for easy dependency management)

## Quick Start

```bash
# Clone the repository
git clone https://github.com/NtQuery/Scylla.git
cd Scylla

# Create build directory
mkdir build && cd build

# Configure (platform-specific options below)
cmake ..

# Build
cmake --build . --config Release

# The binaries will be in build/bin/
```

## Platform-Specific Instructions

### Windows (Native)

#### Using Visual Studio (Recommended for GUI)

```cmd
# Open Developer Command Prompt for Visual Studio
mkdir build
cd build

# Configure for x64
cmake .. -G "Visual Studio 17 2022" -A x64

# Or for x86
cmake .. -G "Visual Studio 16 2019" -A Win32

# Build
cmake --build . --config Release

# Binaries will be in build\bin\Release\
```

#### Using Visual Studio Code

1. Install the CMake Tools extension
2. Open the Scylla folder
3. Press `Ctrl+Shift+P` and select "CMake: Configure"
4. Select your compiler
5. Press `F7` to build

### Windows (MinGW/MSYS2)

```bash
# In MSYS2 MinGW64 shell
mkdir build && cd build
cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

### Linux

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y build-essential cmake ninja-build

# Or for Fedora/RHEL
sudo dnf install gcc gcc-c++ cmake ninja-build

# Configure and build
mkdir build && cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_GUI=OFF
cmake --build .

# The CLI will be in build/bin/scylla-cli
```

**Note:** The GUI is not available on Linux. Use the command-line interface or run the Windows version under Wine.

### macOS

```bash
# Install Xcode Command Line Tools
xcode-select --install

# Configure and build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_GUI=OFF
cmake --build .

# The CLI will be in build/bin/scylla-cli
```

### Cross-Compilation

#### Linux → Windows (MinGW)

```bash
# Install MinGW cross-compiler
sudo apt-get install mingw-w64

# For 64-bit Windows
mkdir build-win64 && cd build-win64
cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain-mingw64.cmake \
         -DCMAKE_BUILD_TYPE=Release
cmake --build .

# For 32-bit Windows
mkdir build-win32 && cd build-win32
cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain-mingw32.cmake \
         -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

## Wine Support

Scylla has been optimized to work well under Wine. The Windows build includes:

- Wine detection at runtime
- Compatibility mode for Wine environment
- Avoidance of problematic Windows APIs
- Well-tested with Wine 5.0+

### Testing under Wine

```bash
# Install Wine (Ubuntu/Debian)
sudo apt-get install wine wine64

# Run Windows build under Wine
wine build/bin/Scylla.exe

# Or the CLI
wine build/bin/scylla-cli.exe info
```

### Wine Version Detection

The Windows build automatically detects when running under Wine and adjusts its behavior for better compatibility. You can verify this by running:

```bash
wine scylla-cli.exe info
```

This will show "Running under Wine: Yes" if detected.

## Build Options

Configure the build with various options:

```bash
cmake .. \
  -DBUILD_GUI=ON \              # Build GUI application (Windows only)
  -DBUILD_CLI=ON \              # Build CLI application (all platforms)
  -DBUILD_SHARED_LIB=ON \       # Build shared library (.dll/.so/.dylib)
  -DBUILD_STATIC_LIB=ON \       # Build static library (.lib/.a)
  -DENABLE_WINE_SUPPORT=ON \    # Enable Wine compatibility features
  -DBUILD_TESTS=OFF \           # Build test suite
  -DCMAKE_BUILD_TYPE=Release    # Release, Debug, RelWithDebInfo, MinSizeRel
```

### Default Options

| Option | Default | Notes |
|--------|---------|-------|
| BUILD_GUI | ON | Only available on Windows/MinGW |
| BUILD_CLI | ON | Available on all platforms |
| BUILD_SHARED_LIB | ON | Creates ScyllaLib.dll/.so/.dylib |
| BUILD_STATIC_LIB | ON | Creates ScyllaStatic.lib/.a |
| ENABLE_WINE_SUPPORT | ON | Wine compatibility mode |
| BUILD_TESTS | OFF | Test suite (future) |

## Output Files

After building, you'll find:

```
build/
├── bin/
│   ├── Scylla.exe              # GUI application (Windows only)
│   ├── scylla-cli              # CLI application (all platforms)
│   └── Scylla.dll              # Shared library (if enabled)
└── lib/
    ├── ScyllaStatic.lib        # Static library (if enabled)
    └── (platform-specific extensions)
```

## Troubleshooting

### CMake can't find compiler

**Solution:** Ensure your compiler is in PATH or specify it explicitly:

```bash
cmake .. -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++
```

### TinyXML not found

The build system automatically downloads TinyXML if not found locally. If you have network issues:

1. Download TinyXML 2.6.2 from SourceForge
2. Extract `tinyxml.cpp`, `tinyxmlerror.cpp`, `tinyxmlparser.cpp`, `tinystr.cpp`, `tinyxml.h`, `tinystr.h`
3. Place them in the `tinyxml/` directory

### WTL not found (Windows GUI)

The `WTL/` directory should contain WTL headers. If missing:

1. Download WTL from https://sourceforge.net/projects/wtl/
2. Extract to `WTL/Include/` directory

### Linux: Permission denied for process access

On Linux, process memory access requires special permissions:

```bash
# Temporary (until reboot)
sudo sysctl -w kernel.yama.ptrace_scope=0

# Or run with sudo
sudo ./scylla-cli

# Better: Add CAP_SYS_PTRACE capability
sudo setcap cap_sys_ptrace=eip ./scylla-cli
```

### macOS: Code signing issues

On macOS, you may need to sign the binary or adjust security settings:

```bash
# Sign the binary
codesign -s - scylla-cli

# Or allow in System Preferences → Security & Privacy
```

## Advanced Topics

### Custom Installation Prefix

```bash
cmake .. -DCMAKE_INSTALL_PREFIX=/opt/scylla
cmake --build .
cmake --install .
```

### Debug Build

```bash
cmake .. -DCMAKE_BUILD_TYPE=Debug
cmake --build .
```

### Building with Ninja (faster builds)

```bash
cmake .. -G Ninja
ninja
```

### Static Linking (Windows)

For a fully standalone executable:

```bash
cmake .. -DBUILD_SHARED_LIB=OFF -DBUILD_STATIC_LIB=ON
cmake --build . --config Release
```

## Continuous Integration

The project includes GitHub Actions workflows that automatically build for:

- Windows (x86, x64) with MSVC
- Linux (Ubuntu 20.04, 22.04, latest)
- macOS (Intel and Apple Silicon)
- MinGW cross-compilation from Linux

See `.github/workflows/build.yml` for details.

## Getting Help

- Report build issues: https://github.com/NtQuery/Scylla/issues
- General questions: See README.md

## License

See LICENSE file for details.
