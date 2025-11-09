# Scylla Wine Compatibility Guide

Scylla has been modernized with excellent Wine compatibility in mind. This guide covers running Scylla under Wine and best practices for Wine environments.

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Wine Versions](#wine-versions)
- [Features and Limitations](#features-and-limitations)
- [Troubleshooting](#troubleshooting)
- [Performance Tips](#performance-tips)
- [Development Notes](#development-notes)

## Overview

Scylla now includes:

✅ **Wine Detection** - Automatically detects Wine environment at runtime
✅ **API Compatibility** - Uses Wine-friendly Windows APIs
✅ **Optimized Calls** - Avoids problematic NT kernel APIs
✅ **Better Stability** - Reduced crashes and hangs under Wine
✅ **Debug Support** - Enhanced logging for Wine environments

## Requirements

### Minimum Wine Version
- **Wine 5.0** or later (recommended: Wine 7.0+)
- **Wine Staging** recommended for best compatibility

### System Requirements
- Linux kernel 4.4+ (for process access)
- 64-bit system recommended
- Wine configured for your architecture (wine or wine64)

## Quick Start

### 1. Install Wine

#### Ubuntu/Debian
```bash
# Add Wine repository
sudo dpkg --add-architecture i386
wget -nc https://dl.winehq.org/wine-builds/winehq.key
sudo apt-key add winehq.key
sudo add-apt-repository 'deb https://dl.winehq.org/wine-builds/ubuntu/ focal main'

# Install Wine Staging (recommended)
sudo apt update
sudo apt install --install-recommends winehq-staging

# Or install stable version
sudo apt install --install-recommends winehq-stable
```

#### Fedora
```bash
sudo dnf install wine
```

#### Arch Linux
```bash
sudo pacman -S wine wine-staging
```

### 2. Run Scylla

```bash
# For 64-bit executables
wine64 Scylla.exe

# For 32-bit executables
wine Scylla.exe

# CLI interface
wine scylla-cli.exe info
```

### 3. Verify Wine Detection

Run the CLI to check if Scylla detects Wine:

```bash
$ wine scylla-cli.exe info
Scylla CLI v0.9.9 - PE Import Table Reconstruction Tool
Cross-platform Edition

Platform Information:
  Operating System: Windows
  Architecture: x64
  Wine Compatibility: Enabled
  Running under Wine: Yes (version: 7.0)
```

## Wine Versions

### Tested Versions

| Wine Version | Status | Notes |
|-------------|--------|-------|
| Wine 8.0+ | ✅ Excellent | Best compatibility, all features work |
| Wine 7.0-7.22 | ✅ Good | Recommended minimum version |
| Wine 6.0-6.23 | ⚠️ Fair | Most features work, some edge cases |
| Wine 5.0-5.22 | ⚠️ Limited | Basic functionality only |
| Wine 4.x | ❌ Not Recommended | Stability issues |

### Wine Staging vs Stable

**Wine Staging** (Recommended)
- Better Windows API coverage
- More recent patches and fixes
- Better debugging support
- Some experimental features

**Wine Stable**
- More conservative
- Better tested
- Good for production use
- Slightly older API support

## Features and Limitations

### ✅ Fully Supported Features

- **PE File Analysis** - Read and analyze PE headers
- **Import Table Reconstruction** - Full IAT rebuilding
- **Process Enumeration** - List running processes
- **Memory Reading** - Read process memory
- **Module Enumeration** - List loaded DLLs
- **Disassembly** - Code disassembly with diStorm
- **GUI Interface** - Full WTL-based GUI works

### ⚠️ Partially Supported Features

- **Memory Writing** - Works but may be slower than native Windows
- **Thread Manipulation** - Basic support, some limitations
- **DLL Injection** - May not work in all scenarios

### ❌ Not Supported Under Wine

- **Kernel Debugging** - Wine doesn't implement kernel debugging APIs
- **Driver Loading** - No driver support in Wine
- **Some NT Native APIs** - Advanced NtQuerySystemInformation calls

## Troubleshooting

### Issue: "Wine cannot find L\"C:\\windows\\system32\\scylla.exe\""

**Solution:** Use proper path syntax:

```bash
# Don't use Windows paths
wine C:\\path\\to\\Scylla.exe  # ❌ Wrong

# Use Unix paths
wine /path/to/Scylla.exe  # ✅ Correct
wine ./Scylla.exe  # ✅ Correct
```

### Issue: Process access fails

**Cause:** Wine processes have different security models.

**Solutions:**

1. Run Wine processes with same user:
```bash
# Start target process
wine target.exe &

# Run Scylla
wine Scylla.exe
```

2. Check Wine version (needs 5.0+):
```bash
wine --version
```

3. Enable debug output:
```bash
WINEDEBUG=+ntdll,+process wine Scylla.exe
```

### Issue: GUI elements render incorrectly

**Cause:** Wine theme or font issues.

**Solution:**

```bash
# Configure Wine
winecfg

# Go to Graphics tab:
# - Enable "Emulate a virtual desktop"
# - Set appropriate resolution

# Or set DPI:
wine reg add "HKCU\\Control Panel\\Desktop" /v LogPixels /t REG_DWORD /d 96
```

### Issue: Crashes or hangs

**Solutions:**

1. Use Wine Staging:
```bash
sudo apt install winehq-staging
```

2. Check for 32-bit/64-bit mismatch:
```bash
file Scylla.exe  # Check if it's PE32 or PE32+
wine --version   # Check Wine architecture support
```

3. Enable crash dialog:
```bash
wine reg add "HKCU\\Software\\Wine\\WineDbg" /v ShowCrashDialog /t REG_DWORD /d 1
```

4. Check logs:
```bash
WINEDEBUG=warn+all wine Scylla.exe 2>&1 | grep -i error
```

### Issue: Can't access native Linux processes

**Cause:** Wine processes run in Windows emulation; can't directly access Linux processes.

**Solution:** Use the native Linux CLI build:

```bash
# Build native Linux version
cmake .. -DBUILD_GUI=OFF
make

# Use native CLI
./scylla-cli info
```

## Performance Tips

### 1. Use Wine Staging

Wine Staging has better performance optimizations:

```bash
sudo apt install winehq-staging
```

### 2. Disable Debug Output

```bash
# Disable all debug output for better performance
WINEDEBUG=-all wine Scylla.exe
```

### 3. Use 64-bit Wine for 64-bit Targets

```bash
# For analyzing 64-bit executables
wine64 Scylla_x64.exe

# For analyzing 32-bit executables
wine Scylla_x86.exe
```

### 4. Configure Wine for Performance

```bash
# Run Wine configuration
winecfg

# Recommended settings:
# - Graphics: "Emulate a virtual desktop" OFF (for better performance)
# - Staging: Enable CSMT (if available)
```

### 5. Use WINEPREFIX for Isolation

```bash
# Create dedicated Wine prefix
export WINEPREFIX=~/.wine-scylla
winecfg  # Initial setup

# Run Scylla in isolated environment
wine Scylla.exe
```

## Development Notes

### How Wine Compatibility is Implemented

Scylla includes Wine-specific code paths:

```cpp
// Automatic Wine detection
bool IsRunningUnderWine() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        void* wine_get_version = GetProcAddress(hNtdll, "wine_get_version");
        return (wine_get_version != nullptr);
    }
    return false;
}

// Wine-optimized code paths
if (IsRunningUnderWine()) {
    // Use simpler, better-supported APIs
    // Avoid advanced NT kernel features
    // Increase timeout values
}
```

### API Choices for Wine Compatibility

**✅ Preferred APIs (Well supported in Wine):**
- `CreateToolhelp32Snapshot` - Process/module enumeration
- `ReadProcessMemory` / `WriteProcessMemory` - Memory access
- `OpenProcess` with standard access rights
- `VirtualQueryEx` - Memory region queries
- Standard Win32 GUI APIs (User32, GDI32)

**❌ Avoided APIs (Poor Wine support):**
- Advanced `NtQuerySystemInformation` calls
- Undocumented NT APIs
- Kernel debugging APIs (`DebugActiveProcess` complexities)
- Driver loading APIs

### Building Wine-Optimized Builds

```bash
# Build with Wine compatibility enabled
cmake .. -DENABLE_WINE_SUPPORT=ON -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

### Testing Under Wine

```bash
# Run full test suite under Wine
wine scylla-cli.exe info

# Test with actual PE file
wine Scylla.exe /path/to/test.exe
```

## Best Practices

### For Users

1. **Keep Wine Updated** - Use latest stable or staging version
2. **Use Dedicated Prefix** - Isolate Scylla in its own WINEPREFIX
3. **Match Architectures** - Use wine for 32-bit, wine64 for 64-bit
4. **Report Issues** - Help improve Wine compatibility

### For Developers

1. **Test on Wine** - Always test Windows builds under Wine
2. **Use Standard APIs** - Stick to well-documented Win32 APIs
3. **Handle Failures Gracefully** - Wine may return different error codes
4. **Add Fallbacks** - Provide alternative code paths when needed

## Comparison: Wine vs Native Windows

| Feature | Native Windows | Wine on Linux |
|---------|----------------|---------------|
| PE Analysis | ✅ Full Speed | ✅ Full Speed |
| Import Rebuilding | ✅ Full Speed | ✅ Full Speed |
| Process Access | ✅ Full Access | ✅ Good Access |
| Memory Reading | ✅ Fast | ⚠️ Slightly Slower |
| GUI Rendering | ✅ Native | ⚠️ Emulated |
| DLL Injection | ✅ Full Support | ⚠️ Limited |

## Resources

- **Wine HQ**: https://www.winehq.org/
- **Wine AppDB**: https://appdb.winehq.org/
- **Wine Wiki**: https://wiki.winehq.org/
- **Scylla Issues**: https://github.com/NtQuery/Scylla/issues

## Contributing

Help improve Scylla's Wine compatibility:

1. Test on different Wine versions
2. Report Wine-specific bugs
3. Submit patches for better compatibility
4. Document workarounds

## License

See LICENSE file for details.
