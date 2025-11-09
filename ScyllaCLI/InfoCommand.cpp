/*
 * Scylla CLI - Info Command Implementation
 */

#include "Commands.h"
#include <iostream>
#include <sstream>

#ifdef _WIN32
    #include <windows.h>
#elif defined(__linux__)
    #include <sys/utsname.h>
#elif defined(__APPLE__)
    #include <sys/utsname.h>
    #include <sys/sysctl.h>
#endif

namespace ScyllaCLI {

std::string InfoCommand::GetHelp() const {
    return R"(
Display information about the platform, Scylla version, and capabilities.

This command shows:
  - Platform and operating system details
  - Architecture (x86, x64, ARM)
  - Wine detection (when applicable)
  - Compiler and build information
  - Available features and capabilities
)";
}

std::string InfoCommand::GetUsage() const {
    return R"(
Usage: scylla-cli info

No options required. This command displays platform information.
)";
}

int InfoCommand::Execute(const CommandOptions& opts) {
    std::cout << "Scylla CLI v0.9.9 - PE Import Table Reconstruction Tool\n";
    std::cout << "Cross-platform Edition\n";
    std::cout << "https://github.com/NtQuery/Scylla\n\n";

    std::cout << "Platform Information:\n";
    std::cout << "═════════════════════════════════════════════════════════\n";

#if defined(_WIN32)
    std::cout << "  Operating System: Windows\n";

    #if defined(_WIN64)
        std::cout << "  Architecture:     x64\n";
    #else
        std::cout << "  Architecture:     x86\n";
    #endif

    #if defined(SCYLLA_WINE_COMPAT)
        std::cout << "  Wine Compatibility: Enabled\n";
    #endif

    // Check if running under Wine
    #ifdef _WIN32
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            void* wine_get_version = (void*)GetProcAddress(hNtdll, "wine_get_version");
            if (wine_get_version) {
                typedef const char* (*wine_get_version_t)(void);
                wine_get_version_t get_version = (wine_get_version_t)wine_get_version;
                std::cout << "  Running under Wine: Yes\n";
                std::cout << "  Wine Version:       " << get_version() << "\n";
            } else {
                std::cout << "  Running under Wine: No\n";
            }
        }
    #endif

    // Windows version
    OSVERSIONINFOW osvi = { sizeof(osvi) };
    if (GetVersionExW(&osvi)) {
        std::cout << "  Windows Version:    " << osvi.dwMajorVersion << "."
                  << osvi.dwMinorVersion << " Build " << osvi.dwBuildNumber << "\n";
    }

#elif defined(__linux__)
    std::cout << "  Operating System: Linux\n";

    struct utsname unameData;
    if (uname(&unameData) == 0) {
        std::cout << "  Kernel:           " << unameData.sysname << " "
                  << unameData.release << "\n";
        std::cout << "  Distribution:     " << unameData.version << "\n";
        std::cout << "  Architecture:     " << unameData.machine << "\n";
    }

#elif defined(__APPLE__)
    std::cout << "  Operating System: macOS\n";

    struct utsname unameData;
    if (uname(&unameData) == 0) {
        std::cout << "  Kernel:           " << unameData.sysname << " "
                  << unameData.release << "\n";
        std::cout << "  Architecture:     " << unameData.machine << "\n";
    }

    // Get macOS version
    char osversion[256];
    size_t size = sizeof(osversion);
    if (sysctlbyname("kern.osproductversion", osversion, &size, NULL, 0) == 0) {
        std::cout << "  macOS Version:    " << osversion << "\n";
    }

#else
    std::cout << "  Operating System: Unknown\n";
#endif

    std::cout << "  C++ Standard:     " << __cplusplus << "\n";

#if defined(__GNUC__)
    std::cout << "  Compiler:         GCC " << __GNUC__ << "."
              << __GNUC_MINOR__ << "." << __GNUC_PATCHLEVEL__ << "\n";
#elif defined(_MSC_VER)
    std::cout << "  Compiler:         MSVC " << _MSC_VER << "\n";
#elif defined(__clang__)
    std::cout << "  Compiler:         Clang " << __clang_major__ << "."
              << __clang_minor__ << "." << __clang_patchlevel__ << "\n";
#endif

    std::cout << "\nBuild Configuration:\n";
    std::cout << "═════════════════════════════════════════════════════════\n";

#ifdef SCYLLA_WINDOWS
    std::cout << "  Platform Support: Windows (native)\n";
#elif defined(SCYLLA_LINUX)
    std::cout << "  Platform Support: Linux (native)\n";
#elif defined(SCYLLA_MACOS)
    std::cout << "  Platform Support: macOS (native)\n";
#endif

#ifdef CMAKE_BUILD_TYPE
    std::cout << "  Build Type:       " << CMAKE_BUILD_TYPE << "\n";
#else
    std::cout << "  Build Type:       Release\n";
#endif

    std::cout << "\nCapabilities:\n";
    std::cout << "═════════════════════════════════════════════════════════\n";
    std::cout << "  ✓ PE file analysis\n";
    std::cout << "  ✓ IAT reconstruction\n";
    std::cout << "  ✓ Import scanning\n";
    std::cout << "  ✓ JSON/XML export\n";

#if defined(_WIN32)
    std::cout << "  ✓ Process dumping\n";
    std::cout << "  ✓ Memory reading\n";
    std::cout << "  ✓ DLL injection\n";
#else
    std::cout << "  ⚠ Process dumping (limited)\n";
    std::cout << "  ⚠ Memory reading (requires root)\n";
    std::cout << "  ✗ DLL injection (not available)\n";
#endif

    std::cout << "  ✓ Batch processing\n";
    std::cout << "  ✓ Plugin support\n";
    std::cout << "  ✓ Packer detection\n";
    std::cout << "  ✓ Security analysis\n";

    std::cout << "\nFormat Support:\n";
    std::cout << "═════════════════════════════════════════════════════════\n";
    std::cout << "  ✓ PE32 (x86)\n";
    std::cout << "  ✓ PE32+ (x64)\n";

#if defined(SCYLLA_ELF_SUPPORT)
    std::cout << "  ✓ ELF (Linux)\n";
#else
    std::cout << "  ⚠ ELF (planned)\n";
#endif

#if defined(SCYLLA_MACHO_SUPPORT)
    std::cout << "  ✓ Mach-O (macOS)\n";
#else
    std::cout << "  ⚠ Mach-O (planned)\n";
#endif

#if defined(SCYLLA_DOTNET_SUPPORT)
    std::cout << "  ✓ .NET assemblies\n";
#else
    std::cout << "  ⚠ .NET (planned)\n";
#endif

    std::cout << "\n";
    return 0;
}

} // namespace ScyllaCLI
