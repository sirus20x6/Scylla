/*
 * Scylla - Debugger Bridge Implementation
 *
 * Factory and utility functions for debugger integration
 */

#include "DebuggerBridge.h"
#include "X64DbgBridge.h"
#include "GDBBridge.h"
#include <algorithm>
#include <chrono>
#include <thread>
#include <fstream>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/types.h>
#endif

namespace scylla {
namespace debugger {

// Factory implementation
std::unique_ptr<IDebuggerBridge> DebuggerBridgeFactory::Create(DebuggerType type) {
    switch (type) {
        case DebuggerType::X64Dbg:
            #ifdef _WIN32
            return std::make_unique<X64DbgBridge>();
            #else
            return nullptr;  // x64dbg only available on Windows
            #endif

        case DebuggerType::GDB:
            #ifndef _WIN32
            return std::make_unique<GDBBridge>();
            #else
            // GDB can work on Windows too (MinGW-w64), but less common
            return std::make_unique<GDBBridge>();
            #endif

        case DebuggerType::LLDB:
            // TODO: Implement LLDB bridge
            return nullptr;

        case DebuggerType::WinDbg:
            // TODO: Implement WinDbg bridge
            return nullptr;

        default:
            return nullptr;
    }
}

std::unique_ptr<IDebuggerBridge> DebuggerBridgeFactory::CreateAuto() {
    // Try to auto-detect available debugger on this platform
    #ifdef _WIN32
    // On Windows, prefer x64dbg if available
    if (IsAvailable(DebuggerType::X64Dbg)) {
        return Create(DebuggerType::X64Dbg);
    }
    #else
    // On Unix-like systems, prefer GDB
    if (IsAvailable(DebuggerType::GDB)) {
        return Create(DebuggerType::GDB);
    }
    // Try LLDB on macOS
    #ifdef __APPLE__
    if (IsAvailable(DebuggerType::LLDB)) {
        return Create(DebuggerType::LLDB);
    }
    #endif
    #endif

    return nullptr;
}

bool DebuggerBridgeFactory::IsAvailable(DebuggerType type) {
    switch (type) {
        case DebuggerType::X64Dbg:
            #ifdef _WIN32
            // Check if x64dbg bridge server is running or plugin is loaded
            // For now, assume available on Windows
            return true;
            #else
            return false;
            #endif

        case DebuggerType::GDB:
            #ifndef _WIN32
            // Check if gdb is in PATH
            return system("which gdb > /dev/null 2>&1") == 0;
            #else
            return system("where gdb > nul 2>&1") == 0;
            #endif

        case DebuggerType::LLDB:
            #ifdef __APPLE__
            return system("which lldb > /dev/null 2>&1") == 0;
            #else
            return false;
            #endif

        case DebuggerType::WinDbg:
            #ifdef _WIN32
            // Check for WinDbg installation
            return false;  // TODO: Implement
            #else
            return false;
            #endif

        default:
            return false;
    }
}

// Utility functions implementation
namespace DebuggerUtils {

std::optional<ModuleInfo> WaitForModuleLoad(IDebuggerBridge& bridge,
                                           const std::string& moduleName,
                                           uint32_t timeoutMs) {
    auto startTime = std::chrono::steady_clock::now();

    while (true) {
        // Check if module is loaded
        auto modules = bridge.GetModules();
        for (const auto& module : modules) {
            if (module.name.find(moduleName) != std::string::npos) {
                return module;
            }
        }

        // Check timeout
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime
        ).count();

        if (elapsed >= timeoutMs) {
            return std::nullopt;
        }

        // Wait a bit before checking again
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

uint64_t FindPattern(IDebuggerBridge& bridge,
                    const std::vector<uint8_t>& pattern,
                    const std::vector<bool>* mask,
                    uint64_t startAddress,
                    uint64_t size) {
    if (pattern.empty()) {
        return 0;
    }

    // Get memory regions if not specified
    if (startAddress == 0 || size == 0) {
        auto regions = bridge.GetMemoryRegions();
        if (regions.empty()) {
            return 0;
        }
        startAddress = regions[0].baseAddress;
        size = regions[0].size;
    }

    // Read memory in chunks
    const size_t chunkSize = 0x10000;  // 64KB chunks
    uint64_t currentAddress = startAddress;
    uint64_t endAddress = startAddress + size;

    while (currentAddress < endAddress) {
        size_t readSize = std::min(chunkSize, static_cast<size_t>(endAddress - currentAddress));
        auto data = bridge.ReadMemory(currentAddress, readSize);

        if (data.empty()) {
            currentAddress += chunkSize;
            continue;
        }

        // Search for pattern
        for (size_t i = 0; i + pattern.size() <= data.size(); i++) {
            bool found = true;

            for (size_t j = 0; j < pattern.size(); j++) {
                // Check mask if provided
                if (mask && j < mask->size() && !(*mask)[j]) {
                    continue;  // Wildcard
                }

                if (data[i + j] != pattern[j]) {
                    found = false;
                    break;
                }
            }

            if (found) {
                return currentAddress + i;
            }
        }

        currentAddress += chunkSize;
    }

    return 0;
}

bool DumpMemory(IDebuggerBridge& bridge,
               const std::string& outputPath,
               uint64_t baseAddress,
               uint64_t size) {
    // Get main module if address not specified
    if (baseAddress == 0) {
        auto modules = bridge.GetModules();
        if (modules.empty()) {
            return false;
        }
        baseAddress = modules[0].baseAddress;
        size = modules[0].size;
    }

    // Read memory
    auto data = bridge.ReadMemory(baseAddress, size);
    if (data.empty()) {
        return false;
    }

    // Write to file
    std::ofstream outFile(outputPath, std::ios::binary);
    if (!outFile) {
        return false;
    }

    outFile.write(reinterpret_cast<const char*>(data.data()), data.size());
    return outFile.good();
}

uint64_t DetectOEPWithDebugger(IDebuggerBridge& bridge) {
    // Automated OEP detection using debugger
    // This uses a combination of heuristics:
    // 1. Set breakpoint on common unpacker patterns
    // 2. Monitor for PUSHAD/POPAD
    // 3. Look for tail jumps
    // 4. Detect entropy transitions

    uint64_t detectedOEP = 0;

    // Set breakpoint on POPAD instruction (common in unpackers)
    // This is a simplified approach - real implementation would be more sophisticated

    // Get current instruction pointer
    auto eip = bridge.ReadRegister("rip");
    if (!eip.has_value()) {
        eip = bridge.ReadRegister("eip");
    }

    if (eip.has_value()) {
        // For now, return current IP as fallback
        // Real implementation would analyze code and set appropriate breakpoints
        detectedOEP = eip.value();
    }

    return detectedOEP;
}

} // namespace DebuggerUtils

} // namespace debugger
} // namespace scylla
