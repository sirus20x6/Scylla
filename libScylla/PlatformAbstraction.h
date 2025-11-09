/*
 * Platform Abstraction Layer for Scylla
 *
 * This header provides cross-platform abstractions for:
 * - Process enumeration and access
 * - Memory reading/writing
 * - Module enumeration
 * - Thread operations
 *
 * Platform-specific implementations are in:
 * - PlatformWindows.cpp (Windows/Wine)
 * - PlatformLinux.cpp (Linux with ptrace)
 * - PlatformMacOS.cpp (macOS with task_for_pid)
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>

namespace Scylla {
namespace Platform {

// Platform-independent types
using ProcessId = uint32_t;
using ThreadId = uint32_t;
using ModuleHandle = uintptr_t;
using Address = uintptr_t;

// Process information structure
struct ProcessInfo {
    ProcessId pid;
    std::wstring name;
    std::wstring path;
    bool is64Bit;
};

// Module information structure
struct ModuleInfo {
    ModuleHandle handle;
    std::wstring name;
    std::wstring path;
    Address baseAddress;
    size_t size;
};

// Thread information structure
struct ThreadInfo {
    ThreadId tid;
    Address startAddress;
    Address entryPoint;
};

/*
 * Platform abstraction interface
 *
 * This interface must be implemented for each platform.
 * Windows implementation uses Win32 API
 * Linux implementation uses ptrace and /proc
 * macOS implementation uses task_for_pid and vm_* APIs
 */
class IPlatform {
public:
    virtual ~IPlatform() = default;

    // Process enumeration
    virtual bool EnumerateProcesses(std::vector<ProcessInfo>& processes) = 0;
    virtual bool OpenProcess(ProcessId pid) = 0;
    virtual bool CloseProcess() = 0;
    virtual ProcessId GetCurrentProcessId() = 0;

    // Memory operations
    virtual bool ReadMemory(Address address, void* buffer, size_t size) = 0;
    virtual bool WriteMemory(Address address, const void* buffer, size_t size) = 0;
    virtual bool QueryMemoryRegion(Address address, Address& baseAddress, size_t& size, uint32_t& protection) = 0;

    // Module enumeration
    virtual bool EnumerateModules(std::vector<ModuleInfo>& modules) = 0;
    virtual ModuleHandle GetModuleHandle(const std::wstring& moduleName) = 0;
    virtual bool GetModuleInfo(ModuleHandle module, ModuleInfo& info) = 0;

    // Thread operations
    virtual bool EnumerateThreads(std::vector<ThreadInfo>& threads) = 0;
    virtual bool SuspendThread(ThreadId tid) = 0;
    virtual bool ResumeThread(ThreadId tid) = 0;

    // Architecture detection
    virtual bool Is64BitProcess() = 0;
    virtual bool IsWow64Process() = 0;

    // Path utilities
    virtual std::wstring GetProcessPath() = 0;
    virtual std::wstring GetModulePath(ModuleHandle module) = 0;
};

/*
 * Factory function to create platform-specific implementation
 *
 * Returns the appropriate platform implementation:
 * - Windows: Uses Win32 API (works in Wine)
 * - Linux: Uses ptrace and /proc filesystem
 * - macOS: Uses Mach kernel APIs
 */
std::unique_ptr<IPlatform> CreatePlatform();

/*
 * Wine detection and compatibility
 */
#ifdef _WIN32
    bool IsRunningUnderWine();
    std::string GetWineVersion();
    void EnableWineOptimizations();
#endif

/*
 * Platform capabilities
 */
struct PlatformCapabilities {
    bool canInjectDLL;
    bool canCreateRemoteThread;
    bool canReadMemory;
    bool canWriteMemory;
    bool canEnumerateModules;
    bool canSuspendThreads;
    bool requiresRoot;  // For ptrace on Linux
};

PlatformCapabilities GetPlatformCapabilities();

/*
 * Error handling
 */
class PlatformException : public std::runtime_error {
public:
    explicit PlatformException(const std::string& message)
        : std::runtime_error(message) {}
};

} // namespace Platform
} // namespace Scylla
