#pragma once

#include <string>
<vector>
#include <cstdint>
#include <memory>
#include <functional>
#include <optional>

namespace scylla {
namespace debugger {

/**
 * Debugger type
 */
enum class DebuggerType {
    None,
    X64Dbg,         // x64dbg (Windows)
    GDB,            // GDB (Linux/Unix)
    LLDB,           // LLDB (macOS/Linux)
    WinDbg          // WinDbg (Windows)
};

/**
 * Debugger state
 */
enum class DebuggerState {
    Disconnected,
    Connected,
    Running,
    Paused,
    Terminated
};

/**
 * Breakpoint type
 */
enum class BreakpointType {
    Software,       // INT3 breakpoint
    Hardware,       // Hardware breakpoint (limited qty)
    Memory,         // Memory access breakpoint
    Conditional     // Conditional breakpoint
};

/**
 * Memory access type
 */
enum class MemoryAccessType {
    Read,
    Write,
    Execute,
    ReadWrite
};

/**
 * Register information
 */
struct RegisterValue {
    std::string name;
    uint64_t value = 0;
    size_t size = 0;  // In bytes (4 for 32-bit, 8 for 64-bit)
};

/**
 * Breakpoint information
 */
struct Breakpoint {
    uint64_t address = 0;
    BreakpointType type = BreakpointType::Software;
    bool enabled = true;
    std::string condition;
    uint32_t hitCount = 0;
    std::function<void(uint64_t address)> callback;
};

/**
 * Memory region information
 */
struct MemoryRegionInfo {
    uint64_t baseAddress = 0;
    uint64_t size = 0;
    uint32_t protect = 0;
    bool isReadable = false;
    bool isWritable = false;
    bool isExecutable = false;
    std::string name;
    std::string type;  // "Private", "Mapped", "Image"
};

/**
 * Module/Library information
 */
struct ModuleInfo {
    std::string name;
    std::string path;
    uint64_t baseAddress = 0;
    uint64_t size = 0;
    uint64_t entryPoint = 0;
};

/**
 * Thread information
 */
struct ThreadInfo {
    uint32_t threadId = 0;
    uint64_t startAddress = 0;
    uint32_t priority = 0;
    bool isSuspended = false;
};

/**
 * Exception information
 */
struct ExceptionInfo {
    uint32_t exceptionCode = 0;
    uint64_t exceptionAddress = 0;
    std::string description;
    bool isFirstChance = true;
};

/**
 * Debugger event callback
 */
struct DebuggerEvents {
    std::function<void(uint64_t address)> onBreakpoint;
    std::function<void(const ExceptionInfo& info)> onException;
    std::function<void(const ModuleInfo& module)> onModuleLoad;
    std::function<void(const ModuleInfo& module)> onModuleUnload;
    std::function<void(uint32_t threadId)> onThreadCreate;
    std::function<void(uint32_t threadId)> onThreadExit;
    std::function<void(int exitCode)> onProcessExit;
};

/**
 * Generic Debugger Bridge Interface
 *
 * Provides unified interface for controlling different debuggers
 * (x64dbg, GDB, LLDB, WinDbg) for automated unpacking workflows.
 */
class IDebuggerBridge {
public:
    virtual ~IDebuggerBridge() = default;

    /**
     * Connect to debugger
     * @param connectionString Debugger-specific connection string
     * @return true if connected successfully
     */
    virtual bool Connect(const std::string& connectionString = "") = 0;

    /**
     * Disconnect from debugger
     */
    virtual void Disconnect() = 0;

    /**
     * Check if connected to debugger
     */
    virtual bool IsConnected() const = 0;

    /**
     * Get current debugger state
     */
    virtual DebuggerState GetState() const = 0;

    /**
     * Attach to process
     * @param pid Process ID to attach to
     * @return true if attached successfully
     */
    virtual bool AttachToProcess(uint32_t pid) = 0;

    /**
     * Detach from current process
     */
    virtual void DetachFromProcess() = 0;

    /**
     * Start new process under debugger
     * @param exePath Executable path
     * @param args Command line arguments
     * @param workingDir Working directory
     * @return true if started successfully
     */
    virtual bool StartProcess(const std::string& exePath,
                             const std::string& args = "",
                             const std::string& workingDir = "") = 0;

    /**
     * Continue execution
     */
    virtual bool Continue() = 0;

    /**
     * Pause execution
     */
    virtual bool Pause() = 0;

    /**
     * Step into (single instruction)
     */
    virtual bool StepInto() = 0;

    /**
     * Step over (skip calls)
     */
    virtual bool StepOver() = 0;

    /**
     * Step out (return from function)
     */
    virtual bool StepOut() = 0;

    /**
     * Run until address
     * @param address Address to run to
     */
    virtual bool RunUntil(uint64_t address) = 0;

    /**
     * Set breakpoint
     * @param bp Breakpoint to set
     * @return Breakpoint ID or 0 on failure
     */
    virtual uint32_t SetBreakpoint(const Breakpoint& bp) = 0;

    /**
     * Remove breakpoint
     * @param breakpointId Breakpoint ID to remove
     */
    virtual bool RemoveBreakpoint(uint32_t breakpointId) = 0;

    /**
     * Enable/disable breakpoint
     * @param breakpointId Breakpoint ID
     * @param enabled Enable or disable
     */
    virtual bool SetBreakpointEnabled(uint32_t breakpointId, bool enabled) = 0;

    /**
     * Read register value
     * @param registerName Register name (e.g., "rip", "eax")
     * @return Register value or nullopt on failure
     */
    virtual std::optional<uint64_t> ReadRegister(const std::string& registerName) = 0;

    /**
     * Write register value
     * @param registerName Register name
     * @param value Value to write
     */
    virtual bool WriteRegister(const std::string& registerName, uint64_t value) = 0;

    /**
     * Get all register values
     */
    virtual std::vector<RegisterValue> GetAllRegisters() = 0;

    /**
     * Read memory
     * @param address Address to read from
     * @param size Number of bytes to read
     * @return Memory contents or empty vector on failure
     */
    virtual std::vector<uint8_t> ReadMemory(uint64_t address, size_t size) = 0;

    /**
     * Write memory
     * @param address Address to write to
     * @param data Data to write
     */
    virtual bool WriteMemory(uint64_t address, const std::vector<uint8_t>& data) = 0;

    /**
     * Get memory regions
     */
    virtual std::vector<MemoryRegionInfo> GetMemoryRegions() = 0;

    /**
     * Get loaded modules
     */
    virtual std::vector<ModuleInfo> GetModules() = 0;

    /**
     * Get module by name
     * @param moduleName Module name (e.g., "ntdll.dll")
     */
    virtual std::optional<ModuleInfo> GetModule(const std::string& moduleName) = 0;

    /**
     * Get threads
     */
    virtual std::vector<ThreadInfo> GetThreads() = 0;

    /**
     * Execute debugger command
     * @param command Debugger-specific command
     * @return Command output
     */
    virtual std::string ExecuteCommand(const std::string& command) = 0;

    /**
     * Set event callbacks
     */
    virtual void SetEventCallbacks(const DebuggerEvents& events) = 0;

    /**
     * Wait for debugger event
     * @param timeoutMs Timeout in milliseconds (0 = infinite)
     * @return true if event occurred, false if timeout
     */
    virtual bool WaitForEvent(uint32_t timeoutMs = 0) = 0;

    /**
     * Get debugger type
     */
    virtual DebuggerType GetDebuggerType() const = 0;

    /**
     * Get debugger version string
     */
    virtual std::string GetDebuggerVersion() const = 0;
};

/**
 * Factory for creating debugger bridges
 */
class DebuggerBridgeFactory {
public:
    /**
     * Create debugger bridge
     * @param type Debugger type
     * @return Debugger bridge instance or nullptr on failure
     */
    static std::unique_ptr<IDebuggerBridge> Create(DebuggerType type);

    /**
     * Auto-detect and create available debugger
     * @return Debugger bridge instance or nullptr if no debugger found
     */
    static std::unique_ptr<IDebuggerBridge> CreateAuto();

    /**
     * Check if debugger type is available on this platform
     */
    static bool IsAvailable(DebuggerType type);
};

/**
 * Helper utilities for debugger operations
 */
namespace DebuggerUtils {
    /**
     * Wait for module to load
     * @param bridge Debugger bridge
     * @param moduleName Module name to wait for
     * @param timeoutMs Timeout in milliseconds
     * @return Module info if loaded, nullopt if timeout
     */
    std::optional<ModuleInfo> WaitForModuleLoad(IDebuggerBridge& bridge,
                                                const std::string& moduleName,
                                                uint32_t timeoutMs = 10000);

    /**
     * Find pattern in memory
     * @param bridge Debugger bridge
     * @param pattern Byte pattern to find
     * @param mask Mask (nullptr for exact match)
     * @param startAddress Start address for search
     * @param size Size of region to search
     * @return Address of pattern or 0 if not found
     */
    uint64_t FindPattern(IDebuggerBridge& bridge,
                        const std::vector<uint8_t>& pattern,
                        const std::vector<bool>* mask = nullptr,
                        uint64_t startAddress = 0,
                        uint64_t size = 0);

    /**
     * Dump process memory to file
     * @param bridge Debugger bridge
     * @param outputPath Output file path
     * @param baseAddress Base address to dump (0 = main module)
     * @param size Size to dump (0 = entire module)
     */
    bool DumpMemory(IDebuggerBridge& bridge,
                   const std::string& outputPath,
                   uint64_t baseAddress = 0,
                   uint64_t size = 0);

    /**
     * Automated OEP detection using debugger
     * @param bridge Debugger bridge
     * @return Detected OEP address or 0
     */
    uint64_t DetectOEPWithDebugger(IDebuggerBridge& bridge);
}

} // namespace debugger
} // namespace scylla
