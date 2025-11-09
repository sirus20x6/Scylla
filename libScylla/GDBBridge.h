#pragma once

#include "DebuggerBridge.h"
#include <map>
#include <mutex>

namespace scylla {
namespace debugger {

/**
 * GDB Bridge Implementation
 *
 * Integrates with GDB (GNU Debugger) via GDB/MI (Machine Interface).
 * Supports Linux, macOS, and other Unix-like systems.
 *
 * Connection methods:
 * 1. Local: Launch GDB as subprocess
 * 2. Remote: Connect to gdbserver via TCP/IP
 * 3. MI: GDB/MI protocol for programmatic control
 */
class GDBBridge : public IDebuggerBridge {
public:
    enum class ConnectionMode {
        Local,      // Local GDB subprocess
        Remote,     // Remote gdbserver connection
        Attach      // Attach to existing GDB session
    };

    GDBBridge();
    ~GDBBridge() override;

    // Connection
    bool Connect(const std::string& connectionString = "") override;
    void Disconnect() override;
    bool IsConnected() const override;
    DebuggerState GetState() const override;

    // Process control
    bool AttachToProcess(uint32_t pid) override;
    void DetachFromProcess() override;
    bool StartProcess(const std::string& exePath,
                     const std::string& args = "",
                     const std::string& workingDir = "") override;

    // Execution control
    bool Continue() override;
    bool Pause() override;
    bool StepInto() override;
    bool StepOver() override;
    bool StepOut() override;
    bool RunUntil(uint64_t address) override;

    // Breakpoints
    uint32_t SetBreakpoint(const Breakpoint& bp) override;
    bool RemoveBreakpoint(uint32_t breakpointId) override;
    bool SetBreakpointEnabled(uint32_t breakpointId, bool enabled) override;

    // Registers
    std::optional<uint64_t> ReadRegister(const std::string& registerName) override;
    bool WriteRegister(const std::string& registerName, uint64_t value) override;
    std::vector<RegisterValue> GetAllRegisters() override;

    // Memory
    std::vector<uint8_t> ReadMemory(uint64_t address, size_t size) override;
    bool WriteMemory(uint64_t address, const std::vector<uint8_t>& data) override;
    std::vector<MemoryRegionInfo> GetMemoryRegions() override;

    // Modules
    std::vector<ModuleInfo> GetModules() override;
    std::optional<ModuleInfo> GetModule(const std::string& moduleName) override;

    // Threads
    std::vector<ThreadInfo> GetThreads() override;

    // Commands
    std::string ExecuteCommand(const std::string& command) override;

    // Events
    void SetEventCallbacks(const DebuggerEvents& events) override;
    bool WaitForEvent(uint32_t timeoutMs = 0) override;

    // Information
    DebuggerType GetDebuggerType() const override { return DebuggerType::GDB; }
    std::string GetDebuggerVersion() const override;

    // GDB-specific methods
    /**
     * Set connection mode
     */
    void SetConnectionMode(ConnectionMode mode) { m_connectionMode = mode; }

    /**
     * Connect to gdbserver
     * @param host Hostname or IP
     * @param port Port number
     */
    bool ConnectToGdbServer(const std::string& host, uint16_t port);

    /**
     * Execute GDB/MI command
     * @param command GDB/MI command
     * @return Response in MI format
     */
    std::string ExecuteMICommand(const std::string& command);

    /**
     * Execute GDB script file
     * @param scriptPath Path to GDB script (.gdb)
     */
    bool ExecuteScriptFile(const std::string& scriptPath);

    /**
     * Set breakpoint with condition
     * @param address Address for breakpoint
     * @param condition GDB condition expression
     */
    uint32_t SetConditionalBreakpoint(uint64_t address, const std::string& condition);

    /**
     * Set watchpoint (memory breakpoint)
     * @param address Address to watch
     * @param size Size of watched region
     * @param accessType Access type (read/write/both)
     */
    uint32_t SetWatchpoint(uint64_t address, size_t size, MemoryAccessType accessType);

    /**
     * Set catchpoint (exception/signal)
     * @param signal Signal name (e.g., "SIGSEGV")
     */
    uint32_t SetCatchpoint(const std::string& signal);

    /**
     * Get backtrace
     * @param maxFrames Maximum number of stack frames
     */
    std::vector<uint64_t> GetBacktrace(size_t maxFrames = 100);

    /**
     * Evaluate expression
     * @param expression GDB expression to evaluate
     * @return Result value or nullopt on error
     */
    std::optional<uint64_t> EvaluateExpression(const std::string& expression);

    /**
     * Get symbol information
     * @param symbolName Symbol name
     */
    struct SymbolInfo {
        std::string name;
        uint64_t address = 0;
        std::string type;
        uint64_t size = 0;
    };
    std::optional<SymbolInfo> GetSymbol(const std::string& symbolName);

    /**
     * Get loaded shared libraries (Linux .so, macOS .dylib)
     */
    struct SharedLibrary {
        std::string name;
        uint64_t baseAddress = 0;
        uint64_t size = 0;
        bool symbolsLoaded = false;
    };
    std::vector<SharedLibrary> GetSharedLibraries();

    /**
     * Set GDB parameter
     * @param param Parameter name (e.g., "pagination", "confirm")
     * @param value Value to set
     */
    bool SetParameter(const std::string& param, const std::string& value);

    /**
     * Enable/disable following fork
     */
    bool SetFollowFork(bool enable);

    /**
     * Enable/disable following exec
     */
    bool SetFollowExec(bool enable);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;

    ConnectionMode m_connectionMode = ConnectionMode::Local;
    DebuggerState m_state = DebuggerState::Disconnected;
    DebuggerEvents m_events;
    std::map<uint32_t, Breakpoint> m_breakpoints;
    std::map<uint32_t, uint32_t> m_breakpointIdMap;  // Our ID -> GDB ID
    std::mutex m_mutex;
    uint32_t m_nextBreakpointId = 1;

    // GDB/MI parsing
    struct MIResult {
        std::string type;  // "done", "running", "stopped", "error"
        std::map<std::string, std::string> values;
        std::string message;
    };

    // Helper methods
    bool SendMICommand(const std::string& command, MIResult& result);
    bool ParseMIResponse(const std::string& response, MIResult& result);
    bool ParseMemoryMap(const std::string& output, std::vector<MemoryRegionInfo>& regions);
    bool ParseSharedLibs(const std::string& output, std::vector<ModuleInfo>& modules);
    void ProcessAsyncEvent(const std::string& eventData);
    std::string RegisterNameToGDB(const std::string& registerName);
    std::string FormatAddress(uint64_t address);
};

} // namespace debugger
} // namespace scylla
