#pragma once

#include "DebuggerBridge.h"
#include <map>
#include <mutex>

namespace scylla {
namespace debugger {

/**
 * x64dbg Bridge Implementation
 *
 * Integrates with x64dbg debugger via its plugin API and remote
 * debugging interface. Supports both 32-bit (x32dbg) and 64-bit (x64dbg).
 *
 * Connection methods:
 * 1. Plugin mode: Direct integration via x64dbg plugin SDK
 * 2. Remote mode: TCP/IP connection to x64dbg bridge server
 * 3. Script mode: Control via x64dbg scripting language
 */
class X64DbgBridge : public IDebuggerBridge {
public:
    enum class ConnectionMode {
        Plugin,     // Direct plugin integration
        Remote,     // TCP/IP remote connection
        Script      // Script-based control
    };

    X64DbgBridge();
    ~X64DbgBridge() override;

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
    DebuggerType GetDebuggerType() const override { return DebuggerType::X64Dbg; }
    std::string GetDebuggerVersion() const override;

    // x64dbg-specific methods
    /**
     * Set connection mode
     */
    void SetConnectionMode(ConnectionMode mode) { m_connectionMode = mode; }

    /**
     * Execute x64dbg script
     * @param scriptPath Path to .txt script file
     * @return true if executed successfully
     */
    bool ExecuteScript(const std::string& scriptPath);

    /**
     * Set breakpoint with x64dbg expression
     * @param expression x64dbg expression (e.g., "GetProcAddress")
     * @param condition Optional condition
     */
    uint32_t SetBreakpointExpression(const std::string& expression,
                                     const std::string& condition = "");

    /**
     * Get symbol address
     * @param symbolName Symbol name (e.g., "kernel32.LoadLibraryA")
     * @return Symbol address or 0 if not found
     */
    uint64_t GetSymbolAddress(const std::string& symbolName);

    /**
     * Enable/disable system breakpoint on module load
     */
    bool SetBreakOnModuleLoad(const std::string& moduleName, bool enable);

    /**
     * Get call stack
     */
    std::vector<uint64_t> GetCallStack();

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;

    ConnectionMode m_connectionMode = ConnectionMode::Remote;
    DebuggerState m_state = DebuggerState::Disconnected;
    DebuggerEvents m_events;
    std::map<uint32_t, Breakpoint> m_breakpoints;
    std::mutex m_mutex;
    uint32_t m_nextBreakpointId = 1;

    // Helper methods
    bool SendCommand(const std::string& command, std::string& response);
    bool ParseMemoryInfo(const std::string& output, std::vector<MemoryRegionInfo>& regions);
    bool ParseModuleInfo(const std::string& output, std::vector<ModuleInfo>& modules);
    void ProcessEvent(const std::string& eventData);
};

} // namespace debugger
} // namespace scylla
