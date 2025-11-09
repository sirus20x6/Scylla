/*
 * Scylla - GDB Bridge Implementation
 *
 * Integration with GDB via GDB/MI (Machine Interface) protocol
 */

#include "GDBBridge.h"
#include <sstream>
#include <fstream>
#include <algorithm>
#include <cstdio>
#include <cstring>

#ifndef _WIN32
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#endif

namespace scylla {
namespace debugger {

// Implementation class
class GDBBridge::Impl {
public:
    FILE* gdbIn = nullptr;
    FILE* gdbOut = nullptr;
    pid_t gdbPid = -1;
    uint32_t miToken = 1;

    bool LaunchGDB() {
        #ifndef _WIN32
        int inPipe[2], outPipe[2];
        
        if (pipe(inPipe) < 0 || pipe(outPipe) < 0) {
            return false;
        }

        gdbPid = fork();
        if (gdbPid < 0) {
            return false;
        }

        if (gdbPid == 0) {
            // Child process: launch GDB
            dup2(inPipe[0], STDIN_FILENO);
            dup2(outPipe[1], STDOUT_FILENO);
            dup2(outPipe[1], STDERR_FILENO);

            close(inPipe[0]);
            close(inPipe[1]);
            close(outPipe[0]);
            close(outPipe[1]);

            execlp("gdb", "gdb", "--interpreter=mi", "--quiet", nullptr);
            exit(1);  // If exec fails
        }

        // Parent process
        close(inPipe[0]);
        close(outPipe[1]);

        gdbIn = fdopen(inPipe[1], "w");
        gdbOut = fdopen(outPipe[0], "r");

        if (!gdbIn || !gdbOut) {
            return false;
        }

        setbuf(gdbIn, nullptr);  // Unbuffered
        return true;
        #else
        // Windows implementation would use CreateProcess with pipes
        return false;
        #endif
    }

    void TerminateGDB() {
        #ifndef _WIN32
        if (gdbPid > 0) {
            kill(gdbPid, SIGTERM);
            waitpid(gdbPid, nullptr, 0);
            gdbPid = -1;
        }
        #endif

        if (gdbIn) {
            fclose(gdbIn);
            gdbIn = nullptr;
        }
        if (gdbOut) {
            fclose(gdbOut);
            gdbOut = nullptr;
        }
    }

    std::string ReadLine() {
        if (!gdbOut) {
            return "";
        }

        char buffer[4096];
        if (fgets(buffer, sizeof(buffer), gdbOut)) {
            return buffer;
        }
        return "";
    }

    bool WriteLine(const std::string& line) {
        if (!gdbIn) {
            return false;
        }

        fprintf(gdbIn, "%s\n", line.c_str());
        fflush(gdbIn);
        return true;
    }

    uint32_t GetNextToken() {
        return miToken++;
    }
};

GDBBridge::GDBBridge() : pImpl(std::make_unique<Impl>()) {
}

GDBBridge::~GDBBridge() {
    Disconnect();
}

bool GDBBridge::Connect(const std::string& connectionString) {
    if (m_connectionMode == ConnectionMode::Local) {
        if (pImpl->LaunchGDB()) {
            m_state = DebuggerState::Connected;

            // Set some default GDB parameters
            ExecuteMICommand("-gdb-set pagination off");
            ExecuteMICommand("-gdb-set confirm off");

            return true;
        }
    }
    else if (m_connectionMode == ConnectionMode::Remote) {
        // Parse connection string (format: "host:port")
        if (connectionString.empty()) {
            return false;
        }

        if (pImpl->LaunchGDB()) {
            // Connect to gdbserver
            std::string cmd = "-target-select remote " + connectionString;
            if (!ExecuteMICommand(cmd).empty()) {
                m_state = DebuggerState::Connected;
                return true;
            }
        }
    }

    return false;
}

void GDBBridge::Disconnect() {
    if (m_state != DebuggerState::Disconnected) {
        ExecuteMICommand("-gdb-exit");
        pImpl->TerminateGDB();
        m_state = DebuggerState::Disconnected;
    }
}

bool GDBBridge::IsConnected() const {
    return m_state != DebuggerState::Disconnected;
}

DebuggerState GDBBridge::GetState() const {
    return m_state;
}

bool GDBBridge::AttachToProcess(uint32_t pid) {
    std::ostringstream cmd;
    cmd << "-target-attach " << pid;
    auto response = ExecuteMICommand(cmd.str());
    return !response.empty();
}

void GDBBridge::DetachFromProcess() {
    ExecuteMICommand("-target-detach");
}

bool GDBBridge::StartProcess(const std::string& exePath, const std::string& args, const std::string& workingDir) {
    // Set executable
    std::string cmd = "-file-exec-and-symbols \"" + exePath + "\"";
    ExecuteMICommand(cmd);

    // Set arguments if provided
    if (!args.empty()) {
        cmd = "-exec-arguments " + args;
        ExecuteMICommand(cmd);
    }

    // Set working directory if provided
    if (!workingDir.empty()) {
        cmd = "-environment-cd \"" + workingDir + "\"";
        ExecuteMICommand(cmd);
    }

    // Start execution
    auto response = ExecuteMICommand("-exec-run");
    if (!response.empty()) {
        m_state = DebuggerState::Running;
        return true;
    }

    return false;
}

bool GDBBridge::Continue() {
    auto response = ExecuteMICommand("-exec-continue");
    if (!response.empty()) {
        m_state = DebuggerState::Running;
        return true;
    }
    return false;
}

bool GDBBridge::Pause() {
    auto response = ExecuteMICommand("-exec-interrupt");
    if (!response.empty()) {
        m_state = DebuggerState::Paused;
        return true;
    }
    return false;
}

bool GDBBridge::StepInto() {
    return !ExecuteMICommand("-exec-step-instruction").empty();
}

bool GDBBridge::StepOver() {
    return !ExecuteMICommand("-exec-next-instruction").empty();
}

bool GDBBridge::StepOut() {
    return !ExecuteMICommand("-exec-finish").empty();
}

bool GDBBridge::RunUntil(uint64_t address) {
    std::ostringstream cmd;
    cmd << "-exec-until *0x" << std::hex << address;
    return !ExecuteMICommand(cmd.str()).empty();
}

uint32_t GDBBridge::SetBreakpoint(const Breakpoint& bp) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::ostringstream cmd;
    cmd << "-break-insert *0x" << std::hex << bp.address;

    MIResult result;
    if (SendMICommand(cmd.str(), result)) {
        uint32_t ourId = m_nextBreakpointId++;
        m_breakpoints[ourId] = bp;

        // Extract GDB breakpoint number from result
        if (result.values.find("number") != result.values.end()) {
            uint32_t gdbId = std::stoul(result.values["number"]);
            m_breakpointIdMap[ourId] = gdbId;
        }

        return ourId;
    }

    return 0;
}

bool GDBBridge::RemoveBreakpoint(uint32_t breakpointId) {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_breakpointIdMap.find(breakpointId);
    if (it == m_breakpointIdMap.end()) {
        return false;
    }

    std::ostringstream cmd;
    cmd << "-break-delete " << it->second;

    if (!ExecuteMICommand(cmd.str()).empty()) {
        m_breakpoints.erase(breakpointId);
        m_breakpointIdMap.erase(it);
        return true;
    }

    return false;
}

bool GDBBridge::SetBreakpointEnabled(uint32_t breakpointId, bool enabled) {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_breakpointIdMap.find(breakpointId);
    if (it == m_breakpointIdMap.end()) {
        return false;
    }

    std::ostringstream cmd;
    cmd << (enabled ? "-break-enable " : "-break-disable ") << it->second;

    if (!ExecuteMICommand(cmd.str()).empty()) {
        auto bpIt = m_breakpoints.find(breakpointId);
        if (bpIt != m_breakpoints.end()) {
            bpIt->second.enabled = enabled;
        }
        return true;
    }

    return false;
}

std::optional<uint64_t> GDBBridge::ReadRegister(const std::string& registerName) {
    std::string gdbReg = RegisterNameToGDB(registerName);
    std::string cmd = "-data-evaluate-expression $" + gdbReg;

    MIResult result;
    if (SendMICommand(cmd, result)) {
        if (result.values.find("value") != result.values.end()) {
            try {
                return std::stoull(result.values["value"], nullptr, 0);
            } catch (...) {
                return std::nullopt;
            }
        }
    }

    return std::nullopt;
}

bool GDBBridge::WriteRegister(const std::string& registerName, uint64_t value) {
    std::string gdbReg = RegisterNameToGDB(registerName);
    std::ostringstream cmd;
    cmd << "-gdb-set $" << gdbReg << " = 0x" << std::hex << value;

    return !ExecuteMICommand(cmd.str()).empty();
}

std::vector<RegisterValue> GDBBridge::GetAllRegisters() {
    // Stub - would use -data-list-register-values
    return {};
}

std::vector<uint8_t> GDBBridge::ReadMemory(uint64_t address, size_t size) {
    std::ostringstream cmd;
    cmd << "-data-read-memory-bytes 0x" << std::hex << address << " " << std::dec << size;

    // Stub - would parse MI response
    return {};
}

bool GDBBridge::WriteMemory(uint64_t address, const std::vector<uint8_t>& data) {
    // Stub - would use -data-write-memory-bytes
    return false;
}

std::vector<MemoryRegionInfo> GDBBridge::GetMemoryRegions() {
    // Use "info proc mappings" for Linux
    std::string output = ExecuteCommand("info proc mappings");

    std::vector<MemoryRegionInfo> regions;
    ParseMemoryMap(output, regions);

    return regions;
}

std::vector<ModuleInfo> GDBBridge::GetModules() {
    std::string output = ExecuteCommand("info sharedlibrary");

    std::vector<ModuleInfo> modules;
    ParseSharedLibs(output, modules);

    return modules;
}

std::optional<ModuleInfo> GDBBridge::GetModule(const std::string& moduleName) {
    auto modules = GetModules();
    for (const auto& mod : modules) {
        if (mod.name.find(moduleName) != std::string::npos) {
            return mod;
        }
    }
    return std::nullopt;
}

std::vector<ThreadInfo> GDBBridge::GetThreads() {
    // Stub - would use -thread-info
    return {};
}

std::string GDBBridge::ExecuteCommand(const std::string& command) {
    // Execute CLI command via MI
    std::string cmd = "-interpreter-exec console \"" + command + "\"";
    return ExecuteMICommand(cmd);
}

void GDBBridge::SetEventCallbacks(const DebuggerEvents& events) {
    m_events = events;
}

bool GDBBridge::WaitForEvent(uint32_t timeoutMs) {
    // Stub implementation
    return false;
}

std::string GDBBridge::GetDebuggerVersion() const {
    return "GDB (Machine Interface)";
}

bool GDBBridge::ConnectToGdbServer(const std::string& host, uint16_t port) {
    std::ostringstream connectionString;
    connectionString << host << ":" << port;

    m_connectionMode = ConnectionMode::Remote;
    return Connect(connectionString.str());
}

std::string GDBBridge::ExecuteMICommand(const std::string& command) {
    MIResult result;
    SendMICommand(command, result);
    return result.message;
}

bool GDBBridge::ExecuteScriptFile(const std::string& scriptPath) {
    std::string cmd = "-interpreter-exec console \"source " + scriptPath + "\"";
    return !ExecuteMICommand(cmd).empty();
}

uint32_t GDBBridge::SetConditionalBreakpoint(uint64_t address, const std::string& condition) {
    std::ostringstream cmd;
    cmd << "-break-insert -c \"" << condition << "\" *0x" << std::hex << address;

    MIResult result;
    if (SendMICommand(cmd.str(), result)) {
        uint32_t ourId = m_nextBreakpointId++;
        Breakpoint bp;
        bp.address = address;
        bp.type = BreakpointType::Conditional;
        bp.condition = condition;
        m_breakpoints[ourId] = bp;
        return ourId;
    }

    return 0;
}

uint32_t GDBBridge::SetWatchpoint(uint64_t address, size_t size, MemoryAccessType accessType) {
    std::ostringstream cmd;
    cmd << "-break-watch ";

    switch (accessType) {
        case MemoryAccessType::Read:
            cmd << "-r ";
            break;
        case MemoryAccessType::Write:
            cmd << "-a ";
            break;
        case MemoryAccessType::ReadWrite:
            cmd << "-a ";
            break;
        default:
            break;
    }

    cmd << "*0x" << std::hex << address;

    MIResult result;
    if (SendMICommand(cmd.str(), result)) {
        return m_nextBreakpointId++;
    }

    return 0;
}

uint32_t GDBBridge::SetCatchpoint(const std::string& signal) {
    std::string cmd = "-catch-signal " + signal;

    MIResult result;
    if (SendMICommand(cmd, result)) {
        return m_nextBreakpointId++;
    }

    return 0;
}

std::vector<uint64_t> GDBBridge::GetBacktrace(size_t maxFrames) {
    // Stub - would use -stack-list-frames
    return {};
}

std::optional<uint64_t> GDBBridge::EvaluateExpression(const std::string& expression) {
    std::string cmd = "-data-evaluate-expression " + expression;

    MIResult result;
    if (SendMICommand(cmd, result)) {
        if (result.values.find("value") != result.values.end()) {
            try {
                return std::stoull(result.values["value"], nullptr, 0);
            } catch (...) {
                return std::nullopt;
            }
        }
    }

    return std::nullopt;
}

std::optional<GDBBridge::SymbolInfo> GDBBridge::GetSymbol(const std::string& symbolName) {
    // Stub - would use "info symbol" or "info address"
    return std::nullopt;
}

std::vector<GDBBridge::SharedLibrary> GDBBridge::GetSharedLibraries() {
    // Stub - would parse "info sharedlibrary"
    return {};
}

bool GDBBridge::SetParameter(const std::string& param, const std::string& value) {
    std::string cmd = "-gdb-set " + param + " " + value;
    return !ExecuteMICommand(cmd).empty();
}

bool GDBBridge::SetFollowFork(bool enable) {
    std::string value = enable ? "child" : "parent";
    return SetParameter("follow-fork-mode", value);
}

bool GDBBridge::SetFollowExec(bool enable) {
    std::string value = enable ? "new" : "same";
    return SetParameter("follow-exec-mode", value);
}

bool GDBBridge::SendMICommand(const std::string& command, MIResult& result) {
    if (!pImpl->WriteLine(command)) {
        return false;
    }

    // Read response
    std::string line;
    while (true) {
        line = pImpl->ReadLine();
        if (line.empty()) {
            break;
        }

        if (ParseMIResponse(line, result)) {
            return result.type == "done";
        }
    }

    return false;
}

bool GDBBridge::ParseMIResponse(const std::string& response, MIResult& result) {
    // Simplified MI response parser
    if (response.find("^done") == 0) {
        result.type = "done";
        result.message = response;
        return true;
    }
    else if (response.find("^running") == 0) {
        result.type = "running";
        return true;
    }
    else if (response.find("^error") == 0) {
        result.type = "error";
        return true;
    }

    // TODO: Parse key=value pairs from response

    return false;
}

bool GDBBridge::ParseMemoryMap(const std::string& output, std::vector<MemoryRegionInfo>& regions) {
    // TODO: Parse /proc/pid/maps format
    return false;
}

bool GDBBridge::ParseSharedLibs(const std::string& output, std::vector<ModuleInfo>& modules) {
    // TODO: Parse shared library list
    return false;
}

void GDBBridge::ProcessAsyncEvent(const std::string& eventData) {
    // TODO: Handle async events (breakpoint hit, signal, etc.)
}

std::string GDBBridge::RegisterNameToGDB(const std::string& registerName) {
    // Map common register names to GDB format
    std::string lower = registerName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    // x86/x64 register mapping
    if (lower == "eip" || lower == "rip") return "pc";
    if (lower == "esp" || lower == "rsp") return "sp";
    if (lower == "ebp" || lower == "rbp") return "bp";

    return lower;
}

std::string GDBBridge::FormatAddress(uint64_t address) {
    std::ostringstream oss;
    oss << "0x" << std::hex << address;
    return oss.str();
}

} // namespace debugger
} // namespace scylla
