/*
 * Scylla - x64dbg Bridge Implementation
 *
 * Integration with x64dbg debugger via remote bridge protocol
 */

#include "X64DbgBridge.h"
#include <sstream>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

namespace scylla {
namespace debugger {

// Implementation class (Pimpl pattern)
class X64DbgBridge::Impl {
public:
    int socket = -1;
    bool connected = false;
    std::string lastResponse;

    bool ConnectSocket(const std::string& host, uint16_t port) {
        #ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            return false;
        }
        #endif

        socket = ::socket(AF_INET, SOCK_STREAM, 0);
        if (socket < 0) {
            return false;
        }

        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port);
        inet_pton(AF_INET, host.c_str(), &serverAddr.sin_addr);

        if (connect(socket, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
            #ifdef _WIN32
            closesocket(socket);
            #else
            close(socket);
            #endif
            socket = -1;
            return false;
        }

        connected = true;
        return true;
    }

    void DisconnectSocket() {
        if (socket >= 0) {
            #ifdef _WIN32
            closesocket(socket);
            WSACleanup();
            #else
            close(socket);
            #endif
            socket = -1;
        }
        connected = false;
    }

    bool SendCommand(const std::string& cmd) {
        if (!connected || socket < 0) {
            return false;
        }

        std::string fullCmd = cmd + "\n";
        ssize_t sent = send(socket, fullCmd.c_str(), fullCmd.size(), 0);
        return sent == static_cast<ssize_t>(fullCmd.size());
    }

    bool ReceiveResponse() {
        if (!connected || socket < 0) {
            return false;
        }

        char buffer[4096];
        ssize_t received = recv(socket, buffer, sizeof(buffer) - 1, 0);
        if (received > 0) {
            buffer[received] = '\0';
            lastResponse = buffer;
            return true;
        }
        return false;
    }
};

X64DbgBridge::X64DbgBridge() : pImpl(std::make_unique<Impl>()) {
}

X64DbgBridge::~X64DbgBridge() {
    Disconnect();
}

bool X64DbgBridge::Connect(const std::string& connectionString) {
    // Default x64dbg bridge port is 1337
    std::string host = "127.0.0.1";
    uint16_t port = 1337;

    // Parse connection string (format: "host:port")
    if (!connectionString.empty()) {
        size_t colonPos = connectionString.find(':');
        if (colonPos != std::string::npos) {
            host = connectionString.substr(0, colonPos);
            port = static_cast<uint16_t>(std::stoi(connectionString.substr(colonPos + 1)));
        }
    }

    if (pImpl->ConnectSocket(host, port)) {
        m_state = DebuggerState::Connected;
        return true;
    }

    return false;
}

void X64DbgBridge::Disconnect() {
    pImpl->DisconnectSocket();
    m_state = DebuggerState::Disconnected;
}

bool X64DbgBridge::IsConnected() const {
    return pImpl->connected;
}

DebuggerState X64DbgBridge::GetState() const {
    return m_state;
}

bool X64DbgBridge::AttachToProcess(uint32_t pid) {
    std::ostringstream cmd;
    cmd << "attach " << pid;
    return SendCommand(cmd.str(), pImpl->lastResponse);
}

void X64DbgBridge::DetachFromProcess() {
    std::string response;
    SendCommand("detach", response);
}

bool X64DbgBridge::StartProcess(const std::string& exePath, const std::string& args, const std::string& workingDir) {
    std::ostringstream cmd;
    cmd << "init \"" << exePath << "\"";
    if (!args.empty()) {
        cmd << " " << args;
    }
    return SendCommand(cmd.str(), pImpl->lastResponse);
}

bool X64DbgBridge::Continue() {
    m_state = DebuggerState::Running;
    return SendCommand("run", pImpl->lastResponse);
}

bool X64DbgBridge::Pause() {
    m_state = DebuggerState::Paused;
    return SendCommand("pause", pImpl->lastResponse);
}

bool X64DbgBridge::StepInto() {
    return SendCommand("sti", pImpl->lastResponse);
}

bool X64DbgBridge::StepOver() {
    return SendCommand("sto", pImpl->lastResponse);
}

bool X64DbgBridge::StepOut() {
    return SendCommand("rtr", pImpl->lastResponse);
}

bool X64DbgBridge::RunUntil(uint64_t address) {
    std::ostringstream cmd;
    cmd << "run " << std::hex << address;
    return SendCommand(cmd.str(), pImpl->lastResponse);
}

uint32_t X64DbgBridge::SetBreakpoint(const Breakpoint& bp) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::ostringstream cmd;
    cmd << "bp " << std::hex << bp.address;
    
    if (SendCommand(cmd.str(), pImpl->lastResponse)) {
        uint32_t id = m_nextBreakpointId++;
        m_breakpoints[id] = bp;
        return id;
    }

    return 0;
}

bool X64DbgBridge::RemoveBreakpoint(uint32_t breakpointId) {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_breakpoints.find(breakpointId);
    if (it == m_breakpoints.end()) {
        return false;
    }

    std::ostringstream cmd;
    cmd << "bc " << std::hex << it->second.address;
    
    if (SendCommand(cmd.str(), pImpl->lastResponse)) {
        m_breakpoints.erase(it);
        return true;
    }

    return false;
}

bool X64DbgBridge::SetBreakpointEnabled(uint32_t breakpointId, bool enabled) {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_breakpoints.find(breakpointId);
    if (it == m_breakpoints.end()) {
        return false;
    }

    std::ostringstream cmd;
    cmd << (enabled ? "be " : "bd ") << std::hex << it->second.address;
    
    if (SendCommand(cmd.str(), pImpl->lastResponse)) {
        it->second.enabled = enabled;
        return true;
    }

    return false;
}

std::optional<uint64_t> X64DbgBridge::ReadRegister(const std::string& registerName) {
    // x64dbg command: print registerName
    std::string cmd = "print " + registerName;
    if (SendCommand(cmd, pImpl->lastResponse)) {
        // Parse response (simplified)
        try {
            return std::stoull(pImpl->lastResponse, nullptr, 16);
        } catch (...) {
            return std::nullopt;
        }
    }
    return std::nullopt;
}

bool X64DbgBridge::WriteRegister(const std::string& registerName, uint64_t value) {
    std::ostringstream cmd;
    cmd << registerName << " = " << std::hex << value;
    return SendCommand(cmd.str(), pImpl->lastResponse);
}

std::vector<RegisterValue> X64DbgBridge::GetAllRegisters() {
    // Stub implementation
    return {};
}

std::vector<uint8_t> X64DbgBridge::ReadMemory(uint64_t address, size_t size) {
    // Stub implementation
    return {};
}

bool X64DbgBridge::WriteMemory(uint64_t address, const std::vector<uint8_t>& data) {
    // Stub implementation
    return false;
}

std::vector<MemoryRegionInfo> X64DbgBridge::GetMemoryRegions() {
    // Stub implementation
    return {};
}

std::vector<ModuleInfo> X64DbgBridge::GetModules() {
    // Stub implementation
    return {};
}

std::optional<ModuleInfo> X64DbgBridge::GetModule(const std::string& moduleName) {
    // Stub implementation
    return std::nullopt;
}

std::vector<ThreadInfo> X64DbgBridge::GetThreads() {
    // Stub implementation
    return {};
}

std::string X64DbgBridge::ExecuteCommand(const std::string& command) {
    SendCommand(command, pImpl->lastResponse);
    return pImpl->lastResponse;
}

void X64DbgBridge::SetEventCallbacks(const DebuggerEvents& events) {
    m_events = events;
}

bool X64DbgBridge::WaitForEvent(uint32_t timeoutMs) {
    // Stub implementation
    return false;
}

std::string X64DbgBridge::GetDebuggerVersion() const {
    return "x64dbg (Bridge Mode)";
}

bool X64DbgBridge::ExecuteScript(const std::string& scriptPath) {
    std::string cmd = "script.load \"" + scriptPath + "\"";
    return SendCommand(cmd, pImpl->lastResponse);
}

uint32_t X64DbgBridge::SetBreakpointExpression(const std::string& expression, const std::string& condition) {
    std::ostringstream cmd;
    cmd << "bp " << expression;
    if (!condition.empty()) {
        cmd << ", " << condition;
    }
    
    if (SendCommand(cmd.str(), pImpl->lastResponse)) {
        return m_nextBreakpointId++;
    }
    return 0;
}

uint64_t X64DbgBridge::GetSymbolAddress(const std::string& symbolName) {
    std::string cmd = "disasm " + symbolName;
    if (SendCommand(cmd, pImpl->lastResponse)) {
        // Parse address from response (simplified)
        try {
            return std::stoull(pImpl->lastResponse, nullptr, 16);
        } catch (...) {
            return 0;
        }
    }
    return 0;
}

bool X64DbgBridge::SetBreakOnModuleLoad(const std::string& moduleName, bool enable) {
    std::string cmd = enable ? ("bpdll " + moduleName) : ("bcdll " + moduleName);
    return SendCommand(cmd, pImpl->lastResponse);
}

std::vector<uint64_t> X64DbgBridge::GetCallStack() {
    // Stub implementation
    return {};
}

bool X64DbgBridge::SendCommand(const std::string& command, std::string& response) {
    if (!pImpl->SendCommand(command)) {
        return false;
    }

    if (pImpl->ReceiveResponse()) {
        response = pImpl->lastResponse;
        return true;
    }

    return false;
}

bool X64DbgBridge::ParseMemoryInfo(const std::string& output, std::vector<MemoryRegionInfo>& regions) {
    // TODO: Parse x64dbg memory info output
    return false;
}

bool X64DbgBridge::ParseModuleInfo(const std::string& output, std::vector<ModuleInfo>& modules) {
    // TODO: Parse x64dbg module info output
    return false;
}

void X64DbgBridge::ProcessEvent(const std::string& eventData) {
    // TODO: Parse and dispatch events
}

} // namespace debugger
} // namespace scylla
