/*
 * Linux Platform Implementation for Scylla
 *
 * This implementation uses:
 * - ptrace for process memory access
 * - /proc filesystem for process/module enumeration
 * - ELF parsing for executable analysis
 *
 * Note: This is a stub implementation that provides the basic framework.
 * Full Linux support requires implementing ptrace-based memory access
 * and ELF file parsing.
 *
 * Requirements:
 * - CAP_SYS_PTRACE capability or root access
 * - Process must not be already traced
 */

#ifdef __linux__

#include "PlatformAbstraction.h"
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <dirent.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <cstring>

namespace Scylla {
namespace Platform {

class LinuxPlatform : public IPlatform {
private:
    pid_t m_targetPid;
    bool m_attached;

    std::wstring stringToWString(const std::string& str) {
        return std::wstring(str.begin(), str.end());
    }

    std::string wstringToString(const std::wstring& wstr) {
        return std::string(wstr.begin(), wstr.end());
    }

public:
    LinuxPlatform()
        : m_targetPid(0)
        , m_attached(false)
    {
    }

    ~LinuxPlatform() override {
        CloseProcess();
    }

    bool EnumerateProcesses(std::vector<ProcessInfo>& processes) override {
        processes.clear();

        DIR* dir = opendir("/proc");
        if (!dir) {
            return false;
        }

        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            // Check if directory name is a number (PID)
            if (entry->d_type != DT_DIR) {
                continue;
            }

            pid_t pid = atoi(entry->d_name);
            if (pid <= 0) {
                continue;
            }

            ProcessInfo info;
            info.pid = pid;

            // Read process name from /proc/[pid]/comm
            std::string commPath = std::string("/proc/") + entry->d_name + "/comm";
            std::ifstream commFile(commPath);
            if (commFile.is_open()) {
                std::string name;
                std::getline(commFile, name);
                info.name = stringToWString(name);
            }

            // Read process path from /proc/[pid]/exe
            std::string exePath = std::string("/proc/") + entry->d_name + "/exe";
            char path[PATH_MAX];
            ssize_t len = readlink(exePath.c_str(), path, sizeof(path) - 1);
            if (len != -1) {
                path[len] = '\0';
                info.path = stringToWString(path);
            }

            // Check if 64-bit (simple heuristic - check ELF class)
            info.is64Bit = (sizeof(void*) == 8);  // Simplified

            processes.push_back(info);
        }

        closedir(dir);
        return true;
    }

    bool OpenProcess(ProcessId pid) override {
        CloseProcess();

        // Attach to process using ptrace
        if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
            return false;
        }

        // Wait for process to stop
        int status;
        if (waitpid(pid, &status, 0) == -1) {
            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
            return false;
        }

        m_targetPid = pid;
        m_attached = true;
        return true;
    }

    bool CloseProcess() override {
        if (m_attached && m_targetPid > 0) {
            ptrace(PTRACE_DETACH, m_targetPid, nullptr, nullptr);
            m_targetPid = 0;
            m_attached = false;
        }
        return true;
    }

    ProcessId GetCurrentProcessId() override {
        return getpid();
    }

    bool ReadMemory(Address address, void* buffer, size_t size) override {
        if (!m_attached) {
            return false;
        }

        // Read memory using ptrace PEEKDATA
        // This is a simplified implementation
        unsigned char* buf = static_cast<unsigned char*>(buffer);
        size_t bytesRead = 0;

        while (bytesRead < size) {
            long word = ptrace(PTRACE_PEEKDATA, m_targetPid,
                             address + bytesRead, nullptr);

            if (word == -1 && errno != 0) {
                return false;
            }

            size_t toCopy = std::min(sizeof(long), size - bytesRead);
            memcpy(buf + bytesRead, &word, toCopy);
            bytesRead += toCopy;
        }

        return true;
    }

    bool WriteMemory(Address address, const void* buffer, size_t size) override {
        if (!m_attached) {
            return false;
        }

        // Write memory using ptrace POKEDATA
        const unsigned char* buf = static_cast<const unsigned char*>(buffer);
        size_t bytesWritten = 0;

        while (bytesWritten < size) {
            long word = 0;
            size_t toCopy = std::min(sizeof(long), size - bytesWritten);

            // Read-modify-write for partial words
            if (toCopy < sizeof(long)) {
                word = ptrace(PTRACE_PEEKDATA, m_targetPid,
                            address + bytesWritten, nullptr);
            }

            memcpy(&word, buf + bytesWritten, toCopy);

            if (ptrace(PTRACE_POKEDATA, m_targetPid,
                      address + bytesWritten, word) == -1) {
                return false;
            }

            bytesWritten += toCopy;
        }

        return true;
    }

    bool QueryMemoryRegion(Address address, Address& baseAddress,
                          size_t& size, uint32_t& protection) override {
        if (!m_attached) {
            return false;
        }

        // Parse /proc/[pid]/maps to find memory region
        std::string mapsPath = "/proc/" + std::to_string(m_targetPid) + "/maps";
        std::ifstream mapsFile(mapsPath);

        if (!mapsFile.is_open()) {
            return false;
        }

        std::string line;
        while (std::getline(mapsFile, line)) {
            unsigned long start, end;
            char perms[5];

            if (sscanf(line.c_str(), "%lx-%lx %4s", &start, &end, perms) == 3) {
                if (address >= start && address < end) {
                    baseAddress = start;
                    size = end - start;

                    // Convert permissions to generic protection flags
                    protection = 0;
                    if (perms[0] == 'r') protection |= 0x01;  // Read
                    if (perms[1] == 'w') protection |= 0x02;  // Write
                    if (perms[2] == 'x') protection |= 0x04;  // Execute

                    return true;
                }
            }
        }

        return false;
    }

    bool EnumerateModules(std::vector<ModuleInfo>& modules) override {
        modules.clear();

        if (!m_attached) {
            return false;
        }

        // Parse /proc/[pid]/maps to find loaded modules (shared libraries)
        std::string mapsPath = "/proc/" + std::to_string(m_targetPid) + "/maps";
        std::ifstream mapsFile(mapsPath);

        if (!mapsFile.is_open()) {
            return false;
        }

        std::string line;
        std::string lastPath;

        while (std::getline(mapsFile, line)) {
            unsigned long start, end;
            char perms[5];
            unsigned long offset;
            char path[PATH_MAX];

            int matches = sscanf(line.c_str(), "%lx-%lx %4s %lx %*s %*s %s",
                               &start, &end, perms, &offset, path);

            if (matches >= 5 && path[0] == '/' && offset == 0) {
                // This is the start of a module
                if (lastPath != path) {
                    ModuleInfo info;
                    info.baseAddress = start;
                    info.size = end - start;
                    info.handle = start;  // Use base address as handle
                    info.path = stringToWString(path);

                    // Extract module name from path
                    std::string pathStr(path);
                    size_t lastSlash = pathStr.find_last_of('/');
                    if (lastSlash != std::string::npos) {
                        info.name = stringToWString(pathStr.substr(lastSlash + 1));
                    } else {
                        info.name = info.path;
                    }

                    modules.push_back(info);
                    lastPath = path;
                }
            }
        }

        return true;
    }

    ModuleHandle GetModuleHandle(const std::wstring& moduleName) override {
        std::vector<ModuleInfo> modules;
        if (EnumerateModules(modules)) {
            std::string searchName = wstringToString(moduleName);
            for (const auto& mod : modules) {
                if (wstringToString(mod.name) == searchName) {
                    return mod.handle;
                }
            }
        }
        return 0;
    }

    bool GetModuleInfo(ModuleHandle module, ModuleInfo& info) override {
        std::vector<ModuleInfo> modules;
        if (EnumerateModules(modules)) {
            for (const auto& mod : modules) {
                if (mod.handle == module) {
                    info = mod;
                    return true;
                }
            }
        }
        return false;
    }

    bool EnumerateThreads(std::vector<ThreadInfo>& threads) override {
        threads.clear();

        if (!m_attached) {
            return false;
        }

        // Read /proc/[pid]/task directory
        std::string taskPath = "/proc/" + std::to_string(m_targetPid) + "/task";
        DIR* dir = opendir(taskPath.c_str());

        if (!dir) {
            return false;
        }

        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            pid_t tid = atoi(entry->d_name);
            if (tid > 0) {
                ThreadInfo info;
                info.tid = tid;
                info.startAddress = 0;  // Would need to parse /proc/[pid]/task/[tid]/maps
                info.entryPoint = 0;
                threads.push_back(info);
            }
        }

        closedir(dir);
        return true;
    }

    bool SuspendThread(ThreadId tid) override {
        // Linux doesn't have a direct equivalent to Windows SuspendThread
        // Would need to use signals (SIGSTOP) or ptrace
        return false;  // Not implemented
    }

    bool ResumeThread(ThreadId tid) override {
        // Would use SIGCONT
        return false;  // Not implemented
    }

    bool Is64BitProcess() override {
        return sizeof(void*) == 8;
    }

    bool IsWow64Process() override {
        return false;  // Linux doesn't have WoW64
    }

    std::wstring GetProcessPath() override {
        if (m_targetPid == 0) {
            return L"";
        }

        std::string exePath = "/proc/" + std::to_string(m_targetPid) + "/exe";
        char path[PATH_MAX];
        ssize_t len = readlink(exePath.c_str(), path, sizeof(path) - 1);

        if (len != -1) {
            path[len] = '\0';
            return stringToWString(path);
        }

        return L"";
    }

    std::wstring GetModulePath(ModuleHandle module) override {
        ModuleInfo info;
        if (GetModuleInfo(module, info)) {
            return info.path;
        }
        return L"";
    }
};

// Factory function
std::unique_ptr<IPlatform> CreatePlatform() {
    return std::make_unique<LinuxPlatform>();
}

PlatformCapabilities GetPlatformCapabilities() {
    PlatformCapabilities caps;
    caps.canInjectDLL = false;  // Would need custom implementation
    caps.canCreateRemoteThread = false;
    caps.canReadMemory = true;
    caps.canWriteMemory = true;
    caps.canEnumerateModules = true;
    caps.canSuspendThreads = false;
    caps.requiresRoot = (geteuid() != 0);  // ptrace usually needs root or CAP_SYS_PTRACE

    return caps;
}

} // namespace Platform
} // namespace Scylla

#endif // __linux__
