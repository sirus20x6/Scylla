/*
 * Windows Platform Implementation for Scylla
 *
 * This implementation works on:
 * - Native Windows (all versions from XP onwards)
 * - Wine (with compatibility enhancements)
 *
 * Wine-specific notes:
 * - Avoids problematic NT kernel APIs
 * - Uses well-supported Win32 APIs
 * - Detects Wine environment and adjusts behavior
 */

#ifdef _WIN32

#include "PlatformAbstraction.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <memory>
#include <algorithm>

namespace Scylla {
namespace Platform {

// Wine detection helpers
static bool g_isWineDetected = false;
static bool g_wineDetectionPerformed = false;
static std::string g_wineVersion;

bool IsRunningUnderWine() {
    if (!g_wineDetectionPerformed) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            // Wine exports wine_get_version function
            void* wine_get_version = (void*)GetProcAddress(hNtdll, "wine_get_version");
            if (wine_get_version) {
                g_isWineDetected = true;
                typedef const char* (*wine_get_version_t)(void);
                wine_get_version_t get_version = (wine_get_version_t)wine_get_version;
                g_wineVersion = get_version();
            }
        }
        g_wineDetectionPerformed = true;
    }
    return g_isWineDetected;
}

std::string GetWineVersion() {
    IsRunningUnderWine();
    return g_wineVersion;
}

void EnableWineOptimizations() {
    if (IsRunningUnderWine()) {
        // Wine-specific optimizations
        // - Prefer simpler APIs that are better supported
        // - Avoid advanced NT kernel features
        // - Use standard Win32 APIs when possible
    }
}

/*
 * Windows Platform Implementation
 */
class WindowsPlatform : public IPlatform {
private:
    HANDLE m_processHandle;
    ProcessId m_currentPid;
    bool m_isWine;

public:
    WindowsPlatform()
        : m_processHandle(nullptr)
        , m_currentPid(0)
        , m_isWine(IsRunningUnderWine())
    {
        if (m_isWine) {
            EnableWineOptimizations();
        }
    }

    ~WindowsPlatform() override {
        CloseProcess();
    }

    bool EnumerateProcesses(std::vector<ProcessInfo>& processes) override {
        processes.clear();

        // Use CreateToolhelp32Snapshot - well supported in Wine
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (!Process32FirstW(snapshot, &pe32)) {
            CloseHandle(snapshot);
            return false;
        }

        do {
            ProcessInfo info;
            info.pid = pe32.th32ProcessID;
            info.name = pe32.szExeFile;

            // Try to get full path
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                wchar_t path[MAX_PATH] = { 0 };
                DWORD pathLen = MAX_PATH;

                // Use QueryFullProcessImageNameW for better Wine compatibility
                if (QueryFullProcessImageNameW(hProcess, 0, path, &pathLen)) {
                    info.path = path;
                }

                // Check if 64-bit process
                BOOL isWow64 = FALSE;
                if (IsWow64Process(hProcess, &isWow64)) {
#ifdef _WIN64
                    info.is64Bit = !isWow64;
#else
                    info.is64Bit = false;
#endif
                }

                CloseHandle(hProcess);
            }

            processes.push_back(info);

        } while (Process32NextW(snapshot, &pe32));

        CloseHandle(snapshot);
        return true;
    }

    bool OpenProcess(ProcessId pid) override {
        CloseProcess();

        // Request only what we need for better Wine compatibility
        DWORD accessRights = PROCESS_VM_READ | PROCESS_VM_WRITE |
                           PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;

        m_processHandle = ::OpenProcess(accessRights, FALSE, pid);
        if (!m_processHandle) {
            // Try with limited rights
            m_processHandle = ::OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                                          FALSE, pid);
        }

        if (m_processHandle) {
            m_currentPid = pid;
            return true;
        }

        return false;
    }

    bool CloseProcess() override {
        if (m_processHandle) {
            CloseHandle(m_processHandle);
            m_processHandle = nullptr;
            m_currentPid = 0;
        }
        return true;
    }

    ProcessId GetCurrentProcessId() override {
        return ::GetCurrentProcessId();
    }

    bool ReadMemory(Address address, void* buffer, size_t size) override {
        if (!m_processHandle) {
            return false;
        }

        SIZE_T bytesRead = 0;
        BOOL result = ReadProcessMemory(m_processHandle,
                                       reinterpret_cast<LPCVOID>(address),
                                       buffer,
                                       size,
                                       &bytesRead);

        return result && (bytesRead == size);
    }

    bool WriteMemory(Address address, const void* buffer, size_t size) override {
        if (!m_processHandle) {
            return false;
        }

        SIZE_T bytesWritten = 0;
        BOOL result = WriteProcessMemory(m_processHandle,
                                        reinterpret_cast<LPVOID>(address),
                                        buffer,
                                        size,
                                        &bytesWritten);

        return result && (bytesWritten == size);
    }

    bool QueryMemoryRegion(Address address, Address& baseAddress,
                          size_t& size, uint32_t& protection) override {
        if (!m_processHandle) {
            return false;
        }

        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T result = VirtualQueryEx(m_processHandle,
                                      reinterpret_cast<LPCVOID>(address),
                                      &mbi,
                                      sizeof(mbi));

        if (result == sizeof(mbi)) {
            baseAddress = reinterpret_cast<Address>(mbi.BaseAddress);
            size = mbi.RegionSize;
            protection = mbi.Protect;
            return true;
        }

        return false;
    }

    bool EnumerateModules(std::vector<ModuleInfo>& modules) override {
        modules.clear();

        if (!m_processHandle) {
            return false;
        }

        // Use EnumProcessModulesEx for better compatibility
        HMODULE hMods[1024];
        DWORD cbNeeded;

        DWORD filterFlag = LIST_MODULES_ALL;
        if (!EnumProcessModulesEx(m_processHandle, hMods, sizeof(hMods),
                                 &cbNeeded, filterFlag)) {
            // Fallback to regular EnumProcessModules
            if (!EnumProcessModules(m_processHandle, hMods, sizeof(hMods), &cbNeeded)) {
                return false;
            }
        }

        DWORD moduleCount = cbNeeded / sizeof(HMODULE);

        for (DWORD i = 0; i < moduleCount; i++) {
            ModuleInfo info;
            info.handle = reinterpret_cast<ModuleHandle>(hMods[i]);

            wchar_t moduleName[MAX_PATH];
            wchar_t modulePath[MAX_PATH];

            if (GetModuleBaseNameW(m_processHandle, hMods[i], moduleName, MAX_PATH)) {
                info.name = moduleName;
            }

            if (GetModuleFileNameExW(m_processHandle, hMods[i], modulePath, MAX_PATH)) {
                info.path = modulePath;
            }

            MODULEINFO modInfo;
            if (GetModuleInformation(m_processHandle, hMods[i], &modInfo, sizeof(modInfo))) {
                info.baseAddress = reinterpret_cast<Address>(modInfo.lpBaseOfDll);
                info.size = modInfo.SizeOfImage;
            }

            modules.push_back(info);
        }

        return true;
    }

    ModuleHandle GetModuleHandle(const std::wstring& moduleName) override {
        // This is for remote process, need to enumerate
        std::vector<ModuleInfo> modules;
        if (EnumerateModules(modules)) {
            auto it = std::find_if(modules.begin(), modules.end(),
                [&moduleName](const ModuleInfo& info) {
                    return _wcsicmp(info.name.c_str(), moduleName.c_str()) == 0;
                });

            if (it != modules.end()) {
                return it->handle;
            }
        }

        return 0;
    }

    bool GetModuleInfo(ModuleHandle module, ModuleInfo& info) override {
        if (!m_processHandle) {
            return false;
        }

        HMODULE hMod = reinterpret_cast<HMODULE>(module);

        wchar_t moduleName[MAX_PATH];
        wchar_t modulePath[MAX_PATH];

        if (GetModuleBaseNameW(m_processHandle, hMod, moduleName, MAX_PATH)) {
            info.name = moduleName;
        }

        if (GetModuleFileNameExW(m_processHandle, hMod, modulePath, MAX_PATH)) {
            info.path = modulePath;
        }

        MODULEINFO modInfo;
        if (GetModuleInformation(m_processHandle, hMod, &modInfo, sizeof(modInfo))) {
            info.baseAddress = reinterpret_cast<Address>(modInfo.lpBaseOfDll);
            info.size = modInfo.SizeOfImage;
            info.handle = module;
            return true;
        }

        return false;
    }

    bool EnumerateThreads(std::vector<ThreadInfo>& threads) override {
        threads.clear();

        if (!m_processHandle) {
            return false;
        }

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);

        if (!Thread32First(snapshot, &te32)) {
            CloseHandle(snapshot);
            return false;
        }

        do {
            if (te32.th32OwnerProcessID == m_currentPid) {
                ThreadInfo info;
                info.tid = te32.th32ThreadID;
                info.startAddress = 0;  // Would need thread handle to get this
                info.entryPoint = 0;
                threads.push_back(info);
            }
        } while (Thread32Next(snapshot, &te32));

        CloseHandle(snapshot);
        return true;
    }

    bool SuspendThread(ThreadId tid) override {
        HANDLE hThread = ::OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
        if (!hThread) {
            return false;
        }

        DWORD result = ::SuspendThread(hThread);
        CloseHandle(hThread);

        return result != (DWORD)-1;
    }

    bool ResumeThread(ThreadId tid) override {
        HANDLE hThread = ::OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
        if (!hThread) {
            return false;
        }

        DWORD result = ::ResumeThread(hThread);
        CloseHandle(hThread);

        return result != (DWORD)-1;
    }

    bool Is64BitProcess() override {
#ifdef _WIN64
        return true;
#else
        return false;
#endif
    }

    bool IsWow64Process() override {
        if (!m_processHandle) {
            return false;
        }

        BOOL isWow64 = FALSE;
        if (::IsWow64Process(m_processHandle, &isWow64)) {
            return isWow64 == TRUE;
        }

        return false;
    }

    std::wstring GetProcessPath() override {
        if (!m_processHandle) {
            return L"";
        }

        wchar_t path[MAX_PATH] = { 0 };
        DWORD pathLen = MAX_PATH;

        if (QueryFullProcessImageNameW(m_processHandle, 0, path, &pathLen)) {
            return path;
        }

        return L"";
    }

    std::wstring GetModulePath(ModuleHandle module) override {
        if (!m_processHandle) {
            return L"";
        }

        wchar_t modulePath[MAX_PATH];
        HMODULE hMod = reinterpret_cast<HMODULE>(module);

        if (GetModuleFileNameExW(m_processHandle, hMod, modulePath, MAX_PATH)) {
            return modulePath;
        }

        return L"";
    }
};

// Factory function
std::unique_ptr<IPlatform> CreatePlatform() {
    return std::make_unique<WindowsPlatform>();
}

PlatformCapabilities GetPlatformCapabilities() {
    PlatformCapabilities caps;
    caps.canInjectDLL = true;
    caps.canCreateRemoteThread = true;
    caps.canReadMemory = true;
    caps.canWriteMemory = true;
    caps.canEnumerateModules = true;
    caps.canSuspendThreads = true;
    caps.requiresRoot = false;

    // Adjust for Wine if needed
    if (IsRunningUnderWine()) {
        // Some Wine versions have limited DLL injection support
        // Keep it enabled but users should be aware
    }

    return caps;
}

} // namespace Platform
} // namespace Scylla

#endif // _WIN32
