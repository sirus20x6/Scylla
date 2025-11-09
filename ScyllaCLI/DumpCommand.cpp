/*
 * Scylla Dump Command - Implementation
 */

#include "DumpCommand.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#else
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <fstream>
#endif

namespace Scylla {
namespace CLI {

// ============================================================================
// Platform-specific helpers
// ============================================================================

#ifdef _WIN32

std::vector<uint32_t> ListProcessesWin32() {
    std::vector<uint32_t> pids;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return pids;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            pids.push_back(pe32.th32ProcessID);
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return pids;
}

std::vector<uint32_t> FindProcessByNameWin32(const std::string& name) {
    std::vector<uint32_t> pids;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return pids;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            // Convert wide string to narrow for comparison
            char exeName[MAX_PATH];
            WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, exeName, MAX_PATH, NULL, NULL);

            if (std::string(exeName).find(name) != std::string::npos) {
                pids.push_back(pe32.th32ProcessID);
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return pids;
}

std::vector<MemoryRegionInfo> EnumerateRegionsWin32(uint32_t processId) {
    std::vector<MemoryRegionInfo> regions;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) {
        return regions;
    }

    MEMORY_BASIC_INFORMATION mbi;
    uint8_t* address = 0;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT) {
            MemoryRegionInfo region;
            region.baseAddress = reinterpret_cast<uint64_t>(mbi.BaseAddress);
            region.size = mbi.RegionSize;
            region.protection = mbi.Protect;
            region.type = mbi.Type;

            // Format protection string
            region.isReadable = (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;
            region.isWritable = (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY)) != 0;
            region.isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;

            region.protectionStr = "";
            region.protectionStr += region.isReadable ? "R" : "-";
            region.protectionStr += region.isWritable ? "W" : "-";
            region.protectionStr += region.isExecutable ? "X" : "-";

            // Type string
            switch (mbi.Type) {
                case MEM_IMAGE: region.typeStr = "Image"; break;
                case MEM_MAPPED: region.typeStr = "Mapped"; break;
                case MEM_PRIVATE: region.typeStr = "Private"; break;
                default: region.typeStr = "Unknown";
            }

            regions.push_back(region);
        }

        address += mbi.RegionSize;
    }

    CloseHandle(hProcess);
    return regions;
}

#else // Linux/Unix

std::vector<uint32_t> ListProcessesLinux() {
    std::vector<uint32_t> pids;

    DIR* dir = opendir("/proc");
    if (!dir) return pids;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type == DT_DIR) {
            // Check if directory name is numeric (PID)
            char* end;
            long pid = strtol(entry->d_name, &end, 10);
            if (*end == '\0' && pid > 0) {
                pids.push_back(static_cast<uint32_t>(pid));
            }
        }
    }

    closedir(dir);
    return pids;
}

std::vector<uint32_t> FindProcessByNameLinux(const std::string& name) {
    std::vector<uint32_t> pids;

    DIR* dir = opendir("/proc");
    if (!dir) return pids;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type == DT_DIR) {
            char* end;
            long pid = strtol(entry->d_name, &end, 10);
            if (*end == '\0' && pid > 0) {
                // Read /proc/[pid]/comm for process name
                std::string commPath = std::string("/proc/") + entry->d_name + "/comm";
                std::ifstream commFile(commPath);
                if (commFile.is_open()) {
                    std::string procName;
                    std::getline(commFile, procName);
                    if (procName.find(name) != std::string::npos) {
                        pids.push_back(static_cast<uint32_t>(pid));
                    }
                }
            }
        }
    }

    closedir(dir);
    return pids;
}

std::vector<MemoryRegionInfo> EnumerateRegionsLinux(uint32_t processId) {
    std::vector<MemoryRegionInfo> regions;

    std::string mapsPath = "/proc/" + std::to_string(processId) + "/maps";
    std::ifstream mapsFile(mapsPath);
    if (!mapsFile.is_open()) {
        return regions;
    }

    std::string line;
    while (std::getline(mapsFile, line)) {
        // Parse /proc/[pid]/maps format:
        // address           perms offset  dev   inode   pathname
        // 08048000-08056000 r-xp 00000000 03:0c 64593   /usr/sbin/gpm

        std::istringstream iss(line);
        std::string addressRange, perms, offset, dev, inode, pathname;

        iss >> addressRange >> perms >> offset >> dev >> inode;
        std::getline(iss, pathname);

        // Parse address range
        size_t dashPos = addressRange.find('-');
        if (dashPos == std::string::npos) continue;

        uint64_t startAddr = std::stoull(addressRange.substr(0, dashPos), nullptr, 16);
        uint64_t endAddr = std::stoull(addressRange.substr(dashPos + 1), nullptr, 16);

        MemoryRegionInfo region;
        region.baseAddress = startAddr;
        region.size = endAddr - startAddr;
        region.protectionStr = perms.substr(0, 3);  // rwx
        region.isReadable = (perms[0] == 'r');
        region.isWritable = (perms[1] == 'w');
        region.isExecutable = (perms[2] == 'x');

        // Determine type from pathname
        if (!pathname.empty() && pathname.find(".so") != std::string::npos) {
            region.typeStr = "Image";
        } else if (pathname.find("[heap]") != std::string::npos ||
                   pathname.find("[stack]") != std::string::npos) {
            region.typeStr = "Private";
        } else {
            region.typeStr = "Mapped";
        }

        regions.push_back(region);
    }

    return regions;
}

#endif

// ============================================================================
// DumpCommand Implementation
// ============================================================================

DumpCommand::DumpCommand() {
}

DumpCommand::~DumpCommand() {
}

std::vector<uint32_t> DumpCommand::ListProcesses() {
#ifdef _WIN32
    return ListProcessesWin32();
#else
    return ListProcessesLinux();
#endif
}

std::vector<uint32_t> DumpCommand::FindProcessByName(const std::string& name) {
#ifdef _WIN32
    return FindProcessByNameWin32(name);
#else
    return FindProcessByNameLinux(name);
#endif
}

std::vector<MemoryRegionInfo> DumpCommand::EnumerateRegions(uint32_t processId) {
#ifdef _WIN32
    return EnumerateRegionsWin32(processId);
#else
    return EnumerateRegionsLinux(processId);
#endif
}

std::vector<std::string> DumpCommand::EnumerateModules(uint32_t processId) {
    std::vector<std::string> modules;

#ifdef _WIN32
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) {
        return modules;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                modules.push_back(szModName);
            }
        }
    }

    CloseHandle(hProcess);
#else
    // Linux: Read /proc/[pid]/maps for loaded modules
    std::string mapsPath = "/proc/" + std::to_string(processId) + "/maps";
    std::ifstream mapsFile(mapsPath);
    if (mapsFile.is_open()) {
        std::string line;
        while (std::getline(mapsFile, line)) {
            size_t pathStart = line.find('/');
            if (pathStart != std::string::npos) {
                std::string path = line.substr(pathStart);
                // Remove duplicates
                if (std::find(modules.begin(), modules.end(), path) == modules.end()) {
                    modules.push_back(path);
                }
            }
        }
    }
#endif

    return modules;
}

void* DumpCommand::OpenProcess(uint32_t processId) {
#ifdef _WIN32
    return ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
#else
    // On Linux, we use ptrace for memory access
    // Return PID as handle
    if (ptrace(PTRACE_ATTACH, processId, NULL, NULL) == 0) {
        waitpid(processId, NULL, 0);
        return reinterpret_cast<void*>(static_cast<uintptr_t>(processId));
    }
    return nullptr;
#endif
}

void DumpCommand::CloseProcess(void* handle) {
#ifdef _WIN32
    CloseHandle(handle);
#else
    uint32_t pid = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(handle));
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
#endif
}

bool DumpCommand::ReadProcessMemory(void* handle, uint64_t address, void* buffer, size_t size) {
#ifdef _WIN32
    SIZE_T bytesRead;
    return ::ReadProcessMemory(handle, reinterpret_cast<LPCVOID>(address), buffer, size, &bytesRead) && bytesRead == size;
#else
    uint32_t pid = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(handle));

    // Read via /proc/[pid]/mem
    std::string memPath = "/proc/" + std::to_string(pid) + "/mem";
    std::ifstream memFile(memPath, std::ios::binary);
    if (!memFile.is_open()) {
        return false;
    }

    memFile.seekg(address);
    memFile.read(static_cast<char*>(buffer), size);

    return memFile.gcount() == static_cast<std::streamsize>(size);
#endif
}

DumpResult DumpCommand::Execute(const DumpConfig& config) {
    DumpResult result = {};
    result.success = false;

    // Validate configuration
    if (config.processId == 0 && config.processName.empty()) {
        result.errors.push_back("No process specified");
        return result;
    }

    // Find process by name if needed
    uint32_t targetPid = config.processId;
    if (targetPid == 0 && !config.processName.empty()) {
        auto pids = FindProcessByName(config.processName);
        if (pids.empty()) {
            result.errors.push_back("Process not found: " + config.processName);
            return result;
        }
        targetPid = pids[0];
        if (pids.size() > 1) {
            result.warnings.push_back("Multiple processes found, using PID " + std::to_string(targetPid));
        }
    }

    // Open process
    void* hProcess = OpenProcess(targetPid);
    if (!hProcess) {
        result.errors.push_back("Failed to open process " + std::to_string(targetPid));
        return result;
    }

    try {
        // Enumerate memory regions
        auto regions = EnumerateRegions(targetPid);
        if (regions.empty()) {
            result.errors.push_back("No memory regions found");
            CloseProcess(hProcess);
            return result;
        }

        // Filter regions based on configuration
        auto filteredRegions = FilterRegions(regions, config);

        std::cout << "Found " << filteredRegions.size() << " regions to dump\n";

        // Dump regions
        size_t totalBytesRead = 0;
        size_t regionsRead = 0;

        for (const auto& region : filteredRegions) {
            std::vector<uint8_t> buffer(region.size);

            if (ReadProcessMemory(hProcess, region.baseAddress, buffer.data(), region.size)) {
                // Write to file
                std::filesystem::path outputFile = config.outputPath;

                if (config.createDirectory && filteredRegions.size() > 1) {
                    // Create directory and save each region separately
                    std::filesystem::create_directories(config.outputPath);

                    std::ostringstream filename;
                    filename << "region_" << std::hex << std::setfill('0') << std::setw(16)
                             << region.baseAddress << "_" << region.size << ".bin";
                    outputFile = config.outputPath / filename.str();
                }

                std::ofstream outFile(outputFile, std::ios::binary | std::ios::app);
                if (outFile.is_open()) {
                    outFile.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
                    totalBytesRead += buffer.size();
                    regionsRead++;
                } else {
                    result.warnings.push_back("Failed to write region at 0x" +
                        std::to_string(region.baseAddress));
                }
            } else {
                result.warnings.push_back("Failed to read region at 0x" +
                    std::to_string(region.baseAddress));
            }
        }

        result.success = (regionsRead > 0);
        result.outputFile = config.outputPath.string();
        result.bytesRead = totalBytesRead;
        result.regionsRead = regionsRead;

        // Save metadata if requested
        if (config.includeMetadata) {
            std::filesystem::path metadataPath = config.outputPath;
            metadataPath.replace_extension(".json");
            SaveMetadata(result, config, metadataPath);
        }

    } catch (const std::exception& e) {
        result.errors.push_back(std::string("Exception: ") + e.what());
    }

    CloseProcess(hProcess);
    return result;
}

DumpResult DumpCommand::QuickDump(uint32_t processId, const std::filesystem::path& outputPath) {
    DumpConfig config = {};
    config.processId = processId;
    config.outputPath = outputPath;
    config.dumpExecutableOnly = true;
    config.rebuildPE = true;
    config.fixImports = true;

    return Execute(config);
}

std::vector<MemoryRegionInfo> DumpCommand::FilterRegions(
    const std::vector<MemoryRegionInfo>& regions,
    const DumpConfig& config)
{
    std::vector<MemoryRegionInfo> filtered;

    for (const auto& region : regions) {
        // Apply filters
        if (config.dumpExecutableOnly && !region.isExecutable) {
            continue;
        }

        if (config.startAddress > 0 && region.baseAddress < config.startAddress) {
            continue;
        }

        if (config.endAddress > 0 && region.baseAddress > config.endAddress) {
            continue;
        }

        if (config.minRegionSize > 0 && region.size < config.minRegionSize) {
            continue;
        }

        if (config.maxRegionSize > 0 && region.size > config.maxRegionSize) {
            continue;
        }

        filtered.push_back(region);
    }

    return filtered;
}

void DumpCommand::SaveMetadata(const DumpResult& result, const DumpConfig& config,
                                const std::filesystem::path& metadataPath)
{
    std::ofstream metaFile(metadataPath);
    if (!metaFile.is_open()) return;

    metaFile << "{\n";
    metaFile << "  \"success\": " << (result.success ? "true" : "false") << ",\n";
    metaFile << "  \"processId\": " << config.processId << ",\n";
    metaFile << "  \"outputFile\": \"" << result.outputFile << "\",\n";
    metaFile << "  \"bytesRead\": " << result.bytesRead << ",\n";
    metaFile << "  \"regionsRead\": " << result.regionsRead << ",\n";

    if (!result.warnings.empty()) {
        metaFile << "  \"warnings\": [\n";
        for (size_t i = 0; i < result.warnings.size(); i++) {
            metaFile << "    \"" << result.warnings[i] << "\"";
            if (i < result.warnings.size() - 1) metaFile << ",";
            metaFile << "\n";
        }
        metaFile << "  ],\n";
    }

    if (!result.errors.empty()) {
        metaFile << "  \"errors\": [\n";
        for (size_t i = 0; i < result.errors.size(); i++) {
            metaFile << "    \"" << result.errors[i] << "\"";
            if (i < result.errors.size() - 1) metaFile << ",";
            metaFile << "\n";
        }
        metaFile << "  ]\n";
    } else {
        metaFile << "  \"errors\": []\n";
    }

    metaFile << "}\n";
}

std::string DumpCommand::FormatProtection(uint32_t protection) {
    std::string result;

#ifdef _WIN32
    if (protection & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))
        result += "R";
    else
        result += "-";

    if (protection & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY))
        result += "W";
    else
        result += "-";

    if (protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))
        result += "X";
    else
        result += "-";
#endif

    return result;
}

// ============================================================================
// BatchDumper Implementation
// ============================================================================

BatchDumper::BatchDumper() {
    m_stats = {};
}

std::vector<DumpResult> BatchDumper::DumpAllProcesses(
    const std::vector<uint32_t>& pids,
    const DumpConfig& baseConfig)
{
    std::vector<DumpResult> results;
    DumpCommand dumper;

    m_stats = {};
    m_stats.totalProcesses = pids.size();

    for (uint32_t pid : pids) {
        DumpConfig config = baseConfig;
        config.processId = pid;

        // Create unique output file for each process
        std::filesystem::path outputPath = baseConfig.outputPath;
        outputPath = outputPath.parent_path() /
                     (outputPath.stem().string() + "_" + std::to_string(pid) + outputPath.extension().string());
        config.outputPath = outputPath;

        std::cout << "Dumping process " << pid << "...\n";
        DumpResult result = dumper.Execute(config);

        if (result.success) {
            m_stats.successfulDumps++;
            m_stats.totalBytesWritten += result.bytesRead;
        } else {
            m_stats.failedDumps++;
        }

        results.push_back(result);
    }

    if (m_stats.successfulDumps > 0) {
        m_stats.averageDumpSize = static_cast<double>(m_stats.totalBytesWritten) / m_stats.successfulDumps;
    }

    return results;
}

std::vector<DumpResult> BatchDumper::DumpByName(const std::string& processName,
                                                const DumpConfig& baseConfig)
{
    auto pids = DumpCommand::FindProcessByName(processName);
    return DumpAllProcesses(pids, baseConfig);
}

} // namespace CLI
} // namespace Scylla
