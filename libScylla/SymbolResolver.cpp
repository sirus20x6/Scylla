#include "SymbolResolver.h"
#include "WindowsCompat.h"
#include <algorithm>
#include <cctype>
#include <regex>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#else
// For non-Windows platforms, we'll implement a basic PDB parser
// This is a simplified implementation - full PDB parsing requires significant work
#endif

namespace scylla {

// Implementation details
class SymbolResolver::Impl {
public:
    PDBInfo pdbInfo;
    uint64_t moduleBase = 0;
    bool initialized = false;
    bool cachingEnabled = true;
    SymbolCache cache;
    std::vector<std::string> symbolServers;

    // Statistics
    uint64_t lookupCount = 0;
    uint64_t cacheHits = 0;
    uint64_t cacheMisses = 0;

#ifdef _WIN32
    HANDLE hProcess = nullptr;
#endif
};

//-----------------------------------------------------------------------------
// SymbolResolver Implementation
//-----------------------------------------------------------------------------

SymbolResolver::SymbolResolver() : pImpl(std::make_unique<Impl>()) {
    InitializeDbgHelp();
}

SymbolResolver::~SymbolResolver() {
    CleanupDbgHelp();
}

void SymbolResolver::InitializeDbgHelp() {
#ifdef _WIN32
    pImpl->hProcess = GetCurrentProcess();

    DWORD options = SymGetOptions();
    options |= SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES;
    SymSetOptions(options);

    if (!SymInitialize(pImpl->hProcess, nullptr, FALSE)) {
        // Initialization failed - will use fallback methods
        pImpl->hProcess = nullptr;
    } else {
        pImpl->initialized = true;
    }
#endif
}

void SymbolResolver::CleanupDbgHelp() {
#ifdef _WIN32
    if (pImpl->hProcess && pImpl->initialized) {
        SymCleanup(pImpl->hProcess);
        pImpl->initialized = false;
    }
#endif
}

bool SymbolResolver::LoadPDB(const std::filesystem::path& pdbPath) {
    if (!std::filesystem::exists(pdbPath)) {
        return false;
    }

    // Use a default module base if none specified
    uint64_t moduleBase = pImpl->moduleBase ? pImpl->moduleBase : 0x10000000;

    return LoadPDBInternal(pdbPath, moduleBase);
}

bool SymbolResolver::LoadSymbolsForPE(const std::filesystem::path& pePath,
                                      const std::vector<std::filesystem::path>& searchPaths) {
    if (!std::filesystem::exists(pePath)) {
        return false;
    }

    // Extract PDB info from PE
    auto pdbInfo = ExtractPDBInfoFromPE(pePath);
    if (!pdbInfo) {
        return false;
    }

    // Try to find PDB file
    std::vector<std::filesystem::path> paths = searchPaths;

    // Add PE directory
    paths.push_back(pePath.parent_path());

    // Add current directory
    paths.push_back(std::filesystem::current_path());

    // Search for PDB
    for (const auto& searchPath : paths) {
        auto pdbPath = searchPath / pdbInfo->path;
        if (std::filesystem::exists(pdbPath)) {
            pImpl->pdbInfo = *pdbInfo;
            return LoadPDB(pdbPath);
        }
    }

    return false;
}

bool SymbolResolver::LoadSymbolsForModule(uint64_t moduleBase, const std::filesystem::path& modulePath) {
    pImpl->moduleBase = moduleBase;
    return LoadSymbolsForPE(modulePath);
}

bool SymbolResolver::LoadPDBInternal(const std::filesystem::path& pdbPath, uint64_t moduleBase) {
#ifdef _WIN32
    if (!pImpl->initialized) {
        return false;
    }

    // Load module
    DWORD64 baseAddr = SymLoadModuleEx(
        pImpl->hProcess,
        nullptr,
        pdbPath.string().c_str(),
        nullptr,
        moduleBase,
        0,  // Size (0 = auto-detect)
        nullptr,
        0
    );

    if (baseAddr == 0) {
        return false;
    }

    pImpl->moduleBase = baseAddr;
    pImpl->pdbInfo.path = pdbPath.string();
    pImpl->pdbInfo.isLoaded = true;

    // Get symbol count
    IMAGEHLP_MODULE64 moduleInfo = { sizeof(IMAGEHLP_MODULE64) };
    if (SymGetModuleInfo64(pImpl->hProcess, baseAddr, &moduleInfo)) {
        pImpl->pdbInfo.symbolCount = moduleInfo.NumSyms;
    }

    return true;
#else
    // Non-Windows: Basic PDB parsing not implemented
    // Would require implementing PDB format parser
    return false;
#endif
}

void SymbolResolver::UnloadSymbols() {
#ifdef _WIN32
    if (pImpl->initialized && pImpl->moduleBase) {
        SymUnloadModule64(pImpl->hProcess, pImpl->moduleBase);
    }
#endif

    pImpl->moduleBase = 0;
    pImpl->pdbInfo.isLoaded = false;
    ClearCache();
}

std::optional<SymbolInfo> SymbolResolver::GetSymbolByAddress(uint64_t address, uint64_t* displacement) {
    pImpl->lookupCount++;

    // Check cache first
    if (pImpl->cachingEnabled) {
        auto cached = pImpl->cache.GetByAddress(address);
        if (cached) {
            pImpl->cacheHits++;
            if (displacement) {
                *displacement = address - cached->address;
            }
            return cached;
        }
        pImpl->cacheMisses++;
    }

    // Lookup symbol
    auto result = LookupSymbolByAddress(address);

    if (result && pImpl->cachingEnabled) {
        pImpl->cache.Add(address, *result);
    }

    if (result && displacement) {
        *displacement = address - result->address;
    }

    return result;
}

std::optional<SymbolInfo> SymbolResolver::LookupSymbolByAddress(uint64_t address) {
#ifdef _WIN32
    if (!pImpl->initialized || !pImpl->pdbInfo.isLoaded) {
        return std::nullopt;
    }

    // Allocate symbol info buffer
    constexpr size_t maxNameLen = 1024;
    char buffer[sizeof(SYMBOL_INFO) + maxNameLen];
    SYMBOL_INFO* symbol = reinterpret_cast<SYMBOL_INFO*>(buffer);
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = maxNameLen;

    DWORD64 disp = 0;
    if (!SymFromAddr(pImpl->hProcess, address, &disp, symbol)) {
        return std::nullopt;
    }

    SymbolInfo info;
    info.name = symbol->Name;
    info.address = symbol->Address;
    info.size = symbol->Size;
    info.isMangled = IsMangledName(info.name);

    // Demangle if needed
    if (info.isMangled) {
        info.demangledName = DemangleName(info.name);
    } else {
        info.demangledName = info.name;
    }

    // Determine symbol type
    if (symbol->Tag == SymTagFunction) {
        info.type = SymbolType::Function;
    } else if (symbol->Tag == SymTagData) {
        info.type = SymbolType::Data;
    } else if (symbol->Tag == SymTagPublicSymbol) {
        info.type = SymbolType::PublicSymbol;
    }

    // Get source file and line number
    IMAGEHLP_LINE64 line = { sizeof(IMAGEHLP_LINE64) };
    DWORD lineDisp = 0;
    if (SymGetLineFromAddr64(pImpl->hProcess, address, &lineDisp, &line)) {
        info.sourceFile = line.FileName;
        info.lineNumber = line.LineNumber;
    }

    return info;
#else
    return std::nullopt;
#endif
}

std::optional<SymbolInfo> SymbolResolver::GetSymbolByName(const std::string& name) {
    pImpl->lookupCount++;

    // Check cache first
    if (pImpl->cachingEnabled) {
        auto cached = pImpl->cache.GetByName(name);
        if (cached) {
            pImpl->cacheHits++;
            return cached;
        }
        pImpl->cacheMisses++;
    }

    // Lookup symbol
    auto result = LookupSymbolByName(name);

    if (result && pImpl->cachingEnabled) {
        pImpl->cache.Add(name, *result);
    }

    return result;
}

std::optional<SymbolInfo> SymbolResolver::LookupSymbolByName(const std::string& name) {
#ifdef _WIN32
    if (!pImpl->initialized || !pImpl->pdbInfo.isLoaded) {
        return std::nullopt;
    }

    // Allocate symbol info buffer
    constexpr size_t maxNameLen = 1024;
    char buffer[sizeof(SYMBOL_INFO) + maxNameLen];
    SYMBOL_INFO* symbol = reinterpret_cast<SYMBOL_INFO*>(buffer);
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = maxNameLen;

    if (!SymFromName(pImpl->hProcess, name.c_str(), symbol)) {
        return std::nullopt;
    }

    SymbolInfo info;
    info.name = symbol->Name;
    info.address = symbol->Address;
    info.size = symbol->Size;
    info.isMangled = IsMangledName(info.name);

    if (info.isMangled) {
        info.demangledName = DemangleName(info.name);
    } else {
        info.demangledName = info.name;
    }

    // Determine symbol type
    if (symbol->Tag == SymTagFunction) {
        info.type = SymbolType::Function;
    } else if (symbol->Tag == SymTagData) {
        info.type = SymbolType::Data;
    }

    return info;
#else
    return std::nullopt;
#endif
}

std::vector<SymbolInfo> SymbolResolver::SearchSymbols(const std::string& pattern,
                                                       const SymbolSearchOptions& options) {
    std::vector<SymbolInfo> results;

#ifdef _WIN32
    if (!pImpl->initialized || !pImpl->pdbInfo.isLoaded) {
        return results;
    }

    // Convert wildcard pattern to regex
    std::string regexPattern = pattern;
    std::replace(regexPattern.begin(), regexPattern.end(), '*', '.');
    std::replace(regexPattern.begin(), regexPattern.end(), '?', '.');

    std::regex regex(regexPattern, options.caseSensitive ?
                     std::regex::ECMAScript : std::regex::icase);

    // Enumerate symbols
    EnumerateSymbols([&](const SymbolInfo& info) {
        bool match = false;

        // Check pattern match
        if (options.exactMatch) {
            if (options.caseSensitive) {
                match = (info.name == pattern);
            } else {
                auto lower = [](std::string s) {
                    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
                    return s;
                };
                match = (lower(info.name) == lower(pattern));
            }
        } else {
            match = std::regex_search(info.name, regex);

            // Also search demangled name if requested
            if (!match && options.searchDemangled && info.isMangled) {
                match = std::regex_search(info.demangledName, regex);
            }
        }

        // Filter by type
        if (match && options.filterType != SymbolType::Unknown) {
            match = (info.type == options.filterType);
        }

        if (match) {
            results.push_back(info);

            // Check max results
            if (results.size() >= options.maxResults) {
                return false;  // Stop enumeration
            }
        }

        return true;  // Continue enumeration
    });
#endif

    return results;
}

uint32_t SymbolResolver::EnumerateSymbols(std::function<bool(const SymbolInfo&)> callback) {
#ifdef _WIN32
    if (!pImpl->initialized || !pImpl->pdbInfo.isLoaded) {
        return 0;
    }

    uint32_t count = 0;

    auto enumCallback = [](PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext) -> BOOL {
        auto* data = reinterpret_cast<std::pair<std::function<bool(const SymbolInfo&)>*, uint32_t*>*>(UserContext);

        SymbolInfo info;
        info.name = pSymInfo->Name;
        info.address = pSymInfo->Address;
        info.size = pSymInfo->Size;
        info.isMangled = SymbolResolver::IsMangledName(info.name);

        if (info.isMangled) {
            info.demangledName = SymbolResolver::DemangleName(info.name);
        } else {
            info.demangledName = info.name;
        }

        // Determine type
        if (pSymInfo->Tag == SymTagFunction) {
            info.type = SymbolType::Function;
        } else if (pSymInfo->Tag == SymTagData) {
            info.type = SymbolType::Data;
        } else if (pSymInfo->Tag == SymTagPublicSymbol) {
            info.type = SymbolType::PublicSymbol;
        }

        (*data->second)++;

        // Call user callback
        return (*data->first)(info) ? TRUE : FALSE;
    };

    std::pair<std::function<bool(const SymbolInfo&)>*, uint32_t*> userData = { &callback, &count };

    SymEnumSymbols(
        pImpl->hProcess,
        pImpl->moduleBase,
        "*",  // Enumerate all symbols
        enumCallback,
        &userData
    );

    return count;
#else
    return 0;
#endif
}

bool SymbolResolver::GetSourceLocation(uint64_t address, std::string& sourceFile, uint32_t& lineNumber) {
#ifdef _WIN32
    if (!pImpl->initialized || !pImpl->pdbInfo.isLoaded) {
        return false;
    }

    IMAGEHLP_LINE64 line = { sizeof(IMAGEHLP_LINE64) };
    DWORD displacement = 0;

    if (SymGetLineFromAddr64(pImpl->hProcess, address, &displacement, &line)) {
        sourceFile = line.FileName;
        lineNumber = line.LineNumber;
        return true;
    }
#endif

    return false;
}

//-----------------------------------------------------------------------------
// Name Demangling
//-----------------------------------------------------------------------------

std::string SymbolResolver::DemangleName(const std::string& mangledName, const DemangleOptions& options) {
    if (!IsMangledName(mangledName)) {
        return mangledName;
    }

    std::string scheme = DetectManglingScheme(mangledName);

    if (scheme == "MSVC") {
        return DemangleMSVC(mangledName, options);
    } else if (scheme == "Itanium" || scheme == "GCC") {
        return DemangleItanium(mangledName, options);
    }

    return mangledName;
}

std::string SymbolResolver::DemangleMSVC(const std::string& mangledName, const DemangleOptions& options) {
#ifdef _WIN32
    char buffer[4096];
    DWORD flags = 0;

    if (!options.includeReturnType) {
        flags |= UNDNAME_NO_RETURN_UDT_MODEL;
    }
    if (!options.includeParameters) {
        flags |= UNDNAME_NO_ARGUMENTS;
    }

    DWORD result = UnDecorateSymbolName(
        mangledName.c_str(),
        buffer,
        sizeof(buffer),
        flags
    );

    if (result > 0) {
        std::string demangled = buffer;
        return SimplifyDemangledName(demangled, options);
    }
#endif

    return mangledName;
}

std::string SymbolResolver::DemangleItanium(const std::string& mangledName, const DemangleOptions& options) {
    // Simplified Itanium/GCC demangling
    // Full implementation would require __cxa_demangle on GCC/Clang
    // or a complete Itanium ABI demangler implementation

    std::string result = mangledName;

    // Basic demangling patterns
    if (mangledName.substr(0, 2) == "_Z") {
        // This is a simplified version - real demangling is complex
        // Would need to parse encoding: _Z + <encoding>
        // For now, just remove common prefixes
        result = mangledName.substr(2);
    }

    return SimplifyDemangledName(result, options);
}

std::string SymbolResolver::SimplifyDemangledName(const std::string& name, const DemangleOptions& options) {
    std::string result = name;

    if (options.simplifyTemplates) {
        result = SymbolUtils::SimplifyTemplates(result);
    }

    if (options.useShortNames) {
        // Replace long type names with short versions
        std::map<std::string, std::string> replacements = {
            {"unsigned int", "uint"},
            {"signed int", "int"},
            {"unsigned char", "uchar"},
            {"unsigned short", "ushort"},
            {"unsigned long", "ulong"},
            {"long long", "int64"},
            {"unsigned long long", "uint64"}
        };

        for (const auto& [from, to] : replacements) {
            size_t pos = 0;
            while ((pos = result.find(from, pos)) != std::string::npos) {
                result.replace(pos, from.length(), to);
                pos += to.length();
            }
        }
    }

    if (!options.includeNamespace) {
        // Remove namespace qualifiers (keep only last component)
        size_t lastColon = result.rfind("::");
        if (lastColon != std::string::npos) {
            result = result.substr(lastColon + 2);
        }
    }

    return result;
}

bool SymbolResolver::IsMangledName(const std::string& name) {
    if (name.empty()) {
        return false;
    }

    // MSVC mangling: starts with ?
    if (name[0] == '?') {
        return true;
    }

    // Itanium/GCC mangling: starts with _Z
    if (name.length() >= 2 && name.substr(0, 2) == "_Z") {
        return true;
    }

    // C mangling: starts with _
    if (name[0] == '_' && name.find("@@") != std::string::npos) {
        return true;
    }

    return false;
}

std::string SymbolResolver::DetectManglingScheme(const std::string& name) {
    if (name.empty()) {
        return "None";
    }

    if (name[0] == '?') {
        return "MSVC";
    }

    if (name.length() >= 2 && name.substr(0, 2) == "_Z") {
        return "Itanium";
    }

    if (name[0] == '_') {
        return "GCC";
    }

    return "None";
}

//-----------------------------------------------------------------------------
// PDB Information
//-----------------------------------------------------------------------------

std::optional<PDBInfo> SymbolResolver::ExtractPDBInfoFromPE(const std::filesystem::path& pePath) {
    std::ifstream file(pePath, std::ios::binary);
    if (!file) {
        return std::nullopt;
    }

    // Read DOS header
    IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        return std::nullopt;
    }

    // Read PE header
    file.seekg(dosHeader.e_lfanew);
    DWORD peSignature;
    file.read(reinterpret_cast<char*>(&peSignature), sizeof(peSignature));

    if (peSignature != IMAGE_NT_SIGNATURE) {
        return std::nullopt;
    }

    // Read file header
    IMAGE_FILE_HEADER fileHeader;
    file.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));

    // Read optional header (only the magic to determine 32/64-bit)
    uint16_t magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    file.seekg(-static_cast<int>(sizeof(magic)), std::ios::cur);

    // Read data directories
    DWORD debugDirRVA = 0;
    DWORD debugDirSize = 0;

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32 optHeader;
        file.read(reinterpret_cast<char*>(&optHeader), sizeof(optHeader));

        if (optHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG) {
            debugDirRVA = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            debugDirSize = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
        }
    } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64 optHeader;
        file.read(reinterpret_cast<char*>(&optHeader), sizeof(optHeader));

        if (optHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG) {
            debugDirRVA = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            debugDirSize = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
        }
    }

    if (debugDirRVA == 0) {
        return std::nullopt;
    }

    // Convert RVA to file offset
    // (Simplified - should properly handle section mapping)
    file.seekg(debugDirRVA, std::ios::beg);

    // Read debug directory entries
    size_t numEntries = debugDirSize / sizeof(IMAGE_DEBUG_DIRECTORY);
    for (size_t i = 0; i < numEntries; i++) {
        IMAGE_DEBUG_DIRECTORY debugDir;
        file.read(reinterpret_cast<char*>(&debugDir), sizeof(debugDir));

        if (debugDir.Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
            // Read CodeView data
            file.seekg(debugDir.PointerToRawData, std::ios::beg);

            DWORD signature;
            file.read(reinterpret_cast<char*>(&signature), sizeof(signature));

            // Check for RSDS signature (PDB 7.0)
            if (signature == 0x53445352) {  // 'RSDS'
                PDBInfo info;

                // Read GUID
                std::vector<uint8_t> guidData(16);
                file.read(reinterpret_cast<char*>(guidData.data()), 16);
                info.guid = SymbolUtils::FormatGUID(guidData);

                // Read age
                file.read(reinterpret_cast<char*>(&info.age), sizeof(info.age));

                // Read PDB path (null-terminated string)
                std::string pdbPath;
                char ch;
                while (file.get(ch) && ch != '\0') {
                    pdbPath += ch;
                }
                info.path = pdbPath;

                return info;
            }
        }
    }

    return std::nullopt;
}

PDBInfo SymbolResolver::GetPDBInfo() const {
    return pImpl->pdbInfo;
}

bool SymbolResolver::IsLoaded() const {
    return pImpl->pdbInfo.isLoaded;
}

uint64_t SymbolResolver::GetModuleBase() const {
    return pImpl->moduleBase;
}

void SymbolResolver::EnableCaching(bool enable) {
    pImpl->cachingEnabled = enable;
}

void SymbolResolver::ClearCache() {
    pImpl->cache.Clear();
}

std::map<std::string, uint64_t> SymbolResolver::GetStatistics() const {
    auto cacheStats = pImpl->cache.GetStatistics();

    return {
        {"lookup_count", pImpl->lookupCount},
        {"cache_hits", cacheStats.hits},
        {"cache_misses", cacheStats.misses},
        {"cache_entries", cacheStats.entryCount},
        {"symbol_count", pImpl->pdbInfo.symbolCount}
    };
}

//-----------------------------------------------------------------------------
// SymbolCache Implementation
//-----------------------------------------------------------------------------

SymbolCache::SymbolCache(size_t maxSize) : maxSize(maxSize) {}

void SymbolCache::Add(uint64_t address, const SymbolInfo& info) {
    if (addressCache.size() >= maxSize) {
        EvictOldest();
    }

    CacheEntry entry;
    entry.info = info;
    entry.lastAccess = std::chrono::steady_clock::now().time_since_epoch().count();

    addressCache[address] = entry;
}

void SymbolCache::Add(const std::string& name, const SymbolInfo& info) {
    if (nameCache.size() >= maxSize) {
        EvictOldest();
    }

    CacheEntry entry;
    entry.info = info;
    entry.lastAccess = std::chrono::steady_clock::now().time_since_epoch().count();

    nameCache[name] = entry;
}

std::optional<SymbolInfo> SymbolCache::GetByAddress(uint64_t address) const {
    auto it = addressCache.find(address);
    if (it != addressCache.end()) {
        hits++;
        const_cast<CacheEntry&>(it->second).lastAccess =
            std::chrono::steady_clock::now().time_since_epoch().count();
        return it->second.info;
    }

    misses++;
    return std::nullopt;
}

std::optional<SymbolInfo> SymbolCache::GetByName(const std::string& name) const {
    auto it = nameCache.find(name);
    if (it != nameCache.end()) {
        hits++;
        const_cast<CacheEntry&>(it->second).lastAccess =
            std::chrono::steady_clock::now().time_since_epoch().count();
        return it->second.info;
    }

    misses++;
    return std::nullopt;
}

void SymbolCache::Clear() {
    addressCache.clear();
    nameCache.clear();
    hits = 0;
    misses = 0;
}

size_t SymbolCache::GetSize() const {
    return addressCache.size() + nameCache.size();
}

SymbolCache::Statistics SymbolCache::GetStatistics() const {
    Statistics stats;
    stats.hits = hits;
    stats.misses = misses;
    stats.entryCount = GetSize();

    uint64_t total = hits + misses;
    stats.hitRate = total > 0 ? static_cast<double>(hits) / total : 0.0;

    return stats;
}

void SymbolCache::EvictOldest() {
    // Find oldest entry in address cache
    if (!addressCache.empty()) {
        auto oldest = std::min_element(addressCache.begin(), addressCache.end(),
            [](const auto& a, const auto& b) {
                return a.second.lastAccess < b.second.lastAccess;
            });
        addressCache.erase(oldest);
    }

    // Find oldest entry in name cache
    if (!nameCache.empty()) {
        auto oldest = std::min_element(nameCache.begin(), nameCache.end(),
            [](const auto& a, const auto& b) {
                return a.second.lastAccess < b.second.lastAccess;
            });
        nameCache.erase(oldest);
    }
}

//-----------------------------------------------------------------------------
// Symbol Utilities
//-----------------------------------------------------------------------------

namespace SymbolUtils {

std::string FormatSymbolInfo(const SymbolInfo& info, bool verbose) {
    std::ostringstream oss;

    if (verbose) {
        oss << "Symbol Information:\n";
        oss << "  Name: " << info.name << "\n";

        if (info.isMangled && !info.demangledName.empty()) {
            oss << "  Demangled: " << info.demangledName << "\n";
        }

        oss << "  Address: 0x" << std::hex << std::setw(16) << std::setfill('0')
            << info.address << std::dec << "\n";
        oss << "  Size: " << info.size << " bytes\n";
        oss << "  Type: ";

        switch (info.type) {
            case SymbolType::Function: oss << "Function"; break;
            case SymbolType::Data: oss << "Data"; break;
            case SymbolType::PublicSymbol: oss << "Public Symbol"; break;
            case SymbolType::Export: oss << "Export"; break;
            case SymbolType::Import: oss << "Import"; break;
            default: oss << "Unknown"; break;
        }
        oss << "\n";

        if (!info.sourceFile.empty()) {
            oss << "  Source: " << info.sourceFile << ":" << info.lineNumber << "\n";
        }

        if (!info.moduleName.empty()) {
            oss << "  Module: " << info.moduleName << "\n";
        }
    } else {
        oss << (info.demangledName.empty() ? info.name : info.demangledName);
        oss << " @ 0x" << std::hex << info.address << std::dec;
    }

    return oss.str();
}

std::vector<uint8_t> ParseGUID(const std::string& guidStr) {
    std::vector<uint8_t> guid(16);

    // Parse GUID string: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
    std::string clean = guidStr;
    clean.erase(std::remove(clean.begin(), clean.end(), '{'), clean.end());
    clean.erase(std::remove(clean.begin(), clean.end(), '}'), clean.end());
    clean.erase(std::remove(clean.begin(), clean.end(), '-'), clean.end());

    for (size_t i = 0; i < 16 && i * 2 < clean.length(); i++) {
        std::string byteStr = clean.substr(i * 2, 2);
        guid[i] = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
    }

    return guid;
}

std::string FormatGUID(const std::vector<uint8_t>& guidData) {
    if (guidData.size() != 16) {
        return "";
    }

    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0');

    // Format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
    oss << "{";
    for (size_t i = 0; i < 4; i++) oss << std::setw(2) << static_cast<int>(guidData[i]);
    oss << "-";
    for (size_t i = 4; i < 6; i++) oss << std::setw(2) << static_cast<int>(guidData[i]);
    oss << "-";
    for (size_t i = 6; i < 8; i++) oss << std::setw(2) << static_cast<int>(guidData[i]);
    oss << "-";
    for (size_t i = 8; i < 10; i++) oss << std::setw(2) << static_cast<int>(guidData[i]);
    oss << "-";
    for (size_t i = 10; i < 16; i++) oss << std::setw(2) << static_cast<int>(guidData[i]);
    oss << "}";

    return oss.str();
}

std::string BuildSymbolServerURL(const std::string& serverUrl,
                                 const std::string& pdbName,
                                 const std::string& guid,
                                 uint32_t age) {
    // Microsoft symbol server format:
    // http://server/pdbname/GUID+AGE/pdbname

    std::ostringstream oss;
    oss << serverUrl;
    if (serverUrl.back() != '/') oss << '/';
    oss << pdbName << '/';

    // Format GUID+AGE
    std::string guidClean = guid;
    guidClean.erase(std::remove(guidClean.begin(), guidClean.end(), '{'), guidClean.end());
    guidClean.erase(std::remove(guidClean.begin(), guidClean.end(), '}'), guidClean.end());
    guidClean.erase(std::remove(guidClean.begin(), guidClean.end(), '-'), guidClean.end());

    oss << guidClean << std::hex << age << std::dec << '/';
    oss << pdbName;

    return oss.str();
}

std::string ExtractFunctionSignature(const std::string& demangledName) {
    // Extract signature from demangled name
    // e.g., "int MyClass::MyFunction(int, float)" -> "int (int, float)"

    size_t parenPos = demangledName.find('(');
    if (parenPos == std::string::npos) {
        return "";
    }

    // Find return type (everything before last :: or space before function name)
    size_t colonPos = demangledName.rfind("::", parenPos);
    size_t spacePos = demangledName.rfind(' ', parenPos);

    size_t returnTypeEnd = (colonPos != std::string::npos) ? colonPos :
                           (spacePos != std::string::npos) ? spacePos : 0;

    std::string returnType = demangledName.substr(0, returnTypeEnd);
    std::string params = demangledName.substr(parenPos);

    return returnType + " " + params;
}

bool IsStdLibSymbol(const std::string& name) {
    return name.find("std::") != std::string::npos ||
           name.find("__std") != std::string::npos ||
           name.find("_STL") != std::string::npos;
}

std::string SimplifyTemplates(const std::string& name) {
    std::string result = name;

    // Simplify common STL templates
    std::map<std::string, std::string> replacements = {
        {"std::basic_string<char,std::char_traits<char>,std::allocator<char>>", "std::string"},
        {"std::basic_string<wchar_t,std::char_traits<wchar_t>,std::allocator<wchar_t>>", "std::wstring"},
        {"std::allocator<char>", "std::allocator"},
        {"std::char_traits<char>", "std::char_traits"}
    };

    for (const auto& [from, to] : replacements) {
        size_t pos = 0;
        while ((pos = result.find(from, pos)) != std::string::npos) {
            result.replace(pos, from.length(), to);
            pos += to.length();
        }
    }

    return result;
}

} // namespace SymbolUtils

} // namespace scylla
