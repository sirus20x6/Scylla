#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <filesystem>
#include <optional>
#include <functional>
#include <cstdint>

namespace scylla {

/**
 * Symbol type enumeration
 */
enum class SymbolType {
    Unknown,
    Function,
    Data,
    PublicSymbol,
    Export,
    Import,
    Label,
    Constant,
    Parameter,
    LocalVariable,
    TypeInfo,
    VTable
};

/**
 * Symbol information structure
 */
struct SymbolInfo {
    std::string name;                    // Symbol name (possibly mangled)
    std::string demangledName;           // Demangled name (if applicable)
    SymbolType type = SymbolType::Unknown;
    uint64_t address = 0;                // Virtual address
    uint64_t size = 0;                   // Symbol size
    std::string moduleName;              // Module/DLL name
    std::string sourceFile;              // Source file (if available)
    uint32_t lineNumber = 0;             // Line number (if available)
    bool isMangled = false;              // Whether name is mangled

    // Additional metadata
    std::map<std::string, std::string> metadata;
};

/**
 * PDB information structure
 */
struct PDBInfo {
    std::string path;                    // PDB file path
    std::string guid;                    // PDB GUID
    uint32_t age = 0;                    // PDB age
    uint32_t signature = 0;              // PDB signature
    bool isLoaded = false;               // Whether PDB is loaded
    uint32_t symbolCount = 0;            // Number of symbols
};

/**
 * Name demangling options
 */
struct DemangleOptions {
    bool includeReturnType = true;       // Include return type in demangled name
    bool includeParameters = true;       // Include parameter types
    bool includeNamespace = true;        // Include namespace qualifiers
    bool simplifyTemplates = false;      // Simplify template arguments
    bool useShortNames = false;          // Use short type names (int vs signed int)
};

/**
 * Symbol search options
 */
struct SymbolSearchOptions {
    bool caseSensitive = true;           // Case-sensitive search
    bool exactMatch = false;             // Exact match vs substring
    bool searchDemangled = true;         // Search in demangled names
    SymbolType filterType = SymbolType::Unknown;  // Filter by type (Unknown = all)
    uint32_t maxResults = 1000;          // Maximum number of results
};

/**
 * Symbol Resolver - PDB parsing and symbol resolution
 *
 * Features:
 * - PDB file loading and parsing
 * - Symbol lookup by name and address
 * - C++ name demangling (MSVC and Itanium/GCC formats)
 * - Symbol enumeration and searching
 * - Source file and line number resolution
 * - Symbol caching for performance
 *
 * Platform support:
 * - Windows: Uses DbgHelp API for PDB parsing
 * - Linux/macOS: Custom PDB parser (limited functionality)
 */
class SymbolResolver {
public:
    SymbolResolver();
    ~SymbolResolver();

    // Prevent copying
    SymbolResolver(const SymbolResolver&) = delete;
    SymbolResolver& operator=(const SymbolResolver&) = delete;

    /**
     * Load symbols from PDB file
     *
     * @param pdbPath Path to PDB file
     * @return true if loaded successfully
     */
    bool LoadPDB(const std::filesystem::path& pdbPath);

    /**
     * Load symbols from PE file (uses embedded PDB path)
     *
     * @param pePath Path to PE file
     * @param searchPaths Optional additional search paths for PDB
     * @return true if loaded successfully
     */
    bool LoadSymbolsForPE(const std::filesystem::path& pePath,
                          const std::vector<std::filesystem::path>& searchPaths = {});

    /**
     * Load symbols from module at runtime
     *
     * @param moduleBase Base address of loaded module
     * @param modulePath Path to module (for PDB lookup)
     * @return true if loaded successfully
     */
    bool LoadSymbolsForModule(uint64_t moduleBase, const std::filesystem::path& modulePath);

    /**
     * Unload all symbols
     */
    void UnloadSymbols();

    /**
     * Get symbol information by address
     *
     * @param address Virtual address
     * @param displacement Optional output for displacement from symbol start
     * @return Symbol info if found
     */
    std::optional<SymbolInfo> GetSymbolByAddress(uint64_t address, uint64_t* displacement = nullptr);

    /**
     * Get symbol information by name
     *
     * @param name Symbol name (can be mangled or demangled)
     * @return Symbol info if found
     */
    std::optional<SymbolInfo> GetSymbolByName(const std::string& name);

    /**
     * Search for symbols matching criteria
     *
     * @param pattern Search pattern (supports wildcards: *, ?)
     * @param options Search options
     * @return List of matching symbols
     */
    std::vector<SymbolInfo> SearchSymbols(const std::string& pattern,
                                          const SymbolSearchOptions& options = {});

    /**
     * Enumerate all symbols
     *
     * @param callback Callback for each symbol
     * @return Number of symbols enumerated
     */
    uint32_t EnumerateSymbols(std::function<bool(const SymbolInfo&)> callback);

    /**
     * Get source file and line number for address
     *
     * @param address Virtual address
     * @param sourceFile Output source file path
     * @param lineNumber Output line number
     * @return true if found
     */
    bool GetSourceLocation(uint64_t address, std::string& sourceFile, uint32_t& lineNumber);

    /**
     * Demangle C++ symbol name
     *
     * @param mangledName Mangled name
     * @param options Demangling options
     * @return Demangled name, or original if not mangled
     */
    static std::string DemangleName(const std::string& mangledName,
                                    const DemangleOptions& options = {});

    /**
     * Check if name is mangled
     *
     * @param name Symbol name
     * @return true if name appears to be mangled
     */
    static bool IsMangledName(const std::string& name);

    /**
     * Detect mangling scheme
     *
     * @param name Symbol name
     * @return "MSVC", "Itanium", "GCC", or "None"
     */
    static std::string DetectManglingScheme(const std::string& name);

    /**
     * Get PDB information
     *
     * @return PDB info structure
     */
    PDBInfo GetPDBInfo() const;

    /**
     * Check if symbols are loaded
     *
     * @return true if symbols loaded
     */
    bool IsLoaded() const;

    /**
     * Get loaded module base address
     *
     * @return Module base address
     */
    uint64_t GetModuleBase() const;

    /**
     * Set symbol server URLs for automatic PDB download
     *
     * @param urls List of symbol server URLs
     */
    void SetSymbolServers(const std::vector<std::string>& urls);

    /**
     * Download PDB from symbol server
     *
     * @param pdbSignature PDB signature/GUID
     * @param pdbName PDB filename
     * @param outputPath Where to save downloaded PDB
     * @return true if downloaded successfully
     */
    bool DownloadPDB(const std::string& pdbSignature,
                     const std::string& pdbName,
                     const std::filesystem::path& outputPath);

    /**
     * Extract PDB info from PE file
     *
     * @param pePath Path to PE file
     * @return PDB info if found
     */
    static std::optional<PDBInfo> ExtractPDBInfoFromPE(const std::filesystem::path& pePath);

    /**
     * Enable/disable symbol caching
     *
     * @param enable Enable caching
     */
    void EnableCaching(bool enable);

    /**
     * Clear symbol cache
     */
    void ClearCache();

    /**
     * Get statistics
     *
     * @return Map of statistic name to value
     */
    std::map<std::string, uint64_t> GetStatistics() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;

    // Internal helpers
    void InitializeDbgHelp();
    void CleanupDbgHelp();
    bool LoadPDBInternal(const std::filesystem::path& pdbPath, uint64_t moduleBase);
    std::optional<SymbolInfo> LookupSymbolByAddress(uint64_t address);
    std::optional<SymbolInfo> LookupSymbolByName(const std::string& name);

    // Demangling internals
    static std::string DemangleMSVC(const std::string& mangledName, const DemangleOptions& options);
    static std::string DemangleItanium(const std::string& mangledName, const DemangleOptions& options);
    static std::string SimplifyDemangledName(const std::string& name, const DemangleOptions& options);
};

/**
 * Symbol cache for performance optimization
 */
class SymbolCache {
public:
    SymbolCache(size_t maxSize = 10000);

    void Add(uint64_t address, const SymbolInfo& info);
    void Add(const std::string& name, const SymbolInfo& info);

    std::optional<SymbolInfo> GetByAddress(uint64_t address) const;
    std::optional<SymbolInfo> GetByName(const std::string& name) const;

    void Clear();
    size_t GetSize() const;

    struct Statistics {
        uint64_t hits = 0;
        uint64_t misses = 0;
        size_t entryCount = 0;
        double hitRate = 0.0;
    };

    Statistics GetStatistics() const;

private:
    struct CacheEntry {
        SymbolInfo info;
        uint64_t lastAccess;
    };

    std::map<uint64_t, CacheEntry> addressCache;
    std::map<std::string, CacheEntry> nameCache;
    size_t maxSize;
    mutable uint64_t hits = 0;
    mutable uint64_t misses = 0;

    void EvictOldest();
};

/**
 * Utility functions for symbol operations
 */
namespace SymbolUtils {
    /**
     * Format symbol info as string
     *
     * @param info Symbol information
     * @param verbose Include detailed information
     * @return Formatted string
     */
    std::string FormatSymbolInfo(const SymbolInfo& info, bool verbose = false);

    /**
     * Parse Windows GUID from string
     *
     * @param guidStr GUID string
     * @return Binary GUID data
     */
    std::vector<uint8_t> ParseGUID(const std::string& guidStr);

    /**
     * Format GUID as string
     *
     * @param guidData Binary GUID data
     * @return GUID string
     */
    std::string FormatGUID(const std::vector<uint8_t>& guidData);

    /**
     * Build symbol server URL
     *
     * @param serverUrl Base server URL
     * @param pdbName PDB filename
     * @param guid PDB GUID
     * @param age PDB age
     * @return Complete download URL
     */
    std::string BuildSymbolServerURL(const std::string& serverUrl,
                                     const std::string& pdbName,
                                     const std::string& guid,
                                     uint32_t age);

    /**
     * Extract function signature from demangled name
     *
     * @param demangledName Demangled symbol name
     * @return Function signature (return type + parameters)
     */
    std::string ExtractFunctionSignature(const std::string& demangledName);

    /**
     * Check if symbol is a C++ standard library symbol
     *
     * @param name Symbol name
     * @return true if std library symbol
     */
    bool IsStdLibSymbol(const std::string& name);

    /**
     * Simplify template arguments in demangled name
     *
     * @param name Demangled name with templates
     * @return Simplified name
     */
    std::string SimplifyTemplates(const std::string& name);
}

} // namespace scylla
