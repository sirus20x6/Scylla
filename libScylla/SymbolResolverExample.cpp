/**
 * Symbol Resolver Usage Examples
 *
 * Demonstrates PDB parsing, symbol resolution, and name demangling
 */

#include "SymbolResolver.h"
#include <iostream>
#include <iomanip>
#include <filesystem>

using namespace scylla;

/**
 * Example 1: Basic Symbol Resolution
 */
void Example_BasicSymbolResolution() {
    std::cout << "=== Example 1: Basic Symbol Resolution ===\n\n";

    SymbolResolver resolver;

    // Load symbols for an executable
    std::filesystem::path exePath = "C:\\Windows\\System32\\notepad.exe";

    std::cout << "Loading symbols for: " << exePath << "\n";

    if (resolver.LoadSymbolsForPE(exePath)) {
        std::cout << "✓ Symbols loaded successfully!\n\n";

        // Get PDB information
        auto pdbInfo = resolver.GetPDBInfo();
        std::cout << "PDB Information:\n";
        std::cout << "  Path: " << pdbInfo.path << "\n";
        std::cout << "  GUID: " << pdbInfo.guid << "\n";
        std::cout << "  Age: " << pdbInfo.age << "\n";
        std::cout << "  Symbols: " << pdbInfo.symbolCount << "\n\n";

        // Look up symbol by address
        uint64_t testAddress = 0x140001000;  // Example address
        auto symbol = resolver.GetSymbolByAddress(testAddress);

        if (symbol) {
            std::cout << "Symbol at 0x" << std::hex << testAddress << std::dec << ":\n";
            std::cout << SymbolUtils::FormatSymbolInfo(*symbol, true) << "\n";
        } else {
            std::cout << "No symbol found at address\n";
        }

    } else {
        std::cout << "✗ Failed to load symbols\n";
        std::cout << "  Make sure PDB file is available\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

/**
 * Example 2: Symbol Search and Enumeration
 */
void Example_SymbolSearch() {
    std::cout << "=== Example 2: Symbol Search ===\n\n";

    SymbolResolver resolver;

    std::filesystem::path exePath = "target.exe";

    if (resolver.LoadSymbolsForPE(exePath)) {
        // Search for symbols matching pattern
        std::cout << "Searching for symbols matching 'Process*':\n\n";

        SymbolSearchOptions options;
        options.caseSensitive = false;
        options.exactMatch = false;
        options.searchDemangled = true;
        options.maxResults = 20;

        auto results = resolver.SearchSymbols("Process*", options);

        std::cout << "Found " << results.size() << " matching symbols:\n";
        std::cout << std::string(70, '-') << "\n";

        for (const auto& symbol : results) {
            std::cout << "  " << symbol.demangledName
                      << " @ 0x" << std::hex << symbol.address << std::dec
                      << " (" << symbol.size << " bytes)\n";
        }

        std::cout << "\n";

        // Enumerate all function symbols
        std::cout << "Enumerating function symbols:\n\n";

        uint32_t functionCount = 0;
        resolver.EnumerateSymbols([&](const SymbolInfo& info) {
            if (info.type == SymbolType::Function) {
                functionCount++;

                if (functionCount <= 10) {  // Show first 10
                    std::cout << "  " << info.demangledName << "\n";
                }
            }

            return functionCount < 1000;  // Stop after 1000 symbols
        });

        std::cout << "\nTotal functions: " << functionCount << "\n";

    } else {
        std::cout << "Failed to load symbols\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

/**
 * Example 3: Name Demangling
 */
void Example_NameDemangling() {
    std::cout << "=== Example 3: Name Demangling ===\n\n";

    // MSVC mangled names
    std::vector<std::string> msvcNames = {
        "?ProcessMessage@@YAHHPAU_MESSAGE@@@Z",
        "?GetInstance@MyClass@@SAPEAV1@XZ",
        "??0MyClass@@QEAA@HH@Z",  // Constructor
        "??1MyClass@@QEAA@XZ",     // Destructor
        "??4MyClass@@QEAAAEAV0@AEBV0@@Z"  // Assignment operator
    };

    std::cout << "MSVC Name Demangling:\n";
    std::cout << std::string(70, '-') << "\n";

    DemangleOptions options;
    options.includeReturnType = true;
    options.includeParameters = true;
    options.includeNamespace = true;

    for (const auto& mangledName : msvcNames) {
        std::cout << "Mangled:   " << mangledName << "\n";
        std::cout << "Demangled: " << SymbolResolver::DemangleName(mangledName, options) << "\n";
        std::cout << "Scheme:    " << SymbolResolver::DetectManglingScheme(mangledName) << "\n\n";
    }

    // Itanium mangled names
    std::vector<std::string> itaniumNames = {
        "_Z9MyFunctionv",
        "_Z12ProcessEventP5Event",
        "_ZN7MyClass11ProcessDataEPci"
    };

    std::cout << "\nItanium/GCC Name Demangling:\n";
    std::cout << std::string(70, '-') << "\n";

    for (const auto& mangledName : itaniumNames) {
        std::cout << "Mangled:   " << mangledName << "\n";
        std::cout << "Demangled: " << SymbolResolver::DemangleName(mangledName, options) << "\n";
        std::cout << "Scheme:    " << SymbolResolver::DetectManglingScheme(mangledName) << "\n\n";
    }

    // Test mangled name detection
    std::cout << "\nMangled Name Detection:\n";
    std::cout << std::string(70, '-') << "\n";

    std::vector<std::string> testNames = {
        "?MyFunction@@YAXXZ",
        "_Z9MyFunctionv",
        "MyFunction",
        "printf",
        "std::string::length"
    };

    for (const auto& name : testNames) {
        std::cout << std::setw(30) << std::left << name << ": "
                  << (SymbolResolver::IsMangledName(name) ? "Mangled" : "Not mangled")
                  << "\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

/**
 * Example 4: Source Location Resolution
 */
void Example_SourceLocation() {
    std::cout << "=== Example 4: Source Location Resolution ===\n\n";

    SymbolResolver resolver;

    std::filesystem::path exePath = "myapp.exe";

    if (resolver.LoadSymbolsForPE(exePath)) {
        std::cout << "Resolving source locations:\n\n";

        // Test addresses
        std::vector<uint64_t> addresses = {
            0x140001000,
            0x140001100,
            0x140001200
        };

        for (uint64_t addr : addresses) {
            std::string sourceFile;
            uint32_t lineNumber;

            if (resolver.GetSourceLocation(addr, sourceFile, lineNumber)) {
                std::cout << "Address 0x" << std::hex << addr << std::dec << ":\n";
                std::cout << "  File: " << sourceFile << "\n";
                std::cout << "  Line: " << lineNumber << "\n\n";
            } else {
                std::cout << "Address 0x" << std::hex << addr << std::dec
                          << ": No source information\n\n";
            }
        }

    } else {
        std::cout << "Failed to load symbols (PDB with line info required)\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

/**
 * Example 5: Symbol Lookup by Name
 */
void Example_LookupByName() {
    std::cout << "=== Example 5: Symbol Lookup by Name ===\n\n";

    SymbolResolver resolver;

    std::filesystem::path exePath = "kernel32.dll";

    if (resolver.LoadSymbolsForPE(exePath)) {
        std::cout << "Looking up common Windows API functions:\n\n";

        std::vector<std::string> functionNames = {
            "CreateFileW",
            "ReadFile",
            "WriteFile",
            "CloseHandle",
            "VirtualAlloc"
        };

        for (const auto& name : functionNames) {
            auto symbol = resolver.GetSymbolByName(name);

            if (symbol) {
                std::cout << name << ":\n";
                std::cout << "  Address: 0x" << std::hex << symbol->address << std::dec << "\n";
                std::cout << "  Size: " << symbol->size << " bytes\n";
                std::cout << "  Type: ";

                switch (symbol->type) {
                    case SymbolType::Function: std::cout << "Function"; break;
                    case SymbolType::Export: std::cout << "Export"; break;
                    default: std::cout << "Other"; break;
                }

                std::cout << "\n\n";
            } else {
                std::cout << name << ": Not found\n\n";
            }
        }

    } else {
        std::cout << "Failed to load symbols for kernel32.dll\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

/**
 * Example 6: Symbol Caching Performance
 */
void Example_Caching() {
    std::cout << "=== Example 6: Symbol Caching Performance ===\n\n";

    SymbolResolver resolver;

    std::filesystem::path exePath = "large_app.exe";

    if (resolver.LoadSymbolsForPE(exePath)) {
        std::cout << "Testing symbol cache performance:\n\n";

        // Enable caching
        resolver.EnableCaching(true);

        uint64_t testAddress = 0x140001000;

        // First lookup (cache miss)
        auto start = std::chrono::high_resolution_clock::now();
        auto symbol1 = resolver.GetSymbolByAddress(testAddress);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration1 = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        std::cout << "First lookup (cache miss): " << duration1.count() << " μs\n";

        // Second lookup (cache hit)
        start = std::chrono::high_resolution_clock::now();
        auto symbol2 = resolver.GetSymbolByAddress(testAddress);
        end = std::chrono::high_resolution_clock::now();
        auto duration2 = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        std::cout << "Second lookup (cache hit): " << duration2.count() << " μs\n";
        std::cout << "Speedup: " << (duration1.count() / std::max(1.0, static_cast<double>(duration2.count())))
                  << "x\n\n";

        // Get statistics
        auto stats = resolver.GetStatistics();

        std::cout << "Statistics:\n";
        std::cout << "  Total lookups: " << stats["lookup_count"] << "\n";
        std::cout << "  Cache hits: " << stats["cache_hits"] << "\n";
        std::cout << "  Cache misses: " << stats["cache_misses"] << "\n";
        std::cout << "  Cache entries: " << stats["cache_entries"] << "\n";
        std::cout << "  Symbol count: " << stats["symbol_count"] << "\n";

        double hitRate = static_cast<double>(stats["cache_hits"]) /
                        std::max(1ULL, stats["cache_hits"] + stats["cache_misses"]);
        std::cout << "  Hit rate: " << std::fixed << std::setprecision(1)
                  << (hitRate * 100.0) << "%\n";

    } else {
        std::cout << "Failed to load symbols\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

/**
 * Example 7: PDB Information Extraction
 */
void Example_PDBExtraction() {
    std::cout << "=== Example 7: PDB Information Extraction ===\n\n";

    std::vector<std::filesystem::path> exeFiles = {
        "C:\\Windows\\System32\\kernel32.dll",
        "C:\\Windows\\System32\\ntdll.dll",
        "C:\\Windows\\System32\\user32.dll"
    };

    std::cout << "Extracting PDB information from PE files:\n\n";

    for (const auto& exePath : exeFiles) {
        if (!std::filesystem::exists(exePath)) {
            continue;
        }

        std::cout << "File: " << exePath.filename() << "\n";

        auto pdbInfo = SymbolResolver::ExtractPDBInfoFromPE(exePath);

        if (pdbInfo) {
            std::cout << "  PDB Path: " << pdbInfo->path << "\n";
            std::cout << "  GUID: " << pdbInfo->guid << "\n";
            std::cout << "  Age: " << pdbInfo->age << "\n";
            std::cout << "  Signature: 0x" << std::hex << pdbInfo->signature << std::dec << "\n";
        } else {
            std::cout << "  No PDB information found\n";
        }

        std::cout << "\n";
    }

    std::cout << std::string(60, '=') << "\n\n";
}

/**
 * Example 8: Advanced Demangling Options
 */
void Example_AdvancedDemangling() {
    std::cout << "=== Example 8: Advanced Demangling Options ===\n\n";

    std::string mangledName = "?ProcessMessage@MyNamespace@MyClass@@QAEHH@Z";

    std::cout << "Original: " << mangledName << "\n\n";

    // Full demangling
    DemangleOptions fullOptions;
    fullOptions.includeReturnType = true;
    fullOptions.includeParameters = true;
    fullOptions.includeNamespace = true;
    fullOptions.simplifyTemplates = false;

    std::cout << "Full:\n  "
              << SymbolResolver::DemangleName(mangledName, fullOptions) << "\n\n";

    // No return type
    DemangleOptions noReturnOptions = fullOptions;
    noReturnOptions.includeReturnType = false;

    std::cout << "No return type:\n  "
              << SymbolResolver::DemangleName(mangledName, noReturnOptions) << "\n\n";

    // No parameters
    DemangleOptions noParamsOptions = fullOptions;
    noParamsOptions.includeParameters = false;

    std::cout << "No parameters:\n  "
              << SymbolResolver::DemangleName(mangledName, noParamsOptions) << "\n\n";

    // No namespace
    DemangleOptions noNamespaceOptions = fullOptions;
    noNamespaceOptions.includeNamespace = false;

    std::cout << "No namespace:\n  "
              << SymbolResolver::DemangleName(mangledName, noNamespaceOptions) << "\n\n";

    // Simplified
    DemangleOptions simpleOptions = fullOptions;
    simpleOptions.simplifyTemplates = true;
    simpleOptions.useShortNames = true;

    std::cout << "Simplified:\n  "
              << SymbolResolver::DemangleName(mangledName, simpleOptions) << "\n";

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

/**
 * Example 9: Symbol Type Filtering
 */
void Example_TypeFiltering() {
    std::cout << "=== Example 9: Symbol Type Filtering ===\n\n";

    SymbolResolver resolver;

    std::filesystem::path exePath = "target.exe";

    if (resolver.LoadSymbolsForPE(exePath)) {
        // Search only for functions
        SymbolSearchOptions options;
        options.filterType = SymbolType::Function;
        options.maxResults = 50;

        auto functions = resolver.SearchSymbols("*", options);

        std::cout << "Functions (first 10):\n";
        for (size_t i = 0; i < std::min(size_t(10), functions.size()); i++) {
            std::cout << "  " << functions[i].demangledName << "\n";
        }
        std::cout << "\nTotal: " << functions.size() << " functions\n\n";

        // Search only for data symbols
        options.filterType = SymbolType::Data;
        auto dataSymbols = resolver.SearchSymbols("*", options);

        std::cout << "Data symbols (first 10):\n";
        for (size_t i = 0; i < std::min(size_t(10), dataSymbols.size()); i++) {
            std::cout << "  " << dataSymbols[i].name << "\n";
        }
        std::cout << "\nTotal: " << dataSymbols.size() << " data symbols\n";

    } else {
        std::cout << "Failed to load symbols\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

/**
 * Example 10: Utility Functions
 */
void Example_Utilities() {
    std::cout << "=== Example 10: Utility Functions ===\n\n";

    // Test GUID formatting
    std::cout << "GUID Utilities:\n";
    std::cout << std::string(50, '-') << "\n";

    std::string guidStr = "{12345678-1234-1234-1234-123456789ABC}";
    auto guidData = SymbolUtils::ParseGUID(guidStr);
    auto formattedGuid = SymbolUtils::FormatGUID(guidData);

    std::cout << "Original: " << guidStr << "\n";
    std::cout << "Parsed and reformatted: " << formattedGuid << "\n\n";

    // Test symbol server URL building
    std::cout << "Symbol Server URL:\n";
    std::cout << std::string(50, '-') << "\n";

    std::string serverUrl = "https://msdl.microsoft.com/download/symbols";
    std::string pdbName = "kernel32.pdb";
    std::string guid = "{12345678-1234-1234-1234-123456789ABC}";
    uint32_t age = 1;

    std::string url = SymbolUtils::BuildSymbolServerURL(serverUrl, pdbName, guid, age);
    std::cout << "URL: " << url << "\n\n";

    // Test template simplification
    std::cout << "Template Simplification:\n";
    std::cout << std::string(50, '-') << "\n";

    std::string complexName = "std::basic_string<char,std::char_traits<char>,std::allocator<char>>";
    std::string simplified = SymbolUtils::SimplifyTemplates(complexName);

    std::cout << "Complex: " << complexName << "\n";
    std::cout << "Simplified: " << simplified << "\n\n";

    // Test std library detection
    std::cout << "STL Symbol Detection:\n";
    std::cout << std::string(50, '-') << "\n";

    std::vector<std::string> names = {
        "std::vector::push_back",
        "MyClass::MyFunction",
        "std::string::length",
        "printf"
    };

    for (const auto& name : names) {
        std::cout << std::setw(30) << std::left << name << ": "
                  << (SymbolUtils::IsStdLibSymbol(name) ? "STL" : "Non-STL")
                  << "\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

int main() {
    std::cout << "\n";
    std::cout << "╔════════════════════════════════════════════════════════════╗\n";
    std::cout << "║      Scylla Symbol Resolver - Usage Examples              ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";

    try {
        Example_BasicSymbolResolution();
        Example_SymbolSearch();
        Example_NameDemangling();
        Example_SourceLocation();
        Example_LookupByName();
        Example_Caching();
        Example_PDBExtraction();
        Example_AdvancedDemangling();
        Example_TypeFiltering();
        Example_Utilities();

        std::cout << "\n✓ All examples completed successfully!\n\n";

    } catch (const std::exception& e) {
        std::cerr << "\n✗ Error: " << e.what() << "\n\n";
        return 1;
    }

    return 0;
}
