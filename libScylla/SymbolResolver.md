# Symbol Resolution and PDB Support

Advanced symbol resolution, PDB parsing, and C++ name demangling for Scylla.

## Overview

The **SymbolResolver** component provides comprehensive symbol resolution capabilities:

- **PDB file loading and parsing** - Full support for PDB 7.0 format
- **Symbol lookup** - Find symbols by address or name
- **Name demangling** - Support for MSVC and Itanium/GCC mangling schemes
- **Source location resolution** - Get source file and line number from address
- **Symbol enumeration** - Iterate through all symbols in a module
- **Symbol caching** - High-performance caching for repeated lookups
- **Symbol server support** - Download PDBs from Microsoft symbol servers

## Features

### PDB File Support

Load symbols from PDB files associated with PE executables:

```cpp
#include "SymbolResolver.h"

SymbolResolver resolver;

// Load symbols for executable (auto-finds PDB)
if (resolver.LoadSymbolsForPE("target.exe")) {
    // Symbols loaded successfully
    auto pdbInfo = resolver.GetPDBInfo();
    std::cout << "Loaded PDB: " << pdbInfo.path << "\n";
    std::cout << "Symbol count: " << pdbInfo.symbolCount << "\n";
}

// Or load PDB directly
resolver.LoadPDB("symbols\\target.pdb");

// Load symbols for loaded module
resolver.LoadSymbolsForModule(moduleBase, "module.dll");
```

### Symbol Lookup

Find symbols by address or name:

```cpp
// Lookup by address
uint64_t address = 0x140001000;
uint64_t displacement;

auto symbol = resolver.GetSymbolByAddress(address, &displacement);
if (symbol) {
    std::cout << "Symbol: " << symbol->demangledName << "\n";
    std::cout << "Address: 0x" << std::hex << symbol->address << "\n";
    std::cout << "Size: " << symbol->size << " bytes\n";
    std::cout << "Displacement: +" << displacement << " bytes\n";
}

// Lookup by name
auto createFile = resolver.GetSymbolByName("CreateFileW");
if (createFile) {
    std::cout << "CreateFileW @ 0x" << std::hex << createFile->address << "\n";
}
```

### Symbol Search

Search for symbols using wildcards:

```cpp
// Search for all Process* functions
SymbolSearchOptions options;
options.caseSensitive = false;
options.searchDemangled = true;
options.maxResults = 100;

auto results = resolver.SearchSymbols("Process*", options);

for (const auto& symbol : results) {
    std::cout << symbol.demangledName << " @ 0x"
              << std::hex << symbol.address << "\n";
}

// Filter by symbol type
options.filterType = SymbolType::Function;
auto functions = resolver.SearchSymbols("*", options);
```

### Symbol Enumeration

Iterate through all symbols:

```cpp
uint32_t count = 0;

resolver.EnumerateSymbols([&](const SymbolInfo& symbol) {
    if (symbol.type == SymbolType::Function) {
        std::cout << symbol.demangledName << "\n";
        count++;
    }

    // Return false to stop enumeration
    return count < 1000;
});

std::cout << "Total functions: " << count << "\n";
```

### Name Demangling

Demangle C++ symbols with flexible options:

```cpp
// MSVC mangled name
std::string mangled = "?ProcessMessage@@YAHHPAU_MESSAGE@@@Z";

// Basic demangling
std::string demangled = SymbolResolver::DemangleName(mangled);
// Result: "int ProcessMessage(struct _MESSAGE *)"

// Custom demangling options
DemangleOptions options;
options.includeReturnType = false;
options.includeParameters = true;
options.includeNamespace = true;
options.simplifyTemplates = true;
options.useShortNames = true;

std::string custom = SymbolResolver::DemangleName(mangled, options);

// Check if name is mangled
if (SymbolResolver::IsMangledName("?MyFunc@@YAXXZ")) {
    std::string scheme = SymbolResolver::DetectManglingScheme("?MyFunc@@YAXXZ");
    // Result: "MSVC"
}
```

Supported mangling schemes:
- **MSVC** - Microsoft Visual C++ (`?` prefix)
- **Itanium** - Itanium C++ ABI (`_Z` prefix)
- **GCC** - GNU C++ compiler

### Source Location Resolution

Get source file and line number for an address:

```cpp
std::string sourceFile;
uint32_t lineNumber;

if (resolver.GetSourceLocation(address, sourceFile, lineNumber)) {
    std::cout << "Source: " << sourceFile << ":" << lineNumber << "\n";
}
```

**Note**: Requires PDB with line number information (compiled with `/Zi` or `/ZI` in MSVC).

### Symbol Caching

Enable caching for improved performance:

```cpp
// Enable caching (enabled by default)
resolver.EnableCaching(true);

// Perform lookups (first lookup populates cache)
auto symbol1 = resolver.GetSymbolByAddress(0x140001000);  // Cache miss
auto symbol2 = resolver.GetSymbolByAddress(0x140001000);  // Cache hit (fast)

// Get statistics
auto stats = resolver.GetStatistics();
std::cout << "Cache hits: " << stats["cache_hits"] << "\n";
std::cout << "Cache misses: " << stats["cache_misses"] << "\n";

double hitRate = static_cast<double>(stats["cache_hits"]) /
                (stats["cache_hits"] + stats["cache_misses"]);
std::cout << "Hit rate: " << (hitRate * 100.0) << "%\n";

// Clear cache
resolver.ClearCache();
```

### PDB Information Extraction

Extract PDB metadata from PE files:

```cpp
auto pdbInfo = SymbolResolver::ExtractPDBInfoFromPE("target.exe");

if (pdbInfo) {
    std::cout << "PDB path: " << pdbInfo->path << "\n";
    std::cout << "GUID: " << pdbInfo->guid << "\n";
    std::cout << "Age: " << pdbInfo->age << "\n";
    std::cout << "Signature: 0x" << std::hex << pdbInfo->signature << "\n";
}
```

## Symbol Types

The `SymbolType` enumeration includes:

- `Unknown` - Unknown symbol type
- `Function` - Function/procedure
- `Data` - Global data variable
- `PublicSymbol` - Public symbol
- `Export` - Exported function
- `Import` - Imported function
- `Label` - Code label
- `Constant` - Constant value
- `Parameter` - Function parameter
- `LocalVariable` - Local variable
- `TypeInfo` - Type information
- `VTable` - Virtual function table

## Symbol Info Structure

```cpp
struct SymbolInfo {
    std::string name;              // Original name (possibly mangled)
    std::string demangledName;     // Demangled name
    SymbolType type;               // Symbol type
    uint64_t address;              // Virtual address
    uint64_t size;                 // Symbol size in bytes
    std::string moduleName;        // Module/DLL name
    std::string sourceFile;        // Source file path
    uint32_t lineNumber;           // Line number
    bool isMangled;                // Whether name is mangled

    std::map<std::string, std::string> metadata;  // Additional metadata
};
```

## Utility Functions

The `SymbolUtils` namespace provides helpful utilities:

```cpp
// Format symbol info as string
std::string info = SymbolUtils::FormatSymbolInfo(symbol, verbose);

// GUID parsing and formatting
auto guidData = SymbolUtils::ParseGUID("{12345678-1234-1234-1234-123456789ABC}");
std::string formatted = SymbolUtils::FormatGUID(guidData);

// Build symbol server URL
std::string url = SymbolUtils::BuildSymbolServerURL(
    "https://msdl.microsoft.com/download/symbols",
    "kernel32.pdb",
    guid,
    age
);

// Extract function signature
std::string sig = SymbolUtils::ExtractFunctionSignature(
    "int MyClass::ProcessData(char*, int)"
);
// Result: "int (char*, int)"

// Check if symbol is from STL
bool isStd = SymbolUtils::IsStdLibSymbol("std::vector::push_back");

// Simplify template names
std::string simplified = SymbolUtils::SimplifyTemplates(
    "std::basic_string<char,std::char_traits<char>,std::allocator<char>>"
);
// Result: "std::string"
```

## Symbol Server Support

Download PDBs from Microsoft symbol servers:

```cpp
// Set symbol server URLs
std::vector<std::string> servers = {
    "https://msdl.microsoft.com/download/symbols",
    "https://chromium-browser-symsrv.commondatastorage.googleapis.com"
};
resolver.SetSymbolServers(servers);

// Extract PDB info from PE
auto pdbInfo = SymbolResolver::ExtractPDBInfoFromPE("target.exe");

if (pdbInfo) {
    // Download PDB
    std::filesystem::path outputPath = "symbols/target.pdb";

    if (resolver.DownloadPDB(pdbInfo->guid, pdbInfo->path, outputPath)) {
        std::cout << "Downloaded PDB to: " << outputPath << "\n";

        // Load the downloaded PDB
        resolver.LoadPDB(outputPath);
    }
}
```

## Advanced Usage

### Custom Symbol Search

```cpp
// Find all constructors
SymbolSearchOptions options;
options.searchDemangled = true;

auto results = resolver.SearchSymbols("*::*", options);

std::vector<SymbolInfo> constructors;
for (const auto& sym : results) {
    if (sym.demangledName.find("::") != std::string::npos &&
        sym.demangledName.find("(") != std::string::npos) {
        constructors.push_back(sym);
    }
}
```

### Symbol Statistics

```cpp
// Analyze symbol distribution
std::map<SymbolType, uint32_t> distribution;

resolver.EnumerateSymbols([&](const SymbolInfo& symbol) {
    distribution[symbol.type]++;
    return true;  // Continue enumeration
});

std::cout << "Symbol Distribution:\n";
std::cout << "  Functions: " << distribution[SymbolType::Function] << "\n";
std::cout << "  Data: " << distribution[SymbolType::Data] << "\n";
std::cout << "  Exports: " << distribution[SymbolType::Export] << "\n";
```

### Batch Symbol Resolution

```cpp
// Resolve multiple addresses
std::vector<uint64_t> addresses = {
    0x140001000, 0x140001100, 0x140001200
};

std::vector<SymbolInfo> symbols;
for (uint64_t addr : addresses) {
    auto symbol = resolver.GetSymbolByAddress(addr);
    if (symbol) {
        symbols.push_back(*symbol);
    }
}

// Generate report
for (const auto& sym : symbols) {
    std::cout << SymbolUtils::FormatSymbolInfo(sym, true) << "\n\n";
}
```

## Platform Support

### Windows
- Full PDB support via **DbgHelp API**
- MSVC and Itanium name demangling
- Source location resolution
- Symbol server support

### Linux/macOS
- Basic PDB parsing (read-only)
- Limited demangling support
- ELF/DWARF symbols (planned)

## Performance

Symbol resolution is optimized for performance:

- **Caching**: Automatic caching of frequently accessed symbols
- **Lazy loading**: Symbols loaded on-demand
- **Efficient search**: Optimized search algorithms for large PDBs
- **Memory management**: Smart memory usage for large symbol files

Typical performance (on Windows with DbgHelp):

| Operation | Speed | Notes |
|-----------|-------|-------|
| Load PDB | 100-500ms | Depends on PDB size |
| Lookup by address (uncached) | 1-5ms | Via DbgHelp |
| Lookup by address (cached) | <0.01ms | Cache hit |
| Lookup by name | 1-10ms | Via DbgHelp |
| Enumerate symbols | 50-200ms | 10,000 symbols |
| Demangle name | 0.1-0.5ms | Simple names |

## Integration Example

Integrate symbol resolution into analysis workflow:

```cpp
#include "SymbolResolver.h"
#include "SecurityAnalyzer.h"

void AnalyzeWithSymbols(const std::filesystem::path& exePath) {
    // Load symbols
    SymbolResolver resolver;
    if (!resolver.LoadSymbolsForPE(exePath)) {
        std::cerr << "Warning: Symbols not available\n";
    }

    // Perform security analysis
    SecurityAnalyzer secAnalyzer;
    auto secResult = secAnalyzer.Analyze(exePath);

    std::cout << "Security Score: " << secResult.securityScore << "\n";

    // Find entry point symbol
    // (In real code, get entry point from PE headers)
    uint64_t entryPoint = 0x140001000;

    auto entrySymbol = resolver.GetSymbolByAddress(entryPoint);
    if (entrySymbol) {
        std::cout << "Entry point: " << entrySymbol->demangledName << "\n";

        // Get source location
        std::string sourceFile;
        uint32_t lineNumber;
        if (resolver.GetSourceLocation(entryPoint, sourceFile, lineNumber)) {
            std::cout << "Source: " << sourceFile << ":" << lineNumber << "\n";
        }
    }

    // Find security-relevant functions
    auto results = resolver.SearchSymbols("*Crypt*", SymbolSearchOptions{});

    if (!results.empty()) {
        std::cout << "\nCryptographic functions found:\n";
        for (const auto& sym : results) {
            std::cout << "  " << sym.demangledName << "\n";
        }
    }
}
```

## Error Handling

Handle errors gracefully:

```cpp
try {
    SymbolResolver resolver;

    if (!resolver.LoadSymbolsForPE("target.exe")) {
        std::cerr << "Failed to load symbols\n";
        std::cerr << "Possible reasons:\n";
        std::cerr << "  - PDB file not found\n";
        std::cerr << "  - PDB version mismatch\n";
        std::cerr << "  - DbgHelp not initialized\n";
        return;
    }

    auto symbol = resolver.GetSymbolByName("NonExistentFunction");
    if (!symbol) {
        std::cout << "Symbol not found (this is normal)\n";
    }

} catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << "\n";
}
```

## Building

The SymbolResolver is included in libScylla when building with CMake:

```bash
mkdir build && cd build
cmake ..
make
```

### Dependencies

**Windows:**
- DbgHelp.lib (Windows SDK)
- ImageHlp.lib (Windows SDK)

**Linux/macOS:**
- No additional dependencies (basic support)

## Limitations

1. **PDB Format**: Currently supports PDB 7.0 (RSDS) format only
2. **Platform**: Full functionality requires Windows + DbgHelp API
3. **Symbol Servers**: Download requires network connectivity
4. **Large PDBs**: Very large PDBs (>500MB) may have slower load times

## Future Enhancements

- [ ] DWARF symbol support (Linux/macOS)
- [ ] ELF symbol table parsing
- [ ] Older PDB formats (NB10)
- [ ] Symbol server caching
- [ ] Custom symbol providers
- [ ] Symbol diff/comparison tools

## Examples

See `SymbolResolverExample.cpp` for comprehensive usage examples covering:

1. Basic symbol resolution
2. Symbol search and enumeration
3. Name demangling
4. Source location resolution
5. Symbol lookup by name
6. Caching performance
7. PDB information extraction
8. Advanced demangling options
9. Symbol type filtering
10. Utility functions

## See Also

- [SecurityAnalyzer](SecurityAnalyzer.md) - Security mitigation analysis
- [PackerDetector](PackerDetector.md) - Packer detection
- [Python Bindings](../python/README.md) - Python API for symbol resolution

## References

- [Microsoft Symbol Server Protocol](https://docs.microsoft.com/en-us/windows/win32/debug/using-symsrv)
- [DbgHelp API Documentation](https://docs.microsoft.com/en-us/windows/win32/debug/dbghelp-functions)
- [Itanium C++ ABI](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangling)
- [MSVC Name Decoration](https://docs.microsoft.com/en-us/cpp/build/reference/decorated-names)
