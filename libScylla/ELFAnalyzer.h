#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <filesystem>
#include <optional>
#include <cstdint>

namespace scylla {
namespace elf {

/**
 * ELF file class
 */
enum class ELFClass {
    None,
    ELF32,      // 32-bit
    ELF64       // 64-bit
};

/**
 * ELF data encoding (endianness)
 */
enum class ELFEncoding {
    None,
    LSB,        // Little-endian
    MSB         // Big-endian
};

/**
 * ELF file type
 */
enum class ELFType {
    None,
    Relocatable,    // .o files
    Executable,     // Executable files
    Shared,         // Shared libraries (.so)
    Core            // Core dumps
};

/**
 * ELF machine architecture
 */
enum class ELFMachine {
    None,
    X86,            // Intel 80386
    X86_64,         // AMD x86-64
    ARM,            // ARM
    AARCH64,        // ARM 64-bit
    MIPS,           // MIPS
    PowerPC,        // PowerPC
    PowerPC64,      // PowerPC 64-bit
    RISC_V,         // RISC-V
    SPARC,          // SPARC
    S390            // IBM S/390
};

/**
 * ELF section type
 */
enum class SectionType {
    Null,
    ProgBits,       // Program data
    SymTab,         // Symbol table
    StrTab,         // String table
    Rela,           // Relocation entries with addends
    Hash,           // Symbol hash table
    Dynamic,        // Dynamic linking information
    Note,           // Notes
    NoBits,         // .bss (uninitialized data)
    Rel,            // Relocation entries
    DynSym,         // Dynamic linker symbol table
    InitArray,      // Array of constructors
    FiniArray,      // Array of destructors
    PreInitArray,   // Array of pre-constructors
    Group,          // Section group
    SymTabShndx     // Extended section indices
};

/**
 * Program header type
 */
enum class ProgramType {
    Null,
    Load,           // Loadable segment
    Dynamic,        // Dynamic linking information
    Interp,         // Interpreter path
    Note,           // Auxiliary information
    ShLib,          // Reserved
    PHdr,           // Program header table
    TLS,            // Thread-local storage
    GNUEHFrame,     // GCC .eh_frame_hdr
    GNUStack,       // Stack executability
    GNURelRo        // Read-only after relocation
};

/**
 * Symbol binding
 */
enum class SymbolBinding {
    Local,
    Global,
    Weak
};

/**
 * Symbol type
 */
enum class SymbolType {
    NoType,
    Object,         // Data object
    Func,           // Function
    Section,        // Section
    File,           // File name
    Common,         // Common data object
    TLS             // Thread-local storage
};

/**
 * ELF header information
 */
struct ELFHeader {
    ELFClass elfClass = ELFClass::None;
    ELFEncoding encoding = ELFEncoding::None;
    uint8_t version = 0;
    uint8_t osABI = 0;
    uint8_t abiVersion = 0;

    ELFType type = ELFType::None;
    ELFMachine machine = ELFMachine::None;
    uint64_t entry = 0;                 // Entry point address
    uint64_t phoff = 0;                 // Program header offset
    uint64_t shoff = 0;                 // Section header offset
    uint32_t flags = 0;
    uint16_t phnum = 0;                 // Number of program headers
    uint16_t shnum = 0;                 // Number of section headers
    uint16_t shstrndx = 0;              // Section header string table index
};

/**
 * Section header information
 */
struct SectionHeader {
    std::string name;
    SectionType type = SectionType::Null;
    uint64_t flags = 0;
    uint64_t addr = 0;                  // Virtual address
    uint64_t offset = 0;                // File offset
    uint64_t size = 0;
    uint32_t link = 0;
    uint32_t info = 0;
    uint64_t addralign = 0;
    uint64_t entsize = 0;

    // Section flags
    bool IsWritable() const { return (flags & 0x1) != 0; }
    bool IsAllocated() const { return (flags & 0x2) != 0; }
    bool IsExecutable() const { return (flags & 0x4) != 0; }
};

/**
 * Program header information
 */
struct ProgramHeader {
    ProgramType type = ProgramType::Null;
    uint64_t offset = 0;                // File offset
    uint64_t vaddr = 0;                 // Virtual address
    uint64_t paddr = 0;                 // Physical address
    uint64_t filesz = 0;                // Size in file
    uint64_t memsz = 0;                 // Size in memory
    uint32_t flags = 0;
    uint64_t align = 0;

    // Segment flags
    bool IsReadable() const { return (flags & 0x4) != 0; }
    bool IsWritable() const { return (flags & 0x2) != 0; }
    bool IsExecutable() const { return (flags & 0x1) != 0; }
};

/**
 * Symbol table entry
 */
struct Symbol {
    std::string name;
    SymbolBinding binding = SymbolBinding::Local;
    SymbolType type = SymbolType::NoType;
    uint64_t value = 0;                 // Symbol value/address
    uint64_t size = 0;
    uint16_t shndx = 0;                 // Section index
    std::string sectionName;

    bool IsFunction() const { return type == SymbolType::Func; }
    bool IsGlobal() const { return binding == SymbolBinding::Global; }
};

/**
 * Dynamic entry
 */
struct DynamicEntry {
    int64_t tag = 0;
    uint64_t value = 0;
    std::string stringValue;            // For string entries (NEEDED, SONAME, etc.)
};

/**
 * Relocation entry
 */
struct Relocation {
    uint64_t offset = 0;
    uint64_t info = 0;
    int64_t addend = 0;
    std::string symbolName;
    uint32_t type = 0;
};

/**
 * ELF security features
 */
struct ELFSecurityFeatures {
    bool nx = false;                    // NX (No-Execute) / DEP
    bool pie = false;                   // Position Independent Executable
    bool relro = false;                 // RELRO (Relocation Read-Only)
    bool fullRelro = false;             // Full RELRO
    bool stackCanary = false;           // Stack canary / SSP
    bool fortify = false;               // FORTIFY_SOURCE
    bool stripped = false;              // Debug symbols stripped
    bool hasBuildId = false;            // Has build ID

    int securityScore = 0;              // Overall security score (0-100)
};

/**
 * ELF analysis result
 */
struct ELFAnalysisResult {
    bool isELF = false;
    ELFHeader header;

    std::vector<SectionHeader> sections;
    std::vector<ProgramHeader> segments;
    std::vector<Symbol> symbols;
    std::vector<DynamicEntry> dynamic;
    std::vector<Relocation> relocations;
    std::vector<std::string> dependencies;  // Shared library dependencies

    ELFSecurityFeatures security;

    std::string interpreter;            // Dynamic linker path
    std::string soname;                 // Shared object name
    std::string buildId;                // Build ID

    // Statistics
    uint32_t functionCount = 0;
    uint32_t globalSymbolCount = 0;
    uint32_t importedFunctionCount = 0;
    uint32_t exportedFunctionCount = 0;

    std::vector<std::string> securityIssues;
    std::vector<std::string> warnings;
};

/**
 * ELF Analyzer - Linux binary analysis
 *
 * Features:
 * - ELF header parsing (32-bit and 64-bit)
 * - Section and segment analysis
 * - Symbol table extraction
 * - Dynamic linking information
 * - Relocation entries
 * - Security feature detection (NX, PIE, RELRO, Canary)
 * - Dependency analysis
 * - Cross-architecture support (x86, ARM, MIPS, etc.)
 *
 * Supports:
 * - ELF32 and ELF64
 * - Little-endian and big-endian
 * - Multiple architectures
 * - Executables, shared libraries, and object files
 */
class ELFAnalyzer {
public:
    ELFAnalyzer();
    ~ELFAnalyzer();

    /**
     * Analyze ELF file
     *
     * @param filePath Path to ELF file
     * @return Analysis results
     */
    ELFAnalysisResult Analyze(const std::filesystem::path& filePath);

    /**
     * Check if file is an ELF binary
     *
     * @param filePath Path to file
     * @return true if ELF file
     */
    static bool IsELFFile(const std::filesystem::path& filePath);

    /**
     * Extract ELF header
     *
     * @param filePath Path to ELF file
     * @return ELF header if valid
     */
    static std::optional<ELFHeader> ExtractHeader(const std::filesystem::path& filePath);

    /**
     * Extract section headers
     *
     * @param filePath Path to ELF file
     * @return List of section headers
     */
    std::vector<SectionHeader> ExtractSections(const std::filesystem::path& filePath);

    /**
     * Extract program headers
     *
     * @param filePath Path to ELF file
     * @return List of program headers
     */
    std::vector<ProgramHeader> ExtractSegments(const std::filesystem::path& filePath);

    /**
     * Extract symbols
     *
     * @param filePath Path to ELF file
     * @return List of symbols
     */
    std::vector<Symbol> ExtractSymbols(const std::filesystem::path& filePath);

    /**
     * Extract dynamic linking information
     *
     * @param filePath Path to ELF file
     * @return List of dynamic entries
     */
    std::vector<DynamicEntry> ExtractDynamic(const std::filesystem::path& filePath);

    /**
     * Extract dependencies
     *
     * @param filePath Path to ELF file
     * @return List of required shared libraries
     */
    std::vector<std::string> ExtractDependencies(const std::filesystem::path& filePath);

    /**
     * Analyze security features
     *
     * @param filePath Path to ELF file
     * @return Security features
     */
    ELFSecurityFeatures AnalyzeSecurity(const std::filesystem::path& filePath);

    /**
     * Get ELF class name
     *
     * @param elfClass ELF class
     * @return Human-readable name
     */
    static std::string GetClassName(ELFClass elfClass);

    /**
     * Get ELF type name
     *
     * @param type ELF type
     * @return Human-readable name
     */
    static std::string GetTypeName(ELFType type);

    /**
     * Get machine name
     *
     * @param machine Machine type
     * @return Human-readable name
     */
    static std::string GetMachineName(ELFMachine machine);

    /**
     * Get section type name
     *
     * @param type Section type
     * @return Human-readable name
     */
    static std::string GetSectionTypeName(SectionType type);

    /**
     * Get program type name
     *
     * @param type Program type
     * @return Human-readable name
     */
    static std::string GetProgramTypeName(ProgramType type);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;

    // Internal parsing methods
    bool ParseELF32(const uint8_t* data, size_t size, ELFAnalysisResult& result);
    bool ParseELF64(const uint8_t* data, size_t size, ELFAnalysisResult& result);

    std::vector<SectionHeader> ParseSections32(const uint8_t* data, const ELFHeader& header);
    std::vector<SectionHeader> ParseSections64(const uint8_t* data, const ELFHeader& header);

    std::vector<ProgramHeader> ParseSegments32(const uint8_t* data, const ELFHeader& header);
    std::vector<ProgramHeader> ParseSegments64(const uint8_t* data, const ELFHeader& header);

    std::vector<Symbol> ParseSymbolTable(const uint8_t* data, size_t size,
                                         const SectionHeader& symtab,
                                         const SectionHeader& strtab,
                                         bool is64bit);

    std::vector<DynamicEntry> ParseDynamicSection(const uint8_t* data, size_t size,
                                                   const SectionHeader& dynamic,
                                                   const std::vector<SectionHeader>& sections,
                                                   bool is64bit);

    ELFSecurityFeatures AnalyzeSecurityFeatures(const ELFAnalysisResult& result);

    std::string ReadString(const uint8_t* data, size_t offset, size_t maxSize) const;
};

/**
 * Utility functions for ELF analysis
 */
namespace ELFUtils {
    /**
     * Format symbol as string
     *
     * @param symbol Symbol information
     * @param verbose Include detailed info
     * @return Formatted string
     */
    std::string FormatSymbol(const Symbol& symbol, bool verbose = false);

    /**
     * Format section as string
     *
     * @param section Section information
     * @param verbose Include detailed info
     * @return Formatted string
     */
    std::string FormatSection(const SectionHeader& section, bool verbose = false);

    /**
     * Format segment as string
     *
     * @param segment Program header information
     * @param verbose Include detailed info
     * @return Formatted string
     */
    std::string FormatSegment(const ProgramHeader& segment, bool verbose = false);

    /**
     * Get symbol binding name
     *
     * @param binding Symbol binding
     * @return Binding name
     */
    std::string GetBindingName(SymbolBinding binding);

    /**
     * Get symbol type name
     *
     * @param type Symbol type
     * @return Type name
     */
    std::string GetSymbolTypeName(SymbolType type);

    /**
     * Format section flags
     *
     * @param flags Section flags
     * @return Formatted string (e.g., "rwx")
     */
    std::string FormatSectionFlags(uint64_t flags);

    /**
     * Format segment flags
     *
     * @param flags Segment flags
     * @return Formatted string (e.g., "r-x")
     */
    std::string FormatSegmentFlags(uint32_t flags);

    /**
     * Calculate security score
     *
     * @param features Security features
     * @return Score (0-100)
     */
    uint32_t CalculateSecurityScore(const ELFSecurityFeatures& features);

    /**
     * Check if binary is likely packed/obfuscated
     *
     * @param result Analysis result
     * @return true if indicators of packing found
     */
    bool IsLikelyPacked(const ELFAnalysisResult& result);

    /**
     * Find section by name
     *
     * @param sections List of sections
     * @param name Section name
     * @return Section if found
     */
    std::optional<SectionHeader> FindSection(const std::vector<SectionHeader>& sections,
                                             const std::string& name);

    /**
     * Find section by type
     *
     * @param sections List of sections
     * @param type Section type
     * @return Section if found
     */
    std::optional<SectionHeader> FindSectionByType(const std::vector<SectionHeader>& sections,
                                                    SectionType type);

    /**
     * Get OS/ABI name
     *
     * @param osABI OS/ABI identifier
     * @return Human-readable name
     */
    std::string GetOSABIName(uint8_t osABI);

    /**
     * Demangle C++ symbol name
     *
     * @param mangledName Mangled name
     * @return Demangled name or original if not mangled
     */
    std::string DemangleSymbol(const std::string& mangledName);
}

} // namespace elf
} // namespace scylla
