#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <filesystem>
#include <optional>
#include <cstdint>

namespace scylla {
namespace macho {

/**
 * Mach-O CPU type
 */
enum class CPUType {
    None,
    X86,            // Intel 32-bit
    X86_64,         // Intel 64-bit
    ARM,            // ARM 32-bit
    ARM64,          // ARM 64-bit (Apple Silicon)
    PowerPC,        // PowerPC 32-bit
    PowerPC64       // PowerPC 64-bit
};

/**
 * Mach-O file type
 */
enum class FileType {
    None,
    Object,         // MH_OBJECT - Relocatable object file
    Execute,        // MH_EXECUTE - Executable file
    FVMLib,         // MH_FVMLIB - Fixed VM shared library
    Core,           // MH_CORE - Core dump
    Preload,        // MH_PRELOAD - Preloaded executable
    Dylib,          // MH_DYLIB - Dynamic shared library
    Dylinker,       // MH_DYLINKER - Dynamic linker
    Bundle,         // MH_BUNDLE - Bundle
    DylibStub,      // MH_DYLIB_STUB - Shared library stub
    DSYM,           // MH_DSYM - Debug symbols
    KextBundle      // MH_KEXT_BUNDLE - Kernel extension
};

/**
 * Load command type
 */
enum class LoadCommandType {
    Segment,                // LC_SEGMENT - 32-bit segment
    SymTab,                 // LC_SYMTAB - Symbol table
    SymSeg,                 // LC_SYMSEG - Symbol segment (obsolete)
    Thread,                 // LC_THREAD - Thread state
    UnixThread,             // LC_UNIXTHREAD - Unix thread
    LoadFVMLib,             // LC_LOADFVMLIB - Load fixed VM library
    IdFVMLib,               // LC_IDFVMLIB - Fixed VM library ID
    Ident,                  // LC_IDENT - Object identification (obsolete)
    FVMFile,                // LC_FVMFILE - Fixed VM file
    PrePage,                // LC_PREPAGE - Prepage command (obsolete)
    DySymTab,               // LC_DYSYMTAB - Dynamic symbol table
    LoadDylib,              // LC_LOAD_DYLIB - Load dynamic library
    IdDylib,                // LC_ID_DYLIB - Dynamic library ID
    LoadDylinker,           // LC_LOAD_DYLINKER - Load dynamic linker
    IdDylinker,             // LC_ID_DYLINKER - Dynamic linker ID
    PreboundDylib,          // LC_PREBOUND_DYLIB - Prebound dynamic library
    Routines,               // LC_ROUTINES - Image routines
    SubFramework,           // LC_SUB_FRAMEWORK - Sub framework
    SubUmbrella,            // LC_SUB_UMBRELLA - Sub umbrella
    SubClient,              // LC_SUB_CLIENT - Sub client
    SubLibrary,             // LC_SUB_LIBRARY - Sub library
    TwoLevelHints,          // LC_TWOLEVEL_HINTS - Two-level namespace hints
    PrebindCksum,           // LC_PREBIND_CKSUM - Prebind checksum
    LoadWeakDylib,          // LC_LOAD_WEAK_DYLIB - Load weak dynamic library
    Segment64,              // LC_SEGMENT_64 - 64-bit segment
    Routines64,             // LC_ROUTINES_64 - 64-bit image routines
    UUID,                   // LC_UUID - UUID
    Rpath,                  // LC_RPATH - Runpath
    CodeSignature,          // LC_CODE_SIGNATURE - Code signature
    SegmentSplitInfo,       // LC_SEGMENT_SPLIT_INFO - Segment split info
    ReexportDylib,          // LC_REEXPORT_DYLIB - Re-export dynamic library
    LazyLoadDylib,          // LC_LAZY_LOAD_DYLIB - Lazy load dynamic library
    EncryptionInfo,         // LC_ENCRYPTION_INFO - Encryption info
    DyldInfo,               // LC_DYLD_INFO - Dyld info
    DyldInfoOnly,           // LC_DYLD_INFO_ONLY - Dyld info only
    LoadUpwardDylib,        // LC_LOAD_UPWARD_DYLIB - Load upward dynamic library
    VersionMinMacOSX,       // LC_VERSION_MIN_MACOSX - Minimum macOS version
    VersionMinIPhoneOS,     // LC_VERSION_MIN_IPHONEOS - Minimum iOS version
    FunctionStarts,         // LC_FUNCTION_STARTS - Function starts
    DyldEnvironment,        // LC_DYLD_ENVIRONMENT - Dyld environment
    Main,                   // LC_MAIN - Entry point
    DataInCode,             // LC_DATA_IN_CODE - Data in code
    SourceVersion,          // LC_SOURCE_VERSION - Source version
    DylibCodeSignDrs,       // LC_DYLIB_CODE_SIGN_DRS - Code signing DRs
    EncryptionInfo64,       // LC_ENCRYPTION_INFO_64 - 64-bit encryption info
    LinkerOption,           // LC_LINKER_OPTION - Linker options
    LinkerOptimizationHint, // LC_LINKER_OPTIMIZATION_HINT - Linker optimization
    VersionMinTvOS,         // LC_VERSION_MIN_TVOS - Minimum tvOS version
    VersionMinWatchOS,      // LC_VERSION_MIN_WATCHOS - Minimum watchOS version
    Note,                   // LC_NOTE - Note
    BuildVersion            // LC_BUILD_VERSION - Build version
};

/**
 * Mach-O header information
 */
struct MachOHeader {
    uint32_t magic = 0;
    CPUType cpuType = CPUType::None;
    uint32_t cpuSubtype = 0;
    FileType fileType = FileType::None;
    uint32_t ncmds = 0;             // Number of load commands
    uint32_t sizeofcmds = 0;        // Size of all load commands
    uint32_t flags = 0;
    uint32_t reserved = 0;          // 64-bit only

    bool Is64Bit() const { return magic == 0xFEEDFACF || magic == 0xCFFAEDFE; }
    bool IsSwapped() const { return magic == 0xCEFAEDFE || magic == 0xCFFAEDFE; }
    bool IsFat() const { return magic == 0xCAFEBABE || magic == 0xBEBAFECA; }
};

/**
 * FAT header for universal binaries
 */
struct FatHeader {
    uint32_t magic = 0;
    uint32_t nfat_arch = 0;         // Number of architectures
};

/**
 * FAT architecture information
 */
struct FatArch {
    CPUType cpuType = CPUType::None;
    uint32_t cpuSubtype = 0;
    uint32_t offset = 0;            // File offset to Mach-O
    uint32_t size = 0;              // Size of Mach-O
    uint32_t align = 0;             // Alignment (power of 2)
};

/**
 * Segment command (32/64-bit)
 */
struct SegmentCommand {
    std::string segname;            // Segment name (e.g., "__TEXT")
    uint64_t vmaddr = 0;            // Virtual memory address
    uint64_t vmsize = 0;            // Virtual memory size
    uint64_t fileoff = 0;           // File offset
    uint64_t filesize = 0;          // File size
    uint32_t maxprot = 0;           // Maximum VM protection
    uint32_t initprot = 0;          // Initial VM protection
    uint32_t nsects = 0;            // Number of sections
    uint32_t flags = 0;

    // Protection flags
    bool IsReadable() const { return (initprot & 0x1) != 0; }
    bool IsWritable() const { return (initprot & 0x2) != 0; }
    bool IsExecutable() const { return (initprot & 0x4) != 0; }
};

/**
 * Section (32/64-bit)
 */
struct Section {
    std::string sectname;           // Section name (e.g., "__text")
    std::string segname;            // Segment name
    uint64_t addr = 0;              // Memory address
    uint64_t size = 0;              // Section size
    uint32_t offset = 0;            // File offset
    uint32_t align = 0;             // Alignment (power of 2)
    uint32_t reloff = 0;            // Relocations file offset
    uint32_t nreloc = 0;            // Number of relocations
    uint32_t flags = 0;
    uint32_t reserved1 = 0;
    uint32_t reserved2 = 0;
    uint32_t reserved3 = 0;         // 64-bit only
    double entropy = 0.0;           // Calculated entropy

    // Section types
    uint8_t GetSectionType() const { return flags & 0xFF; }
    bool IsRegularSection() const { return GetSectionType() == 0x0; }
    bool IsZeroFill() const { return GetSectionType() == 0x1; }
    bool IsCStringLiterals() const { return GetSectionType() == 0x2; }
    bool IsSymbolStubs() const { return GetSectionType() == 0x8; }
};

/**
 * Symbol table entry (nlist)
 */
struct Symbol {
    std::string name;
    uint8_t type = 0;
    uint8_t sect = 0;               // Section number
    uint16_t desc = 0;              // Description
    uint64_t value = 0;             // Symbol value/address

    // Symbol type helpers
    bool IsUndefined() const { return (type & 0x0E) == 0x0; }
    bool IsAbsolute() const { return (type & 0x0E) == 0x2; }
    bool IsSection() const { return (type & 0x0E) == 0xE; }
    bool IsExternal() const { return (type & 0x01) != 0; }
    bool IsPrivateExternal() const { return (type & 0x10) != 0; }
};

/**
 * Dynamic library information
 */
struct DylibInfo {
    std::string name;
    uint32_t timestamp = 0;
    uint32_t currentVersion = 0;
    uint32_t compatibilityVersion = 0;

    std::string GetVersionString() const;
};

/**
 * Code signature information
 */
struct CodeSignature {
    uint32_t dataoff = 0;
    uint32_t datasize = 0;
    bool present = false;
    bool valid = false;
    std::string teamID;
    std::string identity;
    std::vector<std::string> entitlements;
};

/**
 * Dyld binding information
 */
struct BindingInfo {
    std::string symbolName;
    std::string libraryName;
    uint64_t address = 0;
    int64_t addend = 0;
    uint8_t type = 0;
    uint8_t ordinal = 0;
    bool weak = false;
};

/**
 * Security features
 */
struct MachOSecurityFeatures {
    bool pie = false;               // Position Independent Executable
    bool stackCanary = false;       // Stack protection
    bool arc = false;               // Automatic Reference Counting
    bool codeSignature = false;     // Code signed
    bool hardenedRuntime = false;   // Hardened runtime
    bool libraryValidation = false; // Library validation
    bool restrict = false;          // Restrict segment
    bool encrypted = false;         // Encrypted binary
    int securityScore = 0;          // Overall security score (0-100)

    std::vector<std::string> GetEnabledFeatures() const;
    std::vector<std::string> GetMissingFeatures() const;
};

/**
 * Analysis result
 */
struct MachOAnalysisResult {
    MachOHeader header;
    std::vector<SegmentCommand> segments;
    std::vector<Section> sections;
    std::vector<Symbol> symbols;
    std::vector<DylibInfo> dylibs;
    std::vector<BindingInfo> bindings;
    CodeSignature codeSignature;
    MachOSecurityFeatures security;

    uint64_t entryPoint = 0;
    std::string uuid;
    std::string platform;
    std::string minOSVersion;
    std::string sdkVersion;

    bool isUniversalBinary = false;
    std::vector<FatArch> architectures;

    double averageEntropy = 0.0;
    size_t fileSize = 0;

    bool success = false;
    std::string errorMessage;
};

/**
 * Mach-O Analyzer class
 */
class MachOAnalyzer {
public:
    MachOAnalyzer();
    ~MachOAnalyzer();

    /**
     * Analyze a Mach-O file
     * @param filePath Path to the Mach-O file
     * @return Analysis result
     */
    MachOAnalysisResult Analyze(const std::filesystem::path& filePath);

    /**
     * Analyze a specific architecture in a universal binary
     * @param filePath Path to the universal binary
     * @param archIndex Index of the architecture to analyze
     * @return Analysis result
     */
    MachOAnalysisResult AnalyzeArchitecture(const std::filesystem::path& filePath, size_t archIndex);

    /**
     * Check if a file is a Mach-O binary
     * @param filePath Path to check
     * @return true if Mach-O, false otherwise
     */
    static bool IsMachO(const std::filesystem::path& filePath);

    /**
     * Check if a file is a universal binary
     * @param filePath Path to check
     * @return true if universal binary, false otherwise
     */
    static bool IsUniversalBinary(const std::filesystem::path& filePath);

    /**
     * Get FAT header from universal binary
     * @param filePath Path to universal binary
     * @return FAT header with architecture list
     */
    static std::optional<std::pair<FatHeader, std::vector<FatArch>>> GetUniversalBinaryInfo(
        const std::filesystem::path& filePath);

    /**
     * Convert CPU type to string
     */
    static std::string CPUTypeToString(CPUType type);

    /**
     * Convert file type to string
     */
    static std::string FileTypeToString(FileType type);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace macho
} // namespace scylla
