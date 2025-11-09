#include "MachOAnalyzer.h"
#include <fstream>
#include <algorithm>
#include <cmath>
#include <cstring>

namespace scylla {
namespace macho {

// Mach-O magic numbers
constexpr uint32_t MH_MAGIC = 0xFEEDFACE;       // 32-bit
constexpr uint32_t MH_CIGAM = 0xCEFAEDFE;       // 32-bit swapped
constexpr uint32_t MH_MAGIC_64 = 0xFEEDFACF;    // 64-bit
constexpr uint32_t MH_CIGAM_64 = 0xCFFAEDFE;    // 64-bit swapped
constexpr uint32_t FAT_MAGIC = 0xCAFEBABE;      // Universal binary
constexpr uint32_t FAT_CIGAM = 0xBEBAFECA;      // Universal binary swapped

// CPU types
constexpr int32_t CPU_TYPE_X86 = 7;
constexpr int32_t CPU_TYPE_X86_64 = 0x01000007;
constexpr int32_t CPU_TYPE_ARM = 12;
constexpr int32_t CPU_TYPE_ARM64 = 0x0100000C;
constexpr int32_t CPU_TYPE_POWERPC = 18;
constexpr int32_t CPU_TYPE_POWERPC64 = 0x01000012;

// File types
constexpr uint32_t MH_OBJECT = 0x1;
constexpr uint32_t MH_EXECUTE = 0x2;
constexpr uint32_t MH_FVMLIB = 0x3;
constexpr uint32_t MH_CORE = 0x4;
constexpr uint32_t MH_PRELOAD = 0x5;
constexpr uint32_t MH_DYLIB = 0x6;
constexpr uint32_t MH_DYLINKER = 0x7;
constexpr uint32_t MH_BUNDLE = 0x8;
constexpr uint32_t MH_DYLIB_STUB = 0x9;
constexpr uint32_t MH_DSYM = 0xA;
constexpr uint32_t MH_KEXT_BUNDLE = 0xB;

// Flags
constexpr uint32_t MH_PIE = 0x200000;
constexpr uint32_t MH_NO_HEAP_EXECUTION = 0x1000000;

// Load command constants
constexpr uint32_t LC_SEGMENT = 0x1;
constexpr uint32_t LC_SYMTAB = 0x2;
constexpr uint32_t LC_DYSYMTAB = 0xB;
constexpr uint32_t LC_LOAD_DYLIB = 0xC;
constexpr uint32_t LC_ID_DYLIB = 0xD;
constexpr uint32_t LC_LOAD_DYLINKER = 0xE;
constexpr uint32_t LC_SEGMENT_64 = 0x19;
constexpr uint32_t LC_UUID = 0x1B;
constexpr uint32_t LC_CODE_SIGNATURE = 0x1D;
constexpr uint32_t LC_ENCRYPTION_INFO = 0x21;
constexpr uint32_t LC_DYLD_INFO = 0x22;
constexpr uint32_t LC_DYLD_INFO_ONLY = 0x80000022;
constexpr uint32_t LC_VERSION_MIN_MACOSX = 0x24;
constexpr uint32_t LC_VERSION_MIN_IPHONEOS = 0x25;
constexpr uint32_t LC_FUNCTION_STARTS = 0x26;
constexpr uint32_t LC_MAIN = 0x80000028;
constexpr uint32_t LC_DATA_IN_CODE = 0x29;
constexpr uint32_t LC_SOURCE_VERSION = 0x2A;
constexpr uint32_t LC_ENCRYPTION_INFO_64 = 0x2C;
constexpr uint32_t LC_BUILD_VERSION = 0x32;

// Helper functions
template<typename T>
T SwapBytes(T value) {
    T result = 0;
    uint8_t* src = reinterpret_cast<uint8_t*>(&value);
    uint8_t* dst = reinterpret_cast<uint8_t*>(&result);
    for (size_t i = 0; i < sizeof(T); i++) {
        dst[i] = src[sizeof(T) - 1 - i];
    }
    return result;
}

CPUType MapCPUType(int32_t type) {
    switch (type) {
        case CPU_TYPE_X86: return CPUType::X86;
        case CPU_TYPE_X86_64: return CPUType::X86_64;
        case CPU_TYPE_ARM: return CPUType::ARM;
        case CPU_TYPE_ARM64: return CPUType::ARM64;
        case CPU_TYPE_POWERPC: return CPUType::PowerPC;
        case CPU_TYPE_POWERPC64: return CPUType::PowerPC64;
        default: return CPUType::None;
    }
}

FileType MapFileType(uint32_t type) {
    switch (type) {
        case MH_OBJECT: return FileType::Object;
        case MH_EXECUTE: return FileType::Execute;
        case MH_FVMLIB: return FileType::FVMLib;
        case MH_CORE: return FileType::Core;
        case MH_PRELOAD: return FileType::Preload;
        case MH_DYLIB: return FileType::Dylib;
        case MH_DYLINKER: return FileType::Dylinker;
        case MH_BUNDLE: return FileType::Bundle;
        case MH_DYLIB_STUB: return FileType::DylibStub;
        case MH_DSYM: return FileType::DSYM;
        case MH_KEXT_BUNDLE: return FileType::KextBundle;
        default: return FileType::None;
    }
}

double CalculateEntropy(const std::vector<uint8_t>& data) {
    if (data.empty()) return 0.0;

    size_t freq[256] = { 0 };
    for (uint8_t byte : data) {
        freq[byte]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = static_cast<double>(freq[i]) / data.size();
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

std::string DylibInfo::GetVersionString() const {
    uint32_t major = (currentVersion >> 16) & 0xFFFF;
    uint32_t minor = (currentVersion >> 8) & 0xFF;
    uint32_t patch = currentVersion & 0xFF;
    return std::to_string(major) + "." + std::to_string(minor) + "." + std::to_string(patch);
}

std::vector<std::string> MachOSecurityFeatures::GetEnabledFeatures() const {
    std::vector<std::string> features;
    if (pie) features.push_back("PIE");
    if (stackCanary) features.push_back("Stack Canary");
    if (arc) features.push_back("ARC");
    if (codeSignature) features.push_back("Code Signature");
    if (hardenedRuntime) features.push_back("Hardened Runtime");
    if (libraryValidation) features.push_back("Library Validation");
    if (restrict) features.push_back("Restrict Segment");
    if (encrypted) features.push_back("Encrypted");
    return features;
}

std::vector<std::string> MachOSecurityFeatures::GetMissingFeatures() const {
    std::vector<std::string> features;
    if (!pie) features.push_back("PIE");
    if (!stackCanary) features.push_back("Stack Canary");
    if (!arc) features.push_back("ARC");
    if (!codeSignature) features.push_back("Code Signature");
    if (!hardenedRuntime) features.push_back("Hardened Runtime");
    if (!libraryValidation) features.push_back("Library Validation");
    return features;
}

// Implementation class
class MachOAnalyzer::Impl {
public:
    std::ifstream file;
    bool needsSwap = false;
    bool is64Bit = false;

    MachOAnalysisResult result;

    bool ReadHeader(size_t offset = 0);
    bool ReadLoadCommands(size_t offset);
    bool ReadSegment(size_t offset, bool is64);
    bool ReadSymbolTable(size_t offset);
    bool ReadDylibCommand(size_t offset, bool isId);
    bool ReadUUID(size_t offset);
    bool ReadCodeSignature(size_t offset);
    bool ReadEncryptionInfo(size_t offset, bool is64);
    bool ReadVersionMin(size_t offset, std::string& platform);
    bool ReadBuildVersion(size_t offset);
    bool ReadDyldInfo(size_t offset);
    bool ReadMain(size_t offset);

    void AnalyzeSecurity();
    void CalculateSectionEntropy();

    template<typename T>
    T Read() {
        T value;
        file.read(reinterpret_cast<char*>(&value), sizeof(T));
        if (needsSwap) {
            return SwapBytes(value);
        }
        return value;
    }

    std::string ReadString(size_t maxLen = 256) {
        std::string str;
        char ch;
        for (size_t i = 0; i < maxLen; i++) {
            file.read(&ch, 1);
            if (ch == '\0') break;
            str += ch;
        }
        return str;
    }
};

bool MachOAnalyzer::Impl::ReadHeader(size_t offset) {
    file.seekg(offset, std::ios::beg);

    uint32_t magic = Read<uint32_t>();
    result.header.magic = magic;

    // Check magic and determine byte order
    if (magic == MH_MAGIC || magic == MH_MAGIC_64) {
        needsSwap = false;
    } else if (magic == MH_CIGAM || magic == MH_CIGAM_64) {
        needsSwap = true;
        magic = SwapBytes(magic);
        result.header.magic = magic;
    } else {
        result.errorMessage = "Invalid Mach-O magic number";
        return false;
    }

    is64Bit = (magic == MH_MAGIC_64);

    // Read header fields
    int32_t cpuType = Read<int32_t>();
    result.header.cpuType = MapCPUType(cpuType);
    result.header.cpuSubtype = Read<uint32_t>();

    uint32_t fileType = Read<uint32_t>();
    result.header.fileType = MapFileType(fileType);

    result.header.ncmds = Read<uint32_t>();
    result.header.sizeofcmds = Read<uint32_t>();
    result.header.flags = Read<uint32_t>();

    if (is64Bit) {
        result.header.reserved = Read<uint32_t>();
    }

    return true;
}

bool MachOAnalyzer::Impl::ReadLoadCommands(size_t baseOffset) {
    size_t offset = baseOffset + (is64Bit ? 32 : 28);

    for (uint32_t i = 0; i < result.header.ncmds; i++) {
        file.seekg(offset, std::ios::beg);

        uint32_t cmd = Read<uint32_t>();
        uint32_t cmdsize = Read<uint32_t>();

        size_t cmdOffset = offset + 8;

        switch (cmd) {
            case LC_SEGMENT:
                ReadSegment(cmdOffset, false);
                break;
            case LC_SEGMENT_64:
                ReadSegment(cmdOffset, true);
                break;
            case LC_SYMTAB:
                ReadSymbolTable(cmdOffset);
                break;
            case LC_LOAD_DYLIB:
            case LC_LOAD_WEAK_DYLIB:
                ReadDylibCommand(cmdOffset, false);
                break;
            case LC_ID_DYLIB:
                ReadDylibCommand(cmdOffset, true);
                break;
            case LC_UUID:
                ReadUUID(cmdOffset);
                break;
            case LC_CODE_SIGNATURE:
                ReadCodeSignature(cmdOffset);
                break;
            case LC_ENCRYPTION_INFO:
                ReadEncryptionInfo(cmdOffset, false);
                break;
            case LC_ENCRYPTION_INFO_64:
                ReadEncryptionInfo(cmdOffset, true);
                break;
            case LC_VERSION_MIN_MACOSX:
                ReadVersionMin(cmdOffset, result.platform);
                result.platform = "macOS";
                break;
            case LC_VERSION_MIN_IPHONEOS:
                ReadVersionMin(cmdOffset, result.minOSVersion);
                result.platform = "iOS";
                break;
            case LC_BUILD_VERSION:
                ReadBuildVersion(cmdOffset);
                break;
            case LC_DYLD_INFO:
            case LC_DYLD_INFO_ONLY:
                ReadDyldInfo(cmdOffset);
                break;
            case LC_MAIN:
                ReadMain(cmdOffset);
                break;
        }

        offset += cmdsize;
    }

    return true;
}

bool MachOAnalyzer::Impl::ReadSegment(size_t offset, bool is64) {
    file.seekg(offset, std::ios::beg);

    SegmentCommand seg;
    char segname[16];
    file.read(segname, 16);
    seg.segname = std::string(segname, strnlen(segname, 16));

    if (is64) {
        seg.vmaddr = Read<uint64_t>();
        seg.vmsize = Read<uint64_t>();
        seg.fileoff = Read<uint64_t>();
        seg.filesize = Read<uint64_t>();
    } else {
        seg.vmaddr = Read<uint32_t>();
        seg.vmsize = Read<uint32_t>();
        seg.fileoff = Read<uint32_t>();
        seg.filesize = Read<uint32_t>();
    }

    seg.maxprot = Read<int32_t>();
    seg.initprot = Read<int32_t>();
    seg.nsects = Read<uint32_t>();
    seg.flags = Read<uint32_t>();

    result.segments.push_back(seg);

    // Read sections
    for (uint32_t i = 0; i < seg.nsects; i++) {
        Section sect;
        char sectname[16], segname_sect[16];
        file.read(sectname, 16);
        file.read(segname_sect, 16);
        sect.sectname = std::string(sectname, strnlen(sectname, 16));
        sect.segname = std::string(segname_sect, strnlen(segname_sect, 16));

        if (is64) {
            sect.addr = Read<uint64_t>();
            sect.size = Read<uint64_t>();
        } else {
            sect.addr = Read<uint32_t>();
            sect.size = Read<uint32_t>();
        }

        sect.offset = Read<uint32_t>();
        sect.align = Read<uint32_t>();
        sect.reloff = Read<uint32_t>();
        sect.nreloc = Read<uint32_t>();
        sect.flags = Read<uint32_t>();
        sect.reserved1 = Read<uint32_t>();
        sect.reserved2 = Read<uint32_t>();

        if (is64) {
            sect.reserved3 = Read<uint32_t>();
        }

        result.sections.push_back(sect);
    }

    return true;
}

bool MachOAnalyzer::Impl::ReadSymbolTable(size_t offset) {
    file.seekg(offset, std::ios::beg);

    uint32_t symoff = Read<uint32_t>();
    uint32_t nsyms = Read<uint32_t>();
    uint32_t stroff = Read<uint32_t>();
    uint32_t strsize = Read<uint32_t>();

    // Read string table
    std::vector<char> stringTable(strsize);
    file.seekg(stroff, std::ios::beg);
    file.read(stringTable.data(), strsize);

    // Read symbols
    file.seekg(symoff, std::ios::beg);
    for (uint32_t i = 0; i < nsyms; i++) {
        Symbol sym;
        uint32_t strx = Read<uint32_t>();

        if (strx < strsize) {
            sym.name = &stringTable[strx];
        }

        sym.type = Read<uint8_t>();
        sym.sect = Read<uint8_t>();
        sym.desc = Read<uint16_t>();

        if (is64Bit) {
            sym.value = Read<uint64_t>();
        } else {
            sym.value = Read<uint32_t>();
        }

        result.symbols.push_back(sym);
    }

    return true;
}

bool MachOAnalyzer::Impl::ReadDylibCommand(size_t offset, bool isId) {
    file.seekg(offset, std::ios::beg);

    DylibInfo dylib;
    uint32_t nameOffset = Read<uint32_t>();
    dylib.timestamp = Read<uint32_t>();
    dylib.currentVersion = Read<uint32_t>();
    dylib.compatibilityVersion = Read<uint32_t>();

    // Read dylib name
    file.seekg(offset + nameOffset - 8, std::ios::beg);
    dylib.name = ReadString();

    result.dylibs.push_back(dylib);
    return true;
}

bool MachOAnalyzer::Impl::ReadUUID(size_t offset) {
    file.seekg(offset, std::ios::beg);

    uint8_t uuid[16];
    file.read(reinterpret_cast<char*>(uuid), 16);

    char uuidStr[37];
    snprintf(uuidStr, sizeof(uuidStr),
             "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
             uuid[0], uuid[1], uuid[2], uuid[3],
             uuid[4], uuid[5], uuid[6], uuid[7],
             uuid[8], uuid[9], uuid[10], uuid[11],
             uuid[12], uuid[13], uuid[14], uuid[15]);

    result.uuid = uuidStr;
    return true;
}

bool MachOAnalyzer::Impl::ReadCodeSignature(size_t offset) {
    file.seekg(offset, std::ios::beg);

    result.codeSignature.dataoff = Read<uint32_t>();
    result.codeSignature.datasize = Read<uint32_t>();
    result.codeSignature.present = true;

    return true;
}

bool MachOAnalyzer::Impl::ReadEncryptionInfo(size_t offset, bool is64) {
    file.seekg(offset, std::ios::beg);

    uint32_t cryptoff = Read<uint32_t>();
    uint32_t cryptsize = Read<uint32_t>();
    uint32_t cryptid = Read<uint32_t>();

    if (cryptid != 0) {
        result.security.encrypted = true;
    }

    return true;
}

bool MachOAnalyzer::Impl::ReadVersionMin(size_t offset, std::string& version) {
    file.seekg(offset, std::ios::beg);

    uint32_t ver = Read<uint32_t>();
    uint32_t sdk = Read<uint32_t>();

    uint32_t major = (ver >> 16) & 0xFFFF;
    uint32_t minor = (ver >> 8) & 0xFF;
    uint32_t patch = ver & 0xFF;

    version = std::to_string(major) + "." + std::to_string(minor) + "." + std::to_string(patch);

    uint32_t sdk_major = (sdk >> 16) & 0xFFFF;
    uint32_t sdk_minor = (sdk >> 8) & 0xFF;
    uint32_t sdk_patch = sdk & 0xFF;

    result.sdkVersion = std::to_string(sdk_major) + "." + std::to_string(sdk_minor) + "." + std::to_string(sdk_patch);

    return true;
}

bool MachOAnalyzer::Impl::ReadBuildVersion(size_t offset) {
    file.seekg(offset, std::ios::beg);

    uint32_t platform = Read<uint32_t>();
    uint32_t minos = Read<uint32_t>();
    uint32_t sdk = Read<uint32_t>();

    // Map platform
    switch (platform) {
        case 1: result.platform = "macOS"; break;
        case 2: result.platform = "iOS"; break;
        case 3: result.platform = "tvOS"; break;
        case 4: result.platform = "watchOS"; break;
        case 6: result.platform = "macCatalyst"; break;
        default: result.platform = "Unknown"; break;
    }

    uint32_t major = (minos >> 16) & 0xFFFF;
    uint32_t minor = (minos >> 8) & 0xFF;
    uint32_t patch = minos & 0xFF;
    result.minOSVersion = std::to_string(major) + "." + std::to_string(minor) + "." + std::to_string(patch);

    return true;
}

bool MachOAnalyzer::Impl::ReadDyldInfo(size_t offset) {
    file.seekg(offset, std::ios::beg);

    uint32_t rebase_off = Read<uint32_t>();
    uint32_t rebase_size = Read<uint32_t>();
    uint32_t bind_off = Read<uint32_t>();
    uint32_t bind_size = Read<uint32_t>();
    uint32_t weak_bind_off = Read<uint32_t>();
    uint32_t weak_bind_size = Read<uint32_t>();
    uint32_t lazy_bind_off = Read<uint32_t>();
    uint32_t lazy_bind_size = Read<uint32_t>();
    uint32_t export_off = Read<uint32_t>();
    uint32_t export_size = Read<uint32_t>();

    // Could parse binding info here for more details
    return true;
}

bool MachOAnalyzer::Impl::ReadMain(size_t offset) {
    file.seekg(offset, std::ios::beg);

    result.entryPoint = Read<uint64_t>();
    uint64_t stacksize = Read<uint64_t>();

    return true;
}

void MachOAnalyzer::Impl::AnalyzeSecurity() {
    // Check PIE
    result.security.pie = (result.header.flags & MH_PIE) != 0;

    // Check no heap execution
    bool noHeapExec = (result.header.flags & MH_NO_HEAP_EXECUTION) != 0;

    // Check for stack canary - look for __stack_chk symbols
    for (const auto& sym : result.symbols) {
        if (sym.name.find("___stack_chk") != std::string::npos) {
            result.security.stackCanary = true;
        }
        if (sym.name.find("_objc_release") != std::string::npos ||
            sym.name.find("_objc_retain") != std::string::npos) {
            result.security.arc = true;
        }
    }

    // Check code signature
    result.security.codeSignature = result.codeSignature.present;

    // Check for __RESTRICT segment (hardened runtime)
    for (const auto& seg : result.segments) {
        if (seg.segname == "__RESTRICT") {
            result.security.restrict = true;
            result.security.hardenedRuntime = true;
        }
    }

    // Calculate security score
    int score = 0;
    if (result.security.pie) score += 20;
    if (result.security.stackCanary) score += 15;
    if (result.security.arc) score += 15;
    if (result.security.codeSignature) score += 20;
    if (result.security.hardenedRuntime) score += 20;
    if (result.security.libraryValidation) score += 10;

    result.security.securityScore = score;
}

void MachOAnalyzer::Impl::CalculateSectionEntropy() {
    double totalEntropy = 0.0;
    int sectionCount = 0;

    for (auto& section : result.sections) {
        if (section.size == 0 || section.offset == 0) {
            continue;
        }

        // Read section data
        file.seekg(section.offset, std::ios::beg);
        std::vector<uint8_t> data(std::min<size_t>(section.size, 65536)); // Max 64KB per section
        file.read(reinterpret_cast<char*>(data.data()), data.size());

        section.entropy = CalculateEntropy(data);
        totalEntropy += section.entropy;
        sectionCount++;
    }

    if (sectionCount > 0) {
        result.averageEntropy = totalEntropy / sectionCount;
    }
}

// MachOAnalyzer implementation
MachOAnalyzer::MachOAnalyzer() : pImpl(std::make_unique<Impl>()) {}

MachOAnalyzer::~MachOAnalyzer() = default;

MachOAnalysisResult MachOAnalyzer::Analyze(const std::filesystem::path& filePath) {
    pImpl->result = MachOAnalysisResult();
    pImpl->result.success = false;

    // Open file
    pImpl->file.open(filePath, std::ios::binary);
    if (!pImpl->file.is_open()) {
        pImpl->result.errorMessage = "Failed to open file";
        return pImpl->result;
    }

    // Get file size
    pImpl->file.seekg(0, std::ios::end);
    pImpl->result.fileSize = pImpl->file.tellg();
    pImpl->file.seekg(0, std::ios::beg);

    // Check if universal binary
    uint32_t magic;
    pImpl->file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    pImpl->file.seekg(0, std::ios::beg);

    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        pImpl->result.isUniversalBinary = true;

        // Read FAT header
        FatHeader fatHeader;
        fatHeader.magic = magic;

        bool needsSwap = (magic == FAT_CIGAM);
        if (needsSwap) {
            pImpl->file.read(reinterpret_cast<char*>(&fatHeader.nfat_arch), sizeof(uint32_t));
            fatHeader.nfat_arch = SwapBytes(fatHeader.nfat_arch);
        } else {
            pImpl->file.read(reinterpret_cast<char*>(&fatHeader.nfat_arch), sizeof(uint32_t));
        }

        // Read architectures
        for (uint32_t i = 0; i < fatHeader.nfat_arch; i++) {
            FatArch arch;
            int32_t cpuType;
            pImpl->file.read(reinterpret_cast<char*>(&cpuType), sizeof(int32_t));
            pImpl->file.read(reinterpret_cast<char*>(&arch.cpuSubtype), sizeof(uint32_t));
            pImpl->file.read(reinterpret_cast<char*>(&arch.offset), sizeof(uint32_t));
            pImpl->file.read(reinterpret_cast<char*>(&arch.size), sizeof(uint32_t));
            pImpl->file.read(reinterpret_cast<char*>(&arch.align), sizeof(uint32_t));

            if (needsSwap) {
                cpuType = SwapBytes(cpuType);
                arch.cpuSubtype = SwapBytes(arch.cpuSubtype);
                arch.offset = SwapBytes(arch.offset);
                arch.size = SwapBytes(arch.size);
                arch.align = SwapBytes(arch.align);
            }

            arch.cpuType = MapCPUType(cpuType);
            pImpl->result.architectures.push_back(arch);
        }

        // Analyze first architecture by default
        if (!pImpl->result.architectures.empty()) {
            return AnalyzeArchitecture(filePath, 0);
        } else {
            pImpl->result.errorMessage = "No architectures found in universal binary";
            return pImpl->result;
        }
    }

    // Single architecture Mach-O
    if (!pImpl->ReadHeader(0)) {
        return pImpl->result;
    }

    if (!pImpl->ReadLoadCommands(0)) {
        return pImpl->result;
    }

    pImpl->CalculateSectionEntropy();
    pImpl->AnalyzeSecurity();

    pImpl->result.success = true;
    pImpl->file.close();

    return pImpl->result;
}

MachOAnalysisResult MachOAnalyzer::AnalyzeArchitecture(const std::filesystem::path& filePath, size_t archIndex) {
    pImpl->result = MachOAnalysisResult();
    pImpl->result.success = false;

    auto info = GetUniversalBinaryInfo(filePath);
    if (!info || archIndex >= info->second.size()) {
        pImpl->result.errorMessage = "Invalid architecture index";
        return pImpl->result;
    }

    pImpl->file.open(filePath, std::ios::binary);
    if (!pImpl->file.is_open()) {
        pImpl->result.errorMessage = "Failed to open file";
        return pImpl->result;
    }

    const FatArch& arch = info->second[archIndex];
    pImpl->result.isUniversalBinary = true;
    pImpl->result.architectures = info->second;

    if (!pImpl->ReadHeader(arch.offset)) {
        pImpl->file.close();
        return pImpl->result;
    }

    if (!pImpl->ReadLoadCommands(arch.offset)) {
        pImpl->file.close();
        return pImpl->result;
    }

    pImpl->CalculateSectionEntropy();
    pImpl->AnalyzeSecurity();

    pImpl->result.success = true;
    pImpl->file.close();

    return pImpl->result;
}

bool MachOAnalyzer::IsMachO(const std::filesystem::path& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return false;

    uint32_t magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));

    return (magic == MH_MAGIC || magic == MH_CIGAM ||
            magic == MH_MAGIC_64 || magic == MH_CIGAM_64 ||
            magic == FAT_MAGIC || magic == FAT_CIGAM);
}

bool MachOAnalyzer::IsUniversalBinary(const std::filesystem::path& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return false;

    uint32_t magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));

    return (magic == FAT_MAGIC || magic == FAT_CIGAM);
}

std::optional<std::pair<FatHeader, std::vector<FatArch>>> MachOAnalyzer::GetUniversalBinaryInfo(
    const std::filesystem::path& filePath) {

    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return std::nullopt;

    uint32_t magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));

    if (magic != FAT_MAGIC && magic != FAT_CIGAM) {
        return std::nullopt;
    }

    FatHeader header;
    header.magic = magic;
    bool needsSwap = (magic == FAT_CIGAM);

    file.read(reinterpret_cast<char*>(&header.nfat_arch), sizeof(uint32_t));
    if (needsSwap) {
        header.nfat_arch = SwapBytes(header.nfat_arch);
    }

    std::vector<FatArch> architectures;
    for (uint32_t i = 0; i < header.nfat_arch; i++) {
        FatArch arch;
        int32_t cpuType;
        file.read(reinterpret_cast<char*>(&cpuType), sizeof(int32_t));
        file.read(reinterpret_cast<char*>(&arch.cpuSubtype), sizeof(uint32_t));
        file.read(reinterpret_cast<char*>(&arch.offset), sizeof(uint32_t));
        file.read(reinterpret_cast<char*>(&arch.size), sizeof(uint32_t));
        file.read(reinterpret_cast<char*>(&arch.align), sizeof(uint32_t));

        if (needsSwap) {
            cpuType = SwapBytes(cpuType);
            arch.cpuSubtype = SwapBytes(arch.cpuSubtype);
            arch.offset = SwapBytes(arch.offset);
            arch.size = SwapBytes(arch.size);
            arch.align = SwapBytes(arch.align);
        }

        arch.cpuType = MapCPUType(cpuType);
        architectures.push_back(arch);
    }

    return std::make_pair(header, architectures);
}

std::string MachOAnalyzer::CPUTypeToString(CPUType type) {
    switch (type) {
        case CPUType::X86: return "x86";
        case CPUType::X86_64: return "x86_64";
        case CPUType::ARM: return "ARM";
        case CPUType::ARM64: return "ARM64";
        case CPUType::PowerPC: return "PowerPC";
        case CPUType::PowerPC64: return "PowerPC64";
        default: return "Unknown";
    }
}

std::string MachOAnalyzer::FileTypeToString(FileType type) {
    switch (type) {
        case FileType::Object: return "Object";
        case FileType::Execute: return "Executable";
        case FileType::FVMLib: return "Fixed VM Library";
        case FileType::Core: return "Core Dump";
        case FileType::Preload: return "Preloaded Executable";
        case FileType::Dylib: return "Dynamic Library";
        case FileType::Dylinker: return "Dynamic Linker";
        case FileType::Bundle: return "Bundle";
        case FileType::DylibStub: return "Dynamic Library Stub";
        case FileType::DSYM: return "Debug Symbols";
        case FileType::KextBundle: return "Kernel Extension";
        default: return "Unknown";
    }
}

} // namespace macho
} // namespace scylla
