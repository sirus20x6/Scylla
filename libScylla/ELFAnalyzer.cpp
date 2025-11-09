#include "ELFAnalyzer.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <iomanip>

// ELF constants
#define EI_NIDENT 16
#define EI_MAG0 0
#define EI_MAG1 1
#define EI_MAG2 2
#define EI_MAG3 3
#define EI_CLASS 4
#define EI_DATA 5
#define EI_VERSION 6
#define EI_OSABI 7
#define EI_ABIVERSION 8

#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'

#define ELFCLASS32 1
#define ELFCLASS64 2

#define ELFDATA2LSB 1
#define ELFDATA2MSB 2

// ELF32 structures
struct Elf32_Ehdr {
    unsigned char e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Elf32_Shdr {
    uint32_t sh_name;
    uint32_t sh_type;
    uint32_t sh_flags;
    uint32_t sh_addr;
    uint32_t sh_offset;
    uint32_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint32_t sh_addralign;
    uint32_t sh_entsize;
};

struct Elf32_Phdr {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
};

struct Elf32_Sym {
    uint32_t st_name;
    uint32_t st_value;
    uint32_t st_size;
    unsigned char st_info;
    unsigned char st_other;
    uint16_t st_shndx;
};

struct Elf32_Dyn {
    int32_t d_tag;
    union {
        uint32_t d_val;
        uint32_t d_ptr;
    } d_un;
};

// ELF64 structures
struct Elf64_Ehdr {
    unsigned char e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Elf64_Shdr {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};

struct Elf64_Phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

struct Elf64_Sym {
    uint32_t st_name;
    unsigned char st_info;
    unsigned char st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};

struct Elf64_Dyn {
    int64_t d_tag;
    union {
        uint64_t d_val;
        uint64_t d_ptr;
    } d_un;
};

// Dynamic table tags
#define DT_NULL 0
#define DT_NEEDED 1
#define DT_SONAME 14
#define DT_RPATH 15
#define DT_RUNPATH 29

namespace scylla {
namespace elf {

//-----------------------------------------------------------------------------
// ELFAnalyzer Implementation
//-----------------------------------------------------------------------------

class ELFAnalyzer::Impl {
public:
    std::vector<uint8_t> fileData;
    ELFHeader header;

    bool LoadFile(const std::filesystem::path& filePath) {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file) {
            return false;
        }

        size_t fileSize = file.tellg();
        file.seekg(0, std::ios::beg);

        fileData.resize(fileSize);
        file.read(reinterpret_cast<char*>(fileData.data()), fileSize);

        return file.good();
    }
};

ELFAnalyzer::ELFAnalyzer() : pImpl(std::make_unique<Impl>()) {
}

ELFAnalyzer::~ELFAnalyzer() = default;

bool ELFAnalyzer::IsELFFile(const std::filesystem::path& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        return false;
    }

    unsigned char magic[4];
    file.read(reinterpret_cast<char*>(magic), 4);

    return magic[EI_MAG0] == ELFMAG0 &&
           magic[EI_MAG1] == ELFMAG1 &&
           magic[EI_MAG2] == ELFMAG2 &&
           magic[EI_MAG3] == ELFMAG3;
}

std::optional<ELFHeader> ELFAnalyzer::ExtractHeader(const std::filesystem::path& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        return std::nullopt;
    }

    unsigned char e_ident[EI_NIDENT];
    file.read(reinterpret_cast<char*>(e_ident), EI_NIDENT);

    // Check magic number
    if (e_ident[EI_MAG0] != ELFMAG0 ||
        e_ident[EI_MAG1] != ELFMAG1 ||
        e_ident[EI_MAG2] != ELFMAG2 ||
        e_ident[EI_MAG3] != ELFMAG3) {
        return std::nullopt;
    }

    ELFHeader header;

    // Parse identification
    header.elfClass = (e_ident[EI_CLASS] == ELFCLASS32) ? ELFClass::ELF32 :
                      (e_ident[EI_CLASS] == ELFCLASS64) ? ELFClass::ELF64 : ELFClass::None;

    header.encoding = (e_ident[EI_DATA] == ELFDATA2LSB) ? ELFEncoding::LSB :
                      (e_ident[EI_DATA] == ELFDATA2MSB) ? ELFEncoding::MSB : ELFEncoding::None;

    header.version = e_ident[EI_VERSION];
    header.osABI = e_ident[EI_OSABI];
    header.abiVersion = e_ident[EI_ABIVERSION];

    // Read rest of header based on class
    if (header.elfClass == ELFClass::ELF32) {
        Elf32_Ehdr ehdr;
        std::memcpy(ehdr.e_ident, e_ident, EI_NIDENT);
        file.read(reinterpret_cast<char*>(&ehdr.e_type), sizeof(Elf32_Ehdr) - EI_NIDENT);

        header.type = static_cast<ELFType>(ehdr.e_type);
        header.machine = static_cast<ELFMachine>(ehdr.e_machine);
        header.entry = ehdr.e_entry;
        header.phoff = ehdr.e_phoff;
        header.shoff = ehdr.e_shoff;
        header.flags = ehdr.e_flags;
        header.phnum = ehdr.e_phnum;
        header.shnum = ehdr.e_shnum;
        header.shstrndx = ehdr.e_shstrndx;

    } else if (header.elfClass == ELFClass::ELF64) {
        Elf64_Ehdr ehdr;
        std::memcpy(ehdr.e_ident, e_ident, EI_NIDENT);
        file.read(reinterpret_cast<char*>(&ehdr.e_type), sizeof(Elf64_Ehdr) - EI_NIDENT);

        header.type = static_cast<ELFType>(ehdr.e_type);
        header.machine = static_cast<ELFMachine>(ehdr.e_machine);
        header.entry = ehdr.e_entry;
        header.phoff = ehdr.e_phoff;
        header.shoff = ehdr.e_shoff;
        header.flags = ehdr.e_flags;
        header.phnum = ehdr.e_phnum;
        header.shnum = ehdr.e_shnum;
        header.shstrndx = ehdr.e_shstrndx;
    }

    return header;
}

ELFAnalysisResult ELFAnalyzer::Analyze(const std::filesystem::path& filePath) {
    ELFAnalysisResult result;

    // Load file
    if (!pImpl->LoadFile(filePath)) {
        return result;
    }

    const uint8_t* data = pImpl->fileData.data();
    size_t size = pImpl->fileData.size();

    // Check if ELF
    if (size < EI_NIDENT || !IsELFFile(filePath)) {
        result.isELF = false;
        return result;
    }

    result.isELF = true;

    // Extract header
    auto header = ExtractHeader(filePath);
    if (!header) {
        return result;
    }

    result.header = *header;
    pImpl->header = *header;

    // Parse based on class
    if (header->elfClass == ELFClass::ELF32) {
        ParseELF32(data, size, result);
    } else if (header->elfClass == ELFClass::ELF64) {
        ParseELF64(data, size, result);
    }

    // Extract sections
    result.sections = ExtractSections(filePath);

    // Extract segments
    result.segments = ExtractSegments(filePath);

    // Extract symbols
    result.symbols = ExtractSymbols(filePath);

    // Count function symbols
    for (const auto& sym : result.symbols) {
        if (sym.IsFunction()) {
            result.functionCount++;
            if (sym.IsGlobal()) {
                result.exportedFunctionCount++;
            }
        }
        if (sym.IsGlobal()) {
            result.globalSymbolCount++;
        }
    }

    // Extract dynamic information
    result.dynamic = ExtractDynamic(filePath);
    result.dependencies = ExtractDependencies(filePath);

    // Find interpreter
    for (const auto& segment : result.segments) {
        if (segment.type == ProgramType::Interp && segment.offset < size) {
            result.interpreter = ReadString(data + segment.offset, 0, segment.filesz);
            break;
        }
    }

    // Analyze security
    result.security = AnalyzeSecurity(filePath);

    return result;
}

bool ELFAnalyzer::ParseELF32(const uint8_t* data, size_t size, ELFAnalysisResult& result) {
    // Basic parsing - sections/segments extracted separately
    return true;
}

bool ELFAnalyzer::ParseELF64(const uint8_t* data, size_t size, ELFAnalysisResult& result) {
    // Basic parsing - sections/segments extracted separately
    return true;
}

std::vector<SectionHeader> ELFAnalyzer::ExtractSections(const std::filesystem::path& filePath) {
    std::vector<SectionHeader> sections;

    if (pImpl->fileData.empty()) {
        return sections;
    }

    const uint8_t* data = pImpl->fileData.data();
    size_t size = pImpl->fileData.size();

    if (pImpl->header.elfClass == ELFClass::ELF32) {
        sections = ParseSections32(data, pImpl->header);
    } else if (pImpl->header.elfClass == ELFClass::ELF64) {
        sections = ParseSections64(data, pImpl->header);
    }

    return sections;
}

std::vector<SectionHeader> ELFAnalyzer::ParseSections32(const uint8_t* data, const ELFHeader& header) {
    std::vector<SectionHeader> sections;

    if (header.shoff == 0 || header.shnum == 0) {
        return sections;
    }

    // Read section headers
    const Elf32_Shdr* shdrs = reinterpret_cast<const Elf32_Shdr*>(data + header.shoff);

    // Get string table section for section names
    const Elf32_Shdr& shstrtab = shdrs[header.shstrndx];
    const char* strtab = reinterpret_cast<const char*>(data + shstrtab.sh_offset);

    for (uint16_t i = 0; i < header.shnum; i++) {
        SectionHeader section;
        section.name = ReadString(data, shstrtab.sh_offset + shdrs[i].sh_name, 256);
        section.type = static_cast<SectionType>(shdrs[i].sh_type);
        section.flags = shdrs[i].sh_flags;
        section.addr = shdrs[i].sh_addr;
        section.offset = shdrs[i].sh_offset;
        section.size = shdrs[i].sh_size;
        section.link = shdrs[i].sh_link;
        section.info = shdrs[i].sh_info;
        section.addralign = shdrs[i].sh_addralign;
        section.entsize = shdrs[i].sh_entsize;

        sections.push_back(section);
    }

    return sections;
}

std::vector<SectionHeader> ELFAnalyzer::ParseSections64(const uint8_t* data, const ELFHeader& header) {
    std::vector<SectionHeader> sections;

    if (header.shoff == 0 || header.shnum == 0) {
        return sections;
    }

    const Elf64_Shdr* shdrs = reinterpret_cast<const Elf64_Shdr*>(data + header.shoff);
    const Elf64_Shdr& shstrtab = shdrs[header.shstrndx];

    for (uint16_t i = 0; i < header.shnum; i++) {
        SectionHeader section;
        section.name = ReadString(data, shstrtab.sh_offset + shdrs[i].sh_name, 256);
        section.type = static_cast<SectionType>(shdrs[i].sh_type);
        section.flags = shdrs[i].sh_flags;
        section.addr = shdrs[i].sh_addr;
        section.offset = shdrs[i].sh_offset;
        section.size = shdrs[i].sh_size;
        section.link = shdrs[i].sh_link;
        section.info = shdrs[i].sh_info;
        section.addralign = shdrs[i].sh_addralign;
        section.entsize = shdrs[i].sh_entsize;

        sections.push_back(section);
    }

    return sections;
}

std::vector<ProgramHeader> ELFAnalyzer::ExtractSegments(const std::filesystem::path& filePath) {
    std::vector<ProgramHeader> segments;

    if (pImpl->fileData.empty()) {
        return segments;
    }

    const uint8_t* data = pImpl->fileData.data();

    if (pImpl->header.elfClass == ELFClass::ELF32) {
        segments = ParseSegments32(data, pImpl->header);
    } else if (pImpl->header.elfClass == ELFClass::ELF64) {
        segments = ParseSegments64(data, pImpl->header);
    }

    return segments;
}

std::vector<ProgramHeader> ELFAnalyzer::ParseSegments32(const uint8_t* data, const ELFHeader& header) {
    std::vector<ProgramHeader> segments;

    if (header.phoff == 0 || header.phnum == 0) {
        return segments;
    }

    const Elf32_Phdr* phdrs = reinterpret_cast<const Elf32_Phdr*>(data + header.phoff);

    for (uint16_t i = 0; i < header.phnum; i++) {
        ProgramHeader segment;
        segment.type = static_cast<ProgramType>(phdrs[i].p_type);
        segment.offset = phdrs[i].p_offset;
        segment.vaddr = phdrs[i].p_vaddr;
        segment.paddr = phdrs[i].p_paddr;
        segment.filesz = phdrs[i].p_filesz;
        segment.memsz = phdrs[i].p_memsz;
        segment.flags = phdrs[i].p_flags;
        segment.align = phdrs[i].p_align;

        segments.push_back(segment);
    }

    return segments;
}

std::vector<ProgramHeader> ELFAnalyzer::ParseSegments64(const uint8_t* data, const ELFHeader& header) {
    std::vector<ProgramHeader> segments;

    if (header.phoff == 0 || header.phnum == 0) {
        return segments;
    }

    const Elf64_Phdr* phdrs = reinterpret_cast<const Elf64_Phdr*>(data + header.phoff);

    for (uint16_t i = 0; i < header.phnum; i++) {
        ProgramHeader segment;
        segment.type = static_cast<ProgramType>(phdrs[i].p_type);
        segment.offset = phdrs[i].p_offset;
        segment.vaddr = phdrs[i].p_vaddr;
        segment.paddr = phdrs[i].p_paddr;
        segment.filesz = phdrs[i].p_filesz;
        segment.memsz = phdrs[i].p_memsz;
        segment.flags = phdrs[i].p_flags;
        segment.align = phdrs[i].p_align;

        segments.push_back(segment);
    }

    return segments;
}

std::vector<Symbol> ELFAnalyzer::ExtractSymbols(const std::filesystem::path& filePath) {
    std::vector<Symbol> symbols;

    if (pImpl->fileData.empty()) {
        return symbols;
    }

    const uint8_t* data = pImpl->fileData.data();
    size_t size = pImpl->fileData.size();

    auto sections = ExtractSections(filePath);

    // Find symbol tables
    for (const auto& section : sections) {
        if (section.type == SectionType::SymTab || section.type == SectionType::DynSym) {
            // Find corresponding string table
            if (section.link < sections.size()) {
                const auto& strtab = sections[section.link];

                bool is64bit = (pImpl->header.elfClass == ELFClass::ELF64);
                auto sectionSymbols = ParseSymbolTable(data, size, section, strtab, is64bit);
                symbols.insert(symbols.end(), sectionSymbols.begin(), sectionSymbols.end());
            }
        }
    }

    return symbols;
}

std::vector<Symbol> ELFAnalyzer::ParseSymbolTable(const uint8_t* data, size_t size,
                                                   const SectionHeader& symtab,
                                                   const SectionHeader& strtab,
                                                   bool is64bit) {
    std::vector<Symbol> symbols;

    if (symtab.offset >= size || strtab.offset >= size) {
        return symbols;
    }

    size_t entrySize = is64bit ? sizeof(Elf64_Sym) : sizeof(Elf32_Sym);
    size_t count = symtab.size / entrySize;

    for (size_t i = 0; i < count; i++) {
        Symbol sym;

        if (is64bit) {
            const Elf64_Sym* entry = reinterpret_cast<const Elf64_Sym*>(
                data + symtab.offset + i * sizeof(Elf64_Sym));

            sym.name = ReadString(data, strtab.offset + entry->st_name, 256);
            sym.binding = static_cast<SymbolBinding>(entry->st_info >> 4);
            sym.type = static_cast<SymbolType>(entry->st_info & 0xf);
            sym.value = entry->st_value;
            sym.size = entry->st_size;
            sym.shndx = entry->st_shndx;
        } else {
            const Elf32_Sym* entry = reinterpret_cast<const Elf32_Sym*>(
                data + symtab.offset + i * sizeof(Elf32_Sym));

            sym.name = ReadString(data, strtab.offset + entry->st_name, 256);
            sym.binding = static_cast<SymbolBinding>(entry->st_info >> 4);
            sym.type = static_cast<SymbolType>(entry->st_info & 0xf);
            sym.value = entry->st_value;
            sym.size = entry->st_size;
            sym.shndx = entry->st_shndx;
        }

        if (!sym.name.empty()) {
            symbols.push_back(sym);
        }
    }

    return symbols;
}

std::vector<DynamicEntry> ELFAnalyzer::ExtractDynamic(const std::filesystem::path& filePath) {
    std::vector<DynamicEntry> entries;

    if (pImpl->fileData.empty()) {
        return entries;
    }

    const uint8_t* data = pImpl->fileData.data();
    size_t size = pImpl->fileData.size();
    auto sections = ExtractSections(filePath);

    // Find .dynamic section
    for (const auto& section : sections) {
        if (section.type == SectionType::Dynamic) {
            bool is64bit = (pImpl->header.elfClass == ELFClass::ELF64);
            entries = ParseDynamicSection(data, size, section, sections, is64bit);
            break;
        }
    }

    return entries;
}

std::vector<DynamicEntry> ELFAnalyzer::ParseDynamicSection(const uint8_t* data, size_t size,
                                                            const SectionHeader& dynamic,
                                                            const std::vector<SectionHeader>& sections,
                                                            bool is64bit) {
    std::vector<DynamicEntry> entries;

    if (dynamic.offset >= size) {
        return entries;
    }

    // Find string table (.dynstr)
    const SectionHeader* dynstr = nullptr;
    for (const auto& section : sections) {
        if (section.name == ".dynstr") {
            dynstr = &section;
            break;
        }
    }

    size_t entrySize = is64bit ? sizeof(Elf64_Dyn) : sizeof(Elf32_Dyn);
    size_t count = dynamic.size / entrySize;

    for (size_t i = 0; i < count; i++) {
        DynamicEntry entry;

        if (is64bit) {
            const Elf64_Dyn* dyn = reinterpret_cast<const Elf64_Dyn*>(
                data + dynamic.offset + i * sizeof(Elf64_Dyn));

            entry.tag = dyn->d_tag;
            entry.value = dyn->d_un.d_val;

            if (entry.tag == DT_NULL) {
                break;
            }

            // Read string values
            if ((entry.tag == DT_NEEDED || entry.tag == DT_SONAME || entry.tag == DT_RPATH ||
                 entry.tag == DT_RUNPATH) && dynstr) {
                entry.stringValue = ReadString(data, dynstr->offset + entry.value, 256);
            }
        } else {
            const Elf32_Dyn* dyn = reinterpret_cast<const Elf32_Dyn*>(
                data + dynamic.offset + i * sizeof(Elf32_Dyn));

            entry.tag = dyn->d_tag;
            entry.value = dyn->d_un.d_val;

            if (entry.tag == DT_NULL) {
                break;
            }

            if ((entry.tag == DT_NEEDED || entry.tag == DT_SONAME || entry.tag == DT_RPATH ||
                 entry.tag == DT_RUNPATH) && dynstr) {
                entry.stringValue = ReadString(data, dynstr->offset + entry.value, 256);
            }
        }

        entries.push_back(entry);
    }

    return entries;
}

std::vector<std::string> ELFAnalyzer::ExtractDependencies(const std::filesystem::path& filePath) {
    std::vector<std::string> dependencies;

    auto dynamic = ExtractDynamic(filePath);

    for (const auto& entry : dynamic) {
        if (entry.tag == DT_NEEDED && !entry.stringValue.empty()) {
            dependencies.push_back(entry.stringValue);
        }
    }

    return dependencies;
}

ELFSecurityFeatures ELFAnalyzer::AnalyzeSecurity(const std::filesystem::path& filePath) {
    ELFSecurityFeatures features;

    if (pImpl->fileData.empty()) {
        return features;
    }

    auto segments = ExtractSegments(filePath);
    auto sections = ExtractSections(filePath);
    auto dynamic = ExtractDynamic(filePath);

    // Check NX (No-Execute)
    for (const auto& segment : segments) {
        if (segment.type == ProgramType::GNUStack) {
            features.nx = !segment.IsExecutable();
            break;
        }
    }

    // Check PIE (Position Independent Executable)
    features.pie = (pImpl->header.type == ELFType::Shared);

    // Check RELRO
    for (const auto& segment : segments) {
        if (segment.type == ProgramType::GNURelRo) {
            features.relro = true;
            break;
        }
    }

    // Check Full RELRO (requires BIND_NOW in dynamic section)
    for (const auto& entry : dynamic) {
        if (entry.tag == 24) {  // DT_FLAGS
            if (entry.value & 0x00000008) {  // DF_BIND_NOW
                features.fullRelro = true;
            }
        }
    }

    // Check stack canary (presence of __stack_chk_fail symbol)
    auto symbols = ExtractSymbols(filePath);
    for (const auto& sym : symbols) {
        if (sym.name.find("__stack_chk_fail") != std::string::npos) {
            features.stackCanary = true;
        }
        if (sym.name.find("__fortify") != std::string::npos) {
            features.fortify = true;
        }
    }

    // Check if stripped
    bool hasSymTab = false;
    for (const auto& section : sections) {
        if (section.type == SectionType::SymTab) {
            hasSymTab = true;
            break;
        }
    }
    features.stripped = !hasSymTab;

    // Check for build ID
    for (const auto& section : sections) {
        if (section.name == ".note.gnu.build-id") {
            features.hasBuildId = true;
            break;
        }
    }

    // Calculate security score
    features.securityScore = ELFUtils::CalculateSecurityScore(features);

    return features;
}

std::string ELFAnalyzer::ReadString(const uint8_t* data, size_t offset, size_t maxSize) const {
    std::string result;

    for (size_t i = 0; i < maxSize; i++) {
        char c = data[offset + i];
        if (c == '\0') {
            break;
        }
        result += c;
    }

    return result;
}

// Static helper functions

std::string ELFAnalyzer::GetClassName(ELFClass elfClass) {
    switch (elfClass) {
        case ELFClass::ELF32: return "ELF32";
        case ELFClass::ELF64: return "ELF64";
        default: return "Unknown";
    }
}

std::string ELFAnalyzer::GetTypeName(ELFType type) {
    switch (type) {
        case ELFType::Relocatable: return "Relocatable";
        case ELFType::Executable: return "Executable";
        case ELFType::Shared: return "Shared Object";
        case ELFType::Core: return "Core Dump";
        default: return "Unknown";
    }
}

std::string ELFAnalyzer::GetMachineName(ELFMachine machine) {
    switch (machine) {
        case ELFMachine::X86: return "Intel 80386";
        case ELFMachine::X86_64: return "AMD x86-64";
        case ELFMachine::ARM: return "ARM";
        case ELFMachine::AARCH64: return "ARM 64-bit";
        case ELFMachine::MIPS: return "MIPS";
        case ELFMachine::PowerPC: return "PowerPC";
        case ELFMachine::PowerPC64: return "PowerPC 64-bit";
        case ELFMachine::RISC_V: return "RISC-V";
        case ELFMachine::SPARC: return "SPARC";
        case ELFMachine::S390: return "IBM S/390";
        default: return "Unknown";
    }
}

std::string ELFAnalyzer::GetSectionTypeName(SectionType type) {
    switch (type) {
        case SectionType::ProgBits: return "PROGBITS";
        case SectionType::SymTab: return "SYMTAB";
        case SectionType::StrTab: return "STRTAB";
        case SectionType::Rela: return "RELA";
        case SectionType::Hash: return "HASH";
        case SectionType::Dynamic: return "DYNAMIC";
        case SectionType::Note: return "NOTE";
        case SectionType::NoBits: return "NOBITS";
        case SectionType::Rel: return "REL";
        case SectionType::DynSym: return "DYNSYM";
        default: return "UNKNOWN";
    }
}

std::string ELFAnalyzer::GetProgramTypeName(ProgramType type) {
    switch (type) {
        case ProgramType::Load: return "LOAD";
        case ProgramType::Dynamic: return "DYNAMIC";
        case ProgramType::Interp: return "INTERP";
        case ProgramType::Note: return "NOTE";
        case ProgramType::PHdr: return "PHDR";
        case ProgramType::TLS: return "TLS";
        case ProgramType::GNUStack: return "GNU_STACK";
        case ProgramType::GNURelRo: return "GNU_RELRO";
        default: return "UNKNOWN";
    }
}

//-----------------------------------------------------------------------------
// Utility Functions
//-----------------------------------------------------------------------------

namespace ELFUtils {

std::string FormatSymbol(const Symbol& symbol, bool verbose) {
    std::ostringstream oss;

    if (verbose) {
        oss << "Symbol: " << symbol.name << "\n";
        oss << "  Type: " << GetSymbolTypeName(symbol.type) << "\n";
        oss << "  Binding: " << GetBindingName(symbol.binding) << "\n";
        oss << "  Value: 0x" << std::hex << symbol.value << std::dec << "\n";
        oss << "  Size: " << symbol.size << " bytes\n";
    } else {
        oss << symbol.name << " @ 0x" << std::hex << symbol.value << std::dec;
    }

    return oss.str();
}

std::string FormatSection(const SectionHeader& section, bool verbose) {
    std::ostringstream oss;

    if (verbose) {
        oss << "Section: " << section.name << "\n";
        oss << "  Type: " << ELFAnalyzer::GetSectionTypeName(section.type) << "\n";
        oss << "  Flags: " << FormatSectionFlags(section.flags) << "\n";
        oss << "  Addr: 0x" << std::hex << section.addr << std::dec << "\n";
        oss << "  Offset: 0x" << std::hex << section.offset << std::dec << "\n";
        oss << "  Size: " << section.size << " bytes\n";
    } else {
        oss << section.name << " (" << FormatSectionFlags(section.flags) << ")";
    }

    return oss.str();
}

std::string FormatSegment(const ProgramHeader& segment, bool verbose) {
    std::ostringstream oss;

    if (verbose) {
        oss << "Segment: " << ELFAnalyzer::GetProgramTypeName(segment.type) << "\n";
        oss << "  Flags: " << FormatSegmentFlags(segment.flags) << "\n";
        oss << "  VAddr: 0x" << std::hex << segment.vaddr << std::dec << "\n";
        oss << "  FileSize: " << segment.filesz << " bytes\n";
        oss << "  MemSize: " << segment.memsz << " bytes\n";
    } else {
        oss << ELFAnalyzer::GetProgramTypeName(segment.type)
            << " (" << FormatSegmentFlags(segment.flags) << ")";
    }

    return oss.str();
}

std::string GetBindingName(SymbolBinding binding) {
    switch (binding) {
        case SymbolBinding::Local: return "LOCAL";
        case SymbolBinding::Global: return "GLOBAL";
        case SymbolBinding::Weak: return "WEAK";
        default: return "UNKNOWN";
    }
}

std::string GetSymbolTypeName(SymbolType type) {
    switch (type) {
        case SymbolType::NoType: return "NOTYPE";
        case SymbolType::Object: return "OBJECT";
        case SymbolType::Func: return "FUNC";
        case SymbolType::Section: return "SECTION";
        case SymbolType::File: return "FILE";
        case SymbolType::Common: return "COMMON";
        case SymbolType::TLS: return "TLS";
        default: return "UNKNOWN";
    }
}

std::string FormatSectionFlags(uint64_t flags) {
    std::string result;
    if (flags & 0x1) result += 'w';  // Writable
    if (flags & 0x2) result += 'a';  // Allocate
    if (flags & 0x4) result += 'x';  // Executable
    return result.empty() ? "-" : result;
}

std::string FormatSegmentFlags(uint32_t flags) {
    std::string result;
    result += (flags & 0x4) ? 'r' : '-';  // Read
    result += (flags & 0x2) ? 'w' : '-';  // Write
    result += (flags & 0x1) ? 'x' : '-';  // Execute
    return result;
}

uint32_t CalculateSecurityScore(const ELFSecurityFeatures& features) {
    uint32_t score = 0;

    if (features.nx) score += 20;
    if (features.pie) score += 20;
    if (features.relro) score += 15;
    if (features.fullRelro) score += 15;
    if (features.stackCanary) score += 15;
    if (features.fortify) score += 10;
    if (features.hasBuildId) score += 5;

    return std::min(score, 100u);
}

bool IsLikelyPacked(const ELFAnalysisResult& result) {
    // Heuristics for packed/obfuscated binaries
    if (result.sections.empty()) {
        return true;
    }

    // Very few sections
    if (result.sections.size() < 5) {
        return true;
    }

    // No symbols
    if (result.symbols.empty() && result.header.type != ELFType::Core) {
        return true;
    }

    return false;
}

std::optional<SectionHeader> FindSection(const std::vector<SectionHeader>& sections,
                                         const std::string& name) {
    for (const auto& section : sections) {
        if (section.name == name) {
            return section;
        }
    }
    return std::nullopt;
}

std::optional<SectionHeader> FindSectionByType(const std::vector<SectionHeader>& sections,
                                                SectionType type) {
    for (const auto& section : sections) {
        if (section.type == type) {
            return section;
        }
    }
    return std::nullopt;
}

std::string GetOSABIName(uint8_t osABI) {
    switch (osABI) {
        case 0: return "UNIX System V";
        case 1: return "HP-UX";
        case 2: return "NetBSD";
        case 3: return "Linux";
        case 6: return "Solaris";
        case 9: return "FreeBSD";
        case 12: return "OpenBSD";
        default: return "Unknown";
    }
}

std::string DemangleSymbol(const std::string& mangledName) {
    // Simplified demangling - could integrate with c++filt or similar
    // For now, just return the original name
    return mangledName;
}

} // namespace ELFUtils

} // namespace elf
} // namespace scylla
