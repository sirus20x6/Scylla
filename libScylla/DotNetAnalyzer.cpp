#include "DotNetAnalyzer.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <set>

#ifdef _WIN32
#include <windows.h>
#else
// Minimal PE structures for non-Windows
struct IMAGE_DOS_HEADER {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;
};

struct IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
};

#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE 0x00004550
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14
#endif

namespace scylla {
namespace dotnet {

//-----------------------------------------------------------------------------
// DotNetVersion
//-----------------------------------------------------------------------------

std::string DotNetVersion::ToString() const {
    std::ostringstream oss;
    oss << major << "." << minor << "." << build << "." << revision;
    return oss.str();
}

bool DotNetVersion::operator<(const DotNetVersion& other) const {
    if (major != other.major) return major < other.major;
    if (minor != other.minor) return minor < other.minor;
    if (build != other.build) return build < other.build;
    return revision < other.revision;
}

bool DotNetVersion::operator==(const DotNetVersion& other) const {
    return major == other.major && minor == other.minor &&
           build == other.build && revision == other.revision;
}

//-----------------------------------------------------------------------------
// DotNetAnalyzer Implementation
//-----------------------------------------------------------------------------

class DotNetAnalyzer::Impl {
public:
    std::vector<uint8_t> fileData;
    uint32_t clrHeaderRVA = 0;

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

    uint32_t RVAToOffset(uint32_t rva) {
        // Simplified RVA to file offset conversion
        // Full implementation would need section table parsing
        return rva;  // For now, assume RVA == file offset (works for some files)
    }
};

DotNetAnalyzer::DotNetAnalyzer() : pImpl(std::make_unique<Impl>()) {
}

DotNetAnalyzer::~DotNetAnalyzer() = default;

bool DotNetAnalyzer::IsManagedAssembly(const std::filesystem::path& filePath) {
    auto clrHeader = ExtractCLRHeader(filePath);
    return clrHeader.has_value();
}

std::optional<CLRHeader> DotNetAnalyzer::ExtractCLRHeader(const std::filesystem::path& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        return std::nullopt;
    }

    // Read DOS header
    IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        return std::nullopt;
    }

    // Read PE signature
    file.seekg(dosHeader.e_lfanew);
    uint32_t peSignature;
    file.read(reinterpret_cast<char*>(&peSignature), sizeof(peSignature));

    if (peSignature != IMAGE_NT_SIGNATURE) {
        return std::nullopt;
    }

    // Skip file header
    file.seekg(20, std::ios::cur);

    // Read optional header magic
    uint16_t magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    file.seekg(-static_cast<int>(sizeof(magic)), std::ios::cur);

    // Skip to data directories
    size_t dataDirectoryOffset;
    if (magic == 0x10b) {  // PE32
        dataDirectoryOffset = 96;
    } else if (magic == 0x20b) {  // PE32+
        dataDirectoryOffset = 112;
    } else {
        return std::nullopt;
    }

    file.seekg(dataDirectoryOffset, std::ios::cur);

    // Read data directory entries (skip to entry 14 - COM descriptor)
    IMAGE_DATA_DIRECTORY comDescriptor;
    file.seekg(14 * sizeof(IMAGE_DATA_DIRECTORY), std::ios::cur);
    file.read(reinterpret_cast<char*>(&comDescriptor), sizeof(comDescriptor));

    if (comDescriptor.VirtualAddress == 0 || comDescriptor.Size == 0) {
        return std::nullopt;  // Not a .NET assembly
    }

    // Read CLR header
    file.seekg(comDescriptor.VirtualAddress, std::ios::beg);

    CLRHeader clrHeader;
    file.read(reinterpret_cast<char*>(&clrHeader.headerSize), sizeof(uint32_t));
    file.read(reinterpret_cast<char*>(&clrHeader.majorRuntimeVersion), sizeof(uint16_t));
    file.read(reinterpret_cast<char*>(&clrHeader.minorRuntimeVersion), sizeof(uint16_t));
    file.read(reinterpret_cast<char*>(&clrHeader.metadataRVA), sizeof(uint32_t));
    file.read(reinterpret_cast<char*>(&clrHeader.metadataSize), sizeof(uint32_t));
    file.read(reinterpret_cast<char*>(&clrHeader.flags), sizeof(uint32_t));
    file.read(reinterpret_cast<char*>(&clrHeader.entryPointToken), sizeof(uint32_t));
    file.read(reinterpret_cast<char*>(&clrHeader.resourcesRVA), sizeof(uint32_t));
    file.read(reinterpret_cast<char*>(&clrHeader.resourcesSize), sizeof(uint32_t));
    file.read(reinterpret_cast<char*>(&clrHeader.strongNameSignatureRVA), sizeof(uint32_t));
    file.read(reinterpret_cast<char*>(&clrHeader.strongNameSignatureSize), sizeof(uint32_t));

    return clrHeader;
}

DotNetAnalysisResult DotNetAnalyzer::Analyze(const std::filesystem::path& filePath) {
    DotNetAnalysisResult result;

    // Check if managed assembly
    auto clrHeader = ExtractCLRHeader(filePath);
    if (!clrHeader) {
        result.isManagedAssembly = false;
        return result;
    }

    result.isManagedAssembly = true;
    result.clrHeader = *clrHeader;

    // Detect runtime type
    result.runtimeType = DetectRuntimeType(filePath);

    // Detect target framework
    auto targetFramework = DetectTargetFramework(filePath);
    if (targetFramework) {
        result.targetFramework = *targetFramework;
    }

    // Determine architecture
    if (clrHeader->Requires32Bit()) {
        result.architecture = AssemblyArchitecture::X86;
    } else if (clrHeader->IsILOnly()) {
        result.architecture = AssemblyArchitecture::MSIL;
    } else {
        // Mixed-mode assembly - need to check PE header
        result.architecture = AssemblyArchitecture::MSIL;
    }

    // Load file for further analysis
    if (!pImpl->LoadFile(filePath)) {
        return result;
    }

    // Extract assembly info
    result.assemblyInfo = ExtractAssemblyInfo(filePath);

    // Extract types
    result.types = ExtractTypes(filePath);
    result.typeCount = static_cast<uint32_t>(result.types.size());

    // Extract methods
    result.methods = ExtractMethods(filePath);
    result.methodCount = static_cast<uint32_t>(result.methods.size());

    // Analyze IL code
    result.ilStats = AnalyzeIL(filePath);

    // Extract namespaces
    std::set<std::string> uniqueNamespaces;
    for (const auto& type : result.types) {
        if (!type.namespaceName.empty()) {
            uniqueNamespaces.insert(type.namespaceName);
        }
    }
    result.namespaces.assign(uniqueNamespaces.begin(), uniqueNamespaces.end());

    // Detect obfuscation
    result.obfuscationIndicators = DetectObfuscation(result);

    // Check security issues
    result.securityIssues = CheckSecurityIssues(result);

    return result;
}

std::optional<DotNetVersion> DotNetAnalyzer::DetectTargetFramework(const std::filesystem::path& filePath) {
    auto clrHeader = ExtractCLRHeader(filePath);
    if (!clrHeader) {
        return std::nullopt;
    }

    // Map runtime version to framework version
    DotNetVersion version;
    version.major = clrHeader->majorRuntimeVersion;
    version.minor = clrHeader->minorRuntimeVersion;

    // Common mappings:
    // 2.0 = .NET 2.0-3.5
    // 2.5 = .NET 4.0-4.8
    // 4.0+ = .NET Core/5+

    if (version.major == 2 && version.minor == 0) {
        version.build = 50727;  // .NET 2.0-3.5
    } else if (version.major == 2 && version.minor == 5) {
        version.build = 30319;  // .NET 4.0
    } else if (version.major >= 4) {
        version.build = 0;      // .NET Core/5+
    }

    return version;
}

DotNetRuntimeType DotNetAnalyzer::DetectRuntimeType(const std::filesystem::path& filePath) {
    auto targetFramework = DetectTargetFramework(filePath);
    if (!targetFramework) {
        return DotNetRuntimeType::Unknown;
    }

    // Heuristic detection based on runtime version
    if (targetFramework->major >= 5) {
        return DotNetRuntimeType::Net5Plus;
    } else if (targetFramework->major >= 3) {
        return DotNetRuntimeType::NetCore;
    } else {
        return DotNetRuntimeType::NetFramework;
    }
}

AssemblyInfo DotNetAnalyzer::ExtractAssemblyInfo(const std::filesystem::path& filePath) {
    AssemblyInfo info;

    // Simplified: In a full implementation, this would parse the Assembly table
    // from the CLR metadata

    info.name = filePath.stem().string();
    info.version = { 1, 0, 0, 0 };

    return info;
}

std::vector<TypeInfo> DotNetAnalyzer::ExtractTypes(const std::filesystem::path& filePath) {
    std::vector<TypeInfo> types;

    // Simplified: Full implementation would parse TypeDef table from metadata
    // This is a placeholder showing the structure

    return types;
}

std::vector<MethodInfo> DotNetAnalyzer::ExtractMethods(const std::filesystem::path& filePath) {
    std::vector<MethodInfo> methods;

    // Simplified: Full implementation would parse MethodDef table from metadata

    return methods;
}

ILStatistics DotNetAnalyzer::AnalyzeIL(const std::filesystem::path& filePath) {
    ILStatistics stats;

    // Simplified: Full implementation would parse IL code for each method

    return stats;
}

std::vector<std::string> DotNetAnalyzer::DetectObfuscation(const DotNetAnalysisResult& result) {
    std::vector<std::string> indicators;

    // Check for obfuscation indicators
    if (result.typeCount > 0) {
        uint32_t shortNames = 0;
        uint32_t unicodeNames = 0;

        for (const auto& type : result.types) {
            // Short/mangled names
            if (type.name.length() <= 2) {
                shortNames++;
            }

            // Unicode/non-ASCII characters
            for (char c : type.name) {
                if (static_cast<unsigned char>(c) > 127) {
                    unicodeNames++;
                    break;
                }
            }
        }

        if (shortNames > result.typeCount / 3) {
            indicators.push_back("High percentage of short type names");
        }

        if (unicodeNames > result.typeCount / 5) {
            indicators.push_back("Unicode characters in type names");
        }
    }

    // Check for missing metadata
    if (result.methodCount == 0 && result.isManagedAssembly) {
        indicators.push_back("No methods found (possible metadata obfuscation)");
    }

    // Check strong name signature
    if (result.clrHeader.strongNameSignatureSize > 0 && !result.assemblyInfo.IsSigned()) {
        indicators.push_back("Invalid strong name signature");
    }

    return indicators;
}

std::vector<std::string> DotNetAnalyzer::CheckSecurityIssues(const DotNetAnalysisResult& result) {
    std::vector<std::string> issues;

    // Check if unsigned
    if (!result.assemblyInfo.IsSigned()) {
        issues.push_back("Assembly is not strong-name signed");
    }

    // Check runtime version
    if (result.targetFramework.major < 4) {
        issues.push_back("Using outdated .NET Framework version (< 4.0)");
    }

    // Check for mixed-mode (security risk)
    if (!result.clrHeader.IsILOnly()) {
        issues.push_back("Mixed-mode assembly (contains native code)");
    }

    return issues;
}

std::string DotNetAnalyzer::FormatVersion(const DotNetVersion& version) {
    return version.ToString();
}

DotNetVersion DotNetAnalyzer::ParseVersion(const std::string& versionStr) {
    DotNetVersion version;

    std::istringstream iss(versionStr);
    char dot;

    iss >> version.major >> dot >> version.minor;

    if (iss >> dot >> version.build) {
        if (iss >> dot >> version.revision) {
            // All components parsed
        }
    }

    return version;
}

std::string DotNetAnalyzer::GetRuntimeName(DotNetRuntimeType runtime) {
    switch (runtime) {
        case DotNetRuntimeType::NetFramework: return ".NET Framework";
        case DotNetRuntimeType::NetCore: return ".NET Core";
        case DotNetRuntimeType::Net5Plus: return ".NET 5.0+";
        case DotNetRuntimeType::Mono: return "Mono";
        case DotNetRuntimeType::Unity: return "Unity";
        default: return "Unknown";
    }
}

std::string DotNetAnalyzer::GetArchitectureName(AssemblyArchitecture arch) {
    switch (arch) {
        case AssemblyArchitecture::MSIL: return "MSIL (AnyCPU)";
        case AssemblyArchitecture::X86: return "x86 (32-bit)";
        case AssemblyArchitecture::X64: return "x64 (64-bit)";
        case AssemblyArchitecture::ARM: return "ARM";
        case AssemblyArchitecture::ARM64: return "ARM64";
        default: return "Unknown";
    }
}

//-----------------------------------------------------------------------------
// Utility Functions
//-----------------------------------------------------------------------------

namespace DotNetUtils {

std::string FormatTypeInfo(const TypeInfo& type, bool verbose) {
    std::ostringstream oss;

    if (verbose) {
        oss << "Type: " << type.fullName << "\n";
        oss << "  Visibility: " << GetTypeVisibility(type) << "\n";
        oss << "  Kind: " << (type.IsInterface() ? "Interface" : "Class") << "\n";

        if (type.IsAbstract()) oss << "  Abstract: Yes\n";
        if (type.IsSealed()) oss << "  Sealed: Yes\n";

        if (!type.baseType.empty()) {
            oss << "  Base: " << type.baseType << "\n";
        }

        if (!type.interfaces.empty()) {
            oss << "  Interfaces: " << type.interfaces.size() << "\n";
        }

        oss << "  Methods: " << type.methods.size() << "\n";
        oss << "  Fields: " << type.fields.size() << "\n";
        oss << "  Properties: " << type.properties.size() << "\n";
    } else {
        oss << type.fullName;
    }

    return oss.str();
}

std::string FormatMethodInfo(const MethodInfo& method, bool verbose) {
    std::ostringstream oss;

    if (verbose) {
        oss << "Method: " << method.signature << "\n";
        oss << "  Declaring Type: " << method.declaringType << "\n";
        oss << "  Visibility: " << GetMethodVisibility(method) << "\n";
        oss << "  Return Type: " << method.returnType << "\n";

        if (method.IsStatic()) oss << "  Static: Yes\n";
        if (method.IsVirtual()) oss << "  Virtual: Yes\n";
        if (method.IsAbstract()) oss << "  Abstract: Yes\n";

        if (!method.parameters.empty()) {
            oss << "  Parameters: " << method.parameters.size() << "\n";
        }
    } else {
        oss << method.signature;
    }

    return oss.str();
}

std::string GetTypeVisibility(const TypeInfo& type) {
    if (type.IsPublic()) return "Public";
    if (type.IsNotPublic()) return "Internal";
    if (type.IsNestedPublic()) return "Nested Public";
    return "Unknown";
}

std::string GetMethodVisibility(const MethodInfo& method) {
    if (method.IsPublic()) return "Public";
    if (method.IsPrivate()) return "Private";
    return "Unknown";
}

bool IsSystemType(const TypeInfo& type) {
    return type.namespaceName.find("System") == 0 ||
           type.namespaceName.find("Microsoft") == 0;
}

std::string ExtractNamespace(const std::string& fullName) {
    size_t lastDot = fullName.rfind('.');
    if (lastDot != std::string::npos) {
        return fullName.substr(0, lastDot);
    }
    return "";
}

std::string ExtractTypeName(const std::string& fullName) {
    size_t lastDot = fullName.rfind('.');
    if (lastDot != std::string::npos) {
        return fullName.substr(lastDot + 1);
    }
    return fullName;
}

std::string FormatPublicKeyToken(const std::vector<uint8_t>& tokenBytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (uint8_t byte : tokenBytes) {
        oss << std::setw(2) << static_cast<int>(byte);
    }

    return oss.str();
}

std::optional<std::string> DetectObfuscator(const DotNetAnalysisResult& result) {
    // Detect common obfuscators by their characteristics

    if (result.obfuscationIndicators.size() >= 3) {
        // Multiple obfuscation indicators - likely obfuscated
        return "Unknown Obfuscator";
    }

    // Check for specific obfuscator signatures
    for (const auto& type : result.types) {
        if (type.name.find("ConfuserEx") != std::string::npos) {
            return "ConfuserEx";
        }
        if (type.name.find("SmartAssembly") != std::string::npos) {
            return "SmartAssembly";
        }
        if (type.name.find("Dotfuscator") != std::string::npos) {
            return "Dotfuscator";
        }
    }

    return std::nullopt;
}

uint32_t CalculateComplexity(const DotNetAnalysisResult& result) {
    // Simple complexity metric based on various factors
    uint32_t score = 0;

    // Type count contribution
    if (result.typeCount > 100) score += 20;
    else if (result.typeCount > 50) score += 10;
    else if (result.typeCount > 10) score += 5;

    // Method count contribution
    if (result.methodCount > 1000) score += 30;
    else if (result.methodCount > 500) score += 20;
    else if (result.methodCount > 100) score += 10;

    // IL complexity
    if (result.ilStats.totalInstructions > 10000) score += 25;
    else if (result.ilStats.totalInstructions > 5000) score += 15;
    else if (result.ilStats.totalInstructions > 1000) score += 5;

    // Exception handlers (complexity indicator)
    if (result.ilStats.exceptionHandlers > 100) score += 15;
    else if (result.ilStats.exceptionHandlers > 50) score += 10;

    // Namespace count
    if (result.namespaces.size() > 20) score += 10;
    else if (result.namespaces.size() > 10) score += 5;

    return std::min(score, 100u);
}

bool IsLikelyPacked(const DotNetAnalysisResult& result) {
    // Check for packing/protection indicators
    return !result.obfuscationIndicators.empty() ||
           result.ilStats.methodCount < result.typeCount ||  // Suspiciously few methods
           (result.methodCount == 0 && result.isManagedAssembly);  // No methods found
}

} // namespace DotNetUtils

} // namespace dotnet
} // namespace scylla
