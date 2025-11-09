#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <filesystem>
#include <optional>
#include <cstdint>

namespace scylla {
namespace dotnet {

/**
 * .NET runtime type
 */
enum class DotNetRuntimeType {
    Unknown,
    NetFramework,    // .NET Framework (1.0 - 4.8)
    NetCore,         // .NET Core (1.0 - 3.1)
    Net5Plus,        // .NET 5.0+
    Mono,            // Mono runtime
    Unity            // Unity runtime
};

/**
 * Assembly architecture
 */
enum class AssemblyArchitecture {
    MSIL,            // Platform-agnostic (AnyCPU)
    X86,             // 32-bit x86
    X64,             // 64-bit x64
    ARM,             // ARM
    ARM64            // 64-bit ARM
};

/**
 * .NET framework version information
 */
struct DotNetVersion {
    uint16_t major = 0;
    uint16_t minor = 0;
    uint16_t build = 0;
    uint16_t revision = 0;

    std::string ToString() const;
    bool operator<(const DotNetVersion& other) const;
    bool operator==(const DotNetVersion& other) const;
};

/**
 * CLR header information (COM+ header)
 */
struct CLRHeader {
    uint32_t headerSize = 0;
    uint16_t majorRuntimeVersion = 0;
    uint16_t minorRuntimeVersion = 0;
    uint32_t metadataRVA = 0;
    uint32_t metadataSize = 0;
    uint32_t flags = 0;
    uint32_t entryPointToken = 0;
    uint32_t resourcesRVA = 0;
    uint32_t resourcesSize = 0;
    uint32_t strongNameSignatureRVA = 0;
    uint32_t strongNameSignatureSize = 0;

    // Flags
    bool IsILOnly() const { return (flags & 0x00000001) != 0; }
    bool Requires32Bit() const { return (flags & 0x00000002) != 0; }
    bool IsSigned() const { return (flags & 0x00000008) != 0; }
    bool IsNativeEntryPoint() const { return (flags & 0x00000010) != 0; }
};

/**
 * .NET type information
 */
struct TypeInfo {
    std::string name;                    // Type name
    std::string namespaceName;           // Namespace
    std::string fullName;                // Fully qualified name
    std::string baseType;                // Base class name
    uint32_t token = 0;                  // Metadata token
    uint32_t flags = 0;                  // Type attributes

    std::vector<std::string> interfaces; // Implemented interfaces
    std::vector<std::string> fields;     // Field names
    std::vector<std::string> methods;    // Method names
    std::vector<std::string> properties; // Property names
    std::vector<std::string> events;     // Event names

    // Type attributes
    bool IsPublic() const { return (flags & 0x00000007) == 0x00000001; }
    bool IsNotPublic() const { return (flags & 0x00000007) == 0x00000000; }
    bool IsNestedPublic() const { return (flags & 0x00000007) == 0x00000002; }
    bool IsClass() const { return (flags & 0x00000020) == 0; }
    bool IsInterface() const { return (flags & 0x00000020) != 0; }
    bool IsAbstract() const { return (flags & 0x00000080) != 0; }
    bool IsSealed() const { return (flags & 0x00000100) != 0; }
    bool IsValueType() const { return (flags & 0x00000400) != 0; }
};

/**
 * .NET method information
 */
struct MethodInfo {
    std::string name;                    // Method name
    std::string declaringType;           // Type that declares this method
    std::string signature;               // Method signature
    std::string returnType;              // Return type
    uint32_t token = 0;                  // Metadata token
    uint32_t flags = 0;                  // Method attributes
    uint32_t implFlags = 0;              // Implementation flags
    uint32_t rva = 0;                    // RVA of IL code

    std::vector<std::string> parameters; // Parameter types

    // Method attributes
    bool IsPublic() const { return (flags & 0x0007) == 0x0006; }
    bool IsPrivate() const { return (flags & 0x0007) == 0x0001; }
    bool IsStatic() const { return (flags & 0x0010) != 0; }
    bool IsVirtual() const { return (flags & 0x0040) != 0; }
    bool IsAbstract() const { return (flags & 0x0400) != 0; }
    bool IsFinal() const { return (flags & 0x0020) != 0; }
};

/**
 * .NET assembly reference
 */
struct AssemblyReference {
    std::string name;                    // Assembly name
    DotNetVersion version;               // Version
    std::string publicKeyToken;          // Public key token
    std::string culture;                 // Culture/locale
};

/**
 * .NET assembly information
 */
struct AssemblyInfo {
    std::string name;                    // Assembly name
    DotNetVersion version;               // Assembly version
    std::string culture;                 // Culture
    std::string publicKey;               // Public key (if signed)
    std::string publicKeyToken;          // Public key token
    uint32_t flags = 0;                  // Assembly flags

    std::vector<AssemblyReference> references;  // Referenced assemblies

    bool IsSigned() const { return !publicKey.empty(); }
    bool IsRetargetable() const { return (flags & 0x0100) != 0; }
};

/**
 * IL opcode statistics
 */
struct ILStatistics {
    uint32_t totalInstructions = 0;
    uint32_t methodCount = 0;
    uint32_t callInstructions = 0;
    uint32_t newObjInstructions = 0;
    uint32_t loadFieldInstructions = 0;
    uint32_t storeFieldInstructions = 0;
    uint32_t branchInstructions = 0;
    uint32_t exceptionHandlers = 0;

    std::map<std::string, uint32_t> opcodeFrequency;  // Opcode -> count
};

/**
 * .NET analysis result
 */
struct DotNetAnalysisResult {
    bool isManagedAssembly = false;      // Is this a .NET assembly?
    DotNetRuntimeType runtimeType = DotNetRuntimeType::Unknown;
    AssemblyArchitecture architecture = AssemblyArchitecture::MSIL;
    CLRHeader clrHeader;
    AssemblyInfo assemblyInfo;
    DotNetVersion targetFramework;       // Target framework version

    std::vector<TypeInfo> types;         // All types
    std::vector<MethodInfo> methods;     // All methods
    std::vector<std::string> namespaces; // All namespaces
    std::vector<std::string> resources;  // Embedded resources

    ILStatistics ilStats;                // IL code statistics

    // Analysis metadata
    uint32_t typeCount = 0;
    uint32_t methodCount = 0;
    uint32_t fieldCount = 0;
    uint32_t propertyCount = 0;
    uint32_t eventCount = 0;

    std::vector<std::string> securityIssues;     // Security concerns
    std::vector<std::string> obfuscationIndicators;  // Obfuscation signs
};

/**
 * .NET Analyzer - Managed code analysis
 *
 * Features:
 * - CLR header parsing
 * - Metadata table extraction
 * - Type and method discovery
 * - Assembly reference analysis
 * - IL code analysis
 * - Framework version detection
 * - Obfuscation detection
 *
 * Supports:
 * - .NET Framework 1.0 - 4.8
 * - .NET Core 1.0 - 3.1
 * - .NET 5.0+
 * - Mixed-mode assemblies (native + managed)
 */
class DotNetAnalyzer {
public:
    DotNetAnalyzer();
    ~DotNetAnalyzer();

    /**
     * Analyze .NET assembly
     *
     * @param filePath Path to PE file
     * @return Analysis results
     */
    DotNetAnalysisResult Analyze(const std::filesystem::path& filePath);

    /**
     * Check if file is a .NET assembly
     *
     * @param filePath Path to PE file
     * @return true if .NET assembly
     */
    static bool IsManagedAssembly(const std::filesystem::path& filePath);

    /**
     * Extract CLR header
     *
     * @param filePath Path to PE file
     * @return CLR header if found
     */
    static std::optional<CLRHeader> ExtractCLRHeader(const std::filesystem::path& filePath);

    /**
     * Get target framework version
     *
     * @param filePath Path to assembly
     * @return Framework version if detected
     */
    static std::optional<DotNetVersion> DetectTargetFramework(const std::filesystem::path& filePath);

    /**
     * Detect .NET runtime type
     *
     * @param filePath Path to assembly
     * @return Runtime type
     */
    static DotNetRuntimeType DetectRuntimeType(const std::filesystem::path& filePath);

    /**
     * Extract assembly information
     *
     * @param filePath Path to assembly
     * @return Assembly info
     */
    AssemblyInfo ExtractAssemblyInfo(const std::filesystem::path& filePath);

    /**
     * Extract all types from assembly
     *
     * @param filePath Path to assembly
     * @return List of types
     */
    std::vector<TypeInfo> ExtractTypes(const std::filesystem::path& filePath);

    /**
     * Extract all methods from assembly
     *
     * @param filePath Path to assembly
     * @return List of methods
     */
    std::vector<MethodInfo> ExtractMethods(const std::filesystem::path& filePath);

    /**
     * Analyze IL code
     *
     * @param filePath Path to assembly
     * @return IL statistics
     */
    ILStatistics AnalyzeIL(const std::filesystem::path& filePath);

    /**
     * Detect obfuscation
     *
     * @param result Analysis result
     * @return List of obfuscation indicators
     */
    static std::vector<std::string> DetectObfuscation(const DotNetAnalysisResult& result);

    /**
     * Check for security issues
     *
     * @param result Analysis result
     * @return List of security concerns
     */
    static std::vector<std::string> CheckSecurityIssues(const DotNetAnalysisResult& result);

    /**
     * Format version as string
     *
     * @param version Version structure
     * @return Formatted string (e.g., "4.8.0.0")
     */
    static std::string FormatVersion(const DotNetVersion& version);

    /**
     * Parse version from string
     *
     * @param versionStr Version string
     * @return Version structure
     */
    static DotNetVersion ParseVersion(const std::string& versionStr);

    /**
     * Get runtime name
     *
     * @param runtime Runtime type
     * @return Human-readable name
     */
    static std::string GetRuntimeName(DotNetRuntimeType runtime);

    /**
     * Get architecture name
     *
     * @param arch Architecture type
     * @return Human-readable name
     */
    static std::string GetArchitectureName(AssemblyArchitecture arch);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;

    // Internal methods
    CLRHeader ParseCLRHeader(const uint8_t* data, size_t size, uint32_t rva);
    AssemblyInfo ParseMetadata(const uint8_t* data, size_t size);
    std::vector<TypeInfo> ParseTypeDefs(const uint8_t* data, size_t size);
    std::vector<MethodInfo> ParseMethodDefs(const uint8_t* data, size_t size);
    std::vector<AssemblyReference> ParseAssemblyRefs(const uint8_t* data, size_t size);
    ILStatistics AnalyzeILCode(const uint8_t* data, size_t size, const std::vector<MethodInfo>& methods);

    // Metadata helpers
    std::string ReadString(const uint8_t* data, uint32_t offset) const;
    std::string ReadBlob(const uint8_t* data, uint32_t offset) const;
    uint32_t DecodeToken(uint32_t encoded) const;
};

/**
 * Utility functions for .NET analysis
 */
namespace DotNetUtils {
    /**
     * Format type info as string
     *
     * @param type Type information
     * @param verbose Include detailed info
     * @return Formatted string
     */
    std::string FormatTypeInfo(const TypeInfo& type, bool verbose = false);

    /**
     * Format method info as string
     *
     * @param method Method information
     * @param verbose Include detailed info
     * @return Formatted string
     */
    std::string FormatMethodInfo(const MethodInfo& method, bool verbose = false);

    /**
     * Get type visibility name
     *
     * @param type Type information
     * @return Visibility string (Public, Private, etc.)
     */
    std::string GetTypeVisibility(const TypeInfo& type);

    /**
     * Get method visibility name
     *
     * @param method Method information
     * @return Visibility string
     */
    std::string GetMethodVisibility(const MethodInfo& method);

    /**
     * Check if type is from standard library
     *
     * @param type Type information
     * @return true if from BCL (Base Class Library)
     */
    bool IsSystemType(const TypeInfo& type);

    /**
     * Extract namespace from full type name
     *
     * @param fullName Fully qualified type name
     * @return Namespace
     */
    std::string ExtractNamespace(const std::string& fullName);

    /**
     * Extract simple type name from full name
     *
     * @param fullName Fully qualified type name
     * @return Simple name
     */
    std::string ExtractTypeName(const std::string& fullName);

    /**
     * Format public key token
     *
     * @param tokenBytes Token bytes
     * @return Hexadecimal string
     */
    std::string FormatPublicKeyToken(const std::vector<uint8_t>& tokenBytes);

    /**
     * Detect obfuscator from characteristics
     *
     * @param result Analysis result
     * @return Obfuscator name if detected
     */
    std::optional<std::string> DetectObfuscator(const DotNetAnalysisResult& result);

    /**
     * Calculate assembly complexity score
     *
     * @param result Analysis result
     * @return Complexity score (0-100)
     */
    uint32_t CalculateComplexity(const DotNetAnalysisResult& result);

    /**
     * Check if assembly is likely packed/protected
     *
     * @param result Analysis result
     * @return true if indicators of packing found
     */
    bool IsLikelyPacked(const DotNetAnalysisResult& result);
}

} // namespace dotnet
} // namespace scylla
