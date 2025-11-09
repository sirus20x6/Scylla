/*
 * Scylla CLI - Command Definitions
 *
 * Enhanced command-line interface for Scylla
 */

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <cstdint>

namespace ScyllaCLI {

// Command types
enum class CommandType {
    None,
    Info,
    Analyze,
    Dump,
    Rebuild,
    Batch,
    Plugin
};

// Output format types
enum class OutputFormat {
    Text,
    JSON,
    XML,
    CSV
};

// Command options structure
struct CommandOptions {
    std::string inputFile;
    std::string outputFile;
    std::string inputDirectory;
    std::string outputDirectory;

    uint64_t iatAddress = 0;
    uint32_t iatSize = 0;
    uint32_t pid = 0;
    uint64_t entryPoint = 0;

    bool autoDetectIAT = true;
    bool fixOEP = false;
    bool fixImports = true;
    bool verbose = false;
    bool quiet = false;
    bool force = false;

    OutputFormat format = OutputFormat::Text;

    // Analysis options
    bool deepScan = false;
    bool scanAllSections = false;
    int iatSearchDepth = 3;

    // Dump options
    bool dumpAll = false;
    bool rebuildPE = true;

    // Batch options
    bool recursive = false;
    int maxThreads = 4;
};

// Analysis results structures
struct ImportInfo {
    std::string name;
    uint16_t ordinal;
    uint64_t address;
    uint64_t thunk;
    bool valid;
    bool suspicious;
};

struct ModuleImports {
    std::string moduleName;
    std::vector<ImportInfo> imports;
};

struct SectionInfo {
    std::string name;
    uint64_t virtualAddress;
    uint32_t virtualSize;
    uint32_t rawSize;
    uint32_t characteristics;
    double entropy;
    bool executable;
    bool writable;
    bool readable;
};

struct SecurityFeatures {
    bool aslr;
    bool dep;
    bool cfg;
    bool rfg;
    bool seh;
    bool authenticode;
    std::string signer;
};

struct SuspiciousIndicators {
    std::vector<std::string> suspiciousAPIs;
    std::vector<std::string> suspiciousPatterns;
    bool hasPackedSections;
    bool hasSuspiciousImports;
    bool hasSuspiciousEntropy;
    int riskScore;  // 0-100
};

struct AnalysisResults {
    std::string fileName;
    std::string architecture;
    uint64_t imageBase;
    uint64_t entryPoint;
    uint32_t fileSize;
    uint32_t imageSize;

    bool iatFound;
    uint64_t iatAddress;
    uint32_t iatSize;

    std::vector<SectionInfo> sections;
    std::vector<ModuleImports> modules;

    SecurityFeatures security;
    SuspiciousIndicators suspicious;

    std::string packerDetected;
    std::string compilerDetected;

    double totalEntropy;

    int totalImports;
    int validImports;
    int invalidImports;

    bool success;
    std::string errorMessage;
};

// Base command handler interface
class ICommandHandler {
public:
    virtual ~ICommandHandler() = default;
    virtual int Execute(const CommandOptions& opts) = 0;
    virtual std::string GetHelp() const = 0;
    virtual std::string GetUsage() const = 0;
};

// Command implementations
class InfoCommand : public ICommandHandler {
public:
    int Execute(const CommandOptions& opts) override;
    std::string GetHelp() const override;
    std::string GetUsage() const override;
};

class AnalyzeCommand : public ICommandHandler {
public:
    int Execute(const CommandOptions& opts) override;
    std::string GetHelp() const override;
    std::string GetUsage() const override;

private:
    void OutputText(const AnalysisResults& results, bool verbose);
    void OutputJSON(const AnalysisResults& results, const std::string& outputFile);
    void OutputXML(const AnalysisResults& results, const std::string& outputFile);

    AnalysisResults AnalyzeFile(const std::string& filePath, const CommandOptions& opts);
    void DetectPacker(AnalysisResults& results);
    void AnalyzeSecurity(AnalysisResults& results);
    void DetectSuspicious(AnalysisResults& results);
    double CalculateEntropy(const uint8_t* data, size_t size);
};

class DumpCommand : public ICommandHandler {
public:
    int Execute(const CommandOptions& opts) override;
    std::string GetHelp() const override;
    std::string GetUsage() const override;
};

class RebuildCommand : public ICommandHandler {
public:
    int Execute(const CommandOptions& opts) override;
    std::string GetHelp() const override;
    std::string GetUsage() const override;
};

class BatchCommand : public ICommandHandler {
public:
    int Execute(const CommandOptions& opts) override;
    std::string GetHelp() const override;
    std::string GetUsage() const override;

private:
    std::vector<std::string> FindPEFiles(const std::string& directory, bool recursive);
};

// Utility functions
std::string FormatHex(uint64_t value);
std::string FormatSize(uint64_t bytes);
std::string FormatFlags(uint32_t flags);
std::string WStringToString(const std::wstring& wstr);
std::wstring StringToWString(const std::string& str);

// Progress indicator
class ProgressBar {
public:
    ProgressBar(size_t total, const std::string& prefix = "");
    void Update(size_t current);
    void Complete();

private:
    size_t m_total;
    size_t m_current;
    std::string m_prefix;
    bool m_completed;
};

} // namespace ScyllaCLI
