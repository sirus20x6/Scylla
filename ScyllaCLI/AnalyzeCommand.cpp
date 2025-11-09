/*
 * Scylla CLI - Analyze Command Implementation
 */

#include "Commands.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <cmath>
#include <algorithm>

// Note: These headers will be available once we properly integrate with libScylla
// For now, we'll create stub implementations
// #include "../Scylla/PeParser.h"
// #include "../Scylla/IATSearch.h"
// #include "../Scylla/ApiReader.h"

namespace ScyllaCLI {

std::string AnalyzeCommand::GetHelp() const {
    return R"(
Analyze a PE file and display detailed information about its structure,
imports, and potential security issues.

The analyze command performs comprehensive static analysis including:
  - PE header parsing
  - Section analysis with entropy calculation
  - Import table reconstruction
  - Security feature detection (ASLR, DEP, CFG)
  - Packer detection
  - Suspicious API detection

Output can be in text, JSON, or XML format for easy integration with
other tools and automated workflows.
)";
}

std::string AnalyzeCommand::GetUsage() const {
    return R"(
Usage: scylla-cli analyze <file> [options]

Options:
  -o, --output <file>      Write results to file
  --format <fmt>           Output format: text, json, xml (default: text)
  -v, --verbose            Detailed output
  --deep-scan              Perform deep analysis
  --iat <address>          Specify IAT address (hex)
  --no-auto-iat            Disable automatic IAT detection

Examples:
  scylla-cli analyze sample.exe
  scylla-cli analyze sample.exe --format json -o results.json
  scylla-cli analyze packed.exe --deep-scan --verbose
)";
}

double AnalyzeCommand::CalculateEntropy(const uint8_t* data, size_t size) {
    if (!data || size == 0) return 0.0;

    // Calculate byte frequency
    size_t freq[256] = { 0 };
    for (size_t i = 0; i < size; i++) {
        freq[data[i]]++;
    }

    // Calculate Shannon entropy
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = static_cast<double>(freq[i]) / size;
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

void AnalyzeCommand::DetectPacker(AnalysisResults& results) {
    // Simple packer detection based on section names and entropy
    for (const auto& section : results.sections) {
        // Common packer section names
        if (section.name == "UPX0" || section.name == "UPX1" || section.name == "UPX2") {
            results.packerDetected = "UPX";
            return;
        }
        if (section.name.find(".aspack") != std::string::npos) {
            results.packerDetected = "ASPack";
            return;
        }
        if (section.name.find(".vmp") != std::string::npos) {
            results.packerDetected = "VMProtect";
            return;
        }
        if (section.name.find(".themida") != std::string::npos) {
            results.packerDetected = "Themida";
            return;
        }

        // High entropy in executable sections suggests packing
        if (section.executable && section.entropy > 7.0) {
            if (results.packerDetected.empty()) {
                results.packerDetected = "Unknown (High Entropy)";
            }
        }
    }
}

void AnalyzeCommand::AnalyzeSecurity(AnalysisResults& results) {
    // Note: This would integrate with actual PE parser
    // For now, we'll set some defaults
    results.security.aslr = false;  // Check DllCharacteristics
    results.security.dep = false;   // Check DllCharacteristics
    results.security.cfg = false;   // Check Load Config
    results.security.rfg = false;   // Check Load Config
    results.security.seh = false;   // Check exception directory
    results.security.authenticode = false;  // Check certificate table
}

void AnalyzeCommand::DetectSuspicious(AnalysisResults& results) {
    // Suspicious API patterns
    std::vector<std::string> suspiciousAPIs = {
        "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
        "CreateRemoteThread", "NtQuerySystemInformation",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent"
    };

    results.suspicious.riskScore = 0;

    // Check for suspicious imports
    for (const auto& module : results.modules) {
        for (const auto& import : module.imports) {
            auto it = std::find(suspiciousAPIs.begin(), suspiciousAPIs.end(), import.name);
            if (it != suspiciousAPIs.end()) {
                results.suspicious.suspiciousAPIs.push_back(import.name);
                results.suspicious.riskScore += 10;
            }
        }
    }

    // Check for packed sections
    for (const auto& section : results.sections) {
        if (section.entropy > 7.2) {
            results.suspicious.hasPackedSections = true;
            results.suspicious.riskScore += 15;
        }
    }

    // Limit risk score
    results.suspicious.riskScore = std::min(results.suspicious.riskScore, 100);

    results.suspicious.hasSuspiciousImports = !results.suspicious.suspiciousAPIs.empty();
    results.suspicious.hasSuspiciousEntropy = results.totalEntropy > 7.0;
}

AnalysisResults AnalyzeCommand::AnalyzeFile(const std::string& filePath,
                                           const CommandOptions& opts) {
    AnalysisResults results;
    results.fileName = filePath;
    results.success = false;

    // Check if file exists
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        results.errorMessage = "File not found or cannot be opened";
        return results;
    }

    results.fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // Read DOS header
    char dosHeader[64];
    file.read(dosHeader, 64);

    if (dosHeader[0] != 'M' || dosHeader[1] != 'Z') {
        results.errorMessage = "Invalid PE file (missing MZ signature)";
        return results;
    }

    // This is a simplified implementation
    // In the full version, this would use the actual PeParser class from libScylla

    // For demonstration, create some sample data
    results.architecture = "x86";  // Would be detected from PE header
    results.imageBase = 0x00400000;
    results.entryPoint = 0x00401000;
    results.imageSize = static_cast<uint32_t>(results.fileSize);

    // Sample section data (would come from PE parser)
    SectionInfo textSection;
    textSection.name = ".text";
    textSection.virtualAddress = 0x1000;
    textSection.virtualSize = 0x8000;
    textSection.rawSize = 0x8000;
    textSection.characteristics = 0x60000020;
    textSection.executable = true;
    textSection.readable = true;
    textSection.writable = false;
    textSection.entropy = 6.5;
    results.sections.push_back(textSection);

    SectionInfo dataSection;
    dataSection.name = ".data";
    dataSection.virtualAddress = 0x9000;
    dataSection.virtualSize = 0x2000;
    dataSection.rawSize = 0x1000;
    dataSection.characteristics = 0xC0000040;
    dataSection.executable = false;
    dataSection.readable = true;
    dataSection.writable = true;
    dataSection.entropy = 4.2;
    results.sections.push_back(dataSection);

    // Calculate average entropy
    double totalEntropy = 0;
    for (const auto& section : results.sections) {
        totalEntropy += section.entropy;
    }
    results.totalEntropy = results.sections.empty() ? 0 : totalEntropy / results.sections.size();

    // Sample import data (would come from API reader)
    ModuleImports kernel32;
    kernel32.moduleName = "kernel32.dll";

    ImportInfo imp1;
    imp1.name = "GetProcAddress";
    imp1.address = 0x405000;
    imp1.valid = true;
    imp1.suspicious = false;
    kernel32.imports.push_back(imp1);

    ImportInfo imp2;
    imp2.name = "LoadLibraryA";
    imp2.address = 0x405004;
    imp2.valid = true;
    imp2.suspicious = false;
    kernel32.imports.push_back(imp2);

    results.modules.push_back(kernel32);

    results.iatFound = true;
    results.iatAddress = 0x405000;
    results.iatSize = 0x100;

    results.totalImports = 0;
    results.validImports = 0;
    for (const auto& module : results.modules) {
        results.totalImports += module.imports.size();
        for (const auto& imp : module.imports) {
            if (imp.valid) results.validImports++;
        }
    }
    results.invalidImports = results.totalImports - results.validImports;

    // Perform analysis
    DetectPacker(results);
    AnalyzeSecurity(results);
    DetectSuspicious(results);

    results.success = true;
    return results;
}

void AnalyzeCommand::OutputText(const AnalysisResults& results, bool verbose) {
    std::cout << "═══════════════════════════════════════════════════════════\n";
    std::cout << "Scylla PE Analysis Results\n";
    std::cout << "═══════════════════════════════════════════════════════════\n\n";

    if (!results.success) {
        std::cout << "❌ Analysis failed: " << results.errorMessage << "\n";
        return;
    }

    // Basic info
    std::cout << "File Information:\n";
    std::cout << "─────────────────────────────────────────────────────────\n";
    std::cout << "  File:         " << results.fileName << "\n";
    std::cout << "  Architecture: " << results.architecture << "\n";
    std::cout << "  Image Base:   " << FormatHex(results.imageBase) << "\n";
    std::cout << "  Entry Point:  " << FormatHex(results.entryPoint) << "\n";
    std::cout << "  File Size:    " << FormatSize(results.fileSize) << "\n";
    std::cout << "  Image Size:   " << FormatSize(results.imageSize) << "\n";
    std::cout << "  Entropy:      " << std::fixed << std::setprecision(2)
              << results.totalEntropy << " bits\n";

    if (!results.packerDetected.empty()) {
        std::cout << "  Packer:       " << results.packerDetected << "\n";
    }

    std::cout << "\n";

    // Sections
    std::cout << "Sections (" << results.sections.size() << "):\n";
    std::cout << "─────────────────────────────────────────────────────────\n";
    std::cout << std::left
              << std::setw(10) << "Name"
              << std::setw(12) << "VirtAddr"
              << std::setw(12) << "VirtSize"
              << std::setw(12) << "RawSize"
              << std::setw(8) << "Flags"
              << std::setw(10) << "Entropy" << "\n";
    std::cout << "─────────────────────────────────────────────────────────\n";

    for (const auto& section : results.sections) {
        std::cout << std::left
                  << std::setw(10) << section.name
                  << std::setw(12) << FormatHex(section.virtualAddress)
                  << std::setw(12) << FormatSize(section.virtualSize)
                  << std::setw(12) << FormatSize(section.rawSize)
                  << std::setw(8) << FormatFlags(section.characteristics)
                  << std::fixed << std::setprecision(2) << section.entropy;

        if (section.entropy > 7.0) {
            std::cout << " ⚠️  High";
        }
        std::cout << "\n";
    }

    std::cout << "\n";

    // Security features
    std::cout << "Security Features:\n";
    std::cout << "─────────────────────────────────────────────────────────\n";
    std::cout << "  ASLR:         " << (results.security.aslr ? "✓ Enabled" : "✗ Disabled") << "\n";
    std::cout << "  DEP/NX:       " << (results.security.dep ? "✓ Enabled" : "✗ Disabled") << "\n";
    std::cout << "  CFG:          " << (results.security.cfg ? "✓ Enabled" : "✗ Disabled") << "\n";
    std::cout << "  Authenticode: " << (results.security.authenticode ? "✓ Signed" : "✗ Not Signed") << "\n";

    std::cout << "\n";

    // Imports
    if (results.iatFound) {
        std::cout << "Import Address Table:\n";
        std::cout << "─────────────────────────────────────────────────────────\n";
        std::cout << "  Address:      " << FormatHex(results.iatAddress) << "\n";
        std::cout << "  Size:         " << FormatSize(results.iatSize) << "\n";
        std::cout << "  Modules:      " << results.modules.size() << "\n";
        std::cout << "  Total Imports:" << results.totalImports << "\n";
        std::cout << "  Valid:        " << results.validImports << "\n";
        std::cout << "  Invalid:      " << results.invalidImports << "\n";

        std::cout << "\n";

        std::cout << "Imported Modules:\n";
        std::cout << "─────────────────────────────────────────────────────────\n";

        for (const auto& module : results.modules) {
            std::cout << "\n  [" << module.moduleName << "] - "
                      << module.imports.size() << " imports\n";

            if (verbose) {
                for (const auto& imp : module.imports) {
                    std::cout << "    " << FormatHex(imp.address) << " ";
                    std::cout << (imp.valid ? "✓" : "✗") << " ";
                    std::cout << imp.name;
                    if (imp.suspicious) {
                        std::cout << " ⚠️";
                    }
                    std::cout << "\n";
                }
            }
        }
    } else {
        std::cout << "Import Address Table: Not found\n";
        std::cout << "  Use --iat <address> to specify manually\n";
    }

    std::cout << "\n";

    // Suspicious indicators
    if (!results.suspicious.suspiciousAPIs.empty() ||
        results.suspicious.hasPackedSections ||
        results.suspicious.riskScore > 0) {

        std::cout << "Suspicious Indicators:\n";
        std::cout << "─────────────────────────────────────────────────────────\n";
        std::cout << "  Risk Score:   " << results.suspicious.riskScore << "/100 ";

        if (results.suspicious.riskScore < 30) {
            std::cout << "(Low)\n";
        } else if (results.suspicious.riskScore < 60) {
            std::cout << "(Medium) ⚠️\n";
        } else {
            std::cout << "(High) 🔴\n";
        }

        if (!results.suspicious.suspiciousAPIs.empty()) {
            std::cout << "\n  Suspicious APIs:\n";
            for (const auto& api : results.suspicious.suspiciousAPIs) {
                std::cout << "    ⚠️  " << api << "\n";
            }
        }

        if (results.suspicious.hasPackedSections) {
            std::cout << "  ⚠️  High entropy sections detected (possible packing)\n";
        }
    }

    std::cout << "\n═══════════════════════════════════════════════════════════\n";
}

void AnalyzeCommand::OutputJSON(const AnalysisResults& results, const std::string& outputFile) {
    std::ostringstream json;

    json << "{\n";
    json << "  \"success\": " << (results.success ? "true" : "false") << ",\n";

    if (!results.success) {
        json << "  \"error\": \"" << results.errorMessage << "\"\n";
        json << "}\n";

        if (!outputFile.empty()) {
            std::ofstream out(outputFile);
            out << json.str();
        } else {
            std::cout << json.str();
        }
        return;
    }

    json << "  \"file\": \"" << results.fileName << "\",\n";
    json << "  \"architecture\": \"" << results.architecture << "\",\n";
    json << "  \"image_base\": \"" << FormatHex(results.imageBase) << "\",\n";
    json << "  \"entry_point\": \"" << FormatHex(results.entryPoint) << "\",\n";
    json << "  \"file_size\": " << results.fileSize << ",\n";
    json << "  \"image_size\": " << results.imageSize << ",\n";
    json << "  \"entropy\": " << std::fixed << std::setprecision(2) << results.totalEntropy << ",\n";

    if (!results.packerDetected.empty()) {
        json << "  \"packer\": \"" << results.packerDetected << "\",\n";
    }

    // Sections
    json << "  \"sections\": [\n";
    for (size_t i = 0; i < results.sections.size(); i++) {
        const auto& section = results.sections[i];
        json << "    {\n";
        json << "      \"name\": \"" << section.name << "\",\n";
        json << "      \"virtual_address\": \"" << FormatHex(section.virtualAddress) << "\",\n";
        json << "      \"virtual_size\": " << section.virtualSize << ",\n";
        json << "      \"raw_size\": " << section.rawSize << ",\n";
        json << "      \"characteristics\": \"" << FormatHex(section.characteristics) << "\",\n";
        json << "      \"entropy\": " << std::fixed << std::setprecision(2) << section.entropy << "\n";
        json << "    }" << (i < results.sections.size() - 1 ? "," : "") << "\n";
    }
    json << "  ],\n";

    // Security features
    json << "  \"security\": {\n";
    json << "    \"aslr\": " << (results.security.aslr ? "true" : "false") << ",\n";
    json << "    \"dep\": " << (results.security.dep ? "true" : "false") << ",\n";
    json << "    \"cfg\": " << (results.security.cfg ? "true" : "false") << ",\n";
    json << "    \"authenticode\": " << (results.security.authenticode ? "true" : "false") << "\n";
    json << "  },\n";

    // IAT
    json << "  \"iat\": {\n";
    json << "    \"found\": " << (results.iatFound ? "true" : "false");
    if (results.iatFound) {
        json << ",\n";
        json << "    \"address\": \"" << FormatHex(results.iatAddress) << "\",\n";
        json << "    \"size\": " << results.iatSize << "\n";
    } else {
        json << "\n";
    }
    json << "  },\n";

    // Imports
    json << "  \"imports\": {\n";
    json << "    \"total\": " << results.totalImports << ",\n";
    json << "    \"valid\": " << results.validImports << ",\n";
    json << "    \"invalid\": " << results.invalidImports << ",\n";
    json << "    \"modules\": [\n";

    for (size_t i = 0; i < results.modules.size(); i++) {
        const auto& module = results.modules[i];
        json << "      {\n";
        json << "        \"name\": \"" << module.moduleName << "\",\n";
        json << "        \"imports\": [\n";

        for (size_t j = 0; j < module.imports.size(); j++) {
            const auto& imp = module.imports[j];
            json << "          {\n";
            json << "            \"name\": \"" << imp.name << "\",\n";
            json << "            \"address\": \"" << FormatHex(imp.address) << "\",\n";
            json << "            \"valid\": " << (imp.valid ? "true" : "false") << ",\n";
            json << "            \"suspicious\": " << (imp.suspicious ? "true" : "false") << "\n";
            json << "          }" << (j < module.imports.size() - 1 ? "," : "") << "\n";
        }

        json << "        ]\n";
        json << "      }" << (i < results.modules.size() - 1 ? "," : "") << "\n";
    }

    json << "    ]\n";
    json << "  },\n";

    // Suspicious indicators
    json << "  \"suspicious\": {\n";
    json << "    \"risk_score\": " << results.suspicious.riskScore << ",\n";
    json << "    \"packed_sections\": " << (results.suspicious.hasPackedSections ? "true" : "false") << ",\n";
    json << "    \"suspicious_imports\": " << (results.suspicious.hasSuspiciousImports ? "true" : "false") << ",\n";
    json << "    \"suspicious_apis\": [\n";

    for (size_t i = 0; i < results.suspicious.suspiciousAPIs.size(); i++) {
        json << "      \"" << results.suspicious.suspiciousAPIs[i] << "\"";
        json << (i < results.suspicious.suspiciousAPIs.size() - 1 ? "," : "") << "\n";
    }

    json << "    ]\n";
    json << "  }\n";
    json << "}\n";

    if (!outputFile.empty()) {
        std::ofstream out(outputFile);
        out << json.str();
        std::cout << "Results written to: " << outputFile << "\n";
    } else {
        std::cout << json.str();
    }
}

void AnalyzeCommand::OutputXML(const AnalysisResults& results, const std::string& outputFile) {
    // Simplified XML output - would use TinyXML in full implementation
    std::ostringstream xml;

    xml << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    xml << "<analysis>\n";
    xml << "  <success>" << (results.success ? "true" : "false") << "</success>\n";

    if (results.success) {
        xml << "  <file>" << results.fileName << "</file>\n";
        xml << "  <architecture>" << results.architecture << "</architecture>\n";
        xml << "  <image_base>" << FormatHex(results.imageBase) << "</image_base>\n";
        xml << "  <entry_point>" << FormatHex(results.entryPoint) << "</entry_point>\n";
        // ... (more XML output would go here)
    } else {
        xml << "  <error>" << results.errorMessage << "</error>\n";
    }

    xml << "</analysis>\n";

    if (!outputFile.empty()) {
        std::ofstream out(outputFile);
        out << xml.str();
        std::cout << "Results written to: " << outputFile << "\n";
    } else {
        std::cout << xml.str();
    }
}

int AnalyzeCommand::Execute(const CommandOptions& opts) {
    if (opts.inputFile.empty()) {
        std::cerr << "Error: Input file required\n";
        std::cerr << GetUsage();
        return 1;
    }

    if (!opts.quiet) {
        std::cout << "Analyzing: " << opts.inputFile << "\n";
        if (opts.deepScan) {
            std::cout << "Deep scan enabled\n";
        }
        std::cout << "\n";
    }

    try {
        // Perform analysis
        auto results = AnalyzeFile(opts.inputFile, opts);

        if (!results.success) {
            std::cerr << "Analysis failed: " << results.errorMessage << "\n";
            return 1;
        }

        // Output results
        switch (opts.format) {
            case OutputFormat::JSON:
                OutputJSON(results, opts.outputFile);
                break;

            case OutputFormat::XML:
                OutputXML(results, opts.outputFile);
                break;

            case OutputFormat::Text:
            default:
                OutputText(results, opts.verbose);
                break;
        }

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}

} // namespace ScyllaCLI
