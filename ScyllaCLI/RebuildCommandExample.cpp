/*
 * Rebuild Command Usage Examples
 */

#include "RebuildCommand.h"
#include <iostream>

using namespace Scylla::CLI;

void QuickRebuildExample() {
    std::cout << "=== Quick Rebuild Example ===\n\n";

    RebuildCommand rebuilder;

    // Quick rebuild with auto-detection
    auto result = rebuilder.QuickRebuild("dumped.exe", "fixed.exe");

    if (result.success) {
        std::cout << "✓ Rebuild successful!\n";
        std::cout << "  Output: " << result.outputFile << "\n";
        std::cout << "  Imports resolved: " << result.importsResolved << "/"
                  << result.importsFound << "\n";
        std::cout << "  Unresolved: " << result.importsUnresolved << "\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

void CustomRebuildExample() {
    std::cout << "=== Custom Rebuild Example ===\n\n";

    RebuildCommand rebuilder;

    // Configure rebuild
    RebuildConfig config = {};
    config.inputFile = "packed_dump.exe";
    config.outputFile = "unpacked_fixed.exe";

    // IAT settings
    config.autoDetectIAT = true;  // Auto-detect IAT location

    // Rebuild options
    config.rebuildImportDirectory = true;
    config.resolveForwarders = true;
    config.validateImports = true;
    config.fixOEP = true;
    config.oepRVA = 0x1000;  // Known OEP

    // Execute rebuild
    auto result = rebuilder.Execute(config);

    if (result.success) {
        std::cout << "✓ Complete!\n";
        std::cout << "  IAT RVA: 0x" << std::hex << result.iatRVA << std::dec << "\n";
        std::cout << "  Import Dir RVA: 0x" << std::hex << result.importDirectoryRVA << std::dec << "\n";
        std::cout << "  Modules: " << result.modulesFound << "\n";
        std::cout << "  Sections created: " << result.sectionsCreated << "\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

void AnalyzeIATExample() {
    std::cout << "=== IAT Analysis Example ===\n\n";

    RebuildCommand rebuilder;
    IATAnalyzer analyzer;

    // Scan IAT
    auto entries = rebuilder.ScanIAT("sample.exe", 0x2000, 1024);

    std::cout << "Found " << entries.size() << " IAT entries\n\n";

    // Analyze quality
    auto analysis = analyzer.Analyze(entries);

    std::cout << "IAT Analysis:\n";
    std::cout << "  Completeness: " << (analysis.completeness * 100.0) << "%\n";
    std::cout << "  Confidence: " << (analysis.confidence * 100.0) << "%\n";
    std::cout << "  Resolved: " << analysis.resolvedEntries << "\n";
    std::cout << "  Unresolved: " << analysis.unresolvedEntries << "\n";

    if (!analysis.recommendations.empty()) {
        std::cout << "\nRecommendations:\n";
        for (const auto& rec : analysis.recommendations) {
            std::cout << "  • " << rec << "\n";
        }
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

int main() {
    std::cout << "Scylla Rebuild Command Examples\n";
    std::cout << std::string(60, '=') << "\n\n";

    QuickRebuildExample();
    CustomRebuildExample();
    AnalyzeIATExample();

    return 0;
}
