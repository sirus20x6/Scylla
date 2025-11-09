/*
 * Packer Detection Examples
 *
 * Demonstrates how to use the packer detection system
 */

#include "PackerDetector.h"
#include <iostream>
#include <iomanip>
#include <fstream>

using namespace Scylla;

// Example 1: Quick Detection (Signature Only)
void QuickDetectionExample() {
    std::cout << "=== Quick Detection Example ===\n\n";

    PackerDetector detector;
    detector.Initialize();

    // Simulate PE with UPX sections
    std::vector<std::string> sections = {"UPX0", "UPX1", ".rsrc"};
    std::vector<uint8_t> entryPoint = {0x60, 0xBE, 0x00, 0x10, 0x40, 0x00};

    auto result = detector.QuickDetect(sections, entryPoint);

    std::cout << "Packed: " << (result.isPacked ? "YES" : "NO") << "\n";
    if (result.isPacked) {
        std::cout << "Packer: " << result.packerName << "\n";
        std::cout << "Confidence: " << result.confidence << "%\n";
        std::cout << "Method: " << result.detectionMethod << "\n";

        std::cout << "\nIndicators:\n";
        for (const auto& indicator : result.indicators) {
            std::cout << "  - " << indicator << "\n";
        }
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

// Example 2: Full Detection (Signature + Heuristics)
void FullDetectionExample() {
    std::cout << "=== Full Detection Example ===\n\n";

    PackerDetector detector;
    detector.Initialize();

    // Simulate packed PE file
    std::vector<uint8_t> fileData(10000);
    // Fill with high-entropy data (simulating packed code)
    for (size_t i = 0; i < fileData.size(); i++) {
        fileData[i] = static_cast<uint8_t>(rand() % 256);
    }

    std::vector<std::string> sections = {".text", ".data"};
    int importCount = 3;  // Very few imports
    std::vector<std::string> imports = {"LoadLibraryA", "GetProcAddress", "VirtualProtect"};

    auto result = detector.Detect(
        fileData.data(),
        fileData.size(),
        sections,
        importCount,
        imports
    );

    std::cout << "Analysis Results:\n";
    std::cout << "─────────────────────────────────────────────────────────\n";
    std::cout << "Packed:       " << (result.isPacked ? "YES" : "NO") << "\n";
    std::cout << "Packer:       " << result.packerName << "\n";
    std::cout << "Version:      " << result.packerVersion << "\n";
    std::cout << "Confidence:   " << result.confidence << "%\n";
    std::cout << "Method:       " << result.detectionMethod << "\n";

    if (!result.indicators.empty()) {
        std::cout << "\nDetection Indicators:\n";
        for (const auto& indicator : result.indicators) {
            std::cout << "  ⚠  " << indicator << "\n";
        }
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

// Example 3: Testing Multiple Packers
void MultiplePackersExample() {
    std::cout << "=== Testing Multiple Packers ===\n\n";

    PackerDetector detector;
    detector.Initialize();

    struct TestCase {
        std::string name;
        std::vector<std::string> sections;
        std::vector<uint8_t> entryPoint;
    };

    std::vector<TestCase> testCases = {
        {"UPX Sample", {"UPX0", "UPX1"}, {0x60, 0xBE}},
        {"VMProtect Sample", {".vmp0", ".vmp1"}, {}},
        {"Themida Sample", {".themida"}, {}},
        {"ASPack Sample", {".aspack"}, {0x60, 0xE8, 0x03}},
        {"Clean Binary", {".text", ".data", ".rdata"}, {}},
    };

    std::cout << std::left << std::setw(20) << "Sample"
              << std::setw(15) << "Detection"
              << std::setw(20) << "Packer"
              << "Confidence\n";
    std::cout << std::string(70, '─') << "\n";

    for (const auto& test : testCases) {
        auto result = detector.QuickDetect(test.sections, test.entryPoint);

        std::cout << std::left << std::setw(20) << test.name
                  << std::setw(15) << (result.isPacked ? "PACKED" : "Clean")
                  << std::setw(20) << (result.isPacked ? result.packerName : "-")
                  << result.confidence << "%\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

// Example 4: Heuristic Analysis Details
void HeuristicAnalysisExample() {
    std::cout << "=== Heuristic Analysis Example ===\n\n";

    HeuristicAnalyzer analyzer;

    // Generate high-entropy data (packed)
    std::vector<uint8_t> packedData(5000);
    for (auto& byte : packedData) {
        byte = static_cast<uint8_t>(rand() % 256);
    }

    // Generate low-entropy data (not packed)
    std::vector<uint8_t> normalData(5000, 0x00);
    for (size_t i = 0; i < 100; i++) {
        normalData[i * 50] = static_cast<uint8_t>(i);
    }

    std::vector<std::string> sections = {".text", ".data"};
    std::vector<std::string> suspiciousImports = {"LoadLibraryA", "GetProcAddress"};
    std::vector<std::string> normalImports = {
        "MessageBoxA", "CreateWindowExA", "GetModuleHandleA",
        "LoadIcon", "RegisterClassA", "ShowWindow"
    };

    // Analyze packed data
    auto packedResult = analyzer.Analyze(packedData, sections, 2, suspiciousImports);

    std::cout << "Packed Sample Analysis:\n";
    std::cout << "  Entropy:           " << std::fixed << std::setprecision(2)
              << packedResult.codeEntropy << " bits\n";
    std::cout << "  Import Count:      " << packedResult.importCount << "\n";
    std::cout << "  High Entropy:      " << (packedResult.hasHighEntropy ? "YES" : "NO") << "\n";
    std::cout << "  Few Imports:       " << (packedResult.hasFewImports ? "YES" : "NO") << "\n";
    std::cout << "  Suspicious:        " << (packedResult.hasSuspiciousImports ? "YES" : "NO") << "\n";
    std::cout << "  Suspicion Score:   " << packedResult.suspicionScore << "/100\n\n";

    // Analyze normal data
    auto normalResult = analyzer.Analyze(normalData, sections, 6, normalImports);

    std::cout << "Clean Sample Analysis:\n";
    std::cout << "  Entropy:           " << std::fixed << std::setprecision(2)
              << normalResult.codeEntropy << " bits\n";
    std::cout << "  Import Count:      " << normalResult.importCount << "\n";
    std::cout << "  High Entropy:      " << (normalResult.hasHighEntropy ? "YES" : "NO") << "\n";
    std::cout << "  Few Imports:       " << (normalResult.hasFewImports ? "YES" : "NO") << "\n";
    std::cout << "  Suspicious:        " << (normalResult.hasSuspiciousImports ? "YES" : "NO") << "\n";
    std::cout << "  Suspicion Score:   " << normalResult.suspicionScore << "/100\n";

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

// Example 5: Integration with PE Analysis
void IntegrationExample() {
    std::cout << "=== Integration Example ===\n\n";

    std::cout << "Typical workflow:\n\n";

    std::cout << "1. Load PE file\n";
    std::cout << "   PeFile pe(\"sample.exe\");\n\n";

    std::cout << "2. Extract sections\n";
    std::cout << "   auto sections = pe.GetSectionNames();\n\n";

    std::cout << "3. Get entry point\n";
    std::cout << "   auto entryPoint = pe.ReadEntryPoint();\n\n";

    std::cout << "4. Get imports\n";
    std::cout << "   auto imports = pe.GetImports();\n\n";

    std::cout << "5. Detect packer\n";
    std::cout << "   PackerDetector detector;\n";
    std::cout << "   detector.Initialize();\n\n";

    std::cout << "6. Run detection\n";
    std::cout << "   auto result = detector.Detect(\n";
    std::cout << "       pe.GetData(),\n";
    std::cout << "       pe.GetSize(),\n";
    std::cout << "       sections,\n";
    std::cout << "       imports.size(),\n";
    std::cout << "       imports\n";
    std::cout << "   );\n\n";

    std::cout << "7. Handle results\n";
    std::cout << "   if (result.isPacked) {\n";
    std::cout << "       cout << \"Detected: \" << result.packerName;\n";
    std::cout << "       // Take appropriate action\n";
    std::cout << "   }\n";

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

// Example 6: Custom Signatures
void CustomSignatureExample() {
    std::cout << "=== Custom Signature Example ===\n\n";

    PackerDetector detector;
    detector.Initialize();

    // Add custom packer signature
    PackerSignature customSig;
    customSig.name = "MyCustomPacker";
    customSig.sectionNames = {".custom", "custompck"};
    customSig.stringSignatures = {"Custom Packer v1.0"};
    customSig.minEntropy = 6.8;
    customSig.maxEntropy = 8.0;

    detector.GetSignatureDatabase().AddSignature(customSig);

    std::cout << "Added custom signature for: " << customSig.name << "\n";
    std::cout << "Section names: ";
    for (const auto& sec : customSig.sectionNames) {
        std::cout << sec << " ";
    }
    std::cout << "\n";

    std::cout << "\nTotal signatures: "
              << detector.GetSignatureDatabase().GetSignatures().size() << "\n";

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

int main() {
    std::cout << "Scylla Packer Detection Examples\n";
    std::cout << std::string(60, '=') << "\n\n";

    QuickDetectionExample();
    FullDetectionExample();
    MultiplePackersExample();
    HeuristicAnalysisExample();
    IntegrationExample();
    CustomSignatureExample();

    std::cout << "All examples completed!\n";

    return 0;
}
