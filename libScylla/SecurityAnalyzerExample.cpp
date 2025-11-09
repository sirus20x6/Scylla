/*
 * Security Analyzer Usage Examples
 */

#include "SecurityAnalyzer.h"
#include <iostream>
#include <iomanip>

using namespace Scylla::Security;

void BasicSecurityAnalysisExample() {
    std::cout << "=== Basic Security Analysis ===\n\n";

    SecurityAnalyzer analyzer;

    // Analyze a PE file
    auto assessment = analyzer.Analyze("C:\\Windows\\System32\\notepad.exe");

    std::cout << "\nSecurity Assessment:\n";
    std::cout << "  Score: " << assessment.securityScore << "/100\n";
    std::cout << "  Risk Level: ";
    switch (assessment.riskLevel) {
        case SecurityAssessment::RiskLevel::Minimal: std::cout << "Minimal\n"; break;
        case SecurityAssessment::RiskLevel::Low: std::cout << "Low\n"; break;
        case SecurityAssessment::RiskLevel::Medium: std::cout << "Medium\n"; break;
        case SecurityAssessment::RiskLevel::High: std::cout << "High\n"; break;
        case SecurityAssessment::RiskLevel::Critical: std::cout << "Critical\n"; break;
    }

    std::cout << "\nEnabled Mitigations:\n";
    if (assessment.mitigations.depEnabled)
        std::cout << "  ✓ DEP/NX\n";
    if (assessment.mitigations.aslrEnabled)
        std::cout << "  ✓ ASLR\n";
    if (assessment.mitigations.cfgEnabled)
        std::cout << "  ✓ Control Flow Guard\n";
    if (assessment.mitigations.gsEnabled)
        std::cout << "  ✓ Stack Protection (/GS)\n";
    if (assessment.mitigations.safeSEH)
        std::cout << "  ✓ SafeSEH\n";

    if (!assessment.recommendations.empty()) {
        std::cout << "\nRecommendations:\n";
        for (const auto& rec : assessment.recommendations) {
            std::cout << "  • " << rec << "\n";
        }
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

void DetailedMitigationCheckExample() {
    std::cout << "=== Detailed Mitigation Checks ===\n\n";

    SecurityAnalyzer analyzer;
    auto assessment = analyzer.Analyze("sample.exe");

    const auto& m = assessment.mitigations;

    std::cout << "Memory Protections:\n";
    std::cout << "─────────────────────────────────────\n";
    std::cout << "  DEP/NX Enabled:           " << (m.depEnabled ? "YES" : "NO") << "\n";
    std::cout << "  DEP Mode:                 " << m.depMode << "\n";
    std::cout << "  ASLR Enabled:             " << (m.aslrEnabled ? "YES" : "NO") << "\n";
    std::cout << "  High-Entropy ASLR:        " << (m.highEntropyVA ? "YES" : "NO") << "\n";
    std::cout << "  Dynamic Base:             " << (m.dynamicBaseEnabled ? "YES" : "NO") << "\n\n";

    std::cout << "Control Flow Protections:\n";
    std::cout << "─────────────────────────────────────\n";
    std::cout << "  CFG Enabled:              " << (m.cfgEnabled ? "YES" : "NO") << "\n";
    std::cout << "  CFG Instrumented:         " << (m.cfgInstrumented ? "YES" : "NO") << "\n";
    std::cout << "  CFG Function Table:       " << (m.cfgFunctionTable ? "YES" : "NO") << "\n\n";

    std::cout << "Stack Protections:\n";
    std::cout << "─────────────────────────────────────\n";
    std::cout << "  /GS Enabled:              " << (m.gsEnabled ? "YES" : "NO") << "\n";
    std::cout << "  Stack Cookie Present:     " << (m.stackCookiePresent ? "YES" : "NO") << "\n";
    std::cout << "  SafeSEH Enabled:          " << (m.safeSEH ? "YES" : "NO") << "\n";
    std::cout << "  SEH Handler Count:        " << m.sehHandlerCount << "\n";
    std::cout << "  No SEH:                   " << (m.noSEH ? "YES" : "NO") << "\n\n";

    std::cout << "Code Signing:\n";
    std::cout << "─────────────────────────────────────\n";
    std::cout << "  Authenticode Present:     " << (m.authenticodePresent ? "YES" : "NO") << "\n";
    std::cout << "  Signature Valid:          " << (m.signatureValid ? "YES" : "NO") << "\n";
    if (!m.signerName.empty()) {
        std::cout << "  Signer:                   " << m.signerName << "\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

void ComparisonExample() {
    std::cout << "=== Security Comparison ===\n\n";

    SecurityAnalyzer analyzer;

    std::vector<std::string> files = {
        "app_v1.exe",
        "app_v2.exe",
        "app_v3.exe"
    };

    std::cout << std::left;
    std::cout << std::setw(15) << "File"
              << std::setw(8) << "Score"
              << std::setw(8) << "DEP"
              << std::setw(8) << "ASLR"
              << std::setw(8) << "CFG"
              << std::setw(10) << "Signed\n";
    std::cout << std::string(60, '-') << "\n";

    for (const auto& file : files) {
        auto assessment = analyzer.Analyze(file);

        std::cout << std::setw(15) << file
                  << std::setw(8) << assessment.securityScore
                  << std::setw(8) << (assessment.mitigations.depEnabled ? "✓" : "✗")
                  << std::setw(8) << (assessment.mitigations.aslrEnabled ? "✓" : "✗")
                  << std::setw(8) << (assessment.mitigations.cfgEnabled ? "✓" : "✗")
                  << std::setw(10) << (assessment.mitigations.authenticodePresent ? "✓" : "✗")
                  << "\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

void ReportGenerationExample() {
    std::cout << "=== Report Generation ===\n\n";

    SecurityAnalyzer analyzer;
    SecurityReportGenerator reporter;

    auto assessment = analyzer.Analyze("target.exe");

    // Text report
    std::cout << "Generating text report...\n";
    std::ofstream textReport("security_report.txt");
    reporter.GenerateTextReport(assessment, textReport);
    std::cout << "  ✓ security_report.txt\n";

    // JSON report
    std::cout << "Generating JSON report...\n";
    std::ofstream jsonReport("security_report.json");
    reporter.GenerateJSONReport(assessment, jsonReport);
    std::cout << "  ✓ security_report.json\n";

    // Summary to console
    std::cout << "\nSummary:\n";
    reporter.GenerateSummary(assessment, std::cout);

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

void ComplianceCheckExample() {
    std::cout << "=== Compliance Checking ===\n\n";

    SecurityAnalyzer analyzer;
    auto assessment = analyzer.Analyze("commercial_app.exe");

    std::cout << "Compliance Status:\n";
    std::cout << "─────────────────────────────────────\n";

    for (const auto& [standard, compliant] : assessment.compliance) {
        std::cout << "  " << std::left << std::setw(25) << standard
                  << ": " << (compliant ? "✓ Compliant" : "✗ Non-compliant")
                  << "\n";
    }

    std::cout << "\n";

    if (!assessment.compliance["Microsoft SDL"]) {
        std::cout << "Microsoft SDL Requirements:\n";
        std::cout << "  The following mitigations are required:\n";
        std::cout << "  • DEP/NX (compile with /NXCOMPAT)\n";
        std::cout << "  • ASLR (compile with /DYNAMICBASE)\n";
        std::cout << "  • /GS Stack Protection\n";
        std::cout << "  • SafeSEH or No SEH\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

void MalwareAnalysisExample() {
    std::cout << "=== Malware Security Analysis ===\n\n";

    SecurityAnalyzer analyzer;

    std::cout << "Analyzing suspected malware sample...\n\n";

    auto assessment = analyzer.Analyze("suspicious.exe");

    std::cout << "Security Assessment for Malware:\n";
    std::cout << "─────────────────────────────────────\n";
    std::cout << "  Security Score: " << assessment.securityScore << "/100\n\n";

    // Low security score suggests malware
    if (assessment.securityScore < 30) {
        std::cout << "⚠ WARNING: Very low security score!\n";
        std::cout << "This is typical of malware, which often:\n";
        std::cout << "  • Lacks code signing\n";
        std::cout << "  • Disables security mitigations\n";
        std::cout << "  • Uses predictable memory layouts for exploitation\n\n";
    }

    std::cout << "Missing Protections (Red Flags):\n";
    for (const auto& weakness : assessment.weaknesses) {
        std::cout << "  ⚠ " << weakness << "\n";
    }

    std::cout << "\n";

    // Code signing is especially important
    if (!assessment.mitigations.authenticodePresent) {
        std::cout << "⚠ CRITICAL: No code signature!\n";
        std::cout << "  Legitimate software is typically signed.\n";
        std::cout << "  Unsigned executables should be treated as suspicious.\n";
    } else if (!assessment.mitigations.signatureValid) {
        std::cout << "⚠ CRITICAL: Invalid code signature!\n";
        std::cout << "  The executable may have been modified after signing.\n";
        std::cout << "  This is a strong indicator of tampering or malware.\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

void SecurityScoringExample() {
    std::cout << "=== Security Scoring System ===\n\n";

    std::cout << "Scoring Breakdown:\n";
    std::cout << "─────────────────────────────────────\n";
    std::cout << "Core Mitigations (60 points):\n";
    std::cout << "  DEP/NX:                15 points\n";
    std::cout << "  ASLR:                  15 points\n";
    std::cout << "  Control Flow Guard:    20 points\n";
    std::cout << "  Stack Protection:      10 points\n\n";

    std::cout << "Additional Protections (25 points):\n";
    std::cout << "  SafeSEH:               10 points\n";
    std::cout << "  High-Entropy ASLR:      5 points\n";
    std::cout << "  Force Integrity:        5 points\n";
    std::cout << "  No SEH/SafeSEH:         5 points\n\n";

    std::cout << "Code Signing (15 points):\n";
    std::cout << "  Authenticode Present:  10 points\n";
    std::cout << "  Valid Signature:        5 points\n\n";

    std::cout << "Risk Level Thresholds:\n";
    std::cout << "  80-100: Minimal Risk   (Excellent)\n";
    std::cout << "  60-79:  Low Risk       (Good)\n";
    std::cout << "  40-59:  Medium Risk    (Fair)\n";
    std::cout << "  20-39:  High Risk      (Poor)\n";
    std::cout << "  0-19:   Critical Risk  (Very Poor)\n";

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

void RecommendationsExample() {
    std::cout << "=== Build Recommendations ===\n\n";

    SecurityAnalyzer analyzer;
    auto assessment = analyzer.Analyze("my_app.exe");

    std::cout << "Current Security Score: " << assessment.securityScore << "/100\n\n";

    if (!assessment.recommendations.empty()) {
        std::cout << "To improve security, update your build settings:\n\n";

        for (size_t i = 0; i < assessment.recommendations.size(); i++) {
            std::cout << (i + 1) << ". " << assessment.recommendations[i] << "\n";
        }

        std::cout << "\n";
        std::cout << "Example Visual Studio Project Settings:\n";
        std::cout << "  Configuration Properties > Linker > Advanced:\n";

        if (!assessment.mitigations.depEnabled) {
            std::cout << "    Data Execution Prevention (DEP): Yes (/NXCOMPAT)\n";
        }
        if (!assessment.mitigations.aslrEnabled) {
            std::cout << "    Randomized Base Address: Yes (/DYNAMICBASE)\n";
        }
        if (!assessment.mitigations.cfgEnabled) {
            std::cout << "  Configuration Properties > C/C++ > Code Generation:\n";
            std::cout << "    Control Flow Guard: Yes (/guard:cf)\n";
        }
        if (!assessment.mitigations.gsEnabled) {
            std::cout << "    Buffer Security Check: Yes (/GS)\n";
        }
    } else {
        std::cout << "✓ Excellent! All recommended mitigations are enabled.\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

int main() {
    std::cout << "Scylla Security Analyzer Examples\n";
    std::cout << std::string(60, '=') << "\n\n";

    BasicSecurityAnalysisExample();
    DetailedMitigationCheckExample();
    ComparisonExample();
    ReportGenerationExample();
    ComplianceCheckExample();
    MalwareAnalysisExample();
    SecurityScoringExample();
    RecommendationsExample();

    std::cout << "All examples completed!\n";

    return 0;
}
