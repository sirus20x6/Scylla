/*
 * Scylla Security Analysis - Implementation
 */

#include "SecurityAnalyzer.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <imagehlp.h>
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "imagehlp.lib")
#endif

namespace Scylla {
namespace Security {

// DLL Characteristics flags
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA    0x0020
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE       0x0040
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY    0x0080
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT          0x0100
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION       0x0200
#define IMAGE_DLLCHARACTERISTICS_NO_SEH             0x0400
#define IMAGE_DLLCHARACTERISTICS_NO_BIND            0x0800
#define IMAGE_DLLCHARACTERISTICS_APPCONTAINER       0x1000
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER         0x2000
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF           0x4000
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE 0x8000

// ============================================================================
// SecurityAnalyzer Implementation
// ============================================================================

SecurityAnalyzer::SecurityAnalyzer() {
}

SecurityAnalyzer::~SecurityAnalyzer() {
}

SecurityAssessment SecurityAnalyzer::Analyze(const std::filesystem::path& filePath) {
    SecurityAssessment assessment;
    assessment.mitigations = {};
    assessment.securityScore = 0;

    if (!std::filesystem::exists(filePath)) {
        return assessment;
    }

    std::cout << "Analyzing security mitigations for: " << filePath.filename() << "\n";

    // Parse PE headers
    auto peInfo = ParsePEHeaders(filePath);

    // Check DLL Characteristics
    assessment.mitigations.depEnabled =
        HasDLLCharacteristic(peInfo.dllCharacteristics, IMAGE_DLLCHARACTERISTICS_NX_COMPAT);

    assessment.mitigations.aslrEnabled =
        HasDLLCharacteristic(peInfo.dllCharacteristics, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);

    assessment.mitigations.highEntropyVA =
        HasDLLCharacteristic(peInfo.dllCharacteristics, IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA);

    assessment.mitigations.cfgEnabled =
        HasDLLCharacteristic(peInfo.dllCharacteristics, IMAGE_DLLCHARACTERISTICS_GUARD_CF);

    assessment.mitigations.forceIntegrity =
        HasDLLCharacteristic(peInfo.dllCharacteristics, IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY);

    assessment.mitigations.noSEH =
        HasDLLCharacteristic(peInfo.dllCharacteristics, IMAGE_DLLCHARACTERISTICS_NO_SEH);

    assessment.mitigations.noBindFlag =
        HasDLLCharacteristic(peInfo.dllCharacteristics, IMAGE_DLLCHARACTERISTICS_NO_BIND);

    assessment.mitigations.wdmDriver =
        HasDLLCharacteristic(peInfo.dllCharacteristics, IMAGE_DLLCHARACTERISTICS_WDM_DRIVER);

    assessment.mitigations.terminalServerAware =
        HasDLLCharacteristic(peInfo.dllCharacteristics, IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE);

    // Parse Load Config for additional info
    if (peInfo.loadConfigRVA > 0) {
        auto loadConfig = ParseLoadConfig(filePath, peInfo);

        // CFG details
        if (loadConfig.guardCFCheckFunctionPointer > 0) {
            assessment.mitigations.cfgInstrumented = true;
        }
        if (loadConfig.guardCFFunctionTable > 0) {
            assessment.mitigations.cfgFunctionTable = true;
        }

        // SafeSEH
        if (loadConfig.sehHandlerCount > 0) {
            assessment.mitigations.safeSEH = true;
            assessment.mitigations.sehTablePresent = true;
            assessment.mitigations.sehHandlerCount = loadConfig.sehHandlerCount;
        }

        // Stack cookie (/GS)
        if (loadConfig.securityCookie > 0) {
            assessment.mitigations.gsEnabled = true;
            assessment.mitigations.stackCookiePresent = true;
        }
    }

    // Check code signing
    if (peInfo.securityDirRVA > 0) {
        assessment.mitigations.authenticodePresent = true;
        assessment.mitigations.signatureValid = VerifySignature(filePath);
    }

    // DEP mode determination
    if (assessment.mitigations.depEnabled) {
        assessment.mitigations.depMode = "Always On";
        assessment.mitigations.depPermanent = true;
    } else {
        assessment.mitigations.depMode = "Off";
        assessment.mitigations.depPermanent = false;
    }

    // Calculate security score
    assessment.securityScore = CalculateSecurityScore(assessment.mitigations);
    assessment.riskLevel = AssessRiskLevel(assessment.securityScore);

    // Analyze strengths and weaknesses
    if (assessment.mitigations.depEnabled) {
        assessment.strengths.push_back("DEP/NX enabled - prevents code execution in data pages");
    } else {
        assessment.weaknesses.push_back("DEP/NX disabled - vulnerable to code injection attacks");
    }

    if (assessment.mitigations.aslrEnabled) {
        assessment.strengths.push_back("ASLR enabled - randomizes memory layout");
        if (assessment.mitigations.highEntropyVA) {
            assessment.strengths.push_back("High-entropy ASLR - 64-bit address randomization");
        }
    } else {
        assessment.weaknesses.push_back("ASLR disabled - predictable memory addresses");
    }

    if (assessment.mitigations.cfgEnabled) {
        assessment.strengths.push_back("Control Flow Guard enabled - prevents ROP/JOP attacks");
    } else {
        assessment.weaknesses.push_back("CFG disabled - vulnerable to ROP/JOP exploits");
    }

    if (assessment.mitigations.gsEnabled) {
        assessment.strengths.push_back("/GS stack cookies - detects buffer overflows");
    } else {
        assessment.weaknesses.push_back("No stack protection - vulnerable to buffer overflows");
    }

    if (assessment.mitigations.safeSEH) {
        assessment.strengths.push_back("SafeSEH enabled - prevents SEH overwrites");
    } else if (!assessment.mitigations.noSEH) {
        assessment.weaknesses.push_back("SafeSEH disabled - vulnerable to SEH overwrites");
    }

    if (assessment.mitigations.authenticodePresent) {
        if (assessment.mitigations.signatureValid) {
            assessment.strengths.push_back("Valid code signature - verified publisher");
        } else {
            assessment.weaknesses.push_back("Invalid code signature - signature verification failed");
        }
    } else {
        assessment.weaknesses.push_back("Not code-signed - publisher identity not verified");
    }

    // Generate recommendations
    assessment.recommendations = GenerateRecommendations(assessment.mitigations);

    // Check compliance
    assessment.compliance["Microsoft SDL"] = CheckMicrosoftSDL(assessment.mitigations);
    assessment.compliance["CIS Benchmarks"] = CheckCIS(assessment.mitigations);

    std::cout << "Security Score: " << assessment.securityScore << "/100\n";
    std::cout << "Risk Level: ";
    switch (assessment.riskLevel) {
        case SecurityAssessment::RiskLevel::Critical: std::cout << "Critical\n"; break;
        case SecurityAssessment::RiskLevel::High: std::cout << "High\n"; break;
        case SecurityAssessment::RiskLevel::Medium: std::cout << "Medium\n"; break;
        case SecurityAssessment::RiskLevel::Low: std::cout << "Low\n"; break;
        case SecurityAssessment::RiskLevel::Minimal: std::cout << "Minimal\n"; break;
    }

    return assessment;
}

SecurityAnalyzer::PEInfo SecurityAnalyzer::ParsePEHeaders(const std::filesystem::path& filePath) {
    PEInfo info = {};

    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return info;
    }

    // Read DOS header
    uint8_t dosHeader[64];
    file.read(reinterpret_cast<char*>(dosHeader), 64);

    if (dosHeader[0] != 'M' || dosHeader[1] != 'Z') {
        return info;
    }

    // Get PE offset
    uint32_t peOffset = *reinterpret_cast<uint32_t*>(&dosHeader[0x3C]);
    file.seekg(peOffset);

    // Read PE signature
    uint32_t peSig;
    file.read(reinterpret_cast<char*>(&peSig), 4);

    if (peSig != 0x4550) {  // 'PE\0\0'
        return info;
    }

    // Read COFF header
    uint8_t coffHeader[20];
    file.read(reinterpret_cast<char*>(coffHeader), 20);

    uint16_t sizeOfOptionalHeader = *reinterpret_cast<uint16_t*>(&coffHeader[16]);

    // Read Optional header magic
    uint16_t magic;
    file.read(reinterpret_cast<char*>(&magic), 2);

    info.is64Bit = (magic == 0x20B);  // PE32+ = 0x20B, PE32 = 0x10B

    // Skip to DLL Characteristics
    if (info.is64Bit) {
        file.seekg(peOffset + 24 + 70, std::ios::beg);
    } else {
        file.seekg(peOffset + 24 + 70, std::ios::beg);
    }

    file.read(reinterpret_cast<char*>(&info.dllCharacteristics), 2);

    // Read data directories
    size_t dataDirectoryOffset = info.is64Bit ?
        peOffset + 24 + 112 : peOffset + 24 + 96;

    file.seekg(dataDirectoryOffset);

    // Skip Export, Import, Resource, Exception tables
    file.seekg(dataDirectoryOffset + (4 * 8), std::ios::beg);

    // Security directory (index 4)
    file.read(reinterpret_cast<char*>(&info.securityDirRVA), 4);
    file.read(reinterpret_cast<char*>(&info.securityDirSize), 4);

    // Skip Base Reloc
    file.seekg(8, std::ios::cur);

    // Debug, Architecture, GlobalPtr
    file.seekg(24, std::ios::cur);

    // TLS, Load Config (index 10)
    file.seekg(8, std::ios::cur);
    file.read(reinterpret_cast<char*>(&info.loadConfigRVA), 4);
    file.read(reinterpret_cast<char*>(&info.loadConfigSize), 4);

    return info;
}

bool SecurityAnalyzer::HasDLLCharacteristic(uint16_t characteristics, uint16_t flag) {
    return (characteristics & flag) != 0;
}

SecurityAnalyzer::LoadConfigInfo SecurityAnalyzer::ParseLoadConfig(
    const std::filesystem::path& filePath,
    const PEInfo& peInfo)
{
    LoadConfigInfo info = {};

    // Simplified - would need full RVA to file offset conversion
    // For now, just return empty structure
    // Real implementation would parse IMAGE_LOAD_CONFIG_DIRECTORY

    return info;
}

std::vector<uint32_t> SecurityAnalyzer::ParseSEHTable(
    const std::filesystem::path& filePath,
    const LoadConfigInfo& loadConfig)
{
    std::vector<uint32_t> handlers;
    // Simplified implementation
    return handlers;
}

bool SecurityAnalyzer::VerifySignature(const std::filesystem::path& filePath) {
#ifdef _WIN32
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA winTrustData = {};
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.pPolicyCallbackData = NULL;
    winTrustData.pSIPClientData = NULL;
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileInfo;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

    LONG result = WinVerifyTrust(NULL, &policyGUID, &winTrustData);

    // Cleanup
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &winTrustData);

    return (result == ERROR_SUCCESS);
#else
    // On non-Windows, we can't verify Authenticode signatures
    return false;
#endif
}

int SecurityAnalyzer::CalculateSecurityScore(const SecurityMitigations& mitigations) {
    int score = 0;

    // Core mitigations (60 points)
    if (mitigations.depEnabled) score += 15;
    if (mitigations.aslrEnabled) score += 15;
    if (mitigations.cfgEnabled) score += 20;
    if (mitigations.gsEnabled) score += 10;

    // Additional protections (25 points)
    if (mitigations.safeSEH) score += 10;
    if (mitigations.highEntropyVA) score += 5;
    if (mitigations.forceIntegrity) score += 5;
    if (mitigations.noSEH || mitigations.safeSEH) score += 5;

    // Code signing (15 points)
    if (mitigations.authenticodePresent) {
        score += 10;
        if (mitigations.signatureValid) score += 5;
    }

    return std::min(score, 100);
}

SecurityAssessment::RiskLevel SecurityAnalyzer::AssessRiskLevel(int score) {
    if (score >= 80) return SecurityAssessment::RiskLevel::Minimal;
    if (score >= 60) return SecurityAssessment::RiskLevel::Low;
    if (score >= 40) return SecurityAssessment::RiskLevel::Medium;
    if (score >= 20) return SecurityAssessment::RiskLevel::High;
    return SecurityAssessment::RiskLevel::Critical;
}

std::vector<std::string> SecurityAnalyzer::GenerateRecommendations(
    const SecurityMitigations& mitigations)
{
    std::vector<std::string> recommendations;

    if (!mitigations.depEnabled) {
        recommendations.push_back("Enable DEP/NX: Compile with /NXCOMPAT flag");
    }

    if (!mitigations.aslrEnabled) {
        recommendations.push_back("Enable ASLR: Compile with /DYNAMICBASE flag");
    }

    if (!mitigations.cfgEnabled) {
        recommendations.push_back("Enable Control Flow Guard: Compile with /guard:cf flag");
    }

    if (!mitigations.gsEnabled) {
        recommendations.push_back("Enable stack protection: Compile with /GS flag");
    }

    if (!mitigations.safeSEH && !mitigations.noSEH) {
        recommendations.push_back("Enable SafeSEH: Compile with /SAFESEH flag");
    }

    if (!mitigations.highEntropyVA) {
        recommendations.push_back("Enable high-entropy ASLR: Use /HIGHENTROPYVA for 64-bit builds");
    }

    if (!mitigations.authenticodePresent) {
        recommendations.push_back("Sign the binary: Use Authenticode code signing");
    } else if (!mitigations.signatureValid) {
        recommendations.push_back("Fix code signature: Current signature is invalid");
    }

    return recommendations;
}

bool SecurityAnalyzer::CheckMicrosoftSDL(const SecurityMitigations& mitigations) {
    // Microsoft SDL requirements (simplified)
    return mitigations.depEnabled &&
           mitigations.aslrEnabled &&
           mitigations.gsEnabled &&
           (mitigations.safeSEH || mitigations.noSEH);
}

bool SecurityAnalyzer::CheckCIS(const SecurityMitigations& mitigations) {
    // CIS Benchmarks (simplified)
    return mitigations.depEnabled &&
           mitigations.aslrEnabled &&
           mitigations.authenticodePresent;
}

CertificateInfo SecurityAnalyzer::AnalyzeCertificate(const std::filesystem::path& filePath) {
    CertificateInfo cert;
    cert.isValid = false;

#ifdef _WIN32
    // Simplified - would use CryptQueryObject and related APIs
    // to extract full certificate details
#endif

    return cert;
}

// ============================================================================
// SecurityReportGenerator Implementation
// ============================================================================

void SecurityReportGenerator::GenerateTextReport(const SecurityAssessment& assessment,
                                                 std::ostream& out)
{
    out << "Security Analysis Report\n";
    out << "========================\n\n";

    out << "Overall Assessment:\n";
    out << "  Security Score: " << assessment.securityScore << "/100\n";
    out << "  Risk Level: ";
    switch (assessment.riskLevel) {
        case SecurityAssessment::RiskLevel::Critical: out << "Critical\n"; break;
        case SecurityAssessment::RiskLevel::High: out << "High\n"; break;
        case SecurityAssessment::RiskLevel::Medium: out << "Medium\n"; break;
        case SecurityAssessment::RiskLevel::Low: out << "Low\n"; break;
        case SecurityAssessment::RiskLevel::Minimal: out << "Minimal\n"; break;
    }
    out << "\n";

    out << "Security Mitigations:\n";
    out << "  DEP/NX:                " << (assessment.mitigations.depEnabled ? "✓ Enabled" : "✗ Disabled") << "\n";
    out << "  ASLR:                  " << (assessment.mitigations.aslrEnabled ? "✓ Enabled" : "✗ Disabled") << "\n";
    out << "  High-Entropy ASLR:     " << (assessment.mitigations.highEntropyVA ? "✓ Enabled" : "✗ Disabled") << "\n";
    out << "  Control Flow Guard:    " << (assessment.mitigations.cfgEnabled ? "✓ Enabled" : "✗ Disabled") << "\n";
    out << "  Stack Protection (/GS):" << (assessment.mitigations.gsEnabled ? "✓ Enabled" : "✗ Disabled") << "\n";
    out << "  SafeSEH:               " << (assessment.mitigations.safeSEH ? "✓ Enabled" : "✗ Disabled") << "\n";
    out << "  Code Signing:          " << (assessment.mitigations.authenticodePresent ? "✓ Present" : "✗ Not signed") << "\n";
    out << "\n";

    if (!assessment.strengths.empty()) {
        out << "Strengths:\n";
        for (const auto& strength : assessment.strengths) {
            out << "  ✓ " << strength << "\n";
        }
        out << "\n";
    }

    if (!assessment.weaknesses.empty()) {
        out << "Weaknesses:\n";
        for (const auto& weakness : assessment.weaknesses) {
            out << "  ✗ " << weakness << "\n";
        }
        out << "\n";
    }

    if (!assessment.recommendations.empty()) {
        out << "Recommendations:\n";
        for (size_t i = 0; i < assessment.recommendations.size(); i++) {
            out << "  " << (i + 1) << ". " << assessment.recommendations[i] << "\n";
        }
        out << "\n";
    }

    if (!assessment.compliance.empty()) {
        out << "Compliance:\n";
        for (const auto& [standard, compliant] : assessment.compliance) {
            out << "  " << standard << ": " << (compliant ? "✓ Compliant" : "✗ Non-compliant") << "\n";
        }
    }
}

void SecurityReportGenerator::GenerateJSONReport(const SecurityAssessment& assessment,
                                                std::ostream& out)
{
    out << "{\n";
    out << "  \"securityScore\": " << assessment.securityScore << ",\n";
    out << "  \"riskLevel\": \"";
    switch (assessment.riskLevel) {
        case SecurityAssessment::RiskLevel::Critical: out << "Critical"; break;
        case SecurityAssessment::RiskLevel::High: out << "High"; break;
        case SecurityAssessment::RiskLevel::Medium: out << "Medium"; break;
        case SecurityAssessment::RiskLevel::Low: out << "Low"; break;
        case SecurityAssessment::RiskLevel::Minimal: out << "Minimal"; break;
    }
    out << "\",\n";

    out << "  \"mitigations\": {\n";
    out << "    \"dep\": " << (assessment.mitigations.depEnabled ? "true" : "false") << ",\n";
    out << "    \"aslr\": " << (assessment.mitigations.aslrEnabled ? "true" : "false") << ",\n";
    out << "    \"cfg\": " << (assessment.mitigations.cfgEnabled ? "true" : "false") << ",\n";
    out << "    \"gs\": " << (assessment.mitigations.gsEnabled ? "true" : "false") << ",\n";
    out << "    \"safeSEH\": " << (assessment.mitigations.safeSEH ? "true" : "false") << ",\n";
    out << "    \"codeSigning\": " << (assessment.mitigations.authenticodePresent ? "true" : "false") << "\n";
    out << "  },\n";

    out << "  \"strengths\": [\n";
    for (size_t i = 0; i < assessment.strengths.size(); i++) {
        out << "    \"" << assessment.strengths[i] << "\"";
        if (i < assessment.strengths.size() - 1) out << ",";
        out << "\n";
    }
    out << "  ],\n";

    out << "  \"weaknesses\": [\n";
    for (size_t i = 0; i < assessment.weaknesses.size(); i++) {
        out << "    \"" << assessment.weaknesses[i] << "\"";
        if (i < assessment.weaknesses.size() - 1) out << ",";
        out << "\n";
    }
    out << "  ]\n";

    out << "}\n";
}

} // namespace Security
} // namespace Scylla
