/*
 * Scylla - OEP Detection Heuristics
 *
 * Implements automated Original Entry Point detection using multiple
 * heuristics for unpacked executable analysis.
 */

#include "OEPDetector.h"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <map>

namespace scylla {

// Known unpacker patterns
namespace UnpackerPatterns {
    // UPX: POPAD + JMP pattern
    const Pattern UPX_STUB = {
        "UPX",
        {0x61, 0xE9},  // POPAD; JMP
        {true, true},
        0x01  // JMP target is OEP
    };

    // ASPack: PUSHAD + CALL + ... + POPAD pattern
    const Pattern ASPACK_STUB = {
        "ASPack",
        {0x60, 0xE8, 0x00, 0x00, 0x00, 0x00},  // PUSHAD; CALL $+5
        {true, true, false, false, false, false},
        0x00
    };

    // Themida: Complex multi-layer unpacking
    const Pattern THEMIDA_STUB = {
        "Themida",
        {0x55, 0x8B, 0xEC, 0x83, 0xC4},  // push ebp; mov ebp, esp; add esp, X
        {true, true, true, true, true},
        0x00
    };

    // VMProtect: Virtualization entry
    const Pattern VMPROTECT_STUB = {
        "VMProtect",
        {0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3},  // CALL +5; RET (VM entry)
        {true, false, false, false, false, true},
        0x00
    };

    // MPRESS: PUSHAD; MOV EBP, ESP pattern
    const Pattern MPRESS_STUB = {
        "MPRESS",
        {0x60, 0x8B, 0xEC},  // PUSHAD; MOV EBP, ESP
        {true, true, true},
        0x00
    };

    // PEtite: NOP sled + CALL
    const Pattern PETITE_STUB = {
        "PEtite",
        {0x90, 0x90, 0x90, 0xE8},  // NOP NOP NOP CALL
        {true, true, true, true},
        0x00
    };

    std::vector<Pattern> GetAllPatterns() {
        return {UPX_STUB, ASPACK_STUB, THEMIDA_STUB, VMPROTECT_STUB, MPRESS_STUB, PETITE_STUB};
    }
}

// Implementation class
class OEPDetector::Impl {
public:
    OEPDetectorConfig config;
    std::map<uint64_t, double> candidateScores;

    // Disassembly helpers (simplified - real impl would use diStorm)
    struct Instruction {
        uint64_t address = 0;
        uint8_t opcode = 0;
        size_t length = 0;
        bool isJump = false;
        bool isCall = false;
        bool isRet = false;
        int64_t displacement = 0;
        uint64_t targetAddress = 0;
    };

    bool IsValidAddress(uint64_t address, const MemoryRegion& region) {
        return address >= region.address &&
               address < region.address + region.data.size();
    }

    size_t GetOffset(uint64_t address, const MemoryRegion& region) {
        if (!IsValidAddress(address, region)) return 0;
        return static_cast<size_t>(address - region.address);
    }

    // Simplified instruction decoder (real impl would use diStorm)
    Instruction DecodeInstruction(const MemoryRegion& region, uint64_t address) {
        Instruction inst;
        inst.address = address;

        size_t offset = GetOffset(address, region);
        if (offset >= region.data.size()) return inst;

        uint8_t opcode = region.data[offset];
        inst.opcode = opcode;

        // Simplified decoding
        if (opcode == 0xE9) {  // JMP rel32
            inst.isJump = true;
            inst.length = 5;
            if (offset + 5 <= region.data.size()) {
                int32_t disp = *reinterpret_cast<const int32_t*>(&region.data[offset + 1]);
                inst.displacement = disp;
                inst.targetAddress = address + 5 + disp;
            }
        }
        else if (opcode == 0xEB) {  // JMP rel8
            inst.isJump = true;
            inst.length = 2;
            if (offset + 2 <= region.data.size()) {
                int8_t disp = *reinterpret_cast<const int8_t*>(&region.data[offset + 1]);
                inst.displacement = disp;
                inst.targetAddress = address + 2 + disp;
            }
        }
        else if (opcode == 0xE8) {  // CALL rel32
            inst.isCall = true;
            inst.length = 5;
            if (offset + 5 <= region.data.size()) {
                int32_t disp = *reinterpret_cast<const int32_t*>(&region.data[offset + 1]);
                inst.displacement = disp;
                inst.targetAddress = address + 5 + disp;
            }
        }
        else if (opcode == 0xC3 || opcode == 0xC2) {  // RET
            inst.isRet = true;
            inst.length = (opcode == 0xC3) ? 1 : 3;
        }
        else if (opcode == 0x55) {  // PUSH EBP
            inst.length = 1;
        }
        else if (opcode == 0x60) {  // PUSHAD
            inst.length = 1;
        }
        else if (opcode == 0x61) {  // POPAD
            inst.length = 1;
        }
        else {
            inst.length = 1;  // Default
        }

        return inst;
    }

    bool IsFunctionPrologue(const MemoryRegion& region, uint64_t address) {
        size_t offset = GetOffset(address, region);
        if (offset + 3 > region.data.size()) return false;

        // Check for common prologues:
        // 1. push ebp; mov ebp, esp (55 8B EC)
        if (region.data[offset] == 0x55 &&
            region.data[offset + 1] == 0x8B &&
            region.data[offset + 2] == 0xEC) {
            return true;
        }

        // 2. 64-bit: push rbp; mov rbp, rsp (55 48 8B EC or 55 48 89 E5)
        if (offset + 4 <= region.data.size()) {
            if (region.data[offset] == 0x55 &&
                region.data[offset + 1] == 0x48 &&
                (region.data[offset + 2] == 0x8B || region.data[offset + 2] == 0x89)) {
                return true;
            }
        }

        // 3. sub esp, X (83 EC XX)
        if (region.data[offset] == 0x83 &&
            region.data[offset + 1] == 0xEC) {
            return true;
        }

        return false;
    }

    bool MatchesPattern(const MemoryRegion& region, uint64_t address, const UnpackerPatterns::Pattern& pattern) {
        size_t offset = GetOffset(address, region);
        if (offset + pattern.signature.size() > region.data.size()) {
            return false;
        }

        for (size_t i = 0; i < pattern.signature.size(); i++) {
            if (pattern.mask[i]) {  // Must match
                if (region.data[offset + i] != pattern.signature[i]) {
                    return false;
                }
            }
        }

        return true;
    }

    void AddCandidate(uint64_t address, double score) {
        if (candidateScores.find(address) == candidateScores.end()) {
            candidateScores[address] = score;
        } else {
            // Boost score if multiple methods agree
            candidateScores[address] = std::min(1.0, candidateScores[address] + score * 0.3);
        }
    }
};

OEPDetector::OEPDetector() : pImpl(std::make_unique<Impl>()) {}
OEPDetector::~OEPDetector() = default;

OEPResult OEPDetector::DetectOEP(const MemoryRegion& region, const OEPDetectorConfig& config) {
    return DetectOEP(std::vector<MemoryRegion>{region}, 0, config);
}

OEPResult OEPDetector::DetectOEP(const std::vector<MemoryRegion>& regions,
                                 uint64_t iatAddress,
                                 const OEPDetectorConfig& config) {
    pImpl->config = config;
    pImpl->candidateScores.clear();

    OEPResult result;

    if (regions.empty()) {
        result.description = "No memory regions provided";
        return result;
    }

    const auto& mainRegion = regions[0];

    // Apply each detection method
    if (config.enableTailJump) {
        auto candidates = FindTailJumps(mainRegion);
        for (auto addr : candidates) {
            pImpl->AddCandidate(addr, 0.7);
        }
    }

    if (config.enablePushAdPopAd) {
        auto candidates = FindPushAdPopAdPattern(mainRegion);
        for (auto addr : candidates) {
            pImpl->AddCandidate(addr, 0.8);
        }
    }

    if (config.enableEntropyTransition) {
        auto candidates = FindEntropyTransitions(mainRegion);
        for (auto addr : candidates) {
            pImpl->AddCandidate(addr, 0.6);
        }
    }

    if (config.enableFunctionPrologue) {
        auto candidates = FindFunctionPrologues(mainRegion);
        for (auto addr : candidates) {
            pImpl->AddCandidate(addr, 0.5);
        }
    }

    if (config.enableImportReference && iatAddress != 0) {
        uint64_t addr = FindFirstImportReference(mainRegion, mainRegion.address, iatAddress);
        if (addr != 0) {
            pImpl->AddCandidate(addr, 0.75);
        }
    }

    // Find best candidate
    if (pImpl->candidateScores.empty()) {
        result.description = "No OEP candidates found";
        return result;
    }

    // Sort by score
    std::vector<std::pair<uint64_t, double>> sorted(
        pImpl->candidateScores.begin(),
        pImpl->candidateScores.end()
    );
    std::sort(sorted.begin(), sorted.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });

    // Best candidate
    result.found = true;
    result.address = sorted[0].first;
    result.confidence = sorted[0].second;
    result.method = OEPDetectionMethod::Heuristic;

    // Validate the result
    result.hasValidPrologue = pImpl->IsFunctionPrologue(mainRegion, result.address);

    // Calculate entropy before/after
    size_t offset = pImpl->GetOffset(result.address, mainRegion);
    if (offset > 0x1000 && offset + 0x1000 < mainRegion.data.size()) {
        result.entropyBefore = CalculateEntropy(mainRegion.data, offset - 0x1000, 0x1000);
        result.entropyAfter = CalculateEntropy(mainRegion.data, offset, 0x1000);
        result.hasEntropyTransition = (result.entropyBefore > config.entropyThreshold) &&
                                     (result.entropyAfter < config.entropyThreshold);
    }

    // Add alternatives
    for (size_t i = 1; i < sorted.size() && i < config.maxCandidates; i++) {
        if (sorted[i].second >= config.minConfidence) {
            result.alternatives.push_back(sorted[i].first);
        }
    }

    // Description
    result.description = "OEP detected using combined heuristics";
    if (result.hasValidPrologue) {
        result.description += " (valid function prologue)";
    }
    if (result.hasEntropyTransition) {
        result.description += " (entropy transition detected)";
    }

    return result;
}

double OEPDetector::ValidateOEP(uint64_t address, const MemoryRegion& region) {
    double score = 0.0;

    // Check for valid prologue
    if (pImpl->IsFunctionPrologue(region, address)) {
        score += 0.4;
    }

    // Check entropy around address
    size_t offset = pImpl->GetOffset(address, region);
    if (offset + 0x100 < region.data.size()) {
        double entropy = CalculateEntropy(region.data, offset, 0x100);
        if (entropy < 7.0) {  // Normal code entropy
            score += 0.3;
        }
    }

    // Check for nearby RET instruction (indicates function)
    for (size_t i = 0; i < 100 && offset + i < region.data.size(); i++) {
        if (region.data[offset + i] == 0xC3) {  // RET
            score += 0.2;
            break;
        }
    }

    // Check alignment (OEPs often 16-byte aligned)
    if ((address & 0xF) == 0) {
        score += 0.1;
    }

    return std::min(1.0, score);
}

std::vector<uint64_t> OEPDetector::FindTailJumps(const MemoryRegion& region, size_t minJumpDistance) {
    std::vector<uint64_t> candidates;

    // Scan through region looking for large jumps
    for (size_t offset = 0; offset + 5 < region.data.size(); offset++) {
        uint8_t opcode = region.data[offset];

        // JMP rel32 (E9)
        if (opcode == 0xE9) {
            int32_t displacement = *reinterpret_cast<const int32_t*>(&region.data[offset + 1]);
            uint64_t targetAddress = region.address + offset + 5 + displacement;

            // Check if this is a "tail jump" (large forward jump)
            if (displacement > static_cast<int32_t>(minJumpDistance)) {
                // Check if target is in executable region
                if (pImpl->IsValidAddress(targetAddress, region)) {
                    candidates.push_back(targetAddress);
                }
            }
        }
    }

    return candidates;
}

std::vector<uint64_t> OEPDetector::FindPushAdPopAdPattern(const MemoryRegion& region) {
    std::vector<uint64_t> candidates;

    // Look for PUSHAD (60) followed eventually by POPAD (61)
    for (size_t offset = 0; offset < region.data.size(); offset++) {
        if (region.data[offset] == 0x60) {  // PUSHAD
            // Search for matching POPAD within reasonable distance
            for (size_t i = offset + 1; i < offset + 0x2000 && i < region.data.size(); i++) {
                if (region.data[i] == 0x61) {  // POPAD
                    // Check what follows POPAD
                    if (i + 1 < region.data.size()) {
                        // Common pattern: POPAD; JMP
                        if (region.data[i + 1] == 0xE9 || region.data[i + 1] == 0xEB) {
                            auto inst = pImpl->DecodeInstruction(region, region.address + i + 1);
                            if (inst.targetAddress != 0) {
                                candidates.push_back(inst.targetAddress);
                            }
                        }
                        // Or: POPAD; RET
                        else if (region.data[i + 1] == 0xC3) {
                            // OEP might be right after POPAD
                            candidates.push_back(region.address + i + 1);
                        }
                        // Or: POPAD followed by code
                        else {
                            candidates.push_back(region.address + i + 1);
                        }
                    }
                    break;  // Found matching POPAD
                }
            }
        }
    }

    return candidates;
}

std::vector<uint64_t> OEPDetector::FindEntropyTransitions(const MemoryRegion& region, size_t windowSize) {
    std::vector<uint64_t> candidates;

    if (region.data.size() < windowSize * 2) {
        return candidates;
    }

    double prevEntropy = CalculateEntropy(region.data, 0, windowSize);

    // Slide window through region
    for (size_t offset = windowSize; offset + windowSize < region.data.size(); offset += windowSize / 2) {
        double entropy = CalculateEntropy(region.data, offset, windowSize);

        // Check for high->low transition (packed->unpacked)
        if (prevEntropy > pImpl->config.entropyThreshold &&
            entropy < pImpl->config.entropyThreshold) {
            candidates.push_back(region.address + offset);
        }

        prevEntropy = entropy;
    }

    return candidates;
}

std::vector<uint64_t> OEPDetector::FindFunctionPrologues(const MemoryRegion& region) {
    std::vector<uint64_t> candidates;

    for (size_t offset = 0; offset + 3 < region.data.size(); offset++) {
        if (pImpl->IsFunctionPrologue(region, region.address + offset)) {
            candidates.push_back(region.address + offset);
        }
    }

    return candidates;
}

uint64_t OEPDetector::FindFirstImportReference(const MemoryRegion& region,
                                               uint64_t startAddress,
                                               uint64_t iatAddress) {
    size_t startOffset = pImpl->GetOffset(startAddress, region);

    // Scan for IAT references (simplified - real impl would do full disassembly)
    for (size_t offset = startOffset; offset + 4 < region.data.size(); offset++) {
        // Look for MOV reg, [IAT] patterns
        // This is simplified - real implementation would use proper disassembly
        if (region.data[offset] == 0x8B) {  // MOV
            // Check if following bytes look like IAT reference
            uint32_t addr = *reinterpret_cast<const uint32_t*>(&region.data[offset + 2]);
            if (addr >= iatAddress && addr < iatAddress + 0x10000) {
                return region.address + offset;
            }
        }
    }

    return 0;
}

double OEPDetector::CalculateEntropy(const std::vector<uint8_t>& data, size_t offset, size_t size) {
    if (offset + size > data.size() || size == 0) {
        return 0.0;
    }

    // Calculate byte frequency
    std::array<size_t, 256> freq = {};
    for (size_t i = 0; i < size; i++) {
        freq[data[offset + i]]++;
    }

    // Calculate Shannon entropy
    double entropy = 0.0;
    for (size_t count : freq) {
        if (count > 0) {
            double p = static_cast<double>(count) / size;
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

std::string OEPDetector::MatchUnpackerPattern(const MemoryRegion& region, uint64_t address) {
    auto patterns = UnpackerPatterns::GetAllPatterns();

    for (const auto& pattern : patterns) {
        if (pImpl->MatchesPattern(region, address, pattern)) {
            return pattern.name;
        }
    }

    return "";
}

} // namespace scylla
