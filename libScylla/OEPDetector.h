#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <optional>

namespace scylla {

/**
 * OEP detection method used
 */
enum class OEPDetectionMethod {
    None,
    TailJump,           // Large jump near end of section (common in packers)
    PushAdPopAd,        // PUSHAD/POPAD pattern matching
    EntropyTransition,  // High->Low entropy transition point
    FunctionPrologue,   // Standard function prologue detection (push ebp; mov ebp, esp)
    ImportReference,    // First reference to IAT
    CodePattern,        // Known unpacker stub patterns
    Heuristic,          // Combined heuristics
    Manual              // User-specified address
};

/**
 * OEP detection result
 */
struct OEPResult {
    bool found = false;
    uint64_t address = 0;
    OEPDetectionMethod method = OEPDetectionMethod::None;
    double confidence = 0.0;        // 0.0 - 1.0
    std::string description;

    // Supporting evidence
    bool hasValidPrologue = false;
    bool hasImportReferences = false;
    bool hasEntropyTransition = false;
    double entropyBefore = 0.0;
    double entropyAfter = 0.0;

    // Alternative candidates
    std::vector<uint64_t> alternatives;
};

/**
 * OEP detector configuration
 */
struct OEPDetectorConfig {
    // Enable/disable specific detection methods
    bool enableTailJump = true;
    bool enablePushAdPopAd = true;
    bool enableEntropyTransition = true;
    bool enableFunctionPrologue = true;
    bool enableImportReference = true;
    bool enableCodePattern = true;

    // Thresholds
    double minConfidence = 0.5;         // Minimum confidence to report
    size_t maxCandidates = 10;          // Maximum alternative candidates
    double entropyThreshold = 7.0;      // Entropy above this = packed
    size_t minUnpackingStubSize = 0x100;// Minimum size for unpacking stub

    // Search ranges
    uint64_t searchStart = 0;           // 0 = auto (entry point)
    uint64_t searchEnd = 0;             // 0 = auto (section end)
    size_t maxSearchSize = 0x100000;    // Maximum bytes to search (1MB)
};

/**
 * Memory region for analysis
 */
struct MemoryRegion {
    uint64_t address = 0;
    std::vector<uint8_t> data;
    bool executable = false;
    bool writable = false;
    std::string name;
    double entropy = 0.0;
};

/**
 * OEP Detector - Automated Original Entry Point Detection
 *
 * Implements multiple heuristics to automatically detect the OEP
 * in packed/obfuscated executables:
 *
 * 1. Tail Jump Detection: Large jumps near end of unpacking code
 * 2. PUSHAD/POPAD Pattern: Save/restore register state around unpacking
 * 3. Entropy Transition: High entropy (packed) -> Low entropy (code)
 * 4. Function Prologue: Standard function entry patterns
 * 5. Import Reference: First IAT access after unpacking
 * 6. Code Pattern: Known unpacker stub signatures
 */
class OEPDetector {
public:
    OEPDetector();
    ~OEPDetector();

    /**
     * Detect OEP in memory
     * @param region Memory region to analyze
     * @param config Detection configuration
     * @return Detection result with confidence and alternatives
     */
    OEPResult DetectOEP(const MemoryRegion& region, const OEPDetectorConfig& config = OEPDetectorConfig());

    /**
     * Detect OEP using multiple regions (for better context)
     * @param regions Multiple memory regions
     * @param iatAddress IAT address for import reference detection
     * @param config Detection configuration
     * @return Detection result
     */
    OEPResult DetectOEP(const std::vector<MemoryRegion>& regions, uint64_t iatAddress,
                       const OEPDetectorConfig& config = OEPDetectorConfig());

    /**
     * Validate a potential OEP address
     * @param address Address to validate
     * @param region Memory region containing the address
     * @return Confidence score (0.0 - 1.0)
     */
    double ValidateOEP(uint64_t address, const MemoryRegion& region);

    /**
     * Find tail jumps in code (common unpacker pattern)
     * @param region Memory region to search
     * @param minJumpDistance Minimum jump distance to consider
     * @return List of potential OEP addresses
     */
    std::vector<uint64_t> FindTailJumps(const MemoryRegion& region, size_t minJumpDistance = 0x1000);

    /**
     * Find PUSHAD/POPAD patterns (common in unpackers)
     * @param region Memory region to search
     * @return List of POPAD addresses (potential OEPs)
     */
    std::vector<uint64_t> FindPushAdPopAdPattern(const MemoryRegion& region);

    /**
     * Find entropy transitions (packed->unpacked boundary)
     * @param region Memory region to analyze
     * @param windowSize Size of entropy calculation window
     * @return List of transition points
     */
    std::vector<uint64_t> FindEntropyTransitions(const MemoryRegion& region, size_t windowSize = 0x1000);

    /**
     * Find function prologues (standard entry patterns)
     * @param region Memory region to search
     * @return List of prologue addresses
     */
    std::vector<uint64_t> FindFunctionPrologues(const MemoryRegion& region);

    /**
     * Find first import reference after address
     * @param region Memory region to search
     * @param startAddress Where to start searching
     * @param iatAddress IAT base address
     * @return First import reference address or 0
     */
    uint64_t FindFirstImportReference(const MemoryRegion& region, uint64_t startAddress, uint64_t iatAddress);

    /**
     * Calculate entropy for a data block
     * @param data Data to analyze
     * @param offset Offset in data
     * @param size Size of block
     * @return Entropy value (0.0 - 8.0)
     */
    static double CalculateEntropy(const std::vector<uint8_t>& data, size_t offset, size_t size);

    /**
     * Check if code matches known unpacker patterns
     * @param region Memory region
     * @param address Address to check
     * @return Pattern name if matched, empty otherwise
     */
    std::string MatchUnpackerPattern(const MemoryRegion& region, uint64_t address);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

/**
 * Known unpacker stub patterns
 */
namespace UnpackerPatterns {
    struct Pattern {
        std::string name;
        std::vector<uint8_t> signature;
        std::vector<bool> mask;     // true = must match, false = wildcard
        size_t oepOffset;           // Offset to OEP from pattern match
    };

    // Common packer patterns
    extern const Pattern UPX_STUB;
    extern const Pattern ASPACK_STUB;
    extern const Pattern THEMIDA_STUB;
    extern const Pattern VMPROTECT_STUB;
    extern const Pattern MPRESS_STUB;
    extern const Pattern PETITE_STUB;

    std::vector<Pattern> GetAllPatterns();
}

} // namespace scylla
