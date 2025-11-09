/*
 * Scylla Configuration Management System
 *
 * Provides flexible configuration profiles for:
 * - Analysis settings
 * - Packer detection parameters
 * - Performance tuning
 * - Output formatting
 */

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <filesystem>
#include <chrono>

namespace Scylla {

// ============================================================================
// Configuration Structures
// ============================================================================

/*
 * Analysis Configuration
 *
 * Controls how PE files are analyzed
 */
struct AnalysisConfig {
    // IAT Scanning
    bool enableIATScanning = true;
    bool deepIATScan = false;          // More thorough but slower
    size_t iatScanThreads = 0;         // 0 = auto-detect
    size_t maxIATEntries = 10000;      // Safety limit

    // Import Resolution
    bool resolveImportNames = true;
    bool validateImportAddresses = true;
    bool rebuildForwarders = true;

    // Section Analysis
    bool analyzeSections = true;
    bool calculateSectionHashes = false;
    bool detectAnomalies = true;

    // Memory Analysis
    bool scanFullMemory = false;       // Scan all memory regions
    size_t memoryChunkSize = 1024 * 1024;  // 1 MB chunks

    // Timeout Settings
    std::chrono::seconds scanTimeout{60};
    std::chrono::seconds apiResolveTimeout{10};
};

/*
 * Packer Detection Configuration
 *
 * Controls packer detection behavior
 */
struct PackerDetectionConfig {
    // Detection Methods
    bool enableSignatureDetection = true;
    bool enableHeuristicDetection = true;
    bool enableEntropyAnalysis = true;

    // Thresholds
    double entropyThreshold = 7.0;     // Shannon entropy threshold
    int minConfidence = 50;            // Minimum confidence to report
    int suspicionThreshold = 50;       // Heuristic suspicion score

    // Signature Database
    std::string signatureDatabasePath;  // Empty = use built-in
    bool autoUpdateSignatures = false;

    // Analysis Depth
    bool analyzeOverlay = true;
    bool analyzeResources = true;
    bool detectCustomPackers = true;

    // Performance
    size_t maxSignaturesToTest = 100;
    bool stopOnFirstMatch = false;     // Continue testing for better match
};

/*
 * Performance Configuration
 *
 * Controls performance-related settings
 */
struct PerformanceConfig {
    // Threading
    size_t workerThreads = 0;          // 0 = auto-detect
    bool enableParallelProcessing = true;

    // Caching
    bool enableCaching = true;
    size_t apiCacheSize = 1000;        // Number of API entries
    size_t peCacheSize = 50;           // Number of PE analyses
    std::chrono::minutes cacheTTL{60}; // Time to live
    size_t maxCacheMemoryMB = 200;     // Memory limit

    // I/O Optimization
    bool useMemoryMapping = true;      // Memory-mapped file I/O
    size_t ioBufferSize = 64 * 1024;   // 64 KB
    bool asyncIO = false;              // Asynchronous I/O
};

/*
 * Output Configuration
 *
 * Controls output formatting and content
 */
struct OutputConfig {
    // Format
    enum class Format {
        Text,
        JSON,
        XML,
        CSV
    };
    Format defaultFormat = Format::Text;

    // Verbosity
    enum class Verbosity {
        Minimal,    // Only critical info
        Normal,     // Standard output
        Detailed,   // Include extra details
        Debug       // Everything including debug info
    };
    Verbosity verbosity = Verbosity::Normal;

    // Content Filters
    bool showSections = true;
    bool showImports = true;
    bool showExports = true;
    bool showResources = false;
    bool showSecurity = true;
    bool showPacker = true;
    bool showHashes = false;

    // Formatting
    bool colorOutput = true;           // ANSI colors (terminal)
    bool prettyPrint = true;           // Formatted JSON/XML
    int indentSize = 2;                // Spaces for indentation

    // File Output
    std::string outputDirectory;       // Empty = current directory
    bool timestampFiles = false;       // Add timestamp to filenames
    bool overwriteExisting = false;    // Overwrite or append
};

/*
 * Complete Configuration Profile
 *
 * Combines all configuration settings
 */
struct ConfigurationProfile {
    std::string name;
    std::string description;
    std::string version = "1.0";

    AnalysisConfig analysis;
    PackerDetectionConfig packerDetection;
    PerformanceConfig performance;
    OutputConfig output;

    // Metadata
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point modifiedAt;
    std::unordered_map<std::string, std::string> metadata;
};

// ============================================================================
// Configuration Manager
// ============================================================================

/*
 * Configuration Manager
 *
 * Manages loading, saving, and applying configuration profiles
 */
class ConfigurationManager {
public:
    ConfigurationManager();
    ~ConfigurationManager();

    // Singleton Access
    static ConfigurationManager& Instance();

    // Profile Management
    bool LoadProfile(const std::string& name);
    bool LoadProfileFromFile(const std::filesystem::path& path);
    bool SaveProfile(const std::string& name);
    bool SaveProfileToFile(const std::filesystem::path& path);

    // Profile Operations
    bool CreateProfile(const std::string& name, const std::string& description);
    bool DeleteProfile(const std::string& name);
    bool RenameProfile(const std::string& oldName, const std::string& newName);
    bool DuplicateProfile(const std::string& sourceName, const std::string& newName);

    // Profile Queries
    std::vector<std::string> ListProfiles() const;
    bool ProfileExists(const std::string& name) const;
    ConfigurationProfile* GetProfile(const std::string& name);
    const ConfigurationProfile* GetProfile(const std::string& name) const;

    // Current Configuration
    ConfigurationProfile& GetCurrentProfile() { return m_currentProfile; }
    const ConfigurationProfile& GetCurrentProfile() const { return m_currentProfile; }
    void SetCurrentProfile(const ConfigurationProfile& profile);

    // Built-in Profiles
    void LoadBuiltinProfiles();
    ConfigurationProfile CreateDefaultProfile();
    ConfigurationProfile CreateQuickScanProfile();
    ConfigurationProfile CreateDeepAnalysisProfile();
    ConfigurationProfile CreateMalwareAnalysisProfile();
    ConfigurationProfile CreatePerformanceProfile();

    // Configuration Directory
    void SetConfigDirectory(const std::filesystem::path& directory);
    std::filesystem::path GetConfigDirectory() const { return m_configDirectory; }

    // Validation
    bool ValidateProfile(const ConfigurationProfile& profile, std::vector<std::string>& errors);

    // Import/Export
    bool ImportProfile(const std::filesystem::path& path, std::string& profileName);
    bool ExportProfile(const std::string& name, const std::filesystem::path& path);

    // JSON Serialization
    std::string SerializeToJSON(const ConfigurationProfile& profile);
    bool DeserializeFromJSON(const std::string& json, ConfigurationProfile& profile);

private:
    ConfigurationProfile m_currentProfile;
    std::unordered_map<std::string, ConfigurationProfile> m_profiles;
    std::filesystem::path m_configDirectory;

    // Helper Methods
    std::filesystem::path GetProfilePath(const std::string& name) const;
    bool LoadProfileFromJSON(const std::string& json, ConfigurationProfile& profile);
    bool SaveProfileToJSON(const ConfigurationProfile& profile, std::string& json);

    // JSON Parsing Helpers
    void ParseAnalysisConfig(const std::string& json, AnalysisConfig& config);
    void ParsePackerConfig(const std::string& json, PackerDetectionConfig& config);
    void ParsePerformanceConfig(const std::string& json, PerformanceConfig& config);
    void ParseOutputConfig(const std::string& json, OutputConfig& config);

    // JSON Generation Helpers
    void GenerateAnalysisJSON(const AnalysisConfig& config, std::string& json);
    void GeneratePackerJSON(const PackerDetectionConfig& config, std::string& json);
    void GeneratePerformanceJSON(const PerformanceConfig& config, std::string& json);
    void GenerateOutputJSON(const OutputConfig& config, std::string& json);
};

// ============================================================================
// Configuration Helper Functions
// ============================================================================

/*
 * Get configuration directory based on platform
 */
std::filesystem::path GetDefaultConfigDirectory();

/*
 * Create configuration directory if it doesn't exist
 */
bool EnsureConfigDirectoryExists(const std::filesystem::path& directory);

/*
 * Apply configuration to various system components
 */
class ConfigurationApplier {
public:
    static void ApplyAnalysisConfig(const AnalysisConfig& config);
    static void ApplyPackerConfig(const PackerDetectionConfig& config);
    static void ApplyPerformanceConfig(const PerformanceConfig& config);
    static void ApplyOutputConfig(const OutputConfig& config);
    static void ApplyFullProfile(const ConfigurationProfile& profile);
};

} // namespace Scylla
