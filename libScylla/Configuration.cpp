/*
 * Scylla Configuration Management - Implementation
 */

#include "Configuration.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#else
#include <unistd.h>
#include <pwd.h>
#endif

namespace Scylla {

// ============================================================================
// Platform-Specific Helpers
// ============================================================================

std::filesystem::path GetDefaultConfigDirectory() {
#ifdef _WIN32
    wchar_t path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, path))) {
        return std::filesystem::path(path) / "Scylla" / "config";
    }
    return std::filesystem::path("C:\\Users\\Public\\Scylla\\config");
#else
    const char* home = getenv("HOME");
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        home = pw->pw_dir;
    }
    return std::filesystem::path(home) / ".config" / "scylla";
#endif
}

bool EnsureConfigDirectoryExists(const std::filesystem::path& directory) {
    try {
        if (!std::filesystem::exists(directory)) {
            return std::filesystem::create_directories(directory);
        }
        return true;
    } catch (...) {
        return false;
    }
}

// ============================================================================
// ConfigurationManager Implementation
// ============================================================================

ConfigurationManager::ConfigurationManager()
    : m_configDirectory(GetDefaultConfigDirectory())
{
    // Create default profile
    m_currentProfile = CreateDefaultProfile();

    // Load built-in profiles
    LoadBuiltinProfiles();
}

ConfigurationManager::~ConfigurationManager() {
}

ConfigurationManager& ConfigurationManager::Instance() {
    static ConfigurationManager instance;
    return instance;
}

void ConfigurationManager::LoadBuiltinProfiles() {
    // Default Profile
    ConfigurationProfile defaultProfile = CreateDefaultProfile();
    m_profiles["default"] = defaultProfile;

    // Quick Scan Profile
    ConfigurationProfile quickScan = CreateQuickScanProfile();
    m_profiles["quick-scan"] = quickScan;

    // Deep Analysis Profile
    ConfigurationProfile deepAnalysis = CreateDeepAnalysisProfile();
    m_profiles["deep-analysis"] = deepAnalysis;

    // Malware Analysis Profile
    ConfigurationProfile malwareAnalysis = CreateMalwareAnalysisProfile();
    m_profiles["malware-analysis"] = malwareAnalysis;

    // Performance Profile
    ConfigurationProfile performance = CreatePerformanceProfile();
    m_profiles["performance"] = performance;
}

ConfigurationProfile ConfigurationManager::CreateDefaultProfile() {
    ConfigurationProfile profile;
    profile.name = "default";
    profile.description = "Default balanced configuration";
    profile.version = "1.0";
    profile.createdAt = std::chrono::system_clock::now();
    profile.modifiedAt = profile.createdAt;

    // Analysis Config - Balanced
    profile.analysis.enableIATScanning = true;
    profile.analysis.deepIATScan = false;
    profile.analysis.iatScanThreads = 0;  // Auto-detect
    profile.analysis.resolveImportNames = true;
    profile.analysis.analyzeSections = true;
    profile.analysis.detectAnomalies = true;

    // Packer Detection - Standard
    profile.packerDetection.enableSignatureDetection = true;
    profile.packerDetection.enableHeuristicDetection = true;
    profile.packerDetection.entropyThreshold = 7.0;
    profile.packerDetection.minConfidence = 50;

    // Performance - Moderate
    profile.performance.enableParallelProcessing = true;
    profile.performance.enableCaching = true;
    profile.performance.apiCacheSize = 1000;
    profile.performance.peCacheSize = 50;

    // Output - Normal
    profile.output.defaultFormat = OutputConfig::Format::Text;
    profile.output.verbosity = OutputConfig::Verbosity::Normal;
    profile.output.showSections = true;
    profile.output.showImports = true;
    profile.output.showPacker = true;

    return profile;
}

ConfigurationProfile ConfigurationManager::CreateQuickScanProfile() {
    ConfigurationProfile profile;
    profile.name = "quick-scan";
    profile.description = "Fast scanning with minimal details";
    profile.version = "1.0";
    profile.createdAt = std::chrono::system_clock::now();
    profile.modifiedAt = profile.createdAt;

    // Analysis Config - Minimal
    profile.analysis.enableIATScanning = true;
    profile.analysis.deepIATScan = false;
    profile.analysis.iatScanThreads = 4;  // Fixed threads for speed
    profile.analysis.resolveImportNames = true;
    profile.analysis.analyzeSections = false;  // Skip section analysis
    profile.analysis.detectAnomalies = false;
    profile.analysis.scanTimeout = std::chrono::seconds(10);

    // Packer Detection - Signature only
    profile.packerDetection.enableSignatureDetection = true;
    profile.packerDetection.enableHeuristicDetection = false;  // Skip heuristics
    profile.packerDetection.stopOnFirstMatch = true;  // Fast exit

    // Performance - Maximum speed
    profile.performance.enableParallelProcessing = true;
    profile.performance.workerThreads = 8;
    profile.performance.enableCaching = true;
    profile.performance.apiCacheSize = 500;  // Smaller cache

    // Output - Minimal
    profile.output.defaultFormat = OutputConfig::Format::Text;
    profile.output.verbosity = OutputConfig::Verbosity::Minimal;
    profile.output.showSections = false;
    profile.output.showResources = false;
    profile.output.showHashes = false;

    return profile;
}

ConfigurationProfile ConfigurationManager::CreateDeepAnalysisProfile() {
    ConfigurationProfile profile;
    profile.name = "deep-analysis";
    profile.description = "Comprehensive analysis with all features";
    profile.version = "1.0";
    profile.createdAt = std::chrono::system_clock::now();
    profile.modifiedAt = profile.createdAt;

    // Analysis Config - Maximum depth
    profile.analysis.enableIATScanning = true;
    profile.analysis.deepIATScan = true;  // Deep scan enabled
    profile.analysis.iatScanThreads = 0;
    profile.analysis.resolveImportNames = true;
    profile.analysis.validateImportAddresses = true;
    profile.analysis.rebuildForwarders = true;
    profile.analysis.analyzeSections = true;
    profile.analysis.calculateSectionHashes = true;  // Calculate hashes
    profile.analysis.detectAnomalies = true;
    profile.analysis.scanFullMemory = true;  // Scan all memory
    profile.analysis.scanTimeout = std::chrono::seconds(300);  // 5 min timeout

    // Packer Detection - All methods
    profile.packerDetection.enableSignatureDetection = true;
    profile.packerDetection.enableHeuristicDetection = true;
    profile.packerDetection.enableEntropyAnalysis = true;
    profile.packerDetection.analyzeOverlay = true;
    profile.packerDetection.analyzeResources = true;
    profile.packerDetection.detectCustomPackers = true;
    profile.packerDetection.stopOnFirstMatch = false;  // Test all signatures

    // Performance - Quality over speed
    profile.performance.enableParallelProcessing = true;
    profile.performance.enableCaching = true;
    profile.performance.apiCacheSize = 2000;
    profile.performance.peCacheSize = 100;
    profile.performance.maxCacheMemoryMB = 500;

    // Output - Detailed
    profile.output.defaultFormat = OutputConfig::Format::JSON;
    profile.output.verbosity = OutputConfig::Verbosity::Detailed;
    profile.output.showSections = true;
    profile.output.showImports = true;
    profile.output.showExports = true;
    profile.output.showResources = true;
    profile.output.showSecurity = true;
    profile.output.showPacker = true;
    profile.output.showHashes = true;
    profile.output.prettyPrint = true;

    return profile;
}

ConfigurationProfile ConfigurationManager::CreateMalwareAnalysisProfile() {
    ConfigurationProfile profile;
    profile.name = "malware-analysis";
    profile.description = "Optimized for analyzing packed malware samples";
    profile.version = "1.0";
    profile.createdAt = std::chrono::system_clock::now();
    profile.modifiedAt = profile.createdAt;

    // Analysis Config - Security focused
    profile.analysis.enableIATScanning = true;
    profile.analysis.deepIATScan = true;
    profile.analysis.resolveImportNames = true;
    profile.analysis.validateImportAddresses = true;
    profile.analysis.analyzeSections = true;
    profile.analysis.calculateSectionHashes = true;
    profile.analysis.detectAnomalies = true;

    // Packer Detection - Aggressive
    profile.packerDetection.enableSignatureDetection = true;
    profile.packerDetection.enableHeuristicDetection = true;
    profile.packerDetection.enableEntropyAnalysis = true;
    profile.packerDetection.entropyThreshold = 6.5;  // Lower threshold
    profile.packerDetection.minConfidence = 40;  // Lower confidence threshold
    profile.packerDetection.suspicionThreshold = 40;
    profile.packerDetection.analyzeOverlay = true;
    profile.packerDetection.analyzeResources = true;
    profile.packerDetection.detectCustomPackers = true;

    // Performance - Balanced for malware
    profile.performance.enableParallelProcessing = true;
    profile.performance.enableCaching = true;
    profile.performance.apiCacheSize = 1500;
    profile.performance.peCacheSize = 100;

    // Output - Structured for reporting
    profile.output.defaultFormat = OutputConfig::Format::JSON;
    profile.output.verbosity = OutputConfig::Verbosity::Detailed;
    profile.output.showSections = true;
    profile.output.showImports = true;
    profile.output.showExports = true;
    profile.output.showResources = true;
    profile.output.showSecurity = true;
    profile.output.showPacker = true;
    profile.output.showHashes = true;
    profile.output.prettyPrint = true;
    profile.output.timestampFiles = true;  // Timestamp for tracking

    return profile;
}

ConfigurationProfile ConfigurationManager::CreatePerformanceProfile() {
    ConfigurationProfile profile;
    profile.name = "performance";
    profile.description = "Maximum performance for batch processing";
    profile.version = "1.0";
    profile.createdAt = std::chrono::system_clock::now();
    profile.modifiedAt = profile.createdAt;

    // Analysis Config - Essential only
    profile.analysis.enableIATScanning = true;
    profile.analysis.deepIATScan = false;
    profile.analysis.iatScanThreads = 0;  // Auto-detect for max cores
    profile.analysis.resolveImportNames = true;
    profile.analysis.analyzeSections = true;
    profile.analysis.detectAnomalies = false;  // Skip anomaly detection

    // Packer Detection - Fast methods only
    profile.packerDetection.enableSignatureDetection = true;
    profile.packerDetection.enableHeuristicDetection = false;  // Skip slow heuristics
    profile.packerDetection.stopOnFirstMatch = true;

    // Performance - Maximum
    profile.performance.enableParallelProcessing = true;
    profile.performance.workerThreads = 0;  // Use all cores
    profile.performance.enableCaching = true;
    profile.performance.apiCacheSize = 5000;  // Large cache
    profile.performance.peCacheSize = 200;
    profile.performance.maxCacheMemoryMB = 1000;
    profile.performance.useMemoryMapping = true;

    // Output - Minimal overhead
    profile.output.defaultFormat = OutputConfig::Format::JSON;
    profile.output.verbosity = OutputConfig::Verbosity::Normal;
    profile.output.showSections = false;
    profile.output.showResources = false;
    profile.output.prettyPrint = false;  // Compact JSON

    return profile;
}

bool ConfigurationManager::LoadProfile(const std::string& name) {
    // Check if profile exists in memory
    auto it = m_profiles.find(name);
    if (it != m_profiles.end()) {
        m_currentProfile = it->second;
        return true;
    }

    // Try loading from file
    std::filesystem::path profilePath = GetProfilePath(name);
    return LoadProfileFromFile(profilePath);
}

bool ConfigurationManager::LoadProfileFromFile(const std::filesystem::path& path) {
    try {
        std::ifstream file(path);
        if (!file.is_open()) {
            return false;
        }

        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string json = buffer.str();

        ConfigurationProfile profile;
        if (DeserializeFromJSON(json, profile)) {
            m_currentProfile = profile;
            m_profiles[profile.name] = profile;
            return true;
        }

        return false;
    } catch (...) {
        return false;
    }
}

bool ConfigurationManager::SaveProfile(const std::string& name) {
    std::filesystem::path profilePath = GetProfilePath(name);
    return SaveProfileToFile(profilePath);
}

bool ConfigurationManager::SaveProfileToFile(const std::filesystem::path& path) {
    try {
        // Ensure directory exists
        std::filesystem::path directory = path.parent_path();
        if (!EnsureConfigDirectoryExists(directory)) {
            return false;
        }

        std::string json = SerializeToJSON(m_currentProfile);

        std::ofstream file(path);
        if (!file.is_open()) {
            return false;
        }

        file << json;
        return true;
    } catch (...) {
        return false;
    }
}

bool ConfigurationManager::CreateProfile(const std::string& name, const std::string& description) {
    if (ProfileExists(name)) {
        return false;
    }

    ConfigurationProfile profile = CreateDefaultProfile();
    profile.name = name;
    profile.description = description;
    profile.createdAt = std::chrono::system_clock::now();
    profile.modifiedAt = profile.createdAt;

    m_profiles[name] = profile;
    return true;
}

bool ConfigurationManager::DeleteProfile(const std::string& name) {
    // Don't delete built-in profiles
    if (name == "default" || name == "quick-scan" ||
        name == "deep-analysis" || name == "malware-analysis" ||
        name == "performance") {
        return false;
    }

    auto it = m_profiles.find(name);
    if (it != m_profiles.end()) {
        m_profiles.erase(it);

        // Try to delete file
        std::filesystem::path profilePath = GetProfilePath(name);
        try {
            if (std::filesystem::exists(profilePath)) {
                std::filesystem::remove(profilePath);
            }
        } catch (...) {
            // Ignore file deletion errors
        }

        return true;
    }

    return false;
}

bool ConfigurationManager::RenameProfile(const std::string& oldName, const std::string& newName) {
    auto it = m_profiles.find(oldName);
    if (it == m_profiles.end() || ProfileExists(newName)) {
        return false;
    }

    ConfigurationProfile profile = it->second;
    profile.name = newName;
    profile.modifiedAt = std::chrono::system_clock::now();

    m_profiles.erase(it);
    m_profiles[newName] = profile;

    return true;
}

bool ConfigurationManager::DuplicateProfile(const std::string& sourceName, const std::string& newName) {
    auto it = m_profiles.find(sourceName);
    if (it == m_profiles.end() || ProfileExists(newName)) {
        return false;
    }

    ConfigurationProfile profile = it->second;
    profile.name = newName;
    profile.description = "Copy of " + sourceName;
    profile.createdAt = std::chrono::system_clock::now();
    profile.modifiedAt = profile.createdAt;

    m_profiles[newName] = profile;
    return true;
}

std::vector<std::string> ConfigurationManager::ListProfiles() const {
    std::vector<std::string> names;
    for (const auto& pair : m_profiles) {
        names.push_back(pair.first);
    }
    return names;
}

bool ConfigurationManager::ProfileExists(const std::string& name) const {
    return m_profiles.find(name) != m_profiles.end();
}

ConfigurationProfile* ConfigurationManager::GetProfile(const std::string& name) {
    auto it = m_profiles.find(name);
    return (it != m_profiles.end()) ? &it->second : nullptr;
}

const ConfigurationProfile* ConfigurationManager::GetProfile(const std::string& name) const {
    auto it = m_profiles.find(name);
    return (it != m_profiles.end()) ? &it->second : nullptr;
}

void ConfigurationManager::SetCurrentProfile(const ConfigurationProfile& profile) {
    m_currentProfile = profile;
    m_currentProfile.modifiedAt = std::chrono::system_clock::now();
}

void ConfigurationManager::SetConfigDirectory(const std::filesystem::path& directory) {
    m_configDirectory = directory;
    EnsureConfigDirectoryExists(directory);
}

std::filesystem::path ConfigurationManager::GetProfilePath(const std::string& name) const {
    return m_configDirectory / (name + ".json");
}

bool ConfigurationManager::ValidateProfile(const ConfigurationProfile& profile, std::vector<std::string>& errors) {
    errors.clear();

    // Validate name
    if (profile.name.empty()) {
        errors.push_back("Profile name cannot be empty");
    }

    // Validate thresholds
    if (profile.packerDetection.entropyThreshold < 0.0 || profile.packerDetection.entropyThreshold > 8.0) {
        errors.push_back("Entropy threshold must be between 0.0 and 8.0");
    }

    if (profile.packerDetection.minConfidence < 0 || profile.packerDetection.minConfidence > 100) {
        errors.push_back("Minimum confidence must be between 0 and 100");
    }

    // Validate performance settings
    if (profile.performance.maxCacheMemoryMB < 10) {
        errors.push_back("Cache memory must be at least 10 MB");
    }

    return errors.empty();
}

bool ConfigurationManager::ImportProfile(const std::filesystem::path& path, std::string& profileName) {
    ConfigurationProfile profile;
    if (!LoadProfileFromFile(path)) {
        return false;
    }

    profileName = m_currentProfile.name;
    m_profiles[profileName] = m_currentProfile;
    return true;
}

bool ConfigurationManager::ExportProfile(const std::string& name, const std::filesystem::path& path) {
    auto it = m_profiles.find(name);
    if (it == m_profiles.end()) {
        return false;
    }

    ConfigurationProfile backup = m_currentProfile;
    m_currentProfile = it->second;
    bool result = SaveProfileToFile(path);
    m_currentProfile = backup;

    return result;
}

std::string ConfigurationManager::SerializeToJSON(const ConfigurationProfile& profile) {
    std::ostringstream json;

    json << "{\n";
    json << "  \"name\": \"" << profile.name << "\",\n";
    json << "  \"description\": \"" << profile.description << "\",\n";
    json << "  \"version\": \"" << profile.version << "\",\n";

    // Analysis Config
    json << "  \"analysis\": {\n";
    json << "    \"enableIATScanning\": " << (profile.analysis.enableIATScanning ? "true" : "false") << ",\n";
    json << "    \"deepIATScan\": " << (profile.analysis.deepIATScan ? "true" : "false") << ",\n";
    json << "    \"iatScanThreads\": " << profile.analysis.iatScanThreads << ",\n";
    json << "    \"maxIATEntries\": " << profile.analysis.maxIATEntries << ",\n";
    json << "    \"resolveImportNames\": " << (profile.analysis.resolveImportNames ? "true" : "false") << ",\n";
    json << "    \"validateImportAddresses\": " << (profile.analysis.validateImportAddresses ? "true" : "false") << ",\n";
    json << "    \"rebuildForwarders\": " << (profile.analysis.rebuildForwarders ? "true" : "false") << ",\n";
    json << "    \"analyzeSections\": " << (profile.analysis.analyzeSections ? "true" : "false") << ",\n";
    json << "    \"calculateSectionHashes\": " << (profile.analysis.calculateSectionHashes ? "true" : "false") << ",\n";
    json << "    \"detectAnomalies\": " << (profile.analysis.detectAnomalies ? "true" : "false") << ",\n";
    json << "    \"scanFullMemory\": " << (profile.analysis.scanFullMemory ? "true" : "false") << ",\n";
    json << "    \"memoryChunkSize\": " << profile.analysis.memoryChunkSize << ",\n";
    json << "    \"scanTimeout\": " << profile.analysis.scanTimeout.count() << ",\n";
    json << "    \"apiResolveTimeout\": " << profile.analysis.apiResolveTimeout.count() << "\n";
    json << "  },\n";

    // Packer Detection Config
    json << "  \"packerDetection\": {\n";
    json << "    \"enableSignatureDetection\": " << (profile.packerDetection.enableSignatureDetection ? "true" : "false") << ",\n";
    json << "    \"enableHeuristicDetection\": " << (profile.packerDetection.enableHeuristicDetection ? "true" : "false") << ",\n";
    json << "    \"enableEntropyAnalysis\": " << (profile.packerDetection.enableEntropyAnalysis ? "true" : "false") << ",\n";
    json << "    \"entropyThreshold\": " << profile.packerDetection.entropyThreshold << ",\n";
    json << "    \"minConfidence\": " << profile.packerDetection.minConfidence << ",\n";
    json << "    \"suspicionThreshold\": " << profile.packerDetection.suspicionThreshold << ",\n";
    json << "    \"signatureDatabasePath\": \"" << profile.packerDetection.signatureDatabasePath << "\",\n";
    json << "    \"autoUpdateSignatures\": " << (profile.packerDetection.autoUpdateSignatures ? "true" : "false") << ",\n";
    json << "    \"analyzeOverlay\": " << (profile.packerDetection.analyzeOverlay ? "true" : "false") << ",\n";
    json << "    \"analyzeResources\": " << (profile.packerDetection.analyzeResources ? "true" : "false") << ",\n";
    json << "    \"detectCustomPackers\": " << (profile.packerDetection.detectCustomPackers ? "true" : "false") << ",\n";
    json << "    \"maxSignaturesToTest\": " << profile.packerDetection.maxSignaturesToTest << ",\n";
    json << "    \"stopOnFirstMatch\": " << (profile.packerDetection.stopOnFirstMatch ? "true" : "false") << "\n";
    json << "  },\n";

    // Performance Config
    json << "  \"performance\": {\n";
    json << "    \"workerThreads\": " << profile.performance.workerThreads << ",\n";
    json << "    \"enableParallelProcessing\": " << (profile.performance.enableParallelProcessing ? "true" : "false") << ",\n";
    json << "    \"enableCaching\": " << (profile.performance.enableCaching ? "true" : "false") << ",\n";
    json << "    \"apiCacheSize\": " << profile.performance.apiCacheSize << ",\n";
    json << "    \"peCacheSize\": " << profile.performance.peCacheSize << ",\n";
    json << "    \"cacheTTL\": " << profile.performance.cacheTTL.count() << ",\n";
    json << "    \"maxCacheMemoryMB\": " << profile.performance.maxCacheMemoryMB << ",\n";
    json << "    \"useMemoryMapping\": " << (profile.performance.useMemoryMapping ? "true" : "false") << ",\n";
    json << "    \"ioBufferSize\": " << profile.performance.ioBufferSize << ",\n";
    json << "    \"asyncIO\": " << (profile.performance.asyncIO ? "true" : "false") << "\n";
    json << "  },\n";

    // Output Config
    json << "  \"output\": {\n";
    json << "    \"defaultFormat\": \"";
    switch (profile.output.defaultFormat) {
        case OutputConfig::Format::Text: json << "text"; break;
        case OutputConfig::Format::JSON: json << "json"; break;
        case OutputConfig::Format::XML: json << "xml"; break;
        case OutputConfig::Format::CSV: json << "csv"; break;
    }
    json << "\",\n";

    json << "    \"verbosity\": \"";
    switch (profile.output.verbosity) {
        case OutputConfig::Verbosity::Minimal: json << "minimal"; break;
        case OutputConfig::Verbosity::Normal: json << "normal"; break;
        case OutputConfig::Verbosity::Detailed: json << "detailed"; break;
        case OutputConfig::Verbosity::Debug: json << "debug"; break;
    }
    json << "\",\n";

    json << "    \"showSections\": " << (profile.output.showSections ? "true" : "false") << ",\n";
    json << "    \"showImports\": " << (profile.output.showImports ? "true" : "false") << ",\n";
    json << "    \"showExports\": " << (profile.output.showExports ? "true" : "false") << ",\n";
    json << "    \"showResources\": " << (profile.output.showResources ? "true" : "false") << ",\n";
    json << "    \"showSecurity\": " << (profile.output.showSecurity ? "true" : "false") << ",\n";
    json << "    \"showPacker\": " << (profile.output.showPacker ? "true" : "false") << ",\n";
    json << "    \"showHashes\": " << (profile.output.showHashes ? "true" : "false") << ",\n";
    json << "    \"colorOutput\": " << (profile.output.colorOutput ? "true" : "false") << ",\n";
    json << "    \"prettyPrint\": " << (profile.output.prettyPrint ? "true" : "false") << ",\n";
    json << "    \"indentSize\": " << profile.output.indentSize << ",\n";
    json << "    \"outputDirectory\": \"" << profile.output.outputDirectory << "\",\n";
    json << "    \"timestampFiles\": " << (profile.output.timestampFiles ? "true" : "false") << ",\n";
    json << "    \"overwriteExisting\": " << (profile.output.overwriteExisting ? "true" : "false") << "\n";
    json << "  }\n";

    json << "}\n";

    return json.str();
}

bool ConfigurationManager::DeserializeFromJSON(const std::string& json, ConfigurationProfile& profile) {
    // Simple JSON parsing (in a real implementation, use a proper JSON library)
    // For now, this is a placeholder that loads defaults
    // TODO: Implement proper JSON parsing or integrate a JSON library

    profile = CreateDefaultProfile();

    // Extract name from JSON (simple extraction)
    size_t namePos = json.find("\"name\":");
    if (namePos != std::string::npos) {
        size_t start = json.find("\"", namePos + 7) + 1;
        size_t end = json.find("\"", start);
        if (start != std::string::npos && end != std::string::npos) {
            profile.name = json.substr(start, end - start);
        }
    }

    return true;
}

// ============================================================================
// ConfigurationApplier Implementation
// ============================================================================

void ConfigurationApplier::ApplyAnalysisConfig(const AnalysisConfig& config) {
    // Apply analysis configuration to relevant components
    // This would set global configuration values
}

void ConfigurationApplier::ApplyPackerConfig(const PackerDetectionConfig& config) {
    // Apply packer detection configuration
}

void ConfigurationApplier::ApplyPerformanceConfig(const PerformanceConfig& config) {
    // Apply performance configuration
}

void ConfigurationApplier::ApplyOutputConfig(const OutputConfig& config) {
    // Apply output configuration
}

void ConfigurationApplier::ApplyFullProfile(const ConfigurationProfile& profile) {
    ApplyAnalysisConfig(profile.analysis);
    ApplyPackerConfig(profile.packerDetection);
    ApplyPerformanceConfig(profile.performance);
    ApplyOutputConfig(profile.output);
}

} // namespace Scylla
