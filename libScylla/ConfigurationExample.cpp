/*
 * Configuration System Usage Examples
 *
 * Demonstrates how to use Scylla's configuration management system
 */

#include "Configuration.h"
#include <iostream>
#include <iomanip>

using namespace Scylla;

/*
 * Example 1: Using Built-in Profiles
 */
void BuiltinProfilesExample() {
    std::cout << "=== Built-in Profiles Example ===\n\n";

    auto& configMgr = ConfigurationManager::Instance();

    // List all available profiles
    std::cout << "Available profiles:\n";
    for (const auto& name : configMgr.ListProfiles()) {
        auto* profile = configMgr.GetProfile(name);
        if (profile) {
            std::cout << "  - " << std::left << std::setw(20) << name
                      << " : " << profile->description << "\n";
        }
    }
    std::cout << "\n";

    // Load quick-scan profile
    std::cout << "Loading 'quick-scan' profile...\n";
    if (configMgr.LoadProfile("quick-scan")) {
        const auto& profile = configMgr.GetCurrentProfile();
        std::cout << "✓ Profile loaded successfully\n";
        std::cout << "  Name: " << profile.name << "\n";
        std::cout << "  Description: " << profile.description << "\n";
        std::cout << "  Deep IAT scan: " << (profile.analysis.deepIATScan ? "YES" : "NO") << "\n";
        std::cout << "  Heuristic detection: " << (profile.packerDetection.enableHeuristicDetection ? "YES" : "NO") << "\n";
        std::cout << "  Verbosity: ";
        switch (profile.output.verbosity) {
            case OutputConfig::Verbosity::Minimal: std::cout << "Minimal\n"; break;
            case OutputConfig::Verbosity::Normal: std::cout << "Normal\n"; break;
            case OutputConfig::Verbosity::Detailed: std::cout << "Detailed\n"; break;
            case OutputConfig::Verbosity::Debug: std::cout << "Debug\n"; break;
        }
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

/*
 * Example 2: Creating Custom Profiles
 */
void CustomProfileExample() {
    std::cout << "=== Custom Profile Example ===\n\n";

    auto& configMgr = ConfigurationManager::Instance();

    // Create a custom profile for CTF challenges
    std::cout << "Creating custom 'ctf-challenge' profile...\n";

    if (configMgr.CreateProfile("ctf-challenge", "Optimized for CTF binary analysis")) {
        auto* profile = configMgr.GetProfile("ctf-challenge");

        // Customize settings
        profile->analysis.deepIATScan = true;
        profile->analysis.calculateSectionHashes = true;
        profile->packerDetection.enableHeuristicDetection = true;
        profile->packerDetection.detectCustomPackers = true;
        profile->performance.enableCaching = true;
        profile->output.defaultFormat = OutputConfig::Format::JSON;
        profile->output.showHashes = true;

        std::cout << "✓ Custom profile created\n";
        std::cout << "  Deep scan enabled\n";
        std::cout << "  Custom packer detection enabled\n";
        std::cout << "  JSON output format\n";

        // Save to disk
        configMgr.SetConfigDirectory(std::filesystem::temp_directory_path() / "scylla_config");
        if (configMgr.SaveProfile("ctf-challenge")) {
            std::cout << "✓ Profile saved to disk\n";
        }
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

/*
 * Example 3: Profile Comparison
 */
void ProfileComparisonExample() {
    std::cout << "=== Profile Comparison ===\n\n";

    auto& configMgr = ConfigurationManager::Instance();

    struct ProfileStats {
        std::string name;
        bool deepScan;
        bool heuristics;
        int cacheSize;
        std::string format;
    };

    std::vector<ProfileStats> stats;

    for (const auto& profileName : {"quick-scan", "deep-analysis", "malware-analysis", "performance"}) {
        auto* profile = configMgr.GetProfile(profileName);
        if (profile) {
            ProfileStats ps;
            ps.name = profileName;
            ps.deepScan = profile->analysis.deepIATScan;
            ps.heuristics = profile->packerDetection.enableHeuristicDetection;
            ps.cacheSize = profile->performance.apiCacheSize;

            switch (profile->output.defaultFormat) {
                case OutputConfig::Format::Text: ps.format = "Text"; break;
                case OutputConfig::Format::JSON: ps.format = "JSON"; break;
                case OutputConfig::Format::XML: ps.format = "XML"; break;
                case OutputConfig::Format::CSV: ps.format = "CSV"; break;
            }

            stats.push_back(ps);
        }
    }

    // Print comparison table
    std::cout << std::left
              << std::setw(20) << "Profile"
              << std::setw(12) << "Deep Scan"
              << std::setw(15) << "Heuristics"
              << std::setw(12) << "Cache Size"
              << "Format\n";
    std::cout << std::string(70, '-') << "\n";

    for (const auto& ps : stats) {
        std::cout << std::left
                  << std::setw(20) << ps.name
                  << std::setw(12) << (ps.deepScan ? "YES" : "NO")
                  << std::setw(15) << (ps.heuristics ? "YES" : "NO")
                  << std::setw(12) << ps.cacheSize
                  << ps.format << "\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

/*
 * Example 4: Dynamic Configuration
 */
void DynamicConfigurationExample() {
    std::cout << "=== Dynamic Configuration Example ===\n\n";

    auto& configMgr = ConfigurationManager::Instance();

    // Start with quick scan
    configMgr.LoadProfile("quick-scan");
    std::cout << "Starting with 'quick-scan' profile\n";

    auto& profile = configMgr.GetCurrentProfile();
    std::cout << "Initial entropy threshold: " << profile.packerDetection.entropyThreshold << "\n";
    std::cout << "Initial cache size: " << profile.performance.apiCacheSize << "\n\n";

    // Dynamically adjust settings based on file size
    size_t fileSize = 50 * 1024 * 1024;  // 50 MB file

    std::cout << "Analyzing large file (" << (fileSize / 1024 / 1024) << " MB)...\n";
    std::cout << "Adjusting configuration dynamically:\n";

    if (fileSize > 10 * 1024 * 1024) {
        // Large file - increase performance settings
        profile.performance.apiCacheSize = 2000;
        profile.performance.peCacheSize = 100;
        profile.analysis.memoryChunkSize = 2 * 1024 * 1024;  // 2 MB chunks
        std::cout << "  ✓ Increased cache sizes for large file\n";
        std::cout << "  ✓ Increased memory chunk size\n";
    }

    // Detect high entropy (likely packed)
    double entropy = 7.8;

    if (entropy > 7.5) {
        std::cout << "\nHigh entropy detected (" << entropy << "), adjusting for packed file:\n";
        profile.packerDetection.enableHeuristicDetection = true;
        profile.packerDetection.detectCustomPackers = true;
        profile.analysis.deepIATScan = true;
        std::cout << "  ✓ Enabled deep scanning\n";
        std::cout << "  ✓ Enabled heuristic detection\n";
    }

    std::cout << "\nFinal configuration:\n";
    std::cout << "  Cache size: " << profile.performance.apiCacheSize << "\n";
    std::cout << "  Deep scan: " << (profile.analysis.deepIATScan ? "YES" : "NO") << "\n";
    std::cout << "  Heuristics: " << (profile.packerDetection.enableHeuristicDetection ? "YES" : "NO") << "\n";

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

/*
 * Example 5: Profile Import/Export
 */
void ImportExportExample() {
    std::cout << "=== Import/Export Example ===\n\n";

    auto& configMgr = ConfigurationManager::Instance();

    // Set config directory
    std::filesystem::path configDir = std::filesystem::temp_directory_path() / "scylla_config_example";
    configMgr.SetConfigDirectory(configDir);
    EnsureConfigDirectoryExists(configDir);

    std::cout << "Config directory: " << configDir << "\n\n";

    // Export malware-analysis profile
    std::cout << "Exporting 'malware-analysis' profile...\n";
    std::filesystem::path exportPath = configDir / "exported_malware_profile.json";

    if (configMgr.ExportProfile("malware-analysis", exportPath)) {
        std::cout << "✓ Profile exported to: " << exportPath << "\n";
        std::cout << "  File size: " << std::filesystem::file_size(exportPath) << " bytes\n\n";
    }

    // Show JSON content (first few lines)
    std::cout << "Profile JSON (preview):\n";
    std::cout << std::string(60, '-') << "\n";

    auto* profile = configMgr.GetProfile("malware-analysis");
    if (profile) {
        std::string json = configMgr.SerializeToJSON(*profile);

        // Print first 10 lines
        std::istringstream iss(json);
        std::string line;
        int lineCount = 0;
        while (std::getline(iss, line) && lineCount < 10) {
            std::cout << line << "\n";
            lineCount++;
        }
        std::cout << "  ... (truncated)\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

/*
 * Example 6: Profile Validation
 */
void ValidationExample() {
    std::cout << "=== Profile Validation Example ===\n\n";

    auto& configMgr = ConfigurationManager::Instance();

    // Create profile with invalid settings
    ConfigurationProfile invalidProfile = configMgr.CreateDefaultProfile();
    invalidProfile.name = "invalid-test";
    invalidProfile.packerDetection.entropyThreshold = 10.0;  // Invalid: > 8.0
    invalidProfile.packerDetection.minConfidence = 150;      // Invalid: > 100
    invalidProfile.performance.maxCacheMemoryMB = 5;         // Invalid: < 10

    std::cout << "Validating profile with intentional errors...\n";
    std::vector<std::string> errors;

    if (!configMgr.ValidateProfile(invalidProfile, errors)) {
        std::cout << "✗ Validation failed with " << errors.size() << " errors:\n";
        for (size_t i = 0; i < errors.size(); i++) {
            std::cout << "  " << (i + 1) << ". " << errors[i] << "\n";
        }
    }

    std::cout << "\nValidating correct profile...\n";
    auto* validProfile = configMgr.GetProfile("default");
    errors.clear();

    if (configMgr.ValidateProfile(*validProfile, errors)) {
        std::cout << "✓ Validation passed - profile is valid\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

/*
 * Example 7: Profile Management Operations
 */
void ManagementOperationsExample() {
    std::cout << "=== Profile Management Example ===\n\n";

    auto& configMgr = ConfigurationManager::Instance();

    // Duplicate a profile
    std::cout << "Duplicating 'malware-analysis' profile...\n";
    if (configMgr.DuplicateProfile("malware-analysis", "my-malware-config")) {
        std::cout << "✓ Profile duplicated successfully\n";

        auto* profile = configMgr.GetProfile("my-malware-config");
        if (profile) {
            std::cout << "  Original: malware-analysis\n";
            std::cout << "  Copy: " << profile->name << "\n";
            std::cout << "  Description: " << profile->description << "\n\n";
        }
    }

    // Rename profile
    std::cout << "Renaming profile...\n";
    if (configMgr.RenameProfile("my-malware-config", "custom-malware")) {
        std::cout << "✓ Profile renamed: my-malware-config → custom-malware\n\n";
    }

    // List all profiles
    std::cout << "Current profiles:\n";
    for (const auto& name : configMgr.ListProfiles()) {
        std::cout << "  • " << name << "\n";
    }
    std::cout << "\n";

    // Delete custom profile
    std::cout << "Deleting 'custom-malware' profile...\n";
    if (configMgr.DeleteProfile("custom-malware")) {
        std::cout << "✓ Profile deleted\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

int main() {
    std::cout << "Scylla Configuration System Examples\n";
    std::cout << std::string(60, '=') << "\n\n";

    try {
        BuiltinProfilesExample();
        CustomProfileExample();
        ProfileComparisonExample();
        DynamicConfigurationExample();
        ImportExportExample();
        ValidationExample();
        ManagementOperationsExample();

        std::cout << "All examples completed successfully!\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
