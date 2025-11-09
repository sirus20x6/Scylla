#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <cstdint>

// Forward declarations
struct ImGuiContext;

namespace scylla {
namespace gui {

/**
 * Process information for UI display
 */
struct ProcessInfo {
    uint32_t pid = 0;
    std::string name;
    std::string path;
    uint64_t baseAddress = 0;
    uint32_t imageSize = 0;
    bool is64Bit = false;
    bool isManaged = false;  // .NET
};

/**
 * IAT analysis result for UI
 */
struct IATAnalysisResult {
    uint32_t foundAPIs = 0;
    uint32_t invalidAPIs = 0;
    uint32_t suspectAPIs = 0;
    bool completed = false;
    float progress = 0.0f;
    std::string status;
};

/**
 * Security analysis result for UI
 */
struct SecurityAnalysisResult {
    int score = 0;
    std::string riskLevel;
    bool dep = false;
    bool aslr = false;
    bool cfg = false;
    bool signed_ = false;
    std::vector<std::string> weaknesses;
    std::vector<std::string> recommendations;
};

/**
 * Symbol information for UI
 */
struct SymbolEntry {
    std::string name;
    uint64_t address = 0;
    std::string type;
    std::string module;
};

/**
 * UI Theme
 */
enum class Theme {
    Dark,
    Light,
    Classic
};

/**
 * Main Scylla GUI Application
 *
 * Features:
 * - Process selection and attachment
 * - IAT scanning and reconstruction
 * - Security analysis visualization
 * - Symbol browsing
 * - Configuration management
 * - Real-time analysis progress
 * - Export capabilities
 */
class ScyllaGUI {
public:
    ScyllaGUI();
    ~ScyllaGUI();

    /**
     * Initialize GUI
     *
     * @param width Window width
     * @param height Window height
     * @param title Window title
     * @return true if successful
     */
    bool Initialize(int width = 1280, int height = 720, const char* title = "Scylla - Advanced PE Analysis");

    /**
     * Run main GUI loop
     */
    void Run();

    /**
     * Shutdown GUI
     */
    void Shutdown();

    /**
     * Set UI theme
     *
     * @param theme Theme to apply
     */
    void SetTheme(Theme theme);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;

    // UI Rendering
    void RenderMainMenu();
    void RenderProcessSelector();
    void RenderIATAnalysis();
    void RenderSecurityAnalysis();
    void RenderSymbolBrowser();
    void RenderSettings();
    void RenderAbout();

    // Helper windows
    void RenderProcessList();
    void RenderAnalysisProgress();
    void RenderResultsTable();
    void RenderLogConsole();

    // Actions
    void AttachToProcess(uint32_t pid);
    void DetachFromProcess();
    void StartIATScan();
    void StopIATScan();
    void PerformSecurityAnalysis();
    void LoadSymbols();
    void ExportResults(const std::string& format);

    // State management
    bool IsProcessAttached() const;
    void UpdateProcessList();
    void UpdateAnalysisProgress();

    // UI State
    int currentTab = 0;
    bool showProcessList = false;
    bool showAbout = false;
    bool showSettings = false;

    // Data
    std::vector<ProcessInfo> processes;
    ProcessInfo* selectedProcess = nullptr;
    IATAnalysisResult iatResult;
    SecurityAnalysisResult securityResult;
    std::vector<SymbolEntry> symbols;
    std::vector<std::string> logMessages;

    // Settings
    Theme currentTheme = Theme::Dark;
    bool autoRefresh = true;
    int refreshInterval = 1000;  // ms
};

/**
 * Theme configuration
 */
namespace Themes {
    void ApplyDarkTheme();
    void ApplyLightTheme();
    void ApplyClassicTheme();
    void ApplyCustomColors(float hue, float saturation, float value);
}

/**
 * UI utility functions
 */
namespace UIUtils {
    /**
     * Draw colored badge
     */
    void ColoredBadge(const char* label, float r, float g, float b);

    /**
     * Draw progress ring
     */
    void ProgressRing(float progress, float radius, float thickness);

    /**
     * Draw security score gauge
     */
    void SecurityScoreGauge(int score, float radius);

    /**
     * Format file size
     */
    std::string FormatFileSize(uint64_t bytes);

    /**
     * Format address
     */
    std::string FormatAddress(uint64_t address, bool is64bit);

    /**
     * Get risk level color
     */
    void GetRiskLevelColor(const std::string& level, float& r, float& g, float& b);

    /**
     * Center window
     */
    void CenterNextWindow();

    /**
     * Tooltip with delay
     */
    void HelpMarker(const char* desc);
}

} // namespace gui
} // namespace scylla
