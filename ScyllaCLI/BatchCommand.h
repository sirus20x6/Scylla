/*
 * Scylla Batch Processing Command
 *
 * Process multiple files in parallel with aggregated reporting
 */

#pragma once

#include <string>
#include <vector>
#include <filesystem>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>

namespace Scylla {
namespace CLI {

/*
 * Batch processing configuration
 */
struct BatchConfig {
    // Input sources
    std::vector<std::filesystem::path> files;     // Explicit file list
    std::vector<std::filesystem::path> directories; // Directories to scan
    std::vector<std::string> patterns;            // File patterns (*.exe, *.dll)

    // Filtering
    bool recursive;                    // Recursive directory scan
    size_t minFileSize;                // Minimum file size (bytes)
    size_t maxFileSize;                // Maximum file size (bytes)
    std::vector<std::string> excludePatterns; // Exclude patterns

    // Processing
    size_t maxThreads;                 // Maximum parallel workers (0 = auto)
    size_t batchSize;                  // Files per batch
    bool stopOnError;                  // Stop on first error
    bool skipErrors;                   // Continue on errors

    // Output
    std::filesystem::path outputDirectory;  // Output directory
    bool createSubdirectories;         // Create subdirs per file
    bool aggregateReports;             // Single combined report
    std::string reportFormat;          // json, xml, csv, text

    // Resume
    bool enableResume;                 // Enable resume support
    std::filesystem::path resumeFile;  // Resume state file

    // Progress
    bool showProgress;                 // Show progress bar
    bool verbose;                      // Verbose output

    // Operation mode
    enum class Mode {
        Analyze,    // Batch analysis
        Dump,       // Batch dumping
        Rebuild,    // Batch rebuilding
        Custom      // Custom operation
    };
    Mode mode = Mode::Analyze;

    // Custom operation callback
    using CustomOperation = std::function<bool(const std::filesystem::path&)>;
    CustomOperation customOp;
};

/*
 * Per-file processing result
 */
struct FileResult {
    std::filesystem::path filePath;
    bool success;
    std::string errorMessage;

    // Timing
    std::chrono::milliseconds processingTime;

    // File info
    size_t fileSize;
    std::string fileHash;  // SHA-256

    // Analysis results (if mode == Analyze)
    std::string architecture;
    std::string packerDetected;
    size_t importsFound;
    size_t sectionsFound;

    // Warnings
    std::vector<std::string> warnings;
};

/*
 * Batch processing statistics
 */
struct BatchStatistics {
    // Counts
    size_t totalFiles;
    size_t processedFiles;
    size_t successfulFiles;
    size_t failedFiles;
    size_t skippedFiles;

    // Timing
    std::chrono::milliseconds totalTime;
    std::chrono::milliseconds averageTime;
    double filesPerSecond;

    // Data
    size_t totalBytes;
    size_t averageFileSize;

    // Detection stats (for analysis mode)
    std::map<std::string, size_t> packerDistribution;
    std::map<std::string, size_t> architectureDistribution;

    // Error tracking
    std::map<std::string, size_t> errorTypes;
};

/*
 * Batch processing result
 */
struct BatchResult {
    bool success;
    BatchStatistics statistics;
    std::vector<FileResult> results;
    std::filesystem::path reportPath;

    // Detailed errors
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
};

/*
 * Progress callback
 */
using ProgressCallback = std::function<void(size_t processed, size_t total, const std::string& currentFile)>;

/*
 * Batch Command
 *
 * Handles batch processing of multiple files
 */
class BatchCommand {
public:
    BatchCommand();
    ~BatchCommand();

    // Execute batch operation
    BatchResult Execute(const BatchConfig& config);

    // Convenience methods
    BatchResult AnalyzeDirectory(const std::filesystem::path& directory,
                                 const std::string& pattern = "*.exe",
                                 bool recursive = true);

    BatchResult AnalyzeFiles(const std::vector<std::filesystem::path>& files);

    // File discovery
    std::vector<std::filesystem::path> DiscoverFiles(const BatchConfig& config);

    // Progress monitoring
    void SetProgressCallback(ProgressCallback callback);

    // Resume support
    bool SaveResumeState(const std::filesystem::path& resumeFile,
                        const std::vector<std::filesystem::path>& remaining);

    bool LoadResumeState(const std::filesystem::path& resumeFile,
                        std::vector<std::filesystem::path>& files);

private:
    // File discovery helpers
    void ScanDirectory(const std::filesystem::path& directory,
                      const BatchConfig& config,
                      std::vector<std::filesystem::path>& files);

    bool MatchesPattern(const std::filesystem::path& file,
                       const std::vector<std::string>& patterns);

    bool IsExcluded(const std::filesystem::path& file,
                   const std::vector<std::string>& excludePatterns);

    // Processing
    FileResult ProcessFile(const std::filesystem::path& file,
                          const BatchConfig& config);

    void ProcessBatch(const std::vector<std::filesystem::path>& batch,
                     const BatchConfig& config,
                     std::vector<FileResult>& results);

    // Statistics
    void UpdateStatistics(const FileResult& result);
    BatchStatistics ComputeFinalStatistics();

    // Reporting
    bool GenerateReport(const BatchResult& result, const BatchConfig& config);
    void GenerateTextReport(const BatchResult& result, std::ostream& out);
    void GenerateJSONReport(const BatchResult& result, std::ostream& out);
    void GenerateCSVReport(const BatchResult& result, std::ostream& out);
    void GenerateXMLReport(const BatchResult& result, std::ostream& out);

    // Progress tracking
    ProgressCallback m_progressCallback;
    std::atomic<size_t> m_processedCount;
    std::atomic<size_t> m_totalCount;
    std::mutex m_statsMutex;

    // Accumulated statistics
    BatchStatistics m_statistics;
};

/*
 * Batch Analyzer
 *
 * Specialized batch analyzer with intelligence
 */
class BatchAnalyzer {
public:
    struct AnalysisOptions {
        bool detectPackers;
        bool calculateHashes;
        bool deepScan;
        bool extractMetadata;
        std::string configProfile;  // Configuration profile to use
    };

    BatchResult AnalyzeWithOptions(const std::vector<std::filesystem::path>& files,
                                   const AnalysisOptions& options);

    // Pattern analysis
    struct PatternAnalysis {
        std::vector<std::string> commonPackers;
        std::vector<std::string> suspiciousPatterns;
        double averageEntropy;
        std::map<std::string, size_t> commonImports;
    };

    PatternAnalysis AnalyzePatterns(const BatchResult& batchResult);

    // Similarity detection
    struct SimilarityGroup {
        std::vector<std::filesystem::path> files;
        double similarityScore;  // 0.0-1.0
        std::string reason;      // Why they're similar
    };

    std::vector<SimilarityGroup> FindSimilarFiles(const BatchResult& batchResult,
                                                   double threshold = 0.8);
};

/*
 * Report Generator
 *
 * Advanced reporting capabilities
 */
class ReportGenerator {
public:
    // HTML report with charts
    void GenerateHTMLReport(const BatchResult& result,
                           const std::filesystem::path& outputPath);

    // Executive summary
    void GenerateSummary(const BatchResult& result,
                        std::ostream& out);

    // Comparison report
    void GenerateComparisonReport(const std::vector<BatchResult>& results,
                                 const std::filesystem::path& outputPath);

    // Timeline report
    void GenerateTimeline(const BatchResult& result,
                         const std::filesystem::path& outputPath);
};

} // namespace CLI
} // namespace Scylla
