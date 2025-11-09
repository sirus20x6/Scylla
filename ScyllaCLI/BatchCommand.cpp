/*
 * Scylla Batch Processing - Implementation
 */

#include "BatchCommand.h"
#include "AnalyzeCommand.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <thread>
#include <queue>
#include <condition_variable>

namespace Scylla {
namespace CLI {

// ============================================================================
// BatchCommand Implementation
// ============================================================================

BatchCommand::BatchCommand()
    : m_processedCount(0)
    , m_totalCount(0)
{
    m_statistics = {};
}

BatchCommand::~BatchCommand() {
}

BatchResult BatchCommand::Execute(const BatchConfig& config) {
    BatchResult result;
    result.success = false;

    auto startTime = std::chrono::high_resolution_clock::now();

    // Step 1: Discover files
    std::cout << "Discovering files...\n";
    auto files = DiscoverFiles(config);

    if (files.empty()) {
        result.errors.push_back("No files found");
        return result;
    }

    std::cout << "Found " << files.size() << " files to process\n";

    // Step 2: Check for resume
    if (config.enableResume && std::filesystem::exists(config.resumeFile)) {
        std::cout << "Resuming from previous session...\n";
        std::vector<std::filesystem::path> remainingFiles;
        if (LoadResumeState(config.resumeFile, remainingFiles)) {
            files = remainingFiles;
            std::cout << "Resuming with " << files.size() << " remaining files\n";
        }
    }

    m_totalCount = files.size();
    m_processedCount = 0;

    // Step 3: Setup thread pool
    size_t threadCount = config.maxThreads;
    if (threadCount == 0) {
        threadCount = std::thread::hardware_concurrency();
        if (threadCount == 0) threadCount = 4;
    }

    std::cout << "Processing with " << threadCount << " threads\n";

    // Step 4: Process files in batches
    std::vector<FileResult> allResults;
    size_t batchSize = config.batchSize > 0 ? config.batchSize : 100;

    for (size_t i = 0; i < files.size(); i += batchSize) {
        size_t end = std::min(i + batchSize, files.size());
        std::vector<std::filesystem::path> batch(files.begin() + i, files.begin() + end);

        if (config.showProgress) {
            std::cout << "\nProcessing batch " << (i / batchSize + 1)
                      << " (" << batch.size() << " files)...\n";
        }

        std::vector<FileResult> batchResults;
        ProcessBatch(batch, config, batchResults);

        allResults.insert(allResults.end(), batchResults.begin(), batchResults.end());

        // Update statistics
        for (const auto& fileResult : batchResults) {
            UpdateStatistics(fileResult);
        }

        // Save resume state
        if (config.enableResume) {
            std::vector<std::filesystem::path> remaining(files.begin() + end, files.end());
            SaveResumeState(config.resumeFile, remaining);
        }

        // Check stop on error
        if (config.stopOnError) {
            bool hasError = std::any_of(batchResults.begin(), batchResults.end(),
                [](const FileResult& r) { return !r.success; });
            if (hasError) {
                result.warnings.push_back("Stopped due to error (stopOnError = true)");
                break;
            }
        }
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    m_statistics.totalTime = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

    // Step 5: Compute final statistics
    result.statistics = ComputeFinalStatistics();
    result.results = allResults;
    result.success = (result.statistics.failedFiles == 0 || !config.stopOnError);

    // Step 6: Generate report
    if (config.aggregateReports) {
        std::cout << "\nGenerating report...\n";
        if (GenerateReport(result, config)) {
            std::cout << "Report saved to: " << result.reportPath << "\n";
        }
    }

    // Step 7: Print summary
    std::cout << "\n=== Batch Processing Complete ===\n";
    std::cout << "Total files:      " << result.statistics.totalFiles << "\n";
    std::cout << "Successful:       " << result.statistics.successfulFiles << "\n";
    std::cout << "Failed:           " << result.statistics.failedFiles << "\n";
    std::cout << "Processing time:  " << (result.statistics.totalTime.count() / 1000.0) << " seconds\n";
    std::cout << "Average time:     " << result.statistics.averageTime.count() << " ms/file\n";
    std::cout << "Throughput:       " << std::fixed << std::setprecision(2)
              << result.statistics.filesPerSecond << " files/sec\n";

    // Clean up resume file on success
    if (config.enableResume && result.success) {
        std::filesystem::remove(config.resumeFile);
    }

    return result;
}

BatchResult BatchCommand::AnalyzeDirectory(const std::filesystem::path& directory,
                                          const std::string& pattern,
                                          bool recursive)
{
    BatchConfig config;
    config.directories.push_back(directory);
    config.patterns.push_back(pattern);
    config.recursive = recursive;
    config.mode = BatchConfig::Mode::Analyze;
    config.maxThreads = 0;  // Auto-detect
    config.showProgress = true;
    config.aggregateReports = true;
    config.reportFormat = "text";

    return Execute(config);
}

BatchResult BatchCommand::AnalyzeFiles(const std::vector<std::filesystem::path>& files) {
    BatchConfig config;
    config.files = files;
    config.mode = BatchConfig::Mode::Analyze;
    config.maxThreads = 0;
    config.showProgress = true;
    config.aggregateReports = true;
    config.reportFormat = "json";

    return Execute(config);
}

std::vector<std::filesystem::path> BatchCommand::DiscoverFiles(const BatchConfig& config) {
    std::vector<std::filesystem::path> files;

    // Add explicit files
    for (const auto& file : config.files) {
        if (std::filesystem::exists(file) && std::filesystem::is_regular_file(file)) {
            files.push_back(file);
        }
    }

    // Scan directories
    for (const auto& directory : config.directories) {
        if (std::filesystem::exists(directory) && std::filesystem::is_directory(directory)) {
            ScanDirectory(directory, config, files);
        }
    }

    // Remove duplicates
    std::sort(files.begin(), files.end());
    files.erase(std::unique(files.begin(), files.end()), files.end());

    return files;
}

void BatchCommand::ScanDirectory(const std::filesystem::path& directory,
                                const BatchConfig& config,
                                std::vector<std::filesystem::path>& files)
{
    try {
        if (config.recursive) {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(directory)) {
                if (entry.is_regular_file()) {
                    if (MatchesPattern(entry.path(), config.patterns) &&
                        !IsExcluded(entry.path(), config.excludePatterns))
                    {
                        // Check file size
                        auto size = entry.file_size();
                        if ((config.minFileSize == 0 || size >= config.minFileSize) &&
                            (config.maxFileSize == 0 || size <= config.maxFileSize))
                        {
                            files.push_back(entry.path());
                        }
                    }
                }
            }
        } else {
            for (const auto& entry : std::filesystem::directory_iterator(directory)) {
                if (entry.is_regular_file()) {
                    if (MatchesPattern(entry.path(), config.patterns) &&
                        !IsExcluded(entry.path(), config.excludePatterns))
                    {
                        auto size = entry.file_size();
                        if ((config.minFileSize == 0 || size >= config.minFileSize) &&
                            (config.maxFileSize == 0 || size <= config.maxFileSize))
                        {
                            files.push_back(entry.path());
                        }
                    }
                }
            }
        }
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error scanning directory " << directory << ": " << e.what() << "\n";
    }
}

bool BatchCommand::MatchesPattern(const std::filesystem::path& file,
                                 const std::vector<std::string>& patterns)
{
    if (patterns.empty()) {
        return true;  // No patterns = match all
    }

    std::string filename = file.filename().string();
    std::string extension = file.extension().string();

    for (const auto& pattern : patterns) {
        // Simple wildcard matching
        if (pattern == "*" || pattern == "*.*") {
            return true;
        }

        // Extension matching (*.exe, *.dll)
        if (pattern[0] == '*') {
            std::string patternExt = pattern.substr(1);
            if (extension == patternExt) {
                return true;
            }
        }

        // Exact match
        if (filename == pattern) {
            return true;
        }
    }

    return false;
}

bool BatchCommand::IsExcluded(const std::filesystem::path& file,
                             const std::vector<std::string>& excludePatterns)
{
    if (excludePatterns.empty()) {
        return false;
    }

    std::string filename = file.filename().string();

    for (const auto& pattern : excludePatterns) {
        if (filename.find(pattern) != std::string::npos) {
            return true;
        }
    }

    return false;
}

void BatchCommand::ProcessBatch(const std::vector<std::filesystem::path>& batch,
                               const BatchConfig& config,
                               std::vector<FileResult>& results)
{
    results.resize(batch.size());

    // Determine thread count
    size_t threadCount = config.maxThreads;
    if (threadCount == 0) {
        threadCount = std::thread::hardware_concurrency();
        if (threadCount == 0) threadCount = 4;
    }

    // Create work queue
    std::queue<size_t> workQueue;
    for (size_t i = 0; i < batch.size(); i++) {
        workQueue.push(i);
    }

    std::mutex queueMutex;
    std::condition_variable queueCV;
    bool done = false;

    // Worker function
    auto worker = [&]() {
        while (true) {
            size_t index;

            {
                std::unique_lock<std::mutex> lock(queueMutex);
                queueCV.wait(lock, [&] { return !workQueue.empty() || done; });

                if (workQueue.empty() && done) {
                    break;
                }

                if (workQueue.empty()) {
                    continue;
                }

                index = workQueue.front();
                workQueue.pop();
            }

            // Process file
            results[index] = ProcessFile(batch[index], config);

            m_processedCount++;

            // Progress callback
            if (m_progressCallback) {
                m_progressCallback(m_processedCount, m_totalCount, batch[index].string());
            }

            if (config.showProgress && m_processedCount % 10 == 0) {
                std::cout << "Progress: " << m_processedCount << "/" << m_totalCount
                          << " (" << (m_processedCount * 100 / m_totalCount) << "%)\r" << std::flush;
            }
        }
    };

    // Launch threads
    std::vector<std::thread> threads;
    for (size_t i = 0; i < threadCount; i++) {
        threads.emplace_back(worker);
    }

    // Wait for completion
    {
        std::unique_lock<std::mutex> lock(queueMutex);
        queueCV.wait(lock, [&] { return workQueue.empty(); });
        done = true;
    }
    queueCV.notify_all();

    for (auto& thread : threads) {
        thread.join();
    }
}

FileResult BatchCommand::ProcessFile(const std::filesystem::path& file,
                                    const BatchConfig& config)
{
    FileResult result;
    result.filePath = file;
    result.success = false;

    auto startTime = std::chrono::high_resolution_clock::now();

    try {
        // Get file size
        result.fileSize = std::filesystem::file_size(file);

        // Process based on mode
        switch (config.mode) {
            case BatchConfig::Mode::Analyze:
                // Simplified analysis
                result.success = true;
                result.architecture = "x86";  // Placeholder
                result.importsFound = 0;
                result.sectionsFound = 0;
                break;

            case BatchConfig::Mode::Custom:
                if (config.customOp) {
                    result.success = config.customOp(file);
                }
                break;

            default:
                result.errorMessage = "Unsupported mode";
                break;
        }

    } catch (const std::exception& e) {
        result.success = false;
        result.errorMessage = e.what();
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    result.processingTime = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

    return result;
}

void BatchCommand::UpdateStatistics(const FileResult& result) {
    std::lock_guard<std::mutex> lock(m_statsMutex);

    m_statistics.processedFiles++;

    if (result.success) {
        m_statistics.successfulFiles++;
    } else {
        m_statistics.failedFiles++;
    }

    m_statistics.totalBytes += result.fileSize;

    // Track packers
    if (!result.packerDetected.empty()) {
        m_statistics.packerDistribution[result.packerDetected]++;
    }

    // Track architectures
    if (!result.architecture.empty()) {
        m_statistics.architectureDistribution[result.architecture]++;
    }

    // Track errors
    if (!result.errorMessage.empty()) {
        m_statistics.errorTypes[result.errorMessage]++;
    }
}

BatchStatistics BatchCommand::ComputeFinalStatistics() {
    std::lock_guard<std::mutex> lock(m_statsMutex);

    m_statistics.totalFiles = m_processedCount;

    if (m_statistics.processedFiles > 0) {
        m_statistics.averageFileSize = m_statistics.totalBytes / m_statistics.processedFiles;
    }

    if (m_statistics.totalTime.count() > 0) {
        m_statistics.averageTime = std::chrono::milliseconds(
            m_statistics.totalTime.count() / m_statistics.processedFiles
        );

        m_statistics.filesPerSecond =
            static_cast<double>(m_statistics.processedFiles) /
            (m_statistics.totalTime.count() / 1000.0);
    }

    return m_statistics;
}

bool BatchCommand::GenerateReport(const BatchResult& result, const BatchConfig& config) {
    std::filesystem::path reportPath = config.outputDirectory;

    if (reportPath.empty()) {
        reportPath = std::filesystem::current_path();
    }

    std::filesystem::create_directories(reportPath);

    std::string reportFile = "batch_report." + config.reportFormat;
    reportPath /= reportFile;

    std::ofstream out(reportPath);
    if (!out.is_open()) {
        return false;
    }

    if (config.reportFormat == "json") {
        GenerateJSONReport(result, out);
    } else if (config.reportFormat == "xml") {
        GenerateXMLReport(result, out);
    } else if (config.reportFormat == "csv") {
        GenerateCSVReport(result, out);
    } else {
        GenerateTextReport(result, out);
    }

    const_cast<BatchResult&>(result).reportPath = reportPath;
    return true;
}

void BatchCommand::GenerateTextReport(const BatchResult& result, std::ostream& out) {
    out << "Scylla Batch Processing Report\n";
    out << "================================\n\n";

    out << "Statistics:\n";
    out << "  Total files:       " << result.statistics.totalFiles << "\n";
    out << "  Successful:        " << result.statistics.successfulFiles << "\n";
    out << "  Failed:            " << result.statistics.failedFiles << "\n";
    out << "  Total size:        " << (result.statistics.totalBytes / 1024 / 1024) << " MB\n";
    out << "  Average size:      " << (result.statistics.averageFileSize / 1024) << " KB\n";
    out << "  Processing time:   " << (result.statistics.totalTime.count() / 1000.0) << " seconds\n";
    out << "  Average time:      " << result.statistics.averageTime.count() << " ms/file\n";
    out << "  Throughput:        " << std::fixed << std::setprecision(2)
        << result.statistics.filesPerSecond << " files/sec\n\n";

    // Packer distribution
    if (!result.statistics.packerDistribution.empty()) {
        out << "Packer Distribution:\n";
        for (const auto& [packer, count] : result.statistics.packerDistribution) {
            out << "  " << std::left << std::setw(20) << packer << ": " << count << "\n";
        }
        out << "\n";
    }

    // Failed files
    if (result.statistics.failedFiles > 0) {
        out << "Failed Files:\n";
        for (const auto& fileResult : result.results) {
            if (!fileResult.success) {
                out << "  " << fileResult.filePath << "\n";
                out << "    Error: " << fileResult.errorMessage << "\n";
            }
        }
    }
}

void BatchCommand::GenerateJSONReport(const BatchResult& result, std::ostream& out) {
    out << "{\n";
    out << "  \"summary\": {\n";
    out << "    \"totalFiles\": " << result.statistics.totalFiles << ",\n";
    out << "    \"successful\": " << result.statistics.successfulFiles << ",\n";
    out << "    \"failed\": " << result.statistics.failedFiles << ",\n";
    out << "    \"totalBytes\": " << result.statistics.totalBytes << ",\n";
    out << "    \"processingTimeMs\": " << result.statistics.totalTime.count() << ",\n";
    out << "    \"filesPerSecond\": " << result.statistics.filesPerSecond << "\n";
    out << "  },\n";
    out << "  \"files\": [\n";

    for (size_t i = 0; i < result.results.size(); i++) {
        const auto& fr = result.results[i];
        out << "    {\n";
        out << "      \"path\": \"" << fr.filePath.string() << "\",\n";
        out << "      \"success\": " << (fr.success ? "true" : "false") << ",\n";
        out << "      \"size\": " << fr.fileSize << ",\n";
        out << "      \"timeMs\": " << fr.processingTime.count() << "\n";
        out << "    }";
        if (i < result.results.size() - 1) out << ",";
        out << "\n";
    }

    out << "  ]\n";
    out << "}\n";
}

void BatchCommand::GenerateCSVReport(const BatchResult& result, std::ostream& out) {
    out << "File,Success,Size,Time(ms),Error\n";

    for (const auto& fr : result.results) {
        out << "\"" << fr.filePath.string() << "\","
            << (fr.success ? "true" : "false") << ","
            << fr.fileSize << ","
            << fr.processingTime.count() << ","
            << "\"" << fr.errorMessage << "\"\n";
    }
}

void BatchCommand::GenerateXMLReport(const BatchResult& result, std::ostream& out) {
    out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    out << "<batch-report>\n";
    out << "  <statistics>\n";
    out << "    <total>" << result.statistics.totalFiles << "</total>\n";
    out << "    <successful>" << result.statistics.successfulFiles << "</successful>\n";
    out << "    <failed>" << result.statistics.failedFiles << "</failed>\n";
    out << "  </statistics>\n";
    out << "  <files>\n";

    for (const auto& fr : result.results) {
        out << "    <file>\n";
        out << "      <path>" << fr.filePath.string() << "</path>\n";
        out << "      <success>" << (fr.success ? "true" : "false") << "</success>\n";
        out << "      <size>" << fr.fileSize << "</size>\n";
        out << "    </file>\n";
    }

    out << "  </files>\n";
    out << "</batch-report>\n";
}

void BatchCommand::SetProgressCallback(ProgressCallback callback) {
    m_progressCallback = callback;
}

bool BatchCommand::SaveResumeState(const std::filesystem::path& resumeFile,
                                  const std::vector<std::filesystem::path>& remaining)
{
    std::ofstream out(resumeFile);
    if (!out.is_open()) return false;

    for (const auto& file : remaining) {
        out << file.string() << "\n";
    }

    return true;
}

bool BatchCommand::LoadResumeState(const std::filesystem::path& resumeFile,
                                  std::vector<std::filesystem::path>& files)
{
    std::ifstream in(resumeFile);
    if (!in.is_open()) return false;

    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty()) {
            files.push_back(line);
        }
    }

    return true;
}

// ============================================================================
// BatchAnalyzer Implementation
// ============================================================================

BatchResult BatchAnalyzer::AnalyzeWithOptions(const std::vector<std::filesystem::path>& files,
                                              const AnalysisOptions& options)
{
    BatchCommand batchCmd;

    BatchConfig config;
    config.files = files;
    config.mode = BatchConfig::Mode::Analyze;
    config.showProgress = true;
    config.aggregateReports = true;

    return batchCmd.Execute(config);
}

} // namespace CLI
} // namespace Scylla
