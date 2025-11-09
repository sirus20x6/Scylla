/*
 * Batch Processing Examples
 */

#include "BatchCommand.h"
#include <iostream>

using namespace Scylla::CLI;

void BasicBatchExample() {
    std::cout << "=== Basic Batch Processing ===\n\n";

    BatchCommand batch;

    // Analyze all .exe files in a directory
    auto result = batch.AnalyzeDirectory("C:\\malware_samples", "*.exe", true);

    if (result.success) {
        std::cout << "✓ Batch analysis complete!\n";
        std::cout << "  Processed: " << result.statistics.processedFiles << " files\n";
        std::cout << "  Success: " << result.statistics.successfulFiles << "\n";
        std::cout << "  Failed: " << result.statistics.failedFiles << "\n";
        std::cout << "  Time: " << (result.statistics.totalTime.count() / 1000.0) << " seconds\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

void CustomBatchExample() {
    std::cout << "=== Custom Batch Configuration ===\n\n";

    BatchCommand batch;
    BatchConfig config;

    // Setup input
    config.directories.push_back("samples/");
    config.patterns.push_back("*.exe");
    config.patterns.push_back("*.dll");
    config.recursive = true;

    // Filtering
    config.minFileSize = 1024;  // Skip tiny files
    config.maxFileSize = 100 * 1024 * 1024;  // Skip huge files
    config.excludePatterns.push_back("test");  // Skip test files

    // Processing
    config.maxThreads = 8;
    config.batchSize = 50;
    config.skipErrors = true;

    // Output
    config.outputDirectory = "batch_results/";
    config.aggregateReports = true;
    config.reportFormat = "json";
    config.showProgress = true;

    std::cout << "Configuration:\n";
    std::cout << "  Patterns: *.exe, *.dll\n";
    std::cout << "  Recursive: YES\n";
    std::cout << "  Threads: " << config.maxThreads << "\n";
    std::cout << "  Output: " << config.outputDirectory.string() << "\n\n";

    auto result = batch.Execute(config);

    if (result.success) {
        std::cout << "\n✓ Batch complete!\n";
        std::cout << "  Report: " << result.reportPath << "\n";

        // Show packer distribution
        if (!result.statistics.packerDistribution.empty()) {
            std::cout << "\nPacker Distribution:\n";
            for (const auto& [packer, count] : result.statistics.packerDistribution) {
                std::cout << "  " << std::left << std::setw(20) << packer
                          << ": " << count << " files\n";
            }
        }
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

void ProgressCallbackExample() {
    std::cout << "=== Progress Monitoring ===\n\n";

    BatchCommand batch;

    // Set progress callback
    batch.SetProgressCallback([](size_t processed, size_t total, const std::string& file) {
        std::cout << "Progress: [" << processed << "/" << total << "] "
                  << "Processing: " << file << "\r" << std::flush;
    });

    BatchConfig config;
    config.directories.push_back("samples/");
    config.patterns.push_back("*.exe");
    config.maxThreads = 4;
    config.showProgress = false;  // We have custom callback

    auto result = batch.Execute(config);

    std::cout << "\n\nDone! Processed " << result.statistics.processedFiles << " files\n";

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

void ResumeExample() {
    std::cout << "=== Resume Support Example ===\n\n";

    BatchCommand batch;
    BatchConfig config;

    config.directories.push_back("large_dataset/");
    config.patterns.push_back("*.exe");
    config.recursive = true;

    // Enable resume
    config.enableResume = true;
    config.resumeFile = "batch_resume.txt";

    config.maxThreads = 8;
    config.batchSize = 100;

    std::cout << "Processing large dataset with resume support...\n";
    std::cout << "Resume file: " << config.resumeFile << "\n\n";

    auto result = batch.Execute(config);

    if (result.success) {
        std::cout << "✓ Complete! Resume file cleaned up.\n";
    } else {
        std::cout << "⚠ Interrupted. Resume file saved.\n";
        std::cout << "Run again to resume from: " << config.resumeFile << "\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

void MultiFormatReportExample() {
    std::cout << "=== Multi-Format Reports ===\n\n";

    std::vector<std::string> formats = {"text", "json", "csv", "xml"};

    for (const auto& format : formats) {
        std::cout << "Generating " << format << " report...\n";

        BatchCommand batch;
        BatchConfig config;

        config.files = {"sample1.exe", "sample2.exe", "sample3.exe"};
        config.reportFormat = format;
        config.aggregateReports = true;
        config.outputDirectory = "reports/";

        auto result = batch.Execute(config);

        if (result.success) {
            std::cout << "  ✓ Report saved: " << result.reportPath << "\n";
        }
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

void StatisticsExample() {
    std::cout << "=== Detailed Statistics ===\n\n";

    BatchCommand batch;

    auto result = batch.AnalyzeDirectory("samples/", "*.exe", true);

    const auto& stats = result.statistics;

    std::cout << "Processing Statistics:\n";
    std::cout << "─────────────────────────────────────────\n";
    std::cout << "  Total files:        " << stats.totalFiles << "\n";
    std::cout << "  Successful:         " << stats.successfulFiles << "\n";
    std::cout << "  Failed:             " << stats.failedFiles << "\n";
    std::cout << "  Skipped:            " << stats.skippedFiles << "\n\n";

    std::cout << "Performance Metrics:\n";
    std::cout << "─────────────────────────────────────────\n";
    std::cout << "  Total time:         " << (stats.totalTime.count() / 1000.0) << " sec\n";
    std::cout << "  Average time:       " << stats.averageTime.count() << " ms\n";
    std::cout << "  Throughput:         " << std::fixed << std::setprecision(2)
              << stats.filesPerSecond << " files/sec\n\n";

    std::cout << "Data Metrics:\n";
    std::cout << "─────────────────────────────────────────\n";
    std::cout << "  Total size:         " << (stats.totalBytes / 1024 / 1024) << " MB\n";
    std::cout << "  Average size:       " << (stats.averageFileSize / 1024) << " KB\n\n";

    if (!stats.packerDistribution.empty()) {
        std::cout << "Packer Distribution:\n";
        std::cout << "─────────────────────────────────────────\n";
        for (const auto& [packer, count] : stats.packerDistribution) {
            double percentage = (static_cast<double>(count) / stats.totalFiles) * 100.0;
            std::cout << "  " << std::left << std::setw(25) << packer
                      << std::right << std::setw(5) << count
                      << " (" << std::fixed << std::setprecision(1) << percentage << "%)\n";
        }
        std::cout << "\n";
    }

    if (!stats.architectureDistribution.empty()) {
        std::cout << "Architecture Distribution:\n";
        std::cout << "─────────────────────────────────────────\n";
        for (const auto& [arch, count] : stats.architectureDistribution) {
            double percentage = (static_cast<double>(count) / stats.totalFiles) * 100.0;
            std::cout << "  " << std::left << std::setw(10) << arch
                      << std::right << std::setw(5) << count
                      << " (" << std::fixed << std::setprecision(1) << percentage << "%)\n";
        }
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

void CustomOperationExample() {
    std::cout << "=== Custom Operation ===\n\n";

    BatchCommand batch;
    BatchConfig config;

    config.directories.push_back("samples/");
    config.patterns.push_back("*.exe");
    config.mode = BatchConfig::Mode::Custom;

    // Custom operation: Extract strings
    config.customOp = [](const std::filesystem::path& file) -> bool {
        std::cout << "Processing: " << file.filename() << "\n";

        // Custom logic here
        // For example: extract strings, calculate hashes, etc.

        return true;  // Success
    };

    auto result = batch.Execute(config);

    std::cout << "Custom operation processed " << result.statistics.processedFiles
              << " files\n";

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

void RealWorldExample() {
    std::cout << "=== Real-World Malware Analysis Workflow ===\n\n";

    std::cout << "Scenario: Analyze 1000+ malware samples from multiple sources\n\n";

    BatchCommand batch;
    BatchConfig config;

    // Multiple input sources
    config.directories.push_back("/malware/recent/");
    config.directories.push_back("/malware/unpacked/");
    config.directories.push_back("/malware/suspicious/");

    // File types
    config.patterns.push_back("*.exe");
    config.patterns.push_back("*.dll");
    config.patterns.push_back("*.sys");

    // Filtering
    config.recursive = true;
    config.minFileSize = 1024;  // Skip tiny droppers
    config.maxFileSize = 50 * 1024 * 1024;  // Skip massive files

    // Exclude known good files
    config.excludePatterns.push_back("legitimate");
    config.excludePatterns.push_back("whitelist");

    // Performance
    config.maxThreads = 16;  // Use all available cores
    config.batchSize = 100;  // Process in batches of 100

    // Resilience
    config.skipErrors = true;  // Don't stop on errors
    config.enableResume = true;
    config.resumeFile = "malware_analysis_resume.txt";

    // Output
    config.outputDirectory = "analysis_results/";
    config.aggregateReports = true;
    config.reportFormat = "json";
    config.showProgress = true;

    std::cout << "Configuration:\n";
    std::cout << "  Input directories: 3\n";
    std::cout << "  File patterns: *.exe, *.dll, *.sys\n";
    std::cout << "  Threads: " << config.maxThreads << "\n";
    std::cout << "  Resume enabled: YES\n\n";

    std::cout << "Starting batch analysis...\n\n";

    auto result = batch.Execute(config);

    std::cout << "\n\n=== Analysis Complete ===\n";
    std::cout << "Total samples analyzed: " << result.statistics.totalFiles << "\n";
    std::cout << "Successful: " << result.statistics.successfulFiles << "\n";
    std::cout << "Failed: " << result.statistics.failedFiles << "\n";
    std::cout << "Total time: " << (result.statistics.totalTime.count() / 1000.0 / 60.0)
              << " minutes\n";
    std::cout << "Average: " << result.statistics.averageTime.count() << " ms per file\n";
    std::cout << "Throughput: " << std::fixed << std::setprecision(2)
              << result.statistics.filesPerSecond << " files/sec\n\n";

    std::cout << "Report saved to: " << result.reportPath << "\n";

    // Show top packers detected
    if (!result.statistics.packerDistribution.empty()) {
        std::cout << "\nTop 5 Packers Detected:\n";
        std::vector<std::pair<std::string, size_t>> packers(
            result.statistics.packerDistribution.begin(),
            result.statistics.packerDistribution.end()
        );
        std::sort(packers.begin(), packers.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });

        for (size_t i = 0; i < std::min(packers.size(), size_t(5)); i++) {
            std::cout << "  " << (i + 1) << ". " << std::left << std::setw(20)
                      << packers[i].first << ": " << packers[i].second << " files\n";
        }
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

int main() {
    std::cout << "Scylla Batch Processing Examples\n";
    std::cout << std::string(60, '=') << "\n\n";

    BasicBatchExample();
    CustomBatchExample();
    ProgressCallbackExample();
    MultiFormatReportExample();
    StatisticsExample();
    CustomOperationExample();
    RealWorldExample();

    std::cout << "All examples completed!\n";

    return 0;
}
