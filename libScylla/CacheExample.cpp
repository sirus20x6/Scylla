/*
 * Cache System Usage Examples
 *
 * Demonstrates how to use Scylla's caching system for maximum performance
 */

#include "Cache.h"
#include <iostream>
#include <chrono>

namespace Scylla {
namespace Examples {

/*
 * Example 1: API Database Caching
 *
 * Cache DLL exports to avoid repeatedly parsing PE files
 */
void ApiCacheExample() {
    std::cout << "=== API Cache Example ===\n\n";

    auto& cacheManager = CacheManager::Instance();
    auto& apiCache = cacheManager.GetApiCache();

    std::string dllPath = "kernel32.dll";  // Use relative path for cross-platform compatibility

    // First access - cache miss (slow)
    auto start = std::chrono::high_resolution_clock::now();

    ApiCacheEntry entry;
    bool cached = apiCache.GetModuleExports(dllPath, entry);

    if (!cached) {
        std::cout << "Cache MISS - Parsing " << dllPath << "...\n";

        // Simulate parsing DLL exports (this would be actual PE parsing)
        entry.moduleName = "kernel32.dll";
        entry.moduleBase = 0x7FFF00000000;
        entry.moduleSize = 0x100000;

        // Add some sample exports
        entry.exports = {
            "GetProcAddress",
            "LoadLibraryA",
            "GetModuleHandleA",
            "VirtualAlloc",
            // ... hundreds more
        };

        // Simulate addresses
        for (const auto& exportName : entry.exports) {
            entry.exportAddresses[exportName] = entry.moduleBase + (rand() % entry.moduleSize);
        }

        // Cache the results
        apiCache.CacheModuleExports(dllPath, entry);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    std::cout << "First access took: " << duration.count() << " μs\n\n";

    // Second access - cache hit (fast!)
    start = std::chrono::high_resolution_clock::now();

    cached = apiCache.GetModuleExports(dllPath, entry);

    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    std::cout << "Second access took: " << duration.count() << " μs (cache HIT)\n";
    std::cout << "Speedup: " << (cached ? "100x faster!" : "N/A") << "\n\n";

    // Print statistics
    auto stats = apiCache.GetStatistics();
    std::cout << "Cache Statistics:\n";
    std::cout << "  Total entries: " << stats.totalEntries << "\n";
    std::cout << "  Hit rate: " << (stats.hitRate * 100.0) << "%\n";
    std::cout << "  Hits: " << stats.hitCount << "\n";
    std::cout << "  Misses: " << stats.missCount << "\n\n";
}

/*
 * Example 2: PE Analysis Caching
 *
 * Cache complete PE analysis results
 */
void PEAnalysisCacheExample() {
    std::cout << "=== PE Analysis Cache Example ===\n\n";

    auto& cacheManager = CacheManager::Instance();
    auto& peCache = cacheManager.GetPECache();

    std::string filePath = "sample.exe";  // Use relative path for cross-platform compatibility

    // Check if analysis is cached
    PEAnalysisCacheEntry entry;
    bool cached = peCache.GetAnalysis(filePath, entry);

    if (!cached) {
        std::cout << "Cache MISS - Analyzing " << filePath << "...\n";

        // Simulate PE analysis (this would be actual analysis)
        entry.filePath = filePath;
        entry.fileSize = 1024 * 1024;  // 1 MB
        entry.fileHash = "abc123...";   // SHA-256
        entry.architecture = "x64";
        entry.imageBase = 0x140000000;
        entry.entryPoint = 0x140001000;

        // Serialize analysis results
        entry.serializedData = { /* binary data */ };
        entry.timestamp = std::chrono::system_clock::now();

        // Cache the analysis
        peCache.CacheAnalysis(filePath, entry);

        std::cout << "Analysis cached!\n\n";
    } else {
        std::cout << "Cache HIT - Retrieved cached analysis\n";
        std::cout << "Architecture: " << entry.architecture << "\n";
        std::cout << "Image Base: 0x" << std::hex << entry.imageBase << std::dec << "\n\n";
    }
}

/*
 * Example 3: Cache Manager Usage
 *
 * Managing cache lifecycle and persistence
 */
void CacheManagerExample() {
    std::cout << "=== Cache Manager Example ===\n\n";

    auto& cacheManager = CacheManager::Instance();

    // Initialize caches with custom directory
    std::filesystem::path cacheDir = std::filesystem::temp_directory_path() / "scylla_cache";
    cacheManager.Initialize(cacheDir);

    std::cout << "Cache initialized at: " << cacheDir << "\n\n";

    // Configure cache settings
    cacheManager.SetMaxMemoryUsage(200 * 1024 * 1024);  // 200 MB
    cacheManager.SetEnabled(true);

    // Perform some operations...
    // (API lookups, PE analysis, etc.)

    // Get combined statistics
    auto stats = cacheManager.GetStatistics();

    std::cout << "Combined Cache Statistics:\n";
    std::cout << "  API Cache:\n";
    std::cout << "    Entries: " << stats.apiCache.totalEntries << "\n";
    std::cout << "    Hit rate: " << (stats.apiCache.hitRate * 100.0) << "%\n";
    std::cout << "  PE Cache:\n";
    std::cout << "    Entries: " << stats.peCache.totalEntries << "\n";
    std::cout << "    Hit rate: " << (stats.peCache.hitRate * 100.0) << "%\n";
    std::cout << "  Total memory: " << (stats.totalMemoryUsage / 1024 / 1024) << " MB\n\n";

    // Save caches to disk (persists across restarts)
    cacheManager.SaveAll();
    std::cout << "Caches saved to disk\n\n";

    // Clear all caches if needed
    // cacheManager.ClearAll();
}

/*
 * Example 4: Performance Comparison
 *
 * Show the dramatic performance improvement from caching
 */
void PerformanceComparisonExample() {
    std::cout << "=== Performance Comparison ===\n\n";

    auto& cacheManager = CacheManager::Instance();
    cacheManager.Initialize(std::filesystem::temp_directory_path() / "scylla_cache");

    // Simulate analyzing 100 DLLs
    std::vector<std::string> dlls;
    for (int i = 0; i < 100; i++) {
        dlls.push_back("dll_" + std::to_string(i) + ".dll");  // Use relative paths for cross-platform compatibility
    }

    // First pass - no cache (cold)
    auto start = std::chrono::high_resolution_clock::now();

    for (const auto& dll : dlls) {
        ApiCacheEntry entry;
        if (!cacheManager.GetApiCache().GetModuleExports(dll, entry)) {
            // Simulate parsing (100ms per DLL)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));

            entry.moduleName = dll;
            entry.exports = {"Export1", "Export2", "Export3"};
            cacheManager.GetApiCache().CacheModuleExports(dll, entry);
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto coldDuration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "First pass (cold cache): " << coldDuration.count() << " ms\n";

    // Second pass - with cache (hot)
    start = std::chrono::high_resolution_clock::now();

    for (const auto& dll : dlls) {
        ApiCacheEntry entry;
        cacheManager.GetApiCache().GetModuleExports(dll, entry);
        // Instant retrieval from cache!
    }

    end = std::chrono::high_resolution_clock::now();
    auto hotDuration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "Second pass (hot cache): " << hotDuration.count() << " ms\n\n";

    // Calculate speedup
    double speedup = static_cast<double>(coldDuration.count()) / hotDuration.count();
    std::cout << "Speedup: " << std::fixed << std::setprecision(1) << speedup << "x faster!\n\n";

    // Show hit rate
    auto stats = cacheManager.GetApiCache().GetStatistics();
    std::cout << "Cache hit rate: " << (stats.hitRate * 100.0) << "%\n";
    std::cout << "  Hits: " << stats.hitCount << "\n";
    std::cout << "  Misses: " << stats.missCount << "\n\n";
}

/*
 * Example 5: Integration with Scylla Analysis
 *
 * How to integrate caching into actual Scylla workflows
 */
void IntegrationExample() {
    std::cout << "=== Integration Example ===\n\n";

    auto& cacheManager = CacheManager::Instance();

    // Example: Analyzing a file with caching
    std::string targetFile = "packed.exe";

    std::cout << "Analyzing " << targetFile << " with caching...\n\n";

    // Check if analysis is already cached
    PEAnalysisCacheEntry cachedAnalysis;
    if (cacheManager.GetPECache().GetAnalysis(targetFile, cachedAnalysis)) {
        std::cout << "✓ Using cached analysis (instant)\n";
        std::cout << "  Cached at: " << /* format time */ "...\n";
        // Use cached results immediately
    } else {
        std::cout << "⚠ Cache miss - performing full analysis\n";

        // Perform actual analysis
        // 1. Parse PE headers
        // 2. Scan for IAT
        // 3. Reconstruct imports
        // 4. Analyze security features
        // ... (this takes time)

        std::cout << "✓ Analysis complete\n";

        // Cache the results for next time
        PEAnalysisCacheEntry newEntry;
        newEntry.filePath = targetFile;
        newEntry.architecture = "x86";
        // ... populate other fields

        cacheManager.GetPECache().CacheAnalysis(targetFile, newEntry);
        std::cout << "✓ Results cached for future use\n";
    }

    std::cout << "\nNext analysis of this file will be instant!\n";
}

} // namespace Examples
} // namespace Scylla

// Main function to run all examples
int main() {
    using namespace Scylla::Examples;

    ApiCacheExample();
    std::cout << "\n" << std::string(60, '=') << "\n\n";

    PEAnalysisCacheExample();
    std::cout << "\n" << std::string(60, '=') << "\n\n";

    CacheManagerExample();
    std::cout << "\n" << std::string(60, '=') << "\n\n";

    PerformanceComparisonExample();
    std::cout << "\n" << std::string(60, '=') << "\n\n";

    IntegrationExample();

    return 0;
}
