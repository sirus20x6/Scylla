/*
 * Parallel IAT Scanner - Multi-threaded IAT detection
 *
 * This class provides multi-threaded scanning for Import Address Tables
 * to improve performance on multi-core systems.
 */

#pragma once

#include <vector>
#include <thread>
#include <mutex>
#include <future>
#include <functional>
#include <atomic>
#include <queue>
#include <cstdint>

namespace Scylla {

// Memory region to scan
struct MemoryRegion {
    uint64_t address;
    uint64_t size;
    uint8_t* data;
    bool executable;
    bool writable;
    bool readable;
};

// IAT candidate result
struct IATCandidate {
    uint64_t address;
    uint32_t size;
    int confidence;  // 0-100
    bool valid;
    std::vector<uint64_t> pointers;
};

// Scan statistics
struct ScanStatistics {
    size_t regionsScanned;
    size_t bytesScanned;
    size_t candidatesFound;
    double scanTime;  // seconds
    size_t threadsUsed;
};

/*
 * Parallel IAT Scanner
 *
 * Scans memory regions in parallel to find IAT candidates.
 * Uses worker threads to process multiple regions simultaneously.
 */
class ParallelIATScanner {
public:
    ParallelIATScanner();
    ~ParallelIATScanner();

    // Set number of worker threads (default: hardware_concurrency)
    void SetThreadCount(size_t threadCount);

    // Set minimum confidence threshold (0-100)
    void SetMinConfidence(int minConfidence);

    // Scan regions in parallel
    std::vector<IATCandidate> ScanParallel(
        const std::vector<MemoryRegion>& regions
    );

    // Scan single region (used by worker threads)
    std::vector<IATCandidate> ScanRegion(const MemoryRegion& region);

    // Get scan statistics
    const ScanStatistics& GetStatistics() const { return m_statistics; }

    // Cancel ongoing scan
    void Cancel();

private:
    // Worker thread function
    void WorkerThread(
        const std::vector<MemoryRegion>& regions,
        size_t startIndex,
        size_t endIndex,
        std::vector<IATCandidate>& results
    );

    // IAT detection algorithms
    bool IsValidIATPointer(uint64_t pointer, const MemoryRegion& region);
    int CalculateConfidence(const IATCandidate& candidate);
    bool LooksLikeIAT(const uint8_t* data, size_t offset, size_t size);

    // Check if region is likely to contain IAT
    bool IsIATPossibleRegion(const MemoryRegion& region);

    // Pattern matching
    size_t CountValidPointers(const uint8_t* data, size_t size);
    double CalculatePointerDensity(const uint8_t* data, size_t size);

private:
    size_t m_threadCount;
    int m_minConfidence;
    std::atomic<bool> m_cancelled;

    ScanStatistics m_statistics;
    std::mutex m_resultsMutex;
};

/*
 * Thread Pool for batch processing
 */
class ThreadPool {
public:
    explicit ThreadPool(size_t threadCount = std::thread::hardware_concurrency());
    ~ThreadPool();

    // Submit a task to the pool
    template<typename F, typename... Args>
    auto Submit(F&& f, Args&&... args) -> std::future<decltype(f(args...))>;

    // Wait for all tasks to complete
    void WaitAll();

    // Get number of threads
    size_t GetThreadCount() const { return m_workers.size(); }

private:
    std::vector<std::thread> m_workers;
    std::queue<std::function<void()>> m_tasks;
    std::mutex m_queueMutex;
    std::condition_variable m_condition;
    std::atomic<bool> m_stop;
    std::atomic<size_t> m_activeTasks;
};

// Template implementation
template<typename F, typename... Args>
auto ThreadPool::Submit(F&& f, Args&&... args) -> std::future<decltype(f(args...))> {
    using return_type = decltype(f(args...));

    auto task = std::make_shared<std::packaged_task<return_type()>>(
        std::bind(std::forward<F>(f), std::forward<Args>(args)...)
    );

    std::future<return_type> result = task->get_future();

    {
        std::unique_lock<std::mutex> lock(m_queueMutex);
        if (m_stop) {
            throw std::runtime_error("Cannot submit to stopped ThreadPool");
        }

        m_tasks.emplace([task]() { (*task)(); });
    }

    m_condition.notify_one();
    m_activeTasks++;

    return result;
}

} // namespace Scylla
