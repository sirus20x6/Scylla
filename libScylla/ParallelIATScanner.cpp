/*
 * Parallel IAT Scanner - Implementation
 */

#include "ParallelIATScanner.h"
#include <algorithm>
#include <chrono>
#include <queue>
#include <condition_variable>

namespace Scylla {

ParallelIATScanner::ParallelIATScanner()
    : m_threadCount(std::thread::hardware_concurrency())
    , m_minConfidence(70)
    , m_cancelled(false)
{
    if (m_threadCount == 0) {
        m_threadCount = 4;  // Fallback
    }

    m_statistics = {};
}

ParallelIATScanner::~ParallelIATScanner() {
    Cancel();
}

void ParallelIATScanner::SetThreadCount(size_t threadCount) {
    m_threadCount = (threadCount > 0) ? threadCount : 1;
}

void ParallelIATScanner::SetMinConfidence(int minConfidence) {
    m_minConfidence = std::clamp(minConfidence, 0, 100);
}

void ParallelIATScanner::Cancel() {
    m_cancelled = true;
}

bool ParallelIATScanner::IsIATPossibleRegion(const MemoryRegion& region) {
    // IAT is usually in readable, writable, non-executable sections
    if (region.executable) return false;
    if (!region.readable) return false;

    // IAT size is usually between 64 bytes and 64KB
    if (region.size < 64 || region.size > 65536) return false;

    return true;
}

bool ParallelIATScanner::IsValidIATPointer(uint64_t pointer, const MemoryRegion& region) {
    // Check if pointer is reasonable
    if (pointer == 0) return false;

    // Check alignment (pointers are usually aligned)
#ifdef _WIN64
    if (pointer & 0x7) return false;  // 8-byte alignment for x64
#else
    if (pointer & 0x3) return false;  // 4-byte alignment for x86
#endif

    // Check if it looks like a code pointer (high address)
#ifdef _WIN64
    if (pointer < 0x0000000000010000ULL) return false;
    if (pointer > 0x00007FFFFFFFFFFFULL) return false;
#else
    if (pointer < 0x00010000) return false;
    if (pointer > 0xFFFF0000) return false;
#endif

    return true;
}

size_t ParallelIATScanner::CountValidPointers(const uint8_t* data, size_t size) {
    size_t count = 0;
    const size_t ptrSize = sizeof(void*);

    for (size_t i = 0; i + ptrSize <= size; i += ptrSize) {
        uint64_t pointer = 0;

#ifdef _WIN64
        pointer = *reinterpret_cast<const uint64_t*>(data + i);
#else
        pointer = *reinterpret_cast<const uint32_t*>(data + i);
#endif

        if (IsValidIATPointer(pointer, {})) {
            count++;
        }
    }

    return count;
}

double ParallelIATScanner::CalculatePointerDensity(const uint8_t* data, size_t size) {
    if (size == 0) return 0.0;

    size_t ptrSize = sizeof(void*);
    size_t maxPointers = size / ptrSize;
    size_t validPointers = CountValidPointers(data, size);

    return (maxPointers > 0) ? (static_cast<double>(validPointers) / maxPointers) : 0.0;
}

bool ParallelIATScanner::LooksLikeIAT(const uint8_t* data, size_t offset, size_t size) {
    if (!data || offset + 64 > size) return false;

    const uint8_t* ptr = data + offset;
    size_t remainingSize = size - offset;

    // Calculate pointer density
    double density = CalculatePointerDensity(ptr, std::min(remainingSize, size_t(256)));

    // IAT usually has high pointer density (>60%)
    if (density < 0.6) return false;

    // Check for consecutive valid pointers
    size_t consecutiveValid = 0;
    size_t ptrSize = sizeof(void*);

    for (size_t i = 0; i + ptrSize <= std::min(remainingSize, size_t(128)); i += ptrSize) {
        uint64_t pointer = 0;

#ifdef _WIN64
        pointer = *reinterpret_cast<const uint64_t*>(ptr + i);
#else
        pointer = *reinterpret_cast<const uint32_t*>(ptr + i);
#endif

        if (IsValidIATPointer(pointer, {})) {
            consecutiveValid++;
            if (consecutiveValid >= 4) {
                return true;  // Found 4 consecutive valid pointers
            }
        } else {
            consecutiveValid = 0;
        }
    }

    return consecutiveValid >= 3;
}

int ParallelIATScanner::CalculateConfidence(const IATCandidate& candidate) {
    int confidence = 0;

    // Base confidence from pointer count
    size_t ptrCount = candidate.pointers.size();
    if (ptrCount >= 4) confidence += 30;
    if (ptrCount >= 8) confidence += 20;
    if (ptrCount >= 16) confidence += 20;

    // Confidence from size (typical IAT sizes)
    if (candidate.size >= 64 && candidate.size <= 4096) {
        confidence += 20;
    }

    // Confidence from alignment
    if ((candidate.address & 0xFFF) == 0) {
        confidence += 10;  // Page-aligned
    } else if ((candidate.address & 0xFF) == 0) {
        confidence += 5;  // 256-byte aligned
    }

    return std::min(confidence, 100);
}

std::vector<IATCandidate> ParallelIATScanner::ScanRegion(const MemoryRegion& region) {
    std::vector<IATCandidate> candidates;

    if (!IsIATPossibleRegion(region) || !region.data) {
        return candidates;
    }

    // Scan region for IAT patterns
    size_t ptrSize = sizeof(void*);
    size_t step = ptrSize;  // Scan every pointer-sized offset

    for (size_t offset = 0; offset + 64 <= region.size && !m_cancelled; offset += step) {
        if (LooksLikeIAT(region.data, offset, region.size)) {
            IATCandidate candidate;
            candidate.address = region.address + offset;

            // Determine IAT size
            size_t iatSize = 0;
            for (size_t i = offset; i + ptrSize <= region.size; i += ptrSize) {
                uint64_t pointer = 0;

#ifdef _WIN64
                pointer = *reinterpret_cast<const uint64_t*>(region.data + i);
#else
                pointer = *reinterpret_cast<const uint32_t*>(region.data + i);
#endif

                if (pointer == 0) {
                    // Null terminator - end of IAT
                    iatSize = i - offset;
                    break;
                }

                if (IsValidIATPointer(pointer, region)) {
                    candidate.pointers.push_back(pointer);
                } else {
                    // Invalid pointer - might be end of IAT
                    if (candidate.pointers.size() >= 4) {
                        iatSize = i - offset;
                        break;
                    }
                }

                // Limit IAT size
                if (i - offset >= 8192) {
                    iatSize = i - offset;
                    break;
                }
            }

            if (iatSize == 0) {
                iatSize = candidate.pointers.size() * ptrSize;
            }

            candidate.size = static_cast<uint32_t>(iatSize);
            candidate.confidence = CalculateConfidence(candidate);
            candidate.valid = (candidate.confidence >= m_minConfidence);

            if (candidate.valid) {
                candidates.push_back(candidate);
            }

            // Skip ahead past this IAT
            offset += iatSize;
        }
    }

    return candidates;
}

void ParallelIATScanner::WorkerThread(
    const std::vector<MemoryRegion>& regions,
    size_t startIndex,
    size_t endIndex,
    std::vector<IATCandidate>& results)
{
    for (size_t i = startIndex; i < endIndex && !m_cancelled; i++) {
        auto candidates = ScanRegion(regions[i]);

        if (!candidates.empty()) {
            std::lock_guard<std::mutex> lock(m_resultsMutex);
            results.insert(results.end(), candidates.begin(), candidates.end());
        }
    }
}

std::vector<IATCandidate> ParallelIATScanner::ScanParallel(
    const std::vector<MemoryRegion>& regions)
{
    m_cancelled = false;
    m_statistics = {};

    auto startTime = std::chrono::high_resolution_clock::now();

    std::vector<IATCandidate> allResults;

    if (regions.empty()) {
        return allResults;
    }

    // Filter regions that might contain IAT
    std::vector<size_t> viableRegions;
    for (size_t i = 0; i < regions.size(); i++) {
        if (IsIATPossibleRegion(regions[i])) {
            viableRegions.push_back(i);
        }
    }

    if (viableRegions.empty()) {
        return allResults;
    }

    // Determine actual thread count
    size_t threadCount = std::min(m_threadCount, viableRegions.size());

    // Create thread results vectors
    std::vector<std::vector<IATCandidate>> threadResults(threadCount);
    std::vector<std::thread> threads;

    // Divide work among threads
    size_t regionsPerThread = viableRegions.size() / threadCount;
    size_t remainder = viableRegions.size() % threadCount;

    size_t currentIndex = 0;
    for (size_t t = 0; t < threadCount; t++) {
        size_t startIdx = currentIndex;
        size_t count = regionsPerThread + (t < remainder ? 1 : 0);
        size_t endIdx = startIdx + count;

        threads.emplace_back([this, &regions, &viableRegions, &threadResults, t, startIdx, endIdx]() {
            for (size_t i = startIdx; i < endIdx && !m_cancelled; i++) {
                size_t regionIdx = viableRegions[i];
                auto candidates = ScanRegion(regions[regionIdx]);
                threadResults[t].insert(threadResults[t].end(), candidates.begin(), candidates.end());
            }
        });

        currentIndex = endIdx;
    }

    // Wait for all threads
    for (auto& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    // Merge results
    for (const auto& results : threadResults) {
        allResults.insert(allResults.end(), results.begin(), results.end());
    }

    // Sort by confidence (highest first)
    std::sort(allResults.begin(), allResults.end(),
        [](const IATCandidate& a, const IATCandidate& b) {
            return a.confidence > b.confidence;
        });

    // Update statistics
    auto endTime = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = endTime - startTime;

    m_statistics.regionsScanned = regions.size();
    m_statistics.bytesScanned = 0;
    for (const auto& region : regions) {
        m_statistics.bytesScanned += region.size;
    }
    m_statistics.candidatesFound = allResults.size();
    m_statistics.scanTime = elapsed.count();
    m_statistics.threadsUsed = threadCount;

    return allResults;
}

// Thread Pool Implementation

ThreadPool::ThreadPool(size_t threadCount)
    : m_stop(false)
    , m_activeTasks(0)
{
    for (size_t i = 0; i < threadCount; i++) {
        m_workers.emplace_back([this]() {
            while (true) {
                std::function<void()> task;

                {
                    std::unique_lock<std::mutex> lock(m_queueMutex);
                    m_condition.wait(lock, [this]() {
                        return m_stop || !m_tasks.empty();
                    });

                    if (m_stop && m_tasks.empty()) {
                        return;
                    }

                    task = std::move(m_tasks.front());
                    m_tasks.pop();
                }

                task();
                m_activeTasks--;
            }
        });
    }
}

ThreadPool::~ThreadPool() {
    {
        std::unique_lock<std::mutex> lock(m_queueMutex);
        m_stop = true;
    }

    m_condition.notify_all();

    for (auto& worker : m_workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

void ThreadPool::WaitAll() {
    while (m_activeTasks > 0 || !m_tasks.empty()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

} // namespace Scylla
