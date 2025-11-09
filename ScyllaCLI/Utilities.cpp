/*
 * Scylla CLI - Utility Functions
 */

#include "Commands.h"
#include <sstream>
#include <iomanip>
#include <iostream>
#include <cmath>
#include <locale>
#include <codecvt>

namespace ScyllaCLI {

std::string FormatHex(uint64_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << std::setfill('0');

    if (value <= 0xFFFF) {
        oss << std::setw(4) << value;
    } else if (value <= 0xFFFFFFFF) {
        oss << std::setw(8) << value;
    } else {
        oss << std::setw(16) << value;
    }

    return oss.str();
}

std::string FormatSize(uint64_t bytes) {
    const char* units[] = { "B", "KB", "MB", "GB", "TB" };
    int unit = 0;
    double size = static_cast<double>(bytes);

    while (size >= 1024.0 && unit < 4) {
        size /= 1024.0;
        unit++;
    }

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << size << " " << units[unit];
    return oss.str();
}

std::string FormatFlags(uint32_t flags) {
    std::string result;

    // PE section characteristics
    if (flags & 0x20000000) result += "X";  // Execute
    if (flags & 0x40000000) result += "R";  // Read
    if (flags & 0x80000000) result += "W";  // Write

    if (result.empty()) result = "-";

    return result;
}

std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();

    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    try {
        return converter.to_bytes(wstr);
    } catch (...) {
        // Fallback: simple conversion
        return std::string(wstr.begin(), wstr.end());
    }
}

std::wstring StringToWString(const std::string& str) {
    if (str.empty()) return std::wstring();

    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    try {
        return converter.from_bytes(str);
    } catch (...) {
        // Fallback: simple conversion
        return std::wstring(str.begin(), str.end());
    }
}

// Progress Bar Implementation
ProgressBar::ProgressBar(size_t total, const std::string& prefix)
    : m_total(total)
    , m_current(0)
    , m_prefix(prefix)
    , m_completed(false)
{
}

void ProgressBar::Update(size_t current) {
    if (m_completed) return;

    m_current = current;
    int percentage = (m_total > 0) ? (m_current * 100) / m_total : 0;
    int barWidth = 50;
    int pos = (m_total > 0) ? (barWidth * m_current) / m_total : 0;

    std::cout << "\r" << m_prefix << " [";
    for (int i = 0; i < barWidth; ++i) {
        if (i < pos) std::cout << "=";
        else if (i == pos) std::cout << ">";
        else std::cout << " ";
    }
    std::cout << "] " << percentage << "% ("
              << m_current << "/" << m_total << ")";
    std::cout.flush();
}

void ProgressBar::Complete() {
    if (!m_completed) {
        Update(m_total);
        std::cout << std::endl;
        m_completed = true;
    }
}

} // namespace ScyllaCLI
