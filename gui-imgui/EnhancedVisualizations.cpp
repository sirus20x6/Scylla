// Enhanced visualizations implementation for Scylla GUI
// To be integrated into ScyllaGUI.cpp

#include "ScyllaGUI.h"
#include "imgui.h"
#include <algorithm>
#include <cmath>

namespace scylla {
namespace gui {

// Memory Region Data
struct MemoryRegion {
    std::string name;
    uint64_t start;
    uint64_t end;
    bool readable;
    bool writable;
    bool executable;
    float entropy;
};

//-----------------------------------------------------------------------------
// Enhanced Visualizations
//-----------------------------------------------------------------------------

void ScyllaGUI::RenderMemoryMap() {
    ImGui::Begin("Memory Map");

    ImGui::Text("Process Memory Layout");
    ImGui::Separator();
    ImGui::Spacing();

    // Sample memory regions (would come from actual process analysis)
    std::vector<MemoryRegion> regions = {
        {".text", 0x400000, 0x450000, true, false, true, 6.5f},
        {".rdata", 0x450000, 0x460000, true, false, false, 4.2f},
        {".data", 0x460000, 0x470000, true, true, false, 3.8f},
        {".rsrc", 0x470000, 0x480000, true, false, false, 5.1f},
        {"Heap", 0x500000, 0x600000, true, true, false, 2.5f},
        {"Stack", 0x7FF00000, 0x80000000, true, true, false, 1.8f}
    };

    // Color legend
    ImGui::Text("Legend:");
    ImGui::SameLine();
    UIUtils::ColoredBadge("R", 0.2f, 0.5f, 1.0f);
    ImGui::SameLine();
    ImGui::Text("Read");
    ImGui::SameLine(200);
    UIUtils::ColoredBadge("W", 1.0f, 0.5f, 0.2f);
    ImGui::SameLine();
    ImGui::Text("Write");
    ImGui::SameLine(400);
    UIUtils::ColoredBadge("X", 0.2f, 1.0f, 0.2f);
    ImGui::SameLine();
    ImGui::Text("Execute");

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Memory map visualization
    float mapWidth = ImGui::GetContentRegionAvail().x - 20;
    float regionHeight = 40.0f;

    for (const auto& region : regions) {
        float r = 0.3f, g = 0.3f, b = 0.3f;

        // Color based on permissions
        if (region.executable) {
            r = 0.2f; g = 1.0f; b = 0.2f;  // Green for executable
        } else if (region.writable) {
            r = 1.0f; g = 0.5f; b = 0.2f;  // Orange for writable
        } else if (region.readable) {
            r = 0.2f; g = 0.5f; b = 1.0f;  // Blue for read-only
        }

        UIUtils::DrawMemoryRegion(region.name.c_str(), region.start, region.end,
                                  r, g, b, region.readable, region.writable, region.executable);

        ImGui::Spacing();
    }

    ImGui::End();
}

void ScyllaGUI::RenderEntropyVisualization() {
    ImGui::Begin("Entropy Analysis");

    ImGui::Text("Section Entropy Analysis");
    ImGui::Separator();
    ImGui::Spacing();

    // Sample entropy data (would come from actual section analysis)
    std::vector<std::pair<std::string, float>> sectionEntropy = {
        {".text", 6.5f},
        {".rdata", 4.2f},
        {".data", 3.8f},
        {".rsrc", 5.1f},
        {"UPX0", 7.8f},   // Packed section - high entropy
        {"UPX1", 7.9f}
    };

    // Entropy graph
    std::vector<float> entropyValues;
    for (const auto& sec : sectionEntropy) {
        entropyValues.push_back(sec.second);
    }

    float graphWidth = ImGui::GetContentRegionAvail().x - 20;
    float graphHeight = 200.0f;
    UIUtils::DrawEntropyGraph(entropyValues, graphWidth, graphHeight);

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Entropy table
    if (ImGui::BeginTable("EntropyTable", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Section", ImGuiTableColumnFlags_WidthFixed, 150.0f);
        ImGui::TableSetupColumn("Entropy", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const auto& sec : sectionEntropy) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::Text("%s", sec.first.c_str());

            ImGui::TableNextColumn();
            ImGui::Text("%.2f", sec.second);
            ImGui::SameLine();
            UIUtils::DrawEntropyIndicator(sec.second);

            ImGui::TableNextColumn();
            if (sec.second > 7.0f) {
                UIUtils::ColoredBadge("High - Likely Packed", 1.0f, 0.2f, 0.2f);
            } else if (sec.second > 6.0f) {
                UIUtils::ColoredBadge("Medium - Code/Data", 1.0f, 1.0f, 0.2f);
            } else {
                UIUtils::ColoredBadge("Low - Normal", 0.2f, 1.0f, 0.2f);
            }
        }

        ImGui::EndTable();
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::TextWrapped("Note: High entropy (>7.0) typically indicates packed or encrypted sections. "
                      "Medium entropy (5.0-7.0) is normal for code. Low entropy (<5.0) suggests "
                      "uninitialized data or padding.");

    ImGui::End();
}

void ScyllaGUI::RenderDependencyGraph() {
    ImGui::Begin("Import Dependencies");

    ImGui::Text("Module Dependency Graph");
    ImGui::Separator();
    ImGui::Spacing();

    // Sample dependency data
    std::vector<std::string> modules = {
        "main.exe",
        "kernel32.dll",
        "ntdll.dll",
        "user32.dll",
        "advapi32.dll",
        "ws2_32.dll"
    };

    std::vector<std::pair<int, int>> dependencies = {
        {0, 1},  // main.exe -> kernel32.dll
        {0, 3},  // main.exe -> user32.dll
        {0, 4},  // main.exe -> advapi32.dll
        {0, 5},  // main.exe -> ws2_32.dll
        {1, 2},  // kernel32.dll -> ntdll.dll
        {3, 2},  // user32.dll -> ntdll.dll
        {4, 2},  // advapi32.dll -> ntdll.dll
        {5, 2}   // ws2_32.dll -> ntdll.dll
    };

    ImGui::Text("Dependencies:");
    ImGui::Spacing();

    UIUtils::DrawDependencyGraph(modules, dependencies);

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Dependency list
    if (ImGui::BeginTable("DependencyTable", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthFixed, 200.0f);
        ImGui::TableSetupColumn("Depends On", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const auto& dep : dependencies) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::Text("%s", modules[dep.first].c_str());
            ImGui::TableNextColumn();
            ImGui::Text("%s", modules[dep.second].c_str());
        }

        ImGui::EndTable();
    }

    ImGui::End();
}

void ScyllaGUI::RenderStructureTree() {
    ImGui::Begin("Binary Structure");

    ImGui::Text("PE/ELF/Mach-O Structure Tree");
    ImGui::Separator();
    ImGui::Spacing();

    // PE Structure Tree
    if (UIUtils::TreeNodeWithIcon("📄", "PE Header")) {
        UIUtils::DrawHexValue("Magic", 0x5A4D, false);
        UIUtils::DrawHexValue("Machine", 0x8664, false);
        UIUtils::DrawHexValue("Number of Sections", 6, false);
        UIUtils::DrawHexValue("Time Date Stamp", 0x61234567, false);
        UIUtils::DrawHexValue("Characteristics", 0x0022, false);

        if (UIUtils::TreeNodeWithIcon("🔧", "Optional Header")) {
            UIUtils::DrawHexValue("Magic", 0x020B, false);
            UIUtils::DrawHexValue("Address of Entry Point", 0x1000);
            UIUtils::DrawHexValue("Image Base", 0x140000000);
            UIUtils::DrawHexValue("Section Alignment", 0x1000, false);
            UIUtils::DrawHexValue("File Alignment", 0x200, false);

            if (UIUtils::TreeNodeWithIcon("📁", "Data Directories")) {
                ImGui::BulletText("Export Table: 0x00000000");
                ImGui::BulletText("Import Table: 0x00005000");
                ImGui::BulletText("Resource Table: 0x00008000");
                ImGui::BulletText("Exception Table: 0x0000A000");
                ImGui::BulletText("Certificate Table: 0x00000000");
                ImGui::BulletText("Base Relocation Table: 0x0000C000");
                ImGui::BulletText("Debug Directory: 0x00007000");
                ImGui::TreePop();
            }

            ImGui::TreePop();
        }

        if (UIUtils::TreeNodeWithIcon("📦", "Sections")) {
            const char* sections[] = {".text", ".rdata", ".data", ".pdata", ".rsrc", ".reloc"};
            for (int i = 0; i < 6; i++) {
                if (UIUtils::TreeNodeWithIcon("📄", sections[i])) {
                    UIUtils::DrawHexValue("Virtual Address", 0x1000 + (i * 0x1000));
                    UIUtils::DrawHexValue("Virtual Size", 0x500 + (i * 0x100), false);
                    UIUtils::DrawHexValue("Raw Size", 0x600 + (i * 0x100), false);
                    UIUtils::DrawHexValue("Characteristics", 0x60000020, false);

                    // Decode characteristics
                    ImGui::Indent();
                    bool isCode = (i == 0);
                    bool isData = (i >= 1 && i <= 2);
                    if (isCode) ImGui::BulletText("IMAGE_SCN_CNT_CODE");
                    if (isData) ImGui::BulletText("IMAGE_SCN_CNT_INITIALIZED_DATA");
                    ImGui::BulletText("IMAGE_SCN_MEM_READ");
                    if (i == 0) ImGui::BulletText("IMAGE_SCN_MEM_EXECUTE");
                    if (i == 2) ImGui::BulletText("IMAGE_SCN_MEM_WRITE");
                    ImGui::Unindent();

                    ImGui::TreePop();
                }
            }
            ImGui::TreePop();
        }

        if (UIUtils::TreeNodeWithIcon("📚", "Imports")) {
            const char* dlls[] = {"kernel32.dll", "ntdll.dll", "user32.dll"};
            for (int i = 0; i < 3; i++) {
                if (UIUtils::TreeNodeWithIcon("📚", dlls[i])) {
                    ImGui::BulletText("LoadLibraryA");
                    ImGui::BulletText("GetProcAddress");
                    ImGui::BulletText("VirtualAlloc");
                    ImGui::BulletText("CreateThread");
                    ImGui::TreePop();
                }
            }
            ImGui::TreePop();
        }

        if (UIUtils::TreeNodeWithIcon("🔐", "Security")) {
            ImGui::BulletText("ASLR: Enabled");
            ImGui::BulletText("DEP: Enabled");
            ImGui::BulletText("CFG: Enabled");
            ImGui::BulletText("Code Signature: Present");
            ImGui::TreePop();
        }

        ImGui::TreePop();
    }

    ImGui::End();
}

//-----------------------------------------------------------------------------
// Enhanced UI Utilities
//-----------------------------------------------------------------------------

namespace UIUtils {

void DrawEntropyGraph(const std::vector<float>& entropy, float width, float height) {
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    ImVec2 p = ImGui::GetCursorScreenPos();

    // Background
    draw_list->AddRectFilled(p, ImVec2(p.x + width, p.y + height),
                            IM_COL32(30, 30, 30, 255));

    // Grid lines
    for (int i = 0; i <= 8; i++) {
        float y = p.y + height - (i / 8.0f * height);
        draw_list->AddLine(ImVec2(p.x, y), ImVec2(p.x + width, y),
                          IM_COL32(60, 60, 60, 255));
    }

    // Draw entropy bars
    if (!entropy.empty()) {
        float barWidth = width / entropy.size();
        for (size_t i = 0; i < entropy.size(); i++) {
            float barHeight = (entropy[i] / 8.0f) * height;
            float x = p.x + i * barWidth;
            float y = p.y + height - barHeight;

            // Color based on entropy value
            ImU32 color;
            if (entropy[i] > 7.0f) {
                color = IM_COL32(255, 50, 50, 255);  // Red - High/Packed
            } else if (entropy[i] > 6.0f) {
                color = IM_COL32(255, 255, 50, 255);  // Yellow - Medium/Code
            } else {
                color = IM_COL32(50, 255, 50, 255);   // Green - Low/Normal
            }

            draw_list->AddRectFilled(ImVec2(x + 2, y), ImVec2(x + barWidth - 2, p.y + height),
                                    color);
        }
    }

    // Border
    draw_list->AddRect(p, ImVec2(p.x + width, p.y + height),
                      IM_COL32(100, 100, 100, 255));

    ImGui::Dummy(ImVec2(width, height));
}

void DrawMemoryRegion(const char* label, uint64_t start, uint64_t end,
                     float r, float g, float b, bool readable, bool writable, bool executable) {
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    ImVec2 p = ImGui::GetCursorScreenPos();
    float width = ImGui::GetContentRegionAvail().x;
    float height = 35.0f;

    // Background
    draw_list->AddRectFilled(p, ImVec2(p.x + width, p.y + height),
                            IM_COL32(int(r*255), int(g*255), int(b*255), 180));

    // Border
    draw_list->AddRect(p, ImVec2(p.x + width, p.y + height),
                      IM_COL32(int(r*255), int(g*255), int(b*255), 255), 2.0f);

    // Label
    char text[256];
    snprintf(text, sizeof(text), "%s [0x%llX - 0x%llX]",
            label, (unsigned long long)start, (unsigned long long)end);

    draw_list->AddText(ImVec2(p.x + 10, p.y + 8), IM_COL32(255, 255, 255, 255), text);

    // Permission flags
    char perms[4] = "---";
    if (readable) perms[0] = 'R';
    if (writable) perms[1] = 'W';
    if (executable) perms[2] = 'X';

    draw_list->AddText(ImVec2(p.x + width - 50, p.y + 8),
                      IM_COL32(255, 255, 255, 255), perms);

    ImGui::Dummy(ImVec2(width, height));
}

void DrawDependencyGraph(const std::vector<std::string>& nodes,
                        const std::vector<std::pair<int, int>>& edges) {
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    ImVec2 p = ImGui::GetCursorScreenPos();
    float width = ImGui::GetContentRegionAvail().x;
    float height = 300.0f;

    // Calculate node positions (simple circular layout)
    std::vector<ImVec2> positions;
    float centerX = p.x + width / 2;
    float centerY = p.y + height / 2;
    float radius = std::min(width, height) / 3;

    for (size_t i = 0; i < nodes.size(); i++) {
        float angle = (i / float(nodes.size())) * 2.0f * 3.14159f;
        positions.push_back(ImVec2(
            centerX + radius * cosf(angle),
            centerY + radius * sinf(angle)
        ));
    }

    // Draw edges
    for (const auto& edge : edges) {
        draw_list->AddLine(positions[edge.first], positions[edge.second],
                          IM_COL32(100, 100, 100, 200), 2.0f);

        // Arrow head
        ImVec2 dir = ImVec2(
            positions[edge.second].x - positions[edge.first].x,
            positions[edge.second].y - positions[edge.first].y
        );
        float len = sqrtf(dir.x * dir.x + dir.y * dir.y);
        dir.x /= len;
        dir.y /= len;

        ImVec2 arrowPos = ImVec2(
            positions[edge.second].x - dir.x * 30,
            positions[edge.second].y - dir.y * 30
        );
        draw_list->AddTriangleFilled(
            arrowPos,
            ImVec2(arrowPos.x - dir.y * 5 + dir.x * 10, arrowPos.y + dir.x * 5 + dir.y * 10),
            ImVec2(arrowPos.x + dir.y * 5 + dir.x * 10, arrowPos.y - dir.x * 5 + dir.y * 10),
            IM_COL32(100, 100, 100, 200)
        );
    }

    // Draw nodes
    for (size_t i = 0; i < nodes.size(); i++) {
        float nodeRadius = 25.0f;
        ImU32 color = (i == 0) ? IM_COL32(50, 150, 255, 255) : IM_COL32(150, 150, 150, 255);

        draw_list->AddCircleFilled(positions[i], nodeRadius, color);
        draw_list->AddCircle(positions[i], nodeRadius, IM_COL32(255, 255, 255, 255), 32, 2.0f);

        // Label
        ImVec2 textSize = ImGui::CalcTextSize(nodes[i].c_str());
        draw_list->AddText(ImVec2(positions[i].x - textSize.x / 2,
                                  positions[i].y - textSize.y / 2),
                          IM_COL32(255, 255, 255, 255), nodes[i].c_str());
    }

    ImGui::Dummy(ImVec2(width, height));
}

bool TreeNodeWithIcon(const char* icon, const char* label) {
    ImGui::PushID(label);
    bool open = ImGui::TreeNode(label, "%s %s", icon, label);
    ImGui::PopID();
    return open;
}

void DrawHexValue(const char* label, uint64_t value, bool is64bit) {
    if (is64bit) {
        ImGui::Text("%s: 0x%016llX", label, (unsigned long long)value);
    } else {
        ImGui::Text("%s: 0x%08X", label, (unsigned int)value);
    }
}

void DrawEntropyIndicator(float entropy) {
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    ImVec2 p = ImGui::GetCursorScreenPos();
    float width = 60.0f;
    float height = 10.0f;

    // Background
    draw_list->AddRectFilled(p, ImVec2(p.x + width, p.y + height),
                            IM_COL32(50, 50, 50, 255));

    // Fill based on entropy
    float fillWidth = (entropy / 8.0f) * width;
    ImU32 color;
    if (entropy > 7.0f) {
        color = IM_COL32(255, 50, 50, 255);
    } else if (entropy > 6.0f) {
        color = IM_COL32(255, 255, 50, 255);
    } else {
        color = IM_COL32(50, 255, 50, 255);
    }

    draw_list->AddRectFilled(p, ImVec2(p.x + fillWidth, p.y + height), color);

    // Border
    draw_list->AddRect(p, ImVec2(p.x + width, p.y + height),
                      IM_COL32(100, 100, 100, 255));

    ImGui::Dummy(ImVec2(width, height));
}

} // namespace UIUtils

} // namespace gui
} // namespace scylla
