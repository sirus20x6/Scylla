#include "ScyllaGUI.h"

// Dear ImGui
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

// GLFW
#include <GLFW/glfw3.h>

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cmath>

namespace scylla {
namespace gui {

//-----------------------------------------------------------------------------
// Implementation
//-----------------------------------------------------------------------------

class ScyllaGUI::Impl {
public:
    GLFWwindow* window = nullptr;
    ImGuiContext* imguiContext = nullptr;
    bool initialized = false;
};

ScyllaGUI::ScyllaGUI() : pImpl(std::make_unique<Impl>()) {
}

ScyllaGUI::~ScyllaGUI() {
    Shutdown();
}

bool ScyllaGUI::Initialize(int width, int height, const char* title) {
    // Initialize GLFW
    if (!glfwInit()) {
        return false;
    }

    // GL 3.3 + GLSL 330
    const char* glsl_version = "#version 330";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
#ifdef __APPLE__
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#endif

    // Create window
    pImpl->window = glfwCreateWindow(width, height, title, nullptr, nullptr);
    if (!pImpl->window) {
        glfwTerminate();
        return false;
    }

    glfwMakeContextCurrent(pImpl->window);
    glfwSwapInterval(1);  // Enable vsync

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    pImpl->imguiContext = ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;

    // Setup Platform/Renderer backends
    ImGui_ImplGlfw_InitForOpenGL(pImpl->window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // Apply default theme
    SetTheme(Theme::Dark);

    pImpl->initialized = true;
    return true;
}

void ScyllaGUI::Run() {
    if (!pImpl->initialized) {
        return;
    }

    while (!glfwWindowShouldClose(pImpl->window)) {
        glfwPollEvents();

        // Start ImGui frame
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // Create main docking space
        ImGuiViewport* viewport = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(viewport->WorkPos);
        ImGui::SetNextWindowSize(viewport->WorkSize);
        ImGui::SetNextWindowViewport(viewport->ID);

        ImGuiWindowFlags window_flags = ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoDocking;
        window_flags |= ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse;
        window_flags |= ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove;
        window_flags |= ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus;

        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));

        ImGui::Begin("DockSpace", nullptr, window_flags);
        ImGui::PopStyleVar(3);

        // Main menu bar
        RenderMainMenu();

        // DockSpace
        ImGuiID dockspace_id = ImGui::GetID("MainDockSpace");
        ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f), ImGuiDockNodeFlags_None);

        ImGui::End();

        // Render tabs
        RenderProcessSelector();
        RenderIATAnalysis();
        RenderSecurityAnalysis();
        RenderSymbolBrowser();

        // Optional windows
        if (showSettings) {
            RenderSettings();
        }
        if (showAbout) {
            RenderAbout();
        }

        RenderLogConsole();

        // Rendering
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(pImpl->window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.1f, 0.1f, 0.1f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(pImpl->window);
    }
}

void ScyllaGUI::Shutdown() {
    if (pImpl->initialized) {
        ImGui_ImplOpenGL3_Shutdown();
        ImGui_ImplGlfw_Shutdown();
        ImGui::DestroyContext(pImpl->imguiContext);

        glfwDestroyWindow(pImpl->window);
        glfwTerminate();

        pImpl->initialized = false;
    }
}

void ScyllaGUI::SetTheme(Theme theme) {
    currentTheme = theme;

    switch (theme) {
        case Theme::Dark:
            Themes::ApplyDarkTheme();
            break;
        case Theme::Light:
            Themes::ApplyLightTheme();
            break;
        case Theme::Classic:
            Themes::ApplyClassicTheme();
            break;
    }
}

//-----------------------------------------------------------------------------
// UI Rendering
//-----------------------------------------------------------------------------

void ScyllaGUI::RenderMainMenu() {
    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Attach to Process...", "Ctrl+O")) {
                showProcessList = true;
            }
            if (ImGui::MenuItem("Detach", "Ctrl+D", false, IsProcessAttached())) {
                DetachFromProcess();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Export Results...", "Ctrl+E", false, IsProcessAttached())) {
                ExportResults("json");
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Exit", "Alt+F4")) {
                glfwSetWindowShouldClose(pImpl->window, 1);
            }
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Analysis")) {
            if (ImGui::MenuItem("Start IAT Scan", "F5", false, IsProcessAttached())) {
                StartIATScan();
            }
            if (ImGui::MenuItem("Security Analysis", "F6", false, IsProcessAttached())) {
                PerformSecurityAnalysis();
            }
            if (ImGui::MenuItem("Load Symbols", "F7", false, IsProcessAttached())) {
                LoadSymbols();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Stop", "Esc", false, iatResult.progress > 0 && iatResult.progress < 100)) {
                StopIATScan();
            }
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("View")) {
            if (ImGui::BeginMenu("Theme")) {
                if (ImGui::MenuItem("Dark", nullptr, currentTheme == Theme::Dark)) {
                    SetTheme(Theme::Dark);
                }
                if (ImGui::MenuItem("Light", nullptr, currentTheme == Theme::Light)) {
                    SetTheme(Theme::Light);
                }
                if (ImGui::MenuItem("Classic", nullptr, currentTheme == Theme::Classic)) {
                    SetTheme(Theme::Classic);
                }
                ImGui::EndMenu();
            }
            ImGui::Separator();
            ImGui::MenuItem("Process List", nullptr, &showProcessList);
            ImGui::MenuItem("Settings", nullptr, &showSettings);
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Help")) {
            if (ImGui::MenuItem("Documentation")) {
                // Open docs
            }
            if (ImGui::MenuItem("About")) {
                showAbout = true;
            }
            ImGui::EndMenu();
        }

        // Right-aligned status
        ImGui::SameLine(ImGui::GetWindowWidth() - 300);
        if (IsProcessAttached()) {
            ImGui::TextColored(ImVec4(0.2f, 1.0f, 0.2f, 1.0f), "Attached");
            ImGui::SameLine();
            ImGui::Text("PID: %u", selectedProcess ? selectedProcess->pid : 0);
        } else {
            ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.0f, 1.0f), "Not Attached");
        }

        ImGui::EndMenuBar();
    }
}

void ScyllaGUI::RenderProcessSelector() {
    ImGui::Begin("Process Selection");

    ImGui::Text("Select a target process to analyze");
    ImGui::Separator();

    if (ImGui::Button("Refresh Process List", ImVec2(200, 0))) {
        UpdateProcessList();
    }

    ImGui::SameLine();
    ImGui::Checkbox("Auto-refresh", &autoRefresh);

    ImGui::Spacing();

    // Filter
    static char searchFilter[256] = "";
    ImGui::SetNextItemWidth(300);
    ImGui::InputText("Filter", searchFilter, sizeof(searchFilter));

    ImGui::Spacing();

    // Process table
    if (ImGui::BeginTable("ProcessTable", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_ScrollY | ImGuiTableFlags_Sortable)) {
        ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Arch", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        for (auto& proc : processes) {
            // Apply filter
            if (searchFilter[0] != '\0') {
                if (proc.name.find(searchFilter) == std::string::npos &&
                    proc.path.find(searchFilter) == std::string::npos) {
                    continue;
                }
            }

            ImGui::TableNextRow();
            ImGui::TableNextColumn();

            if (ImGui::Selectable(std::to_string(proc.pid).c_str(),
                                 selectedProcess == &proc,
                                 ImGuiSelectableFlags_SpanAllColumns)) {
                selectedProcess = &proc;
            }

            if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
                AttachToProcess(proc.pid);
            }

            ImGui::TableNextColumn();
            ImGui::Text("%s", proc.name.c_str());

            ImGui::TableNextColumn();
            ImGui::Text("%s", proc.path.c_str());

            ImGui::TableNextColumn();
            ImGui::Text("%s", proc.is64Bit ? "x64" : "x86");

            ImGui::TableNextColumn();
            if (proc.isManaged) {
                UIUtils::ColoredBadge(".NET", 0.5f, 0.3f, 1.0f);
            } else {
                ImGui::Text("Native");
            }
        }

        ImGui::EndTable();
    }

    ImGui::Spacing();

    if (selectedProcess) {
        if (ImGui::Button("Attach", ImVec2(120, 0))) {
            AttachToProcess(selectedProcess->pid);
        }
    }

    ImGui::End();
}

void ScyllaGUI::RenderIATAnalysis() {
    ImGui::Begin("IAT Analysis");

    if (!IsProcessAttached()) {
        ImGui::TextColored(ImVec4(1.0f, 0.7f, 0.0f, 1.0f), "Please attach to a process first");
        ImGui::End();
        return;
    }

    // Control buttons
    if (iatResult.progress == 0 || iatResult.completed) {
        if (ImGui::Button("Start IAT Scan", ImVec2(150, 0))) {
            StartIATScan();
        }
    } else {
        if (ImGui::Button("Stop Scan", ImVec2(150, 0))) {
            StopIATScan();
        }
    }

    ImGui::SameLine();
    ImGui::Text("Status: %s", iatResult.status.c_str());

    ImGui::Spacing();

    // Progress
    if (iatResult.progress > 0) {
        ImGui::ProgressBar(iatResult.progress / 100.0f, ImVec2(-1, 0),
                          (std::to_string((int)iatResult.progress) + "%").c_str());
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Results summary
    if (iatResult.foundAPIs > 0 || iatResult.completed) {
        ImGui::Columns(3, "ResultColumns");

        ImGui::TextColored(ImVec4(0.2f, 1.0f, 0.2f, 1.0f), "Found APIs");
        ImGui::Text("%u", iatResult.foundAPIs);
        ImGui::NextColumn();

        ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.2f, 1.0f), "Suspect APIs");
        ImGui::Text("%u", iatResult.suspectAPIs);
        ImGui::NextColumn();

        ImGui::TextColored(ImVec4(1.0f, 0.2f, 0.2f, 1.0f), "Invalid APIs");
        ImGui::Text("%u", iatResult.invalidAPIs);

        ImGui::Columns(1);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Detailed results table
        RenderResultsTable();
    }

    ImGui::End();
}

void ScyllaGUI::RenderSecurityAnalysis() {
    ImGui::Begin("Security Analysis");

    if (!IsProcessAttached()) {
        ImGui::TextColored(ImVec4(1.0f, 0.7f, 0.0f, 1.0f), "Please attach to a process first");
        ImGui::End();
        return;
    }

    if (ImGui::Button("Analyze Security", ImVec2(150, 0))) {
        PerformSecurityAnalysis();
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    if (securityResult.score > 0) {
        // Security score gauge
        ImGui::Text("Security Score:");
        ImGui::SameLine(200);
        UIUtils::SecurityScoreGauge(securityResult.score, 50.0f);
        ImGui::SameLine(280);
        ImGui::Text("%d / 100", securityResult.score);

        ImGui::Spacing();

        // Risk level
        float r, g, b;
        UIUtils::GetRiskLevelColor(securityResult.riskLevel, r, g, b);
        ImGui::Text("Risk Level:");
        ImGui::SameLine(200);
        ImGui::TextColored(ImVec4(r, g, b, 1.0f), "%s", securityResult.riskLevel.c_str());

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Mitigations
        ImGui::Text("Security Mitigations:");
        ImGui::Spacing();

        ImGui::Columns(2, "MitigationColumns");

        ImGui::Checkbox("DEP/NX", (bool*)&securityResult.dep);
        ImGui::Checkbox("ASLR", (bool*)&securityResult.aslr);
        ImGui::NextColumn();
        ImGui::Checkbox("CFG", (bool*)&securityResult.cfg);
        ImGui::Checkbox("Code Signed", (bool*)&securityResult.signed_);

        ImGui::Columns(1);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Weaknesses
        if (!securityResult.weaknesses.empty()) {
            ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.0f, 1.0f), "Weaknesses:");
            for (const auto& weakness : securityResult.weaknesses) {
                ImGui::BulletText("%s", weakness.c_str());
            }
            ImGui::Spacing();
        }

        // Recommendations
        if (!securityResult.recommendations.empty()) {
            ImGui::TextColored(ImVec4(0.2f, 0.8f, 1.0f, 1.0f), "Recommendations:");
            for (const auto& rec : securityResult.recommendations) {
                ImGui::BulletText("%s", rec.c_str());
            }
        }
    }

    ImGui::End();
}

void ScyllaGUI::RenderSymbolBrowser() {
    ImGui::Begin("Symbol Browser");

    if (!IsProcessAttached()) {
        ImGui::TextColored(ImVec4(1.0f, 0.7f, 0.0f, 1.0f), "Please attach to a process first");
        ImGui::End();
        return;
    }

    if (ImGui::Button("Load Symbols", ImVec2(150, 0))) {
        LoadSymbols();
    }

    ImGui::Spacing();

    // Search
    static char symbolSearch[256] = "";
    ImGui::SetNextItemWidth(400);
    ImGui::InputText("Search Symbols", symbolSearch, sizeof(symbolSearch));

    ImGui::Spacing();

    // Symbols table
    if (ImGui::BeginTable("SymbolTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_ScrollY | ImGuiTableFlags_Sortable)) {
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 150.0f);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthFixed, 150.0f);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        for (const auto& sym : symbols) {
            // Apply filter
            if (symbolSearch[0] != '\0') {
                if (sym.name.find(symbolSearch) == std::string::npos) {
                    continue;
                }
            }

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::Text("%s", sym.name.c_str());

            ImGui::TableNextColumn();
            ImGui::Text("0x%016llX", (unsigned long long)sym.address);

            ImGui::TableNextColumn();
            ImGui::Text("%s", sym.type.c_str());

            ImGui::TableNextColumn();
            ImGui::Text("%s", sym.module.c_str());
        }

        ImGui::EndTable();
    }

    ImGui::End();
}

void ScyllaGUI::RenderSettings() {
    UIUtils::CenterNextWindow();
    ImGui::SetNextWindowSize(ImVec2(500, 400), ImGuiCond_FirstUseEver);

    if (ImGui::Begin("Settings", &showSettings)) {
        if (ImGui::BeginTabBar("SettingsTabs")) {
            if (ImGui::BeginTabItem("General")) {
                ImGui::Checkbox("Auto-refresh process list", &autoRefresh);
                ImGui::SliderInt("Refresh interval (ms)", &refreshInterval, 500, 5000);

                ImGui::Spacing();
                ImGui::Separator();
                ImGui::Spacing();

                ImGui::Text("Theme:");
                if (ImGui::RadioButton("Dark", currentTheme == Theme::Dark)) {
                    SetTheme(Theme::Dark);
                }
                ImGui::SameLine();
                if (ImGui::RadioButton("Light", currentTheme == Theme::Light)) {
                    SetTheme(Theme::Light);
                }
                ImGui::SameLine();
                if (ImGui::RadioButton("Classic", currentTheme == Theme::Classic)) {
                    SetTheme(Theme::Classic);
                }

                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Analysis")) {
                ImGui::Text("Analysis Configuration");
                ImGui::Spacing();
                // Add analysis settings here
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Advanced")) {
                ImGui::Text("Advanced Settings");
                ImGui::Spacing();
                // Add advanced settings here
                ImGui::EndTabItem();
            }

            ImGui::EndTabBar();
        }

        ImGui::Spacing();
        if (ImGui::Button("Save", ImVec2(120, 0))) {
            showSettings = false;
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120, 0))) {
            showSettings = false;
        }
    }
    ImGui::End();
}

void ScyllaGUI::RenderAbout() {
    UIUtils::CenterNextWindow();
    ImGui::SetNextWindowSize(ImVec2(450, 300), ImGuiCond_Always);

    if (ImGui::Begin("About Scylla", &showAbout, ImGuiWindowFlags_NoResize)) {
        ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[0]);
        ImGui::SetCursorPosX((ImGui::GetWindowWidth() - ImGui::CalcTextSize("Scylla").x) / 2);
        ImGui::Text("Scylla");
        ImGui::PopFont();

        ImGui::SetCursorPosX((ImGui::GetWindowWidth() - ImGui::CalcTextSize("Advanced PE Analysis Tool").x) / 2);
        ImGui::Text("Advanced PE Analysis Tool");

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::Text("Version: 2.0.0");
        ImGui::Text("Build Date: %s %s", __DATE__, __TIME__);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::TextWrapped("Scylla is a comprehensive binary analysis framework supporting PE, ELF, and .NET formats with advanced security analysis, symbol resolution, and IAT reconstruction.");

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::Text("Features:");
        ImGui::BulletText("IAT Reconstruction");
        ImGui::BulletText("Security Analysis");
        ImGui::BulletText("Symbol Resolution");
        ImGui::BulletText("Multi-format Support");

        ImGui::Spacing();

        if (ImGui::Button("Close", ImVec2(120, 0))) {
            showAbout = false;
        }
    }
    ImGui::End();
}

void ScyllaGUI::RenderResultsTable() {
    // Placeholder for IAT results table
    ImGui::Text("IAT Results:");
    ImGui::Spacing();

    if (ImGui::BeginTable("IATResultsTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 150.0f);
        ImGui::TableSetupColumn("API", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        // Example data
        for (int i = 0; i < 10; i++) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::Text("0x140001%03d", i * 100);
            ImGui::TableNextColumn();
            ImGui::Text("ExampleAPI_%d", i);
            ImGui::TableNextColumn();
            ImGui::Text("kernel32.dll");
            ImGui::TableNextColumn();
            UIUtils::ColoredBadge("Valid", 0.2f, 1.0f, 0.2f);
        }

        ImGui::EndTable();
    }
}

void ScyllaGUI::RenderLogConsole() {
    ImGui::Begin("Log");

    if (ImGui::Button("Clear")) {
        logMessages.clear();
    }

    ImGui::Separator();

    ImGui::BeginChild("LogScrolling", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);
    for (const auto& msg : logMessages) {
        ImGui::TextUnformatted(msg.c_str());
    }
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
        ImGui::SetScrollHereY(1.0f);
    }
    ImGui::EndChild();

    ImGui::End();
}

//-----------------------------------------------------------------------------
// Actions
//-----------------------------------------------------------------------------

void ScyllaGUI::AttachToProcess(uint32_t pid) {
    logMessages.push_back("[INFO] Attaching to process " + std::to_string(pid));
    // Actual implementation would attach to process
}

void ScyllaGUI::DetachFromProcess() {
    logMessages.push_back("[INFO] Detached from process");
    selectedProcess = nullptr;
}

void ScyllaGUI::StartIATScan() {
    logMessages.push_back("[INFO] Starting IAT scan...");
    iatResult.progress = 0;
    iatResult.completed = false;
    iatResult.status = "Scanning...";
    // Start actual scan
}

void ScyllaGUI::StopIATScan() {
    logMessages.push_back("[INFO] IAT scan stopped");
    iatResult.completed = true;
    iatResult.status = "Stopped";
}

void ScyllaGUI::PerformSecurityAnalysis() {
    logMessages.push_back("[INFO] Performing security analysis...");
    // Actual implementation
}

void ScyllaGUI::LoadSymbols() {
    logMessages.push_back("[INFO] Loading symbols...");
    // Actual implementation
}

void ScyllaGUI::ExportResults(const std::string& format) {
    logMessages.push_back("[INFO] Exporting results as " + format);
    // Actual implementation
}

bool ScyllaGUI::IsProcessAttached() const {
    return selectedProcess != nullptr;
}

void ScyllaGUI::UpdateProcessList() {
    logMessages.push_back("[INFO] Refreshing process list...");
    // Actual implementation would enumerate processes
}

void ScyllaGUI::UpdateAnalysisProgress() {
    // Update progress from background tasks
}

//-----------------------------------------------------------------------------
// Themes
//-----------------------------------------------------------------------------

namespace Themes {

void ApplyDarkTheme() {
    ImGuiStyle& style = ImGui::GetStyle();
    ImVec4* colors = style.Colors;

    colors[ImGuiCol_Text] = ImVec4(0.95f, 0.95f, 0.95f, 1.00f);
    colors[ImGuiCol_TextDisabled] = ImVec4(0.50f, 0.50f, 0.50f, 1.00f);
    colors[ImGuiCol_WindowBg] = ImVec4(0.13f, 0.14f, 0.15f, 1.00f);
    colors[ImGuiCol_ChildBg] = ImVec4(0.13f, 0.14f, 0.15f, 1.00f);
    colors[ImGuiCol_PopupBg] = ImVec4(0.13f, 0.14f, 0.15f, 1.00f);
    colors[ImGuiCol_Border] = ImVec4(0.43f, 0.43f, 0.50f, 0.50f);
    colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_FrameBg] = ImVec4(0.25f, 0.25f, 0.25f, 1.00f);
    colors[ImGuiCol_FrameBgHovered] = ImVec4(0.38f, 0.38f, 0.38f, 1.00f);
    colors[ImGuiCol_FrameBgActive] = ImVec4(0.67f, 0.67f, 0.67f, 0.39f);
    colors[ImGuiCol_TitleBg] = ImVec4(0.08f, 0.08f, 0.09f, 1.00f);
    colors[ImGuiCol_TitleBgActive] = ImVec4(0.08f, 0.08f, 0.09f, 1.00f);
    colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.00f, 0.00f, 0.00f, 0.51f);
    colors[ImGuiCol_MenuBarBg] = ImVec4(0.14f, 0.14f, 0.14f, 1.00f);
    colors[ImGuiCol_ScrollbarBg] = ImVec4(0.02f, 0.02f, 0.02f, 0.53f);
    colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.31f, 0.31f, 0.31f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.41f, 0.41f, 0.41f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.51f, 0.51f, 0.51f, 1.00f);
    colors[ImGuiCol_CheckMark] = ImVec4(0.11f, 0.64f, 0.92f, 1.00f);
    colors[ImGuiCol_SliderGrab] = ImVec4(0.11f, 0.64f, 0.92f, 1.00f);
    colors[ImGuiCol_SliderGrabActive] = ImVec4(0.08f, 0.50f, 0.72f, 1.00f);
    colors[ImGuiCol_Button] = ImVec4(0.25f, 0.25f, 0.25f, 1.00f);
    colors[ImGuiCol_ButtonHovered] = ImVec4(0.38f, 0.38f, 0.38f, 1.00f);
    colors[ImGuiCol_ButtonActive] = ImVec4(0.67f, 0.67f, 0.67f, 0.39f);
    colors[ImGuiCol_Header] = ImVec4(0.22f, 0.22f, 0.22f, 1.00f);
    colors[ImGuiCol_HeaderHovered] = ImVec4(0.25f, 0.25f, 0.25f, 1.00f);
    colors[ImGuiCol_HeaderActive] = ImVec4(0.67f, 0.67f, 0.67f, 0.39f);
    colors[ImGuiCol_Separator] = colors[ImGuiCol_Border];
    colors[ImGuiCol_SeparatorHovered] = ImVec4(0.41f, 0.42f, 0.44f, 1.00f);
    colors[ImGuiCol_SeparatorActive] = ImVec4(0.26f, 0.59f, 0.98f, 0.95f);
    colors[ImGuiCol_ResizeGrip] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.29f, 0.30f, 0.31f, 0.67f);
    colors[ImGuiCol_ResizeGripActive] = ImVec4(0.26f, 0.59f, 0.98f, 0.95f);
    colors[ImGuiCol_Tab] = ImVec4(0.08f, 0.08f, 0.09f, 0.83f);
    colors[ImGuiCol_TabHovered] = ImVec4(0.33f, 0.34f, 0.36f, 0.83f);
    colors[ImGuiCol_TabActive] = ImVec4(0.23f, 0.23f, 0.24f, 1.00f);
    colors[ImGuiCol_TabUnfocused] = ImVec4(0.08f, 0.08f, 0.09f, 1.00f);
    colors[ImGuiCol_TabUnfocusedActive] = ImVec4(0.13f, 0.14f, 0.15f, 1.00f);
    colors[ImGuiCol_DockingPreview] = ImVec4(0.26f, 0.59f, 0.98f, 0.70f);
    colors[ImGuiCol_DockingEmptyBg] = ImVec4(0.20f, 0.20f, 0.20f, 1.00f);
    colors[ImGuiCol_PlotLines] = ImVec4(0.61f, 0.61f, 0.61f, 1.00f);
    colors[ImGuiCol_PlotLinesHovered] = ImVec4(1.00f, 0.43f, 0.35f, 1.00f);
    colors[ImGuiCol_PlotHistogram] = ImVec4(0.90f, 0.70f, 0.00f, 1.00f);
    colors[ImGuiCol_PlotHistogramHovered] = ImVec4(1.00f, 0.60f, 0.00f, 1.00f);
    colors[ImGuiCol_TextSelectedBg] = ImVec4(0.26f, 0.59f, 0.98f, 0.35f);
    colors[ImGuiCol_DragDropTarget] = ImVec4(0.11f, 0.64f, 0.92f, 1.00f);
    colors[ImGuiCol_NavHighlight] = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
    colors[ImGuiCol_NavWindowingHighlight] = ImVec4(1.00f, 1.00f, 1.00f, 0.70f);
    colors[ImGuiCol_NavWindowingDimBg] = ImVec4(0.80f, 0.80f, 0.80f, 0.20f);
    colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.80f, 0.80f, 0.80f, 0.35f);

    style.FrameRounding = 2.3f;
    style.ScrollbarRounding = 0;
    style.GrabRounding = 0;
}

void ApplyLightTheme() {
    ImGui::StyleColorsLight();
}

void ApplyClassicTheme() {
    ImGui::StyleColorsClassic();
}

} // namespace Themes

//-----------------------------------------------------------------------------
// UI Utilities
//-----------------------------------------------------------------------------

namespace UIUtils {

void ColoredBadge(const char* label, float r, float g, float b) {
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(r, g, b, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(r * 1.2f, g * 1.2f, b * 1.2f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(r * 0.8f, g * 0.8f, b * 0.8f, 1.0f));
    ImGui::SmallButton(label);
    ImGui::PopStyleColor(3);
}

void SecurityScoreGauge(int score, float radius) {
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    ImVec2 p = ImGui::GetCursorScreenPos();

    float thickness = 6.0f;
    int segments = 32;

    // Background arc
    draw_list->AddCircle(ImVec2(p.x + radius, p.y + radius), radius,
                        IM_COL32(50, 50, 50, 255), segments, thickness);

    // Score arc
    float angle = (score / 100.0f) * 3.14159f * 2.0f;
    ImU32 color = score > 70 ? IM_COL32(50, 255, 50, 255) :
                  score > 40 ? IM_COL32(255, 255, 50, 255) :
                              IM_COL32(255, 50, 50, 255);

    draw_list->PathArcTo(ImVec2(p.x + radius, p.y + radius), radius,
                        -3.14159f / 2.0f, -3.14159f / 2.0f + angle, segments);
    draw_list->PathStroke(color, 0, thickness);

    ImGui::Dummy(ImVec2(radius * 2, radius * 2));
}

void GetRiskLevelColor(const std::string& level, float& r, float& g, float& b) {
    if (level == "Low" || level == "Minimal") {
        r = 0.2f; g = 1.0f; b = 0.2f;
    } else if (level == "Medium") {
        r = 1.0f; g = 1.0f; b = 0.2f;
    } else if (level == "High") {
        r = 1.0f; g = 0.5f; b = 0.0f;
    } else {  // Critical
        r = 1.0f; g = 0.2f; b = 0.2f;
    }
}

void CenterNextWindow() {
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x + viewport->WorkSize.x / 2,
                                   viewport->WorkPos.y + viewport->WorkSize.y / 2),
                           ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
}

void HelpMarker(const char* desc) {
    ImGui::TextDisabled("(?)");
    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
        ImGui::TextUnformatted(desc);
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
}

std::string FormatFileSize(uint64_t bytes) {
    const char* units[] = { "B", "KB", "MB", "GB", "TB" };
    int unit = 0;
    double size = static_cast<double>(bytes);

    while (size >= 1024.0 && unit < 4) {
        size /= 1024.0;
        unit++;
    }

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << size << " " << units[unit];
    return oss.str();
}

std::string FormatAddress(uint64_t address, bool is64bit) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(is64bit ? 16 : 8) << std::setfill('0') << address;
    return oss.str();
}

} // namespace UIUtils

} // namespace gui
} // namespace scylla
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
