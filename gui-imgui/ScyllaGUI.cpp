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
