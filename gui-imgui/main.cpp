/**
 * Scylla GUI Application
 * Main entry point for Dear ImGui-based interface
 */

#include "ScyllaGUI.h"
#include <iostream>

int main(int argc, char** argv) {
    try {
        scylla::gui::ScyllaGUI app;

        if (!app.Initialize()) {
            std::cerr << "Failed to initialize Scylla GUI\n";
            return 1;
        }

        app.Run();
        app.Shutdown();

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return 1;
    }
}
