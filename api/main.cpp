/*
 * Scylla API Server - Entry Point
 */

#include "APIServer.h"
#include <iostream>
#include <csignal>
#include <atomic>

using namespace Scylla::API;

// Global server instance
std::unique_ptr<APIServer> g_server;
std::atomic<bool> g_shutdown(false);

void SignalHandler(int signal) {
    std::cout << "\nShutdown signal received...\n";
    g_shutdown = true;

    if (g_server) {
        g_server->Stop();
    }
}

void PrintUsage() {
    std::cout << "Scylla API Server\n";
    std::cout << "Usage: scylla-api [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --host HOST        Bind to HOST (default: 127.0.0.1)\n";
    std::cout << "  --port PORT        Listen on PORT (default: 8080)\n";
    std::cout << "  --workers N        Use N worker threads (default: 4)\n";
    std::cout << "  --api-key KEY      Require API key authentication\n";
    std::cout << "  --no-cors          Disable CORS headers\n";
    std::cout << "  --upload-dir DIR   Upload directory (default: uploads)\n";
    std::cout << "  --help             Show this help message\n";
}

int main(int argc, char* argv[]) {
    std::cout << "┌─────────────────────────────────────┐\n";
    std::cout << "│   Scylla REST API Server v2.0.0    │\n";
    std::cout << "└─────────────────────────────────────┘\n\n";

    // Parse command-line arguments
    ServerConfig config;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            PrintUsage();
            return 0;
        }
        else if (arg == "--host" && i + 1 < argc) {
            config.host = argv[++i];
        }
        else if (arg == "--port" && i + 1 < argc) {
            config.port = std::stoi(argv[++i]);
        }
        else if (arg == "--workers" && i + 1 < argc) {
            config.workerThreads = std::stoi(argv[++i]);
        }
        else if (arg == "--api-key" && i + 1 < argc) {
            config.apiKey = argv[++i];
            config.enableAuth = true;
        }
        else if (arg == "--no-cors") {
            config.enableCORS = false;
        }
        else if (arg == "--upload-dir" && i + 1 < argc) {
            config.uploadDir = argv[++i];
        }
        else {
            std::cerr << "Unknown option: " << arg << "\n";
            PrintUsage();
            return 1;
        }
    }

    // Install signal handlers
    std::signal(SIGINT, SignalHandler);
    std::signal(SIGTERM, SignalHandler);

    // Create and start server
    g_server = std::make_unique<APIServer>(config);

    if (!g_server->Start()) {
        std::cerr << "Failed to start server\n";
        return 1;
    }

    // Print available endpoints
    std::cout << "\nAvailable Endpoints:\n";
    std::cout << "  GET  /api/health              - Health check\n";
    std::cout << "  GET  /api/version             - Version information\n";
    std::cout << "  GET  /api/stats               - Server statistics\n\n";

    std::cout << "  POST /api/analyze             - Analyze PE file (sync)\n";
    std::cout << "  POST /api/analyze/async       - Analyze PE file (async)\n";
    std::cout << "  GET  /api/jobs/:id            - Get job status\n\n";

    std::cout << "  POST /api/security            - Security analysis\n";
    std::cout << "  POST /api/security/batch      - Batch security analysis\n\n";

    std::cout << "  POST /api/packer              - Packer detection\n";
    std::cout << "  POST /api/packer/batch        - Batch packer detection\n\n";

    std::cout << "  GET  /api/profiles            - List configuration profiles\n";
    std::cout << "  GET  /api/profiles/:name      - Get profile details\n";
    std::cout << "  POST /api/profiles/:name      - Set active profile\n\n";

    std::cout << "  POST /api/upload              - Upload file\n";
    std::cout << "  GET  /api/download/:id        - Download result\n\n";

    std::cout << "  POST /api/batch/analyze       - Batch analyze\n";
    std::cout << "  GET  /api/batch/:id           - Batch job status\n\n";

    std::cout << "Press Ctrl+C to stop server\n";

    // Wait for shutdown
    while (!g_shutdown) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::cout << "Server stopped\n";

    return 0;
}
