/*
 * Scylla CLI - Enhanced Main Entry Point
 */

#include "Commands.h"
#include <iostream>
#include <memory>
#include <map>
#include <string>

using namespace ScyllaCLI;

void printVersion() {
    std::cout << "Scylla CLI v0.9.9 - PE Import Table Reconstruction Tool\n";
    std::cout << "Cross-platform Edition\n";
    std::cout << "https://github.com/NtQuery/Scylla\n\n";
}

void printUsage(const char* progName) {
    std::cout << "Usage: " << progName << " <command> [options]\n\n";

    std::cout << "Commands:\n";
    std::cout << "  info                          Show platform and capability information\n";
    std::cout << "  analyze <file>                Analyze PE file structure and imports\n";
    std::cout << "  dump                          Dump process memory to file\n";
    std::cout << "  rebuild <file>                Rebuild PE import table\n";
    std::cout << "  batch <directory>             Batch process multiple files\n";
    std::cout << "  plugin <action>               Manage plugins\n\n";

    std::cout << "Global Options:\n";
    std::cout << "  -h, --help                    Show help for command\n";
    std::cout << "  -v, --verbose                 Enable verbose output\n";
    std::cout << "  -q, --quiet                   Suppress non-essential output\n";
    std::cout << "  --version                     Show version information\n\n";

    std::cout << "Analyze Options:\n";
    std::cout << "  -o, --output <file>           Write results to file\n";
    std::cout << "  --format <fmt>                Output format: text, json, xml (default: text)\n";
    std::cout << "  --deep-scan                   Perform deep analysis\n";
    std::cout << "  --iat <address>               Specify IAT address (hex)\n";
    std::cout << "  --no-auto-iat                 Disable automatic IAT detection\n\n";

    std::cout << "Dump Options:\n";
    std::cout << "  --pid <pid>                   Process ID to dump\n";
    std::cout << "  -o, --output <file>           Output file path\n";
    std::cout << "  --fix-iat                     Fix import table in dump\n";
    std::cout << "  --fix-oep                     Fix original entry point\n\n";

    std::cout << "Rebuild Options:\n";
    std::cout << "  --iat <address>               IAT address (hex)\n";
    std::cout << "  --iat-size <size>             IAT size (hex)\n";
    std::cout << "  -o, --output <file>           Output file path\n\n";

    std::cout << "Batch Options:\n";
    std::cout << "  -r, --recursive               Process subdirectories\n";
    std::cout << "  --format <fmt>                Output format for results\n";
    std::cout << "  --threads <n>                 Number of worker threads\n";
    std::cout << "  --output-dir <dir>            Output directory for results\n\n";

    std::cout << "Examples:\n";
    std::cout << "  " << progName << " info\n";
    std::cout << "  " << progName << " analyze sample.exe\n";
    std::cout << "  " << progName << " analyze packed.exe --format json -o results.json\n";
    std::cout << "  " << progName << " dump --pid 1234 --output dump.exe --fix-iat\n";
    std::cout << "  " << progName << " rebuild unpacked.exe --iat 0x401000 -o fixed.exe\n";
    std::cout << "  " << progName << " batch ./samples --recursive --format json\n\n";

    std::cout << "For detailed help on a command, use:\n";
    std::cout << "  " << progName << " <command> --help\n\n";
}

CommandOptions parseOptions(int argc, char* argv[], int startIndex) {
    CommandOptions opts;

    for (int i = startIndex; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            opts.verbose = true;  // Use as flag to show help
        }
        else if (arg == "-v" || arg == "--verbose") {
            opts.verbose = true;
        }
        else if (arg == "-q" || arg == "--quiet") {
            opts.quiet = true;
        }
        else if (arg == "-o" || arg == "--output") {
            if (i + 1 < argc) {
                opts.outputFile = argv[++i];
            }
        }
        else if (arg == "--output-dir") {
            if (i + 1 < argc) {
                opts.outputDirectory = argv[++i];
            }
        }
        else if (arg == "--format") {
            if (i + 1 < argc) {
                std::string format = argv[++i];
                if (format == "json") opts.format = OutputFormat::JSON;
                else if (format == "xml") opts.format = OutputFormat::XML;
                else if (format == "csv") opts.format = OutputFormat::CSV;
                else opts.format = OutputFormat::Text;
            }
        }
        else if (arg == "--pid") {
            if (i + 1 < argc) {
                opts.pid = std::stoul(argv[++i]);
            }
        }
        else if (arg == "--iat") {
            if (i + 1 < argc) {
                std::string addrStr = argv[++i];
                opts.iatAddress = std::stoull(addrStr, nullptr, 16);
            }
        }
        else if (arg == "--iat-size") {
            if (i + 1 < argc) {
                std::string sizeStr = argv[++i];
                opts.iatSize = std::stoul(sizeStr, nullptr, 16);
            }
        }
        else if (arg == "--no-auto-iat") {
            opts.autoDetectIAT = false;
        }
        else if (arg == "--fix-iat") {
            opts.fixImports = true;
        }
        else if (arg == "--fix-oep") {
            opts.fixOEP = true;
        }
        else if (arg == "--deep-scan") {
            opts.deepScan = true;
        }
        else if (arg == "-r" || arg == "--recursive") {
            opts.recursive = true;
        }
        else if (arg == "--threads") {
            if (i + 1 < argc) {
                opts.maxThreads = std::stoi(argv[++i]);
            }
        }
        else if (arg == "-f" || arg == "--force") {
            opts.force = true;
        }
        else if (arg[0] != '-') {
            // Positional argument
            if (opts.inputFile.empty()) {
                opts.inputFile = arg;
            } else if (opts.inputDirectory.empty()) {
                opts.inputDirectory = arg;
            }
        }
    }

    return opts;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printVersion();
        printUsage(argv[0]);
        return 1;
    }

    std::string command = argv[1];

    // Handle global options
    if (command == "--version") {
        printVersion();
        return 0;
    }

    if (command == "-h" || command == "--help") {
        printUsage(argv[0]);
        return 0;
    }

    // Parse command-specific options
    CommandOptions opts = parseOptions(argc, argv, 2);

    // Execute command
    try {
        std::unique_ptr<ICommandHandler> handler;

        if (command == "info") {
            handler = std::make_unique<InfoCommand>();

            if (opts.verbose) {  // Used as help flag
                std::cout << handler->GetHelp();
                std::cout << "\n" << handler->GetUsage() << "\n";
                return 0;
            }
        }
        else if (command == "analyze") {
            handler = std::make_unique<AnalyzeCommand>();

            if (opts.verbose && opts.inputFile.empty()) {  // Help requested
                std::cout << handler->GetHelp();
                std::cout << "\n" << handler->GetUsage() << "\n";
                return 0;
            }
        }
        else if (command == "dump") {
            // handler = std::make_unique<DumpCommand>();
            std::cout << "Dump command is under development\n";
            std::cout << "This will allow dumping process memory with IAT reconstruction\n";
            return 1;
        }
        else if (command == "rebuild") {
            // handler = std::make_unique<RebuildCommand>();
            std::cout << "Rebuild command is under development\n";
            std::cout << "This will allow rebuilding PE imports with specified IAT\n";
            return 1;
        }
        else if (command == "batch") {
            // handler = std::make_unique<BatchCommand>();
            std::cout << "Batch command is under development\n";
            std::cout << "This will allow processing multiple files in parallel\n";
            return 1;
        }
        else if (command == "plugin") {
            std::cout << "Plugin command is under development\n";
            std::cout << "This will allow loading and managing Scylla plugins\n";
            return 1;
        }
        else {
            std::cerr << "Unknown command: " << command << "\n\n";
            printUsage(argv[0]);
            return 1;
        }

        // Execute handler
        if (handler) {
            return handler->Execute(opts);
        }

    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "Unknown fatal error occurred\n";
        return 1;
    }

    return 0;
}
