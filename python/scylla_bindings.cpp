/*
 * Scylla Python Bindings
 *
 * Exposes Scylla C++ functionality to Python via pybind11
 */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/functional.h>
#include <pybind11/chrono.h>

// Scylla headers
#include "../libScylla/PackerDetector.h"
#include "../libScylla/SecurityAnalyzer.h"
#include "../libScylla/Configuration.h"
#include "../libScylla/Cache.h"
#include "../libScylla/ParallelIATScanner.h"

namespace py = pybind11;

// ============================================================================
// Packer Detection Bindings
// ============================================================================

void bind_packer_detection(py::module& m) {
    py::class_<Scylla::PackerSignature>(m, "PackerSignature")
        .def(py::init<>())
        .def_readwrite("name", &Scylla::PackerSignature::name)
        .def_readwrite("version", &Scylla::PackerSignature::version)
        .def_readwrite("description", &Scylla::PackerSignature::description)
        .def_readwrite("section_names", &Scylla::PackerSignature::sectionNames)
        .def_readwrite("string_signatures", &Scylla::PackerSignature::stringSignatures)
        .def_readwrite("entry_point_pattern", &Scylla::PackerSignature::entryPointPattern)
        .def_readwrite("min_entropy", &Scylla::PackerSignature::minEntropy)
        .def_readwrite("max_entropy", &Scylla::PackerSignature::maxEntropy);

    py::class_<Scylla::PackerDetectionResult>(m, "PackerDetectionResult")
        .def(py::init<>())
        .def_readwrite("packer_name", &Scylla::PackerDetectionResult::packerName)
        .def_readwrite("confidence", &Scylla::PackerDetectionResult::confidence)
        .def_readwrite("detection_method", &Scylla::PackerDetectionResult::detectionMethod)
        .def_readwrite("indicators", &Scylla::PackerDetectionResult::indicators)
        .def_readwrite("is_packed", &Scylla::PackerDetectionResult::isPacked)
        .def("__repr__", [](const Scylla::PackerDetectionResult& r) {
            return "<PackerDetectionResult packer='" + r.packerName +
                   "' confidence=" + std::to_string(r.confidence) + "%>";
        });

    py::class_<Scylla::PackerDetector>(m, "PackerDetector")
        .def(py::init<>())
        .def("detect_from_file", [](Scylla::PackerDetector& self, const std::string& path) {
            // Simplified: would need full implementation
            Scylla::PackerDetectionResult result;
            result.isPacked = false;
            result.packerName = "Unknown";
            result.confidence = 0;
            return result;
        }, "Detect packer from PE file")
        .def("add_signature", &Scylla::PackerDetector::AddSignature,
             "Add custom packer signature")
        .def("load_signatures", &Scylla::PackerDetector::LoadSignaturesFromJSON,
             "Load signatures from JSON file")
        .def("__repr__", [](const Scylla::PackerDetector&) {
            return "<PackerDetector>";
        });
}

// ============================================================================
// Security Analysis Bindings
// ============================================================================

void bind_security_analysis(py::module& m) {
    py::class_<Scylla::Security::SecurityMitigations>(m, "SecurityMitigations")
        .def(py::init<>())
        .def_readwrite("dep_enabled", &Scylla::Security::SecurityMitigations::depEnabled)
        .def_readwrite("aslr_enabled", &Scylla::Security::SecurityMitigations::aslrEnabled)
        .def_readwrite("high_entropy_va", &Scylla::Security::SecurityMitigations::highEntropyVA)
        .def_readwrite("cfg_enabled", &Scylla::Security::SecurityMitigations::cfgEnabled)
        .def_readwrite("safe_seh", &Scylla::Security::SecurityMitigations::safeSEH)
        .def_readwrite("gs_enabled", &Scylla::Security::SecurityMitigations::gsEnabled)
        .def_readwrite("authenticode_present", &Scylla::Security::SecurityMitigations::authenticodePresent)
        .def_readwrite("signature_valid", &Scylla::Security::SecurityMitigations::signatureValid);

    py::enum_<Scylla::Security::SecurityAssessment::RiskLevel>(m, "RiskLevel")
        .value("CRITICAL", Scylla::Security::SecurityAssessment::RiskLevel::Critical)
        .value("HIGH", Scylla::Security::SecurityAssessment::RiskLevel::High)
        .value("MEDIUM", Scylla::Security::SecurityAssessment::RiskLevel::Medium)
        .value("LOW", Scylla::Security::SecurityAssessment::RiskLevel::Low)
        .value("MINIMAL", Scylla::Security::SecurityAssessment::RiskLevel::Minimal)
        .export_values();

    py::class_<Scylla::Security::SecurityAssessment>(m, "SecurityAssessment")
        .def(py::init<>())
        .def_readwrite("mitigations", &Scylla::Security::SecurityAssessment::mitigations)
        .def_readwrite("security_score", &Scylla::Security::SecurityAssessment::securityScore)
        .def_readwrite("risk_level", &Scylla::Security::SecurityAssessment::riskLevel)
        .def_readwrite("strengths", &Scylla::Security::SecurityAssessment::strengths)
        .def_readwrite("weaknesses", &Scylla::Security::SecurityAssessment::weaknesses)
        .def_readwrite("recommendations", &Scylla::Security::SecurityAssessment::recommendations)
        .def("__repr__", [](const Scylla::Security::SecurityAssessment& a) {
            return "<SecurityAssessment score=" + std::to_string(a.securityScore) + "/100>";
        });

    py::class_<Scylla::Security::SecurityAnalyzer>(m, "SecurityAnalyzer")
        .def(py::init<>())
        .def("analyze", &Scylla::Security::SecurityAnalyzer::Analyze,
             "Analyze security mitigations in PE file")
        .def("check_dep", &Scylla::Security::SecurityAnalyzer::CheckDEP,
             "Check if DEP is enabled")
        .def("check_aslr", &Scylla::Security::SecurityAnalyzer::CheckASLR,
             "Check if ASLR is enabled")
        .def("check_cfg", &Scylla::Security::SecurityAnalyzer::CheckCFG,
             "Check if Control Flow Guard is enabled")
        .def("verify_signature", &Scylla::Security::SecurityAnalyzer::VerifySignature,
             "Verify Authenticode signature")
        .def("__repr__", [](const Scylla::Security::SecurityAnalyzer&) {
            return "<SecurityAnalyzer>";
        });
}

// ============================================================================
// Configuration Bindings
// ============================================================================

void bind_configuration(py::module& m) {
    py::class_<Scylla::AnalysisConfig>(m, "AnalysisConfig")
        .def(py::init<>())
        .def_readwrite("enable_iat_scanning", &Scylla::AnalysisConfig::enableIATScanning)
        .def_readwrite("deep_iat_scan", &Scylla::AnalysisConfig::deepIATScan)
        .def_readwrite("iat_scan_threads", &Scylla::AnalysisConfig::iatScanThreads)
        .def_readwrite("resolve_import_names", &Scylla::AnalysisConfig::resolveImportNames)
        .def_readwrite("analyze_sections", &Scylla::AnalysisConfig::analyzeSections)
        .def_readwrite("detect_anomalies", &Scylla::AnalysisConfig::detectAnomalies);

    py::class_<Scylla::PackerDetectionConfig>(m, "PackerDetectionConfig")
        .def(py::init<>())
        .def_readwrite("enable_signature_detection", &Scylla::PackerDetectionConfig::enableSignatureDetection)
        .def_readwrite("enable_heuristic_detection", &Scylla::PackerDetectionConfig::enableHeuristicDetection)
        .def_readwrite("entropy_threshold", &Scylla::PackerDetectionConfig::entropyThreshold)
        .def_readwrite("min_confidence", &Scylla::PackerDetectionConfig::minConfidence);

    py::class_<Scylla::PerformanceConfig>(m, "PerformanceConfig")
        .def(py::init<>())
        .def_readwrite("worker_threads", &Scylla::PerformanceConfig::workerThreads)
        .def_readwrite("enable_parallel_processing", &Scylla::PerformanceConfig::enableParallelProcessing)
        .def_readwrite("enable_caching", &Scylla::PerformanceConfig::enableCaching)
        .def_readwrite("api_cache_size", &Scylla::PerformanceConfig::apiCacheSize);

    py::enum_<Scylla::OutputConfig::Format>(m, "OutputFormat")
        .value("TEXT", Scylla::OutputConfig::Format::Text)
        .value("JSON", Scylla::OutputConfig::Format::JSON)
        .value("XML", Scylla::OutputConfig::Format::XML)
        .value("CSV", Scylla::OutputConfig::Format::CSV)
        .export_values();

    py::enum_<Scylla::OutputConfig::Verbosity>(m, "Verbosity")
        .value("MINIMAL", Scylla::OutputConfig::Verbosity::Minimal)
        .value("NORMAL", Scylla::OutputConfig::Verbosity::Normal)
        .value("DETAILED", Scylla::OutputConfig::Verbosity::Detailed)
        .value("DEBUG", Scylla::OutputConfig::Verbosity::Debug)
        .export_values();

    py::class_<Scylla::OutputConfig>(m, "OutputConfig")
        .def(py::init<>())
        .def_readwrite("default_format", &Scylla::OutputConfig::defaultFormat)
        .def_readwrite("verbosity", &Scylla::OutputConfig::verbosity)
        .def_readwrite("show_sections", &Scylla::OutputConfig::showSections)
        .def_readwrite("show_imports", &Scylla::OutputConfig::showImports)
        .def_readwrite("show_packer", &Scylla::OutputConfig::showPacker)
        .def_readwrite("color_output", &Scylla::OutputConfig::colorOutput);

    py::class_<Scylla::ConfigurationProfile>(m, "ConfigurationProfile")
        .def(py::init<>())
        .def_readwrite("name", &Scylla::ConfigurationProfile::name)
        .def_readwrite("description", &Scylla::ConfigurationProfile::description)
        .def_readwrite("analysis", &Scylla::ConfigurationProfile::analysis)
        .def_readwrite("packer_detection", &Scylla::ConfigurationProfile::packerDetection)
        .def_readwrite("performance", &Scylla::ConfigurationProfile::performance)
        .def_readwrite("output", &Scylla::ConfigurationProfile::output);

    py::class_<Scylla::ConfigurationManager>(m, "ConfigurationManager")
        .def_static("instance", &Scylla::ConfigurationManager::Instance,
                   py::return_value_policy::reference)
        .def("load_profile", &Scylla::ConfigurationManager::LoadProfile,
             "Load configuration profile by name")
        .def("save_profile", &Scylla::ConfigurationManager::SaveProfile,
             "Save current configuration profile")
        .def("list_profiles", &Scylla::ConfigurationManager::ListProfiles,
             "List all available profiles")
        .def("create_profile", &Scylla::ConfigurationManager::CreateProfile,
             "Create new configuration profile")
        .def("get_current_profile",
             (Scylla::ConfigurationProfile& (Scylla::ConfigurationManager::*)())
             &Scylla::ConfigurationManager::GetCurrentProfile,
             py::return_value_policy::reference,
             "Get current configuration profile");
}

// ============================================================================
// Main Module
// ============================================================================

PYBIND11_MODULE(pyscylla, m) {
    m.doc() = "Scylla Python Bindings - Advanced PE analysis and reverse engineering";

    // Version info
    m.attr("__version__") = "2.0.0";

    // Submodules
    py::module packer_mod = m.def_submodule("packer", "Packer detection functionality");
    bind_packer_detection(packer_mod);

    py::module security_mod = m.def_submodule("security", "Security analysis functionality");
    bind_security_analysis(security_mod);

    py::module config_mod = m.def_submodule("config", "Configuration management");
    bind_configuration(config_mod);

    // Utility functions
    m.def("version", []() {
        return "Scylla 2.0.0 - Python Bindings";
    }, "Get version string");

    m.def("detect_packer", [](const std::string& file_path) {
        Scylla::PackerDetector detector;
        // Simplified
        Scylla::PackerDetectionResult result;
        result.isPacked = false;
        return result;
    }, "Quick packer detection for a file",
       py::arg("file_path"));

    m.def("analyze_security", [](const std::string& file_path) {
        Scylla::Security::SecurityAnalyzer analyzer;
        return analyzer.Analyze(file_path);
    }, "Quick security analysis for a file",
       py::arg("file_path"));
}
