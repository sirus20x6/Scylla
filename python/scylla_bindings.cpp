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
#include "../libScylla/SymbolResolver.h"
#include "../libScylla/ELFAnalyzer.h"
#include "../libScylla/MachOAnalyzer.h"

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
// Symbol Resolution Bindings
// ============================================================================

void bind_symbol_resolution(py::module& m) {
    using namespace scylla;

    // Symbol Type enumeration
    py::enum_<SymbolType>(m, "SymbolType")
        .value("UNKNOWN", SymbolType::Unknown)
        .value("FUNCTION", SymbolType::Function)
        .value("DATA", SymbolType::Data)
        .value("PUBLIC_SYMBOL", SymbolType::PublicSymbol)
        .value("EXPORT", SymbolType::Export)
        .value("IMPORT", SymbolType::Import)
        .value("LABEL", SymbolType::Label)
        .value("CONSTANT", SymbolType::Constant)
        .value("PARAMETER", SymbolType::Parameter)
        .value("LOCAL_VARIABLE", SymbolType::LocalVariable)
        .value("TYPE_INFO", SymbolType::TypeInfo)
        .value("VTABLE", SymbolType::VTable)
        .export_values();

    // SymbolInfo structure
    py::class_<SymbolInfo>(m, "SymbolInfo")
        .def(py::init<>())
        .def_readwrite("name", &SymbolInfo::name)
        .def_readwrite("demangled_name", &SymbolInfo::demangledName)
        .def_readwrite("type", &SymbolInfo::type)
        .def_readwrite("address", &SymbolInfo::address)
        .def_readwrite("size", &SymbolInfo::size)
        .def_readwrite("module_name", &SymbolInfo::moduleName)
        .def_readwrite("source_file", &SymbolInfo::sourceFile)
        .def_readwrite("line_number", &SymbolInfo::lineNumber)
        .def_readwrite("is_mangled", &SymbolInfo::isMangled)
        .def_readwrite("metadata", &SymbolInfo::metadata)
        .def("__repr__", [](const SymbolInfo& s) {
            std::string repr = "<SymbolInfo ";
            repr += s.demangledName.empty() ? s.name : s.demangledName;
            repr += " @ 0x" + std::to_string(s.address) + ">";
            return repr;
        });

    // PDBInfo structure
    py::class_<PDBInfo>(m, "PDBInfo")
        .def(py::init<>())
        .def_readwrite("path", &PDBInfo::path)
        .def_readwrite("guid", &PDBInfo::guid)
        .def_readwrite("age", &PDBInfo::age)
        .def_readwrite("signature", &PDBInfo::signature)
        .def_readwrite("is_loaded", &PDBInfo::isLoaded)
        .def_readwrite("symbol_count", &PDBInfo::symbolCount)
        .def("__repr__", [](const PDBInfo& p) {
            return "<PDBInfo path='" + p.path + "' symbols=" +
                   std::to_string(p.symbolCount) + ">";
        });

    // DemangleOptions structure
    py::class_<DemangleOptions>(m, "DemangleOptions")
        .def(py::init<>())
        .def_readwrite("include_return_type", &DemangleOptions::includeReturnType)
        .def_readwrite("include_parameters", &DemangleOptions::includeParameters)
        .def_readwrite("include_namespace", &DemangleOptions::includeNamespace)
        .def_readwrite("simplify_templates", &DemangleOptions::simplifyTemplates)
        .def_readwrite("use_short_names", &DemangleOptions::useShortNames);

    // SymbolSearchOptions structure
    py::class_<SymbolSearchOptions>(m, "SymbolSearchOptions")
        .def(py::init<>())
        .def_readwrite("case_sensitive", &SymbolSearchOptions::caseSensitive)
        .def_readwrite("exact_match", &SymbolSearchOptions::exactMatch)
        .def_readwrite("search_demangled", &SymbolSearchOptions::searchDemangled)
        .def_readwrite("filter_type", &SymbolSearchOptions::filterType)
        .def_readwrite("max_results", &SymbolSearchOptions::maxResults);

    // SymbolResolver class
    py::class_<SymbolResolver>(m, "SymbolResolver")
        .def(py::init<>())
        .def("load_pdb", &SymbolResolver::LoadPDB,
             "Load symbols from PDB file",
             py::arg("pdb_path"))
        .def("load_symbols_for_pe",
             [](SymbolResolver& self, const std::string& pe_path) {
                 return self.LoadSymbolsForPE(pe_path);
             },
             "Load symbols for PE file (auto-finds PDB)",
             py::arg("pe_path"))
        .def("load_symbols_for_module", &SymbolResolver::LoadSymbolsForModule,
             "Load symbols for loaded module",
             py::arg("module_base"), py::arg("module_path"))
        .def("unload_symbols", &SymbolResolver::UnloadSymbols,
             "Unload all symbols")
        .def("get_symbol_by_address",
             [](SymbolResolver& self, uint64_t address) {
                 return self.GetSymbolByAddress(address);
             },
             "Get symbol info by address",
             py::arg("address"))
        .def("get_symbol_by_name", &SymbolResolver::GetSymbolByName,
             "Get symbol info by name",
             py::arg("name"))
        .def("search_symbols",
             [](SymbolResolver& self, const std::string& pattern) {
                 return self.SearchSymbols(pattern);
             },
             "Search for symbols matching pattern",
             py::arg("pattern"))
        .def("search_symbols",
             [](SymbolResolver& self, const std::string& pattern,
                const SymbolSearchOptions& options) {
                 return self.SearchSymbols(pattern, options);
             },
             "Search for symbols with options",
             py::arg("pattern"), py::arg("options"))
        .def("enumerate_symbols",
             [](SymbolResolver& self, py::function callback) {
                 return self.EnumerateSymbols([callback](const SymbolInfo& info) {
                     py::gil_scoped_acquire acquire;
                     return callback(info).cast<bool>();
                 });
             },
             "Enumerate all symbols",
             py::arg("callback"))
        .def("get_source_location",
             [](SymbolResolver& self, uint64_t address) {
                 std::string source_file;
                 uint32_t line_number;
                 bool found = self.GetSourceLocation(address, source_file, line_number);
                 if (found) {
                     return py::make_tuple(source_file, line_number);
                 }
                 return py::make_tuple(py::str(""), py::int_(0));
             },
             "Get source file and line number for address",
             py::arg("address"))
        .def("get_pdb_info", &SymbolResolver::GetPDBInfo,
             "Get PDB information")
        .def("is_loaded", &SymbolResolver::IsLoaded,
             "Check if symbols are loaded")
        .def("get_module_base", &SymbolResolver::GetModuleBase,
             "Get loaded module base address")
        .def("enable_caching", &SymbolResolver::EnableCaching,
             "Enable/disable symbol caching",
             py::arg("enable"))
        .def("clear_cache", &SymbolResolver::ClearCache,
             "Clear symbol cache")
        .def("get_statistics", &SymbolResolver::GetStatistics,
             "Get statistics")
        .def_static("demangle_name",
                   [](const std::string& name) {
                       return SymbolResolver::DemangleName(name);
                   },
                   "Demangle C++ symbol name",
                   py::arg("mangled_name"))
        .def_static("demangle_name",
                   [](const std::string& name, const DemangleOptions& options) {
                       return SymbolResolver::DemangleName(name, options);
                   },
                   "Demangle C++ symbol name with options",
                   py::arg("mangled_name"), py::arg("options"))
        .def_static("is_mangled_name", &SymbolResolver::IsMangledName,
                   "Check if name is mangled",
                   py::arg("name"))
        .def_static("detect_mangling_scheme", &SymbolResolver::DetectManglingScheme,
                   "Detect mangling scheme (MSVC, Itanium, GCC, or None)",
                   py::arg("name"))
        .def_static("extract_pdb_info_from_pe", &SymbolResolver::ExtractPDBInfoFromPE,
                   "Extract PDB info from PE file",
                   py::arg("pe_path"))
        .def("__repr__", [](const SymbolResolver& r) {
            return "<SymbolResolver loaded=" + std::string(r.IsLoaded() ? "true" : "false") + ">";
        });
}

// ============================================================================
// Mach-O Analysis Bindings
// ============================================================================

void bind_macho_analysis(py::module& m) {
    using namespace scylla::macho;

    // CPU Type enumeration
    py::enum_<CPUType>(m, "CPUType")
        .value("NONE", CPUType::None)
        .value("X86", CPUType::X86)
        .value("X86_64", CPUType::X86_64)
        .value("ARM", CPUType::ARM)
        .value("ARM64", CPUType::ARM64)
        .value("POWERPC", CPUType::PowerPC)
        .value("POWERPC64", CPUType::PowerPC64)
        .export_values();

    // File Type enumeration
    py::enum_<FileType>(m, "FileType")
        .value("NONE", FileType::None)
        .value("OBJECT", FileType::Object)
        .value("EXECUTE", FileType::Execute)
        .value("FVMLIB", FileType::FVMLib)
        .value("CORE", FileType::Core)
        .value("PRELOAD", FileType::Preload)
        .value("DYLIB", FileType::Dylib)
        .value("DYLINKER", FileType::Dylinker)
        .value("BUNDLE", FileType::Bundle)
        .value("DYLIB_STUB", FileType::DylibStub)
        .value("DSYM", FileType::DSYM)
        .value("KEXT_BUNDLE", FileType::KextBundle)
        .export_values();

    // MachOHeader structure
    py::class_<MachOHeader>(m, "MachOHeader")
        .def(py::init<>())
        .def_readwrite("magic", &MachOHeader::magic)
        .def_readwrite("cpu_type", &MachOHeader::cpuType)
        .def_readwrite("cpu_subtype", &MachOHeader::cpuSubtype)
        .def_readwrite("file_type", &MachOHeader::fileType)
        .def_readwrite("ncmds", &MachOHeader::ncmds)
        .def_readwrite("sizeofcmds", &MachOHeader::sizeofcmds)
        .def_readwrite("flags", &MachOHeader::flags)
        .def("is_64_bit", &MachOHeader::Is64Bit)
        .def("is_swapped", &MachOHeader::IsSwapped)
        .def("is_fat", &MachOHeader::IsFat);

    // FatArch structure
    py::class_<FatArch>(m, "FatArch")
        .def(py::init<>())
        .def_readwrite("cpu_type", &FatArch::cpuType)
        .def_readwrite("cpu_subtype", &FatArch::cpuSubtype)
        .def_readwrite("offset", &FatArch::offset)
        .def_readwrite("size", &FatArch::size)
        .def_readwrite("align", &FatArch::align);

    // SegmentCommand structure
    py::class_<SegmentCommand>(m, "SegmentCommand")
        .def(py::init<>())
        .def_readwrite("segname", &SegmentCommand::segname)
        .def_readwrite("vmaddr", &SegmentCommand::vmaddr)
        .def_readwrite("vmsize", &SegmentCommand::vmsize)
        .def_readwrite("fileoff", &SegmentCommand::fileoff)
        .def_readwrite("filesize", &SegmentCommand::filesize)
        .def_readwrite("maxprot", &SegmentCommand::maxprot)
        .def_readwrite("initprot", &SegmentCommand::initprot)
        .def_readwrite("nsects", &SegmentCommand::nsects)
        .def_readwrite("flags", &SegmentCommand::flags)
        .def("is_readable", &SegmentCommand::IsReadable)
        .def("is_writable", &SegmentCommand::IsWritable)
        .def("is_executable", &SegmentCommand::IsExecutable);

    // Section structure
    py::class_<Section>(m, "Section")
        .def(py::init<>())
        .def_readwrite("sectname", &Section::sectname)
        .def_readwrite("segname", &Section::segname)
        .def_readwrite("addr", &Section::addr)
        .def_readwrite("size", &Section::size)
        .def_readwrite("offset", &Section::offset)
        .def_readwrite("align", &Section::align)
        .def_readwrite("entropy", &Section::entropy);

    // Symbol structure
    py::class_<Symbol>(m, "Symbol")
        .def(py::init<>())
        .def_readwrite("name", &Symbol::name)
        .def_readwrite("type", &Symbol::type)
        .def_readwrite("sect", &Symbol::sect)
        .def_readwrite("desc", &Symbol::desc)
        .def_readwrite("value", &Symbol::value)
        .def("is_undefined", &Symbol::IsUndefined)
        .def("is_external", &Symbol::IsExternal);

    // DylibInfo structure
    py::class_<DylibInfo>(m, "DylibInfo")
        .def(py::init<>())
        .def_readwrite("name", &DylibInfo::name)
        .def_readwrite("timestamp", &DylibInfo::timestamp)
        .def_readwrite("current_version", &DylibInfo::currentVersion)
        .def_readwrite("compatibility_version", &DylibInfo::compatibilityVersion)
        .def("get_version_string", &DylibInfo::GetVersionString);

    // CodeSignature structure
    py::class_<CodeSignature>(m, "CodeSignature")
        .def(py::init<>())
        .def_readwrite("present", &CodeSignature::present)
        .def_readwrite("valid", &CodeSignature::valid)
        .def_readwrite("team_id", &CodeSignature::teamID)
        .def_readwrite("identity", &CodeSignature::identity)
        .def_readwrite("entitlements", &CodeSignature::entitlements);

    // MachOSecurityFeatures structure
    py::class_<MachOSecurityFeatures>(m, "MachOSecurityFeatures")
        .def(py::init<>())
        .def_readwrite("pie", &MachOSecurityFeatures::pie)
        .def_readwrite("stack_canary", &MachOSecurityFeatures::stackCanary)
        .def_readwrite("arc", &MachOSecurityFeatures::arc)
        .def_readwrite("code_signature", &MachOSecurityFeatures::codeSignature)
        .def_readwrite("hardened_runtime", &MachOSecurityFeatures::hardenedRuntime)
        .def_readwrite("library_validation", &MachOSecurityFeatures::libraryValidation)
        .def_readwrite("restrict", &MachOSecurityFeatures::restrict)
        .def_readwrite("encrypted", &MachOSecurityFeatures::encrypted)
        .def_readwrite("security_score", &MachOSecurityFeatures::securityScore)
        .def("get_enabled_features", &MachOSecurityFeatures::GetEnabledFeatures)
        .def("get_missing_features", &MachOSecurityFeatures::GetMissingFeatures);

    // MachOAnalysisResult structure
    py::class_<MachOAnalysisResult>(m, "MachOAnalysisResult")
        .def(py::init<>())
        .def_readwrite("header", &MachOAnalysisResult::header)
        .def_readwrite("segments", &MachOAnalysisResult::segments)
        .def_readwrite("sections", &MachOAnalysisResult::sections)
        .def_readwrite("symbols", &MachOAnalysisResult::symbols)
        .def_readwrite("dylibs", &MachOAnalysisResult::dylibs)
        .def_readwrite("code_signature", &MachOAnalysisResult::codeSignature)
        .def_readwrite("security", &MachOAnalysisResult::security)
        .def_readwrite("entry_point", &MachOAnalysisResult::entryPoint)
        .def_readwrite("uuid", &MachOAnalysisResult::uuid)
        .def_readwrite("platform", &MachOAnalysisResult::platform)
        .def_readwrite("min_os_version", &MachOAnalysisResult::minOSVersion)
        .def_readwrite("sdk_version", &MachOAnalysisResult::sdkVersion)
        .def_readwrite("is_universal_binary", &MachOAnalysisResult::isUniversalBinary)
        .def_readwrite("architectures", &MachOAnalysisResult::architectures)
        .def_readwrite("average_entropy", &MachOAnalysisResult::averageEntropy)
        .def_readwrite("file_size", &MachOAnalysisResult::fileSize)
        .def_readwrite("success", &MachOAnalysisResult::success)
        .def_readwrite("error_message", &MachOAnalysisResult::errorMessage);

    // MachOAnalyzer class
    py::class_<MachOAnalyzer>(m, "MachOAnalyzer")
        .def(py::init<>())
        .def("analyze",
             [](MachOAnalyzer& self, const std::string& file_path) {
                 return self.Analyze(file_path);
             },
             "Analyze a Mach-O file",
             py::arg("file_path"))
        .def("analyze_architecture",
             [](MachOAnalyzer& self, const std::string& file_path, size_t arch_index) {
                 return self.AnalyzeArchitecture(file_path, arch_index);
             },
             "Analyze a specific architecture in a universal binary",
             py::arg("file_path"), py::arg("arch_index"))
        .def_static("is_macho",
                   [](const std::string& file_path) {
                       return MachOAnalyzer::IsMachO(file_path);
                   },
                   "Check if a file is a Mach-O binary",
                   py::arg("file_path"))
        .def_static("is_universal_binary",
                   [](const std::string& file_path) {
                       return MachOAnalyzer::IsUniversalBinary(file_path);
                   },
                   "Check if a file is a universal binary",
                   py::arg("file_path"))
        .def_static("cpu_type_to_string", &MachOAnalyzer::CPUTypeToString,
                   "Convert CPU type to string",
                   py::arg("type"))
        .def_static("file_type_to_string", &MachOAnalyzer::FileTypeToString,
                   "Convert file type to string",
                   py::arg("type"));
}

// ============================================================================
// ELF Analysis Bindings
// ============================================================================

void bind_elf_analysis(py::module& m) {
    using namespace scylla::elf;

    // ELF Class enumeration
    py::enum_<ELFClass>(m, "ELFClass")
        .value("NONE", ELFClass::None)
        .value("ELF32", ELFClass::ELF32)
        .value("ELF64", ELFClass::ELF64)
        .export_values();

    // ELF Machine enumeration
    py::enum_<ELFMachine>(m, "ELFMachine")
        .value("NONE", ELFMachine::None)
        .value("X86", ELFMachine::X86)
        .value("X86_64", ELFMachine::X86_64)
        .value("ARM", ELFMachine::ARM)
        .value("AARCH64", ELFMachine::AARCH64)
        .value("MIPS", ELFMachine::MIPS)
        .value("POWERPC", ELFMachine::PowerPC)
        .value("POWERPC64", ELFMachine::PowerPC64)
        .value("RISC_V", ELFMachine::RISC_V)
        .export_values();

    // ELFAnalyzer class (simplified for now)
    py::class_<ELFAnalyzer>(m, "ELFAnalyzer")
        .def(py::init<>())
        .def_static("is_elf",
                   [](const std::string& file_path) {
                       return ELFAnalyzer::IsELF(file_path);
                   },
                   "Check if a file is an ELF binary",
                   py::arg("file_path"));
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

    py::module symbol_mod = m.def_submodule("symbols", "Symbol resolution and demangling");
    bind_symbol_resolution(symbol_mod);

    py::module macho_mod = m.def_submodule("macho", "Mach-O binary analysis");
    bind_macho_analysis(macho_mod);

    py::module elf_mod = m.def_submodule("elf", "ELF binary analysis");
    bind_elf_analysis(elf_mod);

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
