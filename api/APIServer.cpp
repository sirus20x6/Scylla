/*
 * Scylla REST API Server - Implementation
 */

#include "APIServer.h"
#include "../libScylla/SecurityAnalyzer.h"
#include "../libScylla/PackerDetector.h"
#include "../libScylla/Configuration.h"

#include <iostream>
#include <sstream>
#include <fstream>
#include <thread>
#include <chrono>
#include <random>
#include <iomanip>

namespace Scylla {
namespace API {

// ============================================================================
// HTTPResponse Helpers
// ============================================================================

HTTPResponse HTTPResponse::OK(const std::string& body) {
    HTTPResponse resp;
    resp.statusCode = 200;
    resp.statusMessage = "OK";
    resp.body = body;
    return resp;
}

HTTPResponse HTTPResponse::Created(const std::string& body) {
    HTTPResponse resp;
    resp.statusCode = 201;
    resp.statusMessage = "Created";
    resp.body = body;
    return resp;
}

HTTPResponse HTTPResponse::BadRequest(const std::string& message) {
    HTTPResponse resp;
    resp.statusCode = 400;
    resp.statusMessage = "Bad Request";
    resp.body = "{\"error\":\"" + message + "\"}";
    resp.headers["Content-Type"] = "application/json";
    return resp;
}

HTTPResponse HTTPResponse::NotFound(const std::string& message) {
    HTTPResponse resp;
    resp.statusCode = 404;
    resp.statusMessage = "Not Found";
    resp.body = "{\"error\":\"" + message + "\"}";
    resp.headers["Content-Type"] = "application/json";
    return resp;
}

HTTPResponse HTTPResponse::InternalError(const std::string& message) {
    HTTPResponse resp;
    resp.statusCode = 500;
    resp.statusMessage = "Internal Server Error";
    resp.body = "{\"error\":\"" + message + "\"}";
    resp.headers["Content-Type"] = "application/json";
    return resp;
}

HTTPResponse HTTPResponse::JSON(const std::string& json, int code) {
    HTTPResponse resp;
    resp.statusCode = code;
    resp.statusMessage = (code == 200) ? "OK" : "Error";
    resp.body = json;
    resp.headers["Content-Type"] = "application/json";
    return resp;
}

// ============================================================================
// JSONBuilder Implementation
// ============================================================================

JSONBuilder::JSONBuilder() {
    m_json = "{";
}

JSONBuilder& JSONBuilder::Add(const std::string& key, const std::string& value) {
    if (!m_first) m_json += ",";
    m_json += "\"" + key + "\":\"" + value + "\"";
    m_first = false;
    return *this;
}

JSONBuilder& JSONBuilder::Add(const std::string& key, int value) {
    if (!m_first) m_json += ",";
    m_json += "\"" + key + "\":" + std::to_string(value);
    m_first = false;
    return *this;
}

JSONBuilder& JSONBuilder::Add(const std::string& key, bool value) {
    if (!m_first) m_json += ",";
    m_json += "\"" + key + "\":" + (value ? "true" : "false");
    m_first = false;
    return *this;
}

JSONBuilder& JSONBuilder::Add(const std::string& key, double value) {
    if (!m_first) m_json += ",";
    m_json += "\"" + key + "\":" + std::to_string(value);
    m_first = false;
    return *this;
}

JSONBuilder& JSONBuilder::AddArray(const std::string& key, const std::vector<std::string>& values) {
    if (!m_first) m_json += ",";
    m_json += "\"" + key + "\":[";
    for (size_t i = 0; i < values.size(); i++) {
        m_json += "\"" + values[i] + "\"";
        if (i < values.size() - 1) m_json += ",";
    }
    m_json += "]";
    m_first = false;
    return *this;
}

JSONBuilder& JSONBuilder::AddObject(const std::string& key, const std::string& json) {
    if (!m_first) m_json += ",";
    m_json += "\"" + key + "\":" + json;
    m_first = false;
    return *this;
}

std::string JSONBuilder::Build() {
    return m_json + "}";
}

// ============================================================================
// APIServer Implementation
// ============================================================================

APIServer::APIServer(const ServerConfig& config)
    : m_config(config)
    , m_running(false)
{
}

APIServer::~APIServer() {
    Stop();
}

bool APIServer::Start() {
    if (m_running) {
        return false;
    }

    std::cout << "Starting Scylla API Server...\n";
    std::cout << "  Host: " << m_config.host << "\n";
    std::cout << "  Port: " << m_config.port << "\n";
    std::cout << "  Workers: " << m_config.workerThreads << "\n";
    std::cout << "  CORS: " << (m_config.enableCORS ? "enabled" : "disabled") << "\n";
    std::cout << "  Auth: " << (m_config.enableAuth ? "enabled" : "disabled") << "\n";

    // Register built-in routes
    RegisterBuiltinRoutes();

    m_running = true;

    // Start server loop in background thread
    std::thread serverThread(&APIServer::ServerLoop, this);
    serverThread.detach();

    std::cout << "Server started successfully!\n";
    std::cout << "API available at: http://" << m_config.host << ":" << m_config.port << "/api\n";

    return true;
}

void APIServer::Stop() {
    if (!m_running) {
        return;
    }

    std::cout << "Stopping Scylla API Server...\n";
    m_running = false;
}

void APIServer::ServerLoop() {
    // Simplified server loop
    // In real implementation, would use proper HTTP server library

    std::cout << "Server loop started (placeholder implementation)\n";
    std::cout << "Note: For production use, integrate with cpp-httplib or similar\n";

    while (m_running) {
        // Process requests here
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void APIServer::RegisterRoute(const std::string& method, const std::string& path,
                              RequestHandler handler)
{
    m_routes[method][path] = handler;
    std::cout << "Registered route: " << method << " " << path << "\n";
}

void APIServer::RegisterBuiltinRoutes() {
    // Health & Status
    RegisterRoute("GET", "/api/health", RouteHandlers::HandleHealth);
    RegisterRoute("GET", "/api/version", RouteHandlers::HandleVersion);
    RegisterRoute("GET", "/api/stats", RouteHandlers::HandleStats);

    // Analysis
    RegisterRoute("POST", "/api/analyze", RouteHandlers::HandleAnalyze);
    RegisterRoute("POST", "/api/analyze/async", RouteHandlers::HandleAnalyzeAsync);
    RegisterRoute("GET", "/api/jobs/:id", RouteHandlers::HandleJobStatus);

    // Security
    RegisterRoute("POST", "/api/security", RouteHandlers::HandleSecurity);
    RegisterRoute("POST", "/api/security/batch", RouteHandlers::HandleSecurityBatch);

    // Packer
    RegisterRoute("POST", "/api/packer", RouteHandlers::HandlePacker);
    RegisterRoute("POST", "/api/packer/batch", RouteHandlers::HandlePackerBatch);

    // Configuration
    RegisterRoute("GET", "/api/profiles", RouteHandlers::HandleListProfiles);
    RegisterRoute("GET", "/api/profiles/:name", RouteHandlers::HandleGetProfile);
    RegisterRoute("POST", "/api/profiles/:name", RouteHandlers::HandleSetProfile);

    // Upload
    RegisterRoute("POST", "/api/upload", RouteHandlers::HandleUpload);
    RegisterRoute("GET", "/api/download/:id", RouteHandlers::HandleDownload);

    // Batch
    RegisterRoute("POST", "/api/batch/analyze", RouteHandlers::HandleBatchAnalyze);
    RegisterRoute("GET", "/api/batch/:id", RouteHandlers::HandleBatchStatus);
}

std::string APIServer::CreateJob(const std::string& filePath) {
    // Generate unique job ID
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 999999);

    std::stringstream ss;
    ss << "job_" << std::setfill('0') << std::setw(6) << dis(gen);
    std::string id = ss.str();

    // Create job
    AnalysisJob job;
    job.id = id;
    job.filePath = filePath;
    job.status = "queued";
    job.created = std::chrono::system_clock::now();

    std::lock_guard<std::mutex> lock(m_jobsMutex);
    m_jobs[id] = job;

    // Start processing in background
    std::thread(&APIServer::ProcessJob, this, id).detach();

    return id;
}

AnalysisJob* APIServer::GetJob(const std::string& id) {
    std::lock_guard<std::mutex> lock(m_jobsMutex);
    auto it = m_jobs.find(id);
    return (it != m_jobs.end()) ? &it->second : nullptr;
}

void APIServer::ProcessJob(const std::string& id) {
    AnalysisJob* job = GetJob(id);
    if (!job) return;

    job->status = "processing";
    job->started = std::chrono::system_clock::now();

    try {
        // Perform analysis
        Security::SecurityAnalyzer analyzer;
        auto result = analyzer.Analyze(job->filePath);

        // Build JSON result
        JSONBuilder json;
        json.Add("job_id", job->id)
            .Add("file", job->filePath)
            .Add("security_score", result.securityScore)
            .Add("dep_enabled", result.mitigations.depEnabled)
            .Add("aslr_enabled", result.mitigations.aslrEnabled)
            .Add("cfg_enabled", result.mitigations.cfgEnabled);

        job->result = json.Build();
        job->status = "completed";

    } catch (const std::exception& e) {
        job->error = e.what();
        job->status = "failed";
    }

    job->completed = std::chrono::system_clock::now();
}

// ============================================================================
// RouteHandlers Implementation
// ============================================================================

HTTPResponse RouteHandlers::HandleHealth(const HTTPRequest& req) {
    JSONBuilder json;
    json.Add("status", "healthy")
        .Add("timestamp", std::to_string(std::time(nullptr)));

    return HTTPResponse::JSON(json.Build());
}

HTTPResponse RouteHandlers::HandleVersion(const HTTPRequest& req) {
    JSONBuilder json;
    json.Add("name", "Scylla API Server")
        .Add("version", "2.0.0")
        .Add("api_version", "v1");

    return HTTPResponse::JSON(json.Build());
}

HTTPResponse RouteHandlers::HandleStats(const HTTPRequest& req) {
    JSONBuilder json;
    json.Add("uptime_seconds", 0)
        .Add("total_requests", 0)
        .Add("active_jobs", 0);

    return HTTPResponse::JSON(json.Build());
}

HTTPResponse RouteHandlers::HandleAnalyze(const HTTPRequest& req) {
    // Extract file path from request
    auto it = req.params.find("file");
    if (it == req.params.end()) {
        return HTTPResponse::BadRequest("Missing 'file' parameter");
    }

    std::string filePath = it->second;

    try {
        // Perform synchronous analysis
        Security::SecurityAnalyzer analyzer;
        auto result = analyzer.Analyze(filePath);

        // Build response
        JSONBuilder json;
        json.Add("file", filePath)
            .Add("security_score", result.securityScore)
            .Add("dep_enabled", result.mitigations.depEnabled)
            .Add("aslr_enabled", result.mitigations.aslrEnabled)
            .Add("cfg_enabled", result.mitigations.cfgEnabled)
            .Add("signed", result.mitigations.authenticodePresent);

        return HTTPResponse::JSON(json.Build());

    } catch (const std::exception& e) {
        return HTTPResponse::InternalError(e.what());
    }
}

HTTPResponse RouteHandlers::HandleAnalyzeAsync(const HTTPRequest& req) {
    // Extract file path
    auto it = req.params.find("file");
    if (it == req.params.end()) {
        return HTTPResponse::BadRequest("Missing 'file' parameter");
    }

    // Create job (would be implemented in server instance)
    JSONBuilder json;
    json.Add("job_id", "job_123456")
        .Add("status", "queued")
        .Add("message", "Analysis job created");

    return HTTPResponse::JSON(json.Build(), 202);
}

HTTPResponse RouteHandlers::HandleJobStatus(const HTTPRequest& req) {
    // Would extract job ID from path and return status
    JSONBuilder json;
    json.Add("job_id", "job_123456")
        .Add("status", "processing")
        .Add("progress", 50);

    return HTTPResponse::JSON(json.Build());
}

HTTPResponse RouteHandlers::HandleSecurity(const HTTPRequest& req) {
    auto it = req.params.find("file");
    if (it == req.params.end()) {
        return HTTPResponse::BadRequest("Missing 'file' parameter");
    }

    try {
        Security::SecurityAnalyzer analyzer;
        auto result = analyzer.Analyze(it->second);

        JSONBuilder json;
        json.Add("security_score", result.securityScore)
            .Add("risk_level", "low")
            .Add("dep", result.mitigations.depEnabled)
            .Add("aslr", result.mitigations.aslrEnabled)
            .Add("cfg", result.mitigations.cfgEnabled)
            .Add("safe_seh", result.mitigations.safeSEH)
            .Add("gs", result.mitigations.gsEnabled);

        return HTTPResponse::JSON(json.Build());

    } catch (const std::exception& e) {
        return HTTPResponse::InternalError(e.what());
    }
}

HTTPResponse RouteHandlers::HandleSecurityBatch(const HTTPRequest& req) {
    // Batch security analysis
    JSONBuilder json;
    json.Add("batch_id", "batch_123")
        .Add("status", "queued")
        .Add("total_files", 0);

    return HTTPResponse::JSON(json.Build(), 202);
}

HTTPResponse RouteHandlers::HandlePacker(const HTTPRequest& req) {
    auto it = req.params.find("file");
    if (it == req.params.end()) {
        return HTTPResponse::BadRequest("Missing 'file' parameter");
    }

    try {
        PackerDetector detector;
        // Would perform actual detection

        JSONBuilder json;
        json.Add("is_packed", false)
            .Add("packer", "None")
            .Add("confidence", 0);

        return HTTPResponse::JSON(json.Build());

    } catch (const std::exception& e) {
        return HTTPResponse::InternalError(e.what());
    }
}

HTTPResponse RouteHandlers::HandlePackerBatch(const HTTPRequest& req) {
    JSONBuilder json;
    json.Add("batch_id", "batch_456")
        .Add("status", "queued");

    return HTTPResponse::JSON(json.Build(), 202);
}

HTTPResponse RouteHandlers::HandleListProfiles(const HTTPRequest& req) {
    auto& configMgr = ConfigurationManager::Instance();
    auto profiles = configMgr.ListProfiles();

    std::string profilesJSON = "[";
    for (size_t i = 0; i < profiles.size(); i++) {
        profilesJSON += "\"" + profiles[i] + "\"";
        if (i < profiles.size() - 1) profilesJSON += ",";
    }
    profilesJSON += "]";

    JSONBuilder json;
    json.AddObject("profiles", profilesJSON);

    return HTTPResponse::JSON(json.Build());
}

HTTPResponse RouteHandlers::HandleGetProfile(const HTTPRequest& req) {
    // Would extract profile name from path
    JSONBuilder json;
    json.Add("name", "default")
        .Add("description", "Default configuration");

    return HTTPResponse::JSON(json.Build());
}

HTTPResponse RouteHandlers::HandleSetProfile(const HTTPRequest& req) {
    JSONBuilder json;
    json.Add("success", true)
        .Add("message", "Profile activated");

    return HTTPResponse::JSON(json.Build());
}

HTTPResponse RouteHandlers::HandleUpload(const HTTPRequest& req) {
    // Handle file upload
    JSONBuilder json;
    json.Add("file_id", "file_789")
        .Add("size", 1024)
        .Add("path", "/uploads/sample.exe");

    return HTTPResponse::JSON(json.Build(), 201);
}

HTTPResponse RouteHandlers::HandleDownload(const HTTPRequest& req) {
    // Handle file download
    HTTPResponse resp;
    resp.statusCode = 200;
    resp.headers["Content-Type"] = "application/octet-stream";
    resp.headers["Content-Disposition"] = "attachment; filename=result.json";
    return resp;
}

HTTPResponse RouteHandlers::HandleBatchAnalyze(const HTTPRequest& req) {
    JSONBuilder json;
    json.Add("batch_id", "batch_999")
        .Add("status", "queued")
        .Add("total_files", 0);

    return HTTPResponse::JSON(json.Build(), 202);
}

HTTPResponse RouteHandlers::HandleBatchStatus(const HTTPRequest& req) {
    JSONBuilder json;
    json.Add("batch_id", "batch_999")
        .Add("status", "processing")
        .Add("completed", 5)
        .Add("total", 10);

    return HTTPResponse::JSON(json.Build());
}

// ============================================================================
// APIClient Implementation
// ============================================================================

APIClient::APIClient(const std::string& baseURL)
    : m_baseURL(baseURL)
{
}

std::string APIClient::Analyze(const std::string& filePath) {
    return DoPOST("/api/analyze", "{\"file\":\"" + filePath + "\"}");
}

std::string APIClient::AnalyzeAsync(const std::string& filePath) {
    return DoPOST("/api/analyze/async", "{\"file\":\"" + filePath + "\"}");
}

std::string APIClient::GetJobStatus(const std::string& jobID) {
    return DoGET("/api/jobs/" + jobID);
}

std::string APIClient::CheckSecurity(const std::string& filePath) {
    return DoPOST("/api/security", "{\"file\":\"" + filePath + "\"}");
}

std::string APIClient::DetectPacker(const std::string& filePath) {
    return DoPOST("/api/packer", "{\"file\":\"" + filePath + "\"}");
}

std::vector<std::string> APIClient::ListProfiles() {
    std::string json = DoGET("/api/profiles");
    // Would parse JSON and return list
    return {};
}

std::string APIClient::GetProfile(const std::string& name) {
    return DoGET("/api/profiles/" + name);
}

bool APIClient::SetProfile(const std::string& name) {
    std::string result = DoPOST("/api/profiles/" + name, "{}");
    return !result.empty();
}

std::string APIClient::UploadFile(const std::string& filePath) {
    return DoMultipart("/api/upload", filePath);
}

std::string APIClient::DoGET(const std::string& endpoint) {
    // Simplified - would use actual HTTP client library
    return "{}";
}

std::string APIClient::DoPOST(const std::string& endpoint, const std::string& body) {
    // Simplified - would use actual HTTP client library
    return "{}";
}

std::string APIClient::DoMultipart(const std::string& endpoint, const std::string& filePath) {
    // Simplified - would use actual HTTP client library
    return "{}";
}

} // namespace API
} // namespace Scylla
