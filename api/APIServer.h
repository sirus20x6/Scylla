/*
 * Scylla REST API Server
 *
 * HTTP API for remote PE analysis and reverse engineering
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>
#include <atomic>
#include <mutex>

namespace Scylla {
namespace API {

/*
 * HTTP Request
 */
struct HTTPRequest {
    std::string method;          // GET, POST, PUT, DELETE
    std::string path;            // /api/analyze
    std::string query;           // Query string
    std::map<std::string, std::string> headers;
    std::map<std::string, std::string> params;  // Query parameters
    std::string body;            // Request body
    std::vector<uint8_t> binaryBody;  // Binary data (file uploads)
};

/*
 * HTTP Response
 */
struct HTTPResponse {
    int statusCode = 200;
    std::string statusMessage = "OK";
    std::map<std::string, std::string> headers;
    std::string body;
    std::vector<uint8_t> binaryBody;

    // Helper constructors
    static HTTPResponse OK(const std::string& body);
    static HTTPResponse Created(const std::string& body);
    static HTTPResponse BadRequest(const std::string& message);
    static HTTPResponse NotFound(const std::string& message);
    static HTTPResponse InternalError(const std::string& message);
    static HTTPResponse JSON(const std::string& json, int code = 200);
};

/*
 * Request Handler
 */
using RequestHandler = std::function<HTTPResponse(const HTTPRequest&)>;

/*
 * API Server Configuration
 */
struct ServerConfig {
    std::string host = "127.0.0.1";
    int port = 8080;
    int maxConnections = 100;
    int workerThreads = 4;
    bool enableCORS = true;
    bool enableAuth = false;
    std::string apiKey;
    std::string uploadDir = "uploads";
    size_t maxUploadSize = 100 * 1024 * 1024;  // 100 MB
    bool enableRateLimit = true;
    int rateLimit = 60;  // requests per minute
    bool enableLogging = true;
};

/*
 * Analysis Job
 */
struct AnalysisJob {
    std::string id;
    std::string filePath;
    std::string status;  // queued, processing, completed, failed
    std::string result;  // JSON result
    std::string error;
    std::chrono::system_clock::time_point created;
    std::chrono::system_clock::time_point started;
    std::chrono::system_clock::time_point completed;
};

/*
 * API Server
 *
 * RESTful API server for Scylla functionality
 */
class APIServer {
public:
    APIServer(const ServerConfig& config = ServerConfig());
    ~APIServer();

    // Server lifecycle
    bool Start();
    void Stop();
    bool IsRunning() const { return m_running; }

    // Route registration
    void RegisterRoute(const std::string& method, const std::string& path,
                      RequestHandler handler);

    // Built-in routes
    void RegisterBuiltinRoutes();

private:
    ServerConfig m_config;
    std::atomic<bool> m_running;
    std::mutex m_jobsMutex;
    std::map<std::string, AnalysisJob> m_jobs;

    // HTTP server implementation
    void ServerLoop();
    HTTPResponse HandleRequest(const HTTPRequest& request);
    HTTPResponse RouteRequest(const HTTPRequest& request);

    // Route handlers
    std::map<std::string, std::map<std::string, RequestHandler>> m_routes;

    // Middleware
    bool AuthenticateRequest(const HTTPRequest& request);
    bool CheckRateLimit(const std::string& clientIP);
    HTTPResponse ApplyCORS(HTTPResponse response);

    // Job management
    std::string CreateJob(const std::string& filePath);
    AnalysisJob* GetJob(const std::string& id);
    void ProcessJob(const std::string& id);

    // Logging
    void LogRequest(const HTTPRequest& request, const HTTPResponse& response);
};

/*
 * Built-in Route Handlers
 */
class RouteHandlers {
public:
    // Health & Status
    static HTTPResponse HandleHealth(const HTTPRequest& req);
    static HTTPResponse HandleVersion(const HTTPRequest& req);
    static HTTPResponse HandleStats(const HTTPRequest& req);

    // Analysis
    static HTTPResponse HandleAnalyze(const HTTPRequest& req);
    static HTTPResponse HandleAnalyzeAsync(const HTTPRequest& req);
    static HTTPResponse HandleJobStatus(const HTTPRequest& req);

    // Security
    static HTTPResponse HandleSecurity(const HTTPRequest& req);
    static HTTPResponse HandleSecurityBatch(const HTTPRequest& req);

    // Packer Detection
    static HTTPResponse HandlePacker(const HTTPRequest& req);
    static HTTPResponse HandlePackerBatch(const HTTPRequest& req);

    // Configuration
    static HTTPResponse HandleListProfiles(const HTTPRequest& req);
    static HTTPResponse HandleGetProfile(const HTTPRequest& req);
    static HTTPResponse HandleSetProfile(const HTTPRequest& req);

    // File Upload
    static HTTPResponse HandleUpload(const HTTPRequest& req);
    static HTTPResponse HandleDownload(const HTTPRequest& req);

    // Batch Operations
    static HTTPResponse HandleBatchAnalyze(const HTTPRequest& req);
    static HTTPResponse HandleBatchStatus(const HTTPRequest& req);
};

/*
 * JSON Helper
 */
class JSONBuilder {
public:
    JSONBuilder();

    JSONBuilder& Add(const std::string& key, const std::string& value);
    JSONBuilder& Add(const std::string& key, int value);
    JSONBuilder& Add(const std::string& key, bool value);
    JSONBuilder& Add(const std::string& key, double value);
    JSONBuilder& AddArray(const std::string& key, const std::vector<std::string>& values);
    JSONBuilder& AddObject(const std::string& key, const std::string& json);

    std::string Build();

private:
    std::string m_json;
    bool m_first = true;
};

/*
 * API Client
 *
 * C++ client for the Scylla API server
 */
class APIClient {
public:
    APIClient(const std::string& baseURL);

    // Analysis
    std::string Analyze(const std::string& filePath);
    std::string AnalyzeAsync(const std::string& filePath);
    std::string GetJobStatus(const std::string& jobID);

    // Security
    std::string CheckSecurity(const std::string& filePath);

    // Packer
    std::string DetectPacker(const std::string& filePath);

    // Configuration
    std::vector<std::string> ListProfiles();
    std::string GetProfile(const std::string& name);
    bool SetProfile(const std::string& name);

    // File operations
    std::string UploadFile(const std::string& filePath);

private:
    std::string m_baseURL;

    std::string DoGET(const std::string& endpoint);
    std::string DoPOST(const std::string& endpoint, const std::string& body);
    std::string DoMultipart(const std::string& endpoint,
                           const std::string& filePath);
};

} // namespace API
} // namespace Scylla
