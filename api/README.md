# Scylla REST API Server

HTTP API for remote PE analysis and reverse engineering.

## Features

- **RESTful API** - Standard HTTP endpoints with JSON responses
- **Async Analysis** - Long-running jobs with status polling
- **Batch Processing** - Analyze multiple files in parallel
- **Configuration** - Manage analysis profiles remotely
- **File Upload** - Upload files for analysis
- **CORS Support** - Enable cross-origin requests
- **Authentication** - Optional API key authentication
- **Rate Limiting** - Prevent abuse
- **Cross-Platform** - Works on Windows, Linux, and macOS

## Quick Start

### Starting the Server

```bash
# Basic usage
./scylla-api

# Custom host and port
./scylla-api --host 0.0.0.0 --port 9000

# With authentication
./scylla-api --api-key secret123

# More workers for high load
./scylla-api --workers 8
```

### Health Check

```bash
curl http://localhost:8080/api/health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "1234567890"
}
```

## API Endpoints

### Health & Status

#### GET /api/health
Check server health status.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "1234567890"
}
```

#### GET /api/version
Get server version information.

**Response:**
```json
{
  "name": "Scylla API Server",
  "version": "2.0.0",
  "api_version": "v1"
}
```

#### GET /api/stats
Get server statistics.

**Response:**
```json
{
  "uptime_seconds": 3600,
  "total_requests": 1523,
  "active_jobs": 3
}
```

### Analysis

#### POST /api/analyze
Analyze PE file (synchronous).

**Parameters:**
- `file` (string, required) - Path to PE file

**Example:**
```bash
curl -X POST "http://localhost:8080/api/analyze?file=sample.exe"
```

**Response:**
```json
{
  "file": "sample.exe",
  "security_score": 75,
  "dep_enabled": true,
  "aslr_enabled": true,
  "cfg_enabled": false,
  "signed": true
}
```

#### POST /api/analyze/async
Analyze PE file (asynchronous).

**Parameters:**
- `file` (string, required) - Path to PE file

**Example:**
```bash
curl -X POST "http://localhost:8080/api/analyze/async?file=large.exe"
```

**Response:**
```json
{
  "job_id": "job_123456",
  "status": "queued",
  "message": "Analysis job created"
}
```

#### GET /api/jobs/:id
Get analysis job status.

**Example:**
```bash
curl http://localhost:8080/api/jobs/job_123456
```

**Response:**
```json
{
  "job_id": "job_123456",
  "status": "completed",
  "result": {
    "security_score": 75,
    "dep_enabled": true
  }
}
```

### Security Analysis

#### POST /api/security
Check security mitigations.

**Parameters:**
- `file` (string, required) - Path to PE file

**Example:**
```bash
curl -X POST "http://localhost:8080/api/security?file=target.exe"
```

**Response:**
```json
{
  "security_score": 85,
  "risk_level": "low",
  "dep": true,
  "aslr": true,
  "cfg": true,
  "safe_seh": true,
  "gs": true
}
```

#### POST /api/security/batch
Batch security analysis.

**Body:**
```json
{
  "files": ["app1.exe", "app2.exe", "app3.exe"]
}
```

**Response:**
```json
{
  "batch_id": "batch_123",
  "status": "queued",
  "total_files": 3
}
```

### Packer Detection

#### POST /api/packer
Detect packer.

**Parameters:**
- `file` (string, required) - Path to PE file

**Example:**
```bash
curl -X POST "http://localhost:8080/api/packer?file=packed.exe"
```

**Response:**
```json
{
  "is_packed": true,
  "packer": "UPX",
  "confidence": 95
}
```

#### POST /api/packer/batch
Batch packer detection.

### Configuration

#### GET /api/profiles
List all configuration profiles.

**Example:**
```bash
curl http://localhost:8080/api/profiles
```

**Response:**
```json
{
  "profiles": [
    "default",
    "quick-scan",
    "deep-analysis",
    "malware-analysis",
    "performance"
  ]
}
```

#### GET /api/profiles/:name
Get profile details.

**Example:**
```bash
curl http://localhost:8080/api/profiles/malware-analysis
```

**Response:**
```json
{
  "name": "malware-analysis",
  "description": "Optimized for analyzing packed malware samples"
}
```

#### POST /api/profiles/:name
Set active profile.

**Example:**
```bash
curl -X POST http://localhost:8080/api/profiles/malware-analysis
```

**Response:**
```json
{
  "success": true,
  "message": "Profile activated"
}
```

### File Upload

#### POST /api/upload
Upload file for analysis.

**Example:**
```bash
curl -X POST -F "file=@sample.exe" http://localhost:8080/api/upload
```

**Response:**
```json
{
  "file_id": "file_789",
  "size": 102400,
  "path": "/uploads/sample.exe"
}
```

#### GET /api/download/:id
Download analysis result.

### Batch Operations

#### POST /api/batch/analyze
Batch analyze multiple files.

**Body:**
```json
{
  "files": ["file1.exe", "file2.exe", "file3.exe"],
  "profile": "malware-analysis"
}
```

**Response:**
```json
{
  "batch_id": "batch_999",
  "status": "queued",
  "total_files": 3
}
```

#### GET /api/batch/:id
Get batch job status.

**Example:**
```bash
curl http://localhost:8080/api/batch/batch_999
```

**Response:**
```json
{
  "batch_id": "batch_999",
  "status": "processing",
  "completed": 2,
  "total": 3,
  "progress": 66.7
}
```

## Authentication

Enable API key authentication:

```bash
./scylla-api --api-key your-secret-key
```

Include the API key in requests:

```bash
curl -H "X-API-Key: your-secret-key" http://localhost:8080/api/health
```

## Client Examples

### Python

```python
import requests

# Simple request
response = requests.post(
    "http://localhost:8080/api/analyze",
    params={'file': 'sample.exe'}
)
result = response.json()
print(f"Security Score: {result['security_score']}")
```

See `examples/api_client.py` for complete Python client.

### curl

```bash
# Analyze file
curl -X POST "http://localhost:8080/api/analyze?file=sample.exe"

# Check security
curl -X POST "http://localhost:8080/api/security?file=target.exe"

# Detect packer
curl -X POST "http://localhost:8080/api/packer?file=packed.exe"
```

See `examples/curl_examples.sh` for more examples.

### JavaScript

```javascript
// Analyze file
fetch('http://localhost:8080/api/analyze?file=sample.exe', {
    method: 'POST'
})
.then(response => response.json())
.then(data => {
    console.log('Security Score:', data.security_score);
});
```

## Configuration

Server configuration via command-line:

```
Options:
  --host HOST        Bind to HOST (default: 127.0.0.1)
  --port PORT        Listen on PORT (default: 8080)
  --workers N        Use N worker threads (default: 4)
  --api-key KEY      Require API key authentication
  --no-cors          Disable CORS headers
  --upload-dir DIR   Upload directory (default: uploads)
  --help             Show help message
```

## Use Cases

### 1. Automated Malware Analysis Pipeline

```python
from scylla_api import ScyllaAPIClient

client = ScyllaAPIClient("http://localhost:8080")

# Set profile
client.set_profile("malware-analysis")

# Analyze sample
result = client.analyze("suspicious.exe")

if result['security_score'] < 30:
    print("ALERT: Suspicious file detected!")
```

### 2. Web Service Integration

```python
from flask import Flask, request, jsonify
from scylla_api import ScyllaAPIClient

app = Flask(__name__)
client = ScyllaAPIClient("http://localhost:8080")

@app.route('/scan', methods=['POST'])
def scan_file():
    file = request.files['file']
    file.save('temp.exe')

    # Analyze with Scylla
    result = client.analyze('temp.exe')

    return jsonify(result)
```

### 3. Batch Processing Workflow

```python
# Analyze entire directory
files = glob.glob("samples/*.exe")

# Start batch job
batch = client.batch_analyze(files)
batch_id = batch['batch_id']

# Monitor progress
while True:
    status = client.get_batch_status(batch_id)
    if status['status'] == 'completed':
        break
    print(f"Progress: {status['completed']}/{status['total']}")
    time.sleep(1)
```

### 4. CI/CD Integration

```yaml
# .github/workflows/security-check.yml
- name: Security Analysis
  run: |
    # Start Scylla API server
    scylla-api --port 8080 &

    # Analyze build artifacts
    curl -X POST "http://localhost:8080/api/security?file=build/app.exe"
```

## Error Handling

API returns standard HTTP status codes:

- `200 OK` - Success
- `201 Created` - Resource created
- `202 Accepted` - Async job created
- `400 Bad Request` - Invalid parameters
- `401 Unauthorized` - Authentication required
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server error

Error response format:

```json
{
  "error": "Error message description"
}
```

## Rate Limiting

Default: 60 requests per minute per IP.

Rate limit headers:
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1234567890
```

## CORS

CORS is enabled by default. Disable with `--no-cors` flag.

CORS headers:
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: Content-Type, X-API-Key
```

## Building

### CMake

```bash
mkdir build && cd build
cmake -DBUILD_API_SERVER=ON ..
make
```

### Manual

```bash
g++ -std=c++17 -o scylla-api main.cpp APIServer.cpp -lScylla -pthread
```

## Dependencies

- C++17 compiler
- libScylla (core library)
- POSIX threads (Linux/macOS)
- Winsock2 (Windows)

## Performance

- **Throughput**: 100+ requests/second (8 workers)
- **Latency**: <100ms for simple analysis
- **Memory**: ~50MB base + analysis overhead
- **Concurrent Jobs**: Limited by worker count

## Security Considerations

1. **Authentication**: Use API keys in production
2. **HTTPS**: Deploy behind reverse proxy with TLS
3. **File Validation**: Validate uploaded files
4. **Rate Limiting**: Prevent DoS attacks
5. **Network**: Bind to 127.0.0.1 for local-only access

## Deployment

### Docker

```dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y scylla
EXPOSE 8080
CMD ["scylla-api", "--host", "0.0.0.0", "--port", "8080"]
```

### Systemd

```ini
[Unit]
Description=Scylla API Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/scylla-api --host 0.0.0.0 --port 8080
Restart=always

[Install]
WantedBy=multi-user.target
```

### Nginx Reverse Proxy

```nginx
location /scylla/ {
    proxy_pass http://127.0.0.1:8080/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

## License

See the main Scylla repository for license information.

## Support

- Documentation: https://github.com/NtQuery/Scylla/wiki/API
- Issues: https://github.com/NtQuery/Scylla/issues
- Examples: `api/examples/`
