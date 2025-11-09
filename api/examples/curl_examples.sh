#!/bin/bash
# Scylla REST API - curl Examples

API_URL="http://localhost:8080"

echo "Scylla REST API - curl Examples"
echo "================================"
echo ""

# Health Check
echo "1. Health Check"
echo "   GET /api/health"
curl -X GET "$API_URL/api/health"
echo -e "\n"

# Version
echo "2. Version Information"
echo "   GET /api/version"
curl -X GET "$API_URL/api/version"
echo -e "\n"

# Statistics
echo "3. Server Statistics"
echo "   GET /api/stats"
curl -X GET "$API_URL/api/stats"
echo -e "\n"

# Analyze (synchronous)
echo "4. Analyze PE File (Synchronous)"
echo "   POST /api/analyze?file=sample.exe"
curl -X POST "$API_URL/api/analyze?file=sample.exe"
echo -e "\n"

# Analyze (asynchronous)
echo "5. Analyze PE File (Asynchronous)"
echo "   POST /api/analyze/async?file=sample.exe"
JOB_RESPONSE=$(curl -X POST "$API_URL/api/analyze/async?file=sample.exe")
echo "$JOB_RESPONSE"
JOB_ID=$(echo "$JOB_RESPONSE" | grep -o '"job_id":"[^"]*' | cut -d'"' -f4)
echo -e "\n"

# Job Status
if [ ! -z "$JOB_ID" ]; then
    echo "6. Get Job Status"
    echo "   GET /api/jobs/$JOB_ID"
    curl -X GET "$API_URL/api/jobs/$JOB_ID"
    echo -e "\n"
fi

# Security Analysis
echo "7. Security Analysis"
echo "   POST /api/security?file=target.exe"
curl -X POST "$API_URL/api/security?file=target.exe"
echo -e "\n"

# Packer Detection
echo "8. Packer Detection"
echo "   POST /api/packer?file=packed.exe"
curl -X POST "$API_URL/api/packer?file=packed.exe"
echo -e "\n"

# List Profiles
echo "9. List Configuration Profiles"
echo "   GET /api/profiles"
curl -X GET "$API_URL/api/profiles"
echo -e "\n"

# Get Profile
echo "10. Get Profile Details"
echo "    GET /api/profiles/malware-analysis"
curl -X GET "$API_URL/api/profiles/malware-analysis"
echo -e "\n"

# Set Profile
echo "11. Set Active Profile"
echo "    POST /api/profiles/malware-analysis"
curl -X POST "$API_URL/api/profiles/malware-analysis"
echo -e "\n"

# Upload File
echo "12. Upload File"
echo "    POST /api/upload (multipart/form-data)"
# Uncomment if you have a file to upload
# curl -X POST -F "file=@sample.exe" "$API_URL/api/upload"
echo "    (Example: curl -X POST -F \"file=@sample.exe\" $API_URL/api/upload)"
echo -e "\n"

# Batch Analysis
echo "13. Batch Analysis"
echo "    POST /api/batch/analyze"
curl -X POST "$API_URL/api/batch/analyze" \
  -H "Content-Type: application/json" \
  -d '{"files":["sample1.exe","sample2.exe","sample3.exe"]}'
echo -e "\n"

# With Authentication
echo "14. Authenticated Request"
echo "    GET /api/health (with API key)"
# Uncomment and set your API key
# curl -X GET "$API_URL/api/health" -H "X-API-Key: your-api-key-here"
echo "    (Example: curl -X GET $API_URL/api/health -H \"X-API-Key: your-key\")"
echo -e "\n"

# Pretty JSON Output
echo "15. Pretty JSON Output (with jq)"
echo "    GET /api/version | jq"
if command -v jq &> /dev/null; then
    curl -s -X GET "$API_URL/api/version" | jq
else
    echo "    (Install jq for pretty JSON: sudo apt install jq)"
fi
echo -e "\n"

echo "Examples completed!"
echo ""
echo "For more information, see the API documentation at:"
echo "  http://localhost:8080/api/docs"
