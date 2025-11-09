#!/usr/bin/env python3
"""
Scylla API Client - Python Examples

Demonstrates how to use the Scylla REST API from Python.
"""

import requests
import json
import time
from pathlib import Path


class ScyllaAPIClient:
    """Python client for Scylla REST API"""

    def __init__(self, base_url="http://localhost:8080", api_key=None):
        self.base_url = base_url
        self.api_key = api_key
        self.session = requests.Session()

        if api_key:
            self.session.headers['X-API-Key'] = api_key

    def health(self):
        """Check server health"""
        response = self.session.get(f"{self.base_url}/api/health")
        return response.json()

    def version(self):
        """Get server version"""
        response = self.session.get(f"{self.base_url}/api/version")
        return response.json()

    def analyze(self, file_path):
        """Analyze PE file (synchronous)"""
        response = self.session.post(
            f"{self.base_url}/api/analyze",
            params={'file': file_path}
        )
        return response.json()

    def analyze_async(self, file_path):
        """Analyze PE file (asynchronous)"""
        response = self.session.post(
            f"{self.base_url}/api/analyze/async",
            params={'file': file_path}
        )
        return response.json()

    def get_job_status(self, job_id):
        """Get analysis job status"""
        response = self.session.get(f"{self.base_url}/api/jobs/{job_id}")
        return response.json()

    def wait_for_job(self, job_id, timeout=60):
        """Wait for async job to complete"""
        start = time.time()

        while time.time() - start < timeout:
            result = self.get_job_status(job_id)
            status = result.get('status')

            if status == 'completed':
                return result
            elif status == 'failed':
                raise Exception(f"Job failed: {result.get('error')}")

            time.sleep(1)

        raise TimeoutError(f"Job {job_id} did not complete in {timeout}s")

    def check_security(self, file_path):
        """Check security mitigations"""
        response = self.session.post(
            f"{self.base_url}/api/security",
            params={'file': file_path}
        )
        return response.json()

    def detect_packer(self, file_path):
        """Detect packer"""
        response = self.session.post(
            f"{self.base_url}/api/packer",
            params={'file': file_path}
        )
        return response.json()

    def list_profiles(self):
        """List configuration profiles"""
        response = self.session.get(f"{self.base_url}/api/profiles")
        return response.json()

    def get_profile(self, name):
        """Get profile details"""
        response = self.session.get(f"{self.base_url}/api/profiles/{name}")
        return response.json()

    def set_profile(self, name):
        """Set active profile"""
        response = self.session.post(f"{self.base_url}/api/profiles/{name}")
        return response.json()

    def upload_file(self, file_path):
        """Upload file to server"""
        with open(file_path, 'rb') as f:
            files = {'file': f}
            response = self.session.post(
                f"{self.base_url}/api/upload",
                files=files
            )
        return response.json()

    def batch_analyze(self, file_list):
        """Batch analyze multiple files"""
        response = self.session.post(
            f"{self.base_url}/api/batch/analyze",
            json={'files': file_list}
        )
        return response.json()

    def get_batch_status(self, batch_id):
        """Get batch job status"""
        response = self.session.get(f"{self.base_url}/api/batch/{batch_id}")
        return response.json()


def example_basic_analysis():
    """Example: Basic PE analysis"""
    print("=== Basic Analysis Example ===\n")

    client = ScyllaAPIClient()

    # Check server health
    health = client.health()
    print(f"Server Status: {health.get('status')}")

    # Get version
    version = client.version()
    print(f"Server Version: {version.get('version')}\n")

    # Analyze file
    result = client.analyze("C:\\Windows\\System32\\notepad.exe")
    print("Analysis Result:")
    print(f"  File: {result.get('file')}")
    print(f"  Security Score: {result.get('security_score')}/100")
    print(f"  DEP: {'✓' if result.get('dep_enabled') else '✗'}")
    print(f"  ASLR: {'✓' if result.get('aslr_enabled') else '✗'}")
    print(f"  CFG: {'✓' if result.get('cfg_enabled') else '✗'}")


def example_async_analysis():
    """Example: Asynchronous analysis"""
    print("\n=== Async Analysis Example ===\n")

    client = ScyllaAPIClient()

    # Start async analysis
    job = client.analyze_async("sample.exe")
    job_id = job.get('job_id')

    print(f"Job Created: {job_id}")
    print(f"Status: {job.get('status')}\n")

    # Wait for completion
    print("Waiting for analysis to complete...")
    result = client.wait_for_job(job_id)

    print(f"Job Status: {result.get('status')}")
    print(f"Result: {json.dumps(result, indent=2)}")


def example_security_check():
    """Example: Security analysis"""
    print("\n=== Security Check Example ===\n")

    client = ScyllaAPIClient()

    result = client.check_security("target.exe")

    print("Security Analysis:")
    print(f"  Score: {result.get('security_score')}/100")
    print(f"  Risk Level: {result.get('risk_level')}")
    print(f"  DEP: {result.get('dep')}")
    print(f"  ASLR: {result.get('aslr')}")
    print(f"  CFG: {result.get('cfg')}")
    print(f"  SafeSEH: {result.get('safe_seh')}")
    print(f"  /GS: {result.get('gs')}")


def example_packer_detection():
    """Example: Packer detection"""
    print("\n=== Packer Detection Example ===\n")

    client = ScyllaAPIClient()

    result = client.detect_packer("packed.exe")

    print("Packer Detection:")
    print(f"  Packed: {result.get('is_packed')}")
    print(f"  Packer: {result.get('packer')}")
    print(f"  Confidence: {result.get('confidence')}%")


def example_configuration():
    """Example: Configuration management"""
    print("\n=== Configuration Example ===\n")

    client = ScyllaAPIClient()

    # List profiles
    profiles = client.list_profiles()
    print(f"Available Profiles: {profiles.get('profiles')}\n")

    # Get profile
    profile = client.get_profile("malware-analysis")
    print(f"Profile: {profile.get('name')}")
    print(f"Description: {profile.get('description')}\n")

    # Set profile
    result = client.set_profile("malware-analysis")
    print(f"Profile activated: {result.get('success')}")


def example_batch_processing():
    """Example: Batch processing"""
    print("\n=== Batch Processing Example ===\n")

    client = ScyllaAPIClient()

    files = [
        "sample1.exe",
        "sample2.exe",
        "sample3.exe"
    ]

    # Start batch analysis
    batch = client.batch_analyze(files)
    batch_id = batch.get('batch_id')

    print(f"Batch Job Created: {batch_id}")
    print(f"Total Files: {batch.get('total_files')}")
    print(f"Status: {batch.get('status')}\n")

    # Monitor progress
    while True:
        status = client.get_batch_status(batch_id)

        completed = status.get('completed', 0)
        total = status.get('total', 0)

        print(f"Progress: {completed}/{total}")

        if status.get('status') == 'completed':
            break

        time.sleep(2)

    print("\nBatch analysis completed!")


def example_file_upload():
    """Example: File upload and analysis"""
    print("\n=== File Upload Example ===\n")

    client = ScyllaAPIClient()

    # Upload file
    upload_result = client.upload_file("local_sample.exe")

    print(f"File Uploaded:")
    print(f"  File ID: {upload_result.get('file_id')}")
    print(f"  Size: {upload_result.get('size')} bytes")
    print(f"  Path: {upload_result.get('path')}\n")

    # Analyze uploaded file
    file_path = upload_result.get('path')
    result = client.analyze(file_path)

    print(f"Analysis Result:")
    print(f"  Security Score: {result.get('security_score')}/100")


def example_authenticated_access():
    """Example: Authenticated API access"""
    print("\n=== Authenticated Access Example ===\n")

    # Create client with API key
    client = ScyllaAPIClient(
        base_url="http://localhost:8080",
        api_key="your-api-key-here"
    )

    health = client.health()
    print(f"Authenticated request successful: {health.get('status')}")


def example_error_handling():
    """Example: Error handling"""
    print("\n=== Error Handling Example ===\n")

    client = ScyllaAPIClient()

    try:
        # Try to analyze non-existent file
        result = client.analyze("nonexistent.exe")

    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error: {e}")
        print(f"Status Code: {e.response.status_code}")
        print(f"Response: {e.response.text}")

    except Exception as e:
        print(f"Error: {e}")


def example_complete_workflow():
    """Example: Complete malware analysis workflow"""
    print("\n=== Complete Workflow Example ===\n")

    client = ScyllaAPIClient()

    file_path = "suspected_malware.exe"

    print(f"Analyzing: {file_path}\n")

    # 1. Set appropriate profile
    client.set_profile("malware-analysis")
    print("✓ Profile set: malware-analysis")

    # 2. Security analysis
    security = client.check_security(file_path)
    print(f"✓ Security Score: {security.get('security_score')}/100")

    # 3. Packer detection
    packer = client.detect_packer(file_path)
    print(f"✓ Packer: {packer.get('packer')}")

    # 4. Full analysis
    analysis = client.analyze(file_path)
    print(f"✓ Full analysis complete")

    # 5. Generate verdict
    score = security.get('security_score', 0)
    is_packed = packer.get('is_packed', False)
    signed = analysis.get('signed', False)

    suspicion = 0
    if score < 30:
        suspicion += 40
    if is_packed:
        suspicion += 30
    if not signed:
        suspicion += 20

    verdict = "MALICIOUS" if suspicion >= 70 else \
              "SUSPICIOUS" if suspicion >= 40 else "CLEAN"

    print(f"\n{'='*40}")
    print(f"VERDICT: {verdict}")
    print(f"Suspicion Score: {suspicion}/100")
    print(f"{'='*40}")


def main():
    """Run all examples"""
    print("Scylla REST API - Python Client Examples")
    print("=" * 60)

    try:
        example_basic_analysis()
        example_security_check()
        example_packer_detection()
        example_configuration()

        # Uncomment to run other examples:
        # example_async_analysis()
        # example_batch_processing()
        # example_file_upload()
        # example_complete_workflow()

    except requests.exceptions.ConnectionError:
        print("\nError: Could not connect to Scylla API server")
        print("Make sure the server is running on http://localhost:8080")

    except Exception as e:
        print(f"\nError: {e}")


if __name__ == '__main__':
    main()
