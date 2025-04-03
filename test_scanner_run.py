import subprocess
import os

# Prepare required env file
assert os.path.exists(".env"), ".env file is missing"

# Clean previous outputs
if os.path.exists("repo_vuln.db"):
    os.remove("repo_vuln.db")
if os.path.exists("aggregated_vulnerabilities.json"):
    os.remove("aggregated_vulnerabilities.json")

# Run the scanner
print("[Test] Running scanner.py end-to-end")
subprocess.run(["python3", "scanner.py"], check=True)

# Check outputs
assert os.path.exists("repo_vuln.db"), "DB was not created"
assert os.path.exists("aggregated_vulnerabilities.json"), "JSON report missing"

print("[Test] Scanner ran successfully. Reports generated.")


# ✅ CHECKLIST BEFORE RUNNING

# .env must contain:
# - BITBUCKET_WORKSPACE
# - ATLASSIAN_USERNAME
# - ATLASSIAN_API_KEY
# - OPENAI_API_KEY
# - NVD_API_KEY
# - SLACK_WEBHOOK_URL
# - SLACK_API_TOKEN
# - SLACK_CHANNEL_ID

# Required folders (auto-created if missing):
# - repos/
# - sboms/
# - nvdcve_feed/
# - logs/

# Required CLI tools installed:
# - syft
# - grype
# - git
# - Python >= 3.9

# Optional:
# - templates/vuln_report.html (for HTML output)
# - file_upload.py (for Slack file uploads)