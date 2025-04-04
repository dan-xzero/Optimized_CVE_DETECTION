# 🛡️ AI-Powered Vulnerability Scanner

A comprehensive Python-based vulnerability scanner that analyzes Bitbucket repositories using:

- 📦 SBOM Generation via Syft  
- 🔍 Vulnerability Scanning via Grype  
- 🤖 Enrichment via OpenAI (GPT)  
- 🧠 False Positive Detection via AI  
- 🧾 CVE Enrichment via NVD REST API + Shodan EPSS  
- 🗃️ PostgreSQL DB (via SQLAlchemy ORM)  
- 📣 Slack Alerts + Interactive Buttons  
- 🎟️ Jira Ticket Integration (ADF-formatted)  
- 🧩 CPE Extraction from Config Files

---

## ⚙️ Features

| Feature         | Description                                                              |
|----------------|--------------------------------------------------------------------------|
| SBOM            | Generates CycloneDX JSON SBOM via Syft                                  |
| Grype           | Scans for known vulnerabilities (CVE-based)                             |
| OpenAI          | GPT-4/3.5-turbo used for CVE enrichment & false-positive validation      |
| NVD + EPSS      | Real-time CVSS + EPSS scoring from NVD API & Shodan                     |
| Slack           | Sends alerts + buttons to trigger rescans or Jira ticket creation       |
| Jira            | Automatically creates rich ADF Jira tickets                             |
| CPE Extraction  | Uses GPT to identify config-based software and versions                 |

---

## 🧪 How It Works

1. **Repository Fetch** from Bitbucket
2. **Clone & SBOM** via Syft
3. **Grype Scan** for CVEs
4. **OpenAI Enrichment** for severity, mitigation, explanation
5. **False Positive Check** using GPT
6. **CPE Extraction** from YAML/JSON files
7. **Slack Alerts** with actionable buttons
8. **Jira Ticket** creation for critical vulns

---

## ⚙️ PostgreSQL Setup

This project uses **PostgreSQL** (not SQLite) to enable concurrent, scalable vulnerability scans.

### 🐘 Local PostgreSQL Setup (macOS/Linux)

```bash
# Install PostgreSQL
brew install postgresql  # macOS
sudo apt install postgresql postgresql-contrib  # Ubuntu/Debian

# Start PostgreSQL
brew services start postgresql  # macOS
sudo service postgresql start  # Linux

# Create user + DB
psql postgres
CREATE USER postgres WITH PASSWORD 'secret';
CREATE DATABASE repo_vuln OWNER postgres;
```

Ensure your `.env` contains:

```env
DATABASE_URL=postgresql://User:Password@localhost:5432/repo_vuln
```

---

## 🛠️ Setup Instructions

### 1. Clone the Repo

```bash
git clone https://github.com/your-org/vulnerability-scanner.git
cd vulnerability-scanner
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure `.env`

```env
# Bitbucket
BITBUCKET_WORKSPACE=your_workspace
ATLASSIAN_USERNAME=your_email
ATLASSIAN_API_KEY=your_bitbucket_api_token

# Slack
SLACK_API_TOKEN=xoxb-...
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
SLACK_CHANNEL_ID=C01...

# OpenAI
OPENAI_API_KEY=sk-...

# Jira
JIRA_ORG=your-org
JIRA_USERNAME=your_email
JIRA_API_KEY=your_jira_token

# Database
DATABASE_URL=postgresql://postgres:secret@localhost:5432/repo_vuln

# NVD
NVD_API_KEY=your_nvd_api_key
```

---

## 🏁 Run the Scanner

```bash
python scanner_postgress.py
```

Or scan one repo manually:

```bash
python scan_repo_worker.py --repo-name my-repo --clone-url git@bitbucket.org:workspace/my-repo.git --rescan
```

---

## 📁 Directory Structure

```
.
├── scanner_postgress.py     # Main orchestrator
├── scan_repo_worker.py      # Single-repo scan worker
├── models.py                # SQLAlchemy ORM models
├── db.py                    # DB engine/session creator
├── file_upload.py           # Slack file uploader
├── .env                     # Environment secrets
├── requirements.txt
├── sboms/                   # Syft SBOMs
├── repos/                   # Git cloned repos
├── logs/                    # Per-repo logs
└── aggregated_vulnerabilities.json
```

---

## 🧾 Example Slack Alert

```
:rotating_light: Critical Vulnerability Detected!
Repo: `my-repo`
CVE: `CVE-2023-XXXX`
Severity: Critical (Score: 9.8)
[ Create Jira Ticket ]
```

---

## ✅ To-Do

- [ ] Frontend React Dashboard
- [ ] GitHub/GitLab support
- [ ] ServiceNow ticketing
- [ ] Full unit/integration tests

---

## 👨‍💻 Maintainers

danxzero
Contributions & feedback welcome!
