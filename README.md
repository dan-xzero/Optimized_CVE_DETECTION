# 🛡️ CVE Vulnerability Scanner

A full-stack, automated vulnerability scanner that integrates:

- 🔍 **Syft** & **Grype** for SBOM + vulnerability detection
- 🧠 **OpenAI** for enrichment, false positive filtering, scoring
- 📥 **Bitbucket** for repo discovery
- 🧵 **Slack** for alerts + interactive rescans
- 🗂️ **NVD Feeds + REST API** for CVE enrichment
- 🧪 Local **SQLite3** DB for all vuln state

---

## 🚀 How It Works

1. **Repo Sync**: Clones all Bitbucket repos
2. **SBOM Generation**: Uses Syft to detect packages
3. **Grype Scan**: Finds vulnerabilities via Grype
4. **OpenAI Enrichment**: Adds severity, summary, false-positive filtering
5. **NVD Matching**: Downloads NVD feeds + finds CPE matches
6. **Slack Alerts**: Sends critical vulns to Slack with interactive buttons
7. **Optional HTML Report**: Renders an HTML dashboard using Jinja2

---

## ⚙️ Setup

1. Install requirements:
```bash
pip install -r requirements.txt
```

2. Create `.env` file:
```ini
BITBUCKET_WORKSPACE=your_workspace
ATLASSIAN_USERNAME=email@example.com
ATLASSIAN_API_KEY=xxx
OPENAI_API_KEY=sk-...
NVD_API_KEY=...
SLACK_WEBHOOK_URL=...
SLACK_API_TOKEN=xoxb-...
SLACK_CHANNEL_ID=CXXXX
SLACK_SIGNING_SECRET=yyyy
```

3. Install Syft and Grype:
```bash
brew install syft grype   # or use install scripts from GitHub
```

---

## 🧪 Run the Scanner
```bash
python3 scanner.py
```

## 📲 Start Slack Button Handler
```bash
python3 slack_interactivity_server.py
```
(Expose with `ngrok http 5000` and set URL in Slack app settings)

---

## 📁 Files
| File                          | Purpose                              |
|-------------------------------|--------------------------------------|
| `scanner.py`                 | Main scanning pipeline               |
| `scan_repo_worker.py`        | Per-repo subprocess scanner          |
| `slack_interactivity_server.py` | Handles Slack button rescans       |
| `.env`                       | Your API secrets (not committed)     |
| `repo_vuln.db`               | SQLite DB                            |
| `logs/`                      | Individual repo scan logs            |

---

## ✨ Features
- False-positive detection (OpenAI)
- Critical alerts + rescans from Slack
- Auto-downloads + parses NVD feeds
- HTML dashboard (optional)
- EPSS score support (optional)

---

> Built for scale: tested on 250+ repos.  
> Easily extendable to GitHub, GitLab, Jira, ServiceNow.

---

Need help automating with cron/systemd or deploying? Just ask 🙌
