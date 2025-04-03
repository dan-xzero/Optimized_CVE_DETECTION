# Optimized Vulnerability Scanner - Full Version with NVD Feed, OpenAI Logging, and Dynamic Thread Tuning

import os
import io
import json
import sqlite3
import shutil
import subprocess
import time
import urllib.parse
import requests
import zipfile
import datetime
from concurrent.futures import ThreadPoolExecutor
from packaging.version import parse as parse_version
from dotenv import load_dotenv
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from openai import OpenAI
from threading import Lock
import multiprocessing

# Load env vars
load_dotenv(override=True)
BITBUCKET_WORKSPACE = os.getenv("BITBUCKET_WORKSPACE")
ATLASSIAN_USERNAME = os.getenv("ATLASSIAN_USERNAME")
ATLASSIAN_API_KEY = os.getenv("ATLASSIAN_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
NVD_API_KEY = os.getenv("NVD_API_KEY")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
SLACK_API_TOKEN = os.getenv("SLACK_API_TOKEN")
SLACK_CHANNEL_ID = os.getenv("SLACK_CHANNEL_ID")

client = OpenAI(api_key=OPENAI_API_KEY)

# Constants
REPOS_DIR = "repos"
SBOMS_DIR = "sboms"
DB_FILE = "repo_vuln.db"
OPENAI_LOG_FILE = "openai_logs.txt"
OUTPUT_AGGREGATED_FILE = "aggregated_vulnerabilities.json"
NVD_CVE_FEED_FOLDER = "nvdcve_feed"
NVD_CVE_MODIFIED_ZIP_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.zip"
NVD_CVE_RECENT_ZIP_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip"
NVD_CVE_MODIFIED_JSON = os.path.join(NVD_CVE_FEED_FOLDER, "nvdcve-1.1-modified.json")
NVD_CVE_RECENT_JSON = os.path.join(NVD_CVE_FEED_FOLDER, "nvdcve-1.1-recent.json")
NVD_REST_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
NVD_API_HEADERS = {"apiKey": NVD_API_KEY}
REQUEST_DELAY = 1
ONE_DAY_SECONDS = 86400
openai_cache = {}
openai_lock = Lock()

# Dynamic threading
CPU_COUNT = multiprocessing.cpu_count()
MAX_THREADS = min(2 * CPU_COUNT, 16)

print(f"[Thread Config] Detected {CPU_COUNT} CPU cores. Using {MAX_THREADS} threads for repository processing.")

# Slack Helpers

def send_slack_message(text):
    payload = {"text": text, "mrkdwn": True}
    try:
        requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10).raise_for_status()
    except requests.RequestException as e:
        print(f"Slack send error: {e}")


def send_slack_file(filepath, initial_comment=None):
    command = [
        "python", "file_upload.py",
        f'--token="{SLACK_API_TOKEN}"',
        f'--file="{filepath}"',
        f'--channels="{SLACK_CHANNEL_ID}"'
    ]
    try:
        subprocess.run(" ".join(command), shell=True, check=True)
        print("File uploaded to Slack successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error uploading file via command: {e}")

# DB Helpers

def connect_db():
    return sqlite3.connect(DB_FILE)

def init_db():
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS repositories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            clone_url TEXT,
            last_commit TEXT,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS grype_vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repository_name TEXT,
            vulnerability_id TEXT,
            actual_severity TEXT,
            predicted_severity TEXT,
            predicted_score REAL,
            detailed_description TEXT,
            vulnerable_package TEXT,
            mitigation TEXT,
            explanation TEXT,
            query_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(repository_name, vulnerability_id)
        )
    """)
    conn.commit()
    conn.close()

# Repo Helpers

def get_remote_head_commit(clone_url):
    try:
        res = subprocess.run(["git", "ls-remote", clone_url, "HEAD"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return res.stdout.strip().split()[0]
    except subprocess.CalledProcessError:
        return None

def clone_repository(repo_name, clone_url):
    repo_path = os.path.join(REPOS_DIR, repo_name)
    if os.path.exists(repo_path):
        shutil.rmtree(repo_path)
    subprocess.check_call(["git", "clone", clone_url, repo_path])
    return repo_path

def generate_sbom(repo_path, repo_name):
    sbom_path = os.path.join(SBOMS_DIR, f"{repo_name}.json")
    with open(sbom_path, "w") as f:
        subprocess.check_call(["syft", f"dir:{repo_path}", "-o", "cyclonedx-json"], stdout=f)
    return sbom_path

def run_grype(sbom_path):
    try:
        res = subprocess.run(f"cat {sbom_path} | grype --by-cve -o json", shell=True, capture_output=True, text=True, check=True)
        return json.loads(res.stdout)
    except subprocess.CalledProcessError:
        return None

# OpenAI Helpers

def strip_code_fences(text):
    lines = text.strip().splitlines()
    if lines and lines[0].strip().startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines).strip()

# Optimized Vulnerability Scanner - Full Version with NVD Feed, OpenAI Logging, Thread Tuning, and Robust JSON Parsing

# ... [Previous imports and setup] ...

# OpenAI Logging

def log_openai_interaction(prompt, response_text):
    try:
        with open(OPENAI_LOG_FILE, "a", encoding="utf-8") as f:
            f.write("\n------------------------\n")
            f.write(f"Timestamp: {datetime.datetime.utcnow().isoformat()}Z\n")
            f.write("Prompt:\n")
            f.write(prompt + "\n\n")
            f.write("Response:\n")
            f.write(response_text + "\n")
    except Exception as e:
        print(f"Logging error: {e}")

# Modified OpenAI helper with robust JSON parsing

def openai_detailed_assessment(vuln_id, vuln_info):
    with openai_lock:
        if vuln_id in openai_cache:
            return openai_cache[vuln_id]

    prompt = f"""
    Analyze the following vulnerability and provide a detailed assessment:
    Severity: {vuln_info.get('severity')}
    CVSS: {vuln_info.get('cvss')}
    Description: {vuln_info.get('description')}
    References: {vuln_info.get('references')}

    Return JSON with: detailed_description, vulnerable_package, mitigation, predicted_severity, predicted_score (0-10), explanation
    """
    try:
        resp = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300,
            temperature=0
        )
        raw_content = resp.choices[0].message.content.strip()
        log_openai_interaction(prompt, raw_content)
        content = strip_code_fences(raw_content)
        try:
            result = json.loads(content)
            # Ensure all keys are present
            for key in ["predicted_severity", "predicted_score", "detailed_description", "vulnerable_package", "mitigation", "explanation"]:
                result.setdefault(key, "")
        except Exception as e:
            log_openai_interaction(prompt, f"JSON parse error: {e}\nRaw: {raw_content}")
            result = {
                "predicted_severity": "Unknown",
                "predicted_score": 0,
                "detailed_description": "",
                "vulnerable_package": "",
                "mitigation": "",
                "explanation": f"OpenAI JSON parse error: {str(e)}"
            }
        with openai_lock:
            openai_cache[vuln_id] = result
        return result
    except Exception as e:
        error_response = f"Error from OpenAI: {str(e)}"
        log_openai_interaction(prompt, error_response)
        return {
            "predicted_severity": "Unknown",
            "predicted_score": 0,
            "detailed_description": "",
            "vulnerable_package": "",
            "mitigation": "",
            "explanation": error_response
        }

# Next: Parallel repo processing and full scan orchestration...
# Optimized Vulnerability Scanner - Continued

# ... [Previous sections above] ...

# Process a Single Repository

def process_single_repository(repo):
    repo_name = repo.get("name")
    clone_url = repo.get("clone_url")
    if not repo_name or not clone_url:
        return

    conn = connect_db()
    cur = conn.cursor()

    # Check latest commit
    remote_commit = get_remote_head_commit(clone_url)
    cur.execute("SELECT last_commit FROM repositories WHERE name = ?", (repo_name,))
    row = cur.fetchone()
    if row and row[0] == remote_commit:
        print(f"{repo_name}: No changes. Skipping.")
        conn.close()
        return

    try:
        repo_path = clone_repository(repo_name, clone_url)
        sbom_path = generate_sbom(repo_path, repo_name)
        grype_data = run_grype(sbom_path)
        if not grype_data:
            print(f"{repo_name}: No Grype data.")
            return

        for match in grype_data.get("matches", []):
            vuln_info = match.get("vulnerability", {})
            vuln_id = vuln_info.get("id")
            if not vuln_id:
                continue

            # Skip existing
            cur.execute("SELECT 1 FROM grype_vulnerabilities WHERE repository_name=? AND vulnerability_id=?", (repo_name, vuln_id))
            if cur.fetchone():
                continue

            enriched = openai_detailed_assessment(vuln_id, vuln_info)
            cur.execute("""
                INSERT INTO grype_vulnerabilities (
                    repository_name, vulnerability_id, actual_severity,
                    predicted_severity, predicted_score, detailed_description,
                    vulnerable_package, mitigation, explanation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                repo_name, vuln_id, vuln_info.get("severity"),
                enriched.get("predicted_severity"), enriched.get("predicted_score"),
                enriched.get("detailed_description"), enriched.get("vulnerable_package"),
                enriched.get("mitigation"), enriched.get("explanation")
            ))
            conn.commit()

        # Save latest commit
        cur.execute("REPLACE INTO repositories (name, clone_url, last_commit) VALUES (?, ?, ?)",
                    (repo_name, clone_url, remote_commit))
        conn.commit()

    except Exception as e:
        print(f"{repo_name}: Error - {e}")
    finally:
        conn.close()
        if os.path.exists(repo_path):
            shutil.rmtree(repo_path)

# Process All Repositories in Parallel

def fetch_all_repositories():
    url = f"https://api.bitbucket.org/2.0/repositories/{BITBUCKET_WORKSPACE}"
    all_repos = []
    while url:
        resp = requests.get(url, auth=(ATLASSIAN_USERNAME, ATLASSIAN_API_KEY))
        data = resp.json()
        all_repos.extend(data.get("values", []))
        url = data.get("next")
    return [{"name": r["name"], "clone_url": r["links"]["clone"][0]["href"]} for r in all_repos]

def process_repositories_parallel():
    repos = fetch_all_repositories()
    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(process_single_repository, repos)

# Aggregation

def aggregate_vulnerabilities():
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("SELECT repository_name, vulnerability_id, actual_severity, predicted_severity, predicted_score, detailed_description, vulnerable_package, mitigation, explanation FROM grype_vulnerabilities")
    rows = cur.fetchall()
    conn.close()

    results = [
        {
            "repository": r[0], "vulnerability_id": r[1], "actual_severity": r[2],
            "predicted_severity": r[3], "predicted_score": r[4],
            "detailed_description": r[5], "vulnerable_package": r[6],
            "mitigation": r[7], "explanation": r[8]
        } for r in rows
    ]

    with open(OUTPUT_AGGREGATED_FILE, "w") as f:
        json.dump(results, f, indent=2)

    return results

# NVD Feed Helpers

def download_and_extract(url, extract_folder):
    try:
        print(f"Downloading NVD feed from {url}...")
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        zip_data = io.BytesIO(response.content)
        os.makedirs(extract_folder, exist_ok=True)
        with zipfile.ZipFile(zip_data) as z:
            z.extractall(extract_folder)
        print(f"Extraction complete: {extract_folder}")
    except Exception as e:
        print(f"Failed to download NVD feed: {e}")


def refresh_feed_if_old(feed_file, feed_url):
    if os.path.exists(feed_file):
        mtime = os.path.getmtime(feed_file)
        if time.time() - mtime > ONE_DAY_SECONDS:
            download_and_extract(feed_url, os.path.dirname(feed_file))
    else:
        download_and_extract(feed_url, os.path.dirname(feed_file))


def load_json_file(file_path):
    with open(file_path, "r") as f:
        return json.load(f)


def query_nvd_rest_api(cve_id):
    url = f"{NVD_REST_API_BASE}{urllib.parse.quote(cve_id)}"
    try:
        r = requests.get(url, headers=NVD_API_HEADERS, timeout=30)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        print(f"NVD API error for {cve_id}: {e}")
        return None


def extract_nvd_vulns():
    refresh_feed_if_old(NVD_CVE_MODIFIED_JSON, NVD_CVE_MODIFIED_ZIP_URL)
    refresh_feed_if_old(NVD_CVE_RECENT_JSON, NVD_CVE_RECENT_ZIP_URL)
    modified = load_json_file(NVD_CVE_MODIFIED_JSON)
    recent = load_json_file(NVD_CVE_RECENT_JSON)
    return modified.get("CVE_Items", []) + recent.get("CVE_Items", [])


def parse_cpe_string(cpe_str):
    parts = cpe_str.split(":")
    if len(parts) >= 6:
        return parts[3], parts[4], parts[5]
    return None, None, None


def process_nvd_feeds():
    nvd_items = extract_nvd_vulns()
    conn = connect_db()
    cur = conn.cursor()

    cur.execute("SELECT DISTINCT repository_name FROM grype_vulnerabilities")
    repos = [r[0] for r in cur.fetchall()]

    new_entries = []
    for item in nvd_items:
        cve = item.get("cve", {})
        cve_id = cve.get("CVE_data_meta", {}).get("ID")
        if not cve_id:
            continue
        desc_list = cve.get("description", {}).get("description_data", [])
        desc = next((d['value'] for d in desc_list if d['lang'] == 'en'), '')

        for node in item.get("configurations", {}).get("nodes", []):
            for match in node.get("cpe_match", []):
                cpe = match.get("cpe23Uri")
                if not cpe:
                    continue
                vendor, product, version = parse_cpe_string(cpe)
                for repo in repos:
                    if repo.lower().find(product.lower()) != -1:
                        cur.execute("SELECT 1 FROM grype_vulnerabilities WHERE repository_name=? AND vulnerability_id=?", (repo, cve_id))
                        if cur.fetchone():
                            continue
                        enriched = openai_detailed_assessment(cve_id, {
                            "severity": "N/A", "cvss": "N/A", "description": desc, "references": []
                        })
                        cur.execute("""
                            INSERT INTO grype_vulnerabilities (
                                repository_name, vulnerability_id, actual_severity,
                                predicted_severity, predicted_score, detailed_description,
                                vulnerable_package, mitigation, explanation
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            repo, cve_id, "NVD", enriched.get("predicted_severity"),
                            enriched.get("predicted_score"), enriched.get("detailed_description"),
                            enriched.get("vulnerable_package"), enriched.get("mitigation"),
                            enriched.get("explanation")
                        ))
                        conn.commit()
                        new_entries.append((repo, cve_id))

        time.sleep(0.25)

    conn.close()
    return new_entries

# Master Workflow

def run_main():
    os.makedirs(REPOS_DIR, exist_ok=True)
    os.makedirs(SBOMS_DIR, exist_ok=True)
    os.makedirs(NVD_CVE_FEED_FOLDER, exist_ok=True)
    init_db()
    send_slack_message(":rocket: Vulnerability scan started.")
    process_repositories_parallel()

    nvd_matches = process_nvd_feeds()
    results = aggregate_vulnerabilities()

    if results:
        send_slack_file(OUTPUT_AGGREGATED_FILE, ":warning: Vulnerability report attached.")
    else:
        send_slack_message(":white_check_mark: No critical vulnerabilities found.")

    if nvd_matches:
        send_slack_message(f":mag: Added {len(nvd_matches)} new NVD vulnerabilities matched to repositories.")

# Entrypoint
if __name__ == "__main__":
    run_main()
