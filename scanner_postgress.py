# scanner.py — All-in-One Vulnerability Scanner (Part 1/??)
# Includes OpenAI, SBOM, Grype, CPE extraction, NVD Feed matching, SQLite, Slack, and logs

import os
import io
import json
import shutil
import subprocess
import time
import zipfile
import datetime
import urllib.parse
import multiprocessing
from threading import Lock
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
import threading

import requests
from dotenv import load_dotenv
from packaging.version import parse as parse_version
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from openai import OpenAI
from jinja2 import Environment, FileSystemLoader

from sqlalchemy.exc import OperationalError, IntegrityError
from sqlalchemy.dialects.postgresql import insert as pg_insert
from db import SessionLocal, engine
from models import Base, Repository, GrypeVulnerability, NvdVulnerability, RepositoryCpe

import logging


# Load environment variables
load_dotenv(override=True)
BITBUCKET_WORKSPACE = os.getenv("BITBUCKET_WORKSPACE")
ATLASSIAN_USERNAME = os.getenv("ATLASSIAN_USERNAME")
ATLASSIAN_API_KEY = os.getenv("ATLASSIAN_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
NVD_API_KEY = os.getenv("NVD_API_KEY")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
SLACK_API_TOKEN = os.getenv("SLACK_API_TOKEN")
SLACK_CHANNEL_ID = os.getenv("SLACK_CHANNEL_ID")
JIRA_ORG = os.getenv("JIRA_ORG")
JIRA_USERNAME = os.getenv("JIRA_USERNAME")
JIRA_API_KEY = os.getenv("JIRA_API_KEY")
# Constants
REPOS_DIR = "repos"
SBOMS_DIR = "sboms"
SLACK_RETRY_QUEUE_FILE = "slack_retry_queue.json"
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

# Threading and concurrency
CPU_COUNT = multiprocessing.cpu_count()
MAX_THREADS = min(2 * CPU_COUNT, 16)
print(f"[Thread Config] Detected {CPU_COUNT} cores — using {MAX_THREADS} threads.")

# Shared state
client = OpenAI(api_key=OPENAI_API_KEY)
openai_cache = {}
openai_lock = Lock()



logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("scanner.log"),
        logging.StreamHandler()
    ]
)


slack_queue_lock = threading.Lock()

def queue_failed_slack_message(payload):
    try:
        with slack_queue_lock:
            queue = []
            if os.path.exists(SLACK_RETRY_QUEUE_FILE):
                with open(SLACK_RETRY_QUEUE_FILE, "r") as f:
                    try:
                        queue = json.load(f)
                    except json.JSONDecodeError:
                        logging.warning("[Slack Queue] Malformed JSON, resetting queue.")
                        queue = []

            queue.append(payload)
            with open(SLACK_RETRY_QUEUE_FILE, "w") as f:
                json.dump(queue, f, indent=2)
        logging.info("[Slack Queue] Message queued for retry.")
    except Exception as e:
        logging.error(f"[Slack Queue Error] {e}")


def send_slack_rescan_button(repo_name, clone_url):
    payload = {
        "channel": SLACK_CHANNEL_ID,
        "blocks": [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"🔁 *Rescan {repo_name}?*"}
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Rescan Repo"},
                        "value": f"{repo_name}|{clone_url}",
                        "action_id": "rescan_repo"
                    }
                ]
            }
        ],
        "text": f"Rescan requested for {repo_name}"
    }

    try:
        client = WebClient(token=SLACK_API_TOKEN)
        client.chat_postMessage(**payload)
        logging.info(f"[Slack] Rescan button sent for {repo_name}")
    except SlackApiError as e:
        logging.error(f"[Slack Error] Rescan button failed: {e.response['error']}")
        queue_failed_slack_message(payload)
    except Exception as e:
        logging.error(f"[Slack Error] Unexpected error sending rescan button: {e}")
        queue_failed_slack_message(payload)


def send_jira_button(repo_name, vuln_id, severity):
    payload = {
        "channel": SLACK_CHANNEL_ID,
        "blocks": [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Jira ticket for `{vuln_id}` in `{repo_name}`?*"}
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Create Jira Ticket"},
                        "value": f"{repo_name}|{vuln_id}|{severity}",
                        "action_id": "create_jira_ticket"
                    }
                ]
            }
        ],
        "text": f"Jira ticket option for {vuln_id}"
    }

    try:
        client = WebClient(token=SLACK_API_TOKEN)
        client.chat_postMessage(**payload)
        logging.info(f"[Slack] Jira button sent for {repo_name}/{vuln_id}")
    except SlackApiError as e:
        logging.error(f"[Slack Error] Jira button failed: {e.response['error']}")
        queue_failed_slack_message(payload)
    except Exception as e:
        logging.error(f"[Slack Error] Unexpected error sending Jira button: {e}")
        queue_failed_slack_message(payload)



# Slack Notification Functions

def send_slack_message(text):
    payload = {"text": text, "mrkdwn": True}
    try:
        resp = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"Slack send error: {e}")
        queue_failed_slack_message(payload)


def retry_failed_slack_posts():
    if not os.path.exists(SLACK_RETRY_QUEUE_FILE):
        return

    try:
        with open(SLACK_RETRY_QUEUE_FILE, "r") as f:
            queue = json.load(f)
    except json.JSONDecodeError:
        print("[Retry] Could not parse retry queue.")
        return

    successful = []
    for payload in queue:
        try:
            resp = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
            if resp.status_code == 200:
                successful.append(payload)
        except Exception as e:
            print(f"[Retry] Failed again: {e}")

    # Write back remaining failed messages
    if len(successful) < len(queue):
        remaining = [p for p in queue if p not in successful]
        with open(SLACK_RETRY_QUEUE_FILE, "w") as f:
            json.dump(remaining, f, indent=2)
    else:
        os.remove(SLACK_RETRY_QUEUE_FILE)


def send_slack_file(filepath, initial_comment=None):
    command = [
        "python3.9", "file_upload.py",
        f'--token="{SLACK_API_TOKEN}"',
        f'--file="{filepath}"',
        f'--channels="{SLACK_CHANNEL_ID}"'
    ]
    try:
        subprocess.run(" ".join(command), shell=True, check=True)
        print("File uploaded to Slack successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error uploading file via command: {e}")

# Ready for Part 2? DB setup, logging helpers, and OpenAI logging/JSON parsing.
# scanner.py — All-in-One Vulnerability Scanner (Part 2/??)
# Adds DB setup, OpenAI logging/parsing, and multiprocessing-ready NVD CVE match support

# postgres DB Initialization

def connect_db():
    return SessionLocal()


def init_db():
    Base.metadata.drop_all(bind=engine)  # optional: resets all tables
    Base.metadata.create_all(bind=engine)


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

# OpenAI JSON Parsing

def strip_code_fences(text):
    lines = text.strip().splitlines()
    if lines and lines[0].strip().startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines).strip()

def openai_validate_false_positive(cve_id, description, package_name, repo_version):
    prompt = f"""
    Based on the following:
    - Vulnerability: {cve_id}
    - Description: {description}
    - Package affected: {package_name}
    - Repository version used: {repo_version}

    Does the vulnerability apply to this version? Reply with:
    {{ "false_positive": true|false, "explanation": "..." }}
    """
    try:
        resp = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=150,
            temperature=0
        )
        raw = resp.choices[0].message.content.strip()
        log_openai_interaction(prompt, raw)
        parsed = json.loads(strip_code_fences(raw))
        return parsed.get("false_positive", False), parsed.get("explanation", "")
    except Exception as e:
        print(f"OpenAI FP error for {cve_id}: {e}")
        return False, "(Validation failed)"



# scanner.py — Enhanced with EPSS Score Integration (Shodan)

# ... [previous parts retained] ...

# EPSS Score via Shodan API

def query_epss_score(cve_id):
    try:
        url = f"https://cvedb.shodan.io/cve/{cve_id}"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            epss_data = data.get("epss")
            if isinstance(epss_data, dict):
                return epss_data.get("score", 0.0), epss_data.get("percentile", 0.0)
            else:
                print(f"[EPSS Fallback] {cve_id} returned EPS as float: {epss_data}")
    except Exception as e:
        print(f"EPSS fetch error for {cve_id}: {e}")
    return 0.0, 0.0


# Updated OpenAI Enrichment

def openai_detailed_assessment(vuln_id, vuln_info):
    with openai_lock:
        if vuln_id in openai_cache:
            return openai_cache[vuln_id]

    epss_score, epss_pct = query_epss_score(vuln_id)

    prompt = f"""
    Analyze the following vulnerability and provide a detailed assessment:
    Severity: {vuln_info.get('severity')}
    CVSS: {vuln_info.get('cvss')}
    EPSS Score: {epss_score} (percentile: {epss_pct})
    Description: {vuln_info.get('description')}
    References: {vuln_info.get('references')}

    Return JSON with: detailed_description, vulnerable_package, mitigation, predicted_severity, predicted_score (0-10), explanation and based on the prdected_score check the predicted_severity.
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

        result["epss_score"] = epss_score
        result["epss_percentile"] = epss_pct
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
            "explanation": error_response,
            "epss_score": 0.0,
            "epss_percentile": 0.0
        }

# Continue with: Adding epss_score and epss_percentile to DB inserts and aggregations


# Part 3: Next includes cloning, SBOM, Grype, config parsing, saving CPEs, and NVD feed parsing with multiprocessing
# Ready to continue?
# scanner.py — All-in-One Vulnerability Scanner (Part 3/??)
# Adds: Repo cloning, SBOM, Grype, Config File CPE Extraction, CPE DB Save, and NVD Feed Multiprocessing

# Git Helpers

def get_remote_head_commit(clone_url):
    try:
        res = subprocess.run(["git", "ls-remote", clone_url, "HEAD"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
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

# Config File Parsing for CPEs

def read_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        print(f"Read error: {e}")
        return ""

def chunk_text(text, max_len=2000):
    return [text[i:i+max_len] for i in range(0, len(text), max_len)]

def call_openai_cpe(chunk):
    prompt = f"""
    Identify only valid software dependencies it should be a vilid software only in the following config snippet:
    {chunk}
    Return a JSON array with objects having keys: vendor, product, version.
    """
    try:
        resp = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200,
            temperature=0
        )
        raw_content = resp.choices[0].message.content.strip()
        log_openai_interaction(prompt, raw_content)
        content = strip_code_fences(raw_content)
        return json.loads(content) if content.startswith("[") else []
    except Exception as e:
        log_openai_interaction(prompt, f"Error: {e}")
        return []

def extract_cpes_from_repo(repo_path):
    config_exts = (".yml", ".yaml", ".ini", ".cfg")
    all_results = []
    for root, _, files in os.walk(repo_path):
        for fname in files:
            if fname.lower().endswith(config_exts):
                fpath = os.path.join(root, fname)
                content = read_file(fpath)
                for chunk in chunk_text(content):
                    result = call_openai_cpe(chunk)
                    all_results.extend(result)
                    time.sleep(0.25)
    return all_results

# Save Extracted CPEs to DB


def save_repository_cpes(repo_name, cpe_list):
    session = connect_db()
    try:
        repo = session.query(Repository).filter_by(name=repo_name).first()
        if not repo:
            return

        for entry in cpe_list:
            vendor = entry.get("vendor")
            product = entry.get("product")
            version = entry.get("version")
            if vendor and product and version:
                cpe_str = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

                stmt = pg_insert(RepositoryCpe).values(
                    repository_id=repo.id,
                    cpe=cpe_str,
                    vendor=vendor,
                    product=product,
                    version=version
                ).on_conflict_do_nothing(
                    index_elements=["repository_id", "cpe"]
                )

                session.execute(stmt)

        session.commit()

    except Exception as e:
        session.rollback()
        print(f"[DB] Error while saving CPEs for {repo_name}: {e}")
    finally:
        session.close()

# Next: Parallel repo processing, vulnerability insert, NVD feed parsing (with multiprocessing)
# Ready to continue?
# scanner.py — All-in-One Vulnerability Scanner (Part 4/??)
# Adds: Parallel repo processing, Grype vuln insert, NVD feed parsing with multiprocessing

# Parallel repository processing

def fetch_all_repositories():
    url = f"https://api.bitbucket.org/2.0/repositories/{BITBUCKET_WORKSPACE}"
    all_repos = []
    while url:
        resp = requests.get(url, auth=(ATLASSIAN_USERNAME, ATLASSIAN_API_KEY))
        print(f"[Fetch] GET {url} -> {resp.status_code}")
        if resp.status_code != 200:
            break
        data = resp.json()
        all_repos.extend(data.get("values", []))
        url = data.get("next")
    
    print(f"[Fetch] Total repositories fetched: {len(all_repos)}")

    repositories = []
    for r in all_repos:
        name = r.get("name")
        ssh_link = next((link["href"] for link in r.get("links", {}).get("clone", []) if link["name"] == "ssh"), None)
        if name and ssh_link:
            repositories.append({"name": name, "clone_url": ssh_link})
        else:
            print(f"[Skip] Repository {name} missing SSH clone URL")

    return repositories

def process_single_repository(repo, rescan_mode=False):
    repo_name = repo.get("name")
    clone_url = repo.get("clone_url")
    if not repo_name or not clone_url:
        return

    session = connect_db()  # SQLAlchemy session
    remote_commit = get_remote_head_commit(clone_url)
    repo_path = None

    repo_obj = session.query(Repository).filter_by(name=repo_name).first()
    if repo_obj and repo_obj.last_commit == remote_commit and not rescan_mode:
        session.close()
        return

    try:
        repo_path = clone_repository(repo_name, clone_url)
        sbom_path = generate_sbom(repo_path, repo_name)
        grype_data = run_grype(sbom_path)

        # Insert or update repository
        if not repo_obj:
            repo_obj = Repository(name=repo_name, clone_url=clone_url, last_commit=remote_commit)
            session.add(repo_obj)
        else:
            repo_obj.clone_url = clone_url
            repo_obj.last_commit = remote_commit

        session.commit()

        # Extract config CPEs and save
        cpes = extract_cpes_from_repo(repo_path)
        save_repository_cpes(repo_name, cpes)

        if grype_data:
            for match in grype_data.get("matches", []):
                vuln_info = match.get("vulnerability", {})
                vuln_id = vuln_info.get("id")
                if not vuln_id:
                    continue

                enriched = openai_detailed_assessment(vuln_id, vuln_info)
                db_ver = match.get("artifact", {}).get("version", "") or "unknown"
                false_positive, fp_explanation = openai_validate_false_positive(
                    vuln_id,
                    enriched.get("detailed_description", ""),
                    enriched.get("vulnerable_package", ""),
                    db_ver
                )

                # ✅ Conflict-safe insert with PostgreSQL dialect
                stmt = pg_insert(GrypeVulnerability).values(
                    repository_name=repo_name,
                    vulnerability_id=vuln_id,
                    actual_severity=vuln_info.get("severity"),
                    predicted_severity=enriched.get("predicted_severity"),
                    predicted_score=enriched.get("predicted_score"),
                    epss_score=enriched.get("epss_score"),
                    epss_percentile=enriched.get("epss_percentile"),
                    detailed_description=enriched.get("detailed_description"),
                    vulnerable_package=enriched.get("vulnerable_package"),
                    mitigation=enriched.get("mitigation"),
                    explanation=enriched.get("explanation"),
                    false_positive=false_positive,
                    notified=False
                ).on_conflict_do_nothing(
                    index_elements=["repository_name", "vulnerability_id"]
                )

                session.execute(stmt)

                if rescan_mode and enriched.get("predicted_score", 0) >= 9 and not false_positive:
                    clone_url = clone_url or lookup_clone_url(repo_name)
                    send_combined_alert(
                        repo_name,
                        vuln_id,
                        enriched.get("predicted_severity"),
                        enriched.get("predicted_score"),
                        clone_url,
                        enriched.get("vulnerable_package"),
                        enriched.get("detailed_description"),
                        enriched.get("mitigation")
                    )

        session.commit()

    except Exception as e:
        print(f"Repo {repo_name} error: {e}")
        session.rollback()
    finally:
        session.close()
        if os.path.exists(repo_path):
            shutil.rmtree(repo_path)




# scanner.py — Intelligent Workload Sharding: Repo Subprocess Execution


def process_repositories_parallel():
    repos = fetch_all_repositories()
    os.makedirs("logs", exist_ok=True)

    active_procs = []
    for repo in repos:
        name = repo.get("name")
        url = repo.get("clone_url")
        if not name or not url:
            continue

        log_file = open(f"logs/{name}.log", "w")
        cmd = [
            "python3.9", "scan_repo_worker.py",
            "--repo-name", name,
            "--clone-url", url
        ]
        print(f"[Spawner] Launching scan for {name}")
        proc = subprocess.Popen(cmd, stdout=log_file, stderr=subprocess.STDOUT)
        active_procs.append((proc, log_file))

        while len(active_procs) >= CPU_COUNT:
            for p, lf in active_procs:
                if p.poll() is not None:
                    lf.close()
                    active_procs.remove((p, lf))
                    break
            time.sleep(0.5)

    for p, lf in active_procs:
        p.wait()
        lf.close()

    print("[Sharding] All repo scans completed.")


# NVD Feed Parsing - Multiprocessing

def load_json_file(file_path):
    with open(file_path, "r") as f:
        return json.load(f)

def parse_cpe_string(cpe_str):
    parts = cpe_str.split(":")
    if len(parts) >= 6:
        return parts[3], parts[4], parts[5]
    return None, None, None

def process_single_cve(args):
    item, cpe_records = args
    cve = item.get("cve", {})
    cve_id = cve.get("CVE_data_meta", {}).get("ID")
    if not cve_id:
        return None

    # Extract description safely
    desc_list = cve.get("description", {}).get("description_data", [])
    desc = next((d.get('value', '') for d in desc_list if d.get('lang') == 'en'), '')

    # Extract CVSS and Severity
    impact = item.get("impact", {}).get("baseMetricV3", {})
    cvss_data = impact.get("cvssV3", {})
    severity = cvss_data.get("baseSeverity", "")
    cvss = cvss_data.get("baseScore")

    # Estimate EPSS from Shodan
    epss_score, epss_pct = query_epss_score(cve_id)

    # Decision: REST enrichment only if severity is HIGH/CRITICAL or EPSS > 0.7
    if severity not in ["HIGH", "CRITICAL"] and epss_score <= 0.7:
        enriched = {
            "predicted_severity": severity,
            "predicted_score": cvss or 0,
            "detailed_description": desc,
            "vulnerable_package": "",
            "mitigation": "",
            "explanation": "Skipped REST API due to low severity and EPSS",
            "epss_score": epss_score,
            "epss_percentile": epss_pct
        }
    else:
        print(f"[Enrich] Querying REST API for {cve_id} (Severity: {severity}, EPSS: {epss_score})")
        api_data = query_nvd_rest_api(cve_id)
        if api_data:
            desc = next(
                (d.get("value", desc) for d in api_data.get("descriptions", []) if d.get("lang") == "en"),
                desc
            )
            cvss = api_data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore") or cvss

        enriched = openai_detailed_assessment(cve_id, {
            "severity": severity,
            "cvss": cvss or "",
            "description": desc,
            "references": []
        })

    # False positive check
    false_positive, _ = openai_validate_false_positive(
        cve_id,
        enriched.get("detailed_description", ""),
        enriched.get("vulnerable_package", ""),
        "unknown"
    )

    # Match to known repo CPEs
    for node in item.get("configurations", {}).get("nodes", []):
        for match in node.get("cpe_match", []):
            cpe = match.get("cpe23Uri")
            if not cpe:
                continue
            v, p, ver = parse_cpe_string(cpe)
            for repo_id, repo_name, db_v, db_p, db_ver in cpe_records:
                if db_p and p and db_p.lower() in p.lower():
                    return (repo_name, cve_id, enriched, false_positive)

    return None


def process_nvd_feeds():
    print("Downloading and processing NVD feeds...")
    for url in [NVD_CVE_MODIFIED_ZIP_URL, NVD_CVE_RECENT_ZIP_URL]:
        try:
            response = requests.get(url, timeout=60)
            response.raise_for_status()
            zip_data = io.BytesIO(response.content)
            with zipfile.ZipFile(zip_data) as z:
                z.extractall(NVD_CVE_FEED_FOLDER)
        except Exception as e:
            print(f"Feed download error: {e}")

    items = load_json_file(NVD_CVE_MODIFIED_JSON).get("CVE_Items", []) + \
            load_json_file(NVD_CVE_RECENT_JSON).get("CVE_Items", [])

    # Fetch CPEs
    with SessionLocal() as session:
        cpe_records = session.query(
            RepositoryCpe.repository_id,
            Repository.name,
            RepositoryCpe.vendor,
            RepositoryCpe.product,
            RepositoryCpe.version
        ).join(Repository, RepositoryCpe.repository_id == Repository.id).all()

    # Parallel CVE enrichment
    with multiprocessing.Pool(processes=CPU_COUNT) as pool:
        results = pool.map(process_single_cve, [(item, cpe_records) for item in items])

    # Insert results into DB
    from sqlalchemy.dialects.postgresql import insert

# Insert results into DB
    with SessionLocal() as session:
        for result in results:
            if not result:
                continue
            repo_name, cve_id, enriched, false_positive = result

            stmt = insert(NvdVulnerability).values(
                repository_name=repo_name,
                vulnerability_id=cve_id,
                actual_severity="NVD",
                predicted_severity=enriched.get("predicted_severity"),
                predicted_score=enriched.get("predicted_score"),
                epss_score=enriched.get("epss_score"),
                epss_percentile=enriched.get("epss_percentile"),
                detailed_description=enriched.get("detailed_description"),
                vulnerable_package=enriched.get("vulnerable_package"),
                mitigation=enriched.get("mitigation"),
                explanation=enriched.get("explanation"),
                false_positive=false_positive,
                notified=False,
                query_date=datetime.datetime.utcnow()
            )

            # On conflict, update relevant fields
            do_update_stmt = stmt.on_conflict_do_update(
                index_elements=["repository_name", "vulnerability_id"],
                set_={
                    "predicted_severity": stmt.excluded.predicted_severity,
                    "predicted_score": stmt.excluded.predicted_score,
                    "epss_score": stmt.excluded.epss_score,
                    "epss_percentile": stmt.excluded.epss_percentile,
                    "detailed_description": stmt.excluded.detailed_description,
                    "vulnerable_package": stmt.excluded.vulnerable_package,
                    "mitigation": stmt.excluded.mitigation,
                    "explanation": stmt.excluded.explanation,
                    "false_positive": stmt.excluded.false_positive,
                    "notified": stmt.excluded.notified,
                    "query_date": stmt.excluded.query_date
                }
            )

            session.execute(do_update_stmt)
        session.commit()


    print("✅ NVD feed processing complete.")

    
# Shared tracker across calls
nvd_last_reset = time.time()
nvd_request_count = 0
NVD_MAX_REQUESTS = 45
NVD_WINDOW_SECONDS = 30

def query_nvd_rest_api(cve_id, max_retries=3, delay=2):
    global nvd_request_count, nvd_last_reset

    url = f"{NVD_REST_API_BASE}{urllib.parse.quote(cve_id)}"
    headers = {
        "ApiKey": NVD_API_KEY,
        "User-Agent": "danxzero_scanner/1.0"
    }

    for attempt in range(1, max_retries + 1):
        # Handle fixed rate limiting
        now = time.time()
        if now - nvd_last_reset > NVD_WINDOW_SECONDS:
            nvd_request_count = 0
            nvd_last_reset = now

        if nvd_request_count >= NVD_MAX_REQUESTS:
            sleep_time = NVD_WINDOW_SECONDS - (now - nvd_last_reset)
            print(f"[RATE LIMIT] Hit {NVD_MAX_REQUESTS} reqs. Sleeping {int(sleep_time)}s...")
            time.sleep(sleep_time)
            nvd_request_count = 0
            nvd_last_reset = time.time()

        try:
            print(f"[DEBUG] Attempt {attempt} for {cve_id}")
            print(f"[DEBUG] URL: {url}")
            print(f"[DEBUG] Headers: {headers}")

            resp = requests.get(url, headers=headers, timeout=15)
            nvd_request_count += 1

            print(f"[DEBUG] Status = {resp.status_code}")

            if resp.status_code == 403:
                print(f"[DEBUG] 403 Forbidden — API key may be rate-limited.")
                time.sleep(delay * attempt)
                continue

            resp.raise_for_status()
            results = resp.json().get("vulnerabilities", [])
            if results and isinstance(results[0], dict):
                return results[0].get("cve")

        except Exception as e:
            print(f"[NVD ERROR] {cve_id} — {e}")
            time.sleep(delay)

    print(f"[FAIL] Gave up after {max_retries} attempts for {cve_id}")
    return None

# Continue with: Aggregation, Slack report, and run_main entrypoint
# scanner.py — All-in-One Vulnerability Scanner (Final Part)
# Adds: Vulnerability aggregation, Slack upload, critical alert, and main entrypoint

MAX_RETRIES = 5
RETRY_DELAY = 2  # seconds
FAILED_LOG = "failed_slack_retries.log"

def send_combined_alert(repo, cve_id, severity, score, clone_url, pkg=None, explanation=None, mitigation=None, thread_ts=None):
    from slack_sdk.errors import SlackApiError
    from slack_sdk import WebClient
    import time

    client = WebClient(token=SLACK_API_TOKEN)

    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*CVE:* `{cve_id}` — *{severity}* (Score: {score})\n"
                    f"📦 *Package:* `{pkg or 'unknown'}`\n"
                    f"🔍 *Details:* {explanation or '_No explanation available_'}\n"
                    f"🛡️ *Mitigation:* {mitigation or '_None provided_'}"
                )
            }
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Create Jira Ticket"},
                    "value": f"{repo}|{cve_id}|{severity}",
                    "action_id": "create_jira_ticket"
                }
            ]
        }
    ]

    retry = 0
    while retry < 5:
        try:
            response = client.chat_postMessage(
                channel=SLACK_CHANNEL_ID,
                text=f"{severity} vulnerability in {repo}: {cve_id}",
                blocks=blocks,
                thread_ts=thread_ts
            )
            return response
        except SlackApiError as e:
            print(f"[Slack Retry {retry+1}] Failed to post message: {e.response['error']}")
            retry += 1
            time.sleep(2 * retry)
        except Exception as ex:
            print(f"[Slack Retry {retry+1}] General error: {ex}")
            retry += 1
            time.sleep(2 * retry)

    # Fallback: store failed message locally
    failed_dir = "failed_slack_msgs"
    os.makedirs(failed_dir, exist_ok=True)
    fallback_path = os.path.join(failed_dir, f"{repo}_{cve_id}.json")
    with open(fallback_path, "w") as f:
        json.dump({"repo": repo, "cve_id": cve_id, "severity": severity, "score": score, "pkg": pkg, "explanation": explanation, "mitigation": mitigation}, f, indent=2)
    print(f"[Slack Fallback] Message saved to {fallback_path}")

# Aggregate vulnerabilities

def aggregate_vulnerabilities():
    session = connect_db()
    rows = session.query(GrypeVulnerability).all()
    results = [
        {
            "repository": r.repository_name,
            "vulnerability_id": r.vulnerability_id,
            "actual_severity": r.actual_severity,
            "predicted_severity": r.predicted_severity,
            "predicted_score": r.predicted_score,
            "epss_score": r.epss_score,
            "epss_percentile": r.epss_percentile,
            "detailed_description": r.detailed_description,
            "vulnerable_package": r.vulnerable_package,
            "mitigation": r.mitigation,
            "explanation": r.explanation,
            "false_positive": r.false_positive
        } for r in rows
    ]
    with open(OUTPUT_AGGREGATED_FILE, "w") as f:
        json.dump(results, f, indent=2)

    return results

# scanner.py — (Commented) Jira Ticket Creation Stub

def create_jira_ticket(repo, vuln_id, severity):
    import json
    from datetime import datetime

    # Use SQLAlchemy session
    session = connect_db()
    row = session.query(
        GrypeVulnerability.detailed_description,
        GrypeVulnerability.vulnerable_package,
        GrypeVulnerability.mitigation,
        GrypeVulnerability.explanation,
        GrypeVulnerability.predicted_score
    ).filter_by(repository_name=repo, vulnerability_id=vuln_id).first()
    session.close()

    if not row:
        return {
            "text": f"❌ Could not find details for {vuln_id} in {repo}."
        }

    description, pkg, mitigation, explanation, score = row

    summary = f"{severity} vulnerability in {repo}: {vuln_id}"
    priority = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low"
    }.get(severity.upper(), "Medium")

    jira_description_adf = {
        "version": 1,
        "type": "doc",
        "content": [
            {"type": "paragraph", "content": [
                {"type": "text", "text": "📁 "},
                {"type": "text", "text": "Repository: ", "marks": [{"type": "strong"}]},
                {"type": "text", "text": repo}
            ]},
            {"type": "paragraph", "content": [
                {"type": "text", "text": "🆔 "},
                {"type": "text", "text": "CVE: ", "marks": [{"type": "strong"}]},
                {"type": "text", "text": vuln_id}
            ]},
            {"type": "paragraph", "content": [
                {"type": "text", "text": "⚠️ "},
                {"type": "text", "text": "Severity: ", "marks": [{"type": "strong"}]},
                {"type": "text", "text": severity}
            ]},
            {"type": "paragraph", "content": [
                {"type": "text", "text": "📊 "},
                {"type": "text", "text": "Score: ", "marks": [{"type": "strong"}]},
                {"type": "text", "text": str(score)}
            ]},
            {"type": "paragraph", "content": [
                {"type": "text", "text": "📦 "},
                {"type": "text", "text": "Affected Package: ", "marks": [{"type": "strong"}]},
                {"type": "text", "text": pkg}
            ]},
            {"type": "heading", "attrs": {"level": 3}, "content": [
                {"type": "text", "text": "📝 Description"}
            ]},
            {"type": "paragraph", "content": [
                {"type": "text", "text": description}
            ]},
            {"type": "heading", "attrs": {"level": 3}, "content": [
                {"type": "text", "text": "🛡️ Mitigation"}
            ]},
            {"type": "paragraph", "content": [
                {"type": "text", "text": mitigation}
            ]},
            {"type": "heading", "attrs": {"level": 3}, "content": [
                {"type": "text", "text": "🔎 Explanation"}
            ]},
            {"type": "paragraph", "content": [
                {"type": "text", "text": explanation}
            ]}
        ]
    }

    url = f"https://{JIRA_ORG}.atlassian.net/rest/api/3/issue"
    auth = (JIRA_USERNAME, JIRA_API_KEY)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    payload = {
        "fields": {
            "project": {"key": "SECURITY"},
            "summary": summary,
            "description": jira_description_adf,
            "issuetype": {"name": "Bug"},
            "priority": {"name": priority},
            "labels": ["automation_scripts", "sastsec_bug", "security_alert", "security_bug"]
        }
    }

    try:
        print("[Jira Debug] Payload:")
        print(json.dumps(payload, indent=2))

        response = requests.post(url, auth=auth, headers=headers, json=payload)
        response.raise_for_status()
        issue_key = response.json()["key"]
        issue_url = f"https://{JIRA_ORG}.atlassian.net/browse/{issue_key}"

        return {
            "issue_url": issue_url,
            "issue_key": issue_key,
            "response_type": "in_channel",
            "text": f"🎟️ Jira ticket created: <{issue_url}|{issue_key}>",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"🎟️ *Jira ticket created:* <{issue_url}|{issue_key}>\n"
                            f"*Repo:* `{repo}`\n"
                            f"*CVE:* `{vuln_id}`\n"
                            f"*Severity:* *{severity}*\n"
                            f"*Score:* {score}"
                        )
                    }
                }
            ]
        }

    except requests.exceptions.HTTPError as e:
        print(f"[Jira Error] {e}")
        print(f"[Jira Response] {e.response.text}")
        return {
            "text": f"❌ Jira ticket creation failed for `{vuln_id}` — {str(e)}"
        }


# Send critical vulnerability alerts to Slack

def lookup_clone_url(repo_name):
    session = connect_db()
    try:
        repo = session.query(Repository).filter_by(name=repo_name).first()
        return repo.clone_url if repo else "unknown"
    finally:
        session.close()

def send_critical_vuln_alerts(vulns):

    session = connect_db()

    criticals = session.query(GrypeVulnerability).filter(
        GrypeVulnerability.predicted_score >= 7,
        GrypeVulnerability.false_positive == False,
        GrypeVulnerability.notified == False
    ).all()

    if not criticals:
        send_slack_message(":white_check_mark: No new high/critical vulnerabilities found.")
        session.close()
        return

    # Group by repo
    repo_map = defaultdict(list)
    for v in criticals:
        repo_map[v.repository_name].append(v)

    client = WebClient(token=SLACK_API_TOKEN)

    for repo, vulns in repo_map.items():
        crit = sum(1 for v in vulns if v.predicted_score >= 9)
        high = sum(1 for v in vulns if 7 <= v.predicted_score < 9)

        summary_text = (
            f"🔐 *Scan Summary for `{repo}`*\n"
            f":rotating_light:  *{crit} Critical* | ⚠️ *{high} High* \n"
            f"🧵 Vulnerability details in thread."
        )

        try:
            summary_response = client.chat_postMessage(
                channel=SLACK_CHANNEL_ID,
                text=summary_text
            )
            thread_ts = summary_response["ts"]
        except SlackApiError as e:
            print(f"[Slack Summary Error] {e}")
            # Persist the summary failure to retry later
            os.makedirs("failed_slack_msgs", exist_ok=True)
            with open(f"failed_slack_msgs/summary_{repo}.json", "w") as f:
                json.dump({"repo": repo, "text": summary_text}, f)
            continue

        for vuln in vulns:
            for attempt in range(5):
                try:
                    ts = send_combined_alert(
                        repo,
                        vuln.vulnerability_id,
                        vuln.predicted_severity,
                        vuln.predicted_score,
                        lookup_clone_url(repo),
                        vuln.vulnerable_package,
                        vuln.detailed_description,
                        vuln.mitigation,
                        thread_ts=thread_ts
                    )
                    if ts:
                        vuln.notified = True
                    break
                except SlackApiError as e:
                    print(f"[Retry {attempt+1}] Slack post failed: {e}")
                    time.sleep(2 * (attempt + 1))
                    if attempt == 4:
                        os.makedirs("failed_slack_msgs", exist_ok=True)
                        path = f"failed_slack_msgs/{repo}_{vuln.vulnerability_id}.json"
                        with open(path, "w") as f:
                            json.dump({
                                "repo": repo,
                                "vuln_id": vuln.vulnerability_id,
                                "severity": vuln.predicted_severity,
                                "score": vuln.predicted_score,
                                "clone_url": lookup_clone_url(repo),
                                "package": vuln.vulnerable_package,
                                "explanation": vuln.detailed_description,
                                "mitigation": vuln.mitigation,
                                "thread_ts": thread_ts
                            }, f)

    session.commit()
    session.close()

    # ✅ Retry any failed Slack messages
    retry_failed_slack_posts()



# Final Entry Point

def run_main():
    os.makedirs(REPOS_DIR, exist_ok=True)
    os.makedirs(SBOMS_DIR, exist_ok=True)
    os.makedirs(NVD_CVE_FEED_FOLDER, exist_ok=True)

    init_db()  # ORM-based initialization
    send_slack_message(":rocket: Vulnerability scan started.")

    process_repositories_parallel()
    process_nvd_feeds()

    vulnerabilities = aggregate_vulnerabilities()
    if vulnerabilities:
        send_critical_vuln_alerts(vulnerabilities)
        send_slack_file(OUTPUT_AGGREGATED_FILE, ":warning: Vulnerability report attached")
    else:
        send_slack_message(":white_check_mark: No high-severity vulnerabilities found.")



## Main Runner
if __name__ == "__main__":
    run_main()