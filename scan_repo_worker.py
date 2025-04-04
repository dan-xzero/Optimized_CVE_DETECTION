# scan_repo_worker.py — Isolated Repo Scanner Worker
import os
import sys
import argparse
from dotenv import load_dotenv
from scanner_postgress import process_single_repository, aggregate_vulnerabilities, send_slack_message


# Argument Parsing
parser = argparse.ArgumentParser()
parser.add_argument("--repo-name", required=True)
parser.add_argument("--clone-url", required=True)
parser.add_argument("--rescan", action="store_true")
args = parser.parse_args()

# Construct repo dict
repo = {"name": args.repo_name, "clone_url": args.clone_url}
rescan_mode = args.rescan

# Adjust path and load
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".")))
from scanner_postgress import process_single_repository
load_dotenv()

# Run
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-name", required=True)
    parser.add_argument("--clone-url", required=True)
    parser.add_argument("--rescan", action="store_true")
    args = parser.parse_args()

    repo = {"name": args.repo_name, "clone_url": args.clone_url}
    try:
        print(f"[Worker] Starting scan for {args.repo_name}")
        process_single_repository(repo, rescan_mode=args.rescan)
        print(f"[Worker] Completed scan for {args.repo_name}")

        # ✅ After scan, summarize vulnerability count
        vulns = aggregate_vulnerabilities()
        related = [v for v in vulns if v["repository"] == args.repo_name and not v["false_positive"]]

        if args.rescan:
            if related:
                send_slack_message(
                    f"✅ Scan completed for `{args.repo_name}`. Found *{len(related)}* vulnerabilities."
                )
            else:
                send_slack_message(
                    f"✅ Scan completed for `{args.repo_name}`. No new vulnerabilities found. 🎉"
                )

    except Exception as e:
        print(f"[Worker ERROR] {args.repo_name}: {e}")
        send_slack_message(f"❌ Scan failed for `{args.repo_name}`. Error: {e}")
        sys.exit(1)
