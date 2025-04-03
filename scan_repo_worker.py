# scan_repo_worker.py — Isolated Repo Scanner Worker
import os
import sys
import argparse
from dotenv import load_dotenv

# Adjust Python path to import from main scanner
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".")))
from scanner import process_single_repository

load_dotenv()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-name", required=True)
    parser.add_argument("--clone-url", required=True)
    args = parser.parse_args()

    repo = {"name": args.repo_name, "clone_url": args.clone_url}
    try:
        print(f"[Worker] Starting scan for {args.repo_name}")
        process_single_repository(repo)
        print(f"[Worker] Completed scan for {args.repo_name}")
    except Exception as e:
        print(f"[Worker ERROR] {args.repo_name}: {e}")
        sys.exit(1)
