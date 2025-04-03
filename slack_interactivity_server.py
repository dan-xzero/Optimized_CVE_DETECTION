# slack_interactivity_server.py — with Slack request verification

import os
import json
import time
import hmac
import hashlib
import subprocess
from flask import Flask, request, make_response, abort
from dotenv import load_dotenv

load_dotenv()

SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET")

app = Flask(__name__)

def verify_slack_request(req):
    ts = req.headers.get("X-Slack-Request-Timestamp")
    sig = req.headers.get("X-Slack-Signature")
    if not ts or not sig:
        abort(403)
    if abs(time.time() - int(ts)) > 60 * 5:
        abort(403)
    base = f"v0:{ts}:{req.get_data(as_text=True)}"
    expected = "v0=" + hmac.new(
        SLACK_SIGNING_SECRET.encode(),
        base.encode(),
        hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, sig):
        abort(403)

@app.route("/slack/interactivity", methods=["POST"])
def slack_button_handler():
    verify_slack_request(request)
    try:
        payload_raw = request.form.get("payload")
        if not payload_raw:
            return make_response("Missing payload", 400)

        payload = json.loads(payload_raw)
        action = payload.get("actions", [{}])[0]
        if action.get("action_id") == "rescan_repo":
            repo_info = action.get("value", "")
            repo_name, clone_url = repo_info.split("|")

            print(f"[Slack Button] Rescan triggered for {repo_name}")
            subprocess.Popen([
                "python3", "scan_repo_worker.py",
                "--repo-name", repo_name,
                "--clone-url", clone_url
            ])
            return make_response(f"Rescan started for {repo_name}", 200)

    except Exception as e:
        print(f"[Slack Button ERROR] {e}")
        return make_response("Error processing button", 500)

    return make_response("No action processed", 200)

@app.route("/slack/rescan", methods=["POST"])
def slash_rescan():
    verify_slack_request(request)
    text = request.form.get("text", "").strip()
    user = request.form.get("user_name")
    if not text:
        return make_response("Please provide a repo name", 200)

    repo_name = text
    clone_url = f"git@bitbucket.org:lastbrand/{repo_name}.git"  # Customize

    subprocess.Popen([
        "python3", "scan_repo_worker.py",
        "--repo-name", repo_name,
        "--clone-url", clone_url
    ])
    return make_response(f"🔁 Scan triggered for `{repo_name}` by {user}", 200)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=31337, debug=True)