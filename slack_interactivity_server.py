# slack_interactivity_server.py — with Slack request verification

import os
import json
import time
import hmac
import hashlib
import subprocess
from flask import Flask, request, make_response, abort, jsonify
from dotenv import load_dotenv
from scanner import create_jira_ticket, send_slack_message
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError



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
def handle_interaction():
    verify_slack_request(request)
    payload = json.loads(request.form["payload"])
    action = payload["actions"][0]

    if action["action_id"] == "create_jira_ticket":
        repo_name, vuln_id, severity = action["value"].split("|")
        slack_response = create_jira_ticket(repo_name, vuln_id, severity)

        # ✅ Send Slack message with blocks to the channel
        if "issue_url" in slack_response:
            slack_token = os.getenv("SLACK_API_TOKEN")
            slack_channel = os.getenv("SLACK_CHANNEL_ID")
            client = WebClient(token=slack_token)

            try:
                client.chat_postMessage(
                    channel=slack_channel,
                    blocks=slack_response["blocks"],
                    text=slack_response["text"],  # fallback
                    mrkdwn=True
                )
                print("[Slack] Jira ticket Slack message sent")
            except SlackApiError as e:
                print(f"[Slack Error] {e.response['error']}")

        # ✅ Still respond to the button interaction (ephemeral response)
        return jsonify({
            "response_type": "ephemeral",
            "text": f"🎟️ Jira ticket created: <{slack_response['issue_url']}|{slack_response['issue_key']}>"
        })

    return make_response("", 200)


# @app.route("/slack/interactivity", methods=["POST"])
# def slack_button_handler():
#     verify_slack_request(request)
#     try:
#         payload_raw = request.form.get("payload")
#         if not payload_raw:
#             return make_response("Missing payload", 400)

#         payload = json.loads(payload_raw)
#         action = payload.get("actions", [{}])[0]
#         if action.get("action_id") == "rescan_repo":
#             repo_info = action.get("value", "")
#             repo_name, clone_url = repo_info.split("|")

#             print(f"[Slack Button] Rescan triggered for {repo_name}")
#             subprocess.Popen([
#                 "python3", "scan_repo_worker.py",
#                 "--repo-name", repo_name,
#                 "--clone-url", clone_url,
#                 "--rescan" 
#             ])
#             return jsonify({
#     "response_type": "in_channel",
#     "text": f"🔄 Rescan triggered for `{repo_name}` via Slack button."
# })

#     except Exception as e:
#         print(f"[Slack Button ERROR] {e}")
#         return make_response("Error processing button", 500)

#     return make_response("No action processed", 200)

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
        "--clone-url", clone_url,
        "--rescan"
    ])
    return jsonify({
     "response_type": "in_channel",
     "text": f"🔄 Rescan triggered for `{repo_name}` by `{user}` using `/rescan`."
})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=31337, debug=True)