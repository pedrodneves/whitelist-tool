#!/usr/bin/env python3
"""
app.py — Whitelist Tool Backend
================================
A Flask server with two responsibilities:

  1. GitHub OAuth flow
     - /auth/login      → redirects the user to GitHub to grant permission
     - /auth/callback   → GitHub sends the user back here with a code;
                          we exchange it for an access token and return it
                          to the frontend

  2. PR creation
     - /api/submit      → reads the config from the upstream repo,
                          writes the updated file to pedrodneves/configs-private (the fork),
                          then opens a PR from the fork → canton-foundation/configs-private

Why a fork?
  pedrodneves doesn't have write access to canton-foundation/configs-private.
  The fork (pedrodneves/configs-private) is owned by pedrodneves, so the PAT
  generated from that account has full write access to it.
  GitHub allows PRs from forks to the upstream repo — this is the standard
  open source contribution model.

Environment variables (set on Render):
    GITHUB_CLIENT_ID      — from your GitHub OAuth App
    GITHUB_CLIENT_SECRET  — from your GitHub OAuth App
    GITHUB_PAT            — Personal Access Token from pedrodneves with repo scope
    FRONTEND_URL          — https://pedrodneves.github.io/whitelist-tool
    TARGET_REPO_OWNER     — canton-foundation  (where the PR lands)
    TARGET_REPO_NAME      — configs-private
    FORK_OWNER            — pedrodneves        (where we push the branch)
    FLASK_SECRET_KEY      — long random string for signing sessions
"""

import os
import re
import json
import base64
import secrets
import requests

from flask import Flask, request, jsonify, redirect, session
from flask_cors import CORS
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

load_dotenv()

app = Flask(__name__)

# Secret key for signing session cookies
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

# Allow all origins — security comes from the GitHub token, not the origin
CORS(app, origins="*", supports_credentials=False)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

GITHUB_CLIENT_ID     = os.environ["GITHUB_CLIENT_ID"]
GITHUB_CLIENT_SECRET = os.environ["GITHUB_CLIENT_SECRET"]
FRONTEND_URL         = os.environ.get("FRONTEND_URL", "http://localhost:8080")

# The upstream repo — where the PR is opened against
TARGET_OWNER = os.environ.get("TARGET_REPO_OWNER", "canton-foundation")
TARGET_REPO  = os.environ.get("TARGET_REPO_NAME",  "configs-private")

# The fork — where we push the branch (pedrodneves owns this so the PAT works)
FORK_OWNER   = os.environ.get("FORK_OWNER", "pedrodneves")

# PAT from pedrodneves account — has write access to the fork
GITHUB_PAT   = os.environ.get("GITHUB_PAT", "")

GITHUB_API   = "https://api.github.com"
GITHUB_OAUTH = "https://github.com/login/oauth"

# Only need to identify the user — all repo work is done via the PAT
OAUTH_SCOPE  = "read:user"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def pat_headers() -> dict:
    """
    GitHub API headers using the server-side PAT.
    Used for all calls to the fork (read, branch, commit, PR).
    The PAT is stored securely on Render — never exposed to the browser.
    """
    return {
        "Authorization": f"Bearer {GITHUB_PAT}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def user_headers(token: str) -> dict:
    """
    GitHub API headers using the user's OAuth token.
    Only used to identify who is logged in.
    """
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def is_valid_ip(ip: str) -> bool:
    """
    Validate a string is a proper IPv4 address.
    Checks format with regex then verifies each octet is 0-255.
    """
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(part) <= 255 for part in ip.split("."))


def sanitize(text: str) -> str:
    """Strip whitespace and remove characters that could cause issues."""
    dangerous = ['"', "'", "`", ";", "&", "|", "$", "(", ")", "<", ">", "\n", "\r"]
    cleaned = text.strip()
    for char in dangerous:
        cleaned = cleaned.replace(char, "")
    return cleaned


def _extract_token() -> str | None:
    """Read the OAuth token from the Authorization: Bearer <token> header."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    return auth_header[len("Bearer "):]


# ---------------------------------------------------------------------------
# OAuth routes
# ---------------------------------------------------------------------------

@app.route("/auth/login")
def auth_login():
    """
    Step 1 of OAuth — redirect the user to GitHub's authorization page.
    Generates a random state token to prevent CSRF attacks.
    """
    state = secrets.token_urlsafe(16)
    session["oauth_state"] = state

    params = {
        "client_id": GITHUB_CLIENT_ID,
        "scope":     OAUTH_SCOPE,
        "state":     state,
    }

    query_string = "&".join(f"{k}={v}" for k, v in params.items())
    return redirect(f"{GITHUB_OAUTH}/authorize?{query_string}")


@app.route("/auth/callback")
def auth_callback():
    """
    Step 2 of OAuth — GitHub redirects here with ?code=...&state=...
    Verifies state, exchanges code for access token, redirects to frontend
    with token in URL fragment (#token=...) which never hits a server.
    """
    code  = request.args.get("code")
    state = request.args.get("state")

    # CSRF check — state must match what we stored in the session
    if not state or state != session.pop("oauth_state", None):
        return redirect(f"{FRONTEND_URL}/?error=state_mismatch")

    if not code:
        return redirect(f"{FRONTEND_URL}/?error=no_code")

    # Exchange the one-time code for a reusable access token
    token_response = requests.post(
        f"{GITHUB_OAUTH}/access_token",
        json={
            "client_id":     GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code":          code,
        },
        headers={"Accept": "application/json"},
        timeout=10,
    )

    token_data   = token_response.json()
    access_token = token_data.get("access_token")

    if not access_token:
        error = token_data.get("error_description", "token_exchange_failed")
        return redirect(f"{FRONTEND_URL}/?error={error}")

    # Pass token to frontend via URL fragment — never hits a server
    return redirect(f"{FRONTEND_URL}/#token={access_token}")


@app.route("/auth/user")
def auth_user():
    """
    Returns the logged-in user's GitHub profile (login + avatar).
    Used by the frontend to show "Signed in as @username".
    """
    token = _extract_token()
    if not token:
        return jsonify({"error": "Not authenticated"}), 401

    response = requests.get(
        f"{GITHUB_API}/user",
        headers=user_headers(token),
        timeout=10,
    )

    if response.status_code != 200:
        return jsonify({"error": "GitHub API error"}), response.status_code

    user = response.json()
    return jsonify({
        "login":      user["login"],
        "avatar_url": user["avatar_url"],
        "name":       user.get("name", user["login"]),
    })


# ---------------------------------------------------------------------------
# PR creation
# ---------------------------------------------------------------------------

@app.route("/api/submit", methods=["POST"])
def api_submit():
    """
    Main action — the full flow:

      1. Validate all form fields
      2. Read allowed-ip-ranges.json from the UPSTREAM repo (canton-foundation)
      3. Update the JSON in memory (add the new IP)
      4. Sync the fork's main branch with upstream main
      5. Create a new branch on the FORK (pedrodneves/configs-private)
      6. Commit the updated file to that branch
      7. Open a PR from fork:branch → upstream:main

    All GitHub API calls use the server-side PAT — the user's OAuth token
    is only used to show their name in the PR body.
    """

    token = _extract_token()
    if not token:
        return jsonify({"error": "Not authenticated"}), 401

    if not GITHUB_PAT:
        return jsonify({"error": "Server is missing GITHUB_PAT environment variable."}), 500

    # ------------------------------------------------------------------
    # 1. Validate inputs
    # ------------------------------------------------------------------
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data received"}), 400

    network  = sanitize(data.get("network",  ""))
    section  = sanitize(data.get("section",  ""))
    name     = sanitize(data.get("name",     ""))
    sponsor  = sanitize(data.get("sponsor",  ""))
    ip       = sanitize(data.get("ip",       ""))
    approval = sanitize(data.get("approval", ""))
    comment  = sanitize(data.get("comment",  ""))

    errors = []

    # Map input → canonical folder names used in the repo
    network_map = {
        "dev":     "DevNet",
        "devnet":  "DevNet",
        "test":    "TestNet",
        "testnet": "TestNet",
        "main":    "MainNet",
        "mainnet": "MainNet",
    }
    canonical_network = network_map.get(network.lower())
    if not canonical_network:
        errors.append(f"Invalid network '{network}'. Use dev, test, or main.")

    # Map input → canonical JSON section keys
    section_map = {
        "validators":        "validators",
        "v":                 "validators",
        "svs":               "svs",
        "vpns":              "vpns",
        "read-only-clients": "read-only clients",
        "read-only":         "read-only clients",
    }
    canonical_section = section_map.get(section.lower())
    if not canonical_section:
        errors.append(f"Invalid section '{section}'.")

    if not name:
        errors.append("Organisation name is required.")

    if canonical_section not in ("svs", "vpns") and not sponsor:
        errors.append("Sponsor is required for validators and read-only clients.")

    if not ip:
        errors.append("IP address is required.")
    elif not is_valid_ip(ip):
        errors.append(f"'{ip}' is not a valid IPv4 address.")

    if canonical_network in ("TestNet", "MainNet"):
        if not approval:
            errors.append("Approval link is required for testnet and mainnet.")
        elif not approval.startswith("http"):
            errors.append("Approval must be a valid URL.")

    if errors:
        return jsonify({"error": "\n".join(errors)}), 400

    # ------------------------------------------------------------------
    # 2. Get the submitting user's GitHub login (for the PR body)
    # ------------------------------------------------------------------
    user_resp   = requests.get(f"{GITHUB_API}/user", headers=user_headers(token), timeout=10)
    github_user = user_resp.json().get("login", "unknown") if user_resp.status_code == 200 else "unknown"

    # ------------------------------------------------------------------
    # 3. Sync the fork's main branch with upstream FIRST
    #    This must happen before reading the file so we get the latest
    #    content and SHA from the fork — not a stale version.
    #    Without this, PRs include all the commits the fork was behind.
    # ------------------------------------------------------------------
    config_path = f"configs/{canonical_network}/allowed-ip-ranges.json"

    sync_resp = requests.post(
        f"{GITHUB_API}/repos/{FORK_OWNER}/{TARGET_REPO}/merge-upstream",
        headers=pat_headers(),
        json={"branch": "main"},
        timeout=15,
    )
    # 200 = synced successfully, 409 = already up to date or conflict
    if sync_resp.status_code not in (200, 409):
        return jsonify({"error": f"Could not sync fork with upstream. Status: {sync_resp.status_code}"}), 500

    # ------------------------------------------------------------------
    # 4. Read the current config from the FORK (now in sync with upstream)
    #    Reading from the fork gives us the correct file SHA we need
    #    when committing — using the upstream SHA would cause a conflict.
    # ------------------------------------------------------------------
    file_resp = requests.get(
        f"{GITHUB_API}/repos/{FORK_OWNER}/{TARGET_REPO}/contents/{config_path}",
        headers=pat_headers(),
        timeout=10,
    )

    if file_resp.status_code != 200:
        return jsonify({"error": f"Could not read {config_path} from fork. Status: {file_resp.status_code}"}), 500

    file_data    = file_resp.json()
    current_sha  = file_data["sha"]   # SHA from the fork — used when committing
    current_json = json.loads(base64.b64decode(file_data["content"]).decode("utf-8"))

    # ------------------------------------------------------------------
    # 4. Update the config in memory
    # ------------------------------------------------------------------

    # Key format: "OrgName / SponsorName" for validators/read-only, "OrgName" for svs/vpns
    member_key   = name if canonical_section in ("svs", "vpns") else f"{name} / {sponsor}"
    section_data = current_json.setdefault(canonical_section, {})
    existing_ips = section_data.get(member_key, [])

    # Add new IP in CIDR /32 notation (single host address)
    new_ip_cidr = f"{ip}/32"
    if new_ip_cidr not in existing_ips:
        existing_ips.append(new_ip_cidr)

    # Sort IPs numerically (e.g. 10.0.0.2 before 10.0.0.10)
    existing_ips.sort(key=lambda x: [int(p) for p in x.split("/")[0].split(".")])
    section_data[member_key] = existing_ips

    # Sort members alphabetically (case-insensitive)
    current_json[canonical_section] = dict(
        sorted(section_data.items(), key=lambda x: x[0].lower())
    )

    updated_json_str = json.dumps(current_json, indent=2) + "\n"

    # ------------------------------------------------------------------
    # 5. Get main SHA and create a new branch on the FORK
    # ------------------------------------------------------------------
    safe_name   = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    branch_name = f"whitelist-{canonical_network.lower()}-{canonical_section.replace(' ', '-')}-{safe_name}"

    # Read the fork's main HEAD SHA
    main_ref_resp = requests.get(
        f"{GITHUB_API}/repos/{FORK_OWNER}/{TARGET_REPO}/git/ref/heads/main",
        headers=pat_headers(),
        timeout=10,
    )
    if main_ref_resp.status_code != 200:
        return jsonify({"error": f"Could not read fork main branch. Status: {main_ref_resp.status_code}"}), 500

    main_sha = main_ref_resp.json()["object"]["sha"]

    # Create the new branch on the fork (422 = already exists, that's fine)
    create_branch_resp = requests.post(
        f"{GITHUB_API}/repos/{FORK_OWNER}/{TARGET_REPO}/git/refs",
        headers=pat_headers(),
        json={"ref": f"refs/heads/{branch_name}", "sha": main_sha},
        timeout=10,
    )
    if create_branch_resp.status_code not in (201, 422):
        return jsonify({"error": f"Could not create branch: {create_branch_resp.text}"}), 500

    # ------------------------------------------------------------------
    # 6. Commit the updated file to the fork branch
    # ------------------------------------------------------------------

    # current_sha already holds the fork's file SHA (read after sync above)
    updated_b64 = base64.b64encode(updated_json_str.encode("utf-8")).decode("utf-8")

    commit_resp = requests.put(
        f"{GITHUB_API}/repos/{FORK_OWNER}/{TARGET_REPO}/contents/{config_path}",
        headers=pat_headers(),
        json={
            "message": f"Add {name} to {canonical_section} on {canonical_network}",
            "content": updated_b64,
            "sha":     current_sha,
            "branch":  branch_name,
        },
        timeout=10,
    )
    if commit_resp.status_code not in (200, 201):
        return jsonify({"error": f"Could not commit file: {commit_resp.text}"}), 500

    # ------------------------------------------------------------------
    # 7. Open the PR from fork:branch → upstream:main
    # ------------------------------------------------------------------

    pr_title = f"Whitelist {name} on {canonical_network}"
    pr_body  = f"Submitted by @{github_user} via the whitelist tool.\n\n"
    pr_body += f"Approval: {approval}" if approval else "DevNet only, no approval needed."
    if comment:
        pr_body += f"\n\n{comment}"

    pr_resp = requests.post(
        f"{GITHUB_API}/repos/{TARGET_OWNER}/{TARGET_REPO}/pulls",
        headers=pat_headers(),
        json={
            "title": pr_title,
            "body":  pr_body,
            "head":  f"{FORK_OWNER}:{branch_name}",  # fork:branch
            "base":  "main",                           # upstream main
        },
        timeout=10,
    )
    if pr_resp.status_code not in (200, 201):
        return jsonify({"error": f"Could not create PR: {pr_resp.text}"}), 500

    pr_url = pr_resp.json()["html_url"]
    return jsonify({"success": True, "pr_url": pr_url})


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.route("/health")
def health():
    """Returns 200 OK — used by Render to confirm the server is alive."""
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Backend running on http://localhost:8000")
    app.run(host="0.0.0.0", port=8000, debug=True)
