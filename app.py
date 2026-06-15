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
     - /api/submit      → receives form data, uses a PAT to read the private
                          repo and open a PR against canton-foundation/configs-private

Environment variables (set on Render):
    GITHUB_CLIENT_ID      — from your GitHub OAuth App
    GITHUB_CLIENT_SECRET  — from your GitHub OAuth App
    GITHUB_PAT            — Personal Access Token with repo scope (reads configs-private)
    FRONTEND_URL          — https://pedrodneves.github.io/whitelist-tool
    TARGET_REPO_OWNER     — canton-foundation
    TARGET_REPO_NAME      — configs-private
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

# Secret key for signing session cookies — must be stable across restarts in prod
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

# Allow all origins — security comes from the GitHub token, not the origin
CORS(app, origins="*", supports_credentials=False)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

GITHUB_CLIENT_ID     = os.environ["GITHUB_CLIENT_ID"]
GITHUB_CLIENT_SECRET = os.environ["GITHUB_CLIENT_SECRET"]
FRONTEND_URL         = os.environ.get("FRONTEND_URL", "http://localhost:8080")
TARGET_OWNER         = os.environ.get("TARGET_REPO_OWNER", "canton-foundation")
TARGET_REPO          = os.environ.get("TARGET_REPO_NAME", "configs-private")

# PAT = Personal Access Token stored on Render.
# Used for all GitHub API calls against the private configs repo.
# This token needs repo scope on canton-foundation/configs-private.
GITHUB_PAT           = os.environ.get("GITHUB_PAT", "")

GITHUB_API   = "https://api.github.com"
GITHUB_OAUTH = "https://github.com/login/oauth"

# Scopes requested from the user during OAuth login.
# We only need to identify the user — all repo work is done via the PAT.
OAUTH_SCOPE = "read:user"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def pat_headers() -> dict:
    """
    Build GitHub API headers using the server-side PAT.
    Used for all calls to configs-private (read file, create branch, commit, open PR).
    The PAT is stored securely on Render — never exposed to the browser.
    """
    return {
        "Authorization": f"Bearer {GITHUB_PAT}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def user_headers(token: str) -> dict:
    """
    Build GitHub API headers using the user's OAuth token.
    Only used to identify who is logged in (/auth/user route).
    """
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def is_valid_ip(ip: str) -> bool:
    """
    Check that a string is a valid IPv4 address.
    Pattern matches four groups of 1-3 digits separated by dots.
    Then checks each octet is 0-255.
    """
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(part) <= 255 for part in ip.split("."))


def sanitize(text: str) -> str:
    """
    Strip whitespace and remove characters that could cause issues
    in JSON values or branch names.
    """
    dangerous = ['"', "'", "`", ";", "&", "|", "$", "(", ")", "<", ">", "\n", "\r"]
    cleaned = text.strip()
    for char in dangerous:
        cleaned = cleaned.replace(char, "")
    return cleaned


def _extract_token() -> str | None:
    """
    Read the OAuth token from the Authorization: Bearer <token> header.
    Returns None if the header is missing or malformed.
    """
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
    We generate a random 'state' token to prevent CSRF attacks and store
    it in the session cookie to verify when GitHub redirects back.
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
    We verify the state (CSRF check), exchange the code for an access token,
    then redirect to the frontend with the token in the URL fragment (#token=...).
    The fragment is never sent to servers — it stays in the browser only.
    """
    code  = request.args.get("code")
    state = request.args.get("state")

    # CSRF check
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

    # Pass the token to the frontend via URL fragment (never hits a server)
    return redirect(f"{FRONTEND_URL}/#token={access_token}")


@app.route("/auth/user")
def auth_user():
    """
    Returns the logged-in user's GitHub profile (login + avatar).
    Used by the frontend to show "Signed in as @username" in the topbar.
    Uses the user's own OAuth token — not the PAT.
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

    # Only return what the frontend needs
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
    Main action: read the config, update it, create a branch, commit, open PR.

    All GitHub API calls use the server-side PAT (not the user's token).
    This means the tool works for any logged-in user regardless of their
    personal repo permissions — the PAT is what has write access to configs-private.

    The user's identity is still verified via OAuth — we just use it to show
    their name, not to make API calls.
    """

    # Must be logged in to submit
    token = _extract_token()
    if not token:
        return jsonify({"error": "Not authenticated"}), 401

    if not GITHUB_PAT:
        return jsonify({"error": "Server is missing GITHUB_PAT environment variable."}), 500

    # ------------------------------------------------------------------
    # 1. Parse and validate inputs
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

    # Map input network names to canonical folder names used in the repo
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

    # Map input section names to canonical JSON keys
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
    user_resp = requests.get(
        f"{GITHUB_API}/user",
        headers=user_headers(token),
        timeout=10,
    )
    github_user = user_resp.json().get("login", "unknown") if user_resp.status_code == 200 else "unknown"

    # ------------------------------------------------------------------
    # 3. Read the current allowed-ip-ranges.json using the PAT
    # ------------------------------------------------------------------
    config_path = f"configs/{canonical_network}/allowed-ip-ranges.json"

    file_resp = requests.get(
        f"{GITHUB_API}/repos/{TARGET_OWNER}/{TARGET_REPO}/contents/{config_path}",
        headers=pat_headers(),   # PAT has access to the private repo
        timeout=10,
    )

    if file_resp.status_code != 200:
        return jsonify({"error": f"Could not read {config_path} from {TARGET_OWNER}/{TARGET_REPO}. Status: {file_resp.status_code}"}), 500

    file_data       = file_resp.json()
    current_sha     = file_data["sha"]   # needed when committing the update
    current_json    = json.loads(base64.b64decode(file_data["content"]).decode("utf-8"))

    # ------------------------------------------------------------------
    # 4. Update the config in memory
    # ------------------------------------------------------------------

    # Key format depends on section:
    # validators / read-only → "OrgName / SponsorName"
    # svs / vpns             → "OrgName"
    member_key = name if canonical_section in ("svs", "vpns") else f"{name} / {sponsor}"

    section_data = current_json.setdefault(canonical_section, {})
    existing_ips = section_data.get(member_key, [])

    # Add new IP in CIDR /32 notation (single host)
    new_ip_cidr = f"{ip}/32"
    if new_ip_cidr not in existing_ips:
        existing_ips.append(new_ip_cidr)

    # Sort IPs numerically
    existing_ips.sort(key=lambda x: [int(p) for p in x.split("/")[0].split(".")])
    section_data[member_key] = existing_ips

    # Sort members alphabetically (case-insensitive)
    current_json[canonical_section] = dict(
        sorted(section_data.items(), key=lambda x: x[0].lower())
    )

    updated_json_str = json.dumps(current_json, indent=2) + "\n"

    # ------------------------------------------------------------------
    # 5. Get main branch SHA and create a new branch (using PAT)
    # ------------------------------------------------------------------

    safe_name   = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    branch_name = f"whitelist-{canonical_network.lower()}-{canonical_section.replace(' ', '-')}-{safe_name}"

    main_ref_resp = requests.get(
        f"{GITHUB_API}/repos/{TARGET_OWNER}/{TARGET_REPO}/git/ref/heads/main",
        headers=pat_headers(),
        timeout=10,
    )
    if main_ref_resp.status_code != 200:
        return jsonify({"error": f"Could not read main branch. Status: {main_ref_resp.status_code}"}), 500

    main_sha = main_ref_resp.json()["object"]["sha"]

    # Create the branch — 422 means it already exists, which is fine
    create_branch_resp = requests.post(
        f"{GITHUB_API}/repos/{TARGET_OWNER}/{TARGET_REPO}/git/refs",
        headers=pat_headers(),
        json={"ref": f"refs/heads/{branch_name}", "sha": main_sha},
        timeout=10,
    )
    if create_branch_resp.status_code not in (201, 422):
        return jsonify({"error": f"Could not create branch: {create_branch_resp.text}"}), 500

    # ------------------------------------------------------------------
    # 6. Commit the updated file (using PAT)
    # ------------------------------------------------------------------

    updated_b64 = base64.b64encode(updated_json_str.encode("utf-8")).decode("utf-8")

    commit_resp = requests.put(
        f"{GITHUB_API}/repos/{TARGET_OWNER}/{TARGET_REPO}/contents/{config_path}",
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
    # 7. Open the PR (using PAT)
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
            "head":  branch_name,
            "base":  "main",
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
