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
     - /api/submit      → receives form data, uses the user's GitHub token
                          to call the GitHub API directly (no shell script),
                          and opens a PR against canton-foundation/configs-private

Why no shell script?
  The shell script requires git, gh CLI, and the repo to be checked out locally.
  On a cloud server that's painful to maintain. The GitHub REST API can do
  everything the script does (read files, update them, create branches, open PRs)
  from pure HTTP calls — much cleaner for a hosted service.

Dependencies:
    pip install flask flask-cors requests python-dotenv

Environment variables (set in .env or on Render):
    GITHUB_CLIENT_ID      — from your GitHub OAuth App
    GITHUB_CLIENT_SECRET  — from your GitHub OAuth App
    FRONTEND_URL          — where your GitHub Pages site lives
                            e.g. https://canton-foundation.github.io/whitelist-tool
    TARGET_REPO_OWNER     — canton-foundation
    TARGET_REPO_NAME      — configs-private
    ALLOWED_GITHUB_ORG    — optional: only let members of this org use the tool
"""

import os
import re
import json
import secrets
import requests                         # for calling the GitHub API and OAuth endpoints

from flask import Flask, request, jsonify, redirect, session
from flask_cors import CORS             # allows the GitHub Pages frontend to call this API
from dotenv import load_dotenv          # reads .env file into os.environ

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

load_dotenv()   # load .env file (if it exists) — does nothing in production

app = Flask(__name__)

# session() requires a secret key to sign cookies.
# secrets.token_hex(32) generates a cryptographically random 64-char hex string.
# In production this must be a stable value set via environment variable,
# otherwise sessions break every time the server restarts.
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

# CORS = Cross-Origin Resource Sharing.
# Browsers block JS from calling APIs on a different domain by default.
# This tells them it's OK for our GitHub Pages frontend to call this backend.
CORS(app, origins="*", supports_credentials=False)

# ---------------------------------------------------------------------------
# Config — read everything from environment variables, never hardcode secrets
# ---------------------------------------------------------------------------

GITHUB_CLIENT_ID     = os.environ["GITHUB_CLIENT_ID"]
GITHUB_CLIENT_SECRET = os.environ["GITHUB_CLIENT_SECRET"]
FRONTEND_URL         = os.environ.get("FRONTEND_URL", "http://localhost:8080")
TARGET_OWNER         = os.environ.get("TARGET_REPO_OWNER", "canton-foundation")
TARGET_REPO          = os.environ.get("TARGET_REPO_NAME", "configs-private")
ALLOWED_ORG          = os.environ.get("ALLOWED_GITHUB_ORG", "")   # optional gating

# GitHub API and OAuth base URLs
GITHUB_API      = "https://api.github.com"
GITHUB_OAUTH    = "https://github.com/login/oauth"

# The scopes we ask the user to grant:
#   repo — read and write their repos (needed to fork + push + open PR)
OAUTH_SCOPE = "repo read:org"

# ---------------------------------------------------------------------------
# Small helper functions
# ---------------------------------------------------------------------------

def github_headers(token: str) -> dict:
    """
    Build the HTTP headers needed for every GitHub API call.

    Every authenticated GitHub API request needs:
      Authorization: Bearer <token>   — proves who we are
      Accept: application/vnd.github+json — asks for the modern JSON format

    Args:
        token: The user's GitHub OAuth access token.

    Returns:
        A dictionary of HTTP headers.
    """
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def is_valid_ip(ip: str) -> bool:
    """
    Validate that a string is a proper IPv4 address (e.g. 66.18.13.153).

    Uses a regex pattern to check the format, then checks each octet
    is in the range 0–255.

    Args:
        ip: The string to check.

    Returns:
        True if valid, False otherwise.
    """
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(part) <= 255 for part in ip.split("."))


def sanitize(text: str) -> str:
    """
    Strip whitespace and remove shell-dangerous characters from user input.

    Even though we're calling the GitHub API (not a shell) this time,
    it's still good practice to strip garbage from user input.

    Args:
        text: Raw string from the request body.

    Returns:
        Cleaned string.
    """
    dangerous = ['"', "'", "`", ";", "&", "|", "$", "(", ")", "<", ">", "\n", "\r"]
    cleaned = text.strip()
    for char in dangerous:
        cleaned = cleaned.replace(char, "")
    return cleaned


# ---------------------------------------------------------------------------
# OAuth routes
# ---------------------------------------------------------------------------

@app.route("/auth/login")
def auth_login():
    """
    Step 1 of GitHub OAuth.

    The frontend sends the user here. We redirect them to GitHub with:
      - client_id    → identifies our app to GitHub
      - scope        → what permissions we're asking for
      - state        → a random token we generate to prevent CSRF attacks
                       (we check it matches when GitHub sends the user back)

    GitHub shows the user a "Authorize this app?" screen.
    If they approve, GitHub redirects them to /auth/callback.
    """
    # Generate a random state token and store it in the session (a signed cookie)
    state = secrets.token_urlsafe(16)
    session["oauth_state"] = state

    # Build the GitHub authorization URL
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "scope":     OAUTH_SCOPE,
        "state":     state,
    }

    # Turn the params dict into a URL query string and redirect
    query_string = "&".join(f"{k}={v}" for k, v in params.items())
    return redirect(f"{GITHUB_OAUTH}/authorize?{query_string}")


@app.route("/auth/callback")
def auth_callback():
    """
    Step 2 of GitHub OAuth — GitHub redirects the user here after they approve.

    GitHub adds two query parameters to the URL:
      ?code=…&state=…

    We:
      1. Verify the state matches what we stored in the session (CSRF check)
      2. Exchange the code for an access token by calling GitHub's token endpoint
      3. Redirect the user back to the frontend with the token in the URL fragment

    Why in the URL fragment (#token=…)?
      The fragment is never sent to servers, so the token stays in the browser.
      The frontend reads it with JavaScript and stores it in memory.
    """
    code  = request.args.get("code")
    state = request.args.get("state")

    # CSRF check: the state we sent must match the state that came back
    if not state or state != session.pop("oauth_state", None):
        return redirect(f"{FRONTEND_URL}/?error=state_mismatch")

    if not code:
        return redirect(f"{FRONTEND_URL}/?error=no_code")

    # Exchange the code for an access token
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

    token_data = token_response.json()
    access_token = token_data.get("access_token")

    if not access_token:
        error = token_data.get("error_description", "token_exchange_failed")
        return redirect(f"{FRONTEND_URL}/?error={error}")

    # Redirect back to the frontend with the token in the URL fragment.
    # The fragment (#) is never sent to the server — it stays client-side only.
    return redirect(f"{FRONTEND_URL}/#token={access_token}")


@app.route("/auth/user")
def auth_user():
    """
    Returns the authenticated user's GitHub profile.

    The frontend passes the token in the Authorization header.
    We forward it to the GitHub API and return the result.

    Used by the frontend to show "Logged in as @username".
    """
    token = _extract_token()
    if not token:
        return jsonify({"error": "Not authenticated"}), 401

    response = requests.get(
        f"{GITHUB_API}/user",
        headers=github_headers(token),
        timeout=10,
    )

    if response.status_code != 200:
        return jsonify({"error": "GitHub API error"}), response.status_code

    user = response.json()

    # Only return what the frontend needs — no need to send the whole profile
    return jsonify({
        "login":      user["login"],
        "avatar_url": user["avatar_url"],
        "name":       user.get("name", user["login"]),
    })


# ---------------------------------------------------------------------------
# PR creation route
# ---------------------------------------------------------------------------

@app.route("/api/submit", methods=["POST"])
def api_submit():
    """
    The main action: create a PR to add a validator to the whitelist.

    Expects JSON body:
        {
          "network":  "test",
          "section":  "validators",
          "name":     "Fiews",
          "sponsor":  "Global-Synchronizer-Foundation",
          "ip":       "66.18.13.153",
          "approval": "https://lists.sync.global/…",
          "comment":  "optional extra context"
        }

    Steps:
        1. Validate all fields
        2. Check the user is a member of the allowed org (if configured)
        3. Get the current allowed-ip-ranges.json from the target repo
        4. Add the new IP to the correct section
        5. Create a new branch on the user's fork (or the target repo if they have write access)
        6. Commit the updated JSON file
        7. Open a PR from that branch to canton-foundation/configs-private:main
        8. Return the PR URL to the frontend
    """
    token = _extract_token()
    if not token:
        return jsonify({"error": "Not authenticated"}), 401

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

    # Map human-friendly network names to the canonical form used in file paths
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

    # Map human-friendly section names to the keys used in the JSON file
    section_map = {
        "validators":       "validators",
        "v":                "validators",
        "svs":              "svs",
        "sv":               "svs",
        "vpns":             "vpns",
        "vpn":              "vpns",
        "read-only-clients": "read-only clients",
        "read-only":        "read-only clients",
        "r":                "read-only clients",
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
    # 2. Get the authenticated user's GitHub login
    # ------------------------------------------------------------------
    user_resp = requests.get(f"{GITHUB_API}/user", headers=github_headers(token), timeout=10)
    if user_resp.status_code != 200:
        return jsonify({"error": "Could not fetch GitHub user"}), 401
    github_user = user_resp.json()["login"]

    # ------------------------------------------------------------------
    # 3. Optional: check org membership
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # 4. Read the current allowed-ip-ranges.json from the target repo
    # ------------------------------------------------------------------
    config_path = f"configs/{canonical_network}/allowed-ip-ranges.json"

    # GITHUB_PAT is set as an environment variable on Render
    pat = os.environ.get("GITHUB_PAT", "")
    read_headers = github_headers(pat) if pat else github_headers(token)

    file_resp = requests.get(
        f"{GITHUB_API}/repos/{TARGET_OWNER}/{TARGET_REPO}/contents/{config_path}",
        headers=read_headers,
        timeout=10,
    )

    if file_resp.status_code != 200:
        return jsonify({"error": f"Could not read {config_path} from {TARGET_OWNER}/{TARGET_REPO}"}), 500

    file_data = file_resp.json()
    # The file content is base64-encoded — decode it to get the JSON string
    import base64
    current_content_b64 = file_data["content"]                      # base64 string
    current_sha         = file_data["sha"]                          # needed to update the file later
    current_json_str    = base64.b64decode(current_content_b64).decode("utf-8")
    current_config      = json.loads(current_json_str)              # parse into a Python dict

    # ------------------------------------------------------------------
    # 5. Update the config in memory
    # ------------------------------------------------------------------

    # For svs/vpns the member key is just the org name.
    # For validators and read-only the key is "OrgName / SponsorName".
    if canonical_section in ("svs", "vpns"):
        member_key = name
    else:
        member_key = f"{name} / {sponsor}"

    # Get the section dict (create it if it doesn't exist yet)
    section_data = current_config.setdefault(canonical_section, {})

    # Get the existing IPs for this member (or start with an empty list)
    existing_ips = section_data.get(member_key, [])

    # Add the new IP in CIDR notation (/32 = single host)
    new_ip_cidr = f"{ip}/32"
    if new_ip_cidr not in existing_ips:
        existing_ips.append(new_ip_cidr)

    # Sort IPs numerically (so "10.0.0.2" comes before "10.0.0.10")
    existing_ips.sort(key=lambda x: [int(p) for p in x.split("/")[0].split(".")])
    section_data[member_key] = existing_ips

    # Sort members alphabetically (case-insensitive) within the section
    current_config[canonical_section] = dict(
        sorted(section_data.items(), key=lambda x: x[0].lower())
    )

    # Serialise back to a JSON string with consistent 2-space indentation
    updated_json_str = json.dumps(current_config, indent=2) + "\n"

    # ------------------------------------------------------------------
    # 6. Create a branch and commit the updated file
    # ------------------------------------------------------------------

    # We'll push to a new branch on the target repo directly.
    # (This requires the user to have write access. If they don't, you'd
    # need to fork first — see comments at the bottom of this file.)

    # Generate a unique branch name
    safe_name   = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    branch_name = f"whitelist-{canonical_network.lower()}-{canonical_section.replace(' ', '-')}-{safe_name}"

    # Get the SHA of main's HEAD so we can branch from it
    main_ref_resp = requests.get(
        f"{GITHUB_API}/repos/{TARGET_OWNER}/{TARGET_REPO}/git/ref/heads/main",
        headers=github_headers(token),
        timeout=10,
    )
    if main_ref_resp.status_code != 200:
        return jsonify({"error": "Could not read main branch"}), 500

    main_sha = main_ref_resp.json()["object"]["sha"]

    # Create the new branch pointing at main's HEAD
    create_branch_resp = requests.post(
        f"{GITHUB_API}/repos/{TARGET_OWNER}/{TARGET_REPO}/git/refs",
        headers=github_headers(token),
        json={"ref": f"refs/heads/{branch_name}", "sha": main_sha},
        timeout=10,
    )

    # 422 means the branch already exists — that's OK, we'll just push to it
    if create_branch_resp.status_code not in (201, 422):
        return jsonify({"error": f"Could not create branch: {create_branch_resp.text}"}), 500

    # Commit the updated file to the new branch
    # The file content must be base64-encoded for the GitHub API
    updated_content_b64 = base64.b64encode(updated_json_str.encode("utf-8")).decode("utf-8")

    commit_resp = requests.put(
        f"{GITHUB_API}/repos/{TARGET_OWNER}/{TARGET_REPO}/contents/{config_path}",
        headers=github_headers(token),
        json={
            "message": f"Add {name} to {canonical_section} on {canonical_network}",
            "content": updated_content_b64,
            "sha":     current_sha,      # must match the current file SHA or GitHub rejects the update
            "branch":  branch_name,
        },
        timeout=10,
    )

    if commit_resp.status_code not in (200, 201):
        return jsonify({"error": f"Could not commit file: {commit_resp.text}"}), 500

    # ------------------------------------------------------------------
    # 7. Open the PR
    # ------------------------------------------------------------------

    pr_title = f"Whitelist {name} on {canonical_network}"

    if approval:
        pr_body = f"Approval: {approval}"
    else:
        pr_body = "DevNet only, no approval needed."

    if comment:
        pr_body += f"\n\n{comment}"

    pr_resp = requests.post(
        f"{GITHUB_API}/repos/{TARGET_OWNER}/{TARGET_REPO}/pulls",
        headers=github_headers(token),
        json={
            "title": pr_title,
            "body":  pr_body,
            "head":  branch_name,   # the branch with our changes
            "base":  "main",        # merge into main
        },
        timeout=10,
    )

    if pr_resp.status_code not in (200, 201):
        return jsonify({"error": f"Could not create PR: {pr_resp.text}"}), 500

    pr_url = pr_resp.json()["html_url"]

    return jsonify({
        "success": True,
        "pr_url":  pr_url,
        "message": f"PR created: {pr_url}",
    })


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_token() -> str | None:
    """
    Read the GitHub access token from the Authorization header.

    The frontend sends it as:
        Authorization: Bearer <token>

    We split on the space and take the second part.

    Returns:
        The token string, or None if the header is missing/malformed.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    return auth_header[len("Bearer "):]   # everything after "Bearer "


# ---------------------------------------------------------------------------
# Health check (useful for Render to confirm the server is up)
# ---------------------------------------------------------------------------

@app.route("/health")
def health():
    """Simple endpoint that returns 200 OK — used by hosting platforms to check liveness."""
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Backend running on http://localhost:8000")
    app.run(host="0.0.0.0", port=8000, debug=True)
