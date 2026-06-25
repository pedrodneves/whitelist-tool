#!/usr/bin/env python3
"""
app.py — Whitelist Tool Backend
================================
Uses GitHub's low-level Git Data API to create a single clean commit
that contains exactly one change — the new IP — based off upstream's
current HEAD. No fork sync needed, no stale content.

The flow:
  1. Read the file from upstream (canton-foundation/configs-private)
  2. Apply our change in memory
  3. Get upstream's HEAD commit SHA
  4. Create a blob with the new file content on the fork
  5. Create a tree on the fork pointing to upstream's tree + our blob
  6. Create a commit on the fork whose parent is upstream's HEAD
  7. Create a branch on the fork pointing at that commit
  8. Open a PR from fork:branch → upstream:main

This guarantees a single clean commit with exactly one file changed,
regardless of how far behind the fork's main is.

Environment variables (set on Render):
    GITHUB_CLIENT_ID      — from your GitHub OAuth App
    GITHUB_CLIENT_SECRET  — from your GitHub OAuth App
    GITHUB_PAT            — Personal Access Token from pedrodneves with repo scope
    FRONTEND_URL          — https://pedrodneves.github.io/whitelist-tool
    TARGET_REPO_OWNER     — canton-foundation
    TARGET_REPO_NAME      — configs-private
    FORK_OWNER            — pedrodneves
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
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
CORS(app, origins="*", supports_credentials=False)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

GITHUB_CLIENT_ID     = os.environ["GITHUB_CLIENT_ID"]
GITHUB_CLIENT_SECRET = os.environ["GITHUB_CLIENT_SECRET"]
FRONTEND_URL         = os.environ.get("FRONTEND_URL", "http://localhost:8080")
TARGET_OWNER         = os.environ.get("TARGET_REPO_OWNER", "canton-foundation")
TARGET_REPO          = os.environ.get("TARGET_REPO_NAME",  "configs-private")
FORK_OWNER           = os.environ.get("FORK_OWNER", "pedrodneves")
GITHUB_PAT           = os.environ.get("GITHUB_PAT", "")
GITHUB_API           = "https://api.github.com"
GITHUB_OAUTH         = "https://github.com/login/oauth"
OAUTH_SCOPE          = "read:user"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def pat_headers() -> dict:
    """Headers using the server-side PAT — used for all GitHub API calls."""
    return {
        "Authorization": f"Bearer {GITHUB_PAT}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

def user_headers(token: str) -> dict:
    """Headers using the user's OAuth token — only used to identify the user."""
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

def is_valid_ip(ip: str) -> bool:
    """Validate a string is a proper IPv4 address."""
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

def _resolve_network_and_section(network: str, section: str):
    """
    Resolve user-supplied network and section strings to their canonical forms.
    Returns (canonical_network, canonical_section) or (None, None) on failure.
    Used by both /api/check and /api/submit to keep the maps in one place.
    """
    network_map = {
        "dev": "DevNet", "devnet": "DevNet",
        "test": "TestNet", "testnet": "TestNet",
        "main": "MainNet", "mainnet": "MainNet",
    }
    section_map = {
        "validators": "validators", "v": "validators",
        "svs": "svs", "vpns": "vpns",
        "read-only-clients": "read-only clients", "read-only": "read-only clients",
    }
    return (
        network_map.get(network.lower()),
        section_map.get(section.lower()),
    )

# ---------------------------------------------------------------------------
# OAuth routes
# ---------------------------------------------------------------------------

@app.route("/auth/login")
def auth_login():
    """
    Step 1 of OAuth — redirect to GitHub's authorization page.
    Generates a random state token stored in the session to prevent CSRF.
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
    Verifies state, exchanges code for token, redirects to frontend
    with token in URL fragment (#token=...) which never hits a server.
    """
    code  = request.args.get("code")
    state = request.args.get("state")

    if not state or state != session.pop("oauth_state", None):
        return redirect(f"{FRONTEND_URL}/?error=state_mismatch")
    if not code:
        return redirect(f"{FRONTEND_URL}/?error=no_code")

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

    return redirect(f"{FRONTEND_URL}/#token={access_token}")


@app.route("/auth/user")
def auth_user():
    """Returns the logged-in user's GitHub profile for the topbar."""
    token = _extract_token()
    if not token:
        return jsonify({"error": "Not authenticated"}), 401

    response = requests.get(f"{GITHUB_API}/user", headers=user_headers(token), timeout=10)
    if response.status_code != 200:
        return jsonify({"error": "GitHub API error"}), response.status_code

    user = response.json()
    return jsonify({
        "login":      user["login"],
        "avatar_url": user["avatar_url"],
        "name":       user.get("name", user["login"]),
    })

# ---------------------------------------------------------------------------
# Duplicate org check
# ---------------------------------------------------------------------------

@app.route("/api/check", methods=["POST"])
def api_check():
    """
    Check whether an organisation name already exists in a given network+section
    of the upstream JSON file.

    Called by the frontend before the PR is created, so the user sees a warning
    if the org is already whitelisted and can decide whether to continue.

    Request body (JSON):
        network  — e.g. "dev", "test", "main"
        section  — e.g. "validators", "svs"
        name     — organisation name to check
        sponsor  — sponsor name (used to build the member key for validators)

    Response (JSON):
        { "exists": true/false }        — on success
        { "error": "..." }              — if inputs are invalid or upstream unreachable
    """
    token = _extract_token()
    if not token:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json()
    if not data:
        return jsonify({"error": "No data received"}), 400

    # Pull and sanitize the fields we need
    network = sanitize(data.get("network", ""))
    section = sanitize(data.get("section", ""))
    name    = sanitize(data.get("name",    ""))
    sponsor = sanitize(data.get("sponsor", ""))

    canonical_network, canonical_section = _resolve_network_and_section(network, section)

    if not canonical_network:
        return jsonify({"error": f"Invalid network '{network}'"}), 400
    if not canonical_section:
        return jsonify({"error": f"Invalid section '{section}'"}), 400
    if not name:
        return jsonify({"error": "Organisation name is required"}), 400

    # Build the path to the JSON file in the upstream repo
    config_path = f"configs/{canonical_network}/allowed-ip-ranges.json"

    # Fetch the file from the upstream repo using the server-side PAT
    upstream_resp = requests.get(
        f"{GITHUB_API}/repos/{TARGET_OWNER}/{TARGET_REPO}/contents/{config_path}",
        headers=pat_headers(),
        timeout=10,
    )
    if upstream_resp.status_code != 200:
        # If we can't reach upstream, don't block the user — just return not found
        return jsonify({"exists": False, "warning": "Could not reach upstream to verify"})

    # Decode the base64-encoded file content GitHub returns
    raw_json_str = base64.b64decode(upstream_resp.json()["content"]).decode("utf-8")
    current_json = json.loads(raw_json_str)

    # Build the member key exactly as /api/submit would
    # SVs and VPNs use the plain org name; validators use "Name / Sponsor"
    if canonical_section in ("svs", "vpns"):
        member_key = name
    else:
        member_key = f"{name} / {sponsor}" if sponsor else name

    # Check whether this key already appears under the correct section
    section_data = current_json.get(canonical_section, {})
    exists       = member_key in section_data

    return jsonify({"exists": exists, "member_key": member_key})


# ---------------------------------------------------------------------------
# PR creation
# ---------------------------------------------------------------------------

@app.route("/api/submit", methods=["POST"])
def api_submit():
    """
    Creates a clean single-commit PR using GitHub's low-level Git Data API.

    Key insight: instead of branching from the fork's (potentially stale) main,
    we create a commit whose parent is upstream's HEAD directly. This means
    the PR diff will contain ONLY our one change — nothing else.
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

    canonical_network, canonical_section = _resolve_network_and_section(network, section)

    if not canonical_network:
        errors.append(f"Invalid network '{network}'. Use dev, test, or main.")
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
    # 2. Get the submitting user's login (shown in the PR body)
    # ------------------------------------------------------------------
    user_resp   = requests.get(f"{GITHUB_API}/user", headers=user_headers(token), timeout=10)
    github_user = user_resp.json().get("login", "unknown") if user_resp.status_code == 200 else "unknown"

    config_path = f"configs/{canonical_network}/allowed-ip-ranges.json"

    # ------------------------------------------------------------------
    # 3. Read the file from UPSTREAM (always the latest version)
    #    We read the raw bytes — not decoded JSON — so we preserve the
    #    exact original formatting and encoding of every other line.
    # ------------------------------------------------------------------
    upstream_file_resp = requests.get(
        f"{GITHUB_API}/repos/{TARGET_OWNER}/{TARGET_REPO}/contents/{config_path}",
        headers=pat_headers(),
        timeout=10,
    )
    if upstream_file_resp.status_code != 200:
        return jsonify({"error": f"Could not read {config_path} from upstream. Status: {upstream_file_resp.status_code}"}), 500

    upstream_file     = upstream_file_resp.json()
    # Decode the base64 content to get the raw JSON string exactly as stored
    raw_json_str      = base64.b64decode(upstream_file["content"]).decode("utf-8")
    current_json      = json.loads(raw_json_str)

    # ------------------------------------------------------------------
    # 4. Apply our change in memory
    # ------------------------------------------------------------------
    member_key   = name if canonical_section in ("svs", "vpns") else f"{name} / {sponsor}"
    section_data = current_json.setdefault(canonical_section, {})
    existing_ips = section_data.get(member_key, [])

    # Remember whether this org already had IPs — used in the PR body below
    is_rotation = len(existing_ips) > 0

    new_ip_cidr = f"{ip}/32"

    # If the IP is already present for this member, abort early with a clear
    # error rather than creating an empty commit (Files changed: 0).
    if new_ip_cidr in existing_ips:
        return jsonify({
            "error": (
                f"{new_ip_cidr} is already whitelisted for '{member_key}' "
                f"on {canonical_network}. No changes were made."
            )
        }), 400

    existing_ips.append(new_ip_cidr)

    # Sort IPs numerically (so 10.0.0.2 comes before 10.0.0.10)
    existing_ips.sort(key=lambda x: [int(p) for p in x.split("/")[0].split(".")])
    section_data[member_key] = existing_ips

    # Sort members alphabetically (case-insensitive)
    current_json[canonical_section] = dict(
        sorted(section_data.items(), key=lambda x: x[0].lower())
    )

    # ensure_ascii=False preserves unicode characters like accented letters
    # exactly as they appear in the original file — no \uXXXX escaping
    updated_json_str = json.dumps(current_json, indent=2, ensure_ascii=False) + "\n"

    # Safety net: if the serialised result is byte-for-byte identical to what
    # we read, abort rather than push an empty commit.
    if updated_json_str == raw_json_str:
        return jsonify({
            "error": (
                f"No changes detected after applying the update for '{member_key}'. "
                "The IP may already be present in the file. No PR was created."
            )
        }), 400

    # ------------------------------------------------------------------
    # 5. Get upstream's HEAD commit SHA and tree SHA
    #    Our new commit will be a child of this commit, so the PR diff
    #    will only show what changed between upstream HEAD and our commit.
    # ------------------------------------------------------------------
    upstream_ref_resp = requests.get(
        f"{GITHUB_API}/repos/{TARGET_OWNER}/{TARGET_REPO}/git/ref/heads/main",
        headers=pat_headers(),
        timeout=10,
    )
    if upstream_ref_resp.status_code != 200:
        return jsonify({"error": "Could not read upstream main branch."}), 500

    # The SHA of the latest commit on upstream/main
    upstream_head_sha = upstream_ref_resp.json()["object"]["sha"]

    # Get the tree SHA from that commit (needed to create our new tree)
    upstream_commit_resp = requests.get(
        f"{GITHUB_API}/repos/{TARGET_OWNER}/{TARGET_REPO}/git/commits/{upstream_head_sha}",
        headers=pat_headers(),
        timeout=10,
    )
    if upstream_commit_resp.status_code != 200:
        return jsonify({"error": "Could not read upstream HEAD commit."}), 500

    upstream_tree_sha = upstream_commit_resp.json()["tree"]["sha"]

    # ------------------------------------------------------------------
    # 6. Create a blob on the FORK with our updated file content
    #    A blob is just a file object in git's object store.
    # ------------------------------------------------------------------
    blob_resp = requests.post(
        f"{GITHUB_API}/repos/{FORK_OWNER}/{TARGET_REPO}/git/blobs",
        headers=pat_headers(),
        json={
            "content":  base64.b64encode(updated_json_str.encode("utf-8")).decode("utf-8"),
            "encoding": "base64",
        },
        timeout=10,
    )
    if blob_resp.status_code != 201:
        return jsonify({"error": f"Could not create blob: {blob_resp.text}"}), 500

    blob_sha = blob_resp.json()["sha"]

    # ------------------------------------------------------------------
    # 7. Create a tree on the FORK
    #    base_tree = upstream's tree (all other files stay identical)
    #    We only override the one file we changed.
    # ------------------------------------------------------------------
    tree_resp = requests.post(
        f"{GITHUB_API}/repos/{FORK_OWNER}/{TARGET_REPO}/git/trees",
        headers=pat_headers(),
        json={
            "base_tree": upstream_tree_sha,   # inherit all files from upstream
            "tree": [
                {
                    "path": config_path,   # the one file we're changing
                    "mode": "100644",      # regular file
                    "type": "blob",
                    "sha":  blob_sha,      # our updated content
                }
            ],
        },
        timeout=10,
    )
    if tree_resp.status_code != 201:
        return jsonify({"error": f"Could not create tree: {tree_resp.text}"}), 500

    new_tree_sha = tree_resp.json()["sha"]

    # ------------------------------------------------------------------
    # 8. Create a commit on the FORK
    #    Parent = upstream's HEAD — this is what makes the diff clean.
    #    The PR will show exactly: new tree vs parent (upstream HEAD).
    # ------------------------------------------------------------------
    commit_resp = requests.post(
        f"{GITHUB_API}/repos/{FORK_OWNER}/{TARGET_REPO}/git/commits",
        headers=pat_headers(),
        json={
            "message": f"Add {name} to {canonical_section} on {canonical_network}",
            "tree":    new_tree_sha,
            "parents": [upstream_head_sha],   # parent is upstream HEAD, not fork main
        },
        timeout=10,
    )
    if commit_resp.status_code != 201:
        return jsonify({"error": f"Could not create commit: {commit_resp.text}"}), 500

    new_commit_sha = commit_resp.json()["sha"]

    # ------------------------------------------------------------------
    # 9. Create a branch on the FORK pointing at our new commit
    # ------------------------------------------------------------------
    safe_name     = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    random_suffix = secrets.token_hex(3)
    branch_name   = f"whitelist-{canonical_network.lower()}-{canonical_section.replace(' ', '-')}-{safe_name}-{random_suffix}"

    branch_resp = requests.post(
        f"{GITHUB_API}/repos/{FORK_OWNER}/{TARGET_REPO}/git/refs",
        headers=pat_headers(),
        json={
            "ref": f"refs/heads/{branch_name}",
            "sha": new_commit_sha,
        },
        timeout=10,
    )
    if branch_resp.status_code != 201:
        return jsonify({"error": f"Could not create branch: {branch_resp.text}"}), 500

    # ------------------------------------------------------------------
    # 10. Open the PR from fork:branch → upstream:main
    # ------------------------------------------------------------------
    pr_title = f"Whitelist {name} on {canonical_network}"
    pr_body  = f"Submitted by @{github_user} via the whitelist tool.\n\n"
    if is_rotation:
        pr_body += f"**Note:** `{member_key}` already exists in this section — this PR adds or rotates an IP.\n\n"
    pr_body += f"Approval: {approval}" if approval else "DevNet only."
    if comment:
        pr_body += f"\n\n{comment}"

    pr_resp = requests.post(
        f"{GITHUB_API}/repos/{TARGET_OWNER}/{TARGET_REPO}/pulls",
        headers=pat_headers(),
        json={
            "title": pr_title,
            "body":  pr_body,
            "head":  f"{FORK_OWNER}:{branch_name}",
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
