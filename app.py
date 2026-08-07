#!/usr/bin/env python3
"""
app.py — Whitelist Tool entry point
=====================================
This file wires together the Flask app and registers routes.
All business logic lives in the modules below:

    config.py             — environment variables and constants
    auth/github.py        — OAuth login / callback / user profile routes
    github/access.py      — teams.tf fetch and canton membership check
    github/pr.py          — all Git Data API operations (blob → tree → commit → branch → PR)
    validators/inputs.py  — sanitize(), is_valid_ip(), resolve_network_and_section()

Environment variables (set on Render / AWS):
    GITHUB_CLIENT_ID      — from your GitHub OAuth App
    GITHUB_CLIENT_SECRET  — from your GitHub OAuth App
    GITHUB_PAT            — Personal Access Token with repo scope
    FRONTEND_URL          — https://pedrodneves.github.io/whitelist-tool
    TARGET_REPO_OWNER     — canton-foundation
    TARGET_REPO_NAME      — configs-private
    FORK_OWNER            — pedrodneves
    FLASK_SECRET_KEY      — long random string for signing sessions
"""

import json
import base64
import requests

from flask import Flask, request, jsonify
from flask_cors import CORS

from config import FLASK_SECRET_KEY, GITHUB_PAT, TARGET_OWNER, TARGET_REPO
from auth.github import auth_bp, extract_token
from github.access import check_canton_membership
from github.headers import pat_headers
from github.pr import (
    read_upstream_config,
    apply_ip_change,
    get_upstream_head,
    create_blob,
    create_tree,
    create_commit,
    create_branch,
    open_pull_request,
    get_user_login,
)
from validators.inputs import sanitize, is_valid_ip, resolve_network_and_section

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY
CORS(app, origins="*", supports_credentials=False)

# Register the auth blueprint — mounts /auth/login, /auth/callback, /auth/user
app.register_blueprint(auth_bp)


# ---------------------------------------------------------------------------
# Duplicate org check
# ---------------------------------------------------------------------------

@app.route("/api/check", methods=["POST"])
def api_check():
    """
    Check whether an organisation already exists in a given network + section
    of the upstream JSON file.

    Called by the frontend on every keypress in the org name field (debounced)
    so the user sees a warning before they attempt to create a PR.

    Request body (JSON):
        network  — e.g. "dev", "test", "main"
        section  — e.g. "validators", "svs"
        name     — organisation name to check
        sponsor  — sponsor / NaaS provider name

    Response (JSON):
        { "exists": true/false, "member_key": "..." }
        { "error": "..." }
    """
    token = extract_token()
    if not token:
        return jsonify({"error": "Not authenticated"}), 401

    is_member, reason = check_canton_membership(token)
    if not is_member:
        return jsonify({"error": reason}), 403

    data = request.get_json()
    if not data:
        return jsonify({"error": "No data received"}), 400

    network = sanitize(data.get("network", ""))
    section = sanitize(data.get("section", ""))
    name    = sanitize(data.get("name",    ""))
    sponsor = sanitize(data.get("sponsor", ""))

    canonical_network, canonical_section = resolve_network_and_section(network, section)

    if not canonical_network:
        return jsonify({"error": f"Invalid network '{network}'"}), 400
    if not canonical_section:
        return jsonify({"error": f"Invalid section '{section}'"}), 400
    if not name:
        return jsonify({"error": "Organisation name is required"}), 400

    config_path = f"configs/{canonical_network}/allowed-ip-ranges.json"

    # Fetch the file from upstream — use the PAT directly here since we only need the content
    upstream_resp = requests.get(
        f"https://api.github.com/repos/{TARGET_OWNER}/{TARGET_REPO}/contents/{config_path}",
        headers=pat_headers(),
        timeout=10,
    )
    if upstream_resp.status_code != 200:
        return jsonify({"exists": False, "warning": "Could not reach upstream to verify"})

    raw_json_str = base64.b64decode(upstream_resp.json()["content"]).decode("utf-8")
    current_json = json.loads(raw_json_str)

    # Build the member key the same way /api/submit does
    member_key = name if canonical_section in ("svs", "vpns") else (
        f"{name} / {sponsor}" if sponsor else name
    )

    section_data = current_json.get(canonical_section, {})
    exists       = member_key in section_data

    return jsonify({"exists": exists, "member_key": member_key})


# ---------------------------------------------------------------------------
# PR creation
# ---------------------------------------------------------------------------

@app.route("/api/submit", methods=["POST"])
def api_submit():
    """
    Create a clean single-commit PR using GitHub's low-level Git Data API.

    Validates inputs, checks access, then delegates every git step to
    github/pr.py. Returns the PR URL on success.
    """
    token = extract_token()
    if not token:
        return jsonify({"error": "Not authenticated"}), 401
    if not GITHUB_PAT:
        return jsonify({"error": "Server is missing GITHUB_PAT environment variable."}), 500

    is_member, reason = check_canton_membership(token)
    if not is_member:
        return jsonify({"error": reason}), 403

    # ------------------------------------------------------------------
    # 1. Validate and sanitize inputs
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

    canonical_network, canonical_section = resolve_network_and_section(network, section)

    errors = []
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
    # 2. Resolve identifiers
    # ------------------------------------------------------------------
    github_user = get_user_login(token)
    member_key  = name if canonical_section in ("svs", "vpns") else f"{name} / {sponsor}"
    config_path = f"configs/{canonical_network}/allowed-ip-ranges.json"

    # ------------------------------------------------------------------
    # 3. Read upstream config
    # ------------------------------------------------------------------
    raw_json_str, current_json = read_upstream_config(canonical_network)
    if current_json is None:
        return jsonify({"error": f"Could not read {config_path} from upstream."}), 500

    # ------------------------------------------------------------------
    # 4. Apply IP change in memory
    # ------------------------------------------------------------------
    updated_json_str, result = apply_ip_change(
        current_json, raw_json_str, canonical_section, member_key, ip
    )
    if updated_json_str is None:
        # result holds the error message when updated_json_str is None
        return jsonify({"error": result}), 400

    is_rotation = result  # apply_ip_change returns (str, bool) on success

    # ------------------------------------------------------------------
    # 5. Get upstream HEAD
    # ------------------------------------------------------------------
    upstream_head_sha, upstream_tree_sha = get_upstream_head(canonical_network)
    if not upstream_head_sha:
        return jsonify({"error": "Could not read upstream main branch."}), 500

    # ------------------------------------------------------------------
    # 6. Create blob
    # ------------------------------------------------------------------
    blob_sha = create_blob(updated_json_str)
    if not blob_sha:
        return jsonify({"error": "Could not create blob on fork."}), 500

    # ------------------------------------------------------------------
    # 7. Create tree
    # ------------------------------------------------------------------
    new_tree_sha = create_tree(upstream_tree_sha, config_path, blob_sha)
    if not new_tree_sha:
        return jsonify({"error": "Could not create tree on fork."}), 500

    # ------------------------------------------------------------------
    # 8. Create commit
    # ------------------------------------------------------------------
    new_commit_sha = create_commit(
        new_tree_sha, upstream_head_sha, name, canonical_section, canonical_network
    )
    if not new_commit_sha:
        return jsonify({"error": "Could not create commit on fork."}), 500

    # ------------------------------------------------------------------
    # 9. Create branch
    # ------------------------------------------------------------------
    branch_name = create_branch(new_commit_sha, name, canonical_network, canonical_section)
    if not branch_name:
        return jsonify({"error": "Could not create branch on fork."}), 500

    # ------------------------------------------------------------------
    # 10. Open PR
    # ------------------------------------------------------------------
    pr_url = open_pull_request(
        branch_name, name, canonical_network, member_key,
        is_rotation, github_user, approval, comment
    )
    if not pr_url:
        return jsonify({"error": "Could not open pull request."}), 500

    return jsonify({"success": True, "pr_url": pr_url})


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.route("/health")
def health():
    """Returns 200 OK — used by Render / AWS to confirm the server is alive."""
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Backend running on http://localhost:8000")
    app.run(host="0.0.0.0", port=8000, debug=True)
