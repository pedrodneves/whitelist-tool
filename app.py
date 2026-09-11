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
    validators/inputs.py  — sanitising, validation, member-key and IP-list helpers

A single submission may cover several networks at once. Each network has its
own config file, and GitHub's tree API accepts a list of files, so DevNet,
TestNet and MainNet changes all land in ONE commit and ONE pull request.

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

from flask import Flask, request, jsonify
from flask_cors import CORS

from config import FLASK_SECRET_KEY, GITHUB_PAT
from auth.github import auth_bp, extract_token
from github.access import check_canton_membership
from github.pr import (
    config_path_for,
    read_upstream_config,
    get_existing_ips,
    apply_ip_changes,
    get_upstream_head,
    create_blob,
    create_tree,
    create_commit,
    create_branch,
    build_pr_body,
    open_pull_request,
    get_user_login,
)
from validators.inputs import (
    sanitize,
    is_valid_ip,
    resolve_network_and_section,
    resolve_network,
    build_member_key,
    normalise_ip_list,
    SECTIONS_WITHOUT_SPONSOR,
    NETWORKS_REQUIRING_APPROVAL,
)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY
CORS(app, origins="*", supports_credentials=False)

# Register the auth blueprint — mounts /auth/login, /auth/callback, /auth/user
app.register_blueprint(auth_bp)

# Networks are always processed and displayed in this order, whatever order
# the frontend happened to send them in
NETWORK_ORDER = ("DevNet", "TestNet", "MainNet")


# ---------------------------------------------------------------------------
# Request parsing helpers
# ---------------------------------------------------------------------------

def _sorted_networks(canonical_networks) -> list[str]:
    """Return the given networks in fixed DevNet → TestNet → MainNet order."""
    return [n for n in NETWORK_ORDER if n in canonical_networks]


def _parse_network_ips(data: dict) -> tuple[dict[str, list[str]], list[str]]:
    """
    Read the per-network IP lists out of a /api/submit payload.

    Expected shape:
        "networks": { "dev": ["1.2.3.4", "5.6.7.8"], "test": ["9.9.9.9"] }

    The older single-network shape ("network": "dev", "ip": "1.2.3.4") is
    still accepted so an outdated frontend keeps working.

    Returns:
        ({canonical_network: [ips]}, [error strings])
    """
    errors: list[str] = []
    result: dict[str, list[str]] = {}

    raw_networks = data.get("networks")

    # Fall back to the legacy flat shape when "networks" is absent
    if not raw_networks:
        legacy_network = sanitize(data.get("network", ""))
        legacy_ip      = sanitize(data.get("ip", ""))
        if legacy_network:
            raw_networks = {legacy_network: [legacy_ip] if legacy_ip else []}
        else:
            return {}, ["Select at least one network."]

    for network_alias, raw_ips in raw_networks.items():
        canonical_network = resolve_network(sanitize(str(network_alias)))
        if not canonical_network:
            errors.append(f"Invalid network '{network_alias}'. Use dev, test, or main.")
            continue

        ips = normalise_ip_list(raw_ips)
        if not ips:
            errors.append(f"No IP address given for {canonical_network}.")
            continue

        # Validate every address before doing any GitHub work
        for ip in ips:
            if not is_valid_ip(ip):
                errors.append(f"'{ip}' is not a valid IPv4 address ({canonical_network}).")

        result[canonical_network] = ips

    if not result and not errors:
        errors.append("Select at least one network.")

    return result, errors


# ---------------------------------------------------------------------------
# Duplicate org check
# ---------------------------------------------------------------------------

@app.route("/api/check", methods=["POST"])
def api_check():
    """
    Check whether an organisation already exists in the chosen section, for
    every network the user has selected.

    Called by the frontend as the form is filled in (debounced), so the user
    sees which networks already hold this entry before creating a PR.

    Request body (JSON):
        section  — e.g. "validators", "svs"
        name     — organisation name
        sponsor  — sponsor / NaaS provider name
        networks — list of aliases, e.g. ["dev", "test"]

    Response (JSON):
        {
          "member_key": "Acme / Digital-Asset",
          "any_exists": true,
          "results": [
            { "network": "DevNet",  "exists": true,  "existing_ips": ["1.2.3.4/32"] },
            { "network": "TestNet", "exists": false, "existing_ips": [] }
          ]
        }
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

    section = sanitize(data.get("section", ""))
    name    = sanitize(data.get("name",    ""))
    sponsor = sanitize(data.get("sponsor", ""))

    _, canonical_section = resolve_network_and_section("dev", section)
    if not canonical_section:
        return jsonify({"error": f"Invalid section '{section}'"}), 400
    if not name:
        return jsonify({"error": "Organisation name is required"}), 400

    # Accept a list of aliases, or the legacy single "network" string
    raw_networks = data.get("networks") or ([data.get("network")] if data.get("network") else [])
    canonical_networks = []
    for alias in raw_networks:
        canonical_network = resolve_network(sanitize(str(alias)))
        if canonical_network and canonical_network not in canonical_networks:
            canonical_networks.append(canonical_network)

    if not canonical_networks:
        return jsonify({"error": "Select at least one network."}), 400

    member_key = build_member_key(name, sponsor, canonical_section)

    results = []
    for canonical_network in _sorted_networks(canonical_networks):
        _, current_json = read_upstream_config(canonical_network)

        if current_json is None:
            # Upstream unreachable — report it without blocking the user
            results.append({
                "network":      canonical_network,
                "exists":       False,
                "existing_ips": [],
                "warning":      "Could not reach upstream to verify",
            })
            continue

        existing_ips = get_existing_ips(current_json, canonical_section, member_key)
        results.append({
            "network":      canonical_network,
            "exists":       len(existing_ips) > 0,
            "existing_ips": existing_ips,
        })

    return jsonify({
        "member_key": member_key,
        "any_exists": any(r["exists"] for r in results),
        "results":    results,
    })


# ---------------------------------------------------------------------------
# PR creation
# ---------------------------------------------------------------------------

@app.route("/api/submit", methods=["POST"])
def api_submit():
    """
    Create one clean commit and one PR covering every selected network.

    Validates inputs, checks access, applies the IP changes for each network
    in memory, then delegates every git step to github/pr.py.
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

    section  = sanitize(data.get("section",  ""))
    name     = sanitize(data.get("name",     ""))
    sponsor  = sanitize(data.get("sponsor",  ""))
    approval = sanitize(data.get("approval", ""))
    comment  = sanitize(data.get("comment",  ""))

    _, canonical_section = resolve_network_and_section("dev", section)
    network_ips, errors  = _parse_network_ips(data)

    if not canonical_section:
        errors.append(f"Invalid section '{section}'.")
    if not name:
        errors.append("Organisation name is required.")
    if canonical_section and canonical_section not in SECTIONS_WITHOUT_SPONSOR and not sponsor:
        errors.append("Sponsor is required for validators and read-only clients.")

    # One approval link covers the whole request, and is only needed when
    # TestNet or MainNet is among the selected networks
    needs_approval = any(n in NETWORKS_REQUIRING_APPROVAL for n in network_ips)
    if needs_approval:
        if not approval:
            errors.append("Approval link is required when TestNet or MainNet is selected.")
        elif not approval.startswith("http"):
            errors.append("Approval must be a valid URL.")

    if errors:
        return jsonify({"error": "\n".join(errors)}), 400

    # ------------------------------------------------------------------
    # 2. Resolve identifiers
    # ------------------------------------------------------------------
    github_user        = get_user_login(token)
    member_key         = build_member_key(name, sponsor, canonical_section)
    canonical_networks = _sorted_networks(network_ips)

    # ------------------------------------------------------------------
    # 3. Read each network's config and apply its IPs in memory
    # ------------------------------------------------------------------
    changed_files: list[tuple[str, str]] = []   # (config_path, updated_json_str)
    changes:       list[dict]            = []   # per-network summary for the PR body

    for canonical_network in canonical_networks:
        raw_json_str, current_json = read_upstream_config(canonical_network)
        if current_json is None:
            return jsonify({
                "error": f"Could not read {config_path_for(canonical_network)} from upstream."
            }), 500

        outcome = apply_ip_changes(
            current_json,
            raw_json_str,
            canonical_section,
            member_key,
            network_ips[canonical_network],
        )

        changes.append({
            "network":     canonical_network,
            "added":       outcome["added"],
            "skipped":     outcome["skipped"],
            "is_rotation": outcome["is_rotation"],
        })

        # A network with nothing new is simply left out of the commit
        if outcome["updated_json_str"] is not None:
            changed_files.append(
                (config_path_for(canonical_network), outcome["updated_json_str"])
            )

    # Every requested IP was already present — nothing to open a PR for
    if not changed_files:
        already = "; ".join(
            f"{c['network']}: {', '.join(c['skipped'])}" for c in changes if c["skipped"]
        )
        return jsonify({
            "error": (
                f"Every requested IP is already whitelisted for '{member_key}'. "
                f"No changes were made. ({already})"
            )
        }), 400

    # ------------------------------------------------------------------
    # 4. Get upstream HEAD (once — it is repo-level, not per network)
    # ------------------------------------------------------------------
    upstream_head_sha, upstream_tree_sha = get_upstream_head()
    if not upstream_head_sha:
        return jsonify({"error": "Could not read upstream main branch."}), 500

    # ------------------------------------------------------------------
    # 5. Create one blob per changed file
    # ------------------------------------------------------------------
    blobs: list[tuple[str, str]] = []   # (config_path, blob_sha)
    for config_path, updated_json_str in changed_files:
        blob_sha = create_blob(updated_json_str)
        if not blob_sha:
            return jsonify({"error": f"Could not create blob for {config_path}."}), 500
        blobs.append((config_path, blob_sha))

    # ------------------------------------------------------------------
    # 6. Create ONE tree holding every changed file
    # ------------------------------------------------------------------
    new_tree_sha = create_tree(upstream_tree_sha, blobs)
    if not new_tree_sha:
        return jsonify({"error": "Could not create tree on fork."}), 500

    # ------------------------------------------------------------------
    # 7. Create ONE commit
    # ------------------------------------------------------------------
    # Only the networks that actually changed belong in the commit message
    changed_networks = [
        c["network"] for c in changes
        if any(path == config_path_for(c["network"]) for path, _ in blobs)
    ]
    commit_message = (
        f"Add {name} to {canonical_section} on {', '.join(changed_networks)}"
    )

    new_commit_sha = create_commit(new_tree_sha, upstream_head_sha, commit_message)
    if not new_commit_sha:
        return jsonify({"error": "Could not create commit on fork."}), 500

    # ------------------------------------------------------------------
    # 8. Create ONE branch
    # ------------------------------------------------------------------
    branch_name = create_branch(new_commit_sha, name, changed_networks)
    if not branch_name:
        return jsonify({"error": "Could not create branch on fork."}), 500

    # ------------------------------------------------------------------
    # 9. Open ONE pull request
    # ------------------------------------------------------------------
    pr_title = f"Whitelist {name} on {', '.join(changed_networks)}"
    pr_body  = build_pr_body(github_user, approval, comment)

    pr_url = open_pull_request(branch_name, pr_title, pr_body)
    if not pr_url:
        return jsonify({"error": "Could not open pull request."}), 500

    return jsonify({
        "success":    True,
        "pr_url":     pr_url,
        "member_key": member_key,
        "changes":    changes,
    })


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
