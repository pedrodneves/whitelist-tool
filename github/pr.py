"""
github/pr.py — Pull request creation
======================================
Contains all GitHub Git Data API operations needed to produce a single
clean commit PR:

  1. Read the config file from upstream
  2. Apply the IP change in memory
  3. Get upstream HEAD SHA + tree SHA
  4. Create a blob on the fork
  5. Create a tree on the fork
  6. Create a commit on the fork (parent = upstream HEAD)
  7. Create a branch on the fork
  8. Open the PR from fork:branch → upstream:main

Keeping all git steps in one module makes the sequence easy to follow
and test independently from the Flask route layer.
"""

import re
import json
import base64
import secrets
import requests

from config import GITHUB_API, TARGET_OWNER, TARGET_REPO, FORK_OWNER
from github.headers import pat_headers, user_headers


def read_upstream_config(canonical_network: str) -> tuple[str, dict] | tuple[None, None]:
    """
    Fetch the allowed-ip-ranges.json for a given network from the upstream repo.

    Returns:
        (raw_json_str, parsed_dict) — the raw string is needed later for the
                                      byte-for-byte diff check; the dict for editing
        (None, None)                — if the file could not be fetched
    """
    config_path  = f"configs/{canonical_network}/allowed-ip-ranges.json"
    resp = requests.get(
        f"{GITHUB_API}/repos/{TARGET_OWNER}/{TARGET_REPO}/contents/{config_path}",
        headers=pat_headers(),
        timeout=10,
    )
    if resp.status_code != 200:
        return None, None

    raw_json_str = base64.b64decode(resp.json()["content"]).decode("utf-8")
    return raw_json_str, json.loads(raw_json_str)


def apply_ip_change(
    current_json:      dict,
    raw_json_str:      str,
    canonical_section: str,
    member_key:        str,
    ip:                str,
) -> tuple[str, bool] | tuple[None, str]:
    """
    Add the new IP to the correct member entry in the JSON dict.

    Args:
        current_json:      the parsed JSON dict from upstream
        raw_json_str:      the original raw string (used for the identity check)
        canonical_section: e.g. "validators", "svs"
        member_key:        e.g. "Fiews / Digital-Asset"
        ip:                bare IPv4 address e.g. "66.18.13.153"

    Returns:
        (updated_json_str, is_rotation) — on success
        (None, error_message)           — if the IP already exists or no change was made
    """
    section_data = current_json.setdefault(canonical_section, {})
    existing_ips = section_data.get(member_key, [])

    # Track whether the org already had IPs (used in the PR body)
    is_rotation = len(existing_ips) > 0

    new_ip_cidr = f"{ip}/32"

    # Abort early if the IP is already present — avoids an empty commit
    if new_ip_cidr in existing_ips:
        return None, (
            f"{new_ip_cidr} is already whitelisted for '{member_key}' "
            f"in this section. No changes were made."
        )

    existing_ips.append(new_ip_cidr)

    # Sort IPs numerically (so 10.0.0.2 comes before 10.0.0.10)
    existing_ips.sort(key=lambda x: [int(p) for p in x.split("/")[0].split(".")])
    section_data[member_key] = existing_ips

    # Sort members alphabetically (case-insensitive)
    current_json[canonical_section] = dict(
        sorted(section_data.items(), key=lambda x: x[0].lower())
    )

    # ensure_ascii=False preserves unicode characters (accented letters etc.)
    updated_json_str = json.dumps(current_json, indent=2, ensure_ascii=False) + "\n"

    # Safety net: if the result is byte-for-byte identical to what we read,
    # something went wrong — abort rather than push an empty commit
    if updated_json_str == raw_json_str:
        return None, (
            f"No changes detected after applying the update for '{member_key}'. "
            "The IP may already be present in the file. No PR was created."
        )

    return updated_json_str, is_rotation


def get_upstream_head(canonical_network: str) -> tuple[str, str] | tuple[None, None]:
    """
    Get the HEAD commit SHA and tree SHA from upstream/main.

    Our new commit will use upstream HEAD as its parent, making the PR diff
    show only our one change regardless of how stale the fork is.

    Returns:
        (head_sha, tree_sha) — on success
        (None, None)         — if the ref or commit could not be read
    """
    ref_resp = requests.get(
        f"{GITHUB_API}/repos/{TARGET_OWNER}/{TARGET_REPO}/git/ref/heads/main",
        headers=pat_headers(),
        timeout=10,
    )
    if ref_resp.status_code != 200:
        return None, None

    head_sha = ref_resp.json()["object"]["sha"]

    commit_resp = requests.get(
        f"{GITHUB_API}/repos/{TARGET_OWNER}/{TARGET_REPO}/git/commits/{head_sha}",
        headers=pat_headers(),
        timeout=10,
    )
    if commit_resp.status_code != 200:
        return None, None

    tree_sha = commit_resp.json()["tree"]["sha"]
    return head_sha, tree_sha


def create_blob(updated_json_str: str) -> str | None:
    """
    Create a git blob on the fork containing the updated JSON file content.

    A blob is simply a file object in git's object store. Returns the blob
    SHA on success, or None if creation failed.
    """
    resp = requests.post(
        f"{GITHUB_API}/repos/{FORK_OWNER}/{TARGET_REPO}/git/blobs",
        headers=pat_headers(),
        json={
            "content":  base64.b64encode(updated_json_str.encode("utf-8")).decode("utf-8"),
            "encoding": "base64",
        },
        timeout=10,
    )
    return resp.json()["sha"] if resp.status_code == 201 else None


def create_tree(upstream_tree_sha: str, config_path: str, blob_sha: str) -> str | None:
    """
    Create a git tree on the fork.

    Uses upstream's tree as the base so all other files stay identical.
    Only the one config file is overridden with our new blob.
    Returns the new tree SHA, or None on failure.
    """
    resp = requests.post(
        f"{GITHUB_API}/repos/{FORK_OWNER}/{TARGET_REPO}/git/trees",
        headers=pat_headers(),
        json={
            "base_tree": upstream_tree_sha,   # inherit all files from upstream
            "tree": [
                {
                    "path": config_path,  # the one file we're changing
                    "mode": "100644",     # regular file
                    "type": "blob",
                    "sha":  blob_sha,     # our updated content
                }
            ],
        },
        timeout=10,
    )
    return resp.json()["sha"] if resp.status_code == 201 else None


def create_commit(
    new_tree_sha:      str,
    upstream_head_sha: str,
    name:              str,
    canonical_section: str,
    canonical_network: str,
) -> str | None:
    """
    Create a git commit on the fork.

    The parent is upstream's HEAD — this is what makes the PR diff clean.
    Returns the new commit SHA, or None on failure.
    """
    resp = requests.post(
        f"{GITHUB_API}/repos/{FORK_OWNER}/{TARGET_REPO}/git/commits",
        headers=pat_headers(),
        json={
            "message": f"Add {name} to {canonical_section} on {canonical_network}",
            "tree":    new_tree_sha,
            "parents": [upstream_head_sha],  # parent = upstream HEAD, not fork main
        },
        timeout=10,
    )
    return resp.json()["sha"] if resp.status_code == 201 else None


def create_branch(new_commit_sha: str, name: str, canonical_network: str, canonical_section: str) -> str | None:
    """
    Create a branch on the fork pointing at our new commit.

    Branch name is slugified from the org name + network + section + a random
    suffix to avoid collisions. Returns the branch name on success, or None.
    """
    safe_name     = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    random_suffix = secrets.token_hex(3)
    branch_name   = (
        f"whitelist-{canonical_network.lower()}"
        f"-{canonical_section.replace(' ', '-')}"
        f"-{safe_name}-{random_suffix}"
    )

    resp = requests.post(
        f"{GITHUB_API}/repos/{FORK_OWNER}/{TARGET_REPO}/git/refs",
        headers=pat_headers(),
        json={
            "ref": f"refs/heads/{branch_name}",
            "sha": new_commit_sha,
        },
        timeout=10,
    )
    return branch_name if resp.status_code == 201 else None


def open_pull_request(
    branch_name:       str,
    name:              str,
    canonical_network: str,
    member_key:        str,
    is_rotation:       bool,
    github_user:       str,
    approval:          str,
    comment:           str,
) -> str | None:
    """
    Open a PR from fork:branch → upstream:main.

    Builds the PR title and body, then creates the PR via the GitHub API.
    Returns the PR URL on success, or None on failure.
    """
    pr_title = f"Whitelist {name} on {canonical_network}"
    pr_body  = f"Submitted by @{github_user} via the whitelist tool.\n\n"

    if is_rotation:
        pr_body += (
            f"**Note:** `{member_key}` already exists in this section — "
            "this PR adds or rotates an IP.\n\n"
        )

    pr_body += f"Approval: {approval}" if approval else "DevNet only."

    if comment:
        pr_body += f"\n\n{comment}"

    resp = requests.post(
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
    return resp.json().get("html_url") if resp.status_code in (200, 201) else None


def get_user_login(user_token: str) -> str:
    """
    Resolve a GitHub OAuth token to the user's login string.
    Returns the login, or "unknown" if the call fails.
    """
    resp = requests.get(
        f"{GITHUB_API}/user",
        headers=user_headers(user_token),
        timeout=10,
    )
    return resp.json().get("login", "unknown") if resp.status_code == 200 else "unknown"
