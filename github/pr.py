"""
github/pr.py — Pull request creation
======================================
Contains all GitHub Git Data API operations needed to produce a single
clean commit that can touch SEVERAL config files at once.

Why one commit can cover several networks:
    Each network has its own file (configs/DevNet/allowed-ip-ranges.json,
    configs/TestNet/..., configs/MainNet/...). GitHub's "create tree" API
    accepts a LIST of file entries, so we can override all three files in
    a single tree, wrap that tree in a single commit, and open one PR.

The flow:
  1. Read each selected network's config file from upstream
  2. Apply all requested IPs for that network in memory
  3. Get upstream HEAD SHA + tree SHA (once, repo-level)
  4. Create one blob per changed file
  5. Create ONE tree listing every changed file
  6. Create ONE commit (parent = upstream HEAD)
  7. Create ONE branch
  8. Open ONE PR from fork:branch → upstream:main
"""

import re
import json
import base64
import secrets
import requests

from config import GITHUB_API, TARGET_OWNER, TARGET_REPO, FORK_OWNER
from github.headers import pat_headers, user_headers


def config_path_for(canonical_network: str) -> str:
    """
    Build the repo path of the allowed-IP file for a network.
    Kept in one place so every module spells the path identically.
    """
    return f"configs/{canonical_network}/allowed-ip-ranges.json"


def read_upstream_config(canonical_network: str) -> tuple[str, dict] | tuple[None, None]:
    """
    Fetch the allowed-ip-ranges.json for a given network from the upstream repo.

    Returns:
        (raw_json_str, parsed_dict) — the raw string is kept for the
                                      byte-for-byte diff check; the dict for editing
        (None, None)                — if the file could not be fetched
    """
    resp = requests.get(
        f"{GITHUB_API}/repos/{TARGET_OWNER}/{TARGET_REPO}/contents/{config_path_for(canonical_network)}",
        headers=pat_headers(),
        timeout=10,
    )
    if resp.status_code != 200:
        return None, None

    raw_json_str = base64.b64decode(resp.json()["content"]).decode("utf-8")
    return raw_json_str, json.loads(raw_json_str)


def get_existing_ips(current_json: dict, canonical_section: str, member_key: str) -> list[str]:
    """
    Return the IPs already whitelisted for a member in a section.
    Empty list if the member is not present at all.
    Used by /api/check to tell the user what is already there.
    """
    return current_json.get(canonical_section, {}).get(member_key, [])


def apply_ip_changes(
    current_json:      dict,
    raw_json_str:      str,
    canonical_section: str,
    member_key:        str,
    ips:               list[str],
) -> dict:
    """
    Add one or more IPs to a member entry in a single network's JSON.

    Every IP already present is skipped rather than treated as an error —
    a request for three IPs where one already exists should still add the
    other two.

    Args:
        current_json:      parsed JSON dict for this network (mutated in place)
        raw_json_str:      the original raw string, for the no-change check
        canonical_section: e.g. "validators", "svs"
        member_key:        e.g. "Acme / Digital-Asset"
        ips:               bare IPv4 addresses, e.g. ["66.18.13.153", "10.0.0.1"]

    Returns a dict:
        {
          "updated_json_str": str | None,  # None when nothing changed
          "added":            [str],       # IPs written, in CIDR form
          "skipped":          [str],       # IPs already present, in CIDR form
          "is_rotation":      bool,        # member already had IPs before this change
        }
    """
    section_data = current_json.setdefault(canonical_section, {})
    existing_ips = section_data.get(member_key, [])

    # The member already having IPs is what makes this a rotation/addition
    is_rotation = len(existing_ips) > 0

    added:   list[str] = []
    skipped: list[str] = []

    for ip in ips:
        new_ip_cidr = f"{ip}/32"
        if new_ip_cidr in existing_ips:
            skipped.append(new_ip_cidr)
            continue
        existing_ips.append(new_ip_cidr)
        added.append(new_ip_cidr)

    # Nothing new for this network — leave the file untouched
    if not added:
        return {
            "updated_json_str": None,
            "added":            [],
            "skipped":          skipped,
            "is_rotation":      is_rotation,
        }

    # Sort IPs numerically (so 10.0.0.2 comes before 10.0.0.10)
    existing_ips.sort(key=lambda x: [int(p) for p in x.split("/")[0].split(".")])
    section_data[member_key] = existing_ips

    # Sort members alphabetically (case-insensitive)
    current_json[canonical_section] = dict(
        sorted(section_data.items(), key=lambda x: x[0].lower())
    )

    # ensure_ascii=False preserves unicode characters (accented letters etc.)
    updated_json_str = json.dumps(current_json, indent=2, ensure_ascii=False) + "\n"

    # Safety net: an identical result would produce an empty commit
    if updated_json_str == raw_json_str:
        return {
            "updated_json_str": None,
            "added":            [],
            "skipped":          skipped + added,
            "is_rotation":      is_rotation,
        }

    return {
        "updated_json_str": updated_json_str,
        "added":            added,
        "skipped":          skipped,
        "is_rotation":      is_rotation,
    }


def get_upstream_head() -> tuple[str, str] | tuple[None, None]:
    """
    Get the HEAD commit SHA and tree SHA from upstream/main.

    Repo-level, so it is fetched once no matter how many networks are
    being changed. Our commit uses this SHA as its parent, which keeps the
    PR diff limited to our own changes however stale the fork is.

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

    return head_sha, commit_resp.json()["tree"]["sha"]


def create_blob(updated_json_str: str) -> str | None:
    """
    Create a git blob on the fork containing one file's updated content.
    Called once per changed network file. Returns the blob SHA, or None.
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


def create_tree(upstream_tree_sha: str, files: list[tuple[str, str]]) -> str | None:
    """
    Create a single git tree on the fork covering EVERY changed file.

    Args:
        upstream_tree_sha: base tree — all untouched files stay identical
        files:             list of (config_path, blob_sha) pairs, one per
                           network whose file actually changed

    Returns the new tree SHA, or None on failure.
    """
    resp = requests.post(
        f"{GITHUB_API}/repos/{FORK_OWNER}/{TARGET_REPO}/git/trees",
        headers=pat_headers(),
        json={
            "base_tree": upstream_tree_sha,   # inherit everything from upstream
            "tree": [
                {
                    "path": path,       # one entry per changed file
                    "mode": "100644",   # regular file
                    "type": "blob",
                    "sha":  blob_sha,   # that file's updated content
                }
                for path, blob_sha in files
            ],
        },
        timeout=10,
    )
    return resp.json()["sha"] if resp.status_code == 201 else None


def create_commit(new_tree_sha: str, upstream_head_sha: str, message: str) -> str | None:
    """
    Create one git commit on the fork holding all file changes.

    The parent is upstream's HEAD — this is what keeps the PR diff clean.
    Returns the new commit SHA, or None on failure.
    """
    resp = requests.post(
        f"{GITHUB_API}/repos/{FORK_OWNER}/{TARGET_REPO}/git/commits",
        headers=pat_headers(),
        json={
            "message": message,
            "tree":    new_tree_sha,
            "parents": [upstream_head_sha],  # parent = upstream HEAD, not fork main
        },
        timeout=10,
    )
    return resp.json()["sha"] if resp.status_code == 201 else None


def create_branch(new_commit_sha: str, name: str, canonical_networks: list[str]) -> str | None:
    """
    Create a branch on the fork pointing at our new commit.

    The branch name carries the org slug and every network touched, plus a
    random suffix so repeat submissions never collide.
    Returns the branch name on success, or None.
    """
    safe_name     = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    networks_slug = "-".join(n.lower() for n in canonical_networks)
    random_suffix = secrets.token_hex(3)
    branch_name   = f"whitelist-{networks_slug}-{safe_name}-{random_suffix}"

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


def build_pr_body(github_user: str, approval: str, comment: str) -> str:
    """
    Compose the PR description.

    Deliberately minimal — the diff already shows exactly which files and
    IPs changed, so the body only carries what the diff cannot: who
    submitted it, the approval link, and the reason if one was given.

    Args:
        github_user: the submitter's GitHub login
        approval:    approval URL, or "" for DevNet-only requests
        comment:     free-text reason from the submitter, or ""

    Returns the full markdown body.
    """
    body = f"Submitted by @{github_user} via the whitelist tool.\n\n"

    body += f"Approval: {approval}\n" if approval else "DevNet only.\n"

    # Render the reason as a GitHub blockquote so it stands out from the rest
    if comment:
        body += f'\n> Reason: "{comment}"\n'

    return body


def open_pull_request(branch_name: str, title: str, body: str) -> str | None:
    """
    Open a PR from fork:branch → upstream:main.
    Returns the PR URL on success, or None on failure.
    """
    resp = requests.post(
        f"{GITHUB_API}/repos/{TARGET_OWNER}/{TARGET_REPO}/pulls",
        headers=pat_headers(),
        json={
            "title": title,
            "body":  body,
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
