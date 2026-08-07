"""
github/access.py — Access control
===================================
Fetches the sv-ops and admins team member lists live from the Terraform
source of truth (canton-foundation/github/org/teams.tf) and checks whether
a given GitHub user is authorised to use the whitelist tool.

No hardcoded allowlist — access changes take effect the moment teams.tf
is updated in the repo, with no redeployment needed.
"""

import re
import base64
import requests

from config import GITHUB_API
from github.headers import pat_headers, user_headers


def fetch_allowed_users() -> set[str] | None:
    """
    Fetch org/teams.tf from canton-foundation/github and parse out every
    GitHub username listed under the 'sv-ops' and 'admins' team blocks.

    Returns a lowercase set of allowed usernames, or None if the file
    could not be fetched.

    Parsing strategy: locate each team block by its header string, extract
    the members = [ ... ] list within it, then pull all quoted identifiers.
    No full HCL parser needed — the file format is consistent and we only
    care about the two member lists.
    """
    resp = requests.get(
        f"{GITHUB_API}/repos/canton-foundation/github/contents/org/teams.tf",
        headers=pat_headers(),
        timeout=10,
    )
    if resp.status_code != 200:
        return None

    # GitHub returns file contents base64-encoded
    raw = base64.b64decode(resp.json()["content"]).decode("utf-8")

    allowed = set()

    for team_name in ("sv-ops", "admins"):
        # Find the opening of this team block e.g. "sv-ops" = {
        block_start = raw.find(f'"{team_name}"')
        if block_start == -1:
            continue

        # Find the members = [ ... ] list within this block
        members_start = raw.find("members = [", block_start)
        if members_start == -1:
            continue

        # Find the closing bracket of the members list
        members_end = raw.find("]", members_start)
        if members_end == -1:
            continue

        # Extract all quoted strings — GitHub usernames are alphanumeric + hyphens + dots
        members_block = raw[members_start:members_end]
        usernames = re.findall(r'"([A-Za-z0-9][A-Za-z0-9\-.]+)"', members_block)
        allowed.update(u.lower() for u in usernames)

    return allowed


def check_canton_membership(user_token: str) -> tuple[bool, str]:
    """
    Verify the authenticated user appears in the sv-ops or admins team in
    canton-foundation/github/org/teams.tf — the Terraform source of truth.

    Args:
        user_token: the user's GitHub OAuth access token

    Returns:
        (True,  "")        — username found in an allowed team
        (False, "reason")  — not found, or teams.tf could not be fetched
    """
    # Step 1: resolve the user's GitHub login from their own OAuth token
    user_resp = requests.get(
        f"{GITHUB_API}/user",
        headers=user_headers(user_token),
        timeout=10,
    )
    if user_resp.status_code != 200:
        return False, "Could not retrieve your GitHub profile."

    login = user_resp.json().get("login")
    if not login:
        return False, "Could not determine your GitHub username."

    # Step 2: fetch the live allowlist from teams.tf
    allowed_users = fetch_allowed_users()

    if allowed_users is None:
        # Fail closed — deny access rather than accidentally letting anyone through
        return False, (
            "Could not fetch the authorised user list from canton-foundation/github. "
            "Please try again in a moment."
        )

    # Step 3: case-insensitive check (GitHub usernames are case-insensitive)
    if login.lower() in allowed_users:
        return True, ""

    return False, (
        f"@{login} is not listed in the canton-foundation sv-ops or admins team. "
        "Access is restricted to members of those teams only."
    )
