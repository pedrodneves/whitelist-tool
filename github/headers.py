"""
github/headers.py — GitHub API request headers
================================================
Centralises the two header patterns used throughout the app:
  - pat_headers()  → server-side PAT for repo operations
  - user_headers() → user's OAuth token for identity checks
"""

from config import GITHUB_PAT


def pat_headers() -> dict:
    """
    Headers using the server-side PAT.
    Used for all GitHub API calls that operate on repos (read files, create
    blobs, trees, commits, branches, PRs, and team membership lookups).
    """
    return {
        "Authorization": f"Bearer {GITHUB_PAT}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def user_headers(token: str) -> dict:
    """
    Headers using the authenticated user's OAuth token.
    Used only to identify who the user is (GET /user) — not for repo writes.
    """
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
