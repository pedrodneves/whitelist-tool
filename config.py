"""
config.py — Centralised configuration
======================================
All environment variables and shared constants live here.
Every other module imports from this file — nothing reads os.environ directly.
"""

import os
import secrets
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# GitHub OAuth app credentials
# ---------------------------------------------------------------------------
GITHUB_CLIENT_ID     = os.environ["GITHUB_CLIENT_ID"]
GITHUB_CLIENT_SECRET = os.environ["GITHUB_CLIENT_SECRET"]

# ---------------------------------------------------------------------------
# GitHub API
# ---------------------------------------------------------------------------
GITHUB_PAT   = os.environ.get("GITHUB_PAT", "")
GITHUB_API   = "https://api.github.com"
GITHUB_OAUTH = "https://github.com/login/oauth"
OAUTH_SCOPE  = "read:user"

# ---------------------------------------------------------------------------
# Repo targets
# ---------------------------------------------------------------------------
TARGET_OWNER = os.environ.get("TARGET_REPO_OWNER", "canton-foundation")
TARGET_REPO  = os.environ.get("TARGET_REPO_NAME",  "configs-private")
FORK_OWNER   = os.environ.get("FORK_OWNER", "pedrodneves")

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
FRONTEND_URL     = os.environ.get("FRONTEND_URL", "http://localhost:8080")
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
