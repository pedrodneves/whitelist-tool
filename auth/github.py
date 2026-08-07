"""
auth/github.py — GitHub OAuth routes
======================================
Handles the full OAuth 2.0 flow:
  /auth/login    — redirects to GitHub's authorization page
  /auth/callback — exchanges the code for a token, redirects to the frontend
  /auth/user     — returns the logged-in user's GitHub profile

The token is passed back to the frontend in the URL fragment (#token=...)
so it is never sent to any server after the initial exchange.
"""

import secrets
import requests

from flask import Blueprint, request, jsonify, redirect, session

from config import GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, FRONTEND_URL, GITHUB_API, GITHUB_OAUTH, OAUTH_SCOPE
from github.headers import user_headers

# Register all auth routes under the /auth prefix
auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def extract_token() -> str | None:
    """
    Read the OAuth token from the Authorization: Bearer <token> header.
    Returns the token string, or None if the header is absent or malformed.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    return auth_header[len("Bearer "):]


@auth_bp.route("/login")
def login():
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


@auth_bp.route("/callback")
def callback():
    """
    Step 2 of OAuth — GitHub redirects here with ?code=...&state=...
    Verifies the state, exchanges the code for an access token, then
    redirects to the frontend with the token in the URL fragment.
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

    # Pass the token in the fragment — never hits any server after this point
    return redirect(f"{FRONTEND_URL}/#token={access_token}")


@auth_bp.route("/user")
def user():
    """Returns the logged-in user's GitHub profile for the topbar."""
    token = extract_token()
    if not token:
        return jsonify({"error": "Not authenticated"}), 401

    response = requests.get(f"{GITHUB_API}/user", headers=user_headers(token), timeout=10)
    if response.status_code != 200:
        return jsonify({"error": "GitHub API error"}), response.status_code

    github_user = response.json()
    return jsonify({
        "login":      github_user["login"],
        "avatar_url": github_user["avatar_url"],
        "name":       github_user.get("name", github_user["login"]),
    })
