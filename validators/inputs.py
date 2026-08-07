"""
validators/inputs.py — Input validation and sanitisation
==========================================================
All functions that validate or clean user-supplied form data live here.
The route handlers in app.py call these before touching any business logic.
"""

import re


def sanitize(text: str) -> str:
    """
    Strip leading/trailing whitespace and remove characters that could
    cause injection issues or corrupt the JSON output.
    """
    dangerous = ['"', "'", "`", ";", "&", "|", "$", "(", ")", "<", ">", "\n", "\r"]
    cleaned = text.strip()
    for char in dangerous:
        cleaned = cleaned.replace(char, "")
    return cleaned


def is_valid_ip(ip: str) -> bool:
    """
    Return True if the string is a valid IPv4 address (four octets, each 0-255).
    """
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(part) <= 255 for part in ip.split("."))


def resolve_network_and_section(network: str, section: str) -> tuple[str | None, str | None]:
    """
    Map user-supplied network and section strings to their canonical forms.

    Accepts common aliases (e.g. "dev" → "DevNet", "main" → "MainNet") so the
    frontend can send short values and the backend always works with exact strings.

    Returns:
        (canonical_network, canonical_section) — both resolved
        (None, ...)  or  (..., None)           — if either value is unrecognised
    """
    network_map = {
        "dev":     "DevNet",  "devnet":  "DevNet",
        "test":    "TestNet", "testnet": "TestNet",
        "main":    "MainNet", "mainnet": "MainNet",
    }
    section_map = {
        "validators":     "validators",
        "v":              "validators",
        "svs":            "svs",
        "vpns":           "vpns",
        "read-only-clients": "read-only clients",
        "read-only":         "read-only clients",
    }
    return (
        network_map.get(network.lower()),
        section_map.get(section.lower()),
    )
