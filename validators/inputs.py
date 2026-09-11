"""
validators/inputs.py — Input validation and sanitisation
==========================================================
All functions that validate, clean, or normalise user-supplied form data
live here. The route handlers in app.py call these before touching any
business logic.
"""

import re

# Sections where the member key is just the org name, with no sponsor suffix
SECTIONS_WITHOUT_SPONSOR = ("svs", "vpns")

# Networks that require an approval link before a PR may be opened
NETWORKS_REQUIRING_APPROVAL = ("TestNet", "MainNet")


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
        "validators":        "validators",
        "v":                 "validators",
        "svs":               "svs",
        "vpns":              "vpns",
        "read-only-clients": "read-only clients",
        "read-only":         "read-only clients",
    }
    return (
        network_map.get(network.lower()),
        section_map.get(section.lower()),
    )


def resolve_network(network: str) -> str | None:
    """
    Resolve a single network alias to its canonical form.
    Thin wrapper so callers that only need the network don't pass a dummy section.
    """
    canonical_network, _ = resolve_network_and_section(network, "validators")
    return canonical_network


def build_member_key(name: str, sponsor: str, canonical_section: str) -> str:
    """
    Build the exact dictionary key used inside allowed-ip-ranges.json.

    SVs and VPNs are keyed by the plain org name; validators and read-only
    clients are keyed as "Org Name / Sponsor". The same key must be produced
    by /api/check and /api/submit or duplicate detection silently breaks.
    """
    if canonical_section in SECTIONS_WITHOUT_SPONSOR:
        return name
    return f"{name} / {sponsor}" if sponsor else name


def normalise_ip_list(raw) -> list[str]:
    """
    Turn whatever the frontend sent into a clean, de-duplicated list of IPs.

    Accepts either a real list, or a single string containing several IPs
    separated by newlines, commas, semicolons, or spaces — so a user pasting
    a block of addresses into a textarea works without extra client code.
    Order is preserved; blanks and repeats are dropped.
    """
    if raw is None:
        return []

    # Flatten a string into candidate tokens; a list is already tokenised
    if isinstance(raw, str):
        candidates = re.split(r"[\s,;]+", raw)
    else:
        candidates = []
        for item in raw:
            candidates.extend(re.split(r"[\s,;]+", str(item)))

    cleaned: list[str] = []
    for candidate in candidates:
        # Tolerate a pasted /32 suffix — the backend adds it itself
        ip = sanitize(candidate).removesuffix("/32")
        if ip and ip not in cleaned:
            cleaned.append(ip)

    return cleaned
