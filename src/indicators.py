"""Indicator data model and ingestion for the offline IOC investigation tool.

An Indicator is a single threat indicator (domain, ip, hash, url, email) tagged
with where it came from and what a source called it. This module only reads the
vendored local data files (data/infoblox_indicators.csv and data/campaigns/*.json)
and classifies indicator strings by format. It makes no network calls and needs
no API keys; everything it knows comes from the CSV, the MISP JSON files, and
regex/length rules applied to the indicator string itself.

WHAT THIS IS NOT
    Not a live feed reader and not a reputation service. It does not fetch
    anything from infoblox, VirusTotal, or any other API. The "infoblox" source
    name on an Indicator just means the row came from the vendored infoblox CSV
    or the vendored infoblox MISP exports, not that the tool talked to infoblox.
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path

# Resolve data paths relative to this file so the tool works from any cwd.
_SRC_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SRC_DIR.parent
DEFAULT_INFOBLOX_CSV = _PROJECT_ROOT / "data" / "infoblox_indicators.csv"
DEFAULT_CAMPAIGNS_DIR = _PROJECT_ROOT / "data" / "campaigns"

# The itype values this tool assigns. Anything that does not match a known
# format falls into "unknown" rather than being guessed at.
ITYPES = ("ip", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email", "unknown")

# MISP attribute type strings seen in the vendored campaign files, mapped to
# the itype vocabulary above. Anything not in this table is passed through
# detect_type() on the raw value instead.
_MISP_TYPE_MAP = {
    "domain": "domain",
    "ip-dst": "ip",
    "ip-src": "ip",
    "sha256": "sha256",
    "sha1": "sha1",
    "md5": "md5",
    "url": "url",
    "email-src": "email",
    "email-dst": "email",
}


@dataclass(frozen=True)
class Indicator:
    """One threat indicator, as reported by one source."""

    value: str
    itype: str              # ip / ipv6 / domain / url / md5 / sha1 / sha256 / email / unknown
    classification: str     # malicious / suspicious / phishing / etc, or "unknown"
    source: str              # where this row came from, e.g. "infoblox", "infoblox-misp"
    first_seen: str          # ISO date string, or "" if not known
    campaign: str            # campaign name from a MISP event, or "" if not part of one
    tags: tuple[str, ...]    # free-text tags carried over from the source


# --- format detection ---------------------------------------------------

_IPV4_RE = re.compile(
    r"^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$"
)
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", re.I)
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def _is_ipv6(value: str) -> bool:
    """A plain-stdlib IPv6 check without importing the ipaddress module's own
    error handling into the caller. Uses ipaddress under the hood."""
    import ipaddress

    try:
        ipaddress.IPv6Address(value)
        return True
    except ValueError:
        return False


def detect_type(value: str) -> str:
    """Classify a raw indicator string by its FORMAT, not by any external lookup.

    Order matters: hashes are checked by exact hex length before anything else,
    since a 64-char hex string would otherwise look like nothing else here.
    """
    v = value.strip()
    if not v:
        return "unknown"

    if _IPV4_RE.match(v):
        return "ip"
    if _is_ipv6(v):
        return "ipv6"
    if _MD5_RE.match(v):
        return "md5"
    if _SHA1_RE.match(v):
        return "sha1"
    if _SHA256_RE.match(v):
        return "sha256"
    if _EMAIL_RE.match(v):
        return "email"
    if _URL_RE.match(v):
        return "url"
    if _DOMAIN_RE.match(v):
        return "domain"
    return "unknown"


# --- defang / refang -----------------------------------------------------

# Standard analyst-hygiene substitutions, applied in a fixed order so defang
# and refang stay exact inverses of each other.
_DEFANG_PAIRS = (
    ("http://", "hxxp://"),
    ("https://", "hxxps://"),
    ("ftp://", "fxp://"),
    ("@", "[at]"),
    (".", "[.]"),
)


def defang(value: str) -> str:
    """Turn a live indicator into a safe-to-paste, non-clickable form."""
    out = value
    for live, defanged in _DEFANG_PAIRS:
        out = out.replace(live, defanged)
    return out


def refang(value: str) -> str:
    """Reverse defang(): turn a defanged indicator back into its live form."""
    out = value
    for live, defanged in reversed(_DEFANG_PAIRS):
        out = out.replace(defanged, live)
    return out


# --- ingestion -------------------------------------------------------------

def load_infoblox(path: Path = DEFAULT_INFOBLOX_CSV) -> tuple[Indicator, ...]:
    """Read the vendored infoblox_indicators.csv into Indicators.

    Columns are type,indicator,classification,detected_date. The csv's own
    "type" column is trusted as the itype (it already says domain/ip); no
    campaign or tags exist at this level so those are left empty.
    """
    out = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            itype = row["type"].strip().lower()
            if itype not in ITYPES:
                itype = detect_type(row["indicator"])
            out.append(
                Indicator(
                    value=row["indicator"],
                    itype=itype,
                    classification=row["classification"].strip().lower() or "unknown",
                    source="infoblox",
                    first_seen=row["detected_date"].strip(),
                    campaign="",
                    tags=(),
                )
            )
    return tuple(out)


def load_campaigns(dir_path: Path = DEFAULT_CAMPAIGNS_DIR) -> tuple[Indicator, ...]:
    """Read every MISP-format campaign file in dir_path into Indicators.

    Each file holds one Event with a name (info), a list of Tag, and a list
    of Attribute. Every Attribute becomes one Indicator carrying the event's
    name as campaign and the event's tag names as tags. These campaign files
    do not carry a classification field the way the infoblox CSV does, so
    classification is left "unknown" here; campaign membership itself is the
    signal this source contributes.
    """
    out = []
    for fpath in sorted(Path(dir_path).glob("*.json")):
        with open(fpath, encoding="utf-8") as f:
            data = json.load(f)
        event = data.get("Event", {})
        campaign_name = event.get("info", "")
        tag_names = tuple(t.get("name", "") for t in event.get("Tag", []) if t.get("name"))
        for attr in event.get("Attribute", []):
            raw_type = attr.get("type", "")
            value = attr.get("value", "")
            itype = _MISP_TYPE_MAP.get(raw_type)
            if itype is None:
                itype = detect_type(value)
            first_seen = attr.get("first_seen", "") or ""
            # first_seen in these files is an ISO timestamp with a time part;
            # keep just the date portion to match the infoblox csv's format.
            if "T" in first_seen:
                first_seen = first_seen.split("T", 1)[0]
            out.append(
                Indicator(
                    value=value,
                    itype=itype,
                    classification="unknown",
                    source="infoblox-misp",
                    first_seen=first_seen,
                    campaign=campaign_name,
                    tags=tag_names,
                )
            )
    return tuple(out)
