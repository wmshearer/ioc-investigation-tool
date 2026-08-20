"""Offline enrichment for indicators: domain features, a DGA heuristic, and ASN lookup.

Everything here runs against data already on disk. Domain features and the DGA
score are computed from the string itself with plain arithmetic. ASN lookup
reads the vendored data/ip2asn-v4.tsv.gz once and answers from memory with a
binary search. No network calls, no external services.

WHAT THIS IS NOT
    dga_score is a HEURISTIC, not a trained classifier. It combines a handful
    of surface features (entropy, digit ratio, length, dictionary-word check)
    into a single 0..1 number that tends to separate algorithmically generated
    domains from ordinary ones on this data set. It has not been fit to
    labelled DGA data and should not be read as a calibrated probability.
    Reverse-DNS names in the .arpa namespace score 0.0: they are legitimate DNS
    structure, not generated domains, and scoring them as DGA-like was a bug the
    exclusion fixes.
"""

from __future__ import annotations

import bisect
import csv
import gzip
import math
from ipaddress import IPv4Address
from pathlib import Path

from src.indicators import Indicator

_SRC_DIR = Path(__file__).resolve().parent
DEFAULT_ASN_TABLE = _SRC_DIR.parent / "data" / "ip2asn-v4.tsv.gz"

# A small bundled dictionary for the "looks like a real word" check inside
# dga_score. This is intentionally tiny: it is not trying to be a wordlist,
# just enough common English fragments and TLDs that ordinary brand and
# service domains do not get flagged as algorithmic.
_COMMON_WORDS = frozenset(
    {
        "the", "and", "for", "you", "your", "with", "this", "that", "from",
        "mail", "news", "shop", "store", "app", "web", "home", "blog",
        "help", "support", "login", "account", "secure", "bank", "cloud",
        "media", "group", "world", "global", "online", "service", "team",
        "google", "microsoft", "apple", "amazon", "facebook", "office",
    }
)
_COMMON_TLDS = frozenset(
    {"com", "net", "org", "io", "co", "gov", "edu", "us", "uk", "de", "info"}
)


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character, over the characters of s."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


def domain_features(domain: str) -> dict:
    """Surface features of a domain string relevant to DGA-likeness.

    length         total character count
    tld            the last label, lowercased
    num_labels     count of dot-separated labels
    digit_ratio    fraction of characters that are digits
    hyphen_count   number of "-" characters
    entropy        shannon_entropy of the full domain string
    """
    d = domain.strip().lower()
    labels = d.split(".")
    digits = sum(1 for ch in d if ch.isdigit())
    return {
        "length": len(d),
        "tld": labels[-1] if labels else "",
        "num_labels": len(labels),
        "digit_ratio": digits / len(d) if d else 0.0,
        "hyphen_count": d.count("-"),
        "entropy": shannon_entropy(d),
    }


def dga_score(domain: str) -> float:
    """Heuristic 0..1 score for how DGA-like a domain looks.

    Combines four signals, each contributing a bounded amount:
      - entropy: high character entropy is typical of algorithmically
        generated strings. Ordinary words rarely exceed ~3.5 bits/char.
      - digit_ratio: a domain heavy with digits is a common DGA trait.
      - length: DGA labels are often longer than a normal brand name.
      - dictionary check: if the domain's main label (or the whole string)
        contains one of the small bundled common words, the score gets
        pulled down, since real DGA output rarely matches common English.

    This is a heuristic score, not a trained model. It is tuned by hand to
    separate obviously algorithmic strings from ordinary domains on this
    data set; treat it as a triage signal, not ground truth.
    """
    d = domain.strip().lower()

    # Reverse-DNS names in the .arpa namespace (in-addr.arpa for IPv4,
    # ip6.arpa for IPv6) are not generated domains. They are the standard DNS
    # reverse-lookup zones, so their many short numeric/hex labels are expected
    # structure, not a DGA signal. Scoring them as DGA-like was wrong, so they
    # are excluded here and treated as their own infrastructure category by the
    # caller. Return 0.0 so they never land in the algorithmic-domain cluster.
    if d.endswith(".arpa"):
        return 0.0

    feats = domain_features(domain)
    labels = d.split(".")
    main_label = labels[0] if labels else d

    # entropy component: scale so ~4.5+ bits/char (near-random over a small
    # alphabet) saturates the component at 1.0.
    entropy_component = min(feats["entropy"] / 4.5, 1.0)

    # digit ratio component: already 0..1, used directly.
    digit_component = feats["digit_ratio"]

    # length component: domains under 8 chars contribute nothing, domains
    # at 30+ chars saturate at 1.0. Long strings (long random labels, or long
    # chains of labels like reverse-DNS lookalikes) are a DGA-adjacent trait.
    length_component = min(max(feats["length"] - 8, 0) / 22, 1.0)

    # label count component: a domain broken into many short labels (as in
    # dotted reverse-DNS style names) is a distinct algorithmic pattern from
    # a single long random label, so it gets its own component rather than
    # riding on length alone. 2 labels contribute nothing, 10+ saturates.
    label_component = min(max(feats["num_labels"] - 2, 0) / 8, 1.0)

    score = (
        0.35 * entropy_component
        + 0.20 * digit_component
        + 0.25 * length_component
        + 0.20 * label_component
    )

    # dictionary check: a recognizable word or common tld pulls the score
    # down, since it suggests a human-chosen name rather than random output.
    has_word = any(word in main_label for word in _COMMON_WORDS)
    common_tld = feats["tld"] in _COMMON_TLDS
    if has_word:
        score -= 0.35
    if not common_tld:
        score += 0.1

    return max(0.0, min(1.0, score))


def _ip_to_int(ip: str) -> int | None:
    try:
        return int(IPv4Address(ip))
    except ValueError:
        return None


class AsnTable:
    """Offline IPv4 -> ASN/country lookup backed by the vendored ip2asn table.

    Loads and parses data/ip2asn-v4.tsv.gz lazily on the first lookup() call,
    builds a sorted list of range starts, and answers each query with a
    binary search (bisect) instead of a linear scan. Rows marked asn "0" /
    country "None" / description "Not routed" are kept in the table (a
    lookup there is a legitimate answer: this address block simply is not
    announced) but are easy to spot from the returned dict.
    """

    def __init__(self, path: Path = DEFAULT_ASN_TABLE):
        self._path = path
        self._starts: list[int] | None = None
        self._rows: list[tuple[int, int, int, str, str]] | None = None

    def _ensure_loaded(self) -> None:
        if self._rows is not None:
            return
        rows = []
        with gzip.open(self._path, "rt", encoding="utf-8", newline="") as f:
            reader = csv.reader(f, delimiter="\t")
            for row in reader:
                if len(row) < 5:
                    continue
                start_s, end_s, asn_s, country, desc = row[:5]
                start = _ip_to_int(start_s)
                end = _ip_to_int(end_s)
                if start is None or end is None:
                    continue
                try:
                    asn = int(asn_s)
                except ValueError:
                    asn = 0
                rows.append((start, end, asn, country, desc))
        rows.sort(key=lambda r: r[0])
        self._rows = rows
        self._starts = [r[0] for r in rows]

    def lookup(self, ip: str) -> dict | None:
        """Look up an IPv4 address string. Returns None if outside the table
        or the value is not a valid IPv4 address."""
        self._ensure_loaded()
        target = _ip_to_int(ip)
        if target is None:
            return None
        assert self._starts is not None and self._rows is not None
        idx = bisect.bisect_right(self._starts, target) - 1
        if idx < 0:
            return None
        start, end, asn, country, desc = self._rows[idx]
        if not (start <= target <= end):
            return None
        return {
            "asn": asn,
            "country": country,
            "description": desc,
            "routed": asn != 0 and country != "None",
        }


def enrich(ind: Indicator, asn_table: AsnTable | None = None) -> dict:
    """Return an enrichment dict appropriate to the indicator's type.

    domain -> domain_features plus dga_score
    ip     -> AsnTable lookup (needs asn_table; returns {} without one)
    hash   -> just the hash subtype, there is nothing else to compute offline
    other  -> empty dict
    """
    if ind.itype == "domain":
        feats = domain_features(ind.value)
        feats["dga_score"] = dga_score(ind.value)
        return feats
    if ind.itype == "ip":
        if asn_table is None:
            return {}
        result = asn_table.lookup(ind.value)
        return result or {}
    if ind.itype in ("md5", "sha1", "sha256"):
        return {"hash_type": ind.itype}
    return {}
