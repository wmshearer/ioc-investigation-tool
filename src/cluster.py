"""Correlation, clustering, and triage scoring for indicators.

Clustering here means grouping indicators that share an attribute: the same
classification, the same campaign, the same ASN, or a DGA-like domain shape.
Triage scoring turns an indicator plus its enrichment plus its cluster size
into a single 0..100 number an analyst can sort by. All of it is rule-based
arithmetic over data already loaded; nothing here calls out anywhere.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import date
from typing import Callable

from src.enrich import AsnTable, dga_score, enrich
from src.indicators import Indicator

# --- triage weights, named and inspectable ---------------------------------

# Base severity by classification. Malicious and phishing are the highest
# confidence bad-verdict labels in the infoblox taxonomy; suspicious and the
# more specific malware-family labels (clickfix, voltastealer) sit between
# "confirmed bad" and "no verdict". Unknown (campaign-only rows with no
# classification field) gets a modest default rather than zero, since being
# in a named campaign is itself signal.
CLASSIFICATION_WEIGHT = {
    "malicious": 40.0,
    "phishing": 40.0,
    "voltastealer": 38.0,
    "clickfix": 30.0,
    "suspicious": 20.0,
    "unknown": 15.0,
}
DEFAULT_CLASSIFICATION_WEIGHT = 15.0

# Recency weight: newest first_seen in the set scores the full amount, decaying
# linearly to 0 by RECENCY_DECAY_DAYS old. An indicator with no usable date
# gets 0 recency credit rather than a guess.
RECENCY_MAX_WEIGHT = 25.0
RECENCY_DECAY_DAYS = 365

# DGA bump: added on top for domains whose dga_score clears the threshold,
# scaled by how far past the threshold the score is.
DGA_BUMP_THRESHOLD = 0.8
DGA_BUMP_WEIGHT = 20.0

# Cluster size boost: an indicator that shares its clustering key (campaign,
# classification, etc) with many others scores higher, since correlated
# activity is more actionable than a singleton. Saturates at CLUSTER_SIZE_CAP.
CLUSTER_SIZE_WEIGHT = 15.0
CLUSTER_SIZE_CAP = 50


def cluster_by_attribute(
    indicators: tuple[Indicator, ...], key: Callable[[Indicator], str]
) -> dict[str, list[Indicator]]:
    """Group indicators by whatever key(indicator) returns. Indicators whose
    key is the empty string are dropped, since an empty key is "no value"
    rather than a real cluster."""
    groups: dict[str, list[Indicator]] = defaultdict(list)
    for ind in indicators:
        k = key(ind)
        if k:
            groups[k].append(ind)
    return dict(groups)


def cluster_by_campaign(indicators: tuple[Indicator, ...]) -> dict[str, list[Indicator]]:
    """Group indicators that carry a campaign name. Indicators with no
    campaign (most of the raw infoblox CSV rows) are excluded."""
    return cluster_by_attribute(indicators, lambda i: i.campaign)


def cluster_by_asn(
    indicators: tuple[Indicator, ...], asn_table: AsnTable
) -> dict[int, list[Indicator]]:
    """Enrich every ip-type indicator against asn_table and group by ASN.
    Non-ip indicators and unresolvable IPs are excluded."""
    groups: dict[int, list[Indicator]] = defaultdict(list)
    for ind in indicators:
        if ind.itype != "ip":
            continue
        result = asn_table.lookup(ind.value)
        if result is None:
            continue
        groups[result["asn"]].append(ind)
    return dict(groups)


def algorithmic_domain_cluster(
    indicators: tuple[Indicator, ...], threshold: float = 0.6
) -> list[Indicator]:
    """Domain indicators that score high on the algorithmic-shape heuristic.

    These are domains whose dga_score is above the threshold: high entropy,
    heavy on digits, long, or otherwise shaped like a machine generated string
    rather than a human-chosen name. It is deliberately NOT called a DGA
    cluster. The heuristic cannot prove a domain came from a domain-generation
    algorithm, and reverse-DNS .arpa zones (which score 0.0 by design) are the
    reminder of why: surface features alone confuse expected DNS structure with
    generated names. This is a triage bucket of "looks algorithmic, worth a
    closer look", not an attribution.
    """
    out = []
    for ind in indicators:
        if ind.itype != "domain":
            continue
        if dga_score(ind.value) > threshold:
            out.append(ind)
    return out


# Old name kept so nothing that imported it breaks. Prefer the honest name above.
dga_family_cluster = algorithmic_domain_cluster


def _parse_date(s: str) -> date | None:
    if not s:
        return None
    try:
        y, m, d = s.split("-")
        return date(int(y), int(m), int(d))
    except (ValueError, IndexError):
        return None


def _recency_score(first_seen: str, max_date: date | None) -> float:
    if max_date is None:
        return 0.0
    seen = _parse_date(first_seen)
    if seen is None:
        return 0.0
    age_days = (max_date - seen).days
    if age_days <= 0:
        return RECENCY_MAX_WEIGHT
    if age_days >= RECENCY_DECAY_DAYS:
        return 0.0
    fraction = 1.0 - (age_days / RECENCY_DECAY_DAYS)
    return RECENCY_MAX_WEIGHT * fraction


def triage_score(
    ind: Indicator,
    enrichment: dict,
    cluster_size: int,
    max_date: date | None = None,
) -> float:
    """Composite 0..100 triage score.

    classification weight  0..40, from CLASSIFICATION_WEIGHT
    recency                0..25, linear decay from max_date over RECENCY_DECAY_DAYS
    dga bump                0..20, only for domains with dga_score > DGA_BUMP_THRESHOLD
    cluster size boost      0..15, scaled by cluster_size against CLUSTER_SIZE_CAP

    max_date is the newest first_seen across the working set; pass it in so
    recency is relative to the data, not to wall-clock "today".
    """
    score = CLASSIFICATION_WEIGHT.get(ind.classification, DEFAULT_CLASSIFICATION_WEIGHT)

    score += _recency_score(ind.first_seen, max_date)

    dga = enrichment.get("dga_score")
    if dga is not None and dga > DGA_BUMP_THRESHOLD:
        over = (dga - DGA_BUMP_THRESHOLD) / (1.0 - DGA_BUMP_THRESHOLD)
        score += DGA_BUMP_WEIGHT * over

    if cluster_size > 1:
        fraction = min(cluster_size, CLUSTER_SIZE_CAP) / CLUSTER_SIZE_CAP
        score += CLUSTER_SIZE_WEIGHT * fraction

    return max(0.0, min(100.0, score))
