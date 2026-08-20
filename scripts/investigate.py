"""Runnable CLI for the offline IOC investigation tool.

Loads the vendored infoblox csv and MISP campaign files, enriches and
clusters the result, and prints a triage summary. Everything runs from local
data on disk; there are no network calls anywhere in this path.

Usage: python3 scripts/investigate.py
"""

from __future__ import annotations

import sys
from collections import Counter
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.cluster import (
    algorithmic_domain_cluster,
    cluster_by_attribute,
    cluster_by_campaign,
    triage_score,
)
from src.enrich import AsnTable, enrich
from src.indicators import Indicator, defang, load_campaigns, load_infoblox

SAMPLE_SIZE = 10


def _max_date(indicators: tuple[Indicator, ...]) -> date | None:
    best = None
    for ind in indicators:
        if not ind.first_seen:
            continue
        try:
            y, m, d = ind.first_seen.split("-")
            candidate = date(int(y), int(m), int(d))
        except ValueError:
            continue
        if best is None or candidate > best:
            best = candidate
    return best


def main() -> None:
    print("IOC investigation tool - offline enrichment, clustering, and triage")
    print("=" * 72)

    infoblox = load_infoblox()
    campaigns = load_campaigns()
    all_indicators = infoblox + campaigns

    print()
    print(f"Loaded {len(infoblox):,} indicators from infoblox_indicators.csv")
    print(f"Loaded {len(campaigns):,} indicators from data/campaigns/*.json (MISP)")
    print(f"Total: {len(all_indicators):,} indicators")

    print()
    print("Breakdown by type:")
    for itype, count in Counter(i.itype for i in all_indicators).most_common():
        print(f"  {itype:10s} {count:>7,}")

    print()
    print("Breakdown by classification:")
    for cls, count in Counter(i.classification for i in all_indicators).most_common():
        print(f"  {cls:12s} {count:>7,}")

    print()
    print("Building offline ASN table (data/ip2asn-v4.tsv.gz, loads once, lazily)...")
    asn_table = AsnTable()
    ips = [i for i in all_indicators if i.itype == "ip"]
    for i in ips[:1]:
        # trigger the lazy load so its cost is visible in this section, not
        # silently absorbed into a later enrichment call
        asn_table.lookup(i.value)
    print(f"  ASN table ready ({len(ips)} ip-type indicators in the loaded set)")

    print()
    print("Clustering")
    print("-" * 72)

    campaign_clusters = cluster_by_campaign(all_indicators)
    print("Top 5 campaigns by indicator count:")
    top_campaigns = sorted(campaign_clusters.items(), key=lambda kv: len(kv[1]), reverse=True)
    for name, members in top_campaigns[:5]:
        print(f"  {name:45s} {len(members):>6,}")

    print()
    class_clusters = cluster_by_attribute(all_indicators, lambda i: i.classification)
    print("Classification cluster sizes:")
    for cls, members in sorted(class_clusters.items(), key=lambda kv: len(kv[1]), reverse=True):
        print(f"  {cls:12s} {len(members):>7,}")

    print()
    algo_cluster = algorithmic_domain_cluster(all_indicators, threshold=0.6)
    print(f"Algorithmic-looking domain cluster (dga_score > 0.6): {len(algo_cluster):,} domains")
    print("  (high-entropy, machine-shaped names worth a closer look; reverse-DNS .arpa zones excluded)")

    print()
    print("Triage sample")
    print("-" * 72)

    max_date = _max_date(all_indicators)
    print(f"Scoring recency against newest first_seen in the set: {max_date}")

    # Fully enriching all ~41k indicators is unnecessary for a CLI preview,
    # so score a bounded candidate pool: every campaign-linked indicator
    # (already a smaller, higher-signal set) plus the algorithmic-domain
    # cluster, then keep the top SAMPLE_SIZE. This keeps the run to a few seconds.
    candidates = list(campaigns) + algo_cluster
    seen_values = set()
    deduped = []
    for ind in candidates:
        if ind.value in seen_values:
            continue
        seen_values.add(ind.value)
        deduped.append(ind)

    scored = []
    for ind in deduped:
        enrichment = enrich(ind, asn_table=asn_table)
        cluster_size = len(campaign_clusters.get(ind.campaign, [])) if ind.campaign else 1
        score = triage_score(ind, enrichment, cluster_size=cluster_size, max_date=max_date)
        scored.append((score, ind, enrichment))

    scored.sort(key=lambda t: t[0], reverse=True)
    top = scored[:SAMPLE_SIZE]

    header = f"{'indicator':50s} {'type':7s} {'classification':14s} {'campaign':30s} {'dga':>5s} {'triage':>7s}"
    print(header)
    print("-" * len(header))
    for score, ind, enrichment in top:
        dga_display = f"{enrichment['dga_score']:.2f}" if "dga_score" in enrichment else "-"
        value_display = defang(ind.value)
        if len(value_display) > 50:
            value_display = value_display[:47] + "..."
        print(
            f"{value_display:50s} {ind.itype:7s} {ind.classification:14s} "
            f"{ind.campaign[:30]:30s} {dga_display:>5s} {score:>7.1f}"
        )

    print()
    print(f"({len(all_indicators):,} indicators total, showing top {len(top)} of "
          f"{len(deduped):,} scored candidates. Full lists are counts only above.)")


if __name__ == "__main__":
    main()
