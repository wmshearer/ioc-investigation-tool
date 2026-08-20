"""Tests for the offline IOC investigation tool.

Each test locks a finding about the vendored data or the tool's own logic, so
a later change (a rewritten regex, a reweighted score, a data refresh) cannot
quietly break something this project depends on. Real numbers are pinned
where the data is stable (indicator counts); heuristic scores are only
checked for correct ordering, since dga_score and triage_score are explicitly
not calibrated to exact values.
"""

from __future__ import annotations

from datetime import date

from src.indicators import (
    ITYPES,
    Indicator,
    defang,
    detect_type,
    load_campaigns,
    load_infoblox,
    refang,
)
from src.enrich import AsnTable, dga_score, enrich, shannon_entropy
from src.cluster import algorithmic_domain_cluster, cluster_by_campaign, triage_score


# --- indicators.py -----------------------------------------------------

def test_detect_type_classifies_each_known_format():
    """One real example of each format the tool claims to detect."""
    assert detect_type("8.8.8.8") == "ip"
    assert detect_type("malicious-example.com") == "domain"
    assert detect_type("d41d8cd98f00b204e9800998ecf8427e") == "md5"
    assert detect_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"
    assert (
        detect_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        == "sha256"
    )
    assert detect_type("analyst@example.com") == "email"
    assert detect_type("http://example.com/path") == "url"


def test_defang_refang_round_trip():
    """refang(defang(x)) must return exactly x, or the hygiene helpers are lying
    about being inverses of each other."""
    for value in ("http://evil-domain.com/payload", "malicious-example.net"):
        assert refang(defang(value)) == value


def test_load_infoblox_row_count_and_types():
    """Pins the vendored csv's row count and confirms every itype the loader
    assigns is one this tool actually recognizes."""
    indicators = load_infoblox()
    assert len(indicators) == 32970
    for ind in indicators:
        assert ind.itype in ITYPES


def test_load_campaigns_has_thousands_with_campaign_and_tags():
    """The MISP campaign files hold thousands of attributes across 8 events;
    at least one indicator must carry a real campaign name and real tags,
    since that is the whole point of loading this source separately."""
    indicators = load_campaigns()
    assert len(indicators) > 8000
    named = [i for i in indicators if i.campaign]
    tagged = [i for i in indicators if i.tags]
    assert named
    assert tagged


# --- enrich.py -----------------------------------------------------------

def test_shannon_entropy_bounds():
    """A single repeated character has zero entropy; a string with several
    distinct characters in even proportion clears 2 bits/char."""
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("a1b2c3d4e5f6g7h8") > 2.0


def test_dga_score_orders_algorithmic_above_dictionary():
    """An algorithmic-looking domain must score higher than a plain
    dictionary domain. The exact numbers are a tuned heuristic, not a
    contract, so only the ordering is asserted."""
    algorithmic = dga_score("x7k2p9qz3vb1.com")
    clean = dga_score("microsoft.com")
    assert algorithmic > clean


def test_dga_score_excludes_reverse_dns_arpa_zones():
    """Reverse-DNS names in the .arpa namespace are legitimate DNS structure,
    not generated domains. An earlier version scored them high because they are
    long and digit-heavy, which was wrong. They must score 0.0 so they never
    land in the algorithmic-domain cluster."""
    assert dga_score("5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa") == 0.0
    assert dga_score("1.0.0.127.in-addr.arpa") == 0.0


def test_asn_table_lookup_known_cloudflare_ip():
    """1.0.0.1 falls inside the vendored table's 1.0.0.0-1.0.0.255 range,
    which the real ip2asn-v4.tsv.gz lists as AS13335 CLOUDFLARENET, US."""
    table = AsnTable()
    result = table.lookup("1.0.0.1")
    assert result is not None
    assert result["asn"] == 13335
    assert result["country"] == "US"


# --- cluster.py ------------------------------------------------------------

def test_cluster_by_campaign_has_known_names():
    """The volta_stealer campaign file must surface as a cluster key."""
    indicators = load_campaigns()
    clusters = cluster_by_campaign(indicators)
    assert any("volta_stealer" in name for name in clusters)


def test_triage_score_in_range_and_orders_severity_over_benign():
    """A malicious, recent, DGA-shaped domain must score higher than a
    suspicious, old, clean-looking one, and both must land in [0, 100]."""
    max_date = date(2026, 8, 13)

    bad = Indicator(
        value="x7k2p9qz3vb1a8w.com",
        itype="domain",
        classification="malicious",
        source="infoblox",
        first_seen="2026-08-13",
        campaign="",
        tags=(),
    )
    mild = Indicator(
        value="britishnewspost.com",
        itype="domain",
        classification="suspicious",
        source="infoblox",
        first_seen="2025-08-13",
        campaign="",
        tags=(),
    )

    bad_score = triage_score(bad, enrich(bad), cluster_size=1, max_date=max_date)
    mild_score = triage_score(mild, enrich(mild), cluster_size=1, max_date=max_date)

    for s in (bad_score, mild_score):
        assert 0.0 <= s <= 100.0
    assert bad_score > mild_score


def test_algorithmic_domain_cluster_is_nonempty_and_excludes_arpa():
    """The real corpus (with campaign indicators) contains machine-shaped
    domains: random subdomains, hex-encoded names, campaign-generated strings.
    At the 0.6 threshold the algorithmic cluster must be non-empty, and it must
    not contain any .arpa reverse-DNS zone, since those are excluded by design."""
    indicators = load_infoblox() + load_campaigns()
    cluster = algorithmic_domain_cluster(indicators, threshold=0.6)
    assert len(cluster) > 0
    assert not any(ind.value.endswith(".arpa") for ind in cluster)
