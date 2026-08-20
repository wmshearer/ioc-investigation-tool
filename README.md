# IOC Investigation Tool

An offline tool that takes threat indicators, enriches them, groups related ones, and scores
them for triage. It runs entirely against data already on disk. There is no network call, no
API key, and no external service at any point, so the whole thing is reproducible from this
repository alone.

It works on 41,561 real indicators from two public datasets: 32,970 from Infoblox's threat
intelligence dump and 8,591 more pulled from eight of Infoblox's named campaign files.

## What it does

**Enrichment, all local:**
- Detects an indicator's type from its format (IPv4, IPv6, domain, URL, MD5, SHA1, SHA256,
  email).
- Defangs and refangs indicators (`hxxp://`, `[.]`) the way an analyst does before sharing.
- Extracts domain features: length, TLD, label count, digit ratio, and character entropy.
- Scores a domain for how machine-shaped it looks (a DGA-likeness heuristic, described below).
- Looks up an IP's ASN and country from a vendored offline table by binary search.

**Clustering and correlation:**
- Groups indicators by shared attribute: classification, campaign, TLD, or ASN.
- Groups by named campaign (VexTrio, Volta Stealer, and others from the Infoblox data).
- Collects the algorithmic-looking domains into one bucket worth a closer look.

**Triage scoring:**
- Assigns each indicator a 0 to 100 priority from four weighted signals: classification
  severity, recency, algorithmic-shape, and how large a correlated cluster it sits in. The
  weights are named constants at the top of `src/cluster.py`, so they are inspectable rather
  than buried in the code.

## An honest note on the DGA score

The domain score is a heuristic, not a trained classifier. It combines surface features
(entropy, digit ratio, length) into a single number that tends to separate machine-generated
strings from ordinary names on this data. It has not been fit to labelled DGA data, so it is
a triage signal, not a verdict.

An early version of it scored reverse-DNS names in the `.arpa` namespace (like
`5.2.1.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa`) as highly DGA-like, because they are long and full
of digits. That was wrong. Those names are the standard DNS reverse-lookup zones, not
generated domains. The scorer now returns 0.0 for anything in `.arpa`, and the cluster is
named for what it actually is, algorithmic-looking domains, rather than asserting DGA as a
fact. The fix is locked by a test.

## Data

See `DATA_SOURCES.md` for the full attribution. In short:
- Indicators: Infoblox Threat Intelligence, CC BY 4.0, attribution to Infoblox.
- ASN table: IPtoASN.com, public domain (PDDL).

Both are vendored as unmodified snapshots dated 2026-08-20. The tool transforms them at
runtime and never writes back to them.

## Running

```
python3 -m pytest                    # 11 tests
python3 scripts/investigate.py       # load, enrich, cluster, and triage the whole set
```

## Scope

This scores which indicators to look at first from their attributes. It does not detonate
anything, query any live reputation service, or make a network request. It is the offline,
reproducible core of an investigation workflow, the part that can run anywhere with no keys.
