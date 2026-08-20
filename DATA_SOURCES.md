# Data sources and licenses

This project vendors two public datasets. Both are kept as unmodified snapshots in `data/`,
with the fetch date recorded here. All transformation happens at runtime in the code, so the
vendored files stay as the sources published them.

## Infoblox Threat Intelligence (the indicators)

- Source: https://github.com/infobloxopen/threat-intelligence
- Files: `data/infoblox_indicators.csv` (the `indicators/combined.csv` dump) and eight
  campaign files under `data/campaigns/` (a subset of the repo's MISP-format `indicators/misp/`
  event files).
- Snapshot fetched: 2026-08-20.
- License: Creative Commons Attribution 4.0 International (CC BY 4.0). Full text in
  `data/INFOBLOX-CC-BY-4.0-LICENSE.txt`.
- Attribution, as the license requires: threat intelligence data provided by Infoblox under
  CC BY 4.0. Commercial and non-commercial use are both permitted under the license, with
  attribution to Infoblox.
- Contents: 32,970 indicators in the combined dump, almost all domains, classified as
  malicious, suspicious, phishing, clickfix, or voltastealer, dated 2025-08 to 2026-08. The
  campaign files carry named campaigns (VexTrio, Volta Stealer, DGA CTAs, and others) with
  per-campaign domain, IP, hash, URL, and email attributes.

## IPtoASN (the offline ASN and country enrichment table)

- Source: https://iptoasn.com/
- File: `data/ip2asn-v4.tsv.gz` (the `ip2asn-v4.tsv.gz` table, kept compressed).
- Snapshot fetched: 2026-08-20.
- License: Public Domain Dedication and License (PDDL v1.0). No attribution required; recorded
  here for provenance.
- Contents: 533,213 IPv4 ranges, each mapped to an AS number, a country code, and an AS
  description. Used as a local lookup so the tool can enrich an IP with its ASN and country
  without any network call.

## Reused from a sibling project

The tool can also ingest the 16 documented AI-misuse cases from the
`ai-threat-intel-analysis` project as case-record input, to show the same clustering logic
grouping actors by sponsor and campaign period. That project's data is built from public
threat reports and is described in its own repository.
