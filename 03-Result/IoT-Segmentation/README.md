# IoT Segmentation: submission bundle

The IoT segmentation part of the project: the router configuration and analysis code (`02-Code/IoT-Segmentation/`) and
all results and evidence (`03-Result/IoT-Segmentation/`). Built by the owner's `tools/make_submission_bundle.py` from the
working folder (router repo at git HEAD `904f54de74ed`), following the "Sanitised bundle plan" in
`evidence_manifest.md`. It is an overlay of the main project repo: it only contains this part's two subfolders.

## Start here
| Read | For |
|---|---|
| `03-Result/IoT-Segmentation/results_to_evidence.md` | one page: every result in plain words, its evidence IDs and where it's explained, plus a glossary |
| `03-Result/IoT-Segmentation/analysis.md` | the evidence analysis: findings, detection rules, Learning Contract metrics (§9), recommendations |
| `03-Result/IoT-Segmentation/segmentation_report.md` | the router configuration and change record, states A–E |
| `02-Code/IoT-Segmentation/pipeline_guide.md` | the Splunk pipeline and dashboard, step by step, with a guided tour of the dashboard |
| `03-Result/IoT-Segmentation/evidence_manifest.md` | every evidence item (E01 … E119): file, time window, sensitivity, SHA-256 of the original |

The intermediate reports stay here; the main subject report (`01-Subject Report/` in the repo) is the team's.

## Layout
| Folder | Content |
|---|---|
| `02-Code/IoT-Segmentation/tools/` | analysis tools (Python standard library, Zeek runner and site policy, tshark JA4 extraction, Pi-hole trimmer, upload evaluation, report tooling) |
| `02-Code/IoT-Segmentation/pipeline/`, `pipeline_guide.md` | the Splunk pipeline (`iotpipe.py`), detection macros and dashboard (`dashboard.py`), site config, annotations, dashboard screenshots (`guide_images/`) |
| `02-Code/IoT-Segmentation/asuswrt-configs/` | router scripts and configs at git HEAD, minus `ddns-start`; `GIT_LOG.txt` |
| `03-Result/IoT-Segmentation/` | this README, `SHA256SUMS`, `PROVENANCE.tsv`; the reports; captures (`2026*/`), `firewall_logs/`, `router_states/`, active tests (`iot_active/`, `iot_retest/`), `upload_run/`, `function_check/`, `nvram_extract/`, `derived/`, `planning/` (run sheets with the pre-registered thresholds), `pipeline_out/` (Splunk events, lookups and the Splunk app) |

**Paths in the reports** are relative to the old working folder. Evidence paths resolve inside `03-Result/IoT-Segmentation/`;
`tools/…`, `pipeline/…` and `pipeline_guide.md` resolve inside `02-Code/IoT-Segmentation/`; `asuswrt-configs/…` too.

## Redactions and what was left out
| What | Handling |
|---|---|
| Household's public IPv4, delegated IPv6 prefix, ISP-side /64 (`<WAN-IPv4>`, `<PD>`, `<WAN-RA>` in the reports) | remapped to documentation ranges `198.51.100.55`, `2001:db8:100::/48`, `2001:db8:200:c::/64` everywhere (pcap headers and payloads, text) |
| Hue Bridge `sso` token (cleartext HTTP) | overwritten (`X` in pcaps, `REDACTED-HUE-SSO-TOKEN` in text) |
| Roommate VLAN 114 | all 802.1Q-tagged frames dropped; the roommate router's MAC remapped to `02:00:00:00:01:14` |
| Other household hosts | pcaps keep only frames to or from an IoT device or a test host, plus the router's own broadcast and multicast. In the flat (state A) captures this removes the other household computers' traffic |
| Router's DDNS name | the router's ASUS discovery broadcasts (UDP 9999, 7788), which announce it, are dropped from the pcaps |
| Router admin credentials, Wi-Fi passphrases | `Settings_RT-BE88U.CFG` and the nvram dumps are not included. `nvram_extract/` holds the segmentation-relevant keys of each dump (allow-list; see the header of each file) |
| Full Pi-hole export | not included (every household client's DNS). `derived/pihole_iot_trimmed.csv` holds the IoT clients in the experiment windows |
| `ddns-start` (DDNS credential), router repo history | not included; `GIT_LOG.txt` has the commit log with file stats |
| Original dashboard screenshots (E119) | not included (browser bar shows the DDNS name); the cropped ones (E118) are in `pipeline/guide_images/` |
| Kept as is | internal addresses, MACs of the household's own devices, host names of own devices and services |

Every modified pcap frame has its IPv4 header and TCP/UDP/ICMPv6 checksums recomputed. `PROVENANCE.tsv`
lists, per pcap, how many frames were kept and dropped and why.

## Derived outputs were regenerated
`derived/zeek/`, `derived/tls/`, `derived/analysis/` and `derived/pcap_inventory.json` were produced **inside this
bundle** from the sanitised pcaps, by running the hashed tools in `02-Code/IoT-Segmentation/tools/`. For the IoT devices
they match the working folder (every device frame is kept). Two kinds of figure can't be reproduced from this
bundle, by design:
- **Figures about other household hosts in the flat capture:** `analysis.md` §6.1 counts, such as visible L2
  senders and main-LAN mDNS, and §12.1's flat Zeek totals. Those hosts' frames were removed.
- **Anything that needs the full Pi-hole export:** `tools/trim_pihole.py`, and the Pi-hole part of the pipeline.
  `pipeline_out/` therefore contains the events as generated from the original files (own public addresses
  already masked by the pipeline).

Two small differences remain, both in `derived/analysis/upload_eval.json`. Neither comes from IoT-device traffic or
changes a finding:
- **The test host's traffic to the household's own public addresses** (the hairpin path; 6,804 B in the quiet
  window) now goes to documentation-range addresses, which the tools don't count as internet. The test host's
  quiet-window rate is 1.66 MB/h instead of the 1.70 MB/h in `analysis.md` §16; its 17:00 hour is 145,561,063 B
  instead of 145,567,867 B, and its rolling 60-minute maximum 146,815,024 B instead of 146,820,988 B.
- **`l2_bytes_from_wifi_clients`** is 154,032,934 B instead of 154,113,139 B (80,205 B less): the router's own
  Wi-Fi driver frames (EtherType `0x886c`) were dropped from the pcaps.

## Integrity
`SHA256SUMS` covers both subfolders with paths relative to the repo root. From the repo root:
`sha256sum -c "03-Result/IoT-Segmentation/SHA256SUMS"`. `PROVENANCE.tsv` maps each bundle file to its working-folder source,
the source's SHA-256 (as listed in `evidence_manifest.md`) and the transformation applied.

## Re-running
From `03-Result/IoT-Segmentation/`:
```sh
ln -s "../../02-Code/IoT-Segmentation/tools" tools; ln -s "../../02-Code/IoT-Segmentation/pipeline" pipeline
tools/setup_env.sh                                        # tshark, Zeek 8.0, nmap, jq (Debian/Ubuntu)
sh tools/run_zeek.sh; sh tools/tls_fingerprints.sh        # derived/zeek/, derived/tls/
python3 tools/analyze_pcaps.py; python3 tools/summarize_flows.py; python3 tools/volume_eval.py
python3 pipeline/iotpipe.py check                         # Splunk pipeline (see pipeline_guide.md)
```
